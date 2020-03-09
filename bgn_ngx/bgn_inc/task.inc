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

#ifndef _TASK_INC
#define _TASK_INC

#include "type.h"
#include "list_base.h"

#include <setjmp.h>
#include <time.h>

#include "debug.h"

#include "clist.h"
#include "cqueue.h"
#include "cvector.h"
#include "cstack.h"
#include "csig.h"

#include "cthread.h"

#include "cparacfg.inc"
#include "csyscfg.h"
#include "cxml.h"
#include "csys.inc"

#include "mod.inc"
#include "cload.h"
#include "csrv.h"

#include "cproc.h"
#include "ipv4pool.h"
#include "croutine.h"
#include "cepoll.inc"
#include "cconnp.inc"

#define ERR_TASK_SEQNO ((UINT32)(~((UINT32)0)))
#define ERR_FUNC_ID    ((UINT32)(~((UINT32)0)))
#define ERR_PARA_NUM   ((UINT32)(~((UINT32)0)))

#define TASK_CONFIG_XML_MAX_SIZE            ((UINT32) 64 * 1024) /*64KB*/

/*TASK_TAG*/
#define                     TAG_TASK_REQ    ((UINT32)  1)
#define                     TAG_TASK_RSP    ((UINT32)  2)
#define                     TAG_TASK_FWD    ((UINT32)  3)
#define                   TAG_TASK_UNDEF    ((UINT32) -1)

/*TASK_QUEUE_TYPE*/
#define               TASK_RECVING_QUEUE    ((UINT32)  0)   /*not support task priority, i.e., must not use task_queue_add_node to add new node*/
#define               TASK_IS_RECV_QUEUE    ((UINT32)  1)   /*support task priority    */
#define               TASK_TO_SEND_QUEUE    ((UINT32)  2)   /*support task priority    */
#define               TASK_SENDING_QUEUE    ((UINT32)  3)   /*not support task priority, i.e., must not use task_queue_add_node to add new node*/
#define                   TASK_QUEUE_END    ((UINT32)  4)

/*TASK_STATUS*/
#define                 TASK_REQ_TO_SEND    ((UINT32)  1001)
#define                 TASK_REQ_SENDING    ((UINT32)  1002)
#define                 TASK_REQ_RECVING    ((UINT32)  1004)
#define                 TASK_REQ_IS_SENT    ((UINT32)  1008)
#define                 TASK_REQ_IS_RECV    ((UINT32)  1010)
#define                 TASK_REQ_DISCARD    ((UINT32)  1020)
#define                 TASK_REQ_TIMEOUT    ((UINT32)  1040)
#define                 TASK_REQ_SENDAGN    ((UINT32)  1080) /*send again when tcid broken happen*/

#define                 TASK_RSP_TO_SEND    ((UINT32)  2001)
#define                 TASK_RSP_SENDING    ((UINT32)  2002)
#define                 TASK_RSP_RECVING    ((UINT32)  2004)
#define                 TASK_RSP_IS_SENT    ((UINT32)  2008)
#define                 TASK_RSP_IS_RECV    ((UINT32)  2010)
#define                 TASK_RSP_DISCARD    ((UINT32)  2020)
#define                 TASK_RSP_DCODING    ((UINT32)  2040)

#define                 TASK_FWD_TO_SEND    ((UINT32)  4001)
#define                 TASK_FWD_SENDING    ((UINT32)  4002)
#define                 TASK_FWD_RECVING    ((UINT32)  4004)
#define                 TASK_FWD_IS_SENT    ((UINT32)  4008)
#define                 TASK_FWD_IS_RECV    ((UINT32)  4010)
#define                 TASK_FWD_DISCARD    ((UINT32)  4020)

#define                 TASK_WAS_SENT       ((UINT32)  1)
#define                 TASK_WAS_RECV       ((UINT32)  2)
#define                 TASK_NOT_COMP       ((UINT32) -1)

#define                TASK_UNDEF_STATUS    ((UINT32) -1)

/*LOAD BALANCING CHOICE*/
#define              LOAD_BALANCING_LOOP    ((UINT32)  0)
#define              LOAD_BALANCING_MOD     ((UINT32)  1)
#define              LOAD_BALANCING_QUE     ((UINT32)  2)
#define              LOAD_BALANCING_OBJ     ((UINT32)  3)
#define              LOAD_BALANCING_CPU     ((UINT32)  4)
#define              LOAD_BALANCING_MEM     ((UINT32)  5)
#define              LOAD_BALANCING_DSK     ((UINT32)  6)
#define              LOAD_BALANCING_NET     ((UINT32)  7)
#define              LOAD_BALANCING_END     ((UINT32)  8)

/*TASK REQ TYPE*/
#define              TASK_ACT_TYPE          ((UINT32)  1) /*task_act TASK_REQ/TASK_RSP*/
#define              TASK_DEA_TYPE          ((UINT32)  2) /*task_dea TASK_REQ/TASK_RSP*/
#define              TASK_NORMAL_TYPE       ((UINT32)  3) /*normal TASK_REQ/TASK_RSP*/
#define              TASK_UNKNOWN_TYPE      ((UINT32) -1) /*unknow TASK_REQ/TASK_RSP*/

#define              TASK_NEED_RSP_FLAG            ((UINT32)  1) /*flag: task req need task rsp*/
#define              TASK_NOT_NEED_RSP_FLAG        ((UINT32)  2) /*flag: task req NOT need task rsp*/

#define              TASK_NEED_RESCHEDULE_FLAG     ((UINT32)  3) /*flag: task req will be rescheduled when taskcomm broken*/
#define              TASK_NOT_NEED_RESCHEDULE_FLAG ((UINT32)  4) /*flag: task req will NOT be rescheduled when taskcomm broken*/

#define              TASK_NEED_ALL_RSP      ((UINT32) -1) /*need to wait all response come back*/
#define              TASK_NEED_NONE_RSP     ((UINT32)  0) /*not need to wait any response come back*/

#define              TASK_ALWAYS_LIVE       ((UINT32) -1) /*task mgr stay waiting until collected specific num of task rsp*/
#define              TASK_DEFAULT_LIVE      ((UINT32) /*60*/TASK_DEFAULT_LIVE_NSEC) /*task may stay 60s waiting for until collected specific num of task rsp*/

/*TASK PRIORITY*/
#define              TASK_PRIO_NORMAL       ((UINT32)  1) /*FIFO task*/
#define              TASK_PRIO_HIGH         ((UINT32)  2) /*FIFO task, but preempt those normal tasks*/
#define              TASK_PRIO_PREEMPT      ((UINT32)  3) /*LIFO task, preempt any task, including the previous reached PREEMPT tasks*/
#define              TASK_PRIO_UNDEF        ((UINT32) -1) /*FIFO task*/



typedef struct
{
    MOD_NODE        send_mod;          /* from which module */
    MOD_NODE        recv_mod;          /* to which module */
}TASK_HEADER;

typedef struct
{
    UINT32         para_dir;    /* parameter direction*/
    UINT32         para_val;    /* function parameter value */
                                /* if para is pointer, the value = addr of para */
                                /* if para is not pointer, the value = para */
}FUNC_PARA;

typedef struct _TASK_FUNC
{
    UINT32         func_id;               /* func id */
    UINT32         func_para_num;         /* func para num */

    UINT32         func_ret_val;          /* function return value */
                                          /* if return is pointer, the value = addr of return */
                                          /* if return is not pointer, the value = return */

    FUNC_PARA      func_para[ MAX_NUM_OF_FUNC_PARAS ]; /*func parameter table*/
}TASK_FUNC;

struct _TASK_MGR;/*claim the type here due to it be used in definition of TASK_REQ,TASK_RSP*/


typedef struct
{
    TASK_HEADER    task_header;


    struct _TASK_MGR *task_mgr;          /* pointer to TASK MGR to deploy load balancing by TASK_REQ*/
                                         /* task_mgr is used by TASK_REQ*/
                                         /* task_mgr is used by TASK_RSP when and only when task_rsp is committed, and the task_mgr pointer is copied from TASK_REQ*/
    CLOAD_STAT     cload_stat;           /* load of remote mod carried on by TASK_RSP*/

    UINT32         load_balancing_strategy;/* which load balancing strategy is deployed on this TASK_REQ*/

    CROUTINE_NODE  *cthread_node;          /*which cthread is running this task req*/

    MOD_NODE      *recv_mod_new;          /* optional. used to update info of created task mgr*/
    UINT32         recv_mod_update_flag;  /* if recv_mod need to update, set to EC_TRUE, otherwise, set to EC_FALSE*/
    UINT32         mod_id_update_flag;    /* if first para mod_id need to update, set to EC_TRUE, otherwise, set to EC_FALSE*/

    UINT32         need_rsp_flag;         /* need or not response of task req*/
    UINT32         time_to_live;          /* task req/rsp is effective only in seconds. -1 means always living until response is available*/
    CTIMET         start_time;            /* start time*/

    UINT32         this_prio;             /* priority*/

    UINT32         this_type;             /* TASK_REQ type: ACT, DEA, or NORMAL*/
    UINT32         this_tag;              /* what kind of task */
    UINT32         task_seqno;            /* sequence number of task req/rsp used same as that of task mgr */
    UINT32         sub_seqno;             /* sub sequence number to distinguish task req/rsp in the same task mgr*/

    FUNC_ADDR_NODE *func_addr_node;       /* function addr node of task funcion*/
    TASK_FUNC      task_func;             /* task function */

}TASK_ANY, TASK_REQ, TASK_RSP, TASK_FWD;

typedef struct _TASK_NODE
{
    UINT32        this_tag;                    /* what kind of task */

    UINT32        task_status;                 /* task req or rsp status in status machine */
    UINT32        task_flag;                   /* send complete or recv complete flag*/

    CMUTEX        cmutex;                      /* used by task req and task rsp for alignment when task req in IS_SENT state while task rsp in decoding*/

    union
    {
        TASK_ANY     task_any;
        TASK_REQ     task_req;                /* task request */
        TASK_RSP     task_rsp;                /* task response */
        TASK_FWD     task_fwd;                /* task forward */
    }u;

    UINT32       buff_type;                   /*memory type*/
    UINT32       buff_len;                    /*the encoded length or recved length*/
    UINT32       buff_pos;                    /*the recved or sent dynamic length*/
    UINT8 *      buff;                        /*node buff for pack/unpack task req/rsp*/
}TASK_NODE;

typedef EC_BOOL (*CHECKER)(const UINT32);

#define TASK_MGR_COUNTER_TASK_REQ_IS_SENT    ((UINT32) 0) /* number of sent task req                         */
#define TASK_MGR_COUNTER_TASK_REQ_DISCARD    ((UINT32) 1) /* number of discarded task req                    */
#define TASK_MGR_COUNTER_TASK_REQ_TIMEOUT    ((UINT32) 2) /* number of timeout task req                      */
#define TASK_MGR_COUNTER_TASK_RSP_IS_NEED    ((UINT32) 3) /* number of waiting response of task req          */
#define TASK_MGR_COUNTER_TASK_RSP_IS_SUCC    ((UINT32) 4) /* number of success response of task req          */
#define TASK_MGR_COUNTER_TASK_RSP_IS_FAIL    ((UINT32) 5) /* number of failure response of task req          */
#define TASK_MGR_COUNTER_TASK_RSP_RESERVD    ((UINT32) 6) /* number of thread reserve or occupy this task mgr*/
#define TASK_MGR_COUNTER_END                 ((UINT32) 7)

#define TASK_MGR_COUNTER(task_mgr, counter_type)   ((task_mgr)->counter[ (counter_type) ])
#if 0
#define TASK_MGR_COUNTER_DEBUG_INFO(task_mgr, counter_type, location) \
if((counter_type) == TASK_MGR_COUNTER_TASK_RSP_RESERVD){\
    sys_log(LOGSTDOUT, "thread %u, task mgr %lx, seqno %lx, counter %ld ==> %ld at %s:%ld\n", \
                        pthread_self(), task_mgr, TASK_MGR_SEQNO(task_mgr), (counter_type), TASK_MGR_COUNTER(task_mgr, counter_type),\
                        MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));\
}
#else
#define TASK_MGR_COUNTER_DEBUG_INFO(task_mgr, counter_type, location) do{}while(0)
#endif

#define TASK_MGR_COUNTER_INC_BY_TASK_REQ(task_mgr, counter_type, task_req, location) \
do{\
    if((task_mgr) == TASK_REQ_MGR(task_req) && TASK_MGR_SEQNO(task_mgr) == TASK_REQ_SEQNO(task_req)) {\
        TASK_MGR_CRWLOCK_WRLOCK(task_mgr, location);\
        TASK_MGR_COUNTER(task_mgr, counter_type) ++;\
        TASK_MGR_COUNTER_DEBUG_INFO(task_mgr, counter_type, location);\
        TASK_MGR_CRWLOCK_UNLOCK(task_mgr, location);\
    }\
}while(0)

#define TASK_MGR_COUNTER_DEC_BY_TASK_REQ(task_mgr, counter_type, task_req, location) \
do{\
    if((task_mgr) == TASK_REQ_MGR(task_req) && TASK_MGR_SEQNO(task_mgr) == TASK_REQ_SEQNO(task_req)) {\
        TASK_MGR_CRWLOCK_WRLOCK(task_mgr, location);\
        TASK_MGR_COUNTER(task_mgr, counter_type) --;\
        TASK_MGR_COUNTER_DEBUG_INFO(task_mgr, counter_type, location);\
        TASK_MGR_CRWLOCK_UNLOCK(task_mgr, location);\
    }\
}while(0)

#define TASK_MGR_COUNTER_INC_BY_TASK_RSP(task_mgr, counter_type, task_rsp, location) \
do{\
    if((task_mgr) == TASK_RSP_MGR(task_rsp) && TASK_MGR_SEQNO(task_mgr) == TASK_RSP_SEQNO(task_rsp)) {\
        TASK_MGR_CRWLOCK_WRLOCK(task_mgr, location);\
        TASK_MGR_COUNTER(task_mgr, counter_type) ++;\
        TASK_MGR_COUNTER_DEBUG_INFO(task_mgr, counter_type, location);\
        TASK_MGR_CRWLOCK_UNLOCK(task_mgr, location);\
    }\
}while(0)

#define TASK_MGR_COUNTER_DEC_BY_TASK_RSP(task_mgr, counter_type, task_rsp, location) \
do{\
    if((task_mgr) == TASK_RSP_MGR(task_rsp) && TASK_MGR_SEQNO(task_mgr) == TASK_RSP_SEQNO(task_rsp)) {\
        TASK_MGR_CRWLOCK_WRLOCK(task_mgr, location);\
        TASK_MGR_COUNTER(task_mgr, counter_type) --;\
        TASK_MGR_COUNTER_DEBUG_INFO(task_mgr, counter_type, location);\
        TASK_MGR_CRWLOCK_UNLOCK(task_mgr, location);\
    }\
}while(0)

/* task req manager */
typedef struct _TASK_MGR
{
    CROUTINE_COND     croutine_cond;

    MOD_MGR *         mod_mgr;         /* module mgr will deploy load balancing*/
    EC_BOOL           free_flag;       /* free or not free mod_mgr when free task mgr*/

    UINT32            task_prio;       /* task priority which will be followed by TASK_REQ and TASK_RSP*/

    UINT32            task_seqno;      /* manage which tasks with this sequence number */
    UINT32            sub_seqno_gen;   /* generator of sub sequence number in the same task mgr*/
    CLIST             task_queue;      /* task node queue */

    CHECKER           ret_val_checker; /* check return value in response*/

    UINT32            need_rsp_flag;   /* need or not response of task req*/

    UINT32            counter[ TASK_MGR_COUNTER_END ];
    CROUTINE_RWLOCK   croutine_rwlock; /* lock for above num getting or setting */

    UINT32            need_reschedule_flag; /*need or not re-schedule task req when taskcomm broken*/

    UINT32            time_to_live;    /* task mgr is effective only in seconds. -1 means always living until the expected responses collected*/
    CTMV              start_time;      /* start time*/
    CTMV              end_time;        /* end time*/

    EC_BOOL           jump_flag;       /* jump or not jump*/
    EC_BOOL           aging_flag;      /* when aging, task mgr should be in aging list*/
    EC_BOOL           recving_flag;    /*when recving, task_mgr should be in recv list*/
}TASK_MGR;

/*task context*/
typedef struct
{
    TASK_RSP *task_rsp;
}TASK_CONTEXT;

#define TASK_RANK_NODE_GREEN_LIGHT  (EC_TRUE)
#define TASK_RANK_NODE_RED_LIGHT    (EC_FALSE)

typedef struct
{
    CROUTINE_MUTEX  croutine_mutex;
    UINT32          light; /*EC_TRUE: green light, enable isending; EC_FALSE: red light, disable isending*/
}TASK_RANK_NODE;

typedef EC_BOOL (*TASK_RUNNER_FUNC)(void *);

typedef struct
{
    const char       *name;
    TASK_RUNNER_FUNC  exec;
    void             *arg;
}TASK_RUNNER_NODE;

#define TASK_RUNNER_NODE_NAME(task_runner_node)   ((task_runner_node)->name)
#define TASK_RUNNER_NODE_EXEC(task_runner_node)   ((task_runner_node)->exec)
#define TASK_RUNNER_NODE_ARG(task_runner_node)    ((task_runner_node)->arg)


#if 0
typedef struct
{
    UINT32  tcid;
    UINT32  rank;

    void (*executor)(void);
}TASK_RUNNER;

#define TASK_RUNNER_TCID(task_runner)     ((task_runner)->tcid)
#define TASK_RUNNER_TCID_STR(task_runner) (c_word_to_ipv4(TASK_RUNNER_TCID(task_runner)))
#define TASK_RUNNER_RANK(task_runner)     ((task_runner)->rank)
#define TASK_RUNNER_EXEC(task_runner)     ((task_runner)->executor)
#endif

typedef struct
{
    UINT32 year;
    UINT32 month;
    UINT32 mday;
    UINT32 hour;
    UINT32 minute;
    UINT32 second;
}TASK_TIME_FMT;

#define TASK_TIME_FMT_YEAR(task_time_fmt)       ((task_time_fmt)->year)
#define TASK_TIME_FMT_MONTH(task_time_fmt)      ((task_time_fmt)->month)
#define TASK_TIME_FMT_MDAY(task_time_fmt)       ((task_time_fmt)->mday)
#define TASK_TIME_FMT_HOUR(task_time_fmt)       ((task_time_fmt)->hour)
#define TASK_TIME_FMT_MIN(task_time_fmt)        ((task_time_fmt)->minute)
#define TASK_TIME_FMT_SEC(task_time_fmt)        ((task_time_fmt)->second)

typedef struct
{
    TASK_TIME_FMT   start_time;
    TASK_TIME_FMT   end_time;

    UINT32          tcid;
    UINT32          rank;

    UINT32          seqno;
    UINT32          time_to_live;

    UINT32          jump_flag; /*task wait or task no wait*/
    UINT32          need_rsp_flag;
    UINT32          need_reschedule_flag;

    UINT32          total_req_num;
    UINT32          sent_req_num;
    UINT32          discard_req_num;
    UINT32          timeout_req_num;
    UINT32          need_rsp_num;
    UINT32          succ_rsp_num;
    UINT32          fail_rsp_num;
}TASK_REPORT_NODE;

#define TASK_REPORT_NODE_START_TIME(task_report_node)                   (&((task_report_node)->start_time))
#define TASK_REPORT_NODE_END_TIME(task_report_node)                     (&((task_report_node)->end_time))
#define TASK_REPORT_NODE_TCID(task_report_node)                         ((task_report_node)->tcid)
#define TASK_REPORT_NODE_RANK(task_report_node)                         ((task_report_node)->rank)
#define TASK_REPORT_NODE_SEQNO(task_report_node)                        ((task_report_node)->seqno)
#define TASK_REPORT_NODE_TIME_TO_LIVE(task_report_node)                 ((task_report_node)->time_to_live)
#define TASK_REPORT_NODE_WAIT_FLAG(task_report_node)                    ((task_report_node)->jump_flag)
#define TASK_REPORT_NODE_NEED_RSP_FLAG(task_report_node)                ((task_report_node)->need_rsp_flag)
#define TASK_REPORT_NODE_NEED_RESCHEDULE_FLAG(task_report_node)         ((task_report_node)->need_reschedule_flag)
#define TASK_REPORT_NODE_TOTAL_REQ_NUM(task_report_node)                ((task_report_node)->total_req_num)
#define TASK_REPORT_NODE_SENT_REQ_NUM(task_report_node)                 ((task_report_node)->sent_req_num)
#define TASK_REPORT_NODE_DISCARD_REQ_NUM(task_report_node)              ((task_report_node)->discard_req_num)
#define TASK_REPORT_NODE_TIMEOUT_REQ_NUM(task_report_node)              ((task_report_node)->timeout_req_num)
#define TASK_REPORT_NODE_NEED_RSP_NUM(task_report_node)                 ((task_report_node)->need_rsp_num)
#define TASK_REPORT_NODE_SUCC_RSP_NUM(task_report_node)                 ((task_report_node)->succ_rsp_num)
#define TASK_REPORT_NODE_FAIL_RSP_NUM(task_report_node)                 ((task_report_node)->fail_rsp_num)


#define TASK_BRD_TIME_STR_SIZE         ((int)64)

typedef EC_BOOL (*TASK_BRD_EXTRA_CLEANER)(void *);

typedef EC_BOOL (*TASK_BRD_CALLBACK)(void *);


typedef struct
{
    TASK_BRD_CALLBACK        func;
    void                    *arg;
}TASK_BRD_PROCESS_HANDLER;

#define TASK_BRD_PROCESS_HANDLER_FUNC(task_brd_process_handler)           ((task_brd_process_handler)->func)
#define TASK_BRD_PROCESS_HANDLER_ARG(task_brd_process_handler)            ((task_brd_process_handler)->arg)

/*task board*/
typedef struct _TASK_BRD
{
    int          rsvd01;

    int          saved_argc;
    char       **saved_argv;
    char       **os_argv;
    char        *os_argv_last;

    char       **os_environ;
    char       **saved_environ;
    char        *cache_environ;

    UINT32       network_level;/*default is L0. e.g., 0 (L0), 1 (L1), ...*/

    CTIMET       ctime;/*current task_brd time on wall*/
    CTM          ctm;  /*current task_brd time on wall*/
    CTMV         ctmv;
    char         time_str[64];

    CEPOLL      *cepoll;

    CSIG        *csig;
    CSTRING     *sys_cfg_xml_fname_cstr;
    CSTRING     *basic_cfg_xml_fname_cstr;
    CSTRING     *script_fname_cstr; /*for console and dbg*/
    CSTRING     *log_path_cstr;
    CSTRING     *ssl_path_cstr;

    CSET        *netcard_set;

    SYS_CFG     *sys_cfg;         /*sys config of config.xml*/
    CPARACFG    *cparacfg;        /*only for current communicator which is a pointer to one cparacfg in sys_cfg*/
    TASKS_CFG   *local_tasks_cfg; /*local tasks cfg which is a pointer to one tasks_cfg in sys_cfg*/
    TASKS_CFG   *detect_tasks_cfg;/*DETECT tasks cfg*/
    IPV4_POOL   *ipv4_pool;

    int          udp_srv_sockfd;
    int          rsvd02;

    UINT32       reg_type;

    CLIST        recv_task_mgr_list;  /* recving task mgr list*/
    CLIST        aging_task_mgr_list; /* aging task mgr list which waiting for removal*/
    CSTACK       task_mgr_stack;   /* stack of task mgr*/

    CVECTOR      type_conv_vec;
    CVECTOR      func_addr_vec;

    pid_t        do_slave_pid;
    uint32_t     enable_slow_down:1;/*set by outside of BGN. if other enable it, BGN could be slow down or not depend on BGN*/
    uint32_t     tasks_is_running:1;
    uint32_t     rsvd2:30;

    CTHREAD_ID   do_slave_cthread_id;            /* do_slave thread  */
    CTHREAD_ID   do_routine_cthread_id;          /* do_routine thread  */
    CTHREAD_ID   do_cbtimer_cthread_id;          /* do_cbtimer thread*/
    CTHREAD_ID   bcast_cthread_id;               /* dhcp_server_do   */

    UINT32       super_md_id;

    CROUTINE_COND        fwd_croutine_cond;        /* CCOND for forwarding process. release it when forward process is ready*/

    UINT32       this_tcid;        /* taskComm id*/
    UINT32       this_comm;        /* communicator of current process*/
    UINT32       this_size;        /* size of communicator*/
    UINT32       this_rank;        /* rank of current process*/
    UINT32       this_ipaddr;      /* service ipaddr of current taskComm server*/
    UINT32       this_port;        /* service port of current taskComm server*/

    CMUTEX       task_seqno_spool_cmutex;/*cmutex for task sequence number*/
    UINT32       task_seqno_spool; /* task sequence number in current process */

#if (SWITCH_ON == CROUTINE_SUPPORT_CTHREAD_SWITCH)
    CTHREAD_POOL *task_req_thread_spool;/* task thread number in current process */
    CTHREAD_POOL *task_rsp_thread_spool;/* task thread number in current process */
#endif/*(SWITCH_ON == CROUTINE_SUPPORT_CTHREAD_SWITCH)*/

#if (SWITCH_ON == CROUTINE_SUPPORT_COROUTINE_SWITCH)
    CROUTINE_POOL *croutine_pool;/* croutine pool for task req in current process */
#endif /*(SWITCH_ON == CROUTINE_SUPPORT_COROUTINE_SWITCH)*/

    CSRV         *csrv;
    CPROC        *cproc;

    CCONNP_MGR   *http_cconnp_mgr;

    UINT32       cmon_id;

    CLIST        task_queue[ TASK_QUEUE_END ];       /* task req/rsp queue - buffer! */

    CVECTOR      md_node_tbl;

    CVECTOR     *rank_tbl;         /*mount TASK_RANK_NODE which is task req/rsp/fwd sending queue in the current communicator, indexed by rank*/

    CSTACK       runner_stack;           /*executor of current tcid and current rank*/

    CLIST        cload_mgr;

    CVECTOR      broken_tcid_tbl;  /*broken tcid table.*/

    CLIST        mod_mgr_list;     /*each MODULE will maintain a mod_mgr which is registered to TASK_BRD*/
    CLIST        context_list;     /*task context list will maintain the task rsp to activate a module*/

    CLIST        task_report_list; /*task report log cache which records info when a task come to end. item data type: TASK_REPORT_NODE*/
    CLIST        task_cbtimer_list;

    CLIST        task_process_list;/*item is TASK_BRD_PROCESS_HANDLER*/

    EC_BOOL      enable_flag;      /*when enabled (== EC_TRUE), obtain actual load, when disabled (== EC_FALSE), obtain faked load(-1, the max int value)*/
    EC_BOOL      reset_flag;       /*when enabled (== EC_TRUE), reset do_slave thread if down, otherwise, not reset do_slave thread if down*/
    EC_BOOL      ngx_exiting_flag;

    //EC_BOOL      dbg_flag;
    //UINT32       dbg_counter;

    CLOAD_STAT   cload_stat;

    CSYS_CPU_AVG_STAT cpu_avg_stat;

    void        *extra;
    EC_BOOL     (*extra_cleanup)(void *);
}TASK_BRD;



typedef MOD_MGR * (* MD_FGET_MOD_MGR)(const UINT32);

/*---------------------------------------- interface of task mod ----------------------------------------------*/
#define MOD_NODE_TCID(mod_node)             ((mod_node)->tcid)
#define MOD_NODE_TCID_STR(mod_node)         (c_word_to_ipv4(MOD_NODE_TCID(mod_node)))
#define MOD_NODE_COMM(mod_node)             ((mod_node)->comm)
#define MOD_NODE_RANK(mod_node)             ((mod_node)->rank)
#define MOD_NODE_MODI(mod_node)             ((mod_node)->modi)
#define MOD_NODE_HOPS(mod_node)             ((mod_node)->hops)
#define MOD_NODE_LOAD(mod_node)             ((mod_node)->load)
#define MOD_NODE_STAT(mod_node)             ((mod_node)->stat)
#define MOD_NODE_CLOAD_STAT(mod_node)       (&((mod_node)->cload_stat))

#define MOD_NODE_LOAD_GET_QUE(task_brd, mod_node)             task_brd_rank_load_tbl_get_que(task_brd, MOD_NODE_TCID(mod_node), MOD_NODE_RANK(mod_node))
#define MOD_NODE_LOAD_SET_QUE(task_brd, mod_node, new_load)   task_brd_rank_load_tbl_set_que(task_brd, MOD_NODE_TCID(mod_node), MOD_NODE_RANK(mod_node), new_load)

#define MOD_NODE_MATCH(mod_node, tcid, comm, rank, modi) \
(\
           (\
                (CMPI_ANY_TCID == tcid) \
             || (CMPI_ANY_DBG_TCID == tcid && CMPI_DBG_TCID_BEG <= MOD_NODE_TCID(mod_node) && MOD_NODE_TCID(mod_node) <= CMPI_DBG_TCID_END)\
             || (CMPI_ANY_MON_TCID == tcid && CMPI_MON_TCID_BEG <= MOD_NODE_TCID(mod_node) && MOD_NODE_TCID(mod_node) <= CMPI_MON_TCID_END)\
             || (tcid == MOD_NODE_TCID(mod_node))\
           )/*tcid matched*/\
        && (CMPI_ANY_COMM == comm || comm == MOD_NODE_COMM(mod_node))/*comm matched*/\
        && (CMPI_ANY_RANK == rank || rank == MOD_NODE_RANK(mod_node))/*rank matched*/\
        && (CMPI_ANY_MODI == modi || modi == MOD_NODE_MODI(mod_node))/*modi matched*/\
)

/*---------------------------------------- interface of task mod mgr ----------------------------------------------*/
#define MOD_MGR_LDB_CHOICE(mod_mgr)           ((mod_mgr)->ldb_choice.load_balancing_strategy)
#define MOD_MGR_LDB_FUNCPTR(mod_mgr)          ((mod_mgr)->ldb_choice.get)
#define MOD_MGR_LDB_BEST_MOD_NODE(mod_mgr)    ((MOD_MGR_LDB_FUNCPTR(mod_mgr))(mod_mgr)) /*call get function to obtain the best mod_node*/

#define MOD_MGR_LOCAL_MOD(mod_mgr)            (&((mod_mgr)->local_mod))
#define MOD_MGR_LOCAL_MOD_POS(mod_mgr)        ((mod_mgr)->local_mod_pos)
#define MOD_MGR_LOCAL_MOD_TCID(mod_mgr)       (MOD_NODE_TCID(MOD_MGR_LOCAL_MOD(mod_mgr)))
#define MOD_MGR_LOCAL_MOD_TCID_STR(mod_mgr)   (MOD_NODE_TCID_STR(MOD_MGR_LOCAL_MOD(mod_mgr)))
#define MOD_MGR_LOCAL_MOD_RANK(mod_mgr)       (MOD_NODE_RANK(MOD_MGR_LOCAL_MOD(mod_mgr)))

#define MOD_MGR_REMOTE_LIST(mod_mgr)          (&((mod_mgr)->remote_mod_list))
#define MOD_MGR_REMOTE_NUM(mod_mgr)           (cvector_size(MOD_MGR_REMOTE_LIST(mod_mgr)))
#define MOD_MGR_REMOTE_POS(mod_mgr)           ((mod_mgr)->remote_mod_pos)
#define MOD_MGR_REMOTE_MOD(mod_mgr, pos)      ((MOD_NODE *)cvector_get(MOD_MGR_REMOTE_LIST(mod_mgr), (pos)))

/*---------------------------------------- interface of task header ----------------------------------------------*/
#define TASK_HEADER_SEND_MOD(task_header)           (&((task_header)->send_mod))
#define TASK_HEADER_RECV_MOD(task_header)           (&((task_header)->recv_mod))

#define TASK_HEADER_SEND_TCID(task_header)          (MOD_NODE_TCID(TASK_HEADER_SEND_MOD(task_header)))
#define TASK_HEADER_SEND_COMM(task_header)          (MOD_NODE_COMM(TASK_HEADER_SEND_MOD(task_header)))
#define TASK_HEADER_SEND_RANK(task_header)          (MOD_NODE_RANK(TASK_HEADER_SEND_MOD(task_header)))
#define TASK_HEADER_SEND_MODI(task_header)          (MOD_NODE_MODI(TASK_HEADER_SEND_MOD(task_header)))

#define TASK_HEADER_RECV_TCID(task_header)          (MOD_NODE_TCID(TASK_HEADER_RECV_MOD(task_header)))
#define TASK_HEADER_RECV_COMM(task_header)          (MOD_NODE_COMM(TASK_HEADER_RECV_MOD(task_header)))
#define TASK_HEADER_RECV_RANK(task_header)          (MOD_NODE_RANK(TASK_HEADER_RECV_MOD(task_header)))
#define TASK_HEADER_RECV_MODI(task_header)          (MOD_NODE_MODI(TASK_HEADER_RECV_MOD(task_header)))

/*---------------------------------------- interface of task req/rsp/mem/ext ----------------------------------------------*/
#define TASK_REQ_NODE(this_task_req)      list_base_entry(this_task_req, TASK_NODE, u.task_req)
#define TASK_RSP_NODE(this_task_rsp)      list_base_entry(this_task_rsp, TASK_NODE, u.task_rsp)
#define TASK_FWD_NODE(this_task_fwd)      list_base_entry(this_task_fwd, TASK_NODE, u.task_fwd)
#define TASK_ANY_NODE(this_task_any)      list_base_entry(this_task_any, TASK_NODE, u.task_any)

#define TASK_ANY_HEADER(task_any)         (&((task_any)->task_header))
#define TASK_REQ_HEADER(task_req)         (&((task_req)->task_header))
#define TASK_RSP_HEADER(task_rsp)         (&((task_rsp)->task_header))
#define TASK_FWD_HEADER(task_fwd)         (&((task_fwd)->task_header))

#define TASK_REQ_SEND_MOD(task_req)       (TASK_HEADER_SEND_MOD(TASK_REQ_HEADER(task_req)))
#define TASK_REQ_RECV_MOD(task_req)       (TASK_HEADER_RECV_MOD(TASK_REQ_HEADER(task_req)))

#define TASK_RSP_SEND_MOD(task_rsp)       (TASK_HEADER_SEND_MOD(TASK_RSP_HEADER(task_rsp)))
#define TASK_RSP_RECV_MOD(task_rsp)       (TASK_HEADER_RECV_MOD(TASK_RSP_HEADER(task_rsp)))

#define TASK_FWD_SEND_MOD(task_fwd)       (TASK_HEADER_SEND_MOD(TASK_FWD_HEADER(task_fwd)))
#define TASK_FWD_RECV_MOD(task_fwd)       (TASK_HEADER_RECV_MOD(TASK_FWD_HEADER(task_fwd)))

#define TASK_REQ_MGR(task_req)            ((task_req)->task_mgr)
#define TASK_RSP_MGR(task_rsp)            ((task_rsp)->task_mgr)
#define TASK_ANY_MGR(task_any)            ((task_any)->task_mgr)

#define TASK_REQ_CLOAD_STAT(task_req)     (&((task_req)->cload_stat))
#define TASK_RSP_CLOAD_STAT(task_rsp)     (&((task_rsp)->cload_stat))
#define TASK_FWD_CLOAD_STAT(task_fwd)     (&((task_fwd)->cload_stat))
#define TASK_ANY_CLOAD_STAT(task_any)     (&((task_any)->cload_stat))

#define TASK_ANY_NEED_RSP_FLAG(task_any)  ((task_any)->need_rsp_flag)
#define TASK_REQ_NEED_RSP_FLAG(task_req)  ((task_req)->need_rsp_flag)
#define TASK_FWD_NEED_RSP_FLAG(task_fwd)  ((task_fwd)->need_rsp_flag)

#define TASK_ANY_TIME_TO_LIVE(task_any)   ((task_any)->time_to_live)
#define TASK_REQ_TIME_TO_LIVE(task_req)   ((task_req)->time_to_live)
#define TASK_RSP_TIME_TO_LIVE(task_rsp)   ((task_rsp)->time_to_live)
#define TASK_FWD_TIME_TO_LIVE(task_fwd)   ((task_fwd)->time_to_live)

#define TASK_ANY_START_TIME(task_any)     ((task_any)->start_time)
#define TASK_REQ_START_TIME(task_req)     ((task_req)->start_time)
#define TASK_RSP_START_TIME(task_rsp)     ((task_rsp)->start_time)
#define TASK_FWD_START_TIME(task_fwd)     ((task_fwd)->start_time)

#define TASK_REQ_TYPE(task_req)           ((task_req)->this_type)
#define TASK_RSP_TYPE(task_rsp)           ((task_rsp)->this_type)
#define TASK_FWD_TYPE(task_fwd)           ((task_fwd)->this_type)
#define TASK_ANY_TYPE(task_any)           ((task_any)->this_type)

#define TASK_REQ_LDB_CHOICE(task_req)     ((task_req)->load_balancing_strategy)
#define TASK_RSP_LDB_CHOICE(task_rsp)     ((task_rsp)->load_balancing_strategy)
#define TASK_FWD_LDB_CHOICE(task_fwd)     ((task_fwd)->load_balancing_strategy)
#define TASK_ANY_LDB_CHOICE(task_any)     ((task_any)->load_balancing_strategy)

#define TASK_REQ_CTHREAD_NODE(task_req)   ((task_req)->cthread_node)
#define TASK_RSP_CTHREAD_NODE(task_rsp)   ((task_rsp)->cthread_node)
#define TASK_FWD_CTHREAD_NODE(task_fwd)   ((task_fwd)->cthread_node)
#define TASK_ANY_CTHREAD_NODE(task_any)   ((task_any)->cthread_node)

#define TASK_REQ_RECV_MOD_NEW(task_req)   ((task_req)->recv_mod_new)
#define TASK_RSP_RECV_MOD_NEW(task_rsp)   ((task_rsp)->recv_mod_new)

#define TASK_REQ_RECV_MOD_FLAG(task_req)  ((task_req)->recv_mod_update_flag)
#define TASK_RSP_RECV_MOD_FLAG(task_rsp)  ((task_rsp)->recv_mod_update_flag)

#define TASK_REQ_MOD_ID_FLAG(task_req)    ((task_req)->mod_id_update_flag)
#define TASK_RSP_MOD_ID_FLAG(task_rsp)    ((task_rsp)->mod_id_update_flag)

#define TASK_ANY_SEND_TCID(task_any)      (TASK_HEADER_SEND_TCID(TASK_ANY_HEADER(task_any)))
#define TASK_ANY_SEND_COMM(task_any)      (TASK_HEADER_SEND_COMM(TASK_ANY_HEADER(task_any)))
#define TASK_ANY_SEND_RANK(task_any)      (TASK_HEADER_SEND_RANK(TASK_ANY_HEADER(task_any)))
#define TASK_ANY_SEND_MODI(task_any)      (TASK_HEADER_SEND_MODI(TASK_ANY_HEADER(task_any)))
#define TASK_ANY_RECV_TCID(task_any)      (TASK_HEADER_RECV_TCID(TASK_ANY_HEADER(task_any)))
#define TASK_ANY_RECV_COMM(task_any)      (TASK_HEADER_RECV_COMM(TASK_ANY_HEADER(task_any)))
#define TASK_ANY_RECV_RANK(task_any)      (TASK_HEADER_RECV_RANK(TASK_ANY_HEADER(task_any)))
#define TASK_ANY_RECV_MODI(task_any)      (TASK_HEADER_RECV_MODI(TASK_ANY_HEADER(task_any)))

#define TASK_REQ_SEND_TCID(task_req)      (TASK_HEADER_SEND_TCID(TASK_REQ_HEADER(task_req)))
#define TASK_REQ_SEND_COMM(task_req)      (TASK_HEADER_SEND_COMM(TASK_REQ_HEADER(task_req)))
#define TASK_REQ_SEND_RANK(task_req)      (TASK_HEADER_SEND_RANK(TASK_REQ_HEADER(task_req)))
#define TASK_REQ_SEND_MODI(task_req)      (TASK_HEADER_SEND_MODI(TASK_REQ_HEADER(task_req)))
#define TASK_REQ_RECV_TCID(task_req)      (TASK_HEADER_RECV_TCID(TASK_REQ_HEADER(task_req)))
#define TASK_REQ_RECV_COMM(task_req)      (TASK_HEADER_RECV_COMM(TASK_REQ_HEADER(task_req)))
#define TASK_REQ_RECV_RANK(task_req)      (TASK_HEADER_RECV_RANK(TASK_REQ_HEADER(task_req)))
#define TASK_REQ_RECV_MODI(task_req)      (TASK_HEADER_RECV_MODI(TASK_REQ_HEADER(task_req)))


#define TASK_RSP_SEND_TCID(task_rsp)      (TASK_HEADER_SEND_TCID(TASK_RSP_HEADER(task_rsp)))
#define TASK_RSP_SEND_COMM(task_rsp)      (TASK_HEADER_SEND_COMM(TASK_RSP_HEADER(task_rsp)))
#define TASK_RSP_SEND_RANK(task_rsp)      (TASK_HEADER_SEND_RANK(TASK_RSP_HEADER(task_rsp)))
#define TASK_RSP_SEND_MODI(task_rsp)      (TASK_HEADER_SEND_MODI(TASK_RSP_HEADER(task_rsp)))
#define TASK_RSP_RECV_TCID(task_rsp)      (TASK_HEADER_RECV_TCID(TASK_RSP_HEADER(task_rsp)))
#define TASK_RSP_RECV_COMM(task_rsp)      (TASK_HEADER_RECV_COMM(TASK_RSP_HEADER(task_rsp)))
#define TASK_RSP_RECV_RANK(task_rsp)      (TASK_HEADER_RECV_RANK(TASK_RSP_HEADER(task_rsp)))
#define TASK_RSP_RECV_MODI(task_rsp)      (TASK_HEADER_RECV_MODI(TASK_RSP_HEADER(task_rsp)))

#define TASK_FWD_SEND_TCID(task_fwd)      (TASK_HEADER_SEND_TCID(TASK_FWD_HEADER(task_fwd)))
#define TASK_FWD_SEND_COMM(task_fwd)      (TASK_HEADER_SEND_COMM(TASK_FWD_HEADER(task_fwd)))
#define TASK_FWD_SEND_RANK(task_fwd)      (TASK_HEADER_SEND_RANK(TASK_FWD_HEADER(task_fwd)))
#define TASK_FWD_SEND_MODI(task_fwd)      (TASK_HEADER_SEND_MODI(TASK_FWD_HEADER(task_fwd)))
#define TASK_FWD_RECV_TCID(task_fwd)      (TASK_HEADER_RECV_TCID(TASK_FWD_HEADER(task_fwd)))
#define TASK_FWD_RECV_COMM(task_fwd)      (TASK_HEADER_RECV_COMM(TASK_FWD_HEADER(task_fwd)))
#define TASK_FWD_RECV_RANK(task_fwd)      (TASK_HEADER_RECV_RANK(TASK_FWD_HEADER(task_fwd)))
#define TASK_FWD_RECV_MODI(task_fwd)      (TASK_HEADER_RECV_MODI(TASK_FWD_HEADER(task_fwd)))

#define TASK_ANY_SEND_TCID_STR(task_any)  (c_word_to_ipv4(TASK_ANY_SEND_TCID(task_any)))
#define TASK_ANY_RECV_TCID_STR(task_any)  (c_word_to_ipv4(TASK_ANY_RECV_TCID(task_any)))

#define TASK_REQ_SEND_TCID_STR(task_req)  (c_word_to_ipv4(TASK_REQ_SEND_TCID(task_req)))
#define TASK_REQ_RECV_TCID_STR(task_req)  (c_word_to_ipv4(TASK_REQ_RECV_TCID(task_req)))

#define TASK_RSP_SEND_TCID_STR(task_rsp)  (c_word_to_ipv4(TASK_RSP_SEND_TCID(task_rsp)))
#define TASK_RSP_RECV_TCID_STR(task_rsp)  (c_word_to_ipv4(TASK_RSP_RECV_TCID(task_rsp)))

#define TASK_FWD_SEND_TCID_STR(task_fwd)  (c_word_to_ipv4(TASK_FWD_SEND_TCID(task_fwd)))
#define TASK_FWD_RECV_TCID_STR(task_fwd)  (c_word_to_ipv4(TASK_FWD_RECV_TCID(task_fwd)))


#define TASK_ANY_PRIO(task_any)                    ((task_any)->this_prio)
#define TASK_ANY_TAG(task_any)                     ((task_any)->this_tag)
#define TASK_ANY_SEQNO(task_any)                   ((task_any)->task_seqno)
#define TASK_ANY_SUB_SEQNO(task_any)               ((task_any)->sub_seqno)
#define TASK_ANY_FUNC(task_any)                    (&((task_any)->task_func))
#define TASK_ANY_FUNC_ID(task_any)                 (TASK_ANY_FUNC(task_any)->func_id)
#define TASK_ANY_FUNC_PARA_NUM(task_any)           (TASK_ANY_FUNC(task_any)->func_para_num)
#define TASK_ANY_FUNC_PARA_VAL(task_any, para_idx) (TASK_ANY_FUNC(task_any)->func_para[ para_idx ].para_val)
#define TASK_ANY_FUNC_PARA_DIR(task_any, para_idx) (TASK_ANY_FUNC(task_any)->func_para[ para_idx ].para_dir)
#define TASK_ANY_FUNC_ADDR_NODE(task_any)          ((task_any)->func_addr_node)

#define TASK_REQ_PRIO(task_req)                    ((task_req)->this_prio)
#define TASK_REQ_TAG(task_req)                     ((task_req)->this_tag)
#define TASK_REQ_SEQNO(task_req)                   ((task_req)->task_seqno)
#define TASK_REQ_SUB_SEQNO(task_req)               ((task_req)->sub_seqno)
#define TASK_REQ_FUNC(task_req)                    (&((task_req)->task_func))
#define TASK_REQ_FUNC_ID(task_req)                 (TASK_REQ_FUNC(task_req)->func_id)
#define TASK_REQ_FUNC_PARA_NUM(task_req)           (TASK_REQ_FUNC(task_req)->func_para_num)
#define TASK_REQ_FUNC_PARA_VAL(task_req, para_idx) (TASK_REQ_FUNC(task_req)->func_para[ para_idx ].para_val)
#define TASK_REQ_FUNC_PARA_DIR(task_req, para_idx) (TASK_REQ_FUNC(task_req)->func_para[ para_idx ].para_dir)
#define TASK_REQ_FUNC_ADDR_NODE(task_req)          ((task_req)->func_addr_node)

#define TASK_RSP_PRIO(task_rsp)                    ((task_rsp)->this_prio)
#define TASK_RSP_TAG(task_rsp)                     ((task_rsp)->this_tag)
#define TASK_RSP_SEQNO(task_rsp)                   ((task_rsp)->task_seqno)
#define TASK_RSP_SUB_SEQNO(task_rsp)               ((task_rsp)->sub_seqno)
#define TASK_RSP_FUNC(task_rsp)                    (&((task_rsp)->task_func))
#define TASK_RSP_FUNC_ID(task_rsp)                 (TASK_RSP_FUNC(task_rsp)->func_id)
#define TASK_RSP_FUNC_RET(task_rsp)                (TASK_RSP_FUNC(task_rsp)->func_ret_val)
#define TASK_RSP_FUNC_PARA_NUM(task_rsp)           (TASK_RSP_FUNC(task_rsp)->func_para_num)
#define TASK_RSP_FUNC_PARA_VAL(task_rsp, para_idx) (TASK_RSP_FUNC(task_rsp)->func_para[ para_idx ].para_val)
#define TASK_RSP_FUNC_PARA_DIR(task_rsp, para_idx) (TASK_RSP_FUNC(task_rsp)->func_para[ para_idx ].para_dir)
#define TASK_RSP_FUNC_ADDR_NODE(task_rsp)          ((task_rsp)->func_addr_node)

#define TASK_FWD_PRIO(task_fwd)                    ((task_fwd)->this_prio)
#define TASK_FWD_TAG(task_fwd)                     ((task_fwd)->this_tag)
#define TASK_FWD_SEQNO(task_fwd)                   ((task_fwd)->task_seqno)
#define TASK_FWD_SUB_SEQNO(task_fwd)               ((task_fwd)->sub_seqno)
#define TASK_FWD_FUNC(task_fwd)                    (&((task_fwd)->task_func))
#define TASK_FWD_FUNC_ID(task_fwd)                 (TASK_FWD_FUNC(task_fwd)->func_id)
#define TASK_FWD_FUNC_PARA_NUM(task_fwd)           (TASK_FWD_FUNC(task_fwd)->func_para_num)
#define TASK_FWD_FUNC_PARA_VAL(task_fwd, para_idx) (TASK_FWD_FUNC(task_fwd)->func_para[ para_idx ].para_val)
#define TASK_FWD_FUNC_PARA_DIR(task_fwd, para_idx) (TASK_FWD_FUNC(task_fwd)->func_para[ para_idx ].para_dir)
#define TASK_FWD_FUNC_ADDR_NODE(task_fwd)          ((task_fwd)->func_addr_node)

/*---------------------------------------- interface of task node ----------------------------------------------*/

#define TASK_NODE_ANY(task_node)                             (&((task_node)->u.task_any))
#define TASK_NODE_REQ(task_node)                             (&((task_node)->u.task_req))
#define TASK_NODE_RSP(task_node)                             (&((task_node)->u.task_rsp))
#define TASK_NODE_FWD(task_node)                             (&((task_node)->u.task_fwd))

#define TASK_NODE_BUFF(task_node)                            ((task_node)->buff)
#define TASK_NODE_BUFF_TYPE(task_node)                       ((task_node)->buff_type)
#define TASK_NODE_BUFF_LEN(task_node)                        ((task_node)->buff_len)
#define TASK_NODE_BUFF_POS(task_node)                        ((task_node)->buff_pos)
#define TASK_NODE_TAG(task_node)                             ((task_node)->this_tag)
#define TASK_NODE_STATUS(task_node)                          ((task_node)->task_status)
#define TASK_NODE_COMP(task_node)                            ((task_node)->task_flag)
#define TASK_NODE_CMUTEX(task_node)                          (&((task_node)->cmutex))

#define TASK_NODE_CMUTEX_INIT(task_node, location)           (cmutex_init(TASK_NODE_CMUTEX(task_node), CMUTEX_PROCESS_PRIVATE, location))
#define TASK_NODE_CMUTEX_CLEAN(task_node, location)          (cmutex_clean(TASK_NODE_CMUTEX(task_node), location))
#if 0
#define TASK_NODE_CMUTEX_LOCK(task_node, location)           (cmutex_lock(TASK_NODE_CMUTEX(task_node), location))
#define TASK_NODE_CMUTEX_UNLOCK(task_node, location)         (cmutex_unlock(TASK_NODE_CMUTEX(task_node), location))
#endif
#if 1
#define TASK_NODE_CMUTEX_LOCK(task_node, location)           do{}while(0)
#define TASK_NODE_CMUTEX_UNLOCK(task_node, location)         do{}while(0)

#endif
#define TASK_NODE_SEND_TCID(task_node)                       (TASK_ANY_SEND_TCID(TASK_NODE_ANY(task_node)))
#define TASK_NODE_SEND_COMM(task_node)                       (TASK_ANY_SEND_COMM(TASK_NODE_ANY(task_node)))
#define TASK_NODE_SEND_RANK(task_node)                       (TASK_ANY_SEND_RANK(TASK_NODE_ANY(task_node)))
#define TASK_NODE_SEND_MODI(task_node)                       (TASK_ANY_SEND_MODI(TASK_NODE_ANY(task_node)))
#define TASK_NODE_RECV_TCID(task_node)                       (TASK_ANY_RECV_TCID(TASK_NODE_ANY(task_node)))
#define TASK_NODE_RECV_COMM(task_node)                       (TASK_ANY_RECV_COMM(TASK_NODE_ANY(task_node)))
#define TASK_NODE_RECV_RANK(task_node)                       (TASK_ANY_RECV_RANK(TASK_NODE_ANY(task_node)))
#define TASK_NODE_RECV_MODI(task_node)                       (TASK_ANY_RECV_MODI(TASK_NODE_ANY(task_node)))
#define TASK_NODE_PRIO(task_node)                            (TASK_ANY_PRIO(TASK_NODE_ANY(task_node)))
#define TASK_NODE_TYPE(task_node)                            (TASK_ANY_TYPE(TASK_NODE_ANY(task_node)))
#define TASK_NODE_FUNC_ID(task_node)                         (TASK_ANY_FUNC_ID(TASK_NODE_ANY(task_node)))
#define TASK_NODE_SEQNO(task_node)                           (TASK_ANY_SEQNO(TASK_NODE_ANY(task_node)))
#define TASK_NODE_SUB_SEQNO(task_node)                       (TASK_ANY_SUB_SEQNO(TASK_NODE_ANY(task_node)))
#define TASK_NODE_LDB_CHOICE(task_node)                      (TASK_ANY_LDB_CHOICE(TASK_NODE_ANY(task_node)))

#define TASK_NODE_SEND_TCID_STR(task_node)                   (c_word_to_ipv4(TASK_NODE_SEND_TCID(task_node)))
#define TASK_NODE_RECV_TCID_STR(task_node)                   (c_word_to_ipv4(TASK_NODE_RECV_TCID(task_node)))

/*---------------------------------------- interface of task manager ----------------------------------------------*/
#define TASK_MGR_MOD(task_mgr)                             ((task_mgr)->mod_mgr)
#define TASK_MGR_LOCAL_MOD_TCID(task_mgr)                  MOD_MGR_LOCAL_MOD_TCID(TASK_MGR_MOD(task_mgr))
#define TASK_MGR_LOCAL_MOD_RANK(task_mgr)                  MOD_MGR_LOCAL_MOD_RANK(TASK_MGR_MOD(task_mgr))

#define TASK_MGR_QUEUE(task_mgr)                           (&((task_mgr)->task_queue))
#define TASK_MGR_PRIO(task_mgr)                            ((task_mgr)->task_prio)
#define TASK_MGR_SEQNO(task_mgr)                           ((task_mgr)->task_seqno)
#define TASK_MGR_SUB_SEQNO_GEN(task_mgr)                   ((task_mgr)->sub_seqno_gen)
#define TASK_MGR_MOD_FREE_FLAG(task_mgr)                   ((task_mgr)->free_flag)
#define TASK_MGR_NEED_RSP_FLAG(task_mgr)                   ((task_mgr)->need_rsp_flag)
#define TASK_MGR_RETV_CHECKER(task_mgr)                    ((task_mgr)->ret_val_checker)
#define TASK_MGR_RET_VAL_CHECK(task_mgr, ret_val)          ((TASK_MGR_RETV_CHECKER(task_mgr))(ret_val))
#define TASK_MGR_NEED_RESCHEDULE_FLAG(task_mgr)            ((task_mgr)->need_reschedule_flag)
#define TASK_MGR_TIME_TO_LIVE(task_mgr)                    ((task_mgr)->time_to_live)
#define TASK_MGR_START_TIME(task_mgr)                      ((task_mgr)->start_time)
#define TASK_MGR_END_TIME(task_mgr)                        ((task_mgr)->end_time)
#define TASK_MGR_START_TIME_SEC(task_mgr)                  ((task_mgr)->start_time.tv_sec)
#define TASK_MGR_END_TIME_SEC(task_mgr)                    ((task_mgr)->end_time.tv_sec)
#define TASK_MGR_START_TIME_MSEC(task_mgr)                 ((task_mgr)->start_time.tv_usec / 1000)
#define TASK_MGR_END_TIME_MSEC(task_mgr)                   ((task_mgr)->end_time.tv_usec / 1000)
#define TASK_MGR_JMP_FLAG(task_mgr)                        ((task_mgr)->jump_flag)
#define TASK_MGR_AGING_FLAG(task_mgr)                      ((task_mgr)->aging_flag)
#define TASK_MGR_RECVING_FLAG(task_mgr)                    ((task_mgr)->recving_flag)

#define TASK_MGR_CROUTINE_COND(task_mgr)                   (&((task_mgr)->croutine_cond))
#define TASK_MGR_CCOND_INIT(task_mgr, location)             croutine_cond_init(TASK_MGR_CROUTINE_COND(task_mgr), 0/*never timeout*/, location)
#define TASK_MGR_CCOND_CLEAN(task_mgr, location)            croutine_cond_clean(TASK_MGR_CROUTINE_COND(task_mgr), location)
#define TASK_MGR_CCOND_RESERVE(task_mgr, counter, location) croutine_cond_reserve(TASK_MGR_CROUTINE_COND(task_mgr), counter, location)
#define TASK_MGR_CCOND_RELEASE(task_mgr, location)          croutine_cond_release(TASK_MGR_CROUTINE_COND(task_mgr), location)
#define TASK_MGR_CCOND_RELEASE_ALL(task_mgr, location)      croutine_cond_release_all(TASK_MGR_CROUTINE_COND(task_mgr), location)
#define TASK_MGR_CCOND_WAIT(task_mgr, location)             croutine_cond_wait(TASK_MGR_CROUTINE_COND(task_mgr), location)

#define TASK_MGR_CRWLOCK(task_mgr)                         (&((task_mgr)->croutine_rwlock))
#define TASK_MGR_CRWLOCK_INIT(task_mgr, location)          do{croutine_rwlock_init(TASK_MGR_CRWLOCK(task_mgr), CMUTEX_PROCESS_PRIVATE, location);}while(0)
#define TASK_MGR_CRWLOCK_CLEAN(task_mgr, location)         do{croutine_rwlock_clean(TASK_MGR_CRWLOCK(task_mgr), location);}while(0)
#if 0
#define TASK_MGR_CRWLOCK_RDLOCK(task_mgr, location)        do{croutine_rwlock_rdlock(TASK_MGR_CRWLOCK(task_mgr), location);}while(0)
#define TASK_MGR_CRWLOCK_WRLOCK(task_mgr, location)        do{croutine_rwlock_wrlock(TASK_MGR_CRWLOCK(task_mgr), location);}while(0)
#define TASK_MGR_CRWLOCK_UNLOCK(task_mgr, location)        do{croutine_rwlock_unlock(TASK_MGR_CRWLOCK(task_mgr), location);}while(0)
#endif
#if 1
#define TASK_MGR_CRWLOCK_RDLOCK(task_mgr, location)        do{}while(0)
#define TASK_MGR_CRWLOCK_WRLOCK(task_mgr, location)        do{}while(0)
#define TASK_MGR_CRWLOCK_UNLOCK(task_mgr, location)        do{}while(0)

#endif

#define TASK_MGR_ADD_REQ_TAIL(task_mgr, task_req)    \
        clist_push_back(TASK_MGR_QUEUE(task_mgr), TASK_REQ_NODE(task_req))

/*---------------------------------------- interface of task context ----------------------------------------------*/
#define TASK_CONTEXT_TASK_RSP(task_context)   ((task_context)->task_rsp)

/*---------------------------------------- interface of task rank node ----------------------------------------------*/
#define TASK_RANK_NODE_CMUTEX(task_rank_node)                           (&((task_rank_node)->croutine_mutex))
#define TASK_RANK_NODE_CMUTEX_INIT(task_rank_node, location)            (croutine_mutex_init(TASK_RANK_NODE_CMUTEX(task_rank_node), CMUTEX_PROCESS_PRIVATE, location))
#define TASK_RANK_NODE_CMUTEX_CLEAN(task_rank_node, location)           (croutine_mutex_clean(TASK_RANK_NODE_CMUTEX(task_rank_node), location))
#if 0
#define TASK_RANK_NODE_LOCK(task_rank_node, location)                   (croutine_mutex_lock(TASK_RANK_NODE_CMUTEX(task_rank_node), location))
#define TASK_RANK_NODE_UNLOCK(task_rank_node, location)                 (croutine_mutex_unlock(TASK_RANK_NODE_CMUTEX(task_rank_node), location))
#endif
#if 1
#define TASK_RANK_NODE_LOCK(task_rank_node, location)                   do{}while(0)
#define TASK_RANK_NODE_UNLOCK(task_rank_node, location)                 do{}while(0)
#endif

#define TASK_RANK_NODE_LIGHT(task_rank_node)                            ((task_rank_node)->light)


/*---------------------------------------- interface of task board ----------------------------------------------*/
#define TASK_BRD_SAVED_ARGC(task_brd)                      ((task_brd)->saved_argc)
#define TASK_BRD_SAVED_ARGV(task_brd)                      ((task_brd)->saved_argv)
#define TASK_BRD_OS_ARGV(task_brd)                         ((task_brd)->os_argv)
#define TASK_BRD_OS_ARGV_LAST(task_brd)                    ((task_brd)->os_argv_last)
#define TASK_BRD_OS_ENVIRON(task_brd)                      ((task_brd)->os_environ)
#define TASK_BRD_SAVED_ENVIRON(task_brd)                   ((task_brd)->saved_environ)
#define TASK_BRD_CACHE_ENVIRON(task_brd)                   ((task_brd)->cache_environ)

#define TASK_BRD_NETWORK_LEVEL(task_brd)                   ((task_brd)->network_level)

#define TASK_BRD_CTIME(task_brd)                           ((task_brd)->ctime)
#define TASK_BRD_CTM(task_brd)                             (&((task_brd)->ctm))
#define TASK_BRD_CTMV(task_brd)                            (&((task_brd)->ctmv))
#define TASK_BRD_TIME_STR(task_brd)                        ((task_brd)->time_str)
#define TASK_BRD_CEPOLL(task_brd)                          ((task_brd)->cepoll)
#define TASK_BRD_CSIG(task_brd)                            ((task_brd)->csig)
#define TASK_BRD_TASK_MGR_STACK(task_brd)                  (&((task_brd)->task_mgr_stack))
#define TASK_BRD_TASK_MGR_STACK_INIT(task_brd, location)   (cstack_init(TASK_BRD_TASK_MGR_STACK(task_brd), MM_IGNORE, location))
#define TASK_BRD_STACK_MGR_STACK_PUSH(task_brd, task_mgr)  (cstack_push(TASK_BRD_TASK_MGR_STACK(task_brd), task_mgr))
#define TASK_BRD_STACK_MGR_STACK_POP(task_brd)             (cstack_pop(TASK_BRD_TASK_MGR_STACK(task_brd)))
#define TASK_BRD_STACK_MGR_STACK_TOP(task_brd)             (cstack_top(TASK_BRD_TASK_MGR_STACK(task_brd)))

#define TASK_BRD_TYPE_CONV_VEC(task_brd)                   (&((task_brd)->type_conv_vec))
#define TASK_BRD_FUNC_ADDR_VEC(task_brd)                   (&((task_brd)->func_addr_vec))

#define TASK_BRD_SUPER_MD_ID(task_brd)                     ((task_brd)->super_md_id)

#define TASK_BRD_DO_SLAVE_PID(task_brd)                    ((task_brd)->do_slave_pid)
#define TASK_BRD_ENABLE_SLOW_DOWN(task_brd)                ((task_brd)->enable_slow_down)
#define TASK_BRD_TASKS_IS_RUNNING(task_brd)                ((task_brd)->tasks_is_running)

#define TASK_BRD_DO_SLAVE_CTHREAD_ID(task_brd)             ((task_brd)->do_slave_cthread_id)
#define TASK_BRD_DO_ROUTINE_CTHREAD_ID(task_brd)           ((task_brd)->do_routine_cthread_id)
#define TASK_BRD_DO_CBTIMER_CTHREAD_ID(task_brd)           ((task_brd)->do_cbtimer_cthread_id)
#define TASK_BRD_BCAST_CTHREAD_ID(task_brd)                ((task_brd)->bcast_cthread_id)

#define TASK_BRD_FWD_CCOND(task_brd)                               (&((task_brd)->fwd_croutine_cond))
#define TASK_BRD_FWD_CCOND_INIT(task_brd, location)                 croutine_cond_init(TASK_BRD_FWD_CCOND(task_brd), 0/*never timeout*/, location)
#define TASK_BRD_FWD_CCOND_CLEAN(task_brd, location)                croutine_cond_clean(TASK_BRD_FWD_CCOND(task_brd), location)
#define TASK_BRD_FWD_CCOND_RESERVE(task_brd, counter, location)     croutine_cond_reserve(TASK_BRD_FWD_CCOND(task_brd), counter, location)
#define TASK_BRD_FWD_CCOND_RELEASE(task_brd, location)              croutine_cond_release(TASK_BRD_FWD_CCOND(task_brd), location)
#define TASK_BRD_FWD_CCOND_RELEASE_ALL(task_brd, location)          croutine_cond_release_all(TASK_BRD_FWD_CCOND(task_brd), location)
#define TASK_BRD_FWD_CCOND_WAIT(task_brd, location)                 croutine_cond_wait(TASK_BRD_FWD_CCOND(task_brd), location)

#define TASK_BRD_MD_NODE_TBL(task_brd)             (&((task_brd)->md_node_tbl))

#define TASK_BRD_MD_NODE_GET(task_brd, md_type)    \
        ((FUNC_ADDR_MGR *)cvector_get(TASK_BRD_MD_NODE_TBL(task_brd), md_type))

#define TASK_BRD_MD_NODE_SET(task_brd, md_type, md_node)   \
        (cvector_set(TASK_BRD_MD_NODE_TBL(task_brd), md_type, (void *)(md_node)))

#define TASK_BRD_CLOAD_MGR(this_task_brd)                                           (&((this_task_brd)->cload_mgr))

#define TASK_BRD_BROKEN_TCID_TBL(task_brd)                  (&((task_brd)->broken_tcid_tbl))

#define TASK_BRD_SYS_CFG_FNAME(task_brd)                     ((task_brd)->sys_cfg_xml_fname_cstr)
#define TASK_BRD_SYS_CFG_FNAME_STR(task_brd)                 (cstring_get_str(TASK_BRD_SYS_CFG_FNAME(task_brd)))
#define TASK_BRD_BASIC_CFG_FNAME(task_brd)                   ((task_brd)->basic_cfg_xml_fname_cstr)
#define TASK_BRD_BASIC_CFG_FNAME_STR(task_brd)               (cstring_get_str(TASK_BRD_BASIC_CFG_FNAME(task_brd)))
#define TASK_BRD_LOG_PATH(task_brd)                          ((task_brd)->log_path_cstr)
#define TASK_BRD_LOG_PATH_STR(task_brd)                      (cstring_get_str(TASK_BRD_LOG_PATH(task_brd)))
#define TASK_BRD_SSL_PATH(task_brd)                          ((task_brd)->ssl_path_cstr)
#define TASK_BRD_SSL_PATH_STR(task_brd)                      (cstring_get_str(TASK_BRD_SSL_PATH(task_brd)))
#define TASK_BRD_SCRIPT_FNAME(task_brd)                      ((task_brd)->script_fname_cstr)
#define TASK_BRD_SCRIPT_FNAME_STR(task_brd)                  (cstring_get_str(TASK_BRD_SCRIPT_FNAME(task_brd)))

#define TASK_BRD_NETCARDS(task_brd)                          ((task_brd)->netcard_set)
#define TASK_BRD_IPV4_POOL(task_brd)                         ((task_brd)->ipv4_pool)

#define TASK_BRD_SYS_CFG(task_brd)                           ((task_brd)->sys_cfg)
#define TASK_BRD_REG_TYPE(task_brd)                          ((task_brd)->reg_type)
#define TASK_BRD_CPARACFG(task_brd)                          ((task_brd)->cparacfg)
#define TASK_BRD_LOCAL_TASKS_CFG(task_brd)                   ((task_brd)->local_tasks_cfg)
#define TASK_BRD_DETECT_TASKS_CFG(task_brd)                  ((task_brd)->detect_tasks_cfg)
#define TASK_BRD_UDP_SRV_SOCKFD(task_brd)                    ((task_brd)->udp_srv_sockfd)
#define TASK_BRD_RECV_TASK_MGR_LIST(task_brd)                (&((task_brd)->recv_task_mgr_list))
#define TASK_BRD_AGING_TASK_MGR_LIST(task_brd)               (&((task_brd)->aging_task_mgr_list))
#define TASK_BRD_MOD_MGR_LIST(task_brd)                      (&((task_brd)->mod_mgr_list))
#define TASK_BRD_CONTEXT_LIST(task_brd)                      (&((task_brd)->context_list))
#define TASK_BRD_REPORT_LIST(task_brd)                       (&((task_brd)->task_report_list))
#define TASK_BRD_CBTIMER_LIST(task_brd)                      (&((task_brd)->task_cbtimer_list))
#define TASK_BRD_PROCESS_LIST(task_brd)                      (&((task_brd)->task_process_list))

#define TASK_BRD_RECV_TASK_MGR_LIST_INIT(task_brd, location)           (clist_init(TASK_BRD_RECV_TASK_MGR_LIST(task_brd), MM_IGNORE, location))
#define TASK_BRD_ARGING_TASK_MGR_LIST_INIT(task_brd, location)         (clist_init(TASK_BRD_AGING_TASK_MGR_LIST(task_brd), MM_IGNORE, location))

#define TASK_BRD_SEQNO(task_brd)                             ((task_brd)->task_seqno_spool)

#define TASK_BRD_SEQNO_CMUTEX(task_brd)                      (&((task_brd)->task_seqno_spool_cmutex))
#define TASK_BRD_SEQNO_CMUTEX_INT(task_brd, location)        (cmutex_init(TASK_BRD_SEQNO_CMUTEX(task_brd), CMUTEX_PROCESS_PRIVATE, location))
#define TASK_BRD_SEQNO_CMUTEX_CLEAN(task_brd, location)      (cmutex_clean(TASK_BRD_SEQNO_CMUTEX(task_brd), location))
#if 0
#define TASK_BRD_SEQNO_CMUTEX_LOCK(task_brd, location)       (cmutex_lock(TASK_BRD_SEQNO_CMUTEX(task_brd), location))
#define TASK_BRD_SEQNO_CMUTEX_UNLOCK(task_brd, location)     (cmutex_unlock(TASK_BRD_SEQNO_CMUTEX(task_brd), location))
#endif
#if 1
#define TASK_BRD_SEQNO_CMUTEX_LOCK(task_brd, location)       do{}while(0)
#define TASK_BRD_SEQNO_CMUTEX_UNLOCK(task_brd, location)     do{}while(0)
#endif


#if (SWITCH_ON == CROUTINE_SUPPORT_CTHREAD_SWITCH)
#define TASK_BRD_CROUTINE_POOL(task_brd)                     (NULL_PTR)/*xxx*/
#define TASK_BRD_THREAD_NUM(task_brd)                        (TASK_REQ_THREAD_NUM(task_brd) + TASK_RSP_THREAD_NUM(task_brd))

#define TASK_REQ_CTHREAD_POOL(task_brd)                      ((task_brd)->task_req_thread_spool)
#define TASK_REQ_THREAD_NUM(task_brd)                        (cthreadp_size((task_brd)->task_req_thread_spool))

#define TASK_RSP_CTHREAD_POOL(task_brd)                      ((task_brd)->task_rsp_thread_spool)
#define TASK_RSP_THREAD_NUM(task_brd)                        (cthreadp_size((task_brd)->task_rsp_thread_spool))

/*reuse req thread pool as fwd thread pool*/
#define TASK_FWD_CTHREAD_POOL(task_brd)                      ((task_brd)->task_req_thread_spool)
#define TASK_FWD_THREAD_NUM(task_brd)                        (cthreadp_size((task_brd)->task_req_thread_spool))
#endif/*(SWITCH_ON == CROUTINE_SUPPORT_CTHREAD_SWITCH)*/

#if (SWITCH_ON == CROUTINE_SUPPORT_COROUTINE_SWITCH)

#define TASK_BRD_CROUTINE_POOL(task_brd)                     ((task_brd)->croutine_pool)
#define TASK_BRD_CROUTINE_NUM(task_brd)                      (croutine_pool_size(TASK_BRD_CROUTINE_POOL(task_brd)))

#define TASK_BRD_CTHREAD_POOL(task_brd)                      (TASK_BRD_CROUTINE_POOL(task_brd))
#define TASK_BRD_THREAD_NUM(task_brd)                        (croutine_pool_size(TASK_BRD_CTHREAD_POOL(task_brd)))

#define TASK_REQ_CTHREAD_POOL(task_brd)                      (TASK_BRD_CTHREAD_POOL(task_brd))
#define TASK_REQ_THREAD_NUM(task_brd)                        (croutine_pool_size(TASK_REQ_CTHREAD_POOL(task_brd)))

#define TASK_RSP_CTHREAD_POOL(task_brd)                      (TASK_BRD_CTHREAD_POOL(task_brd))
#define TASK_RSP_THREAD_NUM(task_brd)                        (croutine_pool_size(TASK_RSP_CTHREAD_POOL(task_brd)))

/*reuse req thread pool as fwd thread pool*/
#define TASK_FWD_CTHREAD_POOL(task_brd)                      (TASK_BRD_CTHREAD_POOL(task_brd))
#define TASK_FWD_THREAD_NUM(task_brd)                        (croutine_pool_size(TASK_FWD_CTHREAD_POOL(task_brd)))

#endif/*(SWITCH_ON == CROUTINE_SUPPORT_COROUTINE_SWITCH)*/

#define TASK_BRD_CSRV(task_brd)                              ((task_brd)->csrv)
#define TASK_BRD_CPROC(task_brd)                             ((task_brd)->cproc)

#define TASK_BRD_HTTP_CCONNP_MGR(task_brd)                   ((task_brd)->http_cconnp_mgr)

#define TASK_BRD_CMON_ID(task_brd)                           ((task_brd)->cmon_id)

#define TASK_BRD_TCID(task_brd)                              ((task_brd)->this_tcid)
#define TASK_BRD_TCID_STR(task_brd)                          (c_word_to_ipv4(TASK_BRD_TCID(task_brd)))
#define TASK_BRD_COMM(task_brd)                              ((task_brd)->this_comm)
#define TASK_BRD_SIZE(task_brd)                              ((task_brd)->this_size)
#define TASK_BRD_RANK(task_brd)                              ((task_brd)->this_rank)
#define TASK_BRD_CLOAD_STAT(task_brd)                        (&((task_brd)->cload_stat))
#define TASK_BRD_CPU_AVG_STAT(task_brd)                      (&((task_brd)->cpu_avg_stat))
#define TASK_BRD_IPADDR(task_brd)                            ((task_brd)->this_ipaddr)
#define TASK_BRD_PORT(task_brd)                              ((task_brd)->this_port)
#define TASK_BRD_QUEUE(task_brd, queue_type)                 (&((task_brd)->task_queue[ (queue_type) ]))
#define TASK_BRD_RANK_TBL(task_brd)                          ((task_brd)->rank_tbl)

#define TASK_BRD_EXTRA(task_brd)                             ((task_brd)->extra)
#define TASK_BRD_EXTRA_CLEANUP(task_brd)                     ((task_brd)->extra_cleanup)

#define TASK_BRD_RUNNER_STACK(task_brd)                      (&((task_brd)->runner_stack))

#define TASK_BRD_ENABLE_FLAG(task_brd)                       ((task_brd)->enable_flag)
#define TASK_BRD_RESET_FLAG(task_brd)                        ((task_brd)->reset_flag)
#define TASK_BRD_NGX_EXITING_FLAG(task_brd)                  ((task_brd)->ngx_exiting_flag)

#define TASK_BRD_SET_ABORT(task_brd)                                         \
    do{                                                                      \
        if(NULL_PTR != (task_brd) && NULL_PTR != TASK_BRD_CPROC(task_brd)) { \
            CPROC_ABORT_FLAG(TASK_BRD_CPROC(task_brd)) = CPROC_IS_ABORTED;   \
        }                                                                    \
    }while(0)

#define TASK_BRD_IS_ABORT(task_brd)                                          \
    (NULL_PTR != (task_brd) && NULL_PTR != TASK_BRD_CPROC(task_brd)        \
     && CPROC_IS_ABORTED == (CPROC_ABORT_FLAG(TASK_BRD_CPROC(task_brd))))

#endif /*_TASK_INC*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

