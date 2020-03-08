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
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <math.h>
#include <signal.h>
#include <sched.h>
#include <sys/prctl.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>

#include "zlib.h"

#include "type.h"

#include "mm.h"
#include "log.h"
#include "debug.h"

#include "clist.h"
#include "cvector.h"

#include "cmisc.h"

#include "cbc.h"
#include "rank.h"
#include "task.h"
#include "tasks.h"

#include "cmpic.inc"
#include "cmpie.h"
#include "tcnode.h"
#include "super.h"

#include "cxml.h"
#include "cparacfg.inc"
#include "cparacfg.h"

#include "csig.h"
#include "api_ui.h"

#include "cthread.h"
#include "coroutine.inc"
#include "coroutine.h"

#include "cdevice.h"
#include "csys.h"
#include "ccode.h"
#include "cbase64code.h"
#include "cbtimer.h"

#include "api_cmd.h"
#include "api_cmd_ui.h"

#include "chashdb.h"
#include "cconnp.h"

#include "cload.h"
#include "creg.h"
#include "csrv.h"
#include "cproc.h"
#include "dhcp.h"
#include "cepoll.h"
#include "chttp.h"
#include "chttps.h"
#include "crfsmc.h"
#include "crfsmon.h"
#include "crfshttp.h"
#include "crfschttp.h"
#include "cxfsmon.h"
#include "cxfshttp.h"
#include "chfshttp.h"

#include "cagent.h"
#include "ctdns.h"

#include "findex.inc"

extern char** environ;

#if 1
#define TASK_ASSERT(should_be_condition, loc_str) do{\
    if(!(should_be_condition)) {\
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:assert failed at %s\n", (loc_str));\
    }\
}while(0)
#else
#define TASK_ASSERT(should_be_condition, loc_str) do{}while(0)
#endif

#if 0
#define TASK_ASSERT_EXEC(should_be_condition, loc_str, _buff, _len) do{\
    PRINT_BUFF(loc_str, _buff, _len);\
    if(!(should_be_condition)) {\
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:assert failed at %s\n", (loc_str));\
    }\
}while(0)
#else
#define TASK_ASSERT_EXEC(should_be_condition, loc_str, _buff, _len) TASK_ASSERT(should_be_condition, loc_str)
#endif

#if 0
#define PRINT_BUFF(info, buff, len) do{\
    UINT32 __pos;\
    dbg_log(SEC_0015_TASK, 5)(LOGSTDOUT, "%s: ", info);\
    for(__pos = 0; __pos < len; __pos ++)\
    {\
        sys_print(LOGSTDOUT, "%x,", ((UINT8 *)buff)[ __pos ]);\
    }\
    sys_print(LOGSTDOUT, "\n");\
}while(0)
#else
#define PRINT_BUFF(info, buff, len) do{}while(0)
#endif


#if 0
STATIC_CAST static void task_rsp_discard_dbg_info(const TASK_MGR *task_mgr, const TASK_RSP *task_rsp);
STATIC_CAST static void task_rsp_succ_dbg_info(const TASK_MGR *task_mgr, const TASK_RSP *task_rsp);
STATIC_CAST static void task_rsp_fail_dbg_info(const TASK_MGR *task_mgr, const TASK_RSP *task_rsp);
#endif

/*global variables*/
TASK_BRD *g_task_brd = NULL_PTR;

UINT32 g_task_node_buff_type_tbl[MM_END];
UINT32 g_task_node_buff_type_tbl_flag = EC_FALSE;

#if (SWITCH_OFF == NGX_BGN_SWITCH)
const static FUNC_ADDR_NODE g_task_brd_heartbeat_once_func_addr_node = {
/* -- EC_BOOL task_brd_heartbeat_once(TASK_BRD *task_brd); -- */
/*func module     */     MD_TASK,
/*func logic addr */     (UINT32)task_brd_heartbeat_once,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "task_brd_heartbeat_once",
/*func index      */     ERR_FUNC_ID,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     1,
/*func para direct*/     {E_DIRECT_IN,},
/*func para type  */     {e_dbg_void_ptr,},/*trick*/
/*func para val   */     0, 0, {0},
};
#endif/*(SWITCH_OFF == NGX_BGN_SWITCH)*/

#if (SWITCH_ON == LOAD_UPDATE_SWITCH)
const static FUNC_ADDR_NODE g_task_brd_cload_stat_update_once_func_addr_node = {
/* -- EC_BOOL task_brd_cload_stat_update_once(TASK_BRD *task_brd); -- */
/*func module     */     MD_TASK,
/*func logic addr */     (UINT32)task_brd_cload_stat_update_once,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "task_brd_cload_stat_update_once",
/*func index      */     ERR_FUNC_ID,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     1,
/*func para direct*/     {E_DIRECT_IN,},
/*func para type  */     {e_dbg_void_ptr,},/*trick*/
/*func para val   */     0, 0, {0},
};

const static FUNC_ADDR_NODE g_task_brd_cpu_avg_stat_update_once_func_addr_node = {
/* -- EC_BOOL task_brd_cpu_avg_stat_update_once(TASK_BRD *task_brd); -- */
/*func module     */     MD_TASK,
/*func logic addr */     (UINT32)task_brd_cpu_avg_stat_update_once,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "task_brd_cpu_avg_stat_update_once",
/*func index      */     ERR_FUNC_ID,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     1,
/*func para direct*/     {E_DIRECT_IN,},
/*func para type  */     {e_dbg_void_ptr,},/*trick*/
/*func para val   */     0, 0, {0},
};
#endif/*(SWITCH_ON == LOAD_UPDATE_SWITCH)*/

const static FUNC_ADDR_NODE g_task_brd_mcast_config_func_addr_node = {
/* -- EC_BOOL task_brd_mcast_config(TASK_BRD *task_brd); -- */
/*func module     */     MD_TASK,
/*func logic addr */     (UINT32)task_brd_mcast_config,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "task_brd_mcast_config",
/*func index      */     ERR_FUNC_ID,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     1,
/*func para direct*/     {E_DIRECT_IN,},
/*func para type  */     {e_dbg_void_ptr,},/*trick*/
/*func para val   */     0, 0, {0},
};

const static FUNC_ADDR_NODE g_task_brd_mcast_stop_func_addr_node = {
/* -- EC_BOOL task_brd_mcast_config(TASK_BRD *task_brd); -- */
/*func module     */     MD_TASK,
/*func logic addr */     (UINT32)task_brd_stop_mcast_udp_server,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "task_brd_stop_mcast_udp_server",
/*func index      */     ERR_FUNC_ID,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     1,
/*func para direct*/     {E_DIRECT_IN,},
/*func para type  */     {e_dbg_void_ptr,},/*trick*/
/*func para val   */     0, 0, {0},
};


#if (32 == WORDSIZE && ASM_DISABLE_SWITCH == SWITCH_OFF)
UINT32 task_caller(TASK_FUNC *task_func, FUNC_ADDR_NODE *func_addr_node)
{
    FUNC_PARA *func_para;

    UINT32 esp_offset;

    UINT32 para_idx;

    UINT32 ret;

    /*if one PUSH operation occurs in the loop and out of the asm scope, then corrupt!*/
    /*push the parameters of the function from right to left one by one*/
    /*for example, if function is defined as void add(int a, int b,int *c), then do*/
    /* push c */
    /* push b*/
    /* push a*/
    for ( para_idx =  task_func->func_para_num; para_idx > 0; )
    {
            para_idx --;
            func_para = &(task_func->func_para[ para_idx ]);

            __asm__ __volatile__
            (
                "pushl %0;"
                :
                :"im"(func_para->para_val)
                :"memory"
            );
    }

    /*call the function and restore the stack after its return*/
    /*the return value should be returned by EAX register*/
    esp_offset = (task_func->func_para_num) * (WORDSIZE/BYTESIZE);

    if( e_dbg_void == func_addr_node->func_ret_type )
    {
          __asm__ __volatile__
        (
            "call %1;"
            "addl %2, %%esp;"
            :"=m"(ret)
            :"im"(func_addr_node->func_logic_addr),"im"(esp_offset)
            :"memory"
        );
    }
    else
    {
        __asm__ __volatile__
        (
            "call %1;"
            "movl %%eax, %0;"
            "addl %2, %%esp;"
            :"=m"(ret)
            :"im"(func_addr_node->func_logic_addr),"im"(esp_offset)
            :"memory"
        );
        task_func->func_ret_val = ret;
    }

    return ( 0 );
}
#endif/*(32 == WORDSIZE && ASM_DISABLE_SWITCH == SWITCH_OFF)*/

#if (64 == WORDSIZE || (32 == WORDSIZE && ASM_DISABLE_SWITCH == SWITCH_ON))
UINT32 task_caller(TASK_FUNC *task_func, FUNC_ADDR_NODE *func_addr_node)
{
    UINT32 ret;

#if (16 != MAX_NUM_OF_FUNC_PARAS)
#error "fatal error:task.c: MAX_NUM_OF_FUNC_PARAS != 16"
#endif

    #define LOGIC_ADDR(addr_node)       ((addr_node)->func_logic_addr)
    #define PARA_VALUE(task_func, x)    ((task_func)->func_para[ (x) ].para_val)

    #define PARA_LIST_0(task_func)    /*no parameter*/
    #define PARA_LIST_1(task_func)    PARA_VALUE(task_func, 0)
    #define PARA_LIST_2(task_func)    PARA_LIST_1(task_func) ,PARA_VALUE(task_func, 1)
    #define PARA_LIST_3(task_func)    PARA_LIST_2(task_func) ,PARA_VALUE(task_func, 2)
    #define PARA_LIST_4(task_func)    PARA_LIST_3(task_func) ,PARA_VALUE(task_func, 3)
    #define PARA_LIST_5(task_func)    PARA_LIST_4(task_func) ,PARA_VALUE(task_func, 4)
    #define PARA_LIST_6(task_func)    PARA_LIST_5(task_func) ,PARA_VALUE(task_func, 5)
    #define PARA_LIST_7(task_func)    PARA_LIST_6(task_func) ,PARA_VALUE(task_func, 6)
    #define PARA_LIST_8(task_func)    PARA_LIST_7(task_func) ,PARA_VALUE(task_func, 7)
    #define PARA_LIST_9(task_func)    PARA_LIST_8(task_func) ,PARA_VALUE(task_func, 8)
    #define PARA_LIST_10(task_func)   PARA_LIST_9(task_func) ,PARA_VALUE(task_func, 9)
    #define PARA_LIST_11(task_func)   PARA_LIST_10(task_func),PARA_VALUE(task_func, 10)
    #define PARA_LIST_12(task_func)   PARA_LIST_11(task_func),PARA_VALUE(task_func, 11)
    #define PARA_LIST_13(task_func)   PARA_LIST_12(task_func),PARA_VALUE(task_func, 12)
    #define PARA_LIST_14(task_func)   PARA_LIST_13(task_func),PARA_VALUE(task_func, 13)
    #define PARA_LIST_15(task_func)   PARA_LIST_14(task_func),PARA_VALUE(task_func, 14)
    #define PARA_LIST_16(task_func)   PARA_LIST_15(task_func),PARA_VALUE(task_func, 15)

    #define FUNC_CALL(x, addr_node, task_func) \
            ((FUNC_TYPE_##x) LOGIC_ADDR(addr_node))(PARA_LIST_##x(task_func))

    switch(task_func->func_para_num)
    {
        case 0:
            ret = FUNC_CALL(0, func_addr_node, task_func);
            break;
        case 1:
            ret = FUNC_CALL(1, func_addr_node, task_func);
            break;
        case 2:
            ret = FUNC_CALL(2, func_addr_node, task_func);
            break;
        case 3:
            ret = FUNC_CALL(3, func_addr_node, task_func);
            break;
        case 4:
            ret = FUNC_CALL(4, func_addr_node, task_func);
            break;
        case 5:
            ret = FUNC_CALL(5, func_addr_node, task_func);
            break;
        case 6:
            ret = FUNC_CALL(6, func_addr_node, task_func);
            break;
        case 7:
            ret = FUNC_CALL(7, func_addr_node, task_func);
            break;
        case 8:
            ret = FUNC_CALL(8, func_addr_node, task_func);
            break;
        case 9:
            ret = FUNC_CALL(9, func_addr_node, task_func);
            break;
        case 10:
            ret = FUNC_CALL(10, func_addr_node, task_func);
            break;
        case 11:
            ret = FUNC_CALL(11, func_addr_node, task_func);
            break;
        case 12:
            ret = FUNC_CALL(12, func_addr_node, task_func);
            break;
        case 13:
            ret = FUNC_CALL(13, func_addr_node, task_func);
            break;
        case 14:
            ret = FUNC_CALL(14, func_addr_node, task_func);
            break;
        case 15:
            ret = FUNC_CALL(15, func_addr_node, task_func);
            break;
        case 16:
            ret = FUNC_CALL(16, func_addr_node, task_func);
            break;
        default:
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_caller: func para num = %ld overflow\n", task_func->func_para_num);
            return ((UINT32)(-1));
    }

    #undef LOGIC_ADDR
    #undef PARA_VALUE

    #undef PARA_LIST_0
    #undef PARA_LIST_1
    #undef PARA_LIST_2
    #undef PARA_LIST_3
    #undef PARA_LIST_4
    #undef PARA_LIST_5
    #undef PARA_LIST_6
    #undef PARA_LIST_7
    #undef PARA_LIST_8
    #undef PARA_LIST_9
    #undef PARA_LIST_10
    #undef PARA_LIST_11
    #undef PARA_LIST_12
    #undef PARA_LIST_13
    #undef PARA_LIST_14
    #undef PARA_LIST_15
    #undef PARA_LIST_16

    #undef FUNC_CALL

    if( e_dbg_void != func_addr_node->func_ret_type )
    {
        task_func->func_ret_val = ret;
    }
    return ( 0 );
}
#endif/*(64 == WORDSIZE || (32 == WORDSIZE && ASM_DISABLE_SWITCH == SWITCH_ON))*/

EC_BOOL task_node_buff_type_tbl_init()
{
    UINT32 mm_type;
    for(mm_type = 0; mm_type < MM_END; mm_type ++)
    {
        g_task_node_buff_type_tbl[ mm_type ] = fetch_static_mem_typesize(mm_type);
    }
    g_task_node_buff_type_tbl_flag = EC_TRUE;
    return (EC_TRUE);
}

EC_BOOL task_node_buff_type(const UINT32 buff_size, UINT32 *buff_type)
{
    UINT32 mm_type;

    if(EC_FALSE == g_task_node_buff_type_tbl_flag)
    {
        task_node_buff_type_tbl_init();
    }

    for(mm_type = BUFF_MEM_DEF_BEG; mm_type <= BUFF_MEM_DEF_END; mm_type ++)
    {
        if(buff_size <= g_task_node_buff_type_tbl[ mm_type ])
        {
            *buff_type = mm_type;
            return (EC_TRUE);
        }
    }

    *buff_type = MM_END;
    return (EC_FALSE);
}

EC_BOOL task_node_init(TASK_NODE *task_node)
{
    TASK_NODE_TAG(task_node)            = TAG_TASK_UNDEF;
    TASK_NODE_STATUS(task_node)         = TASK_UNDEF_STATUS;
    TASK_NODE_COMP(task_node)           = TASK_NOT_COMP;

    TASK_NODE_CMUTEX_INIT(task_node, LOC_TASK_0001);

    task_any_init(TASK_NODE_ANY(task_node));/*fix*/

    return (EC_TRUE);
}

EC_BOOL task_node_buff_alloc(TASK_NODE *task_node, const UINT32 buff_size)
{
    UINT32 buff_type;

    if(0 == buff_size)
    {
        TASK_NODE_BUFF(task_node)      = NULL_PTR;
        TASK_NODE_BUFF_TYPE(task_node) = MM_END;
        TASK_NODE_BUFF_LEN(task_node)  = 0;
        TASK_NODE_BUFF_POS(task_node)  = 0;
        return (EC_TRUE);
    }

    if(EC_FALSE == task_node_buff_type(buff_size, &buff_type))
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDERR, "error:task_node_buff_alloc: buff_size %ld is overflow\n", buff_size);
        return (EC_FALSE);
    }

    if(NULL_PTR != TASK_NODE_BUFF(task_node))
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_node_buff_alloc: TASK_NODE_BUFF is not null\n");
        task_node_buff_free(task_node);
        TASK_NODE_BUFF(task_node) = NULL_PTR;
    }

    alloc_static_mem(buff_type, &(TASK_NODE_BUFF(task_node)), LOC_TASK_0002);
    if(NULL_PTR == TASK_NODE_BUFF(task_node))
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDERR, "error:task_node_buff_alloc: failed to alloc memory with type %ld\n", buff_type);
        return (EC_FALSE);
    }

    TASK_NODE_BUFF_TYPE(task_node) = buff_type;
    TASK_NODE_BUFF_LEN(task_node)  = buff_size;
    TASK_NODE_BUFF_POS(task_node)  = 0;

    return (EC_TRUE);
}

EC_BOOL task_node_buff_realloc(TASK_NODE *task_node, const UINT32 new_size)
{
    UINT32 old_size;
    //UINT32 old_type;
    UINT32 new_type;

    UINT32 cur_pos;

    UINT8 *old_buff;
    UINT8 *new_buff;

    old_buff = TASK_NODE_BUFF(task_node);
    old_size = TASK_NODE_BUFF_LEN(task_node);
    //old_type = TASK_NODE_BUFF_TYPE(task_node);
    cur_pos  = TASK_NODE_BUFF_POS(task_node);

    if(old_size >= new_size)
    {
        /*nothing to do*/
        dbg_log(SEC_0015_TASK, 0)(LOGSTDERR, "warn:task_node_buff_realloc: old_size %ld >= new_size %ld, give up shrinking\n",
                            old_size, new_size);
        return (EC_TRUE);
    }

    if(0 == old_size)
    {
        return task_node_buff_alloc(task_node, new_size);
    }

    if(EC_FALSE == task_node_buff_type(new_size, &new_type))
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDERR, "error:task_node_buff_realloc: new_size %ld is overflow\n", new_size);
        return (EC_FALSE);
    }

    alloc_static_mem(new_type, &(new_buff), LOC_TASK_0003);
    if(NULL_PTR == TASK_NODE_BUFF(task_node))
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDERR, "error:task_node_buff_realloc: failed to alloc memory with type %ld\n", new_type);
        return (EC_FALSE);
    }

    if(NULL_PTR != old_buff)
    {
        BCOPY(old_buff, new_buff, cur_pos);/*copy data*/

        dbg_log(SEC_0015_TASK, 9)(LOGSTDOUT, "[DEBUG] task_node_buff_realloc: free old TASK_NODE_BUFF %p\n", old_buff);

        task_node_buff_free(task_node);
        TASK_NODE_BUFF(task_node) = NULL_PTR;
    }

    TASK_NODE_BUFF(task_node)      = new_buff;
    TASK_NODE_BUFF_TYPE(task_node) = new_type;
    TASK_NODE_BUFF_LEN(task_node)  = new_size;
    TASK_NODE_BUFF_POS(task_node)  = cur_pos;

    return (EC_TRUE);
}

EC_BOOL task_node_buff_free(TASK_NODE *task_node)
{
    if(NULL_PTR != TASK_NODE_BUFF(task_node))
    {
        free_static_mem(TASK_NODE_BUFF_TYPE(task_node), TASK_NODE_BUFF(task_node), LOC_TASK_0004);
        TASK_NODE_BUFF(task_node)      = NULL_PTR;
        TASK_NODE_BUFF_TYPE(task_node) = MM_END;
        TASK_NODE_BUFF_LEN(task_node)  = 0;
        TASK_NODE_BUFF_POS(task_node)  = 0;
    }
    else
    {
        TASK_NODE_BUFF(task_node)      = NULL_PTR;
        TASK_NODE_BUFF_TYPE(task_node) = MM_END;
        TASK_NODE_BUFF_POS(task_node)  = 0;
        TASK_NODE_BUFF_LEN(task_node)  = 0;
    }
    return (EC_TRUE);
}


TASK_NODE *task_node_new(const UINT32 buff_size, const UINT32 location)
{
    TASK_NODE *task_node;

    alloc_static_mem(MM_TASK_NODE, &task_node, location);
    if(NULL_PTR == task_node)
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_node_new: alloc task node failed\n");
        return (NULL_PTR);
    }

    TASK_NODE_BUFF(task_node) = NULL_PTR;

    if(EC_FALSE == task_node_buff_alloc(task_node, buff_size))
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_node_new: alloc buff of size %ld failed\n", buff_size);
        free_static_mem(MM_TASK_NODE, task_node, location);
        return (NULL_PTR);
    }

    task_node_init(task_node);
    return (task_node);
}

EC_BOOL task_node_clean(TASK_NODE *task_node)
{
    switch(TASK_NODE_TAG(task_node))/*debug*/
    {
        case TAG_TASK_REQ:
        case TAG_TASK_RSP:
        case TAG_TASK_FWD:
            break;
        default:
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_node_clean: unknown task tag: %ld\n", TASK_NODE_TAG(task_node));
    }

    TASK_NODE_TAG(task_node)           = TAG_TASK_UNDEF;
    TASK_NODE_STATUS(task_node)        = TASK_UNDEF_STATUS;

    TASK_NODE_CMUTEX_CLEAN(task_node, LOC_TASK_0005);
    task_node_buff_free(task_node);
    return (EC_TRUE);
}

EC_BOOL task_node_free(TASK_NODE *task_node)
{
    if(NULL_PTR != task_node)
    {
        task_node_clean(task_node);
        free_static_mem(MM_TASK_NODE, task_node, LOC_TASK_0006);
    }

    return (EC_TRUE);
}

EC_BOOL task_node_expand_to(TASK_NODE *task_node, const UINT32 new_size)
{
    return task_node_buff_realloc(task_node, new_size);
}

void task_node_print(LOG *log, const TASK_NODE *task_node)
{
    TASK_ANY *task_any;

    task_any = (TASK_ANY *)TASK_NODE_ANY(task_node);
    switch(TASK_ANY_TAG(task_any))
    {
    case TAG_TASK_REQ:
    sys_log(log, "tag %ld: (tcid %s,comm %ld,rank %ld,modi %ld) -> (tcid %s,comm %ld,rank %ld,modi %ld),tag %ld,seqno %lx.%lx.%lx,subseqno %lx: func id %lx\n",
                TASK_NODE_TAG(task_node),
                TASK_ANY_SEND_TCID_STR(task_any), TASK_ANY_SEND_COMM(task_any), TASK_ANY_SEND_RANK(task_any), TASK_ANY_SEND_MODI(task_any),
                TASK_ANY_RECV_TCID_STR(task_any), TASK_ANY_RECV_COMM(task_any), TASK_ANY_RECV_RANK(task_any), TASK_ANY_RECV_MODI(task_any),
                TASK_ANY_TAG(task_any),
                TASK_ANY_SEND_TCID(task_any), TASK_ANY_SEND_RANK(task_any), TASK_ANY_SEQNO(task_any), TASK_ANY_SUB_SEQNO(task_any),
                TASK_ANY_FUNC_ID(task_any)
            );
    return;

    case TAG_TASK_RSP:
    sys_log(log, "tag %ld: (tcid %s,comm %ld,rank %ld,modi %ld) -> (tcid %s,comm %ld,rank %ld,modi %ld),tag %ld,seqno %lx.%lx.%lx,subseqno %lx: func id %lx\n",
                TASK_NODE_TAG(task_node),
                TASK_ANY_SEND_TCID_STR(task_any), TASK_ANY_SEND_COMM(task_any), TASK_ANY_SEND_RANK(task_any), TASK_ANY_SEND_MODI(task_any),
                TASK_ANY_RECV_TCID_STR(task_any), TASK_ANY_RECV_COMM(task_any), TASK_ANY_RECV_RANK(task_any), TASK_ANY_RECV_MODI(task_any),
                TASK_ANY_TAG(task_any),
                TASK_ANY_RECV_TCID(task_any), TASK_ANY_RECV_RANK(task_any), TASK_ANY_SEQNO(task_any), TASK_ANY_SUB_SEQNO(task_any),
                TASK_ANY_FUNC_ID(task_any)
            );
    return;

    case TAG_TASK_FWD:
    sys_log(log, "tag %ld: (tcid %s,comm %ld,rank %ld,modi %ld) -> (tcid %s,comm %ld,rank %ld,modi %ld),tag %ld,seqno fwd.%lx.%lx.%lx,subseqno %lx: func id %lx\n",
                TASK_NODE_TAG(task_node),
                TASK_ANY_SEND_TCID_STR(task_any), TASK_ANY_SEND_COMM(task_any), TASK_ANY_SEND_RANK(task_any), TASK_ANY_SEND_MODI(task_any),
                TASK_ANY_RECV_TCID_STR(task_any), TASK_ANY_RECV_COMM(task_any), TASK_ANY_RECV_RANK(task_any), TASK_ANY_RECV_MODI(task_any),
                TASK_ANY_TAG(task_any),
                TASK_ANY_SEND_TCID(task_any), TASK_ANY_SEND_RANK(task_any), TASK_ANY_SEQNO(task_any), TASK_ANY_SUB_SEQNO(task_any),
                TASK_ANY_FUNC_ID(task_any)
            );
    return;
    default:
    sys_log(log, "tag %ld: (tcid %s,comm %ld,rank %ld,modi %ld) -> (tcid %s,comm %ld,rank %ld,modi %ld),tag %ld,seqno undef.%lx.%lx.%lx,subseqno %lx: func id %lx\n",
                TASK_NODE_TAG(task_node),
                TASK_ANY_SEND_TCID_STR(task_any), TASK_ANY_SEND_COMM(task_any), TASK_ANY_SEND_RANK(task_any), TASK_ANY_SEND_MODI(task_any),
                TASK_ANY_RECV_TCID_STR(task_any), TASK_ANY_RECV_COMM(task_any), TASK_ANY_RECV_RANK(task_any), TASK_ANY_RECV_MODI(task_any),
                TASK_ANY_TAG(task_any),
                TASK_ANY_SEND_TCID(task_any), TASK_ANY_SEND_RANK(task_any), TASK_ANY_SEQNO(task_any), TASK_ANY_SUB_SEQNO(task_any),
                TASK_ANY_FUNC_ID(task_any)
            );
    }
    return;
}

void task_node_dbg(LOG *log, const char *info, const TASK_NODE *task_node)
{
    sys_log(log, "%s: tag %ld: (tcid %s,comm %ld,rank %ld,modi %ld) -> (tcid %s,comm %ld,rank %ld,modi %ld),tag %ld,seqno %lx.%lx.%lx,subseqno %lx: func id %lx, buff len %ld, buff pos %ld\n",
                info, TASK_NODE_TAG(task_node),
                TASK_NODE_SEND_TCID_STR(task_node), TASK_NODE_SEND_COMM(task_node), TASK_NODE_SEND_RANK(task_node), TASK_NODE_SEND_MODI(task_node),
                TASK_NODE_RECV_TCID_STR(task_node), TASK_NODE_RECV_COMM(task_node), TASK_NODE_RECV_RANK(task_node), TASK_NODE_RECV_MODI(task_node),
                TASK_NODE_TAG(task_node),
                TASK_NODE_SEND_TCID(task_node), TASK_NODE_SEND_RANK(task_node), TASK_NODE_SEQNO(task_node), TASK_NODE_SUB_SEQNO(task_node),
                TASK_NODE_FUNC_ID(task_node),
                TASK_NODE_BUFF_LEN(task_node),TASK_NODE_BUFF_POS(task_node)
            );
    return;
}

EC_BOOL task_node_isend(TASK_BRD *task_brd, TASK_NODE *task_node)
{
    TASK_NODE_BUFF_POS(task_node) = 0;/*patch. applied by fwd isend*/

    if(CMPI_FWD_RANK == TASK_BRD_RANK(task_brd))
    {
        /*forwarding process TODO:*/
        if(TASK_BRD_TCID(task_brd) ==  TASK_NODE_RECV_TCID(task_node))
        {
            return cproc_isend(TASK_BRD_CPROC(task_brd), TASK_NODE_RECV_RANK(task_node), TASK_ANY_TAG(TASK_NODE_ANY(task_node)), task_node);
        }
        else
        {
            return tasks_worker_isend_node(TASKS_CFG_WORKER(TASK_BRD_LOCAL_TASKS_CFG(task_brd)), TASK_NODE_RECV_TCID(task_node), TAG_TASK_FWD, task_node);
        }
    }
    else
    {
        /*sending in local taskComm*/
        if(TASK_BRD_TCID(task_brd) == TASK_NODE_RECV_TCID(task_node))
        {
            return cproc_isend(TASK_BRD_CPROC(task_brd), TASK_NODE_RECV_RANK(task_node), TASK_ANY_TAG(TASK_NODE_ANY(task_node)), task_node);
        }
        /*sending to remote taskComm, need forwarding at first*/
        else
        {
            return cproc_isend(TASK_BRD_CPROC(task_brd), CMPI_FWD_RANK, TAG_TASK_FWD, task_node);
        }
    }
    return (EC_FALSE);
}

TASK_RUNNER_NODE *task_runner_node_new()
{
    TASK_RUNNER_NODE *task_runner_node;

    alloc_static_mem(MM_TASK_RUNNER_NODE, &task_runner_node, LOC_TASK_0007);
    if(NULL_PTR == task_runner_node)
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT,"error:task_runner_node_new: new task_runner_node failed\n");
        return (NULL_PTR);
    }

    task_runner_node_init(task_runner_node);
    return (task_runner_node);
}

EC_BOOL task_runner_node_init(TASK_RUNNER_NODE *task_runner_node)
{
    if(NULL_PTR != task_runner_node)
    {
        TASK_RUNNER_NODE_NAME(task_runner_node) = NULL_PTR;
        TASK_RUNNER_NODE_EXEC(task_runner_node) = NULL_PTR;
        TASK_RUNNER_NODE_ARG(task_runner_node)  = NULL_PTR;
    }
    return (EC_TRUE);
}

EC_BOOL task_runner_node_clean(TASK_RUNNER_NODE *task_runner_node)
{
    if(NULL_PTR != task_runner_node)
    {
        TASK_RUNNER_NODE_NAME(task_runner_node) = NULL_PTR;
        TASK_RUNNER_NODE_EXEC(task_runner_node) = NULL_PTR;
        TASK_RUNNER_NODE_ARG(task_runner_node)  = NULL_PTR;
    }
    return (EC_TRUE);
}

EC_BOOL task_runner_node_free(TASK_RUNNER_NODE *task_runner_node)
{
    if(NULL_PTR != task_runner_node)
    {
        task_runner_node_clean(task_runner_node);
        free_static_mem(MM_TASK_RUNNER_NODE, task_runner_node, LOC_TASK_0008);
    }

    return (EC_TRUE);
}

EC_BOOL task_header_init(TASK_HEADER *task_header)
{
    mod_node_init(TASK_HEADER_SEND_MOD(task_header));
    mod_node_init(TASK_HEADER_RECV_MOD(task_header));

    return (EC_TRUE);
}

EC_BOOL task_header_clone(const TASK_HEADER *src_task_header, TASK_HEADER *des_task_header)
{
    mod_node_clone(TASK_HEADER_SEND_MOD(src_task_header), TASK_HEADER_SEND_MOD(des_task_header));
    mod_node_clone(TASK_HEADER_RECV_MOD(src_task_header), TASK_HEADER_RECV_MOD(des_task_header));

    return (EC_TRUE);
}

EC_BOOL task_func_init(TASK_FUNC *task_func)
{
    UINT32 para_idx;
    FUNC_PARA *func_para;

    task_func->func_id       = ERR_FUNC_ID;
    task_func->func_para_num = ERR_PARA_NUM;
    task_func->func_para_num = 0; /*Jun 5, 2017*/

    for( para_idx = 0; para_idx < MAX_NUM_OF_FUNC_PARAS; para_idx ++ )
    {
        func_para = &(task_func->func_para[ para_idx ]);
        func_para->para_dir = E_DIRECT_END;
        func_para->para_val = 0;
    }

    return (EC_TRUE);
}

EC_BOOL task_func_clone(TASK_FUNC *src_task_func, TASK_FUNC *des_task_func)
{
    UINT32 para_idx;
    FUNC_PARA *src_func_para;
    FUNC_PARA *des_func_para;

    des_task_func->func_id = src_task_func->func_id;
    des_task_func->func_para_num = src_task_func->func_para_num;

    for( para_idx = 0; para_idx < MAX_NUM_OF_FUNC_PARAS; para_idx ++ )
    {
        src_func_para = &(src_task_func->func_para[ para_idx ]);
        des_func_para = &(des_task_func->func_para[ para_idx ]);

        des_func_para->para_dir = src_func_para->para_dir;
    }

    return (EC_TRUE);
}

EC_BOOL task_func_print(LOG *log, const TASK_FUNC *task_func)
{
    UINT32 para_idx;
    FUNC_PARA *func_para;

    sys_log(log, "func_id %lx, func_para_num %ld\n", task_func->func_id, task_func->func_para_num);

    for( para_idx = 0; para_idx < task_func->func_para_num; para_idx ++ )
    {
        func_para = (FUNC_PARA *)&(task_func->func_para[ para_idx ]);
        sys_log(log, "para idx = %ld, direction %ld, val %lx\n", para_idx, func_para->para_dir, func_para->para_val);
    }
    return (EC_TRUE);
}

EC_BOOL task_default_bool_checker(const EC_BOOL ec_bool)
{
    return (ec_bool);
}

EC_BOOL task_default_not_null_pointer_checker(const void *pointer)
{
    if(NULL_PTR != pointer)
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

CTIMET task_brd_default_get_time()
{
    TASK_BRD *task_brd;

    task_brd = task_brd_default_get();
    if(NULL_PTR == task_brd)
    {
        return c_time(NULL_PTR);
    }
    return TASK_BRD_CTIME(task_brd);
}

CTM *task_brd_default_get_localtime()
{
    TASK_BRD *task_brd;

    task_brd = task_brd_default_get();
    if(NULL_PTR == task_brd)
    {
        return (NULL_PTR);
    }
    return TASK_BRD_CTM(task_brd);
}

CTMV *task_brd_default_get_daytime()
{
    TASK_BRD *task_brd;

    task_brd = task_brd_default_get();
    if(NULL_PTR == task_brd)
    {
        return (NULL_PTR);
    }
    return TASK_BRD_CTMV(task_brd);
}

char *task_brd_default_get_time_str()
{
    TASK_BRD *task_brd;

    task_brd = task_brd_default_get();
    if(NULL_PTR == task_brd)
    {
        return (NULL_PTR);
    }
    return TASK_BRD_TIME_STR(task_brd);
}

CEPOLL *task_brd_default_get_cepoll()
{
    TASK_BRD *task_brd;

    task_brd = task_brd_default_get();
    if(NULL_PTR == task_brd)
    {
        return (NULL_PTR);
    }
    return TASK_BRD_CEPOLL(task_brd);
}

EC_BOOL task_brd_default_has_detect()
{
    TASK_BRD *task_brd;

    task_brd = task_brd_default_get();
    if(NULL_PTR == task_brd)
    {
        return (EC_FALSE);
    }

    if(NULL_PTR == TASK_BRD_DETECT_TASKS_CFG(task_brd))
    {
        return (EC_FALSE);
    }
    return (EC_TRUE);
}
TASKS_CFG *task_brd_default_get_detect()
{
    TASK_BRD *task_brd;

    task_brd = task_brd_default_get();
    if(NULL_PTR == task_brd)
    {
        return (NULL_PTR);
    }
    return TASK_BRD_DETECT_TASKS_CFG(task_brd);
}

EC_BOOL task_brd_default_set_ngx_exiting()
{
    TASK_BRD *task_brd;

    task_brd = task_brd_default_get();

    TASK_BRD_NGX_EXITING_FLAG(task_brd) = EC_TRUE;

    return (EC_TRUE);
}

EC_BOOL task_brd_default_is_ngx_exiting()
{
    TASK_BRD *task_brd;

    task_brd = task_brd_default_get();

    return TASK_BRD_NGX_EXITING_FLAG(task_brd);
}

CCONNP_MGR *task_brd_default_get_http_cconnp_mgr()
{
    TASK_BRD *task_brd;

    task_brd = task_brd_default_get();
    if(NULL_PTR == task_brd)
    {
        return (NULL_PTR);
    }
    return TASK_BRD_HTTP_CCONNP_MGR(task_brd);
}

CTIMET task_brd_get_time(TASK_BRD *task_brd)
{
    if(NULL_PTR == task_brd)
    {
        return c_time(NULL_PTR);
    }
    return TASK_BRD_CTIME(task_brd);
}

CTM *task_brd_get_localtime(TASK_BRD *task_brd)
{
    if(NULL_PTR == task_brd)
    {
        return (NULL_PTR);
    }
    return TASK_BRD_CTM(task_brd);
}

CTMV *task_brd_get_daytime(TASK_BRD *task_brd)
{
    if(NULL_PTR == task_brd)
    {
        return (NULL_PTR);
    }
    return TASK_BRD_CTMV(task_brd);
}

char *task_brd_get_time_str(TASK_BRD *task_brd)
{
    if(NULL_PTR == task_brd)
    {
        return (NULL_PTR);
    }
    return TASK_BRD_TIME_STR(task_brd);
}

void task_brd_update_time(TASK_BRD *task_brd)
{
    TASK_BRD_CTIME(task_brd) = c_time(NULL_PTR);
    localtime_r(&(TASK_BRD_CTIME(task_brd)), TASK_BRD_CTM(task_brd));
    gettimeofday(TASK_BRD_CTMV(task_brd), NULL_PTR);

    snprintf(TASK_BRD_TIME_STR(task_brd), TASK_BRD_TIME_STR_SIZE, "%4d-%02d-%02d %02d:%02d:%02d.%03d",
            TIME_IN_YMDHMS(TASK_BRD_CTM(task_brd)),
            (int)(TASK_BRD_CTMV(task_brd)->tv_usec / 1000));
    return;
}

void task_brd_update_time_default()
{
    task_brd_update_time(task_brd_default_get());
    return;
}
CEPOLL *task_brd_get_cepoll(TASK_BRD *task_brd)
{
    if(NULL_PTR == task_brd)
    {
        return (NULL_PTR);
    }
    return TASK_BRD_CEPOLL(task_brd);
}

CRFSMC *task_brd_get_crfsmc(TASK_BRD *task_brd)
{
    if(NULL_PTR == task_brd)
    {
        return (NULL_PTR);
    }
    return TASK_BRD_EXTRA(task_brd);
}

#define RATE(used, max) ((1.0 * (used))/(1.0 * (max)))
#define LEFT(used, max) ((max) - (used))

TASK_REQ *task_req_new(const UINT32 buff_size, const UINT32 task_seqno, const UINT32 sub_seqno,const UINT32 task_type, const TASK_MGR *task_mgr, const UINT32 location)
{
    TASK_NODE *task_node;

    task_node = task_node_new(buff_size, location);
    if(NULL_PTR == task_node)
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_req_new: new task node failed\n");
        return (NULL_PTR);
    }

    task_req_init(TASK_NODE_REQ(task_node), task_seqno, sub_seqno, task_type, task_mgr);
    return TASK_NODE_REQ(task_node);
}

EC_BOOL task_req_init(TASK_REQ *task_req, const UINT32 task_seqno, const UINT32 sub_seqno,const UINT32 task_type, const TASK_MGR *task_mgr)
{
    task_header_init(TASK_REQ_HEADER(task_req));

    cload_stat_init(TASK_REQ_CLOAD_STAT(task_req));
    TASK_REQ_MGR(task_req)  = (TASK_MGR *)task_mgr;

    if(NULL_PTR != TASK_MGR_MOD(task_mgr))
    {
        TASK_REQ_LDB_CHOICE(task_req) = MOD_MGR_LDB_CHOICE(TASK_MGR_MOD(task_mgr));
    }
    else
    {
        TASK_REQ_LDB_CHOICE(task_req) = LOAD_BALANCING_END;
    }

    TASK_REQ_CTHREAD_NODE(task_req)  = NULL_PTR;

    TASK_REQ_RECV_MOD_NEW(task_req)  = NULL_PTR;
    TASK_REQ_RECV_MOD_FLAG(task_req) = EC_FALSE;/*default is not need to update TASK_REQ_MOD*/
    TASK_REQ_MOD_ID_FLAG(task_req)   = EC_FALSE; /*default is not need to update mod id at first para*/

    TASK_REQ_NEED_RSP_FLAG(task_req) = TASK_MGR_NEED_RSP_FLAG(task_mgr);
    TASK_REQ_PRIO(task_req)          = TASK_MGR_PRIO(task_mgr);/*follow priority of task_mgr*/
    TASK_REQ_TYPE(task_req)          = task_type;

    TASK_REQ_TAG(task_req)       = TAG_TASK_UNDEF;
    TASK_REQ_SEQNO(task_req)     = task_seqno;
    TASK_REQ_SUB_SEQNO(task_req) = sub_seqno;

    TASK_REQ_FUNC_ADDR_NODE(task_req) = NULL_PTR;
    task_func_init(TASK_REQ_FUNC(task_req));

    return (EC_TRUE);
}

EC_BOOL task_req_clean(TASK_REQ *task_req)
{
    TASK_FUNC *task_req_func;

    FUNC_ADDR_NODE *func_addr_node;
    TYPE_CONV_ITEM *type_conv_item;

    UINT32 para_idx;

    task_req_func  = TASK_REQ_FUNC(task_req);
    func_addr_node = TASK_REQ_FUNC_ADDR_NODE(task_req);

    if(NULL_PTR == task_req_func)
    {
        dbg_log(SEC_0015_TASK, 9)(LOGSTDOUT, "warn:task_req_clean: task_req %p, task_req_func is null\n", task_req);
        return (EC_TRUE);
    }

    if(NULL_PTR == func_addr_node)
    {
        dbg_log(SEC_0015_TASK, 9)(LOGSTDOUT, "warn:task_req_clean: task_req %p, func_addr_node is null\n", task_req);
        return (EC_TRUE);
    }

    if(e_dbg_void != func_addr_node->func_ret_type)
    {
        type_conv_item = dbg_query_type_conv_item_by_type(func_addr_node->func_ret_type);
        if( NULL_PTR == type_conv_item )
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT,"error:task_req_clean: ret type %ld conv item is not defined\n",
                            func_addr_node->func_ret_type);
            return (EC_FALSE);
        }

        if(EC_TRUE == TYPE_CONV_ITEM_VAR_POINTER_FLAG(type_conv_item) && 0 != task_req_func->func_ret_val)
        {
            dbg_tiny_caller(1, TYPE_CONV_ITEM_VAR_FREE_FUNC(type_conv_item), task_req_func->func_ret_val);
            task_req_func->func_ret_val = 0;
        }
    }

    for( para_idx = 0; para_idx < TASK_REQ_FUNC_PARA_NUM(task_req) && para_idx < MAX_NUM_OF_FUNC_PARAS; para_idx ++ )
    {
        FUNC_PARA *func_para;

        func_para = &(task_req_func->func_para[ para_idx ]);

        type_conv_item = dbg_query_type_conv_item_by_type(func_addr_node->func_para_type[ para_idx ]);
        if( NULL_PTR == type_conv_item )
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT,"error:task_req_clean: para %ld type %ld conv item is not defined\n",
                            para_idx, func_addr_node->func_para_type[ para_idx ]);
            return (EC_FALSE);
        }
        if(EC_TRUE == TYPE_CONV_ITEM_VAR_POINTER_FLAG(type_conv_item) && 0 != func_para->para_val)
        {
            dbg_tiny_caller(1, TYPE_CONV_ITEM_VAR_FREE_FUNC(type_conv_item), func_para->para_val);
            func_para->para_val = 0;
        }
    }
    return (EC_TRUE);
}

EC_BOOL task_req_free(TASK_REQ *task_req)
{
    if(NULL_PTR != task_req)
    {
        TASK_NODE *task_req_node;

        task_req_clean(task_req);

        task_req_node = TASK_REQ_NODE(task_req);
        task_node_free(task_req_node);
    }
    return (EC_TRUE);
}

EC_BOOL task_req_print(LOG *log, const TASK_REQ *task_req)
{
    UINT32 para_idx;
    UINT32 para_num;

    sys_log(log, "\n");
    sys_log(log, "task_req %lx:\n", task_req);
    sys_log(log, "send mod: ");
    mod_node_print(log, TASK_REQ_SEND_MOD(task_req));
    sys_log(log, "recv mod: ");
    mod_node_print(log, TASK_REQ_RECV_MOD(task_req));

    sys_log(log, "priority: %ld, type: %ld, seqno: %lx.%lx.%lx, subseqno: %lx, func_id: %lx, para_num: %ld, first para val: %ld\n",
                    TASK_REQ_PRIO(task_req), TASK_REQ_TYPE(task_req),
                    TASK_REQ_SEND_TCID(task_req),TASK_REQ_SEND_RANK(task_req),TASK_REQ_SEQNO(task_req), TASK_REQ_SUB_SEQNO(task_req),
                    TASK_REQ_FUNC_ID(task_req), TASK_REQ_FUNC_PARA_NUM(task_req),
                    TASK_REQ_FUNC_PARA_VAL(task_req, 0));

    if(EMB_NUM_OF_FUNC_PARAS == TASK_REQ_FUNC_PARA_NUM(task_req))
    {
        para_num =  3;
    }
    else
    {
        para_num = TASK_REQ_FUNC_PARA_NUM(task_req);
    }

    for(para_idx = 0; para_idx < para_num; para_idx ++)
    {
        sys_log(log, "para_idx = %ld, para_dir = %ld, para_val = %lx\n", para_idx,
                        TASK_REQ_FUNC_PARA_DIR(task_req, para_idx),
                        TASK_REQ_FUNC_PARA_VAL(task_req, para_idx));
    }

    sys_log(log, "RECV_MOD update flag: %s\n", EC_TRUE == TASK_REQ_RECV_MOD_FLAG(task_req) ? "EC_TRUE" : "EC_FALSE");
    sys_log(log, "MOD_ID   update flag: %s\n", EC_TRUE == TASK_REQ_MOD_ID_FLAG(task_req) ? "EC_TRUE" : "EC_FALSE");
    sys_log(log, "\n");

    return (EC_TRUE);
}

/**
do load balancing on task req before its sending
    1. select the lightest remote mod node as the recv_mod_node
    2. replace the mod_id parameter if necessary (remember: till now, one task_req is one function invocation)
**/
EC_BOOL task_req_ldb(TASK_REQ *task_req)
{
    TASK_MGR *task_mgr;
    MOD_MGR  *mod_mgr;
    MOD_NODE *recv_mod_node;

    TASK_FUNC *task_req_func;
    FUNC_PARA *func_para;

    if(EC_TRUE == TASK_REQ_RECV_MOD_FLAG(task_req))
    {
        task_mgr = TASK_REQ_MGR(task_req);
        mod_mgr = TASK_MGR_MOD(task_mgr);
        recv_mod_node = MOD_MGR_LDB_BEST_MOD_NODE(mod_mgr);/*apply load balancing strategy*/
        if(NULL_PTR == recv_mod_node)
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT,"error:task_req_ldb: cannot find out anyone recv_mod_node. pls make sure mod_mgr is not empty!\n");
            /*exit(0);*/
            return (EC_FALSE);
        }

        mod_node_clone(recv_mod_node, TASK_REQ_RECV_MOD(task_req));
        /*TASK_REQ_RECV_MOD_FLAG(task_req) = EC_FALSE;*//*due to possible re-schedule, here does not change flag*/
        task_brd_rank_load_inc_que(task_brd_default_get(), MOD_NODE_TCID(recv_mod_node), MOD_NODE_RANK(recv_mod_node));

        if(NULL_PTR != TASK_REQ_RECV_MOD_NEW(task_req))
        {
            mod_node_clone(recv_mod_node, TASK_REQ_RECV_MOD_NEW(task_req));
        }
    }

    if(EC_TRUE == TASK_REQ_MOD_ID_FLAG(task_req))
    {
        task_req_func = TASK_REQ_FUNC(task_req);
        func_para = &(task_req_func->func_para[ 0 ]); /*note: the first parameter must be mod_id position*/
        func_para->para_val = MOD_NODE_MODI(TASK_REQ_RECV_MOD(task_req));
    }

#if 0
    dbg_log(SEC_0015_TASK, 5)(LOGSTDOUT, "========================================= task_req_ldb =========================================\n");
    task_req_print(LOGSTDOUT, task_req);
#endif
    return (EC_TRUE);
}

void func_addr_node_print(LOG *log, const FUNC_ADDR_NODE *func_addr_node)
{
    UINT32 para_idx;
    UINT32 para_num;

    sys_log(log, "------------------------------func_addr_node = %lx --------------------------------\n", func_addr_node);
    sys_log(log, "func func_module: %ld\n",     func_addr_node->func_module);
    sys_log(log, "func logic addr : %lx\n",     func_addr_node->func_logic_addr);
    sys_log(log, "func beg addr   : %lx\n",     func_addr_node->func_beg_addr);
    sys_log(log, "func end addr   : %lx\n",     func_addr_node->func_end_addr);
    sys_log(log, "func addr offset: %lx\n",     func_addr_node->func_addr_offset);
    sys_log(log, "func name       : %s\n",      (char *)(func_addr_node->func_name));
    sys_log(log, "func index      : %lx\n",     func_addr_node->func_index);
    sys_log(log, "func ret type   : %ld\n",     func_addr_node->func_ret_type);
    sys_log(log, "func retval addr: %lx\n",     func_addr_node->func_retval_addr);
    sys_log(log, "func ret val    : %ld\n",     func_addr_node->func_ret_value);
    sys_log(log, "func para num   : %ld\n",     func_addr_node->func_para_num);

    if(EMB_NUM_OF_FUNC_PARAS == func_addr_node->func_para_num)
    {
        para_num = 3;
    }
    else
    {
        para_num = func_addr_node->func_para_num;
    }

    for ( para_idx = 0; para_idx < para_num; para_idx ++  )
    {
        sys_log(log,"para #%ld: para_dir = %ld, para_type = %ld, para_val = %lx\n",
                      para_idx,
                      func_addr_node->func_para_direction[ para_idx ],
                      func_addr_node->func_para_type[ para_idx ],
                      func_addr_node->func_para_value[ para_idx ]);
    }
    return;
}

EC_BOOL task_req_func_para_encode_size(const UINT32 comm, const UINT32 func_para_num, FUNC_PARA *func_para_tbl, const FUNC_ADDR_NODE *func_addr_node, UINT32 *size)
{
    FUNC_PARA *func_para;
    UINT32 para_idx;

    TYPE_CONV_ITEM *type_conv_item;

    if(EMB_NUM_OF_FUNC_PARAS == func_para_num)
    {
        FUNC_ADDR_NODE *ui_func_addr_node;
        UINT32          ui_func_id;
        /*format e.g. tbd_run(tbd_md_id, ui_func_retval_addr, ui_func_id, para_1,....)*/

        /*the 1st para must be container module id*/
        func_para = (func_para_tbl + 0);
        cmpi_encode_uint32_size(comm, (func_para->para_val), size);
        type_conv_item = dbg_query_type_conv_item_by_type(func_addr_node->func_para_type[ 0 ]);
        if( NULL_PTR == type_conv_item )
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT,"error:task_req_func_para_init: para 0 type %ld conv item is not defined\n",
                    func_addr_node->func_para_type[ 0 ]);
            return (EC_FALSE);
        }
        dbg_tiny_caller(3,
            TYPE_CONV_ITEM_VAR_ENCODE_SIZE(type_conv_item),
            comm,
            func_para->para_val,
            size);

        /*the 2nd para must be user interface/function retval addr*/
        func_para = (func_para_tbl + 1);
        /*retval is always E_DIRECT_OUT, so ignore during task_req encoding*/

        /*the 3rd para must be user interface/function id*/
        func_para = (func_para_tbl + 2);
        ui_func_id = func_para->para_val;
        cmpi_encode_uint32_size(comm, (func_para->para_val), size);
        type_conv_item = dbg_query_type_conv_item_by_type(func_addr_node->func_para_type[ 2 ]);
        if( NULL_PTR == type_conv_item )
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT,"error:task_req_func_para_init: para 2 type %ld conv item is not defined\n",
                    func_addr_node->func_para_type[ 2 ]);
            return (EC_FALSE);
        }
        dbg_tiny_caller(3,
            TYPE_CONV_ITEM_VAR_ENCODE_SIZE(type_conv_item),
            comm,
            func_para->para_val,
            size);

        if(0 != dbg_fetch_func_addr_node_by_index(ui_func_id, &ui_func_addr_node))
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_req_func_para_init: failed to fetch user func addr node by func id %lx\n", ui_func_id);
            return (EC_FALSE);
        }
        /*recursively*/
        return task_req_func_para_encode_size(comm, ui_func_addr_node->func_para_num, func_para_tbl + 3, ui_func_addr_node, size);
    }

    for(para_idx = 0; para_idx < func_para_num; para_idx ++ )
    {
        func_para = (func_para_tbl + para_idx);

        func_para->para_dir = func_addr_node->func_para_direction[ para_idx ];
        cmpi_encode_uint32_size(comm, (func_para->para_dir), size);

        if(E_DIRECT_IN == func_para->para_dir || E_DIRECT_IO == func_para->para_dir)
        {
            type_conv_item = dbg_query_type_conv_item_by_type(func_addr_node->func_para_type[ para_idx ]);
            if( NULL_PTR == type_conv_item )
            {
                dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT,"error:task_req_func_para_init: para %ld type %ld conv item is not defined\n",
                        para_idx, func_addr_node->func_para_type[ para_idx ]);
                return (EC_FALSE);
            }
            dbg_tiny_caller(3,
                TYPE_CONV_ITEM_VAR_ENCODE_SIZE(type_conv_item),
                comm,
                func_para->para_val,
                size);
        }
        else
        {
            /*nothing to do*/
        }
    }
    return (EC_TRUE);
}

EC_BOOL task_req_func_para_encode(const UINT32 comm, const UINT32 func_para_num, FUNC_PARA *func_para_tbl, const FUNC_ADDR_NODE *func_addr_node, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
    FUNC_PARA *func_para;
    UINT32 para_idx;

    TYPE_CONV_ITEM *type_conv_item;

    if(EMB_NUM_OF_FUNC_PARAS == func_para_num)
    {
        FUNC_ADDR_NODE *ui_func_addr_node;
        UINT32          ui_func_id;

        /*format e.g. tbd_run(tbd_md_id, ui_func_retval_addr, ui_func_id, para_1,....)*/
        /*then encode order: tbd_md_id => ui_func_id => [ui_func_retval_addr =>] para_1 => ...*/

        func_para = (func_para_tbl + 2);
        ui_func_id = func_para->para_val;
        if(0 != dbg_fetch_func_addr_node_by_index(ui_func_id, &ui_func_addr_node))
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_req_func_para_init: failed to fetch user func addr node by func id %lx\n", ui_func_id);
            return (EC_FALSE);
        }

        /*the 1st para must be container module id*/
        func_para = (func_para_tbl + 0);
        func_para->para_dir = func_addr_node->func_para_direction[ 0 ];
        cmpi_encode_uint32(comm, (func_para->para_dir), out_buff, out_buff_max_len, position);
        type_conv_item = dbg_query_type_conv_item_by_type(func_addr_node->func_para_type[ 0 ]);
        if( NULL_PTR == type_conv_item )
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT,"error:task_req_func_para_init: para 0 type %ld conv item is not defined\n",
                    func_addr_node->func_para_type[ 0 ]);
            return (EC_FALSE);
        }
        dbg_tiny_caller(5,
            TYPE_CONV_ITEM_VAR_ENCODE_FUNC(type_conv_item),
            comm,
            func_para->para_val,
            out_buff,
            out_buff_max_len,
            position);

        /*the 2nd para must be user interface/function retval addr*/
        func_para = (func_para_tbl + 1);
        func_para->para_dir = func_addr_node->func_para_direction[ 1 ];
        /*retval is always E_DIRECT_OUT, so ignore during task_req encoding*/

        /*the 3rd para must be user interface/function id*/
        func_para = (func_para_tbl + 2);
        func_para->para_dir = func_addr_node->func_para_direction[ 2 ];
        ui_func_id = func_para->para_val;

        cmpi_encode_uint32(comm, (func_para->para_dir), out_buff, out_buff_max_len, position);
        type_conv_item = dbg_query_type_conv_item_by_type(func_addr_node->func_para_type[ 2 ]);
        if( NULL_PTR == type_conv_item )
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT,"error:task_req_func_para_init: para 2 type %ld conv item is not defined\n",
                    func_addr_node->func_para_type[ 2 ]);
            return (EC_FALSE);
        }
        dbg_tiny_caller(5,
            TYPE_CONV_ITEM_VAR_ENCODE_FUNC(type_conv_item),
            comm,
            func_para->para_val,
            out_buff,
            out_buff_max_len,
            position);


        /*recursively*/
        return task_req_func_para_encode(comm, ui_func_addr_node->func_para_num, func_para_tbl + 3, ui_func_addr_node, out_buff, out_buff_max_len, position);
    }


    for( para_idx = 0; para_idx < func_para_num; para_idx ++ )
    {
        func_para = (func_para_tbl + para_idx);
        func_para->para_dir = func_addr_node->func_para_direction[ para_idx ];

        cmpi_encode_uint32(comm, (func_para->para_dir), out_buff, out_buff_max_len, position);
        if(E_DIRECT_OUT == func_para->para_dir)
        {
            continue;
        }

        if(E_DIRECT_IN == func_para->para_dir || E_DIRECT_IO == func_para->para_dir)
        {
            type_conv_item = dbg_query_type_conv_item_by_type(func_addr_node->func_para_type[ para_idx ]);
            if( NULL_PTR == type_conv_item )
            {
                dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT,"error:task_req_func_para_init: para %ld type %ld conv item is not defined\n",
                        para_idx, func_addr_node->func_para_type[ para_idx ]);
                return (EC_FALSE);
            }
            dbg_tiny_caller(5,
                TYPE_CONV_ITEM_VAR_ENCODE_FUNC(type_conv_item),
                comm,
                func_para->para_val,
                out_buff,
                out_buff_max_len,
                position);
        }
    }
    return (EC_TRUE);
}

EC_BOOL task_req_func_para_decode(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, UINT32 *func_para_num, FUNC_PARA *func_para_tbl, const FUNC_ADDR_NODE *func_addr_node)
{
    FUNC_PARA *func_para;
    UINT32 para_idx;

    TYPE_CONV_ITEM *type_conv_item;

    void *ap;

    if(EMB_NUM_OF_FUNC_PARAS == (*func_para_num))
    {
        FUNC_ADDR_NODE *ui_func_addr_node;
        UINT32          ui_func_id;
        UINT32          ui_func_para_num;

        /*format e.g. tbd_run(tbd_md_id, ui_func_retval_addr, ui_func_id, para_1,....)*/
        /*then encode order: tbd_md_id => ui_func_id => [ui_func_retval_addr =>] para_1 => ...*/

        /*the 1st para must be container module id*/
        func_para = (func_para_tbl + 0);
        cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(func_para->para_dir));
        type_conv_item = dbg_query_type_conv_item_by_type(func_addr_node->func_para_type[ 0 ]);
        if( NULL_PTR == type_conv_item )
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT,"error:task_req_func_para_decode: para 0 type %ld conv item is not defined\n",
                    func_addr_node->func_para_type[ 0 ]);
            return (EC_FALSE);
        }
        if(EC_TRUE == TYPE_CONV_ITEM_VAR_POINTER_FLAG(type_conv_item))
        {
            alloc_static_mem(TYPE_CONV_ITEM_VAR_MM_TYPE(type_conv_item), (void **)&(func_para->para_val), LOC_TASK_0009);
            dbg_tiny_caller(1, TYPE_CONV_ITEM_VAR_INIT_FUNC(type_conv_item), func_para->para_val);
            ap = (void *)func_para->para_val;
        }
        else
        {
            ap = (void *)&(func_para->para_val);
        }

        if(E_DIRECT_IN == func_para->para_dir || E_DIRECT_IO == func_para->para_dir)
        {
            dbg_tiny_caller(5,
                    TYPE_CONV_ITEM_VAR_DECODE_FUNC(type_conv_item),
                    comm,
                    in_buff,
                    in_buff_max_len,
                    position,
                    ap);
        }

        /*the 3rd para must be user interface/function id*/
        func_para = (func_para_tbl + 2);
        cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(func_para->para_dir));
        type_conv_item = dbg_query_type_conv_item_by_type(func_addr_node->func_para_type[ 2 ]);
        if( NULL_PTR == type_conv_item )
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT,"error:task_req_func_para_decode: para 2 type %ld conv item is not defined\n",
                    func_addr_node->func_para_type[ 2 ]);
            return (EC_FALSE);
        }
        if(EC_TRUE == TYPE_CONV_ITEM_VAR_POINTER_FLAG(type_conv_item))
        {
            alloc_static_mem(TYPE_CONV_ITEM_VAR_MM_TYPE(type_conv_item), (void **)&(func_para->para_val), LOC_TASK_0010);
            dbg_tiny_caller(1, TYPE_CONV_ITEM_VAR_INIT_FUNC(type_conv_item), func_para->para_val);
            ap = (void *)func_para->para_val;
        }
        else
        {
            ap = (void *)&(func_para->para_val);
        }

        if(E_DIRECT_IN == func_para->para_dir || E_DIRECT_IO == func_para->para_dir)
        {
            dbg_tiny_caller(5,
                    TYPE_CONV_ITEM_VAR_DECODE_FUNC(type_conv_item),
                    comm,
                    in_buff,
                    in_buff_max_len,
                    position,
                    ap);
        }

        ui_func_id = func_para->para_val;
        if(0 != dbg_fetch_func_addr_node_by_index(ui_func_id, &ui_func_addr_node))
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_req_func_para_decode: failed to fetch user func addr node by func id %lx\n", ui_func_id);
            return (EC_FALSE);
        }

        /*the 2nd para must be user interface/function retval addr*/
        func_para = (func_para_tbl + 1);
        type_conv_item = dbg_query_type_conv_item_by_type(ui_func_addr_node->func_ret_type);
        if( NULL_PTR == type_conv_item )
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT,"error:task_req_func_para_decode: ret type %ld conv item is not defined\n",
                    ui_func_addr_node->func_ret_type);
            return (EC_FALSE);
        }

        if(EC_TRUE == TYPE_CONV_ITEM_VAR_POINTER_FLAG(type_conv_item))
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_req_func_para_decode: ret type MUST NOT be pointer of func id %lx\n", ui_func_addr_node->func_index);
            return (EC_FALSE);
#if 0
            alloc_static_mem(TYPE_CONV_ITEM_VAR_MM_TYPE(type_conv_item), (void **)&(func_para->para_val), LOC_TASK_0011);
            dbg_tiny_caller(1, TYPE_CONV_ITEM_VAR_INIT_FUNC(type_conv_item), func_para->para_val);
#endif
        }
        else
        {
            func_para->para_val = (UINT32)(&(func_para->para_val));/*oh, shit trick!:-)*/
        }

        ui_func_para_num = ui_func_addr_node->func_para_num;
        (*func_para_num) = 3 + ui_func_para_num;

        return task_req_func_para_decode(comm, in_buff, in_buff_max_len, position, &ui_func_para_num, func_para_tbl + 3, ui_func_addr_node);
    }

    for( para_idx = 0; para_idx < (*func_para_num); para_idx ++ )
    {
        func_para = (func_para_tbl + para_idx );

        cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(func_para->para_dir));

        type_conv_item = dbg_query_type_conv_item_by_type(func_addr_node->func_para_type[ para_idx ]);
        if( NULL_PTR == type_conv_item )
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT,"error:task_req_func_para_decode: para %ld type %ld conv item is not defined\n",
                    para_idx, func_addr_node->func_para_type[ para_idx ]);
            return (EC_FALSE);
        }

        if(EC_TRUE == TYPE_CONV_ITEM_VAR_POINTER_FLAG(type_conv_item))
        {
            alloc_static_mem(TYPE_CONV_ITEM_VAR_MM_TYPE(type_conv_item), (void **)&(func_para->para_val), LOC_TASK_0012);
            dbg_tiny_caller(1, TYPE_CONV_ITEM_VAR_INIT_FUNC(type_conv_item), func_para->para_val);
            ap = (void *)func_para->para_val;
        }
        else
        {
            ap = (void *)&(func_para->para_val);
        }

        if(E_DIRECT_IN == func_para->para_dir || E_DIRECT_IO == func_para->para_dir)
        {
            dbg_tiny_caller(5,
                    TYPE_CONV_ITEM_VAR_DECODE_FUNC(type_conv_item),
                    comm,
                    in_buff,
                    in_buff_max_len,
                    position,
                    ap);
        }
    }
    return (EC_TRUE);
}

EC_BOOL task_req_encode_size(const TASK_REQ *task_req, UINT32 *size)
{
    TASK_FUNC *task_req_func;

    FUNC_ADDR_NODE *func_addr_node;

    UINT32 send_comm;

    /*clear size*/
    *size = 0;

    task_req_func  = (TASK_FUNC *)TASK_REQ_FUNC(task_req);
    func_addr_node = (FUNC_ADDR_NODE *)TASK_REQ_FUNC_ADDR_NODE(task_req);
    send_comm = TASK_REQ_SEND_COMM(task_req);

#if (SWITCH_OFF == TASK_HEADER_COMPRESSED_SWITCH)
    cmpi_encode_uint32_size(send_comm, (UINT32)0, size);/*len used when forwarding*/
    cmpi_encode_uint32_size(send_comm, (UINT32)0, size);/*tag used when forwarding*/

    cmpi_encode_uint32_size(send_comm, (TASK_REQ_SEND_TCID(task_req)), size);
    cmpi_encode_uint32_size(send_comm, (TASK_REQ_SEND_COMM(task_req)), size);
    cmpi_encode_uint32_size(send_comm, (TASK_REQ_SEND_RANK(task_req)), size);
    cmpi_encode_uint32_size(send_comm, (TASK_REQ_SEND_MODI(task_req)), size);

    cmpi_encode_uint32_size(send_comm, (TASK_REQ_RECV_TCID(task_req)), size);
    cmpi_encode_uint32_size(send_comm, (TASK_REQ_RECV_COMM(task_req)), size);
    cmpi_encode_uint32_size(send_comm, (TASK_REQ_RECV_RANK(task_req)), size);
    cmpi_encode_uint32_size(send_comm, (TASK_REQ_RECV_MODI(task_req)), size);

    cmpi_encode_uint32_size(send_comm, (TASK_REQ_LDB_CHOICE(task_req)), size);

    cmpi_encode_uint32_size(send_comm, (TASK_REQ_PRIO(task_req)), size);
    cmpi_encode_uint32_size(send_comm, (TASK_REQ_TYPE(task_req)), size);
    cmpi_encode_uint32_size(send_comm, (TASK_REQ_TAG(task_req)), size);
    cmpi_encode_uint32_size(send_comm, (TASK_REQ_SEQNO(task_req)), size);
    cmpi_encode_uint32_size(send_comm, (TASK_REQ_SUB_SEQNO(task_req)), size);

    cmpi_encode_cload_stat_size(send_comm, (TASK_REQ_CLOAD_STAT(task_req)), size);
    cmpi_encode_uint32_size(send_comm, (TASK_REQ_TIME_TO_LIVE(task_req)), size);

    cmpi_encode_uint32_size(send_comm, (TASK_REQ_FUNC_ID(task_req)), size);
    cmpi_encode_uint32_size(send_comm, (TASK_REQ_FUNC_PARA_NUM(task_req)), size);

    cmpi_encode_uint32_size(send_comm, (TASK_REQ_NEED_RSP_FLAG(task_req)), size);
#endif/*(SWITCH_OFF == TASK_HEADER_COMPRESSED_SWITCH)*/

#if (SWITCH_ON == TASK_HEADER_COMPRESSED_SWITCH)
    cmpi_encode_uint32_compressed_uint32_t_size(send_comm, (UINT32)0, size);/*len used when forwarding*/
    cmpi_encode_uint32_compressed_uint8_t_size(send_comm, (UINT32)0, size);/*tag used when forwarding*/

    cmpi_encode_uint32_compressed_uint32_t_size(send_comm, (TASK_REQ_SEND_TCID(task_req)), size);
    cmpi_encode_uint32_compressed_uint8_t_size(send_comm, (TASK_REQ_SEND_COMM(task_req)), size);
    cmpi_encode_uint32_compressed_uint8_t_size(send_comm, (TASK_REQ_SEND_RANK(task_req)), size);
    cmpi_encode_uint32_compressed_uint16_t_size(send_comm, (TASK_REQ_SEND_MODI(task_req)), size);

    cmpi_encode_uint32_compressed_uint32_t_size(send_comm, (TASK_REQ_RECV_TCID(task_req)), size);
    cmpi_encode_uint32_compressed_uint8_t_size(send_comm, (TASK_REQ_RECV_COMM(task_req)), size);
    cmpi_encode_uint32_compressed_uint8_t_size(send_comm, (TASK_REQ_RECV_RANK(task_req)), size);
    cmpi_encode_uint32_compressed_uint16_t_size(send_comm, (TASK_REQ_RECV_MODI(task_req)), size);

    cmpi_encode_uint32_compressed_uint8_t_size(send_comm, (TASK_REQ_LDB_CHOICE(task_req)), size);

    cmpi_encode_uint32_compressed_uint8_t_size(send_comm, (TASK_REQ_PRIO(task_req)), size);
    cmpi_encode_uint32_compressed_uint8_t_size(send_comm, (TASK_REQ_TYPE(task_req)), size);
    cmpi_encode_uint32_compressed_uint8_t_size(send_comm, (TASK_REQ_TAG(task_req)), size);
    cmpi_encode_uint32_size(send_comm, (TASK_REQ_SEQNO(task_req)), size);
    cmpi_encode_uint32_size(send_comm, (TASK_REQ_SUB_SEQNO(task_req)), size);

    //cmpi_encode_cload_stat_size(send_comm, (TASK_REQ_CLOAD_STAT(task_req)), size);
    cmpi_encode_uint32_size(send_comm, (TASK_REQ_TIME_TO_LIVE(task_req)), size);

    //cmpi_encode_uint32_size(send_comm, (TASK_REQ_FUNC_ID(task_req)), size);
    if(1)
    {
        cmpi_encode_uint32_compressed_uint16_t_size(send_comm, UINT32_HI(TASK_REQ_FUNC_ID(task_req)), size);
        cmpi_encode_uint32_compressed_uint16_t_size(send_comm, UINT32_LO(TASK_REQ_FUNC_ID(task_req)), size);
    }

    cmpi_encode_uint32_compressed_uint8_t_size(send_comm, (TASK_REQ_FUNC_PARA_NUM(task_req)), size);

    cmpi_encode_uint32_compressed_uint8_t_size(send_comm, (TASK_REQ_NEED_RSP_FLAG(task_req)), size);
#endif/*(SWITCH_ON == TASK_HEADER_COMPRESSED_SWITCH)*/

    task_req_func_para_encode_size(send_comm, func_addr_node->func_para_num, (FUNC_PARA *)task_req_func->func_para, func_addr_node, size);

    //cbase64_encode_size((*size), size);

    return (EC_TRUE);
}

EC_BOOL task_req_encode_header(TASK_REQ *task_req)
{
    TASK_NODE *task_req_node;

    UINT32 send_comm;

    UINT8  *out_buff;
    UINT32  out_buff_len;
    UINT32  position;

    task_req_node     = TASK_REQ_NODE(task_req);
    out_buff          = TASK_NODE_BUFF(task_req_node);
    out_buff_len      = TASK_NODE_BUFF_LEN(task_req_node);

    send_comm = TASK_REQ_SEND_COMM(task_req);

    position = 0;

#if (SWITCH_OFF == TASK_HEADER_COMPRESSED_SWITCH)
    cmpi_encode_uint32(send_comm, (out_buff_len), out_buff, out_buff_len, &(position));/*len used when forwarding*/
    cmpi_encode_uint32(send_comm, (TASK_REQ_TAG(task_req)), out_buff, out_buff_len, &(position));/*tag will be modifed when forwarding*/

    cmpi_encode_uint32(send_comm, (TASK_REQ_SEND_TCID(task_req)), out_buff, out_buff_len, &(position));
    cmpi_encode_uint32(send_comm, (TASK_REQ_SEND_COMM(task_req)), out_buff, out_buff_len, &(position));
    cmpi_encode_uint32(send_comm, (TASK_REQ_SEND_RANK(task_req)), out_buff, out_buff_len, &(position));
    cmpi_encode_uint32(send_comm, (TASK_REQ_SEND_MODI(task_req)), out_buff, out_buff_len, &(position));

    cmpi_encode_uint32(send_comm, (TASK_REQ_RECV_TCID(task_req)), out_buff, out_buff_len, &(position));
    cmpi_encode_uint32(send_comm, (TASK_REQ_RECV_COMM(task_req)), out_buff, out_buff_len, &(position));
    cmpi_encode_uint32(send_comm, (TASK_REQ_RECV_RANK(task_req)), out_buff, out_buff_len, &(position));
    cmpi_encode_uint32(send_comm, (TASK_REQ_RECV_MODI(task_req)), out_buff, out_buff_len, &(position));

    cmpi_encode_uint32(send_comm, (TASK_REQ_LDB_CHOICE(task_req)), out_buff, out_buff_len, &(position));

    cmpi_encode_uint32(send_comm, (TASK_REQ_PRIO(task_req)), out_buff, out_buff_len, &(position));
    cmpi_encode_uint32(send_comm, (TASK_REQ_TYPE(task_req)), out_buff, out_buff_len, &(position));
    cmpi_encode_uint32(send_comm, (TASK_REQ_TAG(task_req)), out_buff, out_buff_len, &(position));
    cmpi_encode_uint32(send_comm, (TASK_REQ_SEQNO(task_req)), out_buff, out_buff_len, &(position));
    cmpi_encode_uint32(send_comm, (TASK_REQ_SUB_SEQNO(task_req)), out_buff, out_buff_len, &(position));

    cmpi_encode_cload_stat(send_comm, (TASK_REQ_CLOAD_STAT(task_req)), out_buff, out_buff_len, &(position));
    cmpi_encode_uint32(send_comm, (TASK_REQ_TIME_TO_LIVE(task_req)), out_buff, out_buff_len, &(position));

    cmpi_encode_uint32(send_comm, (TASK_REQ_FUNC_ID(task_req)), out_buff, out_buff_len, &(position));
    cmpi_encode_uint32(send_comm, (TASK_REQ_FUNC_PARA_NUM(task_req)), out_buff, out_buff_len, &(position));

    cmpi_encode_uint32(send_comm, (TASK_REQ_NEED_RSP_FLAG(task_req)), out_buff, out_buff_len, &(position));
#endif/*(SWITCH_OFF == TASK_HEADER_COMPRESSED_SWITCH)*/

#if (SWITCH_ON == TASK_HEADER_COMPRESSED_SWITCH)
    cmpi_encode_uint32_compressed_uint32_t(send_comm, (out_buff_len), out_buff, out_buff_len, &(position));/*len used when forwarding*/
    cmpi_encode_uint32_compressed_uint8_t(send_comm, (TASK_REQ_TAG(task_req)), out_buff, out_buff_len, &(position));/*tag will be modifed when forwarding*/

    cmpi_encode_uint32_compressed_uint32_t(send_comm, (TASK_REQ_SEND_TCID(task_req)), out_buff, out_buff_len, &(position));
    cmpi_encode_uint32_compressed_uint8_t(send_comm, (TASK_REQ_SEND_COMM(task_req)), out_buff, out_buff_len, &(position));
    cmpi_encode_uint32_compressed_uint8_t(send_comm, (TASK_REQ_SEND_RANK(task_req)), out_buff, out_buff_len, &(position));
    cmpi_encode_uint32_compressed_uint16_t(send_comm, (TASK_REQ_SEND_MODI(task_req)), out_buff, out_buff_len, &(position));

    cmpi_encode_uint32_compressed_uint32_t(send_comm, (TASK_REQ_RECV_TCID(task_req)), out_buff, out_buff_len, &(position));
    cmpi_encode_uint32_compressed_uint8_t(send_comm, (TASK_REQ_RECV_COMM(task_req)), out_buff, out_buff_len, &(position));
    cmpi_encode_uint32_compressed_uint8_t(send_comm, (TASK_REQ_RECV_RANK(task_req)), out_buff, out_buff_len, &(position));
    cmpi_encode_uint32_compressed_uint16_t(send_comm, (TASK_REQ_RECV_MODI(task_req)), out_buff, out_buff_len, &(position));

    cmpi_encode_uint32_compressed_uint8_t(send_comm, (TASK_REQ_LDB_CHOICE(task_req)), out_buff, out_buff_len, &(position));

    cmpi_encode_uint32_compressed_uint8_t(send_comm, (TASK_REQ_PRIO(task_req)), out_buff, out_buff_len, &(position));
    cmpi_encode_uint32_compressed_uint8_t(send_comm, (TASK_REQ_TYPE(task_req)), out_buff, out_buff_len, &(position));
    cmpi_encode_uint32_compressed_uint8_t(send_comm, (TASK_REQ_TAG(task_req)), out_buff, out_buff_len, &(position));
    cmpi_encode_uint32(send_comm, (TASK_REQ_SEQNO(task_req)), out_buff, out_buff_len, &(position));
    cmpi_encode_uint32(send_comm, (TASK_REQ_SUB_SEQNO(task_req)), out_buff, out_buff_len, &(position));

    //cmpi_encode_cload_stat(send_comm, (TASK_REQ_CLOAD_STAT(task_req)), out_buff, out_buff_len, &(position));
    cmpi_encode_uint32(send_comm, (TASK_REQ_TIME_TO_LIVE(task_req)), out_buff, out_buff_len, &(position));

    //cmpi_encode_uint32(send_comm, (TASK_REQ_FUNC_ID(task_req)), out_buff, out_buff_len, &(position));
    if(1)
    {
        cmpi_encode_uint32_compressed_uint16_t(send_comm, UINT32_HI(TASK_REQ_FUNC_ID(task_req)), out_buff, out_buff_len, &(position));
        cmpi_encode_uint32_compressed_uint16_t(send_comm, UINT32_LO(TASK_REQ_FUNC_ID(task_req)), out_buff, out_buff_len, &(position));
    }
    cmpi_encode_uint32_compressed_uint8_t(send_comm, (TASK_REQ_FUNC_PARA_NUM(task_req)), out_buff, out_buff_len, &(position));

    cmpi_encode_uint32_compressed_uint8_t(send_comm, (TASK_REQ_NEED_RSP_FLAG(task_req)), out_buff, out_buff_len, &(position));
#endif/*(SWITCH_ON == TASK_HEADER_COMPRESSED_SWITCH)*/

    if(EC_TRUE == TASK_REQ_MOD_ID_FLAG(task_req))
    {
        TASK_FUNC     *task_req_func;
        FUNC_PARA     *func_para;

        task_req_func = TASK_REQ_FUNC(task_req);
        func_para = &(task_req_func->func_para[ 0 ]); /*note: the first parameter must be mod_id position*/

        /*encode para_dir (IN)*/
        cmpi_encode_uint32(send_comm, (func_para->para_dir), out_buff, out_buff_len, &(position));
        /*encode mod_id*/
        cmpi_encode_uint32(send_comm, (func_para->para_val), out_buff, out_buff_len, &(position));
    }

    return (EC_TRUE);
}

EC_BOOL task_req_encode(TASK_REQ *task_req)
{
    TASK_NODE *task_req_node;
    TASK_FUNC *task_req_func;

    FUNC_ADDR_NODE *func_addr_node;

    UINT32 send_comm;

    UINT8  *out_buff;
    UINT32  out_buff_len;
    UINT32  position;
#if 0
    dbg_log(SEC_0015_TASK, 5)(LOGSTDOUT, "encode req: from (tcid %s,comm %ld,rank %ld,modi %ld) to (tcid %s,comm %ld,rank %ld,modi %ld) with priority %ld, type %ld, tag %ld, ldb %ld, seqno %lx.%lx.%lx, subseqno %ld, func id %lx\n",
                    TASK_REQ_SEND_TCID_STR(task_req), TASK_REQ_SEND_COMM(task_req), TASK_REQ_SEND_RANK(task_req), TASK_REQ_SEND_MODI(task_req),
                    TASK_REQ_RECV_TCID_STR(task_req), TASK_REQ_RECV_COMM(task_req), TASK_REQ_RECV_RANK(task_req), TASK_REQ_RECV_MODI(task_req),
                    TASK_REQ_PRIO(task_req), TASK_REQ_TYPE(task_req),
                    TASK_REQ_TAG(task_req), TASK_REQ_LDB_CHOICE(task_req),
                    TASK_REQ_SEND_TCID(task_req), TASK_REQ_SEND_RANK(task_req), TASK_REQ_SEQNO(task_req), TASK_REQ_SUB_SEQNO(task_req),
                    TASK_REQ_FUNC_ID(task_req)
                    );
#endif
    task_req_func     = TASK_REQ_FUNC(task_req);
    func_addr_node    = TASK_REQ_FUNC_ADDR_NODE(task_req);

    task_req_node     = TASK_REQ_NODE(task_req);
    out_buff          = TASK_NODE_BUFF(task_req_node);
    out_buff_len      = TASK_NODE_BUFF_LEN(task_req_node);

    send_comm = TASK_REQ_SEND_COMM(task_req);

    position = 0;

#if (SWITCH_OFF == TASK_HEADER_COMPRESSED_SWITCH)
    cmpi_encode_uint32(send_comm, (out_buff_len), out_buff, out_buff_len, &(position));/*len used when forwarding*/
    cmpi_encode_uint32(send_comm, (TASK_REQ_TAG(task_req)), out_buff, out_buff_len, &(position));/*tag will be modifed when forwarding*/

    cmpi_encode_uint32(send_comm, (TASK_REQ_SEND_TCID(task_req)), out_buff, out_buff_len, &(position));
    cmpi_encode_uint32(send_comm, (TASK_REQ_SEND_COMM(task_req)), out_buff, out_buff_len, &(position));
    cmpi_encode_uint32(send_comm, (TASK_REQ_SEND_RANK(task_req)), out_buff, out_buff_len, &(position));
    cmpi_encode_uint32(send_comm, (TASK_REQ_SEND_MODI(task_req)), out_buff, out_buff_len, &(position));

    cmpi_encode_uint32(send_comm, (TASK_REQ_RECV_TCID(task_req)), out_buff, out_buff_len, &(position));
    cmpi_encode_uint32(send_comm, (TASK_REQ_RECV_COMM(task_req)), out_buff, out_buff_len, &(position));
    cmpi_encode_uint32(send_comm, (TASK_REQ_RECV_RANK(task_req)), out_buff, out_buff_len, &(position));
    cmpi_encode_uint32(send_comm, (TASK_REQ_RECV_MODI(task_req)), out_buff, out_buff_len, &(position));

    cmpi_encode_uint32(send_comm, (TASK_REQ_LDB_CHOICE(task_req)), out_buff, out_buff_len, &(position));

    cmpi_encode_uint32(send_comm, (TASK_REQ_PRIO(task_req)), out_buff, out_buff_len, &(position));
    cmpi_encode_uint32(send_comm, (TASK_REQ_TYPE(task_req)), out_buff, out_buff_len, &(position));
    cmpi_encode_uint32(send_comm, (TASK_REQ_TAG(task_req)), out_buff, out_buff_len, &(position));
    cmpi_encode_uint32(send_comm, (TASK_REQ_SEQNO(task_req)), out_buff, out_buff_len, &(position));
    cmpi_encode_uint32(send_comm, (TASK_REQ_SUB_SEQNO(task_req)), out_buff, out_buff_len, &(position));

    cmpi_encode_cload_stat(send_comm, (TASK_REQ_CLOAD_STAT(task_req)), out_buff, out_buff_len, &(position));
    cmpi_encode_uint32(send_comm, (TASK_REQ_TIME_TO_LIVE(task_req)), out_buff, out_buff_len, &(position));

    cmpi_encode_uint32(send_comm, (TASK_REQ_FUNC_ID(task_req)), out_buff, out_buff_len, &(position));
    cmpi_encode_uint32(send_comm, (TASK_REQ_FUNC_PARA_NUM(task_req)), out_buff, out_buff_len, &(position));

    cmpi_encode_uint32(send_comm, (TASK_REQ_NEED_RSP_FLAG(task_req)), out_buff, out_buff_len, &(position));
#endif/*(SWITCH_OFF == TASK_HEADER_COMPRESSED_SWITCH)*/

#if (SWITCH_ON == TASK_HEADER_COMPRESSED_SWITCH)
    cmpi_encode_uint32_compressed_uint32_t(send_comm, (out_buff_len), out_buff, out_buff_len, &(position));/*len used when forwarding*/
    cmpi_encode_uint32_compressed_uint8_t(send_comm, (TASK_REQ_TAG(task_req)), out_buff, out_buff_len, &(position));/*tag will be modifed when forwarding*/

    cmpi_encode_uint32_compressed_uint32_t(send_comm, (TASK_REQ_SEND_TCID(task_req)), out_buff, out_buff_len, &(position));
    cmpi_encode_uint32_compressed_uint8_t(send_comm, (TASK_REQ_SEND_COMM(task_req)), out_buff, out_buff_len, &(position));
    cmpi_encode_uint32_compressed_uint8_t(send_comm, (TASK_REQ_SEND_RANK(task_req)), out_buff, out_buff_len, &(position));
    cmpi_encode_uint32_compressed_uint16_t(send_comm, (TASK_REQ_SEND_MODI(task_req)), out_buff, out_buff_len, &(position));

    cmpi_encode_uint32_compressed_uint32_t(send_comm, (TASK_REQ_RECV_TCID(task_req)), out_buff, out_buff_len, &(position));
    cmpi_encode_uint32_compressed_uint8_t(send_comm, (TASK_REQ_RECV_COMM(task_req)), out_buff, out_buff_len, &(position));
    cmpi_encode_uint32_compressed_uint8_t(send_comm, (TASK_REQ_RECV_RANK(task_req)), out_buff, out_buff_len, &(position));
    cmpi_encode_uint32_compressed_uint16_t(send_comm, (TASK_REQ_RECV_MODI(task_req)), out_buff, out_buff_len, &(position));

    cmpi_encode_uint32_compressed_uint8_t(send_comm, (TASK_REQ_LDB_CHOICE(task_req)), out_buff, out_buff_len, &(position));

    cmpi_encode_uint32_compressed_uint8_t(send_comm, (TASK_REQ_PRIO(task_req)), out_buff, out_buff_len, &(position));
    cmpi_encode_uint32_compressed_uint8_t(send_comm, (TASK_REQ_TYPE(task_req)), out_buff, out_buff_len, &(position));
    cmpi_encode_uint32_compressed_uint8_t(send_comm, (TASK_REQ_TAG(task_req)), out_buff, out_buff_len, &(position));
    cmpi_encode_uint32(send_comm, (TASK_REQ_SEQNO(task_req)), out_buff, out_buff_len, &(position));
    cmpi_encode_uint32(send_comm, (TASK_REQ_SUB_SEQNO(task_req)), out_buff, out_buff_len, &(position));

    //cmpi_encode_cload_stat(send_comm, (TASK_REQ_CLOAD_STAT(task_req)), out_buff, out_buff_len, &(position));
    cmpi_encode_uint32(send_comm, (TASK_REQ_TIME_TO_LIVE(task_req)), out_buff, out_buff_len, &(position));

    //cmpi_encode_uint32(send_comm, (TASK_REQ_FUNC_ID(task_req)), out_buff, out_buff_len, &(position));
    if(1)
    {
        cmpi_encode_uint32_compressed_uint16_t(send_comm, UINT32_HI(TASK_REQ_FUNC_ID(task_req)), out_buff, out_buff_len, &(position));
        cmpi_encode_uint32_compressed_uint16_t(send_comm, UINT32_LO(TASK_REQ_FUNC_ID(task_req)), out_buff, out_buff_len, &(position));
    }
    cmpi_encode_uint32_compressed_uint8_t(send_comm, (TASK_REQ_FUNC_PARA_NUM(task_req)), out_buff, out_buff_len, &(position));

    cmpi_encode_uint32_compressed_uint8_t(send_comm, (TASK_REQ_NEED_RSP_FLAG(task_req)), out_buff, out_buff_len, &(position));
#endif/*(SWITCH_ON == TASK_HEADER_COMPRESSED_SWITCH)*/

    task_req_func_para_encode(send_comm, task_req_func->func_para_num, (FUNC_PARA *)task_req_func->func_para,
                                         func_addr_node, out_buff, out_buff_len, &(position));

    TASK_NODE_BUFF_LEN(task_req_node) = position;/*set to real length*/

    return (EC_TRUE);
}

EC_BOOL task_req_decode(const UINT32 recv_comm, TASK_REQ *task_req)
{
    TASK_NODE *task_req_node;
    TASK_FUNC *task_req_func;

    FUNC_ADDR_NODE *func_addr_node;
    TYPE_CONV_ITEM *type_conv_item;

    UINT8  *in_buff;
    UINT32  in_buff_len;
    UINT32  position;

    UINT32 discard_info;

    task_req_func     = TASK_REQ_FUNC(task_req);

    task_req_node     = TASK_REQ_NODE(task_req);
    in_buff           = TASK_NODE_BUFF(task_req_node);
    in_buff_len       = TASK_NODE_BUFF_LEN(task_req_node);

    position = 0;

    CTIMET_GET(TASK_REQ_START_TIME(task_req));/*record start time as soon as possible*/

#if (SWITCH_OFF == TASK_HEADER_COMPRESSED_SWITCH)
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(discard_info));/*dicard len info used when forwarding only*/
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(discard_info));/*dicard tag info used when forwarding only*/

    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_REQ_SEND_TCID(task_req)));
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_REQ_SEND_COMM(task_req)));
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_REQ_SEND_RANK(task_req)));
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_REQ_SEND_MODI(task_req)));

    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_REQ_RECV_TCID(task_req)));
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_REQ_RECV_COMM(task_req)));
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_REQ_RECV_RANK(task_req)));
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_REQ_RECV_MODI(task_req)));

    if(CMPI_ANY_COMM == TASK_REQ_RECV_COMM(task_req))
    {
        dbg_log(SEC_0015_TASK, 1)(LOGSTDNULL, "warn: task_req_decode: update TASK_REQ_RECV_COMM from CMPI_ANY_COMM(%ld) to recv_comm(%ld)\n",
                        TASK_REQ_RECV_COMM(task_req), recv_comm);
        TASK_REQ_RECV_COMM(task_req) = recv_comm;
    }

    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_REQ_LDB_CHOICE(task_req)));

    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_REQ_PRIO(task_req)));
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_REQ_TYPE(task_req)));
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_REQ_TAG(task_req)));
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_REQ_SEQNO(task_req)));
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_REQ_SUB_SEQNO(task_req)));

    cmpi_decode_cload_stat(recv_comm, in_buff, in_buff_len, &(position), (TASK_REQ_CLOAD_STAT(task_req)));
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_REQ_TIME_TO_LIVE(task_req)));

    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_REQ_FUNC_ID(task_req)));
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_REQ_FUNC_PARA_NUM(task_req)));

    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_REQ_NEED_RSP_FLAG(task_req)));
#endif/*(SWITCH_OFF == TASK_HEADER_COMPRESSED_SWITCH)*/

#if (SWITCH_ON == TASK_HEADER_COMPRESSED_SWITCH)
    cmpi_decode_uint32_compressed_uint32_t(recv_comm, in_buff, in_buff_len, &(position), &(discard_info));/*dicard len info used when forwarding only*/
    cmpi_decode_uint32_compressed_uint8_t(recv_comm, in_buff, in_buff_len, &(position), &(discard_info));/*dicard tag info used when forwarding only*/

    cmpi_decode_uint32_compressed_uint32_t(recv_comm, in_buff, in_buff_len, &(position), &(TASK_REQ_SEND_TCID(task_req)));
    cmpi_decode_uint32_compressed_uint8_t(recv_comm, in_buff, in_buff_len, &(position), &(TASK_REQ_SEND_COMM(task_req)));
    cmpi_decode_uint32_compressed_uint8_t(recv_comm, in_buff, in_buff_len, &(position), &(TASK_REQ_SEND_RANK(task_req)));
    cmpi_decode_uint32_compressed_uint16_t(recv_comm, in_buff, in_buff_len, &(position), &(TASK_REQ_SEND_MODI(task_req)));

    cmpi_decode_uint32_compressed_uint32_t(recv_comm, in_buff, in_buff_len, &(position), &(TASK_REQ_RECV_TCID(task_req)));
    cmpi_decode_uint32_compressed_uint8_t(recv_comm, in_buff, in_buff_len, &(position), &(TASK_REQ_RECV_COMM(task_req)));
    cmpi_decode_uint32_compressed_uint8_t(recv_comm, in_buff, in_buff_len, &(position), &(TASK_REQ_RECV_RANK(task_req)));
    cmpi_decode_uint32_compressed_uint16_t(recv_comm, in_buff, in_buff_len, &(position), &(TASK_REQ_RECV_MODI(task_req)));

    if(CMPI_ANY_COMM == TASK_REQ_RECV_COMM(task_req))
    {
        dbg_log(SEC_0015_TASK, 1)(LOGSTDNULL, "warn: task_req_decode: update TASK_REQ_RECV_COMM from CMPI_ANY_COMM(%ld) to recv_comm(%ld)\n",
                        TASK_REQ_RECV_COMM(task_req), recv_comm);
        TASK_REQ_RECV_COMM(task_req) = recv_comm;
    }

    cmpi_decode_uint32_compressed_uint8_t(recv_comm, in_buff, in_buff_len, &(position), &(TASK_REQ_LDB_CHOICE(task_req)));

    cmpi_decode_uint32_compressed_uint8_t(recv_comm, in_buff, in_buff_len, &(position), &(TASK_REQ_PRIO(task_req)));
    cmpi_decode_uint32_compressed_uint8_t(recv_comm, in_buff, in_buff_len, &(position), &(TASK_REQ_TYPE(task_req)));
    cmpi_decode_uint32_compressed_uint8_t(recv_comm, in_buff, in_buff_len, &(position), &(TASK_REQ_TAG(task_req)));
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_REQ_SEQNO(task_req)));
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_REQ_SUB_SEQNO(task_req)));

    //cmpi_decode_cload_stat(recv_comm, in_buff, in_buff_len, &(position), (TASK_REQ_CLOAD_STAT(task_req)));
    cload_stat_init(TASK_REQ_CLOAD_STAT(task_req));
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_REQ_TIME_TO_LIVE(task_req)));

    //cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_REQ_FUNC_ID(task_req)));
    if(1)
    {
        UINT32 __mod_type;
        UINT32 __mod_id;

        cmpi_decode_uint32_compressed_uint16_t(recv_comm, in_buff, in_buff_len, &(position), &(__mod_type));
        cmpi_decode_uint32_compressed_uint16_t(recv_comm, in_buff, in_buff_len, &(position), &(__mod_id));

        TASK_REQ_FUNC_ID(task_req) = UINT32_VAL(__mod_type, __mod_id);
    }
    cmpi_decode_uint32_compressed_uint8_t(recv_comm, in_buff, in_buff_len, &(position), &(TASK_REQ_FUNC_PARA_NUM(task_req)));

    cmpi_decode_uint32_compressed_uint8_t(recv_comm, in_buff, in_buff_len, &(position), &(TASK_REQ_NEED_RSP_FLAG(task_req)));
#endif/*(SWITCH_ON == TASK_HEADER_COMPRESSED_SWITCH)*/


#if 0
    dbg_log(SEC_0015_TASK, 5)(LOGSTDOUT, "decode req: from (tcid %s,comm %ld,rank %ld,modi %ld) to (tcid %s,comm %ld,rank %ld,modi %ld) with priority %ld, type %ld, tag %ld, ldb %ld, seqno %lx.%lx.%lx, subseqno %ld, func id %lx\n",
                    TASK_REQ_SEND_TCID_STR(task_req), TASK_REQ_SEND_COMM(task_req), TASK_REQ_SEND_RANK(task_req), TASK_REQ_SEND_MODI(task_req),
                    TASK_REQ_RECV_TCID_STR(task_req), TASK_REQ_RECV_COMM(task_req), TASK_REQ_RECV_RANK(task_req), TASK_REQ_RECV_MODI(task_req),
                    TASK_REQ_PRIO(task_req), TASK_REQ_TYPE(task_req),
                    TASK_REQ_TAG(task_req), TASK_REQ_LDB_CHOICE(task_req),
                    TASK_REQ_SEND_TCID(task_req), TASK_REQ_SEND_RANK(task_req), TASK_REQ_SEQNO(task_req), TASK_REQ_SUB_SEQNO(task_req),
                    TASK_REQ_FUNC_ID(task_req)
                    );
#endif
    if(0 != dbg_fetch_func_addr_node_by_index(task_req_func->func_id, &func_addr_node))
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_req_decode: failed to fetch func addr node by func id %lx\n", task_req_func->func_id);
        return (EC_FALSE);
    }

    TASK_REQ_FUNC_ADDR_NODE(task_req) = func_addr_node;/*mount func_addr_node to task req*/

    type_conv_item = dbg_query_type_conv_item_by_type(func_addr_node->func_ret_type);
    if( NULL_PTR == type_conv_item )
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT,"error:task_req_decode: ret type %ld conv item is not defined\n",
                func_addr_node->func_ret_type);
        return (EC_FALSE);
    }
    if(EC_TRUE == TYPE_CONV_ITEM_VAR_POINTER_FLAG(type_conv_item))
    {
        alloc_static_mem(TYPE_CONV_ITEM_VAR_MM_TYPE(type_conv_item), (void **)&(task_req_func->func_ret_val), LOC_TASK_0013);
        dbg_tiny_caller(1, TYPE_CONV_ITEM_VAR_INIT_FUNC(type_conv_item), task_req_func->func_ret_val);
    }

    task_req_func_para_decode(recv_comm, in_buff, in_buff_len, &(position), &(task_req_func->func_para_num), (FUNC_PARA *)task_req_func->func_para, func_addr_node);
    return (EC_TRUE);
}

EC_BOOL task_req_isend(TASK_BRD *task_brd, TASK_REQ *task_req)
{
    EC_BOOL     ret;

    ret = task_node_isend(task_brd, TASK_REQ_NODE(task_req));
    if(EC_TRUE == ret)
    {
        dbg_log(SEC_0015_TASK, 6)(LOGSTDOUT, "isend  req: from (tcid %s,comm %ld,rank %ld,modi %ld) to (tcid %s,comm %ld,rank %ld,modi %ld) with priority %ld, type %ld, tag %ld, ldb %ld, seqno %lx.%lx.%lx, subseqno %ld, func id %lx\n",
                        TASK_REQ_SEND_TCID_STR(task_req), TASK_REQ_SEND_COMM(task_req), TASK_REQ_SEND_RANK(task_req), TASK_REQ_SEND_MODI(task_req),
                        TASK_REQ_RECV_TCID_STR(task_req), TASK_REQ_RECV_COMM(task_req), TASK_REQ_RECV_RANK(task_req), TASK_REQ_RECV_MODI(task_req),
                        TASK_REQ_PRIO(task_req), TASK_REQ_TYPE(task_req),
                        TASK_REQ_TAG(task_req), TASK_REQ_LDB_CHOICE(task_req),
                        TASK_REQ_SEND_TCID(task_req), TASK_REQ_SEND_RANK(task_req), TASK_REQ_SEQNO(task_req), TASK_REQ_SUB_SEQNO(task_req),
                        TASK_REQ_FUNC_ID(task_req)
                        );

    }
    return (ret);
}

UINT32 task_req_time_elapsed(const TASK_REQ *task_req)
{
    CTIMET cur;

    if(TASK_ALWAYS_LIVE == TASK_REQ_TIME_TO_LIVE(task_req))
    {
        /*never timeout*/
        return (0);
    }

    CTIMET_GET(cur);
    return lrint(CTIMET_DIFF(TASK_REQ_START_TIME(task_req), cur));
}

UINT32 task_req_time_left(const TASK_REQ *task_req)
{
    CTIMET cur;

    if(TASK_ALWAYS_LIVE == TASK_REQ_TIME_TO_LIVE(task_req))
    {
        /*never timeout*/
        return (TASK_ALWAYS_LIVE);
    }

    CTIMET_GET(cur);
    return (TASK_REQ_TIME_TO_LIVE(task_req) - lrint(CTIMET_DIFF(TASK_REQ_START_TIME(task_req), cur)));
}

EC_BOOL task_req_is_timeout(const TASK_REQ *task_req)
{
    CTIMET cur;
    double diff;

    if(TASK_ALWAYS_LIVE == TASK_REQ_TIME_TO_LIVE(task_req))
    {
        /*never timeout*/
        return (EC_FALSE);
    }

    CTIMET_GET(cur);

    diff = CTIMET_DIFF(TASK_REQ_START_TIME(task_req), cur);

    if(diff >= 0.0 + TASK_REQ_TIME_TO_LIVE(task_req))
    {
        /*time out*/
        return (EC_TRUE);
    }

    /*not timeout*/
    return (EC_FALSE);
}

/*NOTE: size of parameter in ap must be equal to sizeof(UINT32)*/
UINT32 task_req_func_para_init(const UINT32 func_para_num, FUNC_PARA *func_para_tbl, va_list ap)
{
    FUNC_PARA *func_para;
    UINT32 para_idx;

    /*when embed user interface*/
    if(EMB_NUM_OF_FUNC_PARAS == func_para_num)
    {
        FUNC_ADDR_NODE *ui_func_addr_node;
        UINT32          ui_func_id;
        /*format e.g. tbd_run(tbd_md_id, ui_func_retval_addr, ui_func_id, para_1,....)*/

        /*the 1st para must be container module id*/
        func_para = (func_para_tbl + 0);
        func_para->para_val = va_arg(ap, UINT32);

        /*the 2nd para must be user interface/function retval addr*/
        func_para = (func_para_tbl + 1);
        func_para->para_val = va_arg(ap, UINT32);

        /*the 3rd para must be user interface/function id*/
        func_para = (func_para_tbl + 2);
        func_para->para_val = va_arg(ap, UINT32);
        ui_func_id = func_para->para_val;

        if(0 != dbg_fetch_func_addr_node_by_index(ui_func_id, &ui_func_addr_node))
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_req_func_para_init: failed to fetch user func addr node by func id %lx\n", ui_func_id);
            return ((UINT32)(-1));
        }

        /*recursively*/
        return task_req_func_para_init(ui_func_addr_node->func_para_num, func_para_tbl + 3, ap);
    }

    if(MAX_NUM_OF_FUNC_PARAS < func_para_num)
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_req_func_para_init: func_para_num = %ld overflow\n", func_para_num);
        return ((UINT32)-1);
    }

    for(para_idx = 0; para_idx < func_para_num; para_idx ++)
    {
        func_para = (func_para_tbl + para_idx);
        func_para->para_val = va_arg(ap, UINT32);
    }

    return (0);
}

EC_BOOL task_req_md_mod_mgr_get(TASK_BRD *task_brd, TASK_REQ *task_req, MOD_MGR **mod_mgr)
{
    TASK_FUNC *task_req_func;

    MOD_MGR *md_mod_mgr;

    UINT32 md_id;
    UINT32 md_type;
    FUNC_ADDR_MGR *func_addr_mgr;

    task_req_func = TASK_REQ_FUNC(task_req);
    md_type = (task_req_func->func_id >> (WORDSIZE / 2)); /*refer findex.inc*/
    func_addr_mgr = TASK_BRD_MD_NODE_GET(task_brd, md_type);

    /*when func invocation in task_req is module start or end, then return nothing*/
    if(task_req_func->func_id == func_addr_mgr->md_start_func_id
    || task_req_func->func_id == func_addr_mgr->md_end_func_id
    || task_req_func->func_id == func_addr_mgr->md_set_mod_mgr_func_id)
    {
        *mod_mgr = (MOD_MGR *)0;
        return (EC_FALSE);
    }

    md_id = TASK_REQ_RECV_MODI(task_req);
    if(0 == func_addr_mgr->md_fget_mod_mgr)
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDERR, "error:task_req_md_mod_mgr_get: func_addr_mgr %p not define md_fget_mod_mgr\n", func_addr_mgr);
        *mod_mgr = (MOD_MGR *)0;
        return (EC_FALSE);
    }
    md_mod_mgr = (MOD_MGR *)(func_addr_mgr->md_fget_mod_mgr)(md_id);

    *mod_mgr = md_mod_mgr;
    return (EC_TRUE);
}

EC_BOOL task_rsp_init(TASK_RSP *task_rsp)
{
    task_header_init(&(task_rsp->task_header));

    cload_stat_init(TASK_RSP_CLOAD_STAT(task_rsp));
    TASK_RSP_MGR(task_rsp) = (TASK_MGR *)0;

    TASK_RSP_LDB_CHOICE(task_rsp)     = LOAD_BALANCING_END; /*default error load balancing strategy*/

    TASK_RSP_CTHREAD_NODE(task_rsp)   = NULL_PTR;

    TASK_REQ_RECV_MOD_NEW(task_rsp)   = NULL_PTR;
    TASK_RSP_RECV_MOD_FLAG(task_rsp)  = EC_FALSE;/*default is not need to update TASK_RSP_MOD*/
    TASK_RSP_MOD_ID_FLAG(task_rsp)    = EC_FALSE; /*default is not need to update mod id at first para*/

    TASK_RSP_PRIO(task_rsp)           = TASK_PRIO_UNDEF;
    TASK_RSP_TYPE(task_rsp)           = TASK_UNKNOWN_TYPE;
    TASK_RSP_TAG(task_rsp)            = TAG_TASK_UNDEF;

    TASK_RSP_SEQNO(task_rsp)          = ERR_TASK_SEQNO;

    TASK_REQ_FUNC_ADDR_NODE(task_rsp) = NULL_PTR;
    task_func_init(TASK_RSP_FUNC(task_rsp));

    return (EC_TRUE);
}

TASK_RSP * task_rsp_new(const UINT32 buff_size, const UINT32 location)
{
    TASK_NODE *task_node;

    task_node = task_node_new(buff_size, location);
    if(NULL_PTR == task_node)
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_rsp_new: new task node failed where location = %ld\n", location);
        return (NULL_PTR);
    }

    task_rsp_init(TASK_NODE_RSP(task_node));
    return TASK_NODE_RSP(task_node);
}

EC_BOOL task_rsp_free(TASK_RSP *task_rsp)
{
    if(NULL_PTR != task_rsp)
    {
        TASK_NODE *task_rsp_node;

        task_rsp_clean(task_rsp);

        task_rsp_node = TASK_RSP_NODE(task_rsp);
        task_node_free(task_rsp_node);
    }
    return (EC_TRUE);
}

EC_BOOL task_rsp_clean(TASK_RSP *task_rsp)
{
    TASK_FUNC *task_rsp_func;

    FUNC_ADDR_NODE *func_addr_node;
    TYPE_CONV_ITEM *type_conv_item;

    UINT32 para_idx;

    task_rsp_func  = TASK_RSP_FUNC(task_rsp);
    func_addr_node = TASK_RSP_FUNC_ADDR_NODE(task_rsp);

    if(NULL_PTR == task_rsp_func)
    {
        dbg_log(SEC_0015_TASK, 9)(LOGSTDOUT, "warn:task_rsp_clean: task_rsp_func is null\n");
        return (EC_TRUE);
    }

    if(NULL_PTR == func_addr_node)
    {
        dbg_log(SEC_0015_TASK, 9)(LOGSTDOUT, "warn:task_rsp_clean: func_addr_node is null\n");
        return (EC_TRUE);
    }

    if(e_dbg_void != func_addr_node->func_ret_type)
    {
        type_conv_item = dbg_query_type_conv_item_by_type(func_addr_node->func_ret_type);
        if( NULL_PTR == type_conv_item )
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT,"error:task_rsp_clean: ret type %ld conv item is not defined\n",
                    func_addr_node->func_ret_type);
            return (EC_FALSE);
        }
        if(EC_TRUE == TYPE_CONV_ITEM_VAR_POINTER_FLAG(type_conv_item) && 0 != task_rsp_func->func_ret_val)
        {
            dbg_tiny_caller(1, TYPE_CONV_ITEM_VAR_FREE_FUNC(type_conv_item), task_rsp_func->func_ret_val);
            task_rsp_func->func_ret_val = 0;
        }
    }

    for( para_idx = 0; para_idx < TASK_RSP_FUNC_PARA_NUM(task_rsp) && para_idx < MAX_NUM_OF_FUNC_PARAS; para_idx ++ )
    {
        FUNC_PARA *func_para;

        func_para = &(task_rsp_func->func_para[ para_idx ]);

        type_conv_item = dbg_query_type_conv_item_by_type(func_addr_node->func_para_type[ para_idx ]);
        if( NULL_PTR == type_conv_item )
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT,"error:task_rsp_clean: para %ld type %ld conv item is not defined\n",
                    para_idx, func_addr_node->func_para_type[ para_idx ]);
            return (EC_FALSE);
        }
        if(EC_TRUE == TYPE_CONV_ITEM_VAR_POINTER_FLAG(type_conv_item) && 0 != func_para->para_val)
        {
            dbg_tiny_caller(1, TYPE_CONV_ITEM_VAR_FREE_FUNC(type_conv_item), func_para->para_val);
            func_para->para_val = 0;
        }
    }
    return (EC_TRUE);
}

EC_BOOL task_rsp_print(LOG *log, const TASK_RSP *task_rsp)
{
    UINT32 para_idx;
    UINT32 para_num;

    sys_log(log, "\n");
    sys_log(log, "task_rsp %lx:\n", task_rsp);
    sys_log(log, "send mod: ");
    mod_node_print(log, TASK_RSP_SEND_MOD(task_rsp));
    sys_log(log, "recv mod: ");
    mod_node_print(log, TASK_RSP_RECV_MOD(task_rsp));

    sys_log(log, "seq no: %lx, subseqno: %lx, func_id: %lx, para_num: %ld, first para val: %ld\n",
                    TASK_RSP_SEQNO(task_rsp), TASK_RSP_SUB_SEQNO(task_rsp),
                    TASK_RSP_FUNC_ID(task_rsp), TASK_RSP_FUNC_PARA_NUM(task_rsp),
                    TASK_RSP_FUNC_PARA_VAL(task_rsp, 0));

    if(EMB_NUM_OF_FUNC_PARAS == TASK_RSP_FUNC_PARA_NUM(task_rsp))
    {
        para_num =  3;
    }
    else
    {
        para_num = TASK_RSP_FUNC_PARA_NUM(task_rsp);
    }

    for(para_idx = 0; para_idx < para_num; para_idx ++)
    {
        sys_log(log, "para_idx = %ld, para_dir = %ld, para_val = %lx\n", para_idx,
                        TASK_RSP_FUNC_PARA_DIR(task_rsp, para_idx),
                        TASK_RSP_FUNC_PARA_VAL(task_rsp, para_idx));
    }

    sys_log(log, "\n");

    return (EC_TRUE);
}

EC_BOOL task_rsp_func_para_encode_size(const UINT32 comm, const UINT32 func_para_num, FUNC_PARA *func_para_tbl, const FUNC_ADDR_NODE *func_addr_node, UINT32 *size)
{
    FUNC_PARA *func_para;
    UINT32 para_idx;

    TYPE_CONV_ITEM *type_conv_item;

    if(EMB_NUM_OF_FUNC_PARAS == func_addr_node->func_para_num)
    {
        FUNC_ADDR_NODE *ui_func_addr_node;
        UINT32          ui_func_id;

        /*format e.g. tbd_run(tbd_md_id, ui_func_retval_addr, ui_func_id, para_1,....)*/
        ui_func_id = (func_para_tbl + 2)->para_val;
        if(0 != dbg_fetch_func_addr_node_by_index(ui_func_id, &ui_func_addr_node))
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_rsp_func_para_encode_size: failed to fetch user func addr node by func id %lx\n", ui_func_id);
            return (EC_FALSE);
        }

        /*the 1st para must be container module id*/
        func_para = (func_para_tbl + 0);
        /*ignore E_DIRECT_IN parameter encoding of task_rsp*/

        /*the 2nd para must be user interface/function retval addr*/
        func_para = (func_para_tbl + 1);
        if(e_dbg_void != ui_func_addr_node->func_ret_type)
        {
            type_conv_item = dbg_query_type_conv_item_by_type(ui_func_addr_node->func_ret_type);
            if( NULL_PTR == type_conv_item )
            {
                dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT,"error:task_rsp_func_para_encode_size: ret type %ld conv item is not defined\n",
                        ui_func_addr_node->func_ret_type);
                return (EC_FALSE);
            }
            dbg_tiny_caller(3,
                TYPE_CONV_ITEM_VAR_ENCODE_SIZE(type_conv_item),
                comm,
                func_para->para_val,
                size);
        }

        /*the 3rd para must be user interface/function id*/
        func_para = (func_para_tbl + 2);
        /*ignore E_DIRECT_IN parameter encoding of task_rsp*/

        /*recursively*/
        return task_rsp_func_para_encode_size(comm, ui_func_addr_node->func_para_num, func_para_tbl + 3, ui_func_addr_node, size);
    }

    for( para_idx = 0; para_idx < func_para_num; para_idx ++ )
    {
        func_para = (func_para_tbl + para_idx);

        if(E_DIRECT_IN == func_para->para_dir)
        {
            continue;
        }

        if(E_DIRECT_OUT == func_para->para_dir || E_DIRECT_IO == func_para->para_dir)
        {
            type_conv_item = dbg_query_type_conv_item_by_type(func_addr_node->func_para_type[ para_idx ]);
            if( NULL_PTR == type_conv_item )
            {
                dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT,"error:task_rsp_func_para_encode_size: para %ld type %ld conv item is not defined\n",
                        para_idx, func_addr_node->func_para_type[ para_idx ]);
                return (EC_FALSE);
            }
            dbg_tiny_caller(3,
                TYPE_CONV_ITEM_VAR_ENCODE_SIZE(type_conv_item),
                comm,
                func_para->para_val,
                size);
        }
    }

    return (EC_TRUE);
}

EC_BOOL task_rsp_func_para_encode(const UINT32 comm, const UINT32 func_para_num, FUNC_PARA *func_para_tbl, const FUNC_ADDR_NODE *func_addr_node, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
    FUNC_PARA *func_para;
    UINT32 para_idx;

    TYPE_CONV_ITEM *type_conv_item;

    if(EMB_NUM_OF_FUNC_PARAS == func_addr_node->func_para_num)
    {
        FUNC_ADDR_NODE *ui_func_addr_node;
        UINT32          ui_func_id;

        /*format e.g. tbd_run(tbd_md_id, ui_func_retval_addr, ui_func_id, para_1,....)*/
        ui_func_id = (func_para_tbl + 2)->para_val;
        if(0 != dbg_fetch_func_addr_node_by_index(ui_func_id, &ui_func_addr_node))
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_rsp_func_para_encode: failed to fetch user func addr node by func id %lx\n", ui_func_id);
            return (EC_FALSE);
        }

        /*the 1st para must be container module id*/
        func_para = (func_para_tbl + 0);
        /*ignore E_DIRECT_IN parameter encoding of task_rsp*/

        /*the 2nd para must be user interface/function retval addr*/
        func_para = (func_para_tbl + 1);
        if(e_dbg_void != ui_func_addr_node->func_ret_type)
        {
            type_conv_item = dbg_query_type_conv_item_by_type(ui_func_addr_node->func_ret_type);
            if( NULL_PTR == type_conv_item )
            {
                dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT,"error:task_rsp_func_para_encode: ret type %ld conv item is not defined\n",
                        ui_func_addr_node->func_ret_type);
                return (EC_FALSE);
            }

            dbg_tiny_caller(5,
                TYPE_CONV_ITEM_VAR_ENCODE_FUNC(type_conv_item),
                comm,
                func_para->para_val,
                out_buff,
                out_buff_max_len,
                position);

            if(EC_TRUE == TYPE_CONV_ITEM_VAR_POINTER_FLAG(type_conv_item))
            {
                dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_rsp_func_para_encode: ret type MUST NOT be pointer of func id %lx\n", ui_func_addr_node->func_index);
                return (EC_FALSE);
            }
        }

        /*the 3rd para must be user interface/function id*/
        func_para = (func_para_tbl + 2);
        /*ignore E_DIRECT_IN parameter encoding of task_rsp*/

        /*recursively*/
        return task_rsp_func_para_encode(comm, ui_func_addr_node->func_para_num, func_para_tbl + 3, ui_func_addr_node, out_buff, out_buff_max_len, position);
    }

    for( para_idx = 0; para_idx < func_para_num; para_idx ++ )
    {
        type_conv_item = dbg_query_type_conv_item_by_type(func_addr_node->func_para_type[ para_idx ]);
        if( NULL_PTR == type_conv_item )
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT,"error:task_rsp_func_para_encode: para %ld type %ld conv item is not defined\n",
                    para_idx, func_addr_node->func_para_type[ para_idx ]);
            return (EC_FALSE);
        }
        func_para = (func_para_tbl + para_idx);

        if(E_DIRECT_OUT == func_para->para_dir || E_DIRECT_IO == func_para->para_dir)
        {
            dbg_tiny_caller(5,
                TYPE_CONV_ITEM_VAR_ENCODE_FUNC(type_conv_item),
                comm,
                func_para->para_val,
                out_buff,
                out_buff_max_len,
                position);
        }

        /*IN & OUT parameter memory must cleanup here*/
        if(EC_TRUE == TYPE_CONV_ITEM_VAR_POINTER_FLAG(type_conv_item) && 0 != func_para->para_val)
        {
            dbg_tiny_caller(1, TYPE_CONV_ITEM_VAR_CLEAN_FUNC(type_conv_item), func_para->para_val);/*WARNING: SHOULD NOT BE 0*/
            free_static_mem(TYPE_CONV_ITEM_VAR_MM_TYPE(type_conv_item), (void *)func_para->para_val, LOC_TASK_0014);/*clean up*/
            func_para->para_val = 0;
        }
    }

    return (EC_TRUE);
}

EC_BOOL task_rsp_func_para_decode0(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, const UINT32 func_para_num, FUNC_PARA *task_req_func_para_tbl, FUNC_PARA *task_rsp_func_para_tbl, const FUNC_ADDR_NODE *func_addr_node)
{
    FUNC_PARA *task_req_func_para;
    UINT32 para_idx;

    TYPE_CONV_ITEM *type_conv_item;

    if(EMB_NUM_OF_FUNC_PARAS == func_addr_node->func_para_num)
    {
        FUNC_ADDR_NODE *ui_func_addr_node;
        UINT32          ui_func_id;

        /*format e.g. tbd_run(tbd_md_id, ui_func_retval_addr, ui_func_id, para_1,....)*/
        ui_func_id = (task_req_func_para_tbl + 2)->para_val;
        if(0 != dbg_fetch_func_addr_node_by_index(ui_func_id, &ui_func_addr_node))
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_rsp_func_para_decode: failed to fetch user func addr node by func id %lx\n", ui_func_id);
            return (EC_FALSE);
        }

        /*the 1st para must be container module id*/
        task_req_func_para = (task_req_func_para_tbl + 0);
        /*ignore E_DIRECT_IN parameter encoding of task_rsp*/

        /*the 2nd para must be user interface/function retval addr*/
        task_req_func_para = (task_req_func_para_tbl + 1);
        if(e_dbg_void != ui_func_addr_node->func_ret_type)
        {
            if(0 == task_req_func_para->para_val)
            {

                dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_rsp_func_para_decode: task_req_func_para para_val must not be null!\n");
                exit(0);/*coding bug, user should fix it*/
            }

            type_conv_item = dbg_query_type_conv_item_by_type(ui_func_addr_node->func_ret_type);
            if( NULL_PTR == type_conv_item )
            {
                dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT,"error:task_rsp_func_para_decode: ret type %ld conv item is not defined\n",
                        ui_func_addr_node->func_ret_type);
                return (EC_FALSE);
            }
            dbg_tiny_caller(5,
                    TYPE_CONV_ITEM_VAR_DECODE_FUNC(type_conv_item),
                    comm,
                    in_buff,
                    in_buff_max_len,
                    position,
                    task_req_func_para->para_val);
        }

        /*the 3rd para must be user interface/function id*/
        task_req_func_para = (task_req_func_para_tbl + 2);
        /*ignore E_DIRECT_IN parameter encoding of task_rsp*/

        /*recursively*/
        return task_rsp_func_para_decode(comm, in_buff, in_buff_max_len, position, ui_func_addr_node->func_para_num, (task_req_func_para_tbl + 3), /*(task_rsp_func_para_tbl + 3), */ui_func_addr_node);
    }

    for( para_idx = 0; para_idx < func_para_num; para_idx ++ )
    {
        task_req_func_para = (task_req_func_para_tbl + para_idx);

        if(E_DIRECT_OUT == func_addr_node->func_para_direction[ para_idx ] || E_DIRECT_IO == func_addr_node->func_para_direction[ para_idx ])
        {
            type_conv_item = dbg_query_type_conv_item_by_type(func_addr_node->func_para_type[ para_idx ]);
            if( NULL_PTR == type_conv_item )
            {
                dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT,"error:task_rsp_func_para_decode: para %ld type %ld conv item is not defined\n",
                        para_idx, func_addr_node->func_para_type[ para_idx ]);
                return (EC_FALSE);
            }
            dbg_tiny_caller(5,
                    TYPE_CONV_ITEM_VAR_DECODE_FUNC(type_conv_item),
                    comm,
                    in_buff,
                    in_buff_max_len,
                    position,
                    task_req_func_para->para_val);
        }
    }

    return (EC_TRUE);
}

EC_BOOL task_rsp_func_para_decode(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, const UINT32 func_para_num, FUNC_PARA *task_req_func_para_tbl, const FUNC_ADDR_NODE *func_addr_node)
{
    FUNC_PARA *task_req_func_para;
    UINT32 para_idx;

    TYPE_CONV_ITEM *type_conv_item;

    if(EMB_NUM_OF_FUNC_PARAS == func_addr_node->func_para_num)
    {
        FUNC_ADDR_NODE *ui_func_addr_node;
        UINT32          ui_func_id;

        /*format e.g. tbd_run(tbd_md_id, ui_func_retval_addr, ui_func_id, para_1,....)*/
        ui_func_id = (task_req_func_para_tbl + 2)->para_val;
        if(0 != dbg_fetch_func_addr_node_by_index(ui_func_id, &ui_func_addr_node))
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_rsp_func_para_decode: failed to fetch user func addr node by func id %lx\n", ui_func_id);
            return (EC_FALSE);
        }

        /*the 1st para must be container module id*/
        task_req_func_para = (task_req_func_para_tbl + 0);
        /*ignore E_DIRECT_IN parameter encoding of task_rsp*/

        /*the 2nd para must be user interface/function retval addr*/
        task_req_func_para = (task_req_func_para_tbl + 1);
        if(e_dbg_void != ui_func_addr_node->func_ret_type)
        {
            if(0 == task_req_func_para->para_val)
            {

                dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_rsp_func_para_decode: task_req_func_para para_val must not be null!\n");
                exit(0);/*coding bug, user should fix it*/
            }

            type_conv_item = dbg_query_type_conv_item_by_type(ui_func_addr_node->func_ret_type);
            if( NULL_PTR == type_conv_item )
            {
                dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT,"error:task_rsp_func_para_decode: ret type %ld conv item is not defined\n",
                        ui_func_addr_node->func_ret_type);
                return (EC_FALSE);
            }
            dbg_tiny_caller(5,
                    TYPE_CONV_ITEM_VAR_DECODE_FUNC(type_conv_item),
                    comm,
                    in_buff,
                    in_buff_max_len,
                    position,
                    task_req_func_para->para_val);
        }

        /*the 3rd para must be user interface/function id*/
        task_req_func_para = (task_req_func_para_tbl + 2);
        /*ignore E_DIRECT_IN parameter encoding of task_rsp*/

        /*recursively*/
        return task_rsp_func_para_decode(comm, in_buff, in_buff_max_len, position, ui_func_addr_node->func_para_num, (task_req_func_para_tbl + 3), ui_func_addr_node);
    }

    for( para_idx = 0; para_idx < func_para_num; para_idx ++ )
    {
        task_req_func_para = (task_req_func_para_tbl + para_idx);

        if(E_DIRECT_OUT == func_addr_node->func_para_direction[ para_idx ] || E_DIRECT_IO == func_addr_node->func_para_direction[ para_idx ])
        {
            type_conv_item = dbg_query_type_conv_item_by_type(func_addr_node->func_para_type[ para_idx ]);
            if( NULL_PTR == type_conv_item )
            {
                dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT,"error:task_rsp_func_para_decode: para %ld type %ld conv item is not defined\n",
                        para_idx, func_addr_node->func_para_type[ para_idx ]);
                return (EC_FALSE);
            }
            dbg_tiny_caller(5,
                    TYPE_CONV_ITEM_VAR_DECODE_FUNC(type_conv_item),
                    comm,
                    in_buff,
                    in_buff_max_len,
                    position,
                    task_req_func_para->para_val);
        }
    }

    return (EC_TRUE);
}

EC_BOOL task_rsp_encode_size(TASK_RSP *task_rsp, FUNC_ADDR_NODE *func_addr_node, UINT32 *size)
{
    TASK_FUNC *task_rsp_func;

    TYPE_CONV_ITEM *type_conv_item;
    UINT32 send_comm;

    task_rsp_func = TASK_RSP_FUNC(task_rsp);
    send_comm     = TASK_RSP_SEND_COMM(task_rsp);

    *size = 0;

#if (SWITCH_OFF == TASK_HEADER_COMPRESSED_SWITCH)
    cmpi_encode_uint32_size(send_comm, 0, size);/*len used when forwarding*/
    cmpi_encode_uint32_size(send_comm, 0, size);/*tag used when forwarding*/

    cmpi_encode_uint32_size(send_comm, (TASK_RSP_SEND_TCID(task_rsp)), size);
    cmpi_encode_uint32_size(send_comm, (TASK_RSP_SEND_COMM(task_rsp)), size);
    cmpi_encode_uint32_size(send_comm, (TASK_RSP_SEND_RANK(task_rsp)), size);
    cmpi_encode_uint32_size(send_comm, (TASK_RSP_SEND_MODI(task_rsp)), size);

    cmpi_encode_uint32_size(send_comm, (TASK_RSP_RECV_TCID(task_rsp)), size);
    cmpi_encode_uint32_size(send_comm, (TASK_RSP_RECV_COMM(task_rsp)), size);
    cmpi_encode_uint32_size(send_comm, (TASK_RSP_RECV_RANK(task_rsp)), size);
    cmpi_encode_uint32_size(send_comm, (TASK_RSP_RECV_MODI(task_rsp)), size);

    cmpi_encode_uint32_size(send_comm, (TASK_RSP_LDB_CHOICE(task_rsp)), size);

    cmpi_encode_uint32_size(send_comm, (TASK_RSP_PRIO(task_rsp)), size);
    cmpi_encode_uint32_size(send_comm, (TASK_RSP_TYPE(task_rsp)), size);
    cmpi_encode_uint32_size(send_comm, (TASK_RSP_TAG(task_rsp)), size);
    cmpi_encode_uint32_size(send_comm, (TASK_RSP_SEQNO(task_rsp)), size);
    cmpi_encode_uint32_size(send_comm, (TASK_RSP_SUB_SEQNO(task_rsp)), size);

    cmpi_encode_cload_stat_size(send_comm, (TASK_RSP_CLOAD_STAT(task_rsp)), size);
    cmpi_encode_uint32_size(send_comm, (TASK_RSP_TIME_TO_LIVE(task_rsp)), size);

    cmpi_encode_uint32_size(send_comm, (TASK_RSP_FUNC_ID(task_rsp)), size);
    cmpi_encode_uint32_size(send_comm, (TASK_RSP_FUNC_PARA_NUM(task_rsp)), size);
#endif/*(SWITCH_OFF == TASK_HEADER_COMPRESSED_SWITCH)*/

#if (SWITCH_ON == TASK_HEADER_COMPRESSED_SWITCH)
    cmpi_encode_uint32_compressed_uint32_t_size(send_comm, 0, size);/*len used when forwarding*/
    cmpi_encode_uint32_compressed_uint8_t_size(send_comm, 0, size);/*tag used when forwarding*/

    cmpi_encode_uint32_compressed_uint32_t_size(send_comm, (TASK_RSP_SEND_TCID(task_rsp)), size);
    cmpi_encode_uint32_compressed_uint8_t_size(send_comm, (TASK_RSP_SEND_COMM(task_rsp)), size);
    cmpi_encode_uint32_compressed_uint8_t_size(send_comm, (TASK_RSP_SEND_RANK(task_rsp)), size);
    cmpi_encode_uint32_compressed_uint16_t_size(send_comm, (TASK_RSP_SEND_MODI(task_rsp)), size);

    cmpi_encode_uint32_compressed_uint32_t_size(send_comm, (TASK_RSP_RECV_TCID(task_rsp)), size);
    cmpi_encode_uint32_compressed_uint8_t_size(send_comm, (TASK_RSP_RECV_COMM(task_rsp)), size);
    cmpi_encode_uint32_compressed_uint8_t_size(send_comm, (TASK_RSP_RECV_RANK(task_rsp)), size);
    cmpi_encode_uint32_compressed_uint16_t_size(send_comm, (TASK_RSP_RECV_MODI(task_rsp)), size);

    cmpi_encode_uint32_compressed_uint8_t_size(send_comm, (TASK_RSP_LDB_CHOICE(task_rsp)), size);

    cmpi_encode_uint32_compressed_uint8_t_size(send_comm, (TASK_RSP_PRIO(task_rsp)), size);
    cmpi_encode_uint32_compressed_uint8_t_size(send_comm, (TASK_RSP_TYPE(task_rsp)), size);
    cmpi_encode_uint32_compressed_uint8_t_size(send_comm, (TASK_RSP_TAG(task_rsp)), size);
    cmpi_encode_uint32_size(send_comm, (TASK_RSP_SEQNO(task_rsp)), size);
    cmpi_encode_uint32_size(send_comm, (TASK_RSP_SUB_SEQNO(task_rsp)), size);

    //cmpi_encode_cload_stat_size(send_comm, (TASK_RSP_CLOAD_STAT(task_rsp)), size);
    cmpi_encode_uint32_size(send_comm, (TASK_RSP_TIME_TO_LIVE(task_rsp)), size);

    //cmpi_encode_uint32_size(send_comm, (TASK_RSP_FUNC_ID(task_rsp)), size);
    if(1)
    {
        cmpi_encode_uint32_compressed_uint16_t_size(send_comm, UINT32_HI(TASK_RSP_FUNC_ID(task_rsp)), size);
        cmpi_encode_uint32_compressed_uint16_t_size(send_comm, UINT32_LO(TASK_RSP_FUNC_ID(task_rsp)), size);
    }
    cmpi_encode_uint32_compressed_uint8_t_size(send_comm, (TASK_RSP_FUNC_PARA_NUM(task_rsp)), size);
#endif/*(SWITCH_ON == TASK_HEADER_COMPRESSED_SWITCH)*/

    if(e_dbg_void != func_addr_node->func_ret_type)
    {
        type_conv_item = dbg_query_type_conv_item_by_type(func_addr_node->func_ret_type);
        if( NULL_PTR == type_conv_item )
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT,"error:task_rsp_encode_size: ret type %ld conv item is not defined\n",
                    func_addr_node->func_ret_type);
            return (EC_FALSE);
        }
        dbg_tiny_caller(3,
            TYPE_CONV_ITEM_VAR_ENCODE_SIZE(type_conv_item),
            send_comm,
            task_rsp_func->func_ret_val,
            size);
    }

    task_rsp_func_para_encode_size(send_comm, task_rsp_func->func_para_num, (FUNC_PARA *)task_rsp_func->func_para, func_addr_node, size);

    return (EC_TRUE);
}

EC_BOOL task_rsp_encode(TASK_RSP *task_rsp)
{
    TASK_NODE *task_rsp_node;
    TASK_FUNC *task_rsp_func;

    FUNC_ADDR_NODE *func_addr_node;

    TYPE_CONV_ITEM *type_conv_item;
    UINT32 send_comm;

    UINT8  *out_buff;
    UINT32  out_buff_len;
    UINT32  position;

    task_rsp_func    = TASK_RSP_FUNC(task_rsp);
    task_rsp_node    = TASK_RSP_NODE(task_rsp);
    func_addr_node   = TASK_RSP_FUNC_ADDR_NODE(task_rsp);

    out_buff         = TASK_NODE_BUFF(task_rsp_node);
    out_buff_len     = TASK_NODE_BUFF_LEN(task_rsp_node);

    send_comm = TASK_RSP_SEND_COMM(task_rsp);

    position = 0;

#if (SWITCH_OFF == TASK_HEADER_COMPRESSED_SWITCH)
    cmpi_encode_uint32(send_comm, (out_buff_len), out_buff, out_buff_len, &(position));/*len used when forwarding*/
    cmpi_encode_uint32(send_comm, (TASK_RSP_TAG(task_rsp)), out_buff, out_buff_len, &(position));/*tag will be modifed when forwarding*/

    cmpi_encode_uint32(send_comm, (TASK_RSP_SEND_TCID(task_rsp)), out_buff, out_buff_len, &(position));
    cmpi_encode_uint32(send_comm, (TASK_RSP_SEND_COMM(task_rsp)), out_buff, out_buff_len, &(position));
    cmpi_encode_uint32(send_comm, (TASK_RSP_SEND_RANK(task_rsp)), out_buff, out_buff_len, &(position));
    cmpi_encode_uint32(send_comm, (TASK_RSP_SEND_MODI(task_rsp)), out_buff, out_buff_len, &(position));

    cmpi_encode_uint32(send_comm, (TASK_RSP_RECV_TCID(task_rsp)), out_buff, out_buff_len, &(position));
    cmpi_encode_uint32(send_comm, (TASK_RSP_RECV_COMM(task_rsp)), out_buff, out_buff_len, &(position));
    cmpi_encode_uint32(send_comm, (TASK_RSP_RECV_RANK(task_rsp)), out_buff, out_buff_len, &(position));
    cmpi_encode_uint32(send_comm, (TASK_RSP_RECV_MODI(task_rsp)), out_buff, out_buff_len, &(position));

    cmpi_encode_uint32(send_comm, (TASK_RSP_LDB_CHOICE(task_rsp)), out_buff, out_buff_len, &(position));

    cmpi_encode_uint32(send_comm, (TASK_RSP_PRIO(task_rsp)), out_buff, out_buff_len, &(position));
    cmpi_encode_uint32(send_comm, (TASK_RSP_TYPE(task_rsp)), out_buff, out_buff_len, &(position));
    cmpi_encode_uint32(send_comm, (TASK_RSP_TAG(task_rsp)), out_buff, out_buff_len, &(position));
    cmpi_encode_uint32(send_comm, (TASK_RSP_SEQNO(task_rsp)), out_buff, out_buff_len, &(position));
    cmpi_encode_uint32(send_comm, (TASK_RSP_SUB_SEQNO(task_rsp)), out_buff, out_buff_len, &(position));

    cmpi_encode_cload_stat(send_comm, (TASK_RSP_CLOAD_STAT(task_rsp)), out_buff, out_buff_len, &(position));
    cmpi_encode_uint32(send_comm, (TASK_RSP_TIME_TO_LIVE(task_rsp)), out_buff, out_buff_len, &(position));

    cmpi_encode_uint32(send_comm, (TASK_RSP_FUNC_ID(task_rsp)), out_buff, out_buff_len, &(position));
    cmpi_encode_uint32(send_comm, (TASK_RSP_FUNC_PARA_NUM(task_rsp)), out_buff, out_buff_len, &(position));
#endif/*(SWITCH_OFF == TASK_HEADER_COMPRESSED_SWITCH)*/

#if (SWITCH_ON == TASK_HEADER_COMPRESSED_SWITCH)
    cmpi_encode_uint32_compressed_uint32_t(send_comm, (out_buff_len), out_buff, out_buff_len, &(position));/*len used when forwarding*/
    cmpi_encode_uint32_compressed_uint8_t(send_comm, (TASK_RSP_TAG(task_rsp)), out_buff, out_buff_len, &(position));/*tag will be modifed when forwarding*/

    cmpi_encode_uint32_compressed_uint32_t(send_comm, (TASK_RSP_SEND_TCID(task_rsp)), out_buff, out_buff_len, &(position));
    cmpi_encode_uint32_compressed_uint8_t(send_comm, (TASK_RSP_SEND_COMM(task_rsp)), out_buff, out_buff_len, &(position));
    cmpi_encode_uint32_compressed_uint8_t(send_comm, (TASK_RSP_SEND_RANK(task_rsp)), out_buff, out_buff_len, &(position));
    cmpi_encode_uint32_compressed_uint16_t(send_comm, (TASK_RSP_SEND_MODI(task_rsp)), out_buff, out_buff_len, &(position));

    cmpi_encode_uint32_compressed_uint32_t(send_comm, (TASK_RSP_RECV_TCID(task_rsp)), out_buff, out_buff_len, &(position));
    cmpi_encode_uint32_compressed_uint8_t(send_comm, (TASK_RSP_RECV_COMM(task_rsp)), out_buff, out_buff_len, &(position));
    cmpi_encode_uint32_compressed_uint8_t(send_comm, (TASK_RSP_RECV_RANK(task_rsp)), out_buff, out_buff_len, &(position));
    cmpi_encode_uint32_compressed_uint16_t(send_comm, (TASK_RSP_RECV_MODI(task_rsp)), out_buff, out_buff_len, &(position));

    cmpi_encode_uint32_compressed_uint8_t(send_comm, (TASK_RSP_LDB_CHOICE(task_rsp)), out_buff, out_buff_len, &(position));

    cmpi_encode_uint32_compressed_uint8_t(send_comm, (TASK_RSP_PRIO(task_rsp)), out_buff, out_buff_len, &(position));
    cmpi_encode_uint32_compressed_uint8_t(send_comm, (TASK_RSP_TYPE(task_rsp)), out_buff, out_buff_len, &(position));
    cmpi_encode_uint32_compressed_uint8_t(send_comm, (TASK_RSP_TAG(task_rsp)), out_buff, out_buff_len, &(position));
    cmpi_encode_uint32(send_comm, (TASK_RSP_SEQNO(task_rsp)), out_buff, out_buff_len, &(position));
    cmpi_encode_uint32(send_comm, (TASK_RSP_SUB_SEQNO(task_rsp)), out_buff, out_buff_len, &(position));

    //cmpi_encode_cload_stat(send_comm, (TASK_RSP_CLOAD_STAT(task_rsp)), out_buff, out_buff_len, &(position));
    cmpi_encode_uint32(send_comm, (TASK_RSP_TIME_TO_LIVE(task_rsp)), out_buff, out_buff_len, &(position));

    //cmpi_encode_uint32(send_comm, (TASK_RSP_FUNC_ID(task_rsp)), out_buff, out_buff_len, &(position));
    if(1)
    {
        cmpi_encode_uint32_compressed_uint16_t(send_comm, UINT32_HI(TASK_RSP_FUNC_ID(task_rsp)), out_buff, out_buff_len, &(position));
        cmpi_encode_uint32_compressed_uint16_t(send_comm, UINT32_LO(TASK_RSP_FUNC_ID(task_rsp)), out_buff, out_buff_len, &(position));
    }
    cmpi_encode_uint32_compressed_uint8_t(send_comm, (TASK_RSP_FUNC_PARA_NUM(task_rsp)), out_buff, out_buff_len, &(position));
#endif/*(SWITCH_ON == TASK_HEADER_COMPRESSED_SWITCH)*/

    if(e_dbg_void != func_addr_node->func_ret_type)
    {
        type_conv_item = dbg_query_type_conv_item_by_type(func_addr_node->func_ret_type);
        if( NULL_PTR == type_conv_item )
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT,"error:task_rsp_encode: ret type %ld conv item is not defined\n",
                    func_addr_node->func_ret_type);
            return (EC_FALSE);
        }

        dbg_tiny_caller(5,
            TYPE_CONV_ITEM_VAR_ENCODE_FUNC(type_conv_item),
            send_comm,
            task_rsp_func->func_ret_val,
            out_buff,
            out_buff_len,
            &(position));

        if(EC_TRUE == TYPE_CONV_ITEM_VAR_POINTER_FLAG(type_conv_item) && 0 != task_rsp_func->func_ret_val)
        {
            dbg_tiny_caller(1, TYPE_CONV_ITEM_VAR_CLEAN_FUNC(type_conv_item), task_rsp_func->func_ret_val);/*WARNING: SHOULD NOT BE 0*/
            free_static_mem(TYPE_CONV_ITEM_VAR_MM_TYPE(type_conv_item), (void *)task_rsp_func->func_ret_val, LOC_TASK_0015);/*clean up*/
            task_rsp_func->func_ret_val = 0;
        }
    }

    task_rsp_func_para_encode(send_comm, task_rsp_func->func_para_num, (FUNC_PARA *)task_rsp_func->func_para, func_addr_node, out_buff, out_buff_len, &(position));

    TASK_NODE_BUFF_LEN(task_rsp_node) = position;/*set to real length*/
    return (EC_TRUE);
}

void task_rsp_decode_thread_cancel_before_func_addr_node(TASK_REQ *task_req)
{
    TASK_NODE_CMUTEX_LOCK(TASK_REQ_NODE(task_req), LOC_TASK_0016);

    TASK_NODE_STATUS(TASK_REQ_NODE(task_req)) = TASK_REQ_DISCARD;

    TASK_MGR_COUNTER_INC_BY_TASK_REQ(TASK_REQ_MGR(task_req), TASK_MGR_COUNTER_TASK_REQ_DISCARD, task_req, LOC_TASK_0017);

    TASK_NODE_CMUTEX_UNLOCK(TASK_REQ_NODE(task_req), LOC_TASK_0018);

    return;
}

void task_rsp_decode_thread_cancel(TASK_RSP *task_rsp)
{
    TASK_MGR_COUNTER_DEC_BY_TASK_RSP(TASK_RSP_MGR(task_rsp), TASK_MGR_COUNTER_TASK_RSP_RESERVD, task_rsp, LOC_TASK_0019);
    return;
}

EC_BOOL task_rsp_match_task_mgr(const TASK_MGR *task_mgr, const TASK_RSP *task_rsp)
{
    if( TASK_RSP_SEQNO(task_rsp) == TASK_MGR_SEQNO(task_mgr))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL task_rsp_match_task_req_node(const TASK_NODE *task_node, const TASK_RSP *task_rsp)
{
    TASK_REQ *task_req;

    task_req = (TASK_REQ *)TASK_NODE_REQ(task_node);

    if( TASK_RSP_SEND_TCID(task_rsp) == TASK_REQ_RECV_TCID(task_req)
     && (CMPI_ANY_COMM == TASK_REQ_RECV_COMM(task_req) || TASK_RSP_SEND_COMM(task_rsp) == TASK_REQ_RECV_COMM(task_req))
     && TASK_RSP_SEND_RANK(task_rsp) == TASK_REQ_RECV_RANK(task_req)
     && TASK_RSP_SEND_MODI(task_rsp) == TASK_REQ_RECV_MODI(task_req)
     && TASK_RSP_SEQNO(task_rsp)     == TASK_REQ_SEQNO(task_req)
     && TASK_RSP_SUB_SEQNO(task_rsp) == TASK_REQ_SUB_SEQNO(task_req))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL task_rsp_reserve(const TASK_BRD *task_brd, TASK_RSP *task_rsp, TASK_MGR **task_mgr_ret, TASK_REQ **task_req_ret)
{
    CLIST      *task_mgr_list;
    CLIST_DATA *task_mgr_data;
    TASK_MGR   *task_mgr;

    CLIST      *task_queue;
    CLIST_DATA *task_node_data;
    TASK_NODE  *task_node;
    TASK_REQ   *task_req;

    task_mgr_list = (CLIST *)TASK_BRD_RECV_TASK_MGR_LIST(task_brd);

    CLIST_LOCK(task_mgr_list, LOC_TASK_0020);/*1st lock*/
    task_mgr_data = clist_search_front_no_lock(task_mgr_list, (void *)task_rsp, (CLIST_DATA_DATA_CMP)task_rsp_match_task_mgr);
    if(NULL_PTR == task_mgr_data)
    {
        CLIST_UNLOCK(task_mgr_list, LOC_TASK_0021);
        return (EC_FALSE);
    }

    task_mgr = (TASK_MGR *)CLIST_DATA_DATA(task_mgr_data);

    task_queue = TASK_MGR_QUEUE(task_mgr);
    CLIST_LOCK(task_queue, LOC_TASK_0022);/*2nd lock*/
    task_node_data = clist_search_front_no_lock(task_queue, (void *)task_rsp, (CLIST_DATA_DATA_CMP)task_rsp_match_task_req_node);
    if(NULL_PTR == task_node_data)
    {
        CLIST_UNLOCK(task_queue, LOC_TASK_0023);
        CLIST_UNLOCK(task_mgr_list, LOC_TASK_0024);
        return (EC_FALSE);
    }

    task_node = (TASK_NODE *)CLIST_DATA_DATA(task_node_data);
    task_req  = TASK_NODE_REQ(task_node);

    if(TASK_MGR_SEQNO(task_mgr) != TASK_REQ_SEQNO(task_req) || task_mgr != TASK_REQ_MGR(task_req))
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_rsp_reserve: task_mgr %p with seqno %lx, task req %p with seqno %lx.%lx.%lx and task mgr %p\n",
                           task_mgr,
                           TASK_MGR_SEQNO(task_mgr),
                           task_req,
                           TASK_REQ_SEND_TCID(task_req), TASK_REQ_SEND_RANK(task_req), TASK_REQ_SEQNO(task_req), TASK_REQ_MGR(task_req));
        CLIST_UNLOCK(task_queue, LOC_TASK_0025);
        CLIST_UNLOCK(task_mgr_list, LOC_TASK_0026);
        return (EC_FALSE);
    }

    /*mount task_mgr of task_req to task_rsp*/
    TASK_RSP_MGR(task_rsp) = task_mgr;

    *task_mgr_ret = task_mgr;
    *task_req_ret = task_req;

    CLIST_UNLOCK(task_queue, LOC_TASK_0027);
    CLIST_UNLOCK(task_mgr_list, LOC_TASK_0028);
    return (EC_TRUE);
}

EC_BOOL task_rsp_decode_header(TASK_RSP *task_rsp)
{
    TASK_NODE *task_rsp_node;

    UINT8  *in_buff;
    UINT32  in_buff_len;
    UINT32  position;

    UINT32   discard_info;

    UINT32 recv_comm;

    recv_comm = CMPI_ANY_COMM;

    task_rsp_node    = TASK_RSP_NODE(task_rsp);
    in_buff          = TASK_NODE_BUFF(task_rsp_node);
    in_buff_len      = TASK_NODE_BUFF_LEN(task_rsp_node);


    position = 0;

#if (SWITCH_OFF == TASK_HEADER_COMPRESSED_SWITCH)
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(discard_info));/*dicard len info used when forwarding only*/
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(discard_info));/*dicard tag info used when forwarding only*/

    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_RSP_SEND_TCID(task_rsp)));
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_RSP_SEND_COMM(task_rsp)));
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_RSP_SEND_RANK(task_rsp)));
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_RSP_SEND_MODI(task_rsp)));

    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_RSP_RECV_TCID(task_rsp)));
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_RSP_RECV_COMM(task_rsp)));
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_RSP_RECV_RANK(task_rsp)));
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_RSP_RECV_MODI(task_rsp)));

    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_RSP_LDB_CHOICE(task_rsp)));

    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_RSP_PRIO(task_rsp)));
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_RSP_TYPE(task_rsp)));
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_RSP_TAG(task_rsp)));
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_RSP_SEQNO(task_rsp)));
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_RSP_SUB_SEQNO(task_rsp)));

    cmpi_decode_cload_stat(recv_comm, in_buff, in_buff_len, &(position), (TASK_RSP_CLOAD_STAT(task_rsp)));
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_RSP_TIME_TO_LIVE(task_rsp)));

    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_RSP_FUNC_ID(task_rsp)));
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_RSP_FUNC_PARA_NUM(task_rsp)));
#endif/*(SWITCH_OFF == TASK_HEADER_COMPRESSED_SWITCH)*/

#if (SWITCH_ON == TASK_HEADER_COMPRESSED_SWITCH)
    cmpi_decode_uint32_compressed_uint32_t(recv_comm, in_buff, in_buff_len, &(position), &(discard_info));/*dicard len info used when forwarding only*/
    cmpi_decode_uint32_compressed_uint8_t(recv_comm, in_buff, in_buff_len, &(position), &(discard_info));/*dicard tag info used when forwarding only*/

    cmpi_decode_uint32_compressed_uint32_t(recv_comm, in_buff, in_buff_len, &(position), &(TASK_RSP_SEND_TCID(task_rsp)));
    cmpi_decode_uint32_compressed_uint8_t(recv_comm, in_buff, in_buff_len, &(position), &(TASK_RSP_SEND_COMM(task_rsp)));
    cmpi_decode_uint32_compressed_uint8_t(recv_comm, in_buff, in_buff_len, &(position), &(TASK_RSP_SEND_RANK(task_rsp)));
    cmpi_decode_uint32_compressed_uint16_t(recv_comm, in_buff, in_buff_len, &(position), &(TASK_RSP_SEND_MODI(task_rsp)));

    cmpi_decode_uint32_compressed_uint32_t(recv_comm, in_buff, in_buff_len, &(position), &(TASK_RSP_RECV_TCID(task_rsp)));
    cmpi_decode_uint32_compressed_uint8_t(recv_comm, in_buff, in_buff_len, &(position), &(TASK_RSP_RECV_COMM(task_rsp)));
    cmpi_decode_uint32_compressed_uint8_t(recv_comm, in_buff, in_buff_len, &(position), &(TASK_RSP_RECV_RANK(task_rsp)));
    cmpi_decode_uint32_compressed_uint16_t(recv_comm, in_buff, in_buff_len, &(position), &(TASK_RSP_RECV_MODI(task_rsp)));

    cmpi_decode_uint32_compressed_uint8_t(recv_comm, in_buff, in_buff_len, &(position), &(TASK_RSP_LDB_CHOICE(task_rsp)));

    cmpi_decode_uint32_compressed_uint8_t(recv_comm, in_buff, in_buff_len, &(position), &(TASK_RSP_PRIO(task_rsp)));
    cmpi_decode_uint32_compressed_uint8_t(recv_comm, in_buff, in_buff_len, &(position), &(TASK_RSP_TYPE(task_rsp)));
    cmpi_decode_uint32_compressed_uint8_t(recv_comm, in_buff, in_buff_len, &(position), &(TASK_RSP_TAG(task_rsp)));
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_RSP_SEQNO(task_rsp)));
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_RSP_SUB_SEQNO(task_rsp)));

    //cmpi_decode_cload_stat(recv_comm, in_buff, in_buff_len, &(position), (TASK_RSP_CLOAD_STAT(task_rsp)));
    cload_stat_init(TASK_RSP_CLOAD_STAT(task_rsp));
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_RSP_TIME_TO_LIVE(task_rsp)));

    //cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_RSP_FUNC_ID(task_rsp)));
    if(1)
    {
        UINT32      __mod_type;
        UINT32      __mod_id;

        cmpi_decode_uint32_compressed_uint16_t(recv_comm, in_buff, in_buff_len, &(position), &(__mod_type));
        cmpi_decode_uint32_compressed_uint16_t(recv_comm, in_buff, in_buff_len, &(position), &(__mod_id));

        TASK_RSP_FUNC_ID(task_rsp) = UINT32_VAL(__mod_type, __mod_id);
    }
    cmpi_decode_uint32_compressed_uint8_t(recv_comm, in_buff, in_buff_len, &(position), &(TASK_RSP_FUNC_PARA_NUM(task_rsp)));
#endif/*(SWITCH_ON == TASK_HEADER_COMPRESSED_SWITCH)*/


    dbg_log(SEC_0015_TASK, 3)(LOGSTDOUT, "decode rsp: from (tcid %s,comm %ld,rank %ld,modi %ld) to (tcid %s,comm %ld,rank %ld,modi %ld) with priority %ld, type %ld, tag %ld, ldb %ld, seqno %lx.%lx.%lx, subseqno %ld, func id %lx\n",
                    TASK_RSP_SEND_TCID_STR(task_rsp), TASK_RSP_SEND_COMM(task_rsp), TASK_RSP_SEND_RANK(task_rsp), TASK_RSP_SEND_MODI(task_rsp),
                    TASK_RSP_RECV_TCID_STR(task_rsp), TASK_RSP_RECV_COMM(task_rsp), TASK_RSP_RECV_RANK(task_rsp), TASK_RSP_RECV_MODI(task_rsp),
                    TASK_RSP_PRIO(task_rsp), TASK_RSP_TYPE(task_rsp),
                    TASK_RSP_TAG(task_rsp), TASK_RSP_LDB_CHOICE(task_rsp),
                    TASK_RSP_RECV_TCID(task_rsp), TASK_RSP_RECV_RANK(task_rsp), TASK_RSP_SEQNO(task_rsp), TASK_RSP_SUB_SEQNO(task_rsp),
                    TASK_RSP_FUNC_ID(task_rsp)
                    );
    return (EC_TRUE);
}

EC_BOOL task_rsp_decode(const UINT32 recv_comm, TASK_BRD *task_brd, TASK_RSP *task_rsp, TASK_MGR **task_mgr_ret, UINT32 *ret_val_check_succ_flag)
{
    TASK_NODE *task_rsp_node;
    TASK_FUNC *task_rsp_func;

    FUNC_ADDR_NODE *func_addr_node;

    TYPE_CONV_ITEM *type_conv_item;

    UINT8  *in_buff;
    UINT32  in_buff_len;
    UINT32  position;

    TASK_MGR   *task_mgr;

    TASK_REQ   *task_req;
    TASK_FUNC  *task_req_func;

    UINT32   discard_info;

    task_rsp_func    = TASK_RSP_FUNC(task_rsp);
    task_rsp_node    = TASK_RSP_NODE(task_rsp);
    in_buff          = TASK_NODE_BUFF(task_rsp_node);
    in_buff_len      = TASK_NODE_BUFF_LEN(task_rsp_node);

    position = 0;

#if (SWITCH_OFF == TASK_HEADER_COMPRESSED_SWITCH)
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(discard_info));/*dicard len info used when forwarding only*/
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(discard_info));/*dicard tag info used when forwarding only*/

    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_RSP_SEND_TCID(task_rsp)));
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_RSP_SEND_COMM(task_rsp)));
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_RSP_SEND_RANK(task_rsp)));
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_RSP_SEND_MODI(task_rsp)));

    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_RSP_RECV_TCID(task_rsp)));
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_RSP_RECV_COMM(task_rsp)));
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_RSP_RECV_RANK(task_rsp)));
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_RSP_RECV_MODI(task_rsp)));

    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_RSP_LDB_CHOICE(task_rsp)));

    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_RSP_PRIO(task_rsp)));
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_RSP_TYPE(task_rsp)));
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_RSP_TAG(task_rsp)));
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_RSP_SEQNO(task_rsp)));
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_RSP_SUB_SEQNO(task_rsp)));

    cmpi_decode_cload_stat(recv_comm, in_buff, in_buff_len, &(position), (TASK_RSP_CLOAD_STAT(task_rsp)));
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_RSP_TIME_TO_LIVE(task_rsp)));

    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_RSP_FUNC_ID(task_rsp)));
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_RSP_FUNC_PARA_NUM(task_rsp)));
#endif/*(SWITCH_OFF == TASK_HEADER_COMPRESSED_SWITCH)*/

#if (SWITCH_ON == TASK_HEADER_COMPRESSED_SWITCH)
    cmpi_decode_uint32_compressed_uint32_t(recv_comm, in_buff, in_buff_len, &(position), &(discard_info));/*dicard len info used when forwarding only*/
    cmpi_decode_uint32_compressed_uint8_t(recv_comm, in_buff, in_buff_len, &(position), &(discard_info));/*dicard tag info used when forwarding only*/

    cmpi_decode_uint32_compressed_uint32_t(recv_comm, in_buff, in_buff_len, &(position), &(TASK_RSP_SEND_TCID(task_rsp)));
    cmpi_decode_uint32_compressed_uint8_t(recv_comm, in_buff, in_buff_len, &(position), &(TASK_RSP_SEND_COMM(task_rsp)));
    cmpi_decode_uint32_compressed_uint8_t(recv_comm, in_buff, in_buff_len, &(position), &(TASK_RSP_SEND_RANK(task_rsp)));
    cmpi_decode_uint32_compressed_uint16_t(recv_comm, in_buff, in_buff_len, &(position), &(TASK_RSP_SEND_MODI(task_rsp)));

    cmpi_decode_uint32_compressed_uint32_t(recv_comm, in_buff, in_buff_len, &(position), &(TASK_RSP_RECV_TCID(task_rsp)));
    cmpi_decode_uint32_compressed_uint8_t(recv_comm, in_buff, in_buff_len, &(position), &(TASK_RSP_RECV_COMM(task_rsp)));
    cmpi_decode_uint32_compressed_uint8_t(recv_comm, in_buff, in_buff_len, &(position), &(TASK_RSP_RECV_RANK(task_rsp)));
    cmpi_decode_uint32_compressed_uint16_t(recv_comm, in_buff, in_buff_len, &(position), &(TASK_RSP_RECV_MODI(task_rsp)));

    cmpi_decode_uint32_compressed_uint8_t(recv_comm, in_buff, in_buff_len, &(position), &(TASK_RSP_LDB_CHOICE(task_rsp)));

    cmpi_decode_uint32_compressed_uint8_t(recv_comm, in_buff, in_buff_len, &(position), &(TASK_RSP_PRIO(task_rsp)));
    cmpi_decode_uint32_compressed_uint8_t(recv_comm, in_buff, in_buff_len, &(position), &(TASK_RSP_TYPE(task_rsp)));
    cmpi_decode_uint32_compressed_uint8_t(recv_comm, in_buff, in_buff_len, &(position), &(TASK_RSP_TAG(task_rsp)));
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_RSP_SEQNO(task_rsp)));
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_RSP_SUB_SEQNO(task_rsp)));

    //cmpi_decode_cload_stat(recv_comm, in_buff, in_buff_len, &(position), (TASK_RSP_CLOAD_STAT(task_rsp)));
    cload_stat_init(TASK_RSP_CLOAD_STAT(task_rsp));
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_RSP_TIME_TO_LIVE(task_rsp)));

    //cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_RSP_FUNC_ID(task_rsp)));
    if(1)
    {
        UINT32      __mod_type;
        UINT32      __mod_id;

        cmpi_decode_uint32_compressed_uint16_t(recv_comm, in_buff, in_buff_len, &(position), &(__mod_type));
        cmpi_decode_uint32_compressed_uint16_t(recv_comm, in_buff, in_buff_len, &(position), &(__mod_id));

        TASK_RSP_FUNC_ID(task_rsp) = UINT32_VAL(__mod_type, __mod_id);
    }
    cmpi_decode_uint32_compressed_uint8_t(recv_comm, in_buff, in_buff_len, &(position), &(TASK_RSP_FUNC_PARA_NUM(task_rsp)));
#endif/*(SWITCH_ON == TASK_HEADER_COMPRESSED_SWITCH)*/

    dbg_log(SEC_0015_TASK, 3)(LOGSTDOUT, "decode rsp: from (tcid %s,comm %ld,rank %ld,modi %ld) to (tcid %s,comm %ld,rank %ld,modi %ld) with priority %ld, type %ld, tag %ld, ldb %ld, seqno %lx.%lx.%lx, subseqno %ld, func id %lx\n",
                    TASK_RSP_SEND_TCID_STR(task_rsp), TASK_RSP_SEND_COMM(task_rsp), TASK_RSP_SEND_RANK(task_rsp), TASK_RSP_SEND_MODI(task_rsp),
                    TASK_RSP_RECV_TCID_STR(task_rsp), TASK_RSP_RECV_COMM(task_rsp), TASK_RSP_RECV_RANK(task_rsp), TASK_RSP_RECV_MODI(task_rsp),
                    TASK_RSP_PRIO(task_rsp), TASK_RSP_TYPE(task_rsp),
                    TASK_RSP_TAG(task_rsp), TASK_RSP_LDB_CHOICE(task_rsp),
                    TASK_RSP_RECV_TCID(task_rsp), TASK_RSP_RECV_RANK(task_rsp), TASK_RSP_SEQNO(task_rsp), TASK_RSP_SUB_SEQNO(task_rsp),
                    TASK_RSP_FUNC_ID(task_rsp)
                    );

    /*now try to match task_req after has decoded task_rsp header*/
    if(EC_FALSE == task_rsp_reserve(task_brd, task_rsp, &task_mgr, &task_req))
    {
        (*task_mgr_ret) = NULL_PTR;
        return (EC_FALSE);
    }

    TASK_MGR_COUNTER_INC_BY_TASK_RSP(task_mgr, TASK_MGR_COUNTER_TASK_RSP_RESERVD, task_rsp, LOC_TASK_0029);

    CROUTINE_CLEANUP_PUSH(task_rsp_decode_thread_cancel, task_rsp);

    //TASK_MGR_CMUTEX_LOCK(task_mgr, LOC_TASK_0030);
    if(TASK_MGR_COUNTER(task_mgr, TASK_MGR_COUNTER_TASK_RSP_IS_NEED) <= TASK_MGR_COUNTER(task_mgr, TASK_MGR_COUNTER_TASK_RSP_IS_SUCC))
    {
        (*task_mgr_ret) = task_mgr;
        //TASK_MGR_CMUTEX_UNLOCK(task_mgr, LOC_TASK_0031);/*unlock*/
        TASK_MGR_COUNTER_DEC_BY_TASK_RSP(task_mgr, TASK_MGR_COUNTER_TASK_RSP_RESERVD, task_rsp, LOC_TASK_0032);
        return (EC_FALSE);
    }
    //TASK_MGR_CMUTEX_UNLOCK(task_mgr, LOC_TASK_0033);/*unlock*/

    TASK_NODE_CMUTEX_LOCK(TASK_REQ_NODE(task_req), LOC_TASK_0034);
    if( TASK_REQ_DISCARD == TASK_NODE_STATUS(TASK_REQ_NODE(task_req))
      || TASK_REQ_TIMEOUT == TASK_NODE_STATUS(TASK_REQ_NODE(task_req))
    )
    {
        (*task_mgr_ret) = task_mgr;
        TASK_NODE_CMUTEX_UNLOCK(TASK_REQ_NODE(task_req), LOC_TASK_0035);
        TASK_MGR_COUNTER_DEC_BY_TASK_RSP(task_mgr, TASK_MGR_COUNTER_TASK_RSP_RESERVD, task_rsp, LOC_TASK_0036);
        return (EC_FALSE);
    }
    else
    {
        /*set task req state to RSP_DCODING will prevent it from changing to TIMEOUT*/
        TASK_NODE_STATUS(TASK_REQ_NODE(task_req)) = TASK_RSP_DCODING;
    }
    TASK_NODE_CMUTEX_UNLOCK(TASK_REQ_NODE(task_req), LOC_TASK_0037);

    task_req_func  = TASK_REQ_FUNC(task_req);
    func_addr_node = TASK_REQ_FUNC_ADDR_NODE(task_req);

    (*ret_val_check_succ_flag) = EC_TRUE;/*default is checked and passed*/

    CROUTINE_CLEANUP_PUSH(task_rsp_decode_thread_cancel_before_func_addr_node, task_req);

    if(e_dbg_void != func_addr_node->func_ret_type)
    {
        if(0 == task_req_func->func_ret_val)
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_rsp_decode: task_req_func of %lx func_ret_val should not be null\n", task_req_func->func_id);
            exit(0);/*coding bug, user should fix it*/
        }

        type_conv_item = dbg_query_type_conv_item_by_type(func_addr_node->func_ret_type);
        if( NULL_PTR == type_conv_item )
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT,"error:task_rsp_decode: ret type %ld conv item is not defined\n",
                    func_addr_node->func_ret_type);
            return (EC_FALSE);
        }

        dbg_tiny_caller(5,
                TYPE_CONV_ITEM_VAR_DECODE_FUNC(type_conv_item),
                recv_comm,
                in_buff,
                in_buff_len,
                &(position),
                task_req_func->func_ret_val);

        /*check return value in response, the checker is defined by user*/
        if(NULL_PTR != TASK_MGR_RETV_CHECKER(TASK_REQ_MGR(task_req)))
        {
            if(EC_TRUE == TYPE_CONV_ITEM_VAR_POINTER_FLAG(type_conv_item))
            {
                (*ret_val_check_succ_flag) = TASK_MGR_RET_VAL_CHECK(TASK_REQ_MGR(task_req), task_req_func->func_ret_val);
            }
            else
            {
                if(sizeof(UINT32) == TYPE_CONV_ITEM_VAR_SIZEOF(type_conv_item))
                {
                    UINT32 val;

                    val = *((UINT32 *)task_req_func->func_ret_val);
                    (*ret_val_check_succ_flag) = TASK_MGR_RET_VAL_CHECK(TASK_REQ_MGR(task_req), val);
                }
                else if(sizeof(UINT16) == TYPE_CONV_ITEM_VAR_SIZEOF(type_conv_item))
                {
                    UINT16 val;

                    val = *((UINT16 *)task_req_func->func_ret_val);
                    (*ret_val_check_succ_flag) = TASK_MGR_RET_VAL_CHECK(TASK_REQ_MGR(task_req), val);
                }
                else if(sizeof(UINT8) == TYPE_CONV_ITEM_VAR_SIZEOF(type_conv_item))
                {
                    UINT8 val;

                    val = *((UINT8 *)task_req_func->func_ret_val);
                    (*ret_val_check_succ_flag) = TASK_MGR_RET_VAL_CHECK(TASK_REQ_MGR(task_req), val);
                }
                else
                {
                    dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_rsp_decode: type %ld has unknow sizeof %ld\n",
                                        TYPE_CONV_ITEM_VAR_DBG_TYPE(type_conv_item), TYPE_CONV_ITEM_VAR_SIZEOF(type_conv_item));
                }
            }
        }
    }

    task_rsp_func_para_decode(recv_comm, in_buff, in_buff_len, &(position), task_rsp_func->func_para_num, (FUNC_PARA *)task_req_func->func_para, /*(FUNC_PARA *)task_rsp_func->func_para, */func_addr_node);

    CROUTINE_CLEANUP_POP( 0 );

    /*update task req status*/
    TASK_NODE_STATUS(TASK_REQ_NODE(task_req)) = TASK_RSP_IS_RECV;

    TASK_MGR_COUNTER_DEC_BY_TASK_RSP(task_mgr, TASK_MGR_COUNTER_TASK_RSP_RESERVD, task_rsp, LOC_TASK_0038);

    CROUTINE_CLEANUP_POP( 0 );

    (*task_mgr_ret) = task_mgr;
    return (EC_TRUE);
}

EC_BOOL task_rsp_isend(TASK_BRD *task_brd, TASK_RSP *task_rsp)
{
    dbg_log(SEC_0015_TASK, 6)(LOGSTDOUT, "isend  rsp: from (tcid %s,comm %ld,rank %ld,modi %ld) to (tcid %s,comm %ld,rank %ld,modi %ld) with priority %ld, type %ld, tag %ld, ldb %ld, seqno %lx.%lx.%lx, subseqno %ld, func id %lx\n",
                    TASK_RSP_SEND_TCID_STR(task_rsp), TASK_RSP_SEND_COMM(task_rsp), TASK_RSP_SEND_RANK(task_rsp), TASK_RSP_SEND_MODI(task_rsp),
                    TASK_RSP_RECV_TCID_STR(task_rsp), TASK_RSP_RECV_COMM(task_rsp), TASK_RSP_RECV_RANK(task_rsp), TASK_RSP_RECV_MODI(task_rsp),
                    TASK_RSP_PRIO(task_rsp), TASK_RSP_TYPE(task_rsp),
                    TASK_RSP_TAG(task_rsp), TASK_RSP_LDB_CHOICE(task_rsp),
                    TASK_RSP_RECV_TCID(task_rsp), TASK_RSP_RECV_RANK(task_rsp), TASK_RSP_SEQNO(task_rsp), TASK_RSP_SUB_SEQNO(task_rsp),
                    TASK_RSP_FUNC_ID(task_rsp)
                    );

    return task_node_isend(task_brd, TASK_RSP_NODE(task_rsp));
}

UINT32 task_rsp_time_elapsed(const TASK_RSP *task_rsp)
{
    CTIMET cur;

    if(TASK_ALWAYS_LIVE == TASK_RSP_TIME_TO_LIVE(task_rsp))
    {
        /*never timeout*/
        return (0);
    }

    CTIMET_GET(cur);
    return lrint(CTIMET_DIFF(TASK_RSP_START_TIME(task_rsp), cur));
}

UINT32 task_rsp_time_left(const TASK_RSP *task_rsp)
{
    CTIMET cur;

    if(TASK_ALWAYS_LIVE == TASK_RSP_TIME_TO_LIVE(task_rsp))
    {
        /*never timeout*/
        return (TASK_ALWAYS_LIVE);
    }

    CTIMET_GET(cur);
    return (TASK_RSP_TIME_TO_LIVE(task_rsp) - lrint(CTIMET_DIFF(TASK_RSP_START_TIME(task_rsp), cur)));
}

EC_BOOL task_rsp_is_timeout(const TASK_RSP *task_rsp)
{
    CTIMET cur;

    if(TASK_ALWAYS_LIVE == TASK_RSP_TIME_TO_LIVE(task_rsp))
    {
        /*never timeout*/
        return (EC_FALSE);
    }

    CTIMET_GET(cur);

    if(CTIMET_DIFF(TASK_RSP_START_TIME(task_rsp), cur) >= 0.0 + TASK_RSP_TIME_TO_LIVE(task_rsp))
    {
        /*time out*/
        return (EC_TRUE);
    }

    /*not timeout*/
    return (EC_FALSE);
}

EC_BOOL task_rsp_md_mod_mgr_get(TASK_BRD *task_brd, TASK_RSP *task_rsp, MOD_MGR **mod_mgr)
{
    TASK_FUNC *task_rsp_func;

    MOD_MGR *md_mod_mgr;

    UINT32 md_id;
    UINT32 md_type;
    FUNC_ADDR_MGR *func_addr_mgr;

    task_rsp_func = TASK_RSP_FUNC(task_rsp);
    md_type = (task_rsp_func->func_id >> (WORDSIZE / 2)); /*refer findex.inc*/
    func_addr_mgr = TASK_BRD_MD_NODE_GET(task_brd, md_type);

    /*when func invocation in task_rsp is module start or end, then return nothing*/
    if(task_rsp_func->func_id == func_addr_mgr->md_start_func_id
    || task_rsp_func->func_id == func_addr_mgr->md_end_func_id
    || task_rsp_func->func_id == func_addr_mgr->md_set_mod_mgr_func_id)
    {
        *mod_mgr = (MOD_MGR *)0;
        return (EC_FALSE);
    }

    md_id = TASK_RSP_SEND_MODI(task_rsp);
    if(0 == func_addr_mgr->md_fget_mod_mgr)
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDERR, "error:task_rsp_md_mod_mgr_get: func_addr_mgr %p not define md_fget_mod_mgr\n", func_addr_mgr);
        *mod_mgr = (MOD_MGR *)0;
        return (EC_FALSE);
    }
    md_mod_mgr = (MOD_MGR *)(func_addr_mgr->md_fget_mod_mgr)(md_id);
    //dbg_log(SEC_0015_TASK, 5)(LOGSTDOUT, "task_rsp_md_mod_mgr_get: md_type %ld, md_id %ld, md_mod_mgr %p\n", md_type, md_id, md_mod_mgr);

    *mod_mgr = md_mod_mgr;
    return (EC_TRUE);
}

EC_BOOL task_fwd_free(TASK_FWD *task_fwd)
{
    TASK_NODE *task_fwd_node;

    task_fwd_node = TASK_FWD_NODE(task_fwd);
    task_node_free(task_fwd_node);

    return (EC_TRUE);
}

EC_BOOL task_fwd_isend(TASK_BRD *task_brd, TASK_FWD *task_fwd)
{
    switch(TASK_FWD_TAG(task_fwd))
    {
    case TAG_TASK_REQ:
    dbg_log(SEC_0015_TASK, 6)(LOGSTDOUT, "isend  fwd: from (tcid %s,comm %ld,rank %ld,modi %ld) to (tcid %s,comm %ld,rank %ld,modi %ld) with priority %ld, type %ld, tag %ld, ldb %ld, seqno %lx.%lx.%lx, subseqno %ld, func id %lx\n",
                    TASK_FWD_SEND_TCID_STR(task_fwd), TASK_FWD_SEND_COMM(task_fwd), TASK_FWD_SEND_RANK(task_fwd), TASK_FWD_SEND_MODI(task_fwd),
                    TASK_FWD_RECV_TCID_STR(task_fwd), TASK_FWD_RECV_COMM(task_fwd), TASK_FWD_RECV_RANK(task_fwd), TASK_FWD_RECV_MODI(task_fwd),
                    TASK_FWD_PRIO(task_fwd), TASK_FWD_TYPE(task_fwd),
                    TASK_FWD_TAG(task_fwd), TASK_FWD_LDB_CHOICE(task_fwd),
                    TASK_FWD_SEND_TCID(task_fwd), TASK_FWD_SEND_RANK(task_fwd), TASK_FWD_SEQNO(task_fwd), TASK_FWD_SUB_SEQNO(task_fwd),
                    TASK_FWD_FUNC_ID(task_fwd)
                    );
    break;

    case TAG_TASK_RSP:
    dbg_log(SEC_0015_TASK, 6)(LOGSTDOUT, "isend  fwd: from (tcid %s,comm %ld,rank %ld,modi %ld) to (tcid %s,comm %ld,rank %ld,modi %ld) with priority %ld, type %ld, tag %ld, ldb %ld, seqno %lx.%lx.%lx, subseqno %ld, func id %lx\n",
                    TASK_FWD_SEND_TCID_STR(task_fwd), TASK_FWD_SEND_COMM(task_fwd), TASK_FWD_SEND_RANK(task_fwd), TASK_FWD_SEND_MODI(task_fwd),
                    TASK_FWD_RECV_TCID_STR(task_fwd), TASK_FWD_RECV_COMM(task_fwd), TASK_FWD_RECV_RANK(task_fwd), TASK_FWD_RECV_MODI(task_fwd),
                    TASK_FWD_PRIO(task_fwd), TASK_FWD_TYPE(task_fwd),
                    TASK_FWD_TAG(task_fwd), TASK_FWD_LDB_CHOICE(task_fwd),
                    TASK_FWD_RECV_TCID(task_fwd), TASK_FWD_RECV_RANK(task_fwd), TASK_FWD_SEQNO(task_fwd), TASK_FWD_SUB_SEQNO(task_fwd),
                    TASK_FWD_FUNC_ID(task_fwd)
                    );
    break;

    case TAG_TASK_FWD:
    dbg_log(SEC_0015_TASK, 6)(LOGSTDOUT, "isend  fwd: from (tcid %s,comm %ld,rank %ld,modi %ld) to (tcid %s,comm %ld,rank %ld,modi %ld) with priority %ld, type %ld, tag %ld, ldb %ld, seqno fwd.%lx.%lx.%lx, subseqno %ld, func id %lx\n",
                    TASK_FWD_SEND_TCID_STR(task_fwd), TASK_FWD_SEND_COMM(task_fwd), TASK_FWD_SEND_RANK(task_fwd), TASK_FWD_SEND_MODI(task_fwd),
                    TASK_FWD_RECV_TCID_STR(task_fwd), TASK_FWD_RECV_COMM(task_fwd), TASK_FWD_RECV_RANK(task_fwd), TASK_FWD_RECV_MODI(task_fwd),
                    TASK_FWD_PRIO(task_fwd), TASK_FWD_TYPE(task_fwd),
                    TASK_FWD_TAG(task_fwd), TASK_FWD_LDB_CHOICE(task_fwd),
                    TASK_FWD_SEND_TCID(task_fwd), TASK_FWD_SEND_RANK(task_fwd), TASK_FWD_SEQNO(task_fwd), TASK_FWD_SUB_SEQNO(task_fwd),
                    TASK_FWD_FUNC_ID(task_fwd)
                    );
    break;

    default:
    dbg_log(SEC_0015_TASK, 6)(LOGSTDOUT, "isend  fwd: from (tcid %s,comm %ld,rank %ld,modi %ld) to (tcid %s,comm %ld,rank %ld,modi %ld) with priority %ld, type %ld, tag %ld, ldb %ld, seqno undef.%lx.%lx.%lx, subseqno %ld, func id %lx\n",
                    TASK_FWD_SEND_TCID_STR(task_fwd), TASK_FWD_SEND_COMM(task_fwd), TASK_FWD_SEND_RANK(task_fwd), TASK_FWD_SEND_MODI(task_fwd),
                    TASK_FWD_RECV_TCID_STR(task_fwd), TASK_FWD_RECV_COMM(task_fwd), TASK_FWD_RECV_RANK(task_fwd), TASK_FWD_RECV_MODI(task_fwd),
                    TASK_FWD_PRIO(task_fwd), TASK_FWD_TYPE(task_fwd),
                    TASK_FWD_TAG(task_fwd), TASK_FWD_LDB_CHOICE(task_fwd),
                    TASK_FWD_SEND_TCID(task_fwd), TASK_FWD_SEND_RANK(task_fwd), TASK_FWD_SEQNO(task_fwd), TASK_FWD_SUB_SEQNO(task_fwd),
                    TASK_FWD_FUNC_ID(task_fwd)
                    );
    break;
    }

    return task_node_isend(task_brd, TASK_FWD_NODE(task_fwd));
}

EC_BOOL task_fwd_direct(TASK_BRD *task_brd, TASK_FWD *task_fwd)
{
    TASK_NODE  *task_fwd_node;

    switch(TASK_FWD_TAG(task_fwd))
    {
    case TAG_TASK_REQ:
    dbg_log(SEC_0015_TASK, 6)(LOGSTDOUT, "direct fwd: from (tcid %s,comm %ld,rank %ld,modi %ld) to (tcid %s,comm %ld,rank %ld,modi %ld) with priority %ld, type %ld, tag %ld, ldb %ld, seqno %lx.%lx.%lx, subseqno %ld, func id %lx\n",
                    TASK_FWD_SEND_TCID_STR(task_fwd), TASK_FWD_SEND_COMM(task_fwd), TASK_FWD_SEND_RANK(task_fwd), TASK_FWD_SEND_MODI(task_fwd),
                    TASK_FWD_RECV_TCID_STR(task_fwd), TASK_FWD_RECV_COMM(task_fwd), TASK_FWD_RECV_RANK(task_fwd), TASK_FWD_RECV_MODI(task_fwd),
                    TASK_FWD_PRIO(task_fwd), TASK_FWD_TYPE(task_fwd),
                    TASK_FWD_TAG(task_fwd), TASK_FWD_LDB_CHOICE(task_fwd),
                    TASK_FWD_SEND_TCID(task_fwd), TASK_FWD_SEND_RANK(task_fwd), TASK_FWD_SEQNO(task_fwd), TASK_FWD_SUB_SEQNO(task_fwd),
                    TASK_FWD_FUNC_ID(task_fwd)
                    );
    break;

    case TAG_TASK_RSP:
    dbg_log(SEC_0015_TASK, 6)(LOGSTDOUT, "direct fwd: from (tcid %s,comm %ld,rank %ld,modi %ld) to (tcid %s,comm %ld,rank %ld,modi %ld) with priority %ld, type %ld, tag %ld, ldb %ld, seqno %lx.%lx.%lx, subseqno %ld, func id %lx\n",
                    TASK_FWD_SEND_TCID_STR(task_fwd), TASK_FWD_SEND_COMM(task_fwd), TASK_FWD_SEND_RANK(task_fwd), TASK_FWD_SEND_MODI(task_fwd),
                    TASK_FWD_RECV_TCID_STR(task_fwd), TASK_FWD_RECV_COMM(task_fwd), TASK_FWD_RECV_RANK(task_fwd), TASK_FWD_RECV_MODI(task_fwd),
                    TASK_FWD_PRIO(task_fwd), TASK_FWD_TYPE(task_fwd),
                    TASK_FWD_TAG(task_fwd), TASK_FWD_LDB_CHOICE(task_fwd),
                    TASK_FWD_RECV_TCID(task_fwd), TASK_FWD_RECV_RANK(task_fwd), TASK_FWD_SEQNO(task_fwd), TASK_FWD_SUB_SEQNO(task_fwd),
                    TASK_FWD_FUNC_ID(task_fwd)
                    );
    break;

    case TAG_TASK_FWD:
    dbg_log(SEC_0015_TASK, 6)(LOGSTDOUT, "direct fwd: from (tcid %s,comm %ld,rank %ld,modi %ld) to (tcid %s,comm %ld,rank %ld,modi %ld) with priority %ld, type %ld, tag %ld, ldb %ld, seqno fwd.%lx.%lx.%lx, subseqno %ld, func id %lx\n",
                    TASK_FWD_SEND_TCID_STR(task_fwd), TASK_FWD_SEND_COMM(task_fwd), TASK_FWD_SEND_RANK(task_fwd), TASK_FWD_SEND_MODI(task_fwd),
                    TASK_FWD_RECV_TCID_STR(task_fwd), TASK_FWD_RECV_COMM(task_fwd), TASK_FWD_RECV_RANK(task_fwd), TASK_FWD_RECV_MODI(task_fwd),
                    TASK_FWD_PRIO(task_fwd), TASK_FWD_TYPE(task_fwd),
                    TASK_FWD_TAG(task_fwd), TASK_FWD_LDB_CHOICE(task_fwd),
                    TASK_FWD_SEND_TCID(task_fwd), TASK_FWD_SEND_RANK(task_fwd), TASK_FWD_SEQNO(task_fwd), TASK_FWD_SUB_SEQNO(task_fwd),
                    TASK_FWD_FUNC_ID(task_fwd)
                    );
    break;

    default:
    dbg_log(SEC_0015_TASK, 6)(LOGSTDOUT, "direct fwd: from (tcid %s,comm %ld,rank %ld,modi %ld) to (tcid %s,comm %ld,rank %ld,modi %ld) with priority %ld, type %ld, tag %ld, ldb %ld, seqno undef.%lx.%lx.%lx, subseqno %ld, func id %lx\n",
                    TASK_FWD_SEND_TCID_STR(task_fwd), TASK_FWD_SEND_COMM(task_fwd), TASK_FWD_SEND_RANK(task_fwd), TASK_FWD_SEND_MODI(task_fwd),
                    TASK_FWD_RECV_TCID_STR(task_fwd), TASK_FWD_RECV_COMM(task_fwd), TASK_FWD_RECV_RANK(task_fwd), TASK_FWD_RECV_MODI(task_fwd),
                    TASK_FWD_PRIO(task_fwd), TASK_FWD_TYPE(task_fwd),
                    TASK_FWD_TAG(task_fwd), TASK_FWD_LDB_CHOICE(task_fwd),
                    TASK_FWD_SEND_TCID(task_fwd), TASK_FWD_SEND_RANK(task_fwd), TASK_FWD_SEQNO(task_fwd), TASK_FWD_SUB_SEQNO(task_fwd),
                    TASK_FWD_FUNC_ID(task_fwd)
                    );
    break;
    }

    //task_func_print(LOGSTDNULL, TASK_FWD_FUNC(task_fwd));

    task_fwd_node = TASK_FWD_NODE(task_fwd);

    TASK_NODE_TAG(task_fwd_node) = TASK_FWD_TAG(task_fwd);
    TASK_FWD_CTHREAD_NODE(task_fwd) = NULL_PTR;

    /*update status*/
    TASK_NODE_STATUS(task_fwd_node) = TASK_FWD_RECVING;

    /*update load info when task_fwd commit*/
    load_set_when_task_fwd_commit(task_brd, task_fwd);

    /*TASK_IS_RECV_QUEUE support task priority, here add node by task_queue_add_node*/
    task_queue_add_node(TASK_BRD_QUEUE(task_brd, TASK_RECVING_QUEUE), task_fwd_node);
    return (EC_TRUE);
}

EC_BOOL task_fwd_direct_no_queue(TASK_BRD *task_brd, TASK_FWD *task_fwd)
{
    TASK_NODE  *task_fwd_node;

    switch(TASK_FWD_TAG(task_fwd))
    {
    case TAG_TASK_REQ:
    dbg_log(SEC_0015_TASK, 6)(LOGSTDOUT, "direct fwd: from (tcid %s,comm %ld,rank %ld,modi %ld) to (tcid %s,comm %ld,rank %ld,modi %ld) with priority %ld, type %ld, tag %ld, ldb %ld, seqno %lx.%lx.%lx, subseqno %ld, func id %lx\n",
                    TASK_FWD_SEND_TCID_STR(task_fwd), TASK_FWD_SEND_COMM(task_fwd), TASK_FWD_SEND_RANK(task_fwd), TASK_FWD_SEND_MODI(task_fwd),
                    TASK_FWD_RECV_TCID_STR(task_fwd), TASK_FWD_RECV_COMM(task_fwd), TASK_FWD_RECV_RANK(task_fwd), TASK_FWD_RECV_MODI(task_fwd),
                    TASK_FWD_PRIO(task_fwd), TASK_FWD_TYPE(task_fwd),
                    TASK_FWD_TAG(task_fwd), TASK_FWD_LDB_CHOICE(task_fwd),
                    TASK_FWD_SEND_TCID(task_fwd), TASK_FWD_SEND_RANK(task_fwd), TASK_FWD_SEQNO(task_fwd), TASK_FWD_SUB_SEQNO(task_fwd),
                    TASK_FWD_FUNC_ID(task_fwd)
                    );
    break;

    case TAG_TASK_RSP:
    dbg_log(SEC_0015_TASK, 6)(LOGSTDOUT, "direct fwd: from (tcid %s,comm %ld,rank %ld,modi %ld) to (tcid %s,comm %ld,rank %ld,modi %ld) with priority %ld, type %ld, tag %ld, ldb %ld, seqno %lx.%lx.%lx, subseqno %ld, func id %lx\n",
                    TASK_FWD_SEND_TCID_STR(task_fwd), TASK_FWD_SEND_COMM(task_fwd), TASK_FWD_SEND_RANK(task_fwd), TASK_FWD_SEND_MODI(task_fwd),
                    TASK_FWD_RECV_TCID_STR(task_fwd), TASK_FWD_RECV_COMM(task_fwd), TASK_FWD_RECV_RANK(task_fwd), TASK_FWD_RECV_MODI(task_fwd),
                    TASK_FWD_PRIO(task_fwd), TASK_FWD_TYPE(task_fwd),
                    TASK_FWD_TAG(task_fwd), TASK_FWD_LDB_CHOICE(task_fwd),
                    TASK_FWD_RECV_TCID(task_fwd), TASK_FWD_RECV_RANK(task_fwd), TASK_FWD_SEQNO(task_fwd), TASK_FWD_SUB_SEQNO(task_fwd),
                    TASK_FWD_FUNC_ID(task_fwd)
                    );
    break;

    case TAG_TASK_FWD:
    dbg_log(SEC_0015_TASK, 6)(LOGSTDOUT, "direct fwd: from (tcid %s,comm %ld,rank %ld,modi %ld) to (tcid %s,comm %ld,rank %ld,modi %ld) with priority %ld, type %ld, tag %ld, ldb %ld, seqno fwd.%lx.%lx.%lx, subseqno %ld, func id %lx\n",
                    TASK_FWD_SEND_TCID_STR(task_fwd), TASK_FWD_SEND_COMM(task_fwd), TASK_FWD_SEND_RANK(task_fwd), TASK_FWD_SEND_MODI(task_fwd),
                    TASK_FWD_RECV_TCID_STR(task_fwd), TASK_FWD_RECV_COMM(task_fwd), TASK_FWD_RECV_RANK(task_fwd), TASK_FWD_RECV_MODI(task_fwd),
                    TASK_FWD_PRIO(task_fwd), TASK_FWD_TYPE(task_fwd),
                    TASK_FWD_TAG(task_fwd), TASK_FWD_LDB_CHOICE(task_fwd),
                    TASK_FWD_SEND_TCID(task_fwd), TASK_FWD_SEND_RANK(task_fwd), TASK_FWD_SEQNO(task_fwd), TASK_FWD_SUB_SEQNO(task_fwd),
                    TASK_FWD_FUNC_ID(task_fwd)
                    );
    break;

    default:
    dbg_log(SEC_0015_TASK, 6)(LOGSTDOUT, "direct fwd: from (tcid %s,comm %ld,rank %ld,modi %ld) to (tcid %s,comm %ld,rank %ld,modi %ld) with priority %ld, type %ld, tag %ld, ldb %ld, seqno undef.%lx.%lx.%lx, subseqno %ld, func id %lx\n",
                    TASK_FWD_SEND_TCID_STR(task_fwd), TASK_FWD_SEND_COMM(task_fwd), TASK_FWD_SEND_RANK(task_fwd), TASK_FWD_SEND_MODI(task_fwd),
                    TASK_FWD_RECV_TCID_STR(task_fwd), TASK_FWD_RECV_COMM(task_fwd), TASK_FWD_RECV_RANK(task_fwd), TASK_FWD_RECV_MODI(task_fwd),
                    TASK_FWD_PRIO(task_fwd), TASK_FWD_TYPE(task_fwd),
                    TASK_FWD_TAG(task_fwd), TASK_FWD_LDB_CHOICE(task_fwd),
                    TASK_FWD_SEND_TCID(task_fwd), TASK_FWD_SEND_RANK(task_fwd), TASK_FWD_SEQNO(task_fwd), TASK_FWD_SUB_SEQNO(task_fwd),
                    TASK_FWD_FUNC_ID(task_fwd)
                    );
    break;
    }

    //task_func_print(LOGSTDNULL, TASK_FWD_FUNC(task_fwd));

    task_fwd_node = TASK_FWD_NODE(task_fwd);

    TASK_NODE_TAG(task_fwd_node) = TASK_FWD_TAG(task_fwd);
    TASK_FWD_CTHREAD_NODE(task_fwd) = NULL_PTR;

    /*update status*/
    TASK_NODE_STATUS(task_fwd_node) = TASK_FWD_RECVING;

    /*update load info when task_fwd commit*/
    load_set_when_task_fwd_commit(task_brd, task_fwd);

    /*TASK_IS_RECV_QUEUE support task priority, here add node by task_queue_add_node*/
    //task_queue_add_node(TASK_BRD_QUEUE(task_brd, TASK_RECVING_QUEUE), task_fwd_node);
    return (EC_TRUE);
}

EC_BOOL task_fwd_is_to_local(const TASK_BRD *task_brd, const TASK_FWD *task_fwd)
{
#if (SWITCH_ON == TASK_FWD_SHORTCUT)
    if(
        (TASK_FWD_RECV_TCID(task_fwd) == TASK_BRD_TCID(task_brd) || CMPI_ANY_TCID == TASK_FWD_RECV_TCID(task_fwd))
      &&(TASK_FWD_RECV_RANK(task_fwd) == TASK_BRD_RANK(task_brd) || CMPI_ANY_RANK == TASK_FWD_RECV_RANK(task_fwd))
     )
    {
        return (EC_TRUE);
    }
#endif/*(SWITCH_ON == TASK_FWD_SHORTCUT)*/
    return (EC_FALSE);
}


EC_BOOL task_fwd_encode(TASK_FWD *task_fwd)
{
    /*should never be implemented !*/
    return (EC_TRUE);
}

EC_BOOL task_fwd_decode(const UINT32 recv_comm, TASK_FWD *task_fwd)
{
    TASK_NODE *task_fwd_node;

    UINT8  *in_buff;
    UINT32  in_buff_len;
    UINT32  position;

    UINT32  discard_info;

    task_fwd_node     = TASK_FWD_NODE(task_fwd);
    in_buff           = TASK_NODE_BUFF(task_fwd_node);
    in_buff_len       = TASK_NODE_BUFF_LEN(task_fwd_node);

    position = 0;

#if (SWITCH_OFF == TASK_HEADER_COMPRESSED_SWITCH)
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(discard_info));/*dicard len info used when forwarding only*/
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(discard_info));/*dicard tag info used when forwarding only*/

    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_FWD_SEND_TCID(task_fwd)));
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_FWD_SEND_COMM(task_fwd)));
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_FWD_SEND_RANK(task_fwd)));
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_FWD_SEND_MODI(task_fwd)));

    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_FWD_RECV_TCID(task_fwd)));
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_FWD_RECV_COMM(task_fwd)));
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_FWD_RECV_RANK(task_fwd)));
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_FWD_RECV_MODI(task_fwd)));

    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_FWD_LDB_CHOICE(task_fwd)));

    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_FWD_PRIO(task_fwd)));
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_FWD_TYPE(task_fwd)));
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_FWD_TAG(task_fwd)));
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_FWD_SEQNO(task_fwd)));
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_FWD_SUB_SEQNO(task_fwd)));

    cmpi_decode_cload_stat(recv_comm, in_buff, in_buff_len, &(position), (TASK_REQ_CLOAD_STAT(task_fwd)));
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_REQ_TIME_TO_LIVE(task_fwd)));

    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_FWD_FUNC_ID(task_fwd)));
#endif/*(SWITCH_OFF == TASK_HEADER_COMPRESSED_SWITCH)*/

#if (SWITCH_ON == TASK_HEADER_COMPRESSED_SWITCH)
    cmpi_decode_uint32_compressed_uint32_t(recv_comm, in_buff, in_buff_len, &(position), &(discard_info));/*dicard len info used when forwarding only*/
    cmpi_decode_uint32_compressed_uint8_t(recv_comm, in_buff, in_buff_len, &(position), &(discard_info));/*dicard tag info used when forwarding only*/

    cmpi_decode_uint32_compressed_uint32_t(recv_comm, in_buff, in_buff_len, &(position), &(TASK_FWD_SEND_TCID(task_fwd)));
    cmpi_decode_uint32_compressed_uint8_t(recv_comm, in_buff, in_buff_len, &(position), &(TASK_FWD_SEND_COMM(task_fwd)));
    cmpi_decode_uint32_compressed_uint8_t(recv_comm, in_buff, in_buff_len, &(position), &(TASK_FWD_SEND_RANK(task_fwd)));
    cmpi_decode_uint32_compressed_uint16_t(recv_comm, in_buff, in_buff_len, &(position), &(TASK_FWD_SEND_MODI(task_fwd)));

    cmpi_decode_uint32_compressed_uint32_t(recv_comm, in_buff, in_buff_len, &(position), &(TASK_FWD_RECV_TCID(task_fwd)));
    cmpi_decode_uint32_compressed_uint8_t(recv_comm, in_buff, in_buff_len, &(position), &(TASK_FWD_RECV_COMM(task_fwd)));
    cmpi_decode_uint32_compressed_uint8_t(recv_comm, in_buff, in_buff_len, &(position), &(TASK_FWD_RECV_RANK(task_fwd)));
    cmpi_decode_uint32_compressed_uint16_t(recv_comm, in_buff, in_buff_len, &(position), &(TASK_FWD_RECV_MODI(task_fwd)));

    cmpi_decode_uint32_compressed_uint8_t(recv_comm, in_buff, in_buff_len, &(position), &(TASK_FWD_LDB_CHOICE(task_fwd)));

    cmpi_decode_uint32_compressed_uint8_t(recv_comm, in_buff, in_buff_len, &(position), &(TASK_FWD_PRIO(task_fwd)));
    cmpi_decode_uint32_compressed_uint8_t(recv_comm, in_buff, in_buff_len, &(position), &(TASK_FWD_TYPE(task_fwd)));
    cmpi_decode_uint32_compressed_uint8_t(recv_comm, in_buff, in_buff_len, &(position), &(TASK_FWD_TAG(task_fwd)));
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_FWD_SEQNO(task_fwd)));
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_FWD_SUB_SEQNO(task_fwd)));

    //cmpi_decode_cload_stat(recv_comm, in_buff, in_buff_len, &(position), (TASK_REQ_CLOAD_STAT(task_fwd)));
    cload_stat_init(TASK_REQ_CLOAD_STAT(task_fwd));
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_REQ_TIME_TO_LIVE(task_fwd)));

    //cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_FWD_FUNC_ID(task_fwd)));
    if(1)
    {
        UINT32      __mod_type;
        UINT32      __mod_id;

        cmpi_decode_uint32_compressed_uint16_t(recv_comm, in_buff, in_buff_len, &(position), &(__mod_type));
        cmpi_decode_uint32_compressed_uint16_t(recv_comm, in_buff, in_buff_len, &(position), &(__mod_id));

        TASK_FWD_FUNC_ID(task_fwd) = UINT32_VAL(__mod_type, __mod_id);
    }
#endif/*(SWITCH_ON == TASK_HEADER_COMPRESSED_SWITCH)*/


#if 0
    dbg_log(SEC_0015_TASK, 5)(LOGSTDOUT, "task_fwd_decode: (tcid %s,comm %ld,rank %ld,modi %ld) -> (tcid %s,comm %ld,rank %ld,modi %ld),tag %ld,seqno %lx.%lx.%lx,subseqno %ld,func id %lx\n",
                    TASK_FWD_SEND_TCID_STR(task_fwd), TASK_FWD_SEND_COMM(task_fwd), TASK_FWD_SEND_RANK(task_fwd), TASK_FWD_SEND_MODI(task_fwd),
                    TASK_FWD_RECV_TCID_STR(task_fwd), TASK_FWD_RECV_COMM(task_fwd), TASK_FWD_RECV_RANK(task_fwd), TASK_FWD_RECV_MODI(task_fwd),
                    TASK_FWD_TAG(task_fwd),
                    TASK_FWD_SEND_TCID(task_fwd), TASK_FWD_SEND_RANK(task_fwd), TASK_FWD_SEQNO(task_fwd), TASK_FWD_SUB_SEQNO(task_fwd),
                    TASK_FWD_FUNC_ID(task_fwd)
                    );
#endif
    return (EC_TRUE);
}

EC_BOOL task_any_init(TASK_ANY *task_any)
{
    task_header_init(&(task_any->task_header));

    cload_stat_init(TASK_ANY_CLOAD_STAT(task_any));

    TASK_ANY_MGR(task_any)  = NULL_PTR;

    TASK_ANY_LDB_CHOICE(task_any) = LOAD_BALANCING_END; /*default error load balancing strategy*/

    TASK_ANY_CTHREAD_NODE(task_any) = NULL_PTR;

    TASK_REQ_RECV_MOD_NEW(task_any)  = NULL_PTR;
    TASK_REQ_RECV_MOD_FLAG(task_any) = EC_FALSE;
    TASK_REQ_MOD_ID_FLAG(task_any)   = EC_FALSE;

    TASK_ANY_PRIO(task_any) = TASK_PRIO_UNDEF;
    TASK_ANY_TYPE(task_any) = TASK_UNKNOWN_TYPE;
    TASK_ANY_TAG(task_any)  = TAG_TASK_UNDEF;

    TASK_ANY_SEQNO(task_any) = ERR_TASK_SEQNO;
    TASK_ANY_SUB_SEQNO(task_any) = ERR_TASK_SEQNO;

    TASK_REQ_FUNC_ADDR_NODE(task_any) = NULL_PTR;
    task_func_init(TASK_ANY_FUNC(task_any));

    return (EC_TRUE);
}

TASK_ANY *task_any_new(const UINT32 buff_size, const UINT32 location)
{
    TASK_NODE *task_node;

    task_node = task_node_new(buff_size, location);
    if(NULL_PTR == task_node)
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_any_new: new task node failed where location = %ld\n", location);
        return (NULL_PTR);
    }

    task_any_init(TASK_NODE_ANY(task_node));
    return (TASK_NODE_ANY(task_node));
}

EC_BOOL task_any_free(TASK_ANY *task_any)
{
    TASK_NODE *task_any_node;

    task_any_node = TASK_ANY_NODE(task_any);
    task_node_free(task_any_node);

    return (EC_TRUE);
}

EC_BOOL task_any_decode(const UINT32 recv_comm, TASK_ANY *task_any)
{
    TASK_NODE *task_any_node;

    UINT8  *in_buff;
    UINT32  in_buff_len;
    UINT32  position;

    UINT32  discard_info;

    task_any_node     = TASK_ANY_NODE(task_any);
    in_buff           = TASK_NODE_BUFF(task_any_node);
    in_buff_len       = TASK_NODE_BUFF_LEN(task_any_node);

    position = 0;

#if (SWITCH_OFF == TASK_HEADER_COMPRESSED_SWITCH)
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(discard_info));/*dicard len info used when forwarding only*/
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(discard_info));/*dicard tag info used when forwarding only*/

    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_ANY_SEND_TCID(task_any)));
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_ANY_SEND_COMM(task_any)));
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_ANY_SEND_RANK(task_any)));
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_ANY_SEND_MODI(task_any)));

    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_ANY_RECV_TCID(task_any)));
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_ANY_RECV_COMM(task_any)));
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_ANY_RECV_RANK(task_any)));
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_ANY_RECV_MODI(task_any)));

    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_ANY_LDB_CHOICE(task_any)));

    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_ANY_PRIO(task_any)));
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_ANY_TYPE(task_any)));
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_ANY_TAG(task_any)));
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_ANY_SEQNO(task_any)));
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_ANY_SUB_SEQNO(task_any)));

    cmpi_decode_cload_stat(recv_comm, in_buff, in_buff_len, &(position), (TASK_REQ_CLOAD_STAT(task_any)));
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_REQ_TIME_TO_LIVE(task_any)));

    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_ANY_FUNC_ID(task_any)));
#endif/*(SWITCH_OFF == TASK_HEADER_COMPRESSED_SWITCH)*/

#if (SWITCH_ON == TASK_HEADER_COMPRESSED_SWITCH)
    cmpi_decode_uint32_compressed_uint32_t(recv_comm, in_buff, in_buff_len, &(position), &(discard_info));/*dicard len info used when forwarding only*/
    cmpi_decode_uint32_compressed_uint8_t(recv_comm, in_buff, in_buff_len, &(position), &(discard_info));/*dicard tag info used when forwarding only*/

    cmpi_decode_uint32_compressed_uint32_t(recv_comm, in_buff, in_buff_len, &(position), &(TASK_ANY_SEND_TCID(task_any)));
    cmpi_decode_uint32_compressed_uint8_t(recv_comm, in_buff, in_buff_len, &(position), &(TASK_ANY_SEND_COMM(task_any)));
    cmpi_decode_uint32_compressed_uint8_t(recv_comm, in_buff, in_buff_len, &(position), &(TASK_ANY_SEND_RANK(task_any)));
    cmpi_decode_uint32_compressed_uint16_t(recv_comm, in_buff, in_buff_len, &(position), &(TASK_ANY_SEND_MODI(task_any)));

    cmpi_decode_uint32_compressed_uint32_t(recv_comm, in_buff, in_buff_len, &(position), &(TASK_ANY_RECV_TCID(task_any)));
    cmpi_decode_uint32_compressed_uint8_t(recv_comm, in_buff, in_buff_len, &(position), &(TASK_ANY_RECV_COMM(task_any)));
    cmpi_decode_uint32_compressed_uint8_t(recv_comm, in_buff, in_buff_len, &(position), &(TASK_ANY_RECV_RANK(task_any)));
    cmpi_decode_uint32_compressed_uint16_t(recv_comm, in_buff, in_buff_len, &(position), &(TASK_ANY_RECV_MODI(task_any)));

    cmpi_decode_uint32_compressed_uint8_t(recv_comm, in_buff, in_buff_len, &(position), &(TASK_ANY_LDB_CHOICE(task_any)));

    cmpi_decode_uint32_compressed_uint8_t(recv_comm, in_buff, in_buff_len, &(position), &(TASK_ANY_PRIO(task_any)));
    cmpi_decode_uint32_compressed_uint8_t(recv_comm, in_buff, in_buff_len, &(position), &(TASK_ANY_TYPE(task_any)));
    cmpi_decode_uint32_compressed_uint8_t(recv_comm, in_buff, in_buff_len, &(position), &(TASK_ANY_TAG(task_any)));
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_ANY_SEQNO(task_any)));
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_ANY_SUB_SEQNO(task_any)));

    //cmpi_decode_cload_stat(recv_comm, in_buff, in_buff_len, &(position), (TASK_REQ_CLOAD_STAT(task_any)));
    cload_stat_init(TASK_REQ_CLOAD_STAT(task_any));
    cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_REQ_TIME_TO_LIVE(task_any)));

    //cmpi_decode_uint32(recv_comm, in_buff, in_buff_len, &(position), &(TASK_ANY_FUNC_ID(task_any)));
    if(1)
    {
        UINT32      __mod_type;
        UINT32      __mod_id;

        cmpi_decode_uint32_compressed_uint16_t(recv_comm, in_buff, in_buff_len, &(position), &(__mod_type));
        cmpi_decode_uint32_compressed_uint16_t(recv_comm, in_buff, in_buff_len, &(position), &(__mod_id));

        TASK_ANY_FUNC_ID(task_any) = UINT32_VAL(__mod_type, __mod_id);
    }
#endif/*(SWITCH_ON == TASK_HEADER_COMPRESSED_SWITCH)*/


#if 0
    dbg_log(SEC_0015_TASK, 5)(LOGSTDOUT, "task_any_decode: (tcid %s,comm %ld,rank %ld,modi %ld) -> (tcid %s,comm %ld,rank %ld,modi %ld),tag %ld,seqno %lx.%lx.%lx,subseqno %ld,func id %lx\n",
                    TASK_ANY_SEND_TCID_STR(task_any), TASK_ANY_SEND_COMM(task_any), TASK_ANY_SEND_RANK(task_any), TASK_ANY_SEND_MODI(task_any),
                    TASK_ANY_RECV_TCID_STR(task_any), TASK_ANY_RECV_COMM(task_any), TASK_ANY_RECV_RANK(task_any), TASK_ANY_RECV_MODI(task_any),
                    TASK_ANY_TAG(task_any),
                    TASK_ANY_SEND_TCID(task_any), TASK_ANY_SEND_RANK(task_any), TASK_ANY_SEQNO(task_any), TASK_ANY_SUB_SEQNO(task_any),
                    TASK_ANY_FUNC_ID(task_any)
                    );
#endif
    return (EC_TRUE);
}

EC_BOOL task_req_cancel(TASK_REQ *task_req)
{
    MOD_NODE recv_mod_node;
    EC_BOOL ret;

    MOD_NODE_TCID(&recv_mod_node) = TASK_REQ_SEND_TCID(task_req);
    MOD_NODE_COMM(&recv_mod_node) = TASK_REQ_SEND_COMM(task_req);
    MOD_NODE_RANK(&recv_mod_node) = TASK_REQ_SEND_RANK(task_req);
    MOD_NODE_MODI(&recv_mod_node) = 0;

    ret = EC_FALSE;
    task_p2p(0, TASK_DEFAULT_LIVE, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &recv_mod_node,
             &ret, FI_super_cancel_task_req, CMPI_ERROR_MODI, TASK_REQ_SEQNO(task_req), TASK_REQ_SUB_SEQNO(task_req), TASK_REQ_RECV_MOD(task_req));
    if(EC_TRUE == ret)
    {
        dbg_log(SEC_0015_TASK, 6)(LOGSTDOUT, "cancel req: from (tcid %s,comm %ld,rank %ld,modi %ld) to (tcid %s,comm %ld,rank %ld,modi %ld) with priority %ld, type %ld, tag %ld, ldb %ld, seqno %lx.%lx.%lx, subseqno %ld, func id %lx\n",
                        TASK_REQ_SEND_TCID_STR(task_req), TASK_REQ_SEND_COMM(task_req), TASK_REQ_SEND_RANK(task_req), TASK_REQ_SEND_MODI(task_req),
                        TASK_REQ_RECV_TCID_STR(task_req), TASK_REQ_RECV_COMM(task_req), TASK_REQ_RECV_RANK(task_req), TASK_REQ_RECV_MODI(task_req),
                        TASK_REQ_PRIO(task_req), TASK_REQ_TYPE(task_req),
                        TASK_REQ_TAG(task_req), TASK_REQ_LDB_CHOICE(task_req),
                        TASK_REQ_SEND_TCID(task_req), TASK_REQ_SEND_RANK(task_req), TASK_REQ_SEQNO(task_req), TASK_REQ_SUB_SEQNO(task_req),
                        TASK_REQ_FUNC_ID(task_req)
                        );
        return (EC_TRUE);
    }

    dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:cancel req: from (tcid %s,comm %ld,rank %ld,modi %ld) to (tcid %s,comm %ld,rank %ld,modi %ld) with priority %ld, type %ld, tag %ld, ldb %ld, seqno %lx.%lx.%lx, subseqno %ld, func id %lx\n",
                    TASK_REQ_SEND_TCID_STR(task_req), TASK_REQ_SEND_COMM(task_req), TASK_REQ_SEND_RANK(task_req), TASK_REQ_SEND_MODI(task_req),
                    TASK_REQ_RECV_TCID_STR(task_req), TASK_REQ_RECV_COMM(task_req), TASK_REQ_RECV_RANK(task_req), TASK_REQ_RECV_MODI(task_req),
                    TASK_REQ_PRIO(task_req), TASK_REQ_TYPE(task_req),
                    TASK_REQ_TAG(task_req), TASK_REQ_LDB_CHOICE(task_req),
                    TASK_REQ_SEND_TCID(task_req), TASK_REQ_SEND_RANK(task_req), TASK_REQ_SEQNO(task_req), TASK_REQ_SUB_SEQNO(task_req),
                    TASK_REQ_FUNC_ID(task_req)
                    );
    return (EC_FALSE);
}

EC_BOOL task_req_discard(TASK_REQ *task_req)
{
    dbg_log(SEC_0015_TASK, 3)(LOGSTDOUT, "info:task_req_discard: cancel task_req %p\n", task_req);
    task_req_cancel(task_req);
    task_req_free(task_req);

    return (EC_TRUE);
}

EC_BOOL task_req_local_handle(TASK_REQ *task_req)
{
    TASK_FUNC  *task_req_func;

    FUNC_ADDR_NODE * func_addr_node;

    /*shortcut/direct handle req*/
    dbg_log(SEC_0015_TASK, 6)(LOGSTDOUT, "direct req: from (tcid %s,comm %ld,rank %ld,modi %ld) to (tcid %s,comm %ld,rank %ld,modi %ld) with priority %ld, type %ld, tag %ld, ldb %ld, seqno %lx.%lx.%lx, subseqno %ld, func id %lx\n",
                    TASK_REQ_SEND_TCID_STR(task_req), TASK_REQ_SEND_COMM(task_req), TASK_REQ_SEND_RANK(task_req), TASK_REQ_SEND_MODI(task_req),
                    TASK_REQ_RECV_TCID_STR(task_req),TASK_REQ_RECV_COMM(task_req), TASK_REQ_RECV_RANK(task_req), TASK_REQ_RECV_MODI(task_req),
                    TASK_REQ_PRIO(task_req), TASK_REQ_TYPE(task_req),
                    TASK_REQ_TAG(task_req),  TASK_REQ_LDB_CHOICE(task_req),
                    TASK_REQ_SEND_TCID(task_req), TASK_REQ_SEND_RANK(task_req), TASK_REQ_SEQNO(task_req), TASK_REQ_SUB_SEQNO(task_req),
                    TASK_REQ_FUNC_ID(task_req)
                    );

    /*handle task_req*/
    task_req_func  = TASK_REQ_FUNC(task_req);
    func_addr_node = TASK_REQ_FUNC_ADDR_NODE(task_req);

    if(NULL_PTR == func_addr_node)
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_req_local_handle: func_addr_node is null\n");
        return (EC_FALSE);
    }

    /*check modi validity. if invalid, notify task req sender to cancel*/
    if(TASK_ACT_TYPE != TASK_REQ_TYPE(task_req))
    {
        UINT32 mod_id;
        UINT32 mod_type;

        mod_id = TASK_REQ_FUNC_PARA_VAL(task_req, 0);/*the first parameter is modi*/
        mod_type = ((func_addr_node->func_index) >> (WORDSIZE / 2));

        if(/*MD_SUPER != mod_type && */CMPI_ANY_MODI != mod_id && NULL_PTR == cbc_md_get(mod_type, mod_id))
        {
            dbg_log(SEC_0015_TASK, 1)(LOGSTDOUT, "warn:task_req_local_handle: mod_type %ld, mod_id %ld, but cbc_md_get get null, cancel task_req %p\n",
                                mod_type, mod_id, task_req);
            task_req_cancel(task_req);
            return (EC_FALSE);
        }
    }

    task_caller(task_req_func, func_addr_node);
    return (EC_TRUE);
}

TASK_RSP * task_req_handle(TASK_REQ *task_req)
{
    TASK_RSP   *task_rsp;
    TASK_NODE  *task_rsp_node;

    TASK_FUNC  *task_req_func;
    TASK_FUNC  *task_rsp_func;

    FUNC_PARA  *task_rsp_func_para;
    FUNC_PARA  *task_req_func_para;
    FUNC_ADDR_NODE * func_addr_node;

    UINT32 para_idx;

    dbg_log(SEC_0015_TASK, 6)(LOGSTDOUT, "handle req: from (tcid %s,comm %ld,rank %ld,modi %ld) to (tcid %s,comm %ld,rank %ld,modi %ld) with priority %ld, type %ld, tag %ld, ldb %ld, seqno %lx.%lx.%lx, subseqno %ld, func id %lx\n",
                    TASK_REQ_SEND_TCID_STR(task_req), TASK_REQ_SEND_COMM(task_req), TASK_REQ_SEND_RANK(task_req), TASK_REQ_SEND_MODI(task_req),
                    TASK_REQ_RECV_TCID_STR(task_req),TASK_REQ_RECV_COMM(task_req), TASK_REQ_RECV_RANK(task_req), TASK_REQ_RECV_MODI(task_req),
                    TASK_REQ_PRIO(task_req), TASK_REQ_TYPE(task_req),
                    TASK_REQ_TAG(task_req),  TASK_REQ_LDB_CHOICE(task_req),
                    TASK_REQ_SEND_TCID(task_req), TASK_REQ_SEND_RANK(task_req), TASK_REQ_SEQNO(task_req), TASK_REQ_SUB_SEQNO(task_req),
                    TASK_REQ_FUNC_ID(task_req)
                    );

    /*handle task_req*/
    task_req_func  = TASK_REQ_FUNC(task_req);
    func_addr_node = TASK_REQ_FUNC_ADDR_NODE(task_req);

    if(NULL_PTR == func_addr_node && 0 != dbg_fetch_func_addr_node_by_index(task_req_func->func_id, &func_addr_node))
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_req_handle: failed to fetch func addr node by func id %lx\n", task_req_func->func_id);
        return (NULL_PTR);
    }

    /*check modi validity. if invalid, notify task req sender to cancel*/
    if(TASK_ACT_TYPE != TASK_REQ_TYPE(task_req))
    {
        UINT32 mod_id;
        UINT32 mod_type;

        mod_id = TASK_REQ_FUNC_PARA_VAL(task_req, 0);/*the first parameter is modi*/
        mod_type = ((func_addr_node->func_index) >> (WORDSIZE / 2));


        if(/*MD_SUPER != mod_type && */CMPI_ANY_MODI != mod_id && NULL_PTR == cbc_md_get(mod_type, mod_id))
        {
            dbg_log(SEC_0015_TASK, 1)(LOGSTDOUT, "warn:task_req_handle: mod_type %ld, mod_id %ld, but cbc_md_get get null, cancel task_req %p\n",
                               mod_type, mod_id, task_req);
            task_req_cancel(task_req);
            return (NULL_PTR);
        }
    }

    task_caller(task_req_func, func_addr_node);

    //CROUTINE_TEST_CANCEL();/*set pthread cancel point*/

    if(TASK_NOT_NEED_RSP_FLAG == TASK_REQ_NEED_RSP_FLAG(task_req))
    {
        load_set_when_task_rsp_is_ignore(task_brd_default_get(), task_req);
        return (NULL_PTR);
    }

    if(EC_TRUE == task_req_is_timeout(task_req))
    {
        return (NULL_PTR);
    }

    task_rsp = task_rsp_new(0, LOC_TASK_0039);

    CROUTINE_CLEANUP_PUSH(task_rsp_free, task_rsp);
    //CROUTINE_TEST_CANCEL();/*set pthread cancel point*/

    TASK_RSP_SEND_TCID(task_rsp) = TASK_REQ_RECV_TCID(task_req);
    TASK_RSP_SEND_COMM(task_rsp) = TASK_REQ_RECV_COMM(task_req);
    TASK_RSP_SEND_RANK(task_rsp) = TASK_REQ_RECV_RANK(task_req);
    TASK_RSP_SEND_MODI(task_rsp) = TASK_REQ_RECV_MODI(task_req);

    TASK_RSP_RECV_TCID(task_rsp) = TASK_REQ_SEND_TCID(task_req);
    TASK_RSP_RECV_COMM(task_rsp) = TASK_REQ_SEND_COMM(task_req);
    TASK_RSP_RECV_RANK(task_rsp) = TASK_REQ_SEND_RANK(task_req);
    TASK_RSP_RECV_MODI(task_rsp) = TASK_REQ_SEND_MODI(task_req);

    TASK_RSP_LDB_CHOICE(task_rsp)= TASK_REQ_LDB_CHOICE(task_req);/*inherit load balancing strategy from TASK_REQ*/
#if 0
    if(LOAD_BALANCING_LOOP != TASK_RSP_LDB_CHOICE(task_rsp) && LOAD_BALANCING_RANK != TASK_RSP_LDB_CHOICE(task_rsp))
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_req_handle: invalid load balancing strategy %ld\n", TASK_RSP_LDB_CHOICE(task_rsp));
    }
#endif

    TASK_RSP_PRIO(task_rsp)      = TASK_REQ_PRIO(task_req);
    TASK_RSP_TYPE(task_rsp)      = TASK_REQ_TYPE(task_req);
    TASK_RSP_TAG(task_rsp)       = TAG_TASK_RSP;
    TASK_RSP_SEQNO(task_rsp)     = TASK_REQ_SEQNO(task_req);
    TASK_RSP_SUB_SEQNO(task_rsp) = TASK_REQ_SUB_SEQNO(task_req);

    task_rsp_func = TASK_RSP_FUNC(task_rsp);

    /*clone task_req_func to task_rsp_func and clean up task_req_func*/
    task_rsp_func->func_id       = task_req_func->func_id;
    task_rsp_func->func_para_num = task_req_func->func_para_num;
    task_rsp_func->func_ret_val  = task_req_func->func_ret_val;

    task_req_func->func_ret_val  = 0;/*clean it*/

    for( para_idx = 0; para_idx < task_req_func->func_para_num; para_idx ++ )
    {
        task_req_func_para = &(task_req_func->func_para[ para_idx ]);
        task_rsp_func_para = &(task_rsp_func->func_para[ para_idx ]);

        task_rsp_func_para->para_dir = task_req_func_para->para_dir;
        task_rsp_func_para->para_val = task_req_func_para->para_val;
        task_req_func_para->para_val = 0;/*clean it*/
    }

    TASK_RSP_FUNC_ADDR_NODE(task_rsp) = func_addr_node;

    task_rsp_node = TASK_RSP_NODE(task_rsp);

    TASK_NODE_TAG(task_rsp_node)   = TAG_TASK_RSP;
    TASK_NODE_STATUS(task_rsp_node)= TASK_RSP_TO_SEND;

    CROUTINE_CLEANUP_POP( 0 );

    return (task_rsp);
}

EC_BOOL task_context_handle(TASK_BRD *task_brd, const TASK_RSP *task_rsp_ret)
{
    if(TASK_ACT_TYPE == TASK_RSP_TYPE(task_rsp_ret) && CMPI_ERROR_MODI == TASK_RSP_FUNC_RET(task_rsp_ret))
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_context_handle: TASK_RSP_FUNC_RET is CMPI_ERROR_MODI\n");
        return (EC_FALSE);
    }

    if(TASK_ACT_TYPE == TASK_RSP_TYPE(task_rsp_ret) && CMPI_ERROR_MODI != TASK_RSP_FUNC_RET(task_rsp_ret))
    {
        TASK_CONTEXT *task_context;
        TASK_RSP     *task_rsp;

        UINT32 md_type;
        FUNC_ADDR_MGR *func_addr_mgr;
        FUNC_ADDR_NODE *func_addr_node;

        task_context = task_context_new();
        task_rsp = task_rsp_new(0, LOC_TASK_0040);

        /*clone task_rsp_ret to task_rsp*/
        TASK_RSP_SEND_TCID(task_rsp) = TASK_RSP_SEND_TCID(task_rsp_ret);
        TASK_RSP_SEND_COMM(task_rsp) = TASK_RSP_SEND_COMM(task_rsp_ret);
        TASK_RSP_SEND_RANK(task_rsp) = TASK_RSP_SEND_RANK(task_rsp_ret);
        TASK_RSP_SEND_MODI(task_rsp) = TASK_RSP_SEND_MODI(task_rsp_ret);

        TASK_RSP_RECV_TCID(task_rsp) = TASK_RSP_RECV_TCID(task_rsp_ret);
        TASK_RSP_RECV_COMM(task_rsp) = TASK_RSP_RECV_COMM(task_rsp_ret);
        TASK_RSP_RECV_RANK(task_rsp) = TASK_RSP_RECV_RANK(task_rsp_ret);
        TASK_RSP_RECV_MODI(task_rsp) = TASK_RSP_RECV_MODI(task_rsp_ret);

        TASK_RSP_LDB_CHOICE(task_rsp)= TASK_RSP_LDB_CHOICE(task_rsp_ret);

        TASK_RSP_TYPE(task_rsp)      = TASK_RSP_TYPE(task_rsp_ret);
        TASK_RSP_TAG(task_rsp)       = TASK_RSP_TAG(task_rsp_ret);
        TASK_RSP_SEQNO(task_rsp)     = TASK_RSP_SEQNO(task_rsp_ret);
        TASK_RSP_SUB_SEQNO(task_rsp) = TASK_RSP_SUB_SEQNO(task_rsp_ret);

        md_type = (TASK_RSP_FUNC_ID(task_rsp_ret)>> (WORDSIZE / 2)); /*refer findex.inc*/
        func_addr_mgr = TASK_BRD_MD_NODE_GET(task_brd, md_type);
        TASK_RSP_FUNC_ID(task_rsp)   = func_addr_mgr->md_end_func_id;

        TASK_RSP_FUNC_RET(task_rsp)  = TASK_RSP_FUNC_RET(task_rsp_ret); /*WARNING: function return value should never be pointer here*/

        /*ok, forge a scenario for calling when possible discarding*/
        TASK_RSP_FUNC_PARA_NUM(task_rsp)    = 1; /*all module end function must be format "void mod_end(UITN32 mod_id)", so only one parameter*/
        TASK_RSP_FUNC_PARA_VAL(task_rsp, 0) = TASK_RSP_FUNC_RET(task_rsp_ret);
        TASK_RSP_FUNC_PARA_DIR(task_rsp, 0) = E_DIRECT_IN;

        if(0 != dbg_fetch_func_addr_node_by_index(TASK_RSP_FUNC_ID(task_rsp), &func_addr_node))
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_context_handle: failed to fetch func addr node by func id %lx\n", TASK_RSP_FUNC_ID(task_rsp));
            return (EC_FALSE);
        }
        TASK_RSP_FUNC_ADDR_NODE(task_rsp) = func_addr_node;/*module end func id*/

        TASK_NODE_TAG(TASK_RSP_NODE(task_rsp))    = TASK_NODE_TAG(TASK_RSP_NODE(task_rsp_ret));
        TASK_NODE_STATUS(TASK_RSP_NODE(task_rsp)) = TASK_NODE_STATUS(TASK_RSP_NODE(task_rsp_ret));

        TASK_CONTEXT_TASK_RSP(task_context) = task_rsp; /*add task_rsp to task_context*/
        clist_push_back(TASK_BRD_CONTEXT_LIST(task_brd), (void *)task_context); /*save task_context to task_brd*/

        return (EC_TRUE);
    }

    if(TASK_DEA_TYPE == TASK_RSP_TYPE(task_rsp_ret))
    {
        CLIST_DATA *clist_data;

        CLIST_LOCK(TASK_BRD_CONTEXT_LIST(task_brd), LOC_TASK_0041);
        CLIST_LOOP_NEXT(TASK_BRD_CONTEXT_LIST(task_brd), clist_data)
        {
            TASK_CONTEXT *task_context;

            task_context = (TASK_CONTEXT *)CLIST_DATA_DATA(clist_data);

            if(/* TASK_RSP_SEND_TCID(TASK_CONTEXT_TASK_RSP(task_context)) == TASK_RSP_SEND_TCID(task_rsp_ret) &&
                TASK_RSP_SEND_COMM(TASK_CONTEXT_TASK_RSP(task_context)) == TASK_RSP_SEND_COMM(task_rsp_ret) &&
                TASK_RSP_SEND_RANK(TASK_CONTEXT_TASK_RSP(task_context)) == TASK_RSP_SEND_RANK(task_rsp_ret) &&*//*must same, jeje!*/
                /*TASK_RSP_FUNC_ID(task_rsp_saved) was replaced with module DEA function id when save to context*/
                TASK_RSP_FUNC_ID(TASK_CONTEXT_TASK_RSP(task_context))   == TASK_RSP_FUNC_ID(task_rsp_ret)  &&
                TASK_RSP_FUNC_RET(TASK_CONTEXT_TASK_RSP(task_context))  == TASK_RSP_SEND_MODI(task_rsp_ret)
             )
            {
                clist_rmv_no_lock(TASK_BRD_CONTEXT_LIST(task_brd), clist_data);
                task_context_free(task_context);

                CLIST_UNLOCK(TASK_BRD_CONTEXT_LIST(task_brd), LOC_TASK_0042);
                return (EC_TRUE);
            }
        }

        CLIST_UNLOCK(TASK_BRD_CONTEXT_LIST(task_brd), LOC_TASK_0043);
        return (EC_TRUE);
    }
    return (EC_TRUE);
}

EC_BOOL task_context_discard_from(TASK_BRD *task_brd, const UINT32 broken_tcid)
{
    CLIST_DATA *clist_data;

    CLIST_LOCK(TASK_BRD_CONTEXT_LIST(task_brd), LOC_TASK_0044);
    CLIST_LOOP_NEXT(TASK_BRD_CONTEXT_LIST(task_brd), clist_data)
    {
        TASK_CONTEXT *task_context;
        TASK_RSP     *task_rsp;

        task_context = (TASK_CONTEXT *)CLIST_DATA_DATA(clist_data);
        task_rsp     = TASK_CONTEXT_TASK_RSP(task_context);

        /*TASK_RSP RECV_TCID is same as  TASK_REQ SEND_TCID, hence here TASK_RSP_RECV_TCID mark the ACT task req from where*/
        if( TASK_RSP_RECV_TCID(task_rsp) == broken_tcid )
        {
            TASK_FUNC *task_func;
            FUNC_ADDR_NODE *func_addr_node;

            CLIST_DATA *clist_data_rmv;

            dbg_log(SEC_0015_TASK, 5)(LOGSTDOUT, "lost contx: from (tcid %s,comm %ld,rank %ld,modi %ld) to (tcid %s,comm %ld,rank %ld,modi %ld) "
                               "with priority %ld, type %ld, tag %ld, ldb %ld, seqno %lx.%lx.%lx, subseqno %ld, func id %lx from broken tcid %s\n",
                            TASK_RSP_SEND_TCID_STR(task_rsp), TASK_RSP_SEND_COMM(task_rsp), TASK_RSP_SEND_RANK(task_rsp), TASK_RSP_SEND_MODI(task_rsp),
                            TASK_RSP_RECV_TCID_STR(task_rsp), TASK_RSP_RECV_COMM(task_rsp), TASK_RSP_RECV_RANK(task_rsp), TASK_RSP_RECV_MODI(task_rsp),
                            TASK_RSP_PRIO(task_rsp), TASK_RSP_TYPE(task_rsp),
                            TASK_RSP_TAG(task_rsp), TASK_RSP_LDB_CHOICE(task_rsp),
                            TASK_RSP_SEND_TCID(task_rsp), TASK_RSP_SEND_RANK(task_rsp), TASK_RSP_SEQNO(task_rsp), TASK_RSP_SUB_SEQNO(task_rsp),
                            TASK_RSP_FUNC_ID(task_rsp),
                            c_word_to_ipv4(broken_tcid)
                            );

            task_func      = TASK_RSP_FUNC(task_rsp);
            func_addr_node =  TASK_RSP_FUNC_ADDR_NODE(task_rsp);

            task_caller(task_func, func_addr_node); /*calling module end function*/

            clist_data_rmv = clist_data;
            clist_data = CLIST_DATA_PREV(clist_data);
            clist_rmv_no_lock(TASK_BRD_CONTEXT_LIST(task_brd), clist_data_rmv);
            task_context_free(task_context);
        }
    }
    CLIST_UNLOCK(TASK_BRD_CONTEXT_LIST(task_brd), LOC_TASK_0045);
    return (EC_TRUE);
}

void task_context_print(LOG *log, const TASK_CONTEXT *task_context)
{
    TASK_RSP *task_rsp;
    TASK_NODE *task_node;

    task_rsp = TASK_CONTEXT_TASK_RSP(task_context);
    task_node = TASK_RSP_NODE(task_rsp);

    sys_print(log, "[task_context %lx, task_rsp %lx] node tag %ld, node status %ld: "
                   "(tcid %s,comm %ld,rank %ld,modi %ld) -> (tcid %s,comm %ld,rank %ld,modi %ld),"
                   "tag %ld,seqno %lx.%lx.%lx,subseqno %ld: func id %lx, retval %ld\n",
                    task_context, task_rsp, TASK_NODE_TAG(task_node), TASK_NODE_STATUS(task_node),
                    TASK_RSP_SEND_TCID_STR(task_rsp), TASK_RSP_SEND_COMM(task_rsp), TASK_RSP_SEND_RANK(task_rsp), TASK_RSP_SEND_MODI(task_rsp),
                    TASK_RSP_RECV_TCID_STR(task_rsp), TASK_RSP_RECV_COMM(task_rsp), TASK_RSP_RECV_RANK(task_rsp), TASK_RSP_RECV_MODI(task_rsp),
                    TASK_RSP_TAG(task_rsp),
                    TASK_RSP_RECV_TCID(task_rsp), TASK_RSP_RECV_RANK(task_rsp), TASK_RSP_SEQNO(task_rsp), TASK_RSP_SUB_SEQNO(task_rsp),
                    TASK_RSP_FUNC_ID(task_rsp),TASK_RSP_FUNC_RET(task_rsp)
             );
    return;
}

void task_report_node_print(LOG *log, const TASK_REPORT_NODE *task_report_node)
{
    sys_log(log, "task report: start at %4d-%02d-%02d %02d:%02d:%02d, end at %4d-%02d-%02d %02d:%02d:%02d, "
                 "time to live %ld, seqno %lx.%lx.%lx, wait flag %ld, need rsp flag %ld, reschedule flag %ld, "
                 "req num %ld, need rsp %ld, succ rsp %ld, fail rsp %ld, sent req %ld, discard req %ld, timeout req %ld\n",
                       TASK_TIME_FMT_YEAR(TASK_REPORT_NODE_START_TIME(task_report_node)), TASK_TIME_FMT_MONTH(TASK_REPORT_NODE_START_TIME(task_report_node)), TASK_TIME_FMT_MDAY(TASK_REPORT_NODE_START_TIME(task_report_node)),
                       TASK_TIME_FMT_HOUR(TASK_REPORT_NODE_START_TIME(task_report_node)), TASK_TIME_FMT_MIN(TASK_REPORT_NODE_START_TIME(task_report_node)), TASK_TIME_FMT_SEC(TASK_REPORT_NODE_START_TIME(task_report_node)),

                       TASK_TIME_FMT_YEAR(TASK_REPORT_NODE_END_TIME(task_report_node)), TASK_TIME_FMT_MONTH(TASK_REPORT_NODE_END_TIME(task_report_node)), TASK_TIME_FMT_MDAY(TASK_REPORT_NODE_END_TIME(task_report_node)),
                       TASK_TIME_FMT_HOUR(TASK_REPORT_NODE_END_TIME(task_report_node)), TASK_TIME_FMT_MIN(TASK_REPORT_NODE_END_TIME(task_report_node)), TASK_TIME_FMT_SEC(TASK_REPORT_NODE_END_TIME(task_report_node)),

                       TASK_REPORT_NODE_TIME_TO_LIVE(task_report_node),
                       TASK_REPORT_NODE_TCID(task_report_node), TASK_REPORT_NODE_RANK(task_report_node), TASK_REPORT_NODE_SEQNO(task_report_node),

                       TASK_REPORT_NODE_WAIT_FLAG(task_report_node), TASK_REPORT_NODE_NEED_RSP_FLAG(task_report_node), TASK_REPORT_NODE_NEED_RESCHEDULE_FLAG(task_report_node),

                       TASK_REPORT_NODE_TOTAL_REQ_NUM(task_report_node),
                       TASK_REPORT_NODE_NEED_RSP_NUM(task_report_node),
                       TASK_REPORT_NODE_SUCC_RSP_NUM(task_report_node),
                       TASK_REPORT_NODE_FAIL_RSP_NUM(task_report_node),
                       TASK_REPORT_NODE_SENT_REQ_NUM(task_report_node),
                       TASK_REPORT_NODE_DISCARD_REQ_NUM(task_report_node),
                       TASK_REPORT_NODE_TIMEOUT_REQ_NUM(task_report_node)
           );
    return;
}

void task_brd_context_list_print(LOG *log, const TASK_BRD *task_brd)
{
    clist_print(log, TASK_BRD_CONTEXT_LIST(task_brd), (CLIST_DATA_DATA_PRINT)task_context_print);
    return;
}

EC_BOOL task_queue_init(CLIST *task_queue)
{
    clist_init(task_queue, MM_IGNORE, LOC_TASK_0046);
    return (EC_TRUE);
}

/* destory task req manager */
EC_BOOL task_queue_clean(CLIST *task_queue)
{
    clist_clean(task_queue, (CQUEUE_DATA_DATA_CLEANER)task_node_free);
    return (EC_TRUE);
}

EC_BOOL task_queue_add_node(CLIST *task_queue, const TASK_NODE *task_node)
{
#if 1
    switch(TASK_ANY_PRIO(TASK_NODE_ANY(task_node)))
    {
        case TASK_PRIO_PREEMPT:
        {
            clist_push_front(task_queue, (void *)task_node);
            break;
        }
        case TASK_PRIO_HIGH:
        {
            CLIST_DATA * clist_data;

            CLIST_LOCK(task_queue, LOC_TASK_0047);
            CLIST_LOOP_NEXT(task_queue, clist_data)
            {
                TASK_NODE *task_node_cur;

                task_node_cur = (TASK_NODE *)CLIST_DATA_DATA(clist_data);
                if(TASK_ANY_PRIO(TASK_NODE_ANY(task_node)) > TASK_ANY_PRIO(TASK_NODE_ANY(task_node_cur)))
                {
                    clist_insert_front_no_lock(task_queue, clist_data, (void *)task_node);
                    CLIST_UNLOCK(task_queue, LOC_TASK_0048);
                    return (EC_TRUE);
                }
            }

            /*if not find a lower priority task_mgr, add to tail*/
            clist_push_back_no_lock(task_queue, (void *)task_node);

            CLIST_UNLOCK(task_queue, LOC_TASK_0049);

            break;
        }
        case TASK_PRIO_NORMAL:
        {
            clist_push_back(task_queue, (void *)task_node);
            break;
        }
        default:
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_queue_add_node: unknow task priority %ld\n", TASK_ANY_PRIO(TASK_NODE_ANY(task_node)));
            return (EC_FALSE);
        }
    }
#else
    clist_push_back(task_queue, (void *)task_node);
#endif
    return (EC_TRUE);
}

EC_BOOL task_queue_rmv_node(CLIST *task_queue, const TASK_NODE *task_node)
{
    clist_del(task_queue, (const void *)task_node, NULL_PTR);
    return (EC_TRUE);
}

TASK_RANK_NODE * task_rank_node_new()
{
    TASK_RANK_NODE *task_rank_node;

    alloc_static_mem(MM_TASK_RANK_NODE, &task_rank_node, LOC_TASK_0050);
    task_rank_node_init(task_rank_node);
    return (task_rank_node);
}

EC_BOOL task_rank_node_init(TASK_RANK_NODE *task_rank_node)
{
    TASK_RANK_NODE_CMUTEX_INIT(task_rank_node, LOC_TASK_0051);
    task_rank_node_enable(task_rank_node);
    return (EC_TRUE);
}

EC_BOOL task_rank_node_clean(TASK_RANK_NODE *task_rank_node)
{
    task_rank_node_disable(task_rank_node);
    TASK_RANK_NODE_CMUTEX_CLEAN(task_rank_node, LOC_TASK_0052);
    return (EC_TRUE);
}

EC_BOOL task_rank_node_free(TASK_RANK_NODE *task_rank_node)
{
    task_rank_node_clean(task_rank_node);
    free_static_mem(MM_TASK_RANK_NODE, task_rank_node, LOC_TASK_0053);
    return (EC_TRUE);
}

EC_BOOL task_rank_node_enable(TASK_RANK_NODE *task_rank_node)
{
    TASK_RANK_NODE_LOCK(task_rank_node, LOC_TASK_0054);
    TASK_RANK_NODE_LIGHT(task_rank_node) = TASK_RANK_NODE_GREEN_LIGHT;
    TASK_RANK_NODE_UNLOCK(task_rank_node, LOC_TASK_0055);
    return (EC_TRUE);
}

EC_BOOL task_rank_node_reserve(TASK_RANK_NODE *task_rank_node)
{
    TASK_RANK_NODE_LOCK(task_rank_node, LOC_TASK_0056);
    if(TASK_RANK_NODE_GREEN_LIGHT == TASK_RANK_NODE_LIGHT(task_rank_node))
    {
        TASK_RANK_NODE_LIGHT(task_rank_node) = TASK_RANK_NODE_RED_LIGHT;
        TASK_RANK_NODE_UNLOCK(task_rank_node, LOC_TASK_0057);
        return (EC_TRUE);
    }
    TASK_RANK_NODE_UNLOCK(task_rank_node, LOC_TASK_0058);
    return (EC_FALSE);
}

EC_BOOL task_rank_node_disable(TASK_RANK_NODE *task_rank_node)
{
    TASK_RANK_NODE_LOCK(task_rank_node, LOC_TASK_0059);
    TASK_RANK_NODE_LIGHT(task_rank_node) = TASK_RANK_NODE_RED_LIGHT;
    TASK_RANK_NODE_UNLOCK(task_rank_node, LOC_TASK_0060);
    return (EC_TRUE);
}

void task_rank_node_print(LOG *log, const TASK_RANK_NODE *task_rank_node)
{
    if(TASK_RANK_NODE_GREEN_LIGHT == TASK_RANK_NODE_LIGHT(task_rank_node))
    {
        sys_log(log, "task_rank_node %lx: green\n", task_rank_node);
        return;
    }
    if(TASK_RANK_NODE_RED_LIGHT == TASK_RANK_NODE_LIGHT(task_rank_node))
    {
        sys_log(log, "task_rank_node %lx: red\n", task_rank_node);
        return;
    }

    sys_log(log, "task_rank_node %lx: unknow error\n", task_rank_node);
    return;
}

CVECTOR * task_rank_tbl_new(const UINT32 size)
{
    CVECTOR *task_rank_tbl;
    UINT32 pos;

    task_rank_tbl = cvector_new(size, MM_TASK_RANK_NODE, LOC_TASK_0061);
    for(pos = 0; pos < size; pos ++)
    {
        TASK_RANK_NODE *task_rank_node;

        task_rank_node = task_rank_node_new();
        cvector_push(task_rank_tbl, (void *)task_rank_node);
    }
    return (task_rank_tbl);
}
/*
EC_BOOL task_rank_tbl_init(CVECTOR *task_rank_tbl)
{
    cvector_init(task_rank_tbl, 0, MM_TASK_RANK_NODE, CVECTOR_LOCK_ENABLE, LOC_TASK_0062);
    return (EC_TRUE);
}
*/
EC_BOOL task_rank_tbl_clean(CVECTOR *task_rank_tbl)
{
    cvector_clean(task_rank_tbl, (CVECTOR_DATA_CLEANER)task_rank_node_free, LOC_TASK_0063);
    return (EC_TRUE);
}

EC_BOOL task_rank_tbl_free(CVECTOR *task_rank_tbl)
{
    task_rank_tbl_clean(task_rank_tbl);
    cvector_free(task_rank_tbl, LOC_TASK_0064);
    return (EC_TRUE);
}

EC_BOOL task_rank_tbl_enable(CVECTOR *task_rank_tbl, const UINT32 rank)
{
    TASK_RANK_NODE *task_rank_node;

    task_rank_node = (TASK_RANK_NODE *)cvector_get(task_rank_tbl, rank);
    if(NULL_PTR == task_rank_node)
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_rank_tbl_enable: task_rank_node for rank %ld does not exist\n", rank);
        return (EC_FALSE);
    }

    task_rank_node_enable(task_rank_node);
    return (EC_TRUE);
}

EC_BOOL task_rank_tbl_enable_all(CVECTOR *task_rank_tbl)
{
    cvector_loop_front(task_rank_tbl, (CVECTOR_DATA_HANDLER)task_rank_node_enable);
    return (EC_TRUE);
}

EC_BOOL task_rank_tbl_reserve(CVECTOR *task_rank_tbl, const UINT32 rank)
{
    TASK_RANK_NODE *task_rank_node;

    task_rank_node = (TASK_RANK_NODE *)cvector_get(task_rank_tbl, rank);
    if(NULL_PTR == task_rank_node)
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_rank_tbl_enable: task_rank_node for rank %ld does not exist\n", rank);
        return (EC_FALSE);
    }

    return task_rank_node_reserve(task_rank_node);
}

EC_BOOL task_rank_tbl_disable(CVECTOR *task_rank_tbl, const UINT32 rank)
{
    TASK_RANK_NODE *task_rank_node;

    task_rank_node = (TASK_RANK_NODE *)cvector_get(task_rank_tbl, rank);
    if(NULL_PTR == task_rank_node)
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_rank_tbl_disable: task_rank_node for rank %ld does not exist\n", rank);
        return (EC_FALSE);
    }

    task_rank_node_disable(task_rank_node);
    return (EC_TRUE);
}

EC_BOOL task_rank_tbl_disable_all(CVECTOR *task_rank_tbl)
{
    cvector_loop_front(task_rank_tbl, (CVECTOR_DATA_HANDLER)task_rank_node_disable);
    return (EC_TRUE);
}

void task_rank_tbl_print(LOG *log, const CVECTOR *task_rank_tbl)
{
    cvector_print(log, task_rank_tbl, (CVECTOR_DATA_PRINT)task_rank_node_print);
    return;
}

void task_queue_print(LOG *log, const CLIST *task_queue)
{
    clist_print(log, task_queue, (CLIST_DATA_DATA_PRINT)task_node_print);
    return;
}

/*discard those being recved from the taskComm tcid*/
EC_BOOL task_queue_discard_from(TASK_BRD *task_brd, CLIST *task_queue, const UINT32 tag, const UINT32 tcid)
{
    CLIST_DATA *clist_data;

    CLIST_LOCK(task_queue, LOC_TASK_0065);
    CLIST_LOOP_NEXT(task_queue, clist_data)
    {
        TASK_NODE  *task_node;
        TASK_ANY   *task_any;

        task_node = (TASK_NODE *)CLIST_DATA_DATA(clist_data);
        task_any  = TASK_NODE_ANY(task_node);
#if 0
        if(NULL_PTR != TASK_ANY_CTHREAD_NODE(task_any))
        {
            continue;
        }
#endif
        if(tag == TASK_ANY_TAG(task_any) && tcid == TASK_ANY_SEND_TCID(task_any))
        {
            CLIST_DATA *clist_data_rmv;

            clist_data_rmv = clist_data;
            clist_data = CLIST_DATA_PREV(clist_data);

            clist_rmv_no_lock(task_queue, clist_data_rmv);

            if(TAG_TASK_REQ == TASK_NODE_TAG(task_node) && NULL_PTR != TASK_REQ_CTHREAD_NODE(TASK_NODE_REQ(task_node)))
            {
                croutine_node_shutdown(TASK_REQ_CTHREAD_NODE(TASK_NODE_REQ(task_node)), TASK_REQ_CTHREAD_POOL(task_brd));
                TASK_REQ_CTHREAD_NODE(TASK_NODE_REQ(task_node)) = NULL_PTR;
            }

            if(TAG_TASK_FWD == TASK_NODE_TAG(task_node) && NULL_PTR != TASK_FWD_CTHREAD_NODE(TASK_NODE_FWD(task_node)))
            {
                croutine_node_shutdown(TASK_FWD_CTHREAD_NODE(TASK_NODE_FWD(task_node)), TASK_FWD_CTHREAD_POOL(task_brd));
                TASK_FWD_CTHREAD_NODE(TASK_NODE_FWD(task_node)) = NULL_PTR;
            }

/******************************************************************************************************************************
            if(TAG_TASK_RSP == TASK_NODE_TAG(task_node) && NULL_PTR != TASK_RSP_CTHREAD_NODE(TASK_NODE_RSP(task_node)))
            {
                cthread_node_shutdown(TASK_RSP_CTHREAD_NODE(TASK_NODE_RSP(task_node)), TASK_RSP_CTHREAD_POOL(task_brd));
                TASK_RSP_CTHREAD_NODE(TASK_NODE_RSP(task_node)) = NULL_PTR;
            }
******************************************************************************************************************************/
            dbg_log(SEC_0015_TASK, 5)(LOGSTDOUT, "lost   any: from (tcid %s,comm %ld,rank %ld,modi %ld) to (tcid %s,comm %ld,rank %ld,modi %ld) with priority %ld, "
                               "type %ld, tag %ld, ldb %ld, seqno %lx.%lx.%lx, subseqno %ld, func id %lx from broken tcid %s\n",
                            TASK_ANY_SEND_TCID_STR(task_any), TASK_ANY_SEND_COMM(task_any), TASK_ANY_SEND_RANK(task_any), TASK_ANY_SEND_MODI(task_any),
                            TASK_ANY_RECV_TCID_STR(task_any), TASK_ANY_RECV_COMM(task_any), TASK_ANY_RECV_RANK(task_any), TASK_ANY_RECV_MODI(task_any),
                            TASK_ANY_PRIO(task_any), TASK_ANY_TYPE(task_any),
                            TASK_ANY_TAG(task_any), TASK_ANY_LDB_CHOICE(task_any),
                            TASK_ANY_SEND_TCID(task_any), TASK_ANY_SEND_RANK(task_any), TASK_ANY_SEQNO(task_any), TASK_ANY_SUB_SEQNO(task_any),
                            TASK_ANY_FUNC_ID(task_any),
                            c_word_to_ipv4(tcid)
                            );

            task_node_free(task_node);
        }
    }
    CLIST_UNLOCK(task_queue, LOC_TASK_0066);
    return (EC_TRUE);
}

/*discard those will send to the taskComm tcid*/
EC_BOOL task_queue_discard_to(TASK_BRD *task_brd, CLIST *task_queue, const UINT32 tag, const UINT32 tcid)
{
    CLIST_DATA *clist_data;

    CLIST_LOCK(task_queue, LOC_TASK_0067);
    CLIST_LOOP_NEXT(task_queue, clist_data)
    {
        TASK_NODE  *task_node;
        TASK_ANY   *task_any;

        task_node = (TASK_NODE *)CLIST_DATA_DATA(clist_data);
        task_any  = TASK_NODE_ANY(task_node);
#if 0
        if(NULL_PTR != TASK_ANY_CTHREAD_NODE(task_any))
        {
            continue;
        }
#endif
        if(tag == TASK_ANY_TAG(task_any) && tcid == TASK_ANY_RECV_TCID(task_any))
        {
            CLIST_DATA *clist_data_rmv;

            clist_data_rmv = clist_data;
            clist_data = CLIST_DATA_PREV(clist_data);

            clist_rmv_no_lock(task_queue, clist_data_rmv);

            dbg_log(SEC_0015_TASK, 5)(LOGSTDOUT, "lost   any: from (tcid %s,comm %ld,rank %ld,modi %ld) to (tcid %s,comm %ld,rank %ld,modi %ld) with priority %ld, "
                               "type %ld, tag %ld, ldb %ld, seqno %lx.%lx.%lx, subseqno %ld, func id %lx to broken tcid %s\n",
                            TASK_ANY_SEND_TCID_STR(task_any), TASK_ANY_SEND_COMM(task_any), TASK_ANY_SEND_RANK(task_any), TASK_ANY_SEND_MODI(task_any),
                            TASK_ANY_RECV_TCID_STR(task_any), TASK_ANY_RECV_COMM(task_any), TASK_ANY_RECV_RANK(task_any), TASK_ANY_RECV_MODI(task_any),
                            TASK_ANY_PRIO(task_any), TASK_ANY_TYPE(task_any),
                            TASK_ANY_TAG(task_any), TASK_ANY_LDB_CHOICE(task_any),
                            TASK_ANY_SEND_TCID(task_any), TASK_ANY_SEND_RANK(task_any), TASK_ANY_SEQNO(task_any), TASK_ANY_SUB_SEQNO(task_any),
                            TASK_ANY_FUNC_ID(task_any),
                            c_word_to_ipv4(tcid)
                            );

            task_node_free(task_node);
        }
    }
    CLIST_UNLOCK(task_queue, LOC_TASK_0068);
    return (EC_TRUE);
}

/*process those being recved from the taskComm tcid*/
EC_BOOL task_queue_process_from(TASK_BRD *task_brd, CLIST *task_queue, const UINT32 tag, const UINT32 tcid)
{
    if(CMPI_FWD_RANK == TASK_BRD_RANK(task_brd))
    {
        /*continue forwarding to target (taskComm, Rank)*/
        /*okay, nothing to do, just keep the task node in queue*/
        return (EC_TRUE);
    }

    if(TAG_TASK_RSP == tag)
    {
        /*continue decoding TASK_RSP to fetch response of the TASK_REQ*/
        /*okay, nothing to do, just keep the task node in queue*/
        return (EC_TRUE);
    }

    /*nothing to do*/
    return (EC_TRUE);
}

/*process those being sending to the taskComm tcid*/
EC_BOOL task_queue_process_to(TASK_BRD *task_brd, CLIST *task_queue, const UINT32 tag, const UINT32 tcid)
{
    /*nothing to do*/
    return (EC_TRUE);
}

/*reschedule those being recved from the taskComm tcid*/
EC_BOOL task_queue_reschedule_from(TASK_BRD *task_brd, CLIST *task_queue, const UINT32 tag, const UINT32 tcid)
{
    /*TODO:*/
    return (EC_TRUE);
}

/*reschedule or discard those task req sending to the taskComm tcid according to each task mgr setting*/
EC_BOOL task_mgr_list_handle_broken_taskcomm(TASK_BRD *task_brd, const UINT32 tcid)
{
    CLIST      *task_mgr_list;
    CLIST_DATA *clist_data;

    task_mgr_list = TASK_BRD_RECV_TASK_MGR_LIST(task_brd);
    /*handle one of existing task req and task rsp*/
    CLIST_LOCK(task_mgr_list, LOC_TASK_0069);
    CLIST_LOOP_NEXT(task_mgr_list, clist_data)
    {
        TASK_MGR *task_mgr;

        task_mgr = (TASK_MGR *)CLIST_DATA_DATA(clist_data);

        if(TASK_NEED_RESCHEDULE_FLAG == TASK_MGR_NEED_RESCHEDULE_FLAG(task_mgr))
        {
            /*reschedule task req to broken taskComm: reset its status to TASK_REQ_TO_SEND and wait for re-sending by load balance strategy*/
            task_mgr_reschedule_to(task_brd, task_mgr, tcid);
        }
        else
        {
            /*discard task req to broken taskComm: reset its status to TASK_REQ_DISCARD*/
            task_mgr_discard_to(task_brd, task_mgr, tcid);
        }
    }
    CLIST_UNLOCK(task_mgr_list, LOC_TASK_0070);

    return (EC_TRUE);
}

void task_brd_task_mgr_list_print(LOG *log, const TASK_BRD *task_brd)
{
    CLIST      *task_mgr_list;
    CLIST_DATA *clist_data;

    task_mgr_list = (CLIST *)TASK_BRD_RECV_TASK_MGR_LIST(task_brd);

    CLIST_LOCK(task_mgr_list, LOC_TASK_0071);
    CLIST_LOOP_NEXT(task_mgr_list, clist_data)
    {
        TASK_MGR *task_mgr;
        task_mgr = (TASK_MGR *)CLIST_DATA_DATA(clist_data);
        task_mgr_print(log, task_mgr);
    }
    CLIST_UNLOCK(task_mgr_list, LOC_TASK_0072);
    return;
}

EC_BOOL task_brd_mod_mgr_list_excl(TASK_BRD *task_brd, const UINT32 tcid)
{
    CLIST *mod_mgr_list;
    CLIST_DATA *clist_data;

    /*clean MOD_MGR list in task_brd*/
    mod_mgr_list = TASK_BRD_MOD_MGR_LIST(task_brd);

    CLIST_LOCK(mod_mgr_list, LOC_TASK_0073);
    CLIST_LOOP_NEXT(mod_mgr_list, clist_data)
    {
        MOD_MGR *mod_mgr;

        mod_mgr = (MOD_MGR *)CLIST_DATA_DATA(clist_data);
        mod_mgr_excl(tcid, CMPI_ANY_COMM, CMPI_ANY_RANK, CMPI_ANY_MODI, mod_mgr);
    }
    CLIST_UNLOCK(mod_mgr_list, LOC_TASK_0074);
    return (EC_TRUE);
}

void task_brd_mod_mgr_list_print(LOG *log, TASK_BRD *task_brd)
{
    clist_print(log, TASK_BRD_MOD_MGR_LIST(task_brd), (CLIST_DATA_DATA_PRINT)mod_mgr_print);
    return;
}

void task_brd_do_nothing(void *none)
{
    dbg_log(SEC_0015_TASK, 5)(LOGSTDOUT, "task_brd_do_nothing was called\n");
    return;
}

EC_BOOL task_mgr_init(const UINT32 seqno, const UINT32 task_prio, const UINT32 task_need_rsp_flag, const UINT32 task_need_rsp_num, const MOD_MGR *mod_mgr, TASK_MGR *task_mgr)
{
    //sys_log(LOGSTDOUT, "[DEBUG] [tid %ld] task_mgr_init: init task_mgr %p\n", CTHREAD_GET_TID(), task_mgr);

    TASK_MGR_MOD(task_mgr) = (MOD_MGR *)mod_mgr/*NULL_PTR*/;

    TASK_MGR_PRIO(task_mgr)                 = task_prio;
    TASK_MGR_SEQNO(task_mgr)                = seqno;
    TASK_MGR_SUB_SEQNO_GEN(task_mgr)        = 0;/*intialize generator*/
    TASK_MGR_NEED_RSP_FLAG(task_mgr)        = task_need_rsp_flag;
    TASK_MGR_MOD_FREE_FLAG(task_mgr)        = EC_FALSE;
    TASK_MGR_JMP_FLAG(task_mgr)             = EC_FALSE;
    TASK_MGR_AGING_FLAG(task_mgr)           = EC_FALSE;
    TASK_MGR_RECVING_FLAG(task_mgr)         = EC_FALSE;

    TASK_MGR_COUNTER(task_mgr, TASK_MGR_COUNTER_TASK_RSP_IS_NEED) = task_need_rsp_num;
    TASK_MGR_COUNTER(task_mgr, TASK_MGR_COUNTER_TASK_RSP_IS_SUCC) = 0;
    TASK_MGR_COUNTER(task_mgr, TASK_MGR_COUNTER_TASK_RSP_IS_FAIL) = 0;
    TASK_MGR_COUNTER(task_mgr, TASK_MGR_COUNTER_TASK_REQ_IS_SENT) = 0;
    TASK_MGR_COUNTER(task_mgr, TASK_MGR_COUNTER_TASK_REQ_DISCARD) = 0;
    TASK_MGR_COUNTER(task_mgr, TASK_MGR_COUNTER_TASK_REQ_TIMEOUT) = 0;
    TASK_MGR_COUNTER(task_mgr, TASK_MGR_COUNTER_TASK_RSP_RESERVD) = 0;

    task_queue_init(TASK_MGR_QUEUE(task_mgr));

    TASK_MGR_CCOND_INIT(task_mgr, LOC_TASK_0075);
    TASK_MGR_CRWLOCK_INIT(task_mgr, LOC_TASK_0076);

    //sys_log(LOGSTDOUT, "[DEBUG] [tid %ld] task_mgr_init: task_mgr %p, ccond %p, ->var.__data.__nwaiters %d\n", CTHREAD_GET_TID(), task_mgr, (TASK_MGR_CROUTINE_COND(task_mgr)), (TASK_MGR_CROUTINE_COND(task_mgr))->var.__data.__nwaiters);
    return (EC_TRUE);
}

UINT32 task_mgr_sub_seqno_gen(TASK_MGR *task_mgr, UINT32 *sub_seqno_new)
{
    UINT32 sub_seqno;

    sub_seqno = TASK_MGR_SUB_SEQNO_GEN(task_mgr);
    TASK_MGR_SUB_SEQNO_GEN(task_mgr) ++;
    *sub_seqno_new = sub_seqno;

    return (0);
}

EC_BOOL task_mgr_clean(TASK_MGR *task_mgr)
{
    //sys_log(LOGSTDOUT, "[DEBUG] [tid %ld] task_mgr_clean: clean task_mgr %p\n", CTHREAD_GET_TID(), task_mgr);
    TASK_MGR_CRWLOCK_WRLOCK(task_mgr, LOC_TASK_0077);

    TASK_MGR_MOD(task_mgr) = NULL_PTR;

    TASK_MGR_PRIO(task_mgr)                 = TASK_PRIO_UNDEF;
    TASK_MGR_SEQNO(task_mgr)                = 0;
    TASK_MGR_SUB_SEQNO_GEN(task_mgr)        = 0;/*intialize generator*/
    TASK_MGR_NEED_RSP_FLAG(task_mgr)        = TASK_NOT_NEED_RSP_FLAG;
    TASK_MGR_MOD_FREE_FLAG(task_mgr)        = EC_FALSE;
    TASK_MGR_JMP_FLAG(task_mgr)             = EC_FALSE;
    TASK_MGR_AGING_FLAG(task_mgr)           = EC_FALSE;
    TASK_MGR_RECVING_FLAG(task_mgr)         = EC_FALSE;

    TASK_MGR_COUNTER(task_mgr, TASK_MGR_COUNTER_TASK_RSP_IS_NEED) = 0;
    TASK_MGR_COUNTER(task_mgr, TASK_MGR_COUNTER_TASK_RSP_IS_SUCC) = 0;
    TASK_MGR_COUNTER(task_mgr, TASK_MGR_COUNTER_TASK_RSP_IS_FAIL) = 0;
    TASK_MGR_COUNTER(task_mgr, TASK_MGR_COUNTER_TASK_REQ_IS_SENT) = 0;
    TASK_MGR_COUNTER(task_mgr, TASK_MGR_COUNTER_TASK_REQ_DISCARD) = 0;
    TASK_MGR_COUNTER(task_mgr, TASK_MGR_COUNTER_TASK_REQ_TIMEOUT) = 0;
    TASK_MGR_COUNTER(task_mgr, TASK_MGR_COUNTER_TASK_RSP_RESERVD) = 0;

    task_queue_clean(TASK_MGR_QUEUE(task_mgr));

    TASK_MGR_CRWLOCK_UNLOCK(task_mgr, LOC_TASK_0078);

    //TASK_MGR_CCOND_RELEASE_ALL(task_mgr, LOC_TASK_0079);
    //TASK_MGR_CCOND_RELEASE(task_mgr, LOC_TASK_0080);
    TASK_MGR_CCOND_CLEAN(task_mgr, LOC_TASK_0081);
    TASK_MGR_CRWLOCK_CLEAN(task_mgr, LOC_TASK_0082);
#if 0
    sys_log(LOGSTDOUT, "[DEBUG] [tid %ld] task_mgr_clean: task_mgr %p, ccond %p, ->var.__data.__nwaiters %d\n",
                        CTHREAD_GET_TID(),
                        task_mgr, (TASK_MGR_CROUTINE_COND(task_mgr)), (TASK_MGR_CROUTINE_COND(task_mgr))->var.__data.__nwaiters);
#endif
    return (EC_TRUE);
}

EC_BOOL task_mgr_free(TASK_MGR *task_mgr)
{
    if(EC_TRUE == TASK_MGR_MOD_FREE_FLAG(task_mgr) && NULL_PTR != TASK_MGR_MOD(task_mgr))
    {
        mod_mgr_free(TASK_MGR_MOD(task_mgr));
        TASK_MGR_MOD(task_mgr) = NULL_PTR;
    }

    task_mgr_clean(task_mgr);

    //sys_log(LOGSTDOUT, "[DEBUG] [tid %ld] task_mgr_free: task_mgr %p, ccond %p, ->var.__data.__nwaiters %d\n", CTHREAD_GET_TID(), task_mgr, (TASK_MGR_CROUTINE_COND(task_mgr)), (TASK_MGR_CROUTINE_COND(task_mgr))->var.__data.__nwaiters);
    free_static_mem(MM_TASK_MGR, task_mgr, LOC_TASK_0083);

    return (EC_TRUE);
}

EC_BOOL task_mgr_req_match(const TASK_MGR *task_mgr, const TASK_RSP *task_rsp, TASK_REQ **task_req)
{
    CLIST      *task_queue;
    CLIST_DATA *clist_data;

    task_queue = TASK_MGR_QUEUE((TASK_MGR *)task_mgr);

    CLIST_LOCK(task_queue, LOC_TASK_0084);
    CLIST_LOOP_NEXT(task_queue, clist_data)
    {
        TASK_NODE  *task_node;
        TASK_REQ   *this_task_req;

        task_node     = (TASK_NODE *)CLIST_DATA_DATA(clist_data);
        this_task_req = TASK_NODE_REQ(task_node);

        if( TASK_RSP_SEND_TCID(task_rsp) == TASK_REQ_RECV_TCID(this_task_req)
         && (CMPI_ANY_COMM == TASK_REQ_RECV_COMM(this_task_req) || TASK_RSP_SEND_COMM(task_rsp) == TASK_REQ_RECV_COMM(this_task_req))
         && TASK_RSP_SEND_RANK(task_rsp) == TASK_REQ_RECV_RANK(this_task_req)
         && TASK_RSP_SEND_MODI(task_rsp) == TASK_REQ_RECV_MODI(this_task_req)
         && TASK_RSP_SEQNO(task_rsp)     == TASK_REQ_SEQNO(this_task_req)
         && TASK_RSP_SUB_SEQNO(task_rsp) == TASK_REQ_SUB_SEQNO(this_task_req))
        {
            *task_req = this_task_req;

            CLIST_UNLOCK(task_queue, LOC_TASK_0085);
            return (EC_TRUE);
        }
    }
    CLIST_UNLOCK(task_queue, LOC_TASK_0086);
    return (EC_FALSE);
}

EC_BOOL task_mgr_match_seqno(const TASK_MGR *task_mgr, const UINT32 seqno)
{
    if( seqno == TASK_MGR_SEQNO(task_mgr))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

TASK_REQ * task_mgr_search_task_req_by_recver(const TASK_MGR *task_mgr, const UINT32 seqno, const UINT32 subseqno, const MOD_NODE *recv_mod_node)
{
    CLIST      *task_queue;
    CLIST_DATA *clist_data;

    task_queue = TASK_MGR_QUEUE((TASK_MGR *)task_mgr);

    CLIST_LOCK(task_queue, LOC_TASK_0087);
    CLIST_LOOP_NEXT(task_queue, clist_data)
    {
        TASK_NODE  *task_node;
        TASK_REQ   *task_req;

        task_node = (TASK_NODE *)CLIST_DATA_DATA(clist_data);
        task_req  = TASK_NODE_REQ(task_node);

        if( MOD_NODE_TCID(recv_mod_node) == TASK_REQ_RECV_TCID(task_req)
         && (CMPI_ANY_COMM == TASK_REQ_RECV_COMM(task_req) || MOD_NODE_COMM(recv_mod_node) == TASK_REQ_RECV_COMM(task_req))
         && MOD_NODE_RANK(recv_mod_node) == TASK_REQ_RECV_RANK(task_req)
         && MOD_NODE_MODI(recv_mod_node) == TASK_REQ_RECV_MODI(task_req)
         && seqno    == TASK_REQ_SEQNO(task_req)
         && subseqno == TASK_REQ_SUB_SEQNO(task_req))
        {
            CLIST_UNLOCK(task_queue, LOC_TASK_0088);
            return (task_req);
        }
    }
    CLIST_UNLOCK(task_queue, LOC_TASK_0089);
    return (NULL_PTR);
}

TASK_CONTEXT * task_context_new()
{
    TASK_CONTEXT *task_context;

    alloc_static_mem(MM_TASK_CONTEXT, &task_context, LOC_TASK_0090);
    if(NULL_PTR != task_context)
    {
        task_context_init(task_context);
    }
    return (task_context);
}

EC_BOOL task_context_init(TASK_CONTEXT *task_context)
{
    TASK_CONTEXT_TASK_RSP(task_context) = NULL_PTR;;
    return (EC_TRUE);
}

EC_BOOL task_context_clean(TASK_CONTEXT *task_context)
{
    if(NULL_PTR != TASK_CONTEXT_TASK_RSP(task_context))
    {
        task_rsp_free(TASK_CONTEXT_TASK_RSP(task_context));
        TASK_CONTEXT_TASK_RSP(task_context) = NULL_PTR;;
    }
    return (EC_TRUE);
}

EC_BOOL task_context_free(TASK_CONTEXT *task_context)
{
    if(NULL_PTR != task_context)
    {
        task_context_clean(task_context);
        free_static_mem(MM_TASK_CONTEXT, task_context, LOC_TASK_0091);
    }
    return (EC_TRUE);
}

EC_BOOL task_time_fmt_init(TASK_TIME_FMT *task_time_fmt)
{
    TASK_TIME_FMT_YEAR(task_time_fmt)  = (UINT32)-1;
    TASK_TIME_FMT_MONTH(task_time_fmt) = (UINT32)-1;
    TASK_TIME_FMT_MDAY(task_time_fmt)  = (UINT32)-1;
    TASK_TIME_FMT_HOUR(task_time_fmt)  = (UINT32)-1;
    TASK_TIME_FMT_MIN(task_time_fmt)   = (UINT32)-1;
    TASK_TIME_FMT_SEC(task_time_fmt)   = (UINT32)-1;

    return (EC_TRUE);
}

EC_BOOL task_time_fmt_clean(TASK_TIME_FMT *task_time_fmt)
{
    TASK_TIME_FMT_YEAR(task_time_fmt)  = (UINT32)-1;
    TASK_TIME_FMT_MONTH(task_time_fmt) = (UINT32)-1;
    TASK_TIME_FMT_MDAY(task_time_fmt)  = (UINT32)-1;
    TASK_TIME_FMT_HOUR(task_time_fmt)  = (UINT32)-1;
    TASK_TIME_FMT_MIN(task_time_fmt)   = (UINT32)-1;
    TASK_TIME_FMT_SEC(task_time_fmt)   = (UINT32)-1;

    return (EC_TRUE);
}

EC_BOOL task_time_fmt_clone(const TASK_TIME_FMT *task_time_fmt_src, TASK_TIME_FMT *task_time_fmt_des)
{
    TASK_TIME_FMT_YEAR(task_time_fmt_des)  = TASK_TIME_FMT_YEAR(task_time_fmt_src) ;
    TASK_TIME_FMT_MONTH(task_time_fmt_des) = TASK_TIME_FMT_MONTH(task_time_fmt_src);
    TASK_TIME_FMT_MDAY(task_time_fmt_des)  = TASK_TIME_FMT_MDAY(task_time_fmt_src) ;
    TASK_TIME_FMT_HOUR(task_time_fmt_des)  = TASK_TIME_FMT_HOUR(task_time_fmt_src) ;
    TASK_TIME_FMT_MIN(task_time_fmt_des)   = TASK_TIME_FMT_MIN(task_time_fmt_src)  ;
    TASK_TIME_FMT_SEC(task_time_fmt_des)   = TASK_TIME_FMT_SEC(task_time_fmt_src)  ;
    return (EC_TRUE);
}


EC_BOOL task_report_node_new(TASK_REPORT_NODE **task_report_node)
{
    alloc_static_mem(MM_TASK_REPORT_NODE, task_report_node, LOC_TASK_0092);
    task_report_node_init((*task_report_node));
    return (EC_TRUE);
}

EC_BOOL task_report_node_init(TASK_REPORT_NODE *task_report_node)
{
    task_time_fmt_init(TASK_REPORT_NODE_START_TIME(task_report_node));
    task_time_fmt_init(TASK_REPORT_NODE_END_TIME(task_report_node));

    TASK_REPORT_NODE_TCID(task_report_node)  = CMPI_ERROR_TCID;
    TASK_REPORT_NODE_RANK(task_report_node)  = CMPI_ERROR_RANK;
    TASK_REPORT_NODE_SEQNO(task_report_node) = (UINT32)-1;

    TASK_REPORT_NODE_TIME_TO_LIVE(task_report_node) = (UINT32)-1;

    TASK_REPORT_NODE_WAIT_FLAG(task_report_node) = EC_FALSE;
    TASK_REPORT_NODE_NEED_RSP_FLAG(task_report_node) = TASK_NOT_NEED_RSP_FLAG;
    TASK_REPORT_NODE_NEED_RESCHEDULE_FLAG(task_report_node) = TASK_NOT_NEED_RESCHEDULE_FLAG;

    TASK_REPORT_NODE_TOTAL_REQ_NUM(task_report_node)   = 0;
    TASK_REPORT_NODE_SENT_REQ_NUM(task_report_node)    = 0;
    TASK_REPORT_NODE_DISCARD_REQ_NUM(task_report_node) = 0;
    TASK_REPORT_NODE_TIMEOUT_REQ_NUM(task_report_node) = 0;
    TASK_REPORT_NODE_NEED_RSP_NUM(task_report_node) = 0;
    TASK_REPORT_NODE_SUCC_RSP_NUM(task_report_node) = 0;
    TASK_REPORT_NODE_FAIL_RSP_NUM(task_report_node) = 0;

    return (EC_TRUE);
}

EC_BOOL task_report_node_clean(TASK_REPORT_NODE *task_report_node)
{
    task_time_fmt_clean(TASK_REPORT_NODE_START_TIME(task_report_node));
    task_time_fmt_clean(TASK_REPORT_NODE_END_TIME(task_report_node));

    TASK_REPORT_NODE_TCID(task_report_node)  = CMPI_ERROR_TCID;
    TASK_REPORT_NODE_RANK(task_report_node)  = CMPI_ERROR_RANK;
    TASK_REPORT_NODE_SEQNO(task_report_node) = (UINT32)-1;

    TASK_REPORT_NODE_TIME_TO_LIVE(task_report_node) = (UINT32)-1;

    TASK_REPORT_NODE_WAIT_FLAG(task_report_node) = EC_FALSE;
    TASK_REPORT_NODE_NEED_RSP_FLAG(task_report_node) = TASK_NOT_NEED_RSP_FLAG;
    TASK_REPORT_NODE_NEED_RESCHEDULE_FLAG(task_report_node) = TASK_NOT_NEED_RESCHEDULE_FLAG;

    TASK_REPORT_NODE_TOTAL_REQ_NUM(task_report_node)   = 0;
    TASK_REPORT_NODE_SENT_REQ_NUM(task_report_node)    = 0;
    TASK_REPORT_NODE_DISCARD_REQ_NUM(task_report_node) = 0;
    TASK_REPORT_NODE_TIMEOUT_REQ_NUM(task_report_node) = 0;
    TASK_REPORT_NODE_NEED_RSP_NUM(task_report_node) = 0;
    TASK_REPORT_NODE_SUCC_RSP_NUM(task_report_node) = 0;
    TASK_REPORT_NODE_FAIL_RSP_NUM(task_report_node) = 0;
    return (EC_TRUE);
}

EC_BOOL task_report_node_free(TASK_REPORT_NODE *task_report_node)
{
    if(NULL_PTR != task_report_node)
    {
        task_report_node_clean(task_report_node);
        free_static_mem(MM_TASK_REPORT_NODE, task_report_node, LOC_TASK_0093);
    }
    return (EC_TRUE);
}

EC_BOOL task_report_node_gen(TASK_REPORT_NODE *task_report_node, const TASK_BRD *task_brd, const TASK_MGR *task_mgr)
{
    TASK_TIME_FMT *start_time;
    TASK_TIME_FMT *end_time;
    CTM *task_mgr_start_tm;
    CTM *task_mgr_end_tm;

    start_time = TASK_REPORT_NODE_START_TIME(task_report_node);
    end_time   = TASK_REPORT_NODE_END_TIME(task_report_node);

    task_mgr_start_tm = CTIMET_TO_TM(TASK_MGR_START_TIME_SEC(task_mgr));
    TASK_TIME_FMT_YEAR(start_time)  = CTM_YEAR(task_mgr_start_tm);
    TASK_TIME_FMT_MONTH(start_time) = CTM_MONTH(task_mgr_start_tm);
    TASK_TIME_FMT_MDAY(start_time)  = CTM_MDAY(task_mgr_start_tm);
    TASK_TIME_FMT_HOUR(start_time)  = CTM_HOUR(task_mgr_start_tm);
    TASK_TIME_FMT_MIN(start_time)   = CTM_MIN(task_mgr_start_tm);
    TASK_TIME_FMT_SEC(start_time)   = CTM_SEC(task_mgr_start_tm);

    task_mgr_end_tm = CTIMET_TO_TM(TASK_MGR_END_TIME_SEC(task_mgr));
    TASK_TIME_FMT_YEAR(end_time)  = CTM_YEAR(task_mgr_end_tm);
    TASK_TIME_FMT_MONTH(end_time) = CTM_MONTH(task_mgr_end_tm);
    TASK_TIME_FMT_MDAY(end_time)  = CTM_MDAY(task_mgr_end_tm);
    TASK_TIME_FMT_HOUR(end_time)  = CTM_HOUR(task_mgr_end_tm);
    TASK_TIME_FMT_MIN(end_time)   = CTM_MIN(task_mgr_end_tm);
    TASK_TIME_FMT_SEC(end_time)   = CTM_SEC(task_mgr_end_tm);

    TASK_REPORT_NODE_TCID(task_report_node)  = TASK_BRD_TCID(task_brd);
    TASK_REPORT_NODE_RANK(task_report_node)  = TASK_BRD_RANK(task_brd);
    TASK_REPORT_NODE_SEQNO(task_report_node) = TASK_MGR_SEQNO(task_mgr);

    TASK_REPORT_NODE_TIME_TO_LIVE(task_report_node) = TASK_MGR_TIME_TO_LIVE(task_mgr);

    TASK_REPORT_NODE_WAIT_FLAG(task_report_node) = TASK_MGR_JMP_FLAG(task_mgr);
    TASK_REPORT_NODE_NEED_RSP_FLAG(task_report_node) = TASK_MGR_NEED_RSP_FLAG(task_mgr);
    TASK_REPORT_NODE_NEED_RESCHEDULE_FLAG(task_report_node) = TASK_MGR_NEED_RESCHEDULE_FLAG(task_mgr);

    TASK_REPORT_NODE_TOTAL_REQ_NUM(task_report_node)   = clist_size(TASK_MGR_QUEUE(task_mgr));

    TASK_REPORT_NODE_SENT_REQ_NUM(task_report_node)    = TASK_MGR_COUNTER(task_mgr, TASK_MGR_COUNTER_TASK_REQ_IS_SENT);
    TASK_REPORT_NODE_DISCARD_REQ_NUM(task_report_node) = TASK_MGR_COUNTER(task_mgr, TASK_MGR_COUNTER_TASK_REQ_DISCARD);
    TASK_REPORT_NODE_TIMEOUT_REQ_NUM(task_report_node) = TASK_MGR_COUNTER(task_mgr, TASK_MGR_COUNTER_TASK_REQ_TIMEOUT);

    TASK_REPORT_NODE_NEED_RSP_NUM(task_report_node) = TASK_MGR_COUNTER(task_mgr, TASK_MGR_COUNTER_TASK_RSP_IS_NEED);
    TASK_REPORT_NODE_SUCC_RSP_NUM(task_report_node) = TASK_MGR_COUNTER(task_mgr, TASK_MGR_COUNTER_TASK_RSP_IS_SUCC);
    TASK_REPORT_NODE_FAIL_RSP_NUM(task_report_node) = TASK_MGR_COUNTER(task_mgr, TASK_MGR_COUNTER_TASK_RSP_IS_FAIL);

    return (EC_TRUE);
}

EC_BOOL task_report_node_clone(const TASK_REPORT_NODE *task_report_node_src, TASK_REPORT_NODE *task_report_node_des)
{
    task_time_fmt_clone(TASK_REPORT_NODE_START_TIME(task_report_node_src), TASK_REPORT_NODE_START_TIME(task_report_node_des));
    task_time_fmt_clone(TASK_REPORT_NODE_END_TIME(task_report_node_src), TASK_REPORT_NODE_END_TIME(task_report_node_des));

    TASK_REPORT_NODE_TCID(task_report_node_des)  = TASK_REPORT_NODE_TCID(task_report_node_src) ;
    TASK_REPORT_NODE_RANK(task_report_node_des)  = TASK_REPORT_NODE_RANK(task_report_node_src) ;
    TASK_REPORT_NODE_SEQNO(task_report_node_des) = TASK_REPORT_NODE_SEQNO(task_report_node_src);

    TASK_REPORT_NODE_TIME_TO_LIVE(task_report_node_des) = TASK_REPORT_NODE_TIME_TO_LIVE(task_report_node_src);

    TASK_REPORT_NODE_WAIT_FLAG(task_report_node_des)            = TASK_REPORT_NODE_WAIT_FLAG(task_report_node_src);
    TASK_REPORT_NODE_NEED_RSP_FLAG(task_report_node_des)        = TASK_REPORT_NODE_NEED_RSP_FLAG(task_report_node_src);
    TASK_REPORT_NODE_NEED_RESCHEDULE_FLAG(task_report_node_des) = TASK_REPORT_NODE_NEED_RESCHEDULE_FLAG(task_report_node_src);

    TASK_REPORT_NODE_TOTAL_REQ_NUM(task_report_node_des)   = TASK_REPORT_NODE_TOTAL_REQ_NUM(task_report_node_src);

    TASK_REPORT_NODE_SENT_REQ_NUM(task_report_node_des)    = TASK_REPORT_NODE_SENT_REQ_NUM(task_report_node_src)   ;
    TASK_REPORT_NODE_DISCARD_REQ_NUM(task_report_node_des) = TASK_REPORT_NODE_DISCARD_REQ_NUM(task_report_node_src);
    TASK_REPORT_NODE_TIMEOUT_REQ_NUM(task_report_node_des) = TASK_REPORT_NODE_TIMEOUT_REQ_NUM(task_report_node_src);

    TASK_REPORT_NODE_NEED_RSP_NUM(task_report_node_des) = TASK_REPORT_NODE_NEED_RSP_NUM(task_report_node_src);
    TASK_REPORT_NODE_SUCC_RSP_NUM(task_report_node_des) = TASK_REPORT_NODE_SUCC_RSP_NUM(task_report_node_src);
    TASK_REPORT_NODE_FAIL_RSP_NUM(task_report_node_des) = TASK_REPORT_NODE_FAIL_RSP_NUM(task_report_node_src);

    return (EC_TRUE);
}

EC_BOOL task_brd_md_node_tbl_init(TASK_BRD *task_brd)
{
    UINT32 md_type;
    FUNC_ADDR_MGR *func_addr_mgr;

    cvector_init(TASK_BRD_MD_NODE_TBL(task_brd), MD_END, MM_FUNC_ADDR_MGR, CVECTOR_LOCK_ENABLE, LOC_TASK_0094);
    for(md_type = 0; md_type < MD_END; md_type ++)
    {
        func_addr_mgr = dbg_fetch_func_addr_mgr_by_md_type(md_type);
        cvector_push(TASK_BRD_MD_NODE_TBL(task_brd), (void *)func_addr_mgr);
    }
    return (EC_TRUE);
}

EC_BOOL task_brd_rank_load_tbl_init(TASK_BRD *task_brd)
{
    cload_mgr_init(TASK_BRD_CLOAD_MGR(task_brd));
    task_brd_rank_load_tbl_push_all(task_brd, TASK_BRD_TCID(task_brd), TASK_BRD_SIZE(task_brd));
    return (EC_TRUE);
}

EC_BOOL task_brd_rank_load_tbl_clean(TASK_BRD *task_brd)
{
    return cload_mgr_clean(TASK_BRD_CLOAD_MGR(task_brd));
}

EC_BOOL task_brd_rank_load_tbl_push(TASK_BRD *task_brd, const UINT32 tcid, const UINT32 rank, const UINT32 load)
{
    return cload_mgr_set_que(TASK_BRD_CLOAD_MGR(task_brd), tcid, rank, load);
}

EC_BOOL task_brd_rank_load_tbl_push_all(TASK_BRD *task_brd, const UINT32 tcid, const UINT32 size)
{
    UINT32 rank;

    for(rank = 0; rank < size; rank ++)
    {
        task_brd_rank_load_tbl_set_que(task_brd, tcid, rank, 0);
    }

    return (EC_TRUE);
}

EC_BOOL task_brd_rank_load_tbl_pop_all(TASK_BRD *task_brd, const UINT32 tcid)
{
    return cload_mgr_del(TASK_BRD_CLOAD_MGR(task_brd), tcid);
}

EC_BOOL task_brd_rank_load_tbl_fast_decrease(TASK_BRD *task_brd, const UINT32 interval_nsec)
{
    return cload_mgr_fast_decrease(TASK_BRD_CLOAD_MGR(task_brd), interval_nsec);
}

EC_BOOL task_brd_rank_load_tbl_set_que(TASK_BRD *task_brd, const UINT32 tcid, const UINT32 rank, const UINT32 que_load)
{
    return cload_mgr_set_que(TASK_BRD_CLOAD_MGR(task_brd), tcid, rank, que_load);
}

UINT32 task_brd_rank_load_tbl_get_que(TASK_BRD *task_brd, const UINT32 tcid, const UINT32 rank)
{
    return cload_mgr_get_que(TASK_BRD_CLOAD_MGR(task_brd), tcid, rank);
}

UINT32 task_brd_rank_load_tbl_get_obj(TASK_BRD *task_brd, const UINT32 tcid, const UINT32 rank)
{
    return cload_mgr_get_obj(TASK_BRD_CLOAD_MGR(task_brd), tcid, rank);
}

UINT32 task_brd_rank_load_tbl_get_cpu(TASK_BRD *task_brd, const UINT32 tcid, const UINT32 rank)
{
    return cload_mgr_get_cpu(TASK_BRD_CLOAD_MGR(task_brd), tcid, rank);
}

UINT32 task_brd_rank_load_tbl_get_mem(TASK_BRD *task_brd, const UINT32 tcid, const UINT32 rank)
{
    return cload_mgr_get_mem(TASK_BRD_CLOAD_MGR(task_brd), tcid, rank);
}

UINT32 task_brd_rank_load_tbl_get_dsk(TASK_BRD *task_brd, const UINT32 tcid, const UINT32 rank)
{
    return cload_mgr_get_dsk(TASK_BRD_CLOAD_MGR(task_brd), tcid, rank);
}

UINT32 task_brd_rank_load_tbl_get_net(TASK_BRD *task_brd, const UINT32 tcid, const UINT32 rank)
{
    return cload_mgr_get_net(TASK_BRD_CLOAD_MGR(task_brd), tcid, rank);
}

EC_BOOL task_brd_broken_tcid_tbl_init(TASK_BRD *task_brd)
{
    cvector_init(TASK_BRD_BROKEN_TCID_TBL(task_brd), 0, MM_UINT32, CVECTOR_LOCK_ENABLE, LOC_TASK_0095);
    return (EC_TRUE);
}

EC_BOOL task_brd_mod_mgr_list_init(TASK_BRD *task_brd)
{
    clist_init(TASK_BRD_MOD_MGR_LIST(task_brd), MM_IGNORE, LOC_TASK_0096);
    return (EC_TRUE);
}

EC_BOOL task_brd_context_list_init(TASK_BRD *task_brd)
{
    clist_init(TASK_BRD_CONTEXT_LIST(task_brd), MM_IGNORE, LOC_TASK_0097);
    return (EC_TRUE);
}

EC_BOOL task_brd_report_list_init(TASK_BRD *task_brd)
{
    clist_init(TASK_BRD_REPORT_LIST(task_brd), MM_IGNORE, LOC_TASK_0098);
    return (EC_TRUE);
}

void task_brd_report_list_add(TASK_BRD *task_brd, const TASK_MGR *task_mgr)
{
    if(EC_FALSE == TASK_MGR_AGING_FLAG(task_mgr))
    {
        CLIST_LOCK(TASK_BRD_REPORT_LIST(task_brd), LOC_TASK_0099);
        if(TASK_REPORT_MAX_NUM > clist_size(TASK_BRD_REPORT_LIST(task_brd)))
        {
            TASK_REPORT_NODE *task_report_node;

            task_report_node_new(&task_report_node);/*create a new one*/
            task_report_node_gen(task_report_node, task_brd, task_mgr);
            clist_push_back_no_lock(TASK_BRD_REPORT_LIST(task_brd), (void *)task_report_node);
        }
        else
        {
            CLIST_DATA *clist_data;
            TASK_REPORT_NODE *task_report_node;

            clist_data = CLIST_FIRST_NODE(TASK_BRD_REPORT_LIST(task_brd));
            CLIST_DATA_DEL(clist_data);

            task_report_node = (TASK_REPORT_NODE *)CLIST_DATA_DATA(clist_data);
            task_report_node_gen(task_report_node, task_brd, task_mgr);

            CLIST_DATA_ADD_BACK(TASK_BRD_REPORT_LIST(task_brd), clist_data);
        }
        CLIST_UNLOCK(TASK_BRD_REPORT_LIST(task_brd), LOC_TASK_0100);
    }
    return;
}

/*note: dump to a vector but not list, because of transfer issue on network. list does not support obvious item type setting yet*/
void task_brd_report_list_dump(TASK_BRD *task_brd, const UINT32 num, CVECTOR *task_report_vec_des)
{
    UINT32 pos;

    //dbg_log(SEC_0015_TASK, 5)(LOGSTDOUT, "######################################   task_brd_report_list_dump beg ######################################\n");
    //task_brd_report_list_print(LOGSTDOUT, task_brd);
    //dbg_log(SEC_0015_TASK, 5)(LOGSTDOUT, "======================================================================================\n");

    CLIST_LOCK(TASK_BRD_REPORT_LIST(task_brd), LOC_TASK_0101);
    for(pos = 0; pos < num && 0 < clist_size(TASK_BRD_REPORT_LIST(task_brd)); pos ++)
    {
        TASK_REPORT_NODE *task_report_node;

        task_report_node = (TASK_REPORT_NODE *)clist_pop_front_no_lock(TASK_BRD_REPORT_LIST(task_brd));/*pop from front*/
        cvector_push(task_report_vec_des, (void *)task_report_node);/*push back*/
    }
    CLIST_UNLOCK(TASK_BRD_REPORT_LIST(task_brd), LOC_TASK_0102);

    //cvector_print(LOGSTDOUT, task_report_vec_des, (CVECTOR_DATA_PRINT)task_report_node_print);
    //dbg_log(SEC_0015_TASK, 5)(LOGSTDOUT, "######################################   task_brd_report_list_dump end ######################################\n");
    return;
}

void task_brd_report_list_print(LOG *log, const TASK_BRD *task_brd)
{
    clist_print(log, TASK_BRD_REPORT_LIST(task_brd), (CLIST_DATA_DATA_PRINT)task_report_node_print);
    return;
}

EC_BOOL task_brd_default_reserve_ipv4_addr(const HARDWARE *hw, uint32_t *ipv4_addr_ret)
{
    TASK_BRD    *task_brd;
    MACIP_CFG   *macip_cfg;
    uint32_t     ipv4_addr;
    UINT8       *mac_addr;

    task_brd = task_brd_default_get();

    mac_addr = (UINT8 *)&(hw->hbuf[1]);

    macip_cfg = sys_cfg_search_macip_cfg_by_mac_addr(TASK_BRD_SYS_CFG(task_brd), mac_addr);
    if(NULL_PTR != macip_cfg)
    {
        ipv4_addr = (uint32_t) MACIP_CFG_IPV4_ADDR(macip_cfg);
        (*ipv4_addr_ret) = htonl(ipv4_addr);
        dbg_log(SEC_0015_TASK, 9)(LOGSTDOUT, "[DEBUG] task_brd_default_reserve_ipv4_addr: find ipv4 addr %s for mac %s\n",
                            c_word_to_ipv4(ipv4_addr), mac_addr_to_str(MACIP_CFG_MAC_ADDR(macip_cfg)));
        return (EC_TRUE);
    }

    while(EC_FALSE == ipv4_pool_is_empty(TASK_BRD_IPV4_POOL(task_brd)))
    {
        if(EC_FALSE == ipv4_pool_reserve(TASK_BRD_IPV4_POOL(task_brd), &ipv4_addr))
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_default_reserve_ipv4_addr: reserve ipv4 addr failed\n");
            return (EC_FALSE);
        }

        macip_cfg = sys_cfg_search_macip_cfg_by_ipv4_addr(TASK_BRD_SYS_CFG(task_brd), ipv4_addr);
        if(NULL_PTR == macip_cfg)
        {
            (*ipv4_addr_ret) = htonl(ipv4_addr);

            sys_cfg_add_macip_cfg(TASK_BRD_SYS_CFG(task_brd), ipv4_addr, mac_addr);
            sys_cfg_add_tasks_cfg(TASK_BRD_SYS_CFG(task_brd), ipv4_addr,
                                  BITS_TO_MASK(TASKS_CFG_DEFAULT_MASKI), BITS_TO_MASK(TASKS_CFG_DEFAULT_MASKE), ipv4_addr,
                                  sys_cfg_get_task_cfg_default_csrv_port(TASK_BRD_SYS_CFG(task_brd)),
                                  CMPI_ERROR_SRVPORT, CMPI_ERROR_SRVPORT);

            /*persistent the new mapping of mac and ip to sysconfig xml file*/
            sys_cfg_flush_xml(TASK_BRD_SYS_CFG(task_brd), TASK_BRD_SYS_CFG_FNAME(task_brd));
            return (EC_TRUE);
        }
    }

    dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_default_reserve_ipv4_addr:reserve ipv4 addr failed\n");
    return (EC_FALSE);
}

EC_BOOL task_brd_default_release_ipv4_addr(const HARDWARE *hw, const uint32_t ipv4_addr)
{
    return (EC_TRUE);
}

TASK_BRD * task_brd_default_new()
{
    g_task_brd = (TASK_BRD *)SAFE_MALLOC(sizeof(TASK_BRD), LOC_TASK_0103);
    BSET(g_task_brd, 0, sizeof(TASK_BRD));
    return (g_task_brd);
}

EC_BOOL task_brd_default_free()
{
    task_brd_free(g_task_brd);
    g_task_brd = NULL_PTR;
    return (EC_TRUE);
}

/*note: 1. here does not initialize task_brd->mod_mgr_default*/
/*note: 2. here has no communication with other processes*/
EC_BOOL task_brd_init(TASK_BRD          *task_brd,
                        const int          argc,
                        char             **argv,
                        const UINT32       network_level,
                        CSTRING           *sys_cfg_xml_fname_cstr,
                        CSTRING           *basic_cfg_xml_fname_cstr,
                        CSTRING           *script_fname_cstr,
                        CSTRING           *log_path_cstr,
                        CSTRING           *ssl_path_cstr)
{
    UINT32 seqno;

    //seqno = ((this_tcid << (WORDSIZE/4)) | this_rank);
    //seqno = (seqno << (WORDSIZE/2));
    seqno = 0;

    /*update task_brd time*/
    task_brd_update_time(task_brd);

    if(EC_FALSE == c_save_args(argc, (const char **)argv))
    {
        return (EC_FALSE);
    }

    if(EC_FALSE == c_save_environ())
    {
        return (EC_FALSE);
    }

    TASK_BRD_CACHE_ENVIRON(task_brd)        = NULL_PTR;

    TASK_BRD_NETWORK_LEVEL(task_brd)        = network_level;

    TASK_BRD_CEPOLL(task_brd)               = NULL_PTR;

    TASK_BRD_SYS_CFG_FNAME(task_brd)        = sys_cfg_xml_fname_cstr;
    TASK_BRD_BASIC_CFG_FNAME(task_brd)      = basic_cfg_xml_fname_cstr;
    TASK_BRD_SCRIPT_FNAME(task_brd)         = script_fname_cstr;
    TASK_BRD_LOG_PATH(task_brd)             = log_path_cstr;
    TASK_BRD_SSL_PATH(task_brd)             = ssl_path_cstr;

    TASK_BRD_NETCARDS(task_brd)             = NULL_PTR;
    TASK_BRD_IPV4_POOL(task_brd)            = NULL_PTR;

    TASK_BRD_SYS_CFG(task_brd)              = NULL_PTR;
    TASK_BRD_CPARACFG(task_brd)             = NULL_PTR;
    TASK_BRD_LOCAL_TASKS_CFG(task_brd)      = NULL_PTR;
    TASK_BRD_DETECT_TASKS_CFG(task_brd)     = NULL_PTR;
    TASK_BRD_UDP_SRV_SOCKFD(task_brd)       = CMPI_ERROR_SOCKFD;
    TASK_BRD_REG_TYPE(task_brd)             = TASK_REGISTER_ALL_SERVER;

    TASK_BRD_RECV_TASK_MGR_LIST_INIT(task_brd, LOC_TASK_0104);
    TASK_BRD_ARGING_TASK_MGR_LIST_INIT(task_brd, LOC_TASK_0105);
    TASK_BRD_TASK_MGR_STACK_INIT(task_brd, LOC_TASK_0106);

    creg_type_conv_vec_init(TASK_BRD_TYPE_CONV_VEC(task_brd));
    creg_type_conv_vec_add_default(TASK_BRD_TYPE_CONV_VEC(task_brd));

    creg_func_addr_vec_init(TASK_BRD_FUNC_ADDR_VEC(task_brd));
    creg_func_addr_vec_add_default(TASK_BRD_FUNC_ADDR_VEC(task_brd));

    TASK_BRD_DO_SLAVE_PID(task_brd)          = ERR_PID;
    TASK_BRD_ENABLE_SLOW_DOWN(task_brd)      = BIT_TRUE;
    TASK_BRD_TASKS_IS_RUNNING(task_brd)      = BIT_FALSE;

    TASK_BRD_DO_SLAVE_CTHREAD_ID(task_brd)   = ERR_CTHREAD_ID;
    TASK_BRD_DO_ROUTINE_CTHREAD_ID(task_brd) = ERR_CTHREAD_ID;
    TASK_BRD_DO_CBTIMER_CTHREAD_ID(task_brd) = ERR_CTHREAD_ID;
    TASK_BRD_BCAST_CTHREAD_ID(task_brd)      = ERR_CTHREAD_ID;

    TASK_BRD_SUPER_MD_ID(task_brd)           = CMPI_ERROR_MODI;

    TASK_BRD_FWD_CCOND_INIT(task_brd, LOC_TASK_0107);

    TASK_BRD_TCID(task_brd) = CMPI_ERROR_TCID;
    TASK_BRD_COMM(task_brd) = CMPI_ERROR_COMM;
    TASK_BRD_SIZE(task_brd) = 0;
    TASK_BRD_RANK(task_brd) = CMPI_ERROR_RANK;

    TASK_BRD_IPADDR(task_brd) = CMPI_ERROR_IPADDR;
    TASK_BRD_PORT(task_brd)   = CMPI_ERROR_SRVPORT;

    TASK_BRD_SEQNO_CMUTEX_INT(task_brd, LOC_TASK_0108);
    TASK_BRD_SEQNO(task_brd) = seqno;

#if (SWITCH_ON == CROUTINE_SUPPORT_CTHREAD_SWITCH)
    /*NOTE: JOINABLE will occupy huge virtual memory when many threads frequently create & exit or cancel, hence DETACHABLE is perfer*/
    TASK_REQ_CTHREAD_POOL(task_brd) = NULL_PTR;
    TASK_REQ_CTHREAD_POOL(task_brd) = NULL_PTR;
#endif/*(SWITCH_ON == CROUTINE_SUPPORT_CTHREAD_SWITCH)*/

#if (SWITCH_ON == CROUTINE_SUPPORT_COROUTINE_SWITCH)
    TASK_BRD_CROUTINE_POOL(task_brd) = NULL_PTR;
#endif/*(SWITCH_ON == CROUTINE_SUPPORT_COROUTINE_SWITCH)*/

    TASK_BRD_CSRV(task_brd)               = NULL_PTR;
    TASK_BRD_CPROC(task_brd)              = NULL_PTR;

    TASK_BRD_HTTP_CCONNP_MGR(task_brd)    = NULL_PTR;

    TASK_BRD_CRFSMON_ID(task_brd)         = CMPI_ERROR_MODI;
    TASK_BRD_CXFSMON_ID(task_brd)         = CMPI_ERROR_MODI;

    /*initialize queues*/
    task_queue_init(TASK_BRD_QUEUE(task_brd, TASK_RECVING_QUEUE));
    task_queue_init(TASK_BRD_QUEUE(task_brd, TASK_IS_RECV_QUEUE));
    task_queue_init(TASK_BRD_QUEUE(task_brd, TASK_TO_SEND_QUEUE));
    task_queue_init(TASK_BRD_QUEUE(task_brd, TASK_SENDING_QUEUE));

    /*initialize MD_NODE table*/
    task_brd_md_node_tbl_init(task_brd);

    TASK_BRD_RANK_TBL(task_brd) = NULL_PTR;

    /*initialize rank load table*/
    task_brd_rank_load_tbl_init(task_brd);

    /*initialize broken tcid table*/
    task_brd_broken_tcid_tbl_init(task_brd);

    /*initialize mod mgr list*/
    task_brd_mod_mgr_list_init(task_brd);

    /*initialize context list*/
    task_brd_context_list_init(task_brd);

    /*initialize task report list*/
    task_brd_report_list_init(task_brd);

    /*initialize task cbtimer list*/
    cbtimer_init(TASK_BRD_CBTIMER_LIST(task_brd));

    /*initialize task processor list*/
    task_brd_process_init(task_brd);

    TASK_BRD_ENABLE_FLAG(task_brd) = EC_TRUE;
    TASK_BRD_RESET_FLAG(task_brd)  = EC_TRUE;/*default is to reset the down do_slave thread*/

    TASK_BRD_NGX_EXITING_FLAG(task_brd) = EC_FALSE;

    cload_stat_init(TASK_BRD_CLOAD_STAT(task_brd));
    csys_cpu_avg_stat_init(TASK_BRD_CPU_AVG_STAT(task_brd));

    cstack_init(TASK_BRD_RUNNER_STACK(task_brd), MM_TASK_RUNNER_NODE, LOC_TASK_0109);

    /*taskover some signals*/
    TASK_BRD_CSIG(task_brd) = csig_new();
    if(NULL_PTR == TASK_BRD_CSIG(task_brd))
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_init: new csig failed\n");
        task_brd_default_abort();
    }
    csig_takeover(TASK_BRD_CSIG(task_brd));

    /*set os or process limite*/
    task_brd_os_setting(task_brd);

    return (EC_TRUE);
}

EC_BOOL task_brd_load_basic_config(TASK_BRD *task_brd, UINT32 *udp_mcast_ipaddr, UINT32 *udp_mcast_port)
{
    SYS_CFG *sys_cfg;
    MCAST_CFG *mcast_cfg;

    if(0 != access((char *)TASK_BRD_BASIC_CFG_FNAME_STR(task_brd), F_OK | R_OK))/*NOT exist or readable*/
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_load_basic_config: not found %s\n", (char *)TASK_BRD_BASIC_CFG_FNAME_STR(task_brd));
        return (EC_FALSE);
    }

    sys_cfg = sys_cfg_new();
    if(NULL_PTR == sys_cfg)
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_load_basic_config: new sys_cfg failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == sys_cfg_load(sys_cfg, (char *)TASK_BRD_BASIC_CFG_FNAME_STR(task_brd)))
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_load_basic_config: load %s failed\n", (char *)TASK_BRD_BASIC_CFG_FNAME_STR(task_brd));
        sys_cfg_free(sys_cfg);
        return (EC_FALSE);
    }

    mcast_cfg = sys_cfg_get_mcast_cfg(sys_cfg);
    (*udp_mcast_ipaddr) = MCAST_CFG_IPADDR(mcast_cfg);
    (*udp_mcast_port)   = MCAST_CFG_PORT(mcast_cfg);

    sys_cfg_free(sys_cfg);

    return (EC_TRUE);
}

/*wait ipv4 addr, subnet, mask, mcast ipaddr, mcast port,etc*/
EC_BOOL task_brd_wait_basic_config(TASK_BRD *task_brd, const CSTRING *bcast_dhcp_netcard_cstr, UINT32 *udp_mcast_ipaddr, UINT32 *udp_mcast_port)
{
    char    *netcard;

    netcard = (char *)cstring_get_str(bcast_dhcp_netcard_cstr);
    if(EC_FALSE == dhcp_if_check_ipv4_defined(netcard))/*netcard not config ipaddr*/
    {
        /*wait mcast info on bcast channel*/
        if(EC_FALSE == dhcp_client_do(netcard, udp_mcast_ipaddr, udp_mcast_port))
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_wait_basic_config: dhcp client faild\n");
            return (EC_FALSE);
        }

        return (EC_TRUE);
    }

    /*when netcard config ipaddr, then fetch mcast config from basic config xml*/
    if(EC_FALSE == task_brd_load_basic_config(task_brd, udp_mcast_ipaddr, udp_mcast_port))
    {
        dbg_log(SEC_0015_TASK, 1)(LOGSTDOUT, "warn:task_brd_wait_basic_config: load basic config %s failed\n", (char *)TASK_BRD_BASIC_CFG_FNAME_STR(task_brd));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL task_brd_wait_sys_config(TASK_BRD *task_brd, const UINT32 udp_mcast_ipaddr, const UINT32 udp_mcast_port)
{
    int sockfd;
    CBYTES  *src_cbytes;
    CBYTES  *des_cbytes;
    UINT32   src_len;
    UINT32   des_len;

    if(EC_FALSE == csocket_start_udp_mcast_recver(udp_mcast_ipaddr, udp_mcast_port, &sockfd))
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_wait_sys_config: start upd client socket failed\n");
        return (EC_FALSE);
    }

    src_cbytes = cbytes_new(TASK_CONFIG_XML_MAX_SIZE);/*64KB*/
    if(NULL_PTR == src_cbytes)
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_wait_sys_config: new src_cbytes with len %ld failed\n", TASK_CONFIG_XML_MAX_SIZE);
        csocket_stop_udp_mcast_recver(sockfd, udp_mcast_ipaddr);
        return (EC_FALSE);
    }

    des_cbytes = cbytes_new(TASK_CONFIG_XML_MAX_SIZE);/*64KB*/
    if(NULL_PTR == des_cbytes)
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_wait_sys_config: new des_cbytes with len %ld failed\n", TASK_CONFIG_XML_MAX_SIZE);
        cbytes_free(src_cbytes);
        csocket_stop_udp_mcast_recver(sockfd, udp_mcast_ipaddr);
        return (EC_FALSE);
    }

    dbg_log(SEC_0015_TASK, 9)(LOGSTDOUT, "[DEBUG] task_brd_wait_sys_config: recving udp data on %s:%ld sockfd %d\n",
                        c_word_to_ipv4(udp_mcast_ipaddr), udp_mcast_port, sockfd);

    if(EC_FALSE == csocket_udp_mcast_recvfrom(sockfd, udp_mcast_ipaddr, udp_mcast_port, cbytes_buf(src_cbytes), cbytes_len(src_cbytes), &src_len))
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_wait_sys_config: udp recv from %s:%ld failed\n", c_word_to_ipv4(udp_mcast_ipaddr), udp_mcast_port);
        csocket_stop_udp_mcast_recver(sockfd, udp_mcast_ipaddr);
        cbytes_free(src_cbytes);
        cbytes_free(des_cbytes);
        return (EC_FALSE);
    }

    cbytes_resize(src_cbytes, src_len);

    /*decompress*/
    des_len = cbytes_len(des_cbytes);
    if(Z_OK != uncompress(cbytes_buf(des_cbytes), &des_len, cbytes_buf(src_cbytes), cbytes_len(src_cbytes)))
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_wait_sys_config:uncompress sysconfig failed\n");
        cbytes_free(src_cbytes);
        cbytes_free(des_cbytes);
        return (EC_FALSE);
    }
    cbytes_free(src_cbytes);/*clean up src bytes cache*/
    cbytes_resize(des_cbytes, des_len);

    dbg_log(SEC_0015_TASK, 9)(LOGSTDOUT, "[DEBUG] task_brd_wait_sys_config: recvd %ld bytes udp data on %s:%ld sockfd %d\n",
                        cbytes_len(des_cbytes), c_word_to_ipv4(udp_mcast_ipaddr), udp_mcast_port, sockfd);

    /*upload config to local and backup old one*/
    if(EC_FALSE == super_upload(CMPI_ANY_MODI, TASK_BRD_SYS_CFG_FNAME(task_brd), des_cbytes, EC_TRUE))
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_wait_sys_config: upload %s failed\n", (char *)TASK_BRD_SYS_CFG_FNAME_STR(task_brd));
        cbytes_free(des_cbytes);
        csocket_stop_udp_mcast_recver(sockfd, udp_mcast_ipaddr);
        return (EC_FALSE);
    }
    cbytes_free(des_cbytes);

    if(EC_FALSE == csocket_stop_udp_mcast_recver(sockfd, udp_mcast_ipaddr))
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_wait_sys_config: stop upd client socket %d failed\n", sockfd);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL task_brd_make_config(TASK_BRD *task_brd, const UINT32 this_tcid)
{
    CAGENT          *cagent;
    char            *fname;

    cagent = cagent_new();
    if(NULL_PTR == cagent)
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_make_config: new cagent failed\n");
        return (EC_FALSE);
    }

    CAGENT_RESERVED_TCID(cagent) = this_tcid;

    fname = (char *)TASK_BRD_SYS_CFG_FNAME_STR(task_brd);
    if(EC_FALSE == cagent_gen_config_xml(cagent, fname))
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_make_config: generate '%s' failed\n", fname);

        cagent_free(cagent);
        return (EC_FALSE);
    }

    if(EC_FALSE == task_brd_load(task_brd))
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_make_config: load config failed\n");

        cagent_free(cagent);
        return (EC_FALSE);
    }

    dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "[DEBUG] task_brd_make_config: "
                                         "make config of tcid '%s' done\n",
                                         c_word_to_ipv4(CAGENT_RESERVED_TCID(cagent)));

    cagent_free(cagent);
    return (EC_TRUE);
}

EC_BOOL task_brd_pull_config(TASK_BRD *task_brd, UINT32 *this_tcid, UINT32 *this_ipaddr, UINT32 *this_port)
{
    CAGENT          *cagent;
    UINT32           ipaddr; /*host ipaddr for internet*/
    const char      *service_name_str;
    CSTRING          service_name;
    CSTRING         *edge_service_name;

    service_name_str = task_brd_parse_arg(TASK_BRD_SAVED_ARGC(task_brd),
                                          (const char **)TASK_BRD_SAVED_ARGV(task_brd),
                                          (const char *)"-p2p_service");
    if(NULL_PTR == service_name_str)
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_pull_config: arg 'p2p_service' absence\n");
        return (EC_FALSE);
    }
    cstring_set_str(&service_name, (const UINT8 *)service_name_str);

    edge_service_name = ctdns_gen_edge_service_name(&service_name);
    if(NULL_PTR == edge_service_name)
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_pull_config: gen edge service name failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == task_brd_collect_netcards(task_brd))
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_pull_config: collect netcards failed\n");
        cstring_free(edge_service_name);
        return (EC_FALSE);
    }

    ipaddr = c_finger_ip_from_netcards(TASK_BRD_NETCARDS(task_brd));
    dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "[DEBUG] task_brd_pull_config: finger ip '%s'\n",
                    c_word_to_ipv4(ipaddr));

    cagent = cagent_new();
    if(NULL_PTR == cagent)
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_pull_config: new cagent failed\n");
        cstring_free(edge_service_name);
        return (EC_FALSE);
    }

    cstring_append_str(CAGENT_TDNS_HOST(cagent), (const UINT8 *)CTDNSHTTP_HOST_DEFAULT);
    CAGENT_TDNS_PORT(cagent) = c_str_to_word((char *)CTDNSHTTP_PORT_DEFAULT);

    if(EC_FALSE == cagent_reserve_tcid(cagent, (const char *)CTDNSHTTP_NODES_SERVICE_NAME, c_word_to_ipv4(ipaddr)))
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_pull_config: reserve tcid failed\n");
        cagent_free(cagent);
        cstring_free(edge_service_name);
        return (EC_FALSE);
    }

    dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "[DEBUG] task_brd_pull_config: reserve tcid '%s' done\n",
                    c_word_to_ipv4(CAGENT_RESERVED_TCID(cagent)));

    if(NULL_PTR == TASK_BRD_SYS_CFG_FNAME(task_brd )
    || EC_FALSE == c_file_access((char *)TASK_BRD_SYS_CFG_FNAME_STR(task_brd), F_OK | R_OK))
    {
        SYS_CFG     *sys_cfg;

        sys_cfg = cagent_gen_config(cagent);
        if(NULL_PTR == sys_cfg)
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_pull_config: gen conf failed\n");

            cagent_release_tcid(cagent, (const char *)CTDNSHTTP_NODES_SERVICE_NAME,
                                c_word_to_ipv4(CAGENT_RESERVED_TCID(cagent)),
                                c_word_to_str(CAGENT_RESERVED_PORT(cagent)));

            cagent_free(cagent);
            cstring_free(edge_service_name);
            return (EC_FALSE);
        }
        TASK_BRD_SYS_CFG(task_brd) = sys_cfg;
    }
    else
    {
        char            *fname;

        fname = (char *)TASK_BRD_SYS_CFG_FNAME_STR(task_brd);
        if(EC_FALSE == cagent_gen_config_xml(cagent, fname))
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_pull_config: generate '%s' failed\n", fname);

            cagent_release_tcid(cagent, (const char *)CTDNSHTTP_NODES_SERVICE_NAME,
                                c_word_to_ipv4(CAGENT_RESERVED_TCID(cagent)),
                                c_word_to_str(CAGENT_RESERVED_PORT(cagent)));

            cagent_free(cagent);
            cstring_free(edge_service_name);
            return (EC_FALSE);
        }

        if(EC_FALSE == task_brd_load(task_brd))
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_pull_config: load config failed\n");

            cagent_release_tcid(cagent, (const char *)CTDNSHTTP_NODES_SERVICE_NAME,
                                c_word_to_ipv4(CAGENT_RESERVED_TCID(cagent)),
                                c_word_to_str(CAGENT_RESERVED_PORT(cagent)));

            cagent_free(cagent);
            cstring_free(edge_service_name);
            return (EC_FALSE);
        }
    }

#if 0
    if(0 < TASK_BRD_NETWORK_LEVEL(task_brd))
    {
        UINT32  network_level;

        network_level = TASK_BRD_NETWORK_LEVEL(task_brd) - 1; /*target upper network*/

        if(EC_FALSE == cagent_set_service(cagent,
                                          c_word_to_str(network_level),
                                          (char *)cstring_get_str(edge_service_name),
                                          c_word_to_ipv4(CAGENT_RESERVED_TCID(cagent)),
                                          c_word_to_ipv4(ipaddr),
                                          c_word_to_str(CAGENT_RESERVED_PORT(cagent))))
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_pull_config: "
                                                 "service '%s', tcid '%s', ip '%s' failed\n",
                                                 cstring_get_str(edge_service_name),
                                                 c_word_to_ipv4(CAGENT_RESERVED_TCID(cagent)),
                                                 c_word_to_ipv4(ipaddr));

            cagent_release_tcid(cagent, (const char *)CTDNSHTTP_NODES_SERVICE_NAME,
                                c_word_to_ipv4(CAGENT_RESERVED_TCID(cagent)),
                                c_word_to_str(CAGENT_RESERVED_PORT(cagent)));

            cagent_free(cagent);
            cstring_free(edge_service_name);
            return (EC_FALSE);
        }
    }
#endif

#if 1
    if(0 < TASK_BRD_NETWORK_LEVEL(task_brd))
    {
        if(EC_FALSE == cagent_set_tcid(cagent,
                                      c_word_to_ipv4(CAGENT_RESERVED_TCID(cagent)),
                                      c_word_to_ipv4(ipaddr),
                                      c_word_to_str(CAGENT_RESERVED_PORT(cagent))))
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_pull_config: "
                                                 "set cid '%s', ip '%s' failed\n",
                                                 c_word_to_ipv4(CAGENT_RESERVED_TCID(cagent)),
                                                 c_word_to_ipv4(ipaddr));

            cagent_release_tcid(cagent, (const char *)CTDNSHTTP_NODES_SERVICE_NAME,
                                c_word_to_ipv4(CAGENT_RESERVED_TCID(cagent)),
                                c_word_to_str(CAGENT_RESERVED_PORT(cagent)));

            cagent_free(cagent);
            cstring_free(edge_service_name);
            return (EC_FALSE);
        }
    }
#endif

    dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "[DEBUG] task_brd_pull_config: "
                                         "service '%s', tcid '%s', ip '%s', port %ld done\n",
                                         cstring_get_str(edge_service_name),
                                         c_word_to_ipv4(CAGENT_RESERVED_TCID(cagent)),
                                         c_word_to_ipv4(ipaddr),
                                         CAGENT_RESERVED_PORT(cagent));

    (*this_tcid)   = CAGENT_RESERVED_TCID(cagent);
    (*this_ipaddr) = CAGENT_LOCAL_IPADDR(cagent);

    if(CMPI_ERROR_SRVPORT == CAGENT_RESERVED_PORT(cagent))
    {
        (*this_port)   = CAGENT_LOCAL_PORT(cagent);
    }
    else
    {
        (*this_port)   = CAGENT_RESERVED_PORT(cagent);
    }
    cagent_free(cagent);
    cstring_free(edge_service_name);
    return (EC_TRUE);
}

EC_BOOL task_brd_wait_config(TASK_BRD *task_brd, const CSTRING *bcast_dhcp_netcard_cstr, UINT32 *this_tcid)
{
    UINT32 udp_mcast_ipaddr;
    UINT32 udp_mcast_port;

    if(EC_FALSE == task_brd_wait_basic_config(task_brd, bcast_dhcp_netcard_cstr, &udp_mcast_ipaddr, &udp_mcast_port))
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_wait_config: wait basic config failed\n");
        return (EC_FALSE);
    }

    /*wait sysconfig info on mcast channel*/
    /*loop to wait for config until get the right configuration*/
    for(;;)
    {
        if(0 == access((char *)TASK_BRD_SYS_CFG_FNAME_STR(task_brd), F_OK | R_OK))
        {
            super_rmv_file(CMPI_ANY_MODI, TASK_BRD_SYS_CFG_FNAME(task_brd));
        }

        if(EC_FALSE == task_brd_wait_sys_config(task_brd, udp_mcast_ipaddr, udp_mcast_port))
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_wait_config: wait sysconfig from mcast network failed, continue waiting...\n");
            continue;
        }

        if(EC_FALSE == task_brd_load(task_brd))
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_wait_config: task_brd load failed, continue waiting...\n");
            continue;
        }

        if(EC_FALSE == task_brd_collect_netcards(task_brd))
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_wait_config: task_brd collect failed, continue waiting...\n");
            continue;
        }

        /*determine tcid by ipaddr if necessary*/
        if(CMPI_ERROR_TCID == (*this_tcid)
        && EC_FALSE == task_brd_parse_tcid_from_netcards(task_brd, TASK_BRD_NETCARDS(task_brd), this_tcid))
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_wait_config: parse tcid from sysconfig and netcards failed, continue waiting...\n");
            continue;
        }

        /*terminate*/
        break;
    }

    /*wait until config ready*/
    return (EC_TRUE);
}

EC_BOOL task_brd_mcast_config(TASK_BRD *task_brd)
{
    MCAST_CFG *mcast_cfg;
    CBYTES  *src_cbytes;
    CBYTES  *des_cbytes;
    UINT32   src_len;
    UINT32   des_len;

    if(EC_FALSE == task_brd_status_mcast_udp_server(task_brd))
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_mcast_config: udp server is inactive\n");
        return (EC_FALSE);
    }

    //dbg_log(SEC_0015_TASK, 9)(LOGSTDOUT, "[DEBUG] task_brd_mcast_config: was called\n");
    if(0 != access((char *)TASK_BRD_SYS_CFG_FNAME_STR(task_brd), F_OK | R_OK))/*NOT exist or readable*/
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_mcast_config: not found %s\n", (char *)TASK_BRD_SYS_CFG_FNAME_STR(task_brd));
        return (EC_FALSE);
    }

    mcast_cfg = sys_cfg_get_mcast_cfg(TASK_BRD_SYS_CFG(task_brd));

    src_cbytes = cbytes_new(0);
    if(NULL_PTR == src_cbytes)
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_mcast_config: new src_cbytes failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == super_download(CMPI_ANY_MODI, TASK_BRD_SYS_CFG_FNAME(task_brd), src_cbytes))
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_mcast_config: download sys cfg xml %s failed\n",
                            (char *)TASK_BRD_SYS_CFG_FNAME_STR(task_brd));
        cbytes_free(src_cbytes);
        return (EC_FALSE);
    }

    /*compress*/
    des_cbytes = cbytes_new(cbytes_len(src_cbytes));
    if(NULL_PTR == src_cbytes)
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_mcast_config: new des_cbytes failed\n");
        cbytes_free(src_cbytes);
        return (EC_FALSE);
    }

    des_len = cbytes_len(des_cbytes);
    if(Z_OK != compress(cbytes_buf(des_cbytes), &des_len, cbytes_buf(src_cbytes), cbytes_len(src_cbytes)))
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_mcast_config:compress sysconfig failed\n");
        cbytes_free(src_cbytes);
        cbytes_free(des_cbytes);
        return (EC_FALSE);
    }

    src_len = cbytes_len(src_cbytes);/*save length info before free*/
    cbytes_free(src_cbytes);
    cbytes_resize(des_cbytes, des_len);

    dbg_log(SEC_0015_TASK, 9)(LOGSTDOUT, "[DEBUG] task_brd_mcast_config: compress sysconfig: %ld bytes => %ld bytes, rate %.2f\n",
                        src_len, des_len, (0.0 + des_len) / (0.0 + src_len));

    if(EC_FALSE == csocket_udp_mcast_sendto(TASK_BRD_UDP_SRV_SOCKFD(task_brd),
                                      MCAST_CFG_IPADDR(mcast_cfg), MCAST_CFG_PORT(mcast_cfg),
                                      cbytes_buf(des_cbytes), cbytes_len(des_cbytes)))
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_mcast_config: mcast sys config %s failed\n", (char *)TASK_BRD_SYS_CFG_FNAME_STR(task_brd));

        cbytes_free(des_cbytes);
        return (EC_FALSE);
    }

    dbg_log(SEC_0015_TASK, 9)(LOGSTDOUT, "[DEBUG] task_brd_mcast_config: send config with %ld bytes on %s:%ld sockfd %d\n",
                        src_len, MCAST_CFG_IPADDR_STR(mcast_cfg), MCAST_CFG_PORT(mcast_cfg), TASK_BRD_UDP_SRV_SOCKFD(task_brd));

    cbytes_free(des_cbytes);

    return (EC_TRUE);
}

EC_BOOL task_brd_is_bcast_dhcp_server(TASK_BRD *task_brd)
{
    BCAST_DHCP_CFG *bcast_dhcp_cfg;

    bcast_dhcp_cfg = SYS_CFG_BCAST_DHCP_CFG(TASK_BRD_SYS_CFG(task_brd));
    if(BCAST_DHCP_CFG_TCID(bcast_dhcp_cfg) == TASK_BRD_TCID(task_brd))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL task_brd_is_auto_bcast_dhcp_udp_server(TASK_BRD *task_brd)
{
    BCAST_DHCP_CFG *bcast_dhcp_cfg;

    bcast_dhcp_cfg = SYS_CFG_BCAST_DHCP_CFG(TASK_BRD_SYS_CFG(task_brd));
    if(BCAST_DHCP_CFG_TCID(bcast_dhcp_cfg) == TASK_BRD_TCID(task_brd) && BCAST_DHCP_SRV_WILL_AUTO_BOOTUP == BCAST_DHCP_CFG_AUTO_FLAG(bcast_dhcp_cfg))
    {
        dbg_log(SEC_0015_TASK, 9)(LOGSTDOUT, "[DEBUG] task_brd_is_auto_bcast_dhcp_udp_server: tcid %s is bcast dhcp server\n", TASK_BRD_TCID_STR(task_brd));
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL task_brd_start_bcast_dhcp_udp_server(TASK_BRD *task_brd)
{
    MCAST_CFG *mcast_cfg;
    BCAST_DHCP_CFG *bcast_dhcp_cfg;
    UINT32 core_max_num;

    mcast_cfg = SYS_CFG_MCAST_CFG(TASK_BRD_SYS_CFG(task_brd));
    bcast_dhcp_cfg = SYS_CFG_BCAST_DHCP_CFG(TASK_BRD_SYS_CFG(task_brd));

    if(NULL_PTR == TASK_BRD_IPV4_POOL(task_brd))
    {
        TASK_BRD_IPV4_POOL(task_brd) = ipv4_pool_new((uint32_t)BCAST_DHCP_CFG_SUBNET(bcast_dhcp_cfg),
                                                     (uint32_t)BCAST_DHCP_CFG_MASK(bcast_dhcp_cfg));
    }

    if(NULL_PTR == TASK_BRD_IPV4_POOL(task_brd))
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_start_bcast_dhcp_udp_server: ipv4 pool is null\n");
        return (EC_FALSE);
    }

    core_max_num = sysconf(_SC_NPROCESSORS_ONLN);
    TASK_BRD_BCAST_CTHREAD_ID(task_brd) = cthread_new(CTHREAD_JOINABLE | CTHREAD_SYSTEM_LEVEL,
                                                (const char *)"dhcp_server_do",
                                                (UINT32)dhcp_server_do,
                                                (UINT32)(TASK_BRD_RANK(task_brd) % core_max_num), /*core #*/
                                                (UINT32)3,/*para num*/
                                                (UINT32)BCAST_DHCP_NETCARD_STR(bcast_dhcp_cfg),
                                                (UINT32)MCAST_CFG_IPADDR(mcast_cfg),
                                                (UINT32)MCAST_CFG_PORT(mcast_cfg)
                                                );
    dbg_log(SEC_0015_TASK, 9)(LOGSTDOUT, "[DEBUG] task_brd_start_bcast_dhcp_udp_server: dhcp_server_do thread %ld\n", TASK_BRD_BCAST_CTHREAD_ID(task_brd));
    return (EC_TRUE);
}

/*
EC_BOOL task_brd_stop_bcast_dhcp_udp_server(TASK_BRD *task_brd)
{
    TASK_BRD_BCAST_CTHREAD_ID(task_brd) = ERR_CTHREAD_ID;
    return (EC_TRUE);
}

EC_BOOL task_brd_status_bcast_dhcp_udp_server(TASK_BRD *task_brd)
{
    if(ERR_CTHREAD_ID == TASK_BRD_BCAST_CTHREAD_ID(task_brd))
    {
        return (EC_FALSE);
    }
    return (EC_TRUE);
}
*/

EC_BOOL task_brd_is_mcast_udp_server(TASK_BRD *task_brd)
{
    MCAST_CFG *mcast_cfg;

    mcast_cfg = SYS_CFG_MCAST_CFG(TASK_BRD_SYS_CFG(task_brd));
    if(MCAST_CFG_TCID(mcast_cfg) == TASK_BRD_TCID(task_brd))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL task_brd_is_auto_mcast_udp_server(TASK_BRD *task_brd)
{
    MCAST_CFG *mcast_cfg;

    mcast_cfg = SYS_CFG_MCAST_CFG(TASK_BRD_SYS_CFG(task_brd));
    if(MCAST_CFG_TCID(mcast_cfg) == TASK_BRD_TCID(task_brd) && MCAST_SRV_WILL_AUTO_BOOTUP == MCAST_CFG_AUTO_FLAG(mcast_cfg))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL task_brd_start_mcast_udp_server(TASK_BRD *task_brd)
{
    MCAST_CFG *mcast_cfg;
    int sockfd;

    mcast_cfg = SYS_CFG_MCAST_CFG(TASK_BRD_SYS_CFG(task_brd));

    if(EC_FALSE == csocket_start_udp_mcast_sender(MCAST_CFG_IPADDR(mcast_cfg), MCAST_CFG_PORT(mcast_cfg), &sockfd))
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_start_mcast_udp_server: start udp server %s:%ld failed\n",
                            MCAST_CFG_IPADDR_STR(mcast_cfg), MCAST_CFG_PORT(mcast_cfg));
        return (EC_FALSE);
    }

    dbg_log(SEC_0015_TASK, 5)(LOGSTDOUT, "task_brd_start_mcast_udp_server: start udp server %s:%ld on sockfd %d successfully\n",
                        MCAST_CFG_IPADDR_STR(mcast_cfg), MCAST_CFG_PORT(mcast_cfg), sockfd);

    TASK_BRD_UDP_SRV_SOCKFD(task_brd) = sockfd;

    /*register to cbtimer list*/
    task_brd_cbtimer_add(task_brd,
                        (UINT8 *)"mcast sysconfig",
                        MCAST_CFG_EXPIRE(mcast_cfg), (FUNC_ADDR_NODE *)&g_task_brd_mcast_stop_func_addr_node,
                        MCAST_CFG_TIMEOUT(mcast_cfg), (FUNC_ADDR_NODE *)&g_task_brd_mcast_config_func_addr_node);
    return (EC_TRUE);
}

EC_BOOL task_brd_stop_mcast_udp_server(TASK_BRD *task_brd)
{
    if(CMPI_ERROR_SOCKFD != TASK_BRD_UDP_SRV_SOCKFD(task_brd))
    {
        MCAST_CFG *mcast_cfg;
        mcast_cfg = SYS_CFG_MCAST_CFG(TASK_BRD_SYS_CFG(task_brd));
        csocket_stop_udp_mcast_sender(TASK_BRD_UDP_SRV_SOCKFD(task_brd), MCAST_CFG_IPADDR(mcast_cfg));
        TASK_BRD_UDP_SRV_SOCKFD(task_brd) = CMPI_ERROR_SOCKFD;
    }
    return (EC_TRUE);
}

EC_BOOL task_brd_status_mcast_udp_server(TASK_BRD *task_brd)
{
    if(CMPI_ERROR_SOCKFD != TASK_BRD_UDP_SRV_SOCKFD(task_brd))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL task_brd_load(TASK_BRD *task_brd)
{
    SYS_CFG   *sys_cfg;

    //TASK_BRD_SUPER_MD_ID(task_brd)  = super_start();/*each rank own one super module*/

    if(0 != access((char *)TASK_BRD_SYS_CFG_FNAME_STR(task_brd), F_OK | R_OK))/*NOT exist or readable*/
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_load: not found %s\n", (char *)TASK_BRD_SYS_CFG_FNAME_STR(task_brd));
        return (EC_FALSE);
    }

    sys_cfg = sys_cfg_new();
    if(NULL_PTR == sys_cfg)
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_load: new sys_cfg failed\n");
        return (EC_FALSE);
    }

    if(NULL_PTR != TASK_BRD_SYS_CFG(task_brd))
    {
        sys_cfg_free(TASK_BRD_SYS_CFG(task_brd));
        TASK_BRD_SYS_CFG(task_brd) = NULL_PTR;
    }

    dbg_log(SEC_0015_TASK, 5)(LOGSTDOUT, "task_brd_load: loading sysconfig from %s\n", (char *)TASK_BRD_SYS_CFG_FNAME_STR(task_brd));
    if(EC_FALSE == sys_cfg_load(sys_cfg, (char *)TASK_BRD_SYS_CFG_FNAME_STR(task_brd)))
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_load: load %s failed\n", (char *)TASK_BRD_SYS_CFG_FNAME_STR(task_brd));
        sys_cfg_free(sys_cfg);
        return (EC_FALSE);
    }

    TASK_BRD_SYS_CFG(task_brd)   = sys_cfg;

    return (EC_TRUE);
}

EC_BOOL task_brd_collect_netcards(TASK_BRD *task_brd)
{
    if(NULL_PTR == TASK_BRD_NETCARDS(task_brd))
    {
        TASK_BRD_NETCARDS(task_brd) = c_collect_netcards();
        //dbg_log(SEC_0015_TASK, 9)(LOGSTDOUT, "[DEBUG] task_brd_collect_netcards: netcards:\n");
        //cset_print(LOGSTDOUT, cnetcard_set, (CSET_DATA_PRINT)cnetcard_print);
    }
    return (EC_TRUE);
}

TASK_BRD * task_brd_default_get()
{
    return g_task_brd;
}

UINT8 *task_brd_default_sys_cfg_xml()
{
    TASK_BRD * task_brd;

    task_brd = task_brd_default_get();
    return TASK_BRD_SYS_CFG_FNAME_STR(task_brd);
}

UINT8 *task_brd_default_basic_cfg_xml()
{
    TASK_BRD * task_brd;

    task_brd = task_brd_default_get();
    return TASK_BRD_BASIC_CFG_FNAME_STR(task_brd);
}

EC_BOOL task_brd_write_pidfile0(const char *pidfile, const pid_t pid)
{
    FILE *fp;

    fp = fopen(pidfile, "w");
    if(NULL_PTR == fp)
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_write_pidfile: open pidfile %s to write failed\n", pidfile);
        return (EC_FALSE);
    }

    fseek(fp, 0, SEEK_SET);
    fprintf(fp, "%u", pid);
    fclose(fp);

    return (EC_TRUE);
}

EC_BOOL task_brd_write_pidfile(const char *pidfile, const pid_t pid)
{
    char buff[16];
    int  len;
    int fd;

    len = snprintf(buff, sizeof(buff), "%d", pid);

    fd = open(pidfile, O_RDWR | O_CREAT, 0666);
    if(-1 == fd)
    {
        fprintf(stderr, "error:task_brd_write_pidfile: write pid %d to '%s' failed\n", pid, pidfile);
        return (EC_FALSE);
    }

    if(0 != ftruncate(fd, 0))
    {
        close(fd);
        fprintf(stderr, "error:task_brd_write_pidfile: truncate '%s' to zero failed\n", pidfile);
        return (EC_FALSE);
    }

    if(len != write(fd, buff, len))
    {
        close(fd);
        fprintf(stderr, "error:task_brd_write_pidfile: write '%s' to file '%s' failed\n", buff, pidfile);
        return (EC_FALSE);
    }

    close(fd);
    return (EC_TRUE);
}

EC_BOOL task_brd_reset_tcid_args(int argc, char **argv, const UINT32 tcid)
{
    int idx;

    for(idx = 0; idx < argc; idx ++)
    {
        if(0 == strcasecmp(argv[idx], "-tcid") && idx + 1 < argc)
        {
            char       *tcid_str;
            char       *tcid_arg;

            uint32_t    tcid_str_len;
            uint32_t    tcid_arg_len;

            tcid_str = c_word_to_ipv4(tcid);
            tcid_arg = argv[idx + 1];

            tcid_str_len = strlen(tcid_str);
            tcid_arg_len = strlen(tcid_arg);

            if(tcid_arg_len < tcid_str_len)
            {
                dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_reset_tcid_args: "
                                                     "insufficent tcid len:  tcid '%s', arg '%s'\n",
                                                     tcid_str, tcid_arg);
                return (EC_FALSE);
            }

            BSET(tcid_arg, ' ', tcid_arg_len + 1);
            BCOPY(tcid_str, tcid_arg, tcid_str_len + 1);

            return (EC_TRUE);
        }
    }

    dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_reset_tcid_args: "
                                         "not found arg 'tcid'\n");
    return (EC_FALSE);
}

const char * task_brd_parse_arg(int argc, const char **argv, const char *tag)
{
    int idx;

    for(idx = 0; idx < argc; idx ++)
    {
        if(0 == strcasecmp(argv[idx], tag) && idx + 1 < argc)
        {
            return (argv[idx + 1]);
        }
    }

    return (NULL_PTR);
}

EC_BOOL task_brd_parse_args(int argc, char **argv, UINT32 *size, UINT32 *tcid, UINT32 *reg_type,
                                    UINT32   *network_level,
                                    CSTRING **sys_cfg_xml_fname_cstr,
                                    CSTRING **basic_cfg_xml_fname_cstr,
                                    CSTRING **script_fname_cstr,
                                    CSTRING **bcast_dhcp_netcard_cstr,
                                    CSTRING **log_path_cstr,
                                    CSTRING **pid_path_cstr,
                                    CSTRING **console_path_cstr,
                                    CSTRING **ssl_path_cstr,
                                    EC_BOOL  *daemon_flag)
{
    int idx;

    /*default setting*/
    (*size) = 1;/*default is 1 process only*/

    for(idx = 0; idx < argc; idx ++)
    {
        if(0 == strcasecmp(argv[idx], "-network_level") && idx + 1 < argc)
        {
            (*network_level) = atol(argv[idx + 1]);
            continue;
        }

        if(0 == strcasecmp(argv[idx], "-np") && idx + 1 < argc)
        {
            //dbg_log(SEC_0015_TASK, 5)(LOGSTDOUT, "size = %s\n", argv[idx + 1]);
            (*size) = atol(argv[idx + 1]);
            continue;
        }

        if(0 == strcasecmp(argv[idx], "-tcid") && idx + 1 < argc)
        {
            //dbg_log(SEC_0015_TASK, 5)(LOGSTDOUT, "tcid = %s\n", argv[idx + 1]);
            if(0 != strcasecmp(argv[idx + 1], "255.255.255.255"))
            {
                (*tcid) = c_ipv4_to_word(argv[idx + 1]);
            }
            continue;
        }

        if(0 == strcasecmp(argv[idx], "-reg") && idx + 1 < argc)
        {
            //dbg_log(SEC_0015_TASK, 5)(LOGSTDOUT, "tcid = %s\n", argv[idx + 1]);
            if(0 == strcasecmp(argv[idx + 1], "all"))
            {
                (*reg_type) = TASK_REGISTER_ALL_SERVER;
                continue;
            }
            if(0 == strcasecmp(argv[idx + 1], "other"))
            {
                (*reg_type) = TASK_REGISTER_OTHER_SERVER;
                continue;
            }
            if(0 == strcasecmp(argv[idx + 1], "udp"))
            {
                (*reg_type) = TASK_REGISTER_UDP_SERVER;
                continue;
            }
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_parse_args: unknown reg type %s\n", argv[idx + 1]);
            return (EC_FALSE);
        }

        if(0 == strcasecmp(argv[idx], "-sconfig") && idx + 1 < argc)
        {
            (*sys_cfg_xml_fname_cstr) = cstring_new((UINT8 *)argv[idx + 1], LOC_TASK_0110);
            continue;
        }

        if(0 == strcasecmp(argv[idx], "-bconfig") && idx + 1 < argc)
        {
            (*basic_cfg_xml_fname_cstr) = cstring_new((UINT8 *)argv[idx + 1], LOC_TASK_0111);
            continue;
        }

        if(0 == strcasecmp(argv[idx], "-script") && idx + 1 < argc)
        {
            (*script_fname_cstr) = cstring_new((UINT8 *)argv[idx + 1], LOC_TASK_0112);
            continue;
        }

        if(0 == strcasecmp(argv[idx], "-eth") && idx + 1 < argc)
        {
            (*bcast_dhcp_netcard_cstr) = cstring_new((UINT8 *)argv[idx + 1], LOC_TASK_0113);
            continue;
        }

        if(0 == strcasecmp(argv[idx], "-logp") && idx + 1 < argc)
        {
            (*log_path_cstr) = cstring_new((UINT8 *)argv[idx + 1], LOC_TASK_0114);
            continue;
        }

        if(0 == strcasecmp(argv[idx], "-pidfile") && idx + 1 < argc)/*optional*/
        {
            (*pid_path_cstr) = cstring_new((UINT8 *)argv[idx + 1], LOC_TASK_0115);
            continue;
        }

        if(0 == strcasecmp(argv[idx], "-daemon") || 0 == strcasecmp(argv[idx], "-d"))
        {
            (*daemon_flag) = EC_TRUE;
            continue;
        }

        if(0 == strcasecmp(argv[idx], "-console") && idx + 1 < argc)
        {
            (*console_path_cstr) = cstring_new((UINT8 *)argv[idx + 1], LOC_TASK_0116);
            continue;
        }
        if(0 == strcasecmp(argv[idx], "-ssl") && idx + 1 < argc)
        {
            (*ssl_path_cstr) = cstring_new((UINT8 *)argv[idx + 1], LOC_TASK_0117);
            continue;
        }
    }

    if(NULL_PTR == (*sys_cfg_xml_fname_cstr))
    {
        /*set default sysconfig xml info*/
        (*sys_cfg_xml_fname_cstr) = cstring_new((UINT8 *)"config.xml", LOC_TASK_0118);
        if(NULL_PTR == (*sys_cfg_xml_fname_cstr))
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_parse_args:new default config xml failed\n");
            return (EC_FALSE);
        }
    }

    if(NULL_PTR == (*basic_cfg_xml_fname_cstr))
    {
        /*set default basic xml info*/
        (*basic_cfg_xml_fname_cstr) = cstring_new((UINT8 *)"basic.xml", LOC_TASK_0119);
        if(NULL_PTR == (*basic_cfg_xml_fname_cstr))
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_parse_args:new basic config xml failed\n");
            return (EC_FALSE);
        }
    }

    if(NULL_PTR == (*bcast_dhcp_netcard_cstr))
    {
        /*set default basic xml info*/
        (*bcast_dhcp_netcard_cstr) = cstring_new((UINT8 *)"eth0", LOC_TASK_0120);
        if(NULL_PTR == (*bcast_dhcp_netcard_cstr))
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_parse_args:new bcast dhcp netcard string failed\n");
            return (EC_FALSE);
        }
    }

    if(NULL_PTR == (*log_path_cstr))
    {
        /*set default log path*/
        (*log_path_cstr) = cstring_new((UINT8 *)"./", LOC_TASK_0121);
        if(NULL_PTR == (*log_path_cstr))
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_parse_args:new default log path failed\n");
            return (EC_FALSE);
        }
    }

    if(NULL_PTR == (*ssl_path_cstr))
    {
        /*set default log path*/
        (*ssl_path_cstr) = cstring_new((UINT8 *)"./", LOC_TASK_0122);
        if(NULL_PTR == (*ssl_path_cstr))
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_parse_args:new default ssl path failed\n");
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

EC_BOOL task_brd_parse_tcid_from_netcards(TASK_BRD *task_brd, const CSET *cnetcard_set, UINT32 *tcid)
{
    TASKS_CFG *tasks_cfg;

    tasks_cfg = sys_cfg_search_tasks_cfg_by_netcards(TASK_BRD_SYS_CFG(task_brd), cnetcard_set);
    if(NULL_PTR == tasks_cfg)
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_parse_tcid_from_netcards: no tasks cfg matched the collected netcards\n");
        return (EC_FALSE);
    }

    if(CMPI_ERROR_TCID == TASKS_CFG_TCID(tasks_cfg))
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_parse_tcid_from_netcards: tasks cfg searched by netcards with invalid tcid\n");
        return (EC_FALSE);
    }

    (*tcid) = TASKS_CFG_TCID(tasks_cfg);

    dbg_log(SEC_0015_TASK, 9)(LOGSTDOUT, "[DEBUG] task_brd_parse_tcid_from_netcards: parsed tcid %s from collected netcards\n",
                        TASKS_CFG_TCID_STR(tasks_cfg));
    return (EC_TRUE);
}

EC_BOOL task_brd_shortcut_config(TASK_BRD *task_brd)
{
    /*local tasks cfg*/
    TASK_BRD_LOCAL_TASKS_CFG(task_brd) = sys_cfg_search_tasks_cfg(TASK_BRD_SYS_CFG(task_brd), TASK_BRD_TCID(task_brd), CMPI_ANY_MASK, CMPI_ANY_MASK);
    if(NULL_PTR == TASK_BRD_LOCAL_TASKS_CFG(task_brd))
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_shortcut_config: not searched tasks cfg for tcid %s failed\n",
                            TASK_BRD_TCID_STR(task_brd));
        return (EC_FALSE);
    }

    /*para cfg of current tcid and rank*/
    TASK_BRD_CPARACFG(task_brd) = sys_cfg_search_cparacfg(TASK_BRD_SYS_CFG(task_brd), TASK_BRD_TCID(task_brd), TASK_BRD_RANK(task_brd));
    if(NULL_PTR == TASK_BRD_CPARACFG(task_brd))
    {
        dbg_log(SEC_0015_TASK, 1)(LOGSTDOUT, "warn:task_brd_shortcut_config: not searched paracfg for tcid %s rank %ld, try to get default setting\n",
                            TASK_BRD_TCID_STR(task_brd), TASK_BRD_RANK(task_brd));

        TASK_BRD_CPARACFG(task_brd) = cparacfg_new(TASK_BRD_TCID(task_brd), TASK_BRD_RANK(task_brd));
        if(NULL_PTR == TASK_BRD_CPARACFG(task_brd))
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_shortcut_config: get default paracfg for tcid %s rank %ld failed\n",
                                TASK_BRD_TCID_STR(task_brd), TASK_BRD_RANK(task_brd));
            return (EC_FALSE);
        }
    }

#if (SWITCH_ON == NGX_BGN_SWITCH)
    /*DETECT tasks cfg*/
    TASK_BRD_DETECT_TASKS_CFG(task_brd) = sys_cfg_search_tasks_cfg_by_role_from_cluster(
                                                            TASK_BRD_SYS_CFG(task_brd),
                                                            (const char *)"detect-ngx",
                                                            (const char *)"master");
    if(NULL_PTR != TASK_BRD_DETECT_TASKS_CFG(task_brd))
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "[DEBUG] task_brd_shortcut_config: found DETECT tcid: %s\n",
                            TASKS_CFG_TCID_STR(TASK_BRD_DETECT_TASKS_CFG(task_brd)));
    }
    else
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "warn:task_brd_shortcut_config: not found 'master' in cluster 'detect-ngx' for DETECT\n");
    }
#endif/*(SWITCH_ON == NGX_BGN_SWITCH)*/
    return (EC_TRUE);
}

/*--------------------------------- create http connection pool ---------------------------------*/
EC_BOOL task_brd_http_connp_one(TASK_BRD *task_brd, const UINT32 remote_tcid, const UINT32 remote_srv_ipaddr, const UINT32 remote_srv_port)
{
    CCONNP *cconnp;
    if(TASKS_CFG_TCID(TASK_BRD_LOCAL_TASKS_CFG(task_brd)) == remote_tcid)/*skip itself*/
    {
        return (EC_TRUE);
    }

    cconnp = cconnp_mgr_add(TASK_BRD_HTTP_CCONNP_MGR(task_brd), remote_tcid, remote_srv_ipaddr, remote_srv_port);
    if(NULL_PTR == cconnp)
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_http_connp_one: add connp tcid %s srv %s:%ld failed\n",
                            c_word_to_ipv4(remote_tcid), c_word_to_ipv4(remote_srv_ipaddr),remote_srv_port);
        return (EC_TRUE);
    }

    dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "[DEBUG] task_brd_http_connp_one: add connp tcid %s srv %s:%ld done\n",
                        CCONNP_SRV_TCID_STR(cconnp), CCONNP_SRV_IPADDR_STR(cconnp), CCONNP_SRV_PORT(cconnp));

    return (EC_TRUE);
}

EC_BOOL task_brd_http_connp_node(TASK_BRD *task_brd, const UINT32 tcid)
{
    TASKS_CFG *remote_tasks_cfg;

    remote_tasks_cfg = sys_cfg_search_tasks_cfg(TASK_BRD_SYS_CFG(task_brd), tcid, CMPI_ANY_MASK, CMPI_ANY_MASK);
    if(NULL_PTR == remote_tasks_cfg)
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "info:task_brd_http_connp_node: not found tasks_cfg of node %s\n", c_word_to_ipv4(tcid));
        return (EC_TRUE);
    }

    /*check whether remote_tasks_cfg has csrvport*/
    if(CMPI_ERROR_SRVPORT == TASKS_CFG_CSRVPORT(remote_tasks_cfg))
    {
        return (EC_TRUE);
    }

    if(EC_FALSE == task_brd_http_connp_one(task_brd,
                                      TASKS_CFG_TCID(remote_tasks_cfg),
                                      TASKS_CFG_SRVIPADDR(remote_tasks_cfg),
                                      TASKS_CFG_CSRVPORT(remote_tasks_cfg)
                                      )
    )
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_http_connp_node: add remote tasks tcid %s: "
                                             "maski %s maske %s [srvipaddr %s:csrvport %ld] to connp failed\n",
                            TASKS_CFG_TCID_STR(remote_tasks_cfg),
                            TASKS_CFG_MASKI_STR(remote_tasks_cfg),
                            TASKS_CFG_MASKE_STR(remote_tasks_cfg),
                            TASKS_CFG_SRVIPADDR_STR(remote_tasks_cfg),
                            TASKS_CFG_CSRVPORT(remote_tasks_cfg));
        return (EC_FALSE);
    }
    dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "[DEBUG] task_brd_http_connp_node: add remote tasks tcid %s: "
                                         "maski %s maske %s [srvipaddr %s:csrvport %ld] to connp done\n",
                        TASKS_CFG_TCID_STR(remote_tasks_cfg),
                        TASKS_CFG_MASKI_STR(remote_tasks_cfg),
                        TASKS_CFG_MASKE_STR(remote_tasks_cfg),
                        TASKS_CFG_SRVIPADDR_STR(remote_tasks_cfg),
                        TASKS_CFG_CSRVPORT(remote_tasks_cfg));
    return (EC_TRUE);
}

EC_BOOL task_brd_http_connp_role_str(TASK_BRD *task_brd, CLUSTER_CFG *cluster_cfg, const char *role_str)
{
    CVECTOR *cluster_nodes;
    UINT32 pos;

    cluster_nodes = CLUSTER_CFG_NODES(cluster_cfg);

    CVECTOR_LOCK(cluster_nodes, LOC_TASK_0123);
    for(pos = 0; pos < cvector_size(cluster_nodes); pos ++)
    {
        CLUSTER_NODE_CFG *cluster_node_cfg;

        cluster_node_cfg = (CLUSTER_NODE_CFG *)cvector_get_no_lock(cluster_nodes, pos);
        if(NULL_PTR == cluster_node_cfg)
        {
            continue;
        }

        if(EC_FALSE == cluster_node_cfg_check_role_str(cluster_node_cfg, role_str))
        {
            dbg_log(SEC_0015_TASK, 9)(LOGSTDOUT, "[DEBUG] task_brd_http_connp_role_str: give up, "
                                                 "due to cluster_node_cfg role %s tcid %s not matched to role %s\n",
                               (char *)CLUSTER_NODE_CFG_ROLE_STR(cluster_node_cfg),
                               (char *)CLUSTER_NODE_CFG_TCID_STR(cluster_node_cfg),
                               role_str);
            continue;
        }

        dbg_log(SEC_0015_TASK, 9)(LOGSTDOUT, "[DEBUG] task_brd_http_connp_role_str: try to add connp to "
                                             "cluster_node_cfg role %s tcid %s which is matched to role %s\n",
                           (char *)CLUSTER_NODE_CFG_ROLE_STR(cluster_node_cfg),
                           (char *)CLUSTER_NODE_CFG_TCID_STR(cluster_node_cfg),
                           role_str);

        task_brd_http_connp_node(task_brd, CLUSTER_NODE_CFG_TCID(cluster_node_cfg));
    }
    CVECTOR_UNLOCK(cluster_nodes, LOC_TASK_0124);

    return (EC_TRUE);
}

EC_BOOL task_brd_http_connp_master_slave_cluster(TASK_BRD *task_brd, CLUSTER_CFG *cluster_cfg)
{
    CLUSTER_NODE_CFG *cluster_node_cfg;

    /*whoami*/
    cluster_node_cfg = cluster_cfg_search_by_tcid_rank(cluster_cfg, TASK_BRD_TCID(task_brd), TASK_BRD_RANK(task_brd));
    if(NULL_PTR == cluster_node_cfg)
    {
        dbg_log(SEC_0015_TASK, 1)(LOGSTDOUT, "warn:task_brd_http_connp_master_slave_cluster: current tcid %s rank %ld not belong to cluster %ld\n",
                           TASK_BRD_TCID_STR(task_brd), TASK_BRD_RANK(task_brd), CLUSTER_CFG_ID(cluster_cfg));
        return (EC_TRUE);
    }

    /*I am master, setup http connection pool of all slaves*/
    if(EC_TRUE == cluster_node_cfg_check_role_str(cluster_node_cfg, (const char *)"master"))
    {
        return task_brd_http_connp_role_str(task_brd, cluster_cfg, (const char *)"slave");
    }

    /*I am slave, setup http connection pool of all masters*/
    if(EC_TRUE == cluster_node_cfg_check_role_str(cluster_node_cfg, (const char *)"slave"))
    {
        return task_brd_http_connp_role_str(task_brd, cluster_cfg, (const char *)"master");
    }

    dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_http_connp_master_slave_cluster: invalid cluster node role %s\n",
                       (char *)CLUSTER_NODE_CFG_ROLE_STR(cluster_node_cfg));
    return (EC_FALSE);
}

EC_BOOL task_brd_http_connp_one_cluster(TASK_BRD *task_brd, const UINT32 cluster_id)
{
    CLUSTER_CFG *cluster_cfg;

    cluster_cfg = sys_cfg_get_cluster_cfg_by_id(TASK_BRD_SYS_CFG(task_brd), cluster_id);
    if(NULL_PTR == cluster_cfg)
    {
        dbg_log(SEC_0015_TASK, 1)(LOGSTDOUT, "warn:task_brd_http_connp_one_cluster: not found cluter %ld definition\n", cluster_id);
        return (EC_TRUE);
    }

    dbg_log(SEC_0015_TASK, 9)(LOGSTDOUT, "[DEBUG] task_brd_http_connp_one_cluster: try to register to cluter %ld (%s)\n",
                        cluster_id, (char *)CLUSTER_CFG_NAME_STR(cluster_cfg));

    if(MODEL_TYPE_MASTER_SLAVE == CLUSTER_CFG_MODEL(cluster_cfg))
    {
        return task_brd_http_connp_master_slave_cluster(task_brd, cluster_cfg);
    }

    dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_http_connp_one_cluster: invalid cluster model %ld\n", CLUSTER_CFG_MODEL(cluster_cfg));
    return (EC_FALSE);
}

EC_BOOL task_brd_http_connp_cluster(TASK_BRD *task_brd)
{
    TASKS_CFG  *tasks_cfg;
    CVECTOR    *cluster_vec;
    EC_BOOL     ret;

    tasks_cfg   = TASK_BRD_LOCAL_TASKS_CFG(task_brd);
    cluster_vec = TASKS_CFG_CLUSTER_VEC(tasks_cfg);
    if(EC_FALSE == cvector_loop(cluster_vec, &ret, NULL_PTR,
                        (UINT32)2,
                        (UINT32)1,
                        (UINT32)task_brd_http_connp_one_cluster,
                        task_brd,
                        NULL_PTR)
    )
    {
        dbg_log(SEC_0015_TASK, 1)(LOGSTDOUT, "warn:task_brd_http_connp_cluster: found some issue, pls double check\n");
    }
    return (EC_TRUE);
}

/*--------------------------------- register remote servers ---------------------------------*/
EC_BOOL task_brd_register_one(TASK_BRD *task_brd, const UINT32 remote_tcid, const UINT32 remote_srv_ipaddr, const UINT32 remote_srv_port, const UINT32 conn_num)
{
    UINT32 csocket_cnode_idx;
    UINT32 conn_count;

    if(TASKS_CFG_TCID(TASK_BRD_LOCAL_TASKS_CFG(task_brd)) == remote_tcid)/*skip itself*/
    {
        return (EC_TRUE);
    }

    //dbg_log(SEC_0015_TASK, 9)(LOGSTDOUT, "[DEBUG] task_brd_register_one: tasks_cfg %lx of task_brd\n", TASK_BRD_LOCAL_TASKS_CFG(task_brd));
    //tasks_cfg_print(LOGSTDOUT, TASK_BRD_LOCAL_TASKS_CFG(task_brd));

    conn_count = tasks_worker_count(TASKS_CFG_WORKER(TASK_BRD_LOCAL_TASKS_CFG(task_brd)), remote_tcid, remote_srv_ipaddr, remote_srv_port)
               + tasks_monitor_count(TASKS_CFG_MONITOR(TASK_BRD_LOCAL_TASKS_CFG(task_brd)), remote_tcid, remote_srv_ipaddr, remote_srv_port);

    /*setup multi sockets to remote taskcomm*/
    for(csocket_cnode_idx = conn_count; csocket_cnode_idx < conn_num; csocket_cnode_idx ++)
    {
        dbg_log(SEC_0015_TASK, 9)(LOGSTDOUT, "[DEBUG]task_brd_register_one: try to register to remote tasks tcid %s srvipaddr %s srvport %ld\n",
                            c_word_to_ipv4(remote_tcid), c_word_to_ipv4(remote_srv_ipaddr),remote_srv_port);

        if(EC_FALSE == tasks_monitor_open(TASKS_CFG_MONITOR(TASK_BRD_LOCAL_TASKS_CFG(task_brd)), remote_tcid, remote_srv_ipaddr, remote_srv_port))
        {
            dbg_log(SEC_0015_TASK, 1)(LOGSTDOUT, "error:task_brd_register_one: register to remote tasks tcid %s srvipaddr %s srvport %ld failed\n",
                                c_word_to_ipv4(remote_tcid), c_word_to_ipv4(remote_srv_ipaddr),remote_srv_port);
            return (EC_FALSE);
        }

        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "[DEBUG] task_brd_register_one: register to remote tasks tcid %s srvipaddr %s srvport %ld done\n",
                            c_word_to_ipv4(remote_tcid), c_word_to_ipv4(remote_srv_ipaddr),remote_srv_port);
    }
    return (EC_TRUE);
}

TASKS_CFG *task_brd_register_node_fetch(TASK_BRD *task_brd, const UINT32 tcid)
{
    TASKS_CFG *remote_tasks_cfg;

    remote_tasks_cfg = sys_cfg_search_tasks_cfg(TASK_BRD_SYS_CFG(task_brd), tcid, CMPI_ANY_MASK, CMPI_ANY_MASK);
    if(NULL_PTR == remote_tasks_cfg)
    {
        dbg_log(SEC_0015_TASK, 5)(LOGSTDOUT, "info:task_brd_register_node_fetch: not found tasks_cfg of node %s\n", c_word_to_ipv4(tcid));
        return (NULL_PTR);
    }

    /*check whether remote_tasks_cfg belong to the intranet of local_tasks_cfg*/
    if(EC_FALSE == tasks_cfg_is_intranet(TASK_BRD_LOCAL_TASKS_CFG(task_brd), remote_tasks_cfg)
    && EC_FALSE == tasks_cfg_is_externet(TASK_BRD_LOCAL_TASKS_CFG(task_brd), remote_tasks_cfg)
    && EC_FALSE == tasks_cfg_is_lannet(TASK_BRD_LOCAL_TASKS_CFG(task_brd), remote_tasks_cfg)
    && EC_FALSE == tasks_cfg_is_dbgnet(TASK_BRD_LOCAL_TASKS_CFG(task_brd), remote_tasks_cfg)
    && EC_FALSE == tasks_cfg_is_monnet(TASK_BRD_LOCAL_TASKS_CFG(task_brd), remote_tasks_cfg)
    )
    {
        return (NULL_PTR);
    }

    if(CMPI_ERROR_IPADDR  == TASKS_CFG_SRVIPADDR(remote_tasks_cfg)
    || CMPI_ERROR_SRVPORT == TASKS_CFG_SRVPORT(remote_tasks_cfg))
    {
        dbg_log(SEC_0015_TASK, 1)(LOGSTDOUT, "error:task_brd_register_node_fetch: not register to remote tasks tcid %s: "
                                             "maski %s maske %s [srvipaddr %s:srvport %ld]\n",
                            TASKS_CFG_TCID_STR(remote_tasks_cfg),
                            TASKS_CFG_MASKI_STR(remote_tasks_cfg),
                            TASKS_CFG_MASKE_STR(remote_tasks_cfg),
                            TASKS_CFG_SRVIPADDR_STR(remote_tasks_cfg),
                            TASKS_CFG_SRVPORT(remote_tasks_cfg));
        return (NULL_PTR);
    }

    return (remote_tasks_cfg);
}

EC_BOOL task_brd_register_node(TASK_BRD *task_brd, const UINT32 tcid)
{
    TASKS_CFG *remote_tasks_cfg;

    remote_tasks_cfg = sys_cfg_search_tasks_cfg(TASK_BRD_SYS_CFG(task_brd), tcid, CMPI_ANY_MASK, CMPI_ANY_MASK);
    if(NULL_PTR == remote_tasks_cfg)
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "info:task_brd_register_node: not found tasks_cfg of node %s\n", c_word_to_ipv4(tcid));
        return (EC_TRUE);
    }

    /*check whether remote_tasks_cfg belong to the intranet of local_tasks_cfg*/
    if(EC_FALSE == tasks_cfg_is_intranet(TASK_BRD_LOCAL_TASKS_CFG(task_brd), remote_tasks_cfg)
    && EC_FALSE == tasks_cfg_is_externet(TASK_BRD_LOCAL_TASKS_CFG(task_brd), remote_tasks_cfg)
    && EC_FALSE == tasks_cfg_is_lannet(TASK_BRD_LOCAL_TASKS_CFG(task_brd), remote_tasks_cfg)
    && EC_FALSE == tasks_cfg_is_dbgnet(TASK_BRD_LOCAL_TASKS_CFG(task_brd), remote_tasks_cfg)
    && EC_FALSE == tasks_cfg_is_monnet(TASK_BRD_LOCAL_TASKS_CFG(task_brd), remote_tasks_cfg)
    )
    {
        return (EC_TRUE);
    }

    if(CMPI_ERROR_IPADDR  == TASKS_CFG_SRVIPADDR(remote_tasks_cfg)
    || CMPI_ERROR_SRVPORT == TASKS_CFG_SRVPORT(remote_tasks_cfg))
    {
        dbg_log(SEC_0015_TASK, 1)(LOGSTDOUT, "error:task_brd_register_node: not register to remote tasks tcid %s: "
                                             "maski %s maske %s [srvipaddr %s:srvport %ld]\n",
                            TASKS_CFG_TCID_STR(remote_tasks_cfg),
                            TASKS_CFG_MASKI_STR(remote_tasks_cfg),
                            TASKS_CFG_MASKE_STR(remote_tasks_cfg),
                            TASKS_CFG_SRVIPADDR_STR(remote_tasks_cfg),
                            TASKS_CFG_SRVPORT(remote_tasks_cfg));
        return (EC_TRUE);
    }

    if(EC_FALSE == task_brd_register_one(task_brd, TASKS_CFG_TCID(remote_tasks_cfg),
                                      TASKS_CFG_SRVIPADDR(remote_tasks_cfg),
                                      TASKS_CFG_SRVPORT(remote_tasks_cfg),
                                      (UINT32)CSOCKET_CNODE_NUM))
    {
        dbg_log(SEC_0015_TASK, 1)(LOGSTDOUT, "error:task_brd_register_node: register to remote tasks tcid %s: "
                                             "maski %s maske %s [srvipaddr %s:srvport %ld] failed\n",
                            TASKS_CFG_TCID_STR(remote_tasks_cfg),
                            TASKS_CFG_MASKI_STR(remote_tasks_cfg),
                            TASKS_CFG_MASKE_STR(remote_tasks_cfg),
                            TASKS_CFG_SRVIPADDR_STR(remote_tasks_cfg),
                            TASKS_CFG_SRVPORT(remote_tasks_cfg));
        return (EC_TRUE);
    }
    dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "[DEBUG] task_brd_register_node: register to remote tasks tcid %s: "
                                         "maski %s maske %s [srvipaddr %s:srvport %ld] done\n",
                        TASKS_CFG_TCID_STR(remote_tasks_cfg),
                        TASKS_CFG_MASKI_STR(remote_tasks_cfg),
                        TASKS_CFG_MASKE_STR(remote_tasks_cfg),
                        TASKS_CFG_SRVIPADDR_STR(remote_tasks_cfg),
                        TASKS_CFG_SRVPORT(remote_tasks_cfg));
    return (EC_TRUE);
}

EC_BOOL task_brd_register_all(TASK_BRD *task_brd, CLUSTER_CFG *cluster_cfg)
{
    CVECTOR *cluster_nodes;
    UINT32 pos;

    cluster_nodes = CLUSTER_CFG_NODES(cluster_cfg);

    CVECTOR_LOCK(cluster_nodes, LOC_TASK_0125);
    for(pos = 0; pos < cvector_size(cluster_nodes); pos ++)
    {
        CLUSTER_NODE_CFG *cluster_node_cfg;

        cluster_node_cfg = (CLUSTER_NODE_CFG *)cvector_get_no_lock(cluster_nodes, pos);
        if(NULL_PTR == cluster_node_cfg)
        {
            continue;
        }

        task_brd_register_node(task_brd, CLUSTER_NODE_CFG_TCID(cluster_node_cfg));
    }
    CVECTOR_UNLOCK(cluster_nodes, LOC_TASK_0126);

    return (EC_TRUE);
}

EC_BOOL task_brd_register_role_str(TASK_BRD *task_brd, CLUSTER_CFG *cluster_cfg, const char *role_str)
{
    CVECTOR *cluster_nodes;
    UINT32 pos;

    cluster_nodes = CLUSTER_CFG_NODES(cluster_cfg);

    CVECTOR_LOCK(cluster_nodes, LOC_TASK_0127);
    for(pos = 0; pos < cvector_size(cluster_nodes); pos ++)
    {
        CLUSTER_NODE_CFG *cluster_node_cfg;

        cluster_node_cfg = (CLUSTER_NODE_CFG *)cvector_get_no_lock(cluster_nodes, pos);
        if(NULL_PTR == cluster_node_cfg)
        {
            continue;
        }

        if(EC_FALSE == cluster_node_cfg_check_role_str(cluster_node_cfg, role_str))
        {
            dbg_log(SEC_0015_TASK, 9)(LOGSTDOUT, "[DEBUG] task_brd_register_role_str: give up, "
                                                 "due to cluster_node_cfg role %s tcid %s  not matched to role %s\n",
                               (char *)CLUSTER_NODE_CFG_ROLE_STR(cluster_node_cfg),
                               (char *)CLUSTER_NODE_CFG_TCID_STR(cluster_node_cfg),
                               role_str);
            continue;
        }

        dbg_log(SEC_0015_TASK, 9)(LOGSTDOUT, "[DEBUG] task_brd_register_role_str: try to register to "
                                             "cluster_node_cfg role %s tcid %s which is matched to role %s\n",
                           (char *)CLUSTER_NODE_CFG_ROLE_STR(cluster_node_cfg),
                           (char *)CLUSTER_NODE_CFG_TCID_STR(cluster_node_cfg),
                           role_str);

        task_brd_register_node(task_brd, CLUSTER_NODE_CFG_TCID(cluster_node_cfg));
    }
    CVECTOR_UNLOCK(cluster_nodes, LOC_TASK_0128);

    return (EC_TRUE);
}

EC_BOOL task_brd_register_role_str_and_group_cstr(TASK_BRD *task_brd, CLUSTER_CFG *cluster_cfg, const char *role_str, CSTRING *group_cstr)
{
    CVECTOR *cluster_nodes;
    UINT32 pos;

    cluster_nodes = CLUSTER_CFG_NODES(cluster_cfg);

    CVECTOR_LOCK(cluster_nodes, LOC_TASK_0129);
    for(pos = 0; pos < cvector_size(cluster_nodes); pos ++)
    {
        CLUSTER_NODE_CFG *cluster_node_cfg;

        cluster_node_cfg = (CLUSTER_NODE_CFG *)cvector_get_no_lock(cluster_nodes, pos);
        if(NULL_PTR == cluster_node_cfg)
        {
            continue;
        }

        if(EC_FALSE == cluster_node_cfg_check_role_str(cluster_node_cfg, role_str))
        {
            dbg_log(SEC_0015_TASK, 9)(LOGSTDOUT, "[DEBUG] task_brd_register_role_str_and_group_cstr: give up, "
                                                 "due to cluster_node_cfg role %s tcid %s  not matched to role %s\n",
                               (char *)CLUSTER_NODE_CFG_ROLE_STR(cluster_node_cfg),
                               (char *)CLUSTER_NODE_CFG_TCID_STR(cluster_node_cfg),
                               role_str);
            continue;
        }

        if(EC_FALSE == cluster_node_cfg_check_group_cstr(cluster_node_cfg, group_cstr))
        {
            dbg_log(SEC_0015_TASK, 9)(LOGSTDOUT, "[DEBUG] task_brd_register_role_str_and_group_cstr: give up, "
                                                 "due to cluster_node_cfg group %s tcid %s  not matched to group %s\n",
                               (char *)CLUSTER_NODE_CFG_GROUP_STR(cluster_node_cfg),
                               (char *)CLUSTER_NODE_CFG_TCID_STR(cluster_node_cfg),
                               (char *)cstring_get_str(group_cstr));
            continue;
        }

        dbg_log(SEC_0015_TASK, 9)(LOGSTDOUT, "[DEBUG] task_brd_register_role_str_and_group_cstr: try to register to "
                                             "cluster_node_cfg role %s tcid %s which is matched to role %s\n",
                           (char *)CLUSTER_NODE_CFG_ROLE_STR(cluster_node_cfg),
                           (char *)CLUSTER_NODE_CFG_TCID_STR(cluster_node_cfg),
                           role_str);

        task_brd_register_node(task_brd, CLUSTER_NODE_CFG_TCID(cluster_node_cfg));
    }
    CVECTOR_UNLOCK(cluster_nodes, LOC_TASK_0130);

    return (EC_TRUE);
}

EC_BOOL task_brd_register_master_slave_cluster(TASK_BRD *task_brd, CLUSTER_CFG *cluster_cfg)
{
    CLUSTER_NODE_CFG *cluster_node_cfg;

    /*whoami*/
    cluster_node_cfg = cluster_cfg_search_by_tcid_rank(cluster_cfg, TASK_BRD_TCID(task_brd), TASK_BRD_RANK(task_brd));
    if(NULL_PTR == cluster_node_cfg)
    {
        dbg_log(SEC_0015_TASK, 1)(LOGSTDOUT, "warn:task_brd_register_master_slave_cluster: current tcid %s rank %ld not belong to cluster %ld\n",
                           TASK_BRD_TCID_STR(task_brd), TASK_BRD_RANK(task_brd), CLUSTER_CFG_ID(cluster_cfg));
        return (EC_TRUE);
    }

    /*I am master, connect to all slaves*/
    if(EC_TRUE == cluster_node_cfg_check_role_str(cluster_node_cfg, (const char *)"master:server"))
    {
        return task_brd_register_role_str(task_brd, cluster_cfg, (const char *)"slave:client");
    }

    /*I am slave, connect to all masters*/
    if(EC_TRUE == cluster_node_cfg_check_role_str(cluster_node_cfg, (const char *)"slave:client"))
    {
        return task_brd_register_role_str(task_brd, cluster_cfg, (const char *)"master:server");
    }

    dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_register_master_slave_cluster: invalid cluster node role %s\n",
                       (char *)CLUSTER_NODE_CFG_ROLE_STR(cluster_node_cfg));
    return (EC_FALSE);
}

EC_BOOL task_brd_register_cross_cluster(TASK_BRD *task_brd, CLUSTER_CFG *cluster_cfg)
{
    return task_brd_register_all(task_brd, cluster_cfg);
}

EC_BOOL task_brd_register_one_cluster(TASK_BRD *task_brd, const UINT32 cluster_id)
{
    CLUSTER_CFG *cluster_cfg;

    cluster_cfg = sys_cfg_get_cluster_cfg_by_id(TASK_BRD_SYS_CFG(task_brd), cluster_id);
    if(NULL_PTR == cluster_cfg)
    {
        dbg_log(SEC_0015_TASK, 1)(LOGSTDOUT, "warn:task_brd_register_one_cluster: not found cluter %ld definition\n", cluster_id);
        return (EC_TRUE);
    }

    dbg_log(SEC_0015_TASK, 9)(LOGSTDOUT, "[DEBUG] task_brd_register_one_cluster: try to register to cluter %ld (%s)\n",
                        cluster_id, (char *)CLUSTER_CFG_NAME_STR(cluster_cfg));

    if(MODEL_TYPE_MASTER_SLAVE == CLUSTER_CFG_MODEL(cluster_cfg))
    {
        return task_brd_register_master_slave_cluster(task_brd, cluster_cfg);
    }

    if(MODEL_TYPE_CROSS_CONNEC == CLUSTER_CFG_MODEL(cluster_cfg))
    {
        return task_brd_register_cross_cluster(task_brd, cluster_cfg);
    }

    dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_register_cluster_one: invalid cluster model %ld\n", CLUSTER_CFG_MODEL(cluster_cfg));
    return (EC_FALSE);
}

EC_BOOL task_brd_register_udp_server(TASK_BRD *task_brd)
{
    MCAST_CFG *mcast_cfg;
    TASKS_CFG *remote_tasks_cfg;

    mcast_cfg = sys_cfg_get_mcast_cfg(TASK_BRD_SYS_CFG(task_brd));

    remote_tasks_cfg = sys_cfg_search_tasks_cfg(TASK_BRD_SYS_CFG(task_brd), MCAST_CFG_TCID(mcast_cfg), CMPI_ANY_MASK, CMPI_ANY_MASK);
    if(NULL_PTR == remote_tasks_cfg)
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_register_udp_server: not found tasks_cfg of udp %s\n", MCAST_CFG_TCID_STR(mcast_cfg));
        return (EC_FALSE);
    }

    /*check whether remote_tasks_cfg belong to the intranet of local_tasks_cfg*/
    if(EC_FALSE == tasks_cfg_is_intranet(TASK_BRD_LOCAL_TASKS_CFG(task_brd), remote_tasks_cfg)
    && EC_FALSE == tasks_cfg_is_externet(TASK_BRD_LOCAL_TASKS_CFG(task_brd), remote_tasks_cfg)
    && EC_FALSE == tasks_cfg_is_lannet(TASK_BRD_LOCAL_TASKS_CFG(task_brd), remote_tasks_cfg)
    && EC_FALSE == tasks_cfg_is_dbgnet(TASK_BRD_LOCAL_TASKS_CFG(task_brd), remote_tasks_cfg)
    && EC_FALSE == tasks_cfg_is_monnet(TASK_BRD_LOCAL_TASKS_CFG(task_brd), remote_tasks_cfg)
    )
    {
        return (EC_FALSE);
    }

    if(EC_FALSE == task_brd_register_one(task_brd, TASKS_CFG_TCID(remote_tasks_cfg),
                                      TASKS_CFG_SRVIPADDR(remote_tasks_cfg), TASKS_CFG_SRVPORT(remote_tasks_cfg), (UINT32)CSOCKET_CNODE_NUM))
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_register_udp_server: failed register to remote tasks tcid %s: maski %s maske %s [srvipaddr %s:srvport %ld]\n",
                            TASKS_CFG_TCID_STR(remote_tasks_cfg), TASKS_CFG_MASKI_STR(remote_tasks_cfg),TASKS_CFG_MASKE_STR(remote_tasks_cfg),
                            TASKS_CFG_SRVIPADDR_STR(remote_tasks_cfg), TASKS_CFG_SRVPORT(remote_tasks_cfg));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL task_brd_register_cluster(TASK_BRD *task_brd)
{
    TASKS_CFG  *tasks_cfg;
    CVECTOR    *cluster_vec;
    EC_BOOL     ret;

    tasks_cfg   = TASK_BRD_LOCAL_TASKS_CFG(task_brd);
    cluster_vec = TASKS_CFG_CLUSTER_VEC(tasks_cfg);
    if(EC_FALSE == cvector_loop(cluster_vec, &ret, NULL_PTR,
                        (UINT32)2,
                        (UINT32)1,
                        (UINT32)task_brd_register_one_cluster,
                        task_brd,
                        NULL_PTR))
    {
        dbg_log(SEC_0015_TASK, 1)(LOGSTDOUT, "warn:task_brd_register_cluster: found some issue, pls double check\n");
    }
    return (EC_TRUE);
}

/*reg_type is I/O parameter*/
EC_BOOL task_brd_adjust_reg_type(TASK_BRD *task_brd, const UINT32 this_tcid, UINT32 *reg_type)
{
    if(TASK_REGISTER_UDP_SERVER == (*reg_type))
    {
        MCAST_CFG *mcast_cfg;
        mcast_cfg = sys_cfg_get_mcast_cfg(TASK_BRD_SYS_CFG(task_brd));
        if(MCAST_TYPE_IS_MASTER == MCAST_CFG_TYPE(mcast_cfg) && this_tcid == MCAST_CFG_TCID(mcast_cfg))
        {
            /*reg udp ==> reg all*/
            (*reg_type) = TASK_REGISTER_ALL_SERVER;
            return (EC_TRUE);
        }
    }
    return (EC_TRUE);
}

EC_BOOL task_brd_enable_coredump()
{
    struct rlimit rlim;

    /* Set Linux DUMPABLE flag */
    if (0 != prctl(PR_SET_DUMPABLE, 1, 0, 0, 0))
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_enable_coredump: prctl failed where errno = %d, errstr = %s\n",
                            errno, strerror(errno));
    }
    /* Make sure coredumps are not limited */
    if (0 == getrlimit(RLIMIT_CORE, &rlim))
    {
        rlim.rlim_cur = rlim.rlim_max;
        setrlimit(RLIMIT_CORE, &rlim);
    }

    return (EC_TRUE);
}

EC_BOOL task_brd_os_setting(TASK_BRD *task_brd)
{
    task_brd_enable_coredump();

#if (SWITCH_OFF == NGX_BGN_SWITCH)
    /*set RLIMIT_NOFILE*/
    {
        struct rlimit limit;
        int           resource;

        resource = RLIMIT_NOFILE;
        if(0 != getrlimit(resource, &limit))
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_os_setting: "
                                                 "[RLIMIT_NOFILE] getrlimit failed, errno = %d, errstr = %s\n",
                                                 errno, strerror(errno));
            return (EC_FALSE);
        }

        dbg_log(SEC_0015_TASK, 1)(LOGSTDOUT, "[DEBUG] task_brd_os_setting: "
                                             "[RLIMIT_NOFILE] resource soft limit: %d, hard limit: %d\n",
                                             limit.rlim_cur, limit.rlim_max);

        limit.rlim_cur = 819200; /*Soft limit*/
        limit.rlim_max = 819200; /*Hard limit (ceiling for rlim_cur)*/

        if(0 != setrlimit(resource, &limit))
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_os_setting: "
                                                 "[RLIMIT_NOFILE] setrlimit soft limit %d or hard limit %d failed, "
                                                 "errno = %d, errstr = %s\n",
                                                 limit.rlim_cur, limit.rlim_max,
                                                 errno, strerror(errno));
            return (EC_FALSE);
        }

        /*clean*/
        limit.rlim_cur = 0;
        limit.rlim_max = 0;

        if(0 != getrlimit(resource, &limit))
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_os_setting: "
                                                 "[RLIMIT_NOFILE] getrlimit failed, errno = %d, errstr = %s\n",
                                                 errno, strerror(errno));
            return (EC_FALSE);
        }

        dbg_log(SEC_0015_TASK, 1)(LOGSTDOUT, "[DEBUG] task_brd_os_setting: "
                                             "[RLIMIT_NOFILE] resource soft limit: %d, hard limit: %d\n",
                                             limit.rlim_cur, limit.rlim_max);

    }
#endif/*(SWITCH_OFF == NGX_BGN_SWITCH)*/

#if 0
    /* setgid / setuid */
    if (global.gid && setgid(global.gid) == -1)
    {
        Alert("[%s.main()] Cannot set gid %d.\n", argv[0], global.gid);
        protocol_unbind_all();
        exit(1);
    }

    if (global.uid && setuid(global.uid) == -1)
    {
        Alert("[%s.main()] Cannot set uid %d.\n", argv[0], global.uid);
        protocol_unbind_all();
        exit(1);
    }
#endif
    return (EC_TRUE);
}

EC_BOOL task_brd_os_setting_print(LOG *log)
{
    struct rlimit limit;

    if(0 == getrlimit(RLIMIT_NOFILE, &limit))
    {
        sys_log(log, "task_brd_os_setting_print: "
                     "[RLIMIT_NOFILE] resource soft limit: %d, hard limit: %d\n",
                     limit.rlim_cur, limit.rlim_max);
    }

    if(0 == getrlimit(RLIMIT_CORE, &limit))
    {
        sys_log(log, "task_brd_os_setting_print: "
                     "[RLIMIT_CORE] resource soft limit: %d, hard limit: %d\n",
                     limit.rlim_cur, limit.rlim_max);
    }
    return (EC_TRUE);
}

char *task_brd_finger_arg(const char *k)
{
    TASK_BRD    *task_brd;

    int          argc;
    char       **argv;

    int          idx;

    task_brd = task_brd_default_get();

    argc = TASK_BRD_SAVED_ARGC(task_brd);
    argv = TASK_BRD_SAVED_ARGV(task_brd);

    for(idx = 0; idx < argc; idx ++)
    {
        if(0 == strcasecmp(argv[idx], k) && idx + 1 < argc)
        {
            return (argv[idx + 1]);
        }
    }

     return (NULL_PTR);
}

/*copied from nginx*/
EC_BOOL task_brd_init_setproctitle()
{
    TASK_BRD    *task_brd;
    char       **os_argv;
    char        *os_argv_last;

    char        *p;
    size_t       size;
    int          i;

    task_brd = task_brd_default_get();

    os_argv = TASK_BRD_OS_ARGV(task_brd);

    size = 0;

    for(i = 0; NULL_PTR != environ[i]; i ++)
    {
        size += strlen(environ[i]) + 1;
    }

    p = safe_malloc(size, LOC_TASK_0131);
    if(NULL_PTR == p)
    {
        return (EC_FALSE);
    }

     TASK_BRD_CACHE_ENVIRON(task_brd) = p;

    os_argv_last = os_argv[0];

    for(i = 0; NULL_PTR != os_argv[i]; i++)
    {
        if(os_argv_last == os_argv[i])
        {
            os_argv_last = os_argv[i] + strlen(os_argv[i]) + 1;
        }
    }

    for(i = 0; environ[i]; i++)
    {
        if (os_argv_last == environ[i])
        {
            size = strlen(environ[i]) + 1;
            os_argv_last = environ[i] + size;

            BCOPY((void *)environ[i], (void *)p, size);
            environ[i] = (char *) p;
            p += size;
        }
    }

    os_argv_last --;

    TASK_BRD_OS_ARGV_LAST(task_brd) = os_argv_last;

    return (EC_TRUE);
}

void task_brd_setproctitle(const char *title)
{
    TASK_BRD    *task_brd;
    char        *node_type;

    char       **os_argv;
    char        *os_argv_last;

    char        *p;

    task_brd = task_brd_default_get();

    node_type = task_brd_finger_arg("-node_type");
    if(NULL_PTR == node_type)
    {
        /*do nothing*/
        return;
    }

    os_argv      = TASK_BRD_OS_ARGV(task_brd);
    os_argv_last = TASK_BRD_OS_ARGV_LAST(task_brd);

    os_argv[1] = NULL_PTR;

    p = c_copy_str_n(node_type, os_argv[0], os_argv_last - os_argv[0]);
    p = c_copy_str_n(": "     , p         , os_argv_last - (char *) p);
    p = c_copy_str_n(title    , p         , os_argv_last - (char *) p);

    if(os_argv_last - (char *) p)
    {
        BSET(p, ' ', os_argv_last - (char *) p);
    }
    return;
}

void task_brd_restsore_setproctitle()
{
    TASK_BRD    *task_brd;
    char        *p;
    int          i;

    task_brd = task_brd_default_get();

    if(NULL_PTR != TASK_BRD_CACHE_ENVIRON(task_brd))
    {
        safe_free(TASK_BRD_CACHE_ENVIRON(task_brd), LOC_TASK_0132);
        TASK_BRD_CACHE_ENVIRON(task_brd) = NULL_PTR;
    }

    for(i = 0; environ[i]; i++)
    {
        environ[i] = TASK_BRD_OS_ENVIRON(task_brd)[i];
        dbg_log(SEC_0015_TASK, 9)(LOGCONSOLE, "[DEBUG] restore env[%d] %s\n", i, environ[i]);
    }

    p = TASK_BRD_OS_ARGV(task_brd)[ 0 ];
    for(i = 0; TASK_BRD_SAVED_ARGV(task_brd)[i]; i++)
    {
        size_t len;

        TASK_BRD_OS_ARGV(task_brd)[ i ] = p;

        len = strlen(TASK_BRD_SAVED_ARGV(task_brd)[i]) + 1;
        BCOPY(TASK_BRD_SAVED_ARGV(task_brd)[i], TASK_BRD_OS_ARGV(task_brd)[ i ], len);

        p += len;

        dbg_log(SEC_0015_TASK, 9)(LOGCONSOLE, "[DEBUG] restore argv[%d] %s\n", i, TASK_BRD_OS_ARGV(task_brd)[i]);
    }
    TASK_BRD_OS_ARGV(task_brd)[ i ] = NULL_PTR;

    return;
}

void task_brd_stop_child(UINT32 arg)
{
    pid_t child_pid;

    child_pid = (pid_t)arg;

    dbg_log(SEC_0015_TASK, 9)(LOGCONSOLE, "task_brd_stop_child: child pid = %ld\n", child_pid);

    kill(child_pid, SIGTERM);
    return;
}


EC_BOOL task_brd_wait_status(pid_t child_pid)
{
    for( ;; )
    {
        pid_t            pid;
        int              status;

        pid = waitpid(child_pid/*-1*/, &status, 0/*WNOHANG*/);

        if(0 == pid)
        {
            dbg_log(SEC_0015_TASK, 9)(LOGCONSOLE, "task_brd_wait_status: waitpid done, pid = 0\n");
            continue;
        }

        if(-1 == pid)
        {
            dbg_log(SEC_0015_TASK, 9)(LOGCONSOLE, "task_brd_wait_status: waitpid failed, errno = %d, errstr = %s => continue\n",
                                errno, strerror(errno));
            return (EC_TRUE);
        }

        if(WTERMSIG(status))
        {
            if(SIGKILL == WTERMSIG(status)
            || SIGTERM == WTERMSIG(status)
            || SIGINT  == WTERMSIG(status))
            {
                dbg_log(SEC_0015_TASK, 9)(LOGCONSOLE, "task_brd_wait_status: %ld exited on signal %d => stop\n",
                                   pid, WTERMSIG(status));
                return (EC_FALSE);
            }
            else
            {
                dbg_log(SEC_0015_TASK, 9)(LOGCONSOLE, "task_brd_wait_status: %ld exited on signal %d => restart\n",
                                   pid, WTERMSIG(status));
                return (EC_TRUE);
            }
        }
        else
        {
            dbg_log(SEC_0015_TASK, 9)(LOGCONSOLE, "task_brd_wait_status: %ld exited with code %d => restart\n",
                               pid, WEXITSTATUS(status));

            return (EC_TRUE);
        }
    }
    return (EC_FALSE);
}

void task_brd_launch_daemon(const CSTRING *pid_path_cstr)
{
    TASK_BRD *task_brd;

    task_brd = task_brd_default_get();

/***********************************************************************************************************************
NAME
       daemon - run in the background

SYNOPSIS
       #include <unistd.h>

       int daemon(int nochdir, int noclose);

   Feature Test Macro Requirements for glibc (see feature_test_macros(7)):

       daemon(): _BSD_SOURCE || (_XOPEN_SOURCE && _XOPEN_SOURCE < 500)

DESCRIPTION
       The daemon() function is for programs wishing to detach themselves from the controlling terminal and run in the background as system daemons.

       If  nochdir is zero, daemon() changes the calling process's current working directory to the root directory ("/"); otherwise, the current working directory
       is left unchanged.

       If noclose is zero, daemon() redirects standard input, standard output and standard error to /dev/null; otherwise,  no  changes  are  made  to  these  file
       descriptors.

RETURN VALUE
       (This  function  forks,  and  if  the fork(2) succeeds, the parent calls _exit(2), so that further errors are seen by the child only.)  On success daemon()
       returns zero.  If an error occurs, daemon() returns -1 and sets errno to any of the errors specified for the fork(2) and setsid(2).

***********************************************************************************************************************/

    while(0)
    {
        pid_t     pid;
        int      *sync_status;

        sync_status = mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        if(MAP_FAILED == sync_status)
        {
            exit(1);
        }

        /*else*/

        (*sync_status) = 0; /*child is not ready yet*/

        pid = fork();

        if(0 > pid)/*fatal error*/
        {
            /* there has been an error */
            fprintf(stderr, "error:task_brd_launch_daemon: fork failed\n");
            fflush(stderr);
            exit(1);
        }

        if(0 == pid) /*child*/
        {
            if(daemon(1, 0) < 0)
            {
                fprintf(stderr, "error:task_brd_launch_daemon: daemon failed\n");
                fflush(stderr);
                return;
            }

            (*sync_status) = 1;

            munmap(sync_status, sizeof(int));
            sync_status = NULL_PTR;
            /* child continues running */
            return;
        }

        /*parent*/

        /*wait for child ready. do not use wait()*/
        while(sync_status && 0 == (*sync_status))
        {
            c_usleep(1, LOC_TASK_0133);
        }

        if(sync_status)
        {
            munmap(sync_status, sizeof(int));
            sync_status = NULL_PTR;
        }

        /*master can modify title only after child is ready*/
        if(EC_TRUE == task_brd_init_setproctitle())
        {
            task_brd_setproctitle("master");
        }

        /*we can write pid to file here. */
        /*if option '-pidfile' is set, child process will also write it*/
        if(NULL_PTR != pid_path_cstr)
        {
            task_brd_write_pidfile((char *)cstring_get_str(pid_path_cstr), pid);
        }
        else
        {
            //task_brd_write_pidfile((const char *)"/var/run/bgn.pid", pid);
        }

        if(1) /*1: master, 0: master supervisor*/
        {
            exit(0);/* parent must leave */
        }

        csig_register(SIGTERM, csig_terminate , CSIG_HANDLE_NOW);/*update flag*/

        csig_atexit_register((CSIG_ATEXIT_HANDLER)task_brd_exit, (UINT32)task_brd);
        csig_atexit_register((CSIG_ATEXIT_HANDLER)task_brd_stop_child, (UINT32)pid);

        if(EC_FALSE == task_brd_wait_status(pid))
        {
            /*if child stop and not need to launch it, exit*/
            exit(0);/* parent must leave */
        }

        /*restore*/
        task_brd_restsore_setproctitle();

        /*pop old atexit callback*/
        csig_atexit_unregister((CSIG_ATEXIT_HANDLER)task_brd_exit, (UINT32)task_brd);
        csig_atexit_unregister((CSIG_ATEXIT_HANDLER)task_brd_stop_child, (UINT32)pid);

        /*next loop, try to launch the corrupted daemon*/
    }

    return;
}

EC_BOOL task_brd_exit(TASK_BRD *task_brd)
{
#if (SWITCH_OFF == NGX_BGN_SWITCH)
    sys_log(LOGSTDOUT, "[DEBUG] task_brd_exit: exit now\n");
#endif/*(SWITCH_OFF == NGX_BGN_SWITCH)*/

#if (SWITCH_ON == NGX_BGN_SWITCH)
    sys_log(LOGSTDOUT, "[DEBUG] task_brd_exit: raise SIGHUP\n");
    raise(SIGHUP);
#endif/*(SWITCH_ON == NGX_BGN_SWITCH)*/
    return (EC_TRUE);
}

/**
*
* task brd init procedure
*
**/
LOG * task_brd_default_init(int argc, char **argv)
{
    TASK_BRD  *task_brd;
    CPROC     *cproc;

    UINT32 this_tcid;
    UINT32 this_comm;
    UINT32 this_rank;
    UINT32 this_size;
    UINT32 this_ipaddr;
    UINT32 this_port;
    UINT32 reg_type;

#if (SWITCH_OFF == NGX_BGN_SWITCH)
    UINT32 core_max_num;
#endif/*(SWITCH_OFF == NGX_BGN_SWITCH)*/

    LOG     *log;
    CSTRING *log_file_name;

    UINT32   network_level;

    CSTRING *sys_cfg_xml_fname_cstr;
    CSTRING *basic_cfg_xml_fname_cstr;
    CSTRING *script_fname_cstr;
    CSTRING *bcast_dhcp_netcard_cstr;
    CSTRING *log_path_cstr;
    CSTRING *pid_path_cstr;
    CSTRING *console_path_cstr;
    CSTRING *ssl_path_cstr;
    EC_BOOL  daemon_flag;

    const char *loglevel;

    init_host_endian();
    cmisc_init(LOC_TASK_0134);

    init_static_mem();

    /*prepare stdout,stderr, stdin devices*/
    log_start();

    loglevel = task_brd_parse_arg(argc, (const char **)argv, (const char *)"-loglevel");
    if(NULL_PTR != loglevel)
    {
        log_set_level(loglevel);
    }

    this_comm   = CMPI_COMM_WORLD;
    this_size   = CMPI_MIN_SIZE;      /*default*/
    this_tcid   = CMPI_ERROR_TCID;
    this_ipaddr = CMPI_ERROR_IPADDR;
    this_port   = CMPI_ERROR_CLNTPORT;
    reg_type    = TASK_REGISTER_ALL_SERVER;/*default*/

    network_level            = CMPI_TOP_NETWORK;
    sys_cfg_xml_fname_cstr   = NULL_PTR;
    basic_cfg_xml_fname_cstr = NULL_PTR;
    script_fname_cstr        = NULL_PTR;
    bcast_dhcp_netcard_cstr  = NULL_PTR;
    log_path_cstr            = NULL_PTR;
    pid_path_cstr            = NULL_PTR;
    console_path_cstr        = NULL_PTR;
    ssl_path_cstr            = NULL_PTR;
    daemon_flag              = EC_FALSE;

    if(EC_FALSE == task_brd_parse_args(argc, argv, &this_size, &this_tcid, &reg_type,
                                        &network_level,
                                        &sys_cfg_xml_fname_cstr,
                                        &basic_cfg_xml_fname_cstr,
                                        &script_fname_cstr,
                                        &bcast_dhcp_netcard_cstr,
                                        &log_path_cstr,
                                        &pid_path_cstr,
                                        &console_path_cstr,
                                        &ssl_path_cstr,
                                        &daemon_flag))
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_default_init: parse args failed\n");
        task_brd_default_abort();
    }

    if(NULL_PTR != pid_path_cstr)
    {
        task_brd_write_pidfile((char *)cstring_get_str(pid_path_cstr), getpid());/*ignore failure*/
        cstring_free(pid_path_cstr);
    }

    task_brd = task_brd_default_new();
    task_brd_init(task_brd,
                  argc,
                  argv,
                  network_level,
                  sys_cfg_xml_fname_cstr,
                  basic_cfg_xml_fname_cstr,
                  script_fname_cstr,
                  log_path_cstr,
                  ssl_path_cstr);

    if(EC_TRUE == daemon_flag)
    {
        task_brd_launch_daemon(NULL_PTR);
    }

    csig_atexit_register((CSIG_ATEXIT_HANDLER)task_brd_exit, (UINT32)task_brd);

    /*if sysconfig xml file not exist, then try to get it from multicast network*/
    if(NULL_PTR == TASK_BRD_SYS_CFG_FNAME(task_brd )
    || EC_FALSE == c_file_access((char *)TASK_BRD_SYS_CFG_FNAME_STR(task_brd), F_OK | R_OK))
    {
        dbg_log(SEC_0015_TASK, 5)(LOGSTDOUT, "task_brd_default_init: %s not accessible\n",
                                             (char *)TASK_BRD_SYS_CFG_FNAME_STR(task_brd));

        if(CMPI_ERROR_TCID != this_tcid)
        {
            if(EC_FALSE == task_brd_make_config(task_brd, this_tcid))
            {
                dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_default_init: make config failed\n");
                task_brd_default_abort();
            }
        }
        else if(SWITCH_ON == TDNS_RESOLVE_SWITCH)
        {
            if(EC_FALSE == task_brd_pull_config(task_brd, &this_tcid, &this_ipaddr, &this_port))
            {
                dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_default_init: pull config failed\n");
                task_brd_default_abort();
            }

            if(EC_FALSE == task_brd_reset_tcid_args(argc, argv, this_tcid))
            {
                dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_default_init: reset tcid args failed\n");
                task_brd_default_abort();
            }
        }
        else
        {
            if(EC_FALSE == task_brd_wait_config(task_brd, bcast_dhcp_netcard_cstr, &this_tcid))
            {
                dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_default_init: wait config failed\n");
                task_brd_default_abort();
            }
        }
    }
    else
    {
        if(EC_FALSE == task_brd_load(task_brd))
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_default_init: task_brd load failed\n");
            task_brd_default_abort();
        }
#if 0/*warning: not adaptive to virutal ip scenario*/
        if(EC_FALSE == task_brd_collect_netcards(task_brd))
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_default_init: task_brd collect netcards failed\n");
            task_brd_default_abort();
        }

        /*determine tcid by ipaddr if necessary*/
        if(CMPI_ERROR_TCID == this_tcid
        && EC_FALSE == task_brd_parse_tcid_from_netcards(task_brd, TASK_BRD_NETCARDS(task_brd), &this_tcid))
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_default_init: parse tcid from sysconfig and netcards failed\n");
            task_brd_default_abort();
        }
#endif
        /*if tcid not appear in cmd line ...*/
        if(CMPI_ERROR_TCID == this_tcid)
        {
            SYS_CFG    *sys_cfg;
            TASK_CFG   *task_cfg;
            TASKS_CFG  *tasks_cfg;

            sys_cfg  = TASK_BRD_SYS_CFG(task_brd);
            task_cfg = SYS_CFG_TASK_CFG(sys_cfg);

            if(1 != cvector_size(TASK_CFG_TASKS_CFG_VEC(task_cfg)))
            {
                dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_default_init: obscure tcid\n");
                task_brd_default_abort();
            }

            tasks_cfg = cvector_get(TASK_CFG_TASKS_CFG_VEC(task_cfg), 0);
            this_tcid = TASKS_CFG_TCID(tasks_cfg);
        }
    }

    /*adjust reg type if necessary*/
    task_brd_adjust_reg_type(task_brd, this_tcid, &reg_type);/*note: when reach here, task_brd has not set tcid*/

    cproc = cproc_new(this_comm, this_size, this_tcid, &this_rank);
    if(NULL_PTR == cproc)
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_default_init: new cproc failed\n");
        task_brd_default_abort();
    }

    /**
     *before open log file, initialized tcid,comm,rank info of task brd
     *due to log file will record pid and tcid info at the first line
     **/

    /*open log and redirect LOGSTDOUT & LOGSTDERR log to it*/
    log_file_name = cstring_new(NULL_PTR, LOC_TASK_0135);
    cstring_format(log_file_name, "%s/rank_%s_%ld", (char *)TASK_BRD_LOG_PATH_STR(task_brd), c_word_to_ipv4(this_tcid), this_rank);
    log = log_file_open((char *)cstring_get_str(log_file_name), /*"a+"*/"w+",
                        this_tcid, this_rank,
                        LOGD_FILE_RECORD_LIMIT_ENABLED, (UINT32)FILE_LOG_NAME_WITH_DATE_SWITCH,
                        LOGD_SWITCH_OFF_ENABLE, LOGD_PID_INFO_ENABLE);
    if(NULL_PTR == log)
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_default_init: open log file %s failed\n", (char *)cstring_get_str(log_file_name));
        task_brd_default_abort();
    }
    sys_log_redirect_setup(LOGSTDOUT, log);
    sys_log_redirect_setup(LOGSTDERR, log);
    cstring_free(log_file_name);

#if (SWITCH_ON == NGX_BGN_SWITCH)
    /*open log and redirect LOGUSER07 log to it*/
    log_file_name = cstring_new(NULL_PTR, LOC_TASK_0136);
    cstring_format(log_file_name, "%s/orig_%s_%ld", (char *)TASK_BRD_LOG_PATH_STR(task_brd), c_word_to_ipv4(this_tcid), this_rank);
    log = log_file_open((char *)cstring_get_str(log_file_name), "a+",
                        this_tcid, this_rank,
                        LOGD_FILE_RECORD_LIMIT_ENABLED, (UINT32)FILE_LOG_NAME_WITH_DATE_SWITCH,
                        LOGD_SWITCH_OFF_DISABLE, LOGD_PID_INFO_DISABLE);
    if(NULL_PTR == log)
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_default_init: open log file %s failed\n", (char *)cstring_get_str(log_file_name));
        task_brd_default_abort();
    }
    sys_log_redirect_setup(LOGUSER07, log);
    cstring_free(log_file_name);
#endif/*(SWITCH_ON == NGX_BGN_SWITCH)*/

    /*print os setting*/
    task_brd_os_setting_print(LOGSTDOUT);

    csig_atexit_register((CSIG_ATEXIT_HANDLER)sys_log_rotate_by_index, (UINT32)DEFAULT_STDOUT_LOG_INDEX);

    /*console log to file if need*/
    if(NULL_PTR != console_path_cstr)
    {
        if(EC_FALSE == user_log_open(LOGUSER06, (char *)cstring_get_str(console_path_cstr), "w+"))
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_default_init: user_log_open '%s' -> LOGUSER06 failed\n",
                               (char *)cstring_get_str(console_path_cstr));
            cstring_free(console_path_cstr);
            task_brd_default_abort();
        }

        cstring_free(console_path_cstr);
        sys_log_redirect_setup(LOGCONSOLE, LOGUSER06);
    }

    /*register module type and module number per block*/
    cbc_new(MD_END); /*set the max number of supported modules*/
    cbc_md_reg(MD_SUPER   ,  1);

#if 0
    if(CMPI_FWD_RANK == this_rank)
    {
        int idx;
        dbg_log(SEC_0015_TASK, 9)(LOGCONSOLE, "rank %d: pid = %d, path_name = %s\n", this_rank, getpid(), (const char *)argv[0]);
        for(idx = 0; NULL_PTR != argv[ idx ]; idx ++)
        {
            dbg_log(SEC_0015_TASK, 9)(LOGCONSOLE, "rank %d: pid = %d, para %ld = %s\n", this_rank, getpid(), idx, (const char *)argv[ idx ]);
        }
    }
#endif

    TASK_BRD_REG_TYPE(task_brd) = reg_type;
    TASK_BRD_CPROC(task_brd)    = cproc;
    TASK_BRD_COMM(task_brd)     = this_comm;
    TASK_BRD_SIZE(task_brd)     = this_size;
    TASK_BRD_TCID(task_brd)     = this_tcid;
    TASK_BRD_RANK(task_brd)     = this_rank;

    if(EC_FALSE == task_brd_shortcut_config(task_brd))
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_default_init: shortcut config failed\n");
        task_brd_default_abort();
    }

    log_level_import(CPARACFG_LOG_LEVEL_TAB(TASK_BRD_CPARACFG(task_brd)), SEC_NONE_END);

    TASK_BRD_SUPER_MD_ID(task_brd)  = super_start();/*each rank own one super module*/
    TASK_BRD_RANK_TBL(task_brd)     = task_rank_tbl_new(TASK_BRD_SIZE(task_brd));

#if (SWITCH_ON == CROUTINE_SUPPORT_CTHREAD_SWITCH)
    TASK_REQ_CTHREAD_POOL(task_brd) = cthreadp_new(TASK_REQ_THREAD_MAX_NUM, CTHREAD_DETACHABLE | CTHREAD_SYSTEM_LEVEL);
    TASK_RSP_CTHREAD_POOL(task_brd) = cthreadp_new(TASK_RSP_THREAD_MAX_NUM, CTHREAD_DETACHABLE | CTHREAD_SYSTEM_LEVEL);
#endif/*(SWITCH_ON == CROUTINE_SUPPORT_CTHREAD_SWITCH)*/

#if (SWITCH_ON == CROUTINE_SUPPORT_COROUTINE_SWITCH)
    TASK_BRD_CROUTINE_POOL(task_brd) = croutine_pool_new(TASK_REQ_THREAD_MAX_NUM, CTHREAD_DETACHABLE | CTHREAD_SYSTEM_LEVEL);
#endif/*(SWITCH_ON == CROUTINE_SUPPORT_COROUTINE_SWITCH)*/
    /*-------------------------------------------------------------------------------------------------------------------------*/

    //sys_log(LOGSTDOUT, "loaded sysconfig:\n");
    //sys_cfg_print_xml(LOGSTDOUT, TASK_BRD_SYS_CFG(task_brd), 0);

    //sys_log(LOGSTDOUT, "current paraconfig:\n");
    //cparacfg_print_xml(log, TASK_BRD_CPARACFG(task_brd), 0);

    TASK_BRD_FWD_CCOND_RESERVE(task_brd, 1, LOC_TASK_0137);

    /*set shortcut of task_brd ip and port*/
    if(CMPI_FWD_RANK == TASK_BRD_RANK(task_brd))
    {
        TASKS_CFG *tasks_cfg;

        TASK_BRD_CEPOLL(task_brd) = cepoll_new(TASK_BRD_CEPOLL_MAX_EVENT_NUM);
        if(NULL_PTR == TASK_BRD_CEPOLL(task_brd))
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_default_init: abort due to cepoll new failed\n");
            task_brd_free(task_brd);

            task_brd_default_abort();/*abort !*/
        }

        tasks_cfg = TASK_BRD_LOCAL_TASKS_CFG(task_brd);
#if 1
        if(CMPI_ERROR_IPADDR != this_ipaddr && TASKS_CFG_SRVIPADDR(tasks_cfg) != this_ipaddr)
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "[DEBUG] task_brd_default_init: reset srvipaddr %s => %s\n",
                            c_word_to_ipv4(TASKS_CFG_SRVIPADDR(tasks_cfg)),
                            c_word_to_ipv4(this_ipaddr));

            TASKS_CFG_SRVIPADDR(tasks_cfg) = this_ipaddr;
        }
#endif
        if(CMPI_ERROR_CLNTPORT != this_port && TASKS_CFG_SRVPORT(tasks_cfg) != this_port)
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "[DEBUG] task_brd_default_init: reset srvport %ld => %ld\n",
                            TASKS_CFG_SRVPORT(tasks_cfg),
                            this_port);

            TASKS_CFG_SRVPORT(tasks_cfg) = this_port;
        }

        TASK_BRD_IPADDR(task_brd) = TASKS_CFG_SRVIPADDR(tasks_cfg);
        TASK_BRD_PORT(task_brd)   = TASKS_CFG_SRVPORT(tasks_cfg);
    }

    /*create http cconnp mgr before http server starting*/
    if(CMPI_FWD_RANK == TASK_BRD_RANK(task_brd))
    {
        CCONNP_MGR *cconnp_mgr;

        cconnp_mgr = cconnp_mgr_new();
        if(NULL_PTR == cconnp_mgr)
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_default_init: abort due to new cconnp_mgr failed\n");
            task_brd_free(task_brd);

            task_brd_default_abort();/*abort !*/
        }
        TASK_BRD_HTTP_CCONNP_MGR(task_brd) = cconnp_mgr;

        task_brd_http_connp_cluster(task_brd);

        if(do_log(SEC_0015_TASK, 9))
        {
            sys_log(LOGSTDOUT, "[DEBUG] task_brd_default_init: cconnp_mgr is\n");
            cconnp_mgr_print(log, cconnp_mgr);
        }
    }

    /*start task communicator server*/
    if(CMPI_FWD_RANK == TASK_BRD_RANK(task_brd))
    {
        TASKS_CFG *tasks_cfg;

        tasks_cfg = TASK_BRD_LOCAL_TASKS_CFG(task_brd);

        /**
        note:
            when port = 0 and start server, the server will occupy random port, and you should never
            finger out the port info from TASKS_CFG_SRVPORT but from TASKS_CFG_SRVSOCKFD
        **/

        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "[DEBUG] task_brd_default_init: srv %s:%ld\n",
                                             c_word_to_ipv4(TASKS_CFG_SRVIPADDR(tasks_cfg)),
                                             TASKS_CFG_SRVPORT(tasks_cfg));
#if (SWITCH_OFF == NGX_BGN_SWITCH)
        if(CMPI_ERROR_IPADDR != TASKS_CFG_SRVIPADDR(tasks_cfg)
        && CMPI_ERROR_SRVPORT != TASKS_CFG_SRVPORT(tasks_cfg)
        && EC_FALSE == tasks_srv_start(tasks_cfg))
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_default_init: abort due to start server failed\n");
            task_brd_free(task_brd);

            task_brd_default_abort();/*abort !*/
        }
        TASK_BRD_TASKS_IS_RUNNING(task_brd) = BIT_TRUE;
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "[DEBUG] task_brd_default_init: start server done\n");
#endif/*(SWITCH_OFF == NGX_BGN_SWITCH)*/

#if (SWITCH_ON == NGX_BGN_SWITCH)
        if(CMPI_ERROR_IPADDR != TASKS_CFG_SRVIPADDR(tasks_cfg)
        && CMPI_ERROR_SRVPORT != TASKS_CFG_SRVPORT(tasks_cfg))
        {
            CTIMET      prev_time;

            prev_time = task_brd_default_get_time();
            while(EC_FALSE == tasks_srv_start(tasks_cfg))
            {
                CTIMET      cur_time;

                cur_time = task_brd_default_get_time();
                if(cur_time >= prev_time + 1) /*1s*/
                {
                    prev_time = cur_time;
                    dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_default_init: start server failed, retry again\n");
                }
                c_usleep(1000, LOC_TASK_0138);

                /*update task_brd time*/
                task_brd_update_time_default();
            }
        }

        TASK_BRD_TASKS_IS_RUNNING(task_brd) = BIT_TRUE;
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "[DEBUG] task_brd_default_init: start server done\n");
#endif/*(SWITCH_ON == NGX_BGN_SWITCH)*/
    }

#if (SWITCH_ON == NGX_BGN_SWITCH)
    /*start crfs monintor*/
    if(SWITCH_ON == NGX_BGN_OVER_RFS_SWITCH
    && CMPI_FWD_RANK == TASK_BRD_RANK(task_brd))
    {
        TASK_BRD_CRFSMON_ID(task_brd) = crfsmon_start();
        if(CMPI_ERROR_MODI == TASK_BRD_CRFSMON_ID(task_brd))
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_default_init: abort due to start crfsmon failed\n");
            task_brd_free(task_brd);

            task_brd_default_abort();/*abort !*/
        }
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "[DEBUG] task_brd_default_init: start crfsmon done\n");
    }

    /*start cxfs monintor*/
    if(SWITCH_ON == NGX_BGN_OVER_XFS_SWITCH
    && CMPI_FWD_RANK == TASK_BRD_RANK(task_brd))
    {
        TASK_BRD_CXFSMON_ID(task_brd) = cxfsmon_start();
        if(CMPI_ERROR_MODI == TASK_BRD_CXFSMON_ID(task_brd))
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_default_init: abort due to start cxfsmon failed\n");
            task_brd_free(task_brd);

            task_brd_default_abort();/*abort !*/
        }
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "[DEBUG] task_brd_default_init: start cxfsmon done\n");
    }
#endif/*(SWITCH_ON == NGX_BGN_SWITCH)*/

#if (SWITCH_OFF == NGX_BGN_SWITCH)
    core_max_num = sysconf(_SC_NPROCESSORS_ONLN);
#endif/*(SWITCH_OFF == NGX_BGN_SWITCH)*/

#if (SWITCH_OFF == NGX_BGN_SWITCH)
#if 0
#if (SWITCH_ON == CROUTINE_SUPPORT_COROUTINE_SWITCH && SWITCH_OFF == CROUTINE_SUPPORT_SINGLE_CTHREAD_SWITCH)
    TASK_BRD_DO_ROUTINE_CTHREAD_ID(task_brd) = cthread_new(CTHREAD_JOINABLE | CTHREAD_SYSTEM_LEVEL,
                                                        (const char *)"do_slave_enhanced",
                                                        (UINT32)do_slave_enhanced,
                                                        (UINT32)(TASK_BRD_RANK(task_brd) % core_max_num), /*core #*/
                                                        (UINT32)1,/*para num*/
                                                        (UINT32)task_brd
                                                        );

    dbg_log(SEC_0015_TASK, 9)(LOGSTDOUT, "[DEBUG] task_brd_default_int: do_slave_enhanced thread %u\n", TASK_BRD_DO_ROUTINE_CTHREAD_ID(task_brd));
#endif/*(SWITCH_ON == CROUTINE_SUPPORT_COROUTINE_SWITCH && SWITCH_OFF == CROUTINE_SUPPORT_SINGLE_CTHREAD_SWITCH)*/
#endif
#if (SWITCH_ON == CROUTINE_SUPPORT_CTHREAD_SWITCH && SWITCH_OFF == CROUTINE_SUPPORT_SINGLE_CTHREAD_SWITCH)
    TASK_BRD_DO_SLAVE_CTHREAD_ID(task_brd) = cthread_new(CTHREAD_JOINABLE | CTHREAD_SYSTEM_LEVEL,
                                                        (const char *)"do_slave",
                                                        (UINT32)do_slave,
                                                        (UINT32)(TASK_BRD_RANK(task_brd) % core_max_num), /*core #*/
                                                        (UINT32)1,/*para num*/
                                                        (UINT32)task_brd
                                                        );
    dbg_log(SEC_0015_TASK, 9)(LOGSTDOUT, "[DEBUG] task_brd_default_int: do_slave thread %u\n", TASK_BRD_DO_SLAVE_CTHREAD_ID(task_brd));
#endif/*(SWITCH_ON == CROUTINE_SUPPORT_CTHREAD_SWITCH) && SWITCH_OFF == CROUTINE_SUPPORT_SINGLE_CTHREAD_SWITCH*/
#endif/* (SWITCH_OFF == NGX_BGN_SWITCH)*/

    /*register to remote servers before current taskcomm is ready*/
    /*note: here is dangerous: dead lock of TASKS_CFG_WORKER(TASK_BRD_LOCAL_TASKS_CFG(task_brd)) and TASKS_CFG_MONITOR(TASK_BRD_LOCAL_TASKS_CFG(task_brd))*/
    if (CMPI_FWD_RANK == TASK_BRD_RANK(task_brd))
    {
        task_brd_register_cluster(task_brd);
    }

    /*[optional] share TASKC_NODE info to forwarding process of taskComm*/
    if (CMPI_FWD_RANK == TASK_BRD_RANK(task_brd))
    {
        super_incl_taskc_node(TASK_BRD_SUPER_MD_ID(task_brd), TASK_BRD_IPADDR(task_brd), TASK_BRD_PORT(task_brd), CMPI_ANY_SOCKFD, TASK_BRD_TCID(task_brd), TASK_BRD_COMM(task_brd), TASK_BRD_SIZE(task_brd));

        dbg_log(SEC_0015_TASK, 5)(LOGSTDOUT, "======================================================================\n");
        dbg_log(SEC_0015_TASK, 5)(LOGSTDOUT, "              super_incl_taskc_node finished                      \n");
        dbg_log(SEC_0015_TASK, 5)(LOGSTDOUT, "======================================================================\n");

        TASK_BRD_FWD_CCOND_RELEASE_ALL(task_brd, LOC_TASK_0139);
    }

    if(CMPI_FWD_RANK != TASK_BRD_RANK(task_brd))
    {
        /*non fwd rank waiting until fwd rank ready*/
        /*sending task to fwd rank, when response come back, fwd rank must be ready*/
        task_brd_wait_proc_ready(task_brd, TASK_BRD_TCID(task_brd), TASK_BRD_COMM(task_brd), CMPI_FWD_RANK);
        TASK_BRD_FWD_CCOND_RELEASE_ALL(task_brd, LOC_TASK_0140);
    }

#if (SWITCH_OFF == NGX_BGN_SWITCH)
#if (SWITCH_OFF == CROUTINE_SUPPORT_SINGLE_CTHREAD_SWITCH)
    TASK_BRD_DO_CBTIMER_CTHREAD_ID(task_brd) = cthread_new(CTHREAD_DETACHABLE | CTHREAD_SYSTEM_LEVEL,
                                                    (const char *)"task_brd_cbtimer_do",
                                                    (UINT32)task_brd_cbtimer_do,
                                                    (UINT32)(TASK_BRD_RANK(task_brd) % core_max_num),/*core #*/
                                                    (UINT32)1,/*para num*/
                                                    (UINT32)task_brd
                                                    );
#endif/*(SWITCH_OFF == CROUTINE_SUPPORT_SINGLE_CTHREAD_SWITCH)*/
    if(SWITCH_ON == RANK_HEARTBEAT_FWD_SWITCH)
    {
        task_brd_cbtimer_add(task_brd,
                             (UINT8 *)"heartbeat",
                             (UINT32)CBTIMER_NEVER_EXPIRE      , NULL_PTR,
                             (UINT32)CLOAD_HEARTBEAT_INTVL_NSEC, (FUNC_ADDR_NODE *)&g_task_brd_heartbeat_once_func_addr_node);
    }
#if (SWITCH_ON == LOAD_UPDATE_SWITCH)
    task_brd_cbtimer_add(task_brd,
                         (UINT8 *)"load update",
                         (UINT32)CBTIMER_NEVER_EXPIRE        , NULL_PTR,
                         (UINT32)CLOAD_STAT_UPDATE_INTVL_NSEC, (FUNC_ADDR_NODE *)&g_task_brd_cload_stat_update_once_func_addr_node);

    task_brd_cbtimer_add(task_brd,
                         (UINT8 *)"cpu avg update",
                         (UINT32)CBTIMER_NEVER_EXPIRE           , NULL_PTR,
                         (UINT32)TASK_BRD_CPU_UPDATE_INTVAL_NSEC, (FUNC_ADDR_NODE *)&g_task_brd_cpu_avg_stat_update_once_func_addr_node);
#endif/*(SWITCH_ON == LOAD_UPDATE_SWITCH)*/
#endif/*(SWITCH_OFF == NGX_BGN_SWITCH)*/

#if (SWITCH_OFF == NGX_BGN_SWITCH)
    /*set cmd runner*/
    if (EC_TRUE == task_brd_check_is_dbg_tcid(this_tcid) && CMPI_DBG_RANK == this_rank)
    {
        CROUTINE_NODE  *croutine_node;

        /*init ccond before thread and coroutine*/
        api_cmd_ui_init_ccond();

        /*[coroutine] command handler*/
        croutine_node = croutine_pool_load(TASK_REQ_CTHREAD_POOL(task_brd),
                                           (UINT32)do_cmd_default, 0);
        if(NULL_PTR == croutine_node)
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_default_int: croutine load for 'do_cmd_default' failed\n");
            task_brd_default_abort();/*abort !*/
        }
        CROUTINE_NODE_COND_RELEASE(croutine_node, LOC_TASK_0141);

        /*[thread] readline thread to get command from console*/
        cthread_new(CTHREAD_DETACHABLE | CTHREAD_SYSTEM_LEVEL,
                    (const char *)"api_cmd_ui_task",
                    (UINT32)api_cmd_ui_task,
                    (UINT32)(TASK_BRD_RANK(task_brd) % core_max_num),/*core #*/
                    (UINT32)0/*para num*/
                    );

        //task_brd_default_add_runner(this_tcid, this_rank, (const char *)"do_cmd_default", (TASK_RUNNER_FUNC)do_cmd_default, NULL_PTR);
        task_brd_default_add_runner(this_tcid, this_rank, (const char *)"do_slave_enhanced", (TASK_RUNNER_FUNC)do_slave_enhanced, task_brd);
    }
    /*set monitor runner*/
    else if (EC_TRUE == task_brd_check_is_monitor_tcid(this_tcid) && CMPI_MON_RANK == this_rank)
    {
        task_brd_default_add_runner(this_tcid, this_rank, (const char *)"do_slave_wait_default", (TASK_RUNNER_FUNC)do_slave_wait_default, task_brd);
    }

    /*set other runner to default*/
    else
    {
#if (SWITCH_ON == CROUTINE_SUPPORT_COROUTINE_SWITCH && SWITCH_ON == CROUTINE_SUPPORT_SINGLE_CTHREAD_SWITCH)
        task_brd_default_add_runner(this_tcid, this_rank, (const char *)"do_slave_enhanced", (TASK_RUNNER_FUNC)do_slave_enhanced, task_brd);
#else/*(SWITCH_ON == CROUTINE_SUPPORT_COROUTINE_SWITCH && SWITCH_ON == CROUTINE_SUPPORT_SINGLE_CTHREAD_SWITCH)*/
        task_brd_default_add_runner(this_tcid, this_rank, (const char *)"do_slave_wait_default", (TASK_RUNNER_FUNC)do_slave_wait_default, task_brd);
#endif/*!(SWITCH_ON == CROUTINE_SUPPORT_COROUTINE_SWITCH && SWITCH_ON == CROUTINE_SUPPORT_SINGLE_CTHREAD_SWITCH)*/
    }
#endif/*(SWITCH_OFF == NGX_BGN_SWITCH)*/

    if(EC_TRUE == task_brd_default_check_csrv_enabled())
    {
        if(EC_TRUE == chttp_defer_request_queue_init())
        {
            task_brd_start_http_srv(task_brd, task_brd_default_get_srv_ipaddr(), task_brd_default_get_csrv_port());
        }
   }

    return (log);
}

UINT32 task_brd_default_get_ipaddr()
{
    TASK_BRD *task_brd;

    task_brd = task_brd_default_get();
    return TASK_BRD_IPADDR(task_brd);
}

UINT32 task_brd_default_get_port()
{
    TASK_BRD *task_brd;

    task_brd = task_brd_default_get();
    return TASK_BRD_PORT(task_brd);
}

UINT32 task_brd_default_get_tcid()
{
    TASK_BRD *task_brd;

    task_brd = task_brd_default_get();
    return TASK_BRD_TCID(task_brd);
}

UINT32 task_brd_default_get_comm()
{
    TASK_BRD *task_brd;

    task_brd = task_brd_default_get();
    return TASK_BRD_COMM(task_brd);
}

UINT32 task_brd_default_get_rank()
{
    TASK_BRD *task_brd;

    task_brd = task_brd_default_get();
    return TASK_BRD_RANK(task_brd);
}

UINT32 task_brd_default_get_size()
{
    TASK_BRD *task_brd;

    task_brd = task_brd_default_get();
    return TASK_BRD_SIZE(task_brd);
}

UINT32 task_brd_default_get_super()
{
    TASK_BRD *task_brd;

    task_brd = task_brd_default_get();
    return TASK_BRD_SUPER_MD_ID(task_brd);
}

CRFSMC  *task_brd_default_get_crfsmc()
{
    TASK_BRD *task_brd;

    task_brd = task_brd_default_get();
    return TASK_BRD_EXTRA(task_brd);
}

EC_BOOL task_brd_default_set_crfsmc(void *data, TASK_BRD_EXTRA_CLEANER cleanup)
{
    return task_brd_set_crfsmc(task_brd_default_get(), data, cleanup);
}

EC_BOOL task_brd_set_crfsmc(TASK_BRD *task_brd, void *data, TASK_BRD_EXTRA_CLEANER cleanup)
{
    /*warning: here will override TASK_BRD_EXTRA*/
    TASK_BRD_EXTRA(task_brd)         = data;
    TASK_BRD_EXTRA_CLEANUP(task_brd) = cleanup;

    return (EC_TRUE);
}

UINT32 task_brd_local_taskc(const TASK_BRD *task_brd)
{
    return TASK_BRD_TCID(task_brd);
}

EC_BOOL task_brd_is_local_taskc(const TASK_BRD *task_brd, const UINT32 this_taskc)
{
    if(this_taskc == TASK_BRD_TCID(task_brd))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL task_brd_wait_proc_ready(const TASK_BRD *task_brd, const UINT32 recv_tcid, const UINT32 recv_comm, const UINT32 recv_rank)
{
    MOD_NODE send_mod_node;
    MOD_NODE recv_mod_node;
    TASK_MGR *task_mgr;
    UINT32    ret;

    if(
        (CMPI_ANY_TCID  == recv_tcid || TASK_BRD_TCID(task_brd) == recv_tcid)
     && (CMPI_ANY_COMM == recv_comm  || TASK_BRD_COMM(task_brd) == recv_comm)
     && (CMPI_ANY_RANK == recv_rank  || TASK_BRD_RANK(task_brd) == recv_rank)
       )
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "fatal error:task_brd_wait_proc_ready: denied to wait for self ready\n");
        return (EC_FALSE);
    }


    MOD_NODE_TCID(&send_mod_node) = TASK_BRD_TCID(task_brd);
    MOD_NODE_COMM(&send_mod_node) = TASK_BRD_COMM(task_brd);
    MOD_NODE_RANK(&send_mod_node) = TASK_BRD_RANK(task_brd);
    MOD_NODE_MODI(&send_mod_node) = 0;
    MOD_NODE_HOPS(&send_mod_node) = 0;
    MOD_NODE_STAT(&send_mod_node) = 0;
    cload_stat_clone(TASK_BRD_CLOAD_STAT(task_brd), MOD_NODE_CLOAD_STAT(&send_mod_node));

    MOD_NODE_TCID(&recv_mod_node) = recv_tcid;
    MOD_NODE_COMM(&recv_mod_node) = recv_comm;
    MOD_NODE_RANK(&recv_mod_node) = recv_rank;
    MOD_NODE_MODI(&recv_mod_node) = 0;
    MOD_NODE_STAT(&recv_mod_node) = 0;
    cload_stat_init(MOD_NODE_CLOAD_STAT(&recv_mod_node));

    task_mgr = task_new(NULL_PTR, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    task_super_inc(task_mgr, &send_mod_node, &recv_mod_node, &ret, FI_super_wait_me_ready, 0);
    task_wait(task_mgr, TASK_ALWAYS_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    return (EC_TRUE);
}

UINT32 task_brd_default_local_taskc()
{
    TASK_BRD *task_brd;

    task_brd = task_brd_default_get();

    return TASK_BRD_TCID(task_brd);
}

EC_BOOL task_brd_default_is_local_taskc(const UINT32 this_taskc)
{
    if(this_taskc == CMPI_LOCAL_TCID)
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL task_brd_check_is_dbg_tcid(const UINT32 tcid)
{
    if((CMPI_ANY_DBG_TCID == tcid) || (CMPI_DBG_TCID_BEG <= tcid && tcid <= CMPI_DBG_TCID_END))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL task_brd_check_is_monitor_tcid(const UINT32 tcid)
{
    if((CMPI_ANY_MON_TCID == tcid) || (CMPI_MON_TCID_BEG <= tcid && tcid <= CMPI_MON_TCID_END))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL task_brd_check_is_work_tcid(const UINT32 tcid)
{
    if(EC_TRUE == task_brd_check_is_dbg_tcid(tcid))
    {

        return (EC_FALSE);
    }

    if(EC_TRUE == task_brd_check_is_monitor_tcid(tcid))
    {

        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL task_brd_default_check_csrv_enabled()
{
    TASKS_CFG *tasks_cfg;

    tasks_cfg = TASK_BRD_LOCAL_TASKS_CFG(task_brd_default_get());
    if(CMPI_ERROR_SRVPORT == TASKS_CFG_CSRVPORT(tasks_cfg))
    {
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL task_brd_default_check_ssrv_enabled()
{
    TASKS_CFG *tasks_cfg;

    tasks_cfg = TASK_BRD_LOCAL_TASKS_CFG(task_brd_default_get());
    if(CMPI_ERROR_SRVPORT == TASKS_CFG_SSRVPORT(tasks_cfg))
    {
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

UINT32 task_brd_default_get_srv_ipaddr()
{
    TASKS_CFG *tasks_cfg;

    tasks_cfg = TASK_BRD_LOCAL_TASKS_CFG(task_brd_default_get());
    return TASKS_CFG_SRVIPADDR(tasks_cfg);
}

UINT32 task_brd_default_get_csrv_port()
{
    TASKS_CFG *tasks_cfg;

    tasks_cfg = TASK_BRD_LOCAL_TASKS_CFG(task_brd_default_get());
    return TASKS_CFG_CSRVPORT(tasks_cfg);
}

UINT32 task_brd_default_get_ssrv_port()
{
    TASKS_CFG *tasks_cfg;

    tasks_cfg = TASK_BRD_LOCAL_TASKS_CFG(task_brd_default_get());
    return TASKS_CFG_SSRVPORT(tasks_cfg);
}

UINT32 task_brd_default_get_network_level()
{
    return TASK_BRD_NETWORK_LEVEL(task_brd_default_get());
}

UINT32 task_brd_default_get_crfsmon_id()
{
    return TASK_BRD_CRFSMON_ID(task_brd_default_get());
}

UINT32 task_brd_default_get_cxfsmon_id()
{
    return TASK_BRD_CXFSMON_ID(task_brd_default_get());
}

UINT32 task_brd_default_get_chfsmon_id()
{
    return TASK_BRD_CHFSMON_ID(task_brd_default_get());
}

EC_BOOL task_brd_default_get_store_http_srv(const CSTRING *path, UINT32 *tcid, UINT32 *srv_ipaddr, UINT32 *srv_port)
{
    if(SWITCH_ON == NGX_BGN_OVER_RFS_SWITCH)
    {
        if(EC_FALSE == crfsmon_crfs_store_http_srv_get(task_brd_default_get_crfsmon_id(),
                                                       path,tcid, srv_ipaddr, srv_port))
        {
            return (EC_FALSE);
        }
        return (EC_TRUE);
    }

    if(SWITCH_ON == NGX_BGN_OVER_XFS_SWITCH)
    {
        if(EC_FALSE == cxfsmon_cxfs_store_http_srv_get(task_brd_default_get_cxfsmon_id(),
                                                       path,tcid, srv_ipaddr, srv_port))
        {
            return (EC_FALSE);
        }
        return (EC_TRUE);
    }

    dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_default_get_store_http_srv: invalid switch\n");
    return (EC_FALSE);
}

EC_BOOL task_brd_default_check_validity()
{
    UINT32 this_tcid;
    UINT32 this_size;

    TASK_BRD *task_brd;

    task_brd = task_brd_default_get();

    this_tcid = TASK_BRD_TCID(task_brd);
    this_size = TASK_BRD_SIZE(task_brd);

    if(EC_TRUE == task_brd_check_is_dbg_tcid(this_tcid))
    {
        if(CMPI_DBG_MIN_RANK_SIZE > this_size)/*DBG taskcomm has only two processes: debug & fwd*/
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_default_check_validity: DBG taskcomm should have only 2 processes\n");
            return (EC_FALSE);
        }
        return (EC_TRUE);
    }

    if(EC_TRUE == task_brd_check_is_monitor_tcid(this_tcid))
    {
        if(CMPI_MON_MIN_RANK_SIZE > this_size)/*MONITOR taskcomm has only two processes: monitor & fwd*/
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_default_check_validity: MONITOR taskcomm should have only 2 processes\n");
            return (EC_FALSE);
        }
        return (EC_TRUE);
    }

    if(EC_TRUE == task_brd_check_is_work_tcid(this_tcid))
    {
        if(CMPI_WORK_MIN_RANK_SIZE > this_size)/*WORK taskcomm has at leas two processes: fwd & workers*/
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_default_check_validity: WORKING taskcomm should have at least 2 processes\n");
            return (EC_FALSE);
        }
        return (EC_TRUE);
    }
    dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_default_check_validity: must never reach here!(tcid = %s, size = %ld)\n", c_word_to_ipv4(this_tcid), this_size);
    return (EC_FALSE);
}

/**
*
* sync taskc_node(tcid, comm, size) info from (current taskcomm, forwarding rank)
*
**/
EC_BOOL task_brd_sync_taskc_mgr(const TASK_BRD *task_brd, TASKC_MGR *taskc_mgr)
{
    if(CMPI_FWD_RANK == TASK_BRD_RANK(task_brd))
    {
        super_sync_taskc_mgr(0, taskc_mgr);
    }
    else
    {
        MOD_NODE  send_mod_node;
        MOD_NODE  recv_mod_node;
        TASK_MGR *task_mgr;
        UINT32    ret;

        /*sync taskc_mgr from (master taskcomm, fwd rank)*/
        task_mgr = task_new(NULL_PTR, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);

        MOD_NODE_TCID(&send_mod_node) = TASK_BRD_TCID(task_brd);
        MOD_NODE_COMM(&send_mod_node) = TASK_BRD_COMM(task_brd);
        MOD_NODE_RANK(&send_mod_node) = TASK_BRD_RANK(task_brd);
        MOD_NODE_MODI(&send_mod_node) = 0;
        MOD_NODE_STAT(&send_mod_node) = 0;
        cload_stat_clone(TASK_BRD_CLOAD_STAT(task_brd), MOD_NODE_CLOAD_STAT(&send_mod_node));

        MOD_NODE_TCID(&recv_mod_node) = TASK_BRD_TCID(task_brd);
        MOD_NODE_COMM(&recv_mod_node) = TASK_BRD_COMM(task_brd);
        MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
        MOD_NODE_MODI(&recv_mod_node) = 0;
        MOD_NODE_STAT(&recv_mod_node) = 0;
        cload_stat_init(MOD_NODE_CLOAD_STAT(&recv_mod_node));

        task_super_inc(task_mgr, &send_mod_node, &recv_mod_node, &ret, FI_super_sync_taskc_mgr, 0, taskc_mgr);
        task_wait(task_mgr, TASK_ALWAYS_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);
    }

    return (EC_TRUE);
}

EC_BOOL task_brd_sync_mod_nodes(const TASK_BRD *task_brd, const UINT32 max_hops, const UINT32 max_remotes, const UINT32 time_to_live, CVECTOR *mod_node_vec)
{
    if(CMPI_FWD_RANK == TASK_BRD_RANK(task_brd))
    {
        TASKS_CFG *local_tasks_cfg;

        local_tasks_cfg = TASK_BRD_LOCAL_TASKS_CFG(task_brd);

        super_sync_taskcomm(TASK_BRD_SUPER_MD_ID(task_brd),
                            TASKS_CFG_TCID(local_tasks_cfg), TASKS_CFG_MASKI(local_tasks_cfg), TASKS_CFG_MASKE(local_tasks_cfg),
                            max_hops, max_remotes, time_to_live, mod_node_vec);
    }
    else
    {
        MOD_NODE send_mod_node;
        MOD_NODE recv_mod_node;
        TASK_MGR *task_mgr;
        /*sync taskc_mgr from (master taskcomm, fwd rank)*/
        task_mgr = task_new(NULL_PTR, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);

        MOD_NODE_TCID(&send_mod_node) = TASK_BRD_TCID(task_brd);
        MOD_NODE_COMM(&send_mod_node) = TASK_BRD_COMM(task_brd);
        MOD_NODE_RANK(&send_mod_node) = TASK_BRD_RANK(task_brd);
        MOD_NODE_MODI(&send_mod_node) = 0;
        MOD_NODE_LOAD(&send_mod_node) = 0;

        mod_node_update_local_stat(&send_mod_node);

        MOD_NODE_TCID(&recv_mod_node) = TASK_BRD_TCID(task_brd);
        MOD_NODE_COMM(&recv_mod_node) = TASK_BRD_COMM(task_brd);
        MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
        MOD_NODE_MODI(&recv_mod_node) = 0;
        MOD_NODE_LOAD(&recv_mod_node) = 0;

        task_super_inc(task_mgr, &send_mod_node, &recv_mod_node,
                        NULL_PTR, FI_super_sync_taskcomm, CMPI_ERROR_MODI,
                        TASK_BRD_TCID(task_brd), CMPI_ANY_MASK, CMPI_ANY_MASK,
                        max_hops, max_remotes, time_to_live, mod_node_vec);

        task_wait(task_mgr, time_to_live, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);
    }

    return (EC_TRUE);
}

EC_BOOL task_brd_sync_cload_node(TASK_BRD *task_brd, CLOAD_NODE *cload_node)
{
    UINT32 tcid;
    UINT32 rank;
    UINT32 size;

#if 0/*will impact on performance*/
    /*sync once at first :-)*/
    task_brd_cload_stat_collect(task_brd);
    cload_mgr_set(TASK_BRD_CLOAD_MGR(task_brd), TASK_BRD_TCID(task_brd), TASK_BRD_RANK(task_brd), TASK_BRD_CLOAD_STAT(task_brd));
#endif
    tcid = CLOAD_NODE_TCID(cload_node);
    size = cvector_size(CLOAD_NODE_RANK_LOAD_STAT_VEC(cload_node));
    for(rank = 0; rank < size; rank ++)
    {
        CLOAD_STAT *cload_stat_src;
        CLOAD_STAT *cload_stat_des;

        cload_stat_des = CLOAD_NODE_RANK_LOAD_STAT(cload_node, rank);
        cload_stat_src = cload_mgr_get(TASK_BRD_CLOAD_MGR(task_brd), tcid, rank);
        cload_stat_clone(cload_stat_src, cload_stat_des);
    }
    return (EC_TRUE);
}

EC_BOOL task_brd_sync_cload_mgr(const TASK_BRD *task_brd, const CVECTOR *tcid_vec, CLOAD_MGR *cload_mgr)
{
    if(CMPI_FWD_RANK == TASK_BRD_RANK(task_brd))
    {
        super_sync_cload_mgr(TASK_BRD_SUPER_MD_ID(task_brd), tcid_vec, cload_mgr);
    }
    else
    {
        MOD_NODE  send_mod_node;
        MOD_NODE  recv_mod_node;
        TASK_MGR *task_mgr;
        UINT32    ret;

        /*sync cload_mgr from (master taskcomm, fwd rank)*/
        task_mgr = task_new(NULL_PTR, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);

        MOD_NODE_TCID(&send_mod_node) = TASK_BRD_TCID(task_brd);
        MOD_NODE_COMM(&send_mod_node) = TASK_BRD_COMM(task_brd);
        MOD_NODE_RANK(&send_mod_node) = TASK_BRD_RANK(task_brd);
        MOD_NODE_MODI(&send_mod_node) = 0;
        MOD_NODE_STAT(&send_mod_node) = 0;
        cload_stat_clone(TASK_BRD_CLOAD_STAT(task_brd), MOD_NODE_CLOAD_STAT(&send_mod_node));

        MOD_NODE_TCID(&recv_mod_node) = TASK_BRD_TCID(task_brd);
        MOD_NODE_COMM(&recv_mod_node) = TASK_BRD_COMM(task_brd);
        MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
        MOD_NODE_MODI(&recv_mod_node) = 0;
        MOD_NODE_STAT(&recv_mod_node) = 0;
        cload_stat_init(MOD_NODE_CLOAD_STAT(&recv_mod_node));

        task_super_inc(task_mgr, &send_mod_node, &recv_mod_node, &ret, FI_super_sync_cload_mgr, CMPI_ERROR_MODI, tcid_vec, cload_mgr);
        task_wait(task_mgr, TASK_ALWAYS_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);
    }

    return (EC_TRUE);
}

EC_BOOL task_brd_task_mgr_add(TASK_BRD *task_brd, TASK_MGR *task_mgr)
{
    CLIST      *task_mgr_list;

    task_mgr_list = TASK_BRD_RECV_TASK_MGR_LIST(task_brd);

    switch(TASK_MGR_PRIO(task_mgr))
    {
        case TASK_PRIO_PREEMPT:
        {
            clist_push_front(task_mgr_list, (void *)task_mgr);
            TASK_MGR_RECVING_FLAG(task_mgr) = EC_TRUE;
            break;
        }
        case TASK_PRIO_HIGH:
        {
            CLIST_DATA *clist_data;

            CLIST_LOCK(task_mgr_list, LOC_TASK_0142);
            CLIST_LOOP_NEXT(task_mgr_list, clist_data)
            {
                TASK_MGR *cur_task_mgr;

                cur_task_mgr = (TASK_MGR *)CLIST_DATA_DATA(clist_data);

                /*find a lower priority task_mgr, add to its prev*/
                if(TASK_MGR_PRIO(task_mgr) > TASK_MGR_PRIO(cur_task_mgr))
                {
                    clist_insert_front_no_lock(task_mgr_list, clist_data, (void *)task_mgr);
                    TASK_MGR_RECVING_FLAG(task_mgr) = EC_TRUE;

                    CLIST_UNLOCK(task_mgr_list, LOC_TASK_0143);
                    return (EC_TRUE);
                }
            }
            CLIST_UNLOCK(task_mgr_list, LOC_TASK_0144);

            /*if not find a lower priority task_mgr, add to tail*/
            clist_push_back(task_mgr_list, (void *)task_mgr);
            TASK_MGR_RECVING_FLAG(task_mgr) = EC_TRUE;

            break;
        }
        case TASK_PRIO_NORMAL:
        {
            clist_push_back(task_mgr_list, (void *)task_mgr);
            TASK_MGR_RECVING_FLAG(task_mgr) = EC_TRUE;
            break;
        }
        default:
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_task_mgr_add: unknow task priority %ld\n", TASK_MGR_PRIO(task_mgr));
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

EC_BOOL task_brd_aging_list_add(TASK_BRD *task_brd, TASK_MGR *task_mgr)
{
    if(EC_FALSE == TASK_MGR_AGING_FLAG(task_mgr))
    {
        clist_push_back(TASK_BRD_AGING_TASK_MGR_LIST(task_brd), (void *)task_mgr);
        TASK_MGR_AGING_FLAG(task_mgr) = EC_TRUE;
    }
    return (EC_TRUE);
}

EC_BOOL task_brd_mod_mgr_add(TASK_BRD *task_brd, MOD_MGR *mod_mgr)
{
    clist_push_back(TASK_BRD_MOD_MGR_LIST(task_brd), (void *)mod_mgr);
    //dbg_log(SEC_0015_TASK, 5)(LOGSTDOUT, "task_brd_mod_mgr_add: add mod_mgr %p to board\n", mod_mgr);
    return (EC_TRUE);
}

EC_BOOL task_brd_mod_mgr_rmv(TASK_BRD *task_brd, MOD_MGR *mod_mgr)
{
    //clist_print(LOGSTDOUT, TASK_BRD_MOD_MGR_LIST(task_brd), NULL_PTR);
    if(NULL_PTR == clist_del(TASK_BRD_MOD_MGR_LIST(task_brd), (void *)mod_mgr, NULL_PTR))
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_mod_mgr_rmv: not find mod_mgr %p in task_brd\n", mod_mgr);
        return (EC_FALSE);
    }
    //dbg_log(SEC_0015_TASK, 5)(LOGSTDOUT, "task_brd_mod_mgr_rmv: remove mod_mgr %p from board\n", mod_mgr);
    return (EC_TRUE);
}

UINT32 task_brd_seqno_gen(TASK_BRD *task_brd, UINT32 *seqno_new)
{
    TASK_BRD_SEQNO_CMUTEX_LOCK(task_brd, LOC_TASK_0145);
    (*seqno_new) = ++ TASK_BRD_SEQNO(task_brd);
    TASK_BRD_SEQNO_CMUTEX_UNLOCK(task_brd, LOC_TASK_0146);
    return (0);
}

EC_BOOL task_brd_clean(TASK_BRD *task_brd)
{
    /*task mgr list clean*/
    clist_clean(TASK_BRD_RECV_TASK_MGR_LIST(task_brd), (CLIST_DATA_DATA_CLEANER)task_mgr_free);
    clist_clean(TASK_BRD_AGING_TASK_MGR_LIST(task_brd), (CLIST_DATA_DATA_CLEANER)task_mgr_free);

/*
    super_end(TASK_BRD_SUPER_MD_ID(task_brd));
    TASK_BRD_SUPER_MD_ID(task_brd) = CMPI_ERROR_MODI;
*/
    /*clean task_mgr stack*/
    cstack_clean(TASK_BRD_TASK_MGR_STACK(task_brd), NULL_PTR);

    /*clean FUNC_ADDR_MGR table*/
    cvector_clean(TASK_BRD_MD_NODE_TBL(task_brd), NULL_PTR, LOC_TASK_0147);

    creg_type_conv_vec_clean(TASK_BRD_TYPE_CONV_VEC(task_brd));
    creg_func_addr_vec_clean(TASK_BRD_FUNC_ADDR_VEC(task_brd));
#if 0/*do it when exit*/
    /*initialize taskComm in forwarding process*/
    if(CMPI_FWD_RANK == TASK_BRD_RANK(task_brd))
    {
        taskc_end(TASK_BRD_TASKC_MD_ID(task_brd));
        TASK_BRD_TASKC_MD_ID(task_brd) = CMPI_ERROR_MODI;

        super_end(TASK_BRD_SUPER_MD_ID(task_brd));
        TASK_BRD_SUPER_MD_ID(task_brd) = CMPI_ERROR_MODI;
    }
#endif
    /*rank load table clean*/
    task_brd_rank_load_tbl_clean(task_brd);

    /*broken tcid table clean*/
    cvector_clean(TASK_BRD_BROKEN_TCID_TBL(task_brd), NULL_PTR, LOC_TASK_0148);

    /*mod mgr list clean*/
    clist_clean(TASK_BRD_MOD_MGR_LIST(task_brd), (CLIST_DATA_DATA_CLEANER)mod_mgr_free);

    /*context list clean*/
    clist_clean(TASK_BRD_CONTEXT_LIST(task_brd), (CLIST_DATA_DATA_CLEANER)task_context_free);

    /*task report list clean*/
    clist_clean(TASK_BRD_REPORT_LIST(task_brd), (CLIST_DATA_DATA_CLEANER)task_report_node_free);

    /*task cbtimer list clean*/
    cbtimer_clean(TASK_BRD_CBTIMER_LIST(task_brd));

    /*initialize task processor list*/
    task_brd_process_clean(task_brd);

    /*queue list clean*/
    task_queue_clean(TASK_BRD_QUEUE(task_brd, TASK_RECVING_QUEUE));
    task_queue_clean(TASK_BRD_QUEUE(task_brd, TASK_IS_RECV_QUEUE));
    task_queue_clean(TASK_BRD_QUEUE(task_brd, TASK_TO_SEND_QUEUE));
    task_queue_clean(TASK_BRD_QUEUE(task_brd, TASK_SENDING_QUEUE));

    if(NULL_PTR != TASK_BRD_SYS_CFG(task_brd))
    {
        sys_cfg_free(TASK_BRD_SYS_CFG(task_brd));
        TASK_BRD_SYS_CFG(task_brd) = NULL_PTR;
    }

    if(NULL_PTR != TASK_BRD_HTTP_CCONNP_MGR(task_brd))
    {
        cconnp_mgr_free(TASK_BRD_HTTP_CCONNP_MGR(task_brd));
        TASK_BRD_HTTP_CCONNP_MGR(task_brd) = NULL_PTR;
    }

    if(NULL_PTR != TASK_BRD_CSRV(task_brd))
    {
        tasks_srv_end(TASK_BRD_LOCAL_TASKS_CFG(task_brd));
        TASK_BRD_CSRV(task_brd) = NULL_PTR;
    }

#if (SWITCH_ON == CROUTINE_SUPPORT_CTHREAD_SWITCH)
    if(NULL_PTR != TASK_REQ_CTHREAD_POOL(task_brd))
    {
        cthreadp_free(TASK_REQ_CTHREAD_POOL(task_brd));
        TASK_REQ_CTHREAD_POOL(task_brd) = NULL_PTR;
    }

    if(NULL_PTR != TASK_RSP_CTHREAD_POOL(task_brd))
    {
        cthreadp_free(TASK_RSP_CTHREAD_POOL(task_brd));
        TASK_RSP_CTHREAD_POOL(task_brd) = NULL_PTR;
    }
#endif/*(SWITCH_ON == CROUTINE_SUPPORT_CTHREAD_SWITCH)*/

#if (SWITCH_ON == CROUTINE_SUPPORT_COROUTINE_SWITCH)
    if(NULL_PTR != TASK_BRD_CROUTINE_POOL(task_brd))
    {
        croutine_pool_free(TASK_BRD_CROUTINE_POOL(task_brd));
        TASK_BRD_CROUTINE_POOL(task_brd) = NULL_PTR;
    }
#endif/*(SWITCH_ON == CROUTINE_SUPPORT_COROUTINE_SWITCH)*/

    cstack_clean(TASK_BRD_RUNNER_STACK(task_brd), (CSTACK_DATA_DATA_CLEANER)task_runner_node_free);

    if(NULL_PTR != TASK_BRD_EXTRA(task_brd) && NULL_PTR != TASK_BRD_EXTRA_CLEANUP(task_brd))
    {
        TASK_BRD_EXTRA_CLEANUP(task_brd)(TASK_BRD_EXTRA(task_brd));

        TASK_BRD_EXTRA(task_brd) = NULL_PTR;
        TASK_BRD_EXTRA_CLEANUP(task_brd) = NULL_PTR;
    }

    return (EC_TRUE);
}

EC_BOOL task_brd_free(TASK_BRD *task_brd)
{
    if(NULL_PTR != task_brd)
    {
        task_brd_clean(task_brd);
        SAFE_FREE(task_brd, LOC_TASK_0149);
    }
    return (EC_TRUE);
}

UINT32 task_brd_get_tcid_by_ipaddr(const TASK_BRD *task_brd, const UINT32 ipaddr)
{
    TASKS_CFG *tasks_cfg;

    tasks_cfg = TASK_BRD_LOCAL_TASKS_CFG(task_brd);
    return tasks_worker_search_tcid_by_ipaddr(TASKS_CFG_WORKER(tasks_cfg), ipaddr);
}

EC_BOOL task_brd_collect_tcid(const TASK_BRD *task_brd, CVECTOR *tcid_vec)
{
    TASKS_CFG *tasks_cfg;

    tasks_cfg = TASK_BRD_LOCAL_TASKS_CFG(task_brd);
    return tasks_worker_collect_tcid(TASKS_CFG_WORKER(tasks_cfg), tcid_vec);
}

EC_BOOL task_brd_collect_ipaddr(const TASK_BRD *task_brd, CVECTOR *ipaddr_vec)
{
    TASKS_CFG *tasks_cfg;

    tasks_cfg = TASK_BRD_LOCAL_TASKS_CFG(task_brd);
    return tasks_worker_collect_ipaddr(TASKS_CFG_WORKER(tasks_cfg), ipaddr_vec);
}


EC_BOOL task_brd_check_tcid_connected(const TASK_BRD *task_brd, const UINT32 tcid)
{
    MOD_NODE send_mod_node;
    MOD_NODE recv_mod_node;
    TASK_MGR *task_mgr;
    EC_BOOL   ret;

    if(tcid == TASK_BRD_TCID(task_brd))
    {
        return (EC_TRUE);
    }

    if(CMPI_FWD_RANK == TASK_BRD_RANK(task_brd))
    {
        return super_check_tcid_connected(0, tcid);
    }

    task_mgr = task_new(NULL_PTR, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);

    MOD_NODE_TCID(&send_mod_node) = TASK_BRD_TCID(task_brd);
    MOD_NODE_COMM(&send_mod_node) = TASK_BRD_COMM(task_brd);
    MOD_NODE_RANK(&send_mod_node) = TASK_BRD_RANK(task_brd);
    MOD_NODE_MODI(&send_mod_node) = 0;
    MOD_NODE_LOAD(&send_mod_node) = 0;

    mod_node_update_local_stat(&send_mod_node);

    MOD_NODE_TCID(&recv_mod_node) = TASK_BRD_TCID(task_brd);
    MOD_NODE_COMM(&recv_mod_node) = TASK_BRD_COMM(task_brd);
    MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&recv_mod_node) = 0;
    MOD_NODE_LOAD(&recv_mod_node) = 0;

    ret = EC_FALSE;
    task_super_inc(task_mgr, &send_mod_node, &recv_mod_node, &ret, FI_super_check_tcid_connected, 0, tcid);
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    return (ret);
}

/**
*
* register a cbtimer
* the handler must look like as EC_BOOL foo(...), i.e., the function return type is EC_BOOL
* when EC_TRUE is returned, wait for next timeout
* when EC_FALSE is returned, unregister it
*
**/
EC_BOOL task_brd_cbtimer_register(TASK_BRD *task_brd, const UINT32 expire_nsec, const UINT32 timeout_nsec, const UINT32 timeout_func_id, ...)
{
    CBTIMER_NODE *cbtimer_node;
    FUNC_ADDR_NODE *func_addr_node;
    TASK_FUNC *handler;

    UINT32 mod_type;

    UINT32 para_idx;
    va_list ap;

    mod_type = (timeout_func_id >> (WORDSIZE / 2));
    if( MD_END <= mod_type )
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDERR, "error:task_brd_cbtimer_register: invalid timeout_func_id %lx\n", timeout_func_id);
        return (EC_FALSE);
    }

    if(0 != dbg_fetch_func_addr_node_by_index(timeout_func_id, &func_addr_node))
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_cbtimer_register: failed to fetch func addr node by func id %lx\n", timeout_func_id);
        return (EC_FALSE);
    }

    cbtimer_node = cbtimer_node_new();
    if(NULL_PTR == cbtimer_node)
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_cbtimer_register: new cbtimer node failed\n");
        return (EC_FALSE);
    }

    CBTIMER_NODE_NAME(cbtimer_node) = cstring_new((UINT8 *)func_addr_node->func_name, LOC_TASK_0150);

    CBTIMER_NODE_EXPIRE_NSEC(cbtimer_node)   = expire_nsec;
    CBTIMER_NODE_TIMEOUT_NSEC(cbtimer_node)  = timeout_nsec;

    CBTIMER_NODE_EXPIRE_FUNC_ADDR_NODE(cbtimer_node)  = NULL_PTR;
    CBTIMER_NODE_TIMEOUT_FUNC_ADDR_NODE(cbtimer_node) = func_addr_node;

    handler = CBTIMER_NODE_TIMEOUT_HANDLER(cbtimer_node);

    handler->func_id       = timeout_func_id;
    handler->func_para_num = func_addr_node->func_para_num;
    handler->func_ret_val  = EC_TRUE;

    va_start(ap, timeout_func_id);
    for(para_idx = 0; para_idx < func_addr_node->func_para_num; para_idx ++ )
    {
        FUNC_PARA *func_para;

        func_para = &(handler->func_para[ para_idx ]);
        func_para->para_val = va_arg(ap, UINT32);
    }
    va_end(ap);

    CTIMET_GET(CBTIMER_NODE_START_TIME(cbtimer_node));
    CTIMET_GET(CBTIMER_NODE_LAST_TIME(cbtimer_node));

    cbtimer_register(TASK_BRD_CBTIMER_LIST(task_brd), cbtimer_node);
    return (EC_TRUE);
}

/*task_brd_func_addr_node is for func such as EC_BOOL foo(TASK_BRD *task_brd)*/
EC_BOOL task_brd_cbtimer_add(TASK_BRD *task_brd, const UINT8 *name,
                                     const UINT32 expire_nsec, FUNC_ADDR_NODE *task_brd_expire_func_addr_node,
                                     const UINT32 timeout_nsec, FUNC_ADDR_NODE *task_brd_timeout_func_addr_node)
{
    CBTIMER_NODE *cbtimer_node;
    TASK_FUNC *timeout_handler;
    TASK_FUNC *expire_handler;

    cbtimer_node = cbtimer_node_new();
    if(NULL_PTR == cbtimer_node)
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_cbtimer_add: new cbtimer node failed\n");
        return (EC_FALSE);
    }

    CBTIMER_NODE_NAME(cbtimer_node) = cstring_new(name, LOC_TASK_0151);
    if(NULL_PTR == CBTIMER_NODE_NAME(cbtimer_node))
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_cbtimer_add: new name cstring failed\n");
        cbtimer_node_free(cbtimer_node);
        return (EC_FALSE);
    }

    CBTIMER_NODE_TIMEOUT_NSEC(cbtimer_node)  = timeout_nsec;
    if(NULL_PTR != task_brd_timeout_func_addr_node)
    {
        CBTIMER_NODE_TIMEOUT_FUNC_ADDR_NODE(cbtimer_node) = task_brd_timeout_func_addr_node;
        timeout_handler = CBTIMER_NODE_TIMEOUT_HANDLER(cbtimer_node);
        timeout_handler->func_id                = task_brd_timeout_func_addr_node->func_index;
        timeout_handler->func_para_num          = 1;
        timeout_handler->func_para[0].para_val  = (UINT32)task_brd;
        timeout_handler->func_ret_val           = EC_TRUE;
    }

    CBTIMER_NODE_EXPIRE_NSEC(cbtimer_node)   = expire_nsec;
    if(NULL_PTR != task_brd_expire_func_addr_node)
    {
        CBTIMER_NODE_EXPIRE_FUNC_ADDR_NODE(cbtimer_node) = task_brd_expire_func_addr_node;
        expire_handler = CBTIMER_NODE_EXPIRE_HANDLER(cbtimer_node);
        expire_handler->func_id                = task_brd_expire_func_addr_node->func_index;
        expire_handler->func_para_num          = 1;
        expire_handler->func_para[0].para_val  = (UINT32)task_brd;
        expire_handler->func_ret_val           = EC_TRUE;
    }

    CTIMET_GET(CBTIMER_NODE_START_TIME(cbtimer_node));
    CTIMET_GET(CBTIMER_NODE_LAST_TIME(cbtimer_node));

    cbtimer_register(TASK_BRD_CBTIMER_LIST(task_brd), cbtimer_node);
    return (EC_TRUE);
}

EC_BOOL task_brd_cbtimer_do(TASK_BRD *task_brd)
{
    for(;;)
    {
        if(EC_FALSE == TASK_BRD_RESET_FLAG(task_brd))
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "task_brd_cbtimer_do: reset flag is true, terminate\n");
            break;
        }
        //dbg_log(SEC_0015_TASK, 9)(LOGSTDOUT, "[DEBUG]task_brd_cbtimer_do: working\n");
        if(EC_FALSE == cbtimer_handle(TASK_BRD_CBTIMER_LIST(task_brd)))
        {
            c_sleep(3, LOC_TASK_0152);
        }
    }
    return (EC_TRUE);
}

TASK_BRD_PROCESS_HANDLER *task_brd_process_find(TASK_BRD *task_brd, TASK_BRD_CALLBACK func, void *arg)
{
    CLIST_DATA      *clist_data;

    CLIST_LOOP_NEXT(TASK_BRD_PROCESS_LIST(task_brd), clist_data)
    {
        TASK_BRD_PROCESS_HANDLER     *task_brd_process_handler;

        task_brd_process_handler = (TASK_BRD_PROCESS_HANDLER *)CLIST_DATA_DATA(clist_data);

        if(func == TASK_BRD_PROCESS_HANDLER_FUNC(task_brd_process_handler)
        && arg == TASK_BRD_PROCESS_HANDLER_ARG(task_brd_process_handler))
        {
            return (task_brd_process_handler);
        }
    }

    return (NULL_PTR);
}

EC_BOOL task_brd_process_add(TASK_BRD *task_brd, TASK_BRD_CALLBACK func, void *arg)
{
    if(NULL_PTR == task_brd_process_find(task_brd, func, arg))
    {
        TASK_BRD_PROCESS_HANDLER     *task_brd_process_handler;

        task_brd_process_handler = safe_malloc(sizeof(TASK_BRD_PROCESS_HANDLER), LOC_TASK_0153);
        if(NULL_PTR == task_brd_process_handler)
        {
            return (EC_FALSE);
        }

        TASK_BRD_PROCESS_HANDLER_FUNC(task_brd_process_handler) = func;
        TASK_BRD_PROCESS_HANDLER_ARG(task_brd_process_handler)  = arg;

        clist_push_back(TASK_BRD_PROCESS_LIST(task_brd), (void *)task_brd_process_handler);
    }

    return (EC_TRUE);
}

EC_BOOL task_brd_process_del(TASK_BRD *task_brd, TASK_BRD_CALLBACK func, void *arg)
{
    CLIST_DATA      *clist_data;

    CLIST_LOOP_NEXT(TASK_BRD_PROCESS_LIST(task_brd), clist_data)
    {
        TASK_BRD_PROCESS_HANDLER     *task_brd_process_handler;

        task_brd_process_handler = (TASK_BRD_PROCESS_HANDLER *)CLIST_DATA_DATA(clist_data);

        if(func == TASK_BRD_PROCESS_HANDLER_FUNC(task_brd_process_handler)
        && arg == TASK_BRD_PROCESS_HANDLER_ARG(task_brd_process_handler))
        {
            clist_erase(TASK_BRD_PROCESS_LIST(task_brd), clist_data);
            safe_free((void *)task_brd_process_handler, LOC_TASK_0154);

            return (EC_TRUE);
        }
    }

    return (EC_FALSE);
}

EC_BOOL task_brd_process_init(TASK_BRD *task_brd)
{
    clist_init(TASK_BRD_PROCESS_LIST(task_brd), MM_UINT32, LOC_TASK_0155);
    return (EC_TRUE);
}

EC_BOOL task_brd_process_clean(TASK_BRD *task_brd)
{
    TASK_BRD_PROCESS_HANDLER     *task_brd_process_handler;

    while(NULL_PTR != (task_brd_process_handler = clist_pop_back(TASK_BRD_PROCESS_LIST(task_brd))))
    {
        safe_free((void *)task_brd_process_handler, LOC_TASK_0156);
    }

    return (EC_TRUE);
}

EC_BOOL task_brd_process_do(TASK_BRD *task_brd)
{
    CLIST                        *task_process_list;
    TASK_BRD_PROCESS_HANDLER     *task_brd_process_handler;

    UINT32           num;
    UINT32           pos;

    task_process_list = TASK_BRD_PROCESS_LIST(task_brd);
    num = clist_size(task_process_list);

    for(pos = 0; pos < num
    && NULL_PTR != (task_brd_process_handler = clist_pop_front(task_process_list));
    pos ++)
    {
        TASK_BRD_CALLBACK             func;
        void                         *arg;

        func = TASK_BRD_PROCESS_HANDLER_FUNC(task_brd_process_handler);
        arg  = TASK_BRD_PROCESS_HANDLER_ARG(task_brd_process_handler);

        safe_free((void *)task_brd_process_handler, LOC_TASK_0157);

        func(arg);
    }

    return (EC_TRUE);
}

UINT32 task_brd_que_load(const TASK_BRD *task_brd)
{
    if(EC_TRUE == TASK_BRD_ENABLE_FLAG(task_brd))
    {
        UINT32 que_sum;

        que_sum = 0;
        que_sum += clist_size(TASK_BRD_QUEUE(task_brd, TASK_RECVING_QUEUE));
        que_sum += clist_size(TASK_BRD_QUEUE(task_brd, TASK_IS_RECV_QUEUE));
        que_sum += clist_size(TASK_BRD_QUEUE(task_brd, TASK_TO_SEND_QUEUE));
        que_sum += clist_size(TASK_BRD_QUEUE(task_brd, TASK_SENDING_QUEUE));

        if(NULL_PTR != TASK_REQ_CTHREAD_POOL(task_brd))
        {
            que_sum += croutine_pool_busy_num(TASK_REQ_CTHREAD_POOL(task_brd));
        }

        if(TASK_RSP_CTHREAD_POOL(task_brd) != TASK_REQ_CTHREAD_POOL(task_brd) && NULL_PTR != TASK_RSP_CTHREAD_POOL(task_brd))
        {
            que_sum -= croutine_pool_busy_num(TASK_RSP_CTHREAD_POOL(task_brd));
        }

        return (que_sum);
    }
    return ((UINT32)-1);
}

UINT32 task_brd_obj_load(const TASK_BRD *task_brd)
{
    return cbc_sum();
}

UINT32 task_brd_cpu_load(const TASK_BRD *task_brd)
{
    CSYS_CPU_AVG_STAT csys_cpu_avg_stat;
    REAL  avg_01_min;

    csys_cpu_avg_stat_get(&csys_cpu_avg_stat);
    avg_01_min = CSYS_CPU_AVG_STAT_01_MIN(&csys_cpu_avg_stat);

    return lrint(avg_01_min * 100.0);
}

UINT32 task_brd_cpu_load_get(const TASK_BRD *task_brd)
{
    const CSYS_CPU_AVG_STAT *csys_cpu_avg_stat;
    REAL  avg_01_min;

    csys_cpu_avg_stat = TASK_BRD_CPU_AVG_STAT(task_brd);
    avg_01_min = CSYS_CPU_AVG_STAT_01_MIN(csys_cpu_avg_stat);

    return lrint(avg_01_min * 100.0);
}

UINT32 task_brd_mem_load(const TASK_BRD *task_brd)
{
    CPROC_MEM_STAT cproc_mem_stat;
    REAL  mem_load;

    cproc_mem_stat_get(&cproc_mem_stat);
    mem_load = CPROC_MEM_LOAD(&cproc_mem_stat);

    return lrint(mem_load * 100.0);
}

UINT32 task_brd_dsk_load(const TASK_BRD *task_brd)
{
    CSYS_DSK_VEC *csys_dsk_stat_vec;

    UINT32 csys_dsk_stat_num;
    UINT32 csys_dsk_stat_pos;

    REAL  dsk_load_sum;

    csys_dsk_stat_vec = csys_dsk_stat_vec_new();
    csys_dsk_stat_vec_get(csys_dsk_stat_vec);

    dsk_load_sum = 0.0;

    csys_dsk_stat_num = csys_dsk_stat_vec_size(csys_dsk_stat_vec);
    for(csys_dsk_stat_pos = 0; csys_dsk_stat_pos < csys_dsk_stat_num; csys_dsk_stat_pos ++)
    {
        CSYS_DSK_STAT *csys_dsk_stat;

        csys_dsk_stat = (CSYS_DSK_STAT *)cvector_get(csys_dsk_stat_vec, csys_dsk_stat_pos);
        dsk_load_sum += CSYS_DSK_LOAD(csys_dsk_stat);
        csys_dsk_stat_free(csys_dsk_stat);
        cvector_set(csys_dsk_stat_vec, csys_dsk_stat_pos, (void *)NULL_PTR);
    }

    csys_dsk_stat_vec_free(csys_dsk_stat_vec);

    return lrint(dsk_load_sum * 100.0 / (1.0 * csys_dsk_stat_num));
}

UINT32 task_brd_net_load(const TASK_BRD *task_brd)
{
    CSYS_ETH_VEC *csys_eth_stat_vec;

    UINT32 csys_eth_stat_num;
    UINT32 csys_eth_stat_pos;

    REAL  eth_rx_load_max;
    REAL  eth_tx_load_max;

    csys_eth_stat_vec = csys_eth_stat_vec_new();
    csys_eth_stat_vec_get(csys_eth_stat_vec);

    eth_rx_load_max = 0.0;
    eth_tx_load_max = 0.0;

    csys_eth_stat_num = csys_eth_stat_vec_size(csys_eth_stat_vec);
    for(csys_eth_stat_pos = 0; csys_eth_stat_pos < csys_eth_stat_num; csys_eth_stat_pos ++)
    {
        CSYS_ETH_STAT *csys_eth_stat;
        REAL eth_speed;/*in KB/s*/

        csys_eth_stat = (CSYS_ETH_STAT *)cvector_get(csys_eth_stat_vec, csys_eth_stat_pos);

        eth_speed = (1.0 * CSYS_ETH_SPEEDMBS(csys_eth_stat) * (1024/8));
        dbg_log(SEC_0015_TASK, 9)(LOGSTDNULL, "[DEBUG] task_brd_net_load: eth_speed = %.2f KB/s, eth_rx_load_max = %.2f KB, eth_tx_load_max = %.2f KB\n", eth_speed, eth_rx_load_max, eth_tx_load_max);
        eth_rx_load_max = DMAX(eth_rx_load_max, ((1.0 * CSYS_ETH_RXTHROUGHPUT(csys_eth_stat)) / eth_speed));
        eth_tx_load_max = DMAX(eth_tx_load_max, ((1.0 * CSYS_ETH_TXTHROUGHPUT(csys_eth_stat)) / eth_speed));
        csys_eth_stat_free(csys_eth_stat);
        cvector_set(csys_eth_stat_vec, csys_eth_stat_pos, (void *)NULL_PTR);
    }

    csys_eth_stat_vec_free(csys_eth_stat_vec);

    return lrint(DMAX(eth_rx_load_max, eth_tx_load_max));
}

EC_BOOL task_brd_task_mgr_match(const TASK_BRD *task_brd, const TASK_RSP *task_rsp, TASK_MGR **task_mgr_ret)
{
    CLIST      *task_mgr_list;
    CLIST_DATA *clist_data;

    task_mgr_list = (CLIST *)TASK_BRD_RECV_TASK_MGR_LIST(task_brd);

    CLIST_LOCK(task_mgr_list, LOC_TASK_0158);
    CLIST_LOOP_NEXT(task_mgr_list, clist_data)
    {
        TASK_MGR *task_mgr;

        task_mgr = (TASK_MGR *)CLIST_DATA_DATA(clist_data);
        if( TASK_RSP_SEQNO(task_rsp) == TASK_MGR_SEQNO(task_mgr))
        {
            *task_mgr_ret = task_mgr;
            CLIST_UNLOCK(task_mgr_list, LOC_TASK_0159);
            return (EC_TRUE);
        }
    }
    CLIST_UNLOCK(task_mgr_list, LOC_TASK_0160);
    return (EC_FALSE);
}

/*if rank != except_rank, then upload rank load in task_brd rank table*/
EC_BOOL task_brd_rank_load_set(TASK_BRD *task_brd, const UINT32 tcid, const UINT32 rank, const CLOAD_STAT *cload_stat)
{
    if(tcid != TASK_BRD_TCID(task_brd) || rank != TASK_BRD_RANK(task_brd))
    {
        return cload_mgr_set(TASK_BRD_CLOAD_MGR(task_brd), tcid, rank, cload_stat);
    }

    return (EC_FALSE);
}

/*if rank != except_rank, then upload rank load in task_brd rank table*/
EC_BOOL task_brd_rank_load_set_que(TASK_BRD *task_brd, const UINT32 tcid, const UINT32 rank, const UINT32 que_load)
{
    if(tcid != TASK_BRD_TCID(task_brd) || rank != TASK_BRD_RANK(task_brd))
    {
        return cload_mgr_set_que(TASK_BRD_CLOAD_MGR(task_brd), tcid, rank, que_load);
    }

    return (EC_FALSE);
}

/*if rank != except_rank, then increase rank load in task_brd rank table*/
EC_BOOL task_brd_rank_load_inc_que(TASK_BRD *task_brd, const UINT32 tcid, const UINT32 rank)
{
    if(tcid != TASK_BRD_TCID(task_brd) || rank != TASK_BRD_RANK(task_brd))
    {
        return cload_mgr_inc_que(TASK_BRD_CLOAD_MGR(task_brd), tcid, rank);
    }

    return (EC_FALSE);
}

EC_BOOL task_brd_rank_load_dec_que(TASK_BRD *task_brd, const UINT32 tcid, const UINT32 rank)
{
    if(tcid != TASK_BRD_TCID(task_brd) || rank != TASK_BRD_RANK(task_brd))
    {
        return cload_mgr_dec_que(TASK_BRD_CLOAD_MGR(task_brd), tcid, rank);
    }

    return (EC_FALSE);
}

UINT32 task_brd_rank_load_print(LOG *log, const TASK_BRD *task_brd)
{
    sys_log(log, "task brd rank load table is:\n");
    cload_mgr_print(log, TASK_BRD_CLOAD_MGR(task_brd));

    return (0);
}

EC_BOOL load_set_when_task_req_isend(TASK_BRD *task_brd, TASK_REQ *task_req)
{
    /*update rank load of task_brd*/
    task_brd_rank_load_inc_que(task_brd, TASK_REQ_SEND_TCID(task_req), TASK_REQ_SEND_RANK(task_req));
    task_brd_rank_load_inc_que(task_brd, TASK_REQ_RECV_TCID(task_req), TASK_REQ_RECV_RANK(task_req));

    return (EC_TRUE);
}

EC_BOOL load_set_when_task_req_commit(TASK_BRD *task_brd, TASK_REQ *task_req)
{
    /*update rank load of task_brd*/
    task_brd_rank_load_inc_que(task_brd, TASK_REQ_SEND_TCID(task_req), TASK_REQ_SEND_RANK(task_req));
    task_brd_rank_load_inc_que(task_brd, TASK_REQ_RECV_TCID(task_req), TASK_REQ_RECV_RANK(task_req));

    task_brd_rank_load_set(task_brd, TASK_REQ_SEND_TCID(task_req), TASK_REQ_SEND_RANK(task_req), TASK_REQ_CLOAD_STAT(task_req));

    return (EC_TRUE);
}

EC_BOOL load_set_when_task_rsp_isend(TASK_BRD *task_brd, TASK_RSP *task_rsp)
{
    task_brd_rank_load_dec_que(task_brd, TASK_RSP_SEND_TCID(task_rsp), TASK_RSP_SEND_RANK(task_rsp));
    task_brd_rank_load_dec_que(task_brd, TASK_RSP_RECV_TCID(task_rsp), TASK_RSP_RECV_RANK(task_rsp));
    return (EC_TRUE);
}

EC_BOOL load_set_when_task_rsp_commit(TASK_BRD *task_brd, TASK_RSP *task_rsp)
{
    task_brd_rank_load_dec_que(task_brd, TASK_RSP_SEND_TCID(task_rsp), TASK_RSP_SEND_RANK(task_rsp));
    task_brd_rank_load_dec_que(task_brd, TASK_RSP_RECV_TCID(task_rsp), TASK_RSP_RECV_RANK(task_rsp));

    /*TASK_RSP take back the load of remote mod node(or remote rank)*/
    /*if the sender of TASK_RSP is NOT its recver, then update load of sender*/
    /*otherwise, do not update load of sender because sender maintain the load info more precisely*/
    task_brd_rank_load_set(task_brd, TASK_RSP_SEND_TCID(task_rsp), TASK_RSP_SEND_RANK(task_rsp), TASK_RSP_CLOAD_STAT(task_rsp));

    return (EC_TRUE);
}

EC_BOOL load_set_when_task_req_is_sent(TASK_BRD *task_brd, TASK_REQ *task_req)
{
    task_brd_rank_load_dec_que(task_brd, TASK_REQ_SEND_TCID(task_req), TASK_REQ_SEND_RANK(task_req));
    task_brd_rank_load_dec_que(task_brd, TASK_REQ_RECV_TCID(task_req), TASK_REQ_RECV_RANK(task_req));
    return (EC_TRUE);
}

EC_BOOL load_set_when_task_rsp_is_ignore(TASK_BRD *task_brd, TASK_REQ *task_req)
{
    task_brd_rank_load_dec_que(task_brd, TASK_REQ_SEND_TCID(task_req), TASK_REQ_SEND_RANK(task_req));
    task_brd_rank_load_dec_que(task_brd, TASK_REQ_RECV_TCID(task_req), TASK_REQ_RECV_RANK(task_req));
    return (EC_TRUE);
}

EC_BOOL load_set_when_task_fwd_commit(TASK_BRD *task_brd, TASK_FWD *task_fwd)
{
    /*update rank load of task_brd*/
    task_brd_rank_load_inc_que(task_brd, TASK_FWD_SEND_TCID(task_fwd), TASK_FWD_SEND_RANK(task_fwd));
    task_brd_rank_load_inc_que(task_brd, TASK_FWD_RECV_TCID(task_fwd), TASK_FWD_RECV_RANK(task_fwd));

    task_brd_rank_load_set(task_brd, TASK_FWD_SEND_TCID(task_fwd), TASK_FWD_SEND_RANK(task_fwd), TASK_FWD_CLOAD_STAT(task_fwd));

    return (EC_TRUE);
}

EC_BOOL task_brd_commit_req(TASK_BRD *task_brd, TASK_REQ *task_req)
{
    TASK_NODE  *task_req_node;

    dbg_log(SEC_0015_TASK, 6)(LOGSTDOUT, "commit req: from (tcid %s,comm %ld,rank %ld,modi %ld) to (tcid %s,comm %ld,rank %ld,modi %ld) with priority %ld, type %ld, tag %ld, ldb %ld, seqno %lx.%lx.%lx, subseqno %ld, func id %lx\n",
                    TASK_REQ_SEND_TCID_STR(task_req), TASK_REQ_SEND_COMM(task_req), TASK_REQ_SEND_RANK(task_req), TASK_REQ_SEND_MODI(task_req),
                    TASK_REQ_RECV_TCID_STR(task_req), TASK_REQ_RECV_COMM(task_req), TASK_REQ_RECV_RANK(task_req), TASK_REQ_RECV_MODI(task_req),
                    TASK_REQ_PRIO(task_req), TASK_REQ_TYPE(task_req),
                    TASK_REQ_TAG(task_req), TASK_REQ_LDB_CHOICE(task_req),
                    TASK_REQ_SEND_TCID(task_req), TASK_REQ_SEND_RANK(task_req), TASK_REQ_SEQNO(task_req), TASK_REQ_SUB_SEQNO(task_req),
                    TASK_REQ_FUNC_ID(task_req)
                    );

    task_req_node = TASK_REQ_NODE(task_req);

    /*update status*/
    TASK_NODE_STATUS(task_req_node) = TASK_REQ_IS_RECV;
    /*TASK_IS_RECV_QUEUE support task priority, here add node by task_queue_add_node*/
    task_queue_add_node(TASK_BRD_QUEUE(task_brd, TASK_IS_RECV_QUEUE), task_req_node);

    CTIMET_GET(TASK_REQ_START_TIME(task_req)); /*okay,record the task req starting time*/

    /*update load info if task_req has been recved*/
    load_set_when_task_req_commit(task_brd, task_req);

    //dbg_log(SEC_0015_TASK, 9)(LOGSTDOUT, "[DEBUG] task_brd_commit_req: task brd rank load table:\n");
    //task_brd_rank_load_tbl_print(LOGSTDOUT, task_brd);

    return (EC_TRUE);
}

EC_BOOL task_brd_commit_req_no_queue(TASK_BRD *task_brd, TASK_REQ *task_req)
{
    TASK_NODE  *task_req_node;

    dbg_log(SEC_0015_TASK, 6)(LOGSTDOUT, "commit req: from (tcid %s,comm %ld,rank %ld,modi %ld) to (tcid %s,comm %ld,rank %ld,modi %ld) with priority %ld, type %ld, tag %ld, ldb %ld, seqno %lx.%lx.%lx, subseqno %ld, func id %lx\n",
                    TASK_REQ_SEND_TCID_STR(task_req), TASK_REQ_SEND_COMM(task_req), TASK_REQ_SEND_RANK(task_req), TASK_REQ_SEND_MODI(task_req),
                    TASK_REQ_RECV_TCID_STR(task_req), TASK_REQ_RECV_COMM(task_req), TASK_REQ_RECV_RANK(task_req), TASK_REQ_RECV_MODI(task_req),
                    TASK_REQ_PRIO(task_req), TASK_REQ_TYPE(task_req),
                    TASK_REQ_TAG(task_req), TASK_REQ_LDB_CHOICE(task_req),
                    TASK_REQ_SEND_TCID(task_req), TASK_REQ_SEND_RANK(task_req), TASK_REQ_SEQNO(task_req), TASK_REQ_SUB_SEQNO(task_req),
                    TASK_REQ_FUNC_ID(task_req)
                    );

    task_req_node = TASK_REQ_NODE(task_req);

    /*update status*/
    TASK_NODE_STATUS(task_req_node) = TASK_REQ_IS_RECV;
    /*TASK_IS_RECV_QUEUE support task priority, here add node by task_queue_add_node*/
    //task_queue_add_node(TASK_BRD_QUEUE(task_brd, TASK_IS_RECV_QUEUE), task_req_node);

    CTIMET_GET(TASK_REQ_START_TIME(task_req)); /*okay,record the task req starting time*/

    /*update load info if task_req has been recved*/
    load_set_when_task_req_commit(task_brd, task_req);

    //dbg_log(SEC_0015_TASK, 9)(LOGSTDOUT, "[DEBUG] task_brd_commit_req: task brd rank load table:\n");
    //task_brd_rank_load_tbl_print(LOGSTDOUT, task_brd);

    return (EC_TRUE);
}

EC_BOOL task_brd_discard_rsp(TASK_BRD *task_brd, TASK_RSP *task_rsp)
{
    dbg_log(SEC_0015_TASK, 5)(LOGSTDOUT, "discard rsp: from (tcid %s,comm %ld,rank %ld,modi %ld) to (tcid %s,comm %ld,rank %ld,modi %ld) with priority %ld, type %ld, tag %ld, ldb %ld, seqno %lx.%lx.%lx, subseqno %ld, func id %lx\n",
                    TASK_RSP_SEND_TCID_STR(task_rsp), TASK_RSP_SEND_COMM(task_rsp), TASK_RSP_SEND_RANK(task_rsp), TASK_RSP_SEND_MODI(task_rsp),
                    TASK_RSP_RECV_TCID_STR(task_rsp), TASK_RSP_RECV_COMM(task_rsp), TASK_RSP_RECV_RANK(task_rsp), TASK_RSP_RECV_MODI(task_rsp),
                    TASK_RSP_PRIO(task_rsp), TASK_RSP_TYPE(task_rsp),
                    TASK_RSP_TAG(task_rsp), TASK_RSP_LDB_CHOICE(task_rsp),
                    TASK_RSP_RECV_TCID(task_rsp), TASK_RSP_RECV_RANK(task_rsp), TASK_RSP_SEQNO(task_rsp), TASK_RSP_SUB_SEQNO(task_rsp),
                    TASK_RSP_FUNC_ID(task_rsp)
                    );

    return (EC_TRUE);
}

EC_BOOL task_brd_commit_rsp(TASK_BRD *task_brd, TASK_RSP *task_rsp)
{
    dbg_log(SEC_0015_TASK, 3)(LOGSTDOUT, "commit rsp: from (tcid %s,comm %ld,rank %ld,modi %ld) to (tcid %s,comm %ld,rank %ld,modi %ld) with priority %ld, type %ld, tag %ld, ldb %ld, seqno %lx.%lx.%lx, subseqno %ld, func id %lx\n",
                    TASK_RSP_SEND_TCID_STR(task_rsp), TASK_RSP_SEND_COMM(task_rsp), TASK_RSP_SEND_RANK(task_rsp), TASK_RSP_SEND_MODI(task_rsp),
                    TASK_RSP_RECV_TCID_STR(task_rsp), TASK_RSP_RECV_COMM(task_rsp), TASK_RSP_RECV_RANK(task_rsp), TASK_RSP_RECV_MODI(task_rsp),
                    TASK_RSP_PRIO(task_rsp), TASK_RSP_TYPE(task_rsp),
                    TASK_RSP_TAG(task_rsp), TASK_RSP_LDB_CHOICE(task_rsp),
                    TASK_RSP_RECV_TCID(task_rsp), TASK_RSP_RECV_RANK(task_rsp), TASK_RSP_SEQNO(task_rsp), TASK_RSP_SUB_SEQNO(task_rsp),
                    TASK_RSP_FUNC_ID(task_rsp)
                    );
    //if(NULL_PTR != TASK_RSP_MGR(task_rsp))
    {
        /*update load info if task_rsp has been recved*/
        load_set_when_task_rsp_commit(task_brd, task_rsp);
    }

    return (EC_TRUE);
}

EC_BOOL task_brd_commit_fwd(TASK_BRD *task_brd, TASK_FWD *task_fwd)
{
    TASK_NODE  *task_fwd_node;

    switch(TASK_FWD_TAG(task_fwd))
    {
        case TAG_TASK_REQ:
        dbg_log(SEC_0015_TASK, 6)(LOGSTDOUT, "commit fwd: from (tcid %s,comm %ld,rank %ld,modi %ld) to (tcid %s,comm %ld,rank %ld,modi %ld) with priority %ld, type %ld, tag %ld, ldb %ld, seqno %lx.%lx.%lx, subseqno %ld, func id %lx\n",
                        TASK_FWD_SEND_TCID_STR(task_fwd), TASK_FWD_SEND_COMM(task_fwd), TASK_FWD_SEND_RANK(task_fwd), TASK_FWD_SEND_MODI(task_fwd),
                        TASK_FWD_RECV_TCID_STR(task_fwd), TASK_FWD_RECV_COMM(task_fwd), TASK_FWD_RECV_RANK(task_fwd), TASK_FWD_RECV_MODI(task_fwd),
                        TASK_FWD_PRIO(task_fwd), TASK_FWD_TYPE(task_fwd),
                        TASK_FWD_TAG(task_fwd), TASK_FWD_LDB_CHOICE(task_fwd),
                        TASK_FWD_SEND_TCID(task_fwd), TASK_FWD_SEND_RANK(task_fwd), TASK_FWD_SEQNO(task_fwd), TASK_FWD_SUB_SEQNO(task_fwd),
                        TASK_FWD_FUNC_ID(task_fwd)
                        );
        break;

        case TAG_TASK_RSP:
        dbg_log(SEC_0015_TASK, 6)(LOGSTDOUT, "commit fwd: from (tcid %s,comm %ld,rank %ld,modi %ld) to (tcid %s,comm %ld,rank %ld,modi %ld) with priority %ld, type %ld, tag %ld, ldb %ld, seqno %lx.%lx.%lx, subseqno %ld, func id %lx\n",
                        TASK_FWD_SEND_TCID_STR(task_fwd), TASK_FWD_SEND_COMM(task_fwd), TASK_FWD_SEND_RANK(task_fwd), TASK_FWD_SEND_MODI(task_fwd),
                        TASK_FWD_RECV_TCID_STR(task_fwd), TASK_FWD_RECV_COMM(task_fwd), TASK_FWD_RECV_RANK(task_fwd), TASK_FWD_RECV_MODI(task_fwd),
                        TASK_FWD_PRIO(task_fwd), TASK_FWD_TYPE(task_fwd),
                        TASK_FWD_TAG(task_fwd), TASK_FWD_LDB_CHOICE(task_fwd),
                        TASK_FWD_RECV_TCID(task_fwd), TASK_FWD_RECV_RANK(task_fwd), TASK_FWD_SEQNO(task_fwd), TASK_FWD_SUB_SEQNO(task_fwd),
                        TASK_FWD_FUNC_ID(task_fwd)
                        );
        break;

        case TAG_TASK_FWD:
        dbg_log(SEC_0015_TASK, 6)(LOGSTDOUT, "commit fwd: from (tcid %s,comm %ld,rank %ld,modi %ld) to (tcid %s,comm %ld,rank %ld,modi %ld) with priority %ld, type %ld, tag %ld, ldb %ld, seqno fwd.%lx.%lx.%lx, subseqno %ld, func id %lx\n",
                        TASK_FWD_SEND_TCID_STR(task_fwd), TASK_FWD_SEND_COMM(task_fwd), TASK_FWD_SEND_RANK(task_fwd), TASK_FWD_SEND_MODI(task_fwd),
                        TASK_FWD_RECV_TCID_STR(task_fwd), TASK_FWD_RECV_COMM(task_fwd), TASK_FWD_RECV_RANK(task_fwd), TASK_FWD_RECV_MODI(task_fwd),
                        TASK_FWD_PRIO(task_fwd), TASK_FWD_TYPE(task_fwd),
                        TASK_FWD_TAG(task_fwd), TASK_FWD_LDB_CHOICE(task_fwd),
                        TASK_FWD_SEND_TCID(task_fwd), TASK_FWD_SEND_RANK(task_fwd), TASK_FWD_SEQNO(task_fwd), TASK_FWD_SUB_SEQNO(task_fwd),
                        TASK_FWD_FUNC_ID(task_fwd)
                        );
        break;

        default:
        dbg_log(SEC_0015_TASK, 6)(LOGSTDOUT, "commit fwd: from (tcid %s,comm %ld,rank %ld,modi %ld) to (tcid %s,comm %ld,rank %ld,modi %ld) with priority %ld, type %ld, tag %ld, ldb %ld, seqno undef.%lx.%lx.%lx, subseqno %ld, func id %lx\n",
                        TASK_FWD_SEND_TCID_STR(task_fwd), TASK_FWD_SEND_COMM(task_fwd), TASK_FWD_SEND_RANK(task_fwd), TASK_FWD_SEND_MODI(task_fwd),
                        TASK_FWD_RECV_TCID_STR(task_fwd), TASK_FWD_RECV_COMM(task_fwd), TASK_FWD_RECV_RANK(task_fwd), TASK_FWD_RECV_MODI(task_fwd),
                        TASK_FWD_PRIO(task_fwd), TASK_FWD_TYPE(task_fwd),
                        TASK_FWD_TAG(task_fwd), TASK_FWD_LDB_CHOICE(task_fwd),
                        TASK_FWD_SEND_TCID(task_fwd), TASK_FWD_SEND_RANK(task_fwd), TASK_FWD_SEQNO(task_fwd), TASK_FWD_SUB_SEQNO(task_fwd),
                        TASK_FWD_FUNC_ID(task_fwd)
                        );
        break;
    }

    //task_func_print(LOGSTDNULL, TASK_FWD_FUNC(task_fwd));

    task_fwd_node = TASK_FWD_NODE(task_fwd);

    /*update status*/
    TASK_NODE_STATUS(task_fwd_node) = TASK_FWD_IS_RECV;

    /*update load info when task_fwd commit*/
    load_set_when_task_fwd_commit(task_brd, task_fwd);

    /*TASK_IS_RECV_QUEUE support task priority, here add node by task_queue_add_node*/
    task_queue_add_node(TASK_BRD_QUEUE(task_brd, TASK_IS_RECV_QUEUE), task_fwd_node);

    return (EC_TRUE);
}

EC_BOOL task_brd_commit_fwd_no_queue(TASK_BRD *task_brd, TASK_FWD *task_fwd)
{
    TASK_NODE  *task_fwd_node;

    switch(TASK_FWD_TAG(task_fwd))
    {
        case TAG_TASK_REQ:
        dbg_log(SEC_0015_TASK, 6)(LOGSTDOUT, "commit fwd: from (tcid %s,comm %ld,rank %ld,modi %ld) to (tcid %s,comm %ld,rank %ld,modi %ld) with priority %ld, type %ld, tag %ld, ldb %ld, seqno %lx.%lx.%lx, subseqno %ld, func id %lx\n",
                        TASK_FWD_SEND_TCID_STR(task_fwd), TASK_FWD_SEND_COMM(task_fwd), TASK_FWD_SEND_RANK(task_fwd), TASK_FWD_SEND_MODI(task_fwd),
                        TASK_FWD_RECV_TCID_STR(task_fwd), TASK_FWD_RECV_COMM(task_fwd), TASK_FWD_RECV_RANK(task_fwd), TASK_FWD_RECV_MODI(task_fwd),
                        TASK_FWD_PRIO(task_fwd), TASK_FWD_TYPE(task_fwd),
                        TASK_FWD_TAG(task_fwd), TASK_FWD_LDB_CHOICE(task_fwd),
                        TASK_FWD_SEND_TCID(task_fwd), TASK_FWD_SEND_RANK(task_fwd), TASK_FWD_SEQNO(task_fwd), TASK_FWD_SUB_SEQNO(task_fwd),
                        TASK_FWD_FUNC_ID(task_fwd)
                        );
        break;

        case TAG_TASK_RSP:
        dbg_log(SEC_0015_TASK, 6)(LOGSTDOUT, "commit fwd: from (tcid %s,comm %ld,rank %ld,modi %ld) to (tcid %s,comm %ld,rank %ld,modi %ld) with priority %ld, type %ld, tag %ld, ldb %ld, seqno %lx.%lx.%lx, subseqno %ld, func id %lx\n",
                        TASK_FWD_SEND_TCID_STR(task_fwd), TASK_FWD_SEND_COMM(task_fwd), TASK_FWD_SEND_RANK(task_fwd), TASK_FWD_SEND_MODI(task_fwd),
                        TASK_FWD_RECV_TCID_STR(task_fwd), TASK_FWD_RECV_COMM(task_fwd), TASK_FWD_RECV_RANK(task_fwd), TASK_FWD_RECV_MODI(task_fwd),
                        TASK_FWD_PRIO(task_fwd), TASK_FWD_TYPE(task_fwd),
                        TASK_FWD_TAG(task_fwd), TASK_FWD_LDB_CHOICE(task_fwd),
                        TASK_FWD_RECV_TCID(task_fwd), TASK_FWD_RECV_RANK(task_fwd), TASK_FWD_SEQNO(task_fwd), TASK_FWD_SUB_SEQNO(task_fwd),
                        TASK_FWD_FUNC_ID(task_fwd)
                        );
        break;

        case TAG_TASK_FWD:
        dbg_log(SEC_0015_TASK, 6)(LOGSTDOUT, "commit fwd: from (tcid %s,comm %ld,rank %ld,modi %ld) to (tcid %s,comm %ld,rank %ld,modi %ld) with priority %ld, type %ld, tag %ld, ldb %ld, seqno fwd.%lx.%lx.%lx, subseqno %ld, func id %lx\n",
                        TASK_FWD_SEND_TCID_STR(task_fwd), TASK_FWD_SEND_COMM(task_fwd), TASK_FWD_SEND_RANK(task_fwd), TASK_FWD_SEND_MODI(task_fwd),
                        TASK_FWD_RECV_TCID_STR(task_fwd), TASK_FWD_RECV_COMM(task_fwd), TASK_FWD_RECV_RANK(task_fwd), TASK_FWD_RECV_MODI(task_fwd),
                        TASK_FWD_PRIO(task_fwd), TASK_FWD_TYPE(task_fwd),
                        TASK_FWD_TAG(task_fwd), TASK_FWD_LDB_CHOICE(task_fwd),
                        TASK_FWD_SEND_TCID(task_fwd), TASK_FWD_SEND_RANK(task_fwd), TASK_FWD_SEQNO(task_fwd), TASK_FWD_SUB_SEQNO(task_fwd),
                        TASK_FWD_FUNC_ID(task_fwd)
                        );
        break;

        default:
        dbg_log(SEC_0015_TASK, 6)(LOGSTDOUT, "commit fwd: from (tcid %s,comm %ld,rank %ld,modi %ld) to (tcid %s,comm %ld,rank %ld,modi %ld) with priority %ld, type %ld, tag %ld, ldb %ld, seqno undef.%lx.%lx.%lx, subseqno %ld, func id %lx\n",
                        TASK_FWD_SEND_TCID_STR(task_fwd), TASK_FWD_SEND_COMM(task_fwd), TASK_FWD_SEND_RANK(task_fwd), TASK_FWD_SEND_MODI(task_fwd),
                        TASK_FWD_RECV_TCID_STR(task_fwd), TASK_FWD_RECV_COMM(task_fwd), TASK_FWD_RECV_RANK(task_fwd), TASK_FWD_RECV_MODI(task_fwd),
                        TASK_FWD_PRIO(task_fwd), TASK_FWD_TYPE(task_fwd),
                        TASK_FWD_TAG(task_fwd), TASK_FWD_LDB_CHOICE(task_fwd),
                        TASK_FWD_SEND_TCID(task_fwd), TASK_FWD_SEND_RANK(task_fwd), TASK_FWD_SEQNO(task_fwd), TASK_FWD_SUB_SEQNO(task_fwd),
                        TASK_FWD_FUNC_ID(task_fwd)
                        );
        break;
    }

    //task_func_print(LOGSTDNULL, TASK_FWD_FUNC(task_fwd));

    task_fwd_node = TASK_FWD_NODE(task_fwd);

    /*update status*/
    TASK_NODE_STATUS(task_fwd_node) = TASK_FWD_IS_RECV;

    /*update load info when task_fwd commit*/
    load_set_when_task_fwd_commit(task_brd, task_fwd);

    /*TASK_IS_RECV_QUEUE support task priority, here add node by task_queue_add_node*/
    //task_queue_add_node(TASK_BRD_QUEUE(task_brd, TASK_IS_RECV_QUEUE), task_fwd_node);

    return (EC_TRUE);
}

EC_BOOL task_brd_to_send_queue_handle(TASK_BRD *task_brd)
{
    CLIST_DATA *clist_data;

    CLIST_LOCK(TASK_BRD_QUEUE(task_brd, TASK_TO_SEND_QUEUE), LOC_TASK_0161);
    CLIST_LOOP_NEXT(TASK_BRD_QUEUE(task_brd, TASK_TO_SEND_QUEUE), clist_data)
    {
        TASK_NODE    *task_node;

        CLIST_DATA   *clist_data_rmv;

        task_node = (TASK_NODE *)CLIST_DATA_DATA(clist_data);

        switch(TASK_NODE_TAG(task_node))
        {
            case TAG_TASK_RSP:
            {
                TASK_RSP   *task_rsp;
                TASK_NODE  *task_rsp_node;

                task_rsp_node = task_node;
                task_rsp = TASK_NODE_RSP(task_rsp_node);

                clist_data_rmv = clist_data;
                clist_data = CLIST_DATA_PREV(clist_data);
                clist_rmv_no_lock(TASK_BRD_QUEUE(task_brd, TASK_TO_SEND_QUEUE), clist_data_rmv);

                /*TODO: when task_rsp timeout ...*/
                if(EC_TRUE == task_rsp_isend(task_brd, task_rsp))
                {
                    TASK_NODE_STATUS(task_rsp_node) = TASK_RSP_SENDING;

                    /*note: TASK_SENDING_QUEUE not support task priority due to it causes disordered transmission*/
                    /*hence the only to add node is by push operation*/
                    clist_push_back(TASK_BRD_QUEUE(task_brd, TASK_SENDING_QUEUE), (void *)task_rsp_node);
                }
                else
                {
                    dbg_log(SEC_0015_TASK, 3)(LOGSTDOUT, "disc rsp: from (tcid %s,comm %ld,rank %ld,modi %ld) to (tcid %s,comm %ld,rank %ld,modi %ld) with priority %ld, type %ld, tag %ld, ldb %ld, seqno %lx.%lx.%lx, subseqno %ld, func id %lx\n",
                            TASK_NODE_SEND_TCID_STR(task_node), TASK_NODE_SEND_COMM(task_node), TASK_NODE_SEND_RANK(task_node), TASK_NODE_SEND_MODI(task_node),
                            TASK_NODE_RECV_TCID_STR(task_node), TASK_NODE_RECV_COMM(task_node), TASK_NODE_RECV_RANK(task_node), TASK_NODE_RECV_MODI(task_node),
                            TASK_NODE_PRIO(task_node), TASK_NODE_TYPE(task_node),
                            TASK_NODE_TAG(task_node), TASK_NODE_LDB_CHOICE(task_node),
                            TASK_NODE_SEND_TCID(task_node), TASK_NODE_SEND_RANK(task_node), TASK_NODE_SEQNO(task_node), TASK_NODE_SUB_SEQNO(task_node),
                            TASK_NODE_FUNC_ID(task_node)
                            );

                    /*free this task rsp*/
                    task_rsp_free(task_rsp);
                }

                break;
            }
            default:
            {
                dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_to_send_queue_handle: unknown task node tag %ld\n", TASK_NODE_TAG(task_node));
            }
        }
    }

    CLIST_UNLOCK(TASK_BRD_QUEUE(task_brd, TASK_TO_SEND_QUEUE), LOC_TASK_0162);
    return (EC_TRUE);
}

EC_BOOL task_brd_sending_queue_handle(TASK_BRD *task_brd)
{
    CLIST_DATA *clist_data;

    //dbg_log(SEC_0015_TASK, 5)(LOGSTDOUT, "task_brd_sending_queue_handle: check sending queue ....\n");

    CLIST_LOCK(TASK_BRD_QUEUE(task_brd, TASK_SENDING_QUEUE), LOC_TASK_0163);
    CLIST_LOOP_NEXT(TASK_BRD_QUEUE(task_brd, TASK_SENDING_QUEUE), clist_data)
    {
        TASK_NODE    *task_node;

        CLIST_DATA   *clist_data_rmv;

        task_node = (TASK_NODE *)CLIST_DATA_DATA(clist_data);

        if(TASK_NODE_BUFF_POS(task_node) != TASK_NODE_BUFF_LEN(task_node) || TASK_WAS_SENT != TASK_NODE_COMP(task_node))
        {
            /*incomplete sending packet means sending congestion, hence suspending next task req/rsp sending but try to recv req/rsp*/
            /*return (EC_FALSE);*/

            /*congestion may happen on some socket or mpi channel, other sockets or channels may work well, so continue sending*/
            continue;
        }
        dbg_log(SEC_0015_TASK, 3)(LOGSTDOUT, "sent  node: from (tcid %s,comm %ld,rank %ld,modi %ld) to (tcid %s,comm %ld,rank %ld,modi %ld) with priority %ld, type %ld, tag %ld, ldb %ld, seqno %lx.%lx.%lx, subseqno %ld, func id %lx\n",
                        TASK_NODE_SEND_TCID_STR(task_node), TASK_NODE_SEND_COMM(task_node), TASK_NODE_SEND_RANK(task_node), TASK_NODE_SEND_MODI(task_node),
                        TASK_NODE_RECV_TCID_STR(task_node), TASK_NODE_RECV_COMM(task_node), TASK_NODE_RECV_RANK(task_node), TASK_NODE_RECV_MODI(task_node),
                        TASK_NODE_PRIO(task_node), TASK_NODE_TYPE(task_node),
                        TASK_NODE_TAG(task_node), TASK_NODE_LDB_CHOICE(task_node),
                        TASK_NODE_SEND_TCID(task_node), TASK_NODE_SEND_RANK(task_node), TASK_NODE_SEQNO(task_node), TASK_NODE_SUB_SEQNO(task_node),
                        TASK_NODE_FUNC_ID(task_node)
                        );
        switch(TASK_NODE_TAG(task_node))
        {
            case TAG_TASK_RSP:
            {
                TASK_RSP   *task_rsp;
                TASK_NODE  *task_rsp_node;

                task_rsp_node = task_node;
                task_rsp = TASK_NODE_RSP(task_rsp_node);
                TASK_NODE_STATUS(task_rsp_node) = TASK_RSP_IS_SENT;

                /*free this task rsp*/
                clist_data_rmv = clist_data;
                clist_data = CLIST_DATA_PREV(clist_data);

                clist_rmv_no_lock(TASK_BRD_QUEUE(task_brd, TASK_SENDING_QUEUE), clist_data_rmv);
                task_rsp_free(task_rsp);

                break;
            }
            case TAG_TASK_FWD:
            {
                TASK_FWD   *task_fwd;
                TASK_NODE  *task_fwd_node;

                task_fwd_node = task_node;
                task_fwd = TASK_NODE_FWD(task_fwd_node);

                TASK_NODE_STATUS(task_fwd_node) = TASK_FWD_IS_SENT;

                /*free this task fwd*/
                clist_data_rmv = clist_data;
                clist_data = CLIST_DATA_PREV(clist_data);

                clist_rmv_no_lock(TASK_BRD_QUEUE(task_brd, TASK_SENDING_QUEUE), clist_data_rmv);
                task_fwd_free(task_fwd);

                break;
            }
            default:
            {
                dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_sending_queue_handle: unknown task node tag %ld\n", TASK_NODE_TAG(task_node));
                dbg_log(SEC_0015_TASK, 5)(LOGSTDOUT, "error node: from (tcid %s,comm %ld,rank %ld,modi %ld) to (tcid %s,comm %ld,rank %ld,modi %ld) with priority %ld, type %ld, tag %ld, ldb %ld, seqno %lx.%lx.%lx, subseqno %ld, func id %lx\n",
                                TASK_NODE_SEND_TCID_STR(task_node), TASK_NODE_SEND_COMM(task_node), TASK_NODE_SEND_RANK(task_node), TASK_NODE_SEND_MODI(task_node),
                                TASK_NODE_RECV_TCID_STR(task_node), TASK_NODE_RECV_COMM(task_node), TASK_NODE_RECV_RANK(task_node), TASK_NODE_RECV_MODI(task_node),
                                TASK_NODE_PRIO(task_node), TASK_NODE_TYPE(task_node),
                                TASK_NODE_TAG(task_node), TASK_NODE_LDB_CHOICE(task_node),
                                TASK_NODE_SEND_TCID(task_node), TASK_NODE_SEND_RANK(task_node), TASK_NODE_SEQNO(task_node), TASK_NODE_SUB_SEQNO(task_node),
                                TASK_NODE_FUNC_ID(task_node)
                                );
            }
        }
    }

    CLIST_UNLOCK(TASK_BRD_QUEUE(task_brd, TASK_SENDING_QUEUE), LOC_TASK_0164);
    return (EC_TRUE);
}

UINT32 task_req_decode_thread(TASK_BRD *task_brd, TASK_NODE *task_node)
{
    TASK_REQ   *task_req;
    TASK_NODE  *task_req_node;

    task_req_node = task_node;
    task_req = TASK_NODE_REQ(task_req_node);

    CROUTINE_CLEANUP_PUSH(task_req_free, task_req);
    task_req_decode(TASK_BRD_COMM(task_brd), task_req);
    CROUTINE_CLEANUP_POP(0);

    task_node_buff_free(task_req_node); /*free buff memory after decoding*/

    /*commit task req to board is_recv queue*/
    task_brd_commit_req(task_brd, task_req);

    return (0);
}

UINT32 task_req_decode_no_queue_thread(TASK_BRD *task_brd, TASK_NODE *task_node)
{
    TASK_REQ   *task_req;
    TASK_NODE  *task_req_node;

    task_req_node = task_node;
    task_req = TASK_NODE_REQ(task_req_node);

    CROUTINE_CLEANUP_PUSH(task_req_free, task_req);
    task_req_decode(TASK_BRD_COMM(task_brd), task_req);
    CROUTINE_CLEANUP_POP(0);

    task_node_buff_free(task_req_node); /*free buff memory after decoding*/

    /*commit task req to board is_recv queue*/
    task_brd_commit_req_no_queue(task_brd, task_req);

    return (0);
}

UINT32 task_req_decode_and_handle_thread(TASK_BRD *task_brd, TASK_NODE *task_node)
{
    TASK_REQ *task_req;

    dbg_log(SEC_0015_TASK, 9)(LOGSTDOUT, "[DEBUG] task_req_decode_and_handle_thread: task_brd %p, task_node %p\n", task_brd, task_node);

    task_req_decode_no_queue_thread(task_brd, task_node);

    task_req = TASK_NODE_REQ(task_node);
    if(EC_TRUE == task_req_is_timeout(task_req))
    {
        dbg_log(SEC_0015_TASK, 5)(LOGSTDOUT, "timeout req: from (tcid %s,comm %ld,rank %ld,modi %ld) to (tcid %s,comm %ld,rank %ld,modi %ld) with priority %ld, type %ld, tag %ld, ldb %ld, seqno %lx.%lx.%lx, subseqno %ld, func id %lx\n",
                        TASK_REQ_SEND_TCID_STR(task_req), TASK_REQ_SEND_COMM(task_req), TASK_REQ_SEND_RANK(task_req), TASK_REQ_SEND_MODI(task_req),
                        TASK_REQ_RECV_TCID_STR(task_req),TASK_REQ_RECV_COMM(task_req), TASK_REQ_RECV_RANK(task_req), TASK_REQ_RECV_MODI(task_req),
                        TASK_REQ_PRIO(task_req), TASK_REQ_TYPE(task_req),
                        TASK_REQ_TAG(task_req), TASK_REQ_LDB_CHOICE(task_req),
                        TASK_REQ_SEND_TCID(task_req), TASK_REQ_SEND_RANK(task_req), TASK_REQ_SEQNO(task_req), TASK_REQ_SUB_SEQNO(task_req),
                        TASK_REQ_FUNC_ID(task_req)
                        );

        task_req_free(task_req);

        return (0);
    }

    task_req_handle_thread(task_brd, task_req);

    return (0);
}

#if 0
STATIC_CAST static void task_rsp_discard_dbg_info(const TASK_MGR *task_mgr, const TASK_RSP *task_rsp)
{
    dbg_log(SEC_0015_TASK, 5)(LOGSTDOUT, "disc rsp: from (tcid %s,comm %ld,rank %ld,modi %ld) to (tcid %s,comm %ld,rank %ld,modi %ld) with priority %ld, type %ld, tag %ld, ldb %ld, seqno %lx.%lx.%lx, subseqno %ld, func id %lx ==> task mgr %lx(%lx), fail %ld, succ %ld\n",
                    TASK_RSP_SEND_TCID_STR(task_rsp), TASK_RSP_SEND_COMM(task_rsp), TASK_RSP_SEND_RANK(task_rsp), TASK_RSP_SEND_MODI(task_rsp),
                    TASK_RSP_RECV_TCID_STR(task_rsp), TASK_RSP_RECV_COMM(task_rsp), TASK_RSP_RECV_RANK(task_rsp), TASK_RSP_RECV_MODI(task_rsp),
                    TASK_RSP_PRIO(task_rsp), TASK_RSP_TYPE(task_rsp),
                    TASK_RSP_TAG(task_rsp), TASK_RSP_LDB_CHOICE(task_rsp),
                    TASK_RSP_RECV_TCID(task_rsp), TASK_RSP_RECV_RANK(task_rsp), TASK_RSP_SEQNO(task_rsp), TASK_RSP_SUB_SEQNO(task_rsp),
                    TASK_RSP_FUNC_ID(task_rsp),
                    TASK_RSP_MGR(task_rsp),task_mgr,
                    TASK_MGR_COUNTER(task_mgr, TASK_MGR_COUNTER_TASK_RSP_IS_FAIL),
                    TASK_MGR_COUNTER(task_mgr, TASK_MGR_COUNTER_TASK_RSP_IS_SUCC)
                    );
    return;
}


STATIC_CAST static void task_rsp_succ_dbg_info(const TASK_MGR *task_mgr, const TASK_RSP *task_rsp)
{
    dbg_log(SEC_0015_TASK, 5)(LOGSTDOUT, "succ rsp: from (tcid %s,comm %ld,rank %ld,modi %ld) to (tcid %s,comm %ld,rank %ld,modi %ld) with priority %ld, type %ld, tag %ld, ldb %ld, seqno %lx.%lx.%lx, subseqno %ld, func id %lx ==> task mgr %lx(%lx), succ %ld, fail %ld\n",
                    TASK_RSP_SEND_TCID_STR(task_rsp), TASK_RSP_SEND_COMM(task_rsp), TASK_RSP_SEND_RANK(task_rsp), TASK_RSP_SEND_MODI(task_rsp),
                    TASK_RSP_RECV_TCID_STR(task_rsp), TASK_RSP_RECV_COMM(task_rsp), TASK_RSP_RECV_RANK(task_rsp), TASK_RSP_RECV_MODI(task_rsp),
                    TASK_RSP_PRIO(task_rsp), TASK_RSP_TYPE(task_rsp),
                    TASK_RSP_TAG(task_rsp), TASK_RSP_LDB_CHOICE(task_rsp),
                    TASK_RSP_RECV_TCID(task_rsp), TASK_RSP_RECV_RANK(task_rsp), TASK_RSP_SEQNO(task_rsp), TASK_RSP_SUB_SEQNO(task_rsp),
                    TASK_RSP_FUNC_ID(task_rsp),
                    TASK_RSP_MGR(task_rsp), task_mgr,
                    TASK_MGR_COUNTER(task_mgr, TASK_MGR_COUNTER_TASK_RSP_IS_SUCC),
                    TASK_MGR_COUNTER(task_mgr, TASK_MGR_COUNTER_TASK_RSP_IS_FAIL)
                    );
    return;
}

STATIC_CAST static void task_rsp_fail_dbg_info(const TASK_MGR *task_mgr, const TASK_RSP *task_rsp)
{
    dbg_log(SEC_0015_TASK, 5)(LOGSTDOUT, "fail rsp: from (tcid %s,comm %ld,rank %ld,modi %ld) to (tcid %s,comm %ld,rank %ld,modi %ld) with priority %ld, type %ld, tag %ld, ldb %ld, seqno %lx.%lx.%lx, subseqno %ld, func id %lx ==> task mgr %lx(%lx), fail %ld, succ %ld\n",
                    TASK_RSP_SEND_TCID_STR(task_rsp), TASK_RSP_SEND_COMM(task_rsp), TASK_RSP_SEND_RANK(task_rsp), TASK_RSP_SEND_MODI(task_rsp),
                    TASK_RSP_RECV_TCID_STR(task_rsp), TASK_RSP_RECV_COMM(task_rsp), TASK_RSP_RECV_RANK(task_rsp), TASK_RSP_RECV_MODI(task_rsp),
                    TASK_RSP_PRIO(task_rsp), TASK_RSP_TYPE(task_rsp),
                    TASK_RSP_TAG(task_rsp), TASK_RSP_LDB_CHOICE(task_rsp),
                    TASK_RSP_RECV_TCID(task_rsp), TASK_RSP_RECV_RANK(task_rsp), TASK_RSP_SEQNO(task_rsp), TASK_RSP_SUB_SEQNO(task_rsp),
                    TASK_RSP_FUNC_ID(task_rsp),
                    TASK_RSP_MGR(task_rsp),task_mgr,
                    TASK_MGR_COUNTER(task_mgr, TASK_MGR_COUNTER_TASK_RSP_IS_FAIL),
                    TASK_MGR_COUNTER(task_mgr, TASK_MGR_COUNTER_TASK_RSP_IS_SUCC)
                    );
    return;
}

#else

#define task_rsp_discard_dbg_info(task_mgr, task_rsp)       do{}while(0)

#define task_rsp_succ_dbg_info(task_mgr, task_rsp)          do{}while(0)

#define task_rsp_fail_dbg_info(task_mgr, task_rsp)          do{}while(0)

#endif

UINT32 task_rsp_decode_thread(TASK_BRD *task_brd, TASK_NODE *task_node)
{
    TASK_RSP   *task_rsp;
    TASK_NODE  *task_rsp_node;
    TASK_MGR   *task_mgr;
    UINT32      ret_val_check_succ_flag;

    task_rsp_node = task_node;
    task_rsp = TASK_NODE_RSP(task_rsp_node);

    //dbg_log(SEC_0015_TASK, 5)(LOGSTDOUT, "task_rsp_decode_thread:push task_rsp %lx [pthread %u]\n", task_rsp, pthread_self());
    CROUTINE_CLEANUP_PUSH(task_rsp_free, task_rsp);

    task_mgr = NULL_PTR;

    /*note: the matched task req will update status to TASK_RSP_IS_RECV*/
    if(EC_FALSE == task_rsp_decode(TASK_BRD_COMM(task_brd), task_brd, task_rsp, &task_mgr, &ret_val_check_succ_flag))
    {
        if(NULL_PTR != task_mgr)
        {
            TASK_MGR_COUNTER_INC_BY_TASK_RSP(task_mgr, TASK_MGR_COUNTER_TASK_RSP_IS_FAIL, task_rsp, LOC_TASK_0165);
            task_rsp_discard_dbg_info(task_mgr, task_rsp);
        }

        task_brd_discard_rsp(task_brd, task_rsp);
    }
    else
    {
        task_brd_commit_rsp(task_brd, task_rsp);

        if(EC_TRUE == ret_val_check_succ_flag)
        {
            TASK_MGR_COUNTER_INC_BY_TASK_RSP(task_mgr, TASK_MGR_COUNTER_TASK_RSP_IS_SUCC, task_rsp, LOC_TASK_0166);
            task_rsp_succ_dbg_info(task_mgr, task_rsp);
        }
        else
        {
            TASK_MGR_COUNTER_INC_BY_TASK_RSP(task_mgr, TASK_MGR_COUNTER_TASK_RSP_IS_FAIL, task_rsp, LOC_TASK_0167);
            task_rsp_fail_dbg_info(task_mgr, task_rsp);
        }
    }

    //dbg_log(SEC_0015_TASK, 5)(LOGSTDOUT, "task_rsp_decode_thread:pop task_rsp %lx [pthread %u]\n", task_rsp, pthread_self());
    CROUTINE_CLEANUP_POP(0);

    task_rsp_free(task_rsp);
    return (0);
}


UINT32 task_fwd_decode_thread(TASK_BRD *task_brd, TASK_NODE *task_node)
{
    TASK_FWD   *task_fwd;
    TASK_NODE  *task_fwd_node;

    task_fwd_node = task_node;
    task_fwd = TASK_NODE_FWD(task_fwd_node);

    //dbg_log(SEC_0015_TASK, 9)(LOGSTDOUT, "[DEBUG] task_fwd_decode_thread: task_brd %p, task_node %p, task_fwd %p\n", task_brd, task_node, task_fwd);

    task_fwd_decode(TASK_BRD_COMM(task_brd), task_fwd);

    /*commit task fwd to board is_recv queue*/
    task_brd_commit_fwd(task_brd, task_fwd);

    return (0);
}

UINT32 task_fwd_decode_and_handle_thread(TASK_BRD *task_brd, TASK_NODE *task_node)
{
    TASK_FWD   *task_fwd;
    TASK_NODE  *task_fwd_node;

    task_fwd_node = task_node;
    task_fwd = TASK_NODE_FWD(task_fwd_node);

    task_fwd_decode(TASK_BRD_COMM(task_brd), task_fwd);

    /*commit task fwd to board is_recv queue*/
    task_brd_commit_fwd_no_queue(task_brd, task_fwd);

    if(EC_TRUE == task_fwd_is_to_local(task_brd, task_fwd))
    {
        task_fwd_direct_no_queue(task_brd, task_fwd);
        task_brd_recving_node_handle_not_load_thread(task_brd, task_fwd_node);
    }
    else
    {
        if(EC_TRUE == task_fwd_isend(task_brd, task_fwd))
        {
            TASK_NODE_STATUS(task_fwd_node) = TASK_FWD_SENDING;

            /*commit task fwd to board sending queue*/
            /*note: TASK_SENDING_QUEUE not support task priority due to it causes disordered transmission*/
            /*hence the only to add node is by push operation*/
            clist_push_back(TASK_BRD_QUEUE(task_brd, TASK_SENDING_QUEUE), (void *)task_fwd_node);
        }
    }

    return (0);
}

UINT32 task_req_node_recving_handle(TASK_BRD *task_brd, TASK_NODE *task_node)
{
#if (SWITCH_ON == TASK_REQ_DECODE_AND_HANDLE_THREAD_SWITCH)
            return task_req_decode_and_handle_thread(task_brd, task_node);
#endif/*(SWITCH_ON == TASK_REQ_DECODE_AND_HANDLE_THREAD_SWITCH)*/
#if (SWITCH_OFF == TASK_REQ_DECODE_AND_HANDLE_THREAD_SWITCH)
            return task_req_decode_thread(task_brd, task_node);
#endif/*(SWITCH_OFF == TASK_REQ_DECODE_AND_HANDLE_THREAD_SWITCH)*/
}

UINT32 task_rsp_node_recving_handle(TASK_BRD *task_brd, TASK_NODE *task_node)
{
    return task_rsp_decode_thread(task_brd, task_node);
}

UINT32 task_fwd_node_recving_handle(TASK_BRD *task_brd, TASK_NODE *task_node)
{
#if (SWITCH_ON == TASK_FWD_DECODE_AND_HANDLE_THREAD_SWITCH)
    return task_fwd_decode_and_handle_thread(task_brd, task_node);
#endif/*(SWITCH_ON == TASK_FWD_DECODE_AND_HANDLE_THREAD_SWITCH)*/
#if (SWITCH_OFF == TASK_FWD_DECODE_AND_HANDLE_THREAD_SWITCH)
    //dbg_log(SEC_0015_TASK, 9)(LOGSTDOUT, "[DEBUG] task_fwd_node_recving_handle: call task_fwd_decode_thread, task_node %p\n", task_node);
    return task_fwd_decode_thread(task_brd, task_node);
#endif/*(SWITCH_OFF == TASK_FWD_DECODE_AND_HANDLE_THREAD_SWITCH)*/
}

UINT32 task_brd_recving_node_handle_not_load_thread(TASK_BRD *task_brd, TASK_NODE *task_node)
{
    switch(TASK_NODE_TAG(task_node))
    {
        case TAG_TASK_REQ:
        {
            return task_req_node_recving_handle(task_brd, task_node);
        }
        case TAG_TASK_RSP:
        {
            return task_rsp_node_recving_handle(task_brd, task_node);
        }
        case TAG_TASK_FWD:
        {
            return task_fwd_node_recving_handle(task_brd, task_node);
        }
        default:
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_recving_node_handle_not_load_thread: unknown task node tag %ld\n", TASK_NODE_TAG(task_node));
        }
    }
    return ((UINT32)-1);
}

CROUTINE_NODE *task_brd_recving_node_handle_load_thread(TASK_BRD *task_brd, TASK_NODE *task_node)
{
    switch(TASK_NODE_TAG(task_node))
    {
        case TAG_TASK_REQ:
        {
            TASK_REQ *task_req;

            task_req = TASK_NODE_REQ(task_node);

#if (SWITCH_ON == TASK_REQ_DECODE_AND_HANDLE_THREAD_SWITCH)
            //dbg_log(SEC_0015_TASK, 9)(LOGSTDOUT, "[DEBUG] task_brd_recving_node_handle_load_thread: croutine_pool_load: task_brd %p, task_node %p\n", task_brd, task_node);
            TASK_REQ_CTHREAD_NODE(task_req) = croutine_pool_load(TASK_REQ_CTHREAD_POOL(task_brd),
                                                            (UINT32)task_req_decode_and_handle_thread,
                                                            (UINT32)2,
                                                            task_brd,
                                                            task_node);
#endif/*(SWITCH_ON == TASK_REQ_DECODE_AND_HANDLE_THREAD_SWITCH)*/
#if (SWITCH_OFF == TASK_REQ_DECODE_AND_HANDLE_THREAD_SWITCH)
            TASK_REQ_CTHREAD_NODE(task_req) = croutine_pool_load(TASK_REQ_CTHREAD_POOL(task_brd),
                                                            (UINT32)task_req_decode_thread,
                                                            (UINT32)2,
                                                            task_brd,
                                                            task_node);
#endif/*(SWITCH_OFF == TASK_REQ_DECODE_AND_HANDLE_THREAD_SWITCH)*/
            return TASK_REQ_CTHREAD_NODE(task_req);
        }
        case TAG_TASK_RSP:
        {
            TASK_RSP *task_rsp;

            task_rsp = TASK_NODE_RSP(task_node);
#if 0
            if(NULL_PTR != TASK_RSP_CTHREAD_NODE(task_rsp))
            {
                dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "[DBG] error: TASK_RSP_CTHREAD_NODE(task_rsp) %lx is not null\n", TASK_RSP_CTHREAD_NODE(task_rsp));
                //continue;
            }
#endif
            //dbg_log(SEC_0015_TASK, 9)(LOGSTDOUT, "[DEBUG] task_brd_recving_node_handle_load_thread: croutine_pool_load: task_brd %p, task_node %p\n", task_brd, task_node);
            TASK_RSP_CTHREAD_NODE(task_rsp)= croutine_pool_load(TASK_RSP_CTHREAD_POOL(task_brd),
                                                            (UINT32)task_rsp_decode_thread,
                                                            (UINT32)2,
                                                            task_brd,
                                                            task_node);
            return TASK_RSP_CTHREAD_NODE(task_rsp);
        }
        case TAG_TASK_FWD:
        {
            TASK_FWD *task_fwd;

            task_fwd = TASK_NODE_FWD(task_node);

#if (SWITCH_ON == TASK_FWD_DECODE_AND_HANDLE_THREAD_SWITCH)
            //dbg_log(SEC_0015_TASK, 9)(LOGSTDOUT, "[DEBUG] task_brd_recving_node_handle_load_thread: croutine_pool_load: task_brd %p, task_node %p\n", task_brd, task_node);
            TASK_FWD_CTHREAD_NODE(task_fwd)  = croutine_pool_load(TASK_FWD_CTHREAD_POOL(task_brd),
                                                            (UINT32)task_fwd_decode_and_handle_thread,
                                                            (UINT32)2,
                                                            task_brd,
                                                            task_node);
#endif/*(SWITCH_ON == TASK_FWD_DECODE_AND_HANDLE_THREAD_SWITCH)*/
#if (SWITCH_OFF == TASK_FWD_DECODE_AND_HANDLE_THREAD_SWITCH)
            //dbg_log(SEC_0015_TASK, 9)(LOGSTDOUT, "[DEBUG] task_brd_recving_node_handle_load_thread: croutine_pool_load task_fwd_decode_thread, task_node %p\n", task_node);
            TASK_FWD_CTHREAD_NODE(task_fwd)  = croutine_pool_load(TASK_FWD_CTHREAD_POOL(task_brd),
                                                            (UINT32)task_fwd_decode_thread,
                                                            (UINT32)2,
                                                            task_brd,
                                                            task_node);
#endif/*(SWITCH_OFF == TASK_FWD_DECODE_AND_HANDLE_THREAD_SWITCH)*/
            return TASK_FWD_CTHREAD_NODE(task_fwd);
        }
        default:
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_recving_node_handle_load_thread: unknown task node tag %ld\n", TASK_NODE_TAG(task_node));
        }
    }
    return (NULL_PTR);
}

/*debug only*/
void task_brd_recving_queue_print(LOG *log, TASK_BRD *task_brd)
{
    CLIST_DATA  *clist_data;
    UINT32 idx;

    CLIST_LOCK(TASK_BRD_QUEUE(task_brd, TASK_RECVING_QUEUE), LOC_TASK_0168);

    idx = 0;
    CLIST_LOOP_NEXT(TASK_BRD_QUEUE(task_brd, TASK_RECVING_QUEUE), clist_data)
    {
        TASK_NODE    *task_node;

        task_node = (TASK_NODE *)CLIST_DATA_DATA(clist_data);
        if(NULL_PTR != task_node)
        {
            dbg_log(SEC_0015_TASK, 3)(log, "[DEBUG] task_brd_recving_queue_print: TASK_RECVING_QUEUE: [%ld] task node %p\n",
                        idx, task_node);
            idx ++;
        }
    }

    CLIST_UNLOCK(TASK_BRD_QUEUE(task_brd, TASK_RECVING_QUEUE), LOC_TASK_0169);
    return;
}

EC_BOOL task_brd_recving_queue_handle(TASK_BRD *task_brd)
{
    CLIST_LOCK(TASK_BRD_QUEUE(task_brd, TASK_RECVING_QUEUE), LOC_TASK_0170);

    for(;;)
    {
        TASK_NODE   *task_node;

        task_node = clist_pop_front_no_lock(TASK_BRD_QUEUE(task_brd, TASK_RECVING_QUEUE));
        if(NULL_PTR == task_node)
        {
            break;
        }

        task_brd_recving_node_handle_not_load_thread(task_brd, task_node);
    }

    CLIST_UNLOCK(TASK_BRD_QUEUE(task_brd, TASK_RECVING_QUEUE), LOC_TASK_0171);
    return (EC_TRUE);
}

void task_req_handle_thread(TASK_BRD *task_brd, TASK_REQ *task_req)
{
    TASK_RSP   *task_rsp;
    TASK_NODE  *task_rsp_node;

    UINT32      task_rsp_buff_size;

    CROUTINE_CLEANUP_PUSH(/*task_req_free*/task_req_discard, task_req);
    task_rsp = task_req_handle(task_req);
    CROUTINE_CLEANUP_POP(0);

    if(NULL_PTR == task_rsp)
    {
        task_req_free(task_req);
        return;
    }

    if(EC_TRUE == task_req_is_timeout(task_req))
    {
        dbg_log(SEC_0015_TASK, 5)(LOGSTDOUT, "timeout req: from (tcid %s,comm %ld,rank %ld,modi %ld) to (tcid %s,comm %ld,rank %ld,modi %ld) with priority %ld, type %ld, tag %ld, ldb %ld, seqno %lx.%lx.%lx, subseqno %ld, func id %lx\n",
                        TASK_REQ_SEND_TCID_STR(task_req), TASK_REQ_SEND_COMM(task_req), TASK_REQ_SEND_RANK(task_req), TASK_REQ_SEND_MODI(task_req),
                        TASK_REQ_RECV_TCID_STR(task_req),TASK_REQ_RECV_COMM(task_req), TASK_REQ_RECV_RANK(task_req), TASK_REQ_RECV_MODI(task_req),
                        TASK_REQ_PRIO(task_req), TASK_REQ_TYPE(task_req),
                        TASK_REQ_TAG(task_req), TASK_REQ_LDB_CHOICE(task_req),
                        TASK_REQ_SEND_TCID(task_req), TASK_REQ_SEND_RANK(task_req), TASK_REQ_SEQNO(task_req), TASK_REQ_SUB_SEQNO(task_req),
                        TASK_REQ_FUNC_ID(task_req)
                        );

        task_req_free(task_req);
        task_rsp_free(task_rsp);

        return;
    }

    /*compute the task rsp left time_to_live by task req*/
    TASK_RSP_TIME_TO_LIVE(task_rsp) = task_req_time_left(task_req);

    cload_stat_clone(TASK_BRD_CLOAD_STAT(task_brd), TASK_RSP_CLOAD_STAT(task_rsp));

    /*ACT or DEA*/
    if(TASK_ACT_TYPE == TASK_RSP_TYPE(task_rsp) || TASK_DEA_TYPE == TASK_RSP_TYPE(task_rsp))
    {
        task_context_handle(task_brd, task_rsp);
    }

    task_rsp_node = TASK_RSP_NODE(task_rsp);
    task_rsp_encode_size(task_rsp, TASK_RSP_FUNC_ADDR_NODE(task_rsp), &task_rsp_buff_size);
    task_node_buff_alloc(task_rsp_node, task_rsp_buff_size);
    task_rsp_encode(task_rsp);

    TASK_NODE_STATUS(task_rsp_node) = TASK_RSP_TO_SEND;
    /*TASK_TO_SEND_QUEUE support task priority, here add node by task_queue_add_node*/
    task_queue_add_node(TASK_BRD_QUEUE(task_brd, TASK_TO_SEND_QUEUE), task_rsp_node);

    /*update load info when isend task_rsp*/
    load_set_when_task_rsp_isend(task_brd, task_rsp);/*no idea regarding mod_mgr here*/

    /*free task req from board is_recv queue*/
    task_req_free(task_req);
    return;
}

/*note: only task_req/task_fwd will come into the queue TASK_IS_RECV_QUEUE*/
EC_BOOL task_brd_is_recv_queue_handle(TASK_BRD *task_brd)
{
    CLIST_DATA *clist_data;

    CLIST_LOCK(TASK_BRD_QUEUE(task_brd, TASK_IS_RECV_QUEUE), LOC_TASK_0172);
    CLIST_LOOP_NEXT(TASK_BRD_QUEUE(task_brd, TASK_IS_RECV_QUEUE), clist_data)
    {
        TASK_NODE  *task_node;

        task_node = (TASK_NODE *)CLIST_DATA_DATA(clist_data);

        switch(TASK_NODE_TAG(task_node))
        {
            case TAG_TASK_REQ:
            {
                TASK_REQ   *task_req;

                TASK_NODE  *task_req_node;

                task_req_node = task_node;
                task_req = TASK_NODE_REQ(task_req_node);

                if(EC_TRUE == task_req_is_timeout(task_req))
                {
                    CLIST_DATA *clist_data_rmv;

                    clist_data_rmv = clist_data;
                    clist_data = CLIST_DATA_PREV(clist_data);
                    clist_rmv_no_lock(TASK_BRD_QUEUE(task_brd, TASK_IS_RECV_QUEUE), clist_data_rmv);

                    dbg_log(SEC_0015_TASK, 5)(LOGSTDOUT, "timeout req: from (tcid %s,comm %ld,rank %ld,modi %ld) to (tcid %s,comm %ld,rank %ld,modi %ld) with priority %ld, type %ld, tag %ld, ldb %ld, seqno %lx.%lx.%lx, subseqno %ld, func id %lx\n",
                                    TASK_REQ_SEND_TCID_STR(task_req), TASK_REQ_SEND_COMM(task_req), TASK_REQ_SEND_RANK(task_req), TASK_REQ_SEND_MODI(task_req),
                                    TASK_REQ_RECV_TCID_STR(task_req),TASK_REQ_RECV_COMM(task_req), TASK_REQ_RECV_RANK(task_req), TASK_REQ_RECV_MODI(task_req),
                                    TASK_REQ_PRIO(task_req), TASK_REQ_TYPE(task_req),
                                    TASK_REQ_TAG(task_req), TASK_REQ_LDB_CHOICE(task_req),
                                    TASK_REQ_SEND_TCID(task_req), TASK_REQ_SEND_RANK(task_req), TASK_REQ_SEQNO(task_req), TASK_REQ_SUB_SEQNO(task_req),
                                    TASK_REQ_FUNC_ID(task_req)
                                    );

                    task_req_free(task_req);

                    break;
                }

#if (SWITCH_ON == TASK_REQ_HANDLE_THREAD_SWITCH)
#if 0
                /*for debug only!*/
                if(NULL_PTR != TASK_REQ_CTHREAD_NODE(task_req))
                {
                    /*note: when TASK_REQ_DECODE_THREAD_SWITCH is switch on, TASK_REQ_CTHREAD_NODE(task_req) should not be null*/
                    dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "[DBG] error: TASK_REQ_CTHREAD_NODE(task_req) %lx is not null\n", TASK_REQ_CTHREAD_NODE(task_req));
                }
#endif
                //dbg_log(SEC_0015_TASK, 9)(LOGSTDOUT, "[DEBUG] task_brd_is_recv_queue_handle: thread try to load...\n");

                //dbg_log(SEC_0015_TASK, 9)(LOGSTDOUT, "[DEBUG] task_brd_is_recv_queue_handle: croutine_pool_load: task_brd %p, task_node %p\n", task_brd, task_node);

                TASK_REQ_CTHREAD_NODE(task_req) = croutine_pool_load(TASK_REQ_CTHREAD_POOL(task_brd),
                                                                (UINT32)task_req_handle_thread,
                                                                (UINT32)2,
                                                                (UINT32)task_brd,
                                                                (UINT32)task_req
                                                                );
                //dbg_log(SEC_0015_TASK, 9)(LOGSTDOUT, "[DEBUG] task_brd_is_recv_queue_handle: routine loaded %lx\n", TASK_REQ_CTHREAD_NODE(task_req));
                if(NULL_PTR != TASK_REQ_CTHREAD_NODE(task_req))
                {
                    CLIST_DATA *clist_data_rmv;

                    clist_data_rmv = clist_data;
                    clist_data = CLIST_DATA_PREV(clist_data);
                    clist_rmv_no_lock(TASK_BRD_QUEUE(task_brd, TASK_IS_RECV_QUEUE), clist_data_rmv);
                    //dbg_log(SEC_0015_TASK, 9)(LOGSTDOUT, "[DEBUG] task_brd_is_recv_queue_handle: try to set thread loaded %lx to busy\n", TASK_REQ_CTHREAD_NODE(task_req));
                    //dbg_log(SEC_0015_TASK, 9)(LOGSTDOUT, "[DEBUG] task_brd_is_recv_queue_handle: set thread loaded %lx to busy done\n", TASK_REQ_CTHREAD_NODE(task_req));
                    CROUTINE_NODE_COND_RELEASE(TASK_REQ_CTHREAD_NODE(task_req), LOC_TASK_0173);
                }
#endif/*(SWITCH_ON == TASK_REQ_HANDLE_THREAD_SWITCH)*/

                break;
            }
#if 1
            case TAG_TASK_FWD:
            {
                TASK_FWD   *task_fwd;

                TASK_NODE  *task_fwd_node;

                task_fwd_node = task_node;
                task_fwd = TASK_NODE_FWD(task_fwd_node);

                if(EC_TRUE == task_fwd_is_to_local(task_brd, task_fwd))
                {
                    CLIST_DATA *clist_data_rmv;

                    clist_data_rmv = clist_data;
                    clist_data = CLIST_DATA_PREV(clist_data);
                    clist_rmv_no_lock(TASK_BRD_QUEUE(task_brd, TASK_IS_RECV_QUEUE), clist_data_rmv);

                    task_fwd_direct(task_brd, task_fwd);
                }
                else
                {
                    if(EC_TRUE == task_fwd_isend(task_brd, task_fwd))
                    {
                        CLIST_DATA *clist_data_rmv;

                        clist_data_rmv = clist_data;
                        clist_data = CLIST_DATA_PREV(clist_data);
                        clist_rmv_no_lock(TASK_BRD_QUEUE(task_brd, TASK_IS_RECV_QUEUE), clist_data_rmv);

                        TASK_NODE_STATUS(task_fwd_node) = TASK_FWD_SENDING;

                        /*commit task fwd to board sending queue*/
                        /*note: TASK_SENDING_QUEUE not support task priority due to it causes disordered transmission*/
                        /*hence the only to add node is by push operation*/
                        clist_push_back(TASK_BRD_QUEUE(task_brd, TASK_SENDING_QUEUE), (void *)task_fwd_node);
                    }
                    else
                    {
                        CLIST_DATA *clist_data_rmv;

                        clist_data_rmv = clist_data;
                        clist_data = CLIST_DATA_PREV(clist_data);
                        clist_rmv_no_lock(TASK_BRD_QUEUE(task_brd, TASK_IS_RECV_QUEUE), clist_data_rmv);

                        dbg_log(SEC_0015_TASK, 3)(LOGSTDOUT, "disc fwd: from (tcid %s,comm %ld,rank %ld,modi %ld) to (tcid %s,comm %ld,rank %ld,modi %ld) with priority %ld, type %ld, tag %ld, ldb %ld, seqno %lx.%lx.%lx, subseqno %ld, func id %lx\n",
                                TASK_NODE_SEND_TCID_STR(task_node), TASK_NODE_SEND_COMM(task_node), TASK_NODE_SEND_RANK(task_node), TASK_NODE_SEND_MODI(task_node),
                                TASK_NODE_RECV_TCID_STR(task_node), TASK_NODE_RECV_COMM(task_node), TASK_NODE_RECV_RANK(task_node), TASK_NODE_RECV_MODI(task_node),
                                TASK_NODE_PRIO(task_node), TASK_NODE_TYPE(task_node),
                                TASK_NODE_TAG(task_node), TASK_NODE_LDB_CHOICE(task_node),
                                TASK_NODE_SEND_TCID(task_node), TASK_NODE_SEND_RANK(task_node), TASK_NODE_SEQNO(task_node), TASK_NODE_SUB_SEQNO(task_node),
                                TASK_NODE_FUNC_ID(task_node)
                            );

                        task_fwd_free(task_fwd);
                    }
                }

                break;
            }
#endif
        }
    }

    CLIST_UNLOCK(TASK_BRD_QUEUE(task_brd, TASK_IS_RECV_QUEUE), LOC_TASK_0174);
    return (EC_TRUE);
}

UINT32 task_mgr_time_elapsed(const TASK_MGR *task_mgr)
{
    CTIMET cur;

    if(TASK_ALWAYS_LIVE == TASK_MGR_TIME_TO_LIVE(task_mgr))
    {
        /*never elapsed*/
        return (0);
    }

    CTIMET_GET(cur);
    return lrint(CTIMET_DIFF(TASK_MGR_START_TIME_SEC(task_mgr), cur));
}

UINT32 task_mgr_time_left(const TASK_MGR *task_mgr)
{
    CTIMET cur;

    if(TASK_ALWAYS_LIVE == TASK_MGR_TIME_TO_LIVE(task_mgr))
    {
        return (TASK_ALWAYS_LIVE);
    }

    CTIMET_GET(cur);
    return (TASK_MGR_TIME_TO_LIVE(task_mgr) - lrint(CTIMET_DIFF(TASK_MGR_START_TIME_SEC(task_mgr), cur)));
}

EC_BOOL task_mgr_is_timeout(const TASK_MGR *task_mgr)
{
    CTIMET cur;

    if(TASK_ALWAYS_LIVE == TASK_MGR_TIME_TO_LIVE(task_mgr))
    {
        /*never timeout*/
        return (EC_FALSE);
    }

    CTIMET_GET(cur);

    if(CTIMET_DIFF(TASK_MGR_START_TIME_SEC(task_mgr), cur) >= 0.0 + TASK_MGR_TIME_TO_LIVE(task_mgr))
    {
        /*time out*/
        return (EC_TRUE);
    }

    /*not timeout*/
    return (EC_FALSE);
}

EC_BOOL task_mgr_encode(TASK_BRD *task_brd, TASK_MGR *task_mgr)
{
    CLIST      *task_queue;
    CLIST_DATA *clist_data;

    task_queue = TASK_MGR_QUEUE(task_mgr);

    CLIST_LOCK(task_queue, LOC_TASK_0175);
    CLIST_LOOP_NEXT(task_queue, clist_data)
    {
        TASK_NODE    *task_node;
        TASK_REQ     *task_req;
        UINT32        buff_size;

        task_node = (TASK_NODE *)CLIST_DATA_DATA(clist_data);
        ASSERT(TAG_TASK_REQ == TASK_NODE_TAG(task_node));

        task_req = TASK_NODE_REQ(task_node);

        task_req_encode_size(task_req, &buff_size);
        task_node_buff_alloc(task_node, buff_size);
        task_req_encode(task_req);
    }

    CLIST_UNLOCK(task_queue, LOC_TASK_0176);
    return (EC_TRUE);
}

EC_BOOL task_mgr_send(TASK_BRD *task_brd, TASK_MGR *task_mgr)
{
    CLIST      *task_queue;
    CLIST_DATA *clist_data;

    task_queue = TASK_MGR_QUEUE(task_mgr);

    CLIST_LOCK(task_queue, LOC_TASK_0177);
    CLIST_LOOP_NEXT(task_queue, clist_data)
    {
        TASK_NODE    *task_node;

        task_node    = (TASK_NODE *)CLIST_DATA_DATA(clist_data);

        if(TAG_TASK_REQ != TASK_NODE_TAG(task_node))
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_mgr_send: unknown task node tag %ld\n", TASK_NODE_TAG(task_node));
            dbg_log(SEC_0015_TASK, 5)(LOGSTDOUT, "invalid node: from (tcid %s,comm %ld,rank %ld,modi %ld) to (tcid %s,comm %ld,rank %ld,modi %ld) with priority %ld, type %ld, tag %ld, ldb %ld, seqno %lx.%lx.%lx, subseqno %ld, func id %lx\n",
                            TASK_NODE_SEND_TCID_STR(task_node), TASK_NODE_SEND_COMM(task_node), TASK_NODE_SEND_RANK(task_node), TASK_NODE_SEND_MODI(task_node),
                            TASK_NODE_RECV_TCID_STR(task_node), TASK_NODE_RECV_COMM(task_node), TASK_NODE_RECV_RANK(task_node), TASK_NODE_RECV_MODI(task_node),
                            TASK_NODE_PRIO(task_node), TASK_NODE_TYPE(task_node),
                            TASK_NODE_TAG(task_node), TASK_NODE_LDB_CHOICE(task_node),
                            TASK_NODE_SEND_TCID(task_node), TASK_NODE_SEND_RANK(task_node), TASK_NODE_SEQNO(task_node), TASK_NODE_SUB_SEQNO(task_node),
                            TASK_NODE_FUNC_ID(task_node)
                            );
            continue;
        }

        if(TASK_REQ_TIMEOUT == TASK_NODE_STATUS(task_node))
        {
            continue;
        }

        if(TASK_REQ_DISCARD == TASK_NODE_STATUS(task_node))
        {
            continue;
        }

        if( TASK_REQ_TO_SEND == TASK_NODE_STATUS(task_node) )
        {
            TASK_REQ   *task_req;
            EC_BOOL     ret;

            if(EC_TRUE == task_mgr_is_timeout(task_mgr))
            {
                /*the first version: count timeout req on discard req num*/
                TASK_MGR_COUNTER_INC_BY_TASK_REQ(task_mgr, TASK_MGR_COUNTER_TASK_REQ_TIMEOUT, TASK_NODE_REQ(task_node), LOC_TASK_0178);

                TASK_NODE_STATUS(task_node) = TASK_REQ_TIMEOUT;
                load_set_when_task_req_is_sent(task_brd, TASK_NODE_REQ(task_node));/*decrease rank load after sent out if not need rsp*/
                continue;
            }

            task_req = TASK_NODE_REQ(task_node);

            if(EC_FALSE == task_req_ldb(task_req))
            {
                dbg_log(SEC_0015_TASK, 5)(LOGSTDOUT, "discard req: from (tcid %s,comm %ld,rank %ld,modi %ld) to (tcid %s,comm %ld,rank %ld,modi %ld) with priority %ld, type %ld, tag %ld, ldb %ld, seqno %lx.%lx.%lx, subseqno %ld, func id %lx\n",
                                TASK_REQ_SEND_TCID_STR(task_req), TASK_REQ_SEND_COMM(task_req), TASK_REQ_SEND_RANK(task_req), TASK_REQ_SEND_MODI(task_req),
                                TASK_REQ_RECV_TCID_STR(task_req), TASK_REQ_RECV_COMM(task_req), TASK_REQ_RECV_RANK(task_req), TASK_REQ_RECV_MODI(task_req),
                                TASK_REQ_PRIO(task_req), TASK_REQ_TYPE(task_req),
                                TASK_REQ_TAG(task_req), TASK_REQ_LDB_CHOICE(task_req),
                                TASK_REQ_SEND_TCID(task_req), TASK_REQ_SEND_RANK(task_req), TASK_REQ_SEQNO(task_req), TASK_REQ_SUB_SEQNO(task_req),
                                TASK_REQ_FUNC_ID(task_req)
                                );
                TASK_MGR_COUNTER_INC_BY_TASK_REQ(task_mgr, TASK_MGR_COUNTER_TASK_REQ_DISCARD, TASK_NODE_REQ(task_node), LOC_TASK_0179);

                TASK_NODE_STATUS(task_node) = TASK_REQ_DISCARD;
                continue;
            }

            /*compute the task req left time_to_live by task mgr*/
            TASK_REQ_TIME_TO_LIVE(task_req) = task_mgr_time_left(task_mgr);

            task_req_encode_header(task_req);/*need to encode header only*/

            ret = task_req_isend(task_brd, task_req);
            if(EC_FALSE == ret)
            {
                TASK_MGR_COUNTER_INC_BY_TASK_REQ(TASK_REQ_MGR(task_req), TASK_MGR_COUNTER_TASK_REQ_DISCARD, task_req, LOC_TASK_0180);

                TASK_NODE_STATUS(task_node) = TASK_REQ_DISCARD;

                dbg_log(SEC_0015_TASK, 5)(LOGSTDOUT, "disc  req: from (tcid %s,comm %ld,rank %ld,modi %ld) to (tcid %s,comm %ld,rank %ld,modi %ld) with priority %ld, type %ld, tag %ld, ldb %ld, seqno %lx.%lx.%lx, subseqno %ld, func id %lx when SENDING\n",
                                TASK_REQ_SEND_TCID_STR(task_req), TASK_REQ_SEND_COMM(task_req), TASK_REQ_SEND_RANK(task_req), TASK_REQ_SEND_MODI(task_req),
                                TASK_REQ_RECV_TCID_STR(task_req), TASK_REQ_RECV_COMM(task_req), TASK_REQ_RECV_RANK(task_req), TASK_REQ_RECV_MODI(task_req),
                                TASK_REQ_PRIO(task_req), TASK_REQ_TYPE(task_req),
                                TASK_REQ_TAG(task_req), TASK_REQ_LDB_CHOICE(task_req),
                                TASK_REQ_SEND_TCID(task_req), TASK_REQ_SEND_RANK(task_req), TASK_REQ_SEQNO(task_req), TASK_REQ_SUB_SEQNO(task_req),
                                TASK_REQ_FUNC_ID(task_req)
                                );
                continue;
            }

            if(EC_AGAIN == ret)
            {
                TASK_NODE_STATUS(task_node) = TASK_REQ_SENDAGN;

                dbg_log(SEC_0015_TASK, 5)(LOGSTDOUT, "again req: from (tcid %s,comm %ld,rank %ld,modi %ld) to (tcid %s,comm %ld,rank %ld,modi %ld) with priority %ld, type %ld, tag %ld, ldb %ld, seqno %lx.%lx.%lx, subseqno %ld, func id %lx when SENDING\n",
                                TASK_REQ_SEND_TCID_STR(task_req), TASK_REQ_SEND_COMM(task_req), TASK_REQ_SEND_RANK(task_req), TASK_REQ_SEND_MODI(task_req),
                                TASK_REQ_RECV_TCID_STR(task_req), TASK_REQ_RECV_COMM(task_req), TASK_REQ_RECV_RANK(task_req), TASK_REQ_RECV_MODI(task_req),
                                TASK_REQ_PRIO(task_req), TASK_REQ_TYPE(task_req),
                                TASK_REQ_TAG(task_req), TASK_REQ_LDB_CHOICE(task_req),
                                TASK_REQ_SEND_TCID(task_req), TASK_REQ_SEND_RANK(task_req), TASK_REQ_SEQNO(task_req), TASK_REQ_SUB_SEQNO(task_req),
                                TASK_REQ_FUNC_ID(task_req)
                                );
                continue;
            }

            TASK_NODE_STATUS(task_node) = TASK_REQ_SENDING;

            /*update load info when isend task_req*/
            load_set_when_task_req_isend(task_brd, task_req);
        }
#if 1
        if( TASK_REQ_SENDAGN == TASK_NODE_STATUS(task_node) )
        {
            TASK_REQ   *task_req;
            EC_BOOL     ret;

            if(EC_TRUE == task_mgr_is_timeout(task_mgr))
            {
                /*the first version: count timeout req on discard req num*/
                TASK_MGR_COUNTER_INC_BY_TASK_REQ(task_mgr, TASK_MGR_COUNTER_TASK_REQ_TIMEOUT, TASK_NODE_REQ(task_node), LOC_TASK_0181);

                TASK_NODE_STATUS(task_node) = TASK_REQ_TIMEOUT;
                load_set_when_task_req_is_sent(task_brd, TASK_NODE_REQ(task_node));/*decrease rank load after sent out if not need rsp*/
                continue;
            }

            task_req = TASK_NODE_REQ(task_node);
            ret = task_req_isend(task_brd, task_req);
            if(EC_FALSE == ret)
            {
                TASK_MGR_COUNTER_INC_BY_TASK_REQ(TASK_REQ_MGR(task_req), TASK_MGR_COUNTER_TASK_REQ_DISCARD, task_req, LOC_TASK_0182);

                TASK_NODE_STATUS(task_node) = TASK_REQ_DISCARD;

                dbg_log(SEC_0015_TASK, 5)(LOGSTDOUT, "disc  req: from (tcid %s,comm %ld,rank %ld,modi %ld) to (tcid %s,comm %ld,rank %ld,modi %ld) with priority %ld, type %ld, tag %ld, ldb %ld, seqno %lx.%lx.%lx, subseqno %ld, func id %lx when SENDING\n",
                                TASK_REQ_SEND_TCID_STR(task_req), TASK_REQ_SEND_COMM(task_req), TASK_REQ_SEND_RANK(task_req), TASK_REQ_SEND_MODI(task_req),
                                TASK_REQ_RECV_TCID_STR(task_req), TASK_REQ_RECV_COMM(task_req), TASK_REQ_RECV_RANK(task_req), TASK_REQ_RECV_MODI(task_req),
                                TASK_REQ_PRIO(task_req), TASK_REQ_TYPE(task_req),
                                TASK_REQ_TAG(task_req), TASK_REQ_LDB_CHOICE(task_req),
                                TASK_REQ_SEND_TCID(task_req), TASK_REQ_SEND_RANK(task_req), TASK_REQ_SEQNO(task_req), TASK_REQ_SUB_SEQNO(task_req),
                                TASK_REQ_FUNC_ID(task_req)
                                );
                continue;
            }

            if(EC_AGAIN == ret)
            {
                continue;
            }

            TASK_NODE_STATUS(task_node) = TASK_REQ_SENDING;

            /*update load info when isend task_req*/
            load_set_when_task_req_isend(task_brd, task_req);
        }
#endif
        if( TASK_REQ_SENDING == TASK_NODE_STATUS(task_node) )
        {
            //dbg_log(SEC_0015_TASK, 5)(LOGSTDOUT, "task_mgr_send: check one sending request ....\n");
            if((TASK_NODE_BUFF_POS(task_node) == TASK_NODE_BUFF_LEN(task_node)) && TASK_WAS_SENT == TASK_NODE_COMP(task_node))
            {
                task_node_buff_free(task_node); /*okay, free buff as early as possible*/
                TASK_NODE_STATUS(task_node) = TASK_REQ_IS_SENT;

                TASK_MGR_COUNTER_INC_BY_TASK_REQ(task_mgr, TASK_MGR_COUNTER_TASK_REQ_IS_SENT, TASK_NODE_REQ(task_node), LOC_TASK_0183);

                if(TASK_NOT_NEED_RSP_FLAG == TASK_MGR_NEED_RSP_FLAG(task_mgr))
                {
                    TASK_NODE_STATUS(task_node) = TASK_RSP_IS_RECV;/*trick*/

                    load_set_when_task_req_is_sent(task_brd, TASK_NODE_REQ(task_node));/*decrease rank load after sent out if not need rsp*/
                }
            }
        }

        if( TASK_REQ_IS_SENT == TASK_NODE_STATUS(task_node) )
        {
            TASK_NODE_CMUTEX_LOCK(task_node, LOC_TASK_0184);
            if(TASK_REQ_IS_SENT == TASK_NODE_STATUS(task_node)/*double check for thread safe*/
            && EC_TRUE == task_mgr_is_timeout(task_mgr)
            )
            {
                TASK_MGR_COUNTER_DEC_BY_TASK_REQ(task_mgr, TASK_MGR_COUNTER_TASK_REQ_IS_SENT, TASK_NODE_REQ(task_node), LOC_TASK_0185);
                TASK_MGR_COUNTER_INC_BY_TASK_REQ(task_mgr, TASK_MGR_COUNTER_TASK_REQ_TIMEOUT, TASK_NODE_REQ(task_node), LOC_TASK_0186);

                TASK_NODE_STATUS(task_node) = TASK_REQ_TIMEOUT;
            }
            TASK_NODE_CMUTEX_UNLOCK(task_node, LOC_TASK_0187);
        }
    }

    CLIST_UNLOCK(task_queue, LOC_TASK_0188);
    return (EC_TRUE);
}

EC_BOOL task_mgr_check(TASK_MGR *task_mgr)
{
    CLIST      *task_queue;
    CLIST_DATA *clist_data;

    UINT32 count[7] = {0,0,0,0,0,0,0};

    task_queue = TASK_MGR_QUEUE(task_mgr);

    CLIST_LOCK(task_queue, LOC_TASK_0189);
    CLIST_LOOP_NEXT(task_queue, clist_data)
    {
        TASK_NODE    *task_node;

        task_node    = (TASK_NODE *)CLIST_DATA_DATA(clist_data);

        if(TASK_REQ_TO_SEND == TASK_NODE_STATUS(task_node))
        {
            count[ 0 ] ++;
            continue;
        }

        if( TASK_REQ_SENDING == TASK_NODE_STATUS(task_node) )
        {
            count[ 1 ] ++;
            continue;
        }

        if( TASK_REQ_RECVING == TASK_NODE_STATUS(task_node) )
        {
            count[ 2 ] ++;
            continue;
        }
        if( TASK_REQ_IS_SENT == TASK_NODE_STATUS(task_node) )
        {
            count[ 3 ] ++;
            continue;
        }

        if( TASK_REQ_IS_RECV == TASK_NODE_STATUS(task_node) )
        {
            count[ 4 ] ++;
            continue;
        }
        if( TASK_REQ_DISCARD == TASK_NODE_STATUS(task_node) )
        {
            count[ 5 ] ++;
            continue;
        }

        if( TASK_REQ_TIMEOUT == TASK_NODE_STATUS(task_node) )
        {
            count[ 6 ] ++;
            continue;
        }
    }
    CLIST_UNLOCK(task_queue, LOC_TASK_0190);
    dbg_log(SEC_0015_TASK, 5)(LOGSTDOUT, "to_send %ld, sending %ld, recving %ld, is_sent %ld, is_recv %ld, discard %ld, timeout %ld\n",
                        count[0], count[1], count[2], count[3], count[4], count[5], count[6]);
    return (EC_TRUE);
}

EC_BOOL task_mgr_recv(TASK_MGR *task_mgr)
{
    UINT32 task_req_num;

    UINT32 need_rsp_num;
    UINT32 succ_rsp_num;
    UINT32 fail_rsp_num;

    UINT32 sent_req_num;
    UINT32 discard_req_num;
    UINT32 timeout_req_num;

    task_req_num = clist_size(TASK_MGR_QUEUE(task_mgr));

    TASK_MGR_CRWLOCK_RDLOCK(task_mgr, LOC_TASK_0191);
    need_rsp_num    = TASK_MGR_COUNTER(task_mgr, TASK_MGR_COUNTER_TASK_RSP_IS_NEED);
    succ_rsp_num    = TASK_MGR_COUNTER(task_mgr, TASK_MGR_COUNTER_TASK_RSP_IS_SUCC);
    fail_rsp_num    = TASK_MGR_COUNTER(task_mgr, TASK_MGR_COUNTER_TASK_RSP_IS_FAIL);

    sent_req_num    = TASK_MGR_COUNTER(task_mgr, TASK_MGR_COUNTER_TASK_REQ_IS_SENT);
    discard_req_num = TASK_MGR_COUNTER(task_mgr, TASK_MGR_COUNTER_TASK_REQ_DISCARD);
    timeout_req_num = TASK_MGR_COUNTER(task_mgr, TASK_MGR_COUNTER_TASK_REQ_TIMEOUT);

    TASK_MGR_CRWLOCK_UNLOCK(task_mgr, LOC_TASK_0192);

    if(TASK_NOT_NEED_RSP_FLAG == TASK_MGR_NEED_RSP_FLAG(task_mgr) && TASK_NEED_NONE_RSP == need_rsp_num)
    {
        if(task_req_num <= sent_req_num)
        {
            return (EC_TRUE);
        }

        if(task_req_num <= sent_req_num + discard_req_num + timeout_req_num)
        {
            dbg_log(SEC_0015_TASK, 1)(LOGSTDOUT, "warn:task_mgr_recv: %ld task req not need rsp, %ld req sent, but %ld req discarded, %ld req timeout\n",
                               task_req_num, sent_req_num, discard_req_num, timeout_req_num);

            return (EC_TRUE);
        }
        return (EC_FALSE);
    }

    if(TASK_NEED_RSP_FLAG == TASK_MGR_NEED_RSP_FLAG(task_mgr))
    {
        if(TASK_NEED_ALL_RSP == need_rsp_num)
        {
            if(task_req_num <= succ_rsp_num)
            {
                return (EC_TRUE);
            }

            if(task_req_num <= succ_rsp_num + fail_rsp_num + discard_req_num + timeout_req_num)
            {
                dbg_log(SEC_0015_TASK, 1)(LOGSTDOUT, "warn:task_mgr_recv: %ld task req need all rsp, %ld rsp succ, but %ld rsp fail, %ld req discarded, %ld req timeout\n",
                                   task_req_num, succ_rsp_num, fail_rsp_num, discard_req_num, timeout_req_num);
                return (EC_TRUE);
            }

            /*debug! had better wait task req timeout but not task mgr, seems the counters have issue, need more investigation*/
            if(EC_TRUE == task_mgr_is_timeout(task_mgr))
            {
                dbg_log(SEC_0015_TASK, 1)(LOGSTDOUT, "warn:task_mgr_recv: task_mgr %p timeout, need_rsp_num %ld, while %ld task req, %ld rsp succ, %ld rsp fail, %ld req discarded, %ld req timeout\n",
                                   task_mgr, need_rsp_num,
                                   task_req_num, succ_rsp_num, fail_rsp_num, discard_req_num, timeout_req_num);
                return (EC_TRUE);
            }

            dbg_log(SEC_0015_TASK, 9)(LOGSTDOUT, "[false:1] task_mgr_recv: %ld task req need %ld rsp, %ld rsp succ, but %ld rsp fail, %ld req discarded, %ld req timeout\n",
                               task_req_num, need_rsp_num, succ_rsp_num, fail_rsp_num, discard_req_num, timeout_req_num);
            return (EC_FALSE);
        }

        if(need_rsp_num <= succ_rsp_num)
        {
            return (EC_TRUE);
        }

        if(task_req_num <= succ_rsp_num + fail_rsp_num + discard_req_num + timeout_req_num)
        {
            dbg_log(SEC_0015_TASK, 1)(LOGSTDOUT, "warn:task_mgr_recv: %ld task req need %ld rsp, %ld rsp succ, but %ld rsp fail, %ld req discarded, %ld req timeout\n",
                               task_req_num, need_rsp_num, succ_rsp_num, fail_rsp_num, discard_req_num, timeout_req_num);
            return (EC_TRUE);
        }

        /*debug! had better wait task req timeout but not task mgr, seems the counters have issue, need more investigation*/
        if(EC_TRUE == task_mgr_is_timeout(task_mgr))
        {
            dbg_log(SEC_0015_TASK, 1)(LOGSTDOUT, "warn:task_mgr_recv: task_mgr %p timeout, need_rsp_num %ld, while %ld task req, %ld rsp succ, %ld rsp fail, %ld req discarded, %ld req timeout\n",
                               task_mgr, need_rsp_num,
                               task_req_num, succ_rsp_num, fail_rsp_num, discard_req_num, timeout_req_num);
            return (EC_TRUE);
        }

        dbg_log(SEC_0015_TASK, 9)(LOGSTDOUT, "[false:2] task_mgr_recv: %ld task req need %ld rsp, %ld rsp succ, but %ld rsp fail, %ld req discarded, %ld req timeout\n",
                           task_req_num, need_rsp_num, succ_rsp_num, fail_rsp_num, discard_req_num, timeout_req_num);

        return (EC_FALSE);
    }

    dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_mgr_recv: invalid map (need_rsp_flag %ld, need_rsp_num %ld) while %ld task req, %ld rsp succ, but %ld rsp fail, %ld req discarded, %ld req timeout\n",
                       TASK_MGR_NEED_RSP_FLAG(task_mgr), need_rsp_num,
                       task_req_num, succ_rsp_num, fail_rsp_num, discard_req_num, timeout_req_num);

    return (EC_FALSE);
}

EC_BOOL task_mgr_reschedule_to(TASK_BRD *task_brd, TASK_MGR *task_mgr, const UINT32 tcid)
{
    CLIST      *task_queue;
    CLIST_DATA *clist_data;

    task_queue = TASK_MGR_QUEUE(task_mgr);

    CLIST_LOCK(task_queue, LOC_TASK_0193);
    CLIST_LOOP_NEXT(task_queue, clist_data)
    {
        TASK_NODE  *task_node;
        TASK_REQ   *task_req;

        task_node = (TASK_NODE *)CLIST_DATA_DATA(clist_data);

        if(TAG_TASK_REQ != TASK_NODE_TAG(task_node))
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_mgr_reschedule_to: unknown task node tag %ld\n", TASK_NODE_TAG(task_node));
            continue;
        }

        /*only the TASK_REQ which did not recv reponse as well as apply load balancing need to re-schedule*/
        if( tcid != TASK_NODE_RECV_TCID(task_node)
         || TASK_RSP_IS_RECV == TASK_NODE_STATUS(task_node)
         || TASK_REQ_TIMEOUT == TASK_NODE_STATUS(task_node)
         || TASK_REQ_DISCARD == TASK_NODE_STATUS(task_node)
         )
        {
            continue;
        }

        /*if apply load balancing strategy, then reschedule it*/
        task_req = TASK_NODE_REQ(task_node);
        if(EC_TRUE == TASK_REQ_RECV_MOD_FLAG(task_req))
        {
            TASK_REQ *task_req;

            /*note: we did not change the seqno/subseqno info of the TASK_REQ*/
            task_node_buff_free(task_node); /*okay, free old buff if exist*/
            TASK_NODE_STATUS(task_node) = TASK_REQ_TO_SEND;

            /*rollback num of sent req of task mgr when reschedule happen*/
            TASK_MGR_COUNTER_DEC_BY_TASK_REQ(task_mgr, TASK_MGR_COUNTER_TASK_REQ_IS_SENT, TASK_NODE_REQ(task_node), LOC_TASK_0194);

            task_req = TASK_NODE_REQ(task_node);

            dbg_log(SEC_0015_TASK, 5)(LOGSTDOUT, "resch  req: from (tcid %s,comm %ld,rank %ld,modi %ld) to (tcid %s,comm %ld,rank %ld,modi %ld) with priority %ld, type %ld, tag %ld, ldb %ld, seqno %lx.%lx.%lx, subseqno %ld, func id %lx\n",
                            TASK_REQ_SEND_TCID_STR(task_req), TASK_REQ_SEND_COMM(task_req), TASK_REQ_SEND_RANK(task_req), TASK_REQ_SEND_MODI(task_req),
                            TASK_REQ_RECV_TCID_STR(task_req), TASK_REQ_RECV_COMM(task_req), TASK_REQ_RECV_RANK(task_req), TASK_REQ_RECV_MODI(task_req),
                            TASK_REQ_PRIO(task_req), TASK_REQ_TYPE(task_req),
                            TASK_REQ_TAG(task_req), TASK_REQ_LDB_CHOICE(task_req),
                            TASK_REQ_SEND_TCID(task_req), TASK_REQ_SEND_RANK(task_req), TASK_REQ_SEQNO(task_req), TASK_REQ_SUB_SEQNO(task_req),
                            TASK_REQ_FUNC_ID(task_req)
                            );
        }
        /*otherwise, discard the whole task_mgr*/
        else
        {
            /*return false and caller should free task_mgr*/
            CLIST_UNLOCK(task_queue, LOC_TASK_0195);
            return (EC_FALSE);
        }
    }

    CLIST_UNLOCK(task_queue, LOC_TASK_0196);
    return (EC_TRUE);
}

EC_BOOL task_mgr_discard_to(TASK_BRD *task_brd, TASK_MGR *task_mgr, const UINT32 tcid)
{
    CLIST      *task_queue;
    CLIST_DATA *clist_data;

    task_queue = TASK_MGR_QUEUE(task_mgr);

    CLIST_LOCK(task_queue, LOC_TASK_0197);
    CLIST_LOOP_NEXT(task_queue, clist_data)
    {
        TASK_NODE  *task_node;

        task_node = (TASK_NODE *)CLIST_DATA_DATA(clist_data);

        if(TAG_TASK_REQ != TASK_NODE_TAG(task_node))
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_mgr_discard_to: unknown task node tag %ld\n", TASK_NODE_TAG(task_node));
            continue;
        }

        /*only the TASK_REQ which did not recv reponse as well as apply load balancing need to discard*/
        if( tcid != TASK_NODE_RECV_TCID(task_node)
         || TASK_RSP_IS_RECV == TASK_NODE_STATUS(task_node)
         || TASK_REQ_DISCARD == TASK_NODE_STATUS(task_node)
         || TASK_REQ_TIMEOUT == TASK_NODE_STATUS(task_node)
        )
        {
            continue;
        }

        task_node_buff_free(task_node); /*okay, free old buff if exist*/

        if(TASK_REQ_SENDING == TASK_NODE_STATUS(task_node))
        {
            TASK_REQ *task_req;

            TASK_MGR_COUNTER_INC_BY_TASK_REQ(task_mgr, TASK_MGR_COUNTER_TASK_REQ_DISCARD, TASK_NODE_REQ(task_node), LOC_TASK_0198);

            TASK_NODE_STATUS(task_node) = TASK_REQ_DISCARD;

            task_req = TASK_NODE_REQ(task_node);
            dbg_log(SEC_0015_TASK, 5)(LOGSTDOUT, "disc  req: from (tcid %s,comm %ld,rank %ld,modi %ld) to (tcid %s,comm %ld,rank %ld,modi %ld) with priority %ld, type %ld, tag %ld, ldb %ld, seqno %lx.%lx.%lx, subseqno %ld, func id %lx when SENDING\n",
                            TASK_REQ_SEND_TCID_STR(task_req), TASK_REQ_SEND_COMM(task_req), TASK_REQ_SEND_RANK(task_req), TASK_REQ_SEND_MODI(task_req),
                            TASK_REQ_RECV_TCID_STR(task_req), TASK_REQ_RECV_COMM(task_req), TASK_REQ_RECV_RANK(task_req), TASK_REQ_RECV_MODI(task_req),
                            TASK_REQ_PRIO(task_req), TASK_REQ_TYPE(task_req),
                            TASK_REQ_TAG(task_req), TASK_REQ_LDB_CHOICE(task_req),
                            TASK_REQ_SEND_TCID(task_req), TASK_REQ_SEND_RANK(task_req), TASK_REQ_SEQNO(task_req), TASK_REQ_SUB_SEQNO(task_req),
                            TASK_REQ_FUNC_ID(task_req)
                            );
            continue;
        }

        if(TASK_REQ_SENDAGN == TASK_NODE_STATUS(task_node))/*Feb 11, 2018*/
        {
            TASK_REQ *task_req;

            TASK_MGR_COUNTER_INC_BY_TASK_REQ(task_mgr, TASK_MGR_COUNTER_TASK_REQ_DISCARD, TASK_NODE_REQ(task_node), LOC_TASK_0199);

            TASK_NODE_STATUS(task_node) = TASK_REQ_DISCARD;

            task_req = TASK_NODE_REQ(task_node);
            dbg_log(SEC_0015_TASK, 5)(LOGSTDOUT, "disc  req: from (tcid %s,comm %ld,rank %ld,modi %ld) to (tcid %s,comm %ld,rank %ld,modi %ld) with priority %ld, type %ld, tag %ld, ldb %ld, seqno %lx.%lx.%lx, subseqno %ld, func id %lx when SENDING\n",
                            TASK_REQ_SEND_TCID_STR(task_req), TASK_REQ_SEND_COMM(task_req), TASK_REQ_SEND_RANK(task_req), TASK_REQ_SEND_MODI(task_req),
                            TASK_REQ_RECV_TCID_STR(task_req), TASK_REQ_RECV_COMM(task_req), TASK_REQ_RECV_RANK(task_req), TASK_REQ_RECV_MODI(task_req),
                            TASK_REQ_PRIO(task_req), TASK_REQ_TYPE(task_req),
                            TASK_REQ_TAG(task_req), TASK_REQ_LDB_CHOICE(task_req),
                            TASK_REQ_SEND_TCID(task_req), TASK_REQ_SEND_RANK(task_req), TASK_REQ_SEQNO(task_req), TASK_REQ_SUB_SEQNO(task_req),
                            TASK_REQ_FUNC_ID(task_req)
                            );
            continue;
        }

        TASK_NODE_CMUTEX_LOCK(task_node, LOC_TASK_0200);
        if(TASK_REQ_IS_SENT == TASK_NODE_STATUS(task_node))
        {
            TASK_REQ *task_req;

            TASK_MGR_COUNTER_DEC_BY_TASK_REQ(task_mgr, TASK_MGR_COUNTER_TASK_REQ_IS_SENT, TASK_NODE_REQ(task_node), LOC_TASK_0201);
            TASK_MGR_COUNTER_INC_BY_TASK_REQ(task_mgr, TASK_MGR_COUNTER_TASK_REQ_DISCARD, TASK_NODE_REQ(task_node), LOC_TASK_0202);

            TASK_NODE_STATUS(task_node) = TASK_REQ_DISCARD;

            task_req = TASK_NODE_REQ(task_node);
            dbg_log(SEC_0015_TASK, 5)(LOGSTDOUT, "disc  req: from (tcid %s,comm %ld,rank %ld,modi %ld) to (tcid %s,comm %ld,rank %ld,modi %ld) with priority %ld, type %ld, tag %ld, ldb %ld, seqno %lx.%lx.%lx, subseqno %ld, func id %lx when IS_SENT\n",
                            TASK_REQ_SEND_TCID_STR(task_req), TASK_REQ_SEND_COMM(task_req), TASK_REQ_SEND_RANK(task_req), TASK_REQ_SEND_MODI(task_req),
                            TASK_REQ_RECV_TCID_STR(task_req), TASK_REQ_RECV_COMM(task_req), TASK_REQ_RECV_RANK(task_req), TASK_REQ_RECV_MODI(task_req),
                            TASK_REQ_PRIO(task_req), TASK_REQ_TYPE(task_req),
                            TASK_REQ_TAG(task_req), TASK_REQ_LDB_CHOICE(task_req),
                            TASK_REQ_SEND_TCID(task_req), TASK_REQ_SEND_RANK(task_req), TASK_REQ_SEQNO(task_req), TASK_REQ_SUB_SEQNO(task_req),
                            TASK_REQ_FUNC_ID(task_req)
                            );

            TASK_NODE_CMUTEX_UNLOCK(task_node, LOC_TASK_0203);
            continue;
        }
        TASK_NODE_CMUTEX_UNLOCK(task_node, LOC_TASK_0204);
    }

    CLIST_UNLOCK(task_queue, LOC_TASK_0205);
    return (EC_TRUE);
}

EC_BOOL task_mgr_print(LOG *log, TASK_MGR *task_mgr)
{
    CLIST      *task_queue;
    CLIST_DATA *clist_data;

    UINT32 idx;

    task_queue = TASK_MGR_QUEUE(task_mgr);

    idx = 0;

    CLIST_LOCK(task_queue, LOC_TASK_0206);
    CLIST_LOOP_NEXT(task_queue, clist_data)
    {
        TASK_NODE  *task_node;
        TASK_REQ   *task_req;

        task_node = (TASK_NODE *)CLIST_DATA_DATA(clist_data);

        if(TAG_TASK_REQ != TASK_NODE_TAG(task_node))
        {
            sys_log(log, "error:task_mgr_print: unknown task node tag %ld\n", TASK_NODE_TAG(task_node));

            idx ++;
            continue;
        }

        task_req = TASK_NODE_REQ(task_node);

        sys_log(log, "[task_mgr %lx, task_queue %lx] No. %ld: node tag %ld, node status %ld: (tcid %s,comm %ld,rank %ld,modi %ld) -> (tcid %s,comm %ld,rank %ld,modi %ld),tag %ld,seqno %lx.%lx.%lx,subseqno %ld: func id %lx\n",
                        task_mgr, task_queue, idx, TASK_NODE_TAG(task_node), TASK_NODE_STATUS(task_node),
                        TASK_REQ_SEND_TCID_STR(task_req), TASK_REQ_SEND_COMM(task_req), TASK_REQ_SEND_RANK(task_req), TASK_REQ_SEND_MODI(task_req),
                        TASK_REQ_RECV_TCID_STR(task_req), TASK_REQ_RECV_COMM(task_req), TASK_REQ_RECV_RANK(task_req), TASK_REQ_RECV_MODI(task_req),
                        TASK_REQ_TAG(task_req),
                        TASK_REQ_SEND_TCID(task_req), TASK_REQ_SEND_RANK(task_req), TASK_REQ_SEQNO(task_req), TASK_REQ_SUB_SEQNO(task_req),
                        TASK_REQ_FUNC_ID(task_req)
                );
        idx ++;
    }

    CLIST_UNLOCK(task_queue, LOC_TASK_0207);
    return (EC_TRUE);
}

void task_brd_send_task_mgr_list(TASK_BRD *task_brd)
{
    CLIST      *task_mgr_list;
    CLIST_DATA *clist_data;

    task_mgr_list = TASK_BRD_RECV_TASK_MGR_LIST(task_brd);

    CLIST_LOCK(task_mgr_list, LOC_TASK_0208);

    /*handle one of existing task req and task rsp*/
    CLIST_LOOP_NEXT(task_mgr_list, clist_data)
    {
        TASK_MGR *task_mgr;

        task_mgr = (TASK_MGR *)CLIST_DATA_DATA(clist_data);

        /*sending task req*/
        task_mgr_send(task_brd, task_mgr);
    }

    CLIST_UNLOCK(task_mgr_list, LOC_TASK_0209);
    return;
}

void task_brd_recv_task_mgr_list(TASK_BRD *task_brd)
{
    CLIST      *task_mgr_list;
    CLIST_DATA *clist_data;

    task_mgr_list = TASK_BRD_RECV_TASK_MGR_LIST(task_brd);

    CLIST_LOCK(task_mgr_list, LOC_TASK_0210);

    /*handle one of existing task req and task rsp*/
    CLIST_LOOP_NEXT(task_mgr_list, clist_data)
    {
        TASK_MGR *task_mgr;

        task_mgr = (TASK_MGR *)CLIST_DATA_DATA(clist_data);
#if 0
        if(task_mgr != TASK_BRD_STACK_MGR_STACK_TOP(task_brd))
        {
            continue;
        }
#endif
        /*handle recved task req or task rsp*/
        /*note: task_mgr_recv return EC_TRUE does not mean all responses are collected successfully,*/
        /*it means only no more response to wait for. the user should distinguish collection succeed or not*/
        if(EC_TRUE == task_mgr_recv(task_mgr))
        {
            CLIST_DATA *clist_data_rmv;

            clist_data_rmv = clist_data;
            clist_data = CLIST_DATA_PREV(clist_data);
            clist_rmv_no_lock(task_mgr_list, clist_data_rmv);

            TASK_MGR_RECVING_FLAG(task_mgr) = EC_FALSE;

            CTIMEOFDAY_GET(TASK_MGR_END_TIME(task_mgr));

            if(EC_TRUE == TASK_MGR_JMP_FLAG(task_mgr))
            {
                TASK_MGR_CCOND_RELEASE(task_mgr, LOC_TASK_0211);
            }
            else
            {
                task_brd_report_list_add(task_brd, task_mgr);

                task_brd_aging_list_add(task_brd, task_mgr);/*move to aging task mgr list*/
            }
        }
    }

    CLIST_UNLOCK(task_mgr_list, LOC_TASK_0212);
    return;
}

void task_brd_aging_task_mgr_list(TASK_BRD *task_brd)
{
    CLIST      *task_mgr_list;
    CLIST_DATA *clist_data;

    task_mgr_list = TASK_BRD_AGING_TASK_MGR_LIST(task_brd);

    CLIST_LOCK(task_mgr_list, LOC_TASK_0213);
    CLIST_LOOP_NEXT(task_mgr_list, clist_data)
    {
        TASK_MGR *task_mgr;

        task_mgr = (TASK_MGR *)CLIST_DATA_DATA(clist_data);
        if(NULL_PTR == task_mgr)
        {
            CLIST_DATA *clist_data_rmv;
            clist_data_rmv = clist_data;
            clist_data = CLIST_DATA_PREV(clist_data);
            clist_rmv_no_lock(task_mgr_list, clist_data_rmv);
            continue;
        }

        if(EC_TRUE == TASK_MGR_RECVING_FLAG(task_mgr))
        {
            continue;
        }

        if(0 == TASK_MGR_COUNTER(task_mgr, TASK_MGR_COUNTER_TASK_RSP_RESERVD)/* && EC_TRUE == task_mgr_recv(task_mgr)*/)
        {
            CLIST_DATA *clist_data_rmv;
            clist_data_rmv = clist_data;
            clist_data = CLIST_DATA_PREV(clist_data);
            clist_rmv_no_lock(task_mgr_list, clist_data_rmv);
            task_mgr_free(task_mgr);
        }
        else
        {
            //dbg_log(SEC_0015_TASK, 5)(LOGSTDOUT, "task_brd_aging_task_mgr_list: task_mgr %lx  reserved by %ld threads\n", task_mgr, TASK_MGR_COUNTER(task_mgr, TASK_MGR_COUNTER_TASK_RSP_RESERVD));
        }
    }

    CLIST_UNLOCK(task_mgr_list, LOC_TASK_0214);
    return;
}

EC_BOOL task_brd_heartbeat_once(TASK_BRD *task_brd)
{
    UINT32 fastdec_heartbeat_interval;

    fastdec_heartbeat_interval = (UINT32)RANK_HEARTBEAT_FASTDEC_INTVL_NSEC;

    //dbg_log(SEC_0015_TASK, 9)(LOGSTDOUT, "[DEBUG] task_brd_heartbeat_once: was called\n");

    if(1)
    {
        /*update current rank load info to rank load table*/
        cload_mgr_set(TASK_BRD_CLOAD_MGR(task_brd), TASK_BRD_TCID(task_brd), TASK_BRD_RANK(task_brd), TASK_BRD_CLOAD_STAT(task_brd));

        if(SWITCH_ON == RANK_HEARTBEAT_FASTDEC_SWITCH)
        {
            task_brd_rank_load_tbl_fast_decrease(task_brd, fastdec_heartbeat_interval);
        }

        /*share load info of current taskcomm in current taskcomm*/
        if(CMPI_FWD_RANK == TASK_BRD_RANK(task_brd) && 1 < TASK_BRD_SIZE(task_brd)
        && (SWITCH_ON == RANK_HEARTBEAT_ALL_SWITCH) && (SWITCH_ON == RANK_HEARTBEAT_FWD_SWITCH))
        {
            TASK_MGR *task_mgr;

            MOD_NODE send_mod_node;
            MOD_NODE recv_mod_node;
            UINT32   rank;

            MOD_NODE_TCID(&send_mod_node) = TASK_BRD_TCID(task_brd);
            MOD_NODE_COMM(&send_mod_node) = TASK_BRD_COMM(task_brd);
            MOD_NODE_RANK(&send_mod_node) = TASK_BRD_RANK(task_brd);
            MOD_NODE_MODI(&send_mod_node) = 0;
            MOD_NODE_HOPS(&send_mod_node) = 0;
            MOD_NODE_LOAD(&send_mod_node) = 0;

            task_mgr = task_new(NULL_PTR, TASK_PRIO_HIGH, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP);
            for(rank = 0; rank < TASK_BRD_SIZE(task_brd); rank ++)
            {
                if(CMPI_FWD_RANK == rank)/*skip fwd rank self*/
                {
                    continue;
                }

                MOD_NODE_TCID(&recv_mod_node) = TASK_BRD_TCID(task_brd);
                MOD_NODE_COMM(&recv_mod_node) = TASK_BRD_COMM(task_brd);
                MOD_NODE_RANK(&recv_mod_node) = rank;
                MOD_NODE_MODI(&recv_mod_node) = 0;
                MOD_NODE_HOPS(&recv_mod_node) = 0;
                MOD_NODE_LOAD(&recv_mod_node) = 0;

                task_super_inc(task_mgr, &send_mod_node, &recv_mod_node,
                                NULL_PTR, FI_super_heartbeat_all, CMPI_ERROR_MODI, TASK_BRD_CLOAD_MGR(task_brd));
            }
            task_no_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);
        }

        /*send load info of current rank to fwd rank*/
        if(CMPI_FWD_RANK != TASK_BRD_RANK(task_brd) && (SWITCH_ON == RANK_HEARTBEAT_FWD_SWITCH))
        {
            TASK_MGR *task_mgr;
            MOD_NODE send_mod_node;
            MOD_NODE recv_mod_node;

            MOD_NODE_TCID(&send_mod_node) = TASK_BRD_TCID(task_brd);
            MOD_NODE_COMM(&send_mod_node) = TASK_BRD_COMM(task_brd);
            MOD_NODE_RANK(&send_mod_node) = TASK_BRD_RANK(task_brd);
            MOD_NODE_MODI(&send_mod_node) = 0;
            MOD_NODE_HOPS(&send_mod_node) = 0;
            MOD_NODE_LOAD(&send_mod_node) = 0;

            MOD_NODE_TCID(&recv_mod_node) = TASK_BRD_TCID(task_brd);
            MOD_NODE_COMM(&recv_mod_node) = TASK_BRD_COMM(task_brd);
            MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
            MOD_NODE_MODI(&recv_mod_node) = 0;
            MOD_NODE_HOPS(&recv_mod_node) = 0;
            MOD_NODE_LOAD(&recv_mod_node) = 0;

            task_mgr = task_new(NULL_PTR, TASK_PRIO_HIGH, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP);
            task_super_inc(task_mgr, &send_mod_node, &recv_mod_node,
                           NULL_PTR, FI_super_heartbeat_on_rank, CMPI_ERROR_MODI,
                           TASK_BRD_TCID(task_brd), TASK_BRD_RANK(task_brd), TASK_BRD_CLOAD_STAT(task_brd));
            task_no_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);
        }
    }
    return (EC_TRUE);
}

EC_BOOL task_brd_heartbeat(TASK_BRD *task_brd)
{
    UINT32 update_heartbeat_interval;
    UINT32 fastdec_heartbeat_interval;

    CTIMET last_update;

    CTIMET_GET(last_update);
    update_heartbeat_interval  = (UINT32)CLOAD_HEARTBEAT_INTVL_NSEC;
    fastdec_heartbeat_interval = (UINT32)RANK_HEARTBEAT_FASTDEC_INTVL_NSEC;

    for(;;)
    {
        CTIMET cur;
        UINT32 elapsed_time_from_last_update;

        dbg_log(SEC_0015_TASK, 9)(LOGSTDOUT, "[DEBUG] task_brd_heartbeat: looping\n");

        CTIMET_GET(cur);

        elapsed_time_from_last_update = lrint(CTIMET_DIFF(last_update, cur));
        if(update_heartbeat_interval > elapsed_time_from_last_update)
        {
            //sched_yield();
            c_sleep(1, LOC_TASK_0215);/*fuck, maybe can use timer to trigger*/
            continue;
        }

        CTIMET_GET(last_update);

        /*update current rank load info to rank load table*/
        cload_mgr_set(TASK_BRD_CLOAD_MGR(task_brd), TASK_BRD_TCID(task_brd), TASK_BRD_RANK(task_brd), TASK_BRD_CLOAD_STAT(task_brd));

        if(SWITCH_ON == RANK_HEARTBEAT_FASTDEC_SWITCH)
        {
            task_brd_rank_load_tbl_fast_decrease(task_brd, fastdec_heartbeat_interval);
        }

        /*share load info of current taskcomm in current taskcomm*/
        if(CMPI_FWD_RANK == TASK_BRD_RANK(task_brd) && (SWITCH_ON == RANK_HEARTBEAT_ALL_SWITCH) && (SWITCH_ON == RANK_HEARTBEAT_FWD_SWITCH))
        {
            TASK_MGR *task_mgr;

            MOD_NODE send_mod_node;
            MOD_NODE recv_mod_node;
            UINT32   rank;

            MOD_NODE_TCID(&send_mod_node) = TASK_BRD_TCID(task_brd);
            MOD_NODE_COMM(&send_mod_node) = TASK_BRD_COMM(task_brd);
            MOD_NODE_RANK(&send_mod_node) = TASK_BRD_RANK(task_brd);
            MOD_NODE_MODI(&send_mod_node) = 0;
            MOD_NODE_HOPS(&send_mod_node) = 0;
            MOD_NODE_LOAD(&send_mod_node) = 0;

            task_mgr = task_new(NULL_PTR, TASK_PRIO_HIGH, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP);
            for(rank = 0; rank < TASK_BRD_SIZE(task_brd); rank ++)
            {
                if(CMPI_FWD_RANK == rank)/*skip fwd rank self*/
                {
                    continue;
                }

                MOD_NODE_TCID(&recv_mod_node) = TASK_BRD_TCID(task_brd);
                MOD_NODE_COMM(&recv_mod_node) = TASK_BRD_COMM(task_brd);
                MOD_NODE_RANK(&recv_mod_node) = rank;
                MOD_NODE_MODI(&recv_mod_node) = 0;
                MOD_NODE_HOPS(&recv_mod_node) = 0;
                MOD_NODE_LOAD(&recv_mod_node) = 0;

                task_super_inc(task_mgr, &send_mod_node, &recv_mod_node,
                                NULL_PTR, FI_super_heartbeat_all, CMPI_ERROR_MODI, TASK_BRD_CLOAD_MGR(task_brd));
            }
            task_no_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);
        }

        /*send load info of current rank to fwd rank*/
        if(CMPI_FWD_RANK != TASK_BRD_RANK(task_brd) && (SWITCH_ON == RANK_HEARTBEAT_FWD_SWITCH))
        {
            TASK_MGR *task_mgr;
            MOD_NODE send_mod_node;
            MOD_NODE recv_mod_node;

            MOD_NODE_TCID(&send_mod_node) = TASK_BRD_TCID(task_brd);
            MOD_NODE_COMM(&send_mod_node) = TASK_BRD_COMM(task_brd);
            MOD_NODE_RANK(&send_mod_node) = TASK_BRD_RANK(task_brd);
            MOD_NODE_MODI(&send_mod_node) = 0;
            MOD_NODE_HOPS(&send_mod_node) = 0;
            MOD_NODE_LOAD(&send_mod_node) = 0;

            MOD_NODE_TCID(&recv_mod_node) = TASK_BRD_TCID(task_brd);
            MOD_NODE_COMM(&recv_mod_node) = TASK_BRD_COMM(task_brd);
            MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
            MOD_NODE_MODI(&recv_mod_node) = 0;
            MOD_NODE_HOPS(&recv_mod_node) = 0;
            MOD_NODE_LOAD(&recv_mod_node) = 0;

            task_mgr = task_new(NULL_PTR, TASK_PRIO_HIGH, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP);
            task_super_inc(task_mgr, &send_mod_node, &recv_mod_node,
                           NULL_PTR, FI_super_heartbeat_on_rank, CMPI_ERROR_MODI,
                           TASK_BRD_TCID(task_brd), TASK_BRD_RANK(task_brd), TASK_BRD_CLOAD_STAT(task_brd));
            task_no_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);
        }
    }
    return (EC_TRUE);
}

EC_BOOL task_brd_cload_stat_collect(TASK_BRD *task_brd)
{
    CLOAD_STAT *cload_stat;

    cload_stat = TASK_BRD_CLOAD_STAT(task_brd);
    CLOAD_STAT_QUE_LOAD(cload_stat) = (UINT16)task_brd_que_load(task_brd);
    CLOAD_STAT_OBJ_LOAD(cload_stat) = (UINT16)task_brd_obj_load(task_brd);
    CLOAD_STAT_CPU_LOAD(cload_stat) = (UINT8 )task_brd_cpu_load(task_brd);
    CLOAD_STAT_MEM_LOAD(cload_stat) = (UINT8 )task_brd_mem_load(task_brd);
    CLOAD_STAT_DSK_LOAD(cload_stat) = (UINT8 )task_brd_dsk_load(task_brd);
    CLOAD_STAT_NET_LOAD(cload_stat) = (UINT8 )task_brd_net_load(task_brd);

    return (EC_TRUE);
}

EC_BOOL task_brd_cload_stat_update_once(TASK_BRD *task_brd)
{
    dbg_log(SEC_0015_TASK, 9)(LOGSTDOUT, "[DEBUG] task_brd_cload_stat_update_once: was called\n");
    task_brd_cload_stat_collect(task_brd);

    /*update current rank load info to rank load table*/
    cload_mgr_set(TASK_BRD_CLOAD_MGR(task_brd), TASK_BRD_TCID(task_brd), TASK_BRD_RANK(task_brd), TASK_BRD_CLOAD_STAT(task_brd));
    return (EC_TRUE);
}

EC_BOOL task_brd_cload_stat_update(TASK_BRD *task_brd)
{
    UINT32 cload_stat_update_interval;

    CTIMET last_update;

    CTIMET_GET(last_update);
    cload_stat_update_interval  = (UINT32)CLOAD_STAT_UPDATE_INTVL_NSEC;

    for(;;)
    {
        CTIMET cur;
        UINT32 elapsed_time_from_last_update;

        CTIMET_GET(cur);

        elapsed_time_from_last_update = lrint(CTIMET_DIFF(last_update, cur));
        if(cload_stat_update_interval > elapsed_time_from_last_update)
        {
            //sched_yield();
            c_sleep(1, LOC_TASK_0216);/*fuck, maybe can use timer to trigger*/
            continue;
        }

        CTIMET_GET(last_update);

        task_brd_cload_stat_collect(task_brd);

        /*update current rank load info to rank load table*/
        cload_mgr_set(TASK_BRD_CLOAD_MGR(task_brd), TASK_BRD_TCID(task_brd), TASK_BRD_RANK(task_brd), TASK_BRD_CLOAD_STAT(task_brd));
    }
    return (EC_TRUE);
}

EC_BOOL task_brd_cpu_avg_stat_update_once(TASK_BRD *task_brd)
{
    dbg_log(SEC_0015_TASK, 9)(LOGSTDOUT, "[DEBUG] task_brd_cpu_avg_stat_update_once: was called\n");
    csys_cpu_avg_stat_get(TASK_BRD_CPU_AVG_STAT(task_brd));
    return (EC_TRUE);
}

#if 1 /*http server*/
EC_BOOL task_brd_start_http_srv(TASK_BRD *task_brd, const UINT32 http_srv_ipaddr, const UINT32 http_srv_port)
{
    if(NULL_PTR != TASK_BRD_CSRV(task_brd))
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_start_http_srv: csrv is already working as server at %s:%ld on sockfd %d\n",
                            c_word_to_ipv4(CSRV_IPADDR(TASK_BRD_CSRV(task_brd))),
                            CSRV_PORT(TASK_BRD_CSRV(task_brd)),
                            CSRV_SOCKFD(TASK_BRD_CSRV(task_brd)));
        return (EC_FALSE);
    }

    TASK_BRD_CSRV(task_brd) = chttp_srv_start(http_srv_ipaddr, http_srv_port, CMPI_ANY_MODI);
    if(NULL_PTR == TASK_BRD_CSRV(task_brd))
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_start_http_srv: start chttp srv failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0015_TASK, 5)(LOGSTDOUT, "task_brd_start_http_srv: start server %s:%ld\n",
                    c_word_to_ipv4(http_srv_ipaddr), http_srv_port);

    return (EC_TRUE);
}

EC_BOOL task_brd_default_start_http_srv(const UINT32 http_srv_ipaddr, const UINT32 http_srv_port)
{
    TASK_BRD *task_brd;

    task_brd = task_brd_default_get();
    return task_brd_start_http_srv(task_brd, http_srv_ipaddr, http_srv_port);
}


EC_BOOL task_brd_stop_http_srv(TASK_BRD *task_brd)
{
    if(NULL_PTR != TASK_BRD_CSRV(task_brd))
    {
        chttp_srv_end(TASK_BRD_CSRV(task_brd));
        TASK_BRD_CSRV(task_brd) = NULL_PTR;
    }

    return (EC_TRUE);
}

EC_BOOL task_brd_default_stop_http_srv()
{
    TASK_BRD *task_brd;

    task_brd = task_brd_default_get();
    return task_brd_stop_http_srv(task_brd);
}

EC_BOOL task_brd_bind_http_srv_modi(TASK_BRD *task_brd, const UINT32 modi)
{
    if(NULL_PTR != TASK_BRD_CSRV(task_brd))
    {
        chttp_srv_bind_modi(TASK_BRD_CSRV(task_brd), modi);
    }

    return (EC_TRUE);
}

EC_BOOL task_brd_default_bind_http_srv_modi(const UINT32 modi)
{
    TASK_BRD *task_brd;

    task_brd = task_brd_default_get();
    return task_brd_bind_http_srv_modi(task_brd, modi);
}
#endif


#if 1 /*https server demo*/
EC_BOOL task_brd_start_https_srv(TASK_BRD *task_brd, const UINT32 https_srv_ipaddr, const UINT32 https_srv_port)
{
    if(NULL_PTR != TASK_BRD_CSRV(task_brd))
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_start_https_srv: TASK_BRD_CSRV is already working as server at %s:%ld on sockfd %d\n",
                            c_word_to_ipv4(CSRV_IPADDR(TASK_BRD_CSRV(task_brd))),
                            CSRV_PORT(TASK_BRD_CSRV(task_brd)),
                            CSRV_SOCKFD(TASK_BRD_CSRV(task_brd)));
        return (EC_FALSE);
    }

    TASK_BRD_CSRV(task_brd) = chttps_srv_start(https_srv_ipaddr, https_srv_port, CMPI_ANY_MODI);
    if(NULL_PTR == TASK_BRD_CSRV(task_brd))
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_start_https_srv: start chttps srv failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0015_TASK, 5)(LOGSTDOUT, "task_brd_start_https_srv: start server at port %ld\n", https_srv_port);

    return (EC_TRUE);
}

EC_BOOL task_brd_default_start_https_srv(const UINT32 https_srv_ipaddr, const UINT32 https_srv_port)
{
    TASK_BRD *task_brd;

    task_brd = task_brd_default_get();
    return task_brd_start_https_srv(task_brd, https_srv_ipaddr, https_srv_port);
}

EC_BOOL task_brd_stop_https_srv(TASK_BRD *task_brd)
{
    if(NULL_PTR != TASK_BRD_CSRV(task_brd))
    {
        chttps_srv_end(TASK_BRD_CSRV(task_brd));
        TASK_BRD_CSRV(task_brd) = NULL_PTR;
    }

    return (EC_TRUE);
}

EC_BOOL task_brd_default_stop_https_srv()
{
    TASK_BRD *task_brd;

    task_brd = task_brd_default_get();
    return task_brd_stop_https_srv(task_brd);
}

EC_BOOL task_brd_bind_https_srv_modi(TASK_BRD *task_brd, const UINT32 modi)
{
    if(NULL_PTR != TASK_BRD_CSRV(task_brd))
    {
        chttps_srv_bind_modi(TASK_BRD_CSRV(task_brd), modi);
    }

    return (EC_TRUE);
}

EC_BOOL task_brd_default_bind_https_srv_modi(const UINT32 modi)
{
    TASK_BRD *task_brd;

    task_brd = task_brd_default_get();
    return task_brd_bind_https_srv_modi(task_brd, modi);
}
#endif



EC_BOOL task_brd_start_csrv(TASK_BRD *task_brd, const UINT32 md_id, const UINT32 srv_ipaddr, const UINT32 csrv_port)
{
    if(NULL_PTR != TASK_BRD_CSRV(task_brd))
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_start_csrv: TASK_BRD_CSRV is already working as server at %s:%ld on sockfd %d\n",
                            c_word_to_ipv4(CSRV_IPADDR(TASK_BRD_CSRV(task_brd))),
                            CSRV_PORT(TASK_BRD_CSRV(task_brd)),
                            CSRV_SOCKFD(TASK_BRD_CSRV(task_brd)));
        return (EC_FALSE);
    }

    TASK_BRD_CSRV(task_brd) = csrv_start(srv_ipaddr, csrv_port, md_id);
    if(NULL_PTR == TASK_BRD_CSRV(task_brd))
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_start_csrv: start csrv on port %ld failed\n", csrv_port);
        return (EC_FALSE);
    }
    dbg_log(SEC_0015_TASK, 5)(LOGSTDOUT, "task_brd_start_csrv: start server at port %ld\n", csrv_port);
    return (EC_TRUE);
}

EC_BOOL task_brd_default_start_csrv()
{
    TASK_BRD *task_brd;

    task_brd = task_brd_default_get();
    return task_brd_start_csrv(task_brd, 0, task_brd_default_get_srv_ipaddr(), task_brd_default_get_csrv_port());
}

EC_BOOL task_brd_default_stop_srvs()
{
    TASK_BRD  *task_brd;
    TASKS_CFG *tasks_cfg;

    task_brd = task_brd_default_get();

    task_brd_stop_http_srv(task_brd);

    tasks_cfg = TASK_BRD_LOCAL_TASKS_CFG(task_brd);
    tasks_srv_end(tasks_cfg);

    return (EC_TRUE);
}

EC_BOOL task_brd_default_stop_logs()
{
    sys_log_redirect_setup(LOGSTDOUT , LOGSTDNULL);
    sys_log_redirect_setup(LOGSTDERR , LOGSTDNULL);
    sys_log_redirect_setup(LOGCONSOLE, LOGSTDNULL);
    sys_log_redirect_setup(LOGUSER09 , LOGSTDNULL);
    sys_log_redirect_setup(LOGUSER08 , LOGSTDNULL);
    sys_log_redirect_setup(LOGUSER07 , LOGSTDNULL);
    sys_log_redirect_setup(LOGUSER06 , LOGSTDNULL);
    sys_log_redirect_setup(LOGUSER05 , LOGSTDNULL);

    return (EC_TRUE);
}

EC_BOOL task_brd_set_abort(TASK_BRD *task_brd)
{
    return cproc_abort(TASK_BRD_CPROC(task_brd));
}

void task_brd_set_abort_default()
{
    cproc_abort_default();
    return;
}

EC_BOOL task_brd_net_add_runner(const UINT32 tcid, const UINT32 mask_nbits, const UINT32 rank, const char * name, TASK_RUNNER_FUNC runner, void *arg)
{
    TASK_BRD *task_brd;
    CSTACK   *task_brd_runner_stack;

    UINT32    mask;

    task_brd = task_brd_default_get();
    task_brd_runner_stack = TASK_BRD_RUNNER_STACK(task_brd);

    mask     = BITS_TO_MASK(mask_nbits);

    if(
        ((tcid & mask) == (TASK_BRD_TCID(task_brd) & mask))
     && (rank == TASK_BRD_RANK(task_brd) || CMPI_ANY_RANK == rank)
     )
    {
        TASK_RUNNER_NODE *task_runner_node;

        task_runner_node = task_runner_node_new();
        if(NULL_PTR == task_runner_node)
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error: task_brd_net_add_runner: new task_runner_node for tcid %s rank %ld runner '%s' failed\n",
                               TASK_BRD_TCID_STR(task_brd), TASK_BRD_RANK(task_brd), name);
            return (EC_FALSE);
        }

        TASK_RUNNER_NODE_NAME(task_runner_node) = name;
        TASK_RUNNER_NODE_EXEC(task_runner_node) = runner;
        TASK_RUNNER_NODE_ARG(task_runner_node)  = arg;

        cstack_push(task_brd_runner_stack, task_runner_node);

        dbg_log(SEC_0015_TASK, 5)(LOGSTDOUT, "task_brd_default_add_runner: tcid %s rank %ld runner set to '%s'\n",
                           TASK_BRD_TCID_STR(task_brd), TASK_BRD_RANK(task_brd), name);
    }
    return (EC_TRUE);
}

EC_BOOL task_brd_range_add_runner(const UINT32 tcid_fr, const UINT32 tcid_to, const UINT32 rank, const char * name, TASK_RUNNER_FUNC runner, void *arg)
{
    TASK_BRD *task_brd;
    CSTACK   *task_brd_runner_stack;

    task_brd = task_brd_default_get();
    task_brd_runner_stack = TASK_BRD_RUNNER_STACK(task_brd);

    if(
        (tcid_fr <= TASK_BRD_TCID(task_brd) && TASK_BRD_TCID(task_brd) <= tcid_to)
     && (rank == TASK_BRD_RANK(task_brd) || CMPI_ANY_RANK == rank)
     )
    {
        TASK_RUNNER_NODE *task_runner_node;

        task_runner_node = task_runner_node_new();
        if(NULL_PTR == task_runner_node)
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error: task_brd_range_add_runner: new task_runner_node for tcid %s rank %ld runner '%s' failed\n",
                               TASK_BRD_TCID_STR(task_brd), TASK_BRD_RANK(task_brd), name);
            return (EC_FALSE);
        }

        TASK_RUNNER_NODE_NAME(task_runner_node) = name;
        TASK_RUNNER_NODE_EXEC(task_runner_node) = runner;
        TASK_RUNNER_NODE_ARG(task_runner_node)  = arg;

        cstack_push(task_brd_runner_stack, task_runner_node);

        dbg_log(SEC_0015_TASK, 5)(LOGSTDOUT, "task_brd_range_add_runner: tcid %s rank %ld runner set to '%s'\n",
                           TASK_BRD_TCID_STR(task_brd), TASK_BRD_RANK(task_brd), name);
    }
    return (EC_TRUE);
}

EC_BOOL task_brd_default_add_runner(const UINT32 tcid, const UINT32 rank, const char * name, TASK_RUNNER_FUNC runner, void *arg)
{
    TASK_BRD *task_brd;
    CSTACK   *task_brd_runner_stack;

    task_brd = task_brd_default_get();
    task_brd_runner_stack = TASK_BRD_RUNNER_STACK(task_brd);

    if(
        (tcid == TASK_BRD_TCID(task_brd) || CMPI_ANY_TCID == tcid )
     && (rank == TASK_BRD_RANK(task_brd) || CMPI_ANY_RANK == rank)
     )
    {
        TASK_RUNNER_NODE *task_runner_node;

        task_runner_node = task_runner_node_new();
        if(NULL_PTR == task_runner_node)
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error: task_brd_default_add_runner: new task_runner_node for tcid %s rank %ld runner '%s' failed\n",
                               TASK_BRD_TCID_STR(task_brd), TASK_BRD_RANK(task_brd), name);
            return (EC_FALSE);
        }

        TASK_RUNNER_NODE_NAME(task_runner_node) = name;
        TASK_RUNNER_NODE_EXEC(task_runner_node) = runner;
        TASK_RUNNER_NODE_ARG(task_runner_node)  = arg;

        cstack_push(task_brd_runner_stack, task_runner_node);

        dbg_log(SEC_0015_TASK, 5)(LOGSTDOUT, "task_brd_default_add_runner: tcid %s rank %ld runner set to '%s'\n",
                           TASK_BRD_TCID_STR(task_brd), TASK_BRD_RANK(task_brd), name);
    }
    return (EC_TRUE);
}

EC_BOOL task_brd_default_fork_runner(const UINT32 tcid, const UINT32 rank, const char * name, TASK_RUNNER_FUNC runner, void *arg)
{
    TASK_BRD *task_brd;

    task_brd = task_brd_default_get();

    if(
        (tcid == TASK_BRD_TCID(task_brd) || CMPI_ANY_TCID == tcid )
     && (rank == TASK_BRD_RANK(task_brd) || CMPI_ANY_RANK == rank)
     )
    {
        coroutine_pool_load(TASK_BRD_CROUTINE_POOL(task_brd), (UINT32)runner, (UINT32)1, arg);

        dbg_log(SEC_0015_TASK, 5)(LOGSTDOUT, "task_brd_default_fork_runner: tcid %s rank %ld runner set to '%s'\n",
                           TASK_BRD_TCID_STR(task_brd), TASK_BRD_RANK(task_brd), name);
    }
    return (EC_TRUE);
}

EC_BOOL task_brd_default_start_runner()
{
    TASK_BRD *task_brd;
    CSTACK   *task_brd_runner_stack;

    task_brd = task_brd_default_get();
    task_brd_runner_stack = TASK_BRD_RUNNER_STACK(task_brd);

    while(EC_FALSE == cstack_is_empty(task_brd_runner_stack))
    {
        TASK_RUNNER_NODE *task_runner_node;

        task_runner_node = cstack_pop(task_brd_runner_stack);
        if(NULL_PTR == task_runner_node)
        {
            continue;
        }

        if(NULL_PTR != TASK_RUNNER_NODE_EXEC(task_runner_node))
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "[DEBUG] task_brd_default_start_runner: tcid %s rank %ld runner '%s' launch\n",
                           TASK_BRD_TCID_STR(task_brd), TASK_BRD_RANK(task_brd), TASK_RUNNER_NODE_NAME(task_runner_node));

            TASK_RUNNER_NODE_EXEC(task_runner_node)(TASK_RUNNER_NODE_ARG(task_runner_node));
        }

        task_runner_node_free(task_runner_node);
    }

    return (EC_TRUE);
}

EC_BOOL task_brd_reset_cmutex_all(TASK_BRD *task_brd)
{
    TASK_BRD_SEQNO_CMUTEX_INT(task_brd, LOC_TASK_0217);

    CLIST_INIT_LOCK(CTHREAD_POOL_WORKER_IDLE_LIST(TASK_REQ_CTHREAD_POOL(task_brd)), LOC_TASK_0218);
    CLIST_INIT_LOCK(CTHREAD_POOL_WORKER_BUSY_LIST(TASK_REQ_CTHREAD_POOL(task_brd)), LOC_TASK_0219);

#if (SWITCH_ON == CROUTINE_SUPPORT_CTHREAD_SWITCH)
    cmutex_init(CTHREAD_POOL_WORKER_CMUTEX(TASK_REQ_CTHREAD_POOL(task_brd)), CMUTEX_PROCESS_PRIVATE, LOC_TASK_0220);
#endif/*(SWITCH_ON == CROUTINE_SUPPORT_CTHREAD_SWITCH)*/

    CVECTOR_INIT_LOCK(TASK_BRD_MD_NODE_TBL(task_brd), LOC_TASK_0221);

    CLIST_INIT_LOCK(TASK_BRD_CLOAD_MGR(task_brd), LOC_TASK_0222);
    CVECTOR_INIT_LOCK(TASK_BRD_BROKEN_TCID_TBL(task_brd), LOC_TASK_0223);
    CLIST_INIT_LOCK(TASK_BRD_MOD_MGR_LIST(task_brd), LOC_TASK_0224);

    CLIST_INIT_LOCK(TASK_BRD_RECV_TASK_MGR_LIST(task_brd), LOC_TASK_0225);

    CLIST_INIT_LOCK(TASK_BRD_CONTEXT_LIST(task_brd), LOC_TASK_0226);
    CLIST_INIT_LOCK(TASK_BRD_REPORT_LIST(task_brd), LOC_TASK_0227);

    CLIST_INIT_LOCK(TASK_BRD_QUEUE(task_brd, TASK_RECVING_QUEUE), LOC_TASK_0228);
    CLIST_INIT_LOCK(TASK_BRD_QUEUE(task_brd, TASK_IS_RECV_QUEUE), LOC_TASK_0229);
    CLIST_INIT_LOCK(TASK_BRD_QUEUE(task_brd, TASK_TO_SEND_QUEUE), LOC_TASK_0230);
    CLIST_INIT_LOCK(TASK_BRD_QUEUE(task_brd, TASK_SENDING_QUEUE), LOC_TASK_0231);

    CVECTOR_INIT_LOCK(TASK_BRD_RANK_TBL(task_brd), LOC_TASK_0232);
    CLIST_INIT_LOCK(TASK_BRD_CBTIMER_LIST(task_brd), LOC_TASK_0233);

    return (EC_TRUE);
}

EC_BOOL task_brd_default_reg_md(
                                        const UINT32 md_type, const UINT32 md_capaciy,
                                        const UINT32 *func_num_ptr, const FUNC_ADDR_NODE *func_addr_node,
                                        const UINT32 md_start_func_id, const UINT32 md_end_func_id,
                                        const UINT32 md_set_mod_mgr_func_id, void * (*md_fget_mod_mgr)(const UINT32)
                                        )
{
    TASK_BRD *task_brd;

    task_brd = task_brd_default_get();

    if(EC_FALSE == cbc_md_reg(md_type, md_capaciy))
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_default_reg_md: register md %ld to cbc failed\n", md_type);
        return (EC_FALSE);
    }

    if(EC_FALSE == creg_func_addr_vec_add(TASK_BRD_FUNC_ADDR_VEC(task_brd),
                                        md_type, func_num_ptr, func_addr_node,
                                        md_start_func_id, md_end_func_id,
                                        md_set_mod_mgr_func_id, md_fget_mod_mgr
                                        )
    )
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_default_reg_md: register md %ld to func_addr_vec failed\n", md_type);
        cbc_md_unreg(md_type);
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL task_brd_default_reg_mm(const UINT32 mm_type, const char *mm_name, const UINT32 block_num, const UINT32 type_size)
{
    if(EC_FALSE == creg_static_mem_tbl_add(mm_type, mm_name, block_num, type_size, LOC_TASK_0234))
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_default_reg_mm: register mm %ld to static_mem_tbl failed\n", mm_type);
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL task_brd_default_reg_conv(
             const UINT32 var_dbg_type, const UINT32 var_sizeof, const UINT32 var_pointer_flag, const UINT32 var_mm_type,
             const UINT32 var_init_func, const UINT32 var_clean_func, const UINT32 var_free_func,
             const UINT32 var_encode_func, const UINT32 var_decode_func, const UINT32 var_encode_size
        )
{
    TASK_BRD *task_brd;

    task_brd = task_brd_default_get();

    if(EC_FALSE == creg_type_conv_vec_add(TASK_BRD_TYPE_CONV_VEC(task_brd),
                                         var_dbg_type, var_sizeof, var_pointer_flag, var_mm_type,
                                         var_init_func, var_clean_func, var_free_func,
                                         var_encode_func, var_decode_func, var_encode_size
                                        )
    )
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_brd_default_reg_conv: register type %ld to type_conv_vec failed\n", var_dbg_type);
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL task_brd_enable_slow_down(TASK_BRD *task_brd)
{
    TASK_BRD_ENABLE_SLOW_DOWN(task_brd) = BIT_TRUE;
    return (EC_TRUE);
}

EC_BOOL task_brd_disable_slow_down(TASK_BRD *task_brd)
{
    TASK_BRD_ENABLE_SLOW_DOWN(task_brd) = BIT_FALSE;
    return (EC_TRUE);
}

EC_BOOL task_brd_default_enable_slow_down()
{
    return task_brd_enable_slow_down(task_brd_default_get());
}

EC_BOOL task_brd_default_disable_slow_down()
{
    return task_brd_disable_slow_down(task_brd_default_get());
}

EC_BOOL task_brd_need_slow_down(TASK_BRD *task_brd, LOG *log, UINT32 level)
{
    UINT32 recving_num;
    UINT32 is_recv_num;
    UINT32 to_send_num;
    UINT32 sending_num;
    //UINT32 recv_task_mgr_num;
    UINT32 aging_task_mgr_num;
    UINT32 req_croutine_num;
    UINT32 rsp_croutine_num;
    //UINT32 csocket_cnode_num; /*Feb 4, 2017*/
    EC_BOOL chttp_defer_request_empty_flag;

    recving_num = 0;
    is_recv_num = 0;
    to_send_num = 0;
    sending_num = 0;

    //recv_task_mgr_num  = 0;
    aging_task_mgr_num = 0;

    req_croutine_num = 0;
    rsp_croutine_num = 0;

    chttp_defer_request_empty_flag = EC_TRUE;

    if(
        0 < (recving_num = clist_size(TASK_BRD_QUEUE(task_brd, TASK_RECVING_QUEUE)))
    ||  0 < (is_recv_num = clist_size(TASK_BRD_QUEUE(task_brd, TASK_IS_RECV_QUEUE)))
    ||  0 < (to_send_num = clist_size(TASK_BRD_QUEUE(task_brd, TASK_TO_SEND_QUEUE)))
    ||  0 < (sending_num = clist_size(TASK_BRD_QUEUE(task_brd, TASK_SENDING_QUEUE)))
    /*||  0 < (recv_task_mgr_num = clist_size(TASK_BRD_RECV_TASK_MGR_LIST(task_brd)))*/
    ||  0 < (aging_task_mgr_num = clist_size(TASK_BRD_AGING_TASK_MGR_LIST(task_brd)))
    ||  0 < (req_croutine_num = croutine_pool_busy_num(TASK_REQ_CTHREAD_POOL(task_brd)))
    ||  0 < (rsp_croutine_num = croutine_pool_busy_num(TASK_RSP_CTHREAD_POOL(task_brd)))
    ||  EC_FALSE == (chttp_defer_request_empty_flag = chttp_defer_request_queue_is_empty())
    )
    {
        dbg_log(SEC_0015_TASK, level)(log, "[DEBUG] task_brd_need_slow_down: [N] recving %ld, is_recv %ld, to_send %ld, sending %ld, "
                           //"rcv_task_mgr %ld, "
                           "aging_task_mgr %ld, req routine %ld, rsp routine %ld, http empty flag %s\n",
                            recving_num, is_recv_num, to_send_num, sending_num,
                            //recv_task_mgr_num,
                            aging_task_mgr_num,
                            req_croutine_num, rsp_croutine_num,
                            c_bool_str(chttp_defer_request_empty_flag));
        return (EC_FALSE);/*not need to slow down*/
    }
    else
    {   /*log level is 11 higher than if-branch log level 10 :-)*/
        dbg_log(SEC_0015_TASK, level)(log, "[DEBUG] task_brd_need_slow_down: [Y] recving %ld, is_recv %ld, to_send %ld, sending %ld, "
                           //"rcv_task_mgr %ld, "
                           "aging_task_mgr %ld, req routine %ld, rsp routine %ld, http empty flag %s\n",
                            recving_num, is_recv_num, to_send_num, sending_num,
                            //recv_task_mgr_num,
                            aging_task_mgr_num,
                            req_croutine_num, rsp_croutine_num,
                            c_bool_str(chttp_defer_request_empty_flag));
    }
    return (EC_TRUE);/*could slow down, not MUST-TO, depend on process*/
}

EC_BOOL task_brd_default_need_slow_down()
{
    return task_brd_need_slow_down(task_brd_default_get(), LOGSTDOUT, LOG_LEVEL_NEVER_HAPPEN);
}

uint32_t task_brd_default_ngx_need_slow_down()/*only for ngx!*/
{
    EC_BOOL flag;

    flag = task_brd_need_slow_down(task_brd_default_get(), LOGSTDOUT, LOG_LEVEL_NEVER_HAPPEN);
    if(EC_TRUE == flag)
    {
        return ((uint32_t)1);
    }

    return ((uint32_t)0);
}

EC_BOOL do_once(TASK_BRD *task_brd)
{
#if 0
    for(;;)
    {
        /*when task req or task rsp in board is recved completely, commit it to some manager*/
        task_brd_recving_queue_handle(task_brd);

        task_brd_to_send_queue_handle(task_brd);

        task_brd_sending_queue_handle(task_brd);

        task_brd_send_task_mgr_list(task_brd);

        task_brd_is_recv_queue_handle(task_brd);

        task_brd_recv_task_mgr_list(task_brd);

        task_brd_aging_task_mgr_list(task_brd);
    }
#endif

#if 1
    for(;;)
    {
        cproc_recving_handle(TASK_BRD_CPROC(task_brd), TASK_BRD_QUEUE(task_brd, TASK_RECVING_QUEUE));
        cproc_sending_handle(TASK_BRD_CPROC(task_brd));
    }
#endif
    return (EC_TRUE);
}

UINT32 g_do_slave_usleep_counter = 0;

EC_BOOL do_slave(TASK_BRD *task_brd)
{
    TASKS_CFG  *tasks_cfg;
    EC_BOOL     tasks_monitor_empty_flag;

    dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "do_slave is running on tid %ld\n", CTHREAD_GET_TID());

    TASK_BRD_DO_SLAVE_PID(task_brd) = CTHREAD_GET_TID();

    tasks_cfg   = TASK_BRD_LOCAL_TASKS_CFG(task_brd);
    tasks_monitor_empty_flag = EC_FALSE;

    for(;;)
    {
        EC_BOOL slow_down_flag;

        /* check if we caught some signals and process them */
        csig_process_queue();

        if(TASK_BRD_IS_ABORT(task_brd))
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "[DEBUG] do_slave: abort flag is set\n");
            TASK_BRD_RESET_FLAG(task_brd) = EC_FALSE;
            break;
        }

        dbg_log(SEC_0015_TASK, 9)(LOGSTDNULL, "[DEBUG] do_slave: [0]\n");

        /*update task_brd time*/
        task_brd_update_time(task_brd);

        /*handle timeout event or expired event*/
        //cbtimer_handle(TASK_BRD_CBTIMER_LIST(task_brd));

        dbg_log(SEC_0015_TASK, 9)(LOGSTDNULL, "[DEBUG] do_slave: [1]\n");

        //dbg_log(SEC_0015_TASK, 9)(LOGSTDOUT, "[DEBUG] do_slave: [2]\n");

        cproc_recving_handle(TASK_BRD_CPROC(task_brd), TASK_BRD_QUEUE(task_brd, TASK_RECVING_QUEUE));
        cproc_sending_handle(TASK_BRD_CPROC(task_brd));

        //dbg_log(SEC_0015_TASK, 9)(LOGSTDOUT, "[DEBUG] do_slave: [3]\n");

        if(EC_FALSE == tasks_monitor_empty_flag)
        {
            dbg_log(SEC_0015_TASK, 5)(LOGSTDOUT, "[DEBUG] do_slave: tasks_monitor_empty_flag is false\n");
            if(EC_TRUE == tasks_monitor_is_empty(TASKS_CFG_MONITOR(tasks_cfg)))
            {
                dbg_log(SEC_0015_TASK, 5)(LOGSTDOUT, "[DEBUG] do_slave: set tasks_monitor_empty_flag to true\n");
                tasks_monitor_empty_flag = EC_TRUE;
            }
        }

        if(EC_TRUE == tasks_monitor_empty_flag)
        {
            //dbg_log(SEC_0015_TASK, 9)(LOGSTDOUT, "[DEBUG] do_slave: [4]\n");
            /*when task req or task rsp in board is recved completely, commit it to some manager*/
            task_brd_recving_queue_handle(task_brd);

            task_brd_to_send_queue_handle(task_brd);

            task_brd_sending_queue_handle(task_brd);

            task_brd_send_task_mgr_list(task_brd);

            task_brd_is_recv_queue_handle(task_brd);

            task_brd_recv_task_mgr_list(task_brd);

            task_brd_aging_task_mgr_list(task_brd);
        }

        dbg_log(SEC_0015_TASK, 9)(LOGSTDNULL, "[DEBUG] do_slave: [5]\n");

        slow_down_flag = EC_TRUE;/*default is to slow down*/

        if(0)/*debug*/
        {
            slow_down_flag = task_brd_need_slow_down(task_brd, LOGSTDOUT, LOG_LEVEL_NEVER_HAPPEN);
        }

        if(NULL_PTR != TASK_BRD_CEPOLL(task_brd))
        {
            if(EC_TRUE == slow_down_flag)
            {
                cepoll_wait(TASK_BRD_CEPOLL(task_brd), TASK_SLOW_DOWN_MSEC);
            }
            else
            {
                cepoll_wait(TASK_BRD_CEPOLL(task_brd), 0);
            }
            cepoll_timeout(TASK_BRD_CEPOLL(task_brd));
            cepoll_loop(TASK_BRD_CEPOLL(task_brd));
        }
        else
        {
            if(EC_TRUE == slow_down_flag)
            {
                g_do_slave_usleep_counter ++;
                c_usleep(TASK_SLOW_DOWN_MSEC, LOC_TASK_0235);
            }
        }
    }

    return (EC_TRUE);
}

EC_BOOL do_slave_enhanced(TASK_BRD *task_brd)
{
    TASKS_CFG  *tasks_cfg;

    COROUTINE_POOL *coroutine_pool;

#if (SWITCH_ON == CROUTINE_SUPPORT_SINGLE_CTHREAD_SWITCH)
    CTIMET cbtimer_handled_time;
#endif/*(SWITCH_ON == CROUTINE_SUPPORT_SINGLE_CTHREAD_SWITCH)*/

    static UINT32 not_slow_down_max_times = 0; /*shit!*/

#if (SWITCH_OFF == NGX_BGN_SWITCH)
    dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "[DEBUG] do_slave_enhanced is running on tid %d\n", CTHREAD_GET_TID());
#endif/*(SWITCH_OFF == NGX_BGN_SWITCH)*/

    if(ERR_PID == TASK_BRD_DO_SLAVE_PID(task_brd))
    {
        TASK_BRD_DO_SLAVE_PID(task_brd) = CTHREAD_GET_TID();
    }

    tasks_cfg   = TASK_BRD_LOCAL_TASKS_CFG(task_brd);

    coroutine_pool = TASK_BRD_CROUTINE_POOL(task_brd);

#if (SWITCH_ON == CROUTINE_SUPPORT_SINGLE_CTHREAD_SWITCH)
    cbtimer_handled_time = TASK_BRD_CTIME(task_brd);/*initialize*/
#endif/*(SWITCH_ON == CROUTINE_SUPPORT_SINGLE_CTHREAD_SWITCH)*/

#if (SWITCH_OFF == NGX_BGN_SWITCH)
    if(CMPI_FWD_RANK == TASK_BRD_RANK(task_brd))
    {
        //task_brd_register_cluster(task_brd);
    }
#endif/*(SWITCH_OFF == NGX_BGN_SWITCH)*/
#if (SWITCH_OFF == NGX_BGN_SWITCH)
    for(;;)
#endif/*(SWITCH_OFF == NGX_BGN_SWITCH)*/
    {
        EC_BOOL slow_down_flag;
        UINT32  loops;
        UINT32  count;

#if (SWITCH_OFF == NGX_BGN_SWITCH)
        /* check if we caught some signals and process them */
        csig_process_queue();
#endif/*(SWITCH_OFF == NGX_BGN_SWITCH)*/
        if(TASK_BRD_IS_ABORT(task_brd))
        {
            TASK_BRD_RESET_FLAG(task_brd) = EC_FALSE;
            return (EC_TRUE);
        }

        /*update task_brd time*/
        task_brd_update_time(task_brd);

#if (SWITCH_ON == CROUTINE_SUPPORT_SINGLE_CTHREAD_SWITCH)
        /*handle timeout event or expired event, check each second*/
        if(1.0 <= CTIMET_DIFF(cbtimer_handled_time, TASK_BRD_CTIME(task_brd)))
        {
            /*handle timeout event or expired event*/
            cbtimer_handle(TASK_BRD_CBTIMER_LIST(task_brd));
            cbtimer_handled_time = TASK_BRD_CTIME(task_brd);/*update*/
        }
#endif/*(SWITCH_ON == CROUTINE_SUPPORT_SINGLE_CTHREAD_SWITCH)*/

#if 0
        /*register to remote servers before current taskcomm is ready*/
        /*note: here is dangerous: dead lock of TASKS_CFG_WORKER(TASK_BRD_LOCAL_TASKS_CFG(task_brd)) and TASKS_CFG_MONITOR(TASK_BRD_LOCAL_TASKS_CFG(task_brd))*/
        if (EC_FALSE == task_brd_register_cluster_flag && CMPI_FWD_RANK == TASK_BRD_RANK(task_brd))
        {
            task_brd_register_cluster(task_brd);
            task_brd_register_cluster_flag = EC_TRUE;
        }
#endif
#if 1
        if(CMPI_FWD_RANK == TASK_BRD_RANK(task_brd))
        {
            tasks_worker_heartbeat(TASKS_CFG_WORKER(tasks_cfg));
        }
#endif
        //dbg_log(SEC_0015_TASK, 9)(LOGSTDOUT, "[DEBUG] do_slave_enhanced: [2]\n");

        cproc_recving_handle(TASK_BRD_CPROC(task_brd), TASK_BRD_QUEUE(task_brd, TASK_RECVING_QUEUE));
        cproc_sending_handle(TASK_BRD_CPROC(task_brd));

        //dbg_log(SEC_0015_TASK, 9)(LOGSTDOUT, "[DEBUG] do_slave_enhanced: [3]\n");

#if 0
        if(EC_FALSE == tasks_monitor_empty_flag)
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "[DEBUG] do_slave_enhanced: tasks_monitor_empty_flag is false\n");
            if(EC_TRUE == tasks_monitor_is_empty(TASKS_CFG_MONITOR(tasks_cfg)))
            {
                dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "[DEBUG] do_slave_enhanced: set tasks_monitor_empty_flag to true\n");
                tasks_monitor_empty_flag = EC_TRUE;
            }
        }
#endif
        //if(EC_TRUE == tasks_monitor_empty_flag)
        for(loops= 4, count = 0; count < loops; count ++)/*ensure to complete task state transition!*/
        {
            //dbg_log(SEC_0015_TASK, 9)(LOGSTDOUT, "[DEBUG] do_slave_enhanced: [4]\n");
            /*when task req or task rsp in board is recved completely, commit it to some manager*/
            task_brd_recving_queue_handle(task_brd);

            task_brd_to_send_queue_handle(task_brd);

            task_brd_sending_queue_handle(task_brd);

            task_brd_send_task_mgr_list(task_brd);

            task_brd_is_recv_queue_handle(task_brd);

            task_brd_recv_task_mgr_list(task_brd);

            task_brd_aging_task_mgr_list(task_brd);
        }

        task_brd_update_time(task_brd);

        if(BIT_TRUE == TASK_BRD_ENABLE_SLOW_DOWN(task_brd))/*set slow down flag*/
        {
            slow_down_flag = task_brd_need_slow_down(task_brd, LOGSTDOUT, LOG_LEVEL_NEVER_HAPPEN);
        }
        else
        {
            slow_down_flag = EC_FALSE;
        }

        if(NULL_PTR != TASK_BRD_CEPOLL(task_brd))
        {
            if(EC_TRUE == slow_down_flag || TASK_NOT_SLOW_DOWN_MAX_TIMES <= not_slow_down_max_times)
            {
                not_slow_down_max_times = 0; /*reset*/

                //dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "[DEBUG] do_slave_enhanced: slow down %d msec beg\n", TASK_SLOW_DOWN_MSEC);
                cepoll_wait(TASK_BRD_CEPOLL(task_brd), TASK_SLOW_DOWN_MSEC);
                /*if slow_down happen, update task_brd time*/
                task_brd_update_time(task_brd);
                //dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "[DEBUG] do_slave_enhanced: slow down %d msec end\n", TASK_SLOW_DOWN_MSEC);
            }
            else
            {
                not_slow_down_max_times ++;/*increase*/
                cepoll_wait(TASK_BRD_CEPOLL(task_brd), 0);
            }

            cepoll_timeout(TASK_BRD_CEPOLL(task_brd));
            cepoll_loop(TASK_BRD_CEPOLL(task_brd));
            task_brd_update_time(task_brd);
        }
        else
        {
            if(EC_TRUE == slow_down_flag)
            {
                g_do_slave_usleep_counter ++;
                c_usleep(TASK_SLOW_DOWN_MSEC, LOC_TASK_0236);
                /*if slow_down happen, update task_brd time*/
                task_brd_update_time(task_brd);
            }
        }

        /*------------------------------------------------------------------------*/
#if (SWITCH_ON == NGX_BGN_SWITCH)
        coroutine_pool_run_all(coroutine_pool);
#endif/*(SWITCH_ON == NGX_BGN_SWITCH)*/

#if (SWITCH_OFF == NGX_BGN_SWITCH)
        //coroutine_pool_run_once(coroutine_pool);
        coroutine_pool_run_all(coroutine_pool);
#endif/*(SWITCH_OFF == NGX_BGN_SWITCH)*/

        task_brd_process_do(task_brd);
    }

    return (EC_TRUE);
}


EC_BOOL do_slave_thread_default()
{
    TASK_BRD *task_brd;
    UINT32 core_max_num;

    task_brd = task_brd_default_get();

    core_max_num = sysconf(_SC_NPROCESSORS_ONLN);

    TASK_BRD_DO_SLAVE_CTHREAD_ID(task_brd) = cthread_new(CTHREAD_JOINABLE | CTHREAD_SYSTEM_LEVEL,
                                                        (const char *)"do_slave",
                                                        (UINT32)do_slave,
                                                        (UINT32)(TASK_BRD_RANK(task_brd) % core_max_num), /*core #*/
                                                        (UINT32)1,/*para num*/
                                                        (UINT32)task_brd
                                                        );
    return (EC_TRUE);
}

EC_BOOL do_slave_wait_default(TASK_BRD *task_brd)
{
#if (SWITCH_ON == CROUTINE_SUPPORT_CTHREAD_SWITCH)
    while(ERR_CTHREAD_ID != TASK_BRD_DO_SLAVE_CTHREAD_ID(task_brd))/*reset automatically*/
    {
        UINT32 core_max_num;

        cthread_wait(TASK_BRD_DO_SLAVE_CTHREAD_ID(task_brd));

        /*when reach here, do_slave was quit for some reason*/
        TASK_BRD_DO_SLAVE_CTHREAD_ID(task_brd) = ERR_CTHREAD_ID;

        if(EC_FALSE == TASK_BRD_RESET_FLAG(task_brd))
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "do_slave_wait_default: NOT restart do_slave thread and quit now\n");
            break;
        }

        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "do_slave_wait_default: try to restart do_slave thread ....\n");

        /*boot do_slave thread automatically*/
        core_max_num = sysconf(_SC_NPROCESSORS_ONLN);/*get available core num at present. only useful when CTHREAD_CORE_SWITCH is ON*/
        TASK_BRD_DO_SLAVE_CTHREAD_ID(task_brd) = cthread_new(CTHREAD_JOINABLE | CTHREAD_SYSTEM_LEVEL,
                                                            (const char *)"do_slave",
                                                            (UINT32)do_slave,
                                                            (UINT32)(TASK_BRD_RANK(task_brd) % core_max_num), /*core #*/
                                                            (UINT32)1,/*para num*/
                                                            (UINT32)task_brd
                                                            );
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT,"do_slave_wait_default: do_slave thread %u\n", TASK_BRD_DO_SLAVE_CTHREAD_ID(task_brd));
        task_brd_reset_cmutex_all(task_brd);
        /*TODO: should register to remote taskcomm again??*/
    }
#endif/*(SWITCH_ON == CROUTINE_SUPPORT_CTHREAD_SWITCH)*/

#if (SWITCH_ON == CROUTINE_SUPPORT_COROUTINE_SWITCH)
    while(ERR_CTHREAD_ID != TASK_BRD_DO_ROUTINE_CTHREAD_ID(task_brd))/*reset automatically*/
    {
        UINT32 core_max_num;

        cthread_wait(TASK_BRD_DO_ROUTINE_CTHREAD_ID(task_brd));

        /*when reach here, do_slave was quit for some reason*/
        TASK_BRD_DO_ROUTINE_CTHREAD_ID(task_brd) = ERR_CTHREAD_ID;

        if(EC_FALSE == TASK_BRD_RESET_FLAG(task_brd))
        {
            dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "do_slave_wait_default: NOT restart do_slave thread and quit now\n");
            break;
        }

        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "do_slave_wait_default: try to restart do_slave thread ....\n");

        /*boot do_slave thread automatically*/
        core_max_num = sysconf(_SC_NPROCESSORS_ONLN);/*get available core num at present. only useful when CTHREAD_CORE_SWITCH is ON*/
        TASK_BRD_DO_ROUTINE_CTHREAD_ID(task_brd) = cthread_new(CTHREAD_JOINABLE | CTHREAD_SYSTEM_LEVEL,
                                                            (const char *)"do_slave_enhanced",
                                                            (UINT32)do_slave_enhanced,
                                                            (UINT32)(TASK_BRD_RANK(task_brd) % core_max_num), /*core #*/
                                                            (UINT32)1,/*para num*/
                                                            (UINT32)task_brd
                                                            );
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT,"do_slave_wait_default: do_slave thread %ld\n", TASK_BRD_DO_ROUTINE_CTHREAD_ID(task_brd));
        task_brd_reset_cmutex_all(task_brd);
        /*TODO: should register to remote taskcomm again??*/
    }
#endif/*(SWITCH_ON == CROUTINE_SUPPORT_COROUTINE_SWITCH)*/
    return (EC_FALSE);
}

EC_BOOL do_slave_default()
{
    TASK_BRD *task_brd;

    task_brd = task_brd_default_get();

    return do_slave(task_brd);
}

/*coroutine to handle a command when it is ready*/
EC_BOOL do_cmd_default()
{
    CMD_ELEM_VEC *cmd_elem_vec;
    CMD_TREE     *cmd_tree;
    CMD_HELP_VEC *cmd_help_vec;

    TASK_BRD *task_brd;

    task_brd = task_brd_default_get();

    cmd_elem_vec = api_cmd_elem_vec_new();
    cmd_help_vec = api_cmd_help_vec_new();
    cmd_tree     = api_cmd_tree_new();

    api_cmd_ui_init(cmd_elem_vec, cmd_tree, cmd_help_vec);

    if(NULL_PTR != TASK_BRD_SCRIPT_FNAME(task_brd))
    {
        api_cmd_ui_do_script(cmd_tree, cmd_help_vec, (char *)TASK_BRD_SCRIPT_FNAME_STR(task_brd));

        api_cmd_elem_vec_free(cmd_elem_vec);
        api_cmd_help_vec_free(cmd_help_vec);
        api_cmd_tree_free(cmd_tree);

        //sys_log(LOGSTDOUT, "[DEBUG] do_cmd_default: show mem status:\n");
        //print_static_mem_status(LOGCONSOLE);

        task_brd_set_abort_default();
        return (EC_TRUE);
    }

    for(;;)
    {
        //dbg_log(SEC_0015_TASK, 9)(LOGSTDOUT, "[DEBUG] do_cmd_default: check\n");
        if(EC_TRUE == api_cmd_ui_readline_is_disabled())/*when command is ready*/
        {
            //dbg_log(SEC_0015_TASK, 9)(LOGSTDOUT, "[DEBUG] do_cmd_default: readline is disabled\n");
            api_cmd_ui_task_once(cmd_tree, cmd_help_vec);

            api_cmd_ui_readline_set_enabled();
        }

        __COROUTINE_WAIT();
    }

    api_cmd_elem_vec_free(cmd_elem_vec);
    api_cmd_help_vec_free(cmd_help_vec);
    api_cmd_tree_free(cmd_tree);

    //sys_log(LOGSTDOUT, "[DEBUG] do_cmd_default: show mem status:\n");
    //print_static_mem_status(LOGCONSOLE);

    return (EC_TRUE);
}

EC_BOOL do_mon_default()
{
    for(;;)
    {
        pause();
    }
    return (EC_TRUE);
}

EC_BOOL task_brd_default_abort()
{
    dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "[DEBUG] task_brd_default_abort: exit\n");
    exit(0);
    return(EC_TRUE);
}

EC_BOOL task_brd_is_running(TASK_BRD *task_brd)
{
    if(BIT_TRUE == TASK_BRD_TASKS_IS_RUNNING(task_brd))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL task_brd_default_is_running()
{
    TASK_BRD *task_brd;

    task_brd = task_brd_default_get();

    return task_brd_is_running(task_brd);
}

EC_BOOL task_brd_end(TASK_BRD *task_brd)
{
#if 0
    LOG *log_stdout;
    LOG *log_stderr;
    LOG *log_stdin;
#endif
    if(NULL_PTR != TASK_BRD_CSRV(task_brd))
    {
        csrv_end(TASK_BRD_CSRV(task_brd));
        TASK_BRD_CSRV(task_brd) = NULL_PTR;
    }
#if 0
    cbc_free();/*cbc_new is called in task_brd_default_init*/

    task_brd_free(task_brd);

    log_stdout = sys_log_redirect_cancel(LOGSTDOUT);
    log_stderr = sys_log_redirect_cancel(LOGSTDERR);
    log_stdin  = sys_log_redirect_cancel(LOGSTDIN);

    if(0 != log_stdout)
    {
        log_free(log_stdout);
    }

    if(0 != log_stderr && log_stderr != log_stdout)
    {
        log_free(log_stderr);
    }

    if(0 != log_stdin && log_stdin != log_stderr && log_stdin != log_stdout)
    {
        log_free(log_stdin);
    }

    destory_static_mem();
#endif
    return (EC_TRUE);
}

EC_BOOL task_brd_default_end()
{
    dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "[DEBUG] task_brd_default_end: task_brd end\n");
    return task_brd_end(task_brd_default_get());
}

/*broadcast to all remote mod nodes in mod mgr, ignore load balancing strategy*/
UINT32 task_bcast(const MOD_MGR *mod_mgr, const UINT32 time_to_live, const UINT32 task_prio, const UINT32 task_need_rsp_flag, const UINT32 task_need_rsp_num, const UINT32 func_id, ...)
{
    TASK_MGR  *task_mgr;
    TASK_REQ  *task_req;
    TASK_NODE *task_req_node;

    MOD_NODE  *send_mod_node;
    MOD_NODE  *recv_mod_node;

    TASK_FUNC *task_req_func;
    FUNC_PARA *func_para;

    FUNC_ADDR_NODE *func_addr_node;

    CVECTOR *remote_mode_node_list;
    UINT32  pos;

    UINT32 sub_seqno;
    UINT32 mod_type;

    UINT32 para_idx;
    UINT32 ret;

    va_list ap;

    mod_type = (func_id >> (WORDSIZE / 2));
    if( MD_END <= mod_type )
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDERR, "error:task_bcast: invalid func_id %lx\n", func_id);
        return ((UINT32)(-1));
    }

    if(0 != dbg_fetch_func_addr_node_by_index(func_id, &func_addr_node))
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_bcast: failed to fetch func addr node by func id %lx\n", func_id);
        return ((UINT32)(-1));
    }

    task_mgr = task_new(mod_mgr, task_prio, task_need_rsp_flag, task_need_rsp_num);

    send_mod_node = (MOD_NODE  *)MOD_MGR_LOCAL_MOD(mod_mgr);
    mod_node_update_local_stat(send_mod_node);/*patch*/

    remote_mode_node_list = (CVECTOR *)MOD_MGR_REMOTE_LIST(mod_mgr);
    for(pos = 0; pos < MOD_MGR_REMOTE_NUM(mod_mgr); pos ++)
    {
        task_mgr_sub_seqno_gen(task_mgr, &sub_seqno);

        task_req = task_req_new(0, TASK_MGR_SEQNO(task_mgr), sub_seqno, TASK_NORMAL_TYPE, task_mgr, LOC_TASK_0237);

        recv_mod_node = (MOD_NODE  *)cvector_get(remote_mode_node_list, pos);

        mod_node_clone(send_mod_node, TASK_REQ_SEND_MOD(task_req));
        mod_node_clone(recv_mod_node, TASK_REQ_RECV_MOD(task_req));
        TASK_REQ_RECV_MOD_FLAG(task_req) = EC_FALSE; /*not need to update*/

        TASK_REQ_TAG(task_req) = TAG_TASK_REQ;

        task_req_func = TASK_REQ_FUNC(task_req);

        task_req_func->func_id       = func_id;
        task_req_func->func_para_num = func_addr_node->func_para_num;
        task_req_func->func_ret_val  = (UINT32)&ret;

        va_start(ap, func_id);
        for(para_idx = 0; para_idx < func_addr_node->func_para_num; para_idx ++ )
        {
            func_para = &(task_req_func->func_para[ para_idx ]);
            func_para->para_val = va_arg(ap, UINT32);
        }
        va_end(ap);

        /*NOTE: replace the first parameter with mod id*/
        func_para = &(task_req_func->func_para[ 0 ]); /*set mod id*/
        func_para->para_val = MOD_NODE_MODI(recv_mod_node);
        TASK_REQ_MOD_ID_FLAG(task_req) = EC_FALSE; /*not need to update mod id*/

        TASK_REQ_FUNC_ADDR_NODE(task_req) = func_addr_node;

        task_req_node = TASK_REQ_NODE(task_req);
        TASK_NODE_TAG(task_req_node)   = TASK_REQ_TAG(task_req);
        TASK_NODE_STATUS(task_req_node)= TASK_REQ_TO_SEND;

        TASK_MGR_ADD_REQ_TAIL(task_mgr, task_req);
    }

    /*task_brd_task_mgr_add(task_brd, task_mgr);*/

    task_wait(task_mgr, time_to_live, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    return (0);
}

/*start remote modules by module start entry as task req*/
/*broadcast to all remote mod nodes in mod mgr, deploy load balancing strategy*/
UINT32 task_act(const MOD_MGR *src_mod_mgr, MOD_MGR **des_mod_mgr, const UINT32 time_to_live, const UINT32 mod_num, const UINT32 load_balancing_choice, const UINT32 task_prio, const UINT32 func_id, ...)
{
    TASK_MGR  *task_mgr;
    TASK_REQ  *task_req;
    TASK_NODE *task_req_node;

    MOD_NODE  *send_mod_node;
    MOD_NODE  *recv_mod_node;

    TASK_FUNC *task_req_func;
    FUNC_PARA *func_para;

    FUNC_ADDR_NODE *func_addr_node;

    MOD_MGR *mod_mgr;

    UINT32 sub_seqno;
    UINT32 mod_type;

    UINT32 mod_idx;
    UINT32 para_idx;

    va_list ap;

    mod_type = (func_id >> (WORDSIZE / 2));
    if( MD_END <= mod_type )
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_act: invalid func_id %lx\n", func_id);
        return ((UINT32)(-1));
    }

    mod_mgr = mod_mgr_new(CMPI_ERROR_MODI, load_balancing_choice);

    send_mod_node = (MOD_NODE  *)MOD_MGR_LOCAL_MOD(src_mod_mgr);
    mod_node_update_local_stat(send_mod_node);/*patch*/

    if(0 != dbg_fetch_func_addr_node_by_index(func_id, &func_addr_node))
    {
        mod_mgr_free(mod_mgr);
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_act: failed to fetch func addr node by func id %lx\n", func_id);
        return ((UINT32)(-1));
    }

    task_mgr = task_new(src_mod_mgr, task_prio, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);

    for(mod_idx = 0; mod_idx < mod_num; mod_idx ++)
    {
        task_mgr_sub_seqno_gen(task_mgr, &sub_seqno);

        task_req = task_req_new(0, TASK_MGR_SEQNO(task_mgr), sub_seqno, TASK_ACT_TYPE, task_mgr, LOC_TASK_0238);

        /*recv_mod_node will be updated during load balancing before send*/
        mod_node_alloc(&recv_mod_node);
        mod_node_init(recv_mod_node);
        cvector_push(MOD_MGR_REMOTE_LIST(mod_mgr), (void *)recv_mod_node);

        mod_node_clone(send_mod_node, TASK_REQ_SEND_MOD(task_req));

        TASK_REQ_RECV_MOD_NEW(task_req) = recv_mod_node;/*wait for update*/
        TASK_REQ_RECV_MOD_FLAG(task_req) = EC_TRUE;/*need to update RECV_MOD*/

        TASK_REQ_TAG(task_req) = TAG_TASK_REQ;

        task_req_func = TASK_REQ_FUNC(task_req);

        task_req_func->func_id       = func_id;
        task_req_func->func_para_num = func_addr_node->func_para_num;
        task_req_func->func_ret_val  = (UINT32)(&(MOD_NODE_MODI(recv_mod_node)));

        va_start(ap, func_id);
        for(para_idx = 0; para_idx < func_addr_node->func_para_num; para_idx ++ )
        {
            func_para = &(task_req_func->func_para[ para_idx ]);
            func_para->para_val = va_arg(ap, UINT32);
        }
        va_end(ap);
        TASK_REQ_MOD_ID_FLAG(task_req) = EC_FALSE; /*not need to update MOD_ID, the first func para*/

        TASK_REQ_FUNC_ADDR_NODE(task_req) = func_addr_node;

        task_req_node = TASK_REQ_NODE(task_req);
        TASK_NODE_TAG(task_req_node)   = TASK_REQ_TAG(task_req);
        TASK_NODE_STATUS(task_req_node)= TASK_REQ_TO_SEND;

        TASK_MGR_ADD_REQ_TAIL(task_mgr, task_req);
    }

    /*mount task_mgr to board*/
    /*task_brd_task_mgr_add(task_brd, task_mgr);*/

    task_wait(task_mgr, time_to_live, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    /*for safe, exclude invalid module id*/
    mod_mgr_excl(CMPI_ANY_TCID, CMPI_ANY_COMM, CMPI_ANY_RANK, CMPI_ERROR_MODI, mod_mgr);

    if(NULL_PTR != des_mod_mgr)
    {
        *des_mod_mgr = mod_mgr; /*return mod_mgr*/
    }
    else
    {
        mod_mgr_free(mod_mgr);
    }
#if 0
    dbg_log(SEC_0015_TASK, 5)(LOGSTDOUT, "------------------------------------ mod_mgr_default beg ----------------------------------\n");
    mod_mgr_print(LOGSTDOUT, mod_mgr_default);
    dbg_log(SEC_0015_TASK, 5)(LOGSTDOUT, "------------------------------------ mod_mgr_default end ----------------------------------\n");
#endif

#if 0
    dbg_log(SEC_0015_TASK, 5)(LOGSTDOUT, "------------------------------------ task_act mod_mgr result: beg ----------------------------------\n");
    mod_mgr_print(LOGSTDOUT, mod_mgr);
    dbg_log(SEC_0015_TASK, 5)(LOGSTDOUT, "------------------------------------ task_act mod_mgr result: end ----------------------------------\n");
#endif
    return (0);
}

/*stop remote modules by module end entry as task req*/
/*broadcast to all remote mod nodes in mod mgr, ignore load balancing strategy*/
UINT32 task_dea(MOD_MGR *mod_mgr, const UINT32 time_to_live, const UINT32 task_prio, const UINT32 func_id, ...)
{
    TASK_MGR  *task_mgr;
    TASK_REQ  *task_req;
    TASK_NODE *task_req_node;

    MOD_NODE  *send_mod_node;
    MOD_NODE  *recv_mod_node;

    TASK_FUNC *task_req_func;
    FUNC_PARA *func_para;

    FUNC_ADDR_NODE *func_addr_node;

    CVECTOR *remote_mode_node_list;
    UINT32 pos;

    UINT32 sub_seqno;
    UINT32 mod_type;

    UINT32 para_idx;
    UINT32 ret;

    va_list ap;

    mod_type = (func_id >> (WORDSIZE / 2));
    if( MD_END <= mod_type )
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDERR, "error:task_dea: invalid func_id %lx\n", mod_type);
        return ((UINT32)(-1));
    }

    if(0 != dbg_fetch_func_addr_node_by_index(func_id, &func_addr_node))
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_dea: failed to fetch func addr node by func id %lx\n", func_id);
        return ((UINT32)(-1));
    }

    task_mgr = task_new(mod_mgr, task_prio, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);

    send_mod_node = (MOD_NODE  *)MOD_MGR_LOCAL_MOD(mod_mgr);
    mod_node_update_local_stat(send_mod_node);/*patch*/

    remote_mode_node_list = MOD_MGR_REMOTE_LIST(mod_mgr);
    for(pos = 0; pos < MOD_MGR_REMOTE_NUM(mod_mgr); pos ++)
    {
        task_mgr_sub_seqno_gen(task_mgr, &sub_seqno);

        task_req = task_req_new(0, TASK_MGR_SEQNO(task_mgr), sub_seqno, TASK_DEA_TYPE, task_mgr, LOC_TASK_0239);

        recv_mod_node = (MOD_NODE  *)cvector_get(remote_mode_node_list, pos);
        mod_node_clone(send_mod_node, TASK_REQ_SEND_MOD(task_req));
        mod_node_clone(recv_mod_node, TASK_REQ_RECV_MOD(task_req));
        TASK_REQ_RECV_MOD_FLAG(task_req) = EC_FALSE; /*not need to update*/

        TASK_REQ_TAG(task_req) = TAG_TASK_REQ;

        task_req_func = TASK_REQ_FUNC(task_req);

        task_req_func->func_id       = func_id;
        task_req_func->func_para_num = func_addr_node->func_para_num;
        task_req_func->func_ret_val  = (UINT32)(&ret);

        va_start(ap, func_id);
        for(para_idx = 0; para_idx < func_addr_node->func_para_num; para_idx ++ )
        {
            func_para = &(task_req_func->func_para[ para_idx ]);
            func_para->para_val = va_arg(ap, UINT32);
        }
        va_end(ap);

        /*NOTE: replace the first parameter with mod id*/
        func_para = &(task_req_func->func_para[ 0 ]);
        func_para->para_val = MOD_NODE_MODI(recv_mod_node);
        TASK_REQ_MOD_ID_FLAG(task_req) = EC_FALSE; /*not need to update*/

        TASK_REQ_FUNC_ADDR_NODE(task_req) = func_addr_node;

        task_req_node = TASK_REQ_NODE(task_req);
        TASK_NODE_TAG(task_req_node)   = TASK_REQ_TAG(task_req);
        TASK_NODE_STATUS(task_req_node)= TASK_REQ_TO_SEND;

        TASK_MGR_ADD_REQ_TAIL(task_mgr, task_req);

    }

    /*task_brd_task_mgr_add(task_brd, task_mgr);*/

    task_wait(task_mgr, time_to_live, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    mod_mgr_free(mod_mgr);

    return (0);
}

/*wait until all task reqs of task mgr are handled and responed(if need rsp) or until all task reqs sending complete(if not need rsp), */
/*then return the calling point to execute*/
EC_BOOL task_wait(TASK_MGR *task_mgr, const UINT32 time_to_live, const UINT32 task_reschedule_flag, CHECKER ret_val_checker)
{
    TASK_BRD *task_brd;
    CTM *start_tm;
    CTM *end_tm;

#if (SWITCH_ON == CROUTINE_SUPPORT_COROUTINE_SWITCH)
    //COROUTINE_NODE *coroutine_node_cur;
#endif/*(SWITCH_ON == CROUTINE_SUPPORT_COROUTINE_SWITCH)*/

    /*if no task req in task mgr, then return after clean up task mgr*/
    if(EC_TRUE == clist_is_empty(TASK_MGR_QUEUE(task_mgr)))
    {
        //dbg_log(SEC_0015_TASK, 5)(LOGSTDOUT, "task_wait: task_mgr %lx is empty\n", task_mgr);
        clist_del(TASK_MGR_QUEUE(task_mgr), (void *)task_mgr, NULL_PTR);
        task_mgr_free(task_mgr);
        return (EC_FALSE);
    }

    TASK_MGR_MOD_FREE_FLAG(task_mgr) = EC_FALSE;
    TASK_MGR_JMP_FLAG(task_mgr)      = EC_TRUE;

    TASK_MGR_TIME_TO_LIVE(task_mgr)  = time_to_live;
    CTIMEOFDAY_GET(TASK_MGR_START_TIME(task_mgr)); /*okay, always record the task mgr starting time*/

    TASK_MGR_NEED_RESCHEDULE_FLAG(task_mgr) = task_reschedule_flag;

    TASK_MGR_RETV_CHECKER(task_mgr) = ret_val_checker;

    task_brd = task_brd_default_get();
    //dbg_log(SEC_0015_TASK, 5)(LOGSTDOUT, "before add: ===========================================================\n");
    //clist_print(LOGSTDOUT, TASK_BRD_RECV_TASK_MGR_LIST(task_brd), (CLIST_DATA_DATA_PRINT)task_mgr_print);

    dbg_log(SEC_0015_TASK, 3)(LOGSTDOUT, "================================= task %lx.%lx.%lx  start %p [tid %ld] ==============================================\n",
                        TASK_BRD_TCID(task_brd), TASK_BRD_RANK(task_brd), TASK_MGR_SEQNO(task_mgr), task_mgr, CTHREAD_GET_TID());

    //coroutine_debug(LOGSTDOUT, "[task_wait]");
#if (SWITCH_ON == CROUTINE_SUPPORT_CTHREAD_SWITCH)
    if(CTHREAD_GET_TID() == TASK_BRD_DO_SLAVE_PID(task_brd))
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_wait: current tid %d, do_slave_pid %d\n", CTHREAD_GET_TID(), TASK_BRD_DO_SLAVE_PID(task_brd));
    }
    ASSERT(CTHREAD_GET_TID() != TASK_BRD_DO_SLAVE_PID(task_brd));
#endif/*(SWITCH_ON == CROUTINE_SUPPORT_CTHREAD_SWITCH)*/

    task_mgr_encode(task_brd, task_mgr);
    TASK_MGR_CCOND_RESERVE(task_mgr, 1, LOC_TASK_0240);

    task_brd_task_mgr_add(task_brd, task_mgr);

    TASK_MGR_CCOND_WAIT(task_mgr, LOC_TASK_0241);

    /*when reach here, task is done*/

    dbg_log(SEC_0015_TASK, 3)(LOGSTDOUT, "================================= task %lx.%lx.%lx  end %p ================================================\n",
                        TASK_BRD_TCID(task_brd), TASK_BRD_RANK(task_brd), TASK_MGR_SEQNO(task_mgr), task_mgr);

    start_tm = CTIMET_TO_LOCAL_TIME(TASK_MGR_START_TIME_SEC(task_mgr));
    end_tm   = CTIMET_TO_LOCAL_TIME(TASK_MGR_END_TIME_SEC(task_mgr));

    dbg_log(SEC_0015_TASK, 2)(LOGSTDOUT, "task_wait report: start at %4d-%02d-%02d %02d:%02d:%02d.%03d, end at %4d-%02d-%02d %02d:%02d:%02d.%03d, "
                      "seqno %lx.%lx.%lx, req num %ld, need rsp %ld, succ rsp %ld, fail rsp %ld, rsvd rsp %ld, "
                      "sent req %ld, discard req %ld, timeout req %ld\n",
                      TIME_IN_YMDHMS(start_tm), (int)TASK_MGR_START_TIME_MSEC(task_mgr),
                      TIME_IN_YMDHMS(end_tm), (int)TASK_MGR_END_TIME_MSEC(task_mgr),
                       TASK_BRD_TCID(task_brd), TASK_BRD_RANK(task_brd), TASK_MGR_SEQNO(task_mgr),
                       clist_size(TASK_MGR_QUEUE(task_mgr)),
                       TASK_MGR_COUNTER(task_mgr, TASK_MGR_COUNTER_TASK_RSP_IS_NEED),
                       TASK_MGR_COUNTER(task_mgr, TASK_MGR_COUNTER_TASK_RSP_IS_SUCC),
                       TASK_MGR_COUNTER(task_mgr, TASK_MGR_COUNTER_TASK_RSP_IS_FAIL),
                       TASK_MGR_COUNTER(task_mgr, TASK_MGR_COUNTER_TASK_RSP_RESERVD),
                       TASK_MGR_COUNTER(task_mgr, TASK_MGR_COUNTER_TASK_REQ_IS_SENT),
                       TASK_MGR_COUNTER(task_mgr, TASK_MGR_COUNTER_TASK_REQ_DISCARD),
                       TASK_MGR_COUNTER(task_mgr, TASK_MGR_COUNTER_TASK_REQ_TIMEOUT)
           );

    task_brd_report_list_add(task_brd, task_mgr);
    task_brd_aging_list_add(task_brd, task_mgr);

    return (EC_TRUE);
}

/*send all task reqs of task mgr without wait, and return the calling point to execute continously. no jump here*/
/*task_mgr will free automatically after collect all responses(if need rsp) or after all requests sending complete(if not need rsp)*/
EC_BOOL task_no_wait(TASK_MGR *task_mgr, const UINT32 time_to_live, const UINT32 task_reschedule_flag, CHECKER ret_val_checker)
{
    TASK_BRD *task_brd;

    /*if no task req in task mgr, then return after clean up task mgr*/
    if(EC_TRUE == clist_is_empty(TASK_MGR_QUEUE(task_mgr)))
    {
        clist_del(TASK_MGR_QUEUE(task_mgr), (void *)task_mgr, NULL_PTR);
        task_mgr_free(task_mgr);
        return (EC_FALSE);
    }

    TASK_MGR_MOD_FREE_FLAG(task_mgr) = EC_TRUE;
    TASK_MGR_JMP_FLAG(task_mgr)      = EC_FALSE;

    TASK_MGR_TIME_TO_LIVE(task_mgr)  = time_to_live;
    CTIMEOFDAY_GET(TASK_MGR_START_TIME(task_mgr)); /*okay, always record the task mgr starting time*/

    TASK_MGR_NEED_RESCHEDULE_FLAG(task_mgr) = task_reschedule_flag;

    TASK_MGR_RETV_CHECKER(task_mgr) = ret_val_checker;

    task_brd = task_brd_default_get();

    task_mgr_encode(task_brd, task_mgr);

    /*note: here cannot call task_mgr_send to send task reqs because it will disorder the sending task req in TASK_SENDING_QUEUE queue*/
    /*and TASK_SENDING_QUEUE not support task priority*/
    /*task_mgr_send(task_brd, task_mgr);*/
    task_brd_task_mgr_add(task_brd, task_mgr);/*mount it to task brd*/

    return (EC_TRUE);
}

/*new a task mgr template without task req and add task mgr to default task board*/
TASK_MGR * task_new(const MOD_MGR *mod_mgr, const UINT32 task_prio, const UINT32 task_need_rsp_flag, const UINT32 task_need_rsp_num)
{
    TASK_BRD *task_brd;
    TASK_MGR  *task_mgr;
    UINT32 task_seqno;

    task_brd = task_brd_default_get();
    task_brd_seqno_gen(task_brd, &task_seqno);

    alloc_static_mem(MM_TASK_MGR, &task_mgr, LOC_TASK_0242);
    task_mgr_init(task_seqno, task_prio, task_need_rsp_flag, task_need_rsp_num, mod_mgr, task_mgr);

    /*task_brd_task_mgr_add(task_brd, task_mgr);*/

    return(task_mgr);
}

UINT32 task_super_inc(TASK_MGR *task_mgr, const MOD_NODE  *send_mod_node, const MOD_NODE *recv_mod_node, const void * func_retval_addr, const UINT32 func_id, ...)
{
    TASK_REQ  *task_req;
    TASK_NODE *task_req_node;

    TASK_FUNC *task_req_func;
    FUNC_PARA *func_para;

    FUNC_ADDR_NODE *func_addr_node;

    UINT32 mod_type;
    UINT32 sub_seqno;

    va_list ap;

    mod_type = (func_id >> (WORDSIZE / 2));
    if( MD_END <= mod_type )
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDERR, "error:task_super_inc: invalid func_id %lx\n", func_id);
        return ((UINT32)(-1));
    }

    if(0 != dbg_fetch_func_addr_node_by_index(func_id, &func_addr_node))
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_super_inc: failed to fetch func addr node by func id %lx\n", func_id);
        return ((UINT32)(-1));
    }

    task_mgr_sub_seqno_gen(task_mgr, &sub_seqno);

    task_req = task_req_new(0, TASK_MGR_SEQNO(task_mgr), sub_seqno, TASK_NORMAL_TYPE, task_mgr, LOC_TASK_0243);

    mod_node_clone(send_mod_node, TASK_REQ_SEND_MOD(task_req));
    mod_node_clone(recv_mod_node, TASK_REQ_RECV_MOD(task_req));
    TASK_REQ_RECV_MOD_FLAG(task_req) = EC_FALSE;

    mod_node_update_local_stat(TASK_REQ_SEND_MOD(task_req));/*patch*/

    TASK_REQ_TAG(task_req) = TAG_TASK_REQ;

    task_req_func = TASK_REQ_FUNC(task_req);

    task_req_func->func_id       = func_id;
    task_req_func->func_para_num = func_addr_node->func_para_num;
    task_req_func->func_ret_val  = (UINT32)func_retval_addr;

    va_start(ap, func_id);
    task_req_func_para_init(func_addr_node->func_para_num, (FUNC_PARA *)task_req_func->func_para, ap);
    va_end(ap);

    func_para = &(task_req_func->func_para[ 0 ]);
    func_para->para_val = MOD_NODE_MODI(recv_mod_node);
    TASK_REQ_MOD_ID_FLAG(task_req) = EC_FALSE;

    TASK_REQ_FUNC_ADDR_NODE(task_req) = func_addr_node;

    task_req_node = TASK_REQ_NODE(task_req);
    TASK_NODE_TAG(task_req_node)   = TASK_REQ_TAG(task_req);
    TASK_NODE_STATUS(task_req_node)= TASK_REQ_TO_SEND;

    TASK_MGR_ADD_REQ_TAIL(task_mgr, task_req);

    return (0);
}

UINT32 task_super_mono(const MOD_MGR *mod_mgr, const UINT32 time_to_live, const UINT32 task_prio, const UINT32 task_need_rsp_flag, const UINT32 task_need_rsp_num, const MOD_NODE *recv_mod_node, const void * func_retval_addr, const UINT32 func_id, ...)
{
    TASK_REQ  *task_req;
    TASK_NODE *task_req_node;

    MOD_NODE  *send_mod_node;

    TASK_FUNC *task_req_func;
    FUNC_PARA *func_para;

    FUNC_ADDR_NODE *func_addr_node;
    TASK_MGR   *task_mgr;

    UINT32 mod_type;

    va_list ap;

    UINT32 sub_seqno;

    mod_type = (func_id >> (WORDSIZE / 2));
    if( MD_END <= mod_type )
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDERR, "error:task_super_mono: invalid func_id %lx\n", func_id);
        return ((UINT32)(-1));
    }

    if(0 != dbg_fetch_func_addr_node_by_index(func_id, &func_addr_node))
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_super_mono: failed to fetch func addr node by func id %lx\n", func_id);
        return ((UINT32)(-1));
    }

    task_mgr = task_new(mod_mgr, task_prio, task_need_rsp_flag, task_need_rsp_num);

    send_mod_node = (MOD_NODE  *)MOD_MGR_LOCAL_MOD(mod_mgr);

    task_mgr_sub_seqno_gen(task_mgr, &sub_seqno);

    task_req = task_req_new(0, TASK_MGR_SEQNO(task_mgr), sub_seqno, TASK_NORMAL_TYPE, task_mgr, LOC_TASK_0244);

    mod_node_clone(send_mod_node, TASK_REQ_SEND_MOD(task_req));
    mod_node_clone(recv_mod_node, TASK_REQ_RECV_MOD(task_req));
    TASK_REQ_RECV_MOD_FLAG(task_req) = EC_FALSE;

    mod_node_update_local_stat(TASK_REQ_SEND_MOD(task_req));/*patch*/

    TASK_REQ_TAG(task_req) = TAG_TASK_REQ;

    task_req_func = TASK_REQ_FUNC(task_req);

    task_req_func->func_id       = func_id;
    task_req_func->func_para_num = func_addr_node->func_para_num;
    task_req_func->func_ret_val  = (UINT32)func_retval_addr;

    va_start(ap, func_id);
    task_req_func_para_init(func_addr_node->func_para_num, (FUNC_PARA *)task_req_func->func_para, ap);
    va_end(ap);

    func_para = &(task_req_func->func_para[ 0 ]);
    func_para->para_val = MOD_NODE_MODI(recv_mod_node);
    TASK_REQ_MOD_ID_FLAG(task_req) = EC_FALSE;

    TASK_REQ_FUNC_ADDR_NODE(task_req) = func_addr_node;

    task_req_node = TASK_REQ_NODE(task_req);
    TASK_NODE_TAG(task_req_node)   = TASK_REQ_TAG(task_req);
    TASK_NODE_STATUS(task_req_node)= TASK_REQ_TO_SEND;

    TASK_MGR_ADD_REQ_TAIL(task_mgr, task_req);

    task_wait(task_mgr, time_to_live, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);
    return (0);
}

UINT32 task_super_mono_no_wait(const MOD_MGR *mod_mgr, const UINT32 time_to_live, const UINT32 task_prio, const UINT32 task_need_rsp_flag, const UINT32 task_need_rsp_num, const MOD_NODE *recv_mod_node, const void * func_retval_addr, const UINT32 func_id, ...)
{
    TASK_REQ  *task_req;
    TASK_NODE *task_req_node;

    MOD_NODE  *send_mod_node;

    TASK_FUNC *task_req_func;
    FUNC_PARA *func_para;

    FUNC_ADDR_NODE *func_addr_node;
    TASK_MGR   *task_mgr;

    UINT32 mod_type;

    va_list ap;

    UINT32 sub_seqno;

    mod_type = (func_id >> (WORDSIZE / 2));
    if( MD_END <= mod_type )
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDERR, "error:task_super_mono_no_wait: invalid func_id %lx\n", func_id);
        return ((UINT32)(-1));
    }

    if(0 != dbg_fetch_func_addr_node_by_index(func_id, &func_addr_node))
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_super_mono_no_wait: failed to fetch func addr node by func id %lx\n", func_id);
        return ((UINT32)(-1));
    }

    task_mgr = task_new(mod_mgr, task_prio, task_need_rsp_flag, task_need_rsp_num);

    send_mod_node = (MOD_NODE  *)MOD_MGR_LOCAL_MOD(mod_mgr);

    task_mgr_sub_seqno_gen(task_mgr, &sub_seqno);

    task_req = task_req_new(0, TASK_MGR_SEQNO(task_mgr), sub_seqno, TASK_NORMAL_TYPE, task_mgr, LOC_TASK_0245);

    mod_node_clone(send_mod_node, TASK_REQ_SEND_MOD(task_req));
    mod_node_clone(recv_mod_node, TASK_REQ_RECV_MOD(task_req));
    TASK_REQ_RECV_MOD_FLAG(task_req) = EC_FALSE;

    mod_node_update_local_stat(TASK_REQ_SEND_MOD(task_req));/*patch*/

    TASK_REQ_TAG(task_req) = TAG_TASK_REQ;

    task_req_func = TASK_REQ_FUNC(task_req);

    task_req_func->func_id       = func_id;
    task_req_func->func_para_num = func_addr_node->func_para_num;
    task_req_func->func_ret_val  = (UINT32)func_retval_addr;

    va_start(ap, func_id);
    task_req_func_para_init(func_addr_node->func_para_num, (FUNC_PARA *)task_req_func->func_para, ap);
    va_end(ap);

    func_para = &(task_req_func->func_para[ 0 ]);
    func_para->para_val = MOD_NODE_MODI(recv_mod_node);
    TASK_REQ_MOD_ID_FLAG(task_req) = EC_FALSE;

    TASK_REQ_FUNC_ADDR_NODE(task_req) = func_addr_node;

    task_req_node = TASK_REQ_NODE(task_req);
    TASK_NODE_TAG(task_req_node)   = TASK_REQ_TAG(task_req);
    TASK_NODE_STATUS(task_req_node)= TASK_REQ_TO_SEND;

    TASK_MGR_ADD_REQ_TAIL(task_mgr, task_req);

    task_no_wait(task_mgr, time_to_live, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);
    return (0);
}

UINT32 task_p2p_inc(TASK_MGR *task_mgr, const UINT32 modi, const MOD_NODE *recv_mod_node, const void * func_retval_addr, const UINT32 func_id, ...)
{
    TASK_REQ  *task_req;
    TASK_NODE *task_req_node;

    MOD_NODE   send_mod_node;

    TASK_FUNC *task_req_func;
    FUNC_PARA *func_para;

    FUNC_ADDR_NODE *func_addr_node;

    UINT32 mod_type;

    va_list ap;

    UINT32 sub_seqno;

    mod_type = (func_id >> (WORDSIZE / 2));
    if( MD_END <= mod_type )
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDERR, "error:task_p2p_inc: invalid func_id %lx\n", func_id);
        return ((UINT32)(-1));
    }

    if(0 != dbg_fetch_func_addr_node_by_index(func_id, &func_addr_node))
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_p2p_inc: failed to fetch func addr node by func id %lx\n", func_id);
        return ((UINT32)(-1));
    }

    mod_node_init(&send_mod_node);
    MOD_NODE_TCID(&send_mod_node) = CMPI_LOCAL_TCID;
    MOD_NODE_COMM(&send_mod_node) = CMPI_LOCAL_COMM;
    MOD_NODE_RANK(&send_mod_node) = CMPI_LOCAL_RANK;
    MOD_NODE_MODI(&send_mod_node) = modi;

    mod_node_update_local_stat(&send_mod_node);/*patch*/

    task_mgr_sub_seqno_gen(task_mgr, &sub_seqno);

    task_req = task_req_new(0, TASK_MGR_SEQNO(task_mgr), sub_seqno, TASK_NORMAL_TYPE, task_mgr, LOC_TASK_0246);

    mod_node_clone(&send_mod_node, TASK_REQ_SEND_MOD(task_req));
    mod_node_clone(recv_mod_node, TASK_REQ_RECV_MOD(task_req));
    TASK_REQ_RECV_MOD_FLAG(task_req) = EC_FALSE;

    TASK_REQ_TAG(task_req) = TAG_TASK_REQ;

    task_req_func = TASK_REQ_FUNC(task_req);

    task_req_func->func_id       = func_id;
    task_req_func->func_para_num = func_addr_node->func_para_num;
    task_req_func->func_ret_val  = (UINT32)func_retval_addr;

    va_start(ap, func_id);
    task_req_func_para_init(func_addr_node->func_para_num, (FUNC_PARA *)task_req_func->func_para, ap);
    va_end(ap);

    func_para = &(task_req_func->func_para[ 0 ]);
    func_para->para_val = MOD_NODE_MODI(recv_mod_node);
    TASK_REQ_MOD_ID_FLAG(task_req) = EC_FALSE;

    TASK_REQ_FUNC_ADDR_NODE(task_req) = func_addr_node;

    task_req_node = TASK_REQ_NODE(task_req);
    TASK_NODE_TAG(task_req_node)   = TASK_REQ_TAG(task_req);
    TASK_NODE_STATUS(task_req_node)= TASK_REQ_TO_SEND;

    TASK_MGR_ADD_REQ_TAIL(task_mgr, task_req);

    return (0);
}

UINT32 task_p2p(const UINT32 modi, const UINT32 time_to_live, const UINT32 task_prio, const UINT32 task_need_rsp_flag, const UINT32 task_need_rsp_num, const MOD_NODE *recv_mod_node, const void * func_retval_addr, const UINT32 func_id, ...)
{
    TASK_BRD  *task_brd;
    TASK_REQ  *task_req;
    TASK_NODE *task_req_node;

    MOD_NODE   send_mod_node;

    TASK_FUNC *task_req_func;
    FUNC_PARA *func_para;

    FUNC_ADDR_NODE *func_addr_node;
    TASK_MGR   *task_mgr;

    UINT32 mod_type;

    va_list ap;

    UINT32 sub_seqno;

    mod_type = (func_id >> (WORDSIZE / 2));
    if( MD_END <= mod_type )
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDERR, "error:task_p2p: invalid func_id %lx\n", func_id);
        return ((UINT32)(-1));
    }

    if(0 != dbg_fetch_func_addr_node_by_index(func_id, &func_addr_node))
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_p2p: failed to fetch func addr node by func id %lx\n", func_id);
        return ((UINT32)(-1));
    }

    /*shortcut*/
    task_brd = task_brd_default_get();
    if(
       MOD_NODE_TCID(recv_mod_node) == TASK_BRD_TCID(task_brd)
    && MOD_NODE_RANK(recv_mod_node) == TASK_BRD_RANK(task_brd)
    )
    {
        TASK_FUNC task_func;

        task_req_func = &task_func;

        if(e_dbg_void != func_addr_node->func_ret_type)
        {
            if(NULL_PTR == func_retval_addr)
            {
                dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_p2p: func_retval_addr should not be null\n");
                exit(0);/*coding bug, user should fix it*/
            }
        }

        task_req_func->func_id       = func_id;
        task_req_func->func_para_num = func_addr_node->func_para_num;
        //task_req_func->func_ret_val  = (UINT32)func_retval_addr;

        va_start(ap, func_id);
        task_req_func_para_init(func_addr_node->func_para_num, (FUNC_PARA *)task_req_func->func_para, ap);
        va_end(ap);

        func_para = &(task_req_func->func_para[ 0 ]);
        func_para->para_val = MOD_NODE_MODI(recv_mod_node);

        //dbg_log(SEC_0015_TASK, 9)(LOGSTDOUT, "[DEBUG] task_p2p: shortcut beg: func_id = %lx\n", func_id);
        task_caller(task_req_func, func_addr_node);
        //dbg_log(SEC_0015_TASK, 9)(LOGSTDOUT, "[DEBUG] task_p2p: shortcut end: func_id = %lx\n", func_id);

        if(e_dbg_void != func_addr_node->func_ret_type)
        {
            *((UINT32 *)func_retval_addr) = task_req_func->func_ret_val;
        }

        return (0);
    }

    task_mgr = task_new(NULL_PTR, task_prio, task_need_rsp_flag, task_need_rsp_num);

    mod_node_init(&send_mod_node);
    MOD_NODE_TCID(&send_mod_node) = CMPI_LOCAL_TCID;
    MOD_NODE_COMM(&send_mod_node) = CMPI_LOCAL_COMM;
    MOD_NODE_RANK(&send_mod_node) = CMPI_LOCAL_RANK;
    MOD_NODE_MODI(&send_mod_node) = modi;

    mod_node_update_local_stat(&send_mod_node);/*patch*/

    task_mgr_sub_seqno_gen(task_mgr, &sub_seqno);

    task_req = task_req_new(0, TASK_MGR_SEQNO(task_mgr), sub_seqno, TASK_NORMAL_TYPE, task_mgr, LOC_TASK_0247);

    mod_node_clone(&send_mod_node, TASK_REQ_SEND_MOD(task_req));
    mod_node_clone(recv_mod_node, TASK_REQ_RECV_MOD(task_req));
    TASK_REQ_RECV_MOD_FLAG(task_req) = EC_FALSE;

    TASK_REQ_TAG(task_req) = TAG_TASK_REQ;

    task_req_func = TASK_REQ_FUNC(task_req);

    task_req_func->func_id       = func_id;
    task_req_func->func_para_num = func_addr_node->func_para_num;
    task_req_func->func_ret_val  = (UINT32)func_retval_addr;

    va_start(ap, func_id);
    task_req_func_para_init(func_addr_node->func_para_num, (FUNC_PARA *)task_req_func->func_para, ap);
    va_end(ap);

    func_para = &(task_req_func->func_para[ 0 ]);
    func_para->para_val = MOD_NODE_MODI(recv_mod_node);
    TASK_REQ_MOD_ID_FLAG(task_req) = EC_FALSE;

    TASK_REQ_FUNC_ADDR_NODE(task_req) = func_addr_node;

    task_req_node = TASK_REQ_NODE(task_req);
    TASK_NODE_TAG(task_req_node)   = TASK_REQ_TAG(task_req);
    TASK_NODE_STATUS(task_req_node)= TASK_REQ_TO_SEND;

    TASK_MGR_ADD_REQ_TAIL(task_mgr, task_req);

    task_wait(task_mgr, time_to_live, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);
    return (0);
}

UINT32 task_p2p_no_wait(const UINT32 modi, const UINT32 time_to_live, const UINT32 task_prio, const UINT32 task_need_rsp_flag, const UINT32 task_need_rsp_num, const MOD_NODE *recv_mod_node, const void * func_retval_addr, const UINT32 func_id, ...)
{
    TASK_REQ  *task_req;
    TASK_NODE *task_req_node;

    MOD_NODE  send_mod_node;

    TASK_FUNC *task_req_func;
    FUNC_PARA *func_para;

    FUNC_ADDR_NODE *func_addr_node;
    TASK_MGR   *task_mgr;

    UINT32 mod_type;

    va_list ap;

    UINT32 sub_seqno;

    mod_type = (func_id >> (WORDSIZE / 2));
    if( MD_END <= mod_type )
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDERR, "error:task_p2p_no_wait: invalid func_id %lx\n", func_id);
        return ((UINT32)(-1));
    }

    if(0 != dbg_fetch_func_addr_node_by_index(func_id, &func_addr_node))
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_p2p_no_wait: failed to fetch func addr node by func id %lx\n", func_id);
        return ((UINT32)(-1));
    }

    task_mgr = task_new(NULL_PTR, task_prio, task_need_rsp_flag, task_need_rsp_num);

    mod_node_init(&send_mod_node);
    MOD_NODE_TCID(&send_mod_node) = CMPI_LOCAL_TCID;
    MOD_NODE_COMM(&send_mod_node) = CMPI_LOCAL_COMM;
    MOD_NODE_RANK(&send_mod_node) = CMPI_LOCAL_RANK;
    MOD_NODE_MODI(&send_mod_node) = modi;

    mod_node_update_local_stat(&send_mod_node);/*patch*/

    task_mgr_sub_seqno_gen(task_mgr, &sub_seqno);

    task_req = task_req_new(0, TASK_MGR_SEQNO(task_mgr), sub_seqno, TASK_NORMAL_TYPE, task_mgr, LOC_TASK_0248);

    mod_node_clone(&send_mod_node, TASK_REQ_SEND_MOD(task_req));
    mod_node_clone(recv_mod_node, TASK_REQ_RECV_MOD(task_req));
    TASK_REQ_RECV_MOD_FLAG(task_req) = EC_FALSE;

    TASK_REQ_TAG(task_req) = TAG_TASK_REQ;

    task_req_func = TASK_REQ_FUNC(task_req);

    task_req_func->func_id       = func_id;
    task_req_func->func_para_num = func_addr_node->func_para_num;
    task_req_func->func_ret_val  = (UINT32)func_retval_addr;

    va_start(ap, func_id);
    task_req_func_para_init(func_addr_node->func_para_num, (FUNC_PARA *)task_req_func->func_para, ap);
    va_end(ap);

    func_para = &(task_req_func->func_para[ 0 ]);
    func_para->para_val = MOD_NODE_MODI(recv_mod_node);
    TASK_REQ_MOD_ID_FLAG(task_req) = EC_FALSE;

    TASK_REQ_FUNC_ADDR_NODE(task_req) = func_addr_node;

    task_req_node = TASK_REQ_NODE(task_req);
    TASK_NODE_TAG(task_req_node)   = TASK_REQ_TAG(task_req);
    TASK_NODE_STATUS(task_req_node)= TASK_REQ_TO_SEND;

    TASK_MGR_ADD_REQ_TAIL(task_mgr, task_req);

    task_no_wait(task_mgr, time_to_live, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);
    return (0);
}

/*add task req to task mgr, the task req will send to best mod node of mod mgr of task mgr based on load balancing strategy of mod mgr*/
UINT32 task_inc(TASK_MGR *task_mgr,const void * func_retval_addr, const UINT32 func_id, ...)
{
    TASK_REQ  *task_req;
    TASK_NODE *task_req_node;

    MOD_NODE  *send_mod_node;

    MOD_MGR *mod_mgr;

    TASK_FUNC *task_req_func;

    FUNC_ADDR_NODE *func_addr_node;

    UINT32 mod_type;
    UINT32 sub_seqno;

    va_list ap;

    mod_type = (func_id >> (WORDSIZE / 2));
    if( MD_END <= mod_type )
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDERR, "error:task_inc: invalid func_id %lx\n", func_id);
        return ((UINT32)(-1));
    }

    mod_mgr = TASK_MGR_MOD(task_mgr);

    send_mod_node = (MOD_NODE  *)MOD_MGR_LOCAL_MOD(mod_mgr);

    mod_node_update_local_stat(send_mod_node);/*patch*/

    if(0 != dbg_fetch_func_addr_node_by_index(func_id, &func_addr_node))
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_inc: failed to fetch func addr node by func id %lx\n", func_id);
        return ((UINT32)(-1));
    }

    task_mgr_sub_seqno_gen(task_mgr, &sub_seqno);

    task_req = task_req_new(0, TASK_MGR_SEQNO(task_mgr), sub_seqno, TASK_NORMAL_TYPE, task_mgr, LOC_TASK_0249);

    mod_node_clone(send_mod_node, TASK_REQ_SEND_MOD(task_req));
    TASK_REQ_RECV_MOD_FLAG(task_req) = EC_TRUE; /*need to update*/

    TASK_REQ_TAG(task_req) = TAG_TASK_REQ;

    task_req_func = TASK_REQ_FUNC(task_req);

    task_req_func->func_id       = func_id;
    task_req_func->func_para_num = func_addr_node->func_para_num;
    task_req_func->func_ret_val  = (UINT32)func_retval_addr;

    va_start(ap, func_id);
    task_req_func_para_init(func_addr_node->func_para_num, (FUNC_PARA *)task_req_func->func_para, ap);
    va_end(ap);

    /*NOTE: replace the first parameter with mod id*/
    TASK_REQ_MOD_ID_FLAG(task_req) = EC_TRUE; /*need to update the mod id at first para*/

    TASK_REQ_FUNC_ADDR_NODE(task_req) = func_addr_node;

    task_req_node = TASK_REQ_NODE(task_req);
    TASK_NODE_TAG(task_req_node)   = TASK_REQ_TAG(task_req);
    TASK_NODE_STATUS(task_req_node)= TASK_REQ_TO_SEND;

    TASK_MGR_ADD_REQ_TAIL(task_mgr, task_req);

    return (0);
}

/*send task req to single best mod_node of mod_mgr based on load balancing strategy of mod_mgr*/
UINT32 task_mono(const MOD_MGR *mod_mgr, const UINT32 time_to_live, const UINT32 task_prio, const UINT32 task_need_rsp_flag, const UINT32 task_need_rsp_num, const UINT32 task_reschedule_flag, const void * func_retval_addr, const UINT32 func_id, ...)
{
    TASK_REQ  *task_req;
    TASK_NODE *task_req_node;

    MOD_NODE  *send_mod_node;

    TASK_FUNC *task_req_func;

    FUNC_ADDR_NODE *func_addr_node;
    TASK_MGR   *task_mgr;

    UINT32 mod_type;
    UINT32 sub_seqno;

    va_list ap;

    mod_type = (func_id >> (WORDSIZE / 2));
    if( MD_END <= mod_type )
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDERR, "error:task_mono: invalid func_id %lx\n", func_id);
        return ((UINT32)(-1));
    }

    if(0 != dbg_fetch_func_addr_node_by_index(func_id, &func_addr_node))
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_mono: failed to fetch func addr node by func id %lx\n", func_id);
        return ((UINT32)(-1));
    }

    task_mgr = task_new(mod_mgr, task_prio, task_need_rsp_flag, task_need_rsp_num);

    send_mod_node = (MOD_NODE  *)MOD_MGR_LOCAL_MOD(mod_mgr);
    mod_node_update_local_stat(send_mod_node);/*patch*/

    task_mgr_sub_seqno_gen(task_mgr, &sub_seqno);

    task_req = task_req_new(0, TASK_MGR_SEQNO(task_mgr), sub_seqno, TASK_NORMAL_TYPE, task_mgr, LOC_TASK_0250);

    mod_node_clone(send_mod_node, TASK_REQ_SEND_MOD(task_req));
    TASK_REQ_RECV_MOD_FLAG(task_req) = EC_TRUE; /*need to update*/

    TASK_REQ_TAG(task_req)    = TAG_TASK_REQ;

    task_req_func = TASK_REQ_FUNC(task_req);

    task_req_func->func_id       = func_id;
    task_req_func->func_para_num = func_addr_node->func_para_num;
    task_req_func->func_ret_val  = (UINT32)func_retval_addr;

    va_start(ap, func_id);
    task_req_func_para_init(func_addr_node->func_para_num, (FUNC_PARA *)task_req_func->func_para, ap);
    va_end(ap);

    /*NOTE: replace the first parameter with mod id*/
    TASK_REQ_MOD_ID_FLAG(task_req) = EC_TRUE; /*need to update the mod id at first para*/

    TASK_REQ_FUNC_ADDR_NODE(task_req) = func_addr_node;

    task_req_node = TASK_REQ_NODE(task_req);
    TASK_NODE_TAG(task_req_node)   = TASK_REQ_TAG(task_req);
    TASK_NODE_STATUS(task_req_node)= TASK_REQ_TO_SEND;

    TASK_MGR_ADD_REQ_TAIL(task_mgr, task_req);

    /*task_brd_task_mgr_add(task_brd, task_mgr);*/

    task_wait(task_mgr, time_to_live, task_reschedule_flag, NULL_PTR);

    return (0);
}

UINT32 task_mono_no_wait(const MOD_MGR *mod_mgr, const UINT32 time_to_live, const UINT32 task_prio, const UINT32 task_need_rsp_flag, const UINT32 task_need_rsp_num, const void * func_retval_addr, const UINT32 func_id, ...)
{
    TASK_REQ  *task_req;
    TASK_NODE *task_req_node;

    MOD_NODE  *send_mod_node;

    TASK_FUNC *task_req_func;

    FUNC_ADDR_NODE *func_addr_node;
    TASK_MGR   *task_mgr;

    UINT32 mod_type;
    UINT32 sub_seqno;

    va_list ap;

    mod_type = (func_id >> (WORDSIZE / 2));
    if( MD_END <= mod_type )
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDERR, "error:task_mono_no_wait: invalid func_id %lx\n", func_id);
        return ((UINT32)(-1));
    }

    if(0 != dbg_fetch_func_addr_node_by_index(func_id, &func_addr_node))
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_mono_no_wait: failed to fetch func addr node by func id %lx\n", func_id);
        return ((UINT32)(-1));
    }

    task_mgr = task_new(mod_mgr, task_prio, task_need_rsp_flag, task_need_rsp_num);

    send_mod_node = (MOD_NODE  *)MOD_MGR_LOCAL_MOD(mod_mgr);
    mod_node_update_local_stat(send_mod_node);/*patch*/

    task_mgr_sub_seqno_gen(task_mgr, &sub_seqno);

    task_req = task_req_new(0, TASK_MGR_SEQNO(task_mgr), sub_seqno, TASK_NORMAL_TYPE, task_mgr, LOC_TASK_0251);

    mod_node_clone(send_mod_node, TASK_REQ_SEND_MOD(task_req));
    TASK_REQ_RECV_MOD_FLAG(task_req) = EC_TRUE; /*need to update*/

    TASK_REQ_TAG(task_req)    = TAG_TASK_REQ;

    task_req_func = TASK_REQ_FUNC(task_req);

    task_req_func->func_id       = func_id;
    task_req_func->func_para_num = func_addr_node->func_para_num;
    task_req_func->func_ret_val  = (UINT32)func_retval_addr;

    va_start(ap, func_id);
    task_req_func_para_init(func_addr_node->func_para_num, (FUNC_PARA *)task_req_func->func_para, ap);
    va_end(ap);

    /*NOTE: replace the first parameter with mod id*/
    TASK_REQ_MOD_ID_FLAG(task_req) = EC_TRUE; /*need to update the mod id at first para*/

    TASK_REQ_FUNC_ADDR_NODE(task_req) = func_addr_node;

    task_req_node = TASK_REQ_NODE(task_req);
    TASK_NODE_TAG(task_req_node)   = TASK_REQ_TAG(task_req);
    TASK_NODE_STATUS(task_req_node)= TASK_REQ_TO_SEND;

    TASK_MGR_ADD_REQ_TAIL(task_mgr, task_req);

    /*task_brd_task_mgr_add(task_brd, task_mgr);*/

    task_no_wait(task_mgr, time_to_live, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    return (0);
}

/*add task req to task mgr, the task req will send to single mod_node of mod_mgr and ignore load balancing strategy of mod_mgr*/
UINT32 task_pos_inc(TASK_MGR *task_mgr, const UINT32 recv_mod_node_pos, const void * func_retval_addr, const UINT32 func_id, ...)
{
    TASK_REQ  *task_req;
    TASK_NODE *task_req_node;

    MOD_NODE  *send_mod_node;
    MOD_NODE  *recv_mod_node;

    TASK_FUNC *task_req_func;
    FUNC_PARA *func_para;

    FUNC_ADDR_NODE *func_addr_node;
    MOD_MGR   *mod_mgr;

    UINT32 mod_type;

    va_list ap;

    UINT32 task_seqno;
    UINT32 sub_seqno;

    mod_type = (func_id >> (WORDSIZE / 2));
    if( MD_END <= mod_type )
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_pos_inc: invalid func_id %lx\n", func_id);
        return ((UINT32)(-1));
    }

    mod_mgr = TASK_MGR_MOD(task_mgr);

    if(recv_mod_node_pos >= MOD_MGR_REMOTE_NUM(mod_mgr))
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_pos_inc: recv_mod_node_pos %ld is overflow where mod mgr remote mod num is %ld\n",
                        recv_mod_node_pos, MOD_MGR_REMOTE_NUM(mod_mgr));

        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_pos_inc: mod_mgr %p remote mod nodes list: \n", mod_mgr);
        cvector_print(LOGSTDOUT, MOD_MGR_REMOTE_LIST((MOD_MGR *)mod_mgr), (CVECTOR_DATA_PRINT)mod_node_print);
        return ((UINT32)(-1));
    }

    if(0 != dbg_fetch_func_addr_node_by_index(func_id, &func_addr_node))
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_pos_inc: failed to fetch func addr node by func id %lx\n", func_id);
        return ((UINT32)(-1));
    }

    send_mod_node = (MOD_NODE  *)MOD_MGR_LOCAL_MOD(mod_mgr);
    recv_mod_node = (MOD_NODE  *)cvector_get(MOD_MGR_REMOTE_LIST(mod_mgr), recv_mod_node_pos);

    task_seqno = TASK_MGR_SEQNO(task_mgr);

    task_mgr_sub_seqno_gen(task_mgr, &sub_seqno);

    task_req = task_req_new(0, task_seqno, sub_seqno, TASK_NORMAL_TYPE, task_mgr, LOC_TASK_0252);

    mod_node_clone(send_mod_node, TASK_REQ_SEND_MOD(task_req));
    mod_node_clone(recv_mod_node, TASK_REQ_RECV_MOD(task_req));
    TASK_REQ_RECV_MOD_FLAG(task_req) = EC_FALSE; /*not need to update*/

    mod_node_update_local_stat(TASK_REQ_SEND_MOD(task_req));/*patch*/

    TASK_REQ_TAG(task_req)    = TAG_TASK_REQ;

    task_req_func = TASK_REQ_FUNC(task_req);

    task_req_func->func_id       = func_id;
    task_req_func->func_para_num = func_addr_node->func_para_num;
    task_req_func->func_ret_val  = (UINT32)func_retval_addr;

    va_start(ap, func_id);
    task_req_func_para_init(func_addr_node->func_para_num, (FUNC_PARA *)task_req_func->func_para, ap);
    va_end(ap);

    /*NOTE: replace the first parameter with mod id*/
    func_para = &(task_req_func->func_para[ 0 ]);
    func_para->para_val = MOD_NODE_MODI(recv_mod_node);
    TASK_REQ_MOD_ID_FLAG(task_req) = EC_FALSE; /*not need to update*/

    TASK_REQ_FUNC_ADDR_NODE(task_req) = func_addr_node;

    task_req_node = TASK_REQ_NODE(task_req);
    TASK_NODE_TAG(task_req_node)   = TASK_REQ_TAG(task_req);
    TASK_NODE_STATUS(task_req_node)= TASK_REQ_TO_SEND;

    TASK_MGR_ADD_REQ_TAIL(task_mgr, task_req);

    return (0);
}

/*send task req to single mod_node of mod_mgr and ignore load balancing strategy of mod_mgr*/
UINT32 task_pos_mono(const MOD_MGR *mod_mgr, const UINT32 time_to_live, const UINT32 task_prio, const UINT32 task_need_rsp_flag, const UINT32 task_need_rsp_num, const UINT32  recv_mod_node_pos, const void * func_retval_addr, const UINT32 func_id, ...)
{
    TASK_REQ  *task_req;
    TASK_NODE *task_req_node;

    MOD_NODE  *send_mod_node;
    MOD_NODE  *recv_mod_node;

    TASK_FUNC *task_req_func;
    FUNC_PARA *func_para;

    FUNC_ADDR_NODE *func_addr_node;
    TASK_MGR   *task_mgr;

    UINT32 mod_type;

    va_list ap;

    UINT32 sub_seqno;

    mod_type = (func_id >> (WORDSIZE / 2));
    if( MD_END <= mod_type )
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDERR, "error:task_pos_mono: invalid func_id %lx\n", func_id);
        return ((UINT32)(-1));
    }

    if(recv_mod_node_pos >= MOD_MGR_REMOTE_NUM(mod_mgr))
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_pos_mono: recv_mod_node_pos %ld is overflow where mod mgr remote mod num is %ld\n",
                        recv_mod_node_pos, MOD_MGR_REMOTE_NUM(mod_mgr));

        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_pos_mono: mod_mgr %p remote mod nodes list: ", mod_mgr);
        cvector_print(LOGSTDOUT, MOD_MGR_REMOTE_LIST(mod_mgr), (CVECTOR_DATA_PRINT)mod_node_print);
        return ((UINT32)(-1));
    }

    if(0 != dbg_fetch_func_addr_node_by_index(func_id, &func_addr_node))
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_pos_mono: failed to fetch func addr node by func id %lx\n", func_id);
        return ((UINT32)(-1));
    }

    task_mgr = task_new(mod_mgr, task_prio, task_need_rsp_flag, task_need_rsp_num);

    send_mod_node = (MOD_NODE  *)MOD_MGR_LOCAL_MOD(mod_mgr);
    recv_mod_node = (MOD_NODE  *)cvector_get(MOD_MGR_REMOTE_LIST(mod_mgr), recv_mod_node_pos);

    task_mgr_sub_seqno_gen(task_mgr, &sub_seqno);

    task_req = task_req_new(0, TASK_MGR_SEQNO(task_mgr), sub_seqno, TASK_NORMAL_TYPE, task_mgr, LOC_TASK_0253);

    mod_node_clone(send_mod_node, TASK_REQ_SEND_MOD(task_req));
    mod_node_clone(recv_mod_node, TASK_REQ_RECV_MOD(task_req));
    TASK_REQ_RECV_MOD_FLAG(task_req) = EC_FALSE; /*not need to update*/

    mod_node_update_local_stat(TASK_REQ_SEND_MOD(task_req));/*patch*/

    TASK_REQ_TAG(task_req)    = TAG_TASK_REQ;

    task_req_func = TASK_REQ_FUNC(task_req);

    task_req_func->func_id       = func_id;
    task_req_func->func_para_num = func_addr_node->func_para_num;
    task_req_func->func_ret_val  = (UINT32)func_retval_addr;

    va_start(ap, func_id);
    task_req_func_para_init(func_addr_node->func_para_num, (FUNC_PARA *)task_req_func->func_para, ap);
    va_end(ap);

    /*NOTE: replace the first parameter with mod id*/
    func_para = &(task_req_func->func_para[ 0 ]);
    func_para->para_val = MOD_NODE_MODI(recv_mod_node);
    TASK_REQ_MOD_ID_FLAG(task_req) = EC_FALSE; /*not need to update*/

    TASK_REQ_FUNC_ADDR_NODE(task_req) = func_addr_node;

    task_req_node = TASK_REQ_NODE(task_req);
    TASK_NODE_TAG(task_req_node)   = TASK_REQ_TAG(task_req);
    TASK_NODE_STATUS(task_req_node)= TASK_REQ_TO_SEND;

    TASK_MGR_ADD_REQ_TAIL(task_mgr, task_req);

    /*task_brd_task_mgr_add(task_brd, task_mgr);*/

    task_wait(task_mgr, time_to_live, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);
    return (0);
}

UINT32 task_pos_mono_no_wait(const MOD_MGR *mod_mgr, const UINT32 time_to_live, const UINT32 task_prio, const UINT32 task_need_rsp_flag, const UINT32 task_need_rsp_num, const UINT32  recv_mod_node_pos, const void * func_retval_addr, const UINT32 func_id, ...)
{
    TASK_REQ  *task_req;
    TASK_NODE *task_req_node;

    MOD_NODE  *send_mod_node;
    MOD_NODE  *recv_mod_node;

    TASK_FUNC *task_req_func;
    FUNC_PARA *func_para;

    FUNC_ADDR_NODE *func_addr_node;
    TASK_MGR   *task_mgr;

    UINT32 mod_type;

    va_list ap;

    UINT32 sub_seqno;

    mod_type = (func_id >> (WORDSIZE / 2));
    if( MD_END <= mod_type )
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDERR, "error:task_pos_mono_no_wait: invalid func_id %lx\n", func_id);
        return ((UINT32)(-1));
    }

    if(recv_mod_node_pos >= MOD_MGR_REMOTE_NUM(mod_mgr))
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_pos_mono_no_wait: recv_mod_node_pos %ld is overflow where mod mgr remote mod num is %ld\n",
                        recv_mod_node_pos, MOD_MGR_REMOTE_NUM(mod_mgr));

        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_pos_mono_no_wait: mod_mgr %p remote mod nodes list: ", mod_mgr);
        cvector_print(LOGSTDOUT, MOD_MGR_REMOTE_LIST(mod_mgr), (CVECTOR_DATA_PRINT)mod_node_print);
        return ((UINT32)(-1));
    }

    if(0 != dbg_fetch_func_addr_node_by_index(func_id, &func_addr_node))
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_pos_mono_no_wait: failed to fetch func addr node by func id %lx\n", func_id);
        return ((UINT32)(-1));
    }

    task_mgr = task_new(mod_mgr, task_prio, task_need_rsp_flag, task_need_rsp_num);

    send_mod_node = (MOD_NODE  *)MOD_MGR_LOCAL_MOD(mod_mgr);
    recv_mod_node = (MOD_NODE  *)cvector_get(MOD_MGR_REMOTE_LIST(mod_mgr), recv_mod_node_pos);

    task_mgr_sub_seqno_gen(task_mgr, &sub_seqno);

    task_req = task_req_new(0, TASK_MGR_SEQNO(task_mgr), sub_seqno, TASK_NORMAL_TYPE, task_mgr, LOC_TASK_0254);

    mod_node_clone(send_mod_node, TASK_REQ_SEND_MOD(task_req));
    mod_node_clone(recv_mod_node, TASK_REQ_RECV_MOD(task_req));
    TASK_REQ_RECV_MOD_FLAG(task_req) = EC_FALSE; /*not need to update*/

    mod_node_update_local_stat(TASK_REQ_SEND_MOD(task_req));/*patch*/

    TASK_REQ_TAG(task_req)    = TAG_TASK_REQ;

    task_req_func = TASK_REQ_FUNC(task_req);

    task_req_func->func_id       = func_id;
    task_req_func->func_para_num = func_addr_node->func_para_num;
    task_req_func->func_ret_val  = (UINT32)func_retval_addr;

    va_start(ap, func_id);
    task_req_func_para_init(func_addr_node->func_para_num, (FUNC_PARA *)task_req_func->func_para, ap);
    va_end(ap);

    /*NOTE: replace the first parameter with mod id*/
    func_para = &(task_req_func->func_para[ 0 ]);
    func_para->para_val = MOD_NODE_MODI(recv_mod_node);
    TASK_REQ_MOD_ID_FLAG(task_req) = EC_FALSE; /*not need to update*/

    TASK_REQ_FUNC_ADDR_NODE(task_req) = func_addr_node;

    task_req_node = TASK_REQ_NODE(task_req);
    TASK_NODE_TAG(task_req_node)   = TASK_REQ_TAG(task_req);
    TASK_NODE_STATUS(task_req_node)= TASK_REQ_TO_SEND;

    TASK_MGR_ADD_REQ_TAIL(task_mgr, task_req);

    /*task_brd_task_mgr_add(task_brd, task_mgr);*/

    task_no_wait(task_mgr, time_to_live, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);
    return (0);
}

UINT32 task_tcid_inc(TASK_MGR *task_mgr, const UINT32 recv_tcid, const void * func_retval_addr, const UINT32 func_id, ...)
{
    TASK_REQ  *task_req;
    TASK_NODE *task_req_node;

    MOD_NODE  *send_mod_node;
    MOD_NODE  *recv_mod_node;

    TASK_FUNC *task_req_func;
    FUNC_PARA *func_para;

    FUNC_ADDR_NODE *func_addr_node;

    MOD_MGR *mod_mgr;

    UINT32 mod_type;

    va_list ap;

    UINT32 task_seqno;
    UINT32 sub_seqno;

    mod_type = (func_id >> (WORDSIZE / 2));
    if( MD_END <= mod_type )
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDERR, "error:task_tcid_inc: invalid func_id %lx\n", func_id);
        return ((UINT32)(-1));
    }

    mod_mgr = TASK_MGR_MOD(task_mgr);

    recv_mod_node = mod_mgr_find_min_load_with_tcid_filter(mod_mgr, recv_tcid);
    if(NULL_PTR == recv_mod_node)
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDERR, "error:task_tcid_inc: no mod_node with tcid %s in mod_mgr %p\n", c_word_to_ipv4(recv_tcid), mod_mgr);
        return ((UINT32)(-1));
    }

    if(0 != dbg_fetch_func_addr_node_by_index(func_id, &func_addr_node))
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_tcid_inc: failed to fetch func addr node by func id %lx\n", func_id);
        return ((UINT32)(-1));
    }

    //task_brd_seqno_gen(task_brd, &task_seqno);

    send_mod_node = (MOD_NODE  *)MOD_MGR_LOCAL_MOD(mod_mgr);

    task_seqno = TASK_MGR_SEQNO(task_mgr);

    task_mgr_sub_seqno_gen(task_mgr, &sub_seqno);

    task_req = task_req_new(0, task_seqno, sub_seqno, TASK_NORMAL_TYPE, task_mgr, LOC_TASK_0255);

    mod_node_clone(send_mod_node, TASK_REQ_SEND_MOD(task_req));
    mod_node_clone(recv_mod_node, TASK_REQ_RECV_MOD(task_req));
    TASK_REQ_RECV_MOD_FLAG(task_req) = EC_FALSE;

    mod_node_update_local_stat(TASK_REQ_SEND_MOD(task_req));/*patch*/

    TASK_REQ_TAG(task_req) = TAG_TASK_REQ;

    task_req_func = TASK_REQ_FUNC(task_req);

    task_req_func->func_id       = func_id;
    task_req_func->func_para_num = func_addr_node->func_para_num;
    task_req_func->func_ret_val  = (UINT32)func_retval_addr;

    va_start(ap, func_id);
    task_req_func_para_init(func_addr_node->func_para_num, (FUNC_PARA *)task_req_func->func_para, ap);
    va_end(ap);

    func_para = &(task_req_func->func_para[ 0 ]);
    func_para->para_val = MOD_NODE_MODI(recv_mod_node);
    TASK_REQ_MOD_ID_FLAG(task_req) = EC_FALSE;

    TASK_REQ_FUNC_ADDR_NODE(task_req) = func_addr_node;

    task_req_node = TASK_REQ_NODE(task_req);
    TASK_NODE_TAG(task_req_node)   = TASK_REQ_TAG(task_req);
    TASK_NODE_STATUS(task_req_node)= TASK_REQ_TO_SEND;

    TASK_MGR_ADD_REQ_TAIL(task_mgr, task_req);

    return (0);
}

UINT32 task_tcid_mono(const MOD_MGR *mod_mgr, const UINT32 time_to_live, const UINT32 task_prio, const UINT32 task_need_rsp_flag, const UINT32 task_need_rsp_num, const UINT32 recv_tcid, const void * func_retval_addr, const UINT32 func_id, ...)
{
    TASK_REQ  *task_req;
    TASK_NODE *task_req_node;

    MOD_NODE  *send_mod_node;
    MOD_NODE  *recv_mod_node;

    TASK_FUNC *task_req_func;
    FUNC_PARA *func_para;

    FUNC_ADDR_NODE *func_addr_node;
    TASK_MGR   *task_mgr;

    UINT32 mod_type;

    va_list ap;

    UINT32 sub_seqno;

    mod_type = (func_id >> (WORDSIZE / 2));
    if( MD_END <= mod_type )
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDERR, "error:task_tcid_mono: invalid func_id %lx\n", func_id);
        return ((UINT32)(-1));
    }

    recv_mod_node = mod_mgr_find_min_load_with_tcid_filter(mod_mgr, recv_tcid);
    if(NULL_PTR == recv_mod_node)
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDERR, "error:task_tcid_mono: no mod_node with tcid %s in mod_mgr %p\n", c_word_to_ipv4(recv_tcid), mod_mgr);
        return ((UINT32)(-1));
    }

    if(0 != dbg_fetch_func_addr_node_by_index(func_id, &func_addr_node))
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_tcid_mono: failed to fetch func addr node by func id %lx\n", func_id);
        return ((UINT32)(-1));
    }

    task_mgr = task_new(mod_mgr, task_prio, task_need_rsp_flag, task_need_rsp_num);

    send_mod_node = (MOD_NODE  *)MOD_MGR_LOCAL_MOD(mod_mgr);

    task_mgr_sub_seqno_gen(task_mgr, &sub_seqno);

    task_req = task_req_new(0, TASK_MGR_SEQNO(task_mgr), sub_seqno, TASK_NORMAL_TYPE, task_mgr, LOC_TASK_0256);

    mod_node_clone(send_mod_node, TASK_REQ_SEND_MOD(task_req));
    mod_node_clone(recv_mod_node, TASK_REQ_RECV_MOD(task_req));
    TASK_REQ_RECV_MOD_FLAG(task_req) = EC_FALSE;

    mod_node_update_local_stat(TASK_REQ_SEND_MOD(task_req));/*patch*/

    TASK_REQ_TAG(task_req) = TAG_TASK_REQ;

    task_req_func = TASK_REQ_FUNC(task_req);

    task_req_func->func_id       = func_id;
    task_req_func->func_para_num = func_addr_node->func_para_num;
    task_req_func->func_ret_val  = (UINT32)func_retval_addr;

    va_start(ap, func_id);
    task_req_func_para_init(func_addr_node->func_para_num, (FUNC_PARA *)task_req_func->func_para, ap);
    va_end(ap);

    func_para = &(task_req_func->func_para[ 0 ]);
    func_para->para_val = MOD_NODE_MODI(recv_mod_node);
    TASK_REQ_MOD_ID_FLAG(task_req) = EC_FALSE;

    TASK_REQ_FUNC_ADDR_NODE(task_req) = func_addr_node;

    task_req_node = TASK_REQ_NODE(task_req);
    TASK_NODE_TAG(task_req_node)   = TASK_REQ_TAG(task_req);
    TASK_NODE_STATUS(task_req_node)= TASK_REQ_TO_SEND;

    TASK_MGR_ADD_REQ_TAIL(task_mgr, task_req);

    task_wait(task_mgr, time_to_live, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);
    return (0);
}

UINT32 task_tcid_mono_no_wait(const MOD_MGR *mod_mgr, const UINT32 time_to_live, const UINT32 task_prio, const UINT32 task_need_rsp_flag, const UINT32 task_need_rsp_num, const UINT32 recv_tcid, const void * func_retval_addr, const UINT32 func_id, ...)
{
    TASK_REQ  *task_req;
    TASK_NODE *task_req_node;

    MOD_NODE  *send_mod_node;
    MOD_NODE  *recv_mod_node;

    TASK_FUNC *task_req_func;
    FUNC_PARA *func_para;

    FUNC_ADDR_NODE *func_addr_node;
    TASK_MGR   *task_mgr;

    UINT32 mod_type;

    va_list ap;

    UINT32 sub_seqno;

    mod_type = (func_id >> (WORDSIZE / 2));
    if( MD_END <= mod_type )
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDERR, "error:task_tcid_mono_no_wait: invalid func_id %lx\n", func_id);
        return ((UINT32)(-1));
    }

    recv_mod_node = mod_mgr_find_min_load_with_tcid_filter(mod_mgr, recv_tcid);
    if(NULL_PTR == recv_mod_node)
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDERR, "error:task_tcid_mono_no_wait: no mod_node with tcid %s in mod_mgr %p\n", c_word_to_ipv4(recv_tcid), mod_mgr);
        return ((UINT32)(-1));
    }

    if(0 != dbg_fetch_func_addr_node_by_index(func_id, &func_addr_node))
    {
        dbg_log(SEC_0015_TASK, 0)(LOGSTDOUT, "error:task_tcid_mono_no_wait: failed to fetch func addr node by func id %lx\n", func_id);
        return ((UINT32)(-1));
    }

    task_mgr = task_new(mod_mgr, task_prio, task_need_rsp_flag, task_need_rsp_num);

    send_mod_node = (MOD_NODE  *)MOD_MGR_LOCAL_MOD(mod_mgr);

    task_mgr_sub_seqno_gen(task_mgr, &sub_seqno);

    task_req = task_req_new(0, TASK_MGR_SEQNO(task_mgr), sub_seqno, TASK_NORMAL_TYPE, task_mgr, LOC_TASK_0257);

    mod_node_clone(send_mod_node, TASK_REQ_SEND_MOD(task_req));
    mod_node_clone(recv_mod_node, TASK_REQ_RECV_MOD(task_req));
    TASK_REQ_RECV_MOD_FLAG(task_req) = EC_FALSE;

    mod_node_update_local_stat(TASK_REQ_SEND_MOD(task_req));/*patch*/

    TASK_REQ_TAG(task_req) = TAG_TASK_REQ;

    task_req_func = TASK_REQ_FUNC(task_req);

    task_req_func->func_id       = func_id;
    task_req_func->func_para_num = func_addr_node->func_para_num;
    task_req_func->func_ret_val  = (UINT32)func_retval_addr;

    va_start(ap, func_id);
    task_req_func_para_init(func_addr_node->func_para_num, (FUNC_PARA *)task_req_func->func_para, ap);
    va_end(ap);

    func_para = &(task_req_func->func_para[ 0 ]);
    func_para->para_val = MOD_NODE_MODI(recv_mod_node);
    TASK_REQ_MOD_ID_FLAG(task_req) = EC_FALSE;

    TASK_REQ_FUNC_ADDR_NODE(task_req) = func_addr_node;

    task_req_node = TASK_REQ_NODE(task_req);
    TASK_NODE_TAG(task_req_node)   = TASK_REQ_TAG(task_req);
    TASK_NODE_STATUS(task_req_node)= TASK_REQ_TO_SEND;

    TASK_MGR_ADD_REQ_TAIL(task_mgr, task_req);

    task_no_wait(task_mgr, time_to_live, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);
    return (0);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

