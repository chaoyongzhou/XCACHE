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

#ifndef _CONTROL_H
#define _CONTROL_H

/*Super Package Debug Switch*/
#define SUPER_DEBUG_SWITCH SWITCH_ON

/*CRFS Package Debug Switch*/
#define CRFS_DEBUG_SWITCH SWITCH_ON

/*CRFSMON Package Debug Switch*/
#define CRFSMON_DEBUG_SWITCH SWITCH_ON

/*CRFSC Package Debug Switch*/
#define CRFSC_DEBUG_SWITCH SWITCH_ON

/*CXFS Package Debug Switch*/
#define CXFS_DEBUG_SWITCH SWITCH_ON

/*CXFSMON Package Debug Switch*/
#define CXFSMON_DEBUG_SWITCH SWITCH_ON

/*CSESSION Package Debug Switch*/
#define CSESSION_DEBUG_SWITCH SWITCH_ON

/*CTimer Package Debug Switch*/
#define CTIMER_DEBUG_SWITCH SWITCH_ON

/*CVENDOR Package Debug Switch*/
#define CVENDOR_DEBUG_SWITCH SWITCH_ON

/*CREFRESH Package Debug Switch*/
#define CREFRESH_DEBUG_SWITCH SWITCH_ON

/*CRFSGW Package Debug Switch*/
#define CRFSGW_DEBUG_SWITCH SWITCH_ON

/*CFLV Package Debug Switch*/
#define CFLV_DEBUG_SWITCH SWITCH_ON

/*CMP4 Package Debug Switch*/
#define CMP4_DEBUG_SWITCH SWITCH_ON

/*CTDNS Package Debug Switch*/
#define CTDNS_DEBUG_SWITCH SWITCH_ON

/*CDETECTN Package Debug Switch*/
#define CDETECTN_DEBUG_SWITCH SWITCH_ON

/*CDETECT Package Debug Switch*/
#define CDETECT_DEBUG_SWITCH SWITCH_ON

/*CP2P Package Debug Switch*/
#define CP2P_DEBUG_SWITCH SWITCH_ON

/*CMIAOPAI Package Debug Switch*/
#define CMIAOPAI_DEBUG_SWITCH SWITCH_ON

/*CLOOPBACK Package Debug Switch*/
#define CLOOPBACK_DEBUG_SWITCH SWITCH_ON

/*CFILE Package Debug Switch*/
#define CFILE_DEBUG_SWITCH SWITCH_ON

/*Encode/Decode Functions Debug Switch*/
#define ENCODE_DEBUG_SWITCH SWITCH_ON

/*Task Functions Debug Switch*/
#define TASK_DEBUG_SWITCH SWITCH_ON

/*TASKC Functions Debug Switch*/
#define TASKC_DEBUG_SWITCH SWITCH_ON

/*Static Memory Control Switch*/
#define STATIC_MEMORY_SWITCH SWITCH_ON

/*Print Static Memory Stats Info Switch*/
#define STATIC_MEM_STATS_INFO_PRINT_SWITCH SWITCH_OFF

/*Static Memory Diagnostication Location Switch*/
#define STATIC_MEM_DIAG_LOC_SWITCH SWITCH_ON

/*Stack Memory Control Switch*/
#define STACK_MEMORY_SWITCH SWITCH_OFF

/*CLIST Memory Control Switch*/
#define CLIST_STATIC_MEM_SWITCH SWITCH_ON

/*CSET Memory Control Switch*/
#define CSET_STATIC_MEM_SWITCH SWITCH_OFF

/*CSTACK Memory Control Switch*/
#define CSTACK_STATIC_MEM_SWITCH SWITCH_OFF

/*CQUEUE Memory Control Switch*/
#define CQUEUE_STATIC_MEM_SWITCH SWITCH_OFF

#if (STATIC_MEMORY_SWITCH == STACK_MEMORY_SWITCH)
#error "fatal error: STATIC_MEMORY_SWITCH equal to STACK_MEMORY_SWITCH"
#endif/* STATIC_MEMORY_SWITCH == STACK_MEMORY_SWITCH */

#define ASM_DISABLE_SWITCH SWITCH_ON

#endif /* _CONTROL_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/

