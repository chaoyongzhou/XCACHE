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

#include "type.h"
#include "mm.h"
#include "log.h"

#include "debug.h"

#include "cmpic.inc"
#include "mod.h"
#include "task.h"

#include "cbc.h"
#include "cstring.h"
#include "tbd.h"

#include "crun.h"

#define TBD_MD_CAPACITY()             (cbc_md_capacity(MD_TBD))

#define TBD_MD_GET(tbd_md_id)     ((TBD_MD *)cbc_md_get(MD_TBD, (tbd_md_id)))

#define TBD_MD_ID_CHECK_INVALID(tbd_md_id)  \
    ( NULL_PTR == TBD_MD_GET(tbd_md_id) || 0 == (TBD_MD_GET(tbd_md_id)->usedcounter) )


/**
*   for test only
*
*   to query the status of TBD Module
*
**/
void tbd_print_module_status(const UINT32 tbd_md_id, LOG *log)
{
    TBD_MD *tbd_md;
    UINT32 this_tbd_md_id;

    for( this_tbd_md_id = 0; this_tbd_md_id < TBD_MD_CAPACITY(); this_tbd_md_id ++ )
    {
        tbd_md = TBD_MD_GET(this_tbd_md_id);

        if ( NULL_PTR != tbd_md && 0 < tbd_md->usedcounter )
        {
            sys_log(log,"TBD Module # %ld : %ld refered\n",
                    this_tbd_md_id,
                    tbd_md->usedcounter);
        }
    }

    return ;
}

/**
*
*   free all static memory occupied by the appointed TBD module
*
*
**/
UINT32 tbd_free_module_static_mem(const UINT32 tbd_md_id)
{
    if ( TBD_MD_ID_CHECK_INVALID(tbd_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:tbd_free_module_static_mem: matrixr module #0x%lx not started.\n",
                tbd_md_id);
        /*note: here do not exit but return only*/
        return ((UINT32)(-1));
    }

    //free_module_static_mem(MD_TBD, tbd_md_id);

    return 0;
}

/**
*
* start TBD module
*
**/
UINT32 tbd_start( )
{
    TBD_MD *tbd_md;
    UINT32 tbd_md_id;

    tbd_md_id = cbc_md_new(MD_TBD, sizeof(TBD_MD));
    if(CMPI_ERROR_MODI == tbd_md_id)
    {
        return (CMPI_ERROR_MODI);
    }

    /* initialize new one TBD module */
    tbd_md = (TBD_MD *)cbc_md_get(MD_TBD, tbd_md_id);
    tbd_md->usedcounter   = 0;

    init_static_mem();

    /*default setting which will be override after tbd_set_mod_mgr calling*/
    tbd_md->mod_mgr = mod_mgr_new(tbd_md_id, LOAD_BALANCING_LOOP);

    tbd_md->usedcounter = 1;

    dbg_log(SEC_0079_TBD, 5)(LOGSTDOUT, "tbd_start: start TBD module #%ld\n", tbd_md_id);

    return ( tbd_md_id );
}

/**
*
* end TBD module
*
**/
void tbd_end(const UINT32 tbd_md_id)
{
    TBD_MD *tbd_md;

    tbd_md = TBD_MD_GET(tbd_md_id);
    if(NULL_PTR == tbd_md)
    {
        dbg_log(SEC_0079_TBD, 0)(LOGSTDOUT,"error:tbd_end: tbd_md_id = %ld not exist.\n", tbd_md_id);
        dbg_exit(MD_TBD, tbd_md_id);
    }

    /* if the module is occupied by others,then decrease counter only */
    if ( 1 < tbd_md->usedcounter )
    {
        tbd_md->usedcounter --;
        return ;
    }

    if ( 0 == tbd_md->usedcounter )
    {
        dbg_log(SEC_0079_TBD, 0)(LOGSTDOUT,"error:tbd_end: tbd_md_id = %ld is not started.\n", tbd_md_id);
        dbg_exit(MD_TBD, tbd_md_id);
    }

    //task_brd_mod_mgr_rmv(tbd_md->task_brd, tbd_md->mod_mgr);
    mod_mgr_free(tbd_md->mod_mgr);
    tbd_md->mod_mgr  = NULL_PTR;

    tbd_md->usedcounter = 0;

    dbg_log(SEC_0079_TBD, 5)(LOGSTDOUT, "tbd_end: stop TBD module #%ld\n", tbd_md_id);

    cbc_md_free(MD_TBD, tbd_md_id);

    breathing_static_mem();

    return ;
}


/**
*
* initialize mod mgr of TBD module
*
**/
UINT32 tbd_set_mod_mgr(const UINT32 tbd_md_id, const MOD_MGR * src_mod_mgr)
{
    TBD_MD *tbd_md;
    MOD_MGR * des_mod_mgr;

#if ( SWITCH_ON == MATRIX_DEBUG_SWITCH )
    if ( TBD_MD_ID_CHECK_INVALID(tbd_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:tbd_set_mod_mgr: matrixr module #0x%lx not started.\n",
                tbd_md_id);
        tbd_print_module_status(tbd_md_id, LOGSTDOUT);
        dbg_exit(MD_TBD, tbd_md_id);
    }
#endif/*MATRIX_DEBUG_SWITCH*/

    tbd_md = TBD_MD_GET(tbd_md_id);
    des_mod_mgr = tbd_md->mod_mgr;

    //dbg_log(SEC_0079_TBD, 5)(LOGSTDOUT, "tbd_set_mod_mgr: md_id %d, des_mod_mgr %lx\n", tbd_md_id, des_mod_mgr);

    mod_mgr_limited_clone(tbd_md_id, src_mod_mgr, des_mod_mgr);
    return (0);
}

/**
*
* get mod mgr of TBD module
*
**/
MOD_MGR * tbd_get_mod_mgr(const UINT32 tbd_md_id)
{
    TBD_MD *tbd_md;

    if ( TBD_MD_ID_CHECK_INVALID(tbd_md_id) )
    {
        return (MOD_MGR *)0;
    }

    tbd_md = TBD_MD_GET(tbd_md_id);
    return tbd_md->mod_mgr;
}

UINT32 tbd_run(const UINT32 tbd_md_id, const void * ui_retval_addr, const UINT32 ui_id, ...)
{
    FUNC_ADDR_NODE *func_addr_node;
    UINT32 func_addr;
    UINT32 func_para_num;
    UINT32 func_para_idx;
    UINT32 func_para_value[ MAX_NUM_OF_FUNC_PARAS ];
    UINT32 func_ret_value;

    va_list ap;

    //dbg_log(SEC_0079_TBD, 5)(LOGSTDOUT, "tbd_run: being called!\n");

    if(0 != dbg_fetch_func_addr_node_by_index(ui_id, &func_addr_node))
    {
        dbg_log(SEC_0079_TBD, 0)(LOGSTDOUT, "error:tbd_run: failed to fetch ui func addr node by ui id %lx\n", ui_id);
        return ((UINT32)-1);
    }

    func_addr      = func_addr_node->func_logic_addr;
    func_para_num  = func_addr_node->func_para_num;

    va_start(ap, ui_id);
    for( func_para_idx = 0; func_para_idx < func_para_num; func_para_idx ++ )
    {
        func_para_value[ func_para_idx ] = va_arg(ap, UINT32);
    }
    va_end(ap);

#if (16 != MAX_NUM_OF_FUNC_PARAS)
#error "fatal error:tbd.c: MAX_NUM_OF_FUNC_PARAS != 16"
#endif
    #define PARA_VALUE(func_para, x)    ((func_para)[ (x) ])

    #define PARA_LIST_0(func_para)    /*no parameter*/
    #define PARA_LIST_1(func_para)    PARA_VALUE(func_para, 0)
    #define PARA_LIST_2(func_para)    PARA_LIST_1(func_para) ,PARA_VALUE(func_para, 1)
    #define PARA_LIST_3(func_para)    PARA_LIST_2(func_para) ,PARA_VALUE(func_para, 2)
    #define PARA_LIST_4(func_para)    PARA_LIST_3(func_para) ,PARA_VALUE(func_para, 3)
    #define PARA_LIST_5(func_para)    PARA_LIST_4(func_para) ,PARA_VALUE(func_para, 4)
    #define PARA_LIST_6(func_para)    PARA_LIST_5(func_para) ,PARA_VALUE(func_para, 5)
    #define PARA_LIST_7(func_para)    PARA_LIST_6(func_para) ,PARA_VALUE(func_para, 6)
    #define PARA_LIST_8(func_para)    PARA_LIST_7(func_para) ,PARA_VALUE(func_para, 7)
    #define PARA_LIST_9(func_para)    PARA_LIST_8(func_para) ,PARA_VALUE(func_para, 8)
    #define PARA_LIST_10(func_para)   PARA_LIST_9(func_para) ,PARA_VALUE(func_para, 9)
    #define PARA_LIST_11(func_para)   PARA_LIST_10(func_para),PARA_VALUE(func_para, 10)
    #define PARA_LIST_12(func_para)   PARA_LIST_11(func_para),PARA_VALUE(func_para, 11)
    #define PARA_LIST_13(func_para)   PARA_LIST_12(func_para),PARA_VALUE(func_para, 12)
    #define PARA_LIST_14(func_para)   PARA_LIST_13(func_para),PARA_VALUE(func_para, 13)
    #define PARA_LIST_15(func_para)   PARA_LIST_14(func_para),PARA_VALUE(func_para, 14)
    #define PARA_LIST_16(func_para)   PARA_LIST_15(func_para),PARA_VALUE(func_para, 15)

    #define FUNC_CALL(x, func_addr, func_para) \
            ((FUNC_TYPE_##x) func_addr)(PARA_LIST_##x(func_para))

    switch(func_para_num)
    {
        case 0:
            func_ret_value = FUNC_CALL(0, func_addr, func_para_value);
            break;
        case 1:
            func_ret_value = FUNC_CALL(1, func_addr, func_para_value);
            break;
        case 2:
            func_ret_value = FUNC_CALL(2, func_addr, func_para_value);
            break;
        case 3:
            func_ret_value = FUNC_CALL(3, func_addr, func_para_value);
            break;
        case 4:
            func_ret_value = FUNC_CALL(4, func_addr, func_para_value);
            break;
        case 5:
            func_ret_value = FUNC_CALL(5, func_addr, func_para_value);
            break;
        case 6:
            func_ret_value = FUNC_CALL(6, func_addr, func_para_value);
            break;
        case 7:
            func_ret_value = FUNC_CALL(7, func_addr, func_para_value);
            break;
        case 8:
            func_ret_value = FUNC_CALL(8, func_addr, func_para_value);
            break;
        case 9:
            func_ret_value = FUNC_CALL(9, func_addr, func_para_value);
            break;
        case 10:
            func_ret_value = FUNC_CALL(10, func_addr, func_para_value);
            break;
        case 11:
            func_ret_value = FUNC_CALL(11, func_addr, func_para_value);
            break;
        case 12:
            func_ret_value = FUNC_CALL(12, func_addr, func_para_value);
            break;
        case 13:
            func_ret_value = FUNC_CALL(13, func_addr, func_para_value);
            break;
        case 14:
            func_ret_value = FUNC_CALL(14, func_addr, func_para_value);
            break;
        case 15:
            func_ret_value = FUNC_CALL(15, func_addr, func_para_value);
            break;
        case 16:
            func_ret_value = FUNC_CALL(16, func_addr, func_para_value);
            break;
        default:
            dbg_log(SEC_0079_TBD, 0)(LOGSTDOUT, "error:tbd_run: func para num = %d overflow\n", func_para_num);
            return ((UINT32)(-1));
    }

    //if(0 != ui_retval_addr)
    {
        //dbg_log(SEC_0079_TBD, 5)(LOGSTDOUT, "tbd_run: ui_retval_addr %lx ==> ", ui_retval_addr);

        *((UINT32 *)ui_retval_addr) = func_ret_value;
        //sys_print(LOGSTDOUT, "%lx ==> %ld\n", ui_retval_addr, *((UINT32 *)ui_retval_addr));
    }

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

    return (0);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

