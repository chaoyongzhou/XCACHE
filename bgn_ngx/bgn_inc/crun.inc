/******************************************************************************
*
* Copyright (C) Chaoyong Zhou
* Email: bgnvendor@163.com 
* QQ: 2796796 
*
*******************************************************************************/
#ifndef _CRUN_INC
#define _CRUN_INC

#include "findex.inc"

FUNC_ADDR_NODE g_crun_func_addr_list[ ] = {
{
/* -- UINT32 usr_run_01(const CSTRING *cstring); -- */
/*func module     */     MD_CRUN,
/*func logic addr */     (UINT32)usr_run_01,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "usr_run_01",
/*func index      */     FI_usr_run_01,
/*func ret type   */     e_dbg_UINT32,
/*func para num   */     1,
/*func para direct*/     {E_DIRECT_IN,},
/*func para type  */     {e_dbg_CSTRING_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- UINT32 usr_run_02(const CSTRING *cstring_01, const CSTRING *cstring_02, CSTRING *cstring_03); -- */
/*func module     */     MD_CRUN,
/*func logic addr */     (UINT32)usr_run_02,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "usr_run_02",
/*func index      */     FI_usr_run_02,
/*func ret type   */     e_dbg_UINT32,
/*func para num   */     3,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_IO,},
/*func para type  */     {e_dbg_CSTRING_ptr,e_dbg_CSTRING_ptr,e_dbg_CSTRING_ptr,},
/*func para val   */     0, 0, {0},
},
};

UINT32 g_crun_func_addr_list_len = sizeof(g_crun_func_addr_list)/sizeof(g_crun_func_addr_list[0]);

#endif/*_CRUN_INC*/


