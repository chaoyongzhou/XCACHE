/******************************************************************************
*
* Copyright (C) Chaoyong Zhou
* Email: bgnvendor@163.com
* QQ: 2796796
*
*******************************************************************************/
#ifndef _TBD_INC
#define _TBD_INC

#include "findex.inc"

FUNC_ADDR_NODE g_tbd_func_addr_list[ ] = {
{
/* -- void tbd_print_module_status(const UINT32 tbd_md_id, LOG *log); -- */
/*func module     */     MD_TBD,
/*func logic addr */     (UINT32)tbd_print_module_status,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "tbd_print_module_status",
/*func index      */     FI_tbd_print_module_status,
/*func ret type   */     e_dbg_void,
/*func para num   */     2,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IO,},
/*func para type  */     {e_dbg_UINT32,e_dbg_LOG_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- UINT32 tbd_free_module_static_mem(const UINT32 tbd_md_id); -- */
/*func module     */     MD_TBD,
/*func logic addr */     (UINT32)tbd_free_module_static_mem,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "tbd_free_module_static_mem",
/*func index      */     FI_tbd_free_module_static_mem,
/*func ret type   */     e_dbg_UINT32,
/*func para num   */     1,
/*func para direct*/     {E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,},
/*func para val   */     0, 0, {0},
},
{
/* -- UINT32 tbd_start( ); -- */
/*func module     */     MD_TBD,
/*func logic addr */     (UINT32)tbd_start,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "tbd_start",
/*func index      */     FI_tbd_start,
/*func ret type   */     e_dbg_UINT32,
/*func para num   */     0,
/*func para direct*/     {E_DIRECT_END,},
/*func para type  */     {e_dbg_type_end,},
/*func para val   */     0, 0, {0},
},
{
/* -- void tbd_end(const UINT32 tbd_md_id); -- */
/*func module     */     MD_TBD,
/*func logic addr */     (UINT32)tbd_end,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "tbd_end",
/*func index      */     FI_tbd_end,
/*func ret type   */     e_dbg_void,
/*func para num   */     1,
/*func para direct*/     {E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,},
/*func para val   */     0, 0, {0},
},
{
/* -- UINT32 tbd_set_mod_mgr(const UINT32 tbd_md_id, const MOD_MGR * src_mod_mgr); -- */
/*func module     */     MD_TBD,
/*func logic addr */     (UINT32)tbd_set_mod_mgr,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "tbd_set_mod_mgr",
/*func index      */     FI_tbd_set_mod_mgr,
/*func ret type   */     e_dbg_UINT32,
/*func para num   */     2,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,e_dbg_MOD_MGR_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- MOD_MGR * tbd_get_mod_mgr(const UINT32 tbd_md_id); -- */
/*func module     */     MD_TBD,
/*func logic addr */     (UINT32)tbd_get_mod_mgr,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "tbd_get_mod_mgr",
/*func index      */     FI_tbd_get_mod_mgr,
/*func ret type   */     e_dbg_MOD_MGR_ptr,
/*func para num   */     1,
/*func para direct*/     {E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,},
/*func para val   */     0, 0, {0},
},
{
/* -- UINT32 tbd_run(const UINT32 tbd_md_id, const void * ui_retval_addr, const UINT32 ui_id, ...); -- */
/*func module     */     MD_TBD,
/*func logic addr */     (UINT32)tbd_run,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "tbd_run",
/*func index      */     FI_tbd_run,
/*func ret type   */     e_dbg_UINT32,
/*func para num   */     EMB_NUM_OF_FUNC_PARAS,/*NOTE: here is uncertain number of parameters*/
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,e_dbg_UINT32,e_dbg_UINT32,},
/*func para val   */     0, 0, {0},
},
};

UINT32 g_tbd_func_addr_list_len = sizeof(g_tbd_func_addr_list)/sizeof(g_tbd_func_addr_list[0]);

#endif/*_TBD_INC*/
