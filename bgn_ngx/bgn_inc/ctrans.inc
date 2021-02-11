/******************************************************************************
*
* Copyright (C) Chaoyong Zhou
* Email: bgnvendor@163.com
* QQ: 2796796
*
*******************************************************************************/
#ifndef _CTRANS_INC
#define _CTRANS_INC

#include "findex.inc"

FUNC_ADDR_NODE g_ctrans_func_addr_list[ ] = {
{
/* -- void ctrans_print_module_status(const UINT32 ctrans_md_id, LOG *log); -- */
/*func module     */     MD_CTRANS,
/*func logic addr */     (UINT32)ctrans_print_module_status,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "ctrans_print_module_status",
/*func index      */     FI_ctrans_print_module_status,
/*func ret type   */     e_dbg_void,
/*func para num   */     2,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IO,},
/*func para type  */     {e_dbg_UINT32,e_dbg_LOG_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- UINT32 ctrans_free_module_static_mem(const UINT32 ctrans_md_id); -- */
/*func module     */     MD_CTRANS,
/*func logic addr */     (UINT32)ctrans_free_module_static_mem,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "ctrans_free_module_static_mem",
/*func index      */     FI_ctrans_free_module_static_mem,
/*func ret type   */     e_dbg_UINT32,
/*func para num   */     1,
/*func para direct*/     {E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,},
/*func para val   */     0, 0, {0},
},
{
/* -- UINT32 ctrans_start(const UINT32 des_tcid, const UINT32 seg_size, const UINT32 seg_concurrence); -- */
/*func module     */     MD_CTRANS,
/*func logic addr */     (UINT32)ctrans_start,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "ctrans_start",
/*func index      */     FI_ctrans_start,
/*func ret type   */     e_dbg_UINT32,
/*func para num   */     3,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,e_dbg_UINT32,e_dbg_UINT32,},
/*func para val   */     0, 0, {0},
},
{
/* -- void ctrans_end(const UINT32 ctrans_md_id); -- */
/*func module     */     MD_CTRANS,
/*func logic addr */     (UINT32)ctrans_end,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "ctrans_end",
/*func index      */     FI_ctrans_end,
/*func ret type   */     e_dbg_void,
/*func para num   */     1,
/*func para direct*/     {E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL ctrans_seg(const UINT32 ctrans_md_id, const CSTRING *src_file_path, const CSTRING *des_file_path, const UINT32 seg_offset, const UINT32 seg_size); -- */
/*func module     */     MD_CTRANS,
/*func logic addr */     (UINT32)ctrans_seg,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "ctrans_seg",
/*func index      */     FI_ctrans_seg,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     5,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,e_dbg_CSTRING_ptr,e_dbg_CSTRING_ptr,e_dbg_UINT32,e_dbg_UINT32,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL ctrans_file(const UINT32 ctrans_md_id, const CSTRING *src_file_path, const CSTRING *des_file_path); -- */
/*func module     */     MD_CTRANS,
/*func logic addr */     (UINT32)ctrans_file,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "ctrans_file",
/*func index      */     FI_ctrans_file,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     3,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,e_dbg_CSTRING_ptr,e_dbg_CSTRING_ptr,},
/*func para val   */     0, 0, {0},
},
};

UINT32 g_ctrans_func_addr_list_len = sizeof(g_ctrans_func_addr_list)/sizeof(g_ctrans_func_addr_list[0]);
#endif/*_CTRANS_INC*/

