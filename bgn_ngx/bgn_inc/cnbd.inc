/******************************************************************************
*
* Copyright (C) Chaoyong Zhou
* Email: bgnvendor@163.com
* QQ: 2796796
*
*******************************************************************************/
#ifndef _CNBD_INC
#define _CNBD_INC

#include "findex.inc"

FUNC_ADDR_NODE g_cnbd_func_addr_list[ ] = {
{
/* -- void cnbd_print_module_status(const UINT32 cnbd_md_id, LOG *log); -- */
/*func module     */     MD_CNBD,
/*func logic addr */     (UINT32)cnbd_print_module_status,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cnbd_print_module_status",
/*func index      */     FI_cnbd_print_module_status,
/*func ret type   */     e_dbg_void,
/*func para num   */     2,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IO,},
/*func para type  */     {e_dbg_UINT32,e_dbg_LOG_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- UINT32 cnbd_free_module_static_mem(const UINT32 cnbd_md_id); -- */
/*func module     */     MD_CNBD,
/*func logic addr */     (UINT32)cnbd_free_module_static_mem,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cnbd_free_module_static_mem",
/*func index      */     FI_cnbd_free_module_static_mem,
/*func ret type   */     e_dbg_UINT32,
/*func para num   */     1,
/*func para direct*/     {E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,},
/*func para val   */     0, 0, {0},
},
{
/* -- UINT32 cnbd_start(const CSTRING *nbd_dev_name, const UINT32 nbd_blk_size, const UINT32 nbd_dev_size, const UINT32 nbd_timeout, const CSTRING *bucket_name); -- */
/*func module     */     MD_CNBD,
/*func logic addr */     (UINT32)cnbd_start,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cnbd_start",
/*func index      */     FI_cnbd_start,
/*func ret type   */     e_dbg_UINT32,
/*func para num   */     5,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_IN,},
/*func para type  */     {e_dbg_CSTRING_ptr,e_dbg_UINT32,e_dbg_UINT32,e_dbg_UINT32,e_dbg_CSTRING_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- void cnbd_end(const UINT32 cnbd_md_id); -- */
/*func module     */     MD_CNBD,
/*func logic addr */     (UINT32)cnbd_end,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cnbd_end",
/*func index      */     FI_cnbd_end,
/*func ret type   */     e_dbg_void,
/*func para num   */     1,
/*func para direct*/     {E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cnbd_handle_req(const UINT32 cnbd_md_id, CNBD_REQ *cnbd_req); -- */
/*func module     */     MD_CNBD,
/*func logic addr */     (UINT32)cnbd_handle_req,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cnbd_handle_req",
/*func index      */     FI_cnbd_handle_req,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     2,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,e_dbg_UINT32,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cnbd_thread_check_running(const UINT32 cnbd_md_id); -- */
/*func module     */     MD_CNBD,
/*func logic addr */     (UINT32)cnbd_thread_check_running,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cnbd_thread_check_running",
/*func index      */     FI_cnbd_thread_check_running,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     1,
/*func para direct*/     {E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cnbd_thread_set_running(const UINT32 cnbd_md_id); -- */
/*func module     */     MD_CNBD,
/*func logic addr */     (UINT32)cnbd_thread_set_running,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cnbd_thread_set_running",
/*func index      */     FI_cnbd_thread_set_running,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     1,
/*func para direct*/     {E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cnbd_thread_set_stopped(const UINT32 cnbd_md_id); -- */
/*func module     */     MD_CNBD,
/*func logic addr */     (UINT32)cnbd_thread_set_stopped,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cnbd_thread_set_stopped",
/*func index      */     FI_cnbd_thread_set_stopped,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     1,
/*func para direct*/     {E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cnbd_thread_check_listen(const UINT32 cnbd_md_id); -- */
/*func module     */     MD_CNBD,
/*func logic addr */     (UINT32)cnbd_thread_check_listen,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cnbd_thread_check_listen",
/*func index      */     FI_cnbd_thread_check_listen,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     1,
/*func para direct*/     {E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,},
/*func para val   */     0, 0, {0},
},
};

UINT32 g_cnbd_func_addr_list_len = sizeof(g_cnbd_func_addr_list)/sizeof(g_cnbd_func_addr_list[0]);
#endif/*_CNBD_INC*/


