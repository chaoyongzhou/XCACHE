/******************************************************************************
*
* Copyright (C) Chaoyong Zhou
* Email: bgnvendor@163.com
* QQ: 2796796
*
*******************************************************************************/
#ifndef _CDETECT_INC
#define _CDETECT_INC

#include "findex.inc"

FUNC_ADDR_NODE g_cdetect_func_addr_list[ ] = {
{
/* -- void cdetect_print_module_status(const UINT32 cdetect_md_id, LOG *log); -- */
/*func module     */     MD_CDETECT,
/*func logic addr */     (UINT32)cdetect_print_module_status,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cdetect_print_module_status",
/*func index      */     FI_cdetect_print_module_status,
/*func ret type   */     e_dbg_void,
/*func para num   */     2,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IO,},
/*func para type  */     {e_dbg_UINT32,e_dbg_LOG_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- UINT32 cdetect_free_module_static_mem(const UINT32 cdetect_md_id); -- */
/*func module     */     MD_CDETECT,
/*func logic addr */     (UINT32)cdetect_free_module_static_mem,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cdetect_free_module_static_mem",
/*func index      */     FI_cdetect_free_module_static_mem,
/*func ret type   */     e_dbg_UINT32,
/*func para num   */     1,
/*func para direct*/     {E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,},
/*func para val   */     0, 0, {0},
},
{
/* -- UINT32 cdetect_start(const CSTRING *cdetect_conf_file); -- */
/*func module     */     MD_CDETECT,
/*func logic addr */     (UINT32)cdetect_start,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cdetect_start",
/*func index      */     FI_cdetect_start,
/*func ret type   */     e_dbg_UINT32,
/*func para num   */     1,
/*func para direct*/     {E_DIRECT_IN,},
/*func para type  */     {e_dbg_CSTRING_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- void cdetect_end(const UINT32 cdetect_md_id); -- */
/*func module     */     MD_CDETECT,
/*func logic addr */     (UINT32)cdetect_end,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cdetect_end",
/*func index      */     FI_cdetect_end,
/*func ret type   */     e_dbg_void,
/*func para num   */     1,
/*func para direct*/     {E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cdetect_show_orig_nodes(const UINT32 crfs_md_id, LOG *log); -- */
/*func module     */     MD_CDETECT,
/*func logic addr */     (UINT32)cdetect_show_orig_nodes,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cdetect_show_orig_nodes",
/*func index      */     FI_cdetect_show_orig_nodes,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     2,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IO,},
/*func para type  */     {e_dbg_UINT32,e_dbg_LOG_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cdetect_show_orig_node(const UINT32 crfs_md_id, const CSTRING *domain, LOG *log); -- */
/*func module     */     MD_CDETECT,
/*func logic addr */     (UINT32)cdetect_show_orig_node,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cdetect_show_orig_node",
/*func index      */     FI_cdetect_show_orig_node,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     3,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_IO,},
/*func para type  */     {e_dbg_UINT32,e_dbg_CSTRING_ptr,e_dbg_LOG_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cdetect_dns_resolve(const UINT32 cdetect_md_id, const CSTRING *domain, UINT32 *ipaddr); -- */
/*func module     */     MD_CDETECT,
/*func logic addr */     (UINT32)cdetect_dns_resolve,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cdetect_dns_resolve",
/*func index      */     FI_cdetect_dns_resolve,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     3,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_OUT,},
/*func para type  */     {e_dbg_UINT32,e_dbg_CSTRING_ptr,e_dbg_UINT32_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cdetect_start_domain(const UINT32 cdetect_md_id, const CSTRING *domain); -- */
/*func module     */     MD_CDETECT,
/*func logic addr */     (UINT32)cdetect_start_domain,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cdetect_start_domain",
/*func index      */     FI_cdetect_start_domain,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     2,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,e_dbg_CSTRING_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cdetect_stop_domain(const UINT32 cdetect_md_id, const CSTRING *domain); -- */
/*func module     */     MD_CDETECT,
/*func logic addr */     (UINT32)cdetect_stop_domain,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cdetect_stop_domain",
/*func index      */     FI_cdetect_stop_domain,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     2,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,e_dbg_CSTRING_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cdetect_process(const UINT32 cdetect_md_id, const UINT32 detect_task_max_num); -- */
/*func module     */     MD_CDETECT,
/*func logic addr */     (UINT32)cdetect_process,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cdetect_process",
/*func index      */     FI_cdetect_process,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     2,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,e_dbg_UINT32,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cdetect_process_loop(const UINT32 cdetect_md_id, const UINT32 detect_task_max_num); -- */
/*func module     */     MD_CDETECT,
/*func logic addr */     (UINT32)cdetect_process_loop,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cdetect_process_loop",
/*func index      */     FI_cdetect_process_loop,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     2,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,e_dbg_UINT32,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cdetect_switch(const UINT32 cdetect_md_id); -- */
/*func module     */     MD_CDETECT,
/*func logic addr */     (UINT32)cdetect_switch,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cdetect_switch",
/*func index      */     FI_cdetect_switch,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     1,
/*func para direct*/     {E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cdetect_reload(const UINT32 cdetect_md_id); -- */
/*func module     */     MD_CDETECT,
/*func logic addr */     (UINT32)cdetect_reload,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cdetect_reload",
/*func index      */     FI_cdetect_reload,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     1,
/*func para direct*/     {E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cdetect_choice(const UINT32 cdetect_md_id, UINT32 *choice); -- */
/*func module     */     MD_CDETECT,
/*func logic addr */     (UINT32)cdetect_choice,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cdetect_choice",
/*func index      */     FI_cdetect_choice,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     2,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_OUT,},
/*func para type  */     {e_dbg_UINT32,e_dbg_UINT32_ptr,},
/*func para val   */     0, 0, {0},
},
};

UINT32 g_cdetect_func_addr_list_len = sizeof(g_cdetect_func_addr_list)/sizeof(g_cdetect_func_addr_list[0]);
#endif/*_CDETECT_INC*/

