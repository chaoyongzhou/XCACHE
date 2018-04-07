/******************************************************************************
*
* Copyright (C) Chaoyong Zhou
* Email: bgnvendor@163.com 
* QQ: 2796796 
*
*******************************************************************************/
#ifndef _CDETECTN_INC
#define _CDETECTN_INC

#include "findex.inc"

FUNC_ADDR_NODE g_cdetectn_func_addr_list[ ] = {
{
/* -- void cdetectn_print_module_status(const UINT32 cdetectn_md_id, LOG *log); -- */
/*func module     */     MD_CDETECTN,
/*func logic addr */     (UINT32)cdetectn_print_module_status,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cdetectn_print_module_status",
/*func index      */     FI_cdetectn_print_module_status,
/*func ret type   */     e_dbg_void,
/*func para num   */     2,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IO,},
/*func para type  */     {e_dbg_UINT32,e_dbg_LOG_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- UINT32 cdetectn_free_module_static_mem(const UINT32 cdetectn_md_id); -- */
/*func module     */     MD_CDETECTN,
/*func logic addr */     (UINT32)cdetectn_free_module_static_mem,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cdetectn_free_module_static_mem",
/*func index      */     FI_cdetectn_free_module_static_mem,
/*func ret type   */     e_dbg_UINT32,
/*func para num   */     1,
/*func para direct*/     {E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,},
/*func para val   */     0, 0, {0},
},
{
/* -- UINT32 cdetectn_start(); -- */
/*func module     */     MD_CDETECTN,
/*func logic addr */     (UINT32)cdetectn_start,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cdetectn_start",
/*func index      */     FI_cdetectn_start,
/*func ret type   */     e_dbg_UINT32,
/*func para num   */     0,
/*func para direct*/     {E_DIRECT_END,},
/*func para type  */     {e_dbg_void,},
/*func para val   */     0, 0, {0},
},
{
/* -- void cdetectn_end(const UINT32 cdetectn_md_id); -- */
/*func module     */     MD_CDETECTN,
/*func logic addr */     (UINT32)cdetectn_end,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cdetectn_end",
/*func index      */     FI_cdetectn_end,
/*func ret type   */     e_dbg_void,
/*func para num   */     1,
/*func para direct*/     {E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cdetectn_show_orig_nodes(const UINT32 crfs_md_id, LOG *log); -- */
/*func module     */     MD_CDETECTN,
/*func logic addr */     (UINT32)cdetectn_show_orig_nodes,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cdetectn_show_orig_nodes",
/*func index      */     FI_cdetectn_show_orig_nodes,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     2,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IO,},
/*func para type  */     {e_dbg_UINT32,e_dbg_LOG_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cdetectn_show_orig_node(const UINT32 crfs_md_id, const CSTRING *domain, LOG *log); -- */
/*func module     */     MD_CDETECTN,
/*func logic addr */     (UINT32)cdetectn_show_orig_node,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cdetectn_show_orig_node",
/*func index      */     FI_cdetectn_show_orig_node,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     3,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_IO,},
/*func para type  */     {e_dbg_UINT32,e_dbg_CSTRING_ptr,e_dbg_LOG_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cdetectn_dns_resolve(const UINT32 cdetectn_md_id, const CSTRING *domain, UINT32 *ipaddr); -- */
/*func module     */     MD_CDETECTN,
/*func logic addr */     (UINT32)cdetectn_dns_resolve,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cdetectn_dns_resolve",
/*func index      */     FI_cdetectn_dns_resolve,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     3,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_OUT,},
/*func para type  */     {e_dbg_UINT32,e_dbg_CSTRING_ptr,e_dbg_UINT32_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cdetectn_start_domain(const UINT32 cdetectn_md_id, const CSTRING *domain); -- */
/*func module     */     MD_CDETECTN,
/*func logic addr */     (UINT32)cdetectn_start_domain,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cdetectn_start_domain",
/*func index      */     FI_cdetectn_start_domain,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     2,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,e_dbg_CSTRING_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cdetectn_stop_domain(const UINT32 cdetectn_md_id, const CSTRING *domain); -- */
/*func module     */     MD_CDETECTN,
/*func logic addr */     (UINT32)cdetectn_stop_domain,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cdetectn_stop_domain",
/*func index      */     FI_cdetectn_stop_domain,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     2,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,e_dbg_CSTRING_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cdetectn_process(const UINT32 cdetectn_md_id, const UINT32 detect_task_max_num); -- */
/*func module     */     MD_CDETECTN,
/*func logic addr */     (UINT32)cdetectn_process,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cdetectn_process",
/*func index      */     FI_cdetectn_process,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     2,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,e_dbg_UINT32,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cdetectn_process_loop(const UINT32 cdetectn_md_id, const UINT32 detect_task_max_num); -- */
/*func module     */     MD_CDETECTN,
/*func logic addr */     (UINT32)cdetectn_process_loop,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cdetectn_process_loop",
/*func index      */     FI_cdetectn_process_loop,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     2,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,e_dbg_UINT32,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cdetectn_load_conf(const UINT32 cdetectn_md_id, const CSTRING *cdetectn_conf_file); -- */
/*func module     */     MD_CDETECTN,
/*func logic addr */     (UINT32)cdetectn_load_conf,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cdetectn_load_conf",
/*func index      */     FI_cdetectn_load_conf,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     2,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,e_dbg_CSTRING_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cdetectn_parse_conf_line(const UINT32 cdetectn_md_id, const UINT32 cdetectn_conf_start, const UINT32 cdetectn_conf_end); -- */
/*func module     */     MD_CDETECTN,
/*func logic addr */     (UINT32)cdetectn_parse_conf_line,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cdetectn_parse_conf_line",
/*func index      */     FI_cdetectn_parse_conf_line,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     3,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,e_dbg_UINT32,e_dbg_UINT32,},
/*func para val   */     0, 0, {0},
},
};

UINT32 g_cdetectn_func_addr_list_len = sizeof(g_cdetectn_func_addr_list)/sizeof(g_cdetectn_func_addr_list[0]);
#endif/*_CDETECTN_INC*/

