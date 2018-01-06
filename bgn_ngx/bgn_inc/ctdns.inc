/******************************************************************************
*
* Copyright (C) Chaoyong Zhou
* Email: bgnvendor@163.com 
* QQ: 2796796 
*
*******************************************************************************/
#ifndef _CTDNS_INC
#define _CTDNS_INC

#include "findex.inc"

FUNC_ADDR_NODE g_ctdns_func_addr_list[ ] = {
{
/* -- void ctdns_print_module_status(const UINT32 ctdns_md_id, LOG *log); -- */
/*func module     */     MD_CTDNS,
/*func logic addr */     (UINT32)ctdns_print_module_status,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "ctdns_print_module_status",
/*func index      */     FI_ctdns_print_module_status,
/*func ret type   */     e_dbg_void,
/*func para num   */     2,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IO,},
/*func para type  */     {e_dbg_UINT32,e_dbg_LOG_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- UINT32 ctdns_free_module_static_mem(const UINT32 ctdns_md_id); -- */
/*func module     */     MD_CTDNS,
/*func logic addr */     (UINT32)ctdns_free_module_static_mem,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "ctdns_free_module_static_mem",
/*func index      */     FI_ctdns_free_module_static_mem,
/*func ret type   */     e_dbg_UINT32,
/*func para num   */     1,
/*func para direct*/     {E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,},
/*func para val   */     0, 0, {0},
},
{
/* -- UINT32 ctdns_start(const CSTRING *ctdns_root_dir); -- */
/*func module     */     MD_CTDNS,
/*func logic addr */     (UINT32)ctdns_start,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "ctdns_start",
/*func index      */     FI_ctdns_start,
/*func ret type   */     e_dbg_UINT32,
/*func para num   */     1,
/*func para direct*/     {E_DIRECT_IN,},
/*func para type  */     {e_dbg_CSTRING_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- void ctdns_end(const UINT32 ctdns_md_id); -- */
/*func module     */     MD_CTDNS,
/*func logic addr */     (UINT32)ctdns_end,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "ctdns_end",
/*func index      */     FI_ctdns_end,
/*func ret type   */     e_dbg_void,
/*func para num   */     1,
/*func para direct*/     {E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL ctdns_open_npp(const UINT32 ctdns_md_id, const CSTRING *ctdnsnp_db_root_dir); -- */
/*func module     */     MD_CTDNS,
/*func logic addr */     (UINT32)ctdns_open_npp,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "ctdns_open_npp",
/*func index      */     FI_ctdns_open_npp,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     2,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,e_dbg_CSTRING_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL ctdns_close_npp(const UINT32 ctdns_md_id); -- */
/*func module     */     MD_CTDNS,
/*func logic addr */     (UINT32)ctdns_close_npp,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "ctdns_close_npp",
/*func index      */     FI_ctdns_close_npp,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     1,
/*func para direct*/     {E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL ctdns_create_npp(const UINT32 ctdns_md_id, const UINT32 ctdnsnp_model, const UINT32 ctdnsnp_max_num, const UINT32 ctdnsnp_2nd_chash_algo_id,  const CSTRING *ctdnsnp_db_root_dir); -- */
/*func module     */     MD_CTDNS,
/*func logic addr */     (UINT32)ctdns_create_npp,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "ctdns_create_npp",
/*func index      */     FI_ctdns_create_npp,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     5,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,e_dbg_UINT32,e_dbg_UINT32,e_dbg_UINT32,e_dbg_CSTRING_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL ctdns_exists(const UINT32 ctdns_md_id, const UINT32 tcid); -- */
/*func module     */     MD_CTDNS,
/*func logic addr */     (UINT32)ctdns_exists,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "ctdns_exists",
/*func index      */     FI_ctdns_exists,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     2,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,e_dbg_UINT32,},
/*func para val   */     0, 0, {0},
},

{
/* -- EC_BOOL ctdns_set(const UINT32 ctdns_md_id, const UINT32 tcid, const UINT32 ipaddr, const CBYTES *key_cbytes); -- */
/*func module     */     MD_CTDNS,
/*func logic addr */     (UINT32)ctdns_set,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "ctdns_set",
/*func index      */     FI_ctdns_set,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     4,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,e_dbg_UINT32,e_dbg_UINT32,e_dbg_CBYTES_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL ctdns_get(const UINT32 ctdns_md_id, const UINT32 tcid, UINT32 *ipaddr, CBYTES *key_cbytes); -- */
/*func module     */     MD_CTDNS,
/*func logic addr */     (UINT32)ctdns_get,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "ctdns_get",
/*func index      */     FI_ctdns_get,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     4,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_OUT,E_DIRECT_OUT,},
/*func para type  */     {e_dbg_UINT32,e_dbg_UINT32,e_dbg_UINT32_ptr,e_dbg_CBYTES_ptr, },
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL ctdns_delete(const UINT32 ctdns_md_id, const UINT32 tcid); -- */
/*func module     */     MD_CTDNS,
/*func logic addr */     (UINT32)ctdns_delete,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "ctdns_delete",
/*func index      */     FI_ctdns_delete,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     2,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,e_dbg_UINT32, },
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL ctdns_flush_npp(const UINT32 ctdns_md_id); -- */
/*func module     */     MD_CTDNS,
/*func logic addr */     (UINT32)ctdns_flush_npp,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "ctdns_flush_npp",
/*func index      */     FI_ctdns_flush_npp,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     1,
/*func para direct*/     {E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL ctdns_tcid_num(const UINT32 ctdns_md_id, UINT32 *tcid_num); -- */
/*func module     */     MD_CTDNS,
/*func logic addr */     (UINT32)ctdns_tcid_num,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "ctdns_tcid_num",
/*func index      */     FI_ctdns_tcid_num,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     2,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_OUT,},
/*func para type  */     {e_dbg_UINT32,e_dbg_UINT32_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL ctdns_show_npp(const UINT32 ctdns_md_id, LOG *log); -- */
/*func module     */     MD_CTDNS,
/*func logic addr */     (UINT32)ctdns_show_npp,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "ctdns_show_npp",
/*func index      */     FI_ctdns_show_npp,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     2,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IO,},
/*func para type  */     {e_dbg_UINT32,e_dbg_LOG_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL ctdns_flush(const UINT32 ctdns_md_id); -- */
/*func module     */     MD_CTDNS,
/*func logic addr */     (UINT32)ctdns_flush,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "ctdns_flush",
/*func index      */     FI_ctdns_flush,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     1,
/*func para direct*/     {E_DIRECT_IN, },
/*func para type  */     {e_dbg_UINT32,},
/*func para val   */     0, 0, {0},
},

};

UINT32 g_ctdns_func_addr_list_len = sizeof(g_ctdns_func_addr_list)/sizeof(g_ctdns_func_addr_list[0]);
#endif/*_CTDNS_INC*/

