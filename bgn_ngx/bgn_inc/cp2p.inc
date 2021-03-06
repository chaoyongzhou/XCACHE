/******************************************************************************
*
* Copyright (C) Chaoyong Zhou
* Email: bgnvendor@163.com
* QQ: 2796796
*
*******************************************************************************/
#ifndef _CP2P_INC
#define _CP2P_INC

#include "findex.inc"

FUNC_ADDR_NODE g_cp2p_func_addr_list[ ] = {
{
/* -- void cp2p_print_module_status(const UINT32 cp2p_md_id, LOG *log); -- */
/*func module     */     MD_CP2P,
/*func logic addr */     (UINT32)cp2p_print_module_status,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cp2p_print_module_status",
/*func index      */     FI_cp2p_print_module_status,
/*func ret type   */     e_dbg_void,
/*func para num   */     2,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IO,},
/*func para type  */     {e_dbg_UINT32,e_dbg_LOG_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- UINT32 cp2p_free_module_static_mem(const UINT32 cp2p_md_id); -- */
/*func module     */     MD_CP2P,
/*func logic addr */     (UINT32)cp2p_free_module_static_mem,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cp2p_free_module_static_mem",
/*func index      */     FI_cp2p_free_module_static_mem,
/*func ret type   */     e_dbg_UINT32,
/*func para num   */     1,
/*func para direct*/     {E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,},
/*func para val   */     0, 0, {0},
},
{
/* -- UINT32 cp2p_start(const CSTRING * cxfs_root_dir, const CSTRING * ctdns_root_dir); -- */
/*func module     */     MD_CP2P,
/*func logic addr */     (UINT32)cp2p_start,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cp2p_start",
/*func index      */     FI_cp2p_start,
/*func ret type   */     e_dbg_UINT32,
/*func para num   */     2,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,},
/*func para type  */     {e_dbg_CSTRING_ptr,e_dbg_CSTRING_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- void cp2p_end(const UINT32 cp2p_md_id); -- */
/*func module     */     MD_CP2P,
/*func logic addr */     (UINT32)cp2p_end,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cp2p_end",
/*func index      */     FI_cp2p_end,
/*func ret type   */     e_dbg_void,
/*func para num   */     1,
/*func para direct*/     {E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cp2p_file_exists_local(const UINT32 cp2p_md_id, const CP2P_FILE *cp2p_file); -- */
/*func module     */     MD_CP2P,
/*func logic addr */     (UINT32)cp2p_file_exists_local,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cp2p_file_exists_local",
/*func index      */     FI_cp2p_file_exists_local,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     2,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,e_dbg_CP2P_FILE_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cp2p_file_exists(const UINT32 cp2p_md_id, const CP2P_FILE *cp2p_file); -- */
/*func module     */     MD_CP2P,
/*func logic addr */     (UINT32)cp2p_file_exists,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cp2p_file_exists",
/*func index      */     FI_cp2p_file_exists,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     2,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,e_dbg_CP2P_FILE_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cp2p_file_push_notify(const UINT32 cp2p_md_id, const UINT32 des_network, const UINT32 des_tcid, const CP2P_FILE *cp2p_file); -- */
/*func module     */     MD_CP2P,
/*func logic addr */     (UINT32)cp2p_file_push_notify,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cp2p_file_push_notify",
/*func index      */     FI_cp2p_file_push_notify,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     4,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,e_dbg_UINT32,e_dbg_UINT32,e_dbg_CP2P_FILE_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cp2p_file_flush_notify(const UINT32 cp2p_md_id, const UINT32 des_network, const UINT32 des_tcid, const CP2P_FILE *cp2p_file); -- */
/*func module     */     MD_CP2P,
/*func logic addr */     (UINT32)cp2p_file_flush_notify,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cp2p_file_flush_notify",
/*func index      */     FI_cp2p_file_flush_notify,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     4,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,e_dbg_UINT32,e_dbg_UINT32,e_dbg_CP2P_FILE_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cp2p_file_report_notify(const UINT32 cp2p_md_id, const UINT32 des_network, const UINT32 des_tcid, const CP2P_FILE *cp2p_file); -- */
/*func module     */     MD_CP2P,
/*func logic addr */     (UINT32)cp2p_file_report_notify,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cp2p_file_report_notify",
/*func index      */     FI_cp2p_file_report_notify,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     4,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,e_dbg_UINT32,e_dbg_UINT32,e_dbg_CP2P_FILE_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cp2p_file_delete_notify(const UINT32 cp2p_md_id, const UINT32 des_network, const UINT32 des_tcid, const CP2P_FILE *cp2p_file); -- */
/*func module     */     MD_CP2P,
/*func logic addr */     (UINT32)cp2p_file_delete_notify,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cp2p_file_delete_notify",
/*func index      */     FI_cp2p_file_delete_notify,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     4,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,e_dbg_UINT32,e_dbg_UINT32,e_dbg_CP2P_FILE_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cp2p_file_download(const UINT32 cp2p_md_id, const UINT32 src_tcid, const CP2P_FILE *cp2p_file); -- */
/*func module     */     MD_CP2P,
/*func logic addr */     (UINT32)cp2p_file_download,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cp2p_file_download",
/*func index      */     FI_cp2p_file_download,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     3,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,e_dbg_UINT32,e_dbg_CP2P_FILE_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cp2p_file_push(const UINT32 cp2p_md_id, const UINT32 des_network, const UINT32 des_tcid, const CP2P_FILE *cp2p_file); -- */
/*func module     */     MD_CP2P,
/*func logic addr */     (UINT32)cp2p_file_push,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cp2p_file_push",
/*func index      */     FI_cp2p_file_push,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     4,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,e_dbg_UINT32,e_dbg_UINT32,e_dbg_CP2P_FILE_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cp2p_file_pull(const UINT32 cp2p_md_id, const CP2P_FILE *cp2p_file); -- */
/*func module     */     MD_CP2P,
/*func logic addr */     (UINT32)cp2p_file_pull,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cp2p_file_pull",
/*func index      */     FI_cp2p_file_pull,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     2,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,e_dbg_CP2P_FILE_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cp2p_file_delete(const UINT32 cp2p_md_id, const UINT32 des_network, const UINT32 des_tcid, const CP2P_FILE *cp2p_file); -- */
/*func module     */     MD_CP2P,
/*func logic addr */     (UINT32)cp2p_file_delete,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cp2p_file_delete",
/*func index      */     FI_cp2p_file_delete,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     4,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,e_dbg_UINT32,e_dbg_UINT32,e_dbg_CP2P_FILE_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cp2p_file_dump(const UINT32 cp2p_md_id, const CP2P_FILE *cp2p_file); -- */
/*func module     */     MD_CP2P,
/*func logic addr */     (UINT32)cp2p_file_dump,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cp2p_file_dump",
/*func index      */     FI_cp2p_file_dump,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     2,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,e_dbg_CP2P_FILE_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cp2p_file_flush(const UINT32 cp2p_md_id, const UINT32 des_network, const UINT32 des_tcid, const CP2P_FILE *cp2p_file);-- */
/*func module     */     MD_CP2P,
/*func logic addr */     (UINT32)cp2p_file_flush,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cp2p_file_flush",
/*func index      */     FI_cp2p_file_flush,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     4,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,e_dbg_UINT32,e_dbg_UINT32,e_dbg_CP2P_FILE_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cp2p_file_report(const UINT32 cp2p_md_id, const UINT32 des_network, const UINT32 des_tcid, const CP2P_FILE *cp2p_file); -- */
/*func module     */     MD_CP2P,
/*func logic addr */     (UINT32)cp2p_file_report,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cp2p_file_report",
/*func index      */     FI_cp2p_file_report,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     4,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,e_dbg_UINT32,e_dbg_UINT32,e_dbg_CP2P_FILE_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cp2p_file_load(const UINT32 cp2p_md_id, const CSTRING *src_file, const CSTRING *service_name, const CSTRING *des_file); -- */
/*func module     */     MD_CP2P,
/*func logic addr */     (UINT32)cp2p_file_load,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cp2p_file_load",
/*func index      */     FI_cp2p_file_load,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     4,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,e_dbg_CSTRING_ptr,e_dbg_CSTRING_ptr,e_dbg_CSTRING_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cp2p_file_upload(const UINT32 cp2p_md_id, const CBYTES *src_file_content, const CSTRING *service_name, const CSTRING *des_file); -- */
/*func module     */     MD_CP2P,
/*func logic addr */     (UINT32)cp2p_file_upload,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cp2p_file_upload",
/*func index      */     FI_cp2p_file_upload,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     4,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,e_dbg_CBYTES_ptr,e_dbg_CSTRING_ptr,e_dbg_CSTRING_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cp2p_cmd_execute(const UINT32 cp2p_md_id, const CP2P_CMD *cp2p_cmd); -- */
/*func module     */     MD_CP2P,
/*func logic addr */     (UINT32)cp2p_cmd_execute,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cp2p_cmd_execute",
/*func index      */     FI_cp2p_cmd_execute,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     2,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,e_dbg_CP2P_CMD_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cp2p_cmd_deliver_notify(const UINT32 cp2p_md_id, const UINT32 des_network, const UINT32 des_tcid, const CP2P_CMD *cp2p_cmd); -- */
/*func module     */     MD_CP2P,
/*func logic addr */     (UINT32)cp2p_cmd_deliver_notify,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cp2p_cmd_deliver_notify",
/*func index      */     FI_cp2p_cmd_deliver_notify,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     4,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,e_dbg_UINT32,e_dbg_UINT32,e_dbg_CP2P_CMD_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cp2p_cmd_deliver(const UINT32 cp2p_md_id, const UINT32 des_network, const UINT32 des_tcid, const CP2P_CMD *cp2p_cmd); -- */
/*func module     */     MD_CP2P,
/*func logic addr */     (UINT32)cp2p_cmd_deliver,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cp2p_cmd_deliver",
/*func index      */     FI_cp2p_cmd_deliver,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     4,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,e_dbg_UINT32,e_dbg_UINT32,e_dbg_CP2P_CMD_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cp2p_online_report(const UINT32 cp2p_md_id, const CSTRING *service_name); -- */
/*func module     */     MD_CP2P,
/*func logic addr */     (UINT32)cp2p_online_report,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cp2p_online_report",
/*func index      */     FI_cp2p_online_report,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     2,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,e_dbg_CSTRING_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cp2p_refresh_cache_notify(const UINT32 cp2p_md_id, const UINT32 des_network, const UINT32 des_tcid, const CSTRING *service, const CSTRING *path); -- */
/*func module     */     MD_CP2P,
/*func logic addr */     (UINT32)cp2p_refresh_cache_notify,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cp2p_refresh_cache_notify",
/*func index      */     FI_cp2p_refresh_cache_notify,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     5,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,e_dbg_UINT32,e_dbg_UINT32,e_dbg_CSTRING_ptr,e_dbg_CSTRING_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cp2p_refresh_cache(const UINT32 cp2p_md_id, const UINT32 des_network, const UINT32 des_tcid, const CSTRING *service, const CSTRING *path); -- */
/*func module     */     MD_CP2P,
/*func logic addr */     (UINT32)cp2p_refresh_cache,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cp2p_refresh_cache",
/*func index      */     FI_cp2p_refresh_cache,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     5,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,e_dbg_UINT32,e_dbg_UINT32,e_dbg_CSTRING_ptr,e_dbg_CSTRING_ptr,},
/*func para val   */     0, 0, {0},
},
};

UINT32 g_cp2p_func_addr_list_len = sizeof(g_cp2p_func_addr_list)/sizeof(g_cp2p_func_addr_list[0]);
#endif/*_CP2P_INC*/

