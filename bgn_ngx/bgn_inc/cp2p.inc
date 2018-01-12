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
/* -- UINT32 cp2p_start(const CSTRING * crfs_root_dir, const CSTRING * ctdns_root_dir); -- */
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
/* -- EC_BOOL cp2p_download_file_exists(const UINT32 cp2p_md_id, const CP2P_FILE *cp2p_file); -- */
/*func module     */     MD_CP2P,
/*func logic addr */     (UINT32)cp2p_download_file_exists,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cp2p_download_file_exists",
/*func index      */     FI_cp2p_download_file_exists,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     2,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,e_dbg_CP2P_FILE_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cp2p_download_file_ep(const UINT32 cp2p_md_id, const UINT32 src_tcid, const CP2P_FILE *cp2p_file); -- */
/*func module     */     MD_CP2P,
/*func logic addr */     (UINT32)cp2p_download_file_ep,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cp2p_download_file_ep",
/*func index      */     FI_cp2p_download_file_ep,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     3,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,e_dbg_UINT32,e_dbg_CP2P_FILE_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cp2p_download_file(const UINT32 cp2p_md_id, const UINT32 src_tcid, const CP2P_FILE *cp2p_file); -- */
/*func module     */     MD_CP2P,
/*func logic addr */     (UINT32)cp2p_download_file,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cp2p_download_file",
/*func index      */     FI_cp2p_download_file,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     3,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,e_dbg_UINT32,e_dbg_CP2P_FILE_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cp2p_download_completion(const UINT32 cp2p_md_id, const UINT32 des_tcid, const CP2P_FILE *cp2p_file); -- */
/*func module     */     MD_CP2P,
/*func logic addr */     (UINT32)cp2p_download_completion,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cp2p_download_completion",
/*func index      */     FI_cp2p_download_completion,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     3,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,e_dbg_UINT32,e_dbg_CP2P_FILE_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cp2p_download_notify(const UINT32 cp2p_md_id, const UINT32 src_tcid, const CP2P_FILE *cp2p_file); -- */
/*func module     */     MD_CP2P,
/*func logic addr */     (UINT32)cp2p_download_notify,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cp2p_download_notify",
/*func index      */     FI_cp2p_download_notify,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     3,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,e_dbg_UINT32,e_dbg_CP2P_FILE_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cp2p_download_broadcast(const UINT32 cp2p_md_id, const CP2P_FILE *cp2p_file); -- */
/*func module     */     MD_CP2P,
/*func logic addr */     (UINT32)cp2p_download_broadcast,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cp2p_download_broadcast",
/*func index      */     FI_cp2p_download_broadcast,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     2,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,e_dbg_CP2P_FILE_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cp2p_upload_file(const UINT32 cp2p_md_id, const CSTRING *src_file, const CSTRING *service_name, const CSTRING *des_file); -- */
/*func module     */     MD_CP2P,
/*func logic addr */     (UINT32)cp2p_upload_file,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cp2p_upload_file",
/*func index      */     FI_cp2p_upload_file,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     4,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,e_dbg_CSTRING_ptr,e_dbg_CSTRING_ptr,e_dbg_CSTRING_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cp2p_execute_cmd(const UINT32 cp2p_md_id, const CP2P_CMD *cp2p_cmd); -- */
/*func module     */     MD_CP2P,
/*func logic addr */     (UINT32)cp2p_execute_cmd,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cp2p_execute_cmd",
/*func index      */     FI_cp2p_execute_cmd,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     2,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,e_dbg_CP2P_CMD_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cp2p_deliver_cmd(const UINT32 cp2p_md_id, const CP2P_CMD *cp2p_cmd); -- */
/*func module     */     MD_CP2P,
/*func logic addr */     (UINT32)cp2p_deliver_cmd,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cp2p_deliver_cmd",
/*func index      */     FI_cp2p_deliver_cmd,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     2,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,e_dbg_CP2P_CMD_ptr,},
/*func para val   */     0, 0, {0},
},
};

UINT32 g_cp2p_func_addr_list_len = sizeof(g_cp2p_func_addr_list)/sizeof(g_cp2p_func_addr_list[0]);
#endif/*_CP2P_INC*/

