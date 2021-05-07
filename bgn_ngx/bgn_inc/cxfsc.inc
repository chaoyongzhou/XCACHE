/******************************************************************************
*
* Copyright (C) Chaoyong Zhou
* Email: bgnvendor@163.com
* QQ: 2796796
*
*******************************************************************************/
#ifndef _CXFSC_INC
#define _CXFSC_INC

#include "findex.inc"

FUNC_ADDR_NODE g_cxfsc_func_addr_list[ ] = {
{
/* -- void cxfsc_print_module_status(const UINT32 cxfsc_md_id, LOG *log); -- */
/*func module     */     MD_CXFSC,
/*func logic addr */     (UINT32)cxfsc_print_module_status,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cxfsc_print_module_status",
/*func index      */     FI_cxfsc_print_module_status,
/*func ret type   */     e_dbg_void,
/*func para num   */     2,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IO,},
/*func para type  */     {e_dbg_UINT32,e_dbg_LOG_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- UINT32 cxfsc_free_module_static_mem(const UINT32 cxfsc_md_id); -- */
/*func module     */     MD_CXFSC,
/*func logic addr */     (UINT32)cxfsc_free_module_static_mem,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cxfsc_free_module_static_mem",
/*func index      */     FI_cxfsc_free_module_static_mem,
/*func ret type   */     e_dbg_UINT32,
/*func para num   */     1,
/*func para direct*/     {E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,},
/*func para val   */     0, 0, {0},
},
{
/* -- UINT32 cxfsc_start(); -- */
/*func module     */     MD_CXFSC,
/*func logic addr */     (UINT32)cxfsc_start,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cxfsc_start",
/*func index      */     FI_cxfsc_start,
/*func ret type   */     e_dbg_UINT32,
/*func para num   */     0,
/*func para direct*/     {E_DIRECT_END,},
/*func para type  */     {e_dbg_type_end},
/*func para val   */     0, 0, {0},
},
{
/* -- void cxfsc_end(const UINT32 cxfsc_md_id); -- */
/*func module     */     MD_CXFSC,
/*func logic addr */     (UINT32)cxfsc_end,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cxfsc_end",
/*func index      */     FI_cxfsc_end,
/*func ret type   */     e_dbg_void,
/*func para num   */     1,
/*func para direct*/     {E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cxfsc_reg_xfs(const UINT32 cxfsc_md_id); -- */
/*func module     */     MD_CXFSC,
/*func logic addr */     (UINT32)cxfsc_reg_xfs,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cxfsc_reg_xfs",
/*func index      */     FI_cxfsc_reg_xfs,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     1,
/*func para direct*/     {E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cxfsc_reg_rnode(const UINT32 cxfsc_md_id, const UINT32 tcid, const UINT32 modi); -- */
/*func module     */     MD_CXFSC,
/*func logic addr */     (UINT32)cxfsc_reg_rnode,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cxfsc_reg_rnode",
/*func index      */     FI_cxfsc_reg_rnode,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     3,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,e_dbg_UINT32,e_dbg_UINT32,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cxfsc_is_file(const UINT32 cxfsc_md_id, const CSTRING *file_path); -- */
/*func module     */     MD_CXFSC,
/*func logic addr */     (UINT32)cxfsc_is_file,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cxfsc_is_file",
/*func index      */     FI_cxfsc_is_file,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     2,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,e_dbg_CSTRING_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cxfsc_file_size(const UINT32 cxfsc_md_id, const CSTRING *path_cstr, uint64_t *file_size); -- */
/*func module     */     MD_CXFSC,
/*func logic addr */     (UINT32)cxfsc_file_size,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cxfsc_file_size",
/*func index      */     FI_cxfsc_file_size,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     3,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_OUT,},
/*func para type  */     {e_dbg_UINT32,e_dbg_CSTRING_ptr,e_dbg_uint64_t_ptr,},
/*func para val   */     0, 0, {0},
},

{
/* -- EC_BOOL cxfsc_write_e(const UINT32 cxfsc_md_id, const CSTRING *file_path, UINT32 *offset, const UINT32 max_len, const CBYTES *cbytes); -- */
/*func module     */     MD_CXFSC,
/*func logic addr */     (UINT32)cxfsc_write_e,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cxfsc_write_e",
/*func index      */     FI_cxfsc_write_e,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     5,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_IO,E_DIRECT_IN,E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,e_dbg_CSTRING_ptr,e_dbg_UINT32_ptr,e_dbg_UINT32,e_dbg_CBYTES_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cxfsc_read_e(const UINT32 cxfsc_md_id, const CSTRING *file_path, UINT32 *offset, const UINT32 max_len, CBYTES *cbytes); -- */
/*func module     */     MD_CXFSC,
/*func logic addr */     (UINT32)cxfsc_read_e,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cxfsc_read_e",
/*func index      */     FI_cxfsc_read_e,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     5,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_IO,E_DIRECT_IN,E_DIRECT_OUT,},
/*func para type  */     {e_dbg_UINT32,e_dbg_CSTRING_ptr,e_dbg_UINT32_ptr,e_dbg_UINT32,e_dbg_CBYTES_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cxfsc_delete_file(const UINT32 cxfsc_md_id, const CSTRING *path); -- */
/*func module     */     MD_CXFSC,
/*func logic addr */     (UINT32)cxfsc_delete_file,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cxfsc_delete_file",
/*func index      */     FI_cxfsc_delete_file,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     2,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,e_dbg_CSTRING_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cxfsc_truncate_file(const UINT32 cxfsc_md_id, const CSTRING *file_path, const UINT32 file_size); -- */
/*func module     */     MD_CXFSC,
/*func logic addr */     (UINT32)cxfsc_truncate_file,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cxfsc_truncate_file",
/*func index      */     FI_cxfsc_truncate_file,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     3,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,e_dbg_CSTRING_ptr,e_dbg_UINT32,},
/*func para val   */     0, 0, {0},
},
};

UINT32 g_cxfsc_func_addr_list_len = sizeof(g_cxfsc_func_addr_list)/sizeof(g_cxfsc_func_addr_list[0]);
#endif/*_CXFSC_INC*/


