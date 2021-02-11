/******************************************************************************
*
* Copyright (C) Chaoyong Zhou
* Email: bgnvendor@163.com
* QQ: 2796796
*
*******************************************************************************/
#ifndef _CFILE_INC
#define _CFILE_INC

#include "findex.inc"

FUNC_ADDR_NODE g_cfile_func_addr_list[ ] = {
{
/* -- void cfile_print_module_status(const UINT32 cfile_md_id, LOG *log); -- */
/*func module     */     MD_CFILE,
/*func logic addr */     (UINT32)cfile_print_module_status,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cfile_print_module_status",
/*func index      */     FI_cfile_print_module_status,
/*func ret type   */     e_dbg_void,
/*func para num   */     2,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IO,},
/*func para type  */     {e_dbg_UINT32,e_dbg_LOG_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- UINT32 cfile_free_module_static_mem(const UINT32 cfile_md_id); -- */
/*func module     */     MD_CFILE,
/*func logic addr */     (UINT32)cfile_free_module_static_mem,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cfile_free_module_static_mem",
/*func index      */     FI_cfile_free_module_static_mem,
/*func ret type   */     e_dbg_UINT32,
/*func para num   */     1,
/*func para direct*/     {E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,},
/*func para val   */     0, 0, {0},
},
{
/* -- UINT32 cfile_start(); -- */
/*func module     */     MD_CFILE,
/*func logic addr */     (UINT32)cfile_start,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cfile_start",
/*func index      */     FI_cfile_start,
/*func ret type   */     e_dbg_void,
/*func para num   */     0,
/*func para direct*/     {E_DIRECT_END,},
/*func para type  */     {e_dbg_void,},
/*func para val   */     0, 0, {0},
},
{
/* -- void cfile_end(const UINT32 cfile_md_id); -- */
/*func module     */     MD_CFILE,
/*func logic addr */     (UINT32)cfile_end,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cfile_end",
/*func index      */     FI_cfile_end,
/*func ret type   */     e_dbg_void,
/*func para num   */     1,
/*func para direct*/     {E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cfile_exists(const UINT32 cfile_md_id, const CSTRING *file_path); -- */
/*func module     */     MD_CFILE,
/*func logic addr */     (UINT32)cfile_exists,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cfile_exists",
/*func index      */     FI_cfile_exists,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     2,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,e_dbg_CSTRING_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cfile_size(const UINT32 cfile_md_id, const CSTRING *file_path, UINT32 *file_size); -- */
/*func module     */     MD_CFILE,
/*func logic addr */     (UINT32)cfile_size,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cfile_size",
/*func index      */     FI_cfile_size,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     3,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_OUT,},
/*func para type  */     {e_dbg_UINT32,e_dbg_CSTRING_ptr,e_dbg_UINT32_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cfile_md5(const UINT32 cfile_md_id, const CSTRING *file_path, CMD5_DIGEST *file_md5sum); -- */
/*func module     */     MD_CFILE,
/*func logic addr */     (UINT32)cfile_md5,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cfile_md5",
/*func index      */     FI_cfile_md5,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     3,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_OUT,},
/*func para type  */     {e_dbg_UINT32,e_dbg_CSTRING_ptr,e_dbg_CMD5_DIGEST_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cfile_load(const UINT32 cfile_md_id, const CSTRING *file_path, CBYTES *file_content); -- */
/*func module     */     MD_CFILE,
/*func logic addr */     (UINT32)cfile_load,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cfile_load",
/*func index      */     FI_cfile_load,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     3,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_OUT,},
/*func para type  */     {e_dbg_UINT32,e_dbg_CSTRING_ptr,e_dbg_CBYTES_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cfile_update(const UINT32 cfile_md_id, const CSTRING *file_path, const CBYTES *file_content); -- */
/*func module     */     MD_CFILE,
/*func logic addr */     (UINT32)cfile_update,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cfile_update",
/*func index      */     FI_cfile_update,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     3,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,e_dbg_CSTRING_ptr,e_dbg_CBYTES_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cfile_remove(const UINT32 cfile_md_id, const CSTRING *file_path); -- */
/*func module     */     MD_CFILE,
/*func logic addr */     (UINT32)cfile_remove,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cfile_remove",
/*func index      */     FI_cfile_remove,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     2,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,e_dbg_CSTRING_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cfile_rename(const UINT32 cfile_md_id, const CSTRING *src_file_path, const CSTRING *des_file_path); -- */
/*func module     */     MD_CFILE,
/*func logic addr */     (UINT32)cfile_rename,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cfile_rename",
/*func index      */     FI_cfile_rename,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     3,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,e_dbg_CSTRING_ptr,e_dbg_CSTRING_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cfile_seg_md5(const UINT32 cfile_md_id, const CSTRING *file_path, const UINT32 seg_offset, const UINT32 seg_size, CMD5_DIGEST *seg_md5sum); -- */
/*func module     */     MD_CFILE,
/*func logic addr */     (UINT32)cfile_seg_md5,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cfile_seg_md5",
/*func index      */     FI_cfile_seg_md5,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     5,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_OUT,},
/*func para type  */     {e_dbg_UINT32,e_dbg_CSTRING_ptr,e_dbg_UINT32,e_dbg_UINT32,e_dbg_CMD5_DIGEST_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cfile_seg_load(const UINT32 cfile_md_id, const CSTRING *file_path, const UINT32 seg_offset, const UINT32 seg_size, CBYTES *seg_content); -- */
/*func module     */     MD_CFILE,
/*func logic addr */     (UINT32)cfile_seg_load,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cfile_seg_load",
/*func index      */     FI_cfile_seg_load,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     5,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_OUT,},
/*func para type  */     {e_dbg_UINT32,e_dbg_CSTRING_ptr,e_dbg_UINT32,e_dbg_UINT32,e_dbg_CBYTES_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cfile_seg_update(const UINT32 cfile_md_id, const CSTRING *file_path, const UINT32 seg_offset, const UINT32 seg_size, const CBYTES *seg_content); -- */
/*func module     */     MD_CFILE,
/*func logic addr */     (UINT32)cfile_seg_update,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cfile_seg_update",
/*func index      */     FI_cfile_seg_update,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     5,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,e_dbg_CSTRING_ptr,e_dbg_UINT32,e_dbg_UINT32,e_dbg_CBYTES_ptr,},
/*func para val   */     0, 0, {0},
},
};

UINT32 g_cfile_func_addr_list_len = sizeof(g_cfile_func_addr_list)/sizeof(g_cfile_func_addr_list[0]);
#endif/*_CFILE_INC*/

