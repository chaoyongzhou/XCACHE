/******************************************************************************
*
* Copyright (C) Chaoyong Zhou
* Email: bgnvendor@163.com
* QQ: 2796796
*
*******************************************************************************/
#ifndef _CXFSNBD_INC
#define _CXFSNBD_INC

#include "findex.inc"

FUNC_ADDR_NODE g_cxfsnbd_func_addr_list[ ] = {
{
/* -- void cxfsnbd_print_module_status(const UINT32 cxfsnbd_md_id, LOG *log); -- */
/*func module     */     MD_CXFSNBD,
/*func logic addr */     (UINT32)cxfsnbd_print_module_status,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cxfsnbd_print_module_status",
/*func index      */     FI_cxfsnbd_print_module_status,
/*func ret type   */     e_dbg_void,
/*func para num   */     2,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IO,},
/*func para type  */     {e_dbg_UINT32,e_dbg_LOG_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- UINT32 cxfsnbd_free_module_static_mem(const UINT32 cxfsnbd_md_id); -- */
/*func module     */     MD_CXFSNBD,
/*func logic addr */     (UINT32)cxfsnbd_free_module_static_mem,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cxfsnbd_free_module_static_mem",
/*func index      */     FI_cxfsnbd_free_module_static_mem,
/*func ret type   */     e_dbg_UINT32,
/*func para num   */     1,
/*func para direct*/     {E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,},
/*func para val   */     0, 0, {0},
},
{
/* -- UINT32 cxfsnbd_start(const CSTRING *nbd_dev_name, const UINT32 nbd_blk_size, const UINT32 nbd_dev_size, const UINT32 nbd_timeout, const CSTRING *bucket_name, const UINT32 cxfs_tcid, const UINT32 cxfs_md_id); -- */
/*func module     */     MD_CXFSNBD,
/*func logic addr */     (UINT32)cxfsnbd_start,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cxfsnbd_start",
/*func index      */     FI_cxfsnbd_start,
/*func ret type   */     e_dbg_UINT32,
/*func para num   */     7,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_IN,E_DIRECT_IN,},
/*func para type  */     {e_dbg_CSTRING_ptr,e_dbg_UINT32,e_dbg_UINT32,e_dbg_UINT32,e_dbg_CSTRING_ptr,e_dbg_UINT32,e_dbg_UINT32,},
/*func para val   */     0, 0, {0},
},
{
/* -- void cxfsnbd_end(const UINT32 cxfsnbd_md_id); -- */
/*func module     */     MD_CXFSNBD,
/*func logic addr */     (UINT32)cxfsnbd_end,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cxfsnbd_end",
/*func index      */     FI_cxfsnbd_end,
/*func ret type   */     e_dbg_void,
/*func para num   */     1,
/*func para direct*/     {E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cxfsnbd_bucket_check(const UINT32 cxfsnbd_md_id); -- */
/*func module     */     MD_CXFSNBD,
/*func logic addr */     (UINT32)cxfsnbd_bucket_check,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cxfsnbd_bucket_check",
/*func index      */     FI_cxfsnbd_bucket_check,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     1,
/*func para direct*/     {E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cxfsnbd_bucket_create(const UINT32 cxfsnbd_md_id); -- */
/*func module     */     MD_CXFSNBD,
/*func logic addr */     (UINT32)cxfsnbd_bucket_create,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cxfsnbd_bucket_create",
/*func index      */     FI_cxfsnbd_bucket_create,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     1,
/*func para direct*/     {E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cxfsnbd_bucket_launch(const UINT32 cxfsnbd_md_id); -- */
/*func module     */     MD_CXFSNBD,
/*func logic addr */     (UINT32)cxfsnbd_bucket_launch,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cxfsnbd_bucket_launch",
/*func index      */     FI_cxfsnbd_bucket_launch,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     1,
/*func para direct*/     {E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,},
/*func para val   */     0, 0, {0},
},
};

UINT32 g_cxfsnbd_func_addr_list_len = sizeof(g_cxfsnbd_func_addr_list)/sizeof(g_cxfsnbd_func_addr_list[0]);
#endif/*_CXFSNBD_INC*/


