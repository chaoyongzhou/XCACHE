/******************************************************************************
*
* Copyright (C) Chaoyong Zhou
* Email: bgnvendor@163.com
* QQ: 2796796
*
*******************************************************************************/
#if (SWITCH_OFF == NGX_BGN_SWITCH)

#ifndef _CUNIXPACKET_AGENT_INC
#define _CUNIXPACKET_AGENT_INC

#include "findex.inc"

FUNC_ADDR_NODE g_cunixpacket_agent_func_addr_list[ ] = {
{
/* -- void cunixpacket_agent_print_module_status(const UINT32 cunixpacket_agent_md_id, LOG *log); -- */
/*func module     */     MD_CUNIXPACKET,
/*func logic addr */     (UINT32)cunixpacket_agent_print_module_status,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cunixpacket_agent_print_module_status",
/*func index      */     FI_cunixpacket_agent_print_module_status,
/*func ret type   */     e_dbg_void,
/*func para num   */     2,
/*func para direct*/     {E_DIRECT_IN,E_DIRECT_IO,},
/*func para type  */     {e_dbg_UINT32,e_dbg_LOG_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- UINT32 cunixpacket_agent_start(const CSTRING *uds_path); -- */
/*func module     */     MD_CUNIXPACKET,
/*func logic addr */     (UINT32)cunixpacket_agent_start,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cunixpacket_agent_start",
/*func index      */     FI_cunixpacket_agent_start,
/*func ret type   */     e_dbg_UINT32,
/*func para num   */     1,
/*func para direct*/     {E_DIRECT_IN,},
/*func para type  */     {e_dbg_CSTRING_ptr,},
/*func para val   */     0, 0, {0},
},
{
/* -- void cunixpacket_agent_end(const UINT32 cunixpacket_agent_md_id); -- */
/*func module     */     MD_CUNIXPACKET,
/*func logic addr */     (UINT32)cunixpacket_agent_end,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cunixpacket_agent_end",
/*func index      */     FI_cunixpacket_agent_end,
/*func ret type   */     e_dbg_void,
/*func para num   */     1,
/*func para direct*/     {E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cunixpacket_agent_process_packet(const UINT32 cunixpacket_agent_md_id); -- */
/*func module     */     MD_CUNIXPACKET,
/*func logic addr */     (UINT32)cunixpacket_agent_process_packet,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cunixpacket_agent_process_packet",
/*func index      */     FI_cunixpacket_agent_process_packet,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     1,
/*func para direct*/     {E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,},
/*func para val   */     0, 0, {0},
},
{
/* -- EC_BOOL cunixpacket_agent_process(const UINT32 cunixpacket_agent_md_id); -- */
/*func module     */     MD_CUNIXPACKET,
/*func logic addr */     (UINT32)cunixpacket_agent_process,
/*func beg addr   */     0,
/*func end addr   */     0,
/*func addr offset*/     0,
/*func name       */     "cunixpacket_agent_process",
/*func index      */     FI_cunixpacket_agent_process,
/*func ret type   */     e_dbg_EC_BOOL,
/*func para num   */     1,
/*func para direct*/     {E_DIRECT_IN,},
/*func para type  */     {e_dbg_UINT32,},
/*func para val   */     0, 0, {0},
},
};

UINT32 g_cunixpacket_agent_func_addr_list_len = sizeof(g_cunixpacket_agent_func_addr_list)/sizeof(g_cunixpacket_agent_func_addr_list[0]);
#endif/*_CUNIXPACKET_AGENT_INC*/

#endif/*(SWITCH_OFF == NGX_BGN_SWITCH)*/

