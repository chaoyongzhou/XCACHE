/******************************************************************************
*
* Copyright (C) Chaoyong Zhou
* Email: bgnvendor@163.com
* QQ: 2796796
*
*******************************************************************************/
#ifdef __cplusplus
extern "C"{
#endif/*__cplusplus*/

/***************************************************************************
* Module Name   :   api_ui_cp.h
*
* Description:
* This header file contains the literals needed for maintenance of UI commmand interface
*
* Dependencies:
*
*****************************************************************************/
#ifndef _API_UI_CP_H
#define _API_UI_CP_H

#include "type.h"
#include "api_ui.inc"

/* Function Prototype */
void api_ui_cp_add_history(API_UI_INSTANCE* instance, API_UI_ELEM* element);
void api_ui_cp_add_param(API_UI_INSTANCE* instance, API_UI_ELEM* element, char* word);
void api_ui_cp_cleanup(API_UI_INSTANCE* instance);
void api_ui_cp_execute(API_UI_INSTANCE* instance);
void api_ui_cp_handle_word(API_UI_INSTANCE* instance, char* word);
void api_ui_cp_help(API_UI_INSTANCE* instance);
API_UI_INSTANCE* api_ui_cp_init(EC_BOOL interactive);
void    api_ui_cp_interactive(API_UI_INSTANCE* instance);
void    api_ui_cp_next_level(API_UI_INSTANCE* instance);
EC_BOOL api_ui_cp_param(API_UI_INSTANCE* instance, char* word);
EC_BOOL api_ui_cp_submenu(API_UI_INSTANCE* instance, char* word);
EC_BOOL api_ui_cp_valid_float(char* word);
EC_BOOL api_ui_cp_valid_integer(char* word);

void api_ui_cp(int argc, char** argv, EC_BOOL interactive, size_t buffer_sz, API_UI_PRINTF_HANDLER print_handler) ;

#endif /* _API_UI_CP_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/
