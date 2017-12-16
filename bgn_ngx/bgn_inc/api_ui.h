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

#ifndef _API_UI_H
#define _API_UI_H

#include <stddef.h>
#include <stdarg.h>

#include "type.h"
#include "api_ui.inc"

#include "cstring.h"

/* Function Prototypes */
API_UI_NODE *api_ui_cmd_tree();

void api_ui_init();
void api_ui_task();

void         api_ui_add_to_new_node_list(API_UI_CNODE** start_ptr, API_UI_NODE** node_ptr);
API_UI_ERR   api_ui_cleanup(API_UI_ERR err, char* copy_cmd_str, API_UI_CNODE* new_node_list);
API_UI_ELEM* api_ui_create_elem(const char* word, const char* help, API_UI_ELEM_TYPE type);
API_UI_NODE* api_ui_create_node(API_UI_ELEM* element, API_UI_SECURITY_LEVEL sl);
void         api_ui_delete_elem(API_UI_ELEM* element);
API_UI_NODE* api_ui_insert_node_sl (API_UI_NODE** node_ptr, API_UI_ELEM* element, API_UI_SECURITY_LEVEL sl);
API_UI_ELEM *api_ui_arg_float(char *arg_name, char *help_str);
API_UI_ELEM* api_ui_arg_list(const char* arg_name, const char * help_str);
API_UI_ERR   api_ui_arg_list_item(API_UI_ELEM* list, const char* item_name,int value, const char* help_str);
API_UI_ELEM *api_ui_arg_range(const char *arg_name, const char *help_str,int low_value, int high_value);
API_UI_ELEM *api_ui_arg_num(const char *arg_name, const char *help_str);
API_UI_ELEM *api_ui_arg_str(const char *arg_name, const char *help_str);
API_UI_ELEM *api_ui_arg_tcid(const char *arg_name, const char *help_str);
API_UI_ERR   api_ui_define(API_UI_HANDLER handler, char* help_str, char* cmd_str, ...);
API_UI_ERR   api_ui_common_define (API_UI_SECURITY_LEVEL sl, API_UI_HANDLER handler, const char* help_str, const char* cmd_str, va_list params);
API_UI_ERR   api_ui_secure_define (API_UI_SECURITY_LEVEL sl, API_UI_HANDLER handler, const char* help_str, const char* cmd_str, ...) ;

API_UI_ERR        api_ui_param_float(API_UI_PARAM *param_list, int param_num, float *decimal_ptr);
API_UI_PARAM_TYPE api_ui_param_get_type(API_UI_PARAM *param_list, int param_num);
API_UI_ERR        api_ui_param_int(API_UI_PARAM *param_list, int param_num, int *value_ptr);
API_UI_ERR        api_ui_param_str(API_UI_PARAM *param_list, int param_num, char *str, size_t size);

API_UI_ERR        api_ui_param_cstring(API_UI_PARAM *param_list, int param_num, CSTRING *cstring);
#endif  /* _API_UI_H */

#ifdef __cplusplus
}
#endif /* _cplusplus */

