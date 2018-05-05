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
* Module Name   :   api_ui_printf.h
*
* Description:
* This header file contains the literals needed for maintenance of UI commmand interface
*
* Dependencies:
*
******************************************************************************/


#ifndef _API_UI_PRINTF_H
#define _API_UI_PRINTF_H

#include "api_ui.h"

/*
 * Data Structures
 */
typedef struct api_ui_buffer
{
	int tid;
	int size;
	int index;
	API_UI_PRINTF_HANDLER handler;
	struct api_ui_buffer* next;
	char* primary;
	char* secondary;
} API_UI_BUFFER;

/*
 * Function Prototypes
 */
void api_ui_register(size_t buffer_sz, API_UI_PRINTF_HANDLER handler);
void api_ui_unregister();
void api_ui_flush();


int api_ui_printf_imp( const char* debug_file, unsigned debug_line, const char* fmt, ... );
int api_ui_vprintf_imp(const char* debug_file, unsigned debug_line, const char* fmt, va_list args);
void huge_api_ui_printf(char *huge_buff);

#define api_ui_printf(args...) api_ui_printf_imp(__FILE__, __LINE__, ##args)

#endif

#ifdef __cplusplus
}
#endif/*__cplusplus*/
