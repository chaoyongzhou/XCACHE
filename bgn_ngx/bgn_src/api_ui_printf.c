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
* Module Name   :   api_ui_printf.c
*
* Description:
*       These functions route the output from UI commands a specified handler.
*
* Dependencies:
*
******************************************************************************/


#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#include "type.h"
#include "log.h"

#include "api_ui_malloc.h"
#include "api_ui_log.h"
#include "api_ui_printf.h"

#define HUGE_CHUNK_SIZE 100

/* Global declarations */
static API_UI_BUFFER* buffer_list = NULL;

#define api_os_current_tid 0


/*---------------------------------------------------------------------------
 * Subroutine Name:    api_ui_register
 *
 * Input        Description
 * -----        -----------
 * buffer_sz    Max string size that handler can support.
 * handler  Function that handles the string output.
 *
 * Output        Description
 * ------        -----------
 * - none -
 *
 * Description:        The function registers the current task.  This way
 *      UIs can be executed from seperate task without any confusion about
 *      where the UI output should go.
 *---------------------------------------------------------------------------*/
void api_ui_register(size_t buffer_sz, API_UI_PRINTF_HANDLER handler)
{
    API_UI_BUFFER* node;
    API_UI_BUFFER** index_ptr;
    int mem_sz;

   int threadId = api_os_current_tid;

    index_ptr = &buffer_list;

    while((*index_ptr) != NULL)
    {
        if ((*index_ptr)->tid == threadId)
        {
            /* Task attempting to register twice */
            return;
        }
        index_ptr = &((*index_ptr)->next);
    }

    /* Register the task */

    /* Allocate the node and both buffers at the same time */
    mem_sz = buffer_sz * 2 + sizeof(API_UI_BUFFER);
    node = (API_UI_BUFFER*)api_ui_malloc(mem_sz, LOC_API_0316);

    if (node != NULL)
    {
        node->size = buffer_sz;
        node->tid = threadId;
        node->primary = (char*)node + sizeof(API_UI_BUFFER);
        node->secondary = node->primary + buffer_sz;
        node->index = 0;
        node->handler = handler;
        node->next = NULL;

        /* Put the null character at the ends */
        node->primary[node->size - 1] = '\0';
        node->secondary[node->size - 1] = '\0';
    }

    (*index_ptr) = node;

    return;
}

/*---------------------------------------------------------------------------
 * Subroutine Name:    api_ui_unregister
 *
 * Input        Description
 * -----        -----------
 * - none -
 *
 * Output        Description
 * ------        -----------
 * - none -
 *
 * Description:        Unregister the current task from being able to print with
 *     api_ui_printf()
 *
 *---------------------------------------------------------------------------*/
void api_ui_unregister()
{
    API_UI_BUFFER** index_ptr;
    API_UI_BUFFER* node;

   int threadId = api_os_current_tid;

    index_ptr = &buffer_list;

    while((*index_ptr) != NULL)
    {
        if ((*index_ptr)->tid == threadId)
        {
            node = (*index_ptr);
            (*index_ptr) = node->next;

            /* Clear the last buffer */
            node->primary[node->index] = '\0';
            (*(node->handler))("%s",node->primary);/*calling handler*/

            /* Free the memory */
            api_ui_free(node, LOC_API_0317);
            break;
        }
        index_ptr = &((*index_ptr)->next);
    }

    return;
}

/*---------------------------------------------------------------------------
 * Subroutine Name:    api_ui_flush
 *
 * Input        Description
 * -----        -----------
 * - none -
 *
 * Output        Description
 * ------        -----------
 * - none -
 *
 * Description:        This function flushes the current buffer.
 *
 *---------------------------------------------------------------------------*/
void api_ui_flush()
{
    API_UI_BUFFER* node;
    int threadId = api_os_current_tid;

    node = buffer_list;

    while(node != NULL)
    {
        if (node->tid == threadId)
        {
            break;
        }
        node = node->next;
    }

    if (node == NULL)
    {
        return;
    }

    /* Flush */
    node->primary[node->index] = '\0';
    (*(node->handler))("%s",node->primary);

    node->index = 0;

    return;
}

/*---------------------------------------------------------------------------
 * Subroutine Name:
 *
 * Input        Description
 * -----        -----------
 * fmt      String format (same tokens as printf())
 * ...      Extra arguments
 *
 * Output        Description
 * ------        -----------
 * int         Number of characters printed
 *
 *
 * Description:        This function should be used instead of printf() in an
 *      UI command.  When the primary buffer is full, the print handler for
 *      the current task is called.
 *
 *---------------------------------------------------------------------------*/
/**
 * Retrieves the array of variadic function arguments and forwards the call to
 * api_ui_vprintf_imp(). This function should be used only indirectly through
 * the api_ui_printf() macro.
 *
 * @param debug_file Filename of the location of function call
 * @param debug_line Line number of the location of function call
 * @param fmt Formatting string
 *
 * @return Result of api_ui_vprintf_imp()
 */

int api_ui_printf_imp( const char* debug_file, unsigned debug_line, const char* fmt, ... )
{
    va_list args;
    va_start( args, fmt );
    int stat = api_ui_vprintf_imp( debug_file, debug_line, fmt, args );
    va_end( args );
    return stat;
}

/*
 * Formats and prints a string on UI console. Destined for use in UI commands.
 * This function should not be used directly, but rather through api_ui_printf()
 * macro or by a custom api_ui_printf version.
 *
 * @param debug_file Filename of the location of function call
 * @param debug_line Line number of the location of function call
 * @param fmt Formatting string
 *
 * @return Result of vsnprintf() for the same list of arguments
 */
int api_ui_vprintf_imp(const char* debug_file, unsigned debug_line, const char* fmt, va_list args)
{
    API_UI_BUFFER* index_list = buffer_list;
    int size;
    int cpy_sz;
    char* str_temp;

    int threadId = api_os_current_tid;

    while(index_list != NULL)
    {
        if (index_list->tid == threadId)
        {
            break;
        }
        index_list = index_list->next;
    }

    /* The task is not registered */
    if (index_list == NULL)
    {

        dbg_log(SEC_0010_API, 5)(LOGSTDOUT,"api_ui_printf - Threadid 0x%x not registered - file: %s line %u",
                  threadId, debug_file, debug_line );
        return -1;
    }


    str_temp = (char *) api_ui_malloc((index_list->size)*2, LOC_API_0318);
    if (NULL == str_temp)
    {
        dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "api_ui_printf - could not allocate %d bytes - file: %s line %u",
                  (index_list->size)*2, debug_file, debug_line );
        return -2;
    }

    size = vsnprintf(str_temp, index_list->size, fmt, args);

    /* If this happens, someone is trying to print more characters than the
     * print handler can deal with.
     */
    if (size > index_list->size)
    {
        dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "api_ui_printf - Printing %d - allowed %d - file: %s line %u",
                  size,index_list->size, debug_file, debug_line );
        api_ui_free(str_temp, LOC_API_0319);
        return -3;
    }

    strncpy(index_list->secondary, str_temp, size);
    api_ui_free(str_temp, LOC_API_0320);

    cpy_sz = index_list->size - index_list->index - 1;

    strncpy(index_list->primary + index_list->index, index_list->secondary, cpy_sz);

    /* The primary buffer is already null terminated */
    if (size > cpy_sz)
    {
        (*(index_list->handler))("%s",index_list->primary);

        strncpy(index_list->primary, index_list->secondary + cpy_sz,
                size - cpy_sz);

        index_list->index = size - cpy_sz;
    }
    else
    {
        index_list->index += size;
    }

    return size;
}

/*---------------------------------------------------------------------------
 * Subroutine Name:    huge_api_ui_printf
 *
 * Input                Description
 * -----                -----------
 * huge_buff            Buffer to be printed
 *
 * Output               Description
 * ------               -----------
 * - none -
 *
 * Description:    This function allows a huge buffer to be printed
 *
 *---------------------------------------------------------------------------*/
void huge_api_ui_printf(char *huge_buff)
{
    int buff_size, n;
    char temp_str[HUGE_CHUNK_SIZE+1];

    if (NULL == huge_buff)
    {
        dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "huge_api_ui_printf() - huge buffer given to be printed is NULL");
        return;
    }

    buff_size = strlen(huge_buff);

    for(n = 0; n < buff_size; n += HUGE_CHUNK_SIZE)
    {
        strncpy(temp_str, (huge_buff + n), sizeof(temp_str) - 1);
        temp_str[sizeof(temp_str) - 1]='\0';
        api_ui_printf("%s", temp_str);
    }
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/


