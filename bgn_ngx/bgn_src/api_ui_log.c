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

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>

#include "type.h"

#define MAX_APP_PRINTF_BUFF_SIZE 225

int app_printf(const char* fmt, ...)
{
    va_list args;
    int retVal = -1;
    /*added code to handle larger buffers*/
    int fmt_length, index;
    char temp_char, *fmtptr;

    fmtptr = (char *)fmt;
    fmt_length = strlen(fmt);

    /* if buffer larger than normal max string */
    if(fmt_length > MAX_APP_PRINTF_BUFF_SIZE)
    {
        va_start(args,fmt);
        /* go through buffer and print chunks */
        for(index = 0; index < fmt_length; index += MAX_APP_PRINTF_BUFF_SIZE)
        {
            /*case for last section of buffer to be printed*/
            if (index + MAX_APP_PRINTF_BUFF_SIZE >= fmt_length)
            {
                retVal = vprintf((fmtptr + index), args);
            }
            else
            {
                temp_char = *(fmtptr + index + MAX_APP_PRINTF_BUFF_SIZE);
                *(fmtptr + index + MAX_APP_PRINTF_BUFF_SIZE) = '\0';
                vprintf((fmtptr + index), args);
                *(fmtptr + index + MAX_APP_PRINTF_BUFF_SIZE) = temp_char;
            }
        }
        va_end(args);
    }
    else
    {
        va_start(args,fmt);
        retVal = vprintf(fmt,args);
        va_end(args);
    }
    if (retVal == EOF)
    {
        printf("app_printf(): I/O error\n");
        return -1;
    }

    return retVal;
}


#ifdef __cplusplus
}
#endif/*__cplusplus*/

