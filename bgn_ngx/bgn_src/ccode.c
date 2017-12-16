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
#include <arpa/inet.h>

#include "ccode.h"

UINT32 g_host_byte_order = HOST_BYTE_ODER_IS_UNKNOW_ENDIAN;

EC_BOOL init_host_endian()
{
    UINT32 probe;

    probe = 1;

    if(*(char *)&probe)/*check low address in byte*/
    {
        g_host_byte_order =  HOST_BYTE_ODER_IS_LITTLE_ENDIAN;
    }
    else
    {
        g_host_byte_order = HOST_BYTE_ODER_IS_BIG_ENDIAN;
    }

    return (EC_TRUE);
}

void print_host_endian(LOG *log)
{
#if (__BYTE_ORDER == __LITTLE_ENDIAN)
    {
        sys_log(log, "host is little endian\n");
    }
#endif/*(__BYTE_ORDER == __LITTLE_ENDIAN)*/
#if (__BYTE_ORDER == __BIG_ENDIAN)
    {
        sys_log(log, "host is big endian\n");
    }
#endif/*(__BYTE_ORDER == __BIG_ENDIAN)*/
    return;
}

void print_uint8_buff(LOG *log, const UINT8 *buff, const UINT32 len)
{
    UINT32 pos;
    for(pos = 0; pos < len; pos ++)
    {
        sys_print(log, "%02x ", buff[ pos ]);

        if(0 == ((pos + 1) % 8) )
        {
            sys_print(log, "\t");
            continue;
        }

        if(0 == ((pos + 1) % 16) )
        {
            sys_print(log, "\n");
            continue;
        }
    }
    sys_print(log, "\n");
    return;
}

void print_uint16_buff(LOG *log, const UINT16 *buff, const UINT32 len)
{
    UINT32 pos;
    for(pos = 0; pos < len; pos ++)
    {
        sys_print(log, "%04x ", buff[ pos ]);

        if(0 == ((pos + 1) % 4) )
        {
            sys_print(log, "\t");
            continue;
        }

        if(0 == ((pos + 1) % 8) )
        {
            sys_print(log, "\n");
            continue;
        }
    }
    sys_print(log, "\n");
    return;
}

void print_uint32_buff(LOG *log, const UINT32 *buff, const UINT32 len)
{
    UINT32 pos;
    for(pos = 0; pos < len; pos ++)
    {
        sys_print(log, "%0lx ", buff[ pos ]);

        if(0 == ((pos + 1) % 2) )
        {
            sys_print(log, "\t");
            continue;
        }

        if(0 == ((pos + 1) % 4) )
        {
            sys_print(log, "\n");
            continue;
        }
    }
    sys_print(log, "\n");
    return;
}

void print_real_buff(LOG *log, const REAL *buff, const UINT32 len)
{
    UINT32 pos;
    for(pos = 0; pos < len; pos ++)
    {
        sys_print(log, "%.4f ", buff[ pos ]);

        if(0 == ((pos + 1) % 2) )
        {
            sys_print(log, "\t");
            continue;
        }

        if(0 == ((pos + 1) % 4) )
        {
            sys_print(log, "\n");
            continue;
        }
    }
    sys_print(log, "\n");
    return;
}

void print_char_buff(LOG *log, const UINT8 *buff, const UINT32 len)
{
    UINT32 pos;
    sys_log(log, "[len %ld] ", len);
    for(pos = 0; pos < len; pos ++)
    {
        sys_print(log, "%c ", buff[ pos ]);

        if(0 == ((pos + 1) % 8) )
        {
            sys_print(log, "\t");
            continue;
        }

        if(0 == ((pos + 1) % 16) )
        {
            sys_print(log, "\n");
            continue;
        }
    }
    sys_print(log, "\n");
    return;
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/
