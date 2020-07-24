/******************************************************************************
*
* Copyright (C) Chaoyong Zhou
* Email: bgnvendor@163.com 
* QQ: 2796796 
*
*******************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char g_buf[4 * 1024 * 1024];

const char g_chars[] = 
    "0123456789"
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const int g_chars_len = sizeof(g_chars) - 1;
int g_pos = 0;

const char get_char()
{   
    g_pos %= g_chars_len;

    return g_chars[ g_pos ++];
}

void fill_head(char *buf, const unsigned long max, unsigned long *used)
{
    if(max > (*used))
    {
        char head[ 16 ];
        unsigned long len;

        len = snprintf(head, 16, "%08ld# ", (*used));
        if(max - (*used) < len)
        {
            len = max - (*used);
        }

        memcpy(buf + (*used), head, len);
        (*used) += len;
    }
    //fprintf(stdout, "[DEBUG] fill_head: max: %ld, used: %ld\n", max, *used);
    return;
}

void fill_tail(char *buf, const unsigned long max, unsigned long *used)
{
    unsigned long idx;
    for(idx = 0; idx < 16 && max > (*used); idx ++)
    {
        buf[ (*used) ++ ] = get_char();
    }
    
    if(max > (*used))
    {
        buf[ (*used) ++ ] = ' ';
    }

    for(idx = 0; idx < 16 && max > (*used); idx ++)
    {
        buf[ (*used) ++ ] = get_char();
    }    
    
    if(max > (*used))
    {
        buf[ (*used) ++ ] = '\n';
    }
    //fprintf(stdout, "[DEBUG] fill_tail: max: %ld, used: %ld\n", max, *used);
}

void fill_buf(char *buf, const unsigned long max)
{
    unsigned long used;   

    for(used = 0; used < max;)
    {
        //fprintf(stdout, "[DEBUG] fill_buf: max: %ld, used: %ld\n", max, used);
        fill_head(buf, max, &used);
        fill_tail(buf, max, &used);
    }
    //fprintf(stdout, "[DEBUG] fill_buf: max: %ld, used: %ld\n", max, used);
}

int main()
{

    
    const char *fnames[] = {
        "4K.dat",
        "8K.dat",
        "16K.dat",
        "32K.dat",
        "64K.dat",
        "128K.dat",
        "256K.dat",
        "512K.dat",
        "1M.dat",

        "1K.dat",
        "2K.dat",
        "3K.dat",
        "5K.dat",
        "6K.dat",
        "7K.dat",
        "9K.dat",
        "10K.dat",
        "11K.dat",
        "12K.dat",
        "13K.dat",
        "14K.dat",
        "15K.dat",

        "2M.dat",
        "4M.dat",
    };

   const unsigned long fsizes[] = {
        4 * 1024,
        8 * 1024,
        16 * 1024,
        32 * 1024,
        64 * 1024,
        128 * 1024,
        256 * 1024,
        512 * 1024,
        1024 * 1024,

        1 * 1024,
        2 * 1024,
        3 * 1024,
        5 * 1024,
        6 * 1024,
        7 * 1024,
        9 * 1024,
        10 * 1024,
        11 * 1024,
        12 * 1024,
        13 * 1024,
        14 * 1024,
        15 * 1024,

        2 * 1024 * 1024,
        4 * 1024 * 1024,
   };
   const unsigned long num = sizeof(fsizes)/sizeof(fsizes[0]);

   unsigned long idx;
   unsigned long pos;

   FILE *fp;

   for (idx = 0; idx < num; idx ++) 
   {
        memset((void *)g_buf, 0, sizeof(g_buf));    
        fill_buf(g_buf, fsizes[idx]);
        
        fp = fopen(fnames[idx], "w");
        //fprintf(stdout, "%.*s\n", fsizes[idx], g_buf);
        fprintf(fp, "%.*s", fsizes[idx], g_buf);
        fclose(fp);
   }
}
