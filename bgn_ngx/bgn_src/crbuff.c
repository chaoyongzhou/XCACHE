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
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>

#include "type.h"

#include "log.h"
#include "mm.h"

#include "cmpic.inc"
#include "cparacfg.inc"

#include "csocket.h"
#include "crbuff.h"
#include "task.h"

#define CRBUFF_PRINT_BLOCK_WIDETH      8
#define CRBUFF_PRINT_LINE_WIDETH      32

#define CRBUFF_FAST_COPY_MODE 1
#define CRBUFF_SLOW_COPY_MODE 2

#define CRBUFF_COPY_MODE  CRBUFF_FAST_COPY_MODE
//#define CRBUFF_COPY_MODE  CRBUFF_SLOW_COPY_MODE

#if 1
#define PRINT_BUFF(info, buff, len) do{\
    UINT32 __pos__;\
    dbg_log(SEC_0033_CRBUFF, 5)(LOGSTDOUT, "%s: ", info);\
    for(__pos__ = 0; __pos__ < len; __pos__ ++)\
    {\
        sys_print(LOGSTDOUT, "%x,", ((UINT8 *)buff)[ __pos__ ]);\
    }\
    sys_print(LOGSTDOUT, "\n");\
}while(0)
#else
#define PRINT_BUFF(info, buff, len) do{}while(0)
#endif

#if 1
#define CRBUFF_DEBUG_AND_ASSERT(crbuff,info, pos, len, max) do{}while(0)

#else
#define CRBUFF_DEBUG_AND_ASSERT(_crbuff,info, pos, len, max)  crbuff_debug(_crbuff, info, pos, len, max)
#endif
static void crbuff_debug(const CRBUFF *crbuff, const char *info, const UINT32 pos, const UINT32 len, const UINT32 max)
{
    if(0 < len)
    {
        dbg_log(SEC_0033_CRBUFF, 9)(LOGSTDOUT, "[DEBUG]%s:crbuff %lx, w_pos: %ld, r_pos %ld, readpos %ld + len %ld = %ld <----> max = %ld\n",
                            (info), crbuff,
                            CRBUFF_WRITE_POS(crbuff), CRBUFF_READ_POS(crbuff),
                            (pos), (len), (pos) + (len), (max));
        if((pos) >= (max) || (pos) + (len) > (max))
        {
            dbg_log(SEC_0033_CRBUFF, 0)(LOGSTDOUT, "error:%s: overflow where pos %ld, len %ld, max %ld\n", (info), (pos), (len), (max));
            dbg_exit(MD_END, CMPI_ANY_MODI);
        }
    }
}

void crbuff_copy(const UINT8 *src, UINT8 *des, UINT32 len)
{
    BCOPY(src, des, len);
#if 0
    UINT32 pos;
    //dbg_log(SEC_0033_CRBUFF, 9)(LOGSTDOUT, "[DEBUG] crbuff_copy: src %lx, des %lx, len %ld\n", src, des, len);
    //PRINT_BUFF("[DEBUG] crbuff_copy: src = ", src, len);
    for(pos = 0; pos < len; pos ++)
    {
        *des ++ = *src ++;
    }
#endif
    return;
}

EC_BOOL crbuff_init(CRBUFF *crbuff)
{
    CRBUFF_WRITE_POS(crbuff) = 0;
    CRBUFF_READ_POS(crbuff)  = 0;
    return (EC_TRUE);
}

CRBUFF * crbuff_new(const UINT32 size)
{
    CRBUFF *crbuff;

    crbuff = (CRBUFF *)SAFE_MALLOC(sizeof(CRBUFF) + size, LOC_CRBUFF_0001);
    if(NULL_PTR == crbuff)
    {
        dbg_log(SEC_0033_CRBUFF, 0)(LOGSTDOUT, "error:crbuff_new: failed to alloc CRBUFF\n");
        return (NULL_PTR);
    }

    crbuff_set_max_len(crbuff, size);
    crbuff_init(crbuff);
    return (crbuff);
}

EC_BOOL crbuff_clean(CRBUFF *crbuff)
{
    CRBUFF_WRITE_POS(crbuff) = 0;
    CRBUFF_READ_POS(crbuff)  = 0;
    return (EC_TRUE);
}

EC_BOOL crbuff_reset(CRBUFF *crbuff)
{
    CRBUFF_WRITE_POS(crbuff) = 0;
    CRBUFF_READ_POS(crbuff)  = 0;
    return (EC_TRUE);
}

EC_BOOL crbuff_free(CRBUFF *crbuff)
{
    if(NULL_PTR != crbuff)
    {
        crbuff_clean(crbuff);
        SAFE_FREE(crbuff, LOC_CRBUFF_0002);
    }
    return (EC_TRUE);
}

EC_BOOL crbuff_set_max_len(CRBUFF *crbuff, const UINT32 size)
{
    CRBUFF_MAX_LEN(crbuff) = size;
    return (EC_TRUE);
}

UINT32 crbuff_get_max_len(const CRBUFF *crbuff)
{
    return CRBUFF_MAX_LEN(crbuff);
}

static void crbuff_print_one_char_with_alignment(LOG *log, const UINT8 ch, const UINT32 count)
{
    sys_print(LOGSTDOUT, "%02x ", ch);
    //sys_print(LOGSTDOUT, "%c ", ch);
    if(0 == (count % CRBUFF_PRINT_BLOCK_WIDETH) && 0 != (count % CRBUFF_PRINT_LINE_WIDETH))
    {
        sys_print(log, "   ");
    }
    if(0 == (count % CRBUFF_PRINT_LINE_WIDETH))
    {
        sys_print(log, "\n");
    }
    return;
}

static void crbuff_print_end_with_alignment(LOG *log, const UINT32 count)
{
    if(0 != (count % CRBUFF_PRINT_LINE_WIDETH))
    {
        sys_print(log, "\n");
    }
    return;
}


static void crbuff_print_whole_cache(LOG *log, const CRBUFF *crbuff)
{
    UINT32 pos;
    UINT32 count;

    dbg_log(SEC_0033_CRBUFF, 5)(LOGSTDOUT, "crbuff %lx: whole cache: \n", crbuff);
    for(count = 1, pos = 0; pos < CRBUFF_MAX_LEN(crbuff); count ++, pos ++)
    {
        crbuff_print_one_char_with_alignment(log, CRBUFF_CACHE_CHAR(crbuff, pos), count);
    }
    crbuff_print_end_with_alignment(log, count);

    return;
}

static void crbuff_print_to_read_cache(LOG *log, const CRBUFF *crbuff)
{
    UINT32 total_read_len;
    UINT32 to_tail_len;

    total_read_len = CRBUFF_WRITE_POS(crbuff) - CRBUFF_READ_POS(crbuff);
    to_tail_len    = CRBUFF_MAX_LEN(crbuff) - (CRBUFF_READ_POS(crbuff) % CRBUFF_MAX_LEN(crbuff));

    dbg_log(SEC_0033_CRBUFF, 5)(LOGSTDOUT, "crbuff %lx: to read cache: \n", crbuff);
    if(total_read_len >= to_tail_len)
    {
        UINT32 pos;
        UINT32 last;
        UINT32 count;

        count = 1;
        pos  = (CRBUFF_READ_POS(crbuff) % CRBUFF_MAX_LEN(crbuff));
        last = (CRBUFF_WRITE_POS(crbuff) % CRBUFF_MAX_LEN(crbuff));

        /*to tail*/
        for(; pos < CRBUFF_MAX_LEN(crbuff); pos ++, count ++)
        {
            crbuff_print_one_char_with_alignment(log, CRBUFF_CACHE_CHAR(crbuff, pos), count);
        }

        for(pos = 0; pos < last; pos ++, count ++)
        {
            crbuff_print_one_char_with_alignment(log, CRBUFF_CACHE_CHAR(crbuff, pos), count);
        }
        crbuff_print_end_with_alignment(log, count);
    }
    else
    {
        UINT32 pos;
        UINT32 last;
        UINT32 count;

        count = 1;
        pos  = (CRBUFF_READ_POS(crbuff) % CRBUFF_MAX_LEN(crbuff));
        last = (CRBUFF_WRITE_POS(crbuff) % CRBUFF_MAX_LEN(crbuff));

        /*to tail*/
        for(; pos < last; pos ++, count ++)
        {
            crbuff_print_one_char_with_alignment(log, CRBUFF_CACHE_CHAR(crbuff, pos), count);
        }
        crbuff_print_end_with_alignment(log, count);
    }
    return;
}
void crbuff_print(LOG *log, const CRBUFF *crbuff)
{
    if(NULL_PTR == crbuff)
    {
        return;
    }
 
    dbg_log(SEC_0033_CRBUFF, 5)(LOGSTDOUT, "crbuff %lx: max_len = %ld, read_pos = %ld, write_pos = %ld\n",
                    crbuff, CRBUFF_MAX_LEN(crbuff), CRBUFF_READ_POS(crbuff), CRBUFF_WRITE_POS(crbuff));

    if( 0 == CRBUFF_MAX_LEN(crbuff))
    {
        dbg_log(SEC_0033_CRBUFF, 5)(LOGSTDOUT, "crbuff %lx: whole cache: (null)\n"      , crbuff);
        dbg_log(SEC_0033_CRBUFF, 5)(LOGSTDOUT, "crbuff %lx: to read cache: (null)\n"    , crbuff);
        return;
    }

    //crbuff_print_whole_cache(log, crbuff);
    crbuff_print_to_read_cache(log, crbuff);

    dbg_log(SEC_0033_CRBUFF, 5)(LOGSTDOUT, "max len        : %ld\n", CRBUFF_MAX_LEN(crbuff));
    dbg_log(SEC_0033_CRBUFF, 5)(LOGSTDOUT, "total write len: %ld\n", crbuff_total_write_len(crbuff));
    dbg_log(SEC_0033_CRBUFF, 5)(LOGSTDOUT, "total read  len: %ld\n", crbuff_total_read_len(crbuff));
    dbg_log(SEC_0033_CRBUFF, 5)(LOGSTDOUT, "once  write len: %ld\n", crbuff_once_write_len(crbuff));
    dbg_log(SEC_0033_CRBUFF, 5)(LOGSTDOUT, "once  read  len: %ld\n", crbuff_once_read_len(crbuff));
    return;
}

UINT32 crbuff_total_write_len(const CRBUFF *crbuff)
{
    return (CRBUFF_MAX_LEN(crbuff) - (CRBUFF_WRITE_POS(crbuff) - CRBUFF_READ_POS(crbuff)));
}

UINT32 crbuff_total_read_len(const CRBUFF *crbuff)
{
    return (CRBUFF_WRITE_POS(crbuff) - CRBUFF_READ_POS(crbuff));
}
/**
*
*   note 0 <= read_pos <= write_pos <= read_pos + max
*   check right boundary k * max,
*   when
*       0 <= read_pos <= write_pos <= read_pos + max <= k * max
*   then
*       once_write_len = read_pos + max - write_pos   => the distance from write_pos to read_pos + max
                       = max - (write_pos - read_pos)
*   when
*       0 <= read_pos <= write_pos <= k * max <= read_pos + max
*   then
*       once_write_len = k * max - write_pos     => the distance from write_pos to k * max
                       = max - (write_pos % max)
*
**/
UINT32 crbuff_once_write_len(const CRBUFF *crbuff)
{
    UINT32 total_write_len;
    UINT32 to_tail_len;

    total_write_len = CRBUFF_MAX_LEN(crbuff) - (CRBUFF_WRITE_POS(crbuff) - CRBUFF_READ_POS(crbuff));
    to_tail_len     = CRBUFF_MAX_LEN(crbuff) - (CRBUFF_WRITE_POS(crbuff) % CRBUFF_MAX_LEN(crbuff));

    if(total_write_len >= to_tail_len)
    {
        return (to_tail_len);
    }
    return (total_write_len);
}

/**
*
*   note 0 <= read_pos <= write_pos
*   check right boundary k * max,
*   when
*       0 <= read_pos <= write_pos <= k * max
*   then
*       once_read_len = (write_pos - read_pos) => the distance from read_pos to write_pos
*   when
*       0 <= read_pos <= k * max <= write_pos
*   then
*       once_write_len = k * max - read_pos => the distance from read_pos to k * max
                       = max - read_pos
*
**/

UINT32 crbuff_once_read_len(const CRBUFF *crbuff)
{
    UINT32 total_read_len;
    UINT32 to_tail_len;

    total_read_len = CRBUFF_WRITE_POS(crbuff) - CRBUFF_READ_POS(crbuff);
    to_tail_len    = CRBUFF_MAX_LEN(crbuff) - (CRBUFF_READ_POS(crbuff) % CRBUFF_MAX_LEN(crbuff));

    if(total_read_len >= to_tail_len)
    {
        return (to_tail_len);
    }
    return (total_read_len);
}

EC_BOOL crbuff_pos_reduce(CRBUFF *crbuff)
{
    /*reduce same pace if necessary*/
    if(CRBUFF_READ_POS(crbuff) >= CRBUFF_MAX_LEN(crbuff) && CRBUFF_WRITE_POS(crbuff) >= CRBUFF_MAX_LEN(crbuff))
    {
        CRBUFF_READ_POS(crbuff)  -= CRBUFF_MAX_LEN(crbuff);
        CRBUFF_WRITE_POS(crbuff) -= CRBUFF_MAX_LEN(crbuff);
    }
    return (EC_TRUE);
}

#if (CRBUFF_COPY_MODE == CRBUFF_SLOW_COPY_MODE)
EC_BOOL crbuff_read(CRBUFF *crbuff, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *out_buff_pos)
{
    UINT32 pos;

    pos = (*out_buff_pos);

    /*when CRBUFF_READ_POS = CRBUFF_WRITE_POS, CRBUFF is empty, no data to read*/
    for(; pos < out_buff_max_len &&  CRBUFF_READ_POS(crbuff) < CRBUFF_WRITE_POS(crbuff); pos ++, CRBUFF_READ_POS(crbuff) ++)
    {
        out_buff[ pos ] = CRBUFF_CACHE_CHAR(crbuff, CRBUFF_READ_POS(crbuff) % CRBUFF_MAX_LEN(crbuff));
    }

    /*reduce same pace if necessary*/
    if(CRBUFF_READ_POS(crbuff) >= CRBUFF_MAX_LEN(crbuff) && CRBUFF_WRITE_POS(crbuff) >= CRBUFF_MAX_LEN(crbuff))
    {
        CRBUFF_READ_POS(crbuff)  -= CRBUFF_MAX_LEN(crbuff);
        CRBUFF_WRITE_POS(crbuff) -= CRBUFF_MAX_LEN(crbuff);
    }

    (*out_buff_pos) = pos;
    return (EC_TRUE);
}
#endif/*(CRBUFF_COPY_MODE == CRBUFF_SLOW_COPY_MODE)*/
#if (CRBUFF_COPY_MODE == CRBUFF_FAST_COPY_MODE)
EC_BOOL crbuff_read(CRBUFF *crbuff, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *out_buff_pos)
{
    UINT32 read_pos;
    UINT32 write_pos;
    UINT32 last_pos;
    UINT32 once_read_len;
    UINT32 pos;

    read_pos  = CRBUFF_READ_POS(crbuff);
    write_pos = CRBUFF_WRITE_POS(crbuff);

    if(read_pos + out_buff_max_len - (*out_buff_pos) >= write_pos)
    {
        last_pos = write_pos;
    }
    else
    {
        last_pos = read_pos + out_buff_max_len - (*out_buff_pos);
    }

    pos = (*out_buff_pos);

    /*read_pos <= last_pos <= max*/
    if(last_pos <= CRBUFF_MAX_LEN(crbuff))
    {
        once_read_len = last_pos - read_pos;
        CRBUFF_DEBUG_AND_ASSERT(crbuff,"crbuff_read", read_pos, once_read_len, CRBUFF_MAX_LEN(crbuff));
        crbuff_copy(CRBUFF_CACHE(crbuff) + read_pos, out_buff + pos, once_read_len);
        pos += once_read_len;
    }
    /*max <= read_pos <= last_pos*/
    else if(read_pos >= CRBUFF_MAX_LEN(crbuff))
    {
        once_read_len = last_pos - read_pos;
        CRBUFF_DEBUG_AND_ASSERT(crbuff,"crbuff_read", read_pos - CRBUFF_MAX_LEN(crbuff), once_read_len, CRBUFF_MAX_LEN(crbuff));
        crbuff_copy(CRBUFF_CACHE(crbuff) + read_pos - CRBUFF_MAX_LEN(crbuff), out_buff + pos, once_read_len);
        pos += once_read_len;
    }
    /*read_pos < max < last_pos*/
    else
    {
        once_read_len = CRBUFF_MAX_LEN(crbuff) - read_pos;
        CRBUFF_DEBUG_AND_ASSERT(crbuff,"crbuff_read", read_pos, once_read_len, CRBUFF_MAX_LEN(crbuff));
        crbuff_copy(CRBUFF_CACHE(crbuff) + read_pos, out_buff + pos, once_read_len);
        pos += once_read_len;

        once_read_len = last_pos - CRBUFF_MAX_LEN(crbuff);
        crbuff_copy(CRBUFF_CACHE(crbuff), out_buff + pos, once_read_len);
        pos += once_read_len;
    }

    /*reduce same pace if necessary*/
    CRBUFF_READ_POS(crbuff) += (pos - (*out_buff_pos));
    if(CRBUFF_READ_POS(crbuff) >= CRBUFF_MAX_LEN(crbuff) && CRBUFF_WRITE_POS(crbuff) >= CRBUFF_MAX_LEN(crbuff))
    {
        CRBUFF_READ_POS(crbuff)  -= CRBUFF_MAX_LEN(crbuff);
        CRBUFF_WRITE_POS(crbuff) -= CRBUFF_MAX_LEN(crbuff);
    }

    (*out_buff_pos) = pos;
    return (EC_TRUE);
}
#endif/*(CRBUFF_COPY_MODE == CRBUFF_FAST_COPY_MODE)*/

#if (CRBUFF_COPY_MODE == CRBUFF_SLOW_COPY_MODE)
EC_BOOL crbuff_write(CRBUFF *crbuff, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *in_buff_pos)
{
    UINT32 pos;
    UINT32 last;

    if(0 == CRBUFF_MAX_LEN(crbuff))
    {
        dbg_log(SEC_0033_CRBUFF, 0)(LOGSTDOUT, "error:crbuff_write: crbuff %lx is empty\n", crbuff);
        return (EC_FALSE);
    }

    pos  = (*in_buff_pos);
    last = CRBUFF_READ_POS(crbuff) + CRBUFF_MAX_LEN(crbuff);

    for(; pos < in_buff_max_len && CRBUFF_WRITE_POS(crbuff) < last; pos ++, CRBUFF_WRITE_POS(crbuff) ++)
    {
        CRBUFF_CACHE_CHAR(crbuff, CRBUFF_WRITE_POS(crbuff) % CRBUFF_MAX_LEN(crbuff)) = in_buff[ pos ];
    }

    /*reduce same pace if necessary*/
    if(CRBUFF_READ_POS(crbuff) >= CRBUFF_MAX_LEN(crbuff) && CRBUFF_WRITE_POS(crbuff) >= CRBUFF_MAX_LEN(crbuff))
    {
        CRBUFF_READ_POS(crbuff)  -= CRBUFF_MAX_LEN(crbuff);
        CRBUFF_WRITE_POS(crbuff) -= CRBUFF_MAX_LEN(crbuff);
    }

    (*in_buff_pos) = pos;
    return (EC_TRUE);
}
#endif/*(CRBUFF_COPY_MODE == CRBUFF_SLOW_COPY_MODE)*/

#if (CRBUFF_COPY_MODE == CRBUFF_FAST_COPY_MODE)
EC_BOOL crbuff_write(CRBUFF *crbuff, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *in_buff_pos)
{
    UINT32 read_pos;
    UINT32 write_pos;
    UINT32 last_pos;
    UINT32 once_write_len;

    UINT32 pos;

    if(0 == CRBUFF_MAX_LEN(crbuff))
    {
        dbg_log(SEC_0033_CRBUFF, 0)(LOGSTDOUT, "error:crbuff_write: crbuff %lx is empty\n", crbuff);
        return (EC_FALSE);
    }

    read_pos  = CRBUFF_READ_POS(crbuff);
    write_pos = CRBUFF_WRITE_POS(crbuff);

    if(read_pos + CRBUFF_MAX_LEN(crbuff) >= write_pos + in_buff_max_len - (*in_buff_pos))
    {
        last_pos = write_pos + in_buff_max_len - (*in_buff_pos);
    }
    else
    {
        last_pos = read_pos + CRBUFF_MAX_LEN(crbuff);
    }

    pos = (*in_buff_pos);

    /*write_pos <= last_pos <= max*/
    if(last_pos <= CRBUFF_MAX_LEN(crbuff))
    {
        once_write_len = last_pos - write_pos;
        CRBUFF_DEBUG_AND_ASSERT(crbuff,"crbuff_write", write_pos, once_write_len, CRBUFF_MAX_LEN(crbuff));
        crbuff_copy(in_buff + pos, CRBUFF_CACHE(crbuff) + write_pos, once_write_len);
        pos += once_write_len;
    }
    /*max <= write_pos <= last_pos*/
    else if(write_pos >= CRBUFF_MAX_LEN(crbuff))
    {
        once_write_len = last_pos - write_pos;
        CRBUFF_DEBUG_AND_ASSERT(crbuff,"crbuff_write", write_pos - CRBUFF_MAX_LEN(crbuff), once_write_len, CRBUFF_MAX_LEN(crbuff));
        crbuff_copy(in_buff + pos, CRBUFF_CACHE(crbuff) + write_pos - CRBUFF_MAX_LEN(crbuff), once_write_len);
        pos += once_write_len;
    }
    /*write_pos < max < last_pos*/
    else
    {
        once_write_len = CRBUFF_MAX_LEN(crbuff) - write_pos;
        CRBUFF_DEBUG_AND_ASSERT(crbuff,"crbuff_write", write_pos, once_write_len, CRBUFF_MAX_LEN(crbuff));
        crbuff_copy(in_buff + pos, CRBUFF_CACHE(crbuff) + write_pos, once_write_len);
        pos += once_write_len;

        once_write_len = last_pos - CRBUFF_MAX_LEN(crbuff);
        CRBUFF_DEBUG_AND_ASSERT(crbuff,"crbuff_write", 0, once_write_len, CRBUFF_MAX_LEN(crbuff));
        crbuff_copy(in_buff + pos, CRBUFF_CACHE(crbuff), once_write_len);
        pos += once_write_len;
    }

    /*reduce same pace if necessary*/
    CRBUFF_WRITE_POS(crbuff) += (pos - (*in_buff_pos));

    if(CRBUFF_READ_POS(crbuff) >= CRBUFF_MAX_LEN(crbuff) && CRBUFF_WRITE_POS(crbuff) >= CRBUFF_MAX_LEN(crbuff))
    {
        CRBUFF_READ_POS(crbuff)  -= CRBUFF_MAX_LEN(crbuff);
        CRBUFF_WRITE_POS(crbuff) -= CRBUFF_MAX_LEN(crbuff);
    }

    (*in_buff_pos) = pos;
    return (EC_TRUE);
}
#endif/*(CRBUFF_COPY_MODE == CRBUFF_FAST_COPY_MODE)*/

/*shift out */
EC_BOOL crbuff_shift(CRBUFF *crbuff, const UINT32 max_shift_data_num, UINT32 *shift_out_data_num)
{
    if(CRBUFF_READ_POS(crbuff) + max_shift_data_num < CRBUFF_WRITE_POS(crbuff))
    {
        (*shift_out_data_num) = max_shift_data_num;
        CRBUFF_READ_POS(crbuff) += max_shift_data_num;
    }
    else
    {
        (*shift_out_data_num) = CRBUFF_WRITE_POS(crbuff) - CRBUFF_READ_POS(crbuff);
        CRBUFF_READ_POS(crbuff) = CRBUFF_WRITE_POS(crbuff);
    }

    /*reduce same pace if necessary*/
    if(CRBUFF_READ_POS(crbuff) >= CRBUFF_MAX_LEN(crbuff) && CRBUFF_WRITE_POS(crbuff) >= CRBUFF_MAX_LEN(crbuff))
    {
        CRBUFF_READ_POS(crbuff)  -= CRBUFF_MAX_LEN(crbuff);
        CRBUFF_WRITE_POS(crbuff) -= CRBUFF_MAX_LEN(crbuff);
    }

    return (EC_TRUE);
}

EC_BOOL crbuff_is_full(const CRBUFF *crbuff)
{
    if(CRBUFF_READ_POS(crbuff) == CRBUFF_WRITE_POS(crbuff))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL crbuff_socket_recv(CRBUFF *crbuff, int sockfd)
{
    UINT32 once_write_len;
    ssize_t  recved_num;

    for(;;)
    {
        once_write_len = crbuff_once_write_len(crbuff);
        if(0 == once_write_len)/*no free space to recv*/
        {
            break;
        }

        once_write_len = DMIN(CSOCKET_RECV_ONCE_MAX_SIZE, once_write_len);

        recved_num = recv(sockfd, (void *)(CRBUFF_CACHE(crbuff) + (CRBUFF_WRITE_POS(crbuff) % CRBUFF_MAX_LEN(crbuff))), once_write_len, 0);
        if(0 > recved_num)
        {
            /*no data to recv or found error*/
            return csocket_no_ierror(sockfd);
        }

        if(0 == recved_num)
        {
            return (EC_TRUE);
        }

        CRBUFF_WRITE_POS(crbuff) += (UINT32)recved_num;
        crbuff_pos_reduce(crbuff);
    }

    return (EC_TRUE);
}

#if (CRBUFF_COPY_MODE == CRBUFF_SLOW_COPY_MODE)
EC_BOOL crbuff_probe(const CRBUFF *crbuff, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *out_buff_pos)
{
    UINT32 src_pos;
    UINT32 des_pos;

    src_pos = CRBUFF_READ_POS(crbuff);
    des_pos = (*out_buff_pos);

    /*when CRBUFF_READ_POS = CRBUFF_WRITE_POS, CRBUFF is empty, no data to read*/
    for(; des_pos < out_buff_max_len &&  src_pos < CRBUFF_WRITE_POS(crbuff); src_pos ++, des_pos ++)
    {
        out_buff[ des_pos ] = CRBUFF_CACHE_CHAR(crbuff, src_pos % CRBUFF_MAX_LEN(crbuff));
    }

    (*out_buff_pos) = des_pos;
    return (EC_TRUE);
}
#endif/*(CRBUFF_COPY_MODE == CRBUFF_SLOW_COPY_MODE)*/

#if (CRBUFF_COPY_MODE == CRBUFF_FAST_COPY_MODE)
EC_BOOL crbuff_probe(const CRBUFF *crbuff, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *out_buff_pos)
{
    UINT32 read_pos;
    UINT32 write_pos;
    UINT32 last_pos;
    UINT32 once_read_len;
    UINT32 pos;

    read_pos  = CRBUFF_READ_POS(crbuff);
    write_pos = CRBUFF_WRITE_POS(crbuff);

    if(read_pos + out_buff_max_len - (*out_buff_pos) >= write_pos)
    {
        last_pos = write_pos;
    }
    else
    {
        last_pos = read_pos + out_buff_max_len - (*out_buff_pos);
    }

    pos = (*out_buff_pos);

    /*read_pos <= last_pos <= max*/
    if(last_pos <= CRBUFF_MAX_LEN(crbuff))
    {
        once_read_len = last_pos - read_pos;
        //dbg_log(SEC_0033_CRBUFF, 9)(LOGSTDOUT, "[DEBUG] crbuff_probe[1]: copy from crbuff pos %ld to out_buff pos %ld with len %ld\n", read_pos, pos, once_read_len);
        CRBUFF_DEBUG_AND_ASSERT(crbuff,"crbuff_probe", read_pos, once_read_len, CRBUFF_MAX_LEN(crbuff));
        crbuff_copy(CRBUFF_CACHE(crbuff) + read_pos, out_buff + pos, once_read_len);
        pos += once_read_len;
    }
    /*max <= read_pos <= last_pos*/
    else if(read_pos >= CRBUFF_MAX_LEN(crbuff))
    {
        once_read_len = last_pos - read_pos;
        //dbg_log(SEC_0033_CRBUFF, 9)(LOGSTDOUT, "[DEBUG] crbuff_probe[2]: copy from crbuff pos %ld to out_buff pos %ld with len %ld\n", read_pos - CRBUFF_MAX_LEN(crbuff), pos, once_read_len);
        CRBUFF_DEBUG_AND_ASSERT(crbuff,"crbuff_probe", read_pos - CRBUFF_MAX_LEN(crbuff), once_read_len, CRBUFF_MAX_LEN(crbuff));
        crbuff_copy(CRBUFF_CACHE(crbuff) + read_pos - CRBUFF_MAX_LEN(crbuff), out_buff + pos, once_read_len);
        pos += once_read_len;
    }
    /*read_pos < max < last_pos*/
    else
    {
        once_read_len = CRBUFF_MAX_LEN(crbuff) - read_pos;
        //dbg_log(SEC_0033_CRBUFF, 9)(LOGSTDOUT, "[DEBUG] crbuff_probe[3]: copy from crbuff pos %ld to out_buff pos %ld with len %ld\n", read_pos, pos, once_read_len);
        CRBUFF_DEBUG_AND_ASSERT(crbuff,"crbuff_probe", read_pos, once_read_len, CRBUFF_MAX_LEN(crbuff));
        crbuff_copy(CRBUFF_CACHE(crbuff) + read_pos, out_buff + pos, once_read_len);
        pos += once_read_len;

        once_read_len = last_pos - CRBUFF_MAX_LEN(crbuff);
        //dbg_log(SEC_0033_CRBUFF, 9)(LOGSTDOUT, "[DEBUG] crbuff_probe[4]: copy from crbuff pos %ld to out_buff pos %ld with len %ld\n", 0, pos, once_read_len);
        CRBUFF_DEBUG_AND_ASSERT(crbuff,"crbuff_probe", 0, once_read_len, CRBUFF_MAX_LEN(crbuff));
        crbuff_copy(CRBUFF_CACHE(crbuff), out_buff + pos, once_read_len);
        pos += once_read_len;
    }

    (*out_buff_pos) = pos;
    return (EC_TRUE);
}
#endif/*(CRBUFF_COPY_MODE == CRBUFF_FAST_COPY_MODE)*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

