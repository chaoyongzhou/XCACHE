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

#include <sys/socket.h>
#include <errno.h>

#include "type.h"

#include "log.h"
#include "mm.h"

#include "csocket.h"
#include "csbuff.h"

#define CSBUFF_PRINT_BLOCK_WIDETH      8
#define CSBUFF_PRINT_LINE_WIDETH      32

#define CSBUFF_ASSERT_POS(info, max_len, r_pos, w_pos) do{\
    if((r_pos) > (w_pos) || ((r_pos) >= (max_len) && (w_pos) >= (max_len))) {\
        dbg_log(SEC_0037_CSBUFF, 0)(LOGSTDOUT, "error:%s: max_len = %ld, r_pos = %ld, w_pos = %ld\n", (info), (max_len), (r_pos), (w_pos));\
    }\
}while(0)

EC_BOOL csbuff_init(CSBUFF *csbuff, const UINT32 cmutex_flag)
{
    CSBUFF_INIT_LOCK(csbuff, cmutex_flag, LOC_CSBUFF_0001);
    CSBUFF_WRITE_POS(csbuff) = 0;
    CSBUFF_READ_POS(csbuff)  = 0;
    return (EC_TRUE);
}

CSBUFF * csbuff_new(const UINT32 size, const UINT32 cmutex_flag)
{
    CSBUFF *csbuff;

    csbuff = (CSBUFF *)SAFE_MALLOC(sizeof(CSBUFF) + size, LOC_CSBUFF_0002);
    if(NULL_PTR == csbuff)
    {
        dbg_log(SEC_0037_CSBUFF, 0)(LOGSTDOUT, "error:csbuff_new: failed to alloc CSBUFF\n");
        return (NULL_PTR);
    }

    csbuff_set_max_len(csbuff, size);
    csbuff_init(csbuff, cmutex_flag);
    return (csbuff);
}

EC_BOOL csbuff_clean(CSBUFF *csbuff)
{
    CSBUFF_WRITE_POS(csbuff) = 0;
    CSBUFF_READ_POS(csbuff)  = 0;
    CSBUFF_CLEAN_LOCK(csbuff, LOC_CSBUFF_0003);
    return (EC_TRUE);
}

EC_BOOL csbuff_reset(CSBUFF *csbuff)
{
    CSBUFF_LOCK(csbuff, LOC_CSBUFF_0004);
    CSBUFF_WRITE_POS(csbuff) = 0;
    CSBUFF_READ_POS(csbuff)  = 0;
    CSBUFF_UNLOCK(csbuff, LOC_CSBUFF_0005);
    return (EC_TRUE);
}

EC_BOOL csbuff_free(CSBUFF *csbuff)
{
    if(NULL_PTR != csbuff)
    {
        csbuff_clean(csbuff);
        SAFE_FREE(csbuff, LOC_CSBUFF_0006);
    }
    return (EC_TRUE);
}

EC_BOOL csbuff_set_max_len(CSBUFF *csbuff, const UINT32 size)
{
    CSBUFF_MAX_LEN(csbuff) = size;
    return (EC_TRUE);
}

UINT32 csbuff_get_max_len(const CSBUFF *csbuff)
{
    return CSBUFF_MAX_LEN(csbuff);
}

STATIC_CAST static void csbuff_print_one_char_with_alignment(LOG *log, const UINT8 ch, const UINT32 count)
{
    sys_print(LOGSTDOUT, "%02x ", ch);
    //sys_print(LOGSTDOUT, "%c ", ch);
    if(0 == (count % CSBUFF_PRINT_BLOCK_WIDETH) && 0 != (count % CSBUFF_PRINT_LINE_WIDETH))
    {
        sys_print(log, "   ");
    }
    if(0 == (count % CSBUFF_PRINT_LINE_WIDETH))
    {
        sys_print(log, "\n");
    }
    return;
}

STATIC_CAST static void csbuff_print_end_with_alignment(LOG *log, const UINT32 count)
{
    if(0 != (count % CSBUFF_PRINT_LINE_WIDETH))
    {
        sys_print(log, "\n");
    }
    return;
}


STATIC_CAST static void csbuff_print_whole_cache(LOG *log, const CSBUFF *csbuff)
{
    UINT32 pos;
    UINT32 count;

    dbg_log(SEC_0037_CSBUFF, 5)(LOGSTDOUT, "csbuff %lx: whole cache: \n", csbuff);
    for(count = 1, pos = 0; pos < CSBUFF_MAX_LEN(csbuff); count ++, pos ++)
    {
        csbuff_print_one_char_with_alignment(log, CSBUFF_CACHE_CHAR(csbuff, pos), count);
    }
    csbuff_print_end_with_alignment(log, count);

    return;
}

STATIC_CAST static void csbuff_print_to_read_cache(LOG *log, const CSBUFF *csbuff)
{
    UINT32 total_read_len;
    UINT32 to_tail_len;

    total_read_len = CSBUFF_WRITE_POS(csbuff) - CSBUFF_READ_POS(csbuff);
    to_tail_len    = CSBUFF_MAX_LEN(csbuff) - (CSBUFF_READ_POS(csbuff) % CSBUFF_MAX_LEN(csbuff));

    dbg_log(SEC_0037_CSBUFF, 5)(LOGSTDOUT, "csbuff %lx: to read cache: \n", csbuff);
    if(total_read_len >= to_tail_len)
    {
        UINT32 pos;
        UINT32 last;
        UINT32 count;

        count = 1;
        pos  = (CSBUFF_READ_POS(csbuff) % CSBUFF_MAX_LEN(csbuff));
        last = (CSBUFF_WRITE_POS(csbuff) % CSBUFF_MAX_LEN(csbuff));

        /*to tail*/
        for(; pos < CSBUFF_MAX_LEN(csbuff); pos ++, count ++)
        {
            csbuff_print_one_char_with_alignment(log, CSBUFF_CACHE_CHAR(csbuff, pos), count);
        }

        for(pos = 0; pos < last; pos ++, count ++)
        {
            csbuff_print_one_char_with_alignment(log, CSBUFF_CACHE_CHAR(csbuff, pos), count);
        }
        csbuff_print_end_with_alignment(log, count);
    }
    else
    {
        UINT32 pos;
        UINT32 last;
        UINT32 count;

        count = 1;
        pos  = (CSBUFF_READ_POS(csbuff) % CSBUFF_MAX_LEN(csbuff));
        last = (CSBUFF_WRITE_POS(csbuff) % CSBUFF_MAX_LEN(csbuff));

        /*to tail*/
        for(; pos < last; pos ++, count ++)
        {
            csbuff_print_one_char_with_alignment(log, CSBUFF_CACHE_CHAR(csbuff, pos), count);
        }
        csbuff_print_end_with_alignment(log, count);
    }
    return;
}
void csbuff_print(LOG *log, CSBUFF *csbuff)
{
    dbg_log(SEC_0037_CSBUFF, 5)(LOGSTDOUT, "csbuff %lx: max_len = %ld, read_pos = %ld, write_pos = %ld\n",
                    csbuff, CSBUFF_MAX_LEN(csbuff), CSBUFF_READ_POS(csbuff), CSBUFF_WRITE_POS(csbuff));

    if( 0 == CSBUFF_MAX_LEN(csbuff))
    {
        dbg_log(SEC_0037_CSBUFF, 5)(LOGSTDOUT, "csbuff %lx: whole cache: (null)\n"      , csbuff);
        dbg_log(SEC_0037_CSBUFF, 5)(LOGSTDOUT, "csbuff %lx: to read cache: (null)\n"    , csbuff);
        return;
    }

    //csbuff_print_whole_cache(log, csbuff);
    csbuff_print_to_read_cache(log, csbuff);

    dbg_log(SEC_0037_CSBUFF, 5)(LOGSTDOUT, "max len        : %ld\n", CSBUFF_MAX_LEN(csbuff));
    dbg_log(SEC_0037_CSBUFF, 5)(LOGSTDOUT, "total write len: %ld\n", csbuff_total_write_len(csbuff));
    dbg_log(SEC_0037_CSBUFF, 5)(LOGSTDOUT, "total read  len: %ld\n", csbuff_total_read_len(csbuff));
    dbg_log(SEC_0037_CSBUFF, 5)(LOGSTDOUT, "once  write len: %ld\n", csbuff_once_write_len(csbuff));
    dbg_log(SEC_0037_CSBUFF, 5)(LOGSTDOUT, "once  read  len: %ld\n", csbuff_once_read_len(csbuff));
    return;
}

UINT32 csbuff_total_write_len(CSBUFF *csbuff)
{
    UINT32 total_write_len;
    CSBUFF_LOCK(csbuff, LOC_CSBUFF_0007);
    total_write_len = (CSBUFF_MAX_LEN(csbuff) - (CSBUFF_WRITE_POS(csbuff) - CSBUFF_READ_POS(csbuff)));
    CSBUFF_UNLOCK(csbuff, LOC_CSBUFF_0008);
    return (total_write_len);
}

UINT32 csbuff_total_read_len(CSBUFF *csbuff)
{
    UINT32 total_read_len;
    CSBUFF_LOCK(csbuff, LOC_CSBUFF_0009);
    total_read_len = (CSBUFF_WRITE_POS(csbuff) - CSBUFF_READ_POS(csbuff));
    CSBUFF_UNLOCK(csbuff, LOC_CSBUFF_0010);

    return (total_read_len);
}

UINT32 csbuff_once_write_len(CSBUFF *csbuff)
{
    UINT32 total_write_len;
    UINT32 to_tail_len;

    CSBUFF_LOCK(csbuff, LOC_CSBUFF_0011);
    total_write_len = CSBUFF_MAX_LEN(csbuff) - (CSBUFF_WRITE_POS(csbuff) - CSBUFF_READ_POS(csbuff));
    to_tail_len     = CSBUFF_MAX_LEN(csbuff) - (CSBUFF_WRITE_POS(csbuff) % CSBUFF_MAX_LEN(csbuff));
    CSBUFF_UNLOCK(csbuff, LOC_CSBUFF_0012);

    if(total_write_len >= to_tail_len)
    {
        return (to_tail_len);
    }
    return (total_write_len);
}

UINT32 csbuff_once_read_len(CSBUFF *csbuff)
{
    UINT32 total_read_len;
    UINT32 to_tail_len;

    CSBUFF_LOCK(csbuff, LOC_CSBUFF_0013);
    total_read_len = CSBUFF_WRITE_POS(csbuff) - CSBUFF_READ_POS(csbuff);
    to_tail_len    = CSBUFF_MAX_LEN(csbuff) - (CSBUFF_READ_POS(csbuff) % CSBUFF_MAX_LEN(csbuff));
    CSBUFF_UNLOCK(csbuff, LOC_CSBUFF_0014);

    if(total_read_len >= to_tail_len)
    {
        return (to_tail_len);
    }
    return (total_read_len);
}

EC_BOOL csbuff_pos_reduce(CSBUFF *csbuff)
{
    CSBUFF_LOCK(csbuff, LOC_CSBUFF_0015);
    /*reduce same pace if necessary*/
    if(CSBUFF_READ_POS(csbuff) >= CSBUFF_MAX_LEN(csbuff) && CSBUFF_WRITE_POS(csbuff) >= CSBUFF_MAX_LEN(csbuff))
    {
        CSBUFF_READ_POS(csbuff)  -= CSBUFF_MAX_LEN(csbuff);
        CSBUFF_WRITE_POS(csbuff) -= CSBUFF_MAX_LEN(csbuff);
    }
    CSBUFF_UNLOCK(csbuff, LOC_CSBUFF_0016);

    return (EC_TRUE);
}

EC_BOOL csbuff_read(CSBUFF *csbuff, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *out_buff_pos)
{
    UINT32 read_pos;
    UINT32 write_pos;
    UINT32 last_pos;
    UINT32 once_read_len;
    UINT32 pos;

    CSBUFF_LOCK(csbuff, LOC_CSBUFF_0017);
    read_pos  = CSBUFF_READ_POS(csbuff);
    write_pos = CSBUFF_WRITE_POS(csbuff);
#if 0
    dbg_log(SEC_0037_CSBUFF, 9)(LOGSTDOUT, "[DEBUG]csbuff_read %lx: beg: max_len = %ld, read_pos %ld, write_pos %ld, start pos %ld, out_buff_max_len %ld\n",
                        csbuff, CSBUFF_MAX_LEN(csbuff), CSBUFF_READ_POS(csbuff), CSBUFF_WRITE_POS(csbuff), (*out_buff_pos), out_buff_max_len);
    CSBUFF_ASSERT_POS("csbuff_read beg", CSBUFF_MAX_LEN(csbuff), CSBUFF_READ_POS(csbuff), CSBUFF_WRITE_POS(csbuff));
#endif
    CSBUFF_UNLOCK(csbuff, LOC_CSBUFF_0018);

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
    if(last_pos <= CSBUFF_MAX_LEN(csbuff))
    {
        once_read_len = last_pos - read_pos;
        BCOPY(CSBUFF_CACHE(csbuff) + read_pos, out_buff + pos, once_read_len);
        pos += once_read_len;
    }
    /*max <= read_pos <= last_pos*/
    else if(read_pos >= CSBUFF_MAX_LEN(csbuff))
    {
        once_read_len = last_pos - read_pos;
        BCOPY(CSBUFF_CACHE(csbuff) + read_pos - CSBUFF_MAX_LEN(csbuff), out_buff + pos, once_read_len);
        pos += once_read_len;
    }
    /*read_pos < max < last_pos*/
    else
    {
        once_read_len = CSBUFF_MAX_LEN(csbuff) - read_pos;
        BCOPY(CSBUFF_CACHE(csbuff) + read_pos, out_buff + pos, once_read_len);
        pos += once_read_len;

        once_read_len = last_pos - CSBUFF_MAX_LEN(csbuff);
        BCOPY(CSBUFF_CACHE(csbuff), out_buff + pos, once_read_len);
        pos += once_read_len;
    }

    /*when CSBUFF_READ_POS = CSBUFF_WRITE_POS, CSBUFF is empty, no data to read*/
/*
    for(; pos < out_buff_max_len && read_pos < write_pos; pos ++, read_pos ++)
    {
        out_buff[ pos ] = CSBUFF_CACHE_CHAR(csbuff, read_pos % CSBUFF_MAX_LEN(csbuff));
    }
*/
    /*reduce same pace if necessary*/
    CSBUFF_LOCK(csbuff, LOC_CSBUFF_0019);
    /*here cannot set CSBUFF_READ_POS = pos due to other writer may had already changed CSBUFF_READ_POS*/
    CSBUFF_READ_POS(csbuff) += (pos - (*out_buff_pos));
    if(CSBUFF_READ_POS(csbuff) >= CSBUFF_MAX_LEN(csbuff) && CSBUFF_WRITE_POS(csbuff) >= CSBUFF_MAX_LEN(csbuff))
    {
        CSBUFF_READ_POS(csbuff)  -= CSBUFF_MAX_LEN(csbuff);
        CSBUFF_WRITE_POS(csbuff) -= CSBUFF_MAX_LEN(csbuff);
    }
#if 0
    dbg_log(SEC_0037_CSBUFF, 9)(LOGSTDOUT, "[DEBUG]csbuff_read %lx: end: max_len = %ld, read_pos %ld, write_pos %ld, read len %ld, reach pos %ld, out_buff_max_len %ld\n",
                        csbuff, CSBUFF_MAX_LEN(csbuff), CSBUFF_READ_POS(csbuff), CSBUFF_WRITE_POS(csbuff), (pos - (*out_buff_pos)), pos, out_buff_max_len);
    CSBUFF_ASSERT_POS("csbuff_read end", CSBUFF_MAX_LEN(csbuff), CSBUFF_READ_POS(csbuff), CSBUFF_WRITE_POS(csbuff));
#endif
    CSBUFF_UNLOCK(csbuff, LOC_CSBUFF_0020);

    (*out_buff_pos) = pos;
    return (EC_TRUE);
}

EC_BOOL csbuff_write(CSBUFF *csbuff, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *in_buff_pos)
{
    UINT32 read_pos;
    UINT32 write_pos;
    UINT32 last_pos;
    UINT32 once_write_len;

    UINT32 pos;

    if(0 == CSBUFF_MAX_LEN(csbuff))
    {
        dbg_log(SEC_0037_CSBUFF, 0)(LOGSTDOUT, "error:csbuff_write: csbuff %lx is empty\n", csbuff);
        return (EC_FALSE);
    }

    CSBUFF_LOCK(csbuff, LOC_CSBUFF_0021);
    read_pos  = CSBUFF_READ_POS(csbuff);
    write_pos = CSBUFF_WRITE_POS(csbuff);
#if 0
    dbg_log(SEC_0037_CSBUFF, 9)(LOGSTDOUT, "[DEBUG]csbuff_write %lx: beg: max_len = %ld, read_pos %ld, write_pos %ld, start pos %ld, out_buff_max_len %ld\n",
                        csbuff, CSBUFF_MAX_LEN(csbuff), CSBUFF_READ_POS(csbuff), CSBUFF_WRITE_POS(csbuff), (*in_buff_pos), in_buff_max_len);
    CSBUFF_ASSERT_POS("csbuff_write beg", CSBUFF_MAX_LEN(csbuff), CSBUFF_READ_POS(csbuff), CSBUFF_WRITE_POS(csbuff));
#endif
    CSBUFF_UNLOCK(csbuff, LOC_CSBUFF_0022);

    if(read_pos + CSBUFF_MAX_LEN(csbuff) >= write_pos + in_buff_max_len - (*in_buff_pos))
    {
        last_pos = write_pos + in_buff_max_len - (*in_buff_pos);
    }
    else
    {
        last_pos = read_pos + CSBUFF_MAX_LEN(csbuff);
    }

    pos = (*in_buff_pos);

    /*write_pos <= last_pos <= max*/
    if(last_pos <= CSBUFF_MAX_LEN(csbuff))
    {
        once_write_len = last_pos - write_pos;
        BCOPY(in_buff + pos, CSBUFF_CACHE(csbuff) + write_pos, once_write_len);
        pos += once_write_len;
    }
    /*max <= write_pos <= last_pos*/
    else if(write_pos >= CSBUFF_MAX_LEN(csbuff))
    {
        once_write_len = last_pos - write_pos;
        BCOPY(in_buff + pos, CSBUFF_CACHE(csbuff) + write_pos - CSBUFF_MAX_LEN(csbuff), once_write_len);
        pos += once_write_len;
    }
    /*write_pos < max < last_pos*/
    else
    {
        once_write_len = CSBUFF_MAX_LEN(csbuff) - write_pos;
        BCOPY(in_buff + pos, CSBUFF_CACHE(csbuff) + write_pos, once_write_len);
        pos += once_write_len;

        once_write_len = last_pos - CSBUFF_MAX_LEN(csbuff);
        BCOPY(in_buff + pos, CSBUFF_CACHE(csbuff), once_write_len);
        pos += once_write_len;
    }

/*
    for(; pos < in_buff_max_len && write_pos < last_pos; pos ++, write_pos ++)
    {
        CSBUFF_CACHE_CHAR(csbuff, write_pos % CSBUFF_MAX_LEN(csbuff)) = in_buff[ pos ];
    }
*/
    /*reduce same pace if necessary*/
    CSBUFF_LOCK(csbuff, LOC_CSBUFF_0023);
    /*here cannot set CSBUFF_WRITE_POS = pos due to other reader may had already changed CSBUFF_READ_POS*/
    CSBUFF_WRITE_POS(csbuff) += (pos - (*in_buff_pos));

    if(CSBUFF_READ_POS(csbuff) >= CSBUFF_MAX_LEN(csbuff) && CSBUFF_WRITE_POS(csbuff) >= CSBUFF_MAX_LEN(csbuff))
    {
        CSBUFF_READ_POS(csbuff)  -= CSBUFF_MAX_LEN(csbuff);
        CSBUFF_WRITE_POS(csbuff) -= CSBUFF_MAX_LEN(csbuff);
    }
#if 0
    dbg_log(SEC_0037_CSBUFF, 9)(LOGSTDOUT, "[DEBUG]csbuff_write %lx: end: max_len = %ld, read_pos %ld, write_pos %ld, read len %ld, reach pos %ld, out_buff_max_len %ld\n",
                        csbuff, CSBUFF_MAX_LEN(csbuff), CSBUFF_READ_POS(csbuff), CSBUFF_WRITE_POS(csbuff), (pos - (*in_buff_pos)), pos, in_buff_max_len);
    CSBUFF_ASSERT_POS("csbuff_write end", CSBUFF_MAX_LEN(csbuff), CSBUFF_READ_POS(csbuff), CSBUFF_WRITE_POS(csbuff));
#endif
    CSBUFF_UNLOCK(csbuff, LOC_CSBUFF_0024);

    (*in_buff_pos) = pos;
    return (EC_TRUE);
}

EC_BOOL csbuff_is_full(const CSBUFF *csbuff)
{
    if(CSBUFF_READ_POS(csbuff) == CSBUFF_WRITE_POS(csbuff))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL csbuff_probe(CSBUFF *csbuff, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *out_buff_pos)
{
    UINT32 read_pos;
    UINT32 write_pos;
    UINT32 last_pos;
    UINT32 once_read_len;
    UINT32 pos;

    CSBUFF_LOCK(csbuff, LOC_CSBUFF_0025);
    read_pos  = CSBUFF_READ_POS(csbuff);
    write_pos = CSBUFF_WRITE_POS(csbuff);
    dbg_log(SEC_0037_CSBUFF, 9)(LOGSTDNULL, "[DEBUG]csbuff_probe %lx: beg: max_len = %ld, read_pos %ld, write_pos %ld, start pos %ld, out_buff_max_len %ld\n",
                        csbuff, CSBUFF_MAX_LEN(csbuff), CSBUFF_READ_POS(csbuff), CSBUFF_WRITE_POS(csbuff), (*out_buff_pos), out_buff_max_len);
    CSBUFF_ASSERT_POS("csbuff_probe beg", CSBUFF_MAX_LEN(csbuff), CSBUFF_READ_POS(csbuff), CSBUFF_WRITE_POS(csbuff));
    CSBUFF_UNLOCK(csbuff, LOC_CSBUFF_0026);

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
    if(last_pos <= CSBUFF_MAX_LEN(csbuff))
    {
        once_read_len = last_pos - read_pos;
        BCOPY(CSBUFF_CACHE(csbuff) + read_pos, out_buff + pos, once_read_len);
        pos += once_read_len;
    }
    /*max <= read_pos <= last_pos*/
    else if(read_pos >= CSBUFF_MAX_LEN(csbuff))
    {
        once_read_len = last_pos - read_pos;
        BCOPY(CSBUFF_CACHE(csbuff) + read_pos - CSBUFF_MAX_LEN(csbuff), out_buff + pos, once_read_len);
        pos += once_read_len;
    }
    /*read_pos < max < last_pos*/
    else
    {
        once_read_len = CSBUFF_MAX_LEN(csbuff) - read_pos;
        BCOPY(CSBUFF_CACHE(csbuff) + read_pos, out_buff + pos, once_read_len);
        pos += once_read_len;

        once_read_len = last_pos - CSBUFF_MAX_LEN(csbuff);
        BCOPY(CSBUFF_CACHE(csbuff), out_buff + pos, once_read_len);
        pos += once_read_len;
    }
#if 0
    /*when CSBUFF_READ_POS = CSBUFF_WRITE_POS, CSBUFF is empty, no data to read*/
    for(; pos < out_buff_max_len &&  read_pos < write_pos; pos ++, read_pos ++)
    {
        out_buff[ pos ] = CSBUFF_CACHE_CHAR(csbuff, read_pos % CSBUFF_MAX_LEN(csbuff));
    }
#endif
    dbg_log(SEC_0037_CSBUFF, 9)(LOGSTDNULL, "[DEBUG]csbuff_probe %lx: end: max_len = %ld, read_pos %ld, write_pos %ld, probe len %ld, reach pos %ld, out_buff_max_len %ld\n",
                        csbuff, CSBUFF_MAX_LEN(csbuff), CSBUFF_READ_POS(csbuff), CSBUFF_WRITE_POS(csbuff), (pos - (*out_buff_pos)), pos, out_buff_max_len);
    CSBUFF_ASSERT_POS("csbuff_probe end", CSBUFF_MAX_LEN(csbuff), CSBUFF_READ_POS(csbuff), CSBUFF_WRITE_POS(csbuff));
    (*out_buff_pos) = pos;
    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

