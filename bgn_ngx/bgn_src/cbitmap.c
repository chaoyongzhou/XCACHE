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

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "type.h"
#include "mm.h"
#include "log.h"
#include "cmisc.h"

#include "cmpic.inc"

#include "cbitmap.h"
#include "cdfs.h"

#include "db_internal.h"

CBITMAP *cbitmap_new(const UINT32 max_bits)
{
    CBITMAP *cbitmap;

    alloc_static_mem(MM_CBITMAP, &cbitmap, LOC_CBITMAP_0001);
    if(NULL_PTR != cbitmap)
    {
        UINT32   aligned_max_bits;
        aligned_max_bits = ((max_bits + WORDSIZE - 1) / WORDSIZE) * WORDSIZE;
        cbitmap_init(cbitmap, aligned_max_bits);
    }
    return (cbitmap);
}

EC_BOOL  cbitmap_init(CBITMAP *cbitmap, const UINT32 max_bits)
{
    UINT32 max_words;
    UINT32 max_bytes;

    max_words = (max_bits + WORDSIZE - 1) / WORDSIZE;
    max_bytes = max_words * sizeof(UINT32);
    CBITMAP_CACHE(cbitmap) = (UINT32 *)SAFE_MALLOC(max_bytes, LOC_CBITMAP_0002);
    if(NULL_PTR == CBITMAP_CACHE(cbitmap))
    {
        dbg_log(SEC_0089_CBITMAP, 0)(LOGSTDOUT, "error:cbitmap_init: alloc %ld bytes failed\n", max_bytes);
        CBITMAP_MAX_BITS(cbitmap) = 0;
        CBITMAP_CUR_BITS(cbitmap) = 0;
        return (EC_FALSE);
    }
    BSET(CBITMAP_CACHE(cbitmap), 0, max_bytes);

    CBITMAP_MAX_BYTES(cbitmap) = max_bytes;
    CBITMAP_MAX_BITS(cbitmap)  = max_bits;
    CBITMAP_CUR_BITS(cbitmap)  = 0;

    return (EC_TRUE);
}

EC_BOOL  cbitmap_clean(CBITMAP *cbitmap)
{
    if(NULL_PTR != cbitmap)
    {
        if(NULL_PTR != CBITMAP_CACHE(cbitmap))
        {
            SAFE_FREE(CBITMAP_CACHE(cbitmap), LOC_CBITMAP_0003);
            CBITMAP_CACHE(cbitmap) = NULL_PTR;
        }
        CBITMAP_MAX_BYTES(cbitmap) = 0;
        CBITMAP_MAX_BITS(cbitmap)  = 0;
        CBITMAP_CUR_BITS(cbitmap)  = 0;
    }
    return (EC_TRUE);
}

EC_BOOL  cbitmap_free(CBITMAP *cbitmap)
{
    if(NULL_PTR != cbitmap)
    {
        cbitmap_clean(cbitmap);
        free_static_mem(MM_CBITMAP, cbitmap, LOC_CBITMAP_0004);
    }
    return (EC_TRUE);
}

EC_BOOL  cbitmap_set(CBITMAP *cbitmap, const UINT32 bit_pos)
{
    UINT32 word_offset;
    UINT32 bit_offset;
    UINT32 e;

    if(bit_pos >= CBITMAP_MAX_BITS(cbitmap))
    {
        dbg_log(SEC_0089_CBITMAP, 0)(LOGSTDOUT, "error:cbitmap_set: bit pos %ld > max bits %ld\n",
                            bit_pos, CBITMAP_MAX_BITS(cbitmap));
        return (EC_FALSE);
    }

    word_offset = (bit_pos / WORDSIZE);
    bit_offset  = (bit_pos % WORDSIZE);
    e = ( UINT32_ONE << bit_offset );

    if(CBITMAP_WORD(cbitmap, word_offset) & e)
    {
        dbg_log(SEC_0089_CBITMAP, 0)(LOGSTDOUT, "error:cbitmap_set: bit pos %ld was already set\n", bit_pos);
        return (EC_FALSE);
    }

    CBITMAP_WORD(cbitmap, word_offset) |= e;
    CBITMAP_CUR_BITS(cbitmap) ++;
    return (EC_TRUE);
}

EC_BOOL  cbitmap_unset(CBITMAP *cbitmap, const UINT32 bit_pos)
{
    UINT32 word_offset;
    UINT32 bit_offset;
    UINT32 e;

    if(bit_pos >= CBITMAP_MAX_BITS(cbitmap))
    {
        dbg_log(SEC_0089_CBITMAP, 0)(LOGSTDOUT, "error:cbitmap_unset: bit pos %ld > max bits %ld\n",
                            bit_pos, CBITMAP_MAX_BITS(cbitmap));
        return (EC_FALSE);
    }

    word_offset = (bit_pos / WORDSIZE);
    bit_offset  = (bit_pos % WORDSIZE);

    e = ( UINT32_ONE << bit_offset );

    if(0 == (CBITMAP_WORD(cbitmap, word_offset) & e))
    {
        dbg_log(SEC_0089_CBITMAP, 0)(LOGSTDOUT, "error:cbitmap_unset: bit pos %ld was not set\n", bit_pos);
        return (EC_FALSE);
    }

    CBITMAP_WORD(cbitmap, word_offset) &= (~e);
    CBITMAP_CUR_BITS(cbitmap) --;
    return (EC_TRUE);
}

EC_BOOL  cbitmap_check(const CBITMAP *cbitmap, const UINT32 bit_pos)
{
    UINT32 word_offset;
    UINT32 bit_offset;
    UINT32 e;

    if(bit_pos >= CBITMAP_MAX_BITS(cbitmap))
    {
        dbg_log(SEC_0089_CBITMAP, 0)(LOGSTDOUT, "error:cbitmap_check: bit pos %ld > max bits %ld\n",
                            bit_pos, CBITMAP_MAX_BITS(cbitmap));
        return (EC_FALSE);
    }

    word_offset = (bit_pos / WORDSIZE);
    bit_offset  = (bit_pos % WORDSIZE);
    e = ( UINT32_ONE << bit_offset );

    if(CBITMAP_WORD(cbitmap, word_offset) & e)
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL  cbitmap_is_full(const CBITMAP *cbitmap)
{
    if(CBITMAP_CUR_BITS(cbitmap) >= CBITMAP_MAX_BITS(cbitmap))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL cbitmap_used_size(const CBITMAP *cbitmap)
{
    return CBITMAP_CUR_BITS(cbitmap);
}

EC_BOOL cbitmap_room_size(const CBITMAP *cbitmap)
{
    return (CBITMAP_MAX_BITS(cbitmap) - CBITMAP_CUR_BITS(cbitmap));
}

EC_BOOL  cbitmap_reserve(CBITMAP *cbitmap, UINT32 *bit_pos)
{
    UINT32 max_words;
    UINT32 beg_word_offset;
    UINT32 beg_bit_offset;
    UINT32 nth_word_offset;
    UINT32 nth_bit_offset;
    UINT32 word;

    if(EC_TRUE == cbitmap_is_full(cbitmap))
    {
        dbg_log(SEC_0089_CBITMAP, 0)(LOGSTDOUT, "error:cbitmap_reserve: bitmap is full\n");
        return (EC_FALSE);
    }

    max_words = (CBITMAP_MAX_BITS(cbitmap) + WORDSIZE - 1) / WORDSIZE;

    beg_word_offset = (CBITMAP_CUR_BITS(cbitmap) / WORDSIZE);
    beg_bit_offset  = (CBITMAP_CUR_BITS(cbitmap) % WORDSIZE);

    nth_word_offset = beg_word_offset;

    word = (CBITMAP_WORD(cbitmap, nth_word_offset) >> beg_bit_offset);
    for(nth_bit_offset = beg_bit_offset; nth_bit_offset < WORDSIZE && 1 == (word & 1); nth_bit_offset ++, word >>= 1)
    {
        /*do nothing*/
    }

    if(nth_bit_offset < WORDSIZE)  /*found one unused bit*/
    {
        (*bit_pos) = (nth_word_offset * WORDSIZE + nth_bit_offset);
        return cbitmap_set(cbitmap, (*bit_pos));
    }

    for(++nth_word_offset; nth_word_offset < max_words; nth_word_offset ++)
    {
        word = CBITMAP_WORD(cbitmap, nth_word_offset);
        for(nth_bit_offset = 0; nth_bit_offset < WORDSIZE && 1 == (word & 1); nth_bit_offset ++, word >>= 1)
        {
            /*do nothing*/
        }

        if(nth_bit_offset < WORDSIZE)  /*found one unused bit*/
        {
            (*bit_pos) = (nth_word_offset * WORDSIZE + nth_bit_offset);
            return cbitmap_set(cbitmap, (*bit_pos));
        }
    }

    for(nth_word_offset = 0; nth_word_offset < beg_word_offset; nth_word_offset ++)
    {
        word = CBITMAP_WORD(cbitmap, nth_word_offset);
        for(nth_bit_offset = 0; nth_bit_offset < WORDSIZE && 1 == (word & 1); nth_bit_offset ++, word >>= 1)
        {
            /*do nothing*/
        }

        if(nth_bit_offset < WORDSIZE)  /*found one unused bit*/
        {
            (*bit_pos) = (nth_word_offset * WORDSIZE + nth_bit_offset);
            return cbitmap_set(cbitmap, (*bit_pos));
        }
    }

    return (EC_FALSE);
}

EC_BOOL  cbitmap_release(CBITMAP *cbitmap, const UINT32 bit_pos)
{
    return cbitmap_unset(cbitmap, bit_pos);
}

EC_BOOL  cbitmap_fexist(const UINT8 *fname)
{
    if(0 == access((char *)fname, F_OK))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

CBITMAP *cbitmap_fcreate(const UINT32 max_bits, const UINT8 *fname)
{
    CBITMAP *cbitmap;
    int fd;

    cbitmap = cbitmap_new(max_bits);
    if(NULL_PTR == cbitmap)
    {
        dbg_log(SEC_0089_CBITMAP, 0)(LOGSTDOUT, "error:cbitmap_file_create: new cbitmap failed\n");
        return (NULL_PTR);
    }

    fd = c_file_open((char *)fname, O_RDWR | O_CREAT, 0666);
    if(-1 == fd)
    {
        dbg_log(SEC_0089_CBITMAP, 0)(LOGSTDOUT,"error:cbitmap_file_create: create %s failed\n", fname);
        cbitmap_free(cbitmap);
        return (NULL_PTR);
    }
    c_file_close(fd);
/*
    if(EC_FALSE == cbitmap_flush(cbitmap, fname))
    {
        dbg_log(SEC_0089_CBITMAP, 0)(LOGSTDOUT, "error:cbitmap_file_create:flush cbitmap failed\n");
        cbitmap_free(cbitmap);
        return (NULL_PTR);
    }
*/
    return (cbitmap);
}

EC_BOOL  cbitmap_flush(const CBITMAP *cbitmap, const UINT8 *fname)
{
    UINT32 max_words;
    UINT32 word_offset;
    UINT32 data;

    int fd;

    fd = c_file_open((char *)fname, O_RDWR, 0666);
    if(-1 == fd)
    {
        dbg_log(SEC_0089_CBITMAP, 0)(LOGSTDOUT,"error:cbitmap_flush: open %s failed\n", fname);
        return (EC_FALSE);
    }

    max_words = (CBITMAP_MAX_BITS(cbitmap) + WORDSIZE - 1) / WORDSIZE;

    data = hton_uint32(CBITMAP_MAX_BITS(cbitmap));
    write(fd, &data, sizeof(UINT32));

    data = hton_uint32(CBITMAP_CUR_BITS(cbitmap));
    write(fd, &data, sizeof(UINT32));

    for(word_offset = 0; word_offset < max_words; word_offset ++)
    {
        data = hton_uint32(CBITMAP_WORD(cbitmap, word_offset));
        write(fd, &data, sizeof(UINT32));
    }

    c_file_close(fd);
    return (EC_TRUE);
}

CBITMAP *cbitmap_fload(const UINT8 *fname)
{
    CBITMAP *cbitmap;
    UINT32 max_bits;
    UINT32 cur_bits;
    UINT32 max_words;
    UINT32 word_offset;
    UINT32 data;

    int fd;

    fd = c_file_open((char *)fname, O_RDWR, 0666);
    if(-1 == fd)
    {
        dbg_log(SEC_0089_CBITMAP, 0)(LOGSTDOUT,"error:cbitmap_fload: open %s failed\n", fname);
        return (NULL_PTR);
    }

    read(fd, &data, sizeof(UINT32));
    max_bits = ntoh_uint32(data);

    read(fd, &data, sizeof(UINT32));
    cur_bits = ntoh_uint32(data);

    cbitmap = cbitmap_new(max_bits);
    if(NULL_PTR == cbitmap)
    {
        dbg_log(SEC_0089_CBITMAP, 0)(LOGSTDOUT, "error:cbitmap_fload: new cbitmap with max bits %ld failed\n", max_bits);
        c_file_close(fd);
        return (NULL_PTR);
    }

    max_words = (max_bits + WORDSIZE - 1) / WORDSIZE;

    CBITMAP_MAX_BITS(cbitmap) = max_bits;
    CBITMAP_CUR_BITS(cbitmap) = cur_bits;
    for(word_offset = 0; word_offset < max_words; word_offset ++)
    {
        read(fd, &data, sizeof(UINT32));
        CBITMAP_WORD(cbitmap, word_offset) = ntoh_uint32(data);
    }

    c_file_close(fd);
    return (cbitmap);
}

EC_BOOL  cbitmap_dump(const CBITMAP *cbitmap, UINT8 **buf, UINT32 *len)
{
    UINT32 max_words;
    UINT32 word_offset;
    UINT8 *des;
    UINT32 data;

    max_words = (CBITMAP_MAX_BITS(cbitmap) + WORDSIZE - 1) / WORDSIZE;

    (*len) = sizeof(UINT32) + sizeof(UINT32) + max_words * sizeof(UINT32);
    (*buf) = (UINT8 *)SAFE_MALLOC((*len), LOC_CBITMAP_0005);
    if(NULL_PTR == (*buf))
    {
        dbg_log(SEC_0089_CBITMAP, 0)(LOGSTDOUT, "error:cbitmap_dump: alloc %ld bytes failed\n", (*len));
        return (EC_FALSE);
    }

    des = (*buf);

    data = hton_uint32(CBITMAP_MAX_BITS(cbitmap));
    BCOPY(&data, des, sizeof(UINT32));
    des += sizeof(UINT32);

    data = hton_uint32(CBITMAP_CUR_BITS(cbitmap));
    BCOPY(&data, des, sizeof(UINT32));
    des += sizeof(UINT32);

    for(word_offset = 0; word_offset < max_words; word_offset ++)
    {
        data = hton_uint32(CBITMAP_WORD(cbitmap, word_offset));
        BCOPY(&data, des, sizeof(UINT32));
        des += sizeof(UINT32);
    }

    return (EC_TRUE);
}

CBITMAP *cbitmap_load(const UINT8 *buf, const UINT32 len)
{
    CBITMAP *cbitmap;

    UINT32 max_bits;
    UINT32 cur_bits;
    UINT32 max_words;
    UINT32 word_offset;
    UINT32 data;
    UINT8 *src;

    if(2 * sizeof(UINT32) > len)
    {
        dbg_log(SEC_0089_CBITMAP, 0)(LOGSTDOUT, "error:cbitmap_load: buf len %ld is invalid\n", len);
        return (NULL_PTR);
    }

    src = (UINT8 *)buf;

    BCOPY(src, &data, sizeof(UINT32));
    max_bits = ntoh_uint32(data);
    src += sizeof(UINT32);

    BCOPY(src, &data, sizeof(UINT32));
    cur_bits = ntoh_uint32(data);
    src += sizeof(UINT32);

    max_words = (max_bits + WORDSIZE - 1) / WORDSIZE;
    if(len != (sizeof(UINT32) + sizeof(UINT32) + max_words * sizeof(UINT32)))
    {
        dbg_log(SEC_0089_CBITMAP, 0)(LOGSTDOUT, "error:cbitmap_load: mismatched buf len %ld to expected len %ld\n",
                           len, (sizeof(UINT32) + sizeof(UINT32) + max_words * sizeof(UINT32)));
        return (NULL_PTR);
    }

    cbitmap = cbitmap_new(max_bits);
    if(NULL_PTR == cbitmap)
    {
        dbg_log(SEC_0089_CBITMAP, 0)(LOGSTDOUT, "error:cbitmap_load: new cbitmap with max bits %ld failed\n", max_bits);
        return (NULL_PTR);
    }

    CBITMAP_MAX_BITS(cbitmap) = max_bits;
    CBITMAP_CUR_BITS(cbitmap) = cur_bits;
    for(word_offset = 0; word_offset < max_words; word_offset ++)
    {
        BCOPY(src, &data, sizeof(UINT32));
        CBITMAP_WORD(cbitmap, word_offset) = ntoh_uint32(data);
        src += sizeof(UINT32);
    }

    return (cbitmap);
}

void cbitmap_print(LOG *log, const CBITMAP *cbitmap)
{
    UINT32 max_words;
    UINT32 word_offset;

    dbg_log(SEC_0089_CBITMAP, 5)(LOGSTDOUT, "cbitmap %lx: max bits %ld, cur bits %ld\n",
                        cbitmap, CBITMAP_MAX_BITS(cbitmap), CBITMAP_CUR_BITS(cbitmap));

    max_words = (CBITMAP_MAX_BITS(cbitmap) + WORDSIZE - 1) / WORDSIZE;
    for(word_offset = 0; word_offset < max_words; word_offset ++)
    {
        UINT32 word;
        UINT32 bit_offset;

        word = CBITMAP_WORD(cbitmap, word_offset);
#if (32 == WORDSIZE)
        dbg_log(SEC_0089_CBITMAP, 5)(LOGSTDOUT, "word %8ld# [%08lx] ", word_offset, word);
#endif/*(32 == WORDSIZE)*/
#if (64 == WORDSIZE)
        dbg_log(SEC_0089_CBITMAP, 5)(LOGSTDOUT, "word %8ld# [%016lx] ", word_offset, word);
#endif/*(64 == WORDSIZE)*/

        for(bit_offset = 0; bit_offset < WORDSIZE; bit_offset ++, word >>= 1)
        {
            sys_print(LOGSTDOUT, "%ld ", word & 1);
        }
        sys_print(LOGSTDOUT, "\n");
    }
    return;
}

EC_BOOL  cbitmap_dfs_exist(const CSTRING *fname_cstr, const UINT32 cdfs_md_id)
{
    return cdfs_exists_npp(cdfs_md_id, fname_cstr);
}

CBITMAP *cbitmap_dfs_create(const UINT32 max_bits, const CSTRING *fname_cstr, const UINT32 cdfs_md_id, const UINT32 replica_num)
{
    CBITMAP *cbitmap;
    UINT32   size;

    cbitmap = cbitmap_new(max_bits);
    if(NULL_PTR == cbitmap)
    {
        dbg_log(SEC_0089_CBITMAP, 0)(LOGSTDOUT, "error:cbitmap_dfs_create: new cbitmap failed\n");
        return (NULL_PTR);
    }

    size = sizeof(UINT32) + sizeof(UINT32) + CBITMAP_MAX_BYTES(cbitmap);

    if(EC_FALSE == cdfs_truncate(cdfs_md_id, fname_cstr, size, replica_num))
    {
        dbg_log(SEC_0089_CBITMAP, 0)(LOGSTDOUT, "error:cbitmap_dfs_create: truncate %s with %ld bytes and %ld replicas failed\n",
                            (char *)cstring_get_str(fname_cstr), size, replica_num);
        cbitmap_free(cbitmap);
        return (NULL_PTR);
    }
    return (cbitmap);
}

EC_BOOL  cbitmap_dfs_flush(const CBITMAP *cbitmap, const CSTRING *fname_cstr, const UINT32 cdfs_md_id)
{
    CBYTES     *cbytes;
    UINT32     len;

    UINT32 max_words;
    UINT32 word_offset;

    uint8_t   *buff;
    uint32_t   counter;

    len = sizeof(UINT32) + sizeof (UINT32) + CBITMAP_MAX_BYTES(cbitmap);
    cbytes = cbytes_new(len);
    if(NULL_PTR == cbytes)
    {
        dbg_log(SEC_0089_CBITMAP, 0)(LOGSTDOUT, "error:cbitmap_dfs_flush: new cbytes with len %ld bytes failed\n", len);
        return (EC_FALSE);
    }

    max_words = (CBITMAP_MAX_BITS(cbitmap) + WORDSIZE - 1) / WORDSIZE;

    buff = CBYTES_BUF(cbytes);

    counter = 0;
    gdbPutWord(buff, &counter, CBITMAP_MAX_BITS(cbitmap));
    gdbPutWord(buff, &counter, CBITMAP_CUR_BITS(cbitmap));

    for(word_offset = 0; word_offset < max_words; word_offset ++)
    {
        gdbPutWord(buff, &counter, CBITMAP_WORD(cbitmap, word_offset));
    }

    if((UINT32)counter > len)/*debug*/
    {
        dbg_log(SEC_0089_CBITMAP, 0)(LOGSTDOUT, "error:cbitmap_dfs_flush: counter %d != len %ld\n", counter, len);
        cbytes_free(cbytes);
        return (EC_FALSE);
    }

    /*resize*/
    CBYTES_LEN(cbytes) = counter;

    if(EC_FALSE == cdfs_update(cdfs_md_id, fname_cstr, cbytes))
    {
        dbg_log(SEC_0089_CBITMAP, 0)(LOGSTDOUT, "error:cbitmap_dfs_flush:flush cbitmap with %ld bytes to %s failed\n",
                            CBITMAP_MAX_BYTES(cbitmap), (char *)cstring_get_str(fname_cstr));
        cbytes_free(cbytes);
        return (EC_FALSE);
    }
    cbytes_free(cbytes);
    return (EC_TRUE);
}

CBITMAP *cbitmap_dfs_load(const CSTRING *fname_cstr, const UINT32 cdfs_md_id)
{
    CBITMAP *cbitmap;
    UINT32 max_bits;
    UINT32 cur_bits;
    UINT32 max_words;
    UINT32 word_offset;

    CBYTES    *cbytes;
    uint8_t   *buff;
    uint32_t   counter;

    cbytes = cbytes_new(0);
    if(NULL_PTR == cbytes)
    {
        dbg_log(SEC_0089_CBITMAP, 0)(LOGSTDOUT, "error:cbitmap_dfs_load: new cdfs buff failed\n");
        return (NULL_PTR);
    }

    if(EC_FALSE == cdfs_read(cdfs_md_id, fname_cstr, cbytes))
    {
        dbg_log(SEC_0089_CBITMAP, 0)(LOGSTDOUT, "error:cbitmap_dfs_load: read from %s failed\n", (char *)cstring_get_str(fname_cstr));
        cbytes_free(cbytes);
        return (NULL_PTR);
    }

    buff = cbytes_buf(cbytes);
    counter = 0;
    max_bits = gdbGetWord(buff, &counter);
    cur_bits = gdbGetWord(buff, &counter);

    cbitmap = cbitmap_new(max_bits);
    if(NULL_PTR == cbitmap)
    {
        dbg_log(SEC_0089_CBITMAP, 0)(LOGSTDOUT, "error:cbitmap_dfs_load: new cbitmap with max bits %ld failed\n", max_bits);
        cbytes_free(cbytes);
        return (NULL_PTR);
    }

    max_words = (max_bits + WORDSIZE - 1) / WORDSIZE;

    CBITMAP_MAX_BITS(cbitmap) = max_bits;
    CBITMAP_CUR_BITS(cbitmap) = cur_bits;
    for(word_offset = 0; word_offset < max_words; word_offset ++)
    {
        CBITMAP_WORD(cbitmap, word_offset) = gdbGetWord(buff, &counter);
    }

    cbytes_free(cbytes);
    return (cbitmap);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

