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

#include "type.h"
#include "mm.h"
#include "log.h"

#include "cmisc.h"
#include "real.h"

#include "csfsb.h"

/*page block:64MB*/

#if 1
#define CSFSB_ASSERT(cond)   ASSERT(cond)
#endif

#if 0
#define CSFSB_ASSERT(cond)   do{}while(0)
#endif

#define ASSERT_CSFSB_PAD_SIZE()                                        \
    CSFSB_ASSERT( CSFSB_PAD_SIZE == (sizeof(CSFSB)                     \
                            - sizeof(uint16_t)                         \
                            - (CSFSB_PAGE_NUM >> 5) * sizeof(uint32_t) \
                            - CSFSB_PAGE_NUM * sizeof(uint32_t)) )
#if 0
static const CSFSB_CONF g_csfsb_conf[] = {
    {"CSFSB_064MB_MODEL", CSFSB_064MB_PAGE_NUM, 0, 0, 0},
    {"CSFSB_032MB_MODEL", CSFSB_032MB_PAGE_NUM, 0, 0, 0},
    {"CSFSB_016MB_MODEL", CSFSB_016MB_PAGE_NUM, 0, 0, 0},
    {"CSFSB_008MB_MODEL", CSFSB_008MB_PAGE_NUM, 0, 0, 0},
    {"CSFSB_004MB_MODEL", CSFSB_004MB_PAGE_NUM, 0, 0, 0},
    {"CSFSB_002MB_MODEL", CSFSB_002MB_PAGE_NUM, 0, 0, 0},
    {"CSFSB_001MB_MODEL", CSFSB_001MB_PAGE_NUM, 0, 0, 0},
    {"CSFSB_512KB_MODEL", CSFSB_512KB_PAGE_NUM, 0, 0, 0},
    {"CSFSB_256KB_MODEL", CSFSB_256KB_PAGE_NUM, 0, 0, 0},
    {"CSFSB_128KB_MODEL", CSFSB_128KB_PAGE_NUM, 0, 0, 0},
    {"CSFSB_064KB_MODEL", CSFSB_064KB_PAGE_NUM, 0, 0, 0},
    {"CSFSB_032KB_MODEL", CSFSB_032KB_PAGE_NUM, 0, 0, 0},
    {"CSFSB_016KB_MODEL", CSFSB_016KB_PAGE_NUM, 0, 0, 0},
    {"CSFSB_008KB_MODEL", CSFSB_008KB_PAGE_NUM, 0, 0, 0},
    {"CSFSB_004KB_MODEL", CSFSB_004KB_PAGE_NUM, 0, 0, 0},
};
#endif
static const uint8_t g_nbits_per_byte[] = {
    /*   0 -   31*/ 0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4, 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
    /*  32 -   63*/ 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    /*  64 -   95*/ 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    /*  96 -  127*/ 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    /* 128 -  159*/ 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    /* 160 -  191*/ 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    /* 192 -  223*/ 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    /* 224 -  255*/ 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, 4, 5, 5, 6, 5, 6, 6, 7, 5, 6, 6, 7, 6, 7, 7, 8,
};


STATIC_CAST static EC_BOOL __csfsb_page_used_bitmap_set(CSFSB *csfsb, const uint16_t bit_pos)
{
    uint32_t *page_used_bitmap;
    uint16_t  page_max_num;
    uint16_t  int_nth;
    uint16_t  bit_nth;

    page_used_bitmap = (uint32_t *)CSFSB_PAGE_USED_BITMAP_TBL(csfsb);
    page_max_num     = CSFSB_PAGE_MAX_NUM(csfsb);

    int_nth = (bit_pos >> 5);  /*bit_pos / 32*/
    bit_nth = (bit_pos & 31);  /*bit_pos % 32*/

    dbg_log(SEC_0166_CSFSB, 9)(LOGSTDOUT, "[DEBUG] __csfsb_page_used_bitmap_set: page_max_num %u, bit_pos %u\n",
                    page_max_num, bit_pos);

    if((page_max_num >> 5) < int_nth)
    {
        dbg_log(SEC_0166_CSFSB, 0)(LOGSTDOUT, "error:__csfsb_page_used_bitmap_set: bit_pos %u overflow\n", bit_pos);
        return (EC_FALSE);
    }

    if(0 != (page_used_bitmap[ int_nth ] & ((uint32_t)(1 << bit_nth))))
    {
        dbg_log(SEC_0166_CSFSB, 0)(LOGSTDOUT, "error:__csfsb_page_used_bitmap_set: bit_pos %u was already set!\n", bit_pos);
        return (EC_FALSE);
    }

    page_used_bitmap[ int_nth ] |= (uint32_t)(1 << bit_nth);

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __csfsb_page_used_bitmap_clear(CSFSB *csfsb, const uint16_t bit_pos)
{
    uint32_t *page_used_bitmap;
    uint16_t  page_max_num;
    uint16_t  int_nth;
    uint16_t  bit_nth;

    page_used_bitmap = (uint32_t *)CSFSB_PAGE_USED_BITMAP_TBL(csfsb);
    page_max_num     = CSFSB_PAGE_MAX_NUM(csfsb);

    int_nth = (bit_pos >> 5);  /*bit_pos / 32*/
    bit_nth = (bit_pos & 31);  /*bit_pos % 32*/

    if((page_max_num >> 5) < int_nth)
    {
        dbg_log(SEC_0166_CSFSB, 0)(LOGSTDOUT, "error:__csfsb_page_used_bitmap_clear: bit_pos %u overflow\n", bit_pos);
        return (EC_FALSE);
    }

    if(0 == (page_used_bitmap[ int_nth ] & ((uint32_t)(1 << bit_nth))))
    {
        dbg_log(SEC_0166_CSFSB, 0)(LOGSTDOUT, "error:__csfsb_page_used_bitmap_clear: bit_pos %u was NOT set!\n", bit_pos);
        return (EC_FALSE);
    }

    page_used_bitmap[ int_nth ] &= (uint32_t)(~(1 << bit_nth));

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __csfsb_page_used_bitmap_get(const CSFSB *csfsb, const uint16_t bit_pos, uint32_t *bit_val)
{
    uint32_t *page_used_bitmap;
    uint16_t  page_max_num;
    uint16_t  int_nth;
    uint16_t  bit_nth;

    page_used_bitmap = (uint32_t *)CSFSB_PAGE_USED_BITMAP_TBL(csfsb);
    page_max_num     = CSFSB_PAGE_MAX_NUM(csfsb);

    int_nth = (bit_pos >> 5);  /*bit_pos / 32*/
    bit_nth = (bit_pos & 31);  /*bit_pos % 32*/

    if((page_max_num >> 5) < int_nth)
    {
        dbg_log(SEC_0166_CSFSB, 0)(LOGSTDOUT, "error:__csfsb_page_used_bitmap_get: bit_pos %u overflow\n", bit_pos);
        return (EC_FALSE);
    }

    if(0 == (page_used_bitmap[ int_nth ] & ((uint32_t)(1 << bit_nth))))
    {
        (*bit_val) = 0;
    }
    else
    {
        (*bit_val) = 1;
    }

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __csfsb_page_used_bitmap_search_from(const CSFSB *csfsb, const uint16_t max_nbits, uint16_t *bit_pos)
{
    uint32_t *page_used_bitmap;
    uint16_t  page_max_num;
    uint16_t  int_nth;
    uint16_t  bit_nth;
    uint16_t  nbits;

    page_used_bitmap = (uint32_t *)CSFSB_PAGE_USED_BITMAP_TBL(csfsb);
    page_max_num     = CSFSB_PAGE_MAX_NUM(csfsb);

    int_nth = ((*bit_pos) >> 5);  /*bit_pos / 32*/
    bit_nth = ((*bit_pos) & 31);  /*bit_pos % 32*/

    dbg_log(SEC_0166_CSFSB, 9)(LOGSTDOUT, "[DEBUG] __csfsb_page_used_bitmap_search_from: int_nth %u, bit_nth %u, max_nbits %u [BEG]\n",
                        int_nth, bit_nth, max_nbits);
    for(nbits = 0;int_nth <= (page_max_num >> 5) && nbits < max_nbits; int_nth ++, bit_nth = 0)
    {
        uint32_t val;

        val = (page_used_bitmap[ int_nth ] >> bit_nth);
        if(0 != val)
        {
            uint32_t  e;

            for(e = 1; 0 == (val & e); e <<= 1, bit_nth ++)
            {
                dbg_log(SEC_0166_CSFSB, 9)(LOGSTDOUT, "[DEBUG] __csfsb_page_used_bitmap_search_from: int_nth %u, bit_nth %u, e %08x, val %08x\n",
                                int_nth, bit_nth, e, val);
                /*do nothing*/
            }

            dbg_log(SEC_0166_CSFSB, 9)(LOGSTDOUT, "[DEBUG] __csfsb_page_used_bitmap_search_from: int_nth %u, bit_nth %u, e %08x, val %08x [SUCC]\n",
                                int_nth, bit_nth, e, val);

            (*bit_pos) = (int_nth << 5) + bit_nth;

            return (EC_TRUE);
        }
        nbits += (32 - bit_nth);
    }

    dbg_log(SEC_0166_CSFSB, 9)(LOGSTDOUT, "[DEBUG] __csfsb_page_used_bitmap_search_from: int_nth %u, bit_nth %u [FAIL]\n",
                        int_nth, bit_nth);
    return (EC_FALSE);
}

STATIC_CAST static EC_BOOL __csfsb_page_used_bitmap_is(const CSFSB *csfsb, const uint16_t bit_pos, const uint32_t bit_val)
{
    uint32_t *page_used_bitmap;
    uint16_t  page_max_num;
    uint16_t  int_nth;
    uint16_t  bit_nth;
    uint32_t  e;

    page_used_bitmap = (uint32_t *)CSFSB_PAGE_USED_BITMAP_TBL(csfsb);
    page_max_num     = CSFSB_PAGE_MAX_NUM(csfsb);

    int_nth = (bit_pos >> 5);  /*bit_pos / 32*/
    bit_nth = (bit_pos & 31);  /*bit_pos % 32*/

    if((page_max_num >> 5) < int_nth)
    {
        dbg_log(SEC_0166_CSFSB, 0)(LOGSTDOUT, "error:__csfsb_page_used_bitmap_get: bit_pos %u overflow\n", bit_pos);
        return (EC_FALSE);
    }

    e = (page_used_bitmap[ int_nth ] & ((uint32_t)(1 << bit_nth)));

    if(0 == e && 0 == bit_val)
    {
        return (EC_TRUE);
    }

    if(0 < e && 1 == bit_val)
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

STATIC_CAST static void __csfsb_page_used_bitmap_print(LOG *log, const CSFSB *csfsb)
{
    uint32_t *page_used_bitmap;
    uint16_t  page_max_num;
    uint16_t  int_nth;
    uint16_t  bit_nth;

    page_used_bitmap = (uint32_t *)CSFSB_PAGE_USED_BITMAP_TBL(csfsb);
    page_max_num     = CSFSB_PAGE_MAX_NUM(csfsb);

    for(int_nth = 0; int_nth <= (page_max_num >> 5); int_nth ++)
    {
        uint32_t  bit_val;
        uint32_t  int_val;

        int_val = page_used_bitmap[ int_nth ];
        if(0 == int_val)/*ignore*/
        {
            continue;
        }

        sys_print(log, "[%8d INT] ", int_nth);

        /*print bits from Lo to Hi*/
        for(bit_nth = 0; bit_nth < 32; bit_nth ++, int_val >>= 1)
        {
            bit_val = (int_val & 1);
            sys_print(log, "%u ", bit_val);
        }
        sys_print(log, "\n");
    }
    return;
}

/*count the num of bit 1*/
STATIC_CAST static uint16_t __csfsb_page_used_bitmap_count_bits(const CSFSB *csfsb)
{
    uint32_t *page_used_bitmap;
    uint16_t  page_max_num;
    uint16_t  int_nth;
    uint16_t  bits_count;

    page_used_bitmap = (uint32_t *)CSFSB_PAGE_USED_BITMAP_TBL(csfsb);
    page_max_num     = CSFSB_PAGE_MAX_NUM(csfsb);

    bits_count = 0;

    for(int_nth = 0; int_nth <= (page_max_num >> 5); int_nth ++)
    {
        uint32_t val;

        val = page_used_bitmap[ int_nth ];

        bits_count += g_nbits_per_byte[ (uint8_t)((val >>  0) & 0xFF) ];
        bits_count += g_nbits_per_byte[ (uint8_t)((val >>  8) & 0xFF) ];
        bits_count += g_nbits_per_byte[ (uint8_t)((val >> 16) & 0xFF) ];
        bits_count += g_nbits_per_byte[ (uint8_t)((val >> 24) & 0xFF) ];
    }
    return (bits_count);
}

STATIC_CAST static EC_BOOL __csfsb_page_used_bitmap_init(CSFSB *csfsb)
{
    uint32_t *page_used_bitmap;
    uint16_t  page_max_num;
    uint16_t  int_nth;

    page_used_bitmap = (uint32_t *)CSFSB_PAGE_USED_BITMAP_TBL(csfsb);
    page_max_num     = CSFSB_PAGE_MAX_NUM(csfsb);

    for(int_nth = 0; int_nth <= (page_max_num >> 5); int_nth ++)
    {
        page_used_bitmap[ int_nth ] = 0;
    }
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __csfsb_page_used_bitmap_clean(CSFSB *csfsb)
{
    uint32_t *page_used_bitmap;
    uint16_t  page_max_num;
    uint16_t  int_nth;

    page_used_bitmap = (uint32_t *)CSFSB_PAGE_USED_BITMAP_TBL(csfsb);
    page_max_num     = CSFSB_PAGE_MAX_NUM(csfsb);

    for(int_nth = 0; int_nth <= (page_max_num >> 5); int_nth ++)
    {
        page_used_bitmap[ int_nth ] = 0;
    }
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __csfsb_page_np_node_pos_init(CSFSB *csfsb, const uint32_t np_node_err_pos)
{
    uint32_t *page_np_node_pos;
    uint16_t  page_max_num;
    uint16_t  pos;

    page_np_node_pos = CSFSB_PAGE_NP_NODE_POS_TBL(csfsb);
    page_max_num     = CSFSB_PAGE_MAX_NUM(csfsb);

    for(pos = 0; pos < page_max_num; pos ++)
    {
        page_np_node_pos[ pos ] = np_node_err_pos;
    }
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __csfsb_page_np_node_pos_clean(CSFSB *csfsb, const uint32_t np_node_err_pos)
{
    uint32_t *page_np_node_pos;
    uint16_t  page_max_num;
    uint16_t  pos;

    page_np_node_pos = CSFSB_PAGE_NP_NODE_POS_TBL(csfsb);
    page_max_num     = CSFSB_PAGE_MAX_NUM(csfsb);

    for(pos = 0; pos < page_max_num; pos ++)
    {
        page_np_node_pos[ pos ] = np_node_err_pos;
    }
    return (EC_TRUE);
}

CSFSB *csfsb_new(const uint32_t np_node_err_pos)
{
    CSFSB *csfsb;

    alloc_static_mem(MM_CSFSB, &csfsb, LOC_CSFSB_0001);
    if(NULL_PTR == csfsb)
    {
        dbg_log(SEC_0166_CSFSB, 0)(LOGSTDOUT, "error:csfsb_new: new csfsb failed\n");
        return (NULL_PTR);
    }

    csfsb_init(csfsb, np_node_err_pos);

    return (csfsb);
}

EC_BOOL csfsb_init(CSFSB *csfsb, const uint32_t np_node_err_pos)
{
    ASSERT_CSFSB_PAD_SIZE();

    if(NULL_PTR != csfsb)
    {
        CSFSB_PAGE_MAX_NUM(csfsb) = CSFSB_PAGE_NUM;/*note: init page max num at first!*/

        __csfsb_page_used_bitmap_init(csfsb);
        __csfsb_page_np_node_pos_init(csfsb, np_node_err_pos);
    }

    return (EC_TRUE);
}

void csfsb_clean(CSFSB *csfsb, const uint32_t np_node_err_pos)
{
    if(NULL_PTR != csfsb)
    {
        __csfsb_page_used_bitmap_clean(csfsb);
        __csfsb_page_np_node_pos_clean(csfsb, np_node_err_pos);

        CSFSB_PAGE_MAX_NUM(csfsb) = 0;/*note: clean page max num at last!*/
    }
    return;
}

EC_BOOL csfsb_free(CSFSB *csfsb, const uint32_t np_node_err_pos)
{
    if(NULL_PTR != csfsb)
    {
        csfsb_clean(csfsb, np_node_err_pos);
        free_static_mem(MM_CSFSB, csfsb, LOC_CSFSB_0002);
    }

    return (EC_TRUE);
}

EC_BOOL csfsb_new_space(CSFSB *csfsb, const uint16_t page_num, const uint16_t page_no, const uint32_t np_node_err_pos, CSFSNP_RECYCLE recycle, void *npp)
{
    uint16_t page_no_cur;
    uint16_t page_no_end;

    page_no_end = page_num + page_no;

    if(CSFSB_PAGE_NUM < page_no_end)
    {
        dbg_log(SEC_0166_CSFSB, 9)(LOGSTDOUT, "error:csfsb_new_space: page num %u from page_no %u overflow\n", page_num, page_no);
        return (EC_FALSE);
    }

    for(page_no_cur = page_no; page_no_cur < page_no_end; /*page_no_cur ++*/)
    {
        uint32_t np_node_pos;
        uint16_t page_num_left;

        page_num_left = page_num - (page_no_cur - page_no);
        if(EC_FALSE == __csfsb_page_used_bitmap_search_from(csfsb, page_num_left, &page_no_cur))
        {
            /*okay, those pages are not used yet or belong to the overrided files*/
            return (EC_TRUE);
        }

        dbg_log(SEC_0166_CSFSB, 9)(LOGSTDOUT, "[DEBUG] csfsb_new_space: page num left %u, seach reached page_no_cur %u\n",
                        page_num_left, page_no_cur);

        /*overlap the expected end, ignore*/
        if(page_no_cur >= page_no_end)
        {
            return (EC_TRUE);
        }

        /*recycle file*/
        np_node_pos = CSFSB_PAGE_NP_NODE_POS_TBL(csfsb)[ page_no_cur ];/*this is the first page*/
        dbg_log(SEC_0166_CSFSB, 9)(LOGSTDOUT, "[DEBUG] csfsb_new_space: trigger npp %p to recycle node_pos %u\n", npp, np_node_pos);

        ASSERT(NULL_PTR != recycle);

        if(EC_FALSE == recycle(npp, np_node_pos))
        {
            dbg_log(SEC_0166_CSFSB, 0)(LOGSTDOUT, "error:csfsb_new_space: npp %p to recycle node_pos %u failed\n", npp, np_node_pos);

            return (EC_FALSE);
        }

        /*cleanup*/
        __csfsb_page_used_bitmap_clear(csfsb, page_no_cur);
        CSFSB_PAGE_NP_NODE_POS_TBL(csfsb)[ page_no_cur ] = np_node_err_pos;

        dbg_log(SEC_0166_CSFSB, 9)(LOGSTDOUT, "[DEBUG] csfsb_new_space: npp %p to recycle node_pos %u done\n", npp, np_node_pos);
    }

    dbg_log(SEC_0166_CSFSB, 0)(LOGSTDOUT, "error:csfsb_new_space: page num %u, new space from page_no %u failed\n", page_num, page_no);

    return (EC_FALSE);
}

EC_BOOL csfsb_bind(CSFSB *csfsb, const uint16_t page_no, const uint32_t np_id, const uint32_t np_node_pos)
{
    if(CSFSB_PAGE_NUM <= page_no)
    {
        dbg_log(SEC_0166_CSFSB, 0)(LOGSTDOUT, "error:csfsb_bind: page_no %u overflow\n", page_no);
        return (EC_FALSE);
    }

    if(do_log(SEC_0166_CSFSB, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] csfsb_bind: csfsb %p is\n", csfsb);
        csfsb_print(LOGSTDOUT, csfsb);
    }

    CSFSB_PAGE_NP_NODE_POS_CHECK(np_id, np_node_pos);

    if(EC_FALSE == __csfsb_page_used_bitmap_set(csfsb, page_no))/*this is the first page*/
    {
        dbg_log(SEC_0166_CSFSB, 0)(LOGSTDOUT, "error:csfsb_bind: set bit of page_no %u failed\n", page_no);
        return (EC_FALSE);
    }

    CSFSB_PAGE_NP_NODE_POS_TBL(csfsb)[ page_no ] = CSFSB_PAGE_NP_NODE_POS_MAKE(np_id, np_node_pos);/*this is the first page*/

    return (EC_TRUE);
}

EC_BOOL csfsb_flush_size(const CSFSB *csfsb, UINT32 *size)
{
    (*size) += sizeof(CSFSB);
    return (EC_TRUE);
}

EC_BOOL csfsb_flush(const CSFSB *csfsb, int fd, UINT32 *offset)
{
    UINT32 osize;/*flush once size*/
    DEBUG(UINT32 offset_saved = *offset;);

    /*flush CSFSB_PAGE_MAX_NUM*/
    osize = sizeof(uint16_t);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(CSFSB_PAGE_MAX_NUM(csfsb))))
    {
        dbg_log(SEC_0166_CSFSB, 0)(LOGSTDOUT, "error:csfsb_flush: flush CSFSB_PAGE_MAX_NUM with %ld bytes at offset %ld of fd %d failed\n",
                            osize, (*offset), fd);
        return (EC_FALSE);
    }

    /*flush rsvd01*/
    osize = CSFSB_PAD_SIZE * sizeof(uint8_t);
    if(EC_FALSE == c_file_pad(fd, offset, osize, FILE_PAD_CHAR))
    {
        dbg_log(SEC_0166_CSFSB, 0)(LOGSTDOUT, "error:csfsb_flush: flush rsvd01 at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*flush CSFSB_PAGE_USED_BITMAP_TBL*/
    osize = (CSFSB_PAGE_NUM >> 5)  * sizeof(uint32_t);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)CSFSB_PAGE_USED_BITMAP_TBL(csfsb)))
    {
        dbg_log(SEC_0166_CSFSB, 0)(LOGSTDOUT, "error:csfsb_flush: write CSFSB_PAGE_USED_BITMAP_TBL at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*flush CSFSB_PAGE_NP_NODE_POS_TBL*/
    osize = CSFSB_PAGE_NUM  * sizeof(uint32_t);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)CSFSB_PAGE_NP_NODE_POS_TBL(csfsb)))
    {
        dbg_log(SEC_0166_CSFSB, 0)(LOGSTDOUT, "error:csfsb_flush: write CSFSB_PAGE_NP_NODE_POS_TBL at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    DEBUG(CSFSB_ASSERT(sizeof(CSFSB) == (*offset) - offset_saved));

    return (EC_TRUE);
}

EC_BOOL csfsb_load(CSFSB *csfsb, int fd, UINT32 *offset)
{
    UINT32 osize;/*load once size*/

    /*load CSFSB_PAGE_MAX_NUM*/
    osize = sizeof(uint16_t);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(CSFSB_PAGE_MAX_NUM(csfsb))))
    {
        dbg_log(SEC_0166_CSFSB, 0)(LOGSTDOUT, "error:csfsb_load: load CSFSB_PAGE_MAX_NUM with %ld bytes at offset %ld of fd %d failed\n",
                            osize, (*offset), fd);
        return (EC_FALSE);
    }

    /*skip rsvd01*/
    (*offset) += CSFSB_PAD_SIZE * sizeof(uint8_t);

    /*load CSFSB_PAGE_USED_BITMAP_TBL*/
    osize = (CSFSB_PAGE_NUM >> 5) * sizeof(uint32_t);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)CSFSB_PAGE_USED_BITMAP_TBL(csfsb)))
    {
        dbg_log(SEC_0166_CSFSB, 0)(LOGSTDOUT, "error:csfsb_load: load CSFSB_PAGE_USED_BITMAP_TBL at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*load CSFSB_PAGE_NP_NODE_POS_TBL*/
    osize = CSFSB_PAGE_NUM * sizeof(uint32_t);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)CSFSB_PAGE_NP_NODE_POS_TBL(csfsb)))
    {
        dbg_log(SEC_0166_CSFSB, 0)(LOGSTDOUT, "error:csfsb_load: load CSFSB_PAGE_NP_NODE_POS_TBL at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

void csfsb_print(LOG *log, const CSFSB *csfsb)
{
    if(NULL_PTR == csfsb)
    {
        sys_log(log, "csfsb is null\n");
        return;
    }
    sys_log(log, "csfsb %p: page max num = %u\n", csfsb, CSFSB_PAGE_MAX_NUM(csfsb));
    return;
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

