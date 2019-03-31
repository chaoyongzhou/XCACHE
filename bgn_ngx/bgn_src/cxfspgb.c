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

#include "db_internal.h"

#include "cxfspgrb.h"
#include "cxfspgb.h"

/*page-cache block:64MB*/

/************************************************************************************************
  comment:
  ========
   1. if deploy balanced binary tree on cxfspgb, we can split 64MB block into 2k-page model :-(
      because we can descript parent/left child/right child offset with 16 bits
      red-black tree should record color info, thus we have only 15 bits to descript offset info,
      otherwise, we need more than 256KB to describe the whole page node info if expand CXFSPGRB_NODE
      offset to 16 bits and alignment CXFSPGRB_NODE structer to 8B.
      where 256KB = 2^15 2k-pages * 8B/per-2k-page-record, current 15 bits representation needs
      128KB for 2k-page block.
************************************************************************************************/
#if (SWITCH_ON == CXFS_ASSERT_SWITCH)
#define CXFSPGB_ASSERT(cond)   ASSERT(cond)
#endif/*(SWITCH_ON == CXFS_ASSERT_SWITCH)*/

#if (SWITCH_OFF == CXFS_ASSERT_SWITCH)
#define CXFSPGB_ASSERT(cond)   do{}while(0)
#endif/*(SWITCH_OFF == CXFS_ASSERT_SWITCH)*/

static const CXFSPGB_CONF g_cxfspgb_conf[] = {
    {"CXFSPGB_064MB_MODEL", CXFSPGB_064MB_MODEL,  CXFSPGB_064MB_BITMAP_SIZE, CXFSPGB_064MB_PAGE_NUM, 0,},
    {"CXFSPGB_032MB_MODEL", CXFSPGB_032MB_MODEL,  CXFSPGB_032MB_BITMAP_SIZE, CXFSPGB_032MB_PAGE_NUM, 0,},
    {"CXFSPGB_016MB_MODEL", CXFSPGB_016MB_MODEL,  CXFSPGB_016MB_BITMAP_SIZE, CXFSPGB_016MB_PAGE_NUM, 0,},
    {"CXFSPGB_008MB_MODEL", CXFSPGB_008MB_MODEL,  CXFSPGB_008MB_BITMAP_SIZE, CXFSPGB_008MB_PAGE_NUM, 0,},
    {"CXFSPGB_004MB_MODEL", CXFSPGB_004MB_MODEL,  CXFSPGB_004MB_BITMAP_SIZE, CXFSPGB_004MB_PAGE_NUM, 0,},
    {"CXFSPGB_002MB_MODEL", CXFSPGB_002MB_MODEL,  CXFSPGB_002MB_BITMAP_SIZE, CXFSPGB_002MB_PAGE_NUM, 0,},
    {"CXFSPGB_001MB_MODEL", CXFSPGB_001MB_MODEL,  CXFSPGB_001MB_BITMAP_SIZE, CXFSPGB_001MB_PAGE_NUM, 0,},
    {"CXFSPGB_512KB_MODEL", CXFSPGB_512KB_MODEL,  CXFSPGB_512KB_BITMAP_SIZE, CXFSPGB_512KB_PAGE_NUM, 0,},
    {"CXFSPGB_256KB_MODEL", CXFSPGB_256KB_MODEL,  CXFSPGB_256KB_BITMAP_SIZE, CXFSPGB_256KB_PAGE_NUM, 0,},
    {"CXFSPGB_128KB_MODEL", CXFSPGB_128KB_MODEL,  CXFSPGB_128KB_BITMAP_SIZE, CXFSPGB_128KB_PAGE_NUM, 0,},
    {"CXFSPGB_064KB_MODEL", CXFSPGB_064KB_MODEL,  CXFSPGB_064KB_BITMAP_SIZE, CXFSPGB_064KB_PAGE_NUM, 0,},
    {"CXFSPGB_032KB_MODEL", CXFSPGB_032KB_MODEL,  CXFSPGB_032KB_BITMAP_SIZE, CXFSPGB_032KB_PAGE_NUM, 0,},
    {"CXFSPGB_016KB_MODEL", CXFSPGB_016KB_MODEL,  CXFSPGB_016KB_BITMAP_SIZE, CXFSPGB_016KB_PAGE_NUM, 0,},
    {"CXFSPGB_008KB_MODEL", CXFSPGB_008KB_MODEL,  CXFSPGB_008KB_BITMAP_SIZE, CXFSPGB_008KB_PAGE_NUM, 0,},
    {"CXFSPGB_004KB_MODEL", CXFSPGB_004KB_MODEL,  CXFSPGB_004KB_BITMAP_SIZE, CXFSPGB_004KB_PAGE_NUM, 0,},
};

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

static const uint16_t g_pgb_bitmap_offset[] = {
    CXFSPGB_RB_BITMAP_OFFSET_OF_064MB_MODEL,
    CXFSPGB_RB_BITMAP_OFFSET_OF_032MB_MODEL,
    CXFSPGB_RB_BITMAP_OFFSET_OF_016MB_MODEL,
    CXFSPGB_RB_BITMAP_OFFSET_OF_008MB_MODEL,
    CXFSPGB_RB_BITMAP_OFFSET_OF_004MB_MODEL,
    CXFSPGB_RB_BITMAP_OFFSET_OF_002MB_MODEL,
    CXFSPGB_RB_BITMAP_OFFSET_OF_001MB_MODEL,
    CXFSPGB_RB_BITMAP_OFFSET_OF_512KB_MODEL,
    CXFSPGB_RB_BITMAP_OFFSET_OF_256KB_MODEL,
    CXFSPGB_RB_BITMAP_OFFSET_OF_128KB_MODEL,
    CXFSPGB_RB_BITMAP_OFFSET_OF_064KB_MODEL,
    CXFSPGB_RB_BITMAP_OFFSET_OF_032KB_MODEL,
    CXFSPGB_RB_BITMAP_OFFSET_OF_016KB_MODEL,
    CXFSPGB_RB_BITMAP_OFFSET_OF_008KB_MODEL,
    CXFSPGB_RB_BITMAP_OFFSET_OF_004KB_MODEL,
};

STATIC_CAST static EC_BOOL __cxfspgb_page_model_cxfspgrb_bitmap_set(CXFSPGB *cxfspgb, const uint16_t page_model, const uint16_t bit_pos)
{
    const CXFSPGB_CONF *cxfspgb_conf;
    uint8_t *pgc_cxfspgrb_bitmap;
    uint16_t byte_nth;
    uint16_t bit_nth;

    CXFSPGB_ASSERT(CXFSPGB_MODEL_NUM > page_model);

    cxfspgb_conf = &(g_cxfspgb_conf[ page_model ]);
    pgc_cxfspgrb_bitmap = CXFSPGB_PAGE_MODEL_CXFSPGRB_BITMAP(cxfspgb, page_model);

    byte_nth = (bit_pos >> 3); /*bit_pos / 8*/
    bit_nth  = (bit_pos & 7);  /*bit_pos % 8*/

    if(CXFSPGB_CONF_CXFSPGRB_BITMAP_SIZE(cxfspgb_conf) <= byte_nth)
    {
        dbg_log(SEC_0201_CXFSPGB, 0)(LOGSTDOUT, "error:__cxfspgb_page_model_cxfspgrb_bitmap_set: page_model %u, bit_pos %u overflow\n", page_model, bit_pos);
        return (EC_FALSE);
    }

    if(0 != (pgc_cxfspgrb_bitmap[ byte_nth ] & (uint8_t)(1 << bit_nth)))
    {
        dbg_log(SEC_0201_CXFSPGB, 0)(LOGSTDOUT, "error:__cxfspgb_page_model_cxfspgrb_bitmap_set: page_model %u, bit_pos %u was already set!\n", page_model, bit_pos);
        return (EC_FALSE);
    }

    pgc_cxfspgrb_bitmap[ byte_nth ] |= (uint8_t)(1 << bit_nth);

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cxfspgb_page_model_cxfspgrb_bitmap_clear(CXFSPGB *cxfspgb, const uint16_t page_model, const uint16_t bit_pos)
{
    const CXFSPGB_CONF *cxfspgb_conf;
    uint8_t *pgc_cxfspgrb_bitmap;
    uint16_t byte_nth;
    uint16_t bit_nth;

    CXFSPGB_ASSERT(CXFSPGB_MODEL_NUM > page_model);

    cxfspgb_conf = &(g_cxfspgb_conf[ page_model ]);
    pgc_cxfspgrb_bitmap = CXFSPGB_PAGE_MODEL_CXFSPGRB_BITMAP(cxfspgb, page_model);

    byte_nth = (bit_pos >> 3); /*bit_pos / 8*/
    bit_nth  = (bit_pos & 7);  /*bit_pos % 8*/

    if(CXFSPGB_CONF_CXFSPGRB_BITMAP_SIZE(cxfspgb_conf) <= byte_nth)
    {
        dbg_log(SEC_0201_CXFSPGB, 0)(LOGSTDOUT, "error:__cxfspgb_page_model_cxfspgrb_bitmap_clear: page_model %u, bit_pos %u overflow\n", page_model, bit_pos);
        return (EC_FALSE);
    }

    if(0 == (pgc_cxfspgrb_bitmap[ byte_nth ] & (uint8_t)(1 << bit_nth)))
    {
        dbg_log(SEC_0201_CXFSPGB, 0)(LOGSTDOUT, "error:__cxfspgb_page_model_cxfspgrb_bitmap_clear: page_model %u, bit_pos %u was NOT set!\n", page_model, bit_pos);
        return (EC_FALSE);
    }

    pgc_cxfspgrb_bitmap[ byte_nth ] &= (uint8_t)(~(1 << bit_nth));

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cxfspgb_page_model_cxfspgrb_bitmap_get(const CXFSPGB *cxfspgb, const uint16_t page_model, const uint16_t bit_pos, uint8_t *bit_val)
{
    const CXFSPGB_CONF *cxfspgb_conf;
    const uint8_t *pgc_cxfspgrb_bitmap;
    uint16_t byte_nth;
    uint16_t bit_nth;

    CXFSPGB_ASSERT(CXFSPGB_MODEL_NUM > page_model);

    cxfspgb_conf = &(g_cxfspgb_conf[ page_model ]);
    pgc_cxfspgrb_bitmap = CXFSPGB_PAGE_MODEL_CXFSPGRB_BITMAP(cxfspgb, page_model);

    byte_nth = (bit_pos >> 3); /*bit_pos / 8*/
    bit_nth  = (bit_pos & 7);  /*bit_pos % 8*/

    if(CXFSPGB_CONF_CXFSPGRB_BITMAP_SIZE(cxfspgb_conf) <= byte_nth)
    {
        dbg_log(SEC_0201_CXFSPGB, 0)(LOGSTDOUT, "error:__cxfspgb_page_model_cxfspgrb_bitmap_clear: page_model %u, bit_pos %u overflow\n", page_model, bit_pos);
        return (EC_FALSE);
    }

    if(0 == (pgc_cxfspgrb_bitmap[ byte_nth ] & (uint8_t)(1 << bit_nth)))
    {
        (*bit_val) = 0;
    }
    else
    {
        (*bit_val) = 1;
    }

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cxfspgb_page_model_cxfspgrb_bitmap_is(const CXFSPGB *cxfspgb, const uint16_t page_model, const uint16_t bit_pos, const uint8_t bit_val)
{
    const CXFSPGB_CONF *cxfspgb_conf;
    const uint8_t *pgc_cxfspgrb_bitmap;
    uint16_t byte_nth;
    uint16_t bit_nth;
    uint8_t  e;

    CXFSPGB_ASSERT(CXFSPGB_MODEL_NUM > page_model);

    cxfspgb_conf = &(g_cxfspgb_conf[ page_model ]);
    pgc_cxfspgrb_bitmap = CXFSPGB_PAGE_MODEL_CXFSPGRB_BITMAP(cxfspgb, page_model);

    byte_nth = (bit_pos >> 3); /*bit_pos / 8*/
    bit_nth  = (bit_pos & 7);  /*bit_pos % 8*/

    if(CXFSPGB_CONF_CXFSPGRB_BITMAP_SIZE(cxfspgb_conf) <= byte_nth)
    {
        dbg_log(SEC_0201_CXFSPGB, 0)(LOGSTDOUT, "error:__cxfspgb_page_model_cxfspgrb_bitmap_is: page_model %u, bit_pos %u overflow\n", page_model, bit_pos);
        return (EC_FALSE);
    }

    e = (pgc_cxfspgrb_bitmap[ byte_nth ] & (uint8_t)(1 << bit_nth));

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

/*check no adjacent (odd, even) bits are both 1*/
STATIC_CAST static EC_BOOL __cxfspgb_page_model_cxfspgrb_bitmap_check(const CXFSPGB *cxfspgb, const uint16_t page_model)
{
    const CXFSPGB_CONF *cxfspgb_conf;
    const uint8_t *pgc_cxfspgrb_bitmap;
    uint16_t byte_nth;

    CXFSPGB_ASSERT(CXFSPGB_MODEL_NUM > page_model);

    cxfspgb_conf = &(g_cxfspgb_conf[ page_model ]);
    pgc_cxfspgrb_bitmap = CXFSPGB_PAGE_MODEL_CXFSPGRB_BITMAP(cxfspgb, page_model);

    for(byte_nth = 0; byte_nth < CXFSPGB_CONF_CXFSPGRB_BITMAP_SIZE(cxfspgb_conf); byte_nth ++)
    {
        uint8_t byte_val;

        byte_val = pgc_cxfspgrb_bitmap[ byte_nth ];

        /*(0000 0011) = 0x03*/
        /*(0000 1100) = 0x0C*/
        /*(0011 0000) = 0x30*/
        /*(1100 0000) = 0xC0*/
        if(0x03 == (byte_val & 0x03)
        || 0x0C == (byte_val & 0x0C)
        || 0x30 == (byte_val & 0x30)
        || 0xC0 == (byte_val & 0xC0))
        {
            dbg_log(SEC_0201_CXFSPGB, 0)(LOGSTDOUT, "error:__cxfspgb_page_model_cxfspgrb_bitmap_check: page_model %u found adjacent 2 bits are set"
                               " at %u # byte which is 0x%x\n",
                               page_model, byte_nth, byte_val);
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

STATIC_CAST static void __cxfspgb_page_model_cxfspgrb_bitmap_print(LOG *log, const CXFSPGB *cxfspgb, const uint16_t page_model)
{
    const CXFSPGB_CONF *cxfspgb_conf;
    const uint8_t *pgc_cxfspgrb_bitmap;
    uint16_t byte_nth;

    CXFSPGB_ASSERT(CXFSPGB_MODEL_NUM > page_model);

    cxfspgb_conf      = &(g_cxfspgb_conf[ page_model ]);
    pgc_cxfspgrb_bitmap = CXFSPGB_PAGE_MODEL_CXFSPGRB_BITMAP(cxfspgb, page_model);

    for(byte_nth = 0; byte_nth < CXFSPGB_CONF_CXFSPGRB_BITMAP_SIZE(cxfspgb_conf); byte_nth ++)
    {
        uint16_t bit_nth;
        uint8_t  bit_val;
        uint8_t  byte_val;

        byte_val = pgc_cxfspgrb_bitmap[ byte_nth ];
        if(0 == byte_val)/*ignore*/
        {
            continue;
        }

        sys_print(log, "[%8d B] ", byte_nth);

        /*print bits from Lo to Hi*/
        for(bit_nth = 0; bit_nth < BYTESIZE; bit_nth ++, byte_val >>= 1)
        {
            bit_val = (byte_val & 1);
            sys_print(log, "%u ", bit_val);
        }
        sys_print(log, "\n");
    }
    return;
}

/*count the num of bit 1*/
STATIC_CAST static uint16_t __cxfspgb_page_model_cxfspgrb_bitmap_count_bits(const CXFSPGB *cxfspgb, const uint16_t page_model)
{
    const CXFSPGB_CONF *cxfspgb_conf;
    const uint8_t *pgc_cxfspgrb_bitmap;
    uint16_t byte_nth;
    uint16_t bits_count;

    CXFSPGB_ASSERT(CXFSPGB_MODEL_NUM > page_model);

    cxfspgb_conf      = &(g_cxfspgb_conf[ page_model ]);
    pgc_cxfspgrb_bitmap = CXFSPGB_PAGE_MODEL_CXFSPGRB_BITMAP(cxfspgb, page_model);
    bits_count     = 0;

    for(byte_nth = 0; byte_nth < CXFSPGB_CONF_CXFSPGRB_BITMAP_SIZE(cxfspgb_conf); byte_nth ++)
    {
        bits_count += g_nbits_per_byte[ pgc_cxfspgrb_bitmap[ byte_nth ] ];
    }
    return (bits_count);
}


/**
  return the first page no in current page model.
  e.g.,
  Page Model                4K-Page No.
  4K Model                  00 01 02 03 04 05 06 07 08 ...
  8K Model                  00          01          02 ...
 16K Model                  00                      01 ...

  if the first page address is at 08 4k-page, then
      if page model is  4k model, return 08
      if page model is  8k model, return 02
      if page model is 16k model, return 01
  endif
**/
STATIC_CAST static uint16_t __cxfspgb_page_model_first_page(const CXFSPGB *cxfspgb, const uint16_t page_model)
{
    uint16_t node_pos;
    const CXFSPGRB_NODE *node;

    node_pos = cxfspgrb_tree_first_node(CXFSPGB_CXFSPGRB_POOL(cxfspgb), CXFSPGB_PAGE_MODEL_CXFSPGRB_ROOT_POS(cxfspgb, page_model));
    if(CXFSPGRB_ERR_POS == node_pos)
    {
        dbg_log(SEC_0201_CXFSPGB, 0)(LOGSTDOUT, "error:__cxfspgb_page_model_first_page: no free page in page model %u\n", page_model);
        return (CXFSPGRB_ERR_POS);
    }

    node = CXFSPGRB_POOL_NODE(CXFSPGB_CXFSPGRB_POOL(cxfspgb), node_pos);
    return (CXFSPGRB_NODE_DATA(node));
}

STATIC_CAST static EC_BOOL __cxfspgb_page_model_check(const CXFSPGB *cxfspgb, const uint16_t page_model)
{
    uint16_t bits_count;
    uint16_t nodes_count;
    uint16_t root_pos;
    uint16_t node_pos;

    const CXFSPGRB_POOL *cxfspgrb_pool;

    cxfspgrb_pool    = CXFSPGB_CXFSPGRB_POOL(cxfspgb);
    root_pos    = CXFSPGB_PAGE_MODEL_CXFSPGRB_ROOT_POS(cxfspgb, page_model);

    /*check consistency of bit count and node count*/
    bits_count  = __cxfspgb_page_model_cxfspgrb_bitmap_count_bits(cxfspgb, page_model);
    nodes_count = cxfspgrb_tree_node_num(CXFSPGB_CXFSPGRB_POOL(cxfspgb), root_pos);

    if(bits_count != nodes_count)
    {
        dbg_log(SEC_0201_CXFSPGB, 9)(LOGSTDOUT, "[DEBUG] __cxfspgb_page_model_check: [FAIL] page model %u found inconsistent where bits_count = %u, but nodes_count = %u\n",
                            page_model, bits_count, nodes_count);
        return (EC_FALSE);
    }

    /*check page no consistency of rbtree and bitmap*/
    for(node_pos = cxfspgrb_tree_first_node(cxfspgrb_pool, root_pos);
         CXFSPGRB_ERR_POS != node_pos;
         node_pos = cxfspgrb_tree_next_node(cxfspgrb_pool, node_pos)
       )
    {
        const CXFSPGRB_NODE *node;
        uint16_t  page_no;

        node = CXFSPGRB_POOL_NODE(cxfspgrb_pool, node_pos);
        if(CXFSPGRB_NODE_NOT_USED == CXFSPGRB_NODE_USED_FLAG(node))
        {
            dbg_log(SEC_0201_CXFSPGB, 9)(LOGSTDOUT, "[DEBUG] error:__cxfspgb_page_model_check: found node at pos %u was not used in page model %u\n",
                                node_pos, page_model);
            return (EC_FALSE);
        }

        page_no = CXFSPGRB_NODE_DATA(node);
        if(EC_FALSE == __cxfspgb_page_model_cxfspgrb_bitmap_is(cxfspgb, page_model, page_no, (uint8_t) 1))
        {
            dbg_log(SEC_0201_CXFSPGB, 9)(LOGSTDOUT, "[DEBUG] __cxfspgb_page_model_check: [FAIL] page model %u found inconsistent "
                               "where page no %u in rbtree without bitmap setting\n",
                                page_model, page_no);
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == __cxfspgb_page_model_cxfspgrb_bitmap_check(cxfspgb, page_model))
    {
        dbg_log(SEC_0201_CXFSPGB, 9)(LOGSTDOUT, "[DEBUG] __cxfspgb_page_model_check: [FAIL] page model %u found bitmap invalidity\n",
                            page_model);
        return (EC_FALSE);
    }

    dbg_log(SEC_0201_CXFSPGB, 9)(LOGSTDOUT, "[DEBUG] __cxfspgb_page_model_check: [SUCC] page model %u owns %u pages\n", page_model, nodes_count);
    return (EC_TRUE);
}

void cxfspgb_page_model_print(LOG *log, const CXFSPGB *cxfspgb, const uint16_t page_model)
{
    const CXFSPGRB_POOL *cxfspgrb_pool;
    const CXFSPGB_CONF  *cxfspgb_conf;
    uint16_t             cxfspgrb_bitmap_size;
    uint16_t             page_num;

    CXFSPGB_ASSERT(CXFSPGB_MODEL_NUM > page_model);

    cxfspgb_conf         = &(g_cxfspgb_conf[ page_model ]);
    cxfspgrb_pool        = CXFSPGB_CXFSPGRB_POOL(cxfspgb);
    cxfspgrb_bitmap_size = CXFSPGB_CONF_CXFSPGRB_BITMAP_SIZE(cxfspgb_conf);
    page_num             = CXFSPGB_CONF_PAGE_NUM(cxfspgb_conf);

    CXFSPGB_ASSERT(page_model == CXFSPGB_CONF_PAGE_MODEL(cxfspgb_conf));
    sys_log(log, "cxfspgb_page_model_print: page model %u (%s), cxfspgrb_bitmap_size %u, page_num %u\n",
                 page_model, CXFSPGB_CONF_NAME(cxfspgb_conf), cxfspgrb_bitmap_size, page_num);
    sys_log(log, "cxfspgb_page_model_print: page model %u, rbtree is\n", page_model);
    cxfspgrb_tree_print(log, cxfspgrb_pool, CXFSPGB_PAGE_MODEL_CXFSPGRB_ROOT_POS(cxfspgb, page_model));
    sys_log(log, "cxfspgb_page_model_print: page model %u, bitmap is\n", page_model);
    __cxfspgb_page_model_cxfspgrb_bitmap_print(log, cxfspgb, page_model);

    return;
}

CXFSPGB *cxfspgb_new(const uint16_t page_model_target)
{
    CXFSPGB *cxfspgb;

    alloc_static_mem(MM_CXFSPGB, &cxfspgb, LOC_CXFSPGB_0001);
    if(NULL_PTR == cxfspgb)
    {
        dbg_log(SEC_0201_CXFSPGB, 0)(LOGSTDOUT, "error:cxfspgb_new: new cxfspgb failed\n");
        return (NULL_PTR);
    }

    cxfspgb_init(cxfspgb, page_model_target);

    return (cxfspgb);
}

/* one page block = 64MB */
EC_BOOL cxfspgb_init(CXFSPGB *cxfspgb, const uint16_t page_model_target)
{
    uint16_t page_max_num;
    uint16_t page_max_num_t;
    uint16_t page_model;

    const CXFSPGB_CONF *cxfspgb_conf;

    if(CXFSPGB_MODEL_NUM <= page_model_target)
    {
        dbg_log(SEC_0201_CXFSPGB, 0)(LOGSTDOUT, "error:cxfspgb_init: page_model_target %u overflow\n", page_model_target);
        return (EC_FALSE);
    }

    cxfspgb_conf    = &(g_cxfspgb_conf[ page_model_target ]);
    page_max_num = CXFSPGB_CONF_PAGE_NUM(cxfspgb_conf);

    page_max_num_t = ((page_max_num + 1) >> 1); /*optimize, use half of rb nodes to represent all pages*/
    if(EC_FALSE == cxfspgrb_pool_init(CXFSPGB_CXFSPGRB_POOL(cxfspgb), page_max_num_t))
    {
        dbg_log(SEC_0201_CXFSPGB, 0)(LOGSTDOUT, "error:cxfspgb_init: init cxfspgrb pool failed where page_max_num_t = %u derived from page_max_num %u\n", page_max_num_t, page_max_num);
        cxfspgb_clean(cxfspgb);
        return (EC_FALSE);
    }
    dbg_log(SEC_0201_CXFSPGB, 9)(LOGSTDNULL, "[DEBUG] cxfspgb_init: init cxfspgrb pool done where page_max_num_t = %u derived from page_max_num %u\n", page_max_num_t, page_max_num);

    BSET(CXFSPGB_PAGE_MODEL_CXFSPGRB_BITMAP_BUFF(cxfspgb), CXFSPGB_PAGE_IS_NOT_FREE, CXFSPGB_RB_BITMAP_SIZE); /*mark as non-free page*/

    for(page_model = 0; CXFSPGB_MODEL_MAX_NUM > page_model; page_model ++)
    {
        CXFSPGB_PAGE_MODEL_CXFSPGRB_ROOT_POS(cxfspgb, page_model) = CXFSPGRB_ERR_POS;
    }

    CXFSPGB_PAGE_MODEL_ASSIGN_BITMAP(cxfspgb) = 0;

    /*set target model*/
    cxfspgb_add_page(cxfspgb, page_model_target, 0/*page_no*/);

    /*statistics*/
    CXFSPGB_PAGE_MAX_NUM(cxfspgb)          = page_max_num;
    CXFSPGB_PAGE_USED_NUM(cxfspgb)         = 0;
    CXFSPGB_PAGE_ACTUAL_USED_SIZE(cxfspgb) = 0;

    return (EC_TRUE);
}

void cxfspgb_clean(CXFSPGB *cxfspgb)
{
    uint16_t page_model;

    cxfspgrb_pool_clean(CXFSPGB_CXFSPGRB_POOL(cxfspgb));

    for(page_model = 0; CXFSPGB_MODEL_MAX_NUM > page_model; page_model ++)
    {
        CXFSPGB_PAGE_MODEL_CXFSPGRB_ROOT_POS(cxfspgb, page_model) = CXFSPGRB_ERR_POS;
        //CXFSPGB_PAGE_MODEL_CXFSPGRB_BITMAP(cxfspgb, page_model)   = NULL_PTR;
    }

    CXFSPGB_PAGE_MODEL_ASSIGN_BITMAP(cxfspgb)     = 0;
    CXFSPGB_PAGE_MAX_NUM(cxfspgb)                 = 0;
    CXFSPGB_PAGE_USED_NUM(cxfspgb)                = 0;
    CXFSPGB_PAGE_ACTUAL_USED_SIZE(cxfspgb)        = 0;
    return;
}

EC_BOOL cxfspgb_free(CXFSPGB *cxfspgb)
{
    if(NULL_PTR != cxfspgb)
    {
        cxfspgb_clean(cxfspgb);
        free_static_mem(MM_CXFSPGB, cxfspgb, LOC_CXFSPGB_0002);
    }

    return (EC_TRUE);
}

/*page_no % (next power of two of page_num) = 0*/
STATIC_CAST static EC_BOOL __cxfspgb_check_validity(const uint16_t page_no, const uint16_t page_num)
{
    uint16_t v;     /*next power of two of page_num. i.e., 2^(v - 1) < page_num <= 2^v*/

    v = page_num;

    /*REF TO: http://graphics.stanford.edu/~seander/bithacks.html#RoundUpPowerOf2*/

    v --;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v ++;

    if(0 == v || 0 != (page_no % v))
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/*add one free page into pool and set page model bitmap*/
EC_BOOL cxfspgb_add_page(CXFSPGB *cxfspgb, const uint16_t page_model, const uint16_t page_no)
{
    //uint8_t *pgc_cxfspgrb_bitmap;
    uint16_t page_no_max;

    CXFSPGB_ASSERT(CXFSPGB_MODEL_NUM > page_model);

    //pgc_cxfspgrb_bitmap = CXFSPGB_PAGE_MODEL_CXFSPGRB_BITMAP(cxfspgb, page_model);

    page_no_max = (uint16_t)(1 << page_model);
    if(page_no >= page_no_max)
    {
        dbg_log(SEC_0201_CXFSPGB, 0)(LOGSTDOUT, "error:cxfspgb_add_page: page_no_max %u but page_no to add is %u, overflow!\n", page_no_max, page_no);
        return (EC_FALSE);
    }

    /*insert page_no to bitmap*/
    if(EC_FALSE == __cxfspgb_page_model_cxfspgrb_bitmap_set(cxfspgb, page_model, page_no))
    {
        dbg_log(SEC_0201_CXFSPGB, 0)(LOGSTDOUT, "error:cxfspgb_add_page: add page_no %u to bitmap of page model %u failed\n", page_no, page_model);
        return (EC_FALSE);
    }

    /*insert page_no to rbtree*/
    if(CXFSPGRB_ERR_POS == cxfspgrb_tree_insert_data(CXFSPGB_CXFSPGRB_POOL(cxfspgb), &(CXFSPGB_PAGE_MODEL_CXFSPGRB_ROOT_POS(cxfspgb, page_model)), page_no))
    {
        dbg_log(SEC_0201_CXFSPGB, 0)(LOGSTDOUT, "error:cxfspgb_add_page: add page_no %u to rbtree of page model %u failed\n", page_no, page_model);
        __cxfspgb_page_model_cxfspgrb_bitmap_clear(cxfspgb, page_model, page_no);
        return (EC_FALSE);
    }

    /*set assignment bitmap*/
    /*set bits of page_model, page_model + 1, ... page_4k_model, the highest bit is for 2k-page which is not supported,clear it!*/
    CXFSPGB_PAGE_MODEL_ASSIGN_BITMAP(cxfspgb) |= (uint16_t)(~((1 << page_model) - 1)) & CXFSPGB_MODEL_MASK_ALL;

    return (EC_TRUE);
}

/*del one free page from pool and clear page model bitmap, i.e., del one page from pool and used it later*/
EC_BOOL cxfspgb_del_page(CXFSPGB *cxfspgb, const uint16_t page_model, const uint16_t page_no)
{
    //uint8_t *pgc_cxfspgrb_bitmap;
    uint16_t page_no_max;

    CXFSPGB_ASSERT(CXFSPGB_MODEL_NUM > page_model);

    //pgc_cxfspgrb_bitmap = CXFSPGB_PAGE_MODEL_CXFSPGRB_BITMAP(cxfspgb, page_model);

    page_no_max = (uint16_t)(1 << page_model);

    if(page_no >= page_no_max)
    {
        dbg_log(SEC_0201_CXFSPGB, 0)(LOGSTDOUT, "error:cxfspgb_del_page: page_no_max %u but page_no to add is %u, overflow!\n", page_no_max, page_no);
        return (EC_FALSE);
    }

    /*del page_no from rbtree*/
    if(EC_FALSE == cxfspgrb_tree_delete_data(CXFSPGB_CXFSPGRB_POOL(cxfspgb), &(CXFSPGB_PAGE_MODEL_CXFSPGRB_ROOT_POS(cxfspgb, page_model)), page_no))
    {
        dbg_log(SEC_0201_CXFSPGB, 0)(LOGSTDOUT, "error:cxfspgb_del_page: del page_no %u from rbtree of page model %u failed\n", page_no, page_model);
        return (EC_FALSE);
    }

    /*del page_no from bitmap*/
    if(EC_FALSE == __cxfspgb_page_model_cxfspgrb_bitmap_clear(cxfspgb, page_model, page_no))
    {
        dbg_log(SEC_0201_CXFSPGB, 0)(LOGSTDOUT, "error:cxfspgb_del_page: del page_no %u from bitmap of page model %u failed\n", page_no, page_model);
        cxfspgrb_tree_insert_data(CXFSPGB_CXFSPGRB_POOL(cxfspgb), &(CXFSPGB_PAGE_MODEL_CXFSPGRB_ROOT_POS(cxfspgb, page_model)), page_no);
        return (EC_FALSE);
    }

    /*clear assignment bitmap if necessary*/
    if(0 == (CXFSPGB_PAGE_MODEL_ASSIGN_BITMAP(cxfspgb) & (uint16_t)((1 << page_model) - 1)))/*upper page-model has no page*/
    {
        uint16_t page_model_t;

        page_model_t = page_model;
        while(CXFSPGB_MODEL_NUM > page_model_t
           && EC_TRUE == cxfspgrb_tree_is_empty(CXFSPGB_CXFSPGRB_POOL(cxfspgb), CXFSPGB_PAGE_MODEL_CXFSPGRB_ROOT_POS(cxfspgb, page_model_t))/*this page-model is empty*/
        )
        {
            CXFSPGB_PAGE_MODEL_ASSIGN_BITMAP(cxfspgb) &= (uint16_t)~(1 << page_model_t);/*clear bit*/
            page_model_t ++;
        }
    }

    return (EC_TRUE);
}

uint16_t cxfspgb_assign_page(CXFSPGB *cxfspgb, const uint16_t page_model)
{
    uint16_t page_no;
    uint16_t page_model_t;
    uint16_t mask;

    page_model_t = page_model;

    mask = (uint16_t)((1 << (page_model + 1)) - 1);
    if(0 == (CXFSPGB_PAGE_MODEL_ASSIGN_BITMAP(cxfspgb) & mask))
    {
        dbg_log(SEC_0201_CXFSPGB, 0)(LOGSTDOUT, "error:cxfspgb_assign_page: page_model = %u where 0 == bitmap %x & mask %x indicates page is not available\n",
                           page_model, CXFSPGB_PAGE_MODEL_ASSIGN_BITMAP(cxfspgb), mask);
        return (CXFSPGRB_ERR_POS);
    }

    while(CXFSPGB_MODEL_NUM > page_model_t
       && EC_TRUE == cxfspgrb_tree_is_empty(CXFSPGB_CXFSPGRB_POOL(cxfspgb), CXFSPGB_PAGE_MODEL_CXFSPGRB_ROOT_POS(cxfspgb, page_model_t))
       )
    {
        page_model_t --;
    }

    if(CXFSPGB_MODEL_NUM <= page_model_t)
    {
        dbg_log(SEC_0201_CXFSPGB, 0)(LOGSTDOUT, "error:cxfspgb_assign_page: no free page available from page model %u\n", page_model);
        return (CXFSPGRB_ERR_POS);
    }

    page_no = __cxfspgb_page_model_first_page(cxfspgb, page_model_t);
    if(CXFSPGRB_ERR_POS == page_no)
    {
        dbg_log(SEC_0201_CXFSPGB, 0)(LOGSTDOUT, "error:cxfspgb_assign_page: no free page in page model %u\n", page_model_t);
        return (CXFSPGRB_ERR_POS);
    }

    if(EC_FALSE == cxfspgb_del_page(cxfspgb, page_model_t, page_no))
    {
        dbg_log(SEC_0201_CXFSPGB, 0)(LOGSTDOUT, "error:cxfspgb_assign_page: del page %u from page model %u failed\n", page_no, page_model_t);
        return (CXFSPGRB_ERR_POS);
    }

    /*--- split phase ---*/
    for(; page_model_t ++ < page_model;)
    {
        /*borrow one page from page_model_t and split it into two page and insert into page_model_t - 1*/
        /*page_no ==> (2*page_no, 2*page_no + 1)*/
        page_no <<= 1;

        if(EC_FALSE == cxfspgb_add_page(cxfspgb, page_model_t, page_no + 1))
        {
            dbg_log(SEC_0201_CXFSPGB, 0)(LOGSTDOUT, "error:cxfspgb_assign_page: borrowed one page %u from page model %u, "
                               "but insert the splitted page %u into page model %u failed\n",
                                (uint16_t)(page_no >> 1), (page_model_t - 1), page_no + 1, page_model_t);
            dbg_log(SEC_0201_CXFSPGB, 0)(LOGSTDOUT, "error:cxfspgb_assign_page: try to return page %u to page model %u ...\n",
                                (uint16_t)(page_no >> 1), (page_model_t - 1));

            return (CXFSPGRB_ERR_POS);
        }
    }

    return (page_no);
}

EC_BOOL cxfspgb_recycle_page(CXFSPGB *cxfspgb, const uint16_t page_model, const uint16_t page_no)
{
    //uint8_t *pgc_cxfspgrb_bitmap;
    uint16_t page_no_max;
    uint16_t page_no_t;
    uint16_t page_model_t;

    CXFSPGB_ASSERT(CXFSPGB_MODEL_NUM > page_model);

    //pgc_cxfspgrb_bitmap = CXFSPGB_PAGE_MODEL_CXFSPGRB_BITMAP(cxfspgb, page_model);

    page_no_max = (uint16_t)(1 << page_model);
    if(page_no >= page_no_max)
    {
        dbg_log(SEC_0201_CXFSPGB, 0)(LOGSTDOUT, "error:cxfspgb_recycle_page: page_no_max %u but page_no to add is %u, overflow!\n", page_no_max, page_no);
        return (EC_FALSE);
    }

    /*--- merge phase ---*/
    for(page_no_t = page_no, page_model_t = page_model; page_model_t > 0; page_model_t --, page_no_t >>= 1)
    {
        uint16_t page_no_o;/*other page no, page_no_t and page_no_o is neighbor*/

        if(page_no_t & 1)/*page_no_t is odd*/
        {
            page_no_o = page_no_t - 1;
        }
        else /*page_no_t is even*/
        {
            page_no_o = page_no_t + 1;
        }

        /*check its neighbor is free-page or not*/
        if(EC_FALSE == __cxfspgb_page_model_cxfspgrb_bitmap_is(cxfspgb, page_model_t, page_no_o, (uint8_t)1))
        {
            break;
        }

        /*if neighbor is free-page, then delete it and add the two-page as one page in upper page_model*/
        cxfspgb_del_page(cxfspgb, page_model_t, page_no_o);
    }

    if(EC_FALSE == cxfspgb_add_page(cxfspgb, page_model_t, page_no_t))
    {
        dbg_log(SEC_0201_CXFSPGB, 0)(LOGSTDOUT, "error:cxfspgb_recycle_page: add page_no %u to page model %u failed\n", page_no_t, page_model_t);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cxfspgb_new_space(CXFSPGB *cxfspgb, const uint32_t size, uint16_t *page_no)
{
    uint16_t page_num_need;
    uint16_t page_num_left;
    uint16_t page_num_has;
    uint16_t page_model;
    uint16_t e;
    uint16_t t;
    uint16_t page_no_t;/*the page No. in certain page model*/
    uint16_t page_no_start;/*the page No. in page model*/
    uint16_t page_no_end;

    if(CXFSPGB_CACHE_MAX_BYTE_SIZE < size)
    {
        dbg_log(SEC_0201_CXFSPGB, 0)(LOGSTDOUT, "error:cxfspgb_new_space: the expected size %u overflow\n", size);
        return (EC_FALSE);
    }

    page_num_need = (uint16_t)((size + CXFSPGB_PAGE_BYTE_SIZE - 1) >> CXFSPGB_PAGE_BIT_SIZE);
    dbg_log(SEC_0201_CXFSPGB, 9)(LOGSTDOUT, "[DEBUG] cxfspgb_new_space: size = %u ==> page_num_need = %u\n", size, page_num_need);

    /*find a page model which can accept the page_num_need pages */
    /*and then split the left space into page model with smaller size  */

    CXFSPGB_ASSERT(CXFSPGB_064MB_PAGE_NUM >= page_num_need);

    /*check bits of page_num_need and determine the page_model*/
    e = CXFSPGB_PAGE_HI_BIT_MASK;
    for(t = page_num_need, page_model = 0; 0 == (t & e); t <<= 1, page_model ++)
    {
        /*do nothing*/
    }
    dbg_log(SEC_0201_CXFSPGB, 9)(LOGSTDOUT, "[DEBUG] cxfspgb_new_space: t = 0x%x, page_model = %u, e = 0x%x, t << 1 is 0x%x\n", t, page_model, e, (t << 1));

    if(CXFSPGB_PAGE_LO_BITS_MASK & t)
    {
        page_model --;/*upgrade page_model one level*/
    }

    dbg_log(SEC_0201_CXFSPGB, 9)(LOGSTDOUT, "[DEBUG] cxfspgb_new_space: page_num_need = %u ==> page_model = %u (has %u pages)\n",
                       page_num_need, page_model, (uint16_t)(1 << (CXFSPGB_MODEL_NUM - 1 - page_model)));

    page_no_t = cxfspgb_assign_page(cxfspgb, page_model);
    if(CXFSPGRB_ERR_POS == page_no_t)
    {
        dbg_log(SEC_0201_CXFSPGB, 0)(LOGSTDOUT, "error:cxfspgb_new_space: assign one page from page model %u failed\n", page_model);
        return (EC_FALSE);
    }

    dbg_log(SEC_0201_CXFSPGB, 9)(LOGSTDOUT, "[DEBUG] cxfspgb_new_space: assign page_no_t = %u from page_model = %u\n", page_no_t, page_model);

    page_num_has  = (uint16_t)(1 << (CXFSPGB_MODEL_NUM - 1 - page_model));       /*2 ^ (16 - page_model - 1)*/
    page_no_start = (uint16_t)(page_no_t  << (CXFSPGB_MODEL_NUM - 1 - page_model));/*page_no_t * page_num_has*/
    page_no_end   = page_no_start + page_num_has;

    page_num_left = page_num_has - page_num_need;

    dbg_log(SEC_0201_CXFSPGB, 9)(LOGSTDOUT, "[DEBUG] cxfspgb_new_space: page_num_has %u, page_no_start %u, page_no_end %u, page_num_left %u\n",
                        page_num_has, page_no_start, page_no_end, page_num_left);

    /*left pages  are {page_no_end - page_num_left, ...., page_no_end - 1}*/
    /*add the left pages to corresponding page models*/
    //dbg_log(SEC_0201_CXFSPGB, 9)(LOGSTDOUT, "[DEBUG] cxfspgb_new_space: page_num_left = 0x%x bits are\n", page_num_left);
    //c_uint16_hi2lo_header_print(LOGSTDOUT);
    //c_uint16_hi2lo_bits_print(LOGSTDOUT, page_num_left);

    for(t = page_num_left, page_model = CXFSPGB_MODEL_NUM - 1, page_no_t = page_no_start + page_num_need;
        0 < t;
        t >>= 1, page_model --, page_no_t >>= 1
       )
    {
        dbg_log(SEC_0201_CXFSPGB, 9)(LOGSTDOUT, "[DEBUG] cxfspgb_new_space: page_no_t %u, page_model %u\n", page_no_t, page_model);
        if(0 == (t & 1))
        {
            continue;
        }
        dbg_log(SEC_0201_CXFSPGB, 9)(LOGSTDOUT, "[DEBUG] cxfspgb_new_space: add page_no_t %u to page_model %u where t(i.e. cur page_num_left) = %u\n",
                            page_no_t, page_model, t);
        if(EC_FALSE == cxfspgb_recycle_page(cxfspgb, page_model, page_no_t))
        {
            dbg_log(SEC_0201_CXFSPGB, 0)(LOGSTDOUT, "error:cxfspgb_new_space: add page_no_t %u to page_model %u failed !!!\n", page_no_t, page_model);
            //cxfspgb_page_model_print(LOGSTDOUT, cxfspgb, page_model);
        }
        page_no_t ++;
    }

    CXFSPGB_PAGE_USED_NUM(cxfspgb)         += page_num_need;
    CXFSPGB_PAGE_ACTUAL_USED_SIZE(cxfspgb) += size;

    CXFSPGB_ASSERT(EC_TRUE == cxfspgb_check(cxfspgb));
    dbg_log(SEC_0201_CXFSPGB, 9)(LOGSTDOUT, "[DEBUG] cxfspgb_new_space: pgb_page_used_num %u due to increment %u\n",
                        CXFSPGB_PAGE_USED_NUM(cxfspgb), page_num_need);
    dbg_log(SEC_0201_CXFSPGB, 9)(LOGSTDOUT, "[DEBUG] cxfspgb_new_space: pgb_actual_used_size %u due to increment %u\n",
                        CXFSPGB_PAGE_ACTUAL_USED_SIZE(cxfspgb), size);

    CXFSPGB_ASSERT(EC_TRUE == __cxfspgb_check_validity(page_no_start, page_num_need));

    (*page_no) = page_no_start;
    return (EC_TRUE);
}

EC_BOOL cxfspgb_free_space(CXFSPGB *cxfspgb, const uint16_t page_start_no, const uint32_t size)
{
    uint16_t page_num_used;
    uint16_t page_model;
    uint16_t t;
    uint16_t page_no;/*the page No. in certain page model*/

    if(CXFSPGB_CACHE_MAX_BYTE_SIZE < size)
    {
        dbg_log(SEC_0201_CXFSPGB, 0)(LOGSTDOUT, "error:cxfspgb_free_space: invalid size %u due to overflow\n", size);
        return (EC_FALSE);
    }

    page_num_used = (uint16_t)((size + CXFSPGB_PAGE_BYTE_SIZE - 1) >> CXFSPGB_PAGE_BIT_SIZE);
    dbg_log(SEC_0201_CXFSPGB, 9)(LOGSTDOUT, "[DEBUG] cxfspgb_free_space: size = %u ==> page_num_used = %u\n", size, page_num_used);

    /*check validity*/
    if(EC_FALSE == __cxfspgb_check_validity(page_start_no, page_num_used))
    {
        dbg_log(SEC_0201_CXFSPGB, 0)(LOGSTDOUT, "error:cxfspgb_free_space: size %u, page %u => size %u, page num %u is invalid\n",
                                                size, page_start_no, size, page_num_used);
        return (EC_FALSE);
    }

    /*find a page model and recycle the used pages */
    CXFSPGB_ASSERT(CXFSPGB_064MB_PAGE_NUM >= page_num_used);

    for(t = page_num_used, page_model = CXFSPGB_MODEL_NUM - 1, page_no = page_start_no + page_num_used;
        0 < t;
        t >>= 1, page_model --, page_no >>= 1
       )
    {
        dbg_log(SEC_0201_CXFSPGB, 9)(LOGSTDOUT, "[DEBUG] cxfspgb_free_space: page_no %u, page_model %u\n", page_no, page_model);
        if(0 == (t & 1))
        {
            continue;
        }

        page_no --;
        dbg_log(SEC_0201_CXFSPGB, 9)(LOGSTDOUT, "[DEBUG] cxfspgb_free_space: recycle page_no %u to page_model %u where t(i.e. cur page_num_used) = %u\n",
                            page_no, page_model, t);
        if(EC_FALSE == cxfspgb_recycle_page(cxfspgb, page_model, page_no))
        {
            dbg_log(SEC_0201_CXFSPGB, 0)(LOGSTDOUT, "error:cxfspgb_free_space: recycle page_no %u to page_model %u failed !!!\n", page_no, page_model);
            //cxfspgb_page_model_print(LOGSTDOUT, cxfspgb, page_model);
        }
    }

    dbg_log(SEC_0201_CXFSPGB, 9)(LOGSTDOUT, "[DEBUG] cxfspgb_free_space: recycle successfully\n");

    CXFSPGB_PAGE_USED_NUM(cxfspgb)         -= page_num_used;
    CXFSPGB_PAGE_ACTUAL_USED_SIZE(cxfspgb) -= size;
    dbg_log(SEC_0201_CXFSPGB, 9)(LOGSTDOUT, "[DEBUG] cxfspgb_free_space: pgb_page_used_num %u due to decrement %u\n",
                        CXFSPGB_PAGE_USED_NUM(cxfspgb), page_num_used);
    dbg_log(SEC_0201_CXFSPGB, 9)(LOGSTDOUT, "[DEBUG] cxfspgb_free_space: pgb_actual_used_size %u due to decrement %u\n",
                        CXFSPGB_PAGE_ACTUAL_USED_SIZE(cxfspgb), size);

    return (EC_TRUE);
}

EC_BOOL cxfspgb_extract_page(CXFSPGB *cxfspgb, const uint16_t page_model, const uint16_t page_no)
{
    uint16_t page_model_t;
    uint16_t page_no_t;
    uint16_t mask;
    uint16_t e;

    page_model_t = page_model;
    page_no_t    = page_no;

    mask = (uint16_t)((1 << (page_model + 1)) - 1);
    if(0 == (CXFSPGB_PAGE_MODEL_ASSIGN_BITMAP(cxfspgb) & mask))
    {
        dbg_log(SEC_0201_CXFSPGB, 0)(LOGSTDOUT, "error:cxfspgb_extract_page: page_model = %u where 0 == bitmap %x & mask %x indicates page is not available\n",
                           page_model, CXFSPGB_PAGE_MODEL_ASSIGN_BITMAP(cxfspgb), mask);
        return (EC_FALSE);
    }

    dbg_log(SEC_0201_CXFSPGB, 9)(LOGSTDOUT, "[DEBUG] cxfspgb_extract_page: page_model_t %u, page_no_t %u => \n",
                                            page_model_t, page_no_t);

    e = 1;
    while(CXFSPGB_MODEL_NUM > page_model_t
       && (EC_TRUE == cxfspgrb_tree_is_empty(CXFSPGB_CXFSPGRB_POOL(cxfspgb), CXFSPGB_PAGE_MODEL_CXFSPGRB_ROOT_POS(cxfspgb, page_model_t))
       ||  CXFSPGRB_ERR_POS == cxfspgrb_tree_search_data(CXFSPGB_CXFSPGRB_POOL(cxfspgb), CXFSPGB_PAGE_MODEL_CXFSPGRB_ROOT_POS(cxfspgb, page_model_t), page_no_t))
       )
    {
        page_model_t --;
        page_no_t >>= 1;
        e <<= 1;

        dbg_log(SEC_0201_CXFSPGB, 9)(LOGSTDOUT, "[DEBUG] cxfspgb_extract_page: => page_model_t %u, page_no_t %u\n",
                                                page_model_t, page_no_t);
    }

    if(CXFSPGB_MODEL_NUM <= page_model_t)
    {
        dbg_log(SEC_0201_CXFSPGB, 0)(LOGSTDOUT, "error:cxfspgb_extract_page: no free page %u available from page model %u\n", page_no, page_model);
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfspgb_del_page(cxfspgb, page_model_t, page_no_t))
    {
        dbg_log(SEC_0201_CXFSPGB, 0)(LOGSTDOUT, "error:cxfspgb_extract_page: del page %u from page model %u failed\n", page_no_t, page_model_t);
        return (EC_FALSE);
    }

    /*--- split phase ---*/
    dbg_log(SEC_0201_CXFSPGB, 9)(LOGSTDOUT, "----------------------------------------------------------\n");
    dbg_log(SEC_0201_CXFSPGB, 9)(LOGSTDOUT, "[DEBUG] cxfspgb_extract_page: page_model_t %u, page_model %u ---------\n",
                                            page_model_t, page_model);
    for(e >>= 1; page_model_t ++ < page_model; e >>= 1)
    {
        /*borrow one page from page_model_t and split it into two page and insert into page_model_t - 1*/
        /*page_no_t ==> (2*page_no_t, 2*page_no_t + 1)*/
        page_no_t <<= 1;

        dbg_log(SEC_0201_CXFSPGB, 9)(LOGSTDOUT, "[DEBUG] cxfspgb_extract_page: "
                            "[split] e %u, page_model_t %u, page_no_t %u v.s. page_no %u\n",
                            e, page_model_t, page_no_t, page_no);

        dbg_log(SEC_0201_CXFSPGB, 9)(LOGSTDOUT, "[DEBUG] cxfspgb_extract_page: [split] e         %s\n",
                            c_uint16_t_to_bin_str(e));

        dbg_log(SEC_0201_CXFSPGB, 9)(LOGSTDOUT, "[DEBUG] cxfspgb_extract_page: [split] page_no   %s\n",
                            c_uint16_t_to_bin_str(page_no));

        dbg_log(SEC_0201_CXFSPGB, 9)(LOGSTDOUT, "[DEBUG] cxfspgb_extract_page: [split] page_no_t %s\n",
                            c_uint16_t_to_bin_str(page_no_t));

        if(e & page_no)
        {
            if(EC_FALSE == cxfspgb_add_page(cxfspgb, page_model_t, page_no_t))
            {
                dbg_log(SEC_0201_CXFSPGB, 0)(LOGSTDOUT, "error:cxfspgb_extract_page: borrowed one page %u from page model %u, "
                                   "but insert the splitted page %u into page model %u failed\n",
                                    (uint16_t)(page_no_t >> 1), (page_model_t - 1), page_no_t, page_model_t);
                dbg_log(SEC_0201_CXFSPGB, 0)(LOGSTDOUT, "error:cxfspgb_extract_page: try to return page %u to page model %u ...\n",
                                    (uint16_t)(page_no_t >> 1), (page_model_t - 1));

                cxfspgb_recycle_page(cxfspgb, (page_model_t - 1), (uint16_t)(page_no_t >> 1));
                return (EC_FALSE);
            }

            page_no_t ++;
        }
        else
        {
            if(EC_FALSE == cxfspgb_add_page(cxfspgb, page_model_t, page_no_t + 1))
            {
                dbg_log(SEC_0201_CXFSPGB, 0)(LOGSTDOUT, "error:cxfspgb_extract_page: borrowed one page %u from page model %u, "
                                   "but insert the splitted page %u into page model %u failed\n",
                                    (uint16_t)(page_no_t >> 1), (page_model_t - 1), page_no_t + 1, page_model_t);
                dbg_log(SEC_0201_CXFSPGB, 0)(LOGSTDOUT, "error:cxfspgb_extract_page: try to return page %u to page model %u ...\n",
                                    (uint16_t)(page_no_t >> 1), (page_model_t - 1));

                cxfspgb_recycle_page(cxfspgb, (page_model_t - 1), (uint16_t)(page_no_t >> 1));
                return (EC_FALSE);
            }
        }
    }

    if(page_no_t != page_no)
    {
        /*should never reach here*/
        dbg_log(SEC_0201_CXFSPGB, 0)(LOGSTDOUT, "error:cxfspgb_extract_page: page model %u, page_no_t %u != page_no %u\n",
                                                page_model, page_no_t, page_no);

        cxfspgb_recycle_page(cxfspgb, page_model, page_no_t);

        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/*reserve specific page*/
EC_BOOL cxfspgb_reserve_page(CXFSPGB *cxfspgb, const uint32_t size, const uint16_t page_no)
{
    uint16_t page_num_need;
    uint16_t page_num_left;
    uint16_t page_num_has;
    uint16_t page_model;
    uint16_t e;
    uint16_t t;
    uint16_t page_no_t;
    uint16_t page_no_start;/*the page No. in page model*/
    uint16_t page_no_end;

    if(CXFSPGB_CACHE_MAX_BYTE_SIZE < size)
    {
        dbg_log(SEC_0201_CXFSPGB, 0)(LOGSTDOUT, "error:cxfspgb_reserve_page: the expected size %u overflow\n", size);
        return (EC_FALSE);
    }

    page_num_need = (uint16_t)((size + CXFSPGB_PAGE_BYTE_SIZE - 1) >> CXFSPGB_PAGE_BIT_SIZE);
    dbg_log(SEC_0201_CXFSPGB, 9)(LOGSTDOUT, "[DEBUG] cxfspgb_reserve_page: size = %u ==> page_num_need = %u\n", size, page_num_need);

    /*check validity*/
    if(EC_FALSE == __cxfspgb_check_validity(page_no, page_num_need))
    {
        dbg_log(SEC_0201_CXFSPGB, 0)(LOGSTDOUT, "error:cxfspgb_reserve_page: size %u, page %u => size %u, page num %u is invalid\n",
                                                size, page_no, size, page_num_need);
        return (EC_FALSE);
    }

    /*find a page model which can accept the page_num_need pages */
    /*and then split the left space into page model with smaller size  */

    CXFSPGB_ASSERT(CXFSPGB_064MB_PAGE_NUM >= page_num_need);

    /*check bits of page_num_need and determine the page_model*/
    e = CXFSPGB_PAGE_HI_BIT_MASK;
    for(t = page_num_need, page_model = 0; 0 == (t & e); t <<= 1, page_model ++)
    {
        /*do nothing*/
    }
    dbg_log(SEC_0201_CXFSPGB, 9)(LOGSTDOUT, "[DEBUG] cxfspgb_reserve_page: t = 0x%x, page_model = %u, e = 0x%x, t << 1 is 0x%x\n", t, page_model, e, (t << 1));

    if(CXFSPGB_PAGE_LO_BITS_MASK & t)
    {
        page_model --;/*upgrade page_model one level*/
    }

    dbg_log(SEC_0201_CXFSPGB, 9)(LOGSTDOUT, "[DEBUG] cxfspgb_reserve_page: page_num_need = %u ==> page_model = %u (has %u pages)\n",
                       page_num_need, page_model, (uint16_t)(1 << (CXFSPGB_MODEL_NUM - 1 - page_model)));

    page_no_t = (uint16_t)(page_no  >> (CXFSPGB_MODEL_NUM - 1 - page_model)); /*page no in specific page model*/
    if(EC_FALSE == cxfspgb_extract_page(cxfspgb, page_model, page_no_t))
    {
        dbg_log(SEC_0201_CXFSPGB, 0)(LOGSTDOUT, "error:cxfspgb_reserve_page: extract page %u from page model %u failed\n", page_no, page_model);
        return (EC_FALSE);
    }

    dbg_log(SEC_0201_CXFSPGB, 9)(LOGSTDOUT, "[DEBUG] cxfspgb_reserve_page: extract page %u from page_model = %u\n", page_no, page_model);

    page_num_has  = (uint16_t)(1 << (CXFSPGB_MODEL_NUM - 1 - page_model));       /*2 ^ (16 - page_model - 1)*/
    page_no_start = (uint16_t)(page_no_t  << (CXFSPGB_MODEL_NUM - 1 - page_model));/*page_no_t * page_num_has*/
    page_no_end   = page_no_start + page_num_has;

    page_num_left = page_num_has - page_num_need;

    dbg_log(SEC_0201_CXFSPGB, 9)(LOGSTDOUT, "[DEBUG] cxfspgb_reserve_page: page_num_has %u, page_no_start %u, page_no_end %u, page_num_left %u\n",
                        page_num_has, page_no_start, page_no_end, page_num_left);

    /*left pages  are {page_no_end - page_num_left, ...., page_no_end - 1}*/
    /*add the left pages to corresponding page models*/
    //dbg_log(SEC_0201_CXFSPGB, 9)(LOGSTDOUT, "[DEBUG] cxfspgb_reserve_page: page_num_left = 0x%x bits are\n", page_num_left);
    //c_uint16_hi2lo_header_print(LOGSTDOUT);
    //c_uint16_hi2lo_bits_print(LOGSTDOUT, page_num_left);

    for(t = page_num_left, page_model = CXFSPGB_MODEL_NUM - 1, page_no_t = page_no_start + page_num_need;
        0 < t;
        t >>= 1, page_model --, page_no_t >>= 1
       )
    {
        dbg_log(SEC_0201_CXFSPGB, 9)(LOGSTDOUT, "[DEBUG] cxfspgb_reserve_page: page_no_t %u, page_model %u\n", page_no_t, page_model);
        if(0 == (t & 1))
        {
            continue;
        }
        dbg_log(SEC_0201_CXFSPGB, 9)(LOGSTDOUT, "[DEBUG] cxfspgb_reserve_page: add page_no_t %u to page_model %u where t(i.e. cur page_num_left) = %u\n",
                            page_no_t, page_model, t);
        if(EC_FALSE == cxfspgb_recycle_page(cxfspgb, page_model, page_no_t))
        {
            dbg_log(SEC_0201_CXFSPGB, 0)(LOGSTDOUT, "error:cxfspgb_reserve_page: add page_no_t %u to page_model %u failed !!!\n", page_no_t, page_model);
            //cxfspgb_page_model_print(LOGSTDOUT, cxfspgb, page_model);
        }
        page_no_t ++;
    }

    CXFSPGB_PAGE_USED_NUM(cxfspgb)         += page_num_need;
    CXFSPGB_PAGE_ACTUAL_USED_SIZE(cxfspgb) += size;

    CXFSPGB_ASSERT(EC_TRUE == cxfspgb_check(cxfspgb));
    dbg_log(SEC_0201_CXFSPGB, 9)(LOGSTDOUT, "[DEBUG] cxfspgb_reserve_page: pgb_page_used_num %u due to increment %u\n",
                        CXFSPGB_PAGE_USED_NUM(cxfspgb), page_num_need);
    dbg_log(SEC_0201_CXFSPGB, 9)(LOGSTDOUT, "[DEBUG] cxfspgb_reserve_page: pgb_actual_used_size %u due to increment %u\n",
                        CXFSPGB_PAGE_ACTUAL_USED_SIZE(cxfspgb), size);

    //(*page_no) = page_no_start;
    return (EC_TRUE);
}

EC_BOOL cxfspgb_release_page(CXFSPGB *cxfspgb, const uint16_t page_no, const uint32_t size)
{
    return cxfspgb_free_space(cxfspgb, page_no, size);
}

/*return true if all pages in block are used, otherwise return false*/
EC_BOOL cxfspgb_is_full(const CXFSPGB *cxfspgb)
{
    if(CXFSPGB_PAGE_USED_NUM(cxfspgb) == CXFSPGB_PAGE_MAX_NUM(cxfspgb))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

/*return true if no page in block is used and block is given, otherwise return false*/
EC_BOOL cxfspgb_is_empty(const CXFSPGB *cxfspgb)
{
    if(0 == CXFSPGB_PAGE_USED_NUM(cxfspgb) && 0 < CXFSPGB_PAGE_MAX_NUM(cxfspgb))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL cxfspgb_check(const CXFSPGB *cxfspgb)
{
    uint16_t  page_model;
    uint16_t  page_free_num;
    EC_BOOL   ret;

    ret = EC_TRUE;

    for(page_model = 0; CXFSPGB_MODEL_NUM > page_model; page_model ++)
    {
        if(EC_FALSE == __cxfspgb_page_model_check(cxfspgb, page_model))
        {
            dbg_log(SEC_0201_CXFSPGB, 5)(LOGSTDOUT, "cxfspgb_check: check page model %u failed\n", page_model);
            ret = EC_FALSE;
        }
        else
        {
            dbg_log(SEC_0201_CXFSPGB, 5)(LOGSTDOUT, "cxfspgb_check: check page model %u successfully\n", page_model);
        }
        dbg_log(SEC_0201_CXFSPGB, 5)(LOGSTDOUT, "----------------------------------------------------------\n");
    }

    page_free_num = 0;
    for(page_model = 0; CXFSPGB_MODEL_NUM > page_model; page_model ++)
    {
        page_free_num += (uint16_t)(__cxfspgb_page_model_cxfspgrb_bitmap_count_bits(cxfspgb, page_model) << (CXFSPGB_MODEL_NUM - 1 - page_model));
    }
    dbg_log(SEC_0201_CXFSPGB, 9)(LOGSTDOUT, "[DEBUG] cxfspgb_check: pgc_page_max_num = %u, pgc_page_used_num = %u, counted page_free_num = %u\n",
                        CXFSPGB_PAGE_MAX_NUM(cxfspgb), CXFSPGB_PAGE_USED_NUM(cxfspgb), page_free_num);

    if(CXFSPGB_PAGE_MAX_NUM(cxfspgb) != CXFSPGB_PAGE_USED_NUM(cxfspgb) + page_free_num)
    {
        dbg_log(SEC_0201_CXFSPGB, 5)(LOGSTDOUT, "cxfspgb_check:[FAIL] pgc_page_max_num %u != %u(pgc_page_used_num %u + counted page_free_num %u)\n",
                           CXFSPGB_PAGE_MAX_NUM(cxfspgb),
                           CXFSPGB_PAGE_USED_NUM(cxfspgb) + page_free_num,
                           CXFSPGB_PAGE_USED_NUM(cxfspgb),
                           page_free_num);
        ret = EC_FALSE;
    }
#if 1
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0201_CXFSPGB, 0)(LOGSTDOUT, "error:cxfspgb_check: check cxfspgb %p failed\n", cxfspgb);
    }
    else
    {
        dbg_log(SEC_0201_CXFSPGB, 9)(LOGSTDOUT, "[DEBUG] cxfspgb_check: check cxfspgb %p done\n", cxfspgb);
    }
#endif
    return (ret);
}

void cxfspgb_print(LOG *log, const CXFSPGB *cxfspgb)
{
    uint16_t  page_model;
    REAL      used_size;
    REAL      occupied_size;

#if 1
    for(page_model = 0; CXFSPGB_MODEL_NUM > page_model; page_model ++)
    {
        cxfspgb_page_model_print(log, cxfspgb, page_model);
        sys_log(log, "----------------------------------------------------------\n");
    }
#endif
    used_size     = (0.0 + CXFSPGB_PAGE_ACTUAL_USED_SIZE(cxfspgb));
    occupied_size = (0.0 + CXFSPGB_PAGE_USED_NUM(cxfspgb) * (uint32_t)(1 << CXFSPGB_PAGE_BIT_SIZE));

    sys_log(log, "cxfspgb_print: cxfspgb %p, bitmap buff %p, "
                 "page max num %u, page used num %u, used size %u, ratio %.2f\n",
                 cxfspgb,
                 CXFSPGB_PAGE_MODEL_CXFSPGRB_BITMAP_BUFF(cxfspgb),
                 CXFSPGB_PAGE_MAX_NUM(cxfspgb),
                 CXFSPGB_PAGE_USED_NUM(cxfspgb),
                 CXFSPGB_PAGE_ACTUAL_USED_SIZE(cxfspgb),
                 EC_TRUE == REAL_ISZERO(CMPI_ERROR_MODI, occupied_size) ? 0.0 : (used_size / occupied_size)
                 );

    sys_log(log, "cxfspgb_print: cxfspgb %p, assign bitmap %s \n",
                 cxfspgb,
                 c_uint16_t_to_bin_str(CXFSPGB_PAGE_MODEL_ASSIGN_BITMAP(cxfspgb))
                 );
    for(page_model = 0; CXFSPGB_MODEL_NUM > page_model; page_model ++)
    {
        const CXFSPGB_CONF *cxfspgb_conf;

        cxfspgb_conf = &(g_cxfspgb_conf[ page_model ]);

        if(CXFSPGB_PAGE_MODEL_ASSIGN_BITMAP(cxfspgb) & (1 << page_model))
        {
            sys_log(log, "cxfspgb_print: cxfspgb %p, model %s has page to assign\n", cxfspgb, CXFSPGB_CONF_NAME(cxfspgb_conf));
        }
        else
        {
            sys_log(log, "cxfspgb_print: cxfspgb %p, model %s no  page to assign\n", cxfspgb, CXFSPGB_CONF_NAME(cxfspgb_conf));
        }
    }
    return;
}

/* ---- debug ---- */
EC_BOOL cxfspgb_debug_cmp(const CXFSPGB *cxfspgb_1st, const CXFSPGB *cxfspgb_2nd)
{
    uint16_t page_model;

    /*cxfspgrb pool*/
    if(EC_FALSE == cxfspgrb_debug_cmp(CXFSPGB_CXFSPGRB_POOL(cxfspgb_1st), CXFSPGB_CXFSPGRB_POOL(cxfspgb_2nd)))
    {
        dbg_log(SEC_0201_CXFSPGB, 0)(LOGSTDOUT, "error:cxfspgb_debug_cmp: inconsistent cxfspgrb pool\n");
        return (EC_FALSE);
    }

    /*root pos*/
    for(page_model = 0; CXFSPGB_MODEL_NUM > page_model; page_model ++ )
    {
        uint16_t root_pos_1st;
        uint16_t root_pos_2nd;

        root_pos_1st = CXFSPGB_PAGE_MODEL_CXFSPGRB_ROOT_POS(cxfspgb_1st, page_model);
        root_pos_2nd = CXFSPGB_PAGE_MODEL_CXFSPGRB_ROOT_POS(cxfspgb_2nd, page_model);

        if(root_pos_1st != root_pos_2nd)
        {
            dbg_log(SEC_0201_CXFSPGB, 0)(LOGSTDOUT, "error:cxfspgb_debug_cmp: inconsistent root_pos: %u != %u at page_model %u\n",
                                root_pos_1st, root_pos_2nd, page_model);
            return (EC_FALSE);
        }
    }

    /*rb bitmap*/
    for(page_model = 0; CXFSPGB_MODEL_NUM > page_model; page_model ++ )
    {
        const CXFSPGB_CONF *cxfspgb_conf;
        const uint8_t *pgc_cxfspgrb_bitmap_1st;
        const uint8_t *pgc_cxfspgrb_bitmap_2nd;
        uint16_t   cxfspgrb_bitmap_size;
        uint16_t   cxfspgrb_bitmap_pos;

        cxfspgb_conf = &(g_cxfspgb_conf[ page_model ]);
        cxfspgrb_bitmap_size = CXFSPGB_CONF_CXFSPGRB_BITMAP_SIZE(cxfspgb_conf);

        pgc_cxfspgrb_bitmap_1st = CXFSPGB_PAGE_MODEL_CXFSPGRB_BITMAP(cxfspgb_1st, page_model);
        pgc_cxfspgrb_bitmap_2nd = CXFSPGB_PAGE_MODEL_CXFSPGRB_BITMAP(cxfspgb_2nd, page_model);

        for(cxfspgrb_bitmap_pos = 0; cxfspgrb_bitmap_pos < cxfspgrb_bitmap_size; cxfspgrb_bitmap_pos ++)
        {
            if(pgc_cxfspgrb_bitmap_1st[ cxfspgrb_bitmap_pos ] != pgc_cxfspgrb_bitmap_2nd[ cxfspgrb_bitmap_pos ])
            {
                dbg_log(SEC_0201_CXFSPGB, 0)(LOGSTDOUT, "error:cxfspgb_debug_cmp: inconsistent bitmap at pos %u: %u != %u where page_model %u\n",
                                    cxfspgrb_bitmap_pos,
                                    pgc_cxfspgrb_bitmap_1st[ cxfspgrb_bitmap_pos ], pgc_cxfspgrb_bitmap_2nd[ cxfspgrb_bitmap_pos ],
                                    page_model);
                return (EC_FALSE);
            }
        }
    }

    /*assign bitmap*/
    if(CXFSPGB_PAGE_MODEL_ASSIGN_BITMAP(cxfspgb_1st) != CXFSPGB_PAGE_MODEL_ASSIGN_BITMAP(cxfspgb_1st))
    {
        dbg_log(SEC_0201_CXFSPGB, 0)(LOGSTDOUT, "error:cxfspgb_debug_cmp: inconsistent CXFSPGB_PAGE_MODEL_ASSIGN_BITMAP: %u != %u\n",
                            CXFSPGB_PAGE_MODEL_ASSIGN_BITMAP(cxfspgb_1st), CXFSPGB_PAGE_MODEL_ASSIGN_BITMAP(cxfspgb_2nd));
        return (EC_FALSE);
    }

    /*page max num*/
    if(CXFSPGB_PAGE_MAX_NUM(cxfspgb_1st) != CXFSPGB_PAGE_MAX_NUM(cxfspgb_1st))
    {
        dbg_log(SEC_0201_CXFSPGB, 0)(LOGSTDOUT, "error:cxfspgb_debug_cmp: inconsistent CXFSPGB_PAGE_MAX_NUM: %u != %u\n",
                            CXFSPGB_PAGE_MAX_NUM(cxfspgb_1st), CXFSPGB_PAGE_MAX_NUM(cxfspgb_2nd));
        return (EC_FALSE);
    }

    /*page used num*/
    if(CXFSPGB_PAGE_USED_NUM(cxfspgb_1st) != CXFSPGB_PAGE_USED_NUM(cxfspgb_1st))
    {
        dbg_log(SEC_0201_CXFSPGB, 0)(LOGSTDOUT, "error:cxfspgb_debug_cmp: inconsistent CXFSPGB_PAGE_USED_NUM: %u != %u\n",
                            CXFSPGB_PAGE_USED_NUM(cxfspgb_1st), CXFSPGB_PAGE_USED_NUM(cxfspgb_2nd));
        return (EC_FALSE);
    }

    /*page actual used bytes num*/
    if(CXFSPGB_PAGE_ACTUAL_USED_SIZE(cxfspgb_1st) != CXFSPGB_PAGE_ACTUAL_USED_SIZE(cxfspgb_1st))
    {
        dbg_log(SEC_0201_CXFSPGB, 0)(LOGSTDOUT, "error:cxfspgb_debug_cmp: inconsistent CXFSPGB_PAGE_ACTUAL_USED_SIZE: %u != %u\n",
                            CXFSPGB_PAGE_ACTUAL_USED_SIZE(cxfspgb_1st), CXFSPGB_PAGE_ACTUAL_USED_SIZE(cxfspgb_2nd));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

