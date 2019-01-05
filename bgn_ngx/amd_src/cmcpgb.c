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

#include "cmcpgrb.h"
#include "cmcpgb.h"

/*page-cache block:32MB*/


#if (SWITCH_ON == CMC_ASSERT_SWITCH)
#define CMCPGB_ASSERT(cond)   ASSERT(cond)
#endif/*(SWITCH_ON == CMC_ASSERT_SWITCH)*/

#if (SWITCH_OFF == CMC_ASSERT_SWITCH)
#define CMCPGB_ASSERT(cond)   do{}while(0)
#endif/*(SWITCH_OFF == CMC_ASSERT_SWITCH)*/

static const CMCPGB_CONF g_cmcpgb_conf[] = {
    {"CMCPGB_032MB_MODEL", CMCPGB_032MB_MODEL,  CMCPGB_032MB_BITMAP_SIZE, 0,},
    {"CMCPGB_016MB_MODEL", CMCPGB_016MB_MODEL,  CMCPGB_016MB_BITMAP_SIZE, 0,},
    {"CMCPGB_008MB_MODEL", CMCPGB_008MB_MODEL,  CMCPGB_008MB_BITMAP_SIZE, 0,},
    {"CMCPGB_004MB_MODEL", CMCPGB_004MB_MODEL,  CMCPGB_004MB_BITMAP_SIZE, 0,},
    {"CMCPGB_002MB_MODEL", CMCPGB_002MB_MODEL,  CMCPGB_002MB_BITMAP_SIZE, 0,},
    {"CMCPGB_001MB_MODEL", CMCPGB_001MB_MODEL,  CMCPGB_001MB_BITMAP_SIZE, 0,},
    {"CMCPGB_512KB_MODEL", CMCPGB_512KB_MODEL,  CMCPGB_512KB_BITMAP_SIZE, 0,},
    {"CMCPGB_256KB_MODEL", CMCPGB_256KB_MODEL,  CMCPGB_256KB_BITMAP_SIZE, 0,},
    {"CMCPGB_128KB_MODEL", CMCPGB_128KB_MODEL,  CMCPGB_128KB_BITMAP_SIZE, 0,},
    {"CMCPGB_064KB_MODEL", CMCPGB_064KB_MODEL,  CMCPGB_064KB_BITMAP_SIZE, 0,},
    {"CMCPGB_032KB_MODEL", CMCPGB_032KB_MODEL,  CMCPGB_032KB_BITMAP_SIZE, 0,},
    {"CMCPGB_016KB_MODEL", CMCPGB_016KB_MODEL,  CMCPGB_016KB_BITMAP_SIZE, 0,},
    {"CMCPGB_008KB_MODEL", CMCPGB_008KB_MODEL,  CMCPGB_008KB_BITMAP_SIZE, 0,},
    {"CMCPGB_004KB_MODEL", CMCPGB_004KB_MODEL,  CMCPGB_004KB_BITMAP_SIZE, 0,},
    {"CMCPGB_002KB_MODEL", CMCPGB_002KB_MODEL,  CMCPGB_002KB_BITMAP_SIZE, 0,},
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

static const uint16_t g_cmcpgb_bitmap_offset[] = {
    CMCPGB_RB_BITMAP_OFFSET_OF_032MB_MODEL,
    CMCPGB_RB_BITMAP_OFFSET_OF_016MB_MODEL,
    CMCPGB_RB_BITMAP_OFFSET_OF_008MB_MODEL,
    CMCPGB_RB_BITMAP_OFFSET_OF_004MB_MODEL,
    CMCPGB_RB_BITMAP_OFFSET_OF_002MB_MODEL,
    CMCPGB_RB_BITMAP_OFFSET_OF_001MB_MODEL,
    CMCPGB_RB_BITMAP_OFFSET_OF_512KB_MODEL,
    CMCPGB_RB_BITMAP_OFFSET_OF_256KB_MODEL,
    CMCPGB_RB_BITMAP_OFFSET_OF_128KB_MODEL,
    CMCPGB_RB_BITMAP_OFFSET_OF_064KB_MODEL,
    CMCPGB_RB_BITMAP_OFFSET_OF_032KB_MODEL,
    CMCPGB_RB_BITMAP_OFFSET_OF_016KB_MODEL,
    CMCPGB_RB_BITMAP_OFFSET_OF_008KB_MODEL,
    CMCPGB_RB_BITMAP_OFFSET_OF_004KB_MODEL,
    CMCPGB_RB_BITMAP_OFFSET_OF_002KB_MODEL,
};

STATIC_CAST static EC_BOOL __cmcpgb_page_model_cmcpgrb_bitmap_set(CMCPGB *cmcpgb, const uint16_t page_model, const uint16_t bit_pos)
{
    const CMCPGB_CONF *cmcpgb_conf;
    uint8_t *pgc_cmcpgrb_bitmap;
    uint16_t byte_nth;
    uint16_t bit_nth;

    CMCPGB_ASSERT(CMCPGB_MODEL_NUM > page_model);

    cmcpgb_conf = &(g_cmcpgb_conf[ page_model ]);
    pgc_cmcpgrb_bitmap = CMCPGB_PAGE_MODEL_CMCPGRB_BITMAP(cmcpgb, page_model);

    byte_nth = (bit_pos >> 3); /*bit_pos / 8*/
    bit_nth  = (bit_pos & 7);  /*bit_pos % 8*/

    if(CMCPGB_CONF_CMCPGRB_BITMAP_SIZE(cmcpgb_conf) <= byte_nth)
    {
        dbg_log(SEC_0098_CMCPGB, 0)(LOGSTDOUT, "error:__cmcpgb_page_model_cmcpgrb_bitmap_set: "
                                               "page_model %u, bit_pos %u overflow\n",
                                               page_model, bit_pos);
        return (EC_FALSE);
    }

    if(0 != (pgc_cmcpgrb_bitmap[ byte_nth ] & (uint8_t)(1 << bit_nth)))
    {
        dbg_log(SEC_0098_CMCPGB, 0)(LOGSTDOUT, "error:__cmcpgb_page_model_cmcpgrb_bitmap_set: "
                                               "page_model %u, bit_pos %u was already set!\n",
                                               page_model, bit_pos);
        return (EC_FALSE);
    }

    pgc_cmcpgrb_bitmap[ byte_nth ] |= (uint8_t)(1 << bit_nth);

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cmcpgb_page_model_cmcpgrb_bitmap_clear(CMCPGB *cmcpgb, const uint16_t page_model, const uint16_t bit_pos)
{
    const CMCPGB_CONF *cmcpgb_conf;
    uint8_t *pgc_cmcpgrb_bitmap;
    uint16_t byte_nth;
    uint16_t bit_nth;

    CMCPGB_ASSERT(CMCPGB_MODEL_NUM > page_model);

    cmcpgb_conf = &(g_cmcpgb_conf[ page_model ]);
    pgc_cmcpgrb_bitmap = CMCPGB_PAGE_MODEL_CMCPGRB_BITMAP(cmcpgb, page_model);

    byte_nth = (bit_pos >> 3); /*bit_pos / 8*/
    bit_nth  = (bit_pos & 7);  /*bit_pos % 8*/

    if(CMCPGB_CONF_CMCPGRB_BITMAP_SIZE(cmcpgb_conf) <= byte_nth)
    {
        dbg_log(SEC_0098_CMCPGB, 0)(LOGSTDOUT, "error:__cmcpgb_page_model_cmcpgrb_bitmap_clear: "
                                               "page_model %u, bit_pos %u overflow\n",
                                               page_model, bit_pos);
        return (EC_FALSE);
    }

    if(0 == (pgc_cmcpgrb_bitmap[ byte_nth ] & (uint8_t)(1 << bit_nth)))
    {
        dbg_log(SEC_0098_CMCPGB, 0)(LOGSTDOUT, "error:__cmcpgb_page_model_cmcpgrb_bitmap_clear: "
                                               "page_model %u, bit_pos %u was NOT set!\n",
                                               page_model, bit_pos);
        return (EC_FALSE);
    }

    pgc_cmcpgrb_bitmap[ byte_nth ] &= (uint8_t)(~(1 << bit_nth));

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cmcpgb_page_model_cmcpgrb_bitmap_get(const CMCPGB *cmcpgb, const uint16_t page_model, const uint16_t bit_pos, uint8_t *bit_val)
{
    const CMCPGB_CONF *cmcpgb_conf;
    const uint8_t *pgc_cmcpgrb_bitmap;
    uint16_t byte_nth;
    uint16_t bit_nth;

    CMCPGB_ASSERT(CMCPGB_MODEL_NUM > page_model);

    cmcpgb_conf = &(g_cmcpgb_conf[ page_model ]);
    pgc_cmcpgrb_bitmap = CMCPGB_PAGE_MODEL_CMCPGRB_BITMAP(cmcpgb, page_model);

    byte_nth = (bit_pos >> 3); /*bit_pos / 8*/
    bit_nth  = (bit_pos & 7);  /*bit_pos % 8*/

    if(CMCPGB_CONF_CMCPGRB_BITMAP_SIZE(cmcpgb_conf) <= byte_nth)
    {
        dbg_log(SEC_0098_CMCPGB, 0)(LOGSTDOUT, "error:__cmcpgb_page_model_cmcpgrb_bitmap_get: "
                                               "page_model %u, bit_pos %u overflow\n",
                                               page_model, bit_pos);
        return (EC_FALSE);
    }

    if(0 == (pgc_cmcpgrb_bitmap[ byte_nth ] & (uint8_t)(1 << bit_nth)))
    {
        (*bit_val) = 0;
    }
    else
    {
        (*bit_val) = 1;
    }

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cmcpgb_page_model_cmcpgrb_bitmap_is(const CMCPGB *cmcpgb, const uint16_t page_model, const uint16_t bit_pos, const uint8_t bit_val)
{
    const CMCPGB_CONF *cmcpgb_conf;
    const uint8_t *pgc_cmcpgrb_bitmap;
    uint16_t byte_nth;
    uint16_t bit_nth;
    uint8_t  e;

    CMCPGB_ASSERT(CMCPGB_MODEL_NUM > page_model);

    cmcpgb_conf = &(g_cmcpgb_conf[ page_model ]);
    pgc_cmcpgrb_bitmap = CMCPGB_PAGE_MODEL_CMCPGRB_BITMAP(cmcpgb, page_model);

    byte_nth = (bit_pos >> 3); /*bit_pos / 8*/
    bit_nth  = (bit_pos & 7);  /*bit_pos % 8*/

    if(CMCPGB_CONF_CMCPGRB_BITMAP_SIZE(cmcpgb_conf) <= byte_nth)
    {
        dbg_log(SEC_0098_CMCPGB, 0)(LOGSTDOUT, "error:__cmcpgb_page_model_cmcpgrb_bitmap_is: "
                                               "page_model %u, bit_pos %u overflow\n",
                                               page_model, bit_pos);
        return (EC_FALSE);
    }

    e = (pgc_cmcpgrb_bitmap[ byte_nth ] & (uint8_t)(1 << bit_nth));

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
STATIC_CAST static EC_BOOL __cmcpgb_page_model_cmcpgrb_bitmap_check(const CMCPGB *cmcpgb, const uint16_t page_model)
{
    const CMCPGB_CONF *cmcpgb_conf;
    const uint8_t *pgc_cmcpgrb_bitmap;
    uint16_t byte_nth;

    CMCPGB_ASSERT(CMCPGB_MODEL_NUM > page_model);

    cmcpgb_conf = &(g_cmcpgb_conf[ page_model ]);
    pgc_cmcpgrb_bitmap = CMCPGB_PAGE_MODEL_CMCPGRB_BITMAP(cmcpgb, page_model);

    for(byte_nth = 0; byte_nth < CMCPGB_CONF_CMCPGRB_BITMAP_SIZE(cmcpgb_conf); byte_nth ++)
    {
        uint8_t byte_val;

        byte_val = pgc_cmcpgrb_bitmap[ byte_nth ];

        /*(0000 0011) = 0x03*/
        /*(0000 1100) = 0x0C*/
        /*(0011 0000) = 0x30*/
        /*(1100 0000) = 0xC0*/
        if(0x03 == (byte_val & 0x03)
        || 0x0C == (byte_val & 0x0C)
        || 0x30 == (byte_val & 0x30)
        || 0xC0 == (byte_val & 0xC0))
        {
            dbg_log(SEC_0098_CMCPGB, 0)(LOGSTDOUT, "error:__cmcpgb_page_model_cmcpgrb_bitmap_check: "
                                                   "page_model %u found adjacent 2 bits are set"
                                                   " at %u # byte which is 0x%x\n",
                                                   page_model, byte_nth, byte_val);
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

STATIC_CAST static void __cmcpgb_page_model_cmcpgrb_bitmap_print(LOG *log, const CMCPGB *cmcpgb, const uint16_t page_model)
{
    const CMCPGB_CONF *cmcpgb_conf;
    const uint8_t *pgc_cmcpgrb_bitmap;
    uint16_t byte_nth;

    CMCPGB_ASSERT(CMCPGB_MODEL_NUM > page_model);

    cmcpgb_conf      = &(g_cmcpgb_conf[ page_model ]);
    pgc_cmcpgrb_bitmap = CMCPGB_PAGE_MODEL_CMCPGRB_BITMAP(cmcpgb, page_model);

    for(byte_nth = 0; byte_nth < CMCPGB_CONF_CMCPGRB_BITMAP_SIZE(cmcpgb_conf); byte_nth ++)
    {
        uint16_t bit_nth;
        uint8_t  bit_val;
        uint8_t  byte_val;

        byte_val = pgc_cmcpgrb_bitmap[ byte_nth ];
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
STATIC_CAST static uint16_t __cmcpgb_page_model_cmcpgrb_bitmap_count_bits(const CMCPGB *cmcpgb, const uint16_t page_model)
{
    const CMCPGB_CONF *cmcpgb_conf;
    const uint8_t *pgc_cmcpgrb_bitmap;
    uint16_t byte_nth;
    uint16_t bits_count;

    CMCPGB_ASSERT(CMCPGB_MODEL_NUM > page_model);

    cmcpgb_conf      = &(g_cmcpgb_conf[ page_model ]);
    pgc_cmcpgrb_bitmap = CMCPGB_PAGE_MODEL_CMCPGRB_BITMAP(cmcpgb, page_model);
    bits_count     = 0;

    for(byte_nth = 0; byte_nth < CMCPGB_CONF_CMCPGRB_BITMAP_SIZE(cmcpgb_conf); byte_nth ++)
    {
        bits_count += g_nbits_per_byte[ pgc_cmcpgrb_bitmap[ byte_nth ] ];
    }
    return (bits_count);
}


/**
  return the first page no in current page model.
  e.g.,
  Page Model                2K-Page No.
  2K Model                  00 01 02 03 04 05 06 07 08 ...
  4K Model                  00          01          02 ...
  8K Model                  00                      01 ...

  if the first page address is at 08 2k-page, then
      if page model is 2k model, return 08
      if page model is 4k model, return 02
      if page model is 8k model, return 01
  endif
**/
STATIC_CAST static uint16_t __cmcpgb_page_model_first_page(const CMCPGB *cmcpgb, const uint16_t page_model)
{
    uint16_t node_pos;
    const CMCPGRB_NODE *node;

    node_pos = cmcpgrb_tree_first_node(CMCPGB_CMCPGRB_POOL(cmcpgb), CMCPGB_PAGE_MODEL_CMCPGRB_ROOT_POS(cmcpgb, page_model));
    if(CMCPGRB_ERR_POS == node_pos)
    {
        dbg_log(SEC_0098_CMCPGB, 0)(LOGSTDOUT, "error:__cmcpgb_page_model_first_page: "
                                               "no free page in page model %u\n",
                                               page_model);
        return (CMCPGRB_ERR_POS);
    }

    node = CMCPGRB_POOL_NODE(CMCPGB_CMCPGRB_POOL(cmcpgb), node_pos);
    return (CMCPGRB_NODE_DATA(node));
}

STATIC_CAST static EC_BOOL __cmcpgb_page_model_check(const CMCPGB *cmcpgb, const uint16_t page_model)
{
    uint16_t bits_count;
    uint16_t nodes_count;
    uint16_t root_pos;
    uint16_t node_pos;

    const CMCPGRB_POOL *cmcpgrb_pool;

    cmcpgrb_pool = CMCPGB_CMCPGRB_POOL(cmcpgb);
    root_pos     = CMCPGB_PAGE_MODEL_CMCPGRB_ROOT_POS(cmcpgb, page_model);

    /*check consistency of bit count and node count*/
    bits_count  = __cmcpgb_page_model_cmcpgrb_bitmap_count_bits(cmcpgb, page_model);
    nodes_count = cmcpgrb_tree_node_num(CMCPGB_CMCPGRB_POOL(cmcpgb), root_pos);

    if(bits_count != nodes_count)
    {
        dbg_log(SEC_0098_CMCPGB, 9)(LOGSTDOUT, "[DEBUG] __cmcpgb_page_model_check: "
                                               "[FAIL] page model %u found inconsistent "
                                               "where bits_count = %u, but nodes_count = %u\n",
                                               page_model, bits_count, nodes_count);
        return (EC_FALSE);
    }

    /*check page no consistency of rbtree and bitmap*/
    for(node_pos = cmcpgrb_tree_first_node(cmcpgrb_pool, root_pos);
         CMCPGRB_ERR_POS != node_pos;
         node_pos = cmcpgrb_tree_next_node(cmcpgrb_pool, node_pos)
       )
    {
        const CMCPGRB_NODE *node;
        uint16_t  page_no;

        node = CMCPGRB_POOL_NODE(cmcpgrb_pool, node_pos);
        if(CMCPGRB_NODE_NOT_USED == CMCPGRB_NODE_USED_FLAG(node))
        {
            dbg_log(SEC_0098_CMCPGB, 9)(LOGSTDOUT, "[DEBUG] error:__cmcpgb_page_model_check: "
                                                   "found node at pos %u was not used in page model %u\n",
                                                   node_pos, page_model);
            return (EC_FALSE);
        }

        page_no = CMCPGRB_NODE_DATA(node);
        if(EC_FALSE == __cmcpgb_page_model_cmcpgrb_bitmap_is(cmcpgb, page_model, page_no, (uint8_t) 1))
        {
            dbg_log(SEC_0098_CMCPGB, 9)(LOGSTDOUT, "[DEBUG] __cmcpgb_page_model_check: "
                                                   "[FAIL] page model %u found inconsistent "
                                                   "where page no %u in rbtree without bitmap setting\n",
                                                   page_model, page_no);
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == __cmcpgb_page_model_cmcpgrb_bitmap_check(cmcpgb, page_model))
    {
        dbg_log(SEC_0098_CMCPGB, 9)(LOGSTDOUT, "[DEBUG] __cmcpgb_page_model_check: "
                                               "[FAIL] page model %u found bitmap invalidity\n",
                                               page_model);
        return (EC_FALSE);
    }

    dbg_log(SEC_0098_CMCPGB, 9)(LOGSTDOUT, "[DEBUG] __cmcpgb_page_model_check: "
                                           "[SUCC] page model %u owns %u pages\n",
                                           page_model, nodes_count);
    return (EC_TRUE);
}

void cmcpgb_page_model_print(LOG *log, const CMCPGB *cmcpgb, const uint16_t page_model)
{
    const CMCPGRB_POOL *cmcpgrb_pool;
    const CMCPGB_CONF *cmcpgb_conf;
    uint16_t   cmcpgrb_bitmap_size;
    uint16_t   page_num;

    CMCPGB_ASSERT(CMCPGB_MODEL_NUM > page_model);

    cmcpgb_conf         = &(g_cmcpgb_conf[ page_model ]);
    cmcpgrb_pool        = CMCPGB_CMCPGRB_POOL(cmcpgb);
    cmcpgrb_bitmap_size = CMCPGB_CONF_CMCPGRB_BITMAP_SIZE(cmcpgb_conf);
    page_num            = CMCPGB_PAGE_NUM;

    CMCPGB_ASSERT(page_model == CMCPGB_CONF_PAGE_MODEL(cmcpgb_conf));
    sys_log(log, "cmcpgb_page_model_print: page model %u, cmcpgrb_bitmap_size %u, page_num %u\n",
                 page_model, cmcpgrb_bitmap_size, page_num);

    sys_log(log, "cmcpgb_page_model_print: page model %u, rbtree is\n", page_model);
    cmcpgrb_tree_print(log, cmcpgrb_pool, CMCPGB_PAGE_MODEL_CMCPGRB_ROOT_POS(cmcpgb, page_model));

    sys_log(log, "cmcpgb_page_model_print: page model %u, bitmap is\n", page_model);
    __cmcpgb_page_model_cmcpgrb_bitmap_print(log, cmcpgb, page_model);

    return;
}

/* one page block = 32MB */
EC_BOOL cmcpgb_init(CMCPGB *cmcpgb, const uint16_t page_model_target)
{
    uint16_t page_max_num;
    uint16_t page_max_num_t;
    uint16_t page_model;

    if(CMCPGB_MODEL_NUM <= page_model_target)
    {
        dbg_log(SEC_0098_CMCPGB, 0)(LOGSTDOUT, "error:cmcpgb_init: "
                                               "page_model_target %u overflow\n",
                                               page_model_target);
        return (EC_FALSE);
    }

    page_max_num = CMCPGB_PAGE_NUM;

    page_max_num_t = ((page_max_num + 1) >> 1); /*optimize, use half of rb nodes to represent all pages*/
    if(EC_FALSE == cmcpgrb_pool_init(CMCPGB_CMCPGRB_POOL(cmcpgb), page_max_num_t))
    {
        dbg_log(SEC_0098_CMCPGB, 0)(LOGSTDOUT, "error:cmcpgb_init: "
                                               "init cmcpgrb pool failed "
                                               "where page_max_num_t = %u derived from page_max_num %u\n",
                                               page_max_num_t, page_max_num);
        cmcpgb_clean(cmcpgb);
        return (EC_FALSE);
    }
    dbg_log(SEC_0098_CMCPGB, 9)(LOGSTDOUT, "[DEBUG] cmcpgb_init: "
                                           "init cmcpgrb pool done "
                                           "where page_max_num_t = %u derived from page_max_num %u\n",
                                           page_max_num_t, page_max_num);

    BSET(CMCPGB_PAGE_MODEL_CMCPGRB_BITMAP_BUFF(cmcpgb), CMCPGB_PAGE_IS_NOT_FREE, CMCPGB_RB_BITMAP_SIZE); /*mark as non-free page*/

    for(page_model = 0; CMCPGB_MODEL_MAX_NUM > page_model; page_model ++)
    {
        CMCPGB_PAGE_MODEL_CMCPGRB_ROOT_POS(cmcpgb, page_model) = CMCPGRB_ERR_POS;
    }

    CMCPGB_PAGE_MODEL_ASSIGN_BITMAP(cmcpgb) = 0;

    /*set target model*/
    cmcpgb_add_page(cmcpgb, page_model_target, 0/*page_no*/);

    /*statistics*/
    CMCPGB_PAGE_MAX_NUM(cmcpgb)          = page_max_num;
    CMCPGB_PAGE_USED_NUM(cmcpgb)         = 0;
    CMCPGB_PAGE_ACTUAL_USED_SIZE(cmcpgb) = 0;

    return (EC_TRUE);
}

void cmcpgb_clean(CMCPGB *cmcpgb)
{
    uint16_t page_model;

    cmcpgrb_pool_clean(CMCPGB_CMCPGRB_POOL(cmcpgb));

    for(page_model = 0; CMCPGB_MODEL_MAX_NUM > page_model; page_model ++)
    {
        CMCPGB_PAGE_MODEL_CMCPGRB_ROOT_POS(cmcpgb, page_model) = CMCPGRB_ERR_POS;
        //CMCPGB_PAGE_MODEL_CMCPGRB_BITMAP(cmcpgb, page_model)   = NULL_PTR;
    }

    CMCPGB_PAGE_MODEL_ASSIGN_BITMAP(cmcpgb)     = 0;
    CMCPGB_PAGE_MAX_NUM(cmcpgb)                 = 0;
    CMCPGB_PAGE_USED_NUM(cmcpgb)                = 0;
    CMCPGB_PAGE_ACTUAL_USED_SIZE(cmcpgb)        = 0;
    return;
}

/*add one free page into pool and set page model bitmap*/
EC_BOOL cmcpgb_add_page(CMCPGB *cmcpgb, const uint16_t page_model, const uint16_t page_no)
{
    uint16_t page_no_max;

    CMCPGB_ASSERT(CMCPGB_MODEL_NUM > page_model);

    page_no_max = (uint16_t)(1 << page_model);
    if(page_no >= page_no_max)
    {
        dbg_log(SEC_0098_CMCPGB, 0)(LOGSTDOUT, "error:cmcpgb_add_page: "
                                               "page_no_max %u but page_no to add is %u, overflow!\n",
                                               page_no_max, page_no);
        return (EC_FALSE);
    }

    /*insert page_no to bitmap*/
    if(EC_FALSE == __cmcpgb_page_model_cmcpgrb_bitmap_set(cmcpgb, page_model, page_no))
    {
        dbg_log(SEC_0098_CMCPGB, 0)(LOGSTDOUT, "error:cmcpgb_add_page: "
                                               " page_no %u to bitmap of page model %u failed\n",
                                               page_no, page_model);
        return (EC_FALSE);
    }

    /*insert page_no to rbtree*/
    if(CMCPGRB_ERR_POS == cmcpgrb_tree_insert_data(CMCPGB_CMCPGRB_POOL(cmcpgb), &(CMCPGB_PAGE_MODEL_CMCPGRB_ROOT_POS(cmcpgb, page_model)), page_no))
    {
        dbg_log(SEC_0098_CMCPGB, 0)(LOGSTDOUT, "error:cmcpgb_add_page: "
                                               "add page_no %u to rbtree of page model %u failed\n",
                                               page_no, page_model);
        __cmcpgb_page_model_cmcpgrb_bitmap_clear(cmcpgb, page_model, page_no);
        return (EC_FALSE);
    }

    /*set assignment bitmap*/
    /*set bits of page_model, page_model + 1, ... page_4k_model, the highest bit is for 2k-page which is not supported,clear it!*/
    CMCPGB_PAGE_MODEL_ASSIGN_BITMAP(cmcpgb) |= (uint16_t)(~((1 << page_model) - 1)) & CMCPGB_MODEL_MASK_ALL;

    return (EC_TRUE);
}

/*del one free page from pool and clear page model bitmap, i.e., del one page from pool and used it later*/
EC_BOOL cmcpgb_del_page(CMCPGB *cmcpgb, const uint16_t page_model, const uint16_t page_no)
{
    uint16_t page_no_max;

    CMCPGB_ASSERT(CMCPGB_MODEL_NUM > page_model);

    page_no_max = (uint16_t)(1 << page_model);

    if(page_no >= page_no_max)
    {
        dbg_log(SEC_0098_CMCPGB, 0)(LOGSTDOUT, "error:cmcpgb_del_page: "
                                               "page_no_max %u but page_no to add is %u, overflow!\n",
                                               page_no_max, page_no);
        return (EC_FALSE);
    }

    /*del page_no from rbtree*/
    if(CMCPGRB_ERR_POS == cmcpgrb_tree_delete_data(CMCPGB_CMCPGRB_POOL(cmcpgb), &(CMCPGB_PAGE_MODEL_CMCPGRB_ROOT_POS(cmcpgb, page_model)), page_no))
    {
        dbg_log(SEC_0098_CMCPGB, 0)(LOGSTDOUT, "error:cmcpgb_del_page: "
                                               "del page_no %u from rbtree of page model %u failed\n",
                                               page_no, page_model);
        return (EC_FALSE);
    }

    /*del page_no from bitmap*/
    if(EC_FALSE == __cmcpgb_page_model_cmcpgrb_bitmap_clear(cmcpgb, page_model, page_no))
    {
        dbg_log(SEC_0098_CMCPGB, 0)(LOGSTDOUT, "error:cmcpgb_del_page: "
                                               "del page_no %u from bitmap of page model %u failed\n",
                                               page_no, page_model);
        cmcpgrb_tree_insert_data(CMCPGB_CMCPGRB_POOL(cmcpgb), &(CMCPGB_PAGE_MODEL_CMCPGRB_ROOT_POS(cmcpgb, page_model)), page_no);
        return (EC_FALSE);
    }

    /*clear assignment bitmap if necessary*/
    if(0 == (CMCPGB_PAGE_MODEL_ASSIGN_BITMAP(cmcpgb) & (uint16_t)((1 << page_model) - 1)))/*upper page-model has no page*/
    {
        uint16_t page_model_t;

        page_model_t = page_model;
        while(CMCPGB_MODEL_NUM > page_model_t
           && EC_TRUE == cmcpgrb_tree_is_empty(CMCPGB_CMCPGRB_POOL(cmcpgb), CMCPGB_PAGE_MODEL_CMCPGRB_ROOT_POS(cmcpgb, page_model_t))/*this page-model is empty*/
        )
        {
            CMCPGB_PAGE_MODEL_ASSIGN_BITMAP(cmcpgb) &= (uint16_t)~(1 << page_model_t);/*clear bit*/
            page_model_t ++;
        }
    }

    return (EC_TRUE);
}

uint16_t cmcpgb_assign_page(CMCPGB *cmcpgb, const uint16_t page_model)
{
    uint16_t page_no;
    uint16_t page_model_t;
    uint16_t mask;

    page_model_t = page_model;

    mask = (uint16_t)((1 << (page_model + 1)) - 1);
    if(0 == (CMCPGB_PAGE_MODEL_ASSIGN_BITMAP(cmcpgb) & mask))
    {
        dbg_log(SEC_0098_CMCPGB, 7)(LOGSTDOUT, "error:cmcpgb_assign_page: "
                           "page_model = %u where 0 == bitmap %x & mask %x indicates page is not available\n",
                           page_model, CMCPGB_PAGE_MODEL_ASSIGN_BITMAP(cmcpgb), mask);
        return (CMCPGRB_ERR_POS);
    }

    while(CMCPGB_MODEL_NUM > page_model_t
       && EC_TRUE == cmcpgrb_tree_is_empty(CMCPGB_CMCPGRB_POOL(cmcpgb), CMCPGB_PAGE_MODEL_CMCPGRB_ROOT_POS(cmcpgb, page_model_t))
       )
    {
        page_model_t --;
    }

    if(CMCPGB_MODEL_NUM <= page_model_t)
    {
        dbg_log(SEC_0098_CMCPGB, 0)(LOGSTDOUT, "error:cmcpgb_assign_page: "
                                               "no free page available from page model %u\n",
                                               page_model);
        return (CMCPGRB_ERR_POS);
    }

    page_no = __cmcpgb_page_model_first_page(cmcpgb, page_model_t);
    if(CMCPGRB_ERR_POS == page_no)
    {
        dbg_log(SEC_0098_CMCPGB, 0)(LOGSTDOUT, "error:cmcpgb_assign_page: "
                                               "no free page in page model %u\n",
                                               page_model_t);
        return (CMCPGRB_ERR_POS);
    }

    if(EC_FALSE == cmcpgb_del_page(cmcpgb, page_model_t, page_no))
    {
        dbg_log(SEC_0098_CMCPGB, 0)(LOGSTDOUT, "error:cmcpgb_assign_page: "
                                               "del page %u from page model %u failed\n",
                                               page_no, page_model_t);
        return (CMCPGRB_ERR_POS);
    }

    /*--- split phase ---*/
    for(; page_model_t ++ < page_model;)
    {
        /*borrow one page from page_model_t and split it into two page and insert into page_model_t - 1*/
        /*page_no ==> (2*page_no, 2*page_no + 1)*/
        page_no <<= 1;

        if(EC_FALSE == cmcpgb_add_page(cmcpgb, page_model_t, page_no + 1))
        {
            dbg_log(SEC_0098_CMCPGB, 0)(LOGSTDOUT, "error:cmcpgb_assign_page: "
                           "borrowed one page %u from page model %u, "
                           "but insert the splitted page %u into page model %u failed\n",
                           (uint16_t)(page_no >> 1), (page_model_t - 1), page_no + 1, page_model_t);
            dbg_log(SEC_0098_CMCPGB, 0)(LOGSTDOUT, "error:cmcpgb_assign_page: "
                            "try to return page %u to page model %u ...\n",
                            (uint16_t)(page_no >> 1), (page_model_t - 1));
#if 0
            /*try ...*/
            if(EC_TRUE == cmcpgb_recycle_page(cmcpgb, page_model_t - 1, (uint16_t)(page_no >> 1)))
            {
                dbg_log(SEC_0098_CMCPGB, 0)(LOGSTDOUT, "error:cmcpgb_assign_page: try to recycle page %u to page model %u ... done\n",
                                    (uint16_t)(page_no >> 1), (page_model_t - 1));
            }
            else
            {
                dbg_log(SEC_0098_CMCPGB, 0)(LOGSTDOUT, "error:cmcpgb_assign_page: try to recycle page %u to page model %u ... failed\n",
                                    (uint16_t)(page_no >> 1), (page_model_t - 1));
            }
#endif
            return (CMCPGRB_ERR_POS);
        }
    }

    return (page_no);
}

EC_BOOL cmcpgb_recycle_page(CMCPGB *cmcpgb, const uint16_t page_model, const uint16_t page_no)
{
    //uint8_t *pgc_cmcpgrb_bitmap;
    uint16_t page_no_max;
    uint16_t page_no_t;
    uint16_t page_model_t;

    CMCPGB_ASSERT(CMCPGB_MODEL_NUM > page_model);

    //pgc_cmcpgrb_bitmap = CMCPGB_PAGE_MODEL_CMCPGRB_BITMAP(cmcpgb, page_model);

    page_no_max = (uint16_t)(1 << page_model);
    if(page_no >= page_no_max)
    {
        dbg_log(SEC_0098_CMCPGB, 0)(LOGSTDOUT, "error:cmcpgb_recycle_page: "
                                               "page_no_max %u but page_no to add is %u, overflow!\n",
                                               page_no_max, page_no);
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
        if(EC_FALSE == __cmcpgb_page_model_cmcpgrb_bitmap_is(cmcpgb, page_model_t, page_no_o, (uint8_t)1))
        {
            break;
        }

        /*if neighbor is free-page, then delete it and add the two-page as one page in upper page_model*/
        cmcpgb_del_page(cmcpgb, page_model_t, page_no_o);
    }

    if(EC_FALSE == cmcpgb_add_page(cmcpgb, page_model_t, page_no_t))
    {
        dbg_log(SEC_0098_CMCPGB, 0)(LOGSTDOUT, "error:cmcpgb_recycle_page: "
                                               "add page_no %u to page model %u failed\n",
                                               page_no_t, page_model_t);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cmcpgb_new_space(CMCPGB *cmcpgb, const uint32_t size, uint16_t *page_no)
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

    if(CMCPGB_SIZE_NBYTES < size)
    {
        dbg_log(SEC_0098_CMCPGB, 0)(LOGSTDOUT, "error:cmcpgb_new_space: "
                                               "the expected size %u overflow\n",
                                               size);
        return (EC_FALSE);
    }

    page_num_need = (uint16_t)((size + CMCPGB_PAGE_SIZE_NBYTES - 1) >> CMCPGB_PAGE_SIZE_NBITS);
    dbg_log(SEC_0098_CMCPGB, 9)(LOGSTDOUT, "[DEBUG] cmcpgb_new_space: "
                                           "size = %u ==> page_num_need = %u\n",
                                           size, page_num_need);

    /*find a page model which can accept the page_num_need pages */
    /*and then split the left space into page model with smaller size  */

    CMCPGB_ASSERT(CMCPGB_PAGE_NUM >= page_num_need);

    /*check bits of page_num_need and determine the page_model*/
    e = CMCPGB_PAGE_HI_BITS_MASK;
    for(t = page_num_need, page_model = 0; 0 == (t & e); t <<= 1, page_model ++)
    {
        /*do nothing*/
    }
    dbg_log(SEC_0098_CMCPGB, 9)(LOGSTDOUT, "[DEBUG] cmcpgb_new_space: "
                                           "t = 0x%x, page_model = %u, e = 0x%x, t << 1 is 0x%x\n",
                                           t, page_model, e, (t << 1));

    if(CMCPGB_PAGE_LO_BITS_MASK & t)
    {
        page_model --;/*upgrade page_model one level*/
    }

    dbg_log(SEC_0098_CMCPGB, 9)(LOGSTDOUT, "[DEBUG] cmcpgb_new_space: "
                       "page_num_need = %u ==> page_model = %u (has %u pages )\n",
                       page_num_need, page_model, (uint16_t)(1 << (CMCPGB_MODEL_NUM - 1 - page_model)));

    page_no_t = cmcpgb_assign_page(cmcpgb, page_model);
    if(CMCPGRB_ERR_POS == page_no_t)
    {
        dbg_log(SEC_0098_CMCPGB, 0)(LOGSTDOUT, "error:cmcpgb_new_space: "
                        "assign one page from page model %u failed\n",
                        page_model);
        return (EC_FALSE);
    }

    dbg_log(SEC_0098_CMCPGB, 9)(LOGSTDOUT, "[DEBUG] cmcpgb_new_space: "
                        "assign page_no_t = %u from page_model = %u\n",
                        page_no_t, page_model);

    page_num_has  = (uint16_t)(1 << (CMCPGB_MODEL_NUM - 1 - page_model));       /*2 ^ (16 - page_model - 1)*/
    page_no_start = (uint16_t)(page_no_t  << (CMCPGB_MODEL_NUM - 1 - page_model));/*page_no_t * page_num_has*/
    page_no_end   = page_no_start + page_num_has;

    page_num_left = page_num_has - page_num_need;

    dbg_log(SEC_0098_CMCPGB, 9)(LOGSTDOUT, "[DEBUG] cmcpgb_new_space: "
                        "page_num_has %u, page_no_start %u, page_no_end %u, page_num_left %u\n",
                        page_num_has, page_no_start, page_no_end, page_num_left);

    /*left pages  are {page_no_end - page_num_left, ...., page_no_end - 1}*/
    /*add the left pages to corresponding page models*/
    //dbg_log(SEC_0098_CMCPGB, 9)(LOGSTDOUT, "[DEBUG] cmcpgb_new_space: page_num_left = 0x%x bits are\n", page_num_left);
    //c_uint16_hi2lo_header_print(LOGSTDOUT);
    //c_uint16_hi2lo_bits_print(LOGSTDOUT, page_num_left);

    for(t = page_num_left, page_model = CMCPGB_MODEL_NUM - 1, page_no_t = page_no_start + page_num_need;
        0 < t;
        t >>= 1, page_model --, page_no_t >>= 1
       )
    {
        dbg_log(SEC_0098_CMCPGB, 9)(LOGSTDOUT, "[DEBUG] cmcpgb_new_space: "
                            "page_no_t %u, page_model %u\n",
                            page_no_t, page_model);
        if(0 == (t & 1))
        {
            continue;
        }
        dbg_log(SEC_0098_CMCPGB, 9)(LOGSTDOUT, "[DEBUG] cmcpgb_new_space: "
                            "add page_no_t %u to page_model %u where t(i.e. cur page_num_left) = %u\n",
                            page_no_t, page_model, t);
        if(EC_FALSE == cmcpgb_recycle_page(cmcpgb, page_model, page_no_t))
        {
            dbg_log(SEC_0098_CMCPGB, 0)(LOGSTDOUT, "error:cmcpgb_new_space: "
                                "add page_no_t %u to page_model %u failed !!!\n",
                                page_no_t, page_model);
            //cmcpgb_page_model_print(LOGSTDOUT, cmcpgb, page_model);
        }
        page_no_t ++;
    }

    CMCPGB_PAGE_USED_NUM(cmcpgb)         += page_num_need;
    CMCPGB_PAGE_ACTUAL_USED_SIZE(cmcpgb) += size;

    CMCPGB_ASSERT(EC_TRUE == cmcpgb_check(cmcpgb));
    dbg_log(SEC_0098_CMCPGB, 9)(LOGSTDOUT, "[DEBUG] cmcpgb_new_space: "
                                           "pgb_page_used_num %u due to increment %u\n",
                                           CMCPGB_PAGE_USED_NUM(cmcpgb), page_num_need);

    dbg_log(SEC_0098_CMCPGB, 9)(LOGSTDOUT, "[DEBUG] cmcpgb_new_space: "
                                           "pgb_actual_used_size %u due to increment %u\n",
                                           CMCPGB_PAGE_ACTUAL_USED_SIZE(cmcpgb), size);

    (*page_no) = page_no_start;
    return (EC_TRUE);
}

EC_BOOL cmcpgb_free_space(CMCPGB *cmcpgb, const uint16_t page_start_no, const uint32_t size)
{
    uint16_t page_num_used;
    uint16_t page_model;
    uint16_t t;
    uint16_t page_no;/*the page No. in certain page model*/

    if(CMCPGB_SIZE_NBYTES < size)
    {
        dbg_log(SEC_0098_CMCPGB, 0)(LOGSTDOUT, "error:cmcpgb_free_space: "
                                               "invalid size %u due to overflow\n",
                                               size);
        return (EC_FALSE);
    }

    page_num_used = (uint16_t)((size + CMCPGB_PAGE_SIZE_NBYTES - 1) >> CMCPGB_PAGE_SIZE_NBITS);
    dbg_log(SEC_0098_CMCPGB, 9)(LOGSTDOUT, "[DEBUG] cmcpgb_free_space: "
                                           "size = %u ==> page_num_used = %u\n",
                                           size, page_num_used);

    /*find a page model and recycle the used pages */
    CMCPGB_ASSERT(CMCPGB_PAGE_NUM >= page_num_used);

    for(t = page_num_used, page_model = CMCPGB_MODEL_NUM - 1, page_no = page_start_no + page_num_used;
        0 < t;
        t >>= 1, page_model --, page_no >>= 1
       )
    {
        dbg_log(SEC_0098_CMCPGB, 9)(LOGSTDOUT, "[DEBUG] cmcpgb_free_space: "
                                               "page_no %u, page_model %u\n",
                                               page_no, page_model);
        if(0 == (t & 1))
        {
            continue;
        }

        page_no --;
        dbg_log(SEC_0098_CMCPGB, 9)(LOGSTDOUT, "[DEBUG] cmcpgb_free_space: "
                            "recycle page_no %u to page_model %u where t(i.e. cur page_num_used) = %u\n",
                            page_no, page_model, t);
        if(EC_FALSE == cmcpgb_recycle_page(cmcpgb, page_model, page_no))
        {
            dbg_log(SEC_0098_CMCPGB, 0)(LOGSTDOUT, "error:cmcpgb_free_space: "
                            "recycle page_no %u to page_model %u failed !!!\n",
                            page_no, page_model);
            //cmcpgb_page_model_print(LOGSTDOUT, cmcpgb, page_model);
        }
    }

    dbg_log(SEC_0098_CMCPGB, 9)(LOGSTDOUT, "[DEBUG] cmcpgb_free_space: recycle successfully\n");

    CMCPGB_PAGE_USED_NUM(cmcpgb)         -= page_num_used;
    CMCPGB_PAGE_ACTUAL_USED_SIZE(cmcpgb) -= size;
    dbg_log(SEC_0098_CMCPGB, 9)(LOGSTDOUT, "[DEBUG] cmcpgb_free_space: "
                        "pgb_page_used_num %u due to decrement %u\n",
                        CMCPGB_PAGE_USED_NUM(cmcpgb), page_num_used);
    dbg_log(SEC_0098_CMCPGB, 9)(LOGSTDOUT, "[DEBUG] cmcpgb_free_space: "
                        "pgb_actual_used_size %u due to decrement %u\n",
                        CMCPGB_PAGE_ACTUAL_USED_SIZE(cmcpgb), size);

    return (EC_TRUE);
}

/*return true if all pages in block are used, otherwise return false*/
EC_BOOL cmcpgb_is_full(const CMCPGB *cmcpgb)
{
    if(CMCPGB_PAGE_USED_NUM(cmcpgb) == CMCPGB_PAGE_MAX_NUM(cmcpgb))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

/*return true if no page in block is used and block is given, otherwise return false*/
EC_BOOL cmcpgb_is_empty(const CMCPGB *cmcpgb)
{
    if(0 == CMCPGB_PAGE_USED_NUM(cmcpgb) && 0 < CMCPGB_PAGE_MAX_NUM(cmcpgb))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL cmcpgb_check(const CMCPGB *cmcpgb)
{
    uint16_t  page_model;
    uint16_t  page_free_num;
    EC_BOOL   ret;

    ret = EC_TRUE;

    for(page_model = 0; CMCPGB_MODEL_NUM > page_model; page_model ++)
    {
        if(EC_FALSE == __cmcpgb_page_model_check(cmcpgb, page_model))
        {
            dbg_log(SEC_0098_CMCPGB, 5)(LOGSTDOUT, "cmcpgb_check: check page model %u failed\n",
                                                   page_model);
            ret = EC_FALSE;
        }
        else
        {
            dbg_log(SEC_0098_CMCPGB, 5)(LOGSTDOUT, "cmcpgb_check: check page model %u successfully\n",
                                                   page_model);
        }
        dbg_log(SEC_0098_CMCPGB, 5)(LOGSTDOUT, "----------------------------------------------------------\n");
    }

    page_free_num = 0;
    for(page_model = 0; CMCPGB_MODEL_NUM > page_model; page_model ++)
    {
        uint16_t nbits;
        uint16_t pages;

        nbits = __cmcpgb_page_model_cmcpgrb_bitmap_count_bits(cmcpgb, page_model);
        pages = (uint16_t)(nbits << (CMCPGB_MODEL_NUM - 1 - page_model));
        dbg_log(SEC_0098_CMCPGB, 5)(LOGSTDOUT, "cmcpgb_check: page model %u, free page num %u\n",
                                               page_model, pages);

        page_free_num += pages;
    }
    dbg_log(SEC_0098_CMCPGB, 9)(LOGSTDOUT, "[DEBUG] cmcpgb_check: "
                        "pgc_page_max_num = %u, pgc_page_used_num = %u, counted page_free_num = %u\n",
                        CMCPGB_PAGE_MAX_NUM(cmcpgb), CMCPGB_PAGE_USED_NUM(cmcpgb), page_free_num);

    if(CMCPGB_PAGE_MAX_NUM(cmcpgb) != CMCPGB_PAGE_USED_NUM(cmcpgb) + page_free_num)
    {
        dbg_log(SEC_0098_CMCPGB, 5)(LOGSTDOUT, "cmcpgb_check:"
                       "[FAIL] pgc_page_max_num %u != %u (pgc_page_used_num %u + counted page_free_num %u)\n",
                       CMCPGB_PAGE_MAX_NUM(cmcpgb),
                       CMCPGB_PAGE_USED_NUM(cmcpgb) + page_free_num,
                       CMCPGB_PAGE_USED_NUM(cmcpgb),
                       page_free_num);
        ret = EC_FALSE;
    }
#if 1
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0098_CMCPGB, 0)(LOGSTDOUT, "error:cmcpgb_check: check cmcpgb %p failed\n", cmcpgb);
    }
    else
    {
        dbg_log(SEC_0098_CMCPGB, 9)(LOGSTDOUT, "[DEBUG] cmcpgb_check: check cmcpgb %p done\n", cmcpgb);
    }
#endif
    return (ret);
}

void cmcpgb_print(LOG *log, const CMCPGB *cmcpgb)
{
    uint16_t  page_model;
    REAL      used_size;
    REAL      occupied_size;

#if 0
    for(page_model = 0; CMCPGB_MODEL_NUM > page_model; page_model ++)
    {
        cmcpgb_page_model_print(log, cmcpgb, page_model);
        sys_log(log, "----------------------------------------------------------\n");
    }
#endif
    used_size     = (0.0 + CMCPGB_PAGE_ACTUAL_USED_SIZE(cmcpgb));
    occupied_size = (0.0 + CMCPGB_PAGE_USED_NUM(cmcpgb) * (uint32_t)(1 << CMCPGB_PAGE_SIZE_NBITS));

    sys_log(log, "cmcpgb_print: cmcpgb %p, bitmap buff %p, "
                 "page max num %u, page used num %u, used size %u, ratio %.2f\n",
                 cmcpgb,
                 CMCPGB_PAGE_MODEL_CMCPGRB_BITMAP_BUFF(cmcpgb),
                 CMCPGB_PAGE_MAX_NUM(cmcpgb),
                 CMCPGB_PAGE_USED_NUM(cmcpgb),
                 CMCPGB_PAGE_ACTUAL_USED_SIZE(cmcpgb),
                 EC_TRUE == REAL_ISZERO(CMPI_ERROR_MODI, occupied_size) ? 0.0 : (used_size / occupied_size)
                 );

    sys_log(log, "cmcpgb_print: cmcpgb %p, assign bitmap %s \n",
                 cmcpgb,
                 c_uint16_t_to_bin_str(CMCPGB_PAGE_MODEL_ASSIGN_BITMAP(cmcpgb))
                 );
    for(page_model = 0; CMCPGB_MODEL_NUM > page_model; page_model ++)
    {
        const CMCPGB_CONF *cmcpgb_conf;

        cmcpgb_conf = &(g_cmcpgb_conf[ page_model ]);

        if(CMCPGB_PAGE_MODEL_ASSIGN_BITMAP(cmcpgb) & (1 << page_model))
        {
            sys_log(log, "cmcpgb_print: cmcpgb %p, model %s has page to assign\n",
                         cmcpgb, CMCPGB_CONF_NAME(cmcpgb_conf));
        }
        else
        {
            sys_log(log, "cmcpgb_print: cmcpgb %p, model %s no  page to assign\n",
                         cmcpgb, CMCPGB_CONF_NAME(cmcpgb_conf));
        }
    }
    return;
}

/* ---- debug ---- */
EC_BOOL cmcpgb_debug_cmp(const CMCPGB *cmcpgb_1st, const CMCPGB *cmcpgb_2nd)
{
    uint16_t page_model;

    /*cmcpgrb pool*/
    if(EC_FALSE == cmcpgrb_debug_cmp(CMCPGB_CMCPGRB_POOL(cmcpgb_1st), CMCPGB_CMCPGRB_POOL(cmcpgb_2nd)))
    {
        dbg_log(SEC_0098_CMCPGB, 0)(LOGSTDOUT, "error:cmcpgb_debug_cmp: inconsistent cmcpgrb pool\n");
        return (EC_FALSE);
    }

    /*root pos*/
    for(page_model = 0; CMCPGB_MODEL_NUM > page_model; page_model ++ )
    {
        uint16_t root_pos_1st;
        uint16_t root_pos_2nd;

        root_pos_1st = CMCPGB_PAGE_MODEL_CMCPGRB_ROOT_POS(cmcpgb_1st, page_model);
        root_pos_2nd = CMCPGB_PAGE_MODEL_CMCPGRB_ROOT_POS(cmcpgb_2nd, page_model);

        if(root_pos_1st != root_pos_2nd)
        {
            dbg_log(SEC_0098_CMCPGB, 0)(LOGSTDOUT, "error:cmcpgb_debug_cmp: "
                                "inconsistent root_pos: %u != %u at page_model %u\n",
                                root_pos_1st, root_pos_2nd, page_model);
            return (EC_FALSE);
        }
    }

    /*rb bitmap*/
    for(page_model = 0; CMCPGB_MODEL_NUM > page_model; page_model ++ )
    {
        const CMCPGB_CONF *cmcpgb_conf;
        const uint8_t *pgc_cmcpgrb_bitmap_1st;
        const uint8_t *pgc_cmcpgrb_bitmap_2nd;
        uint16_t   cmcpgrb_bitmap_size;
        uint16_t   cmcpgrb_bitmap_pos;

        cmcpgb_conf = &(g_cmcpgb_conf[ page_model ]);
        cmcpgrb_bitmap_size = CMCPGB_CONF_CMCPGRB_BITMAP_SIZE(cmcpgb_conf);

        pgc_cmcpgrb_bitmap_1st = CMCPGB_PAGE_MODEL_CMCPGRB_BITMAP(cmcpgb_1st, page_model);
        pgc_cmcpgrb_bitmap_2nd = CMCPGB_PAGE_MODEL_CMCPGRB_BITMAP(cmcpgb_2nd, page_model);

        for(cmcpgrb_bitmap_pos = 0; cmcpgrb_bitmap_pos < cmcpgrb_bitmap_size; cmcpgrb_bitmap_pos ++)
        {
            if(pgc_cmcpgrb_bitmap_1st[ cmcpgrb_bitmap_pos ] != pgc_cmcpgrb_bitmap_2nd[ cmcpgrb_bitmap_pos ])
            {
                dbg_log(SEC_0098_CMCPGB, 0)(LOGSTDOUT, "error:cmcpgb_debug_cmp: "
                                    "inconsistent bitmap at pos %u: %u != %u where page_model %u\n",
                                    cmcpgrb_bitmap_pos,
                                    pgc_cmcpgrb_bitmap_1st[ cmcpgrb_bitmap_pos ], pgc_cmcpgrb_bitmap_2nd[ cmcpgrb_bitmap_pos ],
                                    page_model);
                return (EC_FALSE);
            }
        }
    }

    /*assign bitmap*/
    if(CMCPGB_PAGE_MODEL_ASSIGN_BITMAP(cmcpgb_1st) != CMCPGB_PAGE_MODEL_ASSIGN_BITMAP(cmcpgb_1st))
    {
        dbg_log(SEC_0098_CMCPGB, 0)(LOGSTDOUT, "error:cmcpgb_debug_cmp: "
                            "inconsistent CMCPGB_PAGE_MODEL_ASSIGN_BITMAP: %u != %u\n",
                            CMCPGB_PAGE_MODEL_ASSIGN_BITMAP(cmcpgb_1st),
                            CMCPGB_PAGE_MODEL_ASSIGN_BITMAP(cmcpgb_2nd));
        return (EC_FALSE);
    }

    /*page max num*/
    if(CMCPGB_PAGE_MAX_NUM(cmcpgb_1st) != CMCPGB_PAGE_MAX_NUM(cmcpgb_1st))
    {
        dbg_log(SEC_0098_CMCPGB, 0)(LOGSTDOUT, "error:cmcpgb_debug_cmp: "
                            "inconsistent CMCPGB_PAGE_MAX_NUM: %u != %u\n",
                            CMCPGB_PAGE_MAX_NUM(cmcpgb_1st),
                            CMCPGB_PAGE_MAX_NUM(cmcpgb_2nd));
        return (EC_FALSE);
    }

    /*page used num*/
    if(CMCPGB_PAGE_USED_NUM(cmcpgb_1st) != CMCPGB_PAGE_USED_NUM(cmcpgb_1st))
    {
        dbg_log(SEC_0098_CMCPGB, 0)(LOGSTDOUT, "error:cmcpgb_debug_cmp: "
                            "inconsistent CMCPGB_PAGE_USED_NUM: %u != %u\n",
                            CMCPGB_PAGE_USED_NUM(cmcpgb_1st),
                            CMCPGB_PAGE_USED_NUM(cmcpgb_2nd));
        return (EC_FALSE);
    }

    /*page actual used bytes num*/
    if(CMCPGB_PAGE_ACTUAL_USED_SIZE(cmcpgb_1st) != CMCPGB_PAGE_ACTUAL_USED_SIZE(cmcpgb_1st))
    {
        dbg_log(SEC_0098_CMCPGB, 0)(LOGSTDOUT, "error:cmcpgb_debug_cmp: "
                            "inconsistent CMCPGB_PAGE_ACTUAL_USED_SIZE: %u != %u\n",
                            CMCPGB_PAGE_ACTUAL_USED_SIZE(cmcpgb_1st),
                            CMCPGB_PAGE_ACTUAL_USED_SIZE(cmcpgb_2nd));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

