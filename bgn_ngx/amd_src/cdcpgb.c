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

#include "cdcpgrb.h"
#include "cdcpgb.h"

/*page-cache block:32MB*/


#if (SWITCH_ON == CDC_ASSERT_SWITCH)
#define CDCPGB_ASSERT(cond)   ASSERT(cond)
#endif/*(SWITCH_ON == CDC_ASSERT_SWITCH)*/

#if (SWITCH_OFF == CDC_ASSERT_SWITCH)
#define CDCPGB_ASSERT(cond)   do{}while(0)
#endif/*(SWITCH_OFF == CDC_ASSERT_SWITCH)*/

static const CDCPGB_CONF g_cdcpgb_conf[] = {
    {"CDCPGB_032MB_MODEL", CDCPGB_032MB_MODEL,  CDCPGB_032MB_BITMAP_SIZE, 0,},
    {"CDCPGB_016MB_MODEL", CDCPGB_016MB_MODEL,  CDCPGB_016MB_BITMAP_SIZE, 0,},
    {"CDCPGB_008MB_MODEL", CDCPGB_008MB_MODEL,  CDCPGB_008MB_BITMAP_SIZE, 0,},
    {"CDCPGB_004MB_MODEL", CDCPGB_004MB_MODEL,  CDCPGB_004MB_BITMAP_SIZE, 0,},
    {"CDCPGB_002MB_MODEL", CDCPGB_002MB_MODEL,  CDCPGB_002MB_BITMAP_SIZE, 0,},
    {"CDCPGB_001MB_MODEL", CDCPGB_001MB_MODEL,  CDCPGB_001MB_BITMAP_SIZE, 0,},
    {"CDCPGB_512KB_MODEL", CDCPGB_512KB_MODEL,  CDCPGB_512KB_BITMAP_SIZE, 0,},
    {"CDCPGB_256KB_MODEL", CDCPGB_256KB_MODEL,  CDCPGB_256KB_BITMAP_SIZE, 0,},
    {"CDCPGB_128KB_MODEL", CDCPGB_128KB_MODEL,  CDCPGB_128KB_BITMAP_SIZE, 0,},
    {"CDCPGB_064KB_MODEL", CDCPGB_064KB_MODEL,  CDCPGB_064KB_BITMAP_SIZE, 0,},
    {"CDCPGB_032KB_MODEL", CDCPGB_032KB_MODEL,  CDCPGB_032KB_BITMAP_SIZE, 0,},
    {"CDCPGB_016KB_MODEL", CDCPGB_016KB_MODEL,  CDCPGB_016KB_BITMAP_SIZE, 0,},
    {"CDCPGB_008KB_MODEL", CDCPGB_008KB_MODEL,  CDCPGB_008KB_BITMAP_SIZE, 0,},
    {"CDCPGB_004KB_MODEL", CDCPGB_004KB_MODEL,  CDCPGB_004KB_BITMAP_SIZE, 0,},
    {"CDCPGB_002KB_MODEL", CDCPGB_002KB_MODEL,  CDCPGB_002KB_BITMAP_SIZE, 0,},
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

static const uint16_t g_cdcpgb_bitmap_offset[] = {
    CDCPGB_RB_BITMAP_OFFSET_OF_032MB_MODEL,
    CDCPGB_RB_BITMAP_OFFSET_OF_016MB_MODEL,
    CDCPGB_RB_BITMAP_OFFSET_OF_008MB_MODEL,
    CDCPGB_RB_BITMAP_OFFSET_OF_004MB_MODEL,
    CDCPGB_RB_BITMAP_OFFSET_OF_002MB_MODEL,
    CDCPGB_RB_BITMAP_OFFSET_OF_001MB_MODEL,
    CDCPGB_RB_BITMAP_OFFSET_OF_512KB_MODEL,
    CDCPGB_RB_BITMAP_OFFSET_OF_256KB_MODEL,
    CDCPGB_RB_BITMAP_OFFSET_OF_128KB_MODEL,
    CDCPGB_RB_BITMAP_OFFSET_OF_064KB_MODEL,
    CDCPGB_RB_BITMAP_OFFSET_OF_032KB_MODEL,
    CDCPGB_RB_BITMAP_OFFSET_OF_016KB_MODEL,
    CDCPGB_RB_BITMAP_OFFSET_OF_008KB_MODEL,
    CDCPGB_RB_BITMAP_OFFSET_OF_004KB_MODEL,
    CDCPGB_RB_BITMAP_OFFSET_OF_002KB_MODEL,
};

STATIC_CAST static EC_BOOL __cdcpgb_page_model_cdcpgrb_bitmap_set(CDCPGB *cdcpgb, const uint16_t page_model, const uint16_t bit_pos)
{
    const CDCPGB_CONF *cdcpgb_conf;
    uint8_t *pgc_cdcpgrb_bitmap;
    uint16_t byte_nth;
    uint16_t bit_nth;

    CDCPGB_ASSERT(CDCPGB_MODEL_NUM > page_model);

    cdcpgb_conf = &(g_cdcpgb_conf[ page_model ]);
    pgc_cdcpgrb_bitmap = CDCPGB_PAGE_MODEL_CDCPGRB_BITMAP(cdcpgb, page_model);

    byte_nth = (bit_pos >> 3); /*bit_pos / 8*/
    bit_nth  = (bit_pos & 7);  /*bit_pos % 8*/

    if(CDCPGB_CONF_CDCPGRB_BITMAP_SIZE(cdcpgb_conf) <= byte_nth)
    {
        dbg_log(SEC_0183_CDCPGB, 0)(LOGSTDOUT, "error:__cdcpgb_page_model_cdcpgrb_bitmap_set: page_model %u, bit_pos %u overflow\n", page_model, bit_pos);
        return (EC_FALSE);
    }

    if(0 != (pgc_cdcpgrb_bitmap[ byte_nth ] & (uint8_t)(1 << bit_nth)))
    {
        dbg_log(SEC_0183_CDCPGB, 0)(LOGSTDOUT, "error:__cdcpgb_page_model_cdcpgrb_bitmap_set: page_model %u, bit_pos %u was already set!\n", page_model, bit_pos);
        return (EC_FALSE);
    }

    pgc_cdcpgrb_bitmap[ byte_nth ] |= (uint8_t)(1 << bit_nth);

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdcpgb_page_model_cdcpgrb_bitmap_clear(CDCPGB *cdcpgb, const uint16_t page_model, const uint16_t bit_pos)
{
    const CDCPGB_CONF *cdcpgb_conf;
    uint8_t *pgc_cdcpgrb_bitmap;
    uint16_t byte_nth;
    uint16_t bit_nth;

    CDCPGB_ASSERT(CDCPGB_MODEL_NUM > page_model);

    cdcpgb_conf = &(g_cdcpgb_conf[ page_model ]);
    pgc_cdcpgrb_bitmap = CDCPGB_PAGE_MODEL_CDCPGRB_BITMAP(cdcpgb, page_model);

    byte_nth = (bit_pos >> 3); /*bit_pos / 8*/
    bit_nth  = (bit_pos & 7);  /*bit_pos % 8*/

    if(CDCPGB_CONF_CDCPGRB_BITMAP_SIZE(cdcpgb_conf) <= byte_nth)
    {
        dbg_log(SEC_0183_CDCPGB, 0)(LOGSTDOUT, "error:__cdcpgb_page_model_cdcpgrb_bitmap_clear: page_model %u, bit_pos %u overflow\n", page_model, bit_pos);
        return (EC_FALSE);
    }

    if(0 == (pgc_cdcpgrb_bitmap[ byte_nth ] & (uint8_t)(1 << bit_nth)))
    {
        dbg_log(SEC_0183_CDCPGB, 0)(LOGSTDOUT, "error:__cdcpgb_page_model_cdcpgrb_bitmap_clear: page_model %u, bit_pos %u was NOT set!\n", page_model, bit_pos);
        return (EC_FALSE);
    }

    pgc_cdcpgrb_bitmap[ byte_nth ] &= (uint8_t)(~(1 << bit_nth));

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdcpgb_page_model_cdcpgrb_bitmap_get(const CDCPGB *cdcpgb, const uint16_t page_model, const uint16_t bit_pos, uint8_t *bit_val)
{
    const CDCPGB_CONF *cdcpgb_conf;
    const uint8_t *pgc_cdcpgrb_bitmap;
    uint16_t byte_nth;
    uint16_t bit_nth;

    CDCPGB_ASSERT(CDCPGB_MODEL_NUM > page_model);

    cdcpgb_conf = &(g_cdcpgb_conf[ page_model ]);
    pgc_cdcpgrb_bitmap = CDCPGB_PAGE_MODEL_CDCPGRB_BITMAP(cdcpgb, page_model);

    byte_nth = (bit_pos >> 3); /*bit_pos / 8*/
    bit_nth  = (bit_pos & 7);  /*bit_pos % 8*/

    if(CDCPGB_CONF_CDCPGRB_BITMAP_SIZE(cdcpgb_conf) <= byte_nth)
    {
        dbg_log(SEC_0183_CDCPGB, 0)(LOGSTDOUT, "error:__cdcpgb_page_model_cdcpgrb_bitmap_get: page_model %u, bit_pos %u overflow\n", page_model, bit_pos);
        return (EC_FALSE);
    }

    if(0 == (pgc_cdcpgrb_bitmap[ byte_nth ] & (uint8_t)(1 << bit_nth)))
    {
        (*bit_val) = 0;
    }
    else
    {
        (*bit_val) = 1;
    }

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdcpgb_page_model_cdcpgrb_bitmap_is(const CDCPGB *cdcpgb, const uint16_t page_model, const uint16_t bit_pos, const uint8_t bit_val)
{
    const CDCPGB_CONF *cdcpgb_conf;
    const uint8_t *pgc_cdcpgrb_bitmap;
    uint16_t byte_nth;
    uint16_t bit_nth;
    uint8_t  e;

    CDCPGB_ASSERT(CDCPGB_MODEL_NUM > page_model);

    cdcpgb_conf = &(g_cdcpgb_conf[ page_model ]);
    pgc_cdcpgrb_bitmap = CDCPGB_PAGE_MODEL_CDCPGRB_BITMAP(cdcpgb, page_model);

    byte_nth = (bit_pos >> 3); /*bit_pos / 8*/
    bit_nth  = (bit_pos & 7);  /*bit_pos % 8*/

    if(CDCPGB_CONF_CDCPGRB_BITMAP_SIZE(cdcpgb_conf) <= byte_nth)
    {
        dbg_log(SEC_0183_CDCPGB, 0)(LOGSTDOUT, "error:__cdcpgb_page_model_cdcpgrb_bitmap_is: page_model %u, bit_pos %u overflow\n", page_model, bit_pos);
        return (EC_FALSE);
    }

    e = (pgc_cdcpgrb_bitmap[ byte_nth ] & (uint8_t)(1 << bit_nth));

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
STATIC_CAST static EC_BOOL __cdcpgb_page_model_cdcpgrb_bitmap_check(const CDCPGB *cdcpgb, const uint16_t page_model)
{
    const CDCPGB_CONF *cdcpgb_conf;
    const uint8_t *pgc_cdcpgrb_bitmap;
    uint16_t byte_nth;

    CDCPGB_ASSERT(CDCPGB_MODEL_NUM > page_model);

    cdcpgb_conf = &(g_cdcpgb_conf[ page_model ]);
    pgc_cdcpgrb_bitmap = CDCPGB_PAGE_MODEL_CDCPGRB_BITMAP(cdcpgb, page_model);

    for(byte_nth = 0; byte_nth < CDCPGB_CONF_CDCPGRB_BITMAP_SIZE(cdcpgb_conf); byte_nth ++)
    {
        uint8_t byte_val;

        byte_val = pgc_cdcpgrb_bitmap[ byte_nth ];

        /*(0000 0011) = 0x03*/
        /*(0000 1100) = 0x0C*/
        /*(0011 0000) = 0x30*/
        /*(1100 0000) = 0xC0*/
        if(0x03 == (byte_val & 0x03)
        || 0x0C == (byte_val & 0x0C)
        || 0x30 == (byte_val & 0x30)
        || 0xC0 == (byte_val & 0xC0))
        {
            dbg_log(SEC_0183_CDCPGB, 0)(LOGSTDOUT, "error:__cdcpgb_page_model_cdcpgrb_bitmap_check: "
                               "page_model %u found adjacent 2 bits are set"
                               " at %u # byte which is 0x%x\n",
                               page_model, byte_nth, byte_val);
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

STATIC_CAST static void __cdcpgb_page_model_cdcpgrb_bitmap_print(LOG *log, const CDCPGB *cdcpgb, const uint16_t page_model)
{
    const CDCPGB_CONF *cdcpgb_conf;
    const uint8_t *pgc_cdcpgrb_bitmap;
    uint16_t byte_nth;

    CDCPGB_ASSERT(CDCPGB_MODEL_NUM > page_model);

    cdcpgb_conf      = &(g_cdcpgb_conf[ page_model ]);
    pgc_cdcpgrb_bitmap = CDCPGB_PAGE_MODEL_CDCPGRB_BITMAP(cdcpgb, page_model);

    for(byte_nth = 0; byte_nth < CDCPGB_CONF_CDCPGRB_BITMAP_SIZE(cdcpgb_conf); byte_nth ++)
    {
        uint16_t bit_nth;
        uint8_t  bit_val;
        uint8_t  byte_val;

        byte_val = pgc_cdcpgrb_bitmap[ byte_nth ];
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
STATIC_CAST static uint16_t __cdcpgb_page_model_cdcpgrb_bitmap_count_bits(const CDCPGB *cdcpgb, const uint16_t page_model)
{
    const CDCPGB_CONF *cdcpgb_conf;
    const uint8_t *pgc_cdcpgrb_bitmap;
    uint16_t byte_nth;
    uint16_t bits_count;

    CDCPGB_ASSERT(CDCPGB_MODEL_NUM > page_model);

    cdcpgb_conf      = &(g_cdcpgb_conf[ page_model ]);
    pgc_cdcpgrb_bitmap = CDCPGB_PAGE_MODEL_CDCPGRB_BITMAP(cdcpgb, page_model);
    bits_count     = 0;

    for(byte_nth = 0; byte_nth < CDCPGB_CONF_CDCPGRB_BITMAP_SIZE(cdcpgb_conf); byte_nth ++)
    {
        bits_count += g_nbits_per_byte[ pgc_cdcpgrb_bitmap[ byte_nth ] ];
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
STATIC_CAST static uint16_t __cdcpgb_page_model_first_page(const CDCPGB *cdcpgb, const uint16_t page_model)
{
    uint16_t node_pos;
    const CDCPGRB_NODE *node;

    node_pos = cdcpgrb_tree_first_node(CDCPGB_CDCPGRB_POOL(cdcpgb), CDCPGB_PAGE_MODEL_CDCPGRB_ROOT_POS(cdcpgb, page_model));
    if(CDCPGRB_ERR_POS == node_pos)
    {
        dbg_log(SEC_0183_CDCPGB, 0)(LOGSTDOUT, "error:__cdcpgb_page_model_first_page: no free page in page model %u\n", page_model);
        return (CDCPGRB_ERR_POS);
    }

    node = CDCPGRB_POOL_NODE(CDCPGB_CDCPGRB_POOL(cdcpgb), node_pos);
    return (CDCPGRB_NODE_DATA(node));
}

STATIC_CAST static EC_BOOL __cdcpgb_page_model_check(const CDCPGB *cdcpgb, const uint16_t page_model)
{
    uint16_t bits_count;
    uint16_t nodes_count;
    uint16_t root_pos;
    uint16_t node_pos;

    const CDCPGRB_POOL *cdcpgrb_pool;

    cdcpgrb_pool = CDCPGB_CDCPGRB_POOL(cdcpgb);
    root_pos     = CDCPGB_PAGE_MODEL_CDCPGRB_ROOT_POS(cdcpgb, page_model);

    /*check consistency of bit count and node count*/
    bits_count  = __cdcpgb_page_model_cdcpgrb_bitmap_count_bits(cdcpgb, page_model);
    nodes_count = cdcpgrb_tree_node_num(CDCPGB_CDCPGRB_POOL(cdcpgb), root_pos);

    if(bits_count != nodes_count)
    {
        dbg_log(SEC_0183_CDCPGB, 9)(LOGSTDOUT, "[DEBUG] __cdcpgb_page_model_check: [FAIL] page model %u found inconsistent where bits_count = %u, but nodes_count = %u\n",
                            page_model, bits_count, nodes_count);
        return (EC_FALSE);
    }

    /*check page no consistency of rbtree and bitmap*/
    for(node_pos = cdcpgrb_tree_first_node(cdcpgrb_pool, root_pos);
         CDCPGRB_ERR_POS != node_pos;
         node_pos = cdcpgrb_tree_next_node(cdcpgrb_pool, node_pos)
       )
    {
        const CDCPGRB_NODE *node;
        uint16_t  page_no;

        node = CDCPGRB_POOL_NODE(cdcpgrb_pool, node_pos);
        if(CDCPGRB_NODE_NOT_USED == CDCPGRB_NODE_USED_FLAG(node))
        {
            dbg_log(SEC_0183_CDCPGB, 9)(LOGSTDOUT, "[DEBUG] error:__cdcpgb_page_model_check: found node at pos %u was not used in page model %u\n",
                                node_pos, page_model);
            return (EC_FALSE);
        }

        page_no = CDCPGRB_NODE_DATA(node);
        if(EC_FALSE == __cdcpgb_page_model_cdcpgrb_bitmap_is(cdcpgb, page_model, page_no, (uint8_t) 1))
        {
            dbg_log(SEC_0183_CDCPGB, 9)(LOGSTDOUT, "[DEBUG] __cdcpgb_page_model_check: [FAIL] page model %u found inconsistent "
                               "where page no %u in rbtree without bitmap setting\n",
                                page_model, page_no);
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == __cdcpgb_page_model_cdcpgrb_bitmap_check(cdcpgb, page_model))
    {
        dbg_log(SEC_0183_CDCPGB, 9)(LOGSTDOUT, "[DEBUG] __cdcpgb_page_model_check: [FAIL] page model %u found bitmap invalidity\n",
                            page_model);
        return (EC_FALSE);
    }

    dbg_log(SEC_0183_CDCPGB, 9)(LOGSTDOUT, "[DEBUG] __cdcpgb_page_model_check: [SUCC] page model %u owns %u pages\n", page_model, nodes_count);
    return (EC_TRUE);
}

void cdcpgb_page_model_print(LOG *log, const CDCPGB *cdcpgb, const uint16_t page_model)
{
    const CDCPGRB_POOL *cdcpgrb_pool;
    const CDCPGB_CONF *cdcpgb_conf;
    uint16_t   cdcpgrb_bitmap_size;
    uint16_t   page_num;

    CDCPGB_ASSERT(CDCPGB_MODEL_NUM > page_model);

    cdcpgb_conf         = &(g_cdcpgb_conf[ page_model ]);
    cdcpgrb_pool        = CDCPGB_CDCPGRB_POOL(cdcpgb);
    cdcpgrb_bitmap_size = CDCPGB_CONF_CDCPGRB_BITMAP_SIZE(cdcpgb_conf);
    page_num            = CDCPGB_PAGE_NUM;

    CDCPGB_ASSERT(page_model == CDCPGB_CONF_PAGE_MODEL(cdcpgb_conf));
    sys_log(log, "cdcpgb_page_model_print: page model %u, cdcpgrb_bitmap_size %u, page_num %u\n", page_model, cdcpgrb_bitmap_size, page_num);
    sys_log(log, "cdcpgb_page_model_print: page model %u, rbtree is\n", page_model);
    cdcpgrb_tree_print(log, cdcpgrb_pool, CDCPGB_PAGE_MODEL_CDCPGRB_ROOT_POS(cdcpgb, page_model));
    sys_log(log, "cdcpgb_page_model_print: page model %u, bitmap is\n", page_model);
    __cdcpgb_page_model_cdcpgrb_bitmap_print(log, cdcpgb, page_model);

    return;
}

/* one page block = 32MB */
EC_BOOL cdcpgb_init(CDCPGB *cdcpgb, const uint16_t page_model_target)
{
    uint16_t page_max_num;
    uint16_t page_max_num_t;
    uint16_t page_model;

    if(CDCPGB_MODEL_NUM <= page_model_target)
    {
        dbg_log(SEC_0183_CDCPGB, 0)(LOGSTDOUT, "error:cdcpgb_init: page_model_target %u overflow\n", page_model_target);
        return (EC_FALSE);
    }

    page_max_num = CDCPGB_PAGE_NUM;

    page_max_num_t = ((page_max_num + 1) >> 1); /*optimize, use half of rb nodes to represent all pages*/
    if(EC_FALSE == cdcpgrb_pool_init(CDCPGB_CDCPGRB_POOL(cdcpgb), page_max_num_t))
    {
        dbg_log(SEC_0183_CDCPGB, 0)(LOGSTDOUT, "error:cdcpgb_init: init cdcpgrb pool failed "
                        "where page_max_num_t = %u derived from page_max_num %u\n",
                        page_max_num_t, page_max_num);
        cdcpgb_clean(cdcpgb);
        return (EC_FALSE);
    }
    dbg_log(SEC_0183_CDCPGB, 9)(LOGSTDOUT, "[DEBUG] cdcpgb_init: init cdcpgrb pool done "
                    "where page_max_num_t = %u derived from page_max_num %u\n",
                    page_max_num_t, page_max_num);

    BSET(CDCPGB_PAGE_MODEL_CDCPGRB_BITMAP_BUFF(cdcpgb), CDCPGB_PAGE_IS_NOT_FREE, CDCPGB_RB_BITMAP_SIZE); /*mark as non-free page*/

    for(page_model = 0; CDCPGB_MODEL_MAX_NUM > page_model; page_model ++)
    {
        CDCPGB_PAGE_MODEL_CDCPGRB_ROOT_POS(cdcpgb, page_model) = CDCPGRB_ERR_POS;
    }

    CDCPGB_PAGE_MODEL_ASSIGN_BITMAP(cdcpgb) = 0;

    /*set target model*/
    cdcpgb_add_page(cdcpgb, page_model_target, 0/*page_no*/);

    /*statistics*/
    CDCPGB_PAGE_MAX_NUM(cdcpgb)          = page_max_num;
    CDCPGB_PAGE_USED_NUM(cdcpgb)         = 0;
    CDCPGB_PAGE_ACTUAL_USED_SIZE(cdcpgb) = 0;

    return (EC_TRUE);
}

void cdcpgb_clean(CDCPGB *cdcpgb)
{
    uint16_t page_model;

    cdcpgrb_pool_clean(CDCPGB_CDCPGRB_POOL(cdcpgb));

    for(page_model = 0; CDCPGB_MODEL_MAX_NUM > page_model; page_model ++)
    {
        CDCPGB_PAGE_MODEL_CDCPGRB_ROOT_POS(cdcpgb, page_model) = CDCPGRB_ERR_POS;
        //CDCPGB_PAGE_MODEL_CDCPGRB_BITMAP(cdcpgb, page_model)   = NULL_PTR;
    }

    CDCPGB_PAGE_MODEL_ASSIGN_BITMAP(cdcpgb)     = 0;
    CDCPGB_PAGE_MAX_NUM(cdcpgb)                 = 0;
    CDCPGB_PAGE_USED_NUM(cdcpgb)                = 0;
    CDCPGB_PAGE_ACTUAL_USED_SIZE(cdcpgb)        = 0;
    return;
}

/*add one free page into pool and set page model bitmap*/
EC_BOOL cdcpgb_add_page(CDCPGB *cdcpgb, const uint16_t page_model, const uint16_t page_no)
{
    uint16_t page_no_max;

    CDCPGB_ASSERT(CDCPGB_MODEL_NUM > page_model);

    page_no_max = (uint16_t)(1 << page_model);
    if(page_no >= page_no_max)
    {
        dbg_log(SEC_0183_CDCPGB, 0)(LOGSTDOUT, "error:cdcpgb_add_page: page_no_max %u but page_no to add is %u, overflow!\n", page_no_max, page_no);
        return (EC_FALSE);
    }

    /*insert page_no to bitmap*/
    if(EC_FALSE == __cdcpgb_page_model_cdcpgrb_bitmap_set(cdcpgb, page_model, page_no))
    {
        dbg_log(SEC_0183_CDCPGB, 0)(LOGSTDOUT, "error:cdcpgb_add_page: add page_no %u to bitmap of page model %u failed\n", page_no, page_model);
        return (EC_FALSE);
    }

    /*insert page_no to rbtree*/
    if(CDCPGRB_ERR_POS == cdcpgrb_tree_insert_data(CDCPGB_CDCPGRB_POOL(cdcpgb), &(CDCPGB_PAGE_MODEL_CDCPGRB_ROOT_POS(cdcpgb, page_model)), page_no))
    {
        dbg_log(SEC_0183_CDCPGB, 0)(LOGSTDOUT, "error:cdcpgb_add_page: add page_no %u to rbtree of page model %u failed\n", page_no, page_model);
        __cdcpgb_page_model_cdcpgrb_bitmap_clear(cdcpgb, page_model, page_no);
        return (EC_FALSE);
    }

    /*set assignment bitmap*/
    /*set bits of page_model, page_model + 1, ... page_4k_model, the highest bit is for 2k-page which is not supported,clear it!*/
    CDCPGB_PAGE_MODEL_ASSIGN_BITMAP(cdcpgb) |= (uint16_t)(~((1 << page_model) - 1)) & CDCPGB_MODEL_MASK_ALL;

    return (EC_TRUE);
}

/*del one free page from pool and clear page model bitmap, i.e., del one page from pool and used it later*/
EC_BOOL cdcpgb_del_page(CDCPGB *cdcpgb, const uint16_t page_model, const uint16_t page_no)
{
    uint16_t page_no_max;

    CDCPGB_ASSERT(CDCPGB_MODEL_NUM > page_model);

    page_no_max = (uint16_t)(1 << page_model);

    if(page_no >= page_no_max)
    {
        dbg_log(SEC_0183_CDCPGB, 0)(LOGSTDOUT, "error:cdcpgb_del_page: page_no_max %u but page_no to add is %u, overflow!\n", page_no_max, page_no);
        return (EC_FALSE);
    }

    /*del page_no from rbtree*/
    if(EC_FALSE == cdcpgrb_tree_delete_data(CDCPGB_CDCPGRB_POOL(cdcpgb), &(CDCPGB_PAGE_MODEL_CDCPGRB_ROOT_POS(cdcpgb, page_model)), page_no))
    {
        dbg_log(SEC_0183_CDCPGB, 0)(LOGSTDOUT, "error:cdcpgb_del_page: del page_no %u from rbtree of page model %u failed\n", page_no, page_model);
        return (EC_FALSE);
    }

    /*del page_no from bitmap*/
    if(EC_FALSE == __cdcpgb_page_model_cdcpgrb_bitmap_clear(cdcpgb, page_model, page_no))
    {
        dbg_log(SEC_0183_CDCPGB, 0)(LOGSTDOUT, "error:cdcpgb_del_page: del page_no %u from bitmap of page model %u failed\n", page_no, page_model);
        cdcpgrb_tree_insert_data(CDCPGB_CDCPGRB_POOL(cdcpgb), &(CDCPGB_PAGE_MODEL_CDCPGRB_ROOT_POS(cdcpgb, page_model)), page_no);
        return (EC_FALSE);
    }

    /*clear assignment bitmap if necessary*/
    if(0 == (CDCPGB_PAGE_MODEL_ASSIGN_BITMAP(cdcpgb) & (uint16_t)((1 << page_model) - 1)))/*upper page-model has no page*/
    {
        uint16_t page_model_t;

        page_model_t = page_model;
        while(CDCPGB_MODEL_NUM > page_model_t
           && EC_TRUE == cdcpgrb_tree_is_empty(CDCPGB_CDCPGRB_POOL(cdcpgb), CDCPGB_PAGE_MODEL_CDCPGRB_ROOT_POS(cdcpgb, page_model_t))/*this page-model is empty*/
        )
        {
            CDCPGB_PAGE_MODEL_ASSIGN_BITMAP(cdcpgb) &= (uint16_t)~(1 << page_model_t);/*clear bit*/
            page_model_t ++;
        }
    }

    return (EC_TRUE);
}

uint16_t cdcpgb_assign_page(CDCPGB *cdcpgb, const uint16_t page_model)
{
    uint16_t page_no;
    uint16_t page_model_t;
    uint16_t mask;

    page_model_t = page_model;

    mask = (uint16_t)((1 << (page_model + 1)) - 1);
    if(0 == (CDCPGB_PAGE_MODEL_ASSIGN_BITMAP(cdcpgb) & mask))
    {
        dbg_log(SEC_0183_CDCPGB, 7)(LOGSTDOUT, "error:cdcpgb_assign_page: page_model = %u where 0 == bitmap %x & mask %x indicates page is not available\n",
                           page_model, CDCPGB_PAGE_MODEL_ASSIGN_BITMAP(cdcpgb), mask);
        return (CDCPGRB_ERR_POS);
    }

    while(CDCPGB_MODEL_NUM > page_model_t
       && EC_TRUE == cdcpgrb_tree_is_empty(CDCPGB_CDCPGRB_POOL(cdcpgb), CDCPGB_PAGE_MODEL_CDCPGRB_ROOT_POS(cdcpgb, page_model_t))
       )
    {
        page_model_t --;
    }

    if(CDCPGB_MODEL_NUM <= page_model_t)
    {
        dbg_log(SEC_0183_CDCPGB, 0)(LOGSTDOUT, "error:cdcpgb_assign_page: no free page available from page model %u\n", page_model);
        return (CDCPGRB_ERR_POS);
    }

    page_no = __cdcpgb_page_model_first_page(cdcpgb, page_model_t);
    if(CDCPGRB_ERR_POS == page_no)
    {
        dbg_log(SEC_0183_CDCPGB, 0)(LOGSTDOUT, "error:cdcpgb_assign_page: no free page in page model %u\n", page_model_t);
        return (CDCPGRB_ERR_POS);
    }

    if(EC_FALSE == cdcpgb_del_page(cdcpgb, page_model_t, page_no))
    {
        dbg_log(SEC_0183_CDCPGB, 0)(LOGSTDOUT, "error:cdcpgb_assign_page: del page %u from page model %u failed\n", page_no, page_model_t);
        return (CDCPGRB_ERR_POS);
    }

    /*--- split phase ---*/
    for(; page_model_t ++ < page_model;)
    {
        /*borrow one page from page_model_t and split it into two page and insert into page_model_t - 1*/
        /*page_no ==> (2*page_no, 2*page_no + 1)*/
        page_no <<= 1;

        if(EC_FALSE == cdcpgb_add_page(cdcpgb, page_model_t, page_no + 1))
        {
            dbg_log(SEC_0183_CDCPGB, 0)(LOGSTDOUT, "error:cdcpgb_assign_page: borrowed one page %u from page model %u, "
                               "but insert the splitted page %u into page model %u failed\n",
                                (uint16_t)(page_no >> 1), (page_model_t - 1), page_no + 1, page_model_t);
            dbg_log(SEC_0183_CDCPGB, 0)(LOGSTDOUT, "error:cdcpgb_assign_page: try to return page %u to page model %u ...\n",
                                (uint16_t)(page_no >> 1), (page_model_t - 1));
#if 0
            /*try ...*/
            if(EC_TRUE == cdcpgb_recycle_page(cdcpgb, page_model_t - 1, (uint16_t)(page_no >> 1)))
            {
                dbg_log(SEC_0183_CDCPGB, 0)(LOGSTDOUT, "error:cdcpgb_assign_page: try to recycle page %u to page model %u ... done\n",
                                    (uint16_t)(page_no >> 1), (page_model_t - 1));
            }
            else
            {
                dbg_log(SEC_0183_CDCPGB, 0)(LOGSTDOUT, "error:cdcpgb_assign_page: try to recycle page %u to page model %u ... failed\n",
                                    (uint16_t)(page_no >> 1), (page_model_t - 1));
            }
#endif
            return (CDCPGRB_ERR_POS);
        }
    }

    return (page_no);
}

EC_BOOL cdcpgb_recycle_page(CDCPGB *cdcpgb, const uint16_t page_model, const uint16_t page_no)
{
    //uint8_t *pgc_cdcpgrb_bitmap;
    uint16_t page_no_max;
    uint16_t page_no_t;
    uint16_t page_model_t;

    CDCPGB_ASSERT(CDCPGB_MODEL_NUM > page_model);

    //pgc_cdcpgrb_bitmap = CDCPGB_PAGE_MODEL_CDCPGRB_BITMAP(cdcpgb, page_model);

    page_no_max = (uint16_t)(1 << page_model);
    if(page_no >= page_no_max)
    {
        dbg_log(SEC_0183_CDCPGB, 0)(LOGSTDOUT, "error:cdcpgb_recycle_page: page_no_max %u but page_no to add is %u, overflow!\n", page_no_max, page_no);
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
        if(EC_FALSE == __cdcpgb_page_model_cdcpgrb_bitmap_is(cdcpgb, page_model_t, page_no_o, (uint8_t)1))
        {
            break;
        }

        /*if neighbor is free-page, then delete it and add the two-page as one page in upper page_model*/
        cdcpgb_del_page(cdcpgb, page_model_t, page_no_o);
    }

    if(EC_FALSE == cdcpgb_add_page(cdcpgb, page_model_t, page_no_t))
    {
        dbg_log(SEC_0183_CDCPGB, 0)(LOGSTDOUT, "error:cdcpgb_recycle_page: add page_no %u to page model %u failed\n", page_no_t, page_model_t);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cdcpgb_new_space(CDCPGB *cdcpgb, const uint32_t size, uint16_t *page_no)
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

    if(CDCPGB_SIZE_NBYTES < size)
    {
        dbg_log(SEC_0183_CDCPGB, 0)(LOGSTDOUT, "error:cdcpgb_new_space: the expected size %u overflow\n", size);
        return (EC_FALSE);
    }

    page_num_need = (uint16_t)((size + CDCPGB_PAGE_SIZE_NBYTES - 1) >> CDCPGB_PAGE_SIZE_NBITS);
    dbg_log(SEC_0183_CDCPGB, 9)(LOGSTDOUT, "[DEBUG] cdcpgb_new_space: size = %u ==> page_num_need = %u\n", size, page_num_need);

    /*find a page model which can accept the page_num_need pages */
    /*and then split the left space into page model with smaller size  */

    CDCPGB_ASSERT(CDCPGB_PAGE_NUM >= page_num_need);

    /*check bits of page_num_need and determine the page_model*/
    e = CDCPGB_PAGE_HI_BITS_MASK;
    for(t = page_num_need, page_model = 0; 0 == (t & e); t <<= 1, page_model ++)
    {
        /*do nothing*/
    }
    dbg_log(SEC_0183_CDCPGB, 9)(LOGSTDOUT, "[DEBUG] cdcpgb_new_space: t = 0x%x, page_model = %u, e = 0x%x, t << 1 is 0x%x\n", t, page_model, e, (t << 1));

    if(CDCPGB_PAGE_LO_BITS_MASK & t)
    {
        page_model --;/*upgrade page_model one level*/
    }

    dbg_log(SEC_0183_CDCPGB, 9)(LOGSTDOUT, "[DEBUG] cdcpgb_new_space: page_num_need = %u ==> page_model = %u (has %u pages )\n",
                       page_num_need, page_model, (uint16_t)(1 << (CDCPGB_MODEL_NUM - 1 - page_model)));

    page_no_t = cdcpgb_assign_page(cdcpgb, page_model);
    if(CDCPGRB_ERR_POS == page_no_t)
    {
        dbg_log(SEC_0183_CDCPGB, 0)(LOGSTDOUT, "error:cdcpgb_new_space: assign one page from page model %u failed\n", page_model);
        return (EC_FALSE);
    }

    dbg_log(SEC_0183_CDCPGB, 9)(LOGSTDOUT, "[DEBUG] cdcpgb_new_space: assign page_no_t = %u from page_model = %u\n", page_no_t, page_model);

    page_num_has  = (uint16_t)(1 << (CDCPGB_MODEL_NUM - 1 - page_model));       /*2 ^ (16 - page_model - 1)*/
    page_no_start = (uint16_t)(page_no_t  << (CDCPGB_MODEL_NUM - 1 - page_model));/*page_no_t * page_num_has*/
    page_no_end   = page_no_start + page_num_has;

    page_num_left = page_num_has - page_num_need;

    dbg_log(SEC_0183_CDCPGB, 9)(LOGSTDOUT, "[DEBUG] cdcpgb_new_space: page_num_has %u, page_no_start %u, page_no_end %u, page_num_left %u\n",
                        page_num_has, page_no_start, page_no_end, page_num_left);

    /*left pages  are {page_no_end - page_num_left, ...., page_no_end - 1}*/
    /*add the left pages to corresponding page models*/
    //dbg_log(SEC_0183_CDCPGB, 9)(LOGSTDOUT, "[DEBUG] cdcpgb_new_space: page_num_left = 0x%x bits are\n", page_num_left);
    //c_uint16_hi2lo_header_print(LOGSTDOUT);
    //c_uint16_hi2lo_bits_print(LOGSTDOUT, page_num_left);

    for(t = page_num_left, page_model = CDCPGB_MODEL_NUM - 1, page_no_t = page_no_start + page_num_need;
        0 < t;
        t >>= 1, page_model --, page_no_t >>= 1
       )
    {
        dbg_log(SEC_0183_CDCPGB, 9)(LOGSTDOUT, "[DEBUG] cdcpgb_new_space: page_no_t %u, page_model %u\n", page_no_t, page_model);
        if(0 == (t & 1))
        {
            continue;
        }
        dbg_log(SEC_0183_CDCPGB, 9)(LOGSTDOUT, "[DEBUG] cdcpgb_new_space: add page_no_t %u to page_model %u where t(i.e. cur page_num_left) = %u\n",
                            page_no_t, page_model, t);
        if(EC_FALSE == cdcpgb_recycle_page(cdcpgb, page_model, page_no_t))
        {
            dbg_log(SEC_0183_CDCPGB, 0)(LOGSTDOUT, "error:cdcpgb_new_space: add page_no_t %u to page_model %u failed !!!\n", page_no_t, page_model);
            //cdcpgb_page_model_print(LOGSTDOUT, cdcpgb, page_model);
        }
        page_no_t ++;
    }

    CDCPGB_PAGE_USED_NUM(cdcpgb)         += page_num_need;
    CDCPGB_PAGE_ACTUAL_USED_SIZE(cdcpgb) += size;

    CDCPGB_ASSERT(EC_TRUE == cdcpgb_check(cdcpgb));
    dbg_log(SEC_0183_CDCPGB, 9)(LOGSTDOUT, "[DEBUG] cdcpgb_new_space: pgb_page_used_num %u due to increment %u\n",
                        CDCPGB_PAGE_USED_NUM(cdcpgb), page_num_need);
    dbg_log(SEC_0183_CDCPGB, 9)(LOGSTDOUT, "[DEBUG] cdcpgb_new_space: pgb_actual_used_size %u due to increment %u\n",
                        CDCPGB_PAGE_ACTUAL_USED_SIZE(cdcpgb), size);

    (*page_no) = page_no_start;
    return (EC_TRUE);
}

EC_BOOL cdcpgb_free_space(CDCPGB *cdcpgb, const uint16_t page_start_no, const uint32_t size)
{
    uint16_t page_num_used;
    uint16_t page_model;
    uint16_t t;
    uint16_t page_no;/*the page No. in certain page model*/

    if(CDCPGB_SIZE_NBYTES < size)
    {
        dbg_log(SEC_0183_CDCPGB, 0)(LOGSTDOUT, "error:cdcpgb_free_space: invalid size %u due to overflow\n", size);
        return (EC_FALSE);
    }

    page_num_used = (uint16_t)((size + CDCPGB_PAGE_SIZE_NBYTES - 1) >> CDCPGB_PAGE_SIZE_NBITS);
    dbg_log(SEC_0183_CDCPGB, 9)(LOGSTDOUT, "[DEBUG] cdcpgb_free_space: size = %u ==> page_num_used = %u\n", size, page_num_used);

    /*find a page model and recycle the used pages */
    CDCPGB_ASSERT(CDCPGB_PAGE_NUM >= page_num_used);

    for(t = page_num_used, page_model = CDCPGB_MODEL_NUM - 1, page_no = page_start_no + page_num_used;
        0 < t;
        t >>= 1, page_model --, page_no >>= 1
       )
    {
        dbg_log(SEC_0183_CDCPGB, 9)(LOGSTDOUT, "[DEBUG] cdcpgb_free_space: page_no %u, page_model %u\n", page_no, page_model);
        if(0 == (t & 1))
        {
            continue;
        }

        page_no --;
        dbg_log(SEC_0183_CDCPGB, 9)(LOGSTDOUT, "[DEBUG] cdcpgb_free_space: recycle page_no %u to page_model %u where t(i.e. cur page_num_used) = %u\n",
                            page_no, page_model, t);
        if(EC_FALSE == cdcpgb_recycle_page(cdcpgb, page_model, page_no))
        {
            dbg_log(SEC_0183_CDCPGB, 0)(LOGSTDOUT, "error:cdcpgb_free_space: recycle page_no %u to page_model %u failed !!!\n", page_no, page_model);
            //cdcpgb_page_model_print(LOGSTDOUT, cdcpgb, page_model);
        }
    }

    dbg_log(SEC_0183_CDCPGB, 9)(LOGSTDOUT, "[DEBUG] cdcpgb_free_space: recycle successfully\n");

    CDCPGB_PAGE_USED_NUM(cdcpgb)         -= page_num_used;
    CDCPGB_PAGE_ACTUAL_USED_SIZE(cdcpgb) -= size;
    dbg_log(SEC_0183_CDCPGB, 9)(LOGSTDOUT, "[DEBUG] cdcpgb_free_space: pgb_page_used_num %u due to decrement %u\n",
                        CDCPGB_PAGE_USED_NUM(cdcpgb), page_num_used);
    dbg_log(SEC_0183_CDCPGB, 9)(LOGSTDOUT, "[DEBUG] cdcpgb_free_space: pgb_actual_used_size %u due to decrement %u\n",
                        CDCPGB_PAGE_ACTUAL_USED_SIZE(cdcpgb), size);

    return (EC_TRUE);
}

/*return true if all pages in block are used, otherwise return false*/
EC_BOOL cdcpgb_is_full(const CDCPGB *cdcpgb)
{
    if(CDCPGB_PAGE_USED_NUM(cdcpgb) == CDCPGB_PAGE_MAX_NUM(cdcpgb))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

/*return true if no page in block is used and block is given, otherwise return false*/
EC_BOOL cdcpgb_is_empty(const CDCPGB *cdcpgb)
{
    if(0 == CDCPGB_PAGE_USED_NUM(cdcpgb) && 0 < CDCPGB_PAGE_MAX_NUM(cdcpgb))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL cdcpgb_check(const CDCPGB *cdcpgb)
{
    uint16_t  page_model;
    uint16_t  page_free_num;
    EC_BOOL   ret;

    ret = EC_TRUE;

    for(page_model = 0; CDCPGB_MODEL_NUM > page_model; page_model ++)
    {
        if(EC_FALSE == __cdcpgb_page_model_check(cdcpgb, page_model))
        {
            dbg_log(SEC_0183_CDCPGB, 5)(LOGSTDOUT, "cdcpgb_check: check page model %u failed\n", page_model);
            ret = EC_FALSE;
        }
        else
        {
            dbg_log(SEC_0183_CDCPGB, 5)(LOGSTDOUT, "cdcpgb_check: check page model %u successfully\n", page_model);
        }
        dbg_log(SEC_0183_CDCPGB, 5)(LOGSTDOUT, "----------------------------------------------------------\n");
    }

    page_free_num = 0;
    for(page_model = 0; CDCPGB_MODEL_NUM > page_model; page_model ++)
    {
        uint16_t nbits;
        uint16_t pages;

        nbits = __cdcpgb_page_model_cdcpgrb_bitmap_count_bits(cdcpgb, page_model);
        pages = (uint16_t)(nbits << (CDCPGB_MODEL_NUM - 1 - page_model));
        dbg_log(SEC_0183_CDCPGB, 5)(LOGSTDOUT, "cdcpgb_check: page model %u, free page num %u\n", page_model, pages);

        page_free_num += pages;
    }
    dbg_log(SEC_0183_CDCPGB, 9)(LOGSTDOUT, "[DEBUG] cdcpgb_check: pgc_page_max_num = %u, pgc_page_used_num = %u, counted page_free_num = %u\n",
                        CDCPGB_PAGE_MAX_NUM(cdcpgb), CDCPGB_PAGE_USED_NUM(cdcpgb), page_free_num);

    if(CDCPGB_PAGE_MAX_NUM(cdcpgb) != CDCPGB_PAGE_USED_NUM(cdcpgb) + page_free_num)
    {
        dbg_log(SEC_0183_CDCPGB, 5)(LOGSTDOUT, "cdcpgb_check:[FAIL] pgc_page_max_num %u != %u (pgc_page_used_num %u + counted page_free_num %u)\n",
                           CDCPGB_PAGE_MAX_NUM(cdcpgb),
                           CDCPGB_PAGE_USED_NUM(cdcpgb) + page_free_num,
                           CDCPGB_PAGE_USED_NUM(cdcpgb),
                           page_free_num);
        ret = EC_FALSE;
    }
#if 1
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0183_CDCPGB, 0)(LOGSTDOUT, "error:cdcpgb_check: check cdcpgb %p failed\n", cdcpgb);
    }
    else
    {
        dbg_log(SEC_0183_CDCPGB, 9)(LOGSTDOUT, "[DEBUG] cdcpgb_check: check cdcpgb %p done\n", cdcpgb);
    }
#endif
    return (ret);
}

EC_BOOL cdcpgb_max_size(UINT32 *size)
{
    (*size) += CDCPGB_SIZE;
    return (EC_TRUE);
}

void cdcpgb_print(LOG *log, const CDCPGB *cdcpgb)
{
    uint16_t  page_model;
    REAL      used_size;
    REAL      occupied_size;

#if 0
    for(page_model = 0; CDCPGB_MODEL_NUM > page_model; page_model ++)
    {
        cdcpgb_page_model_print(log, cdcpgb, page_model);
        sys_log(log, "----------------------------------------------------------\n");
    }
#endif
    used_size     = (0.0 + CDCPGB_PAGE_ACTUAL_USED_SIZE(cdcpgb));
    occupied_size = (0.0 + CDCPGB_PAGE_USED_NUM(cdcpgb) * (uint32_t)(1 << CDCPGB_PAGE_SIZE_NBITS));

    sys_log(log, "cdcpgb_print: cdcpgb %p, bitmap buff %p, "
                 "page max num %u, page used num %u, used size %u, ratio %.2f\n",
                 cdcpgb,
                 CDCPGB_PAGE_MODEL_CDCPGRB_BITMAP_BUFF(cdcpgb),
                 CDCPGB_PAGE_MAX_NUM(cdcpgb),
                 CDCPGB_PAGE_USED_NUM(cdcpgb),
                 CDCPGB_PAGE_ACTUAL_USED_SIZE(cdcpgb),
                 EC_TRUE == REAL_ISZERO(CMPI_ERROR_MODI, occupied_size) ? 0.0 : (used_size / occupied_size)
                 );

    sys_log(log, "cdcpgb_print: cdcpgb %p, assign bitmap %s \n",
                 cdcpgb,
                 c_uint16_t_to_bin_str(CDCPGB_PAGE_MODEL_ASSIGN_BITMAP(cdcpgb))
                 );
    for(page_model = 0; CDCPGB_MODEL_NUM > page_model; page_model ++)
    {
        const CDCPGB_CONF *cdcpgb_conf;

        cdcpgb_conf = &(g_cdcpgb_conf[ page_model ]);

        if(CDCPGB_PAGE_MODEL_ASSIGN_BITMAP(cdcpgb) & (1 << page_model))
        {
            sys_log(log, "cdcpgb_print: cdcpgb %p, model %s has page to assign\n", cdcpgb, CDCPGB_CONF_NAME(cdcpgb_conf));
        }
        else
        {
            sys_log(log, "cdcpgb_print: cdcpgb %p, model %s no  page to assign\n", cdcpgb, CDCPGB_CONF_NAME(cdcpgb_conf));
        }
    }
    return;
}

/* ---- debug ---- */
EC_BOOL cdcpgb_debug_cmp(const CDCPGB *cdcpgb_1st, const CDCPGB *cdcpgb_2nd)
{
    uint16_t page_model;

    /*cdcpgrb pool*/
    if(EC_FALSE == cdcpgrb_debug_cmp(CDCPGB_CDCPGRB_POOL(cdcpgb_1st), CDCPGB_CDCPGRB_POOL(cdcpgb_2nd)))
    {
        dbg_log(SEC_0183_CDCPGB, 0)(LOGSTDOUT, "error:cdcpgb_debug_cmp: inconsistent cdcpgrb pool\n");
        return (EC_FALSE);
    }

    /*root pos*/
    for(page_model = 0; CDCPGB_MODEL_NUM > page_model; page_model ++ )
    {
        uint16_t root_pos_1st;
        uint16_t root_pos_2nd;

        root_pos_1st = CDCPGB_PAGE_MODEL_CDCPGRB_ROOT_POS(cdcpgb_1st, page_model);
        root_pos_2nd = CDCPGB_PAGE_MODEL_CDCPGRB_ROOT_POS(cdcpgb_2nd, page_model);

        if(root_pos_1st != root_pos_2nd)
        {
            dbg_log(SEC_0183_CDCPGB, 0)(LOGSTDOUT, "error:cdcpgb_debug_cmp: inconsistent root_pos: %u != %u at page_model %u\n",
                                root_pos_1st, root_pos_2nd, page_model);
            return (EC_FALSE);
        }
    }

    /*rb bitmap*/
    for(page_model = 0; CDCPGB_MODEL_NUM > page_model; page_model ++ )
    {
        const CDCPGB_CONF *cdcpgb_conf;
        const uint8_t *pgc_cdcpgrb_bitmap_1st;
        const uint8_t *pgc_cdcpgrb_bitmap_2nd;
        uint16_t   cdcpgrb_bitmap_size;
        uint16_t   cdcpgrb_bitmap_pos;

        cdcpgb_conf = &(g_cdcpgb_conf[ page_model ]);
        cdcpgrb_bitmap_size = CDCPGB_CONF_CDCPGRB_BITMAP_SIZE(cdcpgb_conf);

        pgc_cdcpgrb_bitmap_1st = CDCPGB_PAGE_MODEL_CDCPGRB_BITMAP(cdcpgb_1st, page_model);
        pgc_cdcpgrb_bitmap_2nd = CDCPGB_PAGE_MODEL_CDCPGRB_BITMAP(cdcpgb_2nd, page_model);

        for(cdcpgrb_bitmap_pos = 0; cdcpgrb_bitmap_pos < cdcpgrb_bitmap_size; cdcpgrb_bitmap_pos ++)
        {
            if(pgc_cdcpgrb_bitmap_1st[ cdcpgrb_bitmap_pos ] != pgc_cdcpgrb_bitmap_2nd[ cdcpgrb_bitmap_pos ])
            {
                dbg_log(SEC_0183_CDCPGB, 0)(LOGSTDOUT, "error:cdcpgb_debug_cmp: inconsistent bitmap at pos %u: %u != %u where page_model %u\n",
                                    cdcpgrb_bitmap_pos,
                                    pgc_cdcpgrb_bitmap_1st[ cdcpgrb_bitmap_pos ], pgc_cdcpgrb_bitmap_2nd[ cdcpgrb_bitmap_pos ],
                                    page_model);
                return (EC_FALSE);
            }
        }
    }

    /*assign bitmap*/
    if(CDCPGB_PAGE_MODEL_ASSIGN_BITMAP(cdcpgb_1st) != CDCPGB_PAGE_MODEL_ASSIGN_BITMAP(cdcpgb_1st))
    {
        dbg_log(SEC_0183_CDCPGB, 0)(LOGSTDOUT, "error:cdcpgb_debug_cmp: inconsistent CDCPGB_PAGE_MODEL_ASSIGN_BITMAP: %u != %u\n",
                            CDCPGB_PAGE_MODEL_ASSIGN_BITMAP(cdcpgb_1st), CDCPGB_PAGE_MODEL_ASSIGN_BITMAP(cdcpgb_2nd));
        return (EC_FALSE);
    }

    /*page max num*/
    if(CDCPGB_PAGE_MAX_NUM(cdcpgb_1st) != CDCPGB_PAGE_MAX_NUM(cdcpgb_1st))
    {
        dbg_log(SEC_0183_CDCPGB, 0)(LOGSTDOUT, "error:cdcpgb_debug_cmp: inconsistent CDCPGB_PAGE_MAX_NUM: %u != %u\n",
                            CDCPGB_PAGE_MAX_NUM(cdcpgb_1st), CDCPGB_PAGE_MAX_NUM(cdcpgb_2nd));
        return (EC_FALSE);
    }

    /*page used num*/
    if(CDCPGB_PAGE_USED_NUM(cdcpgb_1st) != CDCPGB_PAGE_USED_NUM(cdcpgb_1st))
    {
        dbg_log(SEC_0183_CDCPGB, 0)(LOGSTDOUT, "error:cdcpgb_debug_cmp: inconsistent CDCPGB_PAGE_USED_NUM: %u != %u\n",
                            CDCPGB_PAGE_USED_NUM(cdcpgb_1st), CDCPGB_PAGE_USED_NUM(cdcpgb_2nd));
        return (EC_FALSE);
    }

    /*page actual used bytes num*/
    if(CDCPGB_PAGE_ACTUAL_USED_SIZE(cdcpgb_1st) != CDCPGB_PAGE_ACTUAL_USED_SIZE(cdcpgb_1st))
    {
        dbg_log(SEC_0183_CDCPGB, 0)(LOGSTDOUT, "error:cdcpgb_debug_cmp: inconsistent CDCPGB_PAGE_ACTUAL_USED_SIZE: %u != %u\n",
                            CDCPGB_PAGE_ACTUAL_USED_SIZE(cdcpgb_1st), CDCPGB_PAGE_ACTUAL_USED_SIZE(cdcpgb_2nd));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

