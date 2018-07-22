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

#include "cpgrb.h"
#include "cpgb.h"

/*page-cache block:64MB*/

/************************************************************************************************
  comment:
  ========
   1. if deploy balanced binary tree on cpgb, we can split 64MB block into 2k-page model :-(
      because we can descript parent/left child/right child offset with 16 bits
      red-black tree should record color info, thus we have only 15 bits to descript offset info,
      otherwise, we need more than 256KB to describe the whole page node info if expand CPGRB_NODE
      offset to 16 bits and alignment CPGRB_NODE structer to 8B.
      where 256KB = 2^15 2k-pages * 8B/per-2k-page-record, current 15 bits representation needs
      128KB for 2k-page block.
************************************************************************************************/
#if (SWITCH_ON == CRFS_ASSERT_SWITCH)
#define CPGB_ASSERT(cond)   ASSERT(cond)
#endif/*(SWITCH_ON == CRFS_ASSERT_SWITCH)*/

#if (SWITCH_OFF == CRFS_ASSERT_SWITCH)
#define CPGB_ASSERT(cond)   do{}while(0)
#endif/*(SWITCH_OFF == CRFS_ASSERT_SWITCH)*/

#define ASSERT_CPGB_PAD_SIZE() \
    CPGB_ASSERT( CPGB_PAD_SIZE == (sizeof(CPGB) \
                            - sizeof(CPGRB_POOL) \
                            - CPGB_RB_BITMAP_SIZE \
                            - CPGB_RB_BITMAP_PAD_SIZE \
                            - CPGB_MODEL_NUM *sizeof(uint16_t) \
                            - 3 * sizeof(uint16_t) \
                            - sizeof(uint32_t)) )

static const CPGB_CONF g_cpgb_conf[] = {
    {"CPGB_064MB_MODEL", CPGB_064MB_MODEL,  CPGB_064MB_BITMAP_SIZE, CPGB_064MB_PAGE_NUM, 0,},
    {"CPGB_032MB_MODEL", CPGB_032MB_MODEL,  CPGB_032MB_BITMAP_SIZE, CPGB_032MB_PAGE_NUM, 0,},
    {"CPGB_016MB_MODEL", CPGB_016MB_MODEL,  CPGB_016MB_BITMAP_SIZE, CPGB_016MB_PAGE_NUM, 0,},
    {"CPGB_008MB_MODEL", CPGB_008MB_MODEL,  CPGB_008MB_BITMAP_SIZE, CPGB_008MB_PAGE_NUM, 0,},
    {"CPGB_004MB_MODEL", CPGB_004MB_MODEL,  CPGB_004MB_BITMAP_SIZE, CPGB_004MB_PAGE_NUM, 0,},
    {"CPGB_002MB_MODEL", CPGB_002MB_MODEL,  CPGB_002MB_BITMAP_SIZE, CPGB_002MB_PAGE_NUM, 0,},
    {"CPGB_001MB_MODEL", CPGB_001MB_MODEL,  CPGB_001MB_BITMAP_SIZE, CPGB_001MB_PAGE_NUM, 0,},
    {"CPGB_512KB_MODEL", CPGB_512KB_MODEL,  CPGB_512KB_BITMAP_SIZE, CPGB_512KB_PAGE_NUM, 0,},
    {"CPGB_256KB_MODEL", CPGB_256KB_MODEL,  CPGB_256KB_BITMAP_SIZE, CPGB_256KB_PAGE_NUM, 0,},
    {"CPGB_128KB_MODEL", CPGB_128KB_MODEL,  CPGB_128KB_BITMAP_SIZE, CPGB_128KB_PAGE_NUM, 0,},
    {"CPGB_064KB_MODEL", CPGB_064KB_MODEL,  CPGB_064KB_BITMAP_SIZE, CPGB_064KB_PAGE_NUM, 0,},
    {"CPGB_032KB_MODEL", CPGB_032KB_MODEL,  CPGB_032KB_BITMAP_SIZE, CPGB_032KB_PAGE_NUM, 0,},
    {"CPGB_016KB_MODEL", CPGB_016KB_MODEL,  CPGB_016KB_BITMAP_SIZE, CPGB_016KB_PAGE_NUM, 0,},
    {"CPGB_008KB_MODEL", CPGB_008KB_MODEL,  CPGB_008KB_BITMAP_SIZE, CPGB_008KB_PAGE_NUM, 0,},
    {"CPGB_004KB_MODEL", CPGB_004KB_MODEL,  CPGB_004KB_BITMAP_SIZE, CPGB_004KB_PAGE_NUM, 0,},
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
    CPGB_RB_BITMAP_OFFSET_OF_064MB_MODEL,
    CPGB_RB_BITMAP_OFFSET_OF_032MB_MODEL,
    CPGB_RB_BITMAP_OFFSET_OF_016MB_MODEL,
    CPGB_RB_BITMAP_OFFSET_OF_008MB_MODEL,
    CPGB_RB_BITMAP_OFFSET_OF_004MB_MODEL,
    CPGB_RB_BITMAP_OFFSET_OF_002MB_MODEL,
    CPGB_RB_BITMAP_OFFSET_OF_001MB_MODEL,
    CPGB_RB_BITMAP_OFFSET_OF_512KB_MODEL,
    CPGB_RB_BITMAP_OFFSET_OF_256KB_MODEL,
    CPGB_RB_BITMAP_OFFSET_OF_128KB_MODEL,
    CPGB_RB_BITMAP_OFFSET_OF_064KB_MODEL,
    CPGB_RB_BITMAP_OFFSET_OF_032KB_MODEL,
    CPGB_RB_BITMAP_OFFSET_OF_016KB_MODEL,
    CPGB_RB_BITMAP_OFFSET_OF_008KB_MODEL,
    CPGB_RB_BITMAP_OFFSET_OF_004KB_MODEL,
};

STATIC_CAST static EC_BOOL __cpgb_page_model_cpgrb_bitmap_set(CPGB *cpgb, const uint16_t page_model, const uint16_t bit_pos)
{
    const CPGB_CONF *cpgb_conf;
    uint8_t *pgc_cpgrb_bitmap;
    uint16_t byte_nth;
    uint16_t bit_nth;

    CPGB_ASSERT(CPGB_MODEL_NUM > page_model);

    cpgb_conf = &(g_cpgb_conf[ page_model ]);
    pgc_cpgrb_bitmap = CPGB_PAGE_MODEL_CPGRB_BITMAP(cpgb, page_model);

    byte_nth = (bit_pos >> 3); /*bit_pos / 8*/
    bit_nth  = (bit_pos & 7);  /*bit_pos % 8*/

    if(CPGB_CONF_CPGRB_BITMAP_SIZE(cpgb_conf) <= byte_nth)
    {
        dbg_log(SEC_0122_CPGB, 0)(LOGSTDOUT, "error:__cpgb_page_model_cpgrb_bitmap_set: page_model %u, bit_pos %u overflow\n", page_model, bit_pos);
        return (EC_FALSE);
    }

    if(0 != (pgc_cpgrb_bitmap[ byte_nth ] & (uint8_t)(1 << bit_nth)))
    {
        dbg_log(SEC_0122_CPGB, 0)(LOGSTDOUT, "error:__cpgb_page_model_cpgrb_bitmap_set: page_model %u, bit_pos %u was already set!\n", page_model, bit_pos);
        return (EC_FALSE);
    }

    pgc_cpgrb_bitmap[ byte_nth ] |= (uint8_t)(1 << bit_nth);

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cpgb_page_model_cpgrb_bitmap_clear(CPGB *cpgb, const uint16_t page_model, const uint16_t bit_pos)
{
    const CPGB_CONF *cpgb_conf;
    uint8_t *pgc_cpgrb_bitmap;
    uint16_t byte_nth;
    uint16_t bit_nth;

    CPGB_ASSERT(CPGB_MODEL_NUM > page_model);

    cpgb_conf = &(g_cpgb_conf[ page_model ]);
    pgc_cpgrb_bitmap = CPGB_PAGE_MODEL_CPGRB_BITMAP(cpgb, page_model);

    byte_nth = (bit_pos >> 3); /*bit_pos / 8*/
    bit_nth  = (bit_pos & 7);  /*bit_pos % 8*/

    if(CPGB_CONF_CPGRB_BITMAP_SIZE(cpgb_conf) <= byte_nth)
    {
        dbg_log(SEC_0122_CPGB, 0)(LOGSTDOUT, "error:__cpgb_page_model_cpgrb_bitmap_clear: page_model %u, bit_pos %u overflow\n", page_model, bit_pos);
        return (EC_FALSE);
    }

    if(0 == (pgc_cpgrb_bitmap[ byte_nth ] & (uint8_t)(1 << bit_nth)))
    {
        dbg_log(SEC_0122_CPGB, 0)(LOGSTDOUT, "error:__cpgb_page_model_cpgrb_bitmap_clear: page_model %u, bit_pos %u was NOT set!\n", page_model, bit_pos);
        return (EC_FALSE);
    }

    pgc_cpgrb_bitmap[ byte_nth ] &= (uint8_t)(~(1 << bit_nth));

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cpgb_page_model_cpgrb_bitmap_get(const CPGB *cpgb, const uint16_t page_model, const uint16_t bit_pos, uint8_t *bit_val)
{
    const CPGB_CONF *cpgb_conf;
    const uint8_t *pgc_cpgrb_bitmap;
    uint16_t byte_nth;
    uint16_t bit_nth;

    CPGB_ASSERT(CPGB_MODEL_NUM > page_model);

    cpgb_conf = &(g_cpgb_conf[ page_model ]);
    pgc_cpgrb_bitmap = CPGB_PAGE_MODEL_CPGRB_BITMAP(cpgb, page_model);

    byte_nth = (bit_pos >> 3); /*bit_pos / 8*/
    bit_nth  = (bit_pos & 7);  /*bit_pos % 8*/

    if(CPGB_CONF_CPGRB_BITMAP_SIZE(cpgb_conf) <= byte_nth)
    {
        dbg_log(SEC_0122_CPGB, 0)(LOGSTDOUT, "error:__cpgb_page_model_cpgrb_bitmap_clear: page_model %u, bit_pos %u overflow\n", page_model, bit_pos);
        return (EC_FALSE);
    }

    if(0 == (pgc_cpgrb_bitmap[ byte_nth ] & (uint8_t)(1 << bit_nth)))
    {
        (*bit_val) = 0;
    }
    else
    {
        (*bit_val) = 1;
    }

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cpgb_page_model_cpgrb_bitmap_is(const CPGB *cpgb, const uint16_t page_model, const uint16_t bit_pos, const uint8_t bit_val)
{
    const CPGB_CONF *cpgb_conf;
    const uint8_t *pgc_cpgrb_bitmap;
    uint16_t byte_nth;
    uint16_t bit_nth;
    uint8_t  e;

    CPGB_ASSERT(CPGB_MODEL_NUM > page_model);

    cpgb_conf = &(g_cpgb_conf[ page_model ]);
    pgc_cpgrb_bitmap = CPGB_PAGE_MODEL_CPGRB_BITMAP(cpgb, page_model);

    byte_nth = (bit_pos >> 3); /*bit_pos / 8*/
    bit_nth  = (bit_pos & 7);  /*bit_pos % 8*/

    if(CPGB_CONF_CPGRB_BITMAP_SIZE(cpgb_conf) <= byte_nth)
    {
        dbg_log(SEC_0122_CPGB, 0)(LOGSTDOUT, "error:__cpgb_page_model_cpgrb_bitmap_is: page_model %u, bit_pos %u overflow\n", page_model, bit_pos);
        return (EC_FALSE);
    }

    e = (pgc_cpgrb_bitmap[ byte_nth ] & (uint8_t)(1 << bit_nth));

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
STATIC_CAST static EC_BOOL __cpgb_page_model_cpgrb_bitmap_check(const CPGB *cpgb, const uint16_t page_model)
{
    const CPGB_CONF *cpgb_conf;
    const uint8_t *pgc_cpgrb_bitmap;
    uint16_t byte_nth;

    CPGB_ASSERT(CPGB_MODEL_NUM > page_model);

    cpgb_conf = &(g_cpgb_conf[ page_model ]);
    pgc_cpgrb_bitmap = CPGB_PAGE_MODEL_CPGRB_BITMAP(cpgb, page_model);

    for(byte_nth = 0; byte_nth < CPGB_CONF_CPGRB_BITMAP_SIZE(cpgb_conf); byte_nth ++)
    {
        uint8_t byte_val;

        byte_val = pgc_cpgrb_bitmap[ byte_nth ];

        /*(0000 0011) = 0x03*/
        /*(0000 1100) = 0x0C*/
        /*(0011 0000) = 0x30*/
        /*(1100 0000) = 0xC0*/
        if(0x03 == (byte_val & 0x03)
        || 0x0C == (byte_val & 0x0C)
        || 0x30 == (byte_val & 0x30)
        || 0xC0 == (byte_val & 0xC0))
        {
            dbg_log(SEC_0122_CPGB, 0)(LOGSTDOUT, "error:__cpgb_page_model_cpgrb_bitmap_check: page_model %u found adjacent 2 bits are set"
                               " at %u # byte which is 0x%x\n",
                               page_model, byte_nth, byte_val);
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

STATIC_CAST static void __cpgb_page_model_cpgrb_bitmap_print(LOG *log, const CPGB *cpgb, const uint16_t page_model)
{
    const CPGB_CONF *cpgb_conf;
    const uint8_t *pgc_cpgrb_bitmap;
    uint16_t byte_nth;

    CPGB_ASSERT(CPGB_MODEL_NUM > page_model);

    cpgb_conf      = &(g_cpgb_conf[ page_model ]);
    pgc_cpgrb_bitmap = CPGB_PAGE_MODEL_CPGRB_BITMAP(cpgb, page_model);

    for(byte_nth = 0; byte_nth < CPGB_CONF_CPGRB_BITMAP_SIZE(cpgb_conf); byte_nth ++)
    {
        uint16_t bit_nth;
        uint8_t  bit_val;
        uint8_t  byte_val;

        byte_val = pgc_cpgrb_bitmap[ byte_nth ];
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
STATIC_CAST static uint16_t __cpgb_page_model_cpgrb_bitmap_count_bits(const CPGB *cpgb, const uint16_t page_model)
{
    const CPGB_CONF *cpgb_conf;
    const uint8_t *pgc_cpgrb_bitmap;
    uint16_t byte_nth;
    uint16_t bits_count;

    CPGB_ASSERT(CPGB_MODEL_NUM > page_model);

    cpgb_conf      = &(g_cpgb_conf[ page_model ]);
    pgc_cpgrb_bitmap = CPGB_PAGE_MODEL_CPGRB_BITMAP(cpgb, page_model);
    bits_count     = 0;

    for(byte_nth = 0; byte_nth < CPGB_CONF_CPGRB_BITMAP_SIZE(cpgb_conf); byte_nth ++)
    {
        bits_count += g_nbits_per_byte[ pgc_cpgrb_bitmap[ byte_nth ] ];
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
STATIC_CAST static uint16_t __cpgb_page_model_first_page(const CPGB *cpgb, const uint16_t page_model)
{
    uint16_t node_pos;
    const CPGRB_NODE *node;

    node_pos = cpgrb_tree_first_node(CPGB_CPGRB_POOL(cpgb), CPGB_PAGE_MODEL_CPGRB_ROOT_POS(cpgb, page_model));
    if(CPGRB_ERR_POS == node_pos)
    {
        dbg_log(SEC_0122_CPGB, 0)(LOGSTDOUT, "error:__cpgb_page_model_first_page: no free page in page model %u\n", page_model);
        return (CPGRB_ERR_POS);
    }

    node = CPGRB_POOL_NODE(CPGB_CPGRB_POOL(cpgb), node_pos);
    return (CPGRB_NODE_DATA(node));
}

STATIC_CAST static EC_BOOL __cpgb_page_model_check(const CPGB *cpgb, const uint16_t page_model)
{
    uint16_t bits_count;
    uint16_t nodes_count;
    uint16_t root_pos;
    uint16_t node_pos;

    const CPGRB_POOL *cpgrb_pool;

    cpgrb_pool    = CPGB_CPGRB_POOL(cpgb);
    root_pos    = CPGB_PAGE_MODEL_CPGRB_ROOT_POS(cpgb, page_model);

    /*check consistency of bit count and node count*/
    bits_count  = __cpgb_page_model_cpgrb_bitmap_count_bits(cpgb, page_model);
    nodes_count = cpgrb_tree_node_num(CPGB_CPGRB_POOL(cpgb), root_pos);

    if(bits_count != nodes_count)
    {
        dbg_log(SEC_0122_CPGB, 9)(LOGSTDOUT, "[DEBUG] __cpgb_page_model_check: [FAIL] page model %u found inconsistent where bits_count = %u, but nodes_count = %u\n",
                            page_model, bits_count, nodes_count);
        return (EC_FALSE);
    }

    /*check page no consistency of rbtree and bitmap*/
    for(node_pos = cpgrb_tree_first_node(cpgrb_pool, root_pos);
         CPGRB_ERR_POS != node_pos;
         node_pos = cpgrb_tree_next_node(cpgrb_pool, node_pos)
       )
    {
        const CPGRB_NODE *node;
        uint16_t  page_no;

        node = CPGRB_POOL_NODE(cpgrb_pool, node_pos);
        if(CPGRB_NODE_NOT_USED == CPGRB_NODE_USED_FLAG(node))
        {
            dbg_log(SEC_0122_CPGB, 9)(LOGSTDOUT, "[DEBUG] error:__cpgb_page_model_check: found node at pos %u was not used in page model %u\n",
                                node_pos, page_model);
            return (EC_FALSE);
        }

        page_no = CPGRB_NODE_DATA(node);
        if(EC_FALSE == __cpgb_page_model_cpgrb_bitmap_is(cpgb, page_model, page_no, (uint8_t) 1))
        {
            dbg_log(SEC_0122_CPGB, 9)(LOGSTDOUT, "[DEBUG] __cpgb_page_model_check: [FAIL] page model %u found inconsistent "
                               "where page no %u in rbtree without bitmap setting\n",
                                page_model, page_no);
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == __cpgb_page_model_cpgrb_bitmap_check(cpgb, page_model))
    {
        dbg_log(SEC_0122_CPGB, 9)(LOGSTDOUT, "[DEBUG] __cpgb_page_model_check: [FAIL] page model %u found bitmap invalidity\n",
                            page_model);
        return (EC_FALSE);
    }

    dbg_log(SEC_0122_CPGB, 9)(LOGSTDOUT, "[DEBUG] __cpgb_page_model_check: [SUCC] page model %u owns %u pages\n", page_model, nodes_count);
    return (EC_TRUE);
}

void cpgb_page_model_print(LOG *log, const CPGB *cpgb, const uint16_t page_model)
{
    const CPGRB_POOL *cpgrb_pool;
    const CPGB_CONF *cpgb_conf;
    uint16_t   cpgrb_bitmap_size;
    uint16_t   page_num;

    CPGB_ASSERT(CPGB_MODEL_NUM > page_model);

    cpgb_conf         = &(g_cpgb_conf[ page_model ]);
    cpgrb_pool        = CPGB_CPGRB_POOL(cpgb);
    cpgrb_bitmap_size = CPGB_CONF_CPGRB_BITMAP_SIZE(cpgb_conf);
    page_num          = CPGB_CONF_PAGE_NUM(cpgb_conf);

    CPGB_ASSERT(page_model == CPGB_CONF_PAGE_MODEL(cpgb_conf));
    sys_log(log, "cpgb_page_model_print: page model %u, cpgrb_bitmap_size %u, page_num %u\n", page_model, cpgrb_bitmap_size, page_num);
    sys_log(log, "cpgb_page_model_print: page model %u, rbtree is\n", page_model);
    cpgrb_tree_print(log, cpgrb_pool, CPGB_PAGE_MODEL_CPGRB_ROOT_POS(cpgb, page_model));
    sys_log(log, "cpgb_page_model_print: page model %u, bitmap is\n", page_model);
    __cpgb_page_model_cpgrb_bitmap_print(log, cpgb, page_model);

    return;
}

CPGB *cpgb_new(const uint16_t page_model_target)
{
    CPGB *cpgb;

    alloc_static_mem(MM_CPGB, &cpgb, LOC_CPGB_0001);
    if(NULL_PTR == cpgb)
    {
        dbg_log(SEC_0122_CPGB, 0)(LOGSTDOUT, "error:cpgb_new: new cpgb failed\n");
        return (NULL_PTR);
    }

    cpgb_init(cpgb, page_model_target);

    return (cpgb);
}

/* one page block = 64MB */
EC_BOOL cpgb_init(CPGB *cpgb, const uint16_t page_model_target)
{
    uint16_t page_max_num;
    uint16_t page_model;

    const CPGB_CONF *cpgb_conf;

    ASSERT_CPGB_PAD_SIZE();

    if(CPGB_MODEL_NUM <= page_model_target)
    {
        dbg_log(SEC_0122_CPGB, 0)(LOGSTDOUT, "error:cpgb_init: page_model_target %u overflow\n", page_model_target);
        return (EC_FALSE);
    }

    cpgb_conf    = &(g_cpgb_conf[ page_model_target ]);
    page_max_num = CPGB_CONF_PAGE_NUM(cpgb_conf);

    if(EC_FALSE == cpgrb_pool_init(CPGB_CPGRB_POOL(cpgb), page_max_num))
    {
        dbg_log(SEC_0122_CPGB, 0)(LOGSTDOUT, "error:cpgb_init: init cpgrb pool failed where page_max_num = %u\n", page_max_num);
        cpgb_clean(cpgb);
        return (EC_FALSE);
    }

    BSET(CPGB_PAGE_MODEL_CPGRB_BITMAP_BUFF(cpgb), CPGB_PAGE_IS_NOT_FREE, CPGB_RB_BITMAP_SIZE); /*mark as non-free page*/

    for(page_model = 0; CPGB_MODEL_NUM > page_model; page_model ++)
    {
        CPGB_PAGE_MODEL_CPGRB_ROOT_POS(cpgb, page_model) = CPGRB_ERR_POS;
    }

    CPGB_PAGE_MODEL_ASSIGN_BITMAP(cpgb) = 0;

    /*set target model*/
    cpgb_add_page(cpgb, page_model_target, 0/*page_no*/);

    /*statistics*/
    CPGB_PAGE_MAX_NUM(cpgb)          = page_max_num;
    CPGB_PAGE_USED_NUM(cpgb)         = 0;
    CPGB_PAGE_ACTUAL_USED_SIZE(cpgb) = 0;

    return (EC_TRUE);
}

void cpgb_clean(CPGB *cpgb)
{
    uint16_t page_model;

    cpgrb_pool_clean(CPGB_CPGRB_POOL(cpgb));

    for(page_model = 0; CPGB_MODEL_NUM > page_model; page_model ++)
    {
        CPGB_PAGE_MODEL_CPGRB_ROOT_POS(cpgb, page_model) = CPGRB_ERR_POS;
        //CPGB_PAGE_MODEL_CPGRB_BITMAP(cpgb, page_model)   = NULL_PTR;
    }

    CPGB_PAGE_MODEL_ASSIGN_BITMAP(cpgb)     = 0;
    CPGB_PAGE_MAX_NUM(cpgb)                 = 0;
    CPGB_PAGE_USED_NUM(cpgb)                = 0;
    CPGB_PAGE_ACTUAL_USED_SIZE(cpgb)        = 0;
    return;
}

EC_BOOL cpgb_free(CPGB *cpgb)
{
    if(NULL_PTR != cpgb)
    {
        cpgb_clean(cpgb);
        free_static_mem(MM_CPGB, cpgb, LOC_CPGB_0002);
    }

    return (EC_TRUE);
}

/*add one free page into pool and set page model bitmap*/
EC_BOOL cpgb_add_page(CPGB *cpgb, const uint16_t page_model, const uint16_t page_no)
{
    uint8_t *pgc_cpgrb_bitmap;
    uint16_t page_no_max;

    CPGB_ASSERT(CPGB_MODEL_NUM > page_model);

    pgc_cpgrb_bitmap = CPGB_PAGE_MODEL_CPGRB_BITMAP(cpgb, page_model);

    page_no_max = (uint16_t)(1 << page_model);
    if(page_no >= page_no_max)
    {
        dbg_log(SEC_0122_CPGB, 0)(LOGSTDOUT, "error:cpgb_add_page: page_no_max %u but page_no to add is %u, overflow!\n", page_no_max, page_no);
        return (EC_FALSE);
    }

    /*insert page_no to bitmap*/
    if(EC_FALSE == __cpgb_page_model_cpgrb_bitmap_set(cpgb, page_model, page_no))
    {
        dbg_log(SEC_0122_CPGB, 0)(LOGSTDOUT, "error:cpgb_add_page: add page_no %u to bitmap of page model %u failed\n", page_no, page_model);
        return (EC_FALSE);
    }

    /*insert page_no to rbtree*/
    if(CPGRB_ERR_POS == cpgrb_tree_insert_data(CPGB_CPGRB_POOL(cpgb), &(CPGB_PAGE_MODEL_CPGRB_ROOT_POS(cpgb, page_model)), page_no))
    {
        dbg_log(SEC_0122_CPGB, 0)(LOGSTDOUT, "error:cpgb_add_page: add page_no %u to rbtree of page model %u failed\n", page_no, page_model);
        __cpgb_page_model_cpgrb_bitmap_clear(cpgb, page_model, page_no);
        return (EC_FALSE);
    }

    /*set assignment bitmap*/
    /*set bits of page_model, page_model + 1, ... page_4k_model, the highest bit is for 2k-page which is not supported,clear it!*/
    CPGB_PAGE_MODEL_ASSIGN_BITMAP(cpgb) |= (uint16_t)(~((1 << page_model) - 1)) & CPGB_MODEL_MASK_ALL;

    return (EC_TRUE);
}

/*del one free page from pool and clear page model bitmap, i.e., del one page from pool and used it later*/
EC_BOOL cpgb_del_page(CPGB *cpgb, const uint16_t page_model, const uint16_t page_no)
{
    uint8_t *pgc_cpgrb_bitmap;
    uint16_t page_no_max;

    CPGB_ASSERT(CPGB_MODEL_NUM > page_model);

    pgc_cpgrb_bitmap = CPGB_PAGE_MODEL_CPGRB_BITMAP(cpgb, page_model);

    page_no_max = (uint16_t)(1 << page_model);

    if(page_no >= page_no_max)
    {
        dbg_log(SEC_0122_CPGB, 0)(LOGSTDOUT, "error:cpgb_del_page: page_no_max %u but page_no to add is %u, overflow!\n", page_no_max, page_no);
        return (EC_FALSE);
    }

    /*del page_no from rbtree*/
    if(CPGRB_ERR_POS == cpgrb_tree_delete_data(CPGB_CPGRB_POOL(cpgb), &(CPGB_PAGE_MODEL_CPGRB_ROOT_POS(cpgb, page_model)), page_no))
    {
        dbg_log(SEC_0122_CPGB, 0)(LOGSTDOUT, "error:cpgb_del_page: del page_no %u from rbtree of page model %u failed\n", page_no, page_model);
        return (EC_FALSE);
    }

    /*del page_no from bitmap*/
    if(EC_FALSE == __cpgb_page_model_cpgrb_bitmap_clear(cpgb, page_model, page_no))
    {
        dbg_log(SEC_0122_CPGB, 0)(LOGSTDOUT, "error:cpgb_del_page: del page_no %u from bitmap of page model %u failed\n", page_no, page_model);
        cpgrb_tree_insert_data(CPGB_CPGRB_POOL(cpgb), &(CPGB_PAGE_MODEL_CPGRB_ROOT_POS(cpgb, page_model)), page_no);
        return (EC_FALSE);
    }

    /*clear assignment bitmap if necessary*/
    if(0 == (CPGB_PAGE_MODEL_ASSIGN_BITMAP(cpgb) & (uint16_t)((1 << page_model) - 1)))/*upper page-model has no page*/
    {
        uint16_t page_model_t;

        page_model_t = page_model;
        while(CPGB_MODEL_NUM > page_model_t
           && EC_TRUE == cpgrb_tree_is_empty(CPGB_CPGRB_POOL(cpgb), CPGB_PAGE_MODEL_CPGRB_ROOT_POS(cpgb, page_model_t))/*this page-model is empty*/
        )
        {
            CPGB_PAGE_MODEL_ASSIGN_BITMAP(cpgb) &= (uint16_t)~(1 << page_model_t);/*clear bit*/
            page_model_t ++;
        }
    }

    return (EC_TRUE);
}

uint16_t cpgb_assign_page(CPGB *cpgb, const uint16_t page_model)
{
    uint16_t page_no;
    uint16_t page_model_t;
    uint16_t mask;

    page_model_t = page_model;

    mask = (uint16_t)((1 << (page_model + 1)) - 1);
    if(0 == (CPGB_PAGE_MODEL_ASSIGN_BITMAP(cpgb) & mask))
    {
        dbg_log(SEC_0122_CPGB, 0)(LOGSTDOUT, "error:cpgb_assign_page: page_model = %u where 0 == bitmap %x & mask %x indicates page is not available\n",
                           page_model, CPGB_PAGE_MODEL_ASSIGN_BITMAP(cpgb), mask);
        return (CPGRB_ERR_POS);
    }

    while(CPGB_MODEL_NUM > page_model_t
       && EC_TRUE == cpgrb_tree_is_empty(CPGB_CPGRB_POOL(cpgb), CPGB_PAGE_MODEL_CPGRB_ROOT_POS(cpgb, page_model_t))
       )
    {
        page_model_t --;
    }

    if(CPGB_MODEL_NUM <= page_model_t)
    {
        dbg_log(SEC_0122_CPGB, 0)(LOGSTDOUT, "error:cpgb_assign_page: no free page available from page model %u\n", page_model);
        return (CPGRB_ERR_POS);
    }

    page_no = __cpgb_page_model_first_page(cpgb, page_model_t);
    if(CPGRB_ERR_POS == page_no)
    {
        dbg_log(SEC_0122_CPGB, 0)(LOGSTDOUT, "error:cpgb_assign_page: no free page in page model %u\n", page_model_t);
        return (CPGRB_ERR_POS);
    }

    if(EC_FALSE == cpgb_del_page(cpgb, page_model_t, page_no))
    {
        dbg_log(SEC_0122_CPGB, 0)(LOGSTDOUT, "error:cpgb_assign_page: del page %u from page model %u failed\n", page_no, page_model_t);
        return (CPGRB_ERR_POS);
    }

    /*--- split phase ---*/
    for(; page_model_t ++ < page_model;)
    {
        /*borrow one page from page_model_t and split it into two page and insert into page_model_t - 1*/
        /*page_no ==> (2*page_no, 2*page_no + 1)*/
        page_no <<= 1;

        if(EC_FALSE == cpgb_add_page(cpgb, page_model_t, page_no + 1))
        {
            dbg_log(SEC_0122_CPGB, 0)(LOGSTDOUT, "error:cpgb_assign_page: borrowed one page %u from page model %u, "
                               "but insert the splitted page %u into page model %u failed\n",
                                (uint16_t)(page_no >> 1), (page_model_t - 1), page_no + 1, page_model_t);
            dbg_log(SEC_0122_CPGB, 0)(LOGSTDOUT, "error:cpgb_assign_page: try to return page %u to page model %u ...\n",
                                (uint16_t)(page_no >> 1), (page_model_t - 1));
#if 0
            /*try ...*/
            if(EC_TRUE == cpgb_recycle_page(cpgb, page_model_t - 1, (uint16_t)(page_no >> 1)))
            {
                dbg_log(SEC_0122_CPGB, 0)(LOGSTDOUT, "error:cpgb_assign_page: try to recycle page %u to page model %u ... done\n",
                                    (uint16_t)(page_no >> 1), (page_model_t - 1));
            }
            else
            {
                dbg_log(SEC_0122_CPGB, 0)(LOGSTDOUT, "error:cpgb_assign_page: try to recycle page %u to page model %u ... failed\n",
                                    (uint16_t)(page_no >> 1), (page_model_t - 1));
            }
#endif
            return (CPGRB_ERR_POS);
        }
    }

    return (page_no);
}

EC_BOOL cpgb_recycle_page(CPGB *cpgb, const uint16_t page_model, const uint16_t page_no)
{
    uint8_t *pgc_cpgrb_bitmap;
    uint16_t page_no_max;
    uint16_t page_no_t;
    uint16_t page_model_t;

    CPGB_ASSERT(CPGB_MODEL_NUM > page_model);

    pgc_cpgrb_bitmap = CPGB_PAGE_MODEL_CPGRB_BITMAP(cpgb, page_model);

    page_no_max = (uint16_t)(1 << page_model);
    if(page_no >= page_no_max)
    {
        dbg_log(SEC_0122_CPGB, 0)(LOGSTDOUT, "error:cpgb_recycle_page: page_no_max %u but page_no to add is %u, overflow!\n", page_no_max, page_no);
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
        if(EC_FALSE == __cpgb_page_model_cpgrb_bitmap_is(cpgb, page_model_t, page_no_o, (uint8_t)1))
        {
            break;
        }

        /*if neighbor is free-page, then delete it and add the two-page as one page in upper page_model*/
        cpgb_del_page(cpgb, page_model_t, page_no_o);
    }

    if(EC_FALSE == cpgb_add_page(cpgb, page_model_t, page_no_t))
    {
        dbg_log(SEC_0122_CPGB, 0)(LOGSTDOUT, "error:cpgb_recycle_page: add page_no %u to page model %u failed\n", page_no_t, page_model_t);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cpgb_new_space(CPGB *cpgb, const uint32_t size, uint16_t *page_no)
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

    if(CPGB_CACHE_MAX_BYTE_SIZE < size)
    {
        dbg_log(SEC_0122_CPGB, 0)(LOGSTDOUT, "error:cpgb_new_space: the expected size %u overflow\n", size);
        return (EC_FALSE);
    }

    page_num_need = (uint16_t)((size + CPGB_PAGE_BYTE_SIZE - 1) >> CPGB_PAGE_BIT_SIZE);
    dbg_log(SEC_0122_CPGB, 9)(LOGSTDOUT, "[DEBUG] cpgb_new_space: size = %u ==> page_num_need = %u\n", size, page_num_need);

    /*find a page model which can accept the page_num_need pages */
    /*and then split the left space into page model with smaller size  */

    CPGB_ASSERT(CPGB_064MB_PAGE_NUM >= page_num_need);

    /*check bits of page_num_need and determine the page_model*/
    e = CPGB_PAGE_HI_BIT_MASK;
    for(t = page_num_need, page_model = 0; 0 == (t & e); t <<= 1, page_model ++)
    {
        /*do nothing*/
    }
    dbg_log(SEC_0122_CPGB, 9)(LOGSTDOUT, "[DEBUG] cpgb_new_space: t = 0x%x, page_model = %u, e = 0x%x, t << 1 is 0x%x\n", t, page_model, e, (t << 1));

    if(CPGB_PAGE_LO_BITS_MASK & t)
    {
        page_model --;/*upgrade page_model one level*/
    }

    dbg_log(SEC_0122_CPGB, 9)(LOGSTDOUT, "[DEBUG] cpgb_new_space: page_num_need = %u ==> page_model = %u (has %u pages )\n",
                       page_num_need, page_model, (uint16_t)(1 << (CPGB_MODEL_NUM - 1 - page_model)));

    page_no_t = cpgb_assign_page(cpgb, page_model);
    if(CPGRB_ERR_POS == page_no_t)
    {
        dbg_log(SEC_0122_CPGB, 0)(LOGSTDOUT, "error:cpgb_new_space: assign one page from page model %u failed\n", page_model);
        return (EC_FALSE);
    }

    dbg_log(SEC_0122_CPGB, 9)(LOGSTDOUT, "[DEBUG] cpgb_new_space: assign page_no_t = %u from page_model = %u\n", page_no_t, page_model);

    page_num_has  = (uint16_t)(1 << (CPGB_MODEL_NUM - 1 - page_model));       /*2 ^ (16 - page_model - 1)*/
    page_no_start = (uint16_t)(page_no_t  << (CPGB_MODEL_NUM - 1 - page_model));/*page_no_t * page_num_has*/
    page_no_end   = page_no_start + page_num_has;

    page_num_left = page_num_has - page_num_need;

    dbg_log(SEC_0122_CPGB, 9)(LOGSTDOUT, "[DEBUG] cpgb_new_space: page_num_has %u, page_no_start %u, page_no_end %u, page_num_left %u\n",
                        page_num_has, page_no_start, page_no_end, page_num_left);

    /*left pages  are {page_no_end - page_num_left, ...., page_no_end - 1}*/
    /*add the left pages to corresponding page models*/
    //dbg_log(SEC_0122_CPGB, 9)(LOGSTDOUT, "[DEBUG] cpgb_new_space: page_num_left = 0x%x bits are\n", page_num_left);
    //c_uint16_hi2lo_header_print(LOGSTDOUT);
    //c_uint16_hi2lo_bits_print(LOGSTDOUT, page_num_left);

    for(t = page_num_left, page_model = CPGB_MODEL_NUM - 1, page_no_t = page_no_start + page_num_need;
        0 < t;
        t >>= 1, page_model --, page_no_t >>= 1
       )
    {
        dbg_log(SEC_0122_CPGB, 9)(LOGSTDOUT, "[DEBUG] cpgb_new_space: page_no_t %u, page_model %u\n", page_no_t, page_model);
        if(0 == (t & 1))
        {
            continue;
        }
        dbg_log(SEC_0122_CPGB, 9)(LOGSTDOUT, "[DEBUG] cpgb_new_space: add page_no_t %u to page_model %u where t(i.e. cur page_num_left) = %u\n",
                            page_no_t, page_model, t);
        if(EC_FALSE == cpgb_recycle_page(cpgb, page_model, page_no_t))
        {
            dbg_log(SEC_0122_CPGB, 0)(LOGSTDOUT, "error:cpgb_new_space: add page_no_t %u to page_model %u failed !!!\n", page_no_t, page_model);
            //cpgb_page_model_print(LOGSTDOUT, cpgb, page_model);
        }
        page_no_t ++;
    }

    CPGB_PAGE_USED_NUM(cpgb)         += page_num_need;
    CPGB_PAGE_ACTUAL_USED_SIZE(cpgb) += size;

    CPGB_ASSERT(EC_TRUE == cpgb_check(cpgb));
    dbg_log(SEC_0122_CPGB, 9)(LOGSTDOUT, "[DEBUG] cpgb_new_space: pgb_page_used_num %u due to increment %u\n",
                        CPGB_PAGE_USED_NUM(cpgb), page_num_need);
    dbg_log(SEC_0122_CPGB, 9)(LOGSTDOUT, "[DEBUG] cpgb_new_space: pgb_actual_used_size %u due to increment %u\n",
                        CPGB_PAGE_ACTUAL_USED_SIZE(cpgb), size);

    (*page_no) = page_no_start;
    return (EC_TRUE);
}

EC_BOOL cpgb_free_space(CPGB *cpgb, const uint16_t page_start_no, const uint32_t size)
{
    uint16_t page_num_used;
    uint16_t page_model;
    uint16_t t;
    uint16_t page_no;/*the page No. in certain page model*/

    if(CPGB_CACHE_MAX_BYTE_SIZE < size)
    {
        dbg_log(SEC_0122_CPGB, 0)(LOGSTDOUT, "error:cpgb_free_space: invalid size %u due to overflow\n", size);
        return (EC_FALSE);
    }

    page_num_used = (uint16_t)((size + CPGB_PAGE_BYTE_SIZE - 1) >> CPGB_PAGE_BIT_SIZE);
    dbg_log(SEC_0122_CPGB, 9)(LOGSTDOUT, "[DEBUG] cpgb_free_space: size = %u ==> page_num_used = %u\n", size, page_num_used);

    /*find a page model and recycle the used pages */
    CPGB_ASSERT(CPGB_064MB_PAGE_NUM >= page_num_used);

    for(t = page_num_used, page_model = CPGB_MODEL_NUM - 1, page_no = page_start_no + page_num_used;
        0 < t;
        t >>= 1, page_model --, page_no >>= 1
       )
    {
        dbg_log(SEC_0122_CPGB, 9)(LOGSTDOUT, "[DEBUG] cpgb_free_space: page_no %u, page_model %u\n", page_no, page_model);
        if(0 == (t & 1))
        {
            continue;
        }

        page_no --;
        dbg_log(SEC_0122_CPGB, 9)(LOGSTDOUT, "[DEBUG] cpgb_free_space: recycle page_no %u to page_model %u where t(i.e. cur page_num_used) = %u\n",
                            page_no, page_model, t);
        if(EC_FALSE == cpgb_recycle_page(cpgb, page_model, page_no))
        {
            dbg_log(SEC_0122_CPGB, 0)(LOGSTDOUT, "error:cpgb_free_space: recycle page_no %u to page_model %u failed !!!\n", page_no, page_model);
            //cpgb_page_model_print(LOGSTDOUT, cpgb, page_model);
        }
    }

    dbg_log(SEC_0122_CPGB, 9)(LOGSTDOUT, "[DEBUG] cpgb_free_space: recycle successfully\n");

    CPGB_PAGE_USED_NUM(cpgb)         -= page_num_used;
    CPGB_PAGE_ACTUAL_USED_SIZE(cpgb) -= size;
    dbg_log(SEC_0122_CPGB, 9)(LOGSTDOUT, "[DEBUG] cpgb_free_space: pgb_page_used_num %u due to decrement %u\n",
                        CPGB_PAGE_USED_NUM(cpgb), page_num_used);
    dbg_log(SEC_0122_CPGB, 9)(LOGSTDOUT, "[DEBUG] cpgb_free_space: pgb_actual_used_size %u due to decrement %u\n",
                        CPGB_PAGE_ACTUAL_USED_SIZE(cpgb), size);

    return (EC_TRUE);
}

/*return true if all pages in block are used, otherwise return false*/
EC_BOOL cpgb_is_full(const CPGB *cpgb)
{
    if(CPGB_PAGE_USED_NUM(cpgb) == CPGB_PAGE_MAX_NUM(cpgb))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

/*return true if no page in block is used and block is given, otherwise return false*/
EC_BOOL cpgb_is_empty(const CPGB *cpgb)
{
    if(0 == CPGB_PAGE_USED_NUM(cpgb) && 0 < CPGB_PAGE_MAX_NUM(cpgb))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL cpgb_check(const CPGB *cpgb)
{
    uint16_t  page_model;
    uint16_t  page_free_num;
    EC_BOOL   ret;

    ret = EC_TRUE;

    for(page_model = 0; CPGB_MODEL_NUM > page_model; page_model ++)
    {
        if(EC_FALSE == __cpgb_page_model_check(cpgb, page_model))
        {
            dbg_log(SEC_0122_CPGB, 5)(LOGSTDOUT, "cpgb_check: check page model %u failed\n", page_model);
            ret = EC_FALSE;
        }
        else
        {
            dbg_log(SEC_0122_CPGB, 5)(LOGSTDOUT, "cpgb_check: check page model %u successfully\n", page_model);
        }
        dbg_log(SEC_0122_CPGB, 5)(LOGSTDOUT, "----------------------------------------------------------\n");
    }

    page_free_num = 0;
    for(page_model = 0; CPGB_MODEL_NUM > page_model; page_model ++)
    {
        page_free_num += (uint16_t)(__cpgb_page_model_cpgrb_bitmap_count_bits(cpgb, page_model) << (CPGB_MODEL_NUM - 1 - page_model));
    }
    dbg_log(SEC_0122_CPGB, 9)(LOGSTDOUT, "[DEBUG] cpgb_check: pgc_page_max_num = %u, pgc_page_used_num = %u, counted page_free_num = %u\n",
                        CPGB_PAGE_MAX_NUM(cpgb), CPGB_PAGE_USED_NUM(cpgb), page_free_num);

    if(CPGB_PAGE_MAX_NUM(cpgb) != CPGB_PAGE_USED_NUM(cpgb) + page_free_num)
    {
        dbg_log(SEC_0122_CPGB, 5)(LOGSTDOUT, "cpgb_check:[FAIL] pgc_page_max_num %u != %u(pgc_page_used_num %u + counted page_free_num %u)\n",
                           CPGB_PAGE_MAX_NUM(cpgb),
                           CPGB_PAGE_USED_NUM(cpgb) + page_free_num,
                           CPGB_PAGE_USED_NUM(cpgb),
                           page_free_num);
        ret = EC_FALSE;
    }
#if 1
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0122_CPGB, 0)(LOGSTDOUT, "error:cpgb_check: check cpgb %p failed\n", cpgb);
    }
    else
    {
        dbg_log(SEC_0122_CPGB, 9)(LOGSTDOUT, "[DEBUG] cpgb_check: check cpgb %p done\n", cpgb);
    }
#endif
    return (ret);
}

EC_BOOL cpgb_flush_size(const CPGB *cpgb, UINT32 *size)
{
    (*size) += sizeof(CPGB);
    return (EC_TRUE);
}

EC_BOOL cpgb_flush(const CPGB *cpgb, int fd, UINT32 *offset)
{
    UINT32 osize;/*flush once size*/
    DEBUG(UINT32 offset_saved = *offset;);

    /*flush rbtree pool*/
    if(EC_FALSE == cpgrb_flush(CPGB_CPGRB_POOL(cpgb), fd, offset))
    {
        dbg_log(SEC_0122_CPGB, 0)(LOGSTDOUT, "error:cpgb_flush: flush CPGB_CPGRB_POOL at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*flush bitmap buff*/
    osize = CPGB_RB_BITMAP_SIZE;
    if(EC_FALSE == c_file_flush(fd, offset, osize, CPGB_PAGE_MODEL_CPGRB_BITMAP_BUFF(cpgb)))
    {
        dbg_log(SEC_0122_CPGB, 0)(LOGSTDOUT, "error:cpgb_flush: flush CPGB_PAGE_MODEL_CPGRB_BITMAP_BUFF with %ld bytes at offset %ld of fd %d failed\n",
                            osize, (*offset), fd);
        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_pad(fd, offset, CPGB_RB_BITMAP_PAD_SIZE, FILE_PAD_CHAR))
    {
        dbg_log(SEC_0122_CPGB, 0)(LOGSTDOUT, "error:cpgb_flush: flush CPGB_RB_BITMAP_PAD at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*flush rbtree root pos table*/
    osize = CPGB_MODEL_NUM * sizeof(uint16_t);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)CPGB_PAGE_MODEL_CPGRB_ROOT_POS_TBL(cpgb)))
    {
        dbg_log(SEC_0122_CPGB, 0)(LOGSTDOUT, "error:cpgb_flush: flush CPGB_PAGE_MODEL_CPGRB_ROOT_POS_TBL at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*flush CPGB_PAGE_MODEL_ASSIGN_BITMAP*/
    osize = sizeof(uint16_t);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(CPGB_PAGE_MODEL_ASSIGN_BITMAP(cpgb))))
    {
        dbg_log(SEC_0122_CPGB, 0)(LOGSTDOUT, "error:cpgb_flush: write CPGB_PAGE_MODEL_ASSIGN_BITMAP at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*flush CPGB_PAGE_MAX_NUM*/
    osize = sizeof(uint16_t);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(CPGB_PAGE_MAX_NUM(cpgb))))
    {
        dbg_log(SEC_0122_CPGB, 0)(LOGSTDOUT, "error:cpgb_flush: write CPGB_PAGE_MAX_NUM at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*flush CPGB_PAGE_USED_NUM*/
    osize = sizeof(uint16_t);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(CPGB_PAGE_USED_NUM(cpgb))))
    {
        dbg_log(SEC_0122_CPGB, 0)(LOGSTDOUT, "error:cpgb_flush: write CPGB_PAGE_USED_NUM at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*flush CPGB_PAGE_ACTUAL_USED_SIZE*/
    osize = sizeof(uint32_t);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(CPGB_PAGE_ACTUAL_USED_SIZE(cpgb))))
    {
        dbg_log(SEC_0122_CPGB, 0)(LOGSTDOUT, "error:cpgb_flush: write CPGB_PAGE_ACTUAL_USED_SIZE at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_pad(fd, offset, CPGB_PAD_SIZE, FILE_PAD_CHAR))
    {
        dbg_log(SEC_0122_CPGB, 0)(LOGSTDOUT, "error:cpgb_flush: flush CPGB_PAD at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    DEBUG(CPGB_ASSERT(sizeof(CPGB) == (*offset) - offset_saved));

    return (EC_TRUE);
}

EC_BOOL cpgb_load(CPGB *cpgb, int fd, UINT32 *offset)
{
    UINT32 osize;/*load once size*/

    /*load rbtree pool*/
    if(EC_FALSE == cpgrb_load(CPGB_CPGRB_POOL(cpgb), fd, offset))
    {
        dbg_log(SEC_0122_CPGB, 0)(LOGSTDOUT, "error:cpgb_load: load CPGB_CPGRB_POOL at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*load bitmap buff*/
    osize = CPGB_RB_BITMAP_SIZE;
    if(EC_FALSE == c_file_load(fd, offset, osize, CPGB_PAGE_MODEL_CPGRB_BITMAP_BUFF(cpgb)))
    {
        dbg_log(SEC_0122_CPGB, 0)(LOGSTDOUT, "error:cpgb_load: load CPGB_PAGE_MODEL_CPGRB_BITMAP_BUFF with %ld bytes at offset %ld of fd %d failed\n",
                            osize, (*offset), fd);
        return (EC_FALSE);
    }

    (*offset) += CPGB_RB_BITMAP_PAD_SIZE;

    /*load rbtree root pos table*/
    osize = CPGB_MODEL_NUM * sizeof(uint16_t);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)CPGB_PAGE_MODEL_CPGRB_ROOT_POS_TBL(cpgb)))
    {
        dbg_log(SEC_0122_CPGB, 0)(LOGSTDOUT, "error:cpgb_load: load CPGB_PAGE_MODEL_CPGRB_ROOT_POS_TBL at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*load CPGB_PAGE_MODEL_ASSIGN_BITMAP*/
    osize = sizeof(uint16_t);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(CPGB_PAGE_MODEL_ASSIGN_BITMAP(cpgb))))
    {
        dbg_log(SEC_0122_CPGB, 0)(LOGSTDOUT, "error:cpgb_load: load CPGB_PAGE_MODEL_ASSIGN_BITMAP at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*load CPGB_PAGE_MAX_NUM*/
    osize = sizeof(uint16_t);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(CPGB_PAGE_MAX_NUM(cpgb))))
    {
        dbg_log(SEC_0122_CPGB, 0)(LOGSTDOUT, "error:cpgb_load: load CPGB_PAGE_MAX_NUM at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*load CPGB_PAGE_USED_NUM*/
    osize = sizeof(uint16_t);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(CPGB_PAGE_USED_NUM(cpgb))))
    {
        dbg_log(SEC_0122_CPGB, 0)(LOGSTDOUT, "error:cpgb_load: load CPGB_PAGE_USED_NUM at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*load CPGB_PAGE_ACTUAL_USED_SIZE*/
    osize = sizeof(uint32_t);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(CPGB_PAGE_ACTUAL_USED_SIZE(cpgb))))
    {
        dbg_log(SEC_0122_CPGB, 0)(LOGSTDOUT, "error:cpgb_load: load CPGB_PAGE_ACTUAL_USED_SIZE at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    (*offset) += CPGB_PAD_SIZE;

    return (EC_TRUE);
}

void cpgb_print(LOG *log, const CPGB *cpgb)
{
    uint16_t  page_model;
    REAL      used_size;
    REAL      occupied_size;

#if 0
    for(page_model = 0; CPGB_MODEL_NUM > page_model; page_model ++)
    {
        cpgb_page_model_print(log, cpgb, page_model);
        sys_log(log, "----------------------------------------------------------\n");
    }
#endif
    used_size     = (0.0 + CPGB_PAGE_ACTUAL_USED_SIZE(cpgb));
    occupied_size = (0.0 + CPGB_PAGE_USED_NUM(cpgb) * (uint32_t)(1 << CPGB_PAGE_BIT_SIZE));

    sys_log(log, "cpgb_print: cpgb %p, bitmap buff %p, "
                 "page max num %u, page used num %u, used size %u, ratio %.2f\n",
                 cpgb,
                 CPGB_PAGE_MODEL_CPGRB_BITMAP_BUFF(cpgb),
                 CPGB_PAGE_MAX_NUM(cpgb),
                 CPGB_PAGE_USED_NUM(cpgb),
                 CPGB_PAGE_ACTUAL_USED_SIZE(cpgb),
                 EC_TRUE == REAL_ISZERO(CMPI_ERROR_MODI, occupied_size) ? 0.0 : (used_size / occupied_size)
                 );

    sys_log(log, "cpgb_print: cpgb %p, assign bitmap %s \n",
                 cpgb,
                 c_uint16_t_to_bin_str(CPGB_PAGE_MODEL_ASSIGN_BITMAP(cpgb))
                 );
    for(page_model = 0; CPGB_MODEL_NUM > page_model; page_model ++)
    {
        const CPGB_CONF *cpgb_conf;

        cpgb_conf = &(g_cpgb_conf[ page_model ]);

        if(CPGB_PAGE_MODEL_ASSIGN_BITMAP(cpgb) & (1 << page_model))
        {
            sys_log(log, "cpgb_print: cpgb %p, model %s has page to assign\n", cpgb, CPGB_CONF_NAME(cpgb_conf));
        }
        else
        {
            sys_log(log, "cpgb_print: cpgb %p, model %s no  page to assign\n", cpgb, CPGB_CONF_NAME(cpgb_conf));
        }
    }
    return;
}

/* ---- debug ---- */
EC_BOOL cpgb_debug_cmp(const CPGB *cpgb_1st, const CPGB *cpgb_2nd)
{
    uint16_t page_model;

    /*cpgrb pool*/
    if(EC_FALSE == cpgrb_debug_cmp(CPGB_CPGRB_POOL(cpgb_1st), CPGB_CPGRB_POOL(cpgb_2nd)))
    {
        dbg_log(SEC_0122_CPGB, 0)(LOGSTDOUT, "error:cpgb_debug_cmp: inconsistent cpgrb pool\n");
        return (EC_FALSE);
    }

    /*root pos*/
    for(page_model = 0; CPGB_MODEL_NUM > page_model; page_model ++ )
    {
        uint16_t root_pos_1st;
        uint16_t root_pos_2nd;

        root_pos_1st = CPGB_PAGE_MODEL_CPGRB_ROOT_POS(cpgb_1st, page_model);
        root_pos_2nd = CPGB_PAGE_MODEL_CPGRB_ROOT_POS(cpgb_2nd, page_model);

        if(root_pos_1st != root_pos_2nd)
        {
            dbg_log(SEC_0122_CPGB, 0)(LOGSTDOUT, "error:cpgb_debug_cmp: inconsistent root_pos: %u != %u at page_model %u\n",
                                root_pos_1st, root_pos_2nd, page_model);
            return (EC_FALSE);
        }
    }

    /*rb bitmap*/
    for(page_model = 0; CPGB_MODEL_NUM > page_model; page_model ++ )
    {
        const CPGB_CONF *cpgb_conf;
        const uint8_t *pgc_cpgrb_bitmap_1st;
        const uint8_t *pgc_cpgrb_bitmap_2nd;
        uint16_t   cpgrb_bitmap_size;
        uint16_t   cpgrb_bitmap_pos;

        cpgb_conf = &(g_cpgb_conf[ page_model ]);
        cpgrb_bitmap_size = CPGB_CONF_CPGRB_BITMAP_SIZE(cpgb_conf);

        pgc_cpgrb_bitmap_1st = CPGB_PAGE_MODEL_CPGRB_BITMAP(cpgb_1st, page_model);
        pgc_cpgrb_bitmap_2nd = CPGB_PAGE_MODEL_CPGRB_BITMAP(cpgb_2nd, page_model);

        for(cpgrb_bitmap_pos = 0; cpgrb_bitmap_pos < cpgrb_bitmap_size; cpgrb_bitmap_pos ++)
        {
            if(pgc_cpgrb_bitmap_1st[ cpgrb_bitmap_pos ] != pgc_cpgrb_bitmap_1st[ cpgrb_bitmap_pos ])
            {
                dbg_log(SEC_0122_CPGB, 0)(LOGSTDOUT, "error:cpgb_debug_cmp: inconsistent bitmap at pos %u: %u != %u where page_model %u\n",
                                    cpgrb_bitmap_pos,
                                    pgc_cpgrb_bitmap_1st[ cpgrb_bitmap_pos ], pgc_cpgrb_bitmap_2nd[ cpgrb_bitmap_pos ],
                                    page_model);
                return (EC_FALSE);
            }
        }
    }

    /*assign bitmap*/
    if(CPGB_PAGE_MODEL_ASSIGN_BITMAP(cpgb_1st) != CPGB_PAGE_MODEL_ASSIGN_BITMAP(cpgb_1st))
    {
        dbg_log(SEC_0122_CPGB, 0)(LOGSTDOUT, "error:cpgb_debug_cmp: inconsistent CPGB_PAGE_MODEL_ASSIGN_BITMAP: %u != %u\n",
                            CPGB_PAGE_MODEL_ASSIGN_BITMAP(cpgb_1st), CPGB_PAGE_MODEL_ASSIGN_BITMAP(cpgb_2nd));
        return (EC_FALSE);
    }

    /*page max num*/
    if(CPGB_PAGE_MAX_NUM(cpgb_1st) != CPGB_PAGE_MAX_NUM(cpgb_1st))
    {
        dbg_log(SEC_0122_CPGB, 0)(LOGSTDOUT, "error:cpgb_debug_cmp: inconsistent CPGB_PAGE_MAX_NUM: %u != %u\n",
                            CPGB_PAGE_MAX_NUM(cpgb_1st), CPGB_PAGE_MAX_NUM(cpgb_2nd));
        return (EC_FALSE);
    }

    /*page used num*/
    if(CPGB_PAGE_USED_NUM(cpgb_1st) != CPGB_PAGE_USED_NUM(cpgb_1st))
    {
        dbg_log(SEC_0122_CPGB, 0)(LOGSTDOUT, "error:cpgb_debug_cmp: inconsistent CPGB_PAGE_USED_NUM: %u != %u\n",
                            CPGB_PAGE_USED_NUM(cpgb_1st), CPGB_PAGE_USED_NUM(cpgb_2nd));
        return (EC_FALSE);
    }

    /*page actual used bytes num*/
    if(CPGB_PAGE_ACTUAL_USED_SIZE(cpgb_1st) != CPGB_PAGE_ACTUAL_USED_SIZE(cpgb_1st))
    {
        dbg_log(SEC_0122_CPGB, 0)(LOGSTDOUT, "error:cpgb_debug_cmp: inconsistent CPGB_PAGE_ACTUAL_USED_SIZE: %u != %u\n",
                            CPGB_PAGE_ACTUAL_USED_SIZE(cpgb_1st), CPGB_PAGE_ACTUAL_USED_SIZE(cpgb_2nd));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

