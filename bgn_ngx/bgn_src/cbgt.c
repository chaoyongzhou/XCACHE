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

#include <pcre.h>
#include <libgen.h>
#include <zlib.h>

#include "type.h"
#include "mm.h"
#include "log.h"

#include "cbc.h"

#include "cmisc.h"
#include "cmutex.h"
#include "cbytes.h"
#include "cstring.h"
#include "mod.inc"
#include "cmpic.inc"
#include "task.h"
#include "cbtimer.h"
#include "cmpie.h"
#include "cbitmap.h"
#include "csession.h"
#include "cdfs.h"
#include "cbgt.h"


#include "db_internal.h"

#include "findex.inc"

#define CBGT_MD_CAPACITY()          (cbc_md_capacity(MD_CBGT))

#define CBGT_MD_GET(cbgt_md_id)     ((CBGT_MD *)cbc_md_get(MD_CBGT, (cbgt_md_id)))

#define CBGT_MD_ID_CHECK_INVALID(cbgt_md_id)  \
    ((CMPI_ANY_MODI != (cbgt_md_id)) && ((NULL_PTR == CBGT_MD_GET(cbgt_md_id)) || (0 == (CBGT_MD_GET(cbgt_md_id)->usedcounter))))


/*this constant time stamp is for root/meta/colf table. timestamp of user table is inputed by user externally*/

#if 0
#define PRINT_BUFF(info, buff, len) do{\
    UINT32 __pos;\
    dbg_log(SEC_0054_CBGT, 5)(LOGSTDOUT, "%s: ", info);\
    for(__pos = 0; __pos < len; __pos ++)\
    {\
        sys_print(LOGSTDOUT, "%x,", ((UINT8 *)buff)[ __pos ]);\
    }\
    sys_print(LOGSTDOUT, "\n");\
}while(0)
#else
#define PRINT_BUFF(info, buff, len) do{}while(0)
#endif

#if 1
#define CBGT_CHECK_TABLE_EXIST(cbgt_md_id, table_id, mod_node) \
        cbgt_check_exist((cbgt_md_id), (table_id), (mod_node))
#else
#define CBGT_CHECK_TABLE_EXIST(cbgt_md_id, table_id, table_mod_node) \
        __cbgt_mod_node_is_valid(cbgt_md_id, table_mod_node)
#endif

#if 0
#define CBGT_ASSERT(x) ASSERT(x)
#else
#define CBGT_ASSERT(x) do{}while(0)
#endif

STATIC_CAST static const char * __cbgt_type(const UINT32 type);
STATIC_CAST static uint8_t __cbgt_type_to_cbtree_type(const UINT32 type);
STATIC_CAST static void __cbgt_local_mod_node(const UINT32 cbgt_md_id, MOD_NODE *mod_node);
STATIC_CAST static void __cbgt_error_mod_node(const UINT32 cbgt_md_id, MOD_NODE *mod_node);
STATIC_CAST static EC_BOOL __cbgt_make_user_table_key(const UINT32 cbgt_md_id, const CBYTES *row, const CBYTES *colf, const CBYTES *colq, CBYTES *user_table_key);
STATIC_CAST static EC_BOOL __cbgt_make_rmc_table_key(const UINT32 cbgt_md_id, const CBYTES *row, CBYTES *rmc_table_key);
STATIC_CAST static EC_BOOL __cbgt_make_colf_table_key_by_user_table_key(const UINT32 cbgt_md_id, const CBYTES *user_table_key, CBYTES *colf_table_key);
STATIC_CAST static EC_BOOL __cbgt_make_meta_table_key(const UINT32 cbgt_md_id, const CBYTES *user_colf, CBYTES *meta_table_key);
STATIC_CAST static EC_BOOL __cbgt_make_root_table_key(const UINT32 cbgt_md_id, const CBYTES *user_table_name, CBYTES *root_table_key);
STATIC_CAST static int __cbgt_make_open_flags(const UINT32 open_flags);
STATIC_CAST static void __cbgt_print_user_table_key(LOG *log, const uint8_t *key);
STATIC_CAST static void __cbgt_print_user_table_kv(LOG *log, const CBTREE *cbtree, const CBTREE_KEY *cbtree_key);
STATIC_CAST static void __cbgt_print_colf_table_row(LOG *log, const uint8_t *row);
STATIC_CAST static void __cbgt_print_colf_table_key(LOG *log, const uint8_t *key);
STATIC_CAST static void __cbgt_print_colf_kv(LOG *log, const  uint8_t *kv);
STATIC_CAST static void __cbgt_print_colf_table_kv(LOG *log, const CBTREE *cbtree, const CBTREE_KEY *cbtree_key);
STATIC_CAST static void __cbgt_print_meta_table_key(LOG *log, const uint8_t *key);
STATIC_CAST static void __cbgt_print_meta_kv(LOG *log, const  uint8_t *kv);
STATIC_CAST static void __cbgt_print_meta_table_kv(LOG *log, const CBTREE *cbtree, const CBTREE_KEY *cbtree_key);
STATIC_CAST static void __cbgt_print_root_table_key(LOG *log, const uint8_t *key);
STATIC_CAST static void __cbgt_print_root_kv(LOG *log, const  uint8_t *kv);
STATIC_CAST static void __cbgt_print_root_table_kv(LOG *log, const CBTREE *cbtree, const CBTREE_KEY *cbtree_key);
STATIC_CAST static MOD_MGR *__cbgt_gen_mod_mgr(const UINT32 cbgt_md_id, const UINT32 server_type, const UINT32 incl_tcid, const UINT32 incl_rank, const UINT32 excl_tcid, const UINT32 excl_rank);
STATIC_CAST static EC_BOOL __cbgt_start_trigger(const UINT32 cbgt_md_id, const UINT32 server_type, const UINT32 table_id, const CBYTES *table_name, const MOD_NODE *parent, const CSTRING *root_path, const UINT32 open_flags, MOD_NODE *mod_node);
STATIC_CAST static EC_BOOL __cbgt_end_trigger(const UINT32 cbgt_md_id, const MOD_NODE *mod_node);
//static EC_BOOL __cbgt_get_table(const UINT32 cbgt_md_id, const CBYTES *table_name, int (*key_compare)(const uint8_t *, const uint8_t *), UINT32 *table_id, MOD_NODE *mod_node, UINT32 *offset);
STATIC_CAST static EC_BOOL __cbgt_get_rmc_table(const UINT32 cbgt_md_id, const CBYTES *table_name, UINT32 *table_id, MOD_NODE *mod_node);
STATIC_CAST static EC_BOOL __cbgt_get_user_table(const UINT32 cbgt_md_id, const CBYTES *table_name, UINT32 *table_id, MOD_NODE *mod_node);
STATIC_CAST static EC_BOOL __cbgt_open_rmc_table(const UINT32 cbgt_md_id, const UINT32 server_type, const CBYTES *table_name, UINT32 *table_id, MOD_NODE *mod_node);
STATIC_CAST static EC_BOOL __cbgt_open_user_table(const UINT32 cbgt_md_id, const CBYTES *user_table_key, CBYTES *user_table_name, UINT32 *table_id, MOD_NODE *mod_node);

STATIC_CAST static EC_BOOL __cbgt_pcre_compile(const CSTRING *pattern_cstr, pcre **pattern_re);
STATIC_CAST static EC_BOOL __cbgt_pcre_free(pcre *pattern_re);

STATIC_CAST static EC_BOOL __cbgt_set_colf_table_to_session(const UINT32 cbgt_md_id, const CSTRING *colf_session_path, const UINT32 colf_table_id, const MOD_NODE *mod_node);
STATIC_CAST static EC_BOOL __cbgt_get_colf_table_from_session(const UINT32 cbgt_md_id, const CBYTES *table_name, const CBYTES *colf, CSTRING *colf_session_path, UINT32 *colf_table_id, MOD_NODE *mod_node);

STATIC_CAST static EC_BOOL __cbgt_set_meta_table_to_session(const UINT32 cbgt_md_id, const CSTRING *meta_session_path, const UINT32 meta_table_id, const MOD_NODE *mod_node);
STATIC_CAST static EC_BOOL __cbgt_get_meta_table_from_session(const UINT32 cbgt_md_id, const CBYTES *table_name, CSTRING *meta_session_path, UINT32 *meta_table_id, MOD_NODE *mod_node);

STATIC_CAST static const char * __cbgt_type(const UINT32 type)
{
    if(CBGT_TYPE_ROOT_SERVER == type)
    {
        return (const char *)"root server";
    }

    if(CBGT_TYPE_META_SERVER == type)
    {
        return (const char *)"meta server";
    }

    if(CBGT_TYPE_COLF_SERVER == type)
    {
        return (const char *)"colf server";
    }

    if(CBGT_TYPE_USER_SERVER == type)
    {
        return (const char *)"user server";
    }

    if(CBGT_TYPE_USER_CLIENT == type)
    {
        return (const char *)"user client";
    }

    return (const char *)"unknown server";
}

STATIC_CAST static uint8_t __cbgt_type_to_cbtree_type(const UINT32 type)
{
    if(CBGT_TYPE_ROOT_SERVER == type)
    {
        return (CBTREE_IS_BGT_ROOT_TABLE_TYPE);
    }

    if(CBGT_TYPE_META_SERVER == type)
    {
        return (CBTREE_IS_BGT_META_TABLE_TYPE);
    }

    if(CBGT_TYPE_COLF_SERVER == type)
    {
        return (CBTREE_IS_BGT_COLF_TABLE_TYPE);
    }

    if(CBGT_TYPE_USER_SERVER == type)
    {
        return (CBTREE_IS_BGT_USER_TABLE_TYPE);
    }

    if(CBGT_TYPE_USER_CLIENT == type)
    {
        return (CBTREE_IS_ERR_TYPE);
    }

    return (CBTREE_IS_ERR_TYPE);
}

EC_BOOL __cbgt_mod_node_is_valid(const UINT32 cbgt_md_id, const MOD_NODE *mod_node)
{
    if(
       (CMPI_ERROR_TCID == MOD_NODE_TCID(mod_node) || CMPI_ANY_TCID == MOD_NODE_TCID(mod_node))
    || (CMPI_ERROR_COMM == MOD_NODE_COMM(mod_node) || CMPI_ANY_COMM == MOD_NODE_COMM(mod_node))
    || (CMPI_ERROR_RANK == MOD_NODE_RANK(mod_node) || CMPI_ANY_RANK == MOD_NODE_RANK(mod_node))
    || (CMPI_ERROR_MODI == MOD_NODE_MODI(mod_node) || CMPI_ANY_MODI == MOD_NODE_MODI(mod_node))
    )
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL __cbgt_mod_node_is_local(const UINT32 cbgt_md_id, const MOD_NODE *mod_node)
{
    if(
       (CMPI_LOCAL_TCID == MOD_NODE_TCID(mod_node))
    && (CMPI_LOCAL_COMM == MOD_NODE_COMM(mod_node))
    && (CMPI_LOCAL_RANK == MOD_NODE_RANK(mod_node))
    && (cbgt_md_id == MOD_NODE_MODI(mod_node))
    )
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

STATIC_CAST static void __cbgt_local_mod_node(const UINT32 cbgt_md_id, MOD_NODE *mod_node)
{
    MOD_NODE_TCID(mod_node) = CMPI_LOCAL_TCID;
    MOD_NODE_COMM(mod_node) = CMPI_LOCAL_COMM;
    MOD_NODE_RANK(mod_node) = CMPI_LOCAL_RANK;
    MOD_NODE_MODI(mod_node) = cbgt_md_id;
    return;
}

STATIC_CAST static void __cbgt_error_mod_node(const UINT32 cbgt_md_id, MOD_NODE *mod_node)
{
    MOD_NODE_TCID(mod_node) = CMPI_ERROR_TCID;
    MOD_NODE_COMM(mod_node) = CMPI_ERROR_COMM;
    MOD_NODE_RANK(mod_node) = CMPI_ERROR_RANK;
    MOD_NODE_MODI(mod_node) = CMPI_ERROR_MODI;
    return;
}

/*note: here no val parameter is inputed, hence the vlen in user table key must be zero*/
STATIC_CAST static EC_BOOL __cbgt_make_user_table_key(const UINT32 cbgt_md_id, const CBYTES *row, const CBYTES *colf, const CBYTES *colq, CBYTES *user_table_key)
{
    if(EC_FALSE == cbgt_key_init(cbgt_md_id, row, colf, colq, c_time(NULL_PTR), user_table_key))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_make_user_table_key: init key failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cbgt_make_row_of_colf_table_by_start_end_user_table_key(const uint8_t *start_user_table_key, const uint8_t *end_user_table_key, CBYTES *colf_row_bytes)
{
    CBYTES start_user_table_key_bytes;
    CBYTES end_user_table_key_bytes;

    cbytes_init(&start_user_table_key_bytes);
    cbytes_init(&end_user_table_key_bytes);

    cbytes_mount(&start_user_table_key_bytes, keyGettLenHs(start_user_table_key), start_user_table_key);
    cbytes_mount(&end_user_table_key_bytes  , keyGettLenHs(end_user_table_key)  , end_user_table_key);

    if(EC_FALSE == cbytes_cat(&start_user_table_key_bytes, &end_user_table_key_bytes, colf_row_bytes))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_make_row_of_colf_table_by_start_end_user_table_key: make row of colf table failed\n");
        return (EC_FALSE);
    }
    return (EC_TRUE);
}


STATIC_CAST static EC_BOOL __cbgt_make_rmc_table_key(const UINT32 cbgt_md_id, const CBYTES *row, CBYTES *rmc_table_key)
{
    CBYTES colf;
    CBYTES colq;

    cbytes_init(&colf);
    cbytes_init(&colq);

    cbytes_mount(&colf , strlen("info")         , (uint8_t *)"info"         );
    cbytes_mount(&colq , strlen("vpath")        , (uint8_t *)"vpath"        );

    if(EC_FALSE == cbgt_key_init(cbgt_md_id, row, &colf, &colq, c_time(NULL_PTR), rmc_table_key))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_make_rmc_table_key: init key failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cbgt_make_colf_table_key_by_user_table_key(const UINT32 cbgt_md_id, const CBYTES *user_table_key, CBYTES *colf_table_key)
{
    CBYTES colf_row;

#if 0
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] __cbgt_make_colf_table_key_by_user_table_key: user rowkey is ");
    __cbgt_print_user_table_key(LOGSTDOUT, cbytes_buf(user_table_key));
    sys_print(LOGSTDOUT, "\n");
#endif

    cbytes_init(&colf_row);
    if(EC_FALSE == cbytes_cat(user_table_key, user_table_key, &colf_row))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_get_user_table_and_key_no_lock: cat user_table_key and user_table_key failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == __cbgt_make_rmc_table_key(cbgt_md_id, &colf_row, colf_table_key))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_make_colf_table_key_by_user_table_key: init key failed\n");
        cbytes_clean(&colf_row);
        return (EC_FALSE);
    }
    cbytes_clean(&colf_row);
#if 0
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] __cbgt_make_colf_table_key_by_user_table_key: colf rowkey is ");
    __cbgt_print_colf_table_key(LOGSTDOUT, cbytes_buf(colf_table_key));
    sys_print(LOGSTDOUT, "\n");
#endif
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cbgt_make_default_row_of_colf_table(const UINT32 cbgt_md_id, CBYTES *colf_row)
{
    CBYTES row;
    CBYTES colf;
    CBYTES colq;
    //CBYTES ts;
    CBYTES start_user_rowkey;
    CBYTES end_user_rowkey;

    UINT8  min_byte = 0x00;
    UINT8  max_byte = 0xFF;
    //UINT8  min_ts_bytes[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    //UINT8  max_ts_bytes[8] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    ctime_t min_ts = 0x00;
    ctime_t max_ts = (ctime_t)~0;

    cbytes_init(&row);
    cbytes_init(&colf);
    cbytes_init(&colq);
    //cbytes_init(&ts);

    cbytes_mount(&row , 1, &min_byte);
    cbytes_mount(&colf, 1, &min_byte);
    cbytes_mount(&colq, 1, &min_byte);
    //cbytes_mount(&ts  , 8,  min_ts_bytes);

    if(EC_FALSE == cbgt_key_init(cbgt_md_id, &row, &colf, &colq, min_ts, &start_user_rowkey))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_make_default_row_of_colf_table: make start user rowkey failed\n");
        return (EC_FALSE);
    }

    cbytes_init(&row);
    cbytes_init(&colf);
    cbytes_init(&colq);
    //cbytes_init(&ts);

    cbytes_mount(&row , 1, &max_byte);
    cbytes_mount(&colf, 1, &max_byte);
    cbytes_mount(&colq, 1, &max_byte);
    //cbytes_mount(&ts  , 8,  max_ts_bytes);

    if(EC_FALSE == cbgt_key_init(cbgt_md_id, &row, &colf, &colq, max_ts, &end_user_rowkey))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_make_default_row_of_colf_table: make end user rowkey failed\n");
        cbytes_clean(&start_user_rowkey);
        return (EC_FALSE);
    }

    if(EC_FALSE == cbytes_cat(&start_user_rowkey, &end_user_rowkey, colf_row))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_make_default_row_of_colf_table: cat start and end user rowkeys failed\n");
        cbytes_clean(&start_user_rowkey);
        cbytes_clean(&end_user_rowkey);
        return (EC_FALSE);
    }

    cbytes_clean(&start_user_rowkey);
    cbytes_clean(&end_user_rowkey);

    return (EC_TRUE);
}

STATIC_CAST static void __cbgt_split_colf_row_into_start_end_user_table_key(const uint8_t *colf_row, uint8_t **start_user_table_key, uint8_t **end_user_table_key)
{
    (*start_user_table_key) = (uint8_t *)colf_row;
    (*end_user_table_key)   = (uint8_t *)(colf_row + keyGettLenHs(colf_row));
    return;
}

STATIC_CAST static int __cbgt_cmp_colf_row_and_user_table_key(const uint8_t *colf_row, const uint8_t *user_table_key)
{
    uint8_t *start_user_rowkey;
    uint8_t *end_user_rowkey;

    int cmp_ret;

    __cbgt_split_colf_row_into_start_end_user_table_key(colf_row, &start_user_rowkey, &end_user_rowkey);

    cmp_ret = keyCmpHs2(start_user_rowkey, user_table_key);
    if(0 <= cmp_ret)/*i.e., user_table_key <= start_user_rowkey*/
    {
        //sys_print(LOGSTDOUT, "[1]\n");
        return (1);
    }

    cmp_ret = keyCmpHs2(end_user_rowkey, user_table_key);
    if(0 > cmp_ret)/*i.e., user_table_key > end_user_rowkey*/
    {
        //sys_print(LOGSTDOUT, "[-1]\n");
        return (-1);
    }
    //sys_print(LOGSTDOUT, "[0]\n");
    return (0);
}

STATIC_CAST static EC_BOOL __cbgt_make_meta_table_key(const UINT32 cbgt_md_id, const CBYTES *user_colf, CBYTES *meta_table_key)
{
    if(EC_FALSE == __cbgt_make_rmc_table_key(cbgt_md_id, user_colf, meta_table_key))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_make_meta_table_key: init key failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cbgt_make_root_table_key(const UINT32 cbgt_md_id, const CBYTES *user_table_name, CBYTES *root_table_key)
{
    if(EC_FALSE == __cbgt_make_rmc_table_key(cbgt_md_id, user_table_name, root_table_key))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_make_root_table_key: init key failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

STATIC_CAST static int __cbgt_make_open_flags(const UINT32 open_flags)
{
    int flags;

    flags = 0;
    if(open_flags & CBGT_O_RDWR)
    {
        flags |= O_RDWR;
    }

    if(open_flags & CBGT_O_CREAT)
    {
        flags |= O_CREAT;
    }

    return flags;
}

STATIC_CAST static void __cbgt_print_user_table_key(LOG *log, const uint8_t *key)
{
    uint16_t klen;
    uint16_t rlen;
    uint16_t cqlen;
    uint8_t  cflen;
    uint8_t  type;

    const uint8_t *row;
    const uint8_t *colf;
    const uint8_t *colq;
    ctime_t  ts;

    klen  = keyGetkLenHs(key);
    rlen  = keyGetrLenHs(key);
    cflen = keyGetcfLenHs(key);
    cqlen = keyGetcqLenHs(key);

    row  = keyGetRowHs(key);
    colf = keyGetColFamilyHs(key);
    colq = keyGetColQualifierHs(key);
    ts   = keyGetTimeStampHs(key);
    type = keyGetType(key);

    if(1 == rlen && 0x00 == row[0]
    && 1 == cflen && 0x00 == colf[0]
    && 1 == cqlen && 0x00 == colq[0]
    && 0 == ts
    )
    {
        sys_print(log, "(_:_:_:________:%d)", type);
        return;
    }

    if(1 == rlen && 0xFF == row[0]
    && 1 == cflen && 0xFF == colf[0]
    && 1 == cqlen && 0xFF == colq[0]
    && ((ctime_t)~0) == ts
    )
    {
        sys_print(log, "(^:^:^:^^^^^^^^:%d)", type);
        return;
    }

    /*Assume row, colf, colq are human readiable string*/
    sys_print(log,"(%p, %.*s:%.*s:%.*s:%ld:%d)",
                        key,
                        rlen, row,
                        cflen, colf,
                        cqlen, colq,
                        ts,
                        type
                        );
    return;
}

STATIC_CAST static void __cbgt_print_user_table_cbtree_key(LOG *log, const CBTREE *cbtree, const CBTREE_KEY *cbtree_key)
{
    __cbgt_print_user_table_key(log, CBTREE_KEY_LATEST(cbtree_key));
    return;
}


STATIC_CAST static void __cbgt_print_user_table_kv(LOG *log, const CBTREE *cbtree, const CBTREE_KEY *cbtree_key)
{
    const uint8_t *kv;
    kv = CBTREE_KEY_LATEST(cbtree_key);

    sys_log(log,"kv %p: ", kv);
    kvPrintHs(log, kv);
    return;
}

STATIC_CAST static void __cbgt_print_colf_table_key(LOG *log, const uint8_t *key)
{
    uint16_t klen;
    uint16_t rlen;
    uint16_t cqlen;
    uint8_t  cflen;
    uint8_t  type;

    const uint8_t *row;
    const uint8_t *colf;
    const uint8_t *colq;
    ctime_t  ts;

    uint8_t *start_user_rowkey;
    uint8_t *end_user_rowkey;

    klen  = keyGetkLenHs(key);
    rlen  = keyGetrLenHs(key);
    cflen = keyGetcfLenHs(key);
    cqlen = keyGetcqLenHs(key);

    row  = keyGetRowHs(key);
    colf = keyGetColFamilyHs(key);
    colq = keyGetColQualifierHs(key);
    ts   = keyGetTimeStampHs(key);
    type = keyGetType(key);

    __cbgt_split_colf_row_into_start_end_user_table_key(row, &start_user_rowkey, &end_user_rowkey);

    /*Assume row, colf, colq are human readiable string*/
    sys_print(log,"(%p,", key);

    sys_print(log, " startUserRowKey");
    __cbgt_print_user_table_key(log, start_user_rowkey);

    sys_print(log, " endUserRowKey");
    __cbgt_print_user_table_key(log, end_user_rowkey);

    sys_print(log,":%.*s:%.*s:%ld:%d)",
                        cflen, colf,
                        cqlen, colq,
                        ts,
                        type
                        );
    return;
}

STATIC_CAST static void __cbgt_print_colf_table_cbtree_key(LOG *log, const CBTREE *cbtree, const CBTREE_KEY *cbtree_key)
{
    __cbgt_print_colf_table_key(log, CBTREE_KEY_LATEST(cbtree_key));
    return;
}


STATIC_CAST static void __cbgt_print_colf_table_row(LOG *log, const uint8_t *row)
{
    uint8_t *start_user_rowkey;
    uint8_t *end_user_rowkey;

    __cbgt_split_colf_row_into_start_end_user_table_key(row, &start_user_rowkey, &end_user_rowkey);

    /*Assume row, colf, colq are human readiable string*/
    sys_print(log,"(");

    sys_print(log, "startUserRowKey");
    __cbgt_print_user_table_key(log, start_user_rowkey);

    sys_print(log, " endUserRowKey");
    __cbgt_print_user_table_key(log, end_user_rowkey);

    sys_print(log,")");
    return;
}

STATIC_CAST static void __cbgt_print_colf_kv(LOG *log, const  uint8_t *kv)
{
    const uint8_t *key;
    const uint8_t *val;

    UINT32    user_table_id;
    MOD_NODE  user_mod_node;

    uint32_t  counter;

    key  = kv;
    val  = kvGetValueHs(kv);

    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] __cbgt_print_colf_kv: kv %p, vlen %d, value %p\n", kv, kvGetvLenHs(kv), val);

    counter = 0;
    user_table_id = gdbGetWord(val, &counter);
    MOD_NODE_TCID(&user_mod_node) = gdbGetWord(val, &counter);
    MOD_NODE_COMM(&user_mod_node) = gdbGetWord(val, &counter);
    MOD_NODE_RANK(&user_mod_node) = gdbGetWord(val, &counter);
    MOD_NODE_MODI(&user_mod_node) = gdbGetWord(val, &counter);

    sys_print(log,"key = {");
    __cbgt_print_colf_table_key(log, key);
    //kvPrintHs(log, kvGetRowHs(kv));

    sys_print(log,"} ");
    sys_print(log,"val = {user table id %ld, user mod node (tcid %s, comm %ld, rank %ld, modi %ld)}\n",
                        user_table_id,
                        MOD_NODE_TCID_STR(&user_mod_node),
                        MOD_NODE_COMM(&user_mod_node),
                        MOD_NODE_RANK(&user_mod_node),
                        MOD_NODE_MODI(&user_mod_node)
                        );
    return;
}

STATIC_CAST static void __cbgt_print_colf_table_kv(LOG *log, const CBTREE *cbtree, const CBTREE_KEY *cbtree_key)
{
    const uint8_t *kv;
    kv = CBTREE_KEY_LATEST(cbtree_key);
    //sys_log(log,"at %8d: [ROW]", offset);
    //kvPrintHs(log, kvGetRowHs(kv));
    sys_log(log,"kv %p: ", kv);
    __cbgt_print_colf_kv(log, kv);
    return;
}

STATIC_CAST static void __cbgt_print_meta_table_key(LOG *log, const uint8_t *key)
{
    keyPrintHs(log, key);
    return;
}

STATIC_CAST static void __cbgt_print_meta_table_cbtree_key(LOG *log, const CBTREE *cbtree, const CBTREE_KEY *cbtree_key)
{
    __cbgt_print_meta_table_key(log, CBTREE_KEY_LATEST(cbtree_key));
    return;
}

STATIC_CAST static void __cbgt_print_meta_kv(LOG *log, const  uint8_t *kv)
{
    const uint8_t *key;
    const uint8_t *val;

    UINT32    colf_table_id;
    MOD_NODE  colf_mod_node;

    uint32_t  counter;

    key  = kv;
    val  = kvGetValueHs(kv);

    counter = 0;
    colf_table_id = gdbGetWord(val, &counter);
    MOD_NODE_TCID(&colf_mod_node) = gdbGetWord(val, &counter);
    MOD_NODE_COMM(&colf_mod_node) = gdbGetWord(val, &counter);
    MOD_NODE_RANK(&colf_mod_node) = gdbGetWord(val, &counter);
    MOD_NODE_MODI(&colf_mod_node) = gdbGetWord(val, &counter);

    sys_print(log,"key = ");
    keyPrintHs(log, key);
    sys_print(log," ");
    sys_print(log,"val = {colf table id %ld, colf mod node (tcid %s, comm %ld, rank %ld, modi %ld)}\n",
                        colf_table_id,
                        MOD_NODE_TCID_STR(&colf_mod_node),
                        MOD_NODE_COMM(&colf_mod_node),
                        MOD_NODE_RANK(&colf_mod_node),
                        MOD_NODE_MODI(&colf_mod_node)
                        );
    return;
}

STATIC_CAST static void __cbgt_print_meta_table_kv(LOG *log, const CBTREE *cbtree, const CBTREE_KEY *cbtree_key)
{
    const uint8_t *kv;
    kv = CBTREE_KEY_LATEST(cbtree_key);

    sys_log(log,"kv %p: ", kv);
    __cbgt_print_meta_kv(log, kv);
    return;
}

STATIC_CAST static void __cbgt_print_root_table_key(LOG *log, const uint8_t *key)
{
    keyPrintHs(log, key);
    return;
}

STATIC_CAST static void __cbgt_print_root_table_cbtree_key(LOG *log, const CBTREE *cbtree, const CBTREE_KEY *cbtree_key)
{
    __cbgt_print_root_table_key(log, CBTREE_KEY_LATEST(cbtree_key));
    return;
}

STATIC_CAST static void __cbgt_print_root_kv(LOG *log, const  uint8_t *kv)
{
    const uint8_t *key;
    const uint8_t *val;

    UINT32    meta_table_id;
    MOD_NODE  meta_mod_node;

    uint32_t  counter;

    key  = kv;
    val  = kvGetValueHs(kv);

    counter = 0;
    meta_table_id = gdbGetWord(val, &counter);
    MOD_NODE_TCID(&meta_mod_node) = gdbGetWord(val, &counter);
    MOD_NODE_COMM(&meta_mod_node) = gdbGetWord(val, &counter);
    MOD_NODE_RANK(&meta_mod_node) = gdbGetWord(val, &counter);
    MOD_NODE_MODI(&meta_mod_node) = gdbGetWord(val, &counter);

    sys_print(log,"key = ");
    keyPrintHs(log, key);
    sys_print(log," ");
    sys_print(log,"val = {meta table id %ld, meta mod node (tcid %s, comm %ld, rank %ld, modi %ld)}\n",
                        meta_table_id,
                        MOD_NODE_TCID_STR(&meta_mod_node),
                        MOD_NODE_COMM(&meta_mod_node),
                        MOD_NODE_RANK(&meta_mod_node),
                        MOD_NODE_MODI(&meta_mod_node)
                        );
    return;
}

STATIC_CAST static void __cbgt_print_root_table_kv(LOG *log, const CBTREE *cbtree, const CBTREE_KEY *cbtree_key)
{
    const uint8_t *kv;
    kv = CBTREE_KEY_LATEST(cbtree_key);

    sys_log(log,"kv %p: ", kv);
    __cbgt_print_root_kv(log, kv);

    return;
}

STATIC_CAST static MOD_MGR *__cbgt_gen_mod_mgr(const UINT32 cbgt_md_id, const UINT32 server_type, const UINT32 incl_tcid, const UINT32 incl_rank, const UINT32 excl_tcid, const UINT32 excl_rank)
{
    TASK_BRD  *task_brd;
    CLOAD_MGR *cload_mgr;

    MOD_MGR *mod_mgr;
    //CVECTOR *cluster_vec;
    //UINT32   cluster_cfg_pos;
    CVECTOR *tcid_vec;

    task_brd = task_brd_default_get();

    mod_mgr = mod_mgr_new(cbgt_md_id, LOAD_BALANCING_OBJ);
    if(NULL_PTR == mod_mgr)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_gen_mod_mgr: new mod mgr failed\n");
        return (NULL_PTR);
    }

    tcid_vec = cvector_new(0, MM_UINT32, LOC_CBGT_0001);
    if(NULL_PTR == tcid_vec)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_gen_mod_mgr: new tcid vec failed\n");
        mod_mgr_free(mod_mgr);
        return (NULL_PTR);
    }

    cload_mgr = cload_mgr_new();
    if(NULL_PTR == cload_mgr)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_gen_mod_mgr: new cload mgr failed\n");
        mod_mgr_free(mod_mgr);
        return (NULL_PTR);
    }

    if(CBGT_TYPE_ROOT_SERVER == server_type)
    {
        sys_cfg_collect_hsbgt_root_tcid_vec(TASK_BRD_SYS_CFG(task_brd), TASKS_CFG_CLUSTER_VEC(TASK_BRD_LOCAL_TASKS_CFG(task_brd)), tcid_vec);
    }

    if(
       CBGT_TYPE_META_SERVER == server_type
    || CBGT_TYPE_COLF_SERVER == server_type
    || CBGT_TYPE_USER_SERVER == server_type
    )
    {
        sys_cfg_collect_hsbgt_table_tcid_vec(TASK_BRD_SYS_CFG(task_brd), TASKS_CFG_CLUSTER_VEC(TASK_BRD_LOCAL_TASKS_CFG(task_brd)), tcid_vec);
    }

#if 0

    cluster_vec = TASKS_CFG_CLUSTER_VEC(TASK_BRD_LOCAL_TASKS_CFG(task_brd));
    CVECTOR_LOCK(cluster_vec, LOC_CBGT_0002);
    for(cluster_cfg_pos = 0; cluster_cfg_pos < cvector_size(cluster_vec); cluster_cfg_pos ++)
    {
        UINT32 cluster_id;
        CLUSTER_CFG *cluster_cfg;
        CLUSTER_NODE_CFG *cluster_node_cfg;

        cluster_id = (UINT32)cvector_get_no_lock(cluster_vec, cluster_cfg_pos);
        cluster_cfg = sys_cfg_get_cluster_cfg_by_id(TASK_BRD_SYS_CFG(task_brd), cluster_id);
        if(NULL_PTR == cluster_cfg)
        {
            dbg_log(SEC_0054_CBGT, 1)(LOGSTDOUT, "warn:__cbgt_gen_mod_mgr: not found cluter %ld definition\n", cluster_id);
            continue;
        }

        if(MODEL_TYPE_HSBGT_CONNEC != CLUSTER_CFG_MODEL(cluster_cfg))
        {
            dbg_log(SEC_0054_CBGT, 5)(LOGSTDOUT, "__cbgt_gen_mod_mgr: cluter %ld is not hsbgt model, skip it\n", cluster_id);
            continue;
        }

        /*whoami*/
        cluster_node_cfg = cluster_cfg_search_by_tcid_rank(cluster_cfg, TASK_BRD_TCID(task_brd), TASK_BRD_RANK(task_brd));
        if(NULL_PTR == cluster_node_cfg)
        {
            dbg_log(SEC_0054_CBGT, 1)(LOGSTDOUT, "warn:__cbgt_gen_mod_mgr: current tcid %s rank %ld not belong to cluster %ld\n",
                               TASK_BRD_TCID_STR(task_brd), TASK_BRD_RANK(task_brd), CLUSTER_CFG_ID(cluster_cfg));
            continue;
        }

        /*I am table*/
        if(EC_TRUE == cluster_node_cfg_check_role_str(cluster_node_cfg, (const char *)"table"))
        {
            /*I am root table, collect all root table tcid vec*/
            if(EC_TRUE == cluster_node_cfg_check_group_str(cluster_node_cfg, (const char *)"root"))
            {
                cluster_cfg_collect_tcid_vec_by_role_and_group_str(cluster_cfg, MODEL_TYPE_HSBGT_CONNEC, (const char *)"table", (const char *)"root", tcid_vec);
                continue;
            }
            /*I am NOT root table, collect table tcid vec*/
            else
            {
                cluster_cfg_collect_tcid_vec_by_role_str(cluster_cfg, MODEL_TYPE_HSBGT_CONNEC, (const char *)"table", tcid_vec);
            }
        }

        /*I am client, nothing to do*/
        if(EC_TRUE == cluster_node_cfg_check_role_str(cluster_node_cfg, (const char *)"client"))
        {
            /*nothing to do*/
        }
    }
    CVECTOR_UNLOCK(cluster_vec, LOC_CBGT_0003);
#endif
    /*note: sync cload_stat info (que,obj,cpu,dsk,mem,...) from each rank to ensure table is distributed*/
    task_brd_sync_cload_mgr(task_brd, tcid_vec, cload_mgr);
    mod_mgr_gen_from_cload_mgr(cload_mgr, incl_tcid, incl_rank, cbgt_md_id, mod_mgr);
    cvector_free(tcid_vec, LOC_CBGT_0004);
    cload_mgr_free(cload_mgr);

    mod_mgr_excl(excl_tcid, CMPI_ANY_COMM, excl_rank, cbgt_md_id, mod_mgr);

#if 1
    dbg_log(SEC_0054_CBGT, 5)(LOGSTDOUT, "------------------------------------ __cbgt_gen_mod_mgr beg ----------------------------------\n");
    mod_mgr_print(LOGSTDOUT, mod_mgr);
    dbg_log(SEC_0054_CBGT, 5)(LOGSTDOUT, "------------------------------------ __cbgt_gen_mod_mgr end ----------------------------------\n");
#endif
    return (mod_mgr);
}

STATIC_CAST static EC_BOOL __cbgt_start_trigger(const UINT32 cbgt_md_id, const UINT32 server_type, const UINT32 table_id, const CBYTES *table_name, const MOD_NODE *parent, const CSTRING *root_path, const UINT32 open_flags, MOD_NODE *mod_node)
{
    MOD_MGR *src_mod_mgr;
    MOD_MGR *des_mod_mgr;
    UINT32   mod_num;

    mod_num = 1;

    //src_mod_mgr = __cbgt_gen_mod_mgr(cbgt_md_id, CMPI_ANY_TCID, CMPI_ANY_RANK, CMPI_ANY_TCID, CMPI_FWD_RANK);
    src_mod_mgr = __cbgt_gen_mod_mgr(cbgt_md_id, server_type, CMPI_ANY_TCID, CMPI_ANY_RANK, CMPI_ANY_TCID, CMPI_ERROR_RANK);
    if(NULL_PTR == src_mod_mgr)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_start_trigger: gen mod mgr failed\n");
        return (EC_FALSE);
    }

    mod_mgr_excl(CMPI_ANY_DBG_TCID, CMPI_ANY_COMM, CMPI_ANY_RANK, CMPI_ANY_MODI, src_mod_mgr);
    mod_mgr_excl(CMPI_ANY_MON_TCID, CMPI_ANY_COMM, CMPI_ANY_RANK, CMPI_ANY_MODI, src_mod_mgr);

#if 1
    dbg_log(SEC_0054_CBGT, 5)(LOGSTDOUT, "------------------------------------ __cbgt_start_trigger beg ----------------------------------\n");
    mod_mgr_print(LOGSTDOUT, src_mod_mgr);
    dbg_log(SEC_0054_CBGT, 5)(LOGSTDOUT, "------------------------------------ __cbgt_start_trigger end ----------------------------------\n");
#endif

    if(0 != task_act(src_mod_mgr, &des_mod_mgr, TASK_DEFAULT_LIVE, mod_num, LOAD_BALANCING_OBJ, TASK_PRIO_NORMAL,
                   FI_cbgt_start, server_type, table_id, table_name, parent, root_path, open_flags))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_start_trigger: start CBGT module failed\n");
        mod_mgr_free(src_mod_mgr);
        return (EC_FALSE);
    }

    mod_mgr_free(src_mod_mgr);

    if(NULL_PTR == des_mod_mgr)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_start_trigger: activate nothing\n");
        return (EC_FALSE);
    }

    if(0 == MOD_MGR_REMOTE_NUM(des_mod_mgr))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_start_trigger: start none CBGT module\n");
        mod_mgr_free(des_mod_mgr);
        return (EC_FALSE);
    }

    if(mod_num != MOD_MGR_REMOTE_NUM(des_mod_mgr))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_start_trigger: start %ld CBGT modules but need %ld CBGT modules\n",
                            MOD_MGR_REMOTE_NUM(des_mod_mgr), mod_num);
        mod_mgr_free(des_mod_mgr);
        return (EC_FALSE);
    }

    mod_node_clone(MOD_MGR_REMOTE_MOD(des_mod_mgr, 0), mod_node);
    mod_mgr_free(des_mod_mgr);
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cbgt_end_trigger(const UINT32 cbgt_md_id, const MOD_NODE *mod_node)
{
    MOD_MGR *src_mod_mgr;

    src_mod_mgr = mod_mgr_new(cbgt_md_id, LOAD_BALANCING_LOOP);
    if(NULL_PTR == src_mod_mgr)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_end_trigger: new mod mgr failed which expect to accept mod node\n");
        return (EC_FALSE);
    }

    mod_mgr_incl(MOD_NODE_TCID(mod_node), MOD_NODE_COMM(mod_node), MOD_NODE_RANK(mod_node), MOD_NODE_MODI(mod_node), src_mod_mgr);

    if(0 != task_dea(src_mod_mgr, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, FI_cbgt_end, CMPI_ERROR_MODI))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_end_trigger: start CBGT module failed\n");
        mod_mgr_free(src_mod_mgr);
        return (EC_FALSE);
    }

    //mod_mgr_free(src_mod_mgr);
    return (EC_TRUE);
}

STATIC_CAST static void __cbgt_print_table_name(const UINT32 cbgt_md_id, LOG *log)
{
    CBGT_MD  *cbgt_md;
    CBYTES   *table_name;
    UINT32    table_id;
    UINT32    type;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:__cbgt_print_table_name: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    table_id   = CBGT_MD_TABLE_ID(cbgt_md);
    table_name = CBGT_MD_TABLE_NAME(cbgt_md);
    type = CBGT_MD_TYPE(cbgt_md);

    sys_log(log, "__cbgt_print_table_name: CBGT module %ld, table id %ld, type %s, table name ",
                       cbgt_md_id, table_id, __cbgt_type(type));

    if(NULL_PTR == table_name)
    {
        sys_print(log, "(null)\n");
        return;
    }

    if(EC_TRUE == cbgt_is_root_server(cbgt_md_id))
    {
        /*inputed outside of cbgt*/
        sys_print(log, "%.*s\n", cbytes_len(table_name), cbytes_buf(table_name));
        return;
    }

    if(EC_TRUE == cbgt_is_meta_server(cbgt_md_id))
    {
        /*user tablename stored in root table*/
        sys_print(log, "%.*s\n", cbytes_len(table_name), cbytes_buf(table_name));
        return;
    }

    if(EC_TRUE == cbgt_is_colf_server(cbgt_md_id))
    {
        /*colf name stored in meta table*/
        sys_print(log, "%.*s\n", cbytes_len(table_name), cbytes_buf(table_name));
        return;
    }

    if(EC_TRUE == cbgt_is_user_server(cbgt_md_id))
    {
        __cbgt_print_colf_table_row(log, cbytes_buf(table_name));
        sys_print(log, "\n");
        return;
    }

    sys_log(log, "unknown type %ld", type);
    sys_print(log, "\n");
    return;
}

STATIC_CAST static void __cbgt_print_row(const UINT32 cbgt_md_id, const CBYTES *row, LOG *log)
{
    CBGT_MD  *cbgt_md;
    UINT32    table_id;
    UINT32    type;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:__cbgt_print_row: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    table_id   = CBGT_MD_TABLE_ID(cbgt_md);
    type = CBGT_MD_TYPE(cbgt_md);

    sys_log(log, "__cbgt_print_row: CBGT module %ld, table id %ld, type %s, input row is ",
                       cbgt_md_id, table_id, __cbgt_type(type));

    if(NULL_PTR == row)
    {
        sys_print(log, "(null)\n");
        return;
    }

    if(EC_TRUE == cbgt_is_root_server(cbgt_md_id))
    {
        /*inputed outside of cbgt*/
        sys_print(log, "%.*s\n", cbytes_len(row), cbytes_buf(row));
        return;
    }

    if(EC_TRUE == cbgt_is_meta_server(cbgt_md_id))
    {
        /*user tablename stored in root table*/
        sys_print(log, "%.*s\n", cbytes_len(row), cbytes_buf(row));
        return;
    }

    if(EC_TRUE == cbgt_is_colf_server(cbgt_md_id))
    {
        /*colf name stored in meta table*/
        __cbgt_print_colf_table_row(log, cbytes_buf(row));
        return;
    }

    if(EC_TRUE == cbgt_is_user_server(cbgt_md_id))
    {
        sys_print(log, "%.*s\n", cbytes_len(row), cbytes_buf(row));
        return;
    }

    sys_log(log, "unknown type %ld", type);
    sys_print(log, "\n");
    return;
}

STATIC_CAST static void __cbgt_print_key(const UINT32 cbgt_md_id, const uint8_t *key, LOG *log)
{
    CBGT_MD  *cbgt_md;
    UINT32    table_id;
    UINT32    type;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:__cbgt_print_key: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    table_id   = CBGT_MD_TABLE_ID(cbgt_md);
    type = CBGT_MD_TYPE(cbgt_md);

    sys_log(log, "__cbgt_print_key: CBGT module %ld, table id %ld, type %s, input key is ",
                       cbgt_md_id, table_id, __cbgt_type(type));

    if(NULL_PTR == key)
    {
        sys_print(log, "(null)\n");
        return;
    }

    if(EC_TRUE == cbgt_is_root_server(cbgt_md_id))
    {
        __cbgt_print_root_table_key(log, key);
        return;
    }

    if(EC_TRUE == cbgt_is_meta_server(cbgt_md_id))
    {
        /*user tablename stored in root table*/
        __cbgt_print_meta_table_key(log, key);
        return;
    }

    if(EC_TRUE == cbgt_is_colf_server(cbgt_md_id))
    {
        /*colf name stored in meta table*/
        __cbgt_print_colf_table_key(log, key);
        return;
    }

    if(EC_TRUE == cbgt_is_user_server(cbgt_md_id))
    {
        __cbgt_print_user_table_key(log, key);
        return;
    }

    sys_log(log, "unknown type %ld", type);
    sys_print(log, "\n");
    return;
}

STATIC_CAST static CSTRING *__cbgt_gen_root_record_file_name_cstr(const CSTRING *root_path)
{
    CSTRING *root_record_file_name;
    root_record_file_name = cstring_new(NULL_PTR, LOC_CBGT_0005);
    if(NULL_PTR == root_record_file_name)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_gen_root_record_file_name_cstr: new cstring failed\n");
        return (NULL_PTR);
    }
    cstring_format(root_record_file_name, "%s/root_table.record", (char *)cstring_get_str(root_path));
    return (root_record_file_name);
}

#if (SWITCH_OFF == CBGT_BASED_ON_HSDFS_SWITCH)
EC_BOOL __cbgt_flush_root_record_file(const UINT32 cbgt_md_id, const CSTRING *root_path, const UINT32 root_table_id, const MOD_NODE *root_mod_node)
{
    CSTRING *root_record_file_name;
    UINT32 data;
    int fd;

    root_record_file_name = __cbgt_gen_root_record_file_name_cstr(root_path);
    if(NULL_PTR == root_record_file_name)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_flush_root_record_file: gen root record file name failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == c_basedir_create((char *)cstring_get_str(root_record_file_name)))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_flush_root_record_file: create basedir of file %s failed\n",
                            (char *)cstring_get_str(root_record_file_name));
        cstring_free(root_record_file_name);
        return (EC_FALSE);
    }

    fd = c_file_open((char *)cstring_get_str(root_record_file_name), O_RDWR | O_CREAT, 0666);
    if(-1 == fd)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT,"error:__cbgt_flush_root_record_file: create %s failed\n", (char *)cstring_get_str(root_record_file_name));
        cstring_free(root_record_file_name);
        return (EC_FALSE);
    }

    data = hton_uint32(root_table_id);
    write(fd, &data, sizeof(UINT32));

    data = hton_uint32(MOD_NODE_TCID(root_mod_node));
    write(fd, &data, sizeof(UINT32));

    data = hton_uint32(MOD_NODE_COMM(root_mod_node));
    write(fd, &data, sizeof(UINT32));

    data = hton_uint32(MOD_NODE_RANK(root_mod_node));
    write(fd, &data, sizeof(UINT32));

    data = hton_uint32(MOD_NODE_MODI(root_mod_node));
    write(fd, &data, sizeof(UINT32));

    close(fd);

    cstring_free(root_record_file_name);
    return (EC_TRUE);

}

EC_BOOL __cbgt_load_root_record_file(const UINT32 cbgt_md_id, const CSTRING *root_path, UINT32 *root_table_id, MOD_NODE *root_mod_node)
{
    CSTRING *root_record_file_name;
    UINT32 data;
    int fd;

    root_record_file_name = __cbgt_gen_root_record_file_name_cstr(root_path);
    if(NULL_PTR == root_record_file_name)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_load_root_record_file: gen root record file name failed\n");
        return (EC_FALSE);
    }

    fd = c_file_open((char *)cstring_get_str(root_record_file_name), O_RDWR, 0666);
    if(-1 == fd)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT,"error:__cbgt_load_root_record_file: open %s failed\n", (char *)cstring_get_str(root_record_file_name));
        cstring_free(root_record_file_name);
        return (EC_FALSE);
    }

    /*root table id | tcid | comm | rank | modi*/

    read(fd, &data, sizeof(UINT32));
    (*root_table_id) = ntoh_uint32(data);

    read(fd, &data, sizeof(UINT32));
    MOD_NODE_TCID(root_mod_node) = ntoh_uint32(data);

    read(fd, &data, sizeof(UINT32));
    MOD_NODE_COMM(root_mod_node) = ntoh_uint32(data);

    read(fd, &data, sizeof(UINT32));
    MOD_NODE_RANK(root_mod_node) = ntoh_uint32(data);

    read(fd, &data, sizeof(UINT32));
    MOD_NODE_MODI(root_mod_node) = ntoh_uint32(data);

    close(fd);

    cstring_free(root_record_file_name);
    return (EC_TRUE);

}
#endif/*(SWITCH_OFF == CBGT_BASED_ON_HSDFS_SWITCH)*/

#if (SWITCH_ON == CBGT_BASED_ON_HSDFS_SWITCH)
EC_BOOL __cbgt_flush_root_record_file(const UINT32 cbgt_md_id, const CSTRING *root_path, const UINT32 root_table_id, const MOD_NODE *root_mod_node)
{
    CBGT_MD *cbgt_md;
    CSTRING *root_record_file_name;

    uint8_t  buff[CBGT_RECORD_FILE_SIZE];
    uint32_t counter;

    CBYTES   cbytes;

    cbgt_md = CBGT_MD_GET(cbgt_md_id);

    root_record_file_name = __cbgt_gen_root_record_file_name_cstr(root_path);
    if(NULL_PTR == root_record_file_name)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_flush_root_record_file: gen root record file name failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cdfs_exists_npp(CBGT_MD_CDFS_MD_ID(cbgt_md), root_record_file_name))
    {
        if(EC_FALSE == cdfs_truncate(CBGT_MD_CDFS_MD_ID(cbgt_md), root_record_file_name, CBGT_RECORD_FILE_SIZE, CBGT_REPLICA_NUM))
        {
            dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_flush_root_record_file: truncate %s with %ld bytes and %ld replicas failed\n",
                                (char *)cstring_get_str(root_record_file_name), (UINT32)CBGT_RECORD_FILE_SIZE, CBGT_REPLICA_NUM);
            cstring_free(root_record_file_name);
            return (EC_FALSE);
        }
    }

    counter = 0;
    gdbPutWord(buff, &counter, root_table_id);
    gdbPutWord(buff, &counter, MOD_NODE_TCID(root_mod_node));
    gdbPutWord(buff, &counter, MOD_NODE_COMM(root_mod_node));
    gdbPutWord(buff, &counter, MOD_NODE_RANK(root_mod_node));
    gdbPutWord(buff, &counter, MOD_NODE_MODI(root_mod_node));

    cbytes_init(&cbytes);
    cbytes_mount(&cbytes, counter, buff);
    if(EC_FALSE == cdfs_update(CBGT_MD_CDFS_MD_ID(cbgt_md), root_record_file_name, &cbytes))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_flush_root_record_file:flush table %ld (tcid %s,comm %ld,rank %ld,modi %ld) to root record file %s failed\n",
                            root_table_id,
                            MOD_NODE_TCID_STR(root_mod_node),
                            MOD_NODE_COMM(root_mod_node),
                            MOD_NODE_RANK(root_mod_node),
                            MOD_NODE_MODI(root_mod_node),
                            (char *)cstring_get_str(root_record_file_name)
                            );
        cbytes_umount(&cbytes, NULL_PTR, NULL_PTR);
        cstring_free(root_record_file_name);
        return (EC_FALSE);
    }

    cbytes_umount(&cbytes, NULL_PTR, NULL_PTR);
    cstring_free(root_record_file_name);
    return (EC_TRUE);

}

EC_BOOL __cbgt_load_root_record_file(const UINT32 cbgt_md_id, const CSTRING *root_path, UINT32 *root_table_id, MOD_NODE *root_mod_node)
{
    CBGT_MD *cbgt_md;
    CSTRING *root_record_file_name;

    CBYTES    *cbytes;
    uint8_t   *buff;
    uint32_t   counter;

    cbgt_md = CBGT_MD_GET(cbgt_md_id);

    root_record_file_name = __cbgt_gen_root_record_file_name_cstr(root_path);
    if(NULL_PTR == root_record_file_name)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_load_root_record_file: gen root record file name failed\n");
        return (EC_FALSE);
    }

    cbytes = cbytes_new(0);
    if(NULL_PTR == cbytes)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_load_root_record_file: new cdfs buff failed\n");
        cstring_free(root_record_file_name);
        return (EC_FALSE);
    }

    if(EC_FALSE == cdfs_read(CBGT_MD_CDFS_MD_ID(cbgt_md), root_record_file_name, cbytes))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_load_root_record_file:read %s failed\n", (char *)cstring_get_str(root_record_file_name));
        cstring_free(root_record_file_name);
        cbytes_free(cbytes);
        return (EC_FALSE);
    }

    buff = cbytes_buf(cbytes);

    counter = 0;
    (*root_table_id) = gdbGetWord(buff, &counter);
    MOD_NODE_TCID(root_mod_node) = gdbGetWord(buff, &counter);
    MOD_NODE_COMM(root_mod_node) = gdbGetWord(buff, &counter);
    MOD_NODE_RANK(root_mod_node) = gdbGetWord(buff, &counter);
    MOD_NODE_MODI(root_mod_node) = gdbGetWord(buff, &counter);

    cstring_free(root_record_file_name);
    cbytes_free(cbytes);
    return (EC_TRUE);

}
#endif/*(SWITCH_ON == CBGT_BASED_ON_HSDFS_SWITCH)*/

STATIC_CAST static CSTRING *__cbgt_gen_cbitmap_file_name_cstr(const CSTRING *root_path)
{
    CSTRING *table_id_pool_fname;
    table_id_pool_fname = cstring_new(NULL_PTR, LOC_CBGT_0006);
    if(NULL_PTR == table_id_pool_fname)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_gen_cbitmap_file_name_cstr: new cstring failed\n");
        return (NULL_PTR);
    }
    cstring_format(table_id_pool_fname, "%s/table_id.pool", (char *)cstring_get_str(root_path));
    return (table_id_pool_fname);
}

#if (SWITCH_OFF == CBGT_BASED_ON_HSDFS_SWITCH)
STATIC_CAST static EC_BOOL __cbgt_exist_table_id_pool(const UINT32 cbgt_md_id, const CSTRING *table_id_pool_fname)
{
    return cbitmap_fexist(cstring_get_str(table_id_pool_fname));
}

STATIC_CAST static CBITMAP *__cbgt_create_table_id_pool(const UINT32 cbgt_md_id, const CSTRING *table_id_pool_fname, const UINT32 max_bits)
{
    return cbitmap_fcreate(max_bits, cstring_get_str(table_id_pool_fname));
}

STATIC_CAST static EC_BOOL __cbgt_flush_table_id_pool(const UINT32 cbgt_md_id, const CSTRING *table_id_pool_fname, const CBITMAP *cbitmap)
{
    return cbitmap_flush(cbitmap, cstring_get_str(table_id_pool_fname));
}

STATIC_CAST static CBITMAP  *__cbgt_load_table_id_pool(const UINT32 cbgt_md_id, const CSTRING *table_id_pool_fname)
{
    return cbitmap_fload(cstring_get_str(table_id_pool_fname));
}
#endif/*(SWITCH_OFF == CBGT_BASED_ON_HSDFS_SWITCH)*/

#if (SWITCH_ON == CBGT_BASED_ON_HSDFS_SWITCH)
STATIC_CAST static EC_BOOL __cbgt_exist_table_id_pool(const UINT32 cbgt_md_id, const CSTRING *table_id_pool_fname)
{
    CBGT_MD *cbgt_md;
    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    return cbitmap_dfs_exist(table_id_pool_fname, CBGT_MD_CDFS_MD_ID(cbgt_md));
}

STATIC_CAST static CBITMAP *__cbgt_create_table_id_pool(const UINT32 cbgt_md_id, const CSTRING *table_id_pool_fname, const UINT32 max_bits)
{
    CBGT_MD *cbgt_md;
    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    return cbitmap_dfs_create(max_bits, table_id_pool_fname, CBGT_MD_CDFS_MD_ID(cbgt_md), CBGT_REPLICA_NUM);
}

STATIC_CAST static EC_BOOL __cbgt_flush_table_id_pool(const UINT32 cbgt_md_id, const CSTRING *table_id_pool_fname, const CBITMAP *cbitmap)
{
    CBGT_MD *cbgt_md;
    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    return cbitmap_dfs_flush(cbitmap, table_id_pool_fname, CBGT_MD_CDFS_MD_ID(cbgt_md));
}

STATIC_CAST static CBITMAP  *__cbgt_load_table_id_pool(const UINT32 cbgt_md_id, const CSTRING *table_id_pool_fname)
{
    CBGT_MD *cbgt_md;
    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    return cbitmap_dfs_load(table_id_pool_fname, CBGT_MD_CDFS_MD_ID(cbgt_md));
}
#endif/*(SWITCH_ON == CBGT_BASED_ON_HSDFS_SWITCH)*/

/*root table server load table id pool*/
STATIC_CAST static CBITMAP *__cbgt_open_table_id_pool(const UINT32 cbgt_md_id, const UINT32 table_id, const CSTRING *root_path, const UINT32 open_flags)
{
    CBITMAP *cbitmap;
    CSTRING *table_id_pool_fname;

    table_id_pool_fname = __cbgt_gen_cbitmap_file_name_cstr(root_path);
    if(NULL_PTR == table_id_pool_fname)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_open_table_id_pool: gen cbitmap file name failed where root_path = %s\n",
                            (char *)cstring_get_str(root_path));
        return (NULL_PTR);
    }

    if(EC_FALSE == __cbgt_exist_table_id_pool(cbgt_md_id, table_id_pool_fname))
    {
        if(0 == (open_flags & CBGT_O_CREAT))
        {
            dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_open_table_id_pool: table id pool %s not exist and not be created\n",
                                (char *)cstring_get_str(table_id_pool_fname));
            cstring_free(table_id_pool_fname);
            return (NULL_PTR);
        }

        cbitmap = __cbgt_create_table_id_pool(cbgt_md_id, table_id_pool_fname, CBGT_TABLE_MAX_NUM);
        if(NULL_PTR == cbitmap)
        {
            dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_open_table_id_pool: create table id pool %s failed\n",
                                (char *)cstring_get_str(table_id_pool_fname));
            cstring_free(table_id_pool_fname);
            return (NULL_PTR);
        }
        cbitmap_set(cbitmap, table_id);
        __cbgt_flush_table_id_pool(cbgt_md_id, table_id_pool_fname, cbitmap);
#if 0
        dbg_log(SEC_0054_CBGT, 9)(LOGSTDNULL, "[DEBUG] __cbgt_open_table_id_pool: create table id pool %s and set table id %ld and flush it\n",
                            (char *)cstring_get_str(table_id_pool_fname), table_id);
#endif
    }
    else
    {
        cbitmap = __cbgt_load_table_id_pool(cbgt_md_id, table_id_pool_fname);
        if(NULL_PTR == cbitmap)
        {
            dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_open_table_id_pool: load table id pool %s failed\n",
                                (char *)cstring_get_str(table_id_pool_fname));
            cstring_free(table_id_pool_fname);
            return (NULL_PTR);
        }

        if(EC_FALSE == cbitmap_check(cbitmap, table_id))
        {
            dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_open_table_id_pool: loaded table id pool %s NOT SET table id %ld\n",
                                (char *)cstring_get_str(table_id_pool_fname), table_id);
            cbitmap_free(cbitmap);/*also works when it is null*/
            cstring_free(table_id_pool_fname);
            return (NULL_PTR);
        }
    }

    cstring_free(table_id_pool_fname);/*clean up*/

    return (cbitmap);
}

STATIC_CAST static uint8_t *__cbgt_gen_table_fame(const uint8_t *root_path, const word_t table_id)
{
    uint8_t *fname;
    uint32_t len;

    len = strlen((char *)root_path) + strlen("/table") + 32;
    fname = (uint8_t *)safe_malloc(len, LOC_CBGT_0007);
    if(NULL_PTR == fname)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_gen_table_fame: malloc %d bytes failed\n", len);
        return (NULL_PTR);
    }
    BSET(fname, (uint8_t)0, len);

    snprintf((char *)fname, len, "%s/%ld/%ld/%ld/%ld/hsbgt.dat",
                (char *)root_path,
                TABLE_PATH_LAYOUT_DIR0_NO(table_id),
                TABLE_PATH_LAYOUT_DIR1_NO(table_id),
                TABLE_PATH_LAYOUT_DIR2_NO(table_id),
                TABLE_PATH_LAYOUT_DIR3_NO(table_id)
                );
    return (fname);
}


STATIC_CAST static EC_BOOL __cbgt_whereis_root_server(const UINT32   cbgt_md_id,
                                                    const UINT32   server_type,
                                                    const UINT32   table_id,
                                                    const CSTRING *root_path,
                                                    const UINT32   open_flags,
                                                    UINT32        *root_table_id,
                                                    MOD_NODE      *root_mod_node)
{
    if(CBGT_TYPE_ROOT_SERVER == server_type)
    {
        /*make sure root server was not started*/
        if(EC_FALSE == __cbgt_load_root_record_file(cbgt_md_id, root_path, root_table_id, root_mod_node))
        {
            if(0 == (open_flags & CBGT_O_CREAT))/*when not need to create, report error and return false*/
            {
                dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_whereis_root_server: load root record file failed\n");
                return (EC_FALSE);
            }
            (*root_table_id) = table_id;
            dbg_log(SEC_0054_CBGT, 1)(LOGSTDOUT, "warn:__cbgt_whereis_root_server:load root record file failed, wait for creating it\n");
            return (EC_TRUE);
        }

        if(table_id != (*root_table_id))
        {
            dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_whereis_root_server: loaded root table id %ld but expected to start root table id %ld\n",
                               (*root_table_id), table_id);
            return (EC_FALSE);
        }

        if(EC_FALSE == __cbgt_mod_node_is_valid(CMPI_ANY_MODI, root_mod_node))
        {
            /*okay, root server not started, return true to continue starting...*/
            return (EC_TRUE);
        }

        if(EC_TRUE == __cbgt_mod_node_is_local(cbgt_md_id, root_mod_node))
        {
            /*okay, root server was started at here? found one mismatched: root record file not flushed! */
            /*hence return true to continue starting...*/
            return (EC_TRUE);
        }

        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_whereis_root_server: root table %ld was already started on (tcid %s, comm %ld, rank %ld, modi %ld)\n",
                            (*root_table_id),
                            MOD_NODE_TCID_STR(root_mod_node),
                            MOD_NODE_COMM(root_mod_node),
                            MOD_NODE_RANK(root_mod_node),
                            MOD_NODE_MODI(root_mod_node)
                            );
            return (EC_FALSE);
    }

    if(EC_FALSE == __cbgt_load_root_record_file(cbgt_md_id, root_path, root_table_id, root_mod_node))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_whereis_root_server: load root record file failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == __cbgt_mod_node_is_valid(CMPI_ANY_MODI, root_mod_node))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_whereis_root_server: root table was not started yet\n");
        return (EC_FALSE);
    }
#if 0
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDNULL, "[DEBUG] __cbgt_whereis_root_server: root is table %ld (tcid %s, comm %ld, rank %ld, modi %ld)\n",
                       (*root_table_id),
                       MOD_NODE_TCID_STR(root_mod_node),
                       MOD_NODE_COMM(root_mod_node),
                       MOD_NODE_RANK(root_mod_node),
                       MOD_NODE_MODI(root_mod_node)
                       );
#endif
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cbgt_start_hsdfs(const UINT32 cbgt_md_id)
{
    CBGT_MD *cbgt_md;
    cbgt_md = CBGT_MD_GET(cbgt_md_id);

#if (SWITCH_ON == CBGT_BASED_ON_HSDFS_SWITCH)
    CBGT_MD_CDFS_MD_ID(cbgt_md)= cdfs_start(CBGT_MIN_NP_NUM);
    if(CMPI_ERROR_MODI == CBGT_MD_CDFS_MD_ID(cbgt_md))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_start_hsdfs: start hsdfs client failed\n");
        return (EC_FALSE);
    }

    cdfs_add_npp_vec(CBGT_MD_CDFS_MD_ID(cbgt_md));
    cdfs_add_dn_vec(CBGT_MD_CDFS_MD_ID(cbgt_md));
#endif/*(SWITCH_ON == CBGT_BASED_ON_HSDFS_SWITCH)*/

#if (SWITCH_OFF == CBGT_BASED_ON_HSDFS_SWITCH)
    CBGT_MD_CDFS_MD_ID(cbgt_md) = CMPI_ERROR_MODI;
#endif/*(SWITCH_OFF == CBGT_BASED_ON_HSDFS_SWITCH)*/
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cbgt_end_hsdfs(const UINT32 cbgt_md_id)
{
    CBGT_MD *cbgt_md;
    cbgt_md = CBGT_MD_GET(cbgt_md_id);

    if(CMPI_ERROR_MODI != CBGT_MD_CDFS_MD_ID(cbgt_md))
    {
        cdfs_end(CBGT_MD_CDFS_MD_ID(cbgt_md));
        CBGT_MD_CDFS_MD_ID(cbgt_md) = CMPI_ERROR_MODI;
    }
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cbgt_start_csession(const UINT32 cbgt_md_id)
{
    CBGT_MD *cbgt_md;
    cbgt_md = CBGT_MD_GET(cbgt_md_id);

    CBGT_MD_CSESSION_MD_ID(cbgt_md) = csession_start();
    if(CMPI_ERROR_MODI == CBGT_MD_CSESSION_MD_ID(cbgt_md))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_start_csession: start csession client failed\n");
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cbgt_end_csession(const UINT32 cbgt_md_id)
{
    CBGT_MD *cbgt_md;
    cbgt_md = CBGT_MD_GET(cbgt_md_id);

    if(CMPI_ERROR_MODI != CBGT_MD_CSESSION_MD_ID(cbgt_md))
    {
        csession_end(CBGT_MD_CSESSION_MD_ID(cbgt_md));
        CBGT_MD_CSESSION_MD_ID(cbgt_md) = CMPI_ERROR_MODI;
    }
    return (EC_TRUE);
}


/**
*   for test only
*
*   to query the status of CBGT Module
*
**/
void cbgt_print_module_status(const UINT32 cbgt_md_id, LOG *log)
{
    CBGT_MD *cbgt_md;
    UINT32 this_cbgt_md_id;

    for( this_cbgt_md_id = 0; this_cbgt_md_id < CBGT_MD_CAPACITY(); this_cbgt_md_id ++ )
    {
        cbgt_md = CBGT_MD_GET(this_cbgt_md_id);

        if ( NULL_PTR != cbgt_md && 0 < cbgt_md->usedcounter )
        {
            MOD_NODE *parent;
            parent = CBGT_MD_PARENT_MOD(cbgt_md);
            sys_log(log,"CBGT Module # %ld : %ld refered, table %ld, type is %s, parent (tcid %s, comm %ld, rank %ld, modi %ld)\n",
                        this_cbgt_md_id,
                        cbgt_md->usedcounter,
                        CBGT_MD_TABLE_ID(cbgt_md),
                        __cbgt_type(CBGT_MD_TYPE(cbgt_md)),
                        (NULL_PTR == parent) ? c_word_to_ipv4(CMPI_ERROR_TCID) : MOD_NODE_TCID_STR(parent),
                        (NULL_PTR == parent) ? CMPI_ERROR_COMM                 : MOD_NODE_COMM(parent),
                        (NULL_PTR == parent) ? CMPI_ERROR_RANK                 : MOD_NODE_RANK(parent),
                        (NULL_PTR == parent) ? CMPI_ERROR_MODI                 : MOD_NODE_MODI(parent)
                    );
        }
    }

    return ;
}

/**
*
*   free all static memory occupied by the appointed CBGT module
*
*
**/
UINT32 cbgt_free_module_static_mem(const UINT32 cbgt_md_id)
{
    CBGT_MD  *cbgt_md;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_free_module_static_mem: cbgt module #%ld not started.\n",
                cbgt_md_id);
        /*note: here do not exit but return only*/
        return ((UINT32)-1);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);

    free_module_static_mem(MD_CBGT, cbgt_md_id);

    return 0;
}

/**
*
* start CBGT module
*
**/
UINT32 cbgt_start(const UINT32 server_type, const UINT32 table_id, const CBYTES *table_name, const MOD_NODE *parent, const CSTRING *root_path, const UINT32 open_flags)
{
    CBGT_MD *cbgt_md;
    UINT32   cbgt_md_id;

    MOD_MGR  *mod_mgr;
    CBGT_GDB *gdb;

    UINT32      root_table_id;
    MOD_NODE    root_mod_node;

    cbgt_md_id = cbc_md_new(MD_CBGT, sizeof(CBGT_MD));
    if(CMPI_ERROR_MODI == cbgt_md_id)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_start: no more cbgt module resource available\n");
        return (CMPI_ERROR_MODI);
    }
#if 0
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_start: server_type = %ld\n", server_type);
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_start: table_id = %ld\n", table_id);
    if(NULL_PTR != table_name)
    {
        dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_start: table_name = %.*s\n", cbytes_len(table_name), cbytes_buf(table_name));
    }
    else
    {
        dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_start: table_name = (null)\n");
    }
    if(NULL_PTR != parent)
    {
        dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_start: parent = (%s,%ld,%ld,%ld)\n", MOD_NODE_TCID_STR(parent), MOD_NODE_COMM(parent), MOD_NODE_RANK(parent), MOD_NODE_MODI(parent));
    }
    else
    {
        dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_start: parent = (null)\n");
    }

    if(NULL_PTR != root_path)
    {
        dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_start: root_path = %s\n", cstring_get_str(root_path));
    }
    else
    {
        dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_start: root_path = (null)\n");
    }
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_start: open_flags = %ld\n", open_flags);
#endif
    /* initialize new one CBGT module */
    cbgt_md = (CBGT_MD *)cbc_md_get(MD_CBGT, cbgt_md_id);
    cbgt_md->usedcounter = 0;

    /*set session name*/
    CBGT_MD_CSESSION_NAME(cbgt_md) = cstring_new(CBGT_SESSION_NAME, LOC_CBGT_0008);
    if(NULL_PTR == CBGT_MD_CSESSION_NAME(cbgt_md))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_start: new session name failed\n");
        cbc_md_free(MD_CBGT, cbgt_md_id);
        return (CMPI_ERROR_MODI);
    }

    /* start cession client */
    if(EC_FALSE == __cbgt_start_csession(cbgt_md_id))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_start: start csession client failed\n");
        cbc_md_free(MD_CBGT, cbgt_md_id);
        return (CMPI_ERROR_MODI);
    }

    csession_add(CBGT_MD_CSESSION_MD_ID(cbgt_md), CBGT_MD_CSESSION_NAME(cbgt_md), /*CSESSION_NEVER_EXPIRE*/CBGT_AGING_INTERVAL_NSEC);

    /* start hsdfs client */
    if(EC_FALSE == __cbgt_start_hsdfs(cbgt_md_id))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_start: start hsdfs client failed\n");
        __cbgt_end_csession(cbgt_md_id);
        cstring_free(CBGT_MD_CSESSION_NAME(cbgt_md));
        CBGT_MD_CSESSION_NAME(cbgt_md) = NULL_PTR;
        cbc_md_free(MD_CBGT, cbgt_md_id);
        return (CMPI_ERROR_MODI);
    }

    if(EC_FALSE == __cbgt_whereis_root_server(cbgt_md_id, server_type, table_id, root_path, open_flags, &root_table_id, &root_mod_node))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_start: query root server failed\n");
        __cbgt_end_hsdfs(cbgt_md_id);
        __cbgt_end_csession(cbgt_md_id);
        cstring_free(CBGT_MD_CSESSION_NAME(cbgt_md));
        CBGT_MD_CSESSION_NAME(cbgt_md) = NULL_PTR;
        cbc_md_free(MD_CBGT, cbgt_md_id);
        return (CMPI_ERROR_MODI);
    }

    CBGT_MD_INIT_TABLE_CRWLOCK(cbgt_md, LOC_CBGT_0009);
    CBGT_MD_INIT_TABLE_ID_POOL_CMUTEX(cbgt_md, LOC_CBGT_0010);
    CBGT_MD_INIT_LAST_ACCESS_TIME_CMUTEX(cbgt_md, LOC_CBGT_0011);

    /* create a new module node */
    init_static_mem();

    gdb = NULL_PTR;

    if(CBGT_ERR_TABLE_ID == table_id)
    {
        if(CBGT_TYPE_USER_CLIENT != server_type)
        {
            dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_start: invalid table id where server type %s\n", __cbgt_type(server_type));
            __cbgt_end_hsdfs(cbgt_md_id);
            __cbgt_end_csession(cbgt_md_id);
            cstring_free(CBGT_MD_CSESSION_NAME(cbgt_md));
            CBGT_MD_CSESSION_NAME(cbgt_md) = NULL_PTR;
            cbc_md_free(MD_CBGT, cbgt_md_id);
            return (CMPI_ERROR_MODI);
        }
    }
    else
    {
        gdb = cbgt_gdb_open(cstring_get_str(root_path), table_id, CBGT_MD_CDFS_MD_ID(cbgt_md),
                            __cbgt_make_open_flags(open_flags),__cbgt_type_to_cbtree_type(server_type));
        if(NULL_PTR == gdb)
        {
            dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_start: open table %ld failed\n", table_id);
            __cbgt_end_hsdfs(cbgt_md_id);
            __cbgt_end_csession(cbgt_md_id);
            cstring_free(CBGT_MD_CSESSION_NAME(cbgt_md));
            CBGT_MD_CSESSION_NAME(cbgt_md) = NULL_PTR;
            cbc_md_free(MD_CBGT, cbgt_md_id);
            return (CMPI_ERROR_MODI);
        }
    }

    CBGT_MD_TABLE_ID(cbgt_md)  = table_id;
    CBGT_MD_ROOT_PATH(cbgt_md) = cstring_new(cstring_get_str(root_path), LOC_CBGT_0012);
    if(NULL_PTR == CBGT_MD_ROOT_PATH(cbgt_md))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_start: clone root_path %s failed\n", (char *)cstring_get_str(root_path));
        cbgt_gdb_close(gdb);/*also works when gdb is null*/
        __cbgt_end_hsdfs(cbgt_md_id);
        __cbgt_end_csession(cbgt_md_id);
        cstring_free(CBGT_MD_CSESSION_NAME(cbgt_md));
        CBGT_MD_CSESSION_NAME(cbgt_md) = NULL_PTR;
        cbc_md_free(MD_CBGT, cbgt_md_id);
        return (CMPI_ERROR_MODI);
    }

    CBGT_MD_GDB(cbgt_md) = gdb;

    CBGT_MD_TABLE_ID_POOL(cbgt_md) = NULL_PTR;
    if(CBGT_TYPE_ROOT_SERVER == server_type)
    {
        CBGT_MD_TABLE_ID_POOL(cbgt_md) = __cbgt_open_table_id_pool(cbgt_md_id, table_id, root_path, open_flags);
        if(NULL_PTR == CBGT_MD_TABLE_ID_POOL(cbgt_md))
        {
            dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_start: load table id pool failed\n");
            cbgt_gdb_close(gdb);/*also works when gdb is null*/
            __cbgt_end_hsdfs(cbgt_md_id);
            __cbgt_end_csession(cbgt_md_id);
            cstring_free(CBGT_MD_CSESSION_NAME(cbgt_md));
            CBGT_MD_CSESSION_NAME(cbgt_md) = NULL_PTR;
            cbc_md_free(MD_CBGT, cbgt_md_id);
            return (CMPI_ERROR_MODI);
        }
    }

    /*set root mod node*/
    if(CBGT_TYPE_ROOT_SERVER == server_type)
    {
        CBGT_MD_ROOT_MOD(cbgt_md) = mod_node_new();
        if(NULL_PTR == CBGT_MD_ROOT_MOD(cbgt_md))
        {
            dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_start: new mod node failed\n");
            cbgt_gdb_close(gdb);/*also works when gdb is null*/
            cbitmap_free(CBGT_MD_TABLE_ID_POOL(cbgt_md));/*also works when it is null*/
            __cbgt_end_hsdfs(cbgt_md_id);
            __cbgt_end_csession(cbgt_md_id);
            cstring_free(CBGT_MD_CSESSION_NAME(cbgt_md));
            CBGT_MD_CSESSION_NAME(cbgt_md) = NULL_PTR;
            cbc_md_free(MD_CBGT, cbgt_md_id);
            return (CMPI_ERROR_MODI);
        }
        __cbgt_local_mod_node(cbgt_md_id, CBGT_MD_ROOT_MOD(cbgt_md));
        CBGT_MD_ROOT_TABLE(cbgt_md) = root_table_id;
    }
    else
    {
        CBGT_MD_ROOT_MOD(cbgt_md) = mod_node_new();
        if(NULL_PTR == CBGT_MD_ROOT_MOD(cbgt_md))
        {
            dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_start: new mod node failed\n");
            cbgt_gdb_close(gdb);/*also works when gdb is null*/
            __cbgt_end_hsdfs(cbgt_md_id);
            __cbgt_end_csession(cbgt_md_id);
            cstring_free(CBGT_MD_CSESSION_NAME(cbgt_md));
            CBGT_MD_CSESSION_NAME(cbgt_md) = NULL_PTR;
            cbc_md_free(MD_CBGT, cbgt_md_id);
            return (CMPI_ERROR_MODI);
        }

        mod_node_clone(&root_mod_node, CBGT_MD_ROOT_MOD(cbgt_md));
        CBGT_MD_ROOT_TABLE(cbgt_md) = root_table_id;
    }

    mod_mgr = mod_mgr_new(cbgt_md_id, /*LOAD_BALANCING_LOOP*//*LOAD_BALANCING_MOD*/LOAD_BALANCING_OBJ);
    if(NULL_PTR == mod_mgr)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_start: new mod mgr failed\n");
        cbgt_gdb_close(gdb);/*also works when gdb is null*/
        cbitmap_free(CBGT_MD_TABLE_ID_POOL(cbgt_md));/*also works when it is null*/
        mod_node_free(CBGT_MD_ROOT_MOD(cbgt_md));
        __cbgt_end_hsdfs(cbgt_md_id);
        __cbgt_end_csession(cbgt_md_id);
        cstring_free(CBGT_MD_CSESSION_NAME(cbgt_md));
        CBGT_MD_CSESSION_NAME(cbgt_md) = NULL_PTR;
        cbc_md_free(MD_CBGT, cbgt_md_id);
        return (CMPI_ERROR_MODI);
    }
    CBGT_MD_MOD_MGR(cbgt_md) = mod_mgr;

    CBGT_MD_TYPE(cbgt_md) = server_type;

    CBGT_MD_TABLE_NAME(cbgt_md) = NULL_PTR;
    if(NULL_PTR != table_name)
    {
        CBGT_MD_TABLE_NAME(cbgt_md) = cbytes_new(0);
        cbytes_clone(table_name, CBGT_MD_TABLE_NAME(cbgt_md));
    }

    if(NULL_PTR != parent && EC_TRUE == __cbgt_mod_node_is_valid(cbgt_md_id, parent))
    {
        CBGT_MD_PARENT_MOD(cbgt_md) = mod_node_new();
        mod_node_clone(parent, CBGT_MD_PARENT_MOD(cbgt_md));
    }
    else
    {
        CBGT_MD_PARENT_MOD(cbgt_md) = NULL_PTR;
    }

    cbgt_md->usedcounter = 1;/*move ahead:-)*/

    /*set first record of colf table*/
    if(CBGT_TYPE_COLF_SERVER == server_type && NULL_PTR != gdb && EC_TRUE == cbgt_gdb_is_empty(gdb))
    {
        CBYTES colf_row;

        dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_start: gdb of colf table is empty, try to create its first user table\n");
        if(EC_FALSE == __cbgt_make_default_row_of_colf_table(cbgt_md_id, &colf_row))
        {
            dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_start: make default row of colf table failed");
            cbgt_gdb_close(gdb);/*also works when gdb is null*/
            cbitmap_free(CBGT_MD_TABLE_ID_POOL(cbgt_md));/*also works when it is null*/
            mod_node_free(CBGT_MD_ROOT_MOD(cbgt_md));
            __cbgt_end_hsdfs(cbgt_md_id);
            __cbgt_end_csession(cbgt_md_id);
            cstring_free(CBGT_MD_CSESSION_NAME(cbgt_md));
            CBGT_MD_CSESSION_NAME(cbgt_md) = NULL_PTR;
            cbc_md_free(MD_CBGT, cbgt_md_id);
            return (CMPI_ERROR_MODI);
        }

        if(EC_FALSE == cbgt_create_table_on_colf(cbgt_md_id, &colf_row))
        {
            dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_start: create default user table on colf table failed");
            cbytes_clean(&colf_row);
            cbgt_gdb_close(gdb);/*also works when gdb is null*/
            cbitmap_free(CBGT_MD_TABLE_ID_POOL(cbgt_md));/*also works when it is null*/
            mod_node_free(CBGT_MD_ROOT_MOD(cbgt_md));
            __cbgt_end_hsdfs(cbgt_md_id);
            __cbgt_end_csession(cbgt_md_id);
            cstring_free(CBGT_MD_CSESSION_NAME(cbgt_md));
            CBGT_MD_CSESSION_NAME(cbgt_md) = NULL_PTR;
            cbc_md_free(MD_CBGT, cbgt_md_id);
            return (CMPI_ERROR_MODI);
        }
        cbytes_clean(&colf_row);
    }

    if(CBGT_TYPE_ROOT_SERVER == server_type)
    {
        MOD_NODE mod_node;
        __cbgt_local_mod_node(cbgt_md_id, &mod_node);
        if(EC_FALSE == __cbgt_flush_root_record_file(cbgt_md_id, root_path, table_id, &mod_node))
        {
            dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_start: flush root record file failed\n");
            cbgt_end(cbgt_md_id);
            return (CMPI_ERROR_MODI);
        }
    }

    /*root server never aging*/
    if(CBGT_TYPE_ROOT_SERVER != server_type && CBGT_TYPE_USER_CLIENT != server_type)
    {
        //dbg_log(SEC_0054_CBGT, 9)(LOGSTDNULL, "[DEBUG] cbgt_start: register CBGT %ld for aging\n", cbgt_md_id);

        CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0013);
        /*aging has bug!*/
        task_brd_cbtimer_register(task_brd_default_get(), CBTIMER_NEVER_EXPIRE, CBGT_AGING_INTERVAL_NSEC, FI_cbgt_aging_handle, cbgt_md_id);
    }

    dbg_log(SEC_0054_CBGT, 5)(LOGSTDOUT, "cbgt_start: start CBGT module #%ld for table %ld, type %s\n", cbgt_md_id, table_id, __cbgt_type(server_type));
    __cbgt_print_table_name(cbgt_md_id, LOGSTDOUT);
    //dbg_log(SEC_0054_CBGT, 3)(LOGSTDOUT, "========================= cbgt_start: CBGT table info:\n");
    //cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
    //cbc_print();

    //super_register_hsbgt_cluster(0);

    return ( cbgt_md_id );
}

/**
*
* end CBGT module
*
**/
void cbgt_end(const UINT32 cbgt_md_id)
{
    CBGT_MD *cbgt_md;

    UINT32 server_type;
    UINT32 table_id;

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    if(NULL_PTR == cbgt_md)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT,"error:cbgt_end: cbgt_md_id = %ld not exist.\n", cbgt_md_id);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
    /* if the module is occupied by others,then decrease counter only */
    if ( 1 < cbgt_md->usedcounter )
    {
        cbgt_md->usedcounter --;
        return ;
    }

    if ( 0 == cbgt_md->usedcounter )
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT,"error:cbgt_end: cbgt_md_id = %ld is not started.\n", cbgt_md_id);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }

    //CBGT_MD_CRWLOCK_TABLE_WRLOCK(cbgt_md, LOC_CBGT_0014);

    server_type = CBGT_MD_TYPE(cbgt_md);
    table_id    = CBGT_MD_TABLE_ID(cbgt_md);

    dbg_log(SEC_0054_CBGT, 5)(LOGSTDOUT, "cbgt_end: try to stop CBGT module #%ld of table %ld, type %s\n", cbgt_md_id, table_id, __cbgt_type(server_type));
    __cbgt_print_table_name(cbgt_md_id, LOGSTDOUT);

    if(CBGT_TYPE_ROOT_SERVER == server_type)
    {
        MOD_NODE err_mod_node;
        __cbgt_error_mod_node(cbgt_md_id, &err_mod_node);
        if(EC_FALSE == __cbgt_flush_root_record_file(cbgt_md_id, CBGT_MD_ROOT_PATH(cbgt_md), table_id, &err_mod_node))
        {
            dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_end: update root record file failed\n");
            //return;
        }
    }
    else
    {
        /*report to parent: I am closing!*/
        cbgt_report_closing(cbgt_md_id);
    }

    /* if nobody else occupied the module,then free its resource */

    /*DANGEROUS: close all sons*/
    if(NULL_PTR != CBGT_MD_MOD_MGR(cbgt_md))
    {
        //cbgt_close_mod_mgr(cbgt_md_id);
        mod_mgr_excl(CMPI_LOCAL_TCID, CMPI_LOCAL_COMM, CMPI_LOCAL_RANK, cbgt_md_id, CBGT_MD_MOD_MGR(cbgt_md));
        task_dea(CBGT_MD_MOD_MGR(cbgt_md), TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, FI_cbgt_end, CMPI_ERROR_MODI);
        CBGT_MD_MOD_MGR(cbgt_md)  = NULL_PTR;
    }

    if(NULL_PTR != CBGT_MD_GDB(cbgt_md))
    {
        cbgt_gdb_close(CBGT_MD_GDB(cbgt_md));
        CBGT_MD_GDB(cbgt_md) = NULL_PTR;
    }

    if(NULL_PTR != CBGT_MD_TABLE_ID_POOL(cbgt_md))
    {
        CSTRING *table_id_pool_fname;

        table_id_pool_fname = __cbgt_gen_cbitmap_file_name_cstr(CBGT_MD_ROOT_PATH(cbgt_md));
        __cbgt_flush_table_id_pool(cbgt_md_id, table_id_pool_fname, CBGT_MD_TABLE_ID_POOL(cbgt_md));
        cstring_free(table_id_pool_fname);

        cbitmap_free(CBGT_MD_TABLE_ID_POOL(cbgt_md));
        CBGT_MD_TABLE_ID_POOL(cbgt_md) = NULL_PTR;
    }

    __cbgt_end_hsdfs(cbgt_md_id);

    if(CMPI_ERROR_MODI != CBGT_MD_CSESSION_MD_ID(cbgt_md))
    {
        csession_end(CBGT_MD_CSESSION_MD_ID(cbgt_md));
        CBGT_MD_CSESSION_MD_ID(cbgt_md) = CMPI_ERROR_MODI;
    }
    if(NULL_PTR != CBGT_MD_CSESSION_NAME(cbgt_md))
    {
        cstring_free(CBGT_MD_CSESSION_NAME(cbgt_md));
        CBGT_MD_CSESSION_NAME(cbgt_md) = NULL_PTR;
    }

    if(NULL_PTR != CBGT_MD_ROOT_PATH(cbgt_md))
    {
        cstring_free(CBGT_MD_ROOT_PATH(cbgt_md));
        CBGT_MD_ROOT_PATH(cbgt_md) = NULL_PTR;
    }

    if(NULL_PTR != CBGT_MD_PARENT_MOD(cbgt_md))
    {
        mod_node_free(CBGT_MD_PARENT_MOD(cbgt_md));
        CBGT_MD_PARENT_MOD(cbgt_md) = NULL_PTR;
    }

    CBGT_MD_TYPE(cbgt_md) = CBGT_TYPE_UNDEF;

    if(NULL_PTR != CBGT_MD_TABLE_NAME(cbgt_md))
    {
        cbytes_free(CBGT_MD_TABLE_NAME(cbgt_md));
        CBGT_MD_TABLE_NAME(cbgt_md) = NULL_PTR;
    }

    /* free module : */
    //cbgt_free_module_static_mem(cbgt_md_id);
    //CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0015);

    CBGT_MD_CLEAN_TABLE_CRWLOCK(cbgt_md, LOC_CBGT_0016);
    CBGT_MD_CLEAN_TABLE_ID_POOL_CMUTEX(cbgt_md, LOC_CBGT_0017);
    CBGT_MD_CLEAN_LAST_ACCESS_TIME_CMUTEX(cbgt_md, LOC_CBGT_0018);
    cbgt_md->usedcounter = 0;

    dbg_log(SEC_0054_CBGT, 5)(LOGSTDOUT, "cbgt_end: stop CBGT module #%ld of table %ld, type %s\n", cbgt_md_id, table_id, __cbgt_type(server_type));
    cbc_md_free(MD_CBGT, cbgt_md_id);

    //breathing_static_mem();

    //dbg_log(SEC_0054_CBGT, 3)(LOGSTDOUT, "========================= cbgt_end: CBGT table info:\n");
    //cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
    //cbc_print();

    return ;
}

EC_BOOL cbgt_aging_handle(const UINT32 cbgt_md_id)
{
    CBGT_MD *cbgt_md;
    CTIMET   cur_time;
    REAL     diff_nsec;

    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_aging_handle: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        return (EC_FALSE);
    }

    cbgt_md = CBGT_MD_GET(cbgt_md_id);

    /*aging happen only when all its sons were closed*/
    if(0 < MOD_MGR_REMOTE_NUM(CBGT_MD_MOD_MGR(cbgt_md)))
    {
        CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0019);
        return (EC_TRUE);
    }

    CTIMET_GET(cur_time);
    diff_nsec = CTIMET_DIFF(CBGT_MD_LAST_ACCESS_TIME(cbgt_md), cur_time);
    if(diff_nsec >= 0.0 + CBGT_AGING_INTERVAL_NSEC)
    {
        dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_aging_handle: cbgt_md_id %ld is aged where diff_nsec %.2f, expired_nsec %ld\n",
                            cbgt_md_id, diff_nsec, (UINT32)CBGT_AGING_INTERVAL_NSEC);
        cbgt_end(cbgt_md_id);
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

UINT32 cbgt_set_mod_mgr(const UINT32 cbgt_md_id, const MOD_MGR * src_mod_mgr)
{
    CBGT_MD *cbgt_md;
    MOD_MGR  *des_mod_mgr;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_set_mod_mgr: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    des_mod_mgr = CBGT_MD_MOD_MGR(cbgt_md);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0020);

    dbg_log(SEC_0054_CBGT, 5)(LOGSTDOUT, "cbgt_set_mod_mgr: md_id %ld, input src_mod_mgr %p\n", cbgt_md_id, src_mod_mgr);
    mod_mgr_print(LOGSTDOUT, src_mod_mgr);

    /*figure out mod_nodes with tcid belong to set of cbgtnp_tcid_vec and cbgtnp_tcid_vec*/
    mod_mgr_limited_clone(cbgt_md_id, src_mod_mgr, des_mod_mgr);

    dbg_log(SEC_0054_CBGT, 5)(LOGSTDOUT, "====================================cbgt_set_mod_mgr: des_mod_mgr %p beg====================================\n", des_mod_mgr);
    mod_mgr_print(LOGSTDOUT, des_mod_mgr);
    dbg_log(SEC_0054_CBGT, 5)(LOGSTDOUT, "====================================cbgt_set_mod_mgr: des_mod_mgr %p end====================================\n", des_mod_mgr);

    return (0);
}

MOD_MGR * cbgt_get_mod_mgr(const UINT32 cbgt_md_id)
{
    CBGT_MD *cbgt_md;

    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        return (MOD_MGR *)0;
    }

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0021);
    return CBGT_MD_MOD_MGR(cbgt_md);
}

void    cbgt_close_mod_mgr(const UINT32 cbgt_md_id)
{
    CBGT_MD *cbgt_md;
    MOD_MGR *mod_mgr;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_close_mod_mgr: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    mod_mgr = CBGT_MD_MOD_MGR(cbgt_md);

    task_dea(mod_mgr, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, FI_cbgt_end, CMPI_ERROR_MODI);
    //CBGT_MD_MOD_MGR(cbgt_md) = NULL_PTR;
    return;
}

void cbgt_print_status(const UINT32 cbgt_md_id, LOG *log)
{
    CBGT_MD *cbgt_md;

    MOD_MGR    *mod_mgr;

    UINT32      table_id;

    MOD_NODE   *parent;
    MOD_NODE   *root;

    if(CMPI_ANY_MODI == cbgt_md_id)
    {
        UINT32 this_cbgt_md_id;

        for( this_cbgt_md_id = 0; this_cbgt_md_id < CBGT_MD_CAPACITY(); this_cbgt_md_id ++ )
        {
            cbgt_md = CBGT_MD_GET(this_cbgt_md_id);

            if ( NULL_PTR != cbgt_md && 0 < cbgt_md->usedcounter )
            {
                sys_log(log, "---------------------------------------------------------------------------\n");
                cbgt_print_status(this_cbgt_md_id, log);
            }
        }

        return;
    }

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_print_status: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md   = CBGT_MD_GET(cbgt_md_id);
    mod_mgr   = CBGT_MD_MOD_MGR(cbgt_md);
    table_id  = CBGT_MD_TABLE_ID(cbgt_md);
    parent    = CBGT_MD_PARENT_MOD(cbgt_md);
    root      = CBGT_MD_ROOT_MOD(cbgt_md);

    sys_log(log,"CBGT Module # %ld : %ld refered, table id %ld, type is %s\n",
                cbgt_md_id,
                cbgt_md->usedcounter,
                table_id,
                __cbgt_type(CBGT_MD_TYPE(cbgt_md))
            );

    if(NULL_PTR != root)
    {
        sys_log(log, "root_mod_node = (tcid %s, comm %ld, rank %ld, modi %ld)\n",
                        MOD_NODE_TCID_STR(root),
                        MOD_NODE_COMM(root),
                        MOD_NODE_RANK(root),
                        MOD_NODE_MODI(root));
    }
    else
    {
        sys_log(log, "root_mod_node = (null)\n");
    }

    if(NULL_PTR != parent)
    {
        sys_log(log, "parent_mod_node = (tcid %s, comm %ld, rank %ld, modi %ld)\n",
                        MOD_NODE_TCID_STR(parent),
                        MOD_NODE_COMM(parent),
                        MOD_NODE_RANK(parent),
                        MOD_NODE_MODI(parent));
    }
    else
    {
        sys_log(log, "parent_mod_node = (null)\n");
    }

    if(NULL_PTR != CBGT_MD_ROOT_PATH_STR(cbgt_md))
    {
        sys_log(log, "root_path = %s\n", (char *)CBGT_MD_ROOT_PATH_STR(cbgt_md));
    }
    else
    {
        sys_log(log, "root_path = (null)\n");
    }

    __cbgt_print_table_name(cbgt_md_id, log);

    mod_mgr_print(log, mod_mgr);

    return ;
}

CBGT_GDB *cbgt_gdb_new()
{
    CBGT_GDB *gdb;

    alloc_static_mem(MM_CBGT_GDB, &gdb, LOC_CBGT_0022);
    if(NULL_PTR == gdb)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_gdb_new: new gdb failed\n");
        return (NULL_PTR);
    }

    cbgt_gdb_init(gdb);
    return (gdb);
}

EC_BOOL cbgt_gdb_init(CBGT_GDB *gdb)
{
    cstring_init(CBGT_GDB_FNAME(gdb), NULL_PTR);
    CBGT_GDB_FD(gdb)         = ERR_FD;
    CBGT_GDB_TABLE_ID(gdb)   = CBGT_ERR_TABLE_ID;
    CBGT_GDB_CDFS_MD_ID(gdb) = CMPI_ERROR_MODI;
    CBGT_GDB_CBTREE(gdb)     = NULL_PTR;
    CBGT_GDB_TYPE(gdb)       = CBGT_TYPE_UNDEF;
    CBGT_GDB_CRWLOCK_INIT(gdb, LOC_CBGT_0023);
    return (EC_TRUE);
}

EC_BOOL cbgt_gdb_clean(CBGT_GDB *gdb)
{
    cstring_clean(CBGT_GDB_FNAME(gdb));

    if(NULL_PTR != CBGT_GDB_CBTREE(gdb))
    {
        cbtree_free(CBGT_GDB_CBTREE(gdb));
        CBGT_GDB_CBTREE(gdb) = NULL_PTR;
    }

    if(ERR_FD != CBGT_GDB_FD(gdb))
    {
        c_file_close(CBGT_GDB_FD(gdb));
        CBGT_GDB_FD(gdb) = ERR_FD;
    }

    CBGT_GDB_TABLE_ID(gdb)   = CBGT_ERR_TABLE_ID;
    CBGT_GDB_CDFS_MD_ID(gdb) = CMPI_ERROR_MODI;
    CBGT_GDB_TYPE(gdb)       = CBGT_TYPE_UNDEF;
    CBGT_GDB_CRWLOCK_CLEAN(gdb, LOC_CBGT_0024);
    return (EC_TRUE);
}

EC_BOOL cbgt_gdb_free(CBGT_GDB *gdb)
{
    if(NULL_PTR != gdb)
    {
        cbgt_gdb_clean(gdb);
        free_static_mem(MM_CBGT_GDB, gdb, LOC_CBGT_0025);
    }
    return (EC_TRUE);
}

#if (SWITCH_OFF == CBGT_BASED_ON_HSDFS_SWITCH)
CBGT_GDB *cbgt_gdb_open(const uint8_t *root_path, const word_t table_id, const word_t cdfs_md_id, const int flags, const UINT32 cbtree_type)
{
    CBGT_GDB *gdb;
    CBTREE   *cbtree;
    uint8_t  *fname;

    if(NULL_PTR == root_path)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_gdb_open: root_path is null\n");
        return (NULL_PTR);
    }

    fname = __cbgt_gen_table_fame(root_path, table_id);
    if(NULL_PTR == fname)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_gdb_open: gen table fname of table id %ld failed\n", table_id);
        return (NULL_PTR);
    }

    cbtree = NULL_PTR;

    if(flags & O_RDWR)
    {
        cbtree = cbtree_load((char *)fname);
    }

    if (NULL_PTR == cbtree)
    {
        safe_free(fname, LOC_CBGT_0026);

        if (flags & O_CREAT)
        {
            return cbgt_gdb_create(root_path, table_id, cdfs_md_id, cbtree_type);
        }
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_gdb_open: unable to open table %ld\n", table_id);
        return (NULL_PTR);
    }

    gdb = cbgt_gdb_new();
    if(NULL_PTR == gdb)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_gdb_open: new gdb failed\n");
        safe_free(fname, LOC_CBGT_0027);
        cbtree_free(cbtree);
        return (NULL_PTR);
    }

    cstring_set_str(CBGT_GDB_FNAME(gdb), fname);
    CBGT_GDB_TABLE_ID(gdb)   = table_id;
    CBGT_GDB_CDFS_MD_ID(gdb) = cdfs_md_id;
    CBGT_GDB_CBTREE(gdb)     = cbtree;

    return (gdb);
}

EC_BOOL cbgt_gdb_load(CBGT_GDB *gdb)
{
    CBTREE *cbtree;
    int     fd;

    if(NULL_PTR == gdb)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_gdb_load: gdb is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR != CBGT_GDB_CBTREE(gdb))
    {
        cbtree_free(CBGT_GDB_CBTREE(gdb));
        CBGT_GDB_CBTREE(gdb) = NULL_PTR;
    }

    if(ERR_FD != CBGT_GDB_FD(gdb))
    {
        c_file_close(CBGT_GDB_FD(gdb));
        CBGT_GDB_FD(gdb) = ERR_FD;
    }

    fd = c_file_open((char *)CBGT_GDB_FNAME_STR(gdb), O_RDWR, 0666);
    if(ERR_FD == fd)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_gdb_load: open file %s failed\n", (char *)CBGT_GDB_FNAME_STR(gdb));
        return (EC_FALSE);
    }

    cbtree = cbtree_load_posix(fd);
    if(NULL_PTR == cbtree)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_gdb_load: load cbtree from file %s failed\n", (char *)CBGT_GDB_FNAME_STR(gdb));
        c_file_close(fd);
        return (EC_FALSE);
    }

    CBGT_GDB_FD(gdb) = fd;
    CBGT_GDB_CBTREE(gdb) = cbtree;

    return (EC_TRUE);
}


CBGT_GDB *cbgt_gdb_create(const uint8_t *root_path, const word_t table_id, const word_t cdfs_md_id, const UINT32 cbtree_type)
{
    CBGT_GDB *gdb;
    CBTREE   *cbtree;

    uint8_t *fname;
    int      fd;

    fname = __cbgt_gen_table_fame(root_path, table_id);
    if(NULL_PTR == fname)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_gdb_create: gen table fname of table id %ld failed\n", table_id);
        return (NULL_PTR);
    }

    fd = c_file_open((char *)fname, O_RDWR | O_CREAT, 0666);
    if(ERR_FD == fd)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_gdb_create: open file %s failed\n", fname);
        safe_free(fname, LOC_CBGT_0028);
        return (NULL_PTR);
    }

    cbtree = cbtree_new(CBTREE_MAX_ORDER, CBTREE_MAX_VERSION, cbtree_type);
    if(NULL_PTR == cbtree)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_gdb_create: new cbtree failed\n");
        safe_free(fname, LOC_CBGT_0029);
        return (NULL_PTR);
    }
    CBTREE_SET_DIRTY(cbtree);/*when cbtree is created, set it dirty*/

    gdb = cbgt_gdb_new();
    if(NULL_PTR == gdb)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_gdb_create: new gdb failed\n");
        safe_free(fname, LOC_CBGT_0030);
        cbtree_free(cbtree);
        return (NULL_PTR);
    }

    cstring_set_str(CBGT_GDB_FNAME(gdb), fname);
    CBGT_GDB_FD(gdb)         = fd;
    CBGT_GDB_TABLE_ID(gdb)   = table_id;
    CBGT_GDB_CDFS_MD_ID(gdb) = cdfs_md_id;
    CBGT_GDB_CBTREE(gdb)     = cbtree;

    return (gdb);
}

EC_BOOL cbgt_gdb_flush(CBGT_GDB *gdb)
{
    if(NULL_PTR == CBGT_GDB_CBTREE(gdb))
    {
        dbg_log(SEC_0054_CBGT, 1)(LOGSTDOUT, "warn:cbgt_gdb_flush: cbtree of gdb %p is null, flush nothing\n", gdb);
        return (EC_TRUE);
    }

    CBGT_GDB_CRWLOCK_WRLOCK(gdb, LOC_CBGT_0031);

    if(EC_FALSE == cbtree_is_dirty(CBGT_GDB_CBTREE(gdb)))
    {
        dbg_log(SEC_0054_CBGT, 1)(LOGSTDOUT, "warn:cbgt_gdb_flush: gdb is not dirty, NOT flush\n");
        CBGT_GDB_CRWLOCK_UNLOCK(gdb, LOC_CBGT_0032);
        return (EC_TRUE);
    }

    if(ERR_FD == CBGT_GDB_FD(gdb))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_gdb_flush: fd is invalid\n");
        CBGT_GDB_CRWLOCK_UNLOCK(gdb, LOC_CBGT_0033);
        return (EC_FALSE);
    }

    if(EC_FALSE == cbtree_flush_posix(CBGT_GDB_CBTREE(gdb), CBGT_GDB_FD(gdb)))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_gdb_flush: flush cbtree to fd %d file %s failed\n",
                            CBGT_GDB_FD(gdb), (char *)CBGT_GDB_FNAME_STR(gdb));
        CBGT_GDB_CRWLOCK_UNLOCK(gdb, LOC_CBGT_0034);
        return (EC_FALSE);
    }
    CBGT_GDB_CRWLOCK_UNLOCK(gdb, LOC_CBGT_0035);
    return (EC_TRUE);
}

EC_BOOL cbgt_gdb_unlink(CBGT_GDB *gdb, const CSTRING *root_path, const UINT32 table_id)
{
    uint8_t *fname;

    CBGT_GDB_CRWLOCK_WRLOCK(gdb, LOC_CBGT_0036);
    fname = __cbgt_gen_table_fame(cstring_get_str(root_path), table_id);
    if(NULL_PTR == fname)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_gdb_unlink: gen file %s of table id %ld failed\n",
                          (char *)fname, table_id);
        CBGT_GDB_CRWLOCK_UNLOCK(gdb, LOC_CBGT_0037);
        return (EC_FALSE);
    }

    unlink((char *)fname);
    safe_free(fname, LOC_CBGT_0038);
    CBGT_GDB_CRWLOCK_UNLOCK(gdb, LOC_CBGT_0039);
    return (EC_TRUE);
}

#endif/*(SWITCH_OFF == CBGT_BASED_ON_HSDFS_SWITCH)*/

#if (SWITCH_ON == CBGT_BASED_ON_HSDFS_SWITCH)
CBGT_GDB *cbgt_gdb_open(const uint8_t *root_path, const word_t table_id, const word_t cdfs_md_id, const int flags, const UINT32 cbtree_type)
{
    CBGT_GDB *gdb;
    CBTREE   *cbtree;
    uint8_t  *fname;

    if(NULL_PTR == root_path)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_gdb_open: root_path is null\n");
        return (NULL_PTR);
    }

    fname = __cbgt_gen_table_fame(root_path, table_id);
    if(NULL_PTR == fname)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_gdb_open: gen table fname of table id %ld failed\n", table_id);
        return (NULL_PTR);
    }

    cbtree = NULL_PTR;

    if(flags & O_RDWR)
    {
        CSTRING *fname_cstr;

        fname_cstr = cstring_new(fname, LOC_CBGT_0040);
        if(NULL_PTR == fname_cstr)
        {
            dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_gdb_open: new fname cstr failed\n");
            safe_free(fname, LOC_CBGT_0041);
            return (NULL_PTR);
        }

        cbtree = cbtree_load_hsdfs(cdfs_md_id, fname_cstr);
        cstring_free(fname_cstr);
    }

    if (NULL_PTR == cbtree)
    {
        safe_free(fname, LOC_CBGT_0042);

        if (flags & O_CREAT)
        {
            return cbgt_gdb_create(root_path, table_id, cdfs_md_id, cbtree_type);
        }
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_gdb_open: unable to open table %ld\n", table_id);
        return (NULL_PTR);
    }

    gdb = cbgt_gdb_new();
    if(NULL_PTR == gdb)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_gdb_open: new gdb failed\n");
        safe_free(fname, LOC_CBGT_0043);
        cbtree_free(cbtree);
        return (NULL_PTR);
    }

    cstring_set_str(CBGT_GDB_FNAME(gdb), fname);
    CBGT_GDB_TABLE_ID(gdb)   = table_id;
    CBGT_GDB_CDFS_MD_ID(gdb) = cdfs_md_id;
    CBGT_GDB_CBTREE(gdb)     = cbtree;
    return (gdb);
}

EC_BOOL cbgt_gdb_load(CBGT_GDB *gdb)
{
    CBTREE *cbtree;

    if(NULL_PTR == gdb)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_gdb_load: gdb is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR != CBGT_GDB_CBTREE(gdb))
    {
        cbtree_free(CBGT_GDB_CBTREE(gdb));
        CBGT_GDB_CBTREE(gdb) = NULL_PTR;
    }

    cbtree = cbtree_load_hsdfs(CBGT_GDB_CDFS_MD_ID(gdb), CBGT_GDB_FNAME(gdb));
    if(NULL_PTR == cbtree)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_gdb_load: load cbtree from file %s failed\n", (char *)CBGT_GDB_FNAME_STR(gdb));
        return (EC_FALSE);
    }

    CBGT_GDB_CBTREE(gdb) = cbtree;

    return (EC_TRUE);
}

CBGT_GDB *cbgt_gdb_create(const uint8_t *root_path, const word_t table_id, const word_t cdfs_md_id, const UINT32 cbtree_type)
{
    CBGT_GDB *gdb;
    CBTREE   *cbtree;

    uint8_t *fname;
    CSTRING  fname_cstr_t;

    fname = __cbgt_gen_table_fame(root_path, table_id);
    if(NULL_PTR == fname)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_gdb_create: gen table fname of table id %ld failed\n", table_id);
        return (NULL_PTR);
    }

    cstring_set_str(&fname_cstr_t, fname);

    /**
    *
    * the raw file with not more than file_size bytes will be compressed
    * and pushed into cdfs file which accept up to CBGT_CDFS_FILE_MAX_SIZE bytes
    *
    * one can set file_size >> CBGT_CDFS_FILE_MAX_SIZE depending on compress algorithm
    *
    **/
    if(EC_FALSE == cdfs_truncate(cdfs_md_id, &fname_cstr_t, CBGT_CDFS_FILE_MAX_SIZE, CBGT_REPLICA_NUM))
    {
        safe_free(fname, LOC_CBGT_0044);
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_gdb_create: truncate %s with size %ld and replica %ld failed\n",
                          (char *)fname, CBGT_CDFS_FILE_MAX_SIZE, CBGT_REPLICA_NUM);
        return (NULL_PTR);
    }

    cbtree = cbtree_new(CBTREE_MAX_ORDER, CBTREE_MAX_VERSION, cbtree_type);
    if(NULL_PTR == cbtree)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_gdb_create: new cbtree failed\n");
        safe_free(fname, LOC_CBGT_0045);
        return (NULL_PTR);
    }
    CBTREE_SET_DIRTY(cbtree);/*when cbtree is created, set it dirty*/

    gdb = cbgt_gdb_new();
    if(NULL_PTR == gdb)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_gdb_create: new gdb failed\n");
        safe_free(fname, LOC_CBGT_0046);
        cbtree_free(cbtree);
        return (NULL_PTR);
    }

    cstring_set_str(CBGT_GDB_FNAME(gdb), fname);
    CBGT_GDB_FD(gdb)         = ERR_FD;
    CBGT_GDB_TABLE_ID(gdb)   = table_id;
    CBGT_GDB_CDFS_MD_ID(gdb) = cdfs_md_id;
    CBGT_GDB_CBTREE(gdb)     = cbtree;

    return (gdb);
}

EC_BOOL cbgt_gdb_flush(CBGT_GDB *gdb)
{
    CSTRING  *fname_cstr;

    uint32_t  encoded_size;
    uint32_t  encoded_pos;
    uint8_t  *encoded_buff;

    word_t    compressed_len;
    uint8_t  *compressed_buff;
    uint32_t  counter;
    CBYTES    cbytes;

    if(NULL_PTR == CBGT_GDB_CBTREE(gdb))
    {
        dbg_log(SEC_0054_CBGT, 1)(LOGSTDOUT, "warn:cbgt_gdb_flush: cbtree of gdb %p is null, flush nothing\n", gdb);
        return (EC_TRUE);
    }

    CBGT_GDB_CRWLOCK_WRLOCK(gdb, LOC_CBGT_0047);
    if(EC_FALSE == cbtree_is_dirty(CBGT_GDB_CBTREE(gdb)))
    {
        CBGT_GDB_CRWLOCK_UNLOCK(gdb, LOC_CBGT_0048);
        dbg_log(SEC_0054_CBGT, 1)(LOGSTDOUT, "warn:cbgt_gdb_flush: gdb is not dirty, NOT flush\n");
        return (EC_TRUE);
    }

    fname_cstr = CBGT_GDB_FNAME(gdb);

    encoded_size = 0;
    if(EC_FALSE == cbtree_encode_size(CBGT_GDB_CBTREE(gdb), &encoded_size))
    {
        CBGT_GDB_CRWLOCK_UNLOCK(gdb, LOC_CBGT_0049);
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_gdb_flush: encode_size of gdb %p failed\n", gdb);
        return (EC_FALSE);
    }

    /*make encoding buff ready*/
    encoded_buff = (uint8_t *)safe_malloc(encoded_size, LOC_CBGT_0050);
    if(NULL == encoded_buff)
    {
        CBGT_GDB_CRWLOCK_UNLOCK(gdb, LOC_CBGT_0051);
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_gdb_flush: alloc %d bytes encoding buff failed\n", encoded_size);
        return (EC_FALSE);
    }

    /*encoding*/
    encoded_pos = 0;
    if(EC_FALSE == cbtree_encode(CBGT_GDB_CBTREE(gdb), encoded_buff, encoded_size, &encoded_pos))
    {
        CBGT_GDB_CRWLOCK_UNLOCK(gdb, LOC_CBGT_0052);
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_gdb_flush: encode gdb %p to buff %p with size %d failed\n",
                           gdb, encoded_buff, encoded_size);
        safe_free(encoded_buff, LOC_CBGT_0053);
        return (EC_FALSE);
    }

    /*make compression buff ready*/
    compressed_len = encoded_pos;
    compressed_buff = (uint8_t *)safe_malloc(compressed_len + sizeof(uint32_t), LOC_CBGT_0054);
    if(NULL == compressed_buff)
    {
        CBGT_GDB_CRWLOCK_UNLOCK(gdb, LOC_CBGT_0055);
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_gdb_flush: alloc %ld bytes compression buff failed\n", compressed_len + sizeof(uint32_t));
        safe_free(encoded_buff, LOC_CBGT_0056);
        return (EC_FALSE);
    }

    counter = 0;
    gdbPut32(compressed_buff, &counter, encoded_pos);

    /*compressing*/
    if(Z_OK != compress(compressed_buff + counter, &compressed_len, encoded_buff, encoded_pos))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_gdb_flush: compress buff %p size %d to buff %p failed\n",
                            encoded_buff, encoded_pos, compressed_buff);

        CBGT_GDB_CRWLOCK_UNLOCK(gdb, LOC_CBGT_0057);
        safe_free(encoded_buff, LOC_CBGT_0058);
        safe_free(compressed_buff, LOC_CBGT_0059);
        return (EC_FALSE);
    }

    safe_free(encoded_buff, LOC_CBGT_0060);/*free memory as fast as possible*/
#if 1
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_gdb_flush: compress %u bytes => %ld bytes, rate = %.2f\n",
                       encoded_pos, compressed_len, (compressed_len + 0.0)/(encoded_pos + 0.0));
#endif
    /*flush compressed buff to hsdfs*/
    cbytes_init(&cbytes);
    cbytes_mount(&cbytes, compressed_len + counter, compressed_buff);
    if(EC_FALSE == cdfs_update(CBGT_GDB_CDFS_MD_ID(gdb), fname_cstr, &cbytes))
    {
        CBGT_GDB_CRWLOCK_UNLOCK(gdb, LOC_CBGT_0061);
        cbytes_umount(&cbytes, NULL_PTR, NULL_PTR);
        safe_free(compressed_buff, LOC_CBGT_0062);
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_gdb_flush: update %s with %ld bytes failed\n",
                            (char *)cstring_get_str(fname_cstr), compressed_len + counter);
        return (EC_FALSE);
    }

    cbtree_clear_dirty(CBGT_GDB_CBTREE(gdb));
    CBGT_GDB_CRWLOCK_UNLOCK(gdb, LOC_CBGT_0063);

    cbytes_umount(&cbytes, NULL_PTR, NULL_PTR);
    safe_free(compressed_buff, LOC_CBGT_0064);
    return (EC_TRUE);
}

EC_BOOL cbgt_gdb_unlink(CBGT_GDB *gdb, const CSTRING *root_path, const UINT32 table_id)
{
    uint8_t *fname;
    CSTRING  fname_cstr;

    CBGT_GDB_CRWLOCK_WRLOCK(gdb, LOC_CBGT_0065);
    fname = __cbgt_gen_table_fame(cstring_get_str(root_path), table_id);
    if(NULL_PTR == fname)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_gdb_unlink: gen table fname from root path %s and table id %ld failed\n",
                          (char *)cstring_get_str(root_path), table_id);
        CBGT_GDB_CRWLOCK_UNLOCK(gdb, LOC_CBGT_0066);
        return (EC_FALSE);
    }

    cstring_set_str(&fname_cstr, fname);

    if(EC_FALSE == cdfs_delete(CBGT_GDB_CDFS_MD_ID(gdb), &fname_cstr, CDFSNP_ITEM_FILE_IS_REG))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_gdb_unlink: delete hdfs file %s of table id %ld failed\n",
                          (char *)cstring_get_str(&fname_cstr), table_id);
        safe_free(fname, LOC_CBGT_0067);
        CBGT_GDB_CRWLOCK_UNLOCK(gdb, LOC_CBGT_0068);
        return (EC_FALSE);
    }

    safe_free(fname, LOC_CBGT_0069);
    CBGT_GDB_CRWLOCK_UNLOCK(gdb, LOC_CBGT_0070);
    return (EC_TRUE);
}
#endif/*(SWITCH_ON == CBGT_BASED_ON_HSDFS_SWITCH)*/

EC_BOOL cbgt_gdb_close(CBGT_GDB *gdb)
{
    if(NULL_PTR == gdb)
    {
        return (EC_TRUE);
    }

    cbgt_gdb_flush(gdb);
    cbgt_gdb_free(gdb);

    return (EC_TRUE);
}

EC_BOOL cbgt_gdb_close_without_flush(CBGT_GDB *gdb)
{
    if(NULL_PTR == gdb)
    {
        return (EC_TRUE);
    }

    cbgt_gdb_free(gdb);

    return (EC_TRUE);
}

EC_BOOL cbgt_gdb_del_key(CBGT_GDB *gdb, const uint8_t *key)
{
    if(NULL_PTR == gdb)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_gdb_del_key: gdb is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == CBGT_GDB_CBTREE(gdb))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_gdb_del_key: cbtree of gdb %p is null\n", gdb);
        return (EC_FALSE);
    }

    if(EC_FALSE == cbtree_delete(CBGT_GDB_CBTREE(gdb), key))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_gdb_del_key: del key from gdb %p failed\n", gdb);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cbgt_gdb_insert_key(CBGT_GDB *gdb, const uint8_t *key)
{
    if(NULL_PTR == gdb)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_gdb_insert_key: gdb is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == CBGT_GDB_CBTREE(gdb))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_gdb_insert_key: cbtree of gdb %p is null\n", gdb);
        return (EC_FALSE);
    }

    CBGT_GDB_CRWLOCK_WRLOCK(gdb, LOC_CBGT_0071);
    if(EC_FALSE == cbtree_insert(CBGT_GDB_CBTREE(gdb), key))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_gdb_insert_key: del key from gdb %p failed\n", gdb);
        CBGT_GDB_CRWLOCK_UNLOCK(gdb, LOC_CBGT_0072);
        return (EC_FALSE);
    }
    CBGT_GDB_CRWLOCK_UNLOCK(gdb, LOC_CBGT_0073);
    return (EC_TRUE);
}

CBTREE_KEY *cbgt_gdb_search_key(const CBGT_GDB *gdb, const uint8_t *key)
{
    CBTREE_KEY *cbtree_key;
    if(NULL_PTR == gdb)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_gdb_search_key: gdb is null\n");
        return (NULL_PTR);
    }

    if(NULL_PTR == CBGT_GDB_CBTREE(gdb))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_gdb_search_key: cbtree of gdb %p is null\n", gdb);
        return (NULL_PTR);
    }
    CBGT_GDB_CRWLOCK_RDLOCK((CBGT_GDB *)gdb, LOC_CBGT_0074);
    cbtree_key = cbtree_search(CBGT_GDB_CBTREE(gdb), key);
    CBGT_GDB_CRWLOCK_UNLOCK((CBGT_GDB *)gdb, LOC_CBGT_0075);
    return (cbtree_key);
}

EC_BOOL   cbgt_gdb_update_val(CBGT_GDB *gdb, const uint8_t *key, const uint8_t *val, const uint32_t vlen)
{
    KeyValue keyValue;
    uint8_t *kv;

    keyValueInitHs(&keyValue,
                   vlen, /*vlen*/
                   keyGetrLenHs(key) , keyGetRowHs(key),
                   keyGetcfLenHs(key), keyGetColFamilyHs(key),
                   keyGetcqLenHs(key), keyGetColQualifierHs(key),
                   c_time(NULL_PTR), /*timestamp*/
                   KEY_TYPE_IS_PUT,
                   val  /*val is null*/
                   );

    kv = kvNewHs(&keyValue, LOC_CBGT_0076);
    if(NULL_PTR == kv)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_gdb_update_val: failed to alloc %d bytes for key\n", keyValueGettLenHs(&keyValue));
        return (EC_FALSE);
    }
    kvPutHs(kv, &keyValue);

    if(EC_FALSE == cbgt_gdb_insert_key(gdb, kv))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_gdb_update_val: insert new kv to gdb %p failed\n", gdb);
        kvFreeHs(kv, LOC_CBGT_0077);
        return (EC_FALSE);
    }
    kvFreeHs(kv, LOC_CBGT_0078);
    return (EC_TRUE);
}

EC_BOOL cbgt_gdb_is_full(const CBGT_GDB *gdb)
{
    CBTREE *cbtree;

    if(NULL_PTR == gdb)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_gdb_is_full: gdb is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == CBGT_GDB_CBTREE(gdb))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_gdb_is_full: cbtree of gdb %p is null\n", gdb);
        return (EC_FALSE);
    }

    cbtree = CBGT_GDB_CBTREE(gdb);
    //dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_gdb_is_full: cbtree %p size %ld, tlen %ld\n", cbtree, CBTREE_SIZE(cbtree), CBTREE_TLEN(cbtree));

    if(CBGT_SPLIT_TRIGGER_TLEN <= CBTREE_TLEN(cbtree))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL cbgt_gdb_is_empty(const CBGT_GDB *gdb)
{
    if(NULL_PTR == gdb)
    {
        return (EC_TRUE);
    }

    if(EC_TRUE == cbtree_is_empty(CBGT_GDB_CBTREE(gdb)))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL cbgt_gdb_get_last_key(const CBGT_GDB *gdb, uint8_t **last_key)
{
    CBTREE     *cbtree;
    CBTREE_KEY *cbtree_key;
    uint8_t    *kv;
    uint8_t    *dup_key;

    if(NULL_PTR == gdb)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_gdb_get_last_key: gdb is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == CBGT_GDB_CBTREE(gdb))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_gdb_get_last_key: cbtree of gdb %p is null\n", gdb);
        return (EC_FALSE);
    }

    cbtree = CBGT_GDB_CBTREE(gdb);
    cbtree_key = cbtree_node_get_r_key(cbtree, CBTREE_ROOT_NODE(cbtree));
    kv = CBTREE_KEY_LATEST(cbtree_key);

    dup_key = keyDupHs(kv, LOC_CBGT_0079);
    if(NULL_PTR == dup_key)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_gdb_get_last_key: dup key from kv %p failed\n", kv);
        return (EC_FALSE);
    }

    (*last_key) = dup_key;
    return (EC_TRUE);
}

/*old_gdb will keep the right btree, and left_gdb will obtain the left btree*/
EC_BOOL cbgt_gdb_split(CBGT_GDB *old_gdb, CBGT_GDB *left_gdb)
{
    CBTREE *old_cbtree;
    CBTREE *left_cbtree;

    CBGT_GDB_CRWLOCK_WRLOCK(old_gdb, LOC_CBGT_0080);
    old_cbtree = CBGT_GDB_CBTREE(old_gdb);
    if(EC_FALSE == cbtree_split(old_cbtree, &left_cbtree))
    {
        CBGT_GDB_CRWLOCK_UNLOCK(old_gdb, LOC_CBGT_0081);
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_gdb_split: split cbtree %p failed\n", old_cbtree);
        return (EC_FALSE);
    }

    CBGT_GDB_CBTREE(left_gdb) = left_cbtree;
    CBGT_GDB_CRWLOCK_UNLOCK(old_gdb, LOC_CBGT_0082);

    return (EC_TRUE);
}

/*old_gdb is the right gdb*/
EC_BOOL cbgt_gdb_merge(CBGT_GDB *old_gdb, CBGT_GDB *left_gdb)
{
    CBTREE *des_cbtree;

    des_cbtree = cbtree_merge(CBGT_GDB_CBTREE(left_gdb), CBGT_GDB_CBTREE(old_gdb));
    if(NULL_PTR == des_cbtree)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_gdb_merge: merge left cbtree %p and right cbtree %p failed\n",
                            CBGT_GDB_CBTREE(left_gdb), CBGT_GDB_CBTREE(old_gdb));
        return (EC_FALSE);
    }

    CBGT_GDB_CBTREE(left_gdb) = NULL_PTR;
    CBGT_GDB_CBTREE(old_gdb)  = des_cbtree;
    return (EC_TRUE);
}

void cbgt_gdb_traversal(LOG *log, const CBGT_GDB *gdb, CBTREE_KEY_PRINTER key_printer)
{
    const CBTREE *cbtree;

    if(NULL_PTR == gdb)
    {
        sys_log(log, "cbgt_gdb_traversal: null gdb\n");
        return;
    }

    if(NULL_PTR == CBGT_GDB_CBTREE(gdb))
    {
        sys_log(log, "cbgt_gdb_traversal: null tree\n");
        return;
    }

    cbtree = CBGT_GDB_CBTREE(gdb);

    cbtree_print( log, cbtree, CBTREE_ROOT_NODE(cbtree), (uint8_t)0, key_printer);
    return;
}

void cbgt_gdb_runthrough(LOG *log, const CBGT_GDB *gdb, void (*process)(LOG *, const CBTREE *, const CBTREE_KEY *))
{
    const CBTREE *cbtree;

    if(NULL_PTR == gdb)
    {
        sys_log(log, "cbgt_gdb_runthrough: null gdb\n");
        return;
    }

    if(NULL_PTR == CBGT_GDB_CBTREE(gdb))
    {
        sys_log(log, "cbgt_gdb_runthrough: null tree\n");
        return;
    }

    cbtree = CBGT_GDB_CBTREE(gdb);

    cbtree_runthrough(log, cbtree, CBTREE_LEFT_LEAF(cbtree), process);
    return;
}

EC_BOOL cbgt_is_root_server(const UINT32 cbgt_md_id)
{
    CBGT_MD *cbgt_md;

    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "warn:cbgt_is_root_server: cbgt module #%ld not started.\n",
                cbgt_md_id);
        return (EC_FALSE);
    }

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0083);
    if(CBGT_TYPE_ROOT_SERVER == CBGT_MD_TYPE(cbgt_md))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL cbgt_is_meta_server(const UINT32 cbgt_md_id)
{
    CBGT_MD *cbgt_md;

    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "warn:cbgt_is_meta_server: cbgt module #%ld not started.\n",
                cbgt_md_id);
        return (EC_FALSE);
    }

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0084);
    if(CBGT_TYPE_META_SERVER == CBGT_MD_TYPE(cbgt_md))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL cbgt_is_colf_server(const UINT32 cbgt_md_id)
{
    CBGT_MD *cbgt_md;

    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "warn:cbgt_is_colf_server: cbgt module #%ld not started.\n",
                cbgt_md_id);
        return (EC_FALSE);
    }

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0085);
    if(CBGT_TYPE_COLF_SERVER == CBGT_MD_TYPE(cbgt_md))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL cbgt_is_user_server(const UINT32 cbgt_md_id)
{
    CBGT_MD *cbgt_md;

    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "warn:cbgt_is_user_server: cbgt module #%ld not started.\n",
                cbgt_md_id);
        return (EC_FALSE);
    }

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0086);
    if(CBGT_TYPE_USER_SERVER == CBGT_MD_TYPE(cbgt_md))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL cbgt_is_user_client(const UINT32 cbgt_md_id)
{
    CBGT_MD *cbgt_md;

    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "warn:cbgt_is_user_client: cbgt module #%ld not started.\n",
                cbgt_md_id);
        return (EC_FALSE);
    }

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0087);
    if(CBGT_TYPE_USER_CLIENT == CBGT_MD_TYPE(cbgt_md))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

/*check table_id exist on remote mod_node or not*/
EC_BOOL cbgt_check_exist(const UINT32 cbgt_md_id, const UINT32 table_id, const MOD_NODE *mod_node)
{
    UINT32 remote_table_id;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_check_exist: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    if(EC_FALSE == __cbgt_mod_node_is_valid(cbgt_md_id, mod_node))
    {
        return (EC_FALSE);
    }

    remote_table_id = CBGT_ERR_TABLE_ID;
    task_p2p(cbgt_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             mod_node,
             &remote_table_id, FI_cbgt_fetch_table_id, CMPI_ERROR_MODI);

    if(CBGT_ERR_TABLE_ID == remote_table_id || table_id != remote_table_id)
    {
        return (EC_FALSE);/*not exist*/
    }

    return (EC_TRUE);
}

/*when CBGT module not exist, return CBGT_ERR_TABLE_ID*/
UINT32  cbgt_fetch_table_id(const UINT32 cbgt_md_id)
{
    CBGT_MD *cbgt_md;

    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_fetch_table_id: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        return (CBGT_ERR_TABLE_ID);
    }

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    return CBGT_MD_TABLE_ID(cbgt_md);
}

CBYTES *cbgt_kv_new(const UINT32 cbgt_md_id)
{
#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_kv_new: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    return cbytes_new(0);
}

EC_BOOL cbgt_kv_init(const UINT32 cbgt_md_id, const CBYTES *row, const CBYTES *colf, const CBYTES *colq, const CBYTES *val, CBYTES *kv)
{
    KeyValue keyValue;
    uint8_t *kv_buff;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_kv_init: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    /*check validiity*/
    if(NULL_PTR != val && (cbytes_len(val) & (~0xFFFFFFFF)))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_kv_init: invalid val len %ld\n", cbytes_len(val));
        return (EC_FALSE);
    }

    if(cbytes_len(row) & (~0xFFFF))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_kv_init: invalid row len %ld\n", cbytes_len(row));
        return (EC_FALSE);
    }

    if(cbytes_len(colf) & (~0xFF))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_kv_init: invalid colf len %ld\n", cbytes_len(colf));
        return (EC_FALSE);
    }

    if(cbytes_len(colq) & (~0xFFFF))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_kv_init: invalid colq len %ld\n", cbytes_len(colq));
        return (EC_FALSE);
    }

    if(NULL_PTR != val)
    {
        keyValueInitHs(&keyValue,
                       (uint32_t)cbytes_len(val),
                       (uint16_t)cbytes_len(row), cbytes_buf(row),
                       (uint8_t )cbytes_len(colf), cbytes_buf(colf),
                       (uint16_t)cbytes_len(colq), cbytes_buf(colq),
                       c_time(NULL_PTR),
                       KEY_TYPE_IS_PUT,
                       cbytes_buf(val));
    }
    else
    {
        keyValueInitHs(&keyValue,
                       (uint32_t)0,
                       (uint16_t)cbytes_len(row), cbytes_buf(row),
                       (uint8_t )cbytes_len(colf), cbytes_buf(colf),
                       (uint16_t)cbytes_len(colq), cbytes_buf(colq),
                       c_time(NULL_PTR),
                       KEY_TYPE_IS_PUT,
                       NULL_PTR);

    }
    kv_buff = kvNewHs(&keyValue, LOC_CBGT_0088);
    if(NULL_PTR == kv_buff)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_kv_init: failed to alloc %d bytes for kv\n", keyValueGettLenHs(&keyValue));
        return (EC_FALSE);
    }
    kvPutHs(kv_buff, &keyValue);

    cbytes_mount(kv, keyValueGettLenHs(&keyValue), kv_buff);
    return (EC_TRUE);
}

EC_BOOL cbgt_kv_clean(const UINT32 cbgt_md_id, CBYTES *kv)
{
#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_kv_clean: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    if(NULL_PTR != cbytes_buf(kv))
    {
        kvFreeHs(cbytes_buf(kv), LOC_CBGT_0089);
        cbytes_umount(kv, NULL_PTR, NULL_PTR);
    }
    return (EC_TRUE);
}

EC_BOOL cbgt_kv_free(const UINT32 cbgt_md_id, CBYTES *kv)
{
#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_kv_clean: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_kv_clean(cbgt_md_id, kv);
    cbytes_free(kv);
    return (EC_TRUE);
}

CBYTES *cbgt_key_new(const UINT32 cbgt_md_id)
{
#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_key_new: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    return cbytes_new(0);
}

EC_BOOL cbgt_key_init(const UINT32 cbgt_md_id, const CBYTES *row, const CBYTES *colf, const CBYTES *colq, const ctime_t ts, CBYTES *key)
{
    KeyValue keyValue;
    uint8_t *key_buff;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_key_init: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    /*check validity*/
    if(KV_FORMAT_TSLEN != sizeof(ctime_t))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_key_init: invalid timestamp len %ld\n", sizeof(ctime_t));
        return (EC_FALSE);
    }
    if(cbytes_len(row) & (~0xFFFF))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_key_init: invalid row len %ld\n", cbytes_len(row));
        return (EC_FALSE);
    }

    if(cbytes_len(colf) & (~0xFF))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_key_init: invalid colf len %ld\n", cbytes_len(colf));
        return (EC_FALSE);
    }

    if(cbytes_len(colq) & (~0xFFFF))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_key_init: invalid colq len %ld\n", cbytes_len(colq));
        return (EC_FALSE);
    }

    keyValueInitHs(&keyValue,
                   (uint32_t)0, /*vlen*/
                   (uint16_t)cbytes_len(row), cbytes_buf(row),
                   (uint8_t )cbytes_len(colf), cbytes_buf(colf),
                   (uint16_t)cbytes_len(colq), cbytes_buf(colq),
                   ts, /*timestamp*/
                   KEY_TYPE_IS_PUT,
                   NULL_PTR  /*val is null*/
                   );

    key_buff = kvNewHs(&keyValue, LOC_CBGT_0090);
    if(NULL_PTR == key_buff)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_key_init: failed to alloc %d bytes for key\n", keyValueGettLenHs(&keyValue));
        return (EC_FALSE);
    }
    kvPutHs(key_buff, &keyValue);

    cbytes_mount(key, keyValueGettLenHs(&keyValue), key_buff);
    return (EC_TRUE);
}

EC_BOOL cbgt_key_clean(const UINT32 cbgt_md_id, CBYTES *key)
{
#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_key_clean: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    if(NULL_PTR != cbytes_buf(key))
    {
        keyFreeHs(cbytes_buf(key), LOC_CBGT_0091);
        cbytes_umount(key, NULL_PTR, NULL_PTR);
    }
    return (EC_TRUE);
}

EC_BOOL cbgt_key_free(const UINT32 cbgt_md_id, CBYTES *key)
{
#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_key_clean: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_key_clean(cbgt_md_id, key);
    cbytes_free(key);
    return (EC_TRUE);
}

EC_BOOL cbgt_reserve_table_id(const UINT32 cbgt_md_id, UINT32 *table_id)
{
    CBGT_MD    *cbgt_md;
    MOD_NODE   *parent;
    CBITMAP    *table_id_pool;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_reserve_table_id: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    parent  = CBGT_MD_PARENT_MOD(cbgt_md);
    table_id_pool = CBGT_MD_TABLE_ID_POOL(cbgt_md);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0092);

    if(EC_TRUE == cbgt_is_root_server(cbgt_md_id))
    {
        //cbitmap_print(table_id_pool, LOGSTDOUT);
        CBGT_MD_CMUTEX_TABLE_ID_POOL_LOCK(cbgt_md, LOC_CBGT_0093);
        if(EC_FALSE == cbitmap_reserve(table_id_pool, table_id))
        {
            CBGT_MD_CMUTEX_TABLE_ID_POOL_UNLOCK(cbgt_md, LOC_CBGT_0094);
            dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_reserve_table_id: reserve table id failed\n");
            return (EC_FALSE);
        }
        CBGT_MD_CMUTEX_TABLE_ID_POOL_UNLOCK(cbgt_md, LOC_CBGT_0095);
        //dbg_log(SEC_0054_CBGT, 9)(LOGSTDNULL, "[DEBUG] cbgt_reserve_table_id: reserved table id %ld\n", (*table_id));
        return (EC_TRUE);
    }

    if(EC_TRUE == cbgt_is_user_client(cbgt_md_id))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_reserve_table_id: uesr client should never be reached\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == parent)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_reserve_table_id: parent of table %ld type %s is null\n",
                            CBGT_MD_TABLE_ID(cbgt_md), __cbgt_type(CBGT_MD_TYPE(cbgt_md)));
        return (EC_FALSE);
    }

    if(EC_TRUE == cbgt_is_meta_server(cbgt_md_id)
    || EC_TRUE == cbgt_is_colf_server(cbgt_md_id)
    || EC_TRUE == cbgt_is_user_server(cbgt_md_id)
    )
    {
        EC_BOOL ret;

        ret = EC_FALSE;
        task_p2p(cbgt_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                 parent,
                 &ret, FI_cbgt_reserve_table_id, CMPI_ERROR_MODI, table_id);
        if(EC_FALSE == ret)
        {
            dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_reserve_table_id: table %ld type %s reserve table id from parent failed\n",
                                CBGT_MD_TABLE_ID(cbgt_md), __cbgt_type(CBGT_MD_TYPE(cbgt_md)));
            return (EC_FALSE);
        }
        return (EC_TRUE);
    }

    dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_reserve_table_id: table %ld type is unknow\n", CBGT_MD_TABLE_ID(cbgt_md));
    return (EC_FALSE);
}

EC_BOOL cbgt_release_table_id(const UINT32 cbgt_md_id, const UINT32 table_id)
{
    CBGT_MD    *cbgt_md;
    MOD_NODE   *parent;
    CBITMAP    *table_id_pool;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_release_table_id: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    parent  = CBGT_MD_PARENT_MOD(cbgt_md);
    table_id_pool = CBGT_MD_TABLE_ID_POOL(cbgt_md);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0096);

    if(EC_TRUE == cbgt_is_root_server(cbgt_md_id))
    {
        CBGT_MD_CMUTEX_TABLE_ID_POOL_LOCK(cbgt_md, LOC_CBGT_0097);
        if(EC_FALSE == cbitmap_release(table_id_pool, table_id))
        {
            CBGT_MD_CMUTEX_TABLE_ID_POOL_UNLOCK(cbgt_md, LOC_CBGT_0098);
            dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_release_table_id: release table id %ld failed\n", table_id);
            return (EC_FALSE);
        }
        CBGT_MD_CMUTEX_TABLE_ID_POOL_UNLOCK(cbgt_md, LOC_CBGT_0099);
        return (EC_TRUE);
    }

    if(EC_TRUE == cbgt_is_user_client(cbgt_md_id))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_release_table_id: uesr client should never be reached\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == parent)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_release_table_id: parent of table %ld type %s is null\n",
                            CBGT_MD_TABLE_ID(cbgt_md), __cbgt_type(CBGT_MD_TYPE(cbgt_md)));
        return (EC_FALSE);
    }

    if(EC_TRUE == cbgt_is_meta_server(cbgt_md_id)
    || EC_TRUE == cbgt_is_colf_server(cbgt_md_id)
    || EC_TRUE == cbgt_is_user_server(cbgt_md_id)
    )
    {
        EC_BOOL ret;

        ret = EC_FALSE;
        task_p2p(cbgt_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                 parent,
                 &ret, FI_cbgt_release_table_id, CMPI_ERROR_MODI, table_id);
        if(EC_FALSE == ret)
        {
            dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_release_table_id: table %ld type %s release table id %ld from parent failed\n",
                                CBGT_MD_TABLE_ID(cbgt_md), __cbgt_type(CBGT_MD_TYPE(cbgt_md)), table_id);
            return (EC_FALSE);
        }
        return (EC_TRUE);
    }

    dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_release_table_id: table %ld type is unknow\n", CBGT_MD_TABLE_ID(cbgt_md));
    return (EC_FALSE);
}

EC_BOOL cbgt_get_root_mod_node(const UINT32 cbgt_md_id, MOD_NODE *mod_node)
{
    CBGT_MD    *cbgt_md;
    MOD_NODE   *parent;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_get_root_mod_node: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    parent  = CBGT_MD_PARENT_MOD(cbgt_md);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0100);

    if(EC_TRUE == cbgt_is_root_server(cbgt_md_id))
    {
        __cbgt_local_mod_node(cbgt_md_id, mod_node);
        return (EC_TRUE);
    }

    if(EC_TRUE == cbgt_is_meta_server(cbgt_md_id))
    {
        if(NULL_PTR == parent)
        {
            dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_get_root_mod_node: meta table %ld parent is unknown\n",
                                CBGT_MD_TABLE_ID(cbgt_md));
            return (EC_FALSE);
        }
        mod_node_clone(parent, mod_node);
        return (EC_TRUE);
    }

    if(EC_TRUE == cbgt_is_colf_server(cbgt_md_id))
    {
        EC_BOOL ret;

        ret = EC_FALSE;
        task_p2p(cbgt_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                 parent,
                 &ret,FI_cbgt_get_root_mod_node, CMPI_ERROR_MODI, mod_node);
        if(EC_FALSE == ret)
        {
            dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_get_root_mod_node: colf table %ld query root failed\n",
                                CBGT_MD_TABLE_ID(cbgt_md));
            return (EC_FALSE);
        }
        return (EC_TRUE);
    }

    if(EC_TRUE == cbgt_is_user_server(cbgt_md_id))
    {
        EC_BOOL ret;

        ret = EC_FALSE;
        task_p2p(cbgt_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                 parent,
                 &ret,FI_cbgt_get_root_mod_node, CMPI_ERROR_MODI, mod_node);
        if(EC_FALSE == ret)
        {
            dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_get_root_mod_node: user table %ld query root failed\n",
                                CBGT_MD_TABLE_ID(cbgt_md));
            return (EC_FALSE);
        }
        return (EC_TRUE);
    }

    dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_get_root_mod_node: unknow server type %ld\n", CBGT_MD_TYPE(cbgt_md));
    return (EC_FALSE);
}

EC_BOOL cbgt_split_register_no_lock(const UINT32 cbgt_md_id,
                                const CBYTES *old_row  ,  const UINT32 old_table_id , const MOD_NODE *old_mod_node ,
                                const CBYTES *left_row , const UINT32 left_table_id , const MOD_NODE *left_mod_node,
                                const CBYTES *right_row, const UINT32 right_table_id, const MOD_NODE *right_mod_node)
{
    CBGT_MD *cbgt_md;
    CBYTES   rowkey;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_split_register_no_lock: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0101);
#if 0
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_split_register_no_lock: [1]\n");
    cbgt_traversal_no_lock(cbgt_md_id, LOGSTDOUT);
#endif
    if(EC_FALSE == __cbgt_make_colf_table_key_by_user_table_key(cbgt_md_id, old_row, &rowkey))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_split_register_no_lock: make rowkey of colf table failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cbgt_delete_kv_no_lock(cbgt_md_id, &rowkey))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_split_register_no_lock: delete old row from cbgt %ld table %ld failed\n",
                            cbgt_md_id, CBGT_MD_TABLE_ID(cbgt_md));
        __cbgt_print_colf_table_key(LOGSTDOUT, cbytes_buf(&rowkey));
        sys_print(LOGSTDOUT, "\n");
        cbytes_clean(&rowkey);
        return (EC_FALSE);
    }
    cbytes_clean(&rowkey);
#if 0
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_split_register_no_lock: [2]\n");
    cbgt_traversal_no_lock(cbgt_md_id, LOGSTDOUT);
#endif
    /*insert left */
    if(EC_FALSE == cbgt_insert_register_no_lock(cbgt_md_id, left_row, left_table_id, left_mod_node))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_split_register_no_lock: insert left table %ld (tcid %s, comm %ld, rank %ld, modi %ld) register info in parent table %ld failed\n",
                            left_table_id,
                            MOD_NODE_TCID_STR(left_mod_node),
                            MOD_NODE_COMM(left_mod_node),
                            MOD_NODE_RANK(left_mod_node),
                            MOD_NODE_MODI(left_mod_node),
                            CBGT_MD_TABLE_ID(cbgt_md));

        /*rollback old*/
        if(EC_FALSE == cbgt_insert_register_no_lock(cbgt_md_id, old_row, old_table_id, old_mod_node))
        {
            dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_split_register_no_lock: restore old table %ld (tcid %s, comm %ld, rank %ld, modi %ld) register info to parent table %ld failed\n",
                                old_table_id,
                                MOD_NODE_TCID_STR(old_mod_node),
                                MOD_NODE_COMM(old_mod_node),
                                MOD_NODE_RANK(old_mod_node),
                                MOD_NODE_MODI(old_mod_node),
                                CBGT_MD_TABLE_ID(cbgt_md));
        }
        return (EC_FALSE);
    }

    if(EC_TRUE == __cbgt_mod_node_is_valid(cbgt_md_id, left_mod_node))
    {
        mod_mgr_incl(MOD_NODE_TCID(left_mod_node), MOD_NODE_COMM(left_mod_node), MOD_NODE_RANK(left_mod_node), MOD_NODE_MODI(left_mod_node), CBGT_MD_MOD_MGR(cbgt_md));
    }
#if 0
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_split_register_no_lock: [3]\n");
    cbgt_traversal_no_lock(cbgt_md_id, LOGSTDOUT);
#endif
    /*insert right */
    if(EC_FALSE == cbgt_insert_register_no_lock(cbgt_md_id, right_row, right_table_id, right_mod_node))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_split_register_no_lock: insert right table %ld (tcid %s, comm %ld, rank %ld, modi %ld) register info in parent table %ld failed\n",
                            right_table_id,
                            MOD_NODE_TCID_STR(right_mod_node),
                            MOD_NODE_COMM(right_mod_node),
                            MOD_NODE_RANK(right_mod_node),
                            MOD_NODE_MODI(right_mod_node),
                            CBGT_MD_TABLE_ID(cbgt_md));

        /*rollback old*/
        if(EC_FALSE == cbgt_insert_register_no_lock(cbgt_md_id, old_row, old_table_id, old_mod_node))
        {
            dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_split_register_no_lock: restore old table %ld (tcid %s, comm %ld, rank %ld, modi %ld) register info to parent table %ld failed\n",
                                old_table_id,
                                MOD_NODE_TCID_STR(old_mod_node),
                                MOD_NODE_COMM(old_mod_node),
                                MOD_NODE_RANK(old_mod_node),
                                MOD_NODE_MODI(old_mod_node),
                                CBGT_MD_TABLE_ID(cbgt_md));
        }

        /*rollback and rmv left*/
        if(EC_FALSE == __cbgt_make_colf_table_key_by_user_table_key(cbgt_md_id, left_row, &rowkey))
        {
            dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_split_register_no_lock: make rowkey of left table failed\n");
            return (EC_FALSE);
        }

        if(EC_FALSE == cbgt_delete_kv_no_lock(cbgt_md_id, &rowkey))
        {
            dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_split_register_no_lock: delete left row from cbgt %ld table %ld failed\n",
                                cbgt_md_id, CBGT_MD_TABLE_ID(cbgt_md));
            __cbgt_print_colf_table_key(LOGSTDOUT, cbytes_buf(&rowkey));
            sys_print(LOGSTDOUT, "\n");
            cbytes_clean(&rowkey);
            return (EC_FALSE);
        }
        cbytes_clean(&rowkey);

        if(EC_FALSE == mod_node_cmp(left_mod_node, old_mod_node))
        {
            mod_mgr_excl(MOD_NODE_TCID(left_mod_node), MOD_NODE_COMM(left_mod_node), MOD_NODE_RANK(left_mod_node), MOD_NODE_MODI(left_mod_node), CBGT_MD_MOD_MGR(cbgt_md));
        }

        return (EC_FALSE);
    }

    if(EC_TRUE == __cbgt_mod_node_is_valid(cbgt_md_id, right_mod_node))
    {
        mod_mgr_incl(MOD_NODE_TCID(right_mod_node), MOD_NODE_COMM(right_mod_node), MOD_NODE_RANK(right_mod_node), MOD_NODE_MODI(right_mod_node), CBGT_MD_MOD_MGR(cbgt_md));
    }
#if 0
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_split_register_no_lock: [4]\n");
    cbgt_traversal_no_lock(cbgt_md_id, LOGSTDOUT);
#endif
    return (EC_TRUE);
}

EC_BOOL cbgt_split_register(const UINT32 cbgt_md_id,
                                const CBYTES *old_row  ,  const UINT32 old_table_id , const MOD_NODE *old_mod_node ,
                                const CBYTES *left_row , const UINT32 left_table_id , const MOD_NODE *left_mod_node,
                                const CBYTES *right_row, const UINT32 right_table_id, const MOD_NODE *right_mod_node)
{
    CBGT_MD *cbgt_md;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_split_register: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0102);
#if 0
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_split_register: cbgt %ld, table %ld, old_row:  ", cbgt_md_id, CBGT_MD_TABLE_ID(cbgt_md));
    __cbgt_print_colf_table_row(LOGSTDOUT, cbytes_buf(old_row));
    sys_print(LOGSTDOUT, "\n");

    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_split_register: cbgt %ld, table %ld, left_row: ", cbgt_md_id, CBGT_MD_TABLE_ID(cbgt_md));
    __cbgt_print_colf_table_row(LOGSTDOUT, cbytes_buf(left_row));
    sys_print(LOGSTDOUT, "\n");

    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_split_register: cbgt %ld, table %ld, right_row: ", cbgt_md_id, CBGT_MD_TABLE_ID(cbgt_md));
    __cbgt_print_colf_table_row(LOGSTDOUT, cbytes_buf(right_row));
    sys_print(LOGSTDOUT, "\n");
#endif
    CBGT_MD_CRWLOCK_TABLE_WRLOCK(cbgt_md, LOC_CBGT_0103);
    if(EC_FALSE == cbgt_split_register_no_lock(cbgt_md_id,
                                                old_row  , old_table_id  , old_mod_node,
                                                left_row , left_table_id , left_mod_node,
                                                right_row, right_table_id, right_mod_node))
    {
        CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0104);
        return (EC_FALSE);
    }
    CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0105);

    return (EC_TRUE);
}

EC_BOOL cbgt_merge_register_no_lock(const UINT32 cbgt_md_id,
                                const CBYTES *left_row , const UINT32 left_table_id , const MOD_NODE *left_mod_node,
                                const CBYTES *right_row, const UINT32 right_table_id, const MOD_NODE *right_mod_node,
                                const CBYTES *des_row  , const UINT32 des_table_id  , const MOD_NODE *des_mod_node )
{
    CBGT_MD *cbgt_md;
    CBYTES   rowkey;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_merge_register_no_lock: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0106);
#if 0
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_merge_register_no_lock: des_row: ");
    __cbgt_print_colf_table_row(LOGSTDOUT, cbytes_buf(des_row));
    sys_print(LOGSTDOUT, "\n");

    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_merge_register_no_lock: left_row: ");
    __cbgt_print_colf_table_row(LOGSTDOUT, cbytes_buf(left_row));
    sys_print(LOGSTDOUT, "\n");

    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_merge_register_no_lock: right_row: ");
    __cbgt_print_colf_table_row(LOGSTDOUT, cbytes_buf(right_row));
    sys_print(LOGSTDOUT, "\n");
#endif
    /*delete left*/
    if(EC_FALSE == __cbgt_make_colf_table_key_by_user_table_key(cbgt_md_id, left_row, &rowkey))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_merge_register_no_lock: make rowkey of colf table from left row failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cbgt_delete_kv_no_lock(cbgt_md_id, &rowkey))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_merge_register_no_lock: delete left row failed\n");
        cbytes_clean(&rowkey);
        return (EC_FALSE);
    }
    cbytes_clean(&rowkey);

    /*delete right*/
    if(EC_FALSE == __cbgt_make_colf_table_key_by_user_table_key(cbgt_md_id, right_row, &rowkey))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_merge_register_no_lock: make rowkey of colf table from right row failed\n");

        /*roll back left*/
        if(EC_FALSE == cbgt_insert_register_no_lock(cbgt_md_id, left_row, left_table_id, left_mod_node))
        {
            dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_split_register: restore left table %ld (tcid %s, comm %ld, rank %ld, modi %ld) register info to parent table %ld failed\n",
                                left_table_id,
                                MOD_NODE_TCID_STR(left_mod_node),
                                MOD_NODE_COMM(left_mod_node),
                                MOD_NODE_RANK(left_mod_node),
                                MOD_NODE_MODI(left_mod_node),
                                CBGT_MD_TABLE_ID(cbgt_md));
        }
        return (EC_FALSE);
    }

    if(EC_FALSE == cbgt_delete_kv_no_lock(cbgt_md_id, &rowkey))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_merge_register_no_lock: delete right row failed\n");

        /*roll back left*/
        if(EC_FALSE == cbgt_insert_register_no_lock(cbgt_md_id, left_row, left_table_id, left_mod_node))
        {
            dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_split_register: restore left table %ld (tcid %s, comm %ld, rank %ld, modi %ld) register info to parent table %ld failed\n",
                                left_table_id,
                                MOD_NODE_TCID_STR(left_mod_node),
                                MOD_NODE_COMM(left_mod_node),
                                MOD_NODE_RANK(left_mod_node),
                                MOD_NODE_MODI(left_mod_node),
                                CBGT_MD_TABLE_ID(cbgt_md));
        }
        cbytes_clean(&rowkey);
        return (EC_FALSE);
    }
    cbytes_clean(&rowkey);

    /*insert left */
    if(EC_FALSE == cbgt_insert_register_no_lock(cbgt_md_id, des_row, des_table_id, des_mod_node))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_split_register: insert des table %ld (tcid %s, comm %ld, rank %ld, modi %ld) register info in parent table %ld failed\n",
                            des_table_id,
                            MOD_NODE_TCID_STR(des_mod_node),
                            MOD_NODE_COMM(des_mod_node),
                            MOD_NODE_RANK(des_mod_node),
                            MOD_NODE_MODI(des_mod_node),
                            CBGT_MD_TABLE_ID(cbgt_md));

        /*roll back left*/
        if(EC_FALSE == cbgt_insert_register_no_lock(cbgt_md_id, left_row, left_table_id, left_mod_node))
        {
            dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_split_register: restore left table %ld (tcid %s, comm %ld, rank %ld, modi %ld) register info to parent table %ld failed\n",
                                left_table_id,
                                MOD_NODE_TCID_STR(left_mod_node),
                                MOD_NODE_COMM(left_mod_node),
                                MOD_NODE_RANK(left_mod_node),
                                MOD_NODE_MODI(left_mod_node),
                                CBGT_MD_TABLE_ID(cbgt_md));
        }

        /*roll back right*/
        if(EC_FALSE == cbgt_insert_register_no_lock(cbgt_md_id, right_row, right_table_id, right_mod_node))
        {
            dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_split_register: restore right table %ld (tcid %s, comm %ld, rank %ld, modi %ld) register info to parent table %ld failed\n",
                                right_table_id,
                                MOD_NODE_TCID_STR(right_mod_node),
                                MOD_NODE_COMM(right_mod_node),
                                MOD_NODE_RANK(right_mod_node),
                                MOD_NODE_MODI(right_mod_node),
                                CBGT_MD_TABLE_ID(cbgt_md));
        }
        return (EC_FALSE);
    }

    if(EC_TRUE == __cbgt_mod_node_is_valid(cbgt_md_id, des_mod_node))
    {
        mod_mgr_incl(MOD_NODE_TCID(des_mod_node), MOD_NODE_COMM(des_mod_node), MOD_NODE_RANK(des_mod_node), MOD_NODE_MODI(des_mod_node), CBGT_MD_MOD_MGR(cbgt_md));
    }
    return (EC_TRUE);
}

EC_BOOL cbgt_merge_register(const UINT32 cbgt_md_id,
                                const CBYTES *left_row , const UINT32 left_table_id , const MOD_NODE *left_mod_node,
                                const CBYTES *right_row, const UINT32 right_table_id, const MOD_NODE *right_mod_node,
                                const CBYTES *des_row  , const UINT32 des_table_id  , const MOD_NODE *des_mod_node )
{
    CBGT_MD *cbgt_md;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_merge_register: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0107);

    CBGT_MD_CRWLOCK_TABLE_WRLOCK(cbgt_md, LOC_CBGT_0108);
    if(EC_FALSE == cbgt_merge_register_no_lock(cbgt_md_id,
                                                left_row , left_table_id , left_mod_node,
                                                right_row, right_table_id, right_mod_node,
                                                des_row  , des_table_id  , des_mod_node))
    {
        CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0109);
        return (EC_FALSE);
    }
    CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0110);

    return (EC_TRUE);
}

EC_BOOL cbgt_delete_kv_no_lock(const UINT32 cbgt_md_id, const CBYTES *key_bytes)
{
    CBGT_MD    *cbgt_md;

    uint8_t    *key;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_delete_kv_no_lock: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0111);

    key = cbytes_buf(key_bytes);

    if(EC_TRUE == cbgt_gdb_del_key(CBGT_MD_GDB(cbgt_md), key))
    {
        return (EC_TRUE);
    }

    dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_delete_kv_no_lock: cbgt %ld, table %ld, type %s, delete key failed\n",
                        cbgt_md_id, CBGT_MD_TABLE_ID(cbgt_md), __cbgt_type(CBGT_MD_TYPE(cbgt_md)));
    __cbgt_print_key(cbgt_md_id, key, LOGSTDOUT);
    sys_print(LOGSTDOUT, "\n");
    //cbgt_runthrough_no_lock(cbgt_md_id, LOGSTDOUT);
    return (EC_FALSE);
}

EC_BOOL cbgt_delete_kv(const UINT32 cbgt_md_id, const CBYTES *key_bytes)
{
    CBGT_MD    *cbgt_md;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_delete_kv: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0112);

    CBGT_MD_CRWLOCK_TABLE_WRLOCK(cbgt_md, LOC_CBGT_0113);
    if(EC_FALSE == cbgt_delete_kv_no_lock(cbgt_md_id, key_bytes))
    {
        CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0114);
        return (EC_FALSE);
    }
    CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0115);

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cbgt_clean_report_vec_words(const UINT32 cbgt_md_id, CVECTOR *report_vec)
{
    UINT32 num;
    UINT32 pos;

    num = cvector_size(report_vec);
    for(pos = 0; pos < num; pos ++)
    {
        UINT32    *word;

        word = (UINT32 *)cvector_get_no_lock(report_vec, pos);
        cvector_set_no_lock(report_vec, pos, NULL_PTR);
        free_static_mem(MM_UINT32, word, LOC_CBGT_0116);
    }

    return (EC_TRUE);
}

EC_BOOL __cbgt_merge_one_group(const UINT32 cbgt_md_id, const CVECTOR *kv_bytes_vec)
{
    CBGT_MD   *cbgt_md;

    MOD_MGR   *mod_mgr;
    TASK_MGR  *task_mgr;

    MOD_NODE   colf_mod_node;

    UINT32     kv_bytes_pos;

    UINT32     remote_mod_node_num;
    UINT32     remote_mod_node_idx;

    CVECTOR   *report_vec;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:__cbgt_merge_one_group: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0117);
#if 0
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDNULL, "[DEBUG] __cbgt_merge_one_group: CBGT module %ld: table %ld type %s\n",
                        cbgt_md_id, CBGT_MD_TABLE_ID(cbgt_md), __cbgt_type(CBGT_MD_TYPE(cbgt_md)));
#endif
    mod_mgr = mod_mgr_new(cbgt_md_id, LOAD_BALANCING_LOOP);
    if(NULL_PTR == mod_mgr)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_merge_one_group: new mod mgr failed\n");
        return (EC_FALSE);
    }

    __cbgt_local_mod_node(cbgt_md_id, &colf_mod_node);

    /*start odd user table*/
    for(kv_bytes_pos = 0; kv_bytes_pos + 2 <= cvector_size(kv_bytes_vec); kv_bytes_pos += 2)
    {
        UINT32   table_id;
        MOD_NODE mod_node;
        CBYTES   user_rowkey;
        CBYTES  *kv_bytes;

        kv_bytes = (CBYTES *)cvector_get_no_lock(kv_bytes_vec, kv_bytes_pos + 1);

        cbytes_init(&user_rowkey);
        if(EC_FALSE == cbgt_fetch_row(cbgt_md_id, kv_bytes, &user_rowkey))
        {
            dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_merge_one_group: fetch key from kv_bytes on table %ld type %s failed\n",
                                CBGT_MD_TABLE_ID(cbgt_md), __cbgt_type(CBGT_MD_TABLE_ID(cbgt_md)));

            task_dea(mod_mgr, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, FI_cbgt_end, CMPI_ERROR_MODI);
            return (EC_FALSE);
        }

        if(EC_FALSE == cbgt_fetch_from_rmc(cbgt_md_id, kv_bytes, &table_id,  &mod_node))
        {
            dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_merge_one_group: fetch (table id, mod node) from kv_bytes on table %ld type %s failed\n",
                                CBGT_MD_TABLE_ID(cbgt_md), __cbgt_type(CBGT_MD_TABLE_ID(cbgt_md)));

            cbytes_clean(&user_rowkey);
            task_dea(mod_mgr, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, FI_cbgt_end, CMPI_ERROR_MODI);
            return (EC_FALSE);
        }
#if 0
        dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] __cbgt_merge_one_group: table_name = ");
        __cbgt_print_user_table_key(LOGSTDOUT, cbytes_buf(&user_rowkey));
        sys_print(LOGSTDOUT, " mod_node = (tcid %s, comm %ld, rank %ld, modi %ld)\n",
                    MOD_NODE_TCID_STR(&mod_node),
                    MOD_NODE_COMM(&mod_node),
                    MOD_NODE_RANK(&mod_node),
                    MOD_NODE_MODI(&mod_node));
#endif
        if(EC_FALSE == __cbgt_start_trigger(cbgt_md_id,
                             CBGT_TYPE_USER_SERVER,
                             table_id,
                             &user_rowkey,
                             &colf_mod_node,
                             CBGT_MD_ROOT_PATH(cbgt_md),
                             CBGT_O_RDWR,
                             &mod_node))
        {
            dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_merge_one_group: cbgt start user table %ld on table %ld type %s failed\n",
                            table_id, CBGT_MD_TABLE_ID(cbgt_md), __cbgt_type(CBGT_MD_TABLE_ID(cbgt_md)));
            cbytes_clean(&user_rowkey);
            task_dea(mod_mgr, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, FI_cbgt_end, CMPI_ERROR_MODI);
            return (EC_FALSE);
        }
        cbytes_clean(&user_rowkey);

        mod_mgr_incl(MOD_NODE_TCID(&mod_node), MOD_NODE_COMM(&mod_node), MOD_NODE_RANK(&mod_node), MOD_NODE_MODI(&mod_node), mod_mgr);
    }

    report_vec = cvector_new(0, MM_UINT32, LOC_CBGT_0118);

    /*merge even table to the started odd table*/
    task_mgr = task_new(mod_mgr, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(kv_bytes_pos = 0, remote_mod_node_idx = 0;
        kv_bytes_pos + 2 <= cvector_size(kv_bytes_vec) && remote_mod_node_idx < remote_mod_node_num;
        kv_bytes_pos += 2, remote_mod_node_idx ++)
    {
        CBYTES   table_name;
        UINT32   table_id;
        MOD_NODE mod_node;

        UINT32    *ret;
        CBYTES  *kv_bytes;

        kv_bytes = (CBYTES *)cvector_get_no_lock(kv_bytes_vec, kv_bytes_pos);


        if(EC_FALSE == cbgt_fetch_row(cbgt_md_id, kv_bytes, &table_name))
        {
            dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_merge_one_group: fetch row from kv_bytes on table %ld type %s failed\n",
                                CBGT_MD_TABLE_ID(cbgt_md), __cbgt_type(CBGT_MD_TABLE_ID(cbgt_md)));

            task_dea(mod_mgr, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, FI_cbgt_end, CMPI_ERROR_MODI);
            task_mgr_free(task_mgr);
            __cbgt_clean_report_vec_words(cbgt_md_id, report_vec);
            cvector_free_no_lock(report_vec, LOC_CBGT_0119);
            return (EC_FALSE);
        }

        if(EC_FALSE == cbgt_fetch_from_rmc(cbgt_md_id, kv_bytes, &table_id,  &mod_node))
        {
            dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_merge_one_group: fetch (table id, mod node) from kv_bytes on table %ld type %s failed\n",
                                CBGT_MD_TABLE_ID(cbgt_md), __cbgt_type(CBGT_MD_TABLE_ID(cbgt_md)));

            task_dea(mod_mgr, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, FI_cbgt_end, CMPI_ERROR_MODI);
            task_mgr_free(task_mgr);
            __cbgt_clean_report_vec_words(cbgt_md_id, report_vec);
            cvector_free_no_lock(report_vec, LOC_CBGT_0120);
            return (EC_FALSE);
        }

        alloc_static_mem(MM_UINT32, &ret, LOC_CBGT_0121);
        cvector_push_no_lock(report_vec, (void *)ret);
        (*ret) = EC_FALSE;

        task_pos_inc(task_mgr, remote_mod_node_idx, ret, FI_cbgt_merge_table, CMPI_ERROR_MODI, &table_name, table_id);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    /*TODO: check ret value*/
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        UINT32    *ret;

        ret = (UINT32 *)cvector_get_no_lock(report_vec, remote_mod_node_idx);
        cvector_set_no_lock(report_vec, remote_mod_node_idx, NULL_PTR);
        free_static_mem(MM_UINT32, ret, LOC_CBGT_0122);
    }
    cvector_free_no_lock(report_vec, LOC_CBGT_0123);

    /*end odd user table*/
    task_dea(mod_mgr, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, FI_cbgt_end, CMPI_ERROR_MODI);

    return (EC_TRUE);
}

EC_BOOL __cbgt_merge_groups(const UINT32 cbgt_md_id)
{
    CBGT_MD   *cbgt_md;
    CBGT_GDB  *gdb;

    UINT32     count;
    CVECTOR    kv_bytes_vec;

    CBTREE      *cbtree;
    CBTREE_NODE *cbtree_node;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:__cbgt_merge_groups: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0124);

    gdb = CBGT_MD_GDB(cbgt_md);
    cbtree = CBGT_GDB_CBTREE(gdb);
    if(NULL_PTR == cbtree)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_merge_groups: cbtree is null\n");
        return (EC_FALSE);
    }

    cvector_init(&kv_bytes_vec, 0, MM_CBYTES, CVECTOR_LOCK_ENABLE, LOC_CBGT_0125);

    count = 0;
    for(cbtree_node = CBTREE_LEFT_LEAF(cbtree);
        NULL_PTR != cbtree_node;
        cbtree_node = CBTREE_NODE_CHILD(cbtree_node , CBTREE_ORDER(cbtree) - 1)
        )
    {
        uint8_t idx;

        for(idx = 0; idx < CBTREE_NODE_COUNT(cbtree_node); idx ++)
        {
            CBTREE_KEY *cbtree_key;
            uint8_t *kv;
            CBYTES  *kv_bytes;

            cbtree_key = CBTREE_NODE_KEY(cbtree_node, idx);
            kv = CBTREE_KEY_LATEST(cbtree_key);

            kv_bytes = cbytes_new(0);
            if(NULL_PTR == kv_bytes)
            {
                dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_merge_groups: new cbytes failed\n");
                cvector_clean_no_lock(&kv_bytes_vec, (CVECTOR_DATA_CLEANER)cbytes_free, LOC_CBGT_0126);
                return (EC_FALSE);
            }

            if(EC_FALSE == cbytes_set(kv_bytes, kv, kvGettLenHs(kv)))
            {
                dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_merge_groups: set cbytes failed\n");
                cbytes_free(kv_bytes);
                cvector_clean_no_lock(&kv_bytes_vec, (CVECTOR_DATA_CLEANER)cbytes_free, LOC_CBGT_0127);
                return (EC_FALSE);
            }

            cvector_push_no_lock(&kv_bytes_vec, (void *)kv_bytes);
        }

        count += CBTREE_NODE_COUNT(cbtree_node);

        if((CBGT_ONCE_MERGE_TABLE_NUM * 2) > count)
        {
            continue;
        }

        if(EC_FALSE == __cbgt_merge_one_group(cbgt_md_id, &kv_bytes_vec))
        {
            dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_merge_groups: merge group on table %ld type %s failed\n",
                                CBGT_MD_TABLE_ID(cbgt_md), __cbgt_type(CBGT_MD_TABLE_ID(cbgt_md)));
            cvector_clean_no_lock(&kv_bytes_vec, (CVECTOR_DATA_CLEANER)cbytes_free, LOC_CBGT_0128);
            return (EC_FALSE);
        }
        cvector_clean_no_lock(&kv_bytes_vec, (CVECTOR_DATA_CLEANER)cbytes_free, LOC_CBGT_0129);
    }

    /*handle the left*/
    if(0 < cvector_size(&kv_bytes_vec) && EC_FALSE == __cbgt_merge_one_group(cbgt_md_id, &kv_bytes_vec))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_merge_groups: merge group on table %ld type %s failed\n",
                            CBGT_MD_TABLE_ID(cbgt_md), __cbgt_type(CBGT_MD_TABLE_ID(cbgt_md)));
        cvector_clean_no_lock(&kv_bytes_vec, (CVECTOR_DATA_CLEANER)cbytes_free, LOC_CBGT_0130);
        return (EC_FALSE);
    }
    cvector_clean_no_lock(&kv_bytes_vec, (CVECTOR_DATA_CLEANER)cbytes_free, LOC_CBGT_0131);

    return (EC_TRUE);
}

EC_BOOL cbgt_merge(const UINT32 cbgt_md_id)
{
    CBGT_MD   *cbgt_md;

    MOD_MGR   *mod_mgr;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_merge: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    mod_mgr = CBGT_MD_MOD_MGR(cbgt_md);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0132);
#if 0
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDNULL, "[DEBUG] cbgt_merge: CBGT module %ld: table %ld type %s\n",
                        cbgt_md_id, CBGT_MD_TABLE_ID(cbgt_md), __cbgt_type(CBGT_MD_TYPE(cbgt_md)));
#endif
    if(EC_TRUE == cbgt_is_user_server(cbgt_md_id) || EC_TRUE == cbgt_is_user_client(cbgt_md_id))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_merge: table %ld type %s should never reach here\n",
                            CBGT_MD_TABLE_ID(cbgt_md), __cbgt_type(CBGT_MD_TYPE(cbgt_md)));
        return (EC_FALSE);
    }

    if(EC_TRUE == cbgt_is_root_server(cbgt_md_id) || EC_TRUE == cbgt_is_meta_server(cbgt_md_id))
    {
        TASK_MGR  *task_mgr;

        CVECTOR   *report_vec;

        UINT32     remote_mod_node_idx;
        UINT32     remote_mod_node_num;

        report_vec = cvector_new(0, MM_UINT32, LOC_CBGT_0133);

        task_mgr = task_new(mod_mgr, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
        remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
        for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
        {
            UINT32    *ret;

            alloc_static_mem(MM_UINT32, &ret, LOC_CBGT_0134);
            cvector_push_no_lock(report_vec, (void *)ret);
            (*ret) = EC_FALSE;

            task_pos_inc(task_mgr, remote_mod_node_idx, ret, FI_cbgt_merge, CMPI_ERROR_MODI);
        }
        task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

        for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
        {
            UINT32    *ret;

            ret = (UINT32 *)cvector_get_no_lock(report_vec, remote_mod_node_idx);
            cvector_set_no_lock(report_vec, remote_mod_node_idx, NULL_PTR);
            free_static_mem(MM_UINT32, ret, LOC_CBGT_0135);
        }
        cvector_free_no_lock(report_vec, LOC_CBGT_0136);

        return (EC_TRUE);
    }

    if(EC_FALSE == cbgt_is_colf_server(cbgt_md_id))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_merge: table %ld type %s is not colf server\n",
                            CBGT_MD_TABLE_ID(cbgt_md), __cbgt_type(CBGT_MD_TYPE(cbgt_md)));
        return (EC_FALSE);
    }

    /*close all user tables of this colf*/
    task_dea(mod_mgr, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, FI_cbgt_end, CMPI_ERROR_MODI);
    CBGT_MD_MOD_MGR(cbgt_md) = mod_mgr_new(cbgt_md_id, LOAD_BALANCING_OBJ);
    if(NULL_PTR == CBGT_MD_MOD_MGR(cbgt_md))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_merge: new mod mgr for CBGT module %ld after dea old all failed\n", cbgt_md_id);
        return (EC_FALSE);
    }

    CBGT_MD_CRWLOCK_TABLE_WRLOCK(cbgt_md, LOC_CBGT_0137);
    if(EC_FALSE == __cbgt_merge_groups(cbgt_md_id))
    {
        CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0138);
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_merge: collect all offset failed\n");
        return (EC_FALSE);
    }
    CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0139);

    return (EC_TRUE);
}

/*split_flag will indicate whether or not the orignal table was broken/splitted, despite of success or failure*/
/*split_flag = EC_TRUE means split happen, EC_FALSE means not happen*/
STATIC_CAST static EC_BOOL __cbgt_split_no_lock(const UINT32 cbgt_md_id, EC_BOOL *split_flag)
{
    CBGT_MD   *cbgt_md;
    CBGT_GDB  *old_gdb;
    CBGT_GDB  *left_gdb;

    UINT32     local_table_id;
    UINT32     left_table_id;
    UINT32     right_table_id;

    MOD_NODE  *parent;
    CBYTES    *table_name;

    /*parse from current table name which format is (start_user_rowkey, end_user_rowkey]*/
    uint8_t   *start_user_rowkey;
    uint8_t   *end_user_rowkey;

    uint8_t   *last_user_rowkey;

    CBYTES     left_colf_row;
    CBYTES     right_colf_row;

    MOD_NODE   local_mod_node;
    MOD_NODE   left_mod_node;
    MOD_NODE   right_mod_node;

    EC_BOOL  ret;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:__cbgt_split_no_lock: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    parent         = CBGT_MD_PARENT_MOD(cbgt_md);
    table_name     = CBGT_MD_TABLE_NAME(cbgt_md);
    local_table_id = CBGT_MD_TABLE_ID(cbgt_md);
    old_gdb        = CBGT_MD_GDB(cbgt_md);
    right_table_id = CBGT_MD_TABLE_ID(cbgt_md);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0140);

    (*split_flag) = EC_FALSE;

    if(EC_FALSE == cbgt_is_user_server(cbgt_md_id))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_split_no_lock: current table %ld is not user table, but split happen on user table only\n",
                            right_table_id);
        return (EC_FALSE);
    }

    if(EC_FALSE == cbgt_reserve_table_id(cbgt_md_id, &left_table_id))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_split_no_lock: reserve table id from current table %ld type %s failed\n",
                            CBGT_MD_TABLE_ID(cbgt_md), __cbgt_type(CBGT_MD_TYPE(cbgt_md)));
        return (EC_FALSE);
    }

    dbg_log(SEC_0054_CBGT, 0)(LOGCONSOLE, "[DEBUG] __cbgt_split_no_lock: enter\n");

    __cbgt_local_mod_node(cbgt_md_id, &local_mod_node);
    __cbgt_error_mod_node(cbgt_md_id, &left_mod_node);
    __cbgt_local_mod_node(cbgt_md_id, &right_mod_node);

    //CBGT_MD_CRWLOCK_TABLE_WRLOCK(cbgt_md, LOC_CBGT_0141);

    /*create left table*/
    left_gdb = cbgt_gdb_open(CBGT_MD_ROOT_PATH_STR(cbgt_md), left_table_id, CBGT_MD_CDFS_MD_ID(cbgt_md),
                             O_CREAT, __cbgt_type_to_cbtree_type(CBGT_MD_TYPE(cbgt_md)));
    if(NULL_PTR == left_gdb)
    {
        //CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0142);
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_split_no_lock: create table %ld failed\n", left_table_id);
        cbgt_release_table_id(cbgt_md_id, left_table_id);
        return (EC_FALSE);
    }

    (*split_flag) = EC_TRUE;

    if(EC_FALSE == cbgt_gdb_split(old_gdb, left_gdb))
    {
        //CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0143);
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_split_no_lock: split table %ld failed\n", local_table_id);
        cbgt_gdb_close_without_flush(left_gdb);
        cbgt_release_table_id(cbgt_md_id, left_table_id);
        return (EC_FALSE);
    }

    /*write endkey and table id to parent table*/
    if(EC_FALSE == cbgt_gdb_get_last_key(left_gdb, &last_user_rowkey))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_split_no_lock: get last key from left gdb %p of table %ld failed\n", left_gdb, local_table_id);
        cbgt_gdb_close_without_flush(left_gdb);
        cbgt_release_table_id(cbgt_md_id, left_table_id);
        return (EC_FALSE);
    }

    __cbgt_split_colf_row_into_start_end_user_table_key(cbytes_buf(table_name), &start_user_rowkey, &end_user_rowkey);

    if(EC_FALSE == __cbgt_make_row_of_colf_table_by_start_end_user_table_key(start_user_rowkey, last_user_rowkey, &left_colf_row))
    {
        //CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0144);
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_split_no_lock: make row of colf table by left user table (startUserRowKey, lastUserRowKey) failed\n");
        safe_free(last_user_rowkey, LOC_CBGT_0145);
        cbgt_gdb_close_without_flush(left_gdb);
        cbgt_release_table_id(cbgt_md_id, left_table_id);
        return (EC_FALSE);
    }

    if(EC_FALSE == __cbgt_make_row_of_colf_table_by_start_end_user_table_key(last_user_rowkey, end_user_rowkey, &right_colf_row))
    {
        //CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0146);
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_split_no_lock: make row of colf table by right user table (lastUserRowKey, endUserRowKey) failed\n");
        safe_free(last_user_rowkey, LOC_CBGT_0147);
        cbytes_clean(&left_colf_row);
        cbgt_gdb_close_without_flush(left_gdb);
        cbgt_release_table_id(cbgt_md_id, left_table_id);
        return (EC_FALSE);
    }
    safe_free(last_user_rowkey, LOC_CBGT_0148);

    ret = EC_FALSE;
    task_p2p(cbgt_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             parent,
             &ret, FI_cbgt_split_register, CMPI_ERROR_MODI, table_name     , local_table_id, &local_mod_node,
                                                          &left_colf_row , left_table_id , &left_mod_node ,
                                                          &right_colf_row, right_table_id, &right_mod_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_split_no_lock: register left table %ld to parent (tcid %s, comm %ld, rank %ld, modi %ld) failed\n",
                            left_table_id,
                            MOD_NODE_TCID_STR(parent),
                            MOD_NODE_COMM(parent),
                            MOD_NODE_RANK(parent),
                            MOD_NODE_MODI(parent)
                            );

        cbytes_clean(&left_colf_row);
        cbytes_clean(&right_colf_row);

        cbgt_gdb_close_without_flush(left_gdb);
        cbgt_release_table_id(cbgt_md_id, left_table_id);
        return (EC_FALSE);
    }

    /*replace current gdb with right_gdb*/
    cbytes_clean(table_name);
    cbytes_clone(&right_colf_row, table_name);

    cbytes_clean(&left_colf_row);
    cbytes_clean(&right_colf_row);

    cbgt_gdb_close(left_gdb);/*will flush it*/
    return (EC_TRUE);
}

EC_BOOL cbgt_split_no_lock(const UINT32 cbgt_md_id)
{
    CBGT_MD   *cbgt_md;
    EC_BOOL    split_flag;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_split_no_lock: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    split_flag = EC_FALSE;/*default is split not happen*/

    /*flush before split*/
    if(EC_FALSE == cbgt_gdb_flush(CBGT_MD_GDB(cbgt_md)))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_split_no_lock: flush table %ld before split failed\n", CBGT_MD_TABLE_ID(cbgt_md));
        return (EC_FALSE);
    }

    if(EC_FALSE == __cbgt_split_no_lock(cbgt_md_id, &split_flag))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_split_no_lock: split table %ld failed\n", CBGT_MD_TABLE_ID(cbgt_md));
        if(EC_TRUE == split_flag)
        {
            cbgt_gdb_load(CBGT_MD_GDB(cbgt_md));/*restore!*/
        }

        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cbgt_split(const UINT32 cbgt_md_id)
{
    CBGT_MD   *cbgt_md;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_split: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);

    CBGT_MD_CRWLOCK_TABLE_WRLOCK(cbgt_md, LOC_CBGT_0149);
    if(EC_FALSE == cbgt_split_no_lock(cbgt_md_id))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_split: table %ld split failed\n", CBGT_MD_TABLE_ID(cbgt_md));
        CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0150);
        return (EC_FALSE);
    }
    CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0151);
    return (EC_TRUE);
}

EC_BOOL cbgt_unlink(const UINT32 cbgt_md_id, const UINT32 table_id)
{
    CBGT_MD *cbgt_md;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_unlink: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0152);

    dbg_log(SEC_0054_CBGT, 9)(LOGSTDNULL, "[DEBUG]cbgt_unlink: table id %ld\n", table_id);

    cbgt_gdb_unlink(CBGT_MD_GDB(cbgt_md), CBGT_MD_ROOT_PATH(cbgt_md), table_id);

    return (EC_TRUE);
}

/*merge table content to current table...*/
EC_BOOL cbgt_merge_table(const UINT32 cbgt_md_id, const CBYTES *left_table_name, const UINT32 left_table_id)
{
    CBGT_MD  *cbgt_md;

    CBGT_GDB  *right_gdb;
    CBGT_GDB  *left_gdb;

    UINT32     right_table_id;
    UINT32     des_table_id;

    CBYTES    *right_table_name;
    MOD_NODE  *parent;

    MOD_NODE   left_mod_node;
    MOD_NODE   right_mod_node;
    MOD_NODE   des_mod_node;

    uint8_t   *right_start_user_rowkey;
    uint8_t   *right_end_user_rowkey;

    uint8_t   *left_start_user_rowkey;
    uint8_t   *left_end_user_rowkey;

    CBYTES    *des_table_name;

    EC_BOOL    ret;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_merge_table: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    right_table_id   = CBGT_MD_TABLE_ID(cbgt_md);
    right_table_name = CBGT_MD_TABLE_NAME(cbgt_md);
    parent           = CBGT_MD_PARENT_MOD(cbgt_md);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0153);

    des_table_id  = right_table_id;
#if 0
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDNULL, "[DEBUG] cbgt_merge_table: CBGT module %ld: table %ld type %s: try to merge table %ld\n",
                        cbgt_md_id, CBGT_MD_TABLE_ID(cbgt_md), __cbgt_type(CBGT_MD_TYPE(cbgt_md)), left_table_id);
#endif
    if(EC_FALSE == cbgt_is_user_server(cbgt_md_id))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_merge_table: current table %ld is not user table, but merge can happen on user table only\n",
                            des_table_id);
        return (EC_FALSE);
    }

    __cbgt_split_colf_row_into_start_end_user_table_key(cbytes_buf(left_table_name), &left_start_user_rowkey, &left_end_user_rowkey);
    __cbgt_split_colf_row_into_start_end_user_table_key(cbytes_buf(right_table_name), &right_start_user_rowkey, &right_end_user_rowkey);

    if(0 != keyCmpHs2(left_end_user_rowkey, right_start_user_rowkey))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_merge_table: refuse to merge due to not neighbor tables\n");
#if 0
        dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_merge_table: left table name: ");
        __cbgt_print_colf_table_row(LOGSTDOUT, cbytes_buf(left_table_name));
        sys_print(LOGSTDOUT, "\n");

        dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_merge_table: right table name: ");
        __cbgt_print_colf_table_row(LOGSTDOUT, cbytes_buf(right_table_name));
        sys_print(LOGSTDOUT, "\n");
#endif
        return (EC_FALSE);
    }

    des_table_name = cbytes_new(0);
    if(EC_FALSE == __cbgt_make_row_of_colf_table_by_start_end_user_table_key(left_start_user_rowkey, right_end_user_rowkey, des_table_name))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_merge_table: make row of colf table by left user table startUserRowKey and right user table endUserRowKey) failed\n");
        return (EC_FALSE);
    }
#if 0
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_merge_table: des table name: ");
    __cbgt_print_colf_table_row(LOGSTDOUT, cbytes_buf(des_table_name));
    sys_print(LOGSTDOUT, "\n");
#endif
    __cbgt_error_mod_node(cbgt_md_id, &left_mod_node);
    __cbgt_local_mod_node(cbgt_md_id, &right_mod_node);
    __cbgt_local_mod_node(cbgt_md_id, &des_mod_node);

    CBGT_MD_CRWLOCK_TABLE_WRLOCK(cbgt_md, LOC_CBGT_0154);
    right_gdb = CBGT_MD_GDB(cbgt_md);

    left_gdb = cbgt_gdb_open(CBGT_MD_ROOT_PATH_STR(cbgt_md), left_table_id, CBGT_MD_CDFS_MD_ID(cbgt_md),
                            O_RDWR, __cbgt_type_to_cbtree_type(CBGT_MD_TYPE(cbgt_md)));
    if(NULL_PTR == left_gdb)
    {
        CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0155);
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_merge_table: open table %ld for reading/writting failed\n", left_table_id);
        cbytes_free(des_table_name);
        return (EC_FALSE);
    }

    if(EC_FALSE == cbgt_gdb_merge(right_gdb, left_gdb))
    {
        CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0156);
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_merge_table: merge left table %ld and right table %ld failed\n",
                            left_table_id, right_table_id);
        cbytes_free(des_table_name);
        cbgt_gdb_close_without_flush(left_gdb);
        return (EC_FALSE);
    }
    cbgt_gdb_close_without_flush(left_gdb);

    ret = EC_FALSE;
    task_p2p(cbgt_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             parent,
             &ret, FI_cbgt_merge_register, CMPI_ERROR_MODI, right_table_name , right_table_id, &right_mod_node,
                                                          left_table_name  , left_table_id , &left_mod_node ,
                                                          des_table_name   , des_table_id  , &des_mod_node);

    if(EC_FALSE == ret)
    {
        CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0157);
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_merge_table: merge register to parent failed\n");
        cbytes_free(des_table_name);
        return (EC_FALSE);
    }

    /*return back table id to table id pool*/
    cbgt_release_table_id(cbgt_md_id, left_table_id);

    /*handover*/
    cbytes_free(CBGT_MD_TABLE_NAME(cbgt_md));
    CBGT_MD_TABLE_NAME(cbgt_md) = des_table_name;

    cbgt_unlink(cbgt_md_id, left_table_id);

    cbgt_gdb_flush(right_gdb);
    CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0158);
    return (EC_TRUE);
}

EC_BOOL cbgt_flush(const UINT32 cbgt_md_id)
{
    CBGT_MD *cbgt_md;

    if(CMPI_ANY_MODI == cbgt_md_id)
    {
        UINT32 this_cbgt_md_id;
        UINT32 succ_num;

        for( succ_num = 0, this_cbgt_md_id = 0; this_cbgt_md_id < CBGT_MD_CAPACITY(); this_cbgt_md_id ++ )
        {
            cbgt_md = CBGT_MD_GET(this_cbgt_md_id);

            if (NULL_PTR != cbgt_md && 0 < cbgt_md->usedcounter && EC_TRUE == cbgt_flush(this_cbgt_md_id))
            {
                succ_num ++;
            }
        }

        return (0 == succ_num? EC_FALSE : EC_TRUE);
    }

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_flush: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0159);

    if(NULL_PTR != CBGT_MD_GDB(cbgt_md))
    {
        CBGT_MD_CMUTEX_TABLE_ID_POOL_LOCK(cbgt_md, LOC_CBGT_0160);
        cbgt_gdb_flush(CBGT_MD_GDB(cbgt_md));
        CBGT_MD_CMUTEX_TABLE_ID_POOL_UNLOCK(cbgt_md, LOC_CBGT_0161);
    }

    if(EC_TRUE == cbgt_is_root_server(cbgt_md_id))
    {
        CSTRING *table_id_pool_fname;
        MOD_NODE root_mod_node;

        CBGT_MD_CMUTEX_TABLE_ID_POOL_LOCK(cbgt_md, LOC_CBGT_0162);
        /*flush bitmap*/
        table_id_pool_fname = __cbgt_gen_cbitmap_file_name_cstr(CBGT_MD_ROOT_PATH(cbgt_md));
        __cbgt_flush_table_id_pool(cbgt_md_id, table_id_pool_fname, CBGT_MD_TABLE_ID_POOL(cbgt_md));
        cstring_free(table_id_pool_fname);

        /*flush */
        __cbgt_local_mod_node(cbgt_md_id, &root_mod_node);
        __cbgt_flush_root_record_file(cbgt_md_id, CBGT_MD_ROOT_PATH(cbgt_md), CBGT_MD_TABLE_ID(cbgt_md), &root_mod_node);
        CBGT_MD_CMUTEX_TABLE_ID_POOL_UNLOCK(cbgt_md, LOC_CBGT_0163);
    }

    return (EC_TRUE);
}

EC_BOOL cbgt_exist_table(const UINT32 cbgt_md_id, const CBYTES *table_name)
{
    CBGT_MD    *cbgt_md;
    CBGT_GDB   *gdb;

    CBYTES key;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_exist_table: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0164);

    if(EC_FALSE == __cbgt_make_rmc_table_key(cbgt_md_id, table_name, &key))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_exist_table: init key failed\n");
        return (EC_FALSE);
    }

    CBGT_MD_CRWLOCK_TABLE_RDLOCK(cbgt_md, LOC_CBGT_0165);
    gdb = CBGT_MD_GDB(cbgt_md);

    if(NULL_PTR != cbgt_gdb_search_key(gdb, cbytes_buf(&key)))
    {
        CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0166);
        cbgt_key_clean(cbgt_md_id, &key);
        return (EC_TRUE);
    }
    CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0167);

    cbgt_key_clean(cbgt_md_id, &key);
    return (EC_FALSE);
}

/*on root server. col_family_name_vec is cbytes vector*/
EC_BOOL cbgt_create_table_on_root(const UINT32 cbgt_md_id, const CBYTES *table_name, const CVECTOR *col_family_name_vec)
{
    CBGT_MD    *cbgt_md;

    UINT32      meta_table_id;

    MOD_NODE    root_mod_node;
    MOD_NODE    meta_mod_node;

    CBYTES      meta_table_row;

    EC_BOOL     ret;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_create_table_on_root: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    if(EC_FALSE == cbgt_is_root_server(cbgt_md_id))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_create_table_on_root: cbgt module #%ld was not root server\n", cbgt_md_id);
        return (EC_FALSE);
    }

    __cbgt_local_mod_node(cbgt_md_id, &root_mod_node);

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0168);

    if(EC_FALSE == cbgt_reserve_table_id(cbgt_md_id, &meta_table_id))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_create_table_on_root: reserve table id on root table %ld failed\n",
                            CBGT_MD_TABLE_ID(cbgt_md));
        return (EC_FALSE);
    }


    if(EC_FALSE == __cbgt_start_trigger(cbgt_md_id,
                                       CBGT_TYPE_META_SERVER,
                                       meta_table_id,
                                       table_name,
                                       &root_mod_node,
                                       CBGT_MD_ROOT_PATH(cbgt_md),
                                       CBGT_O_CREAT,
                                       &meta_mod_node))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_create_table_on_root: cbgt start meta table %ld failed\n", meta_table_id);
        cbgt_release_table_id(cbgt_md_id, meta_table_id);
        return (EC_FALSE);
    }

    /*write meta table info into root table*/
    cbytes_init(&meta_table_row);
    cbytes_mount(&meta_table_row , cbytes_len(table_name), cbytes_buf(table_name));
    if(EC_FALSE == cbgt_insert_register(cbgt_md_id, &meta_table_row, meta_table_id, &meta_mod_node))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_create_table_on_root: insert register of meta table %ld into root table %ld failed\n",
                           meta_table_id, CBGT_MD_TABLE_ID(cbgt_md));
        cbgt_release_table_id(cbgt_md_id, meta_table_id);
        return (EC_FALSE);
    }

    /*create colf tables on meta server*/
    ret = EC_FALSE;
    task_super_mono(CBGT_MD_MOD_MGR(cbgt_md), TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                     &meta_mod_node,
                     &ret, FI_cbgt_create_table_on_meta, CMPI_ERROR_MODI, col_family_name_vec);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_create_table_on_root: create colf tables of user table %.*s on meta table %ld (tcid %s, comm %ld, rank %ld, modi %ld) failed\n",
                            (uint32_t)cbytes_len(table_name), (char *)cbytes_buf(table_name),
                            meta_table_id,
                            MOD_NODE_TCID_STR(&meta_mod_node), MOD_NODE_COMM(&meta_mod_node), MOD_NODE_RANK(&meta_mod_node), MOD_NODE_MODI(&meta_mod_node));
        cbgt_release_table_id(cbgt_md_id, meta_table_id);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cbgt_create_table_on_meta(const UINT32 cbgt_md_id, const CVECTOR *col_family_name_vec)
{
    CBGT_MD    *cbgt_md;
    UINT32      pos;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_create_table_on_meta: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    if(EC_FALSE == cbgt_is_meta_server(cbgt_md_id))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_create_table_on_meta: cbgt module #%ld was not meta server\n", cbgt_md_id);
        return (EC_FALSE);
    }

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0169);

    for(pos = 0; pos < cvector_size(col_family_name_vec); pos ++)
    {
        CBYTES  *colf_name;

        colf_name = (CBYTES *)cvector_get_no_lock(col_family_name_vec, pos);
        if(NULL_PTR == colf_name)
        {
            continue;
        }

        if(EC_FALSE == cbgt_create_colf_on_meta(cbgt_md_id, colf_name))
        {
            dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_create_table_on_meta: cbgt create colf table %.*s failed\n",
                                (uint32_t)cbytes_len(colf_name), cbytes_buf(colf_name));
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

EC_BOOL cbgt_create_colf_on_meta(const UINT32 cbgt_md_id, const CBYTES  *colf_name)
{
    CBGT_MD    *cbgt_md;

    MOD_NODE    meta_mod_node;
    MOD_NODE    colf_mod_node;

    CBYTES      colf_table_row;
    UINT32      colf_table_id;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_create_colf_on_meta: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    if(EC_FALSE == cbgt_is_meta_server(cbgt_md_id))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_create_colf_on_meta: cbgt module #%ld was not meta server\n", cbgt_md_id);
        return (EC_FALSE);
    }

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0170);

    __cbgt_local_mod_node(cbgt_md_id, &meta_mod_node);

    if(EC_FALSE == cbgt_reserve_table_id(cbgt_md_id, &colf_table_id))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_create_colf_on_meta: reserve table id on meta table %ld failed\n",
                            CBGT_MD_TABLE_ID(cbgt_md));
        return (EC_FALSE);
    }

    if(EC_FALSE == __cbgt_start_trigger(cbgt_md_id,
                                       CBGT_TYPE_COLF_SERVER,
                                       colf_table_id,
                                       colf_name,
                                       &meta_mod_node,
                                       CBGT_MD_ROOT_PATH(cbgt_md),
                                       CBGT_O_CREAT,
                                       &colf_mod_node))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_create_colf_on_meta: cbgt start colf table %ld failed\n", colf_table_id);
        cbgt_release_table_id(cbgt_md_id, colf_table_id);
        return (EC_FALSE);
    }

    /*write colf table info into meta table*/
    cbytes_init(&colf_table_row);
    cbytes_mount(&colf_table_row , cbytes_len(colf_name), cbytes_buf(colf_name));
    if(EC_FALSE == cbgt_insert_register(cbgt_md_id, &colf_table_row, colf_table_id, &colf_mod_node))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_create_colf_on_meta: insert register of colf table %ld into meta table %ld failed\n",
                           colf_table_id, CBGT_MD_TABLE_ID(cbgt_md));

        cbgt_release_table_id(cbgt_md_id, colf_table_id);
        __cbgt_end_trigger(cbgt_md_id, &colf_mod_node);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/*use row of col table as the user table name*/
EC_BOOL cbgt_create_table_on_colf(const UINT32 cbgt_md_id, const CBYTES *colf_row)
{
    CBGT_MD    *cbgt_md;

    MOD_NODE    colf_mod_node;

    UINT32      user_table_id;

    MOD_NODE    user_mod_node;


#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_create_table_on_colf: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    if(EC_FALSE == cbgt_is_colf_server(cbgt_md_id))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_create_table_on_colf: cbgt module #%ld was not colf server\n", cbgt_md_id);
        return (EC_FALSE);
    }

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0171);

    __cbgt_local_mod_node(cbgt_md_id, &colf_mod_node);

    if(EC_FALSE == cbgt_reserve_table_id(cbgt_md_id, &user_table_id))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_create_table_on_colf: reserve table id on colf table %ld failed\n",
                            CBGT_MD_TABLE_ID(cbgt_md));
        return (EC_FALSE);
    }

    if(EC_FALSE == __cbgt_start_trigger(cbgt_md_id,
                          CBGT_TYPE_USER_SERVER,
                          user_table_id,
                          colf_row,
                          &colf_mod_node,
                          CBGT_MD_ROOT_PATH(cbgt_md),
                          CBGT_O_CREAT,
                          &user_mod_node))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_create_table_on_colf: cbgt start user table %ld failed\n", user_table_id);
        cbgt_release_table_id(cbgt_md_id, user_table_id);
        return (EC_FALSE);
    }

    /*register user table info to col table*/
    if(EC_FALSE == cbgt_insert_register(cbgt_md_id, colf_row, user_table_id, &user_mod_node))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_create_table_on_colf: insert the new user table %ld into colf table %ld failed\n",
                            user_table_id, CBGT_MD_TABLE_ID(cbgt_md));

        cbgt_release_table_id(cbgt_md_id, user_table_id);
        __cbgt_end_trigger(cbgt_md_id, &user_mod_node);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cbgt_get_table_and_key_no_lock(const UINT32 cbgt_md_id, const CBYTES *table_key, UINT32 *table_id, MOD_NODE *mod_node, CBYTES *key_bytes)
{
    CBGT_MD    *cbgt_md;

    CBTREE_KEY *cbtree_key;

    const uint8_t *key;
    const uint8_t *_kv;
    const uint8_t *_key;
    const uint8_t *value;
    uint32_t vlen;

    uint32_t counter;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:__cbgt_get_table_and_key_no_lock: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0172);

    cbtree_key = cbgt_gdb_search_key(CBGT_MD_GDB(cbgt_md), cbytes_buf(table_key));
    if(NULL_PTR == cbtree_key)
    {
        return (EC_FALSE);
    }

    key = CBTREE_KEY_LATEST(cbtree_key);
    _kv  = key;
    _key = _kv;

    value = kvGetValueHs(_kv);
    vlen  = kvGetvLenHs(_kv);
    cbytes_set(key_bytes, _key, keyGettLenHs(_key));

    counter = 0;
    CBGT_ASSERT(counter + sizeof(word_t) <= vlen);
    (*table_id) = gdbGetWord(value, &counter);
    CBGT_ASSERT(counter + sizeof(word_t) <= vlen);
    MOD_NODE_TCID(mod_node) = gdbGetWord(value, &counter);
    CBGT_ASSERT(counter + sizeof(word_t) <= vlen);
    MOD_NODE_COMM(mod_node) = gdbGetWord(value, &counter);
    CBGT_ASSERT(counter + sizeof(word_t) <= vlen);
    MOD_NODE_RANK(mod_node) = gdbGetWord(value, &counter);
    CBGT_ASSERT(counter + sizeof(word_t) <= vlen);
    MOD_NODE_MODI(mod_node) = gdbGetWord(value, &counter);
#if 0
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] __cbgt_get_table_and_key_no_lock: tabel %ld (tcid %s, comm %ld, rank %ld, modi %ld)\n",
                       (*table_id), MOD_NODE_TCID_STR(mod_node), MOD_NODE_COMM(mod_node), MOD_NODE_RANK(mod_node), MOD_NODE_MODI(mod_node));
#endif
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cbgt_get_table(const UINT32 cbgt_md_id, const CBYTES *table_name, UINT32 *table_id, MOD_NODE *mod_node)
{
    CBGT_MD    *cbgt_md;

    CBYTES      key;
    CBTREE_KEY *cbtree_key;

    const uint8_t *kv;
    const uint8_t *value;
    uint32_t vlen;

    uint32_t counter;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:__cbgt_get_table: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0173);

    if(EC_FALSE == __cbgt_make_rmc_table_key(cbgt_md_id, table_name, &key))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_get_table: make rowkey failed\n");
        return (EC_FALSE);
    }

    CBGT_ASSERT(cbytes_len(&key));
    CBGT_ASSERT(cbytes_buf(&key));

    CBGT_MD_CRWLOCK_TABLE_RDLOCK(cbgt_md, LOC_CBGT_0174);
    cbtree_key = cbgt_gdb_search_key(CBGT_MD_GDB(cbgt_md), cbytes_buf(&key));
    if(NULL_PTR == cbtree_key)
    {
        CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0175);

        cbgt_key_clean(cbgt_md_id, &key);
        return (EC_FALSE);
    }
    cbgt_key_clean(cbgt_md_id, &key);

    kv = CBTREE_KEY_LATEST(cbtree_key);

    value = kvGetValueHs(kv);
    vlen  = kvGetvLenHs(kv);
    CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0176);

    counter = 0;
    CBGT_ASSERT(counter + sizeof(word_t) <= vlen);
    (*table_id) = gdbGetWord(value, &counter);
    CBGT_ASSERT(counter + sizeof(word_t) <= vlen);
    MOD_NODE_TCID(mod_node) = gdbGetWord(value, &counter);
    CBGT_ASSERT(counter + sizeof(word_t) <= vlen);
    MOD_NODE_COMM(mod_node) = gdbGetWord(value, &counter);
    CBGT_ASSERT(counter + sizeof(word_t) <= vlen);
    MOD_NODE_RANK(mod_node) = gdbGetWord(value, &counter);
    CBGT_ASSERT(counter + sizeof(word_t) <= vlen);
    MOD_NODE_MODI(mod_node) = gdbGetWord(value, &counter);
#if 0
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] __cbgt_get_table: tabel %ld (tcid %s, comm %ld, rank %ld, modi %ld)\n",
                       (*table_id), MOD_NODE_TCID_STR(mod_node), MOD_NODE_COMM(mod_node), MOD_NODE_RANK(mod_node), MOD_NODE_MODI(mod_node));
#endif
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cbgt_get_rmc_table_and_key_no_lock(const UINT32 cbgt_md_id, const CBYTES *table_name, UINT32 *table_id, MOD_NODE *mod_node, CBYTES *key_bytes)
{
    CBGT_MD    *cbgt_md;
    CBYTES      rmc_rowkey;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:__cbgt_get_rmc_table_and_key_no_lock: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0177);

    if(do_log(SEC_0054_CBGT, 9))
    {
        dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] __cbgt_get_rmc_table_and_key_no_lock: table name: ");
        __cbgt_print_row(cbgt_md_id, table_name, LOGSTDOUT);
    }

    cbytes_init(&rmc_rowkey);
    if(EC_FALSE == __cbgt_make_rmc_table_key(cbgt_md_id, table_name, &rmc_rowkey))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_get_rmc_table_and_key_no_lock: make rowkey failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == __cbgt_get_table_and_key_no_lock(cbgt_md_id, &rmc_rowkey, table_id, mod_node, key_bytes))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_get_rmc_table_and_key_no_lock: search table %.*s on table %ld type %s failed\n",
                            (uint32_t)cbytes_len(table_name), (char *)cbytes_buf(table_name),
                            CBGT_MD_TABLE_ID(cbgt_md), __cbgt_type(CBGT_MD_TYPE(cbgt_md)));
        cbytes_clean(&rmc_rowkey);
        return (EC_FALSE);
    }
    cbytes_clean(&rmc_rowkey);
#if 0
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] __cbgt_get_rmc_table_and_key_no_lock: tabel %ld (tcid %s, comm %ld, rank %ld, modi %ld)\n",
                       (*table_id), MOD_NODE_TCID_STR(mod_node), MOD_NODE_COMM(mod_node), MOD_NODE_RANK(mod_node), MOD_NODE_MODI(mod_node));
#endif
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cbgt_get_rmc_table(const UINT32 cbgt_md_id, const CBYTES *table_name, UINT32 *table_id, MOD_NODE *mod_node)
{
    CBGT_MD    *cbgt_md;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:__cbgt_get_rmc_table: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0178);
#if 0
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] __cbgt_get_rmc_table: table name: ");
    __cbgt_print_row(cbgt_md_id, table_name, LOGSTDOUT);
#endif
    if(EC_FALSE == __cbgt_get_table(cbgt_md_id, table_name, table_id, mod_node))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_get_rmc_table: search table %.*s on table %ld type %s failed\n",
                            (uint32_t)cbytes_len(table_name), (char *)cbytes_buf(table_name),
                            CBGT_MD_TABLE_ID(cbgt_md), __cbgt_type(CBGT_MD_TYPE(cbgt_md)));
        return (EC_FALSE);
    }
#if 0
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] __cbgt_get_rmc_table: tabel %ld (tcid %s, comm %ld, rank %ld, modi %ld)\n",
                       (*table_id), MOD_NODE_TCID_STR(mod_node), MOD_NODE_COMM(mod_node), MOD_NODE_RANK(mod_node), MOD_NODE_MODI(mod_node));
#endif
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cbgt_get_user_table_and_key_no_lock(const UINT32 cbgt_md_id, const CBYTES *user_table_key, UINT32 *table_id, MOD_NODE *mod_node, CBYTES *key_bytes)
{
    CBGT_MD    *cbgt_md;
    CBYTES      col_rowkey;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:__cbgt_get_user_table_and_key_no_lock: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0179);
#if 0
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] __cbgt_get_user_table_and_key_no_lock: enter: CBGT Module # %ld: table %ld type %s\n",
                        cbgt_md_id, CBGT_MD_TABLE_ID(cbgt_md), __cbgt_type(CBGT_MD_TYPE(cbgt_md)));

    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] __cbgt_get_user_table_and_key_no_lock: enter: as user rowkey: ");
    __cbgt_print_user_table_key(LOGSTDOUT, cbytes_buf(user_table_key));
    sys_print(LOGSTDOUT, "\n");
#endif

    cbytes_init(&col_rowkey);
    if(EC_FALSE == __cbgt_make_colf_table_key_by_user_table_key(cbgt_md_id, user_table_key, &col_rowkey))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_get_user_table_and_key_no_lock: make col_rowkey failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == __cbgt_get_table_and_key_no_lock(cbgt_md_id, &col_rowkey, table_id, mod_node, key_bytes))
    {
#if 0
        dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] __cbgt_get_user_table_and_key_no_lock: as user rowkey: ");
        __cbgt_print_user_table_key(LOGSTDOUT, cbytes_buf(user_table_key));
        sys_print(LOGSTDOUT, "\n");
#endif
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_get_user_table_and_key_no_lock: search user table on table %ld type %s failed\n",
                            CBGT_MD_TABLE_ID(cbgt_md), __cbgt_type(CBGT_MD_TYPE(cbgt_md)));
        cbytes_clean(&col_rowkey);
        return (EC_FALSE);
    }
    cbytes_clean(&col_rowkey);
#if 0
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] __cbgt_get_user_table_and_key_no_lock: tabel %ld (tcid %s, comm %ld, rank %ld, modi %ld)\n",
                       (*table_id), MOD_NODE_TCID_STR(mod_node), MOD_NODE_COMM(mod_node), MOD_NODE_RANK(mod_node), MOD_NODE_MODI(mod_node));
#endif
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cbgt_get_user_table(const UINT32 cbgt_md_id, const CBYTES *user_rowkey, UINT32 *table_id, MOD_NODE *mod_node)
{
    CBGT_MD    *cbgt_md;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:__cbgt_get_user_table: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0180);
#if 0
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] __cbgt_get_user_table: enter: CBGT Module # %ld: table %ld type %s\n",
                        cbgt_md_id, CBGT_MD_TABLE_ID(cbgt_md), __cbgt_type(CBGT_MD_TYPE(cbgt_md)));

    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] __cbgt_get_user_table: enter: as user rowkey: ");
    __cbgt_print_user_table_key(LOGSTDOUT, cbytes_buf(user_rowkey));
    sys_print(LOGSTDOUT, "\n");
#endif
    if(EC_FALSE == __cbgt_get_table(cbgt_md_id, user_rowkey, table_id, mod_node))
    {
#if 0
        dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] __cbgt_get_user_table: as user rowkey: ");
        __cbgt_print_user_table_key(LOGSTDOUT, cbytes_buf(user_rowkey));
        sys_print(LOGSTDOUT, "\n");
#endif
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_get_user_table: search user table on table %ld type %s failed\n",
                            CBGT_MD_TABLE_ID(cbgt_md), __cbgt_type(CBGT_MD_TYPE(cbgt_md)));
        return (EC_FALSE);
    }
#if 0
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] __cbgt_get_user_table: tabel %ld (tcid %s, comm %ld, rank %ld, modi %ld)\n",
                       (*table_id), MOD_NODE_TCID_STR(mod_node), MOD_NODE_COMM(mod_node), MOD_NODE_RANK(mod_node), MOD_NODE_MODI(mod_node));
#endif
    return (EC_TRUE);
}

EC_BOOL cbgt_get_colf_table_from_root(const UINT32 cbgt_md_id, const CBYTES *table_name, const CBYTES *colf, UINT32 *table_id, MOD_NODE *mod_node)
{
    CBGT_MD    *cbgt_md;
    MOD_NODE   *parent;

    UINT32      meta_table_id;
    MOD_NODE    meta_mod_node;

    EC_BOOL     ret;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_get_colf_table_from_root: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    parent  = CBGT_MD_PARENT_MOD(cbgt_md);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0181);

#if 0
    if(EC_FALSE == cbgt_is_root_server(cbgt_md_id))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_get_colf_table_from_root: cur table %ld is not root\n",
                            CBGT_MD_TABLE_ID(cbgt_md));
        return (EC_FALSE);
    }
#endif
#if 1
    if(EC_FALSE == cbgt_is_root_server(cbgt_md_id))
    {
        MOD_NODE *root_mod_node;

        root_mod_node = CBGT_MD_ROOT_MOD(cbgt_md);

        ret = EC_FALSE;
        task_p2p(cbgt_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                 root_mod_node,
                 &ret,FI_cbgt_get_colf_table_from_root, CMPI_ERROR_MODI, table_name, colf, table_id, mod_node);
        if(EC_FALSE == ret)
        {
            dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_get_colf_table_from_root: get colf table of user table %.*s colf %.*s from root (tcid %s, comm %ld, rank %ld, modi %ld) failed\n",
                                (uint32_t)cbytes_len(table_name), (char *)cbytes_buf(table_name),
                                (uint32_t)cbytes_len(colf), (char *)cbytes_buf(colf),
                                MOD_NODE_TCID_STR(root_mod_node), MOD_NODE_COMM(root_mod_node), MOD_NODE_RANK(root_mod_node), MOD_NODE_MODI(root_mod_node));
            return (EC_FALSE);
        }
        return (EC_TRUE);
    }
#endif

    /*get meta table*/
    if(EC_FALSE == __cbgt_get_rmc_table(cbgt_md_id, table_name, &meta_table_id, &meta_mod_node))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_get_colf_table_from_root: get meta table of user table %.*s from root table %ld failed\n",
                            (uint32_t)cbytes_len(table_name), (char *)cbytes_buf(table_name), CBGT_MD_TABLE_ID(cbgt_md));
        return (EC_FALSE);
    }

    if(EC_FALSE == __cbgt_mod_node_is_valid(cbgt_md_id, &meta_mod_node))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_get_colf_table_from_root: meta table %ld of user table %.*s was not registered to root table %ld\n",
                            meta_table_id, (uint32_t)cbytes_len(table_name), (char *)cbytes_buf(table_name), CBGT_MD_TABLE_ID(cbgt_md));
        return (EC_FALSE);
    }

    ret = EC_FALSE;
    task_p2p(cbgt_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &meta_mod_node,
             &ret, FI_cbgt_get_colf_table_from_meta, CMPI_ERROR_MODI, colf, table_id, mod_node);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_get_colf_table_from_root: get colf table of user table %.*s from meta table %ld on root table %ld failed\n",
                            (uint32_t)cbytes_len(table_name), (char *)cbytes_buf(table_name), meta_table_id, CBGT_MD_TABLE_ID(cbgt_md));
        return (EC_FALSE);
    }
#if 0
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_get_colf_table_from_root: get colf table {table id %ld, (tcid %s, comm %ld, rank %ld, modi %ld)} "
                       "of user table %.*s from meta table %ld on root table %ld successfully\n",
                        (*table_id), MOD_NODE_TCID_STR(mod_node), MOD_NODE_COMM(mod_node), MOD_NODE_RANK(mod_node), MOD_NODE_MODI(mod_node),
                        (uint32_t)cbytes_len(table_name), (char *)cbytes_buf(table_name), meta_table_id, CBGT_MD_TABLE_ID(cbgt_md));
#endif
    return (EC_TRUE);

}

EC_BOOL cbgt_get_colf_table_from_meta(const UINT32 cbgt_md_id, const CBYTES *colf, UINT32 *table_id, MOD_NODE *mod_node)
{
    CBGT_MD    *cbgt_md;
    MOD_NODE   *parent;

    UINT32      colf_table_id;
    MOD_NODE    meta_mod_node;
    MOD_NODE    colf_mod_node;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_get_colf_table_from_meta: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    parent  = CBGT_MD_PARENT_MOD(cbgt_md);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0182);

    if(EC_FALSE == cbgt_is_meta_server(cbgt_md_id))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_get_colf_table_from_meta: cur table %ld is not meta\n",
                            CBGT_MD_TABLE_ID(cbgt_md));
        return (EC_FALSE);
    }

    __cbgt_local_mod_node(cbgt_md_id, &meta_mod_node);

    /*get colf table*/
    if(EC_FALSE == __cbgt_get_rmc_table(cbgt_md_id, colf, &colf_table_id, &colf_mod_node))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_get_colf_table_from_meta: get colf table %.*s from meta table %ld failed\n",
                            (uint32_t)cbytes_len(colf), (char *)cbytes_buf(colf), CBGT_MD_TABLE_ID(cbgt_md));
        return (EC_FALSE);
    }

    if(EC_FALSE == __cbgt_mod_node_is_valid(cbgt_md_id, &colf_mod_node))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_get_colf_table_from_meta: colf table %ld of colf %.*s was not registered to meta table %ld\n",
                            colf_table_id, (uint32_t)cbytes_len(colf), (char *)cbytes_buf(colf), CBGT_MD_TABLE_ID(cbgt_md));
        return (EC_FALSE);
    }

    (*table_id) = colf_table_id;
    mod_node_clone(&colf_mod_node, mod_node);
#if 0
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_get_colf_table_from_meta: get colf table {table id %ld, (tcid %s, comm %ld, rank %ld, modi %ld)} "
                       "of colf %.*s on meta table %ld successfully\n",
                        (*table_id), MOD_NODE_TCID_STR(mod_node), MOD_NODE_COMM(mod_node), MOD_NODE_RANK(mod_node), MOD_NODE_MODI(mod_node),
                        (uint32_t)cbytes_len(colf), (char *)cbytes_buf(colf), CBGT_MD_TABLE_ID(cbgt_md));
#endif
    return (EC_TRUE);

}

EC_BOOL cbgt_get_user_table_from_root(const UINT32 cbgt_md_id, const CBYTES *table_name, const CBYTES *row, const CBYTES *colf, const CBYTES *colq, UINT32 *table_id, MOD_NODE *mod_node)
{
    CBGT_MD    *cbgt_md;
    MOD_NODE   *parent;

    UINT32      meta_table_id;
    MOD_NODE    meta_mod_node;

    EC_BOOL     ret;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_get_user_table_from_root: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    parent  = CBGT_MD_PARENT_MOD(cbgt_md);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0183);
#if 0
    if(EC_FALSE == cbgt_is_root_server(cbgt_md_id))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_get_user_table_from_root: cur table %ld is not root\n",
                            CBGT_MD_TABLE_ID(cbgt_md));
        return (EC_FALSE);
    }
#endif
#if 1
    if(EC_FALSE == cbgt_is_root_server(cbgt_md_id))
    {
        MOD_NODE *root_mod_node;

        root_mod_node = CBGT_MD_ROOT_MOD(cbgt_md);

        ret = EC_FALSE;
        task_p2p(cbgt_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                 root_mod_node,
                 &ret,FI_cbgt_get_user_table_from_root, CMPI_ERROR_MODI, table_name, row, colf, colq, table_id, mod_node);
        if(EC_FALSE == ret)
        {
            dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_get_user_table_from_root: get user table of table %.*s (%.*s:%.*s:%.*s) from root (tcid %s, comm %ld, rank %ld, modi %ld) failed\n",
                                (uint32_t)cbytes_len(table_name), (char *)cbytes_buf(table_name),
                                (uint32_t)cbytes_len(row) , (char *)cbytes_buf(row),
                                (uint32_t)cbytes_len(colf), (char *)cbytes_buf(colf),
                                (uint32_t)cbytes_len(colq), (char *)cbytes_buf(colq),
                                MOD_NODE_TCID_STR(root_mod_node), MOD_NODE_COMM(root_mod_node), MOD_NODE_RANK(root_mod_node), MOD_NODE_MODI(root_mod_node));
            return (EC_FALSE);
        }
        return (EC_TRUE);
    }
#endif

    /*get meta table*/
    if(EC_FALSE == __cbgt_get_rmc_table(cbgt_md_id, table_name, &meta_table_id, &meta_mod_node))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_get_user_table_from_root: get meta table of user table %.*s from root table %ld failed\n",
                            (uint32_t)cbytes_len(table_name), (char *)cbytes_buf(table_name), CBGT_MD_TABLE_ID(cbgt_md));
        return (EC_FALSE);
    }

    if(EC_FALSE == __cbgt_mod_node_is_valid(cbgt_md_id, &meta_mod_node))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_get_user_table_from_root: meta table %ld of user table %.*s was not registered to root table %ld\n",
                            meta_table_id, (uint32_t)cbytes_len(table_name), (char *)cbytes_buf(table_name), CBGT_MD_TABLE_ID(cbgt_md));
        return (EC_FALSE);
    }

    ret = EC_FALSE;
    task_p2p(cbgt_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &meta_mod_node,
             &ret, FI_cbgt_get_user_table_from_meta, CMPI_ERROR_MODI, row, colf, colq, table_id, mod_node);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_get_user_table_from_root: get user table of table %.*s (%.*s:%.*s:%.*s) from meta table %ld on root table %ld failed\n",
                            (uint32_t)cbytes_len(table_name), (char *)cbytes_buf(table_name),
                            (uint32_t)cbytes_len(row) , (char *)cbytes_buf(row),
                            (uint32_t)cbytes_len(colf), (char *)cbytes_buf(colf),
                            (uint32_t)cbytes_len(colq), (char *)cbytes_buf(colq),
                            meta_table_id, CBGT_MD_TABLE_ID(cbgt_md));
        return (EC_FALSE);
    }
#if 0
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_get_user_table_from_root: get user table {table id %ld, (tcid %s, comm %ld, rank %ld, modi %ld)} "
                       "of table %.*s (%.*s:%.*s:%.*s) from meta table %ld on root table %ld successfully\n",
                        (*table_id), MOD_NODE_TCID_STR(mod_node), MOD_NODE_COMM(mod_node), MOD_NODE_RANK(mod_node), MOD_NODE_MODI(mod_node),
                        (uint32_t)cbytes_len(table_name), (char *)cbytes_buf(table_name),
                        (uint32_t)cbytes_len(row) , (char *)cbytes_buf(row),
                        (uint32_t)cbytes_len(colf), (char *)cbytes_buf(colf),
                        (uint32_t)cbytes_len(colq), (char *)cbytes_buf(colq),
                        meta_table_id, CBGT_MD_TABLE_ID(cbgt_md));
#endif
    return (EC_TRUE);

}

EC_BOOL cbgt_get_user_table_from_meta(const UINT32 cbgt_md_id, const CBYTES *row, const CBYTES *colf, const CBYTES *colq, UINT32 *table_id, MOD_NODE *mod_node)
{
    CBGT_MD    *cbgt_md;
    MOD_NODE   *parent;

    UINT32      colf_table_id;
    MOD_NODE    colf_mod_node;

    EC_BOOL     ret;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_get_user_table_from_meta: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    parent  = CBGT_MD_PARENT_MOD(cbgt_md);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0184);

    if(EC_FALSE == cbgt_is_meta_server(cbgt_md_id))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_get_user_table_from_meta: cur table %ld is not meta\n",
                            CBGT_MD_TABLE_ID(cbgt_md));
        return (EC_FALSE);
    }

    /*get colf table*/
    if(EC_FALSE == __cbgt_get_rmc_table(cbgt_md_id, colf, &colf_table_id, &colf_mod_node))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_get_user_table_from_meta: get colf table of %.*s from meta table %ld failed\n",
                            (uint32_t)cbytes_len(colf), (char *)cbytes_buf(colf), CBGT_MD_TABLE_ID(cbgt_md));
        return (EC_FALSE);
    }

    if(EC_FALSE == __cbgt_mod_node_is_valid(cbgt_md_id, &colf_mod_node))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_get_user_table_from_meta: colf table %ld of %.*s was not registered to meta table %ld\n",
                            colf_table_id, (uint32_t)cbytes_len(colf), (char *)cbytes_buf(colf), CBGT_MD_TABLE_ID(cbgt_md));
        return (EC_FALSE);
    }

    ret = EC_FALSE;
    task_p2p(cbgt_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &colf_mod_node,
             &ret, FI_cbgt_get_user_table_from_colf, CMPI_ERROR_MODI, row, colf, colq, table_id, mod_node);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_get_user_table_from_meta: get user table for (%.*s:%.*s:%.*s) from colf table %ld on meta table %ld failed\n",
                            (uint32_t)cbytes_len(row) , (char *)cbytes_buf(row),
                            (uint32_t)cbytes_len(colf), (char *)cbytes_buf(colf),
                            (uint32_t)cbytes_len(colq), (char *)cbytes_buf(colq),
                            colf_table_id,
                            CBGT_MD_TABLE_ID(cbgt_md));
        return (EC_FALSE);
    }
#if 0
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_get_user_table_from_meta: get user table {table id %ld, (tcid %s, comm %ld, rank %ld, modi %ld)} "
                       "for (%.*s:%.*s:%.*s) from colf table %ld on meta table %ld successfully\n",
                        (*table_id), MOD_NODE_TCID_STR(mod_node), MOD_NODE_COMM(mod_node), MOD_NODE_RANK(mod_node), MOD_NODE_MODI(mod_node),
                        (uint32_t)cbytes_len(row) , (char *)cbytes_buf(row),
                        (uint32_t)cbytes_len(colf), (char *)cbytes_buf(colf),
                        (uint32_t)cbytes_len(colq), (char *)cbytes_buf(colq),
                        colf_table_id,
                        CBGT_MD_TABLE_ID(cbgt_md));
#endif
    return (EC_TRUE);

}

EC_BOOL cbgt_get_user_table_from_colf(const UINT32 cbgt_md_id, const CBYTES *row, const CBYTES *colf, const CBYTES *colq, UINT32 *table_id, MOD_NODE *mod_node)
{
    CBGT_MD    *cbgt_md;
    MOD_NODE   *parent;

    UINT32      user_table_id;
    MOD_NODE    user_mod_node;

    CBYTES      user_rowkey;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_get_user_table_from_colf: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    parent  = CBGT_MD_PARENT_MOD(cbgt_md);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0185);

    if(EC_FALSE == cbgt_is_colf_server(cbgt_md_id))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_get_user_table_from_colf: cur table %ld is not colf\n",
                            CBGT_MD_TABLE_ID(cbgt_md));
        return (EC_FALSE);
    }

    cbytes_init(&user_rowkey);

    if(EC_FALSE == __cbgt_make_user_table_key(cbgt_md_id, row, colf, colq, &user_rowkey))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_get_user_table_from_colf: make rowkey of (%.*s:%.*s:%.*s) on col table %ld failed\n",
                            (uint32_t)cbytes_len(row) , (char *)cbytes_buf(row),
                            (uint32_t)cbytes_len(colf), (char *)cbytes_buf(colf),
                            (uint32_t)cbytes_len(colq), (char *)cbytes_buf(colq),
                            CBGT_MD_TABLE_ID(cbgt_md));
        return (EC_FALSE);
    }

    /*get user table*/
    if(EC_FALSE == __cbgt_get_user_table(cbgt_md_id, &user_rowkey, &user_table_id, &user_mod_node))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_get_user_table_from_colf: get user table of (%.*s:%.*s:%.*s) from colf table %ld failed\n",
                            (uint32_t)cbytes_len(row) , (char *)cbytes_buf(row),
                            (uint32_t)cbytes_len(colf), (char *)cbytes_buf(colf),
                            (uint32_t)cbytes_len(colq), (char *)cbytes_buf(colq),
                            CBGT_MD_TABLE_ID(cbgt_md));

        cbgt_key_clean(cbgt_md_id, &user_rowkey);
        return (EC_FALSE);
    }

    cbgt_key_clean(cbgt_md_id, &user_rowkey);

    if(EC_FALSE == __cbgt_mod_node_is_valid(cbgt_md_id, &user_mod_node))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_get_user_table_from_colf: user table %ld of (%.*s:%.*s:%.*s) was not registered to colf table %ld\n",
                            user_table_id,
                            (uint32_t)cbytes_len(row) , (char *)cbytes_buf(row),
                            (uint32_t)cbytes_len(colf), (char *)cbytes_buf(colf),
                            (uint32_t)cbytes_len(colq), (char *)cbytes_buf(colq),
                            CBGT_MD_TABLE_ID(cbgt_md));
        return (EC_FALSE);
    }

    (*table_id) = user_table_id;
    mod_node_clone(&user_mod_node, mod_node);
#if 0
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_get_user_table_from_colf: get user table {table id %ld, (tcid %s, comm %ld, rank %ld, modi %ld)} "
                       "of (%.*s:%.*s:%.*s) on colf table %ld successfully\n",
                        (*table_id), MOD_NODE_TCID_STR(mod_node), MOD_NODE_COMM(mod_node), MOD_NODE_RANK(mod_node), MOD_NODE_MODI(mod_node),
                        (uint32_t)cbytes_len(row) , (char *)cbytes_buf(row),
                        (uint32_t)cbytes_len(colf), (char *)cbytes_buf(colf),
                        (uint32_t)cbytes_len(colq), (char *)cbytes_buf(colq),
                        CBGT_MD_TABLE_ID(cbgt_md));
#endif
    return (EC_TRUE);

}

STATIC_CAST static EC_BOOL __cbgt_open_rmc_table(const UINT32 cbgt_md_id, const UINT32 server_type, const CBYTES *table_name, UINT32 *table_id, MOD_NODE *mod_node)
{
    CBGT_MD  *cbgt_md;

    UINT32    son_table_id;
    MOD_NODE  son_mod_node;

    CBYTES    key_bytes;

    CSTRING meta_session_path;
    CSTRING   colf_session_path;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:__cbgt_open_rmc_table: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0186);

    if(EC_FALSE == cbgt_is_root_server(cbgt_md_id)
    && EC_FALSE == cbgt_is_meta_server(cbgt_md_id)
    //&& EC_FALSE == cbgt_is_colf_server(cbgt_md_id)
    )
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_open_rmc_table: table %ld type %s is not root or meta table\n",
                            CBGT_MD_TABLE_ID(cbgt_md), __cbgt_type(CBGT_MD_TYPE(cbgt_md)));
        return (EC_FALSE);
    }

    cstring_init(&meta_session_path, NULL_PTR);
    cstring_init(&colf_session_path, NULL_PTR);

    /*lookup meta table in session*/
    if(CBGT_TYPE_META_SERVER == server_type)
    {
        if(EC_TRUE == __cbgt_get_meta_table_from_session(cbgt_md_id, table_name, &meta_session_path, table_id, mod_node)
        && EC_TRUE == CBGT_CHECK_TABLE_EXIST(cbgt_md_id, (*table_id), mod_node))
        {
            cstring_clean(&meta_session_path);
            return (EC_TRUE);
        }
    }

    /*lookup colf table in session*/
    if(CBGT_TYPE_COLF_SERVER == server_type)
    {
        if(EC_TRUE == __cbgt_get_colf_table_from_session(cbgt_md_id, table_name/*unknow user table name*/, table_name, &colf_session_path, table_id, mod_node)
        && EC_TRUE == CBGT_CHECK_TABLE_EXIST(cbgt_md_id, (*table_id), mod_node))
        {
            cstring_clean(&meta_session_path);
            cstring_clean(&colf_session_path);
            return (EC_TRUE);
        }
    }

    cbytes_init(&key_bytes);

    CBGT_MD_CRWLOCK_TABLE_WRLOCK(cbgt_md, LOC_CBGT_0187);
    if(EC_FALSE == __cbgt_get_rmc_table_and_key_no_lock(cbgt_md_id, table_name, &son_table_id, &son_mod_node, &key_bytes))
    {
        CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0188);
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_open_rmc_table: get son table %.*s from cur table %ld failed\n",
                            (uint32_t)cbytes_len(table_name), (char *)cbytes_buf(table_name),
                            CBGT_MD_TABLE_ID(cbgt_md));
        cstring_clean(&meta_session_path);
        cstring_clean(&colf_session_path);
        return (EC_FALSE);
    }
#if 0
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] __cbgt_open_rmc_table: get son table table %.*s type %s from cur table %ld type %s "
                       "==> table %ld (tcid %s, comm %ld, rank %ld, modi %ld)\n",
                       (uint32_t)cbytes_len(table_name), (char *)cbytes_buf(table_name), __cbgt_type(server_type),
                       CBGT_MD_TABLE_ID(cbgt_md), __cbgt_type(CBGT_MD_TYPE(cbgt_md)),
                       son_table_id,
                       MOD_NODE_TCID_STR(&son_mod_node), MOD_NODE_COMM(&son_mod_node), MOD_NODE_RANK(&son_mod_node), MOD_NODE_MODI(&son_mod_node)
                       );
#endif
    if(EC_FALSE == CBGT_CHECK_TABLE_EXIST(cbgt_md_id, son_table_id, &son_mod_node))
    {
        MOD_NODE  cur_mod_node;
#if 0
        dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] __cbgt_open_rmc_table: son_mod_node is invalid, try to start %s on table %ld type %s\n",
                            __cbgt_type(server_type), CBGT_MD_TABLE_ID(cbgt_md), __cbgt_type(CBGT_MD_TYPE(cbgt_md)));
#endif
        __cbgt_local_mod_node(cbgt_md_id, &cur_mod_node);

        if(EC_FALSE == __cbgt_start_trigger(cbgt_md_id,
                                              server_type,
                                              son_table_id,
                                              table_name,
                                              &cur_mod_node,
                                              CBGT_MD_ROOT_PATH(cbgt_md),
                                              CBGT_O_RDWR,
                                              &son_mod_node))
        {
            CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0189);
            dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_open_rmc_table: open table %ld type %s on table %ld type %s failed\n",
                                son_table_id, __cbgt_type(server_type),
                                CBGT_MD_TABLE_ID(cbgt_md), __cbgt_type(CBGT_MD_TYPE(cbgt_md)));
            cbytes_clean(&key_bytes);
            cstring_clean(&meta_session_path);
            cstring_clean(&colf_session_path);
            return (EC_FALSE);
        }

        if(EC_FALSE == __cbgt_mod_node_is_valid(cbgt_md_id, &son_mod_node))
        {
            CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0190);
            dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_open_rmc_table: open son table %.*s from cur table %ld failed\n",
                                (uint32_t)cbytes_len(table_name), (char *)cbytes_buf(table_name),
                                CBGT_MD_TABLE_ID(cbgt_md));
            cbytes_clean(&key_bytes);
            cstring_clean(&meta_session_path);
            cstring_clean(&colf_session_path);
            return (EC_FALSE);
        }

#if 0
        if(CBGT_TYPE_COLF_SERVER == server_type)
        {
            EC_BOOL __ret;
            dbg_log(SEC_0054_CBGT, 5)(LOGSTDOUT, "__cbgt_open_rmc_table: before update, colf is ##################################\n");
            task_p2p(cbgt_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                     &son_mod_node,
                     &__ret, FI_cbgt_traversal, CMPI_ERROR_MODI, LOGSTDOUT);
         }
#endif

        /*update register info of son table*/
        if(EC_FALSE == cbgt_update_register_no_lock(cbgt_md_id, &key_bytes, son_table_id, &son_mod_node))
        {
            CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0191);
            dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_open_rmc_table: update register of table %.*s id %ld type %s (tcid %s, comm %ld, rank %ld, modi %ld) "
                                "to table %ld type %s failed\n",
                               (uint32_t)cbytes_len(table_name), (char *)cbytes_buf(table_name),
                               son_table_id, __cbgt_type(server_type),
                               MOD_NODE_TCID_STR(&son_mod_node), MOD_NODE_COMM(&son_mod_node), MOD_NODE_RANK(&son_mod_node), MOD_NODE_MODI(&son_mod_node),
                               CBGT_MD_TABLE_ID(cbgt_md), __cbgt_type(CBGT_MD_TYPE(cbgt_md)));
            cbytes_clean(&key_bytes);
            cstring_clean(&meta_session_path);
            cstring_clean(&colf_session_path);
            return (EC_FALSE);
        }

#if 0
        if(CBGT_TYPE_COLF_SERVER == server_type)
        {
            EC_BOOL __ret;
            dbg_log(SEC_0054_CBGT, 5)(LOGSTDOUT, "__cbgt_open_rmc_table: after update, colf is ##################################\n");
            task_p2p(cbgt_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                     &son_mod_node,
                     &__ret, FI_cbgt_traversal, CMPI_ERROR_MODI, LOGSTDOUT);
         }
#endif
    }
    CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0192);
    cbytes_clean(&key_bytes);

    (*table_id) = son_table_id;
    mod_node_clone(&son_mod_node, mod_node);

    if(CBGT_TYPE_META_SERVER == server_type)
    {
        __cbgt_set_meta_table_to_session(cbgt_md_id, &meta_session_path, (*table_id), mod_node);
    }

    if(CBGT_TYPE_COLF_SERVER == server_type)
    {
        __cbgt_set_colf_table_to_session(cbgt_md_id, &colf_session_path, (*table_id), mod_node);
    }
#if 0
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] __cbgt_open_rmc_table: table %ld (tcid %s, comm %ld, rank %ld, modi %ld)\n",
                       son_table_id,
                       MOD_NODE_TCID_STR(mod_node), MOD_NODE_COMM(mod_node), MOD_NODE_RANK(mod_node), MOD_NODE_MODI(mod_node));
#endif
    cstring_clean(&meta_session_path);
    cstring_clean(&colf_session_path);
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cbgt_open_user_table(const UINT32 cbgt_md_id, const CBYTES *user_table_key, CBYTES *user_table_name, UINT32 *table_id, MOD_NODE *mod_node)
{
    CBGT_MD  *cbgt_md;

    UINT32    user_table_id;
    MOD_NODE  user_mod_node;

    CBYTES    key_bytes;


#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:__cbgt_open_user_table: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/
#if 0
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] __cbgt_open_user_table: table name: ");
    __cbgt_print_user_table_key(LOGSTDOUT, cbytes_buf(user_table_key));
    sys_print(LOGSTDOUT, "\n");
#endif
    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0193);

    if(EC_FALSE == cbgt_is_colf_server(cbgt_md_id))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_open_user_table: table %ld type %s is not colf table\n",
                            CBGT_MD_TABLE_ID(cbgt_md), __cbgt_type(CBGT_MD_TYPE(cbgt_md)));
        return (EC_FALSE);
    }

    cbytes_init(&key_bytes);

    CBGT_MD_CRWLOCK_TABLE_WRLOCK(cbgt_md, LOC_CBGT_0194);
    if(EC_FALSE == __cbgt_get_user_table_and_key_no_lock(cbgt_md_id, user_table_key, &user_table_id, &user_mod_node, &key_bytes))
    {
        CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0195);
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_open_user_table: get user table %.*s from col table %ld failed\n",
                            (uint32_t)cbytes_len(user_table_key), (char *)cbytes_buf(user_table_key),
                            CBGT_MD_TABLE_ID(cbgt_md));
        return (EC_FALSE);
    }
#if 0
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] __cbgt_open_user_table: get user table from col table %ld "
                       "==> table %ld (tcid %s, comm %ld, rank %ld, modi %ld)\n",
                       CBGT_MD_TABLE_ID(cbgt_md),
                       user_table_id,
                       MOD_NODE_TCID_STR(&user_mod_node), MOD_NODE_COMM(&user_mod_node), MOD_NODE_RANK(&user_mod_node), MOD_NODE_MODI(&user_mod_node)
                       );
#endif

    if(EC_FALSE == cbgt_fetch_row_no_lock(cbgt_md_id, &key_bytes, user_table_name))
    {
        CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0196);
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_open_user_table: fetch colf row key for table %.*s from colf table %ld failed\n",
                            (uint32_t)cbytes_len(user_table_key), (char *)cbytes_buf(user_table_key),
                            CBGT_MD_TABLE_ID(cbgt_md));
        cbytes_clean(&key_bytes);
        return (EC_FALSE);
    }

    //dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] __cbgt_open_user_table: user_table_name buf %p, len %ld\n", cbytes_buf(user_table_name), cbytes_len(user_table_name));

    if(EC_FALSE == CBGT_CHECK_TABLE_EXIST(cbgt_md_id, user_table_id, &user_mod_node))
    {
        MOD_NODE   colf_mod_node;

#if 0
        dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] __cbgt_open_user_table: user_mod_node is invalid, try to start user table on col table %ld\n",
                            CBGT_MD_TABLE_ID(cbgt_md), __cbgt_type(CBGT_MD_TYPE(cbgt_md)));
#endif

        __cbgt_local_mod_node(cbgt_md_id, &colf_mod_node);

        if(EC_FALSE == __cbgt_start_trigger(cbgt_md_id,
                                              CBGT_TYPE_USER_SERVER,
                                              user_table_id,
                                              user_table_name,/*user table name is the row of colf key*/
                                              &colf_mod_node,
                                              CBGT_MD_ROOT_PATH(cbgt_md),
                                              CBGT_O_RDWR,
                                              &user_mod_node))
        {
            CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0197);
            dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_open_user_table: open user table %ld on colf table %ld failed\n",
                                user_table_id, CBGT_MD_TABLE_ID(cbgt_md));
            cbytes_clean(&key_bytes);
            return (EC_FALSE);
        }

        if(EC_FALSE == __cbgt_mod_node_is_valid(cbgt_md_id, &user_mod_node))
        {
            CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0198);
            dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_open_user_table: open user table %.*s from colf table %ld failed\n",
                                (uint32_t)cbytes_len(user_table_key), (char *)cbytes_buf(user_table_key),
                                CBGT_MD_TABLE_ID(cbgt_md));
            cbytes_clean(&key_bytes);
            return (EC_FALSE);
        }

        /*update register info of user table*/
        if(EC_FALSE == cbgt_update_register_no_lock(cbgt_md_id, &key_bytes, user_table_id, &user_mod_node))
        {
            CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0199);
            dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_open_user_table: register user table %ld (tcid %s, comm %ld, rank %ld, modi %ld) "
                                "to colf table %ld failed\n",
                               user_table_id,
                               MOD_NODE_TCID_STR(&user_mod_node), MOD_NODE_COMM(&user_mod_node), MOD_NODE_RANK(&user_mod_node), MOD_NODE_MODI(&user_mod_node),
                               CBGT_MD_TABLE_ID(cbgt_md));
            cbytes_clean(&key_bytes);
            return (EC_FALSE);
        }
    }
    CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0200);
    cbytes_clean(&key_bytes);

    (*table_id) = user_table_id;
    mod_node_clone(&user_mod_node, mod_node);
#if 0
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] __cbgt_open_user_table: table %ld (tcid %s, comm %ld, rank %ld, modi %ld)\n",
                       user_table_id,
                       MOD_NODE_TCID_STR(mod_node), MOD_NODE_COMM(mod_node), MOD_NODE_RANK(mod_node), MOD_NODE_MODI(mod_node));
#endif
    return (EC_TRUE);
}

EC_BOOL cbgt_open_colf_table_from_root(const UINT32 cbgt_md_id, const CBYTES *table_name, const CBYTES *colf, UINT32 *table_id, MOD_NODE *mod_node)
{
    CBGT_MD   *cbgt_md;
    UINT32    meta_table_id;

    MOD_NODE  meta_mod_node;
    CSTRING   colf_session_path;

    EC_BOOL   ret;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_open_colf_table_from_root: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0201);
#if 0
    if(EC_FALSE == cbgt_is_root_server(cbgt_md_id))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_open_colf_table_from_root: table %ld is not root table\n",
                            CBGT_MD_TABLE_ID(cbgt_md));
        return (EC_FALSE);
    }
#endif

     /*lookup user table + colf table in session*/
     cstring_init(&colf_session_path, NULL_PTR);
     if(EC_TRUE == __cbgt_get_colf_table_from_session(cbgt_md_id, table_name, colf, &colf_session_path, table_id, mod_node))
     {
        cstring_clean(&colf_session_path);
        return (EC_TRUE);
     }


#if 1
    if(EC_FALSE == cbgt_is_root_server(cbgt_md_id))
    {
        MOD_NODE *root_mod_node;

        root_mod_node = CBGT_MD_ROOT_MOD(cbgt_md);

        ret = EC_FALSE;
        task_p2p(cbgt_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                 root_mod_node,
                 &ret,FI_cbgt_open_colf_table_from_root, CMPI_ERROR_MODI, table_name, colf, table_id, mod_node);
        if(EC_FALSE == ret)
        {
            dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_open_colf_table_from_root: open colf table of user table %.*s colf %.*s from root (tcid %s, comm %ld, rank %ld, modi %ld) failed\n",
                                (uint32_t)cbytes_len(table_name), (char *)cbytes_buf(table_name),
                                (uint32_t)cbytes_len(colf), (char *)cbytes_buf(colf),
                                MOD_NODE_TCID_STR(root_mod_node), MOD_NODE_COMM(root_mod_node), MOD_NODE_RANK(root_mod_node), MOD_NODE_MODI(root_mod_node));
            cstring_clean(&colf_session_path);
            return (EC_FALSE);
        }
        __cbgt_set_colf_table_to_session(cbgt_md_id, &colf_session_path, (*table_id), mod_node);
        cstring_clean(&colf_session_path);
        return (EC_TRUE);
    }
#endif

    if(EC_FALSE == __cbgt_open_rmc_table(cbgt_md_id, CBGT_TYPE_META_SERVER, table_name, &meta_table_id, &meta_mod_node))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_open_colf_table_from_root: open meta table of user table %.*s on root table %ld failed\n",
                            (uint32_t)cbytes_len(table_name), (char *)cbytes_buf(table_name),
                            CBGT_MD_TABLE_ID(cbgt_md));
        cstring_clean(&colf_session_path);
        return (EC_FALSE);
    }

    ret = EC_FALSE;
    task_p2p(cbgt_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &meta_mod_node,
             &ret, FI_cbgt_open_colf_table_from_meta, CMPI_ERROR_MODI, colf, table_id, mod_node);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_open_colf_table_from_root: open colf table %.*s of user table %.*s from meta table %ld on root table %ld failed\n",
                            (uint32_t)cbytes_len(colf), (char *)cbytes_buf(colf),
                            (uint32_t)cbytes_len(table_name), (char *)cbytes_buf(table_name),
                            meta_table_id, CBGT_MD_TABLE_ID(cbgt_md));
        cstring_clean(&colf_session_path);
        return (EC_FALSE);
    }

    __cbgt_set_colf_table_to_session(cbgt_md_id, &colf_session_path, (*table_id), mod_node);
#if 0
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_open_colf_table_from_root: open colf table {table id %ld, (tcid %s, comm %ld, rank %ld, modi %ld)} "
                       "of user table %.*s from meta table %ld on root table %ld successfully\n",
                        (*table_id), MOD_NODE_TCID_STR(mod_node), MOD_NODE_COMM(mod_node), MOD_NODE_RANK(mod_node), MOD_NODE_MODI(mod_node),
                        (uint32_t)cbytes_len(table_name), (char *)cbytes_buf(table_name), meta_table_id, CBGT_MD_TABLE_ID(cbgt_md));
#endif
    cstring_clean(&colf_session_path);
    return (EC_TRUE);
}

EC_BOOL cbgt_open_colf_table_from_meta(const UINT32 cbgt_md_id, const CBYTES *colf, UINT32 *table_id, MOD_NODE *mod_node)
{
    CBGT_MD   *cbgt_md;
    UINT32    colf_table_id;
    MOD_NODE  colf_mod_node;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_open_colf_table_from_meta: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0202);

    if(EC_FALSE == cbgt_is_meta_server(cbgt_md_id))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_open_colf_table_from_meta: table %ld is not meta table\n",
                            CBGT_MD_TABLE_ID(cbgt_md));
        return (EC_FALSE);
    }

    if(EC_FALSE == __cbgt_open_rmc_table(cbgt_md_id, CBGT_TYPE_COLF_SERVER, colf, &colf_table_id, &colf_mod_node))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_open_colf_table_from_meta: open colf table %.*s on meta table %ld failed\n",
                            (uint32_t)cbytes_len(colf), (char *)cbytes_buf(colf),
                            CBGT_MD_TABLE_ID(cbgt_md));
        return (EC_FALSE);
    }

    (*table_id) = colf_table_id;
    mod_node_clone(&colf_mod_node, mod_node);
#if 0
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_open_colf_table_from_meta: open colf table {table id %ld, (tcid %s, comm %ld, rank %ld, modi %ld)} "
                       "of colf %.*s on meta table %ld successfully\n",
                        (*table_id), MOD_NODE_TCID_STR(mod_node), MOD_NODE_COMM(mod_node), MOD_NODE_RANK(mod_node), MOD_NODE_MODI(mod_node),
                        (uint32_t)cbytes_len(colf), (char *)cbytes_buf(colf), CBGT_MD_TABLE_ID(cbgt_md));
#endif
    return (EC_TRUE);
}

EC_BOOL cbgt_open_user_table_from_root(const UINT32 cbgt_md_id, const CBYTES *table_name, const CBYTES * row, const CBYTES *colf, const CBYTES * colq, CBYTES *user_table_name, UINT32 *table_id, MOD_NODE *mod_node)
{
    CBGT_MD  *cbgt_md;
    UINT32    meta_table_id;
    MOD_NODE  meta_mod_node;

    EC_BOOL   ret;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_open_user_table_from_root: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0203);

#if 0
    if(EC_FALSE == cbgt_is_root_server(cbgt_md_id))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_open_user_table_from_root: table %ld is not root table\n",
                            CBGT_MD_TABLE_ID(cbgt_md));
        return (EC_FALSE);
    }
#endif

#if 1
    if(EC_FALSE == cbgt_is_root_server(cbgt_md_id))
    {
        MOD_NODE *root_mod_node;

        root_mod_node = CBGT_MD_ROOT_MOD(cbgt_md);

        ret = EC_FALSE;
        task_p2p(cbgt_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                 root_mod_node,
                 &ret,FI_cbgt_open_user_table_from_root, CMPI_ERROR_MODI, table_name, row, colf, colq, user_table_name, table_id, mod_node);
        if(EC_FALSE == ret)
        {
            dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_open_user_table_from_root: open user table of (%.*s:%.*s:%.*s) from root failed\n",
                                (uint32_t)cbytes_len(row) , (char *)cbytes_buf(row),
                                (uint32_t)cbytes_len(colf), (char *)cbytes_buf(colf),
                                (uint32_t)cbytes_len(colq), (char *)cbytes_buf(colq));
            return (EC_FALSE);
        }
        return (EC_TRUE);
    }
#endif

    if(EC_FALSE == __cbgt_open_rmc_table(cbgt_md_id, CBGT_TYPE_META_SERVER, table_name, &meta_table_id, &meta_mod_node))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_open_user_table_from_root: open meta table of user table %.*s on root table %ld failed\n",
                            (uint32_t)cbytes_len(table_name), (char *)cbytes_buf(table_name),
                            CBGT_MD_TABLE_ID(cbgt_md));
        return (EC_FALSE);
    }

    ret = EC_FALSE;
    task_p2p(cbgt_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &meta_mod_node,
             &ret, FI_cbgt_open_user_table_from_meta, CMPI_ERROR_MODI, row, colf, colq, user_table_name, table_id, mod_node);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_open_user_table_from_root: open user table of (%.*s:%.*s:%.*s) from meta table %ld on root table %ld failed\n",
                            (uint32_t)cbytes_len(row) , (char *)cbytes_buf(row),
                            (uint32_t)cbytes_len(colf), (char *)cbytes_buf(colf),
                            (uint32_t)cbytes_len(colq), (char *)cbytes_buf(colq),
                            meta_table_id,
                            CBGT_MD_TABLE_ID(cbgt_md));
        return (EC_FALSE);
    }
#if 0
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_open_user_table_from_root: open user table %.*s {table id %ld, (tcid %s, comm %ld, rank %ld, modi %ld)} "
                       "for (%.*s:%.*s:%.*s) from meta table %ld on root table %ld successfully\n",
                        cbytes_len(table_name), (char *)cbytes_buf(table_name),
                        (*table_id),
                        MOD_NODE_TCID_STR(mod_node), MOD_NODE_COMM(mod_node), MOD_NODE_RANK(mod_node), MOD_NODE_MODI(mod_node),
                        (uint32_t)cbytes_len(row) , (char *)cbytes_buf(row),
                        (uint32_t)cbytes_len(colf), (char *)cbytes_buf(colf),
                        (uint32_t)cbytes_len(colq), (char *)cbytes_buf(colq),
                        meta_table_id,
                        CBGT_MD_TABLE_ID(cbgt_md));
#endif
    return (EC_TRUE);
}

EC_BOOL cbgt_open_user_table_from_meta(const UINT32 cbgt_md_id, const CBYTES * row, const CBYTES *colf, const CBYTES * colq, CBYTES *user_table_name, UINT32 *table_id, MOD_NODE *mod_node)
{
    CBGT_MD  *cbgt_md;
    UINT32    colf_table_id;
    MOD_NODE  colf_mod_node;

    EC_BOOL   ret;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_open_colf_table_from_meta: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/
#if 0
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_open_user_table_from_meta: row : %.*s\n", cbytes_len(row), (char *)cbytes_buf(row));
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_open_user_table_from_meta: colf: %.*s\n", cbytes_len(colf), (char *)cbytes_buf(colf));
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_open_user_table_from_meta: colq: %.*s\n", cbytes_len(colq), (char *)cbytes_buf(colq));
#endif
    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0204);

    if(EC_FALSE == cbgt_is_meta_server(cbgt_md_id))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_open_colf_table_from_meta: table %ld is not meta table\n",
                            CBGT_MD_TABLE_ID(cbgt_md));
        return (EC_FALSE);
    }

    if(EC_FALSE == __cbgt_open_rmc_table(cbgt_md_id, CBGT_TYPE_COLF_SERVER, colf, &colf_table_id, &colf_mod_node))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_open_colf_table_from_meta: open colf table %.*s on meta table %ld failed\n",
                            (uint32_t)cbytes_len(colf), (char *)cbytes_buf(colf),
                            CBGT_MD_TABLE_ID(cbgt_md));
        return (EC_FALSE);
    }

#if 0
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_open_colf_table_from_meta: open colf table {table id %ld, (tcid %s, comm %ld, rank %ld, modi %ld)} "
                       "for colf %.*s on meta table %ld successfully\n",
                        colf_table_id,
                        MOD_NODE_TCID_STR(&colf_mod_node), MOD_NODE_COMM(&colf_mod_node), MOD_NODE_RANK(&colf_mod_node), MOD_NODE_MODI(&colf_mod_node),
                        cbytes_len(colf), (char *)cbytes_buf(colf),
                        CBGT_MD_TABLE_ID(cbgt_md));
#endif

#if 0
    dbg_log(SEC_0054_CBGT, 5)(LOGSTDOUT, "##########################################################################################\n");
    task_p2p(cbgt_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &colf_mod_node,
             &ret, FI_cbgt_traversal, CMPI_ERROR_MODI, LOGSTDOUT);
#endif

    ret = EC_FALSE;
    task_p2p(cbgt_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &colf_mod_node,
             &ret, FI_cbgt_open_user_table_from_colf, CMPI_ERROR_MODI, row, colf, colq, user_table_name, table_id, mod_node);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_open_colf_table_from_meta: open user table of (%.*s:%.*s:%.*s) from colf table %ld on meta table %ld failed\n",
                            (uint32_t)cbytes_len(row) , (char *)cbytes_buf(row),
                            (uint32_t)cbytes_len(colf), (char *)cbytes_buf(colf),
                            (uint32_t)cbytes_len(colq), (char *)cbytes_buf(colq),
                            colf_table_id,
                            CBGT_MD_TABLE_ID(cbgt_md));
        return (EC_FALSE);
    }
#if 0
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_open_colf_table_from_meta: open user table {table id %ld, (tcid %s, comm %ld, rank %ld, modi %ld)} "
                       "for (%.*s:%.*s:%.*s) from colf table %ld on meta table %ld successfully\n",
                        (*table_id),
                        MOD_NODE_TCID_STR(mod_node), MOD_NODE_COMM(mod_node), MOD_NODE_RANK(mod_node), MOD_NODE_MODI(mod_node),
                        (uint32_t)cbytes_len(row) , (char *)cbytes_buf(row),
                        (uint32_t)cbytes_len(colf), (char *)cbytes_buf(colf),
                        (uint32_t)cbytes_len(colq), (char *)cbytes_buf(colq),
                        colf_table_id,
                        CBGT_MD_TABLE_ID(cbgt_md));
#endif
    return (EC_TRUE);
}

EC_BOOL cbgt_open_user_table_from_colf(const UINT32 cbgt_md_id, const CBYTES * row, const CBYTES *colf, const CBYTES * colq, CBYTES *user_table_name, UINT32 *table_id, MOD_NODE *mod_node)
{
    CBGT_MD  *cbgt_md;

    CBYTES    user_table_key;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_open_user_table_from_colf: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/
#if 0
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_open_user_table_from_colf: row  : %.*s\n", cbytes_len(row), (char *)cbytes_buf(row));
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_open_user_table_from_colf: colf : %.*s\n", cbytes_len(colf), (char *)cbytes_buf(colf));
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_open_user_table_from_colf: colq : %.*s\n", cbytes_len(colq), (char *)cbytes_buf(colq));
#endif
    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0205);

    if(EC_FALSE == cbgt_is_colf_server(cbgt_md_id))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_open_user_table_from_colf: table %ld is not colf table\n",
                            CBGT_MD_TABLE_ID(cbgt_md));
        return (EC_FALSE);
    }

    if(EC_FALSE == __cbgt_make_user_table_key(cbgt_md_id, row, colf, colq, &user_table_key))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_open_user_table_from_colf: make rowkey of (%.*s:%.*s:%.*s) on colf table %ld failed\n",
                            (uint32_t)cbytes_len(row) , (char *)cbytes_buf(row),
                            (uint32_t)cbytes_len(colf), (char *)cbytes_buf(colf),
                            (uint32_t)cbytes_len(colq), (char *)cbytes_buf(colq),
                            CBGT_MD_TABLE_ID(cbgt_md));
        return (EC_FALSE);
    }

    if(EC_FALSE == __cbgt_open_user_table(cbgt_md_id, &user_table_key, user_table_name, table_id, mod_node))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_open_user_table_from_colf: open user table of (%.*s:%.*s:%.*s) on colf table %ld failed\n",
                            (uint32_t)cbytes_len(row) , (char *)cbytes_buf(row),
                            (uint32_t)cbytes_len(colf), (char *)cbytes_buf(colf),
                            (uint32_t)cbytes_len(colq), (char *)cbytes_buf(colq),
                            CBGT_MD_TABLE_ID(cbgt_md));
        cbgt_key_clean(cbgt_md_id, &user_table_key);
        return (EC_FALSE);
    }
    cbgt_key_clean(cbgt_md_id, &user_table_key);
#if 0
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_open_user_table_from_colf: user_table_name buf %p, len %ld\n", cbytes_buf(user_table_name), cbytes_len(user_table_name));

    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_open_user_table_from_colf: open user table {table id %ld, (tcid %s, comm %ld, rank %ld, modi %ld)} "
                       "for (%.*s:%.*s:%.*s) on colf table %ld successfully\n",
                        (*table_id), MOD_NODE_TCID_STR(mod_node), MOD_NODE_COMM(mod_node), MOD_NODE_RANK(mod_node), MOD_NODE_MODI(mod_node),
                        (uint32_t)cbytes_len(row) , (char *)cbytes_buf(row),
                        (uint32_t)cbytes_len(colf), (char *)cbytes_buf(colf),
                        (uint32_t)cbytes_len(colq), (char *)cbytes_buf(colq),
                        CBGT_MD_TABLE_ID(cbgt_md));
#endif
    return (EC_TRUE);
}

/*set mod_node of (table_id, table_name) to invalid which table is one son of current table*/
EC_BOOL cbgt_close_rmc_table(const UINT32 cbgt_md_id, const CBYTES *table_name, const UINT32 table_id)
{
    CBGT_MD   *cbgt_md;
    MOD_NODE   table_mod_node;

    UINT32     _table_id;
    CBYTES     key_bytes;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_close_rmc_table: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0206);

    if(EC_FALSE == cbgt_is_root_server(cbgt_md_id)
    && EC_FALSE == cbgt_is_meta_server(cbgt_md_id)
    //&& EC_FALSE == cbgt_is_colf_server(cbgt_md_id)
    )
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_close_rmc_table: table %ld (type %s) is not root/meta table\n",
                            CBGT_MD_TABLE_ID(cbgt_md), __cbgt_type(CBGT_MD_TYPE(cbgt_md)));
        return (EC_FALSE);
    }

    cbytes_init(&key_bytes);

    CBGT_MD_CRWLOCK_TABLE_WRLOCK(cbgt_md, LOC_CBGT_0207);
    if(EC_FALSE == __cbgt_get_rmc_table_and_key_no_lock(cbgt_md_id, table_name, &_table_id, &table_mod_node, &key_bytes))
    {
        CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0208);
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_close_rmc_table: get table %ld failed from table %ld\n",
                            table_id, CBGT_MD_TABLE_ID(cbgt_md));
        return (EC_FALSE);
    }

    if(table_id != _table_id)
    {
        CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0209);
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_close_rmc_table: inconsistent fetched table id %ld and expected table id %ld where table name is %.*s\n",
                            _table_id, table_id, (uint32_t)cbytes_len(table_name), cbytes_buf(table_name));
        return (EC_FALSE);
    }

    if(EC_FALSE == cbgt_mess_register_no_lock(cbgt_md_id, &key_bytes, table_id))
    {
        CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0210);
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_close_rmc_table: mess register of table {table id %ld, (tcid %s, comm %ld, rank %ld, modi %ld)} failed\n",
                            table_id,
                            MOD_NODE_TCID_STR(&table_mod_node), MOD_NODE_COMM(&table_mod_node), MOD_NODE_RANK(&table_mod_node), MOD_NODE_MODI(&table_mod_node));
        cbytes_clean(&key_bytes);
        return (EC_FALSE);
    }
    cbytes_clean(&key_bytes);

    mod_mgr_excl(MOD_NODE_TCID(&table_mod_node),
                 MOD_NODE_COMM(&table_mod_node),
                 MOD_NODE_RANK(&table_mod_node),
                 MOD_NODE_MODI(&table_mod_node),
                 CBGT_MD_MOD_MGR(cbgt_md));
    CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0211);
    return (EC_TRUE);
}

EC_BOOL cbgt_close_user_table(const UINT32 cbgt_md_id, const CBYTES *table_name, const UINT32 table_id)
{
    CBGT_MD   *cbgt_md;
    MOD_NODE   table_mod_node;
    CBYTES     colf_table_key;

    UINT32     _table_id;
    CBYTES     key_bytes;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_close_user_table: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0212);

    if( EC_FALSE == cbgt_is_colf_server(cbgt_md_id))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_close_user_table: table %ld (type %s) is not colf table\n",
                            CBGT_MD_TABLE_ID(cbgt_md), __cbgt_type(CBGT_MD_TYPE(cbgt_md)));
        return (EC_FALSE);
    }

#if 0
        if(1)
        {
            dbg_log(SEC_0054_CBGT, 5)(LOGSTDOUT, "cbgt_close_user_table: before close, colf table %ld is ##################################\n", CBGT_MD_TABLE_ID(cbgt_md));
            cbgt_traversal(cbgt_md_id, LOGSTDOUT);

            __cbgt_print_colf_table_key(LOGSTDOUT, cbytes_buf(table_name));
            sys_print(LOGSTDOUT, "\n");
        }
#endif

    if(EC_FALSE == __cbgt_make_rmc_table_key(cbgt_md_id, table_name, &colf_table_key))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_close_user_table: make colf table key failed\n");
        return (EC_FALSE);
    }

    cbytes_init(&key_bytes);

    CBGT_MD_CRWLOCK_TABLE_WRLOCK(cbgt_md, LOC_CBGT_0213);
    if(EC_FALSE == __cbgt_get_table_and_key_no_lock(cbgt_md_id, &colf_table_key, &_table_id, &table_mod_node, &key_bytes))
    {
        CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0214);
        cbytes_clean(&colf_table_key);
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_close_user_table: get table %ld failed from table %ld\n",
                            table_id, CBGT_MD_TABLE_ID(cbgt_md));
        return (EC_FALSE);
    }
    cbytes_clean(&colf_table_key);

#if 0
        if(1)
        {
            dbg_log(SEC_0054_CBGT, 5)(LOGSTDOUT, "cbgt_close_user_table: after get user table info, colf is ##################################\n");
            cbgt_traversal_no_lock(cbgt_md_id, LOGSTDOUT);
        }
#endif

    if(table_id != _table_id)
    {
        CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0215);
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_close_user_table: inconsisent fetched table id %ld and expected table id %ld where table name is ",
                            _table_id, table_id);
        __cbgt_print_colf_table_key(LOGSTDOUT, cbytes_buf(table_name));
        sys_print(LOGSTDOUT, "\n");
        cbytes_clean(&key_bytes);
        return (EC_FALSE);
    }

#if 0
        if(1)
        {
            dbg_log(SEC_0054_CBGT, 5)(LOGSTDOUT, "cbgt_close_user_table: before mess, colf is ##################################\n");
            cbgt_traversal_no_lock(cbgt_md_id, LOGSTDOUT);
        }
#endif

    if(EC_FALSE == cbgt_mess_register_no_lock(cbgt_md_id, &key_bytes, table_id))
    {
        CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0216);
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_close_user_table: mess register of table {table id %ld, (tcid %s, comm %ld, rank %ld, modi %ld)} failed\n",
                            table_id,
                            MOD_NODE_TCID_STR(&table_mod_node), MOD_NODE_COMM(&table_mod_node), MOD_NODE_RANK(&table_mod_node), MOD_NODE_MODI(&table_mod_node));
        cbytes_clean(&key_bytes);
        return (EC_FALSE);
    }
    cbytes_clean(&key_bytes);

    mod_mgr_excl(MOD_NODE_TCID(&table_mod_node),
                 MOD_NODE_COMM(&table_mod_node),
                 MOD_NODE_RANK(&table_mod_node),
                 MOD_NODE_MODI(&table_mod_node),
                 CBGT_MD_MOD_MGR(cbgt_md));
    CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0217);

#if 0
        if(1)
        {
            dbg_log(SEC_0054_CBGT, 5)(LOGSTDOUT, "cbgt_close_user_table: after close, colf is ##################################\n");
            cbgt_traversal(cbgt_md_id, LOGSTDOUT);
        }
#endif
    return (EC_TRUE);
}

/*report to parent: I am closing!*/
EC_BOOL cbgt_report_closing(const UINT32 cbgt_md_id)
{
    CBGT_MD    *cbgt_md;
    MOD_NODE   *parent;
    CSTRING    *root_path;

    UINT32      table_id;
    CBYTES     *table_name;

    EC_BOOL     ret;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_report_closing: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md    = CBGT_MD_GET(cbgt_md_id);
    parent     = CBGT_MD_PARENT_MOD(cbgt_md);
    root_path  = CBGT_MD_ROOT_PATH(cbgt_md);
    table_id   = CBGT_MD_TABLE_ID(cbgt_md);
    table_name = CBGT_MD_TABLE_NAME(cbgt_md);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0218);

    if(EC_TRUE == cbgt_is_user_client(cbgt_md_id))
    {
        /*nothing to report*/
        return (EC_TRUE);
    }

    if(EC_TRUE == cbgt_is_root_server(cbgt_md_id))
    {
#if 0
        MOD_NODE error_mod_node;
        __cbgt_error_mod_node(cbgt_md_id, &error_mod_node);
        CBGT_MD_CRWLOCK_TABLE_WRLOCK(cbgt_md, LOC_CBGT_0219);
        __cbgt_flush_root_record_file(cbgt_md_id, root_path, table_id, &error_mod_node);
        CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0220);
#endif
        return (EC_TRUE);
    }

    if(NULL_PTR == table_name)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_report_closing: table name is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == parent)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_report_closing: parent of table %ld type %s is null\n",
                            CBGT_MD_TABLE_ID(cbgt_md), __cbgt_type(CBGT_MD_TYPE(cbgt_md)));
        return (EC_FALSE);
    }

    if(EC_TRUE == cbgt_is_meta_server(cbgt_md_id))
    {
        ret = EC_FALSE;
        task_p2p(cbgt_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                parent,
                &ret, FI_cbgt_close_rmc_table, CMPI_ERROR_MODI, table_name, table_id);

        if(EC_FALSE == ret)
        {
            dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_report_closing: report meta table %ld closing to root failed\n", table_id);
            return (EC_FALSE);
        }
        return (EC_TRUE);
    }

    if(EC_TRUE == cbgt_is_colf_server(cbgt_md_id))
    {
        ret = EC_FALSE;
        task_p2p(cbgt_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                parent,
                &ret, FI_cbgt_close_rmc_table, CMPI_ERROR_MODI, table_name, table_id);

        if(EC_FALSE == ret)
        {
            dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_report_closing: report colf table %ld closing to meta failed\n", table_id);
            return (EC_FALSE);
        }
        return (EC_TRUE);
    }

    if(EC_TRUE == cbgt_is_user_server(cbgt_md_id))
    {
#if 0
        uint8_t * start_user_rowkey;
        uint8_t * end_user_rowkey;
        CBYTES    user_rowkey;

        __cbgt_split_colf_row_into_start_end_user_table_key(cbytes_buf(table_name), &start_user_rowkey, &end_user_rowkey);

        /*select the end user rowkey due to range is left-open-right-close: (startUserRowKey, endUserRowKey]*/
        cbytes_init(&user_rowkey);
        cbytes_mount(&user_rowkey, keyGettLenHs(end_user_rowkey), end_user_rowkey);
#endif

#if 1
        dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_report_closing: user server table %ld and table name is ", table_id);
        __cbgt_print_colf_table_row(LOGSTDOUT, cbytes_buf(table_name));
        sys_print(LOGSTDOUT, "\n");
#endif

        ret = EC_FALSE;
        task_p2p(cbgt_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                parent,
                &ret, FI_cbgt_close_user_table, CMPI_ERROR_MODI, table_name, table_id);

        if(EC_FALSE == ret)
        {
            dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_report_closing: report user table %ld closing to colf failed\n", table_id);
            return (EC_FALSE);
        }
        return (EC_TRUE);
    }

    dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_report_closing: table %ld type %ld is invalid\n",
                        CBGT_MD_TABLE_ID(cbgt_md), CBGT_MD_TYPE(cbgt_md));

    return (EC_FALSE);
}

EC_BOOL cbgt_fetch_key_no_lock(const UINT32 cbgt_md_id, const CBYTES *kv_bytes, CBYTES *key_bytes)
{
    CBGT_MD    *cbgt_md;

    uint8_t    *key;
    uint16_t    klen;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_fetch_key_no_lock: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md  = CBGT_MD_GET(cbgt_md_id);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0221);

    key  = cbytes_buf(kv_bytes);
    klen = keyGetkLenHs(key);

    cbytes_set(key_bytes, key, klen);
    return (EC_TRUE);
}

EC_BOOL cbgt_fetch_key(const UINT32 cbgt_md_id, const CBYTES *kv_bytes, CBYTES *key_bytes)
{
    CBGT_MD    *cbgt_md;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_fetch_key: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md  = CBGT_MD_GET(cbgt_md_id);

    //CBGT_MD_CRWLOCK_TABLE_RDLOCK(cbgt_md, LOC_CBGT_0222);
    if(EC_FALSE == cbgt_fetch_key_no_lock(cbgt_md_id, kv_bytes, key_bytes))
    {
        //CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0223);
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_fetch_key: fetch key from table %ld failed\n",
                            CBGT_MD_TABLE_ID(cbgt_md));
        return (EC_FALSE);
    }
    //CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0224);

    return (EC_TRUE);
}

EC_BOOL cbgt_fetch_row_no_lock(const UINT32 cbgt_md_id, const CBYTES *kv_bytes, CBYTES *row_bytes)
{
    CBGT_MD    *cbgt_md;
    uint8_t    *kv;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_fetch_row_no_lock: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md  = CBGT_MD_GET(cbgt_md_id);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0225);

    kv = cbytes_buf(kv_bytes);
    cbytes_set(row_bytes, keyGetRowHs(kv), keyGetrLenHs(kv));
    return (EC_TRUE);
}

EC_BOOL cbgt_fetch_row(const UINT32 cbgt_md_id, const CBYTES *kv_bytes, CBYTES *row_bytes)
{
    CBGT_MD    *cbgt_md;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_fetch_row: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md  = CBGT_MD_GET(cbgt_md_id);

    //CBGT_MD_CRWLOCK_TABLE_RDLOCK(cbgt_md, LOC_CBGT_0226);
    if(EC_FALSE == cbgt_fetch_row_no_lock(cbgt_md_id, kv_bytes, row_bytes))
    {
        //CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0227);
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_fetch_row: fetch key from table %ld failed\n",
                            CBGT_MD_TABLE_ID(cbgt_md));
        return (EC_FALSE);
    }
    //CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0228);
    return (EC_TRUE);
}

EC_BOOL cbgt_fetch_from_rmc_no_lock(const UINT32 cbgt_md_id, const CBYTES *kv_bytes, UINT32 *table_id, MOD_NODE *mod_node)
{
    CBGT_MD    *cbgt_md;

    const uint8_t    *kv;
    const uint8_t    *value;

    uint32_t    counter;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_fetch_from_rmc_no_lock: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md  = CBGT_MD_GET(cbgt_md_id);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0229);

    kv    = cbytes_buf(kv_bytes);
    value = kvGetValueHs(kv);

    counter = 0;
    (*table_id) = gdbGetWord(value, &counter);
    MOD_NODE_TCID(mod_node) = gdbGetWord(value, &counter);
    MOD_NODE_COMM(mod_node) = gdbGetWord(value, &counter);
    MOD_NODE_RANK(mod_node) = gdbGetWord(value, &counter);
    MOD_NODE_MODI(mod_node) = gdbGetWord(value, &counter);

    return (EC_TRUE);
}

EC_BOOL cbgt_fetch_from_rmc(const UINT32 cbgt_md_id, const CBYTES *kv_bytes, UINT32 *table_id, MOD_NODE *mod_node)
{
    CBGT_MD    *cbgt_md;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_fetch_from_rmc: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md  = CBGT_MD_GET(cbgt_md_id);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0230);

    //CBGT_MD_CRWLOCK_TABLE_RDLOCK(cbgt_md, LOC_CBGT_0231);
    if(EC_FALSE == cbgt_fetch_from_rmc_no_lock(cbgt_md_id, kv_bytes, table_id, mod_node))
    {
        //CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0232);
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_fetch_from_rmc: fetch table id and mod node from table %ld failed\n",
                            CBGT_MD_TABLE_ID(cbgt_md));
        return (EC_FALSE);
    }
    //CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0233);

    return (EC_TRUE);
}

EC_BOOL cbgt_insert_rfqv_no_lock(const UINT32 cbgt_md_id, const CBYTES *row, const CBYTES *colf, const CBYTES *colq, const CBYTES *val)
{
    CBGT_MD    *cbgt_md;
    CBGT_GDB   *gdb;

    CBYTES   kv;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_insert_rfqv_no_lock: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0234);

    cbytes_init(&kv);
    if(EC_FALSE == cbgt_kv_init(cbgt_md_id, row, colf, colq, val, &kv))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_insert_rfqv_no_lock: init kv failed\n");
        return (EC_FALSE);
    }

    /*note: GDB of the CBGT module may be splitted and may be replaced with new gdb*/
    /*hence we should obtain gdb only after WRLOCK is done*/
    gdb = CBGT_MD_GDB(cbgt_md);
    /*split happen only ONCE when idx file full or dat file full*/
    if(EC_TRUE == cbgt_gdb_is_full(gdb))
    {
        dbg_log(SEC_0054_CBGT, 5)(LOGSTDOUT, "cbgt_insert_rfqv_no_lock: cbgt %ld, table %ld: data file is full, trigger split\n",
                            cbgt_md_id, CBGT_MD_TABLE_ID(cbgt_md));
        cbgt_split_no_lock(cbgt_md_id);
    }

    gdb = CBGT_MD_GDB(cbgt_md);/*get gdb again due to split may happen before*/
    if(EC_FALSE == cbgt_gdb_insert_key(gdb, cbytes_buf(&kv)))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_insert_rfqv_no_lock: insert kv into gdb %p failed \n", gdb);
        cbgt_kv_clean(cbgt_md_id, &kv);
        return (EC_FALSE);
    }

    cbgt_kv_clean(cbgt_md_id, &kv);
    return (EC_TRUE);
}

EC_BOOL cbgt_insert_rfqv(const UINT32 cbgt_md_id, const CBYTES *row, const CBYTES *colf, const CBYTES *colq, const CBYTES *val)
{
    CBGT_MD  *cbgt_md;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_insert_rfqv: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0235);

    if(EC_TRUE == cbgt_is_user_server(cbgt_md_id))/*working on user table*/
    {
        CBYTES    user_rowkey;

        if(EC_FALSE == __cbgt_make_user_table_key(cbgt_md_id, row, colf, colq, &user_rowkey))
        {
            dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_insert_rfqv: make rowkey of (%.*s:%.*s:%.*s) on colf table %ld failed\n",
                                (uint32_t)cbytes_len(row) , (char *)cbytes_buf(row),
                                (uint32_t)cbytes_len(colf), (char *)cbytes_buf(colf),
                                (uint32_t)cbytes_len(colq), (char *)cbytes_buf(colq),
                                CBGT_MD_TABLE_ID(cbgt_md));
            return (EC_FALSE);
        }

        CBGT_MD_CRWLOCK_TABLE_WRLOCK(cbgt_md, LOC_CBGT_0236);
        /*confirm the insertion kv inserting into the right user table because the user table covering range will change if split happened*/
        if(EC_FALSE == __cbgt_cmp_colf_row_and_user_table_key(cbytes_buf(CBGT_MD_TABLE_NAME(cbgt_md)), cbytes_buf(&user_rowkey)))
        {
            CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0237);

            dbg_log(SEC_0054_CBGT, 1)(LOGSTDOUT, "warn:cbgt_insert_rfqv: user key ");
            __cbgt_print_user_table_key(LOGSTDOUT, cbytes_buf(&user_rowkey));
            sys_print(LOGSTDOUT, " not belong to user table ");
            __cbgt_print_colf_table_row(LOGSTDOUT, cbytes_buf(CBGT_MD_TABLE_NAME(cbgt_md)));
            sys_print(LOGSTDOUT, "\n");
            cbytes_clean(&user_rowkey);
            return (EC_OBSCURE);/*ask caller to try again*/
        }
        cbytes_clean(&user_rowkey);

        if(EC_FALSE == cbgt_insert_rfqv_no_lock(cbgt_md_id, row, colf, colq, val))
        {
            CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0238);
            return (EC_FALSE);
        }
        CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0239);

        return (EC_TRUE);
    }

    /*working on non-user table*/
    CBGT_MD_CRWLOCK_TABLE_WRLOCK(cbgt_md, LOC_CBGT_0240);
    if(EC_FALSE == cbgt_insert_rfqv_no_lock(cbgt_md_id, row, colf, colq, val))
    {
        CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0241);
        return (EC_FALSE);
    }
    CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0242);
    return (EC_TRUE);
}

EC_BOOL cbgt_update_value_no_lock(const UINT32 cbgt_md_id, const CBYTES *key, CBYTES *val)
{
    CBGT_MD    *cbgt_md;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_update_value_no_lock: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0243);

    if(EC_FALSE == cbgt_gdb_update_val(CBGT_MD_GDB(cbgt_md), cbytes_buf(key), cbytes_buf(val), (uint32_t)cbytes_len(val)))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_update_value_no_lock: update value of table %ld failed\n",
                            CBGT_MD_TABLE_ID(cbgt_md));
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL cbgt_update_value(const UINT32 cbgt_md_id, const CBYTES *key, CBYTES *val)
{
    CBGT_MD    *cbgt_md;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_update_value: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);

    CBGT_MD_CRWLOCK_TABLE_WRLOCK(cbgt_md, LOC_CBGT_0244);
    if(EC_FALSE == cbgt_update_value_no_lock(cbgt_md_id, key, val))
    {
        CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0245);
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_update_value: update value of table %ld failed\n",
                            CBGT_MD_TABLE_ID(cbgt_md));
        return (EC_FALSE);
    }
    CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0246);
    return (EC_TRUE);
}

EC_BOOL cbgt_mess_register_no_lock(const UINT32 cbgt_md_id, const CBYTES *key, const UINT32 table_id)
{
    CBGT_MD    *cbgt_md;

    uint8_t  buffer[CBGT_REG_BUFF_MAX_SIZE];
    uint32_t counter;

    MOD_NODE mod_node;

    CBYTES   val;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_mess_register_no_lock: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0247);

    __cbgt_error_mod_node(cbgt_md_id, &mod_node);

    counter = 0;
    CBGT_ASSERT(counter + sizeof(word_t) <= CBGT_REG_BUFF_MAX_SIZE);
    gdbPutWord(buffer, &counter, table_id);
    CBGT_ASSERT(counter + sizeof(word_t) <= CBGT_REG_BUFF_MAX_SIZE);
    gdbPutWord(buffer, &counter, MOD_NODE_TCID(&mod_node));
    CBGT_ASSERT(counter + sizeof(word_t) <= CBGT_REG_BUFF_MAX_SIZE);
    gdbPutWord(buffer, &counter, MOD_NODE_COMM(&mod_node));
    CBGT_ASSERT(counter + sizeof(word_t) <= CBGT_REG_BUFF_MAX_SIZE);
    gdbPutWord(buffer, &counter, MOD_NODE_RANK(&mod_node));
    CBGT_ASSERT(counter + sizeof(word_t) <= CBGT_REG_BUFF_MAX_SIZE);
    gdbPutWord(buffer, &counter, MOD_NODE_MODI(&mod_node));

    cbytes_init(&val);
    cbytes_mount(&val, counter, buffer);
    if(EC_FALSE == cbgt_update_value_no_lock(cbgt_md_id, key, &val))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_mess_register_no_lock: update table %ld register info in parent table %ld failed\n",
                            table_id, CBGT_MD_TABLE_ID(cbgt_md));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cbgt_mess_register(const UINT32 cbgt_md_id, const CBYTES *key, const UINT32 table_id)
{
    CBGT_MD    *cbgt_md;

    uint8_t  buffer[CBGT_REG_BUFF_MAX_SIZE];
    uint32_t counter;

    MOD_NODE mod_node;

    CBYTES   val;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_mess_register: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0248);

    __cbgt_error_mod_node(cbgt_md_id, &mod_node);

    counter = 0;
    CBGT_ASSERT(counter + sizeof(word_t) <= CBGT_REG_BUFF_MAX_SIZE);
    gdbPutWord(buffer, &counter, table_id);
    CBGT_ASSERT(counter + sizeof(word_t) <= CBGT_REG_BUFF_MAX_SIZE);
    gdbPutWord(buffer, &counter, MOD_NODE_TCID(&mod_node));
    CBGT_ASSERT(counter + sizeof(word_t) <= CBGT_REG_BUFF_MAX_SIZE);
    gdbPutWord(buffer, &counter, MOD_NODE_COMM(&mod_node));
    CBGT_ASSERT(counter + sizeof(word_t) <= CBGT_REG_BUFF_MAX_SIZE);
    gdbPutWord(buffer, &counter, MOD_NODE_RANK(&mod_node));
    CBGT_ASSERT(counter + sizeof(word_t) <= CBGT_REG_BUFF_MAX_SIZE);
    gdbPutWord(buffer, &counter, MOD_NODE_MODI(&mod_node));

    cbytes_init(&val);
    cbytes_mount(&val, counter, buffer);
    if(EC_FALSE == cbgt_update_value(cbgt_md_id, key, &val))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_mess_register: update table %ld register info in parent table %ld failed\n",
                            table_id, CBGT_MD_TABLE_ID(cbgt_md));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cbgt_update_register_no_lock(const UINT32 cbgt_md_id, const CBYTES *key, const UINT32 table_id, const MOD_NODE *mod_node)
{
    CBGT_MD    *cbgt_md;

    uint8_t  buffer[CBGT_REG_BUFF_MAX_SIZE];
    uint32_t counter;

    CBYTES   val;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_update_register_no_lock: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0249);

    counter = 0;
    CBGT_ASSERT(counter + sizeof(word_t) <= CBGT_REG_BUFF_MAX_SIZE);
    gdbPutWord(buffer, &counter, table_id);
    CBGT_ASSERT(counter + sizeof(word_t) <= CBGT_REG_BUFF_MAX_SIZE);
    gdbPutWord(buffer, &counter, MOD_NODE_TCID(mod_node));
    CBGT_ASSERT(counter + sizeof(word_t) <= CBGT_REG_BUFF_MAX_SIZE);
    gdbPutWord(buffer, &counter, MOD_NODE_COMM(mod_node));
    CBGT_ASSERT(counter + sizeof(word_t) <= CBGT_REG_BUFF_MAX_SIZE);
    gdbPutWord(buffer, &counter, MOD_NODE_RANK(mod_node));
    CBGT_ASSERT(counter + sizeof(word_t) <= CBGT_REG_BUFF_MAX_SIZE);
    gdbPutWord(buffer, &counter, MOD_NODE_MODI(mod_node));

    cbytes_init(&val);
    cbytes_mount(&val, counter, buffer);
    if(EC_FALSE == cbgt_update_value_no_lock(cbgt_md_id, key, &val))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_update_register_no_lock: update table %ld register info in parent table %ld failed\n",
                            table_id, CBGT_MD_TABLE_ID(cbgt_md));
        return (EC_FALSE);
    }

    if(EC_TRUE == __cbgt_mod_node_is_valid(cbgt_md_id, mod_node))
    {
        mod_mgr_incl(MOD_NODE_TCID(mod_node), MOD_NODE_COMM(mod_node), MOD_NODE_RANK(mod_node), MOD_NODE_MODI(mod_node), CBGT_MD_MOD_MGR(cbgt_md));
    }
    return (EC_TRUE);
}

EC_BOOL cbgt_update_register(const UINT32 cbgt_md_id, const CBYTES *key, const UINT32 table_id, const MOD_NODE *mod_node)
{
    CBGT_MD    *cbgt_md;

    uint8_t  buffer[CBGT_REG_BUFF_MAX_SIZE];
    uint32_t counter;

    CBYTES   val;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_update_register: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0250);

    counter = 0;
    CBGT_ASSERT(counter + sizeof(word_t) <= CBGT_REG_BUFF_MAX_SIZE);
    gdbPutWord(buffer, &counter, table_id);
    CBGT_ASSERT(counter + sizeof(word_t) <= CBGT_REG_BUFF_MAX_SIZE);
    gdbPutWord(buffer, &counter, MOD_NODE_TCID(mod_node));
    CBGT_ASSERT(counter + sizeof(word_t) <= CBGT_REG_BUFF_MAX_SIZE);
    gdbPutWord(buffer, &counter, MOD_NODE_COMM(mod_node));
    CBGT_ASSERT(counter + sizeof(word_t) <= CBGT_REG_BUFF_MAX_SIZE);
    gdbPutWord(buffer, &counter, MOD_NODE_RANK(mod_node));
    CBGT_ASSERT(counter + sizeof(word_t) <= CBGT_REG_BUFF_MAX_SIZE);
    gdbPutWord(buffer, &counter, MOD_NODE_MODI(mod_node));

    cbytes_init(&val);
    cbytes_mount(&val, counter, buffer);
    if(EC_FALSE == cbgt_update_value(cbgt_md_id, key, &val))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_update_register: update table %ld register info in parent table %ld failed\n",
                            table_id, CBGT_MD_TABLE_ID(cbgt_md));
        return (EC_FALSE);
    }

    if(EC_TRUE == __cbgt_mod_node_is_valid(cbgt_md_id, mod_node))
    {
        mod_mgr_incl(MOD_NODE_TCID(mod_node), MOD_NODE_COMM(mod_node), MOD_NODE_RANK(mod_node), MOD_NODE_MODI(mod_node), CBGT_MD_MOD_MGR(cbgt_md));
    }
    return (EC_TRUE);
}

EC_BOOL cbgt_insert_register_no_lock(const UINT32 cbgt_md_id, const CBYTES *row, const UINT32 table_id, const MOD_NODE *mod_node)
{
    CBGT_MD    *cbgt_md;

    uint8_t  buffer[CBGT_REG_BUFF_MAX_SIZE];
    uint32_t counter;

    CBYTES   table_row;
    CBYTES   table_colf;
    CBYTES   table_colq;
    CBYTES   table_val;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_insert_register_no_lock: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0251);

    counter = 0;
    CBGT_ASSERT(counter + sizeof(word_t) <= CBGT_REG_BUFF_MAX_SIZE);
    gdbPutWord(buffer, &counter, table_id);
    CBGT_ASSERT(counter + sizeof(word_t) <= CBGT_REG_BUFF_MAX_SIZE);
    gdbPutWord(buffer, &counter, MOD_NODE_TCID(mod_node));
    CBGT_ASSERT(counter + sizeof(word_t) <= CBGT_REG_BUFF_MAX_SIZE);
    gdbPutWord(buffer, &counter, MOD_NODE_COMM(mod_node));
    CBGT_ASSERT(counter + sizeof(word_t) <= CBGT_REG_BUFF_MAX_SIZE);
    gdbPutWord(buffer, &counter, MOD_NODE_RANK(mod_node));
    CBGT_ASSERT(counter + sizeof(word_t) <= CBGT_REG_BUFF_MAX_SIZE);
    gdbPutWord(buffer, &counter, MOD_NODE_MODI(mod_node));

    cbytes_init(&table_row);
    cbytes_init(&table_colf);
    cbytes_init(&table_colq);
    cbytes_init(&table_val);

    cbytes_mount(&table_row , cbytes_len(row)        , cbytes_buf(row)   );
    cbytes_mount(&table_colf, strlen("info")         , (uint8_t *)"info" );
    cbytes_mount(&table_colq, strlen("vpath")        , (uint8_t *)"vpath");
    cbytes_mount(&table_val , counter                , buffer            );

    if(EC_FALSE == cbgt_insert_rfqv_no_lock(cbgt_md_id, &table_row, &table_colf, &table_colq, &table_val))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_insert_register: insert table %ld register info in parent table %ld failed\n",
                            table_id, CBGT_MD_TABLE_ID(cbgt_md));
        return (EC_FALSE);
    }

    if(EC_TRUE == __cbgt_mod_node_is_valid(cbgt_md_id, mod_node))
    {
        mod_mgr_incl(MOD_NODE_TCID(mod_node), MOD_NODE_COMM(mod_node), MOD_NODE_RANK(mod_node), MOD_NODE_MODI(mod_node), CBGT_MD_MOD_MGR(cbgt_md));
    }
    return (EC_TRUE);
}

EC_BOOL cbgt_insert_register(const UINT32 cbgt_md_id, const CBYTES *row, const UINT32 table_id, const MOD_NODE *mod_node)
{
    CBGT_MD    *cbgt_md;

    uint8_t  buffer[CBGT_REG_BUFF_MAX_SIZE];
    uint32_t counter;

    CBYTES   table_row;
    CBYTES   table_colf;
    CBYTES   table_colq;
    CBYTES   table_val;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_insert_register: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0252);
#if 0
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_insert_register: tabel %ld (tcid %s, comm %ld, rank %ld, modi %ld)\n",
                       table_id, MOD_NODE_TCID_STR(mod_node), MOD_NODE_COMM(mod_node), MOD_NODE_RANK(mod_node), MOD_NODE_MODI(mod_node));
#endif
    counter = 0;
    CBGT_ASSERT(counter + sizeof(word_t) <= CBGT_REG_BUFF_MAX_SIZE);
    gdbPutWord(buffer, &counter, table_id);
    CBGT_ASSERT(counter + sizeof(word_t) <= CBGT_REG_BUFF_MAX_SIZE);
    gdbPutWord(buffer, &counter, MOD_NODE_TCID(mod_node));
    CBGT_ASSERT(counter + sizeof(word_t) <= CBGT_REG_BUFF_MAX_SIZE);
    gdbPutWord(buffer, &counter, MOD_NODE_COMM(mod_node));
    CBGT_ASSERT(counter + sizeof(word_t) <= CBGT_REG_BUFF_MAX_SIZE);
    gdbPutWord(buffer, &counter, MOD_NODE_RANK(mod_node));
    CBGT_ASSERT(counter + sizeof(word_t) <= CBGT_REG_BUFF_MAX_SIZE);
    gdbPutWord(buffer, &counter, MOD_NODE_MODI(mod_node));

    cbytes_init(&table_row);
    cbytes_init(&table_colf);
    cbytes_init(&table_colq);
    cbytes_init(&table_val);

    cbytes_mount(&table_row , cbytes_len(row)        , cbytes_buf(row)   );
    cbytes_mount(&table_colf, strlen("info")         , (uint8_t *)"info" );
    cbytes_mount(&table_colq, strlen("vpath")        , (uint8_t *)"vpath");
    cbytes_mount(&table_val , counter                , buffer            );

    if(EC_FALSE == cbgt_insert_rfqv(cbgt_md_id, &table_row, &table_colf, &table_colq, &table_val))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_insert_register: insert table %ld register info in parent table %ld failed\n",
                            table_id, CBGT_MD_TABLE_ID(cbgt_md));
        return (EC_FALSE);
    }

    if(EC_TRUE == __cbgt_mod_node_is_valid(cbgt_md_id, mod_node))
    {
        mod_mgr_incl(MOD_NODE_TCID(mod_node), MOD_NODE_COMM(mod_node), MOD_NODE_RANK(mod_node), MOD_NODE_MODI(mod_node), CBGT_MD_MOD_MGR(cbgt_md));
    }
    return (EC_TRUE);
}

EC_BOOL cbgt_fetch_user_table_no_lock(const UINT32 cbgt_md_id, const CBYTES *row, const CBYTES *colf, const CBYTES *colq, UINT32 *user_table_id, MOD_NODE *user_mod_node)
{
    CBGT_MD    *cbgt_md;
    CBYTES      kv;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_fetch_user_table_no_lock: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    if(EC_FALSE == cbgt_is_colf_server(cbgt_md_id))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_fetch_user_table_no_lock: cbgt module #%ld was not colf server\n", cbgt_md_id);
        return (EC_FALSE);
    }

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0253);

    cbytes_init(&kv);

    if(EC_FALSE == cbgt_fetch_kv_from_colf_no_lock(cbgt_md_id, row, colf, colq, &kv))
    {
         dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_fetch_user_table_no_lock: search (%.*s:%.*s:%.*s) in colf table %ld failed\n",
                            (uint32_t)cbytes_len(row) , (char *)cbytes_buf(row),
                            (uint32_t)cbytes_len(colf), (char *)cbytes_buf(colf),
                            (uint32_t)cbytes_len(colq), (char *)cbytes_buf(colq),
                            CBGT_MD_TABLE_ID(cbgt_md));
        return (EC_FALSE);
    }

    if(EC_FALSE == cbgt_fetch_from_rmc_no_lock(cbgt_md_id, &kv, user_table_id, user_mod_node))
    {
         dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_fetch_user_table_no_lock: fetch user table id and mod node "
                           "for user table (%.*s:%.*s:%.*s) in colf table %ld failed\n",
                            (uint32_t)cbytes_len(row) , (char *)cbytes_buf(row),
                            (uint32_t)cbytes_len(colf), (char *)cbytes_buf(colf),
                            (uint32_t)cbytes_len(colq), (char *)cbytes_buf(colq),
                            CBGT_MD_TABLE_ID(cbgt_md));
        cbytes_clean(&kv);
        return (EC_FALSE);
    }
#if 0
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT,"[DEBUG] cbgt_fetch_user_table_no_lock: {user table id %ld, user mod node (tcid %s, comm %ld, rank %ld, modi %ld)}\n",
                        (*user_table_id),
                        MOD_NODE_TCID_STR(user_mod_node),
                        MOD_NODE_COMM(user_mod_node),
                        MOD_NODE_RANK(user_mod_node),
                        MOD_NODE_MODI(user_mod_node)
                        );
#endif
    /*if user table not open, try to open*/
    if(EC_FALSE == CBGT_CHECK_TABLE_EXIST(cbgt_md_id, (*user_table_id), user_mod_node))
    {
        CBYTES      col_row;
        MOD_NODE    colf_mod_node;

        __cbgt_local_mod_node(cbgt_md_id, &colf_mod_node);

        cbytes_init(&col_row);
        if(EC_FALSE == cbgt_fetch_row_no_lock(cbgt_md_id, &kv, &col_row))
        {
             dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_fetch_user_table_no_lock: fetch colf row key for (%.*s:%.*s:%.*s) from colf table %ld failed\n",
                                (uint32_t)cbytes_len(row) , (char *)cbytes_buf(row),
                                (uint32_t)cbytes_len(colf), (char *)cbytes_buf(colf),
                                (uint32_t)cbytes_len(colq), (char *)cbytes_buf(colq),
                                CBGT_MD_TABLE_ID(cbgt_md));
            cbytes_clean(&kv);
            return (EC_FALSE);
        }

        if(EC_FALSE == __cbgt_start_trigger(cbgt_md_id,
                                      CBGT_TYPE_USER_SERVER,
                                      (*user_table_id),
                                      &col_row, /*user table name is the row of col table*/
                                      &colf_mod_node,
                                      CBGT_MD_ROOT_PATH(cbgt_md),
                                      CBGT_O_RDWR,
                                      user_mod_node))
        {
            dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_fetch_user_table_no_lock: cbgt start user table %ld on colf table %ld failed\n",
                                (*user_table_id), CBGT_MD_TABLE_ID(cbgt_md));
            cbytes_clean(&col_row);
            cbytes_clean(&kv);
            return (EC_FALSE);
        }
        cbytes_clean(&col_row);

        /*update colf table*/
        if(EC_FALSE == cbgt_update_register_no_lock(cbgt_md_id, &kv, (*user_table_id), user_mod_node))
        {
             dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_fetch_user_table_no_lock: update register of user table %ld in colf table %ld failed\n",
                               (*user_table_id), CBGT_MD_TABLE_ID(cbgt_md));
            __cbgt_end_trigger(cbgt_md_id, user_mod_node);
            cbytes_clean(&kv);
            return (EC_FALSE);
        }
    }

    cbytes_clean(&kv);
    return (EC_TRUE);
}

EC_BOOL cbgt_fetch_user_table(const UINT32 cbgt_md_id, const CBYTES *row, const CBYTES *colf, const CBYTES *colq, UINT32 *user_table_id, MOD_NODE *user_mod_node)
{
    CBGT_MD    *cbgt_md;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_fetch_user_table: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    if(EC_FALSE == cbgt_is_colf_server(cbgt_md_id))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_fetch_user_table: cbgt module #%ld was not colf server\n", cbgt_md_id);
        return (EC_FALSE);
    }

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0254);

    CBGT_MD_CRWLOCK_TABLE_WRLOCK(cbgt_md, LOC_CBGT_0255);
    if(EC_FALSE == cbgt_fetch_user_table_no_lock(cbgt_md_id, row, colf, colq, user_table_id, user_mod_node))
    {
        CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0256);
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_fetch_user_table: fetch user table failed\n");
        return (EC_FALSE);
    }
    CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0257);
    return (EC_TRUE);
}

EC_BOOL cbgt_insert_colf(const UINT32 cbgt_md_id, const CBYTES *row, const CBYTES *colf, const CBYTES *colq, const CBYTES *val)
{
    CBGT_MD    *cbgt_md;

    MOD_NODE    user_mod_node;

    UINT32      user_table_id;
    UINT32      count;

    EC_BOOL     ret;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_insert_colf: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    if(EC_FALSE == cbgt_is_colf_server(cbgt_md_id))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_insert_colf: cbgt module #%ld was not colf server\n", cbgt_md_id);
        return (EC_FALSE);
    }

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0258);

    /**
    *   note: why not apply statement: for(ret = EC_OBSCURE, count = 0; count < CBGT_INSERT_TRY_TIMES; count ++)
    *   reason is considering tcid broken scenario. when broken happen, ret is EC_OBSCURE which was initialize,
    *   thus, the loop will continue and try until reach upper limit, but the fact is we should give up immdiately.
    *   hence ret should be initialized as EC_FALSE but not EC_OBSCURE, and we check if ret is EC_OBSCURE when task
    *   comes back. if ret is EC_FALSE, peer found error or broken happend, hence not necessary to try again. if
    *   ret is EC_OBSCURE, peer found entering wrong user table, we can try again
    **/

    count = 0;
    do
    {
        if(EC_FALSE == cbgt_fetch_user_table(cbgt_md_id, row, colf, colq, &user_table_id, &user_mod_node))
        {
            dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_insert_colf: fetch user table of (%.*s:%.*s:%.*s) in colf table %ld failed\n",
                                (uint32_t)cbytes_len(row) , (char *)cbytes_buf(row),
                                (uint32_t)cbytes_len(colf), (char *)cbytes_buf(colf),
                                (uint32_t)cbytes_len(colq), (char *)cbytes_buf(colq),
                                CBGT_MD_TABLE_ID(cbgt_md));
            return (EC_FALSE);
        }
#if 0
        dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG ]cbgt_insert_colf: open user table (%.*s:%.*s:%.*s) id %ld at (%s,%ld,%ld,%ld) of colf table %ld done\n",
                                cbytes_len(row) , (char *)cbytes_buf(row),
                                cbytes_len(colf), (char *)cbytes_buf(colf),
                                cbytes_len(colq), (char *)cbytes_buf(colq),
                                user_table_id,
                                MOD_NODE_TCID_STR(&user_mod_node), MOD_NODE_COMM(&user_mod_node), MOD_NODE_RANK(&user_mod_node), MOD_NODE_MODI(&user_mod_node),
                                CBGT_MD_TABLE_ID(cbgt_md));
#endif

        ret = EC_FALSE;
        task_p2p(cbgt_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                 &user_mod_node,
                 &ret, FI_cbgt_insert_rfqv, CMPI_ERROR_MODI, row, colf, colq, val);
    }while(EC_OBSCURE == ret && ++ count < CBGT_INSERT_TRY_TIMES);

    if(EC_FALSE == ret || EC_OBSCURE == ret)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_insert_colf: insert (%.*s:%.*s:%.*s) into user table %ld on colf table %ld failed\n",
                            (uint32_t)cbytes_len(row) , (char *)cbytes_buf(row),
                            (uint32_t)cbytes_len(colf), (char *)cbytes_buf(colf),
                            (uint32_t)cbytes_len(colq), (char *)cbytes_buf(colq),
                            user_table_id,
                            CBGT_MD_TABLE_ID(cbgt_md));
        return (EC_FALSE);
    }

    if(EC_TRUE == cbgt_gdb_is_full(CBGT_MD_GDB(cbgt_md)))
    {
        dbg_log(SEC_0054_CBGT, 5)(LOGSTDOUT, "cbgt_insert_colf: colf table is full, trigger merge\n");
        cbgt_merge(cbgt_md_id);
        return (EC_TRUE);
    }

    return (EC_TRUE);
}

/*user_table_name is (star_user_table_key,end_user_table_key)*/
STATIC_CAST static EC_BOOL __cbgt_set_user_table_to_session(const UINT32 cbgt_md_id, const CSTRING *colf_session_path, const CBYTES *user_table_name, const UINT32 user_table_id, const MOD_NODE *mod_node)
{
    CBGT_MD    *cbgt_md;
    CSTRING     path;

    CBYTES      val;
    char       *user_table_name_hex_str;
    uint8_t     buff[64];
    uint32_t    pos;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:__cbgt_set_user_table_to_session: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);

    user_table_name_hex_str = c_bytes_to_hex_str(cbytes_buf(user_table_name), cbytes_len(user_table_name));
    if(NULL_PTR == user_table_name_hex_str)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_set_user_table_to_session: conv user_table_name from bytes to hex str failed\n");
        return (EC_FALSE);
    }
#if 0
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] __cbgt_set_user_table_to_session : user_table_name buf %p len %ld\n", cbytes_buf(user_table_name), cbytes_len(user_table_name));
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] __cbgt_set_user_table_to_session : user_table_name_hex_str = %s\n", user_table_name_hex_str);
#endif
    cstring_init(&path, NULL_PTR);
    /*user table name + colf name*/
    cstring_format(&path, "%s/user:%s", (char *)cstring_get_str(colf_session_path), user_table_name_hex_str);

    pos = 0;
    gdbPutWord(buff, &pos, user_table_id);
    gdbPutWord(buff, &pos, MOD_NODE_TCID(mod_node));
    gdbPutWord(buff, &pos, MOD_NODE_COMM(mod_node));
    gdbPutWord(buff, &pos, MOD_NODE_RANK(mod_node));
    gdbPutWord(buff, &pos, MOD_NODE_MODI(mod_node));

    cbytes_init(&val);
    cbytes_mount(&val, pos, (UINT8 *)buff);
#if 0
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDNULL, "[DEBUG] __cbgt_set_colf_table_to_session: %s => %.*s\n",
                        (char *)cstring_get_str(&path),
                        cbytes_len(&val), (char *)cbytes_buf(&val));
#endif
    if(EC_FALSE == csession_set_by_name(CBGT_MD_CSESSION_MD_ID(cbgt_md), CBGT_MD_CSESSION_NAME(cbgt_md), &path, &val))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_set_user_table_to_session: csession set by %s failed\n",
                            (char *)cstring_get_str(CBGT_MD_CSESSION_NAME(cbgt_md)));
        cstring_clean(&path);
        safe_free(user_table_name_hex_str, LOC_CBGT_0259);
        return (EC_FALSE);
    }

    cstring_clean(&path);
    safe_free(user_table_name_hex_str, LOC_CBGT_0260);
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cbgt_check_user_csession_item_is_expected_user_table(const CSESSION_ITEM *user_csession_item, const CBYTES *user_table_key_bytes)
{
    UINT8  *colf_row_bytes;
    UINT32  colf_row_len;
#if 0
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] __cbgt_check_user_csession_item_is_expected_user_table: %s [len %ld vs %ld]\n",
                        (char *)CSESSION_ITEM_KEY_STR(user_csession_item),
                        strlen((char *)CSESSION_ITEM_KEY_STR(user_csession_item)),
                        cstring_get_len(CSESSION_ITEM_KEY(user_csession_item)));
#endif
#if 1
    /*5 = strlen("user:")*/
    if(EC_FALSE == c_hex_str_to_bytes((char *)CSESSION_ITEM_KEY_STR(user_csession_item) + 5, &colf_row_bytes, &colf_row_len))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_check_user_csession_item_is_expected_user_table: hex str to bytes failed: %s\n", (char *)CSESSION_ITEM_KEY_STR(user_csession_item));
        return (EC_FALSE);
    }

    if(0 != __cbgt_cmp_colf_row_and_user_table_key(colf_row_bytes, cbytes_buf(user_table_key_bytes)))
    {
        safe_free(colf_row_bytes, LOC_CBGT_0261);
        return (EC_FALSE);
    }

    safe_free(colf_row_bytes, LOC_CBGT_0262);
#endif
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cbgt_get_user_table_from_session(const UINT32 cbgt_md_id, const CSTRING *colf_session_path,
                                                                const CBYTES *row, const CBYTES *colf, const CBYTES *colq,
                                                                UINT32 *user_table_id, MOD_NODE *mod_node)
{
    CBGT_MD    *cbgt_md;
    CLIST      *csession_item_list;

    CSESSION_ITEM *root_csession_item;
    CSESSION_ITEM *colf_csession_item;
    CSESSION_ITEM *user_csession_item;
    CBYTES         user_table_key_bytes;

    CLIST_DATA    *clist_data;
    EC_BOOL        ret;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:__cbgt_get_user_table_from_session: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);

    //dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] __cbgt_get_user_table_from_session: colf_session_path %s\n", (char *)cstring_get_str(colf_session_path));

    csession_item_list = clist_new(MM_CSESSION_ITEM, LOC_CBGT_0263);
    if(NULL_PTR == csession_item_list)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_get_user_table_from_session: new csession item list failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == csession_get_children_by_name(CBGT_MD_CSESSION_MD_ID(cbgt_md), CBGT_MD_CSESSION_NAME(cbgt_md), colf_session_path, csession_item_list))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_get_user_table_from_session: csession get by %s failed\n",
                            (char *)cstring_get_str(colf_session_path));
        clist_free(csession_item_list, LOC_CBGT_0264);
        return (EC_FALSE);
    }

    //dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] __cbgt_get_user_table_from_session: csession_item_list is \n");
    //clist_print_level(LOGSTDOUT, csession_item_list, 0, (CLIST_DATA_LEVEL_PRINT)csession_item_print);

    root_csession_item = (CSESSION_ITEM *)clist_back_no_lock(csession_item_list);
    if(NULL_PTR == root_csession_item)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_get_user_table_from_session: not found sub csession item under %s\n",
                            (char *)cstring_get_str(colf_session_path));
        clist_free(csession_item_list, LOC_CBGT_0265);
        return (EC_FALSE);
    }

    //dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] __cbgt_get_user_table_from_session: root_csession_item is:\n");
    //csession_item_print(LOGSTDOUT, root_csession_item, 0);

    colf_csession_item = (CSESSION_ITEM *)clist_back_no_lock(CSESSION_ITEM_CHILDREN(root_csession_item));
    if(NULL_PTR == colf_csession_item)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_get_user_table_from_session: not found colf csession item under %s\n",
                            (char *)cstring_get_str(colf_session_path));
        clist_free(csession_item_list, LOC_CBGT_0266);
        return (EC_FALSE);
    }

    //dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] __cbgt_get_user_table_from_session: colf_csession_item is:\n");
    //csession_item_print(LOGSTDOUT, colf_csession_item, 0);

    cbytes_init(&user_table_key_bytes);
    if(EC_FALSE == __cbgt_make_user_table_key(CMPI_ANY_MODI, row, colf, colq, &user_table_key_bytes))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_get_user_table_from_session: make user table key failed\n");
        clist_free(csession_item_list, LOC_CBGT_0267);
        return (EC_FALSE);
    }

    //dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] __cbgt_get_user_table_from_session: current sessions:\n");
    //csession_print(LOGSTDOUT, CBGT_MD_CSESSION_MD_ID(cbgt_md), 0);

    ret = EC_FALSE;
    user_csession_item = NULL_PTR;
    CLIST_LOOP_NEXT(CSESSION_ITEM_CHILDREN(colf_csession_item), clist_data)
    {
        user_csession_item = (CSESSION_ITEM *)CLIST_DATA_DATA(clist_data);
        if(NULL_PTR == user_csession_item)
        {
            continue;
        }

        //dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] __cbgt_get_user_table_from_session: user_csession_item is:\n");
        //csession_item_print(LOGSTDOUT, user_csession_item, 0);

        /*check it is expected user table*/
        if(EC_TRUE == __cbgt_check_user_csession_item_is_expected_user_table(user_csession_item, &user_table_key_bytes))
        {
            ret = EC_TRUE;
            break;
        }
    }
    cbytes_clean(&user_table_key_bytes);

    //csession_item_print(LOGSTDOUT, colf_csession_item, 0);

    if(EC_TRUE == ret && NULL_PTR != user_csession_item)
    {
        CBYTES        *val;
        uint8_t       *buff;
        uint32_t       pos;

        val = CSESSION_ITEM_VAL(user_csession_item);
        buff = cbytes_buf(val);

        pos = 0;
        (*user_table_id)        = gdbGetWord(buff, &pos);
        MOD_NODE_TCID(mod_node) = gdbGetWord(buff, &pos);
        MOD_NODE_COMM(mod_node) = gdbGetWord(buff, &pos);
        MOD_NODE_RANK(mod_node) = gdbGetWord(buff, &pos);
        MOD_NODE_MODI(mod_node) = gdbGetWord(buff, &pos);

#if 0
        dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG]__cbgt_get_user_table_from_session: %ld (%s,%ld,%ld,%ld)\n",
                            (*user_table_id),
                            MOD_NODE_TCID_STR(mod_node),
                            MOD_NODE_COMM(mod_node),
                            MOD_NODE_RANK(mod_node),
                            MOD_NODE_MODI(mod_node));
#endif

        clist_free(csession_item_list, LOC_CBGT_0268);
        return (EC_TRUE);
    }

    clist_free(csession_item_list, LOC_CBGT_0269);
    return (EC_FALSE);
}

STATIC_CAST static EC_BOOL __cbgt_set_colf_table_to_session(const UINT32 cbgt_md_id, const CSTRING *colf_session_path, const UINT32 colf_table_id, const MOD_NODE *mod_node)
{
    CBGT_MD    *cbgt_md;

    CBYTES      val;
    uint8_t     buff[64];
    uint32_t    pos;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:__cbgt_set_colf_table_to_session: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);

    pos = 0;
    gdbPutWord(buff, &pos, colf_table_id);
    gdbPutWord(buff, &pos, MOD_NODE_TCID(mod_node));
    gdbPutWord(buff, &pos, MOD_NODE_COMM(mod_node));
    gdbPutWord(buff, &pos, MOD_NODE_RANK(mod_node));
    gdbPutWord(buff, &pos, MOD_NODE_MODI(mod_node));

    cbytes_init(&val);
    cbytes_mount(&val, pos, (UINT8 *)buff);
#if 0
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDNULL, "[DEBUG] __cbgt_set_colf_table_to_session: %s => %.*s\n",
                        (char *)cstring_get_str(colf_session_path),
                        cbytes_len(&val), (char *)cbytes_buf(&val));
#endif
    if(EC_FALSE == csession_set_by_name(CBGT_MD_CSESSION_MD_ID(cbgt_md), CBGT_MD_CSESSION_NAME(cbgt_md), colf_session_path, &val))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_set_colf_table_to_session: csession set by %s failed\n",
                            (char *)cstring_get_str(CBGT_MD_CSESSION_NAME(cbgt_md)));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cbgt_get_colf_table_from_session(const UINT32 cbgt_md_id, const CBYTES *table_name, const CBYTES *colf,
                                                              CSTRING *colf_session_path, UINT32 *colf_table_id, MOD_NODE *mod_node)
{
    CBGT_MD    *cbgt_md;
    CLIST      *csession_item_list;

    CSESSION_ITEM *csession_item;
    CBYTES        *val;

    uint8_t       *buff;
    uint32_t       pos;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:__cbgt_get_colf_table_from_session: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);

    /*user table name + colf name*/
    cstring_format(colf_session_path, "table:%.*s/colf:%.*s",
                          (uint32_t)cbytes_len(table_name), (char *)cbytes_buf(table_name),
                          (uint32_t)cbytes_len(colf), (char *)cbytes_buf(colf));

    csession_item_list = clist_new(MM_CSESSION_ITEM, LOC_CBGT_0270);
    if(NULL_PTR == csession_item_list)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_get_colf_table_from_session: new csession item list failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == csession_get_by_name(CBGT_MD_CSESSION_MD_ID(cbgt_md), CBGT_MD_CSESSION_NAME(cbgt_md), colf_session_path, csession_item_list))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_get_colf_table_from_session: csession get by %s failed\n",
                            (char *)cstring_get_str(CBGT_MD_CSESSION_NAME(cbgt_md)));
        clist_free(csession_item_list, LOC_CBGT_0271);
        return (EC_FALSE);
    }

    //dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] __cbgt_get_colf_table_from_session: csession_item_list is \n");
    //clist_print_level(LOGSTDOUT, csession_item_list, 0, (CLIST_DATA_LEVEL_PRINT)csession_item_print);

    csession_item = (CSESSION_ITEM *)clist_back(csession_item_list);
    if(NULL_PTR == csession_item)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_get_colf_table_from_session: not found session item for table %.*s\n",
                            (uint32_t)cbytes_len(table_name), (char *)cbytes_buf(table_name));
        clist_free(csession_item_list, LOC_CBGT_0272);
        return (EC_FALSE);
    }

    csession_item = (CSESSION_ITEM *)clist_back(CSESSION_ITEM_CHILDREN(csession_item));
    if(NULL_PTR == csession_item)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_get_colf_table_from_session: not found session item for table %.*s colf %.*s\n",
                            (uint32_t)cbytes_len(table_name), (char *)cbytes_buf(table_name),
                            (uint32_t)cbytes_len(colf), (char *)cbytes_buf(colf));
        clist_free(csession_item_list, LOC_CBGT_0273);
        return (EC_FALSE);
    }

    //csession_item_print(LOGSTDOUT, csession_item, 0);
    val = CSESSION_ITEM_VAL(csession_item);
    buff = cbytes_buf(val);

    pos = 0;
    (*colf_table_id)        = gdbGetWord(buff, &pos);
    MOD_NODE_TCID(mod_node) = gdbGetWord(buff, &pos);
    MOD_NODE_COMM(mod_node) = gdbGetWord(buff, &pos);
    MOD_NODE_RANK(mod_node) = gdbGetWord(buff, &pos);
    MOD_NODE_MODI(mod_node) = gdbGetWord(buff, &pos);
#if 0
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG]__cbgt_get_colf_table_from_session: %ld (%s,%ld,%ld,%ld)\n",
                        (*colf_table_id),
                        MOD_NODE_TCID_STR(mod_node),
                        MOD_NODE_COMM(mod_node),
                        MOD_NODE_RANK(mod_node),
                        MOD_NODE_MODI(mod_node));
#endif
    clist_free(csession_item_list, LOC_CBGT_0274);

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cbgt_rmv_colf_table_from_session(const UINT32 cbgt_md_id, const CSTRING *colf_session_path)
{
    CBGT_MD    *cbgt_md;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:__cbgt_rmv_colf_table_from_session: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);

    /*oh shit! here should purge colf session only*/
    csession_rmv_by_name(CBGT_MD_CSESSION_MD_ID(cbgt_md), CBGT_MD_CSESSION_NAME(cbgt_md));
    csession_add(CBGT_MD_CSESSION_MD_ID(cbgt_md), CBGT_MD_CSESSION_NAME(cbgt_md), CSESSION_NEVER_EXPIRE);

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cbgt_set_meta_table_to_session(const UINT32 cbgt_md_id, const CSTRING *meta_session_path, const UINT32 meta_table_id, const MOD_NODE *mod_node)
{
    CBGT_MD    *cbgt_md;

    CBYTES      val;
    uint8_t     buff[64];
    uint32_t    pos;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:__cbgt_set_meta_table_to_session: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);

    pos = 0;
    gdbPutWord(buff, &pos, meta_table_id);
    gdbPutWord(buff, &pos, MOD_NODE_TCID(mod_node));
    gdbPutWord(buff, &pos, MOD_NODE_COMM(mod_node));
    gdbPutWord(buff, &pos, MOD_NODE_RANK(mod_node));
    gdbPutWord(buff, &pos, MOD_NODE_MODI(mod_node));

    cbytes_init(&val);
    cbytes_mount(&val, pos, (UINT8 *)buff);
#if 0
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDNULL, "[DEBUG] __cbgt_set_meta_table_to_session: %s => %.*s\n",
                        (char *)cstring_get_str(meta_session_path),
                        cbytes_len(&val), (char *)cbytes_buf(&val));
#endif
    if(EC_FALSE == csession_set_by_name(CBGT_MD_CSESSION_MD_ID(cbgt_md), CBGT_MD_CSESSION_NAME(cbgt_md), meta_session_path, &val))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_set_meta_table_to_session: csession set by %s failed\n",
                            (char *)cstring_get_str(CBGT_MD_CSESSION_NAME(cbgt_md)));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

void cbgt_was_access(const UINT32 cbgt_md_id)
{
    CBGT_MD    *cbgt_md;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_was_access: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0275);
#if 0
    if(NULL_PTR != CBGT_MD_PARENT_MOD(cbgt_md))
    {
        task_p2p_no_wait(cbgt_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP,
                         CBGT_MD_PARENT_MOD(cbgt_md), NULL_PTR, FI_cbgt_was_access, CMPI_ERROR_MODI);
    }
#endif
    return;
}

STATIC_CAST static EC_BOOL __cbgt_get_meta_table_from_session(const UINT32 cbgt_md_id, const CBYTES *table_name, CSTRING *meta_session_path, UINT32 *meta_table_id, MOD_NODE *mod_node)
{
    CBGT_MD    *cbgt_md;
    CLIST      *csession_item_list;

    CSESSION_ITEM *csession_item;
    CBYTES        *val;

    uint8_t       *buff;
    uint32_t       pos;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:__cbgt_get_meta_table_from_session: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);

    /*user table name + meta name*/
    cstring_format(meta_session_path, "meta:%.*s",
                          (uint32_t)cbytes_len(table_name), (char *)cbytes_buf(table_name));

    csession_item_list = clist_new(MM_CSESSION_ITEM, LOC_CBGT_0276);
    if(NULL_PTR == csession_item_list)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_get_meta_table_from_session: new csession item list failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == csession_get_by_name(CBGT_MD_CSESSION_MD_ID(cbgt_md), CBGT_MD_CSESSION_NAME(cbgt_md), meta_session_path, csession_item_list))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_get_meta_table_from_session: csession get by %s failed\n",
                            (char *)cstring_get_str(CBGT_MD_CSESSION_NAME(cbgt_md)));
        clist_free(csession_item_list, LOC_CBGT_0277);
        return (EC_FALSE);
    }

    //dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] __cbgt_get_meta_table_from_session: csession_item_list is \n");
    //clist_print_level(LOGSTDOUT, csession_item_list, 0, (CLIST_DATA_LEVEL_PRINT)csession_item_print);

    csession_item = (CSESSION_ITEM *)clist_back(csession_item_list);
    if(NULL_PTR == csession_item)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_get_meta_table_from_session: not found session item for meta %.*s\n",
                            (uint32_t)cbytes_len(table_name), (char *)cbytes_buf(table_name));
        clist_free(csession_item_list, LOC_CBGT_0278);
        return (EC_FALSE);
    }

    //csession_item_print(LOGSTDOUT, csession_item, 0);
    val = CSESSION_ITEM_VAL(csession_item);
    buff = cbytes_buf(val);

    pos = 0;
    (*meta_table_id)        = gdbGetWord(buff, &pos);
    MOD_NODE_TCID(mod_node) = gdbGetWord(buff, &pos);
    MOD_NODE_COMM(mod_node) = gdbGetWord(buff, &pos);
    MOD_NODE_RANK(mod_node) = gdbGetWord(buff, &pos);
    MOD_NODE_MODI(mod_node) = gdbGetWord(buff, &pos);
#if 0
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG]__cbgt_get_meta_table_from_session: %ld (%s,%ld,%ld,%ld)\n",
                        (*meta_table_id),
                        MOD_NODE_TCID_STR(mod_node),
                        MOD_NODE_COMM(mod_node),
                        MOD_NODE_RANK(mod_node),
                        MOD_NODE_MODI(mod_node));
#endif
    clist_free(csession_item_list, LOC_CBGT_0279);

    return (EC_TRUE);
}

EC_BOOL cbgt_insert(const UINT32 cbgt_md_id, const CBYTES *table_name, const CBYTES *row, const CBYTES *colf, const CBYTES *colq, const CBYTES *val)
{
    CBGT_MD    *cbgt_md;

    MOD_NODE   *root_mod_node;
    MOD_NODE    colf_mod_node;

    UINT32      colf_table_id;

    EC_BOOL     ret;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_insert: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    root_mod_node = CBGT_MD_ROOT_MOD(cbgt_md);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0280);

    /*open colf table*/
    /*note:cbgt_open_colf_table_from_root will check session at first. if hit nothing, ask root for help*/
    if(EC_FALSE == cbgt_open_colf_table_from_root(cbgt_md_id, table_name, colf, &colf_table_id, &colf_mod_node))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_insert: open colf table %.*s of user table %.*s failed\n",
                            (uint32_t)cbytes_len(colf), (char *)cbytes_buf(colf),
                            (uint32_t)cbytes_len(table_name), (char *)cbytes_buf(table_name));
        return (EC_FALSE);
    }
#if 0
        dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_insert: open colf table %.*s id %ld at (%s,%ld,%ld,%ld) of user table %.*s done\n",
                            cbytes_len(colf), (char *)cbytes_buf(colf), colf_table_id,
                            MOD_NODE_TCID_STR(&colf_mod_node), MOD_NODE_COMM(&colf_mod_node), MOD_NODE_RANK(&colf_mod_node), MOD_NODE_MODI(&colf_mod_node),
                            cbytes_len(table_name), (char *)cbytes_buf(table_name));
#endif

    /*insert kv by colf server*/
    ret = EC_FALSE;
    task_p2p(cbgt_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                     &colf_mod_node,
                     &ret,FI_cbgt_insert_colf, CMPI_ERROR_MODI, row, colf, colq, val);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_insert: insert (%.*s:%.*s:%.*s) into user table %.*s via colf table %ld:(tcid %s, comm %ld, rank %ld, modi %ld) failed\n",
                            (uint32_t)cbytes_len(row) , (char *)cbytes_buf(row),
                            (uint32_t)cbytes_len(colf), (char *)cbytes_buf(colf),
                            (uint32_t)cbytes_len(colq), (char *)cbytes_buf(colq),
                            (uint32_t)cbytes_len(table_name)  , (char *)cbytes_buf(table_name),
                            colf_table_id,
                            MOD_NODE_TCID_STR(&colf_mod_node),
                            MOD_NODE_COMM(&colf_mod_node),
                            MOD_NODE_RANK(&colf_mod_node),
                            MOD_NODE_MODI(&colf_mod_node));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}


/*oh shit! cbgt_fetch_kv_from_colf_no_lock will return the whole kv but not only value part! */
/*quite easy to confuse us between cbgt_fetch_kv_from_colf_no_lock and cbgt_search_from_colf. Different Return!*/
EC_BOOL cbgt_fetch_kv_from_colf_no_lock(const UINT32 cbgt_md_id, const CBYTES *row, const CBYTES *colf, const CBYTES *colq, CBYTES *kv)
{
    CBGT_MD    *cbgt_md;
    CBGT_GDB   *colf_gdb;

    CBYTES   user_rowkey;
    CBYTES   colf_rowkey;

    CBTREE_KEY *cbtree_key;
    UINT8      *key;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_fetch_kv_from_colf_no_lock: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0281);

    if(EC_FALSE == __cbgt_make_user_table_key(cbgt_md_id, row, colf, colq, &user_rowkey))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_fetch_kv_from_colf_no_lock: make row key of user table failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == __cbgt_make_colf_table_key_by_user_table_key(cbgt_md_id, &user_rowkey, &colf_rowkey))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_fetch_kv_from_colf_no_lock: make row key of colf table failed\n");
        cbgt_key_clean(cbgt_md_id, &user_rowkey);
        return (EC_FALSE);
    }
    cbgt_key_clean(cbgt_md_id, &user_rowkey);

    colf_gdb = CBGT_MD_GDB(cbgt_md);

    CBGT_ASSERT(CBTREE_IS_BGT_COLF_TABLE_TYPE == CBTREE_KEY_TYPE(CBGT_GDB_CBTREE(colf_gdb)));
    cbtree_key = cbgt_gdb_search_key(colf_gdb, cbytes_buf(&colf_rowkey));
    if(NULL_PTR == cbtree_key)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_fetch_kv_from_colf_no_lock: search in colf table %ld failed\n", CBGT_MD_TABLE_ID(cbgt_md));
        cbgt_key_clean(cbgt_md_id, &colf_rowkey);
        return (EC_FALSE);
    }

    key = CBTREE_KEY_LATEST(cbtree_key);

    cbytes_set(kv, key, kvGettLenHs(key));
    cbgt_key_clean(cbgt_md_id, &colf_rowkey);

    return (EC_TRUE);
}

EC_BOOL cbgt_search_from_colf(const UINT32 cbgt_md_id, const CBYTES *row, const CBYTES *colf, const CBYTES *colq, CBYTES *val)
{
    CBGT_MD    *cbgt_md;
    CBGT_GDB   *colf_gdb;

    CBYTES   user_rowkey;
    CBYTES   colf_rowkey;

    CBTREE_KEY *cbtree_key;
    UINT8      *key;
    UINT8      *kv;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_search_from_colf: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0282);

    if(EC_FALSE == __cbgt_make_user_table_key(cbgt_md_id, row, colf, colq, &user_rowkey))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_search_from_colf: make row key of user table failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == __cbgt_make_colf_table_key_by_user_table_key(cbgt_md_id, &user_rowkey, &colf_rowkey))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_search_from_colf: make row key of colf table failed\n");
        cbgt_key_clean(cbgt_md_id, &user_rowkey);
        return (EC_FALSE);
    }
    cbgt_key_clean(cbgt_md_id, &user_rowkey);

    CBGT_MD_CRWLOCK_TABLE_RDLOCK(cbgt_md, LOC_CBGT_0283);
    colf_gdb = CBGT_MD_GDB(cbgt_md);

    CBGT_ASSERT(CBTREE_IS_BGT_COLF_TABLE_TYPE == CBTREE_KEY_TYPE(CBGT_GDB_CBTREE(colf_gdb)));
    cbtree_key = cbgt_gdb_search_key(colf_gdb, cbytes_buf(&colf_rowkey));
    if(NULL_PTR == cbtree_key)
    {
        CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0284);

        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_search_from_colf: search in colf table %ld failed\n", CBGT_MD_TABLE_ID(cbgt_md));

        cbgt_key_clean(cbgt_md_id, &colf_rowkey);
        return (EC_FALSE);
    }

    key = CBTREE_KEY_LATEST(cbtree_key);
    kv  = key;
    cbytes_set(val, kvGetValueHs(kv), kvGetvLenHs(kv));/*dump value from kv*/
    CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0285);

    cbgt_key_clean(cbgt_md_id, &colf_rowkey);
    return (EC_TRUE);
}

EC_BOOL cbgt_search_from_user(const UINT32 cbgt_md_id, const CBYTES *row, const CBYTES *colf, const CBYTES *colq, CBYTES *val)
{
    CBGT_MD    *cbgt_md;
    CBGT_GDB   *user_gdb;

    CBYTES      user_rowkey;
    CBTREE_KEY *cbtree_key;
    UINT8      *key;
    UINT8      *kv;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_search_from_user: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0286);

    if(EC_FALSE == __cbgt_make_user_table_key(cbgt_md_id, row, colf, colq, &user_rowkey))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_search_from_user: make rowkey of user table failed\n");
        return (EC_FALSE);
    }

    CBGT_MD_CRWLOCK_TABLE_RDLOCK(cbgt_md, LOC_CBGT_0287);
    user_gdb = CBGT_MD_GDB(cbgt_md);
    cbtree_key = cbgt_gdb_search_key(user_gdb, cbytes_buf(&user_rowkey));
    if(NULL_PTR == cbtree_key)
    {
        CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0288);
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_search_from_user: search in user table %ld failed\n", CBGT_MD_TABLE_ID(cbgt_md));
        cbgt_key_clean(cbgt_md_id, &user_rowkey);
        return (EC_FALSE);
    }

    key = CBTREE_KEY_LATEST(cbtree_key);
    kv  = key;
    cbytes_set(val, kvGetValueHs(kv), kvGetvLenHs(kv));/*dump value from kv*/

    CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0289);
    cbgt_key_clean(cbgt_md_id, &user_rowkey);

    return (EC_TRUE);
}

EC_BOOL cbgt_search(const UINT32 cbgt_md_id, const CBYTES *table_name, const CBYTES *row, const CBYTES *colf, const CBYTES *colq, CBYTES *val)
{
    CBGT_MD    *cbgt_md;

    MOD_NODE   *root_mod_node;
    MOD_NODE    user_mod_node;

    UINT32      user_table_id;
    CBYTES      user_table_name;

    EC_BOOL     ret;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_search: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    root_mod_node = CBGT_MD_ROOT_MOD(cbgt_md);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0290);

    /*get user table*/
    cbytes_init(&user_table_name);
    if(EC_FALSE == cbgt_open_user_table_from_root(cbgt_md_id, table_name, row, colf, colq, &user_table_name, &user_table_id, &user_mod_node))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_search: open user table of %.*s (%.*s:%.*s:%.*s) failed\n",
                            (uint32_t)cbytes_len(table_name), (char *)cbytes_buf(table_name),
                            (uint32_t)cbytes_len(row) , (char *)cbytes_buf(row),
                            (uint32_t)cbytes_len(colf), (char *)cbytes_buf(colf),
                            (uint32_t)cbytes_len(colq), (char *)cbytes_buf(colq));
        cbytes_clean(&user_table_name);
        return (EC_FALSE);
    }
    cbytes_clean(&user_table_name);

    /*search in user table*/
    ret = EC_FALSE;
    task_p2p(cbgt_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &user_mod_node,
             &ret,FI_cbgt_search_from_user, CMPI_ERROR_MODI, row, colf, colq, val);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_search: search %.*s (%.*s:%.*s:%.*s) in user table %ld:(tcid %s, comm %ld, rank %ld, modi %ld) failed\n",
                            (uint32_t)cbytes_len(table_name), (char *)cbytes_buf(table_name),
                            (uint32_t)cbytes_len(row) , (char *)cbytes_buf(row),
                            (uint32_t)cbytes_len(colf), (char *)cbytes_buf(colf),
                            (uint32_t)cbytes_len(colq), (char *)cbytes_buf(colq),
                            user_table_id,
                            MOD_NODE_TCID_STR(&user_mod_node),
                            MOD_NODE_COMM(&user_mod_node),
                            MOD_NODE_RANK(&user_mod_node),
                            MOD_NODE_MODI(&user_mod_node));
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL cbgt_fetch_from_user(const UINT32 cbgt_md_id, const CBYTES *row, const CBYTES *colf, const CBYTES *colq, CBYTES *val)
{
    CBGT_MD    *cbgt_md;
    CBGT_GDB   *user_gdb;

    CBYTES      user_rowkey;
    CBTREE_KEY *cbtree_key;

    UINT8      *kv;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        return (EC_OBSCURE);
#if 0
        sys_log(LOGSTDOUT,
                "error:cbgt_fetch_from_user: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
#endif
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0291);

    if(EC_FALSE == __cbgt_make_user_table_key(cbgt_md_id, row, colf, colq, &user_rowkey))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_fetch_from_user: make rowkey of user table failed\n");
        return (EC_FALSE);
    }
#if 0
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG]cbgt_fetch_from_user: [1] user key ");
    __cbgt_print_user_table_key(LOGSTDOUT, cbytes_buf(&user_rowkey));
    sys_print(LOGSTDOUT, "\n");
#endif
    CBGT_MD_CRWLOCK_TABLE_RDLOCK(cbgt_md, LOC_CBGT_0292);
    /*confirm fetching in the right user table because the user table covering range will change if split happened*/
    if(EC_FALSE == __cbgt_cmp_colf_row_and_user_table_key(cbytes_buf(CBGT_MD_TABLE_NAME(cbgt_md)), cbytes_buf(&user_rowkey)))
    {
        CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0293);

        dbg_log(SEC_0054_CBGT, 1)(LOGSTDOUT, "warn:cbgt_fetch_from_user: user key ");
        __cbgt_print_user_table_key(LOGSTDOUT, cbytes_buf(&user_rowkey));
        sys_print(LOGSTDOUT, " not belong to user table ");
        __cbgt_print_colf_table_row(LOGSTDOUT, cbytes_buf(CBGT_MD_TABLE_NAME(cbgt_md)));
        sys_print(LOGSTDOUT, "\n");
        cbytes_clean(&user_rowkey);
        return (EC_OBSCURE);/*ask caller to try again*/
    }
#if 0
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG]cbgt_fetch_from_user: [2] user key ");
    __cbgt_print_user_table_key(LOGSTDOUT, cbytes_buf(&user_rowkey));
    sys_print(LOGSTDOUT, "\n");
#endif
    user_gdb = CBGT_MD_GDB(cbgt_md);
    cbtree_key = cbgt_gdb_search_key(user_gdb, cbytes_buf(&user_rowkey));
    if(NULL_PTR == cbtree_key)
    {
        CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0294);

        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_fetch_from_user: search (%.*s:%.*s:%.*s) in user table %ld failed\n",
                            (uint32_t)cbytes_len(row) , (char *)cbytes_buf(row),
                            (uint32_t)cbytes_len(colf), (char *)cbytes_buf(colf),
                            (uint32_t)cbytes_len(colq), (char *)cbytes_buf(colq),
                            CBGT_MD_TABLE_ID(cbgt_md));
        cbgt_key_clean(cbgt_md_id, &user_rowkey);
        return (EC_FALSE);
    }

    cbgt_key_clean(cbgt_md_id, &user_rowkey);

    kv = CBTREE_KEY_LATEST(cbtree_key);
    cbytes_set(val, kvGetValueHs(kv), kvGetvLenHs(kv));/*dump value part*/

    CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0295);
    return (EC_TRUE);
}

EC_BOOL cbgt_fetch0(const UINT32 cbgt_md_id, const CBYTES *table_name, const CBYTES *row, const CBYTES *colf, const CBYTES *colq, CBYTES *val)
{
    CBGT_MD    *cbgt_md;

    MOD_NODE   *root_mod_node;
    //MOD_NODE    colf_mod_node;
    MOD_NODE    user_mod_node;

    //UINT32      colf_table_id;
    UINT32      user_table_id;
    CBYTES      user_table_name;
    UINT32      count;

    EC_BOOL     ret;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_fetch: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    root_mod_node = CBGT_MD_ROOT_MOD(cbgt_md);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0296);

#if 0
    dbg_log(SEC_0054_CBGT, 5)(LOGSTDOUT, "------------------------------------------ cbgt_fetch enter ------------------------------------------\n");
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_fetch: table name: %.*s\n", cbytes_len(table_name), (char *)cbytes_buf(table_name));
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_fetch: row       : %.*s\n", cbytes_len(row) , (char *)cbytes_buf(row));
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_fetch: colf      : %.*s\n", cbytes_len(colf), (char *)cbytes_buf(colf));
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_fetch: colq      : %.*s\n", cbytes_len(colq), (char *)cbytes_buf(colq));
#endif
    /**
    *   note: why not apply statement: for(ret = EC_OBSCURE, count = 0; count < CBGT_INSERT_TRY_TIMES; count ++)
    *   reason is considering tcid broken scenario. when broken happen, ret is EC_OBSCURE which was initialize,
    *   thus, the loop will continue and try until reach upper limit, but the fact is we should give up immdiately.
    *   hence ret should be initialized as EC_FALSE but not EC_OBSCURE, and we check if ret is EC_OBSCURE when task
    *   comes back. if ret is EC_FALSE, peer found error or broken happend, hence not necessary to try again. if
    *   ret is EC_OBSCURE, peer found entering wrong user table, we can try again
    **/
    cbytes_init(&user_table_name);
    count = 0;
    do
    {
        /*get user table*/
        if(EC_FALSE == cbgt_open_user_table_from_root(cbgt_md_id, table_name, row, colf, colq, &user_table_name, &user_table_id, &user_mod_node))
        {
            dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_fetch: open user table of %.*s (%.*s:%.*s:%.*s) failed\n",
                                (uint32_t)cbytes_len(table_name), (char *)cbytes_buf(table_name),
                                (uint32_t)cbytes_len(row) , (char *)cbytes_buf(row),
                                (uint32_t)cbytes_len(colf), (char *)cbytes_buf(colf),
                                (uint32_t)cbytes_len(colq), (char *)cbytes_buf(colq));
            cbytes_clean(&user_table_name);
            return (EC_FALSE);
        }
        cbytes_clean(&user_table_name);
#if 0
        dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG]cbgt_fetch: open user table %.*s (%.*s:%.*s:%.*s) in user table %ld:(tcid %s, comm %ld, rank %ld, modi %ld) done\n",
                            (uint32_t)cbytes_len(table_name), (char *)cbytes_buf(table_name),
                            (uint32_t)cbytes_len(row) , (char *)cbytes_buf(row),
                            (uint32_t)cbytes_len(colf), (char *)cbytes_buf(colf),
                            (uint32_t)cbytes_len(colq), (char *)cbytes_buf(colq),
                            user_table_id,
                            MOD_NODE_TCID_STR(&user_mod_node),
                            MOD_NODE_COMM(&user_mod_node),
                            MOD_NODE_RANK(&user_mod_node),
                            MOD_NODE_MODI(&user_mod_node));
#endif
        /*fetch in user table*/
        ret = EC_FALSE;
        task_p2p(cbgt_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                 &user_mod_node,
                 &ret,FI_cbgt_fetch_from_user, CMPI_ERROR_MODI, row, colf, colq, val);
    }while(EC_OBSCURE == ret && ++ count < CBGT_FETCH_TRY_TIMES);

    if(EC_FALSE == ret || EC_OBSCURE == ret)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_fetch: fetch value of table %.*s (%.*s:%.*s:%.*s) in user table %ld:(tcid %s, comm %ld, rank %ld, modi %ld) failed\n",
                            (uint32_t)cbytes_len(table_name), (char *)cbytes_buf(table_name),
                            (uint32_t)cbytes_len(row) , (char *)cbytes_buf(row),
                            (uint32_t)cbytes_len(colf), (char *)cbytes_buf(colf),
                            (uint32_t)cbytes_len(colq), (char *)cbytes_buf(colq),
                            user_table_id,
                            MOD_NODE_TCID_STR(&user_mod_node),
                            MOD_NODE_COMM(&user_mod_node),
                            MOD_NODE_RANK(&user_mod_node),
                            MOD_NODE_MODI(&user_mod_node));
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL __cbgt_fetch(const UINT32 cbgt_md_id, const CBYTES *table_name, const CBYTES *row, const CBYTES *colf, const CBYTES *colq, CBYTES *val)
{
    CBGT_MD    *cbgt_md;

    MOD_NODE   *root_mod_node;
    MOD_NODE    colf_mod_node;
    MOD_NODE    user_mod_node;

    UINT32      colf_table_id;
    UINT32      user_table_id;

    CSTRING     colf_session_path;

    EC_BOOL     ret;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:__cbgt_fetch: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    root_mod_node = CBGT_MD_ROOT_MOD(cbgt_md);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0297);

#if 0
    dbg_log(SEC_0054_CBGT, 5)(LOGSTDOUT, "------------------------------------------ __cbgt_fetch enter ------------------------------------------\n");
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] __cbgt_fetch: table name: %.*s\n", cbytes_len(table_name), (char *)cbytes_buf(table_name));
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] __cbgt_fetch: row       : %.*s\n", cbytes_len(row) , (char *)cbytes_buf(row));
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] __cbgt_fetch: colf      : %.*s\n", cbytes_len(colf), (char *)cbytes_buf(colf));
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] __cbgt_fetch: colq      : %.*s\n", cbytes_len(colq), (char *)cbytes_buf(colq));
#endif
#if 1
    /*get colf table info from session*/
    cstring_init(&colf_session_path, NULL_PTR);
    if(EC_FALSE == __cbgt_get_colf_table_from_session(cbgt_md_id, table_name, colf, &colf_session_path, &colf_table_id, &colf_mod_node))
    {
        CBYTES      user_table_name;

        //dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] __cbgt_fetch: NOT hit colf tabe in session\n");

        cbytes_init(&user_table_name);

        /*open colf table*/
        if(EC_FALSE == cbgt_open_colf_table_from_root(cbgt_md_id, table_name, colf, &colf_table_id, &colf_mod_node))
        {
            dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_fetch: open colf table %.*s of user table %.*s failed\n",
                                (uint32_t)cbytes_len(colf), (char *)cbytes_buf(colf),
                                (uint32_t)cbytes_len(table_name), (char *)cbytes_buf(table_name));
            cstring_clean(&colf_session_path);
            return (EC_FALSE);
        }

        __cbgt_set_colf_table_to_session(cbgt_md_id, &colf_session_path, colf_table_id, &colf_mod_node);

        ret = EC_FALSE;
        task_p2p(cbgt_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                 &colf_mod_node,
                 &ret,FI_cbgt_open_user_table_from_colf, CMPI_ERROR_MODI, row, colf, colq, &user_table_name, &user_table_id, &user_mod_node);

        if(EC_FALSE == ret)
        {
            dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_fetch: open user table of %.*s (%.*s:%.*s:%.*s) from colf table %ld:(tcid %s, comm %ld, rank %ld, modi %ld) failed\n",
                                (uint32_t)cbytes_len(table_name), (char *)cbytes_buf(table_name),
                                (uint32_t)cbytes_len(row) , (char *)cbytes_buf(row),
                                (uint32_t)cbytes_len(colf), (char *)cbytes_buf(colf),
                                (uint32_t)cbytes_len(colq), (char *)cbytes_buf(colq),
                                user_table_id,
                                MOD_NODE_TCID_STR(&colf_mod_node),
                                MOD_NODE_COMM(&colf_mod_node),
                                MOD_NODE_RANK(&colf_mod_node),
                                MOD_NODE_MODI(&colf_mod_node));
            cstring_clean(&colf_session_path);
            cbytes_clean(&user_table_name);
            return (EC_FALSE);
        }

        __cbgt_set_user_table_to_session(cbgt_md_id, &colf_session_path, &user_table_name, user_table_id, &user_mod_node);
        cbytes_clean(&user_table_name);
    }
    else
    {
#if 0
        task_p2p_no_wait(cbgt_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP,
                         &colf_mod_node, NULL_PTR, FI_cbgt_was_access, CMPI_ERROR_MODI);
#endif
#if 0
        dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] __cbgt_fetch: fetched colf table from session: %ld:(tcid %s, comm %ld, rank %ld, modi %ld) done\n",
                        colf_table_id,
                        MOD_NODE_TCID_STR(&colf_mod_node),
                        MOD_NODE_COMM(&colf_mod_node),
                        MOD_NODE_RANK(&colf_mod_node),
                        MOD_NODE_MODI(&colf_mod_node));
#endif
        /*reuse colf_session_path*/
        if(EC_FALSE == __cbgt_get_user_table_from_session(cbgt_md_id, &colf_session_path, row, colf, colq, &user_table_id, &user_mod_node))
        {
            CBYTES      user_table_name;

            //dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] __cbgt_fetch: NOT hit user tabe in session\n");

            cbytes_init(&user_table_name);

            ret = EC_FALSE;
            task_p2p(cbgt_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                     &colf_mod_node,
                     &ret,FI_cbgt_open_user_table_from_colf, CMPI_ERROR_MODI, row, colf, colq, &user_table_name, &user_table_id, &user_mod_node);

            if(EC_FALSE == ret)
            {
                dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_fetch: open user table of %.*s (%.*s:%.*s:%.*s) from colf table %ld:(tcid %s, comm %ld, rank %ld, modi %ld) failed\n",
                                    (uint32_t)cbytes_len(table_name), (char *)cbytes_buf(table_name),
                                    (uint32_t)cbytes_len(row) , (char *)cbytes_buf(row),
                                    (uint32_t)cbytes_len(colf), (char *)cbytes_buf(colf),
                                    (uint32_t)cbytes_len(colq), (char *)cbytes_buf(colq),
                                    user_table_id,
                                    MOD_NODE_TCID_STR(&colf_mod_node),
                                    MOD_NODE_COMM(&colf_mod_node),
                                    MOD_NODE_RANK(&colf_mod_node),
                                    MOD_NODE_MODI(&colf_mod_node));
                cstring_clean(&colf_session_path);
                cbytes_clean(&user_table_name);
                return (EC_FALSE);
            }

            __cbgt_set_user_table_to_session(cbgt_md_id, &colf_session_path, &user_table_name, user_table_id, &user_mod_node);
            cbytes_clean(&user_table_name);
        }
#if 0
        else
        {
            dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] __cbgt_fetch: fetched user table from session: %ld:(tcid %s, comm %ld, rank %ld, modi %ld) done\n",
                                user_table_id,
                                MOD_NODE_TCID_STR(&user_mod_node),
                                MOD_NODE_COMM(&user_mod_node),
                                MOD_NODE_RANK(&user_mod_node),
                                MOD_NODE_MODI(&user_mod_node));
        }
#endif
    }

    /*now user table is lock down*/
    ret = EC_FALSE;
    task_p2p(cbgt_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &user_mod_node,
             &ret,FI_cbgt_fetch_from_user, CMPI_ERROR_MODI, row, colf, colq, val);

    if(EC_OBSCURE == ret)
    {
        /*retire colf session*/
        __cbgt_rmv_colf_table_from_session(cbgt_md_id, &colf_session_path);
    }

    cstring_clean(&colf_session_path);
    return (ret);
#endif
}

EC_BOOL cbgt_fetch(const UINT32 cbgt_md_id, const CBYTES *table_name, const CBYTES *row, const CBYTES *colf, const CBYTES *colq, CBYTES *val)
{
    UINT32      count;

    EC_BOOL     ret;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_fetch: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

#if 0
    dbg_log(SEC_0054_CBGT, 5)(LOGSTDOUT, "------------------------------------------ cbgt_fetch enter ------------------------------------------\n");
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_fetch: table name: %.*s\n", cbytes_len(table_name), (char *)cbytes_buf(table_name));
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_fetch: row       : %.*s\n", cbytes_len(row) , (char *)cbytes_buf(row));
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_fetch: colf      : %.*s\n", cbytes_len(colf), (char *)cbytes_buf(colf));
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_fetch: colq      : %.*s\n", cbytes_len(colq), (char *)cbytes_buf(colq));
#endif
#if 1
    count = 0;
    do
    {
        ret = __cbgt_fetch(cbgt_md_id, table_name, row, colf, colq, val);
        //dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_fetch: ret = %ld\n", ret);
    }while(EC_OBSCURE == ret && ++ count < CBGT_FETCH_TRY_TIMES);

    if(EC_FALSE == ret || EC_OBSCURE == ret)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_fetch: fetch value of table %.*s (%.*s:%.*s:%.*s) failed\n",
                            (uint32_t)cbytes_len(table_name), (char *)cbytes_buf(table_name),
                            (uint32_t)cbytes_len(row) , (char *)cbytes_buf(row),
                            (uint32_t)cbytes_len(colf), (char *)cbytes_buf(colf),
                            (uint32_t)cbytes_len(colq), (char *)cbytes_buf(colq));
        return (EC_FALSE);
    }

#endif
    return (EC_TRUE);
}

EC_BOOL cbgt_delete_from_user(const UINT32 cbgt_md_id, const CBYTES *row, const CBYTES *colf, const CBYTES *colq)
{
    CBGT_MD    *cbgt_md;
    CBYTES      user_rowkey;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_delete_from_user: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0298);

    if(EC_FALSE == __cbgt_make_user_table_key(cbgt_md_id, row, colf, colq, &user_rowkey))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_delete_from_user: make rowkey of (%.*s:%.*s:%.*s) on user table %ld failed\n",
                            (uint32_t)cbytes_len(row) , (char *)cbytes_buf(row),
                            (uint32_t)cbytes_len(colf), (char *)cbytes_buf(colf),
                            (uint32_t)cbytes_len(colq), (char *)cbytes_buf(colq),
                            CBGT_MD_TABLE_ID(cbgt_md));
        return (EC_FALSE);
    }

    CBGT_MD_CRWLOCK_TABLE_WRLOCK(cbgt_md, LOC_CBGT_0299);
    /*confirm deleting in the right user table because the user table covering range will change if split happened*/
    if(EC_FALSE == __cbgt_cmp_colf_row_and_user_table_key(cbytes_buf(CBGT_MD_TABLE_NAME(cbgt_md)), cbytes_buf(&user_rowkey)))
    {
        CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0300);
        dbg_log(SEC_0054_CBGT, 1)(LOGSTDOUT, "warn:cbgt_delete_from_user: user key ");
        __cbgt_print_user_table_key(LOGSTDOUT, cbytes_buf(&user_rowkey));
        sys_print(LOGSTDOUT, " not belong to user table ");
        __cbgt_print_colf_table_row(LOGSTDOUT, cbytes_buf(CBGT_MD_TABLE_NAME(cbgt_md)));
        sys_print(LOGSTDOUT, "\n");
        cbytes_clean(&user_rowkey);
        return (EC_OBSCURE);/*ask caller to try again*/
    }

    if(EC_FALSE == cbgt_delete_kv_no_lock(cbgt_md_id, &user_rowkey))
    {
        CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0301);
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_delete_from_user: delete key of (%.*s:%.*s:%.*s) on table %ld failed\n",
                            (uint32_t)cbytes_len(row) , (char *)cbytes_buf(row),
                            (uint32_t)cbytes_len(colf), (char *)cbytes_buf(colf),
                            (uint32_t)cbytes_len(colq), (char *)cbytes_buf(colq),
                            CBGT_MD_TABLE_ID(cbgt_md));
        cbytes_clean(&user_rowkey);
        return (EC_FALSE);
    }
    CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0302);

    cbytes_clean(&user_rowkey);
    return (EC_TRUE);
}

EC_BOOL cbgt_delete_from_colf(const UINT32 cbgt_md_id, const CBYTES *row, const CBYTES *colf, const CBYTES *colq)
{
    CBGT_MD    *cbgt_md;

    MOD_NODE    colf_mod_node;
    MOD_NODE    user_mod_node;

    UINT32      colf_table_id;
    UINT32      user_table_id;
    CBYTES      user_table_name;

    EC_BOOL     ret;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_delete_from_colf: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    colf_table_id   = CBGT_MD_TABLE_ID(cbgt_md);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0303);

    cbytes_init(&user_table_name);
    if(EC_FALSE == cbgt_open_user_table_from_colf(cbgt_md_id, row, colf, colq, &user_table_name, &user_table_id, &user_mod_node))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_delete_from_colf: open user table for (%.*s:%.*s:%.*s) in colf table %ld failed\n",
                            (uint32_t)cbytes_len(row) , (char *)cbytes_buf(row),
                            (uint32_t)cbytes_len(colf), (char *)cbytes_buf(colf),
                            (uint32_t)cbytes_len(colq), (char *)cbytes_buf(colq),
                            CBGT_MD_TABLE_ID(cbgt_md));
        cbytes_clean(&user_table_name);
        return (EC_FALSE);
    }
    cbytes_clean(&user_table_name);

    __cbgt_local_mod_node(cbgt_md_id, &colf_mod_node);

    /*delete from user table*/
    ret = EC_FALSE;
    task_p2p(cbgt_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &user_mod_node,
             &ret,FI_cbgt_delete_from_user, CMPI_ERROR_MODI, row, colf, colq);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_delete_from_colf: delete (%.*s:%.*s:%.*s) from col table %ld:(tcid %s, comm %ld, rank %ld, modi %ld) failed\n",
                            (uint32_t)cbytes_len(row) , (char *)cbytes_buf(row),
                            (uint32_t)cbytes_len(colf), (char *)cbytes_buf(colf),
                            (uint32_t)cbytes_len(colq), (char *)cbytes_buf(colq),
                            colf_table_id,
                            MOD_NODE_TCID_STR(&colf_mod_node),
                            MOD_NODE_COMM(&colf_mod_node),
                            MOD_NODE_RANK(&colf_mod_node),
                            MOD_NODE_MODI(&colf_mod_node));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cbgt_delete(const UINT32 cbgt_md_id, const CBYTES *table_name, const CBYTES *row, const CBYTES *colf, const CBYTES *colq)
{
    CBGT_MD    *cbgt_md;

    MOD_NODE    user_mod_node;

    UINT32      user_table_id;
    CBYTES      user_table_name;
    UINT32      count;

    EC_BOOL     ret;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_delete: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0304);

    /**
    *   note: why not apply statement: for(ret = EC_OBSCURE, count = 0; count < CBGT_INSERT_TRY_TIMES; count ++)
    *   reason is considering tcid broken scenario. when broken happen, ret is EC_OBSCURE which was initialize,
    *   thus, the loop will continue and try until reach upper limit, but the fact is we should give up immdiately.
    *   hence ret should be initialized as EC_FALSE but not EC_OBSCURE, and we check if ret is EC_OBSCURE when task
    *   comes back. if ret is EC_FALSE, peer found error or broken happend, hence not necessary to try again. if
    *   ret is EC_OBSCURE, peer found entering wrong user table, we can try again
    **/
    cbytes_init(&user_table_name);
    count = 0;
    do
    {
        /*get user table*/
        if(EC_FALSE == cbgt_open_user_table_from_root(cbgt_md_id, table_name, row, colf, colq, &user_table_name, &user_table_id, &user_mod_node))
        {
            dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_delete: open user table of table %.*s (%.*s:%.*s:%.*s) failed\n",
                                (uint32_t)cbytes_len(table_name), (char *)cbytes_buf(table_name),
                                (uint32_t)cbytes_len(row) , (char *)cbytes_buf(row),
                                (uint32_t)cbytes_len(colf), (char *)cbytes_buf(colf),
                                (uint32_t)cbytes_len(colq), (char *)cbytes_buf(colq));
            cbytes_clean(&user_table_name);
            return (EC_FALSE);
        }
        cbytes_clean(&user_table_name);

        /*delete from user table*/
        ret = EC_FALSE;
        task_p2p(cbgt_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                 &user_mod_node,
                 &ret,FI_cbgt_delete_from_user, CMPI_ERROR_MODI, row, colf, colq);
    }while(EC_OBSCURE == ret && ++ count < CBGT_DELETE_TRY_TIMES);

    if(EC_FALSE == ret || EC_OBSCURE == ret)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_delete: delete table %.*s (%.*s:%.*s:%.*s) in user table %ld:(tcid %s, comm %ld, rank %ld, modi %ld) failed\n",
                            (uint32_t)cbytes_len(table_name), (char *)cbytes_buf(table_name),
                            (uint32_t)cbytes_len(row) , (char *)cbytes_buf(row),
                            (uint32_t)cbytes_len(colf), (char *)cbytes_buf(colf),
                            (uint32_t)cbytes_len(colq), (char *)cbytes_buf(colq),
                            user_table_id,
                            MOD_NODE_TCID_STR(&user_mod_node),
                            MOD_NODE_COMM(&user_mod_node),
                            MOD_NODE_RANK(&user_mod_node),
                            MOD_NODE_MODI(&user_mod_node));
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cbgt_cleanup_colf_table_one_kv(const UINT32 cbgt_md_id, const UINT8 *kv)
{
    CBGT_MD    *cbgt_md;

    MOD_NODE    user_mod_node;
    UINT32      user_table_id;

    const uint8_t    *value;
    uint32_t    counter;

    cbgt_md = CBGT_MD_GET(cbgt_md_id);

    value = kvGetValueHs(kv);

    counter = 0;
    user_table_id = gdbGetWord(value, &counter);
    MOD_NODE_TCID(&user_mod_node) = gdbGetWord(value, &counter);
    MOD_NODE_COMM(&user_mod_node) = gdbGetWord(value, &counter);
    MOD_NODE_RANK(&user_mod_node) = gdbGetWord(value, &counter);
    MOD_NODE_MODI(&user_mod_node) = gdbGetWord(value, &counter);
#if 0
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_cleanup_colf_table: user table id %ld (tcid %s, comm %ld, rank %ld, modi %ld)\n",
                       user_table_id,
                       MOD_NODE_TCID_STR(&user_mod_node),
                       MOD_NODE_COMM(&user_mod_node),
                       MOD_NODE_RANK(&user_mod_node),
                       MOD_NODE_MODI(&user_mod_node));
#endif
    if(EC_TRUE == __cbgt_mod_node_is_valid(cbgt_md_id, &user_mod_node))
    {
        __cbgt_end_trigger(cbgt_md_id, &user_mod_node);
    }

    cbgt_unlink(cbgt_md_id, user_table_id);
    cbgt_release_table_id(cbgt_md_id, user_table_id);

    return (EC_TRUE);
}

EC_BOOL cbgt_cleanup_colf_table(const UINT32 cbgt_md_id, const CBYTES *table_name)
{
    CBGT_MD    *cbgt_md;
    CBGT_GDB   *gdb;

    EC_BOOL     ret;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_cleanup_colf_table: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    gdb = CBGT_MD_GDB(cbgt_md);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0305);

    if(EC_FALSE == cbgt_is_colf_server(cbgt_md_id))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_cleanup_colf_table: cbgt module #%ld was not meta server\n", cbgt_md_id);
        return (EC_FALSE);
    }

    if(EC_FALSE == cbytes_cmp(CBGT_MD_TABLE_NAME(cbgt_md), table_name))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_cleanup_colf_table: mismatched table name where %.*s vs %.*s\n",
                           (uint32_t)cbytes_len(table_name), cbytes_buf(table_name),
                           (uint32_t)cbytes_len(CBGT_MD_TABLE_NAME(cbgt_md)), cbytes_buf(CBGT_MD_TABLE_NAME(cbgt_md)));
        return (EC_FALSE);
    }

    ret = EC_FALSE;
    if(EC_FALSE == cbtree_scan(CBGT_GDB_CBTREE(gdb),
                        (void *)&ret, (C_RETVAL_CHECKER)c_checker_default,
                        (UINT32)2,
                        (UINT32)1,
                        (UINT32)__cbgt_cleanup_colf_table_one_kv,
                        cbgt_md_id,
                        NULL_PTR))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_cleanup_colf_table: scan and clean colf tables failed\n");
        return (EC_FALSE);
    }

    cbtree_clean(CBGT_GDB_CBTREE(gdb));
    CBGT_GDB_CBTREE(gdb) = NULL_PTR;

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cbgt_cleanup_meta_table_one_kv(const UINT32 cbgt_md_id, const UINT8 *kv)
{
    CBGT_MD    *cbgt_md;

    CBYTES      colf_table_name;
    MOD_NODE    colf_mod_node;
    UINT32      colf_table_id;
    EC_BOOL     ret;

    cbgt_md = CBGT_MD_GET(cbgt_md_id);

    cbytes_init(&colf_table_name);
    cbytes_mount(&colf_table_name, kvGetrLenHs(kv), kvGetRowHs(kv));

    if(EC_FALSE == __cbgt_open_rmc_table(cbgt_md_id, CBGT_TYPE_COLF_SERVER, &colf_table_name, &colf_table_id, &colf_mod_node))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_cleanup_meta_table_one_kv: open colf table on meta table %ld failed where colf table is ",
                            CBGT_MD_TABLE_ID(cbgt_md));
        __cbgt_print_meta_table_key(LOGSTDOUT, kv);
        sys_print(LOGSTDOUT, "\n");
        cbytes_clean(&colf_table_name);
        return (EC_FALSE);
    }

    ret = EC_FALSE;
    task_p2p(cbgt_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &colf_mod_node,
             &ret, FI_cbgt_cleanup_colf_table, CMPI_ERROR_MODI, &colf_table_name);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_cleanup_meta_table_one_kv: delete colf table from meta table %ld failed where colf table is \n",
                            CBGT_MD_TABLE_ID(cbgt_md)
                            );
        __cbgt_print_meta_table_key(LOGSTDOUT, kv);
        sys_print(LOGSTDOUT, "\n");
        cbytes_clean(&colf_table_name);
        return (EC_FALSE);
    }

    __cbgt_end_trigger(cbgt_md_id, &colf_mod_node);/*stop colf server*/
    cbgt_unlink(cbgt_md_id, colf_table_id);      /*delete colf table*/

    cbytes_umount(&colf_table_name, NULL_PTR, NULL_PTR);

    cbgt_release_table_id(cbgt_md_id, colf_table_id);

    return (EC_TRUE);
}

EC_BOOL cbgt_cleanup_meta_table(const UINT32 cbgt_md_id, const CBYTES *table_name)
{
    CBGT_MD    *cbgt_md;
    CBGT_GDB   *gdb;

    EC_BOOL     ret;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_cleanup_meta_table: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    gdb = CBGT_MD_GDB(cbgt_md);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0306);

    if(EC_FALSE == cbgt_is_meta_server(cbgt_md_id))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_cleanup_meta_table: cbgt module #%ld was not meta server\n", cbgt_md_id);
        return (EC_FALSE);
    }

    if(EC_FALSE == cbytes_cmp(CBGT_MD_TABLE_NAME(cbgt_md), table_name))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_cleanup_meta_table: mismatched table name where %.*s vs %.*s\n",
                           (uint32_t)cbytes_len(table_name), cbytes_buf(table_name),
                           (uint32_t)cbytes_len(CBGT_MD_TABLE_NAME(cbgt_md)), cbytes_buf(CBGT_MD_TABLE_NAME(cbgt_md))
                           );
        return (EC_FALSE);
    }

    ret = EC_FALSE;
    if(EC_FALSE == cbtree_scan(CBGT_GDB_CBTREE(gdb),
                        (void *)&ret, (C_RETVAL_CHECKER)c_checker_default,
                        (UINT32)2,
                        (UINT32)1,
                        (UINT32)__cbgt_cleanup_meta_table_one_kv,
                        cbgt_md_id,
                        NULL_PTR))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_cleanup_meta_table: scan and clean meta tables failed\n");
        return (EC_FALSE);
    }

    cbtree_clean(CBGT_GDB_CBTREE(gdb));
    CBGT_GDB_CBTREE(gdb) = NULL_PTR;

    return (EC_TRUE);
}

EC_BOOL cbgt_delete_user_table(const UINT32 cbgt_md_id, const CBYTES *table_name)
{
    CBGT_MD    *cbgt_md;

    MOD_NODE    meta_mod_node;

    UINT32      meta_table_id;

    CBYTES      root_rowkey;

    EC_BOOL     ret;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_delete_user_table: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0307);

    if(EC_FALSE == cbgt_is_root_server(cbgt_md_id))
    {
        ret = EC_FALSE;
        task_p2p(cbgt_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                 CBGT_MD_ROOT_MOD(cbgt_md),
                 &ret, FI_cbgt_delete_user_table, CMPI_ERROR_MODI, table_name);
        if(EC_FALSE == ret)
        {
            dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_delete_user_table: delete user table %.*s from table %ld type %s failed\n",
                                (uint32_t)cbytes_len(table_name), (char *)cbytes_buf(table_name),
                                CBGT_MD_TABLE_ID(cbgt_md), __cbgt_type(CBGT_MD_TYPE(cbgt_md))
                                );
            return (EC_FALSE);
        }
        return (EC_TRUE);
    }

    if(EC_FALSE == __cbgt_open_rmc_table(cbgt_md_id, CBGT_TYPE_META_SERVER, table_name, &meta_table_id, &meta_mod_node))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_delete_user_table: open meta table %.*s on root table %ld failed\n",
                            (uint32_t)cbytes_len(table_name), (char *)cbytes_buf(table_name),
                            CBGT_MD_TABLE_ID(cbgt_md));
        return (EC_FALSE);
    }

    ret = EC_FALSE;
    task_p2p(cbgt_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &meta_mod_node,
             &ret, FI_cbgt_cleanup_meta_table, CMPI_ERROR_MODI, table_name);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_delete_user_table: delete meta table %.*s from root table %ld failed\n",
                            (uint32_t)cbytes_len(table_name), (char *)cbytes_buf(table_name),
                            CBGT_MD_TABLE_ID(cbgt_md)
                            );
        return (EC_FALSE);
    }

    __cbgt_end_trigger(cbgt_md_id, &meta_mod_node);/*stop meta server*/
    cbgt_unlink(cbgt_md_id, meta_table_id);      /*delete meta table*/

    if(EC_FALSE == __cbgt_make_root_table_key(cbgt_md_id, table_name, &root_rowkey))/*delete meta register info*/
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_delete_user_table: make rowkey of root table failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cbgt_delete_kv(cbgt_md_id, &root_rowkey))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_delete_user_table: delete user table %.*s register from cbgt %ld table %ld failed\n",
                            (uint32_t)cbytes_len(table_name), (char *)cbytes_buf(table_name),
                            cbgt_md_id, CBGT_MD_TABLE_ID(cbgt_md));
        cbytes_clean(&root_rowkey);
        return (EC_FALSE);
    }
    cbytes_clean(&root_rowkey);

    cbgt_release_table_id(cbgt_md_id, meta_table_id);

    return (EC_TRUE);
}

EC_BOOL cbgt_delete_colf_table(const UINT32 cbgt_md_id, const CBYTES *table_name, const CBYTES *colf_name)
{
    CBGT_MD    *cbgt_md;

    EC_BOOL     ret;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_delete_colf_table: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0308);

    if(EC_FALSE == cbgt_is_root_server(cbgt_md_id)
    && EC_FALSE == cbgt_is_meta_server(cbgt_md_id))
    {
        ret = EC_FALSE;
        task_p2p(cbgt_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                 CBGT_MD_ROOT_MOD(cbgt_md),
                 &ret, FI_cbgt_delete_colf_table, CMPI_ERROR_MODI, table_name, colf_name);
        if(EC_FALSE == ret)
        {
            dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_delete_colf_table: delete colf table %.*s:%.*s from table %ld type %s failed\n",
                                (uint32_t)cbytes_len(table_name), (char *)cbytes_buf(table_name),
                                (uint32_t)cbytes_len(colf_name), (char *)cbytes_buf(colf_name),
                                CBGT_MD_TABLE_ID(cbgt_md), __cbgt_type(CBGT_MD_TYPE(cbgt_md))
                                );
            return (EC_FALSE);
        }
        return (EC_TRUE);
    }

    if(EC_TRUE == cbgt_is_root_server(cbgt_md_id))
    {
        MOD_NODE    meta_mod_node;
        UINT32      meta_table_id;

        if(EC_FALSE == __cbgt_open_rmc_table(cbgt_md_id, CBGT_TYPE_META_SERVER, table_name, &meta_table_id, &meta_mod_node))
        {
            dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_delete_colf_table: open meta table %.*s on root table %ld failed\n",
                                (uint32_t)cbytes_len(table_name), (char *)cbytes_buf(table_name),
                                CBGT_MD_TABLE_ID(cbgt_md));
            return (EC_FALSE);
        }

        /*ask meta table to do*/
        ret = EC_FALSE;
        task_p2p(cbgt_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                 &meta_mod_node,
                 &ret, FI_cbgt_delete_colf_table, CMPI_ERROR_MODI, table_name, colf_name);
        if(EC_FALSE == ret)
        {
            dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_delete_colf_table: delete colf table %.*s:%.*s from root table %ld failed\n",
                                (uint32_t)cbytes_len(table_name), (char *)cbytes_buf(table_name),
                                (uint32_t)cbytes_len(colf_name), (char *)cbytes_buf(colf_name),
                                CBGT_MD_TABLE_ID(cbgt_md)
                                );
            return (EC_FALSE);
        }
        return (EC_TRUE);
    }

    if(EC_TRUE == cbgt_is_meta_server(cbgt_md_id))
    {
        MOD_NODE    colf_mod_node;
        UINT32      colf_table_id;
        CBYTES      meta_rowkey;

        if(EC_FALSE == __cbgt_open_rmc_table(cbgt_md_id, CBGT_TYPE_COLF_SERVER, colf_name, &colf_table_id, &colf_mod_node))
        {
            dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_delete_colf_table: open colf table %.*s on meta table %ld failed\n",
                                (uint32_t)cbytes_len(colf_name), (char *)cbytes_buf(colf_name),
                                CBGT_MD_TABLE_ID(cbgt_md));
            return (EC_FALSE);
        }

        ret = EC_FALSE;
        task_p2p(cbgt_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                 &colf_mod_node,
                 &ret, FI_cbgt_cleanup_colf_table, CMPI_ERROR_MODI, colf_name);
        if(EC_FALSE == ret)
        {
            dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_delete_colf_table: delete colf table %.*s:%.*s from root table %ld failed\n",
                                (uint32_t)cbytes_len(table_name), (char *)cbytes_buf(table_name),
                                (uint32_t)cbytes_len(colf_name), (char *)cbytes_buf(colf_name),
                                CBGT_MD_TABLE_ID(cbgt_md)
                                );
            return (EC_FALSE);
        }

        __cbgt_end_trigger(cbgt_md_id, &colf_mod_node);/*stop colf server*/
        cbgt_unlink(cbgt_md_id, colf_table_id);      /*delete colf table*/

        if(EC_FALSE == __cbgt_make_meta_table_key(cbgt_md_id, colf_name, &meta_rowkey))
        {
            dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_delete_colf_table: make rowkey from colf %.*s of cbgt %ld meta table %ld\n",
                                (uint32_t)cbytes_len(colf_name), (char *)cbytes_buf(colf_name),
                                cbgt_md_id, CBGT_MD_TABLE_ID(cbgt_md));
            return (EC_FALSE);
        }

        if(EC_FALSE == cbgt_delete_kv(cbgt_md_id, &meta_rowkey))/*delete colf register info*/
        {
            dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_delete_colf_table: delete colf table %.*s register from cbgt %ld table %ld failed\n",
                                (uint32_t)cbytes_len(colf_name), (char *)cbytes_buf(colf_name),
                                cbgt_md_id, CBGT_MD_TABLE_ID(cbgt_md));
            cbytes_clean(&meta_rowkey);
            return (EC_FALSE);
        }
        cbytes_clean(&meta_rowkey);

        cbgt_release_table_id(cbgt_md_id, colf_table_id);

        return (EC_TRUE);
    }

    return (EC_TRUE);
}

EC_BOOL cbgt_add_colf_table(const UINT32 cbgt_md_id, const CBYTES *table_name, const CBYTES *colf_name)
{
    CBGT_MD    *cbgt_md;

    UINT32      meta_table_id;
    MOD_NODE    meta_mod_node;

    EC_BOOL     ret;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_add_colf_table: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0309);

    if(EC_FALSE == cbgt_is_root_server(cbgt_md_id))
    {
        ret = EC_FALSE;
        task_p2p(cbgt_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                 CBGT_MD_ROOT_MOD(cbgt_md),
                 &ret, FI_cbgt_add_colf_table, CMPI_ERROR_MODI, table_name, colf_name);
        if(EC_FALSE == ret)
        {
            dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_add_colf_table: add colf table %.*s:%.*s from table %ld type %s failed\n",
                                (uint32_t)cbytes_len(table_name), (char *)cbytes_buf(table_name),
                                (uint32_t)cbytes_len(colf_name), (char *)cbytes_buf(colf_name),
                                CBGT_MD_TABLE_ID(cbgt_md), __cbgt_type(CBGT_MD_TYPE(cbgt_md))
                                );
            return (EC_FALSE);
        }
        return (EC_TRUE);
    }

    if(EC_FALSE == __cbgt_open_rmc_table(cbgt_md_id, CBGT_TYPE_META_SERVER, table_name, &meta_table_id, &meta_mod_node))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_add_colf_table: open meta table %.*s on root table %ld failed\n",
                            (uint32_t)cbytes_len(table_name), (char *)cbytes_buf(table_name),
                            CBGT_MD_TABLE_ID(cbgt_md));
        return (EC_FALSE);
    }

    /*ask meta table to do*/
    ret = EC_FALSE;
    task_p2p(cbgt_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &meta_mod_node,
             &ret, FI_cbgt_create_colf_on_meta, CMPI_ERROR_MODI, colf_name);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_add_colf_table: add colf table %.*s:%.*s from root table %ld failed\n",
                            (uint32_t)cbytes_len(table_name), (char *)cbytes_buf(table_name),
                            (uint32_t)cbytes_len(colf_name), (char *)cbytes_buf(colf_name),
                            CBGT_MD_TABLE_ID(cbgt_md)
                            );
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

STATIC_CAST static void __cbgt_kvPrintHs(LOG *log, CBYTES *kv_cbytes)
{
    kvPrintHs(log, cbytes_buf(kv_cbytes));
    return;
}

STATIC_CAST static EC_BOOL __cbgt_pcre_compile(const CSTRING *pattern_cstr, pcre **pattern_re)
{
    pcre *re;
    const char *errstr;
    int erroffset;

    if(EC_TRUE == cstring_is_empty(pattern_cstr))
    {
        (*pattern_re) = NULL_PTR;
        return (EC_TRUE);
    }

    re = pcre_compile((char *)cstring_get_str(pattern_cstr), 0, &errstr, &erroffset, NULL_PTR);
    if(NULL_PTR == re)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_pcre_compile: pcre compile pattern %s at %d:%s failed\n",
                            (char *)cstring_get_str(pattern_cstr), erroffset, errstr);
        return (EC_FALSE);
    }

    (*pattern_re) = re;
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cbgt_pcre_free(pcre *pattern_re)
{
    if(NULL_PTR != pattern_re)
    {
        pcre_free(pattern_re);
    }
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cbgt_select_from_table(const UINT32 cbgt_md_id, const UINT8 *kv, int (*kv_regex)(const uint8_t *, pcre *, pcre *, pcre *,pcre *),
                                                pcre *row_re, pcre *colf_re, pcre *colq_re, pcre *val_re, CVECTOR *kv_vec)
{
    if(0 != kv_regex(kv, row_re, colf_re, colq_re, val_re))
    {
        CBYTES *kv_bytes;
        /*matched*/
        //dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] __cbgt_select_from_table: matched kv %p\n", kv);

        kv_bytes = cbytes_new(0);
        if(NULL == kv_bytes)
        {
            dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:__cbgt_select_from_table: new kv cbytes failed\n");
            return (EC_FALSE);
        }

        cbytes_set(kv_bytes, kv, kvGettLenHs(kv));
        cvector_push(kv_vec, (void *)kv_bytes);
    }
    return (EC_TRUE);
}

EC_BOOL cbgt_select_from_user(const UINT32 cbgt_md_id, const CSTRING *row_pattern, const CSTRING *colf_pattern, const CSTRING *colq_pattern, const CSTRING *val_pattern, CVECTOR *ret_kv_vec)
{
    CBGT_MD    *cbgt_md;
    CBGT_GDB   *gdb;
    EC_BOOL     ret;

    pcre *row_re;
    pcre *colf_re;
    pcre *colq_re;
    pcre *val_re;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_select_from_user: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md     = CBGT_MD_GET(cbgt_md_id);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0310);

    if(EC_FALSE == __cbgt_pcre_compile(row_pattern, &row_re))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_select_from_user: pcre compile row pattern %s failed\n",
                            (char *)cstring_get_str(row_pattern));
        return (EC_FALSE);
    }

    if(EC_FALSE == __cbgt_pcre_compile(colf_pattern, &colf_re))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_select_from_user: pcre compile colf pattern %s failed\n",
                            (char *)cstring_get_str(colf_pattern));
        __cbgt_pcre_free(row_re);
        return (EC_FALSE);
    }

    if(EC_FALSE == __cbgt_pcre_compile(colq_pattern, &colq_re))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_select_from_user: pcre compile colq pattern %s failed\n",
                            (char *)cstring_get_str(colq_pattern));
        __cbgt_pcre_free(row_re);
        __cbgt_pcre_free(colf_re);
        return (EC_FALSE);
    }

     if(EC_FALSE == __cbgt_pcre_compile(val_pattern, &val_re))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_select_from_user: pcre compile val pattern %s failed\n",
                            (char *)cstring_get_str(val_pattern));
        __cbgt_pcre_free(row_re);
        __cbgt_pcre_free(colf_re);
        __cbgt_pcre_free(colq_re);
        return (EC_FALSE);
    }

    CBGT_MD_CRWLOCK_TABLE_RDLOCK(cbgt_md, LOC_CBGT_0311);
    gdb = CBGT_MD_GDB(cbgt_md);

    ret = EC_FALSE;
    if(EC_FALSE == cbtree_scan(CBGT_GDB_CBTREE(gdb),
                        (void *)&ret, (C_RETVAL_CHECKER)c_checker_default,
                        (UINT32)8,
                        (UINT32)1,
                        (UINT32)__cbgt_select_from_table,
                        cbgt_md_id,
                        NULL_PTR,
                        kvRegex,
                        row_re, colf_re, colq_re, val_re, ret_kv_vec
                        ))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_select_from_user: scan and select from user table failed\n");
        CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0312);
        __cbgt_pcre_free(row_re);
        __cbgt_pcre_free(colf_re);
        __cbgt_pcre_free(colq_re);
        __cbgt_pcre_free(val_re);
        return (EC_FALSE);
    }

    CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0313);
    if(do_log(SEC_0054_CBGT, 9))
    {
        dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_select_from_user: ret_kv_vec is\n");
        cvector_print_no_lock(LOGSTDOUT, ret_kv_vec, (CVECTOR_DATA_PRINT)__cbgt_kvPrintHs);
    }

    __cbgt_pcre_free(row_re);
    __cbgt_pcre_free(colf_re);
    __cbgt_pcre_free(colq_re);
    __cbgt_pcre_free(val_re);
    return (EC_TRUE);
}

EC_BOOL cbgt_select_from_colf(const UINT32 cbgt_md_id, const UINT32 cached_mode, const CSTRING *row_pattern, const CSTRING *colf_pattern, const CSTRING *colq_pattern, const CSTRING *val_pattern, CVECTOR *ret_kv_vec)
{
    CBGT_MD    *cbgt_md;
    CBGT_GDB   *gdb;

    TASK_MGR   *task_mgr;
    CVECTOR    *colf_kv_vec;

    CVECTOR    *report_vec;
    UINT32      pos;
    EC_BOOL     ret;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_select_from_colf: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md     = CBGT_MD_GET(cbgt_md_id);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0314);

    colf_kv_vec = cvector_new(0, MM_CBYTES, LOC_CBGT_0315);
    if(NULL_PTR == colf_kv_vec)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_select_from_colf: new colf table kv vec failed\n");
        return (EC_FALSE);
    }

    CBGT_MD_CRWLOCK_TABLE_RDLOCK(cbgt_md, LOC_CBGT_0316);
    gdb = CBGT_MD_GDB(cbgt_md);
    ret = EC_FALSE;
    cbtree_scan(CBGT_GDB_CBTREE(gdb),
                        (void *)&ret, (C_RETVAL_CHECKER)c_checker_default,
                        (UINT32)8,
                        (UINT32)1,
                        (UINT32)__cbgt_select_from_table,
                        cbgt_md_id,
                        NULL_PTR,
                        kvRegex,
                        NULL_PTR, NULL_PTR, NULL_PTR, NULL_PTR, colf_kv_vec
                        );
    CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0317);

    if(0 == cvector_size(colf_kv_vec))
    {
        dbg_log(SEC_0054_CBGT, 1)(LOGSTDOUT, "warn:cbgt_select_from_colf: no matching colf table\n");
        cvector_free(colf_kv_vec, LOC_CBGT_0318);
        return (EC_TRUE);
    }

    report_vec = cvector_new(0, MM_CVECTOR, LOC_CBGT_0319);
    if(NULL_PTR == report_vec)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_select_from_colf: new report vec failed\n");
        cvector_clean(colf_kv_vec, (CVECTOR_DATA_CLEANER)cbytes_free, LOC_CBGT_0320);
        cvector_free(colf_kv_vec, LOC_CBGT_0321);
        return (EC_FALSE);
    }

    task_mgr = task_new(NULL_PTR, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);

    for(pos = 0; pos < cvector_size(colf_kv_vec); pos ++)
    {
        CBYTES     *colf_kv_bytes;

        MOD_NODE    user_mod_node;
        UINT32      user_table_id;

        const uint8_t  *value;
        uint32_t        counter;

        colf_kv_bytes = (CBYTES *)cvector_get_no_lock(colf_kv_vec, pos);
        if(NULL_PTR == colf_kv_bytes)
        {
            continue;
        }

        value = kvGetValueHs(cbytes_buf(colf_kv_bytes));

        counter = 0;
        user_table_id = gdbGetWord(value, &counter);
        MOD_NODE_TCID(&user_mod_node) = gdbGetWord(value, &counter);
        MOD_NODE_COMM(&user_mod_node) = gdbGetWord(value, &counter);
        MOD_NODE_RANK(&user_mod_node) = gdbGetWord(value, &counter);
        MOD_NODE_MODI(&user_mod_node) = gdbGetWord(value, &counter);
#if 0
        sys_print(LOGSTDOUT, "[DEBUG]cbgt_select_from_colf:user table id %ld, (tcid %s, comm %ld, rank %ld, modi %ld)\n",
                            user_table_id,
                            MOD_NODE_TCID_STR(&user_mod_node),
                            MOD_NODE_COMM(&user_mod_node),
                            MOD_NODE_RANK(&user_mod_node),
                            MOD_NODE_MODI(&user_mod_node)
                            );
#endif
        if(EC_FALSE == CBGT_CHECK_TABLE_EXIST(cbgt_md_id, user_table_id, &user_mod_node)
        && CBGT_SELECT_FROM_ALL_TABLE == cached_mode)
        {
            MOD_NODE colf_mod_node;
            CBYTES   user_table_name;

            cbytes_init(&user_table_name);
            cbytes_mount(&user_table_name, kvGetrLenHs(cbytes_buf(colf_kv_bytes)), kvGetRowHs(cbytes_buf(colf_kv_bytes)));

            __cbgt_local_mod_node(cbgt_md_id, &colf_mod_node);
            if(EC_FALSE == __cbgt_start_trigger(cbgt_md_id,
                                                CBGT_TYPE_USER_SERVER,
                                                user_table_id,
                                                &user_table_name,
                                                &colf_mod_node,
                                                CBGT_MD_ROOT_PATH(cbgt_md),
                                                CBGT_O_RDWR,
                                                &user_mod_node))
            {
                dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_select_from_colf: cbgt start user table %ld on colf table %ld failed\n",
                                    user_table_id, CBGT_MD_TABLE_ID(cbgt_md));
                continue;
            }
            /*WARNING: we start the user server without registering into colf or without end it later, it is dangerous*/
            /*         if register it here, we have to save "offset" info when scan colf table*/

            /*update register info of user table*/
            if(EC_FALSE == cbgt_update_register(cbgt_md_id, colf_kv_bytes, user_table_id, &user_mod_node))
            {
                dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_select_from_colf: update register of user table %.*s id %ld (tcid %s, comm %ld, rank %ld, modi %ld) "
                                    "to colf table %ld failed\n",
                                   (uint32_t)cbytes_len(&user_table_name), (char *)cbytes_buf(&user_table_name),
                                   user_table_id,
                                   MOD_NODE_TCID_STR(&user_mod_node), MOD_NODE_COMM(&user_mod_node), MOD_NODE_RANK(&user_mod_node), MOD_NODE_MODI(&user_mod_node),
                                   CBGT_MD_TABLE_ID(cbgt_md));
                continue;
            }

        }

        if(EC_TRUE == __cbgt_mod_node_is_valid(cbgt_md_id, &user_mod_node))
        {
            CVECTOR *user_table_kv_vec;
            EC_BOOL  ret;

            user_table_kv_vec = cvector_new(0, MM_CBYTES, LOC_CBGT_0322);
            if(NULL_PTR == user_table_kv_vec)
            {
                dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_select_from_colf: new user table kv vec failed\n");
                break;
            }
#if 0
            dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_select_from_colf: user_table_kv_vec addr %p (%ld)\n", user_table_kv_vec, user_table_kv_vec);
#endif
            /*select from cached colf table*/
            ret = EC_FALSE;
            task_p2p_inc(task_mgr, cbgt_md_id, &user_mod_node,
                         &ret, FI_cbgt_select_from_user, CMPI_ERROR_MODI,
                         row_pattern, colf_pattern, colq_pattern, val_pattern,
                         user_table_kv_vec);

            cvector_push_no_lock(report_vec, (void *)user_table_kv_vec);
        }
    }

    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    cvector_clean(colf_kv_vec, (CVECTOR_DATA_CLEANER)cbytes_free, LOC_CBGT_0323);
    cvector_free(colf_kv_vec, LOC_CBGT_0324);

    for(pos = 0; pos < cvector_size(report_vec); pos ++)
    {
        CVECTOR *user_table_kv_vec;

        user_table_kv_vec = (CVECTOR *)cvector_get_no_lock(report_vec, pos);
        if(NULL_PTR == user_table_kv_vec)
        {
            continue;
        }

        cvector_merge_with_move(user_table_kv_vec, ret_kv_vec, NULL_PTR);

        cvector_clean_no_lock(user_table_kv_vec, (CVECTOR_DATA_CLEANER)cbytes_free, LOC_CBGT_0325);
        cvector_free_no_lock(user_table_kv_vec, LOC_CBGT_0326);
        cvector_set_no_lock(report_vec, pos, NULL_PTR);
    }

    cvector_free_no_lock(report_vec, LOC_CBGT_0327);

    return (EC_TRUE);
}

EC_BOOL cbgt_select_from_meta(const UINT32 cbgt_md_id, const UINT32 cached_mode, const CSTRING *row_pattern, const CSTRING *colf_pattern, const CSTRING *colq_pattern, const CSTRING *val_pattern, CVECTOR *ret_kv_vec)
{
    CBGT_MD    *cbgt_md;
    CBGT_GDB  *gdb;

    pcre *colf_re;

    TASK_MGR   *task_mgr;
    CVECTOR    *meta_kv_vec;

    CVECTOR    *report_vec;

    UINT32      pos;
    EC_BOOL     ret;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_select_from_meta: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md     = CBGT_MD_GET(cbgt_md_id);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0328);

    if(EC_FALSE == __cbgt_pcre_compile(colf_pattern, &colf_re))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_select_from_meta: pcre compile colf pattern %s failed\n",
                            (char *)cstring_get_str(colf_pattern));
        return (EC_FALSE);
    }

    meta_kv_vec = cvector_new(0, MM_CBYTES, LOC_CBGT_0329);
    if(NULL_PTR == meta_kv_vec)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_select_from_meta: new meta table kv vec failed\n");
        __cbgt_pcre_free(colf_re);
        return (EC_FALSE);
    }

    CBGT_MD_CRWLOCK_TABLE_RDLOCK(cbgt_md, LOC_CBGT_0330);
    gdb = CBGT_MD_GDB(cbgt_md);
    /*note: colf is the row of meta table*/
    ret = EC_FALSE;
    cbtree_scan(CBGT_GDB_CBTREE(gdb),
                        (void *)&ret, (C_RETVAL_CHECKER)c_checker_default,
                        (UINT32)8,
                        (UINT32)1,
                        (UINT32)__cbgt_select_from_table,
                        cbgt_md_id,
                        NULL_PTR,
                        kvRegex,
                        colf_re, NULL_PTR, NULL_PTR, NULL_PTR, meta_kv_vec
                        );
    CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0331);

    __cbgt_pcre_free(colf_re);

    if(0 == cvector_size(meta_kv_vec))
    {
        dbg_log(SEC_0054_CBGT, 1)(LOGSTDOUT, "warn:cbgt_select_from_meta: no matching colf table\n");
        cvector_clean(meta_kv_vec, (CVECTOR_DATA_CLEANER)cbytes_free, LOC_CBGT_0332);
        cvector_free(meta_kv_vec, LOC_CBGT_0333);
        return (EC_TRUE);
    }

    report_vec = cvector_new(0, MM_CVECTOR, LOC_CBGT_0334);
    if(NULL_PTR == report_vec)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_select_from_meta: new report vec failed\n");
        cvector_clean(meta_kv_vec, (CVECTOR_DATA_CLEANER)cbytes_free, LOC_CBGT_0335);
        cvector_free(meta_kv_vec, LOC_CBGT_0336);
        return (EC_FALSE);
    }

    task_mgr = task_new(NULL_PTR, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);

    for(pos = 0; pos < cvector_size(meta_kv_vec); pos ++)
    {
        CBYTES     *meta_kv_bytes;

        MOD_NODE    colf_mod_node;
        UINT32      colf_table_id;

        const uint8_t  *value;
        uint32_t        counter;

        meta_kv_bytes = (CBYTES *)cvector_get_no_lock(meta_kv_vec, pos);
        if(NULL_PTR == meta_kv_bytes)
        {
            continue;
        }

        value = kvGetValueHs(cbytes_buf(meta_kv_bytes));

        counter = 0;
        colf_table_id = gdbGetWord(value, &counter);
        MOD_NODE_TCID(&colf_mod_node) = gdbGetWord(value, &counter);
        MOD_NODE_COMM(&colf_mod_node) = gdbGetWord(value, &counter);
        MOD_NODE_RANK(&colf_mod_node) = gdbGetWord(value, &counter);
        MOD_NODE_MODI(&colf_mod_node) = gdbGetWord(value, &counter);
#if 0
        dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG]cbgt_select_from_meta:colf table id %ld, (tcid %s, comm %ld, rank %ld, modi %ld)\n",
                            colf_table_id,
                            MOD_NODE_TCID_STR(&colf_mod_node),
                            MOD_NODE_COMM(&colf_mod_node),
                            MOD_NODE_RANK(&colf_mod_node),
                            MOD_NODE_MODI(&colf_mod_node)
                            );
#endif
        if(EC_FALSE == CBGT_CHECK_TABLE_EXIST(cbgt_md_id, colf_table_id, &colf_mod_node)
        && CBGT_SELECT_FROM_ALL_TABLE == cached_mode)
        {
            MOD_NODE meta_mod_node;
            CBYTES   colf_table_name;

            cbytes_init(&colf_table_name);
            cbytes_mount(&colf_table_name, kvGetrLenHs(cbytes_buf(meta_kv_bytes)), kvGetRowHs(cbytes_buf(meta_kv_bytes)));

            __cbgt_local_mod_node(cbgt_md_id, &meta_mod_node);
            if(EC_FALSE == __cbgt_start_trigger(cbgt_md_id,
                                                CBGT_TYPE_COLF_SERVER,
                                                colf_table_id,
                                                &colf_table_name,
                                                &meta_mod_node,
                                                CBGT_MD_ROOT_PATH(cbgt_md),
                                                CBGT_O_RDWR,
                                                &colf_mod_node))
            {
                dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_select_from_meta: cbgt start colf table %ld on meta table %ld failed\n",
                                    colf_table_id, CBGT_MD_TABLE_ID(cbgt_md));
                continue;
            }

            /*WARNING: we start the colf server without registering into meta or without end it later, it is dangerous*/
            /*         if register it here, we have to save "offset" info when scan meta table*/

            /*update register info of user table*/
            if(EC_FALSE == cbgt_update_register(cbgt_md_id, meta_kv_bytes, colf_table_id, &colf_mod_node))
            {
                dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_select_from_meta: update register of colf table %.*s id %ld (tcid %s, comm %ld, rank %ld, modi %ld) "
                                    "to meta table %ld failed\n",
                                   (uint32_t)cbytes_len(&colf_table_name), (char *)cbytes_buf(&colf_table_name),
                                   colf_table_id,
                                   MOD_NODE_TCID_STR(&colf_mod_node), MOD_NODE_COMM(&colf_mod_node), MOD_NODE_RANK(&colf_mod_node), MOD_NODE_MODI(&colf_mod_node),
                                   CBGT_MD_TABLE_ID(cbgt_md));
                continue;
            }
        }

        if(EC_TRUE == __cbgt_mod_node_is_valid(cbgt_md_id, &colf_mod_node))
        {
            CVECTOR *user_table_kv_vec;
            EC_BOOL  ret;

            user_table_kv_vec = cvector_new(0, MM_CBYTES, LOC_CBGT_0337);
            if(NULL_PTR == user_table_kv_vec)
            {
                dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_select_from_meta: new user table kv vec failed\n");
                break;
            }

            /*select from cached colf table*/
            ret = EC_FALSE;
            task_p2p_inc(task_mgr, cbgt_md_id, &colf_mod_node,
                         &ret, FI_cbgt_select_from_colf, CMPI_ERROR_MODI, cached_mode,
                         row_pattern, colf_pattern, colq_pattern, val_pattern,
                         user_table_kv_vec);

            cvector_push_no_lock(report_vec, (void *)user_table_kv_vec);
        }
    }

    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    cvector_clean(meta_kv_vec, (CVECTOR_DATA_CLEANER)cbytes_free, LOC_CBGT_0338);
    cvector_free(meta_kv_vec, LOC_CBGT_0339);

    for(pos = 0; pos < cvector_size(report_vec); pos ++)
    {
        CVECTOR *user_table_kv_vec;

        user_table_kv_vec = (CVECTOR *)cvector_get_no_lock(report_vec, pos);
        if(NULL_PTR == user_table_kv_vec)
        {
            continue;
        }

        cvector_merge_with_move(user_table_kv_vec, ret_kv_vec, NULL_PTR);

        cvector_clean_no_lock(user_table_kv_vec, (CVECTOR_DATA_CLEANER)cbytes_free, LOC_CBGT_0340);
        cvector_free_no_lock(user_table_kv_vec, LOC_CBGT_0341);
        cvector_set_no_lock(report_vec, pos, NULL_PTR);
    }

    cvector_free_no_lock(report_vec, LOC_CBGT_0342);

    return (EC_TRUE);
}

EC_BOOL cbgt_select_from_root(const UINT32 cbgt_md_id, const UINT32 cached_mode, const CSTRING *table_pattern, const CSTRING *row_pattern, const CSTRING *colf_pattern, const CSTRING *colq_pattern, const CSTRING *val_pattern, CVECTOR *ret_kv_vec)
{
    CBGT_MD    *cbgt_md;
    CBGT_GDB   *gdb;

    pcre *table_re;

    TASK_MGR   *task_mgr;

    CVECTOR    *root_kv_vec;
    CVECTOR    *report_vec;

    UINT32   pos;
    EC_BOOL  ret;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_select_from_root: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md     = CBGT_MD_GET(cbgt_md_id);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0343);
#if 0
    dbg_log(SEC_0054_CBGT, 5)(LOGSTDOUT, "------------------------------------------ cbgt_select_from_root enter ------------------------------------------\n");
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_select_from_root: table_pattern: %s\n"  , (char *)cstring_get_str(table_pattern));
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_select_from_root: row_pattern  : %s\n"  , (char *)cstring_get_str(row_pattern));
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_select_from_root: colf_pattern : %s\n"  , (char *)cstring_get_str(colf_pattern));
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_select_from_root: colq_pattern : %s\n"  , (char *)cstring_get_str(colq_pattern));
#endif
    if(EC_FALSE == __cbgt_pcre_compile(table_pattern, &table_re))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_select_from_root: pcre compile table pattern %s failed\n",
                            (char *)cstring_get_str(colf_pattern));
        return (EC_FALSE);
    }

    root_kv_vec = cvector_new(0, MM_CBYTES, LOC_CBGT_0344);
    if(NULL_PTR == root_kv_vec)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_select_from_root: new root table kv vec failed\n");
        __cbgt_pcre_free(table_re);
        return (EC_FALSE);
    }

    CBGT_MD_CRWLOCK_TABLE_RDLOCK(cbgt_md, LOC_CBGT_0345);
    gdb = CBGT_MD_GDB(cbgt_md);
    /*note: table name is the row of root table*/
    ret = EC_FALSE;
    cbtree_scan(CBGT_GDB_CBTREE(gdb),
                        (void *)&ret, (C_RETVAL_CHECKER)c_checker_default,
                        (UINT32)8,
                        (UINT32)1,
                        (UINT32)__cbgt_select_from_table,
                        cbgt_md_id,
                        NULL_PTR,
                        kvRegex,
                        table_re, NULL_PTR, NULL_PTR, NULL_PTR, root_kv_vec
                        );
    CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0346);

    __cbgt_pcre_free(table_re);

    if(0 == cvector_size(root_kv_vec))
    {
        dbg_log(SEC_0054_CBGT, 1)(LOGSTDOUT, "warn:cbgt_select_from_root: no matching user table\n");
        cvector_free(root_kv_vec, LOC_CBGT_0347);
        return (EC_TRUE);
    }

    report_vec = cvector_new(0, MM_CVECTOR, LOC_CBGT_0348);
    if(NULL_PTR == report_vec)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_select_from_root: new report vec failed\n");
        cvector_clean(root_kv_vec, (CVECTOR_DATA_CLEANER)cbytes_free, LOC_CBGT_0349);
        cvector_free(root_kv_vec, LOC_CBGT_0350);
        return (EC_FALSE);
    }

    task_mgr = task_new(NULL_PTR, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);

    for(pos = 0; pos < cvector_size(root_kv_vec); pos ++)
    {
        CBYTES *root_kv_bytes;

        MOD_NODE    meta_mod_node;
        UINT32      meta_table_id;

        const uint8_t  *value;
        uint32_t        counter;

        root_kv_bytes = (CBYTES *)cvector_get_no_lock(root_kv_vec, pos);
        if(NULL_PTR == root_kv_bytes)
        {
            continue;
        }

        value = kvGetValueHs(cbytes_buf(root_kv_bytes));

        counter = 0;
        meta_table_id = gdbGetWord(value, &counter);
        MOD_NODE_TCID(&meta_mod_node) = gdbGetWord(value, &counter);
        MOD_NODE_COMM(&meta_mod_node) = gdbGetWord(value, &counter);
        MOD_NODE_RANK(&meta_mod_node) = gdbGetWord(value, &counter);
        MOD_NODE_MODI(&meta_mod_node) = gdbGetWord(value, &counter);
#if 0
        sys_print(LOGSTDOUT, "[DEBUG]cbgt_select_from_root:meta table id %ld, (tcid %s, comm %ld, rank %ld, modi %ld)\n",
                            meta_table_id,
                            MOD_NODE_TCID_STR(&meta_mod_node),
                            MOD_NODE_COMM(&meta_mod_node),
                            MOD_NODE_RANK(&meta_mod_node),
                            MOD_NODE_MODI(&meta_mod_node)
                            );
#endif
        if(EC_FALSE == CBGT_CHECK_TABLE_EXIST(cbgt_md_id, meta_table_id, &meta_mod_node)
        && CBGT_SELECT_FROM_ALL_TABLE == cached_mode)
        {
            MOD_NODE root_mod_node;
            CBYTES   meta_table_name;

            cbytes_init(&meta_table_name);
            cbytes_mount(&meta_table_name, kvGetrLenHs(cbytes_buf(root_kv_bytes)), kvGetRowHs(cbytes_buf(root_kv_bytes)));

            __cbgt_local_mod_node(cbgt_md_id, &root_mod_node);
            if(EC_FALSE == __cbgt_start_trigger(cbgt_md_id,
                                                CBGT_TYPE_META_SERVER,
                                                meta_table_id,
                                                &meta_table_name,
                                                &root_mod_node,
                                                CBGT_MD_ROOT_PATH(cbgt_md),
                                                CBGT_O_RDWR,
                                                &meta_mod_node))
            {
                dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_select_from_root: cbgt start meta table %ld on root table %ld failed\n",
                                    meta_table_id, CBGT_MD_TABLE_ID(cbgt_md));
                continue;
            }

            /*WARNING: we start the meta server without registering into root or without end it later, it is dangerous*/
            /*         if register it here, we have to save "offset" info when scan root table*/

            /*update register info of meta table*/
            if(EC_FALSE == cbgt_update_register(cbgt_md_id, root_kv_bytes, meta_table_id, &meta_mod_node))
            {
                dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_select_from_root: update register of meta table %.*s id %ld (tcid %s, comm %ld, rank %ld, modi %ld) "
                                   "to root table %ld failed\n",
                                   (uint32_t)cbytes_len(&meta_table_name), (char *)cbytes_buf(&meta_table_name),
                                   meta_table_id,
                                   MOD_NODE_TCID_STR(&meta_mod_node), MOD_NODE_COMM(&meta_mod_node), MOD_NODE_RANK(&meta_mod_node), MOD_NODE_MODI(&meta_mod_node),
                                   CBGT_MD_TABLE_ID(cbgt_md));
                continue;
            }
        }

        if(EC_TRUE == __cbgt_mod_node_is_valid(cbgt_md_id, &meta_mod_node))
        {
            CVECTOR *user_table_kv_vec;
            EC_BOOL  ret;

            user_table_kv_vec = cvector_new(0, MM_CBYTES, LOC_CBGT_0351);
            if(NULL_PTR == user_table_kv_vec)
            {
                dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_select_from_root: new user table kv vec failed\n");
                break;
            }

            /*select from cached colf table*/
            ret = EC_FALSE;
            task_p2p_inc(task_mgr, cbgt_md_id, &meta_mod_node,
                         &ret, FI_cbgt_select_from_meta, CMPI_ERROR_MODI, cached_mode,
                         row_pattern, colf_pattern, colq_pattern, val_pattern,
                         user_table_kv_vec);

            cvector_push_no_lock(report_vec, (void *)user_table_kv_vec);
        }
    }

    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    cvector_clean(root_kv_vec, (CVECTOR_DATA_CLEANER)cbytes_free, LOC_CBGT_0352);
    cvector_free(root_kv_vec, LOC_CBGT_0353);

    for(pos = 0; pos < cvector_size(report_vec); pos ++)
    {
        CVECTOR *user_table_kv_vec;

        user_table_kv_vec = (CVECTOR *)cvector_get_no_lock(report_vec, pos);
        if(NULL_PTR == user_table_kv_vec)
        {
            continue;
        }

        cvector_merge_with_move(user_table_kv_vec, ret_kv_vec, NULL_PTR);

        cvector_clean_no_lock(user_table_kv_vec, (CVECTOR_DATA_CLEANER)cbytes_free, LOC_CBGT_0354);
        cvector_free_no_lock(user_table_kv_vec, LOC_CBGT_0355);
        cvector_set_no_lock(report_vec, pos, NULL_PTR);
    }

    cvector_free_no_lock(report_vec, LOC_CBGT_0356);

    return (EC_TRUE);
}

EC_BOOL cbgt_select_in_meta(const UINT32 cbgt_md_id, const UINT32 cached_mode, const CBYTES *table_name, const CSTRING *row_pattern, const CSTRING *colf_pattern, const CSTRING *colq_pattern, const CSTRING *val_pattern, CVECTOR *ret_kv_vec)
{
    CBGT_MD    *cbgt_md;

    MOD_NODE    meta_mod_node;

    UINT32      meta_table_id;

    EC_BOOL     ret;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_select_in_meta: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0357);

    if(EC_FALSE == cbgt_is_root_server(cbgt_md_id))
    {
        EC_BOOL ret;
        task_p2p(cbgt_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                 CBGT_MD_ROOT_MOD(cbgt_md) ,
                 &ret, FI_cbgt_select_in_meta, CMPI_ERROR_MODI, cached_mode,
                 table_name, row_pattern, colf_pattern, colq_pattern, val_pattern,
                 ret_kv_vec);
        if(EC_FALSE == ret)
        {
            dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_select_in_meta: select %.*s (%s)(%s)(%s) from cbgt %ld table %ld type %s failed\n",
                                (uint32_t)cbytes_len(table_name), (char *)cbytes_buf(table_name),
                                (char *)cstring_get_str(row_pattern),
                                (char *)cstring_get_str(colf_pattern),
                                (char *)cstring_get_str(colq_pattern),
                                cbgt_md_id, CBGT_MD_TABLE_ID(cbgt_md), __cbgt_type(CBGT_MD_TYPE(cbgt_md))
                                );
            return (EC_FALSE);
        }
        return (EC_TRUE);
    }
#if 0
    dbg_log(SEC_0054_CBGT, 5)(LOGSTDOUT, "------------------------------------------ cbgt_select_in_meta enter ------------------------------------------\n");
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_select_in_meta: table name  : %.*s\n", cbytes_len(table_name), (char *)cbytes_buf(table_name));
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_select_in_meta: row_pattern : %s\n"  , (char *)cstring_get_str(row_pattern));
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_select_in_meta: colf_pattern: %s\n"  , (char *)cstring_get_str(colf_pattern));
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_select_in_meta: colq_pattern: %s\n"  , (char *)cstring_get_str(colq_pattern));
#endif
    /*get meta table*/
    if(EC_FALSE == __cbgt_open_rmc_table(cbgt_md_id, CBGT_TYPE_META_SERVER, table_name, &meta_table_id, &meta_mod_node))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_select_in_meta: open meta table of user table %.*s on root table %ld failed\n",
                            (uint32_t)cbytes_len(table_name), (char *)cbytes_buf(table_name),
                            CBGT_MD_TABLE_ID(cbgt_md));
        return (EC_FALSE);
    }

    /*select in user table*/
    ret = EC_FALSE;
    task_p2p(cbgt_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &meta_mod_node,
             &ret, FI_cbgt_select_from_meta, CMPI_ERROR_MODI, cached_mode,
             row_pattern, colf_pattern, colq_pattern, val_pattern,
             ret_kv_vec);

    if(EC_FALSE == ret || EC_OBSCURE == ret)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_select_in_meta: select %.*s (%s)(%s)(%s) failed\n",
                            (uint32_t)cbytes_len(table_name), (char *)cbytes_buf(table_name),
                            (char *)cstring_get_str(row_pattern),
                            (char *)cstring_get_str(colf_pattern),
                            (char *)cstring_get_str(colq_pattern));
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL cbgt_select_in_colf(const UINT32 cbgt_md_id, const UINT32 cached_mode, const CBYTES *table_name, const CBYTES *colf_name, const CSTRING *row_pattern,  const CSTRING *colq_pattern, const CSTRING *val_pattern, CVECTOR *ret_kv_vec)
{
    CBGT_MD    *cbgt_md;

    MOD_NODE    colf_mod_node;

    UINT32      colf_table_id;
    CSTRING     colf_pattern;

    EC_BOOL     ret;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_select_in_colf: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0358);

    if(EC_FALSE == cbgt_is_root_server(cbgt_md_id))
    {
        EC_BOOL ret;
        task_p2p(cbgt_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                 CBGT_MD_ROOT_MOD(cbgt_md) ,
                 &ret, FI_cbgt_select_in_colf, CMPI_ERROR_MODI, cached_mode,
                 table_name, colf_name, row_pattern, colq_pattern, val_pattern,
                 ret_kv_vec);
        if(EC_FALSE == ret)
        {
            dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_select_in_colf: select %.*s:%.*s (%s)(%s)from cbgt %ld table %ld type %s failed\n",
                                (uint32_t)cbytes_len(table_name), (char *)cbytes_buf(table_name),
                                (uint32_t)cbytes_len(colf_name), (char *)cbytes_buf(colf_name),
                                (char *)cstring_get_str(row_pattern),
                                (char *)cstring_get_str(colq_pattern),
                                cbgt_md_id, CBGT_MD_TABLE_ID(cbgt_md), __cbgt_type(CBGT_MD_TYPE(cbgt_md))
                                );
            return (EC_FALSE);
        }
        return (EC_TRUE);
    }
#if 0
    dbg_log(SEC_0054_CBGT, 5)(LOGSTDOUT, "------------------------------------------ cbgt_select_in_colf enter ------------------------------------------\n");
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_select_in_colf: table name  : %.*s\n", cbytes_len(table_name), (char *)cbytes_buf(table_name));
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_select_in_colf: colf name   : %.*s\n", cbytes_len(colf_name), (char *)cbytes_buf(colf_name));
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_select_in_colf: colq_pattern: %s\n"  , (char *)cstring_get_str(colq_pattern));
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_select_in_colf: ts_pattern  : %s\n"  , (char *)cstring_get_str(ts_pattern));
#endif
    /*open colf table*/
    if(EC_FALSE == cbgt_open_colf_table_from_root(cbgt_md_id, table_name, colf_name, &colf_table_id, &colf_mod_node))
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_insert: open colf table %.*s:%.*s failed\n",
                            (uint32_t)cbytes_len(table_name), (char *)cbytes_buf(table_name),
                            (uint32_t)cbytes_len(colf_name), (char *)cbytes_buf(colf_name));
        return (EC_FALSE);
    }

    cstring_set_str(&colf_pattern, (UINT8 *)".*");

    /*select in colf table*/
    ret = EC_FALSE;
    task_p2p(cbgt_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &colf_mod_node,
             &ret, FI_cbgt_select_from_colf, CMPI_ERROR_MODI, cached_mode,
             row_pattern, &colf_pattern, colq_pattern, val_pattern,
             ret_kv_vec);

    if(EC_FALSE == ret || EC_OBSCURE == ret)
    {
        dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_select_in_colf: select in %.*s:%.*s (%s)(%s) failed\n",
                            (uint32_t)cbytes_len(table_name), (char *)cbytes_buf(table_name),
                            (uint32_t)cbytes_len(colf_name), (char *)cbytes_buf(colf_name),
                            (char *)cstring_get_str(row_pattern),
                            (char *)cstring_get_str(colq_pattern));
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL cbgt_select(const UINT32 cbgt_md_id, const UINT32 cached_mode, const CSTRING *table_pattern, const CSTRING *row_pattern, const CSTRING *colf_pattern, const CSTRING *colq_pattern, const CSTRING *val_pattern, CVECTOR *ret_kv_vec)
{
    CBGT_MD    *cbgt_md;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_select: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md     = CBGT_MD_GET(cbgt_md_id);

    if(EC_FALSE == cbgt_is_root_server(cbgt_md_id))
    {
        EC_BOOL ret;
        task_p2p(cbgt_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                 CBGT_MD_ROOT_MOD(cbgt_md) ,
                 &ret, FI_cbgt_select_from_root, CMPI_ERROR_MODI, cached_mode,
                 table_pattern, row_pattern, colf_pattern, colq_pattern, val_pattern,
                 ret_kv_vec);
        if(EC_FALSE == ret)
        {
            dbg_log(SEC_0054_CBGT, 0)(LOGSTDOUT, "error:cbgt_select: select %s (%s)(%s)(%s) from cbgt %ld table %ld type %s failed\n",
                                (char *)cstring_get_str(table_pattern),
                                (char *)cstring_get_str(row_pattern),
                                (char *)cstring_get_str(colf_pattern),
                                (char *)cstring_get_str(colq_pattern),
                                cbgt_md_id, CBGT_MD_TABLE_ID(cbgt_md), __cbgt_type(CBGT_MD_TYPE(cbgt_md))
                                );
            return (EC_FALSE);
        }
        return (EC_TRUE);
    }
#if 0
    dbg_log(SEC_0054_CBGT, 5)(LOGSTDOUT, "------------------------------------------ cbgt_select enter ------------------------------------------\n");
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_select: table_pattern: %s\n"  , (char *)cstring_get_str(table_pattern));
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_select: row_pattern  : %s\n"  , (char *)cstring_get_str(row_pattern));
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_select: colf_pattern : %s\n"  , (char *)cstring_get_str(colf_pattern));
    dbg_log(SEC_0054_CBGT, 9)(LOGSTDOUT, "[DEBUG] cbgt_select: colq_pattern : %s\n"  , (char *)cstring_get_str(colq_pattern));
#endif
    return cbgt_select_from_root(cbgt_md_id, cached_mode,
                                table_pattern, row_pattern, colf_pattern, colq_pattern, val_pattern,
                                ret_kv_vec);
}

void cbgt_traversal_no_lock(const UINT32 cbgt_md_id, LOG *log)
{
    CBGT_MD    *cbgt_md;
    CBGT_GDB   *gdb;

    UINT32      server_type;
    UINT32      table_id;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_traversal_no_lock: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md     = CBGT_MD_GET(cbgt_md_id);
    gdb         = CBGT_MD_GDB(cbgt_md);
    server_type = CBGT_MD_TYPE(cbgt_md);
    table_id    = CBGT_MD_TABLE_ID(cbgt_md);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0359);

    sys_log(log, "cbgt_traversal_no_lock: cbgt module %ld, table %ld, type %s: beg ==> \n",
                        cbgt_md_id, table_id, __cbgt_type(server_type));

    if(CBGT_TYPE_ROOT_SERVER == server_type)
    {
        cbgt_gdb_traversal(log, gdb, (CBTREE_KEY_PRINTER)__cbgt_print_root_table_cbtree_key);
    }
    else if(CBGT_TYPE_META_SERVER == server_type)
    {
        cbgt_gdb_traversal(log, gdb, (CBTREE_KEY_PRINTER)__cbgt_print_meta_table_cbtree_key);
    }
    else if(CBGT_TYPE_COLF_SERVER == server_type)
    {
        cbgt_gdb_traversal(log, gdb, (CBTREE_KEY_PRINTER)__cbgt_print_colf_table_cbtree_key);
    }
    else if(CBGT_TYPE_USER_SERVER == server_type)
    {
        cbgt_gdb_traversal(log, gdb, (CBTREE_KEY_PRINTER)__cbgt_print_user_table_cbtree_key);
    }
    else
    {
        sys_log(log, "error:cbgt_traversal_no_lock: unknown type\n");
    }

    sys_log(log, "cbgt_traversal_no_lock: cbgt module %ld, table %ld, type %s: end <== \n",
                        cbgt_md_id, table_id, __cbgt_type(server_type));
    return;
}

void cbgt_traversal(const UINT32 cbgt_md_id, LOG *log)
{
    CBGT_MD    *cbgt_md;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_traversal: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0360);

    CBGT_MD_CRWLOCK_TABLE_RDLOCK(cbgt_md, LOC_CBGT_0361);
    cbgt_traversal_no_lock(cbgt_md_id, log);
    CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0362);
    return;
}

void cbgt_runthrough_no_lock(const UINT32 cbgt_md_id, LOG *log)
{
    CBGT_MD    *cbgt_md;
    CBGT_GDB   *gdb;

    UINT32      server_type;
    UINT32      table_id;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_runthrough_no_lock: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md     = CBGT_MD_GET(cbgt_md_id);
    gdb         = CBGT_MD_GDB(cbgt_md);
    server_type = CBGT_MD_TYPE(cbgt_md);
    table_id    = CBGT_MD_TABLE_ID(cbgt_md);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0363);

    sys_log(log, "cbgt_runthrough_no_lock: cbgt module %ld, table %ld, type %s: beg ==> \n",
                        cbgt_md_id, table_id, __cbgt_type(server_type));

    sys_log(log, "cbgt_runthrough_no_lock: table name is\n");
    __cbgt_print_table_name(cbgt_md_id, log);

    if(CBGT_TYPE_ROOT_SERVER == server_type)
    {
        cbgt_gdb_runthrough(log, gdb, (CBTREE_KEY_PRINTER)__cbgt_print_root_table_kv);
    }
    else if(CBGT_TYPE_META_SERVER == server_type)
    {
        cbgt_gdb_runthrough(log, gdb, (CBTREE_KEY_PRINTER)__cbgt_print_meta_table_kv);
    }
    else if(CBGT_TYPE_COLF_SERVER == server_type)
    {
        cbgt_gdb_runthrough(log, gdb, (CBTREE_KEY_PRINTER)__cbgt_print_colf_table_kv);
    }
    else if(CBGT_TYPE_USER_SERVER == server_type)
    {
        cbgt_gdb_runthrough(log, gdb, (CBTREE_KEY_PRINTER)__cbgt_print_user_table_kv);
    }
    else
    {
        sys_log(log, "error:cbgt_runthrough_no_lock: unknown type\n");
    }

    sys_log(log, "cbgt_runthrough_no_lock: cbgt module %ld, table %ld, type %s: end <== \n",
                        cbgt_md_id, table_id, __cbgt_type(server_type));

    return;
}

void cbgt_runthrough(const UINT32 cbgt_md_id, LOG *log)
{
    CBGT_MD    *cbgt_md;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_runthrough: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md = CBGT_MD_GET(cbgt_md_id);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0364);

    CBGT_MD_CRWLOCK_TABLE_RDLOCK(cbgt_md, LOC_CBGT_0365);
    cbgt_runthrough_no_lock(cbgt_md_id, log);
    CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, LOC_CBGT_0366);

    return;
}

void cbgt_traversal_depth(const UINT32 cbgt_md_id, LOG *log)
{
    CBGT_MD    *cbgt_md;
    MOD_MGR    *mod_mgr;

    UINT32      server_type;
    UINT32      table_id;
    UINT32      pos;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_traversal_depth: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md     = CBGT_MD_GET(cbgt_md_id);
    mod_mgr     = CBGT_MD_MOD_MGR(cbgt_md);
    server_type = CBGT_MD_TYPE(cbgt_md);
    table_id    = CBGT_MD_TABLE_ID(cbgt_md);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0367);

    sys_log(log, "cbgt_traversal_depth: cbgt module %ld, table %ld, type %s: beg ==> \n",
                        cbgt_md_id, table_id, __cbgt_type(server_type));

    cbgt_traversal(cbgt_md_id, log);

    sys_log(log, "cbgt_traversal_depth: cbgt module %ld, table %ld, type %s: end <== \n",
                        cbgt_md_id, table_id, __cbgt_type(server_type));

    for(pos = 0; pos < cvector_size(MOD_MGR_REMOTE_LIST(mod_mgr)); pos ++)
    {
        MOD_NODE *mod_node;

        EC_BOOL   ret;

        mod_node = (MOD_NODE *)cvector_get(MOD_MGR_REMOTE_LIST(mod_mgr), pos);

        ret = EC_FALSE;
        task_p2p(cbgt_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                 mod_node,
                 &ret,FI_cbgt_traversal_depth, CMPI_ERROR_MODI, log);
    }

    return;
}

void cbgt_runthrough_depth(const UINT32 cbgt_md_id, LOG *log)
{
    CBGT_MD    *cbgt_md;
    MOD_MGR    *mod_mgr;

    UINT32      server_type;
    UINT32      table_id;
    UINT32      pos;

#if ( SWITCH_ON == CBGT_DEBUG_SWITCH )
    if ( CBGT_MD_ID_CHECK_INVALID(cbgt_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cbgt_runthrough_depth: cbgt module #%ld not started.\n",
                cbgt_md_id);
        cbgt_print_module_status(cbgt_md_id, LOGSTDOUT);
        dbg_exit(MD_CBGT, cbgt_md_id);
    }
#endif/*CBGT_DEBUG_SWITCH*/

    cbgt_md     = CBGT_MD_GET(cbgt_md_id);
    mod_mgr     = CBGT_MD_MOD_MGR(cbgt_md);
    server_type = CBGT_MD_TYPE(cbgt_md);
    table_id    = CBGT_MD_TABLE_ID(cbgt_md);
    CBGT_MD_WAS_ACCESS(cbgt_md, LOC_CBGT_0368);

    sys_log(log, "cbgt_runthrough_depth: cbgt module %ld, table %ld, type %s: beg ==> \n",
                        cbgt_md_id, table_id, __cbgt_type(server_type));

    cbgt_runthrough(cbgt_md_id, log);

    sys_log(log, "cbgt_runthrough_depth: cbgt module %ld, table %ld, type %s: end <== \n",
                        cbgt_md_id, table_id, __cbgt_type(server_type));

    for(pos = 0; pos < cvector_size(MOD_MGR_REMOTE_LIST(mod_mgr)); pos ++)
    {
        MOD_NODE *mod_node;

        EC_BOOL   ret;

        mod_node = (MOD_NODE *)cvector_get(MOD_MGR_REMOTE_LIST(mod_mgr), pos);
        ret = EC_FALSE;
        task_p2p(cbgt_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                 mod_node,
                 &ret,FI_cbgt_runthrough_depth, CMPI_ERROR_MODI, log);
    }

    return;
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

