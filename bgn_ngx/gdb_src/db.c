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

#include "db_internal.h"
#include "pcre.h"


#if 1
#define PRINT_BUFF(info, buff, len) do{\
    UINT32 __pos;\
    dbg_log(SEC_0131_DB, 5)(LOGSTDOUT, "%s: ", info);\
    for(__pos = 0; __pos < (len); __pos ++)\
    {\
        sys_print(LOGSTDOUT, "%x,", ((UINT8 *)buff)[ __pos ]);\
    }\
    sys_print(LOGSTDOUT, "\n");\
}while(0)
#else
#define PRINT_BUFF(info, buff, len) do{}while(0)
#endif

static void
__setupDatabase(GDatabase *db)
{
    db->openBlockCount = 0;
    db->openBlockSize  = 10;

    MEM_CHECK(db->openBlocks = (GdbBlock **)SAFE_MALLOC(db->openBlockSize * sizeof(GdbBlock *), LOC_DB_0001));
    memset(db->openBlocks, 0, db->openBlockSize * sizeof(GdbBlock *));
}

STATIC_CAST static uint8_t *__genIdxFileName(const uint8_t *root_path, const word_t table_id)
{
    uint8_t *fidx_name;
    uint32_t len;

    len = strlen((char *)root_path) + strlen("/idx/raw.idx") + 32;
    MEM_CHECK(fidx_name = (uint8_t *)SAFE_MALLOC(len, LOC_DB_0002));
    memset(fidx_name, 0, len);

    snprintf((char *)fidx_name, len, "%s/idx/%ld/%ld/%ld/%ld/raw.idx",
                (char *)root_path,
                TABLE_PATH_LAYOUT_DIR0_NO(table_id),
                TABLE_PATH_LAYOUT_DIR1_NO(table_id),
                TABLE_PATH_LAYOUT_DIR2_NO(table_id),
                TABLE_PATH_LAYOUT_DIR3_NO(table_id)
                );

    return (fidx_name);
}

STATIC_CAST static uint8_t *__genDatFileName(const uint8_t *root_path, const word_t table_id)
{
    uint8_t *fdat_name;
    uint32_t len;

    len = strlen((char *)root_path) + strlen("/dat/raw.dat") + 32;
    MEM_CHECK(fdat_name = (uint8_t *)SAFE_MALLOC(len, LOC_DB_0003));
    memset(fdat_name, 0, len);

    snprintf((char *)fdat_name, len, "%s/dat/%ld/%ld/%ld/%ld/raw.dat",
                (char *)root_path,
                TABLE_PATH_LAYOUT_DIR0_NO(table_id),
                TABLE_PATH_LAYOUT_DIR1_NO(table_id),
                TABLE_PATH_LAYOUT_DIR2_NO(table_id),
                TABLE_PATH_LAYOUT_DIR3_NO(table_id)
                );

    return (fdat_name);
}

STATIC_CAST static uint8_t *__dupFileName(const uint8_t *root_path)
{
    uint8_t *file_name;
    MEM_CHECK(file_name = (uint8_t *)SAFE_MALLOC(strlen((char *)root_path) + 1, LOC_DB_0004));
    sprintf((char *)file_name, "%s", (char *)root_path);
    return (file_name);
}

int gdbIdxfd(const GDatabase *db)
{
    if(NULL == db || NULL == db->idxRawFile)
    {
        return -1;
    }

    return db->idxRawFile->fd;
}

int gdbDatfd(const GDatabase *db)
{
    if(NULL == db || NULL == db->datRawFile)
    {
        return -1;
    }

    return db->datRawFile->fd;
}

word_t gdbTableId(const GDatabase *db)
{
    MEM_CHECK(db);
    return db->table_id;
}

GDatabase *
gdbMake(const uint8_t *root_path, const word_t table_id, const word_t cdfs_md_id, const int idx_fd, const int dat_fd)
{
    GDatabase *db;

    uint8_t *fidx_name;
    uint8_t *fdat_name;

    MEM_CHECK(fidx_name = __genIdxFileName(root_path, table_id));
    MEM_CHECK(fdat_name = __genDatFileName(root_path, table_id));

    MEM_CHECK(db = (GDatabase *)SAFE_MALLOC(sizeof(GDatabase), LOC_DB_0005));
    memset(db, 0, sizeof(GDatabase));
    gdbInitlockFreeBlockList(db, LOC_DB_0006);

    MEM_CHECK(db->idxRawFile = rawFileNew(fidx_name, idx_fd, O_RDWR, RAW_IDX_FILE_MAX_SIZE , cdfs_md_id));
    MEM_CHECK(db->datRawFile = rawFileNew(fdat_name, dat_fd, O_RDWR, RAW_DATA_FILE_MAX_SIZE, cdfs_md_id));

    SAFE_FREE(fidx_name, LOC_DB_0007);
    SAFE_FREE(fdat_name, LOC_DB_0008);

    db->table_id = table_id;
    db->type     = GDB_INDEX_FILE;
    db->mode     = PM_MODE_READ_WRITE;
    MEM_CHECK(db->filename = __dupFileName(root_path));
    db->cdfs_md_id = cdfs_md_id;

    __setupDatabase(db);

    gdbWriteHeader(db);

    /* Leave enough room for the free block list. */
    rawFileSeek(db->idxRawFile, DB_FREE_BLOCK_LIST_OFFSET, SEEK_SET);
    gdbPad(db->idxRawFile, DB_FREE_BLOCK_LIST_OFFSET, DB_FREE_BLOCK_LIST_SIZE);

    db->mainTree = btreeCreate(db, BTREE_ORDER);

    return db;
}

GDatabase *
gdbOpen(const uint8_t *root_path, const word_t table_id, const word_t cdfs_md_id, const int flags)
{
    GDatabase *db;
    RawFile   *idxRawFile;

    uint8_t *fidx_name;
    uint8_t *fdat_name;

    cxReturnValueUnless(root_path != NULL,     NULL);

    idxRawFile = NULL;

    if(flags & O_RDWR)
    {
        MEM_CHECK(fidx_name = __genIdxFileName(root_path, table_id));
        idxRawFile = rawFileOpen(fidx_name, O_RDWR, RAW_IDX_FILE_MAX_SIZE, cdfs_md_id);
        SAFE_FREE(fidx_name, LOC_DB_0009);
    }

    if (idxRawFile == NULL)
    {
        if (flags & O_CREAT)
        {
            return gdbCreate(root_path, table_id, cdfs_md_id);
        }
        else
        {
            dbg_log(SEC_0131_DB, 0)(LOGSTDOUT, "error:gdbOpen: Unable to open table %ld\n", table_id);
            return NULL;
        }
    }

    MEM_CHECK(db = (GDatabase *)SAFE_MALLOC(sizeof(GDatabase), LOC_DB_0010));
    memset(db, 0, sizeof(GDatabase));
    gdbInitlockFreeBlockList(db, LOC_DB_0011);

    db->idxRawFile = idxRawFile;

    if(gdbReadHeader(db) == 0)
    {
        dbg_log(SEC_0131_DB, 0)(LOGSTDOUT, "error:gdbOpen: read header of table %ld failed\n", table_id);
        rawFileClose(db->idxRawFile);
        SAFE_FREE(db, LOC_DB_0012);
        return NULL;
    }

    if(db->type != GDB_INDEX_FILE)
    {
        dbg_log(SEC_0131_DB, 0)(LOGSTDOUT, "error:gdbOpen: read header of table %ld failed due to invalid db type %d\n", table_id, db->type);
        rawFileClose(db->idxRawFile);
        SAFE_FREE(db, LOC_DB_0013);
        return NULL;
    }

    MEM_CHECK(fdat_name = __genDatFileName(root_path, table_id));
    MEM_CHECK(db->datRawFile = rawFileOpen(fdat_name, O_RDWR, RAW_DATA_FILE_MAX_SIZE, cdfs_md_id));
    SAFE_FREE(fdat_name, LOC_DB_0014);

    __setupDatabase(db);

    db->table_id = table_id;
    db->mode     = PM_MODE_READ_WRITE;
    db->filename = __dupFileName(root_path);
    db->cdfs_md_id = cdfs_md_id;

    db->mainTree = btreeOpen(db, DB_MAIN_TREE_OFFSET);

    return db;
}

void
gdbClean(GDatabase *db)
{
    cxReturnUnless(db != NULL);

    if (db->idxRawFile != NULL)
    {
        rawFileFree(db->idxRawFile);
        db->idxRawFile = NULL;
    }

    if(db->datRawFile != NULL)
    {
        rawFileFree(db->datRawFile);
        db->datRawFile = NULL;
    }

    if(db->mainTree != NULL)
    {
        btreeClose(db->mainTree);
        db->mainTree = NULL;
    }
    return;
}

void
gdbReset(GDatabase *db)
{
    cxReturnUnless(db != NULL);

    if (db->idxRawFile != NULL)
    {
        rawFileReset(db->idxRawFile);
    }

    if(db->datRawFile != NULL)
    {
        rawFileReset(db->datRawFile);
    }

    if(db->mainTree != NULL)
    {
        btreeClose(db->mainTree);
        db->mainTree = NULL;
    }
    return;
}

void
gdbClose(GDatabase *db)
{
    cxReturnUnless(db != NULL);

    gdbFlush(db);
    gdbClean(db);

    gdbDestroy(db);
    return;
}

void gdbUnMake(GDatabase *db)
{
    cxReturnUnless(db != NULL);
#if 0
    if(NULL != db->idxRawFile)
    {
        rawFileUnMake(db->idxRawFile);
    }

    if(NULL != db->datRawFile)
    {
        rawFileUnMake(db->datRawFile);
    }
#endif
    db->idxRawFile->fd = -1;
    db->datRawFile->fd = -1;
    gdbClean(db);

    gdbDestroy(db);
    return;
}

GDatabase *
gdbCreate(const uint8_t *root_path, const word_t table_id, const word_t cdfs_md_id)
{
    GDatabase *db;
    RawFile   *idxRawFile;
    RawFile   *datRawFile;

    uint8_t *fidx_name;
    uint8_t *fdat_name;

    MEM_CHECK(fidx_name = __genIdxFileName(root_path, table_id));
    idxRawFile = rawFileCreate(fidx_name, RAW_IDX_FILE_MAX_SIZE, cdfs_md_id);
    if(NULL == idxRawFile)
    {
        dbg_log(SEC_0131_DB, 0)(LOGSTDOUT, "error:gdbCreate: Unable to create idx %s for table %ld\n",
                            (char *)fidx_name, table_id);
        SAFE_FREE(fidx_name, LOC_DB_0015);
        return NULL;
    }
    SAFE_FREE(fidx_name, LOC_DB_0016);

    MEM_CHECK(fdat_name = __genDatFileName(root_path, table_id));
    datRawFile = rawFileCreate(fdat_name, RAW_DATA_FILE_MAX_SIZE, cdfs_md_id);
    if(NULL == datRawFile)
    {
        dbg_log(SEC_0131_DB, 0)(LOGSTDOUT, "error:gdbCreate: Unable to create dat %s for table %ld\n",
                            (char *)fdat_name, table_id);
        SAFE_FREE(fdat_name, LOC_DB_0017);
        rawFileClose(idxRawFile);
        return NULL;
    }
    SAFE_FREE(fdat_name, LOC_DB_0018);

    MEM_CHECK(db = (GDatabase *)SAFE_MALLOC(sizeof(GDatabase), LOC_DB_0019));
    memset(db, 0, sizeof(GDatabase));
    gdbInitlockFreeBlockList(db, LOC_DB_0020);

    __setupDatabase(db);

    db->idxRawFile = idxRawFile;
    db->datRawFile  = datRawFile;
    db->table_id = table_id;
    db->type     = GDB_INDEX_FILE;
    db->mode     = PM_MODE_READ_WRITE | PM_MODE_CREATED;
    db->filename = __dupFileName(root_path);
    db->cdfs_md_id = cdfs_md_id;

    gdbWriteHeader(db);

    /* Leave enough room for the free block list. */
    rawFileSeek(db->idxRawFile, DB_FREE_BLOCK_LIST_OFFSET, SEEK_SET);
    gdbPad(db->idxRawFile, DB_FREE_BLOCK_LIST_OFFSET, DB_FREE_BLOCK_LIST_SIZE);

    db->mainTree = btreeCreate(db, BTREE_ORDER);

    return db;
}

GDatabase *
gdbDestroy(GDatabase *db)
{
    cxReturnValueUnless(db != NULL, NULL);

    SAFE_FREE(db->openBlocks, LOC_DB_0021);
    SAFE_FREE(db->filename, LOC_DB_0022);
    SAFE_FREE(db, LOC_DB_0023);

    return NULL;
}

GdbStatus
gdbFlush(GDatabase *db)
{
    cxReturnValueUnless(db != NULL, GDB_ERROR);

    if (db->idxRawFile != NULL)
    {
        rawFileFlush(db->idxRawFile);
    }

    if(db->datRawFile != NULL)
    {
        rawFileFlush(db->datRawFile);
    }
    return GDB_SUCCESS;
}

GdbStatus
gdbUnlink(const uint8_t *root_path, const word_t table_id)
{
    uint8_t *fidx_name;
    uint8_t *fdat_name;

    MEM_CHECK(fidx_name = __genIdxFileName(root_path, table_id));
    MEM_CHECK(fdat_name = __genDatFileName(root_path, table_id));

    dbg_log(SEC_0131_DB, 9)(LOGSTDOUT, "[DEBUG] gdbUnlink: unlink idx file: %s\n", (char *)fidx_name);
    unlink((char *)fidx_name);

    dbg_log(SEC_0131_DB, 9)(LOGSTDOUT, "[DEBUG] gdbUnlink: unlink dat file: %s\n", (char *)fdat_name);
    unlink((char *)fdat_name);

    SAFE_FREE(fidx_name, LOC_DB_0024);
    SAFE_FREE(fdat_name, LOC_DB_0025);

    return GDB_SUCCESS;
}

uint8_t
gdbIsEmpty(const GDatabase *db)
{
    if(NULL == db || NULL == db->mainTree)
    {
        dbg_log(SEC_0131_DB, 0)(LOGSTDOUT, "error:gdbIsEmpty: db or tree is null\n");
        return 0;
    }

    if(0 == db->mainTree->size)
    {
        return 1;
    }
    return 0;
}


GdbStatus
gdbSplit(const GDatabase *db, GDatabase *db_left, GDatabase *db_right)
{
    uint8_t ret;

    ret = btreeSplit(db->mainTree      , db->datRawFile,
                     db_left->mainTree , db_left->datRawFile,
                     db_right->mainTree, db_right->datRawFile);
    return (ret ? GDB_SUCCESS : GDB_ERROR);
}

GdbStatus
gdbAddTree(GDatabase *db, BTree *tree, const uint8_t *key, BTree **newTree)
{
    GdbStatus   status;
    offset_t    offset;
    //uint16_t    blockSize;
    uint8_t     type;

    if (db == NULL || tree == NULL || db->idxRawFile == NULL || key == NULL ||
        newTree == NULL)
    {
        return GDB_ERROR;
    }

    *newTree = btreeCreate(db, BTREE_ORDER);

    offset = (*newTree)->block->offset;
    //blockSize = (*newTree)->block->multiple;
    type = (*newTree)->block->type;

    if (*newTree == NULL)
    {
        *newTree = NULL;

        return GDB_ERROR;
    }

    status = btreeInsert(tree, key, offset, 0);

    if (status == GDB_DUPLICATE)
    {
        /* Return the existing newTree. */
        btreeClose(*newTree);
        gdbFreeBlock(db, offset, type);

        offset = btreeSearch(tree, key, keyCmp);

        if (offset == 0)
        {
            /* I doubt this will ever happen. */
            dbg_log(SEC_0131_DB, 5)(LOGSTDOUT,
                    _("error:gdbAddTree: Possible database corruption! Back up "
                      "your database and contact a developer.\n"));
            exit(1);
        }

        *newTree = btreeOpen(db, offset);

        status = GDB_SUCCESS;
    }
    else if (status == GDB_ERROR)
    {
        btreeClose(*newTree);

        rawFileSeek(db->idxRawFile, offset, SEEK_SET);

#if 0
        gdbPad(db->idxRawFile, blockSize);
#endif

        gdbFreeBlock(db, offset, type);

        *newTree = NULL;
    }

    return status;
}

GdbStatus
gdbInsertKeyValue(GDatabase *db, const KeyValue *keyValue, const uint8_t replaceDup)
{
    uint8_t  result;
    uint32_t offset;

    GdbStatus status;

    result = RAW_FILE_SUCC;
    offset = GDB_UNKNOW_OFFSET;
    status = GDB_ERROR;

    /*insert dat file*/
    if(NULL != db->datRawFile)
    {
        uint8_t *kv;
        uint16_t tlen;

        MEM_CHECK(kv  = kvNewHs(keyValue, LOC_DB_0026));
        kvPutHs(kv, keyValue);

        tlen = keyValueGettLenHs(keyValue);
        result = rawFileAppend8slen(db->datRawFile, kv, tlen, &offset);
        if(RAW_FILE_FAIL == result)
        {
            dbg_log(SEC_0131_DB, 0)(LOGSTDOUT,"error:gdbInsertKeyValue: insert kv failed where kv is ");
            kvPrintHs(LOGSTDOUT, kv);
        }
        kvFreeHs(kv, LOC_DB_0027);
    }

    /*insert idx file*/
    if(RAW_FILE_SUCC == result)
    {
        uint8_t *key;
        uint16_t klen;

        klen = keyValueGetkLenHs(keyValue);

        MEM_CHECK(key = keyNewHs(klen, LOC_DB_0028));
        keyValuePutKeyHs(key, keyValue);
        //__print_chars(key, keyValue->klen);

        status = btreeInsert(db->mainTree, key, offset, replaceDup);
        //print_kv_status(key, status);

        keyFreeHs(key, LOC_DB_0029);
    }

    return status;
}

GdbStatus
gdbInsertKV(GDatabase *db, const uint8_t *kv, const uint8_t replaceDup)
{
    uint8_t  result;
    uint32_t offset;

    GdbStatus status;

    result = RAW_FILE_SUCC;
    offset = GDB_UNKNOW_OFFSET;
    status = GDB_ERROR;

    /*insert dat file*/
    if(NULL != db->datRawFile)
    {
        uint32_t tlen;

        tlen = kvGettLenHs(kv);
        result = rawFileAppend8slen(db->datRawFile, kv, tlen, &offset);
        if(RAW_FILE_FAIL == result)
        {
            dbg_log(SEC_0131_DB, 0)(LOGSTDOUT,"error:gdbInsertKV: insert kv failed where kv is ");
            kvPrintHs(LOGSTDOUT, kv);
        }
    }

    /*insert idx file*/
    if(RAW_FILE_SUCC == result)
    {
        const uint8_t *key;

        key = kv;
        status = btreeInsert(db->mainTree, key, offset, replaceDup);
    }

    return status;
}

GdbStatus
gdbDeleteKey(GDatabase *db, const uint8_t *key, int(* keyCompare)(const uint8_t *, const uint8_t *), offset_t *offset)
{
    if(NULL == db || NULL == db->mainTree)
    {
        dbg_log(SEC_0131_DB, 0)(LOGSTDOUT, "error:gdbDeleteKey: db %p is null or btree %p is null\n", db, db->mainTree);
        return GDB_ERROR;
    }
    BTREE_CRWLOCK_WRLOCK(db->mainTree, LOC_DB_0030);
    (*offset) = btreeDelete(db->mainTree, key);
    BTREE_CRWLOCK_UNLOCK(db->mainTree, LOC_DB_0031);
    if(0 == (*offset))
    {
        return GDB_ERROR;
    }
    return GDB_SUCCESS;
}

GdbStatus
gdbDeleteVal(GDatabase *db, offset_t offset)
{
    offset_t cur_offset;
    uint16_t klen;
    if(0 == offset || NULL == db->datRawFile)
    {
        return GDB_ERROR;
    }

    cur_offset = offset;
    cur_offset += sizeof(uint32_t);/*skip dlen*/

    /*fetch klen*/
    if(RAW_FILE_FAIL == rawFileRead16(db->datRawFile, &klen, cur_offset))
    {
        dbg_log(SEC_0131_DB, 0)(LOGSTDOUT,"error:gdbDeleteVal: read klen at offset %d failed\n", cur_offset);
        return GDB_ERROR;
    }

    cur_offset += (KV_FORMAT_KLEN + KV_FORMAT_VLEN + klen - KV_FORMAT_TPLEN);/*locate to type*/

    if(RAW_FILE_FAIL == rawFileWrite8(db->datRawFile, KEY_TYPE_IS_RMV, cur_offset))
    {
        dbg_log(SEC_0131_DB, 0)(LOGSTDOUT,"error:gdbDeleteVal: put KEY_TYPE_IS_RMV at offset %d failed\n", cur_offset);
        return GDB_ERROR;
    }

    return GDB_SUCCESS;
}

GdbStatus
gdbScanKey(const GDatabase *db, const uint8_t *key, int(* keyCompare)(const uint8_t *, const uint8_t *), offset_t *offset)
{
    if(0 == btreeScan(db->mainTree, db->datRawFile, key, keyCompare, offset))
    {
        return GDB_ERROR;
    }
    return GDB_SUCCESS;
}

GdbStatus
gdbSearchKey(const GDatabase *db, const uint8_t *key, int(* keyCompare)(const uint8_t *, const uint8_t *), offset_t *offset)
{
    (*offset) = btreeSearch(db->mainTree, key, keyCompare);
    return GDB_SUCCESS;
}

GdbStatus
gdbFetchKey(const GDatabase *db, const offset_t offset, uint8_t **key, uint16_t *key_len)
{
    uint32_t dlen;
    uint16_t klen;
    uint32_t _tlen;

    uint32_t tlen;

    offset_t cur_offset;

    cur_offset = offset;

    if(RAW_FILE_FAIL == rawFileRead32(db->datRawFile, &dlen, cur_offset))
    {
        dbg_log(SEC_0131_DB, 0)(LOGSTDOUT,"error:gdbFetchKey: read dlen at offset %d failed\n", cur_offset);
        return GDB_ERROR;
    }
    cur_offset += sizeof(uint32_t);

    if(RAW_FILE_FAIL == rawFileRead16(db->datRawFile, &klen, cur_offset))
    {
        dbg_log(SEC_0131_DB, 0)(LOGSTDOUT,"error:gdbFetchKey: read klen at offset %d failed\n", cur_offset);
        return GDB_ERROR;
    }

    tlen = klen + KV_FORMAT_KLEN + KV_FORMAT_VLEN;

    (*key) = (uint8_t *)SAFE_MALLOC(tlen, LOC_DB_0032);
    if(NULL == (*key))
    {
        dbg_log(SEC_0131_DB, 0)(LOGSTDOUT,"error:gdbFetchKey: alloc %d bytes failed\n", tlen);
        (*key_len) = 0;
        return GDB_ERROR;
    }

    if(RAW_FILE_FAIL == rawFileRead8s(db->datRawFile, (*key), tlen, &_tlen, cur_offset) || _tlen != tlen)
    {
        dbg_log(SEC_0131_DB, 0)(LOGSTDOUT,"error:gdbFetchKey: read key %d bytes at offset %d failed where _tlen = %d\n",
                          tlen, cur_offset, _tlen);

        SAFE_FREE((*key), LOC_DB_0033);
        (*key) = NULL;
        (*key_len) = 0;
        return GDB_ERROR;
    }

    (*key_len) = (uint16_t)tlen;

    return GDB_SUCCESS;
}

GdbStatus
gdbFetchValue(const GDatabase *db, const offset_t offset, uint8_t **val, uint32_t *val_len)
{
    uint32_t dlen;
    uint16_t klen;
    uint32_t vlen;

    offset_t cur_offset;

    cur_offset = offset;

    if(RAW_FILE_FAIL == rawFileRead32(db->datRawFile, &dlen, cur_offset))
    {
        dbg_log(SEC_0131_DB, 0)(LOGSTDOUT,"error:gdbFetchValue: read dlen at offset %d failed\n", cur_offset);
        return GDB_ERROR;
    }
    cur_offset += sizeof(uint32_t);

    if(RAW_FILE_FAIL == rawFileRead16(db->datRawFile, &klen, cur_offset))
    {
        dbg_log(SEC_0131_DB, 0)(LOGSTDOUT,"error:gdbFetchValue: read klen at offset %d failed\n", cur_offset);
        return GDB_ERROR;
    }
    cur_offset += sizeof(uint16_t);

    if(RAW_FILE_FAIL == rawFileRead32(db->datRawFile, &vlen, cur_offset))
    {
        dbg_log(SEC_0131_DB, 0)(LOGSTDOUT,"error:gdbFetchValue: read vlen at offset %d failed\n", cur_offset);
        return GDB_ERROR;
    }
    cur_offset += sizeof(uint32_t);

    cur_offset += klen;/*skip key*/

    (*val) = (uint8_t *)SAFE_MALLOC(vlen, LOC_DB_0034);
    if(NULL == (*val))
    {
        dbg_log(SEC_0131_DB, 0)(LOGSTDOUT,"error:gdbFetchValue: alloc %d bytes failed\n", vlen);
        return GDB_ERROR;
    }

    if(RAW_FILE_FAIL == rawFileRead8s(db->datRawFile, (*val), vlen, val_len, cur_offset) || vlen != (*val_len))
    {
        dbg_log(SEC_0131_DB, 0)(LOGSTDOUT,"error:gdbFetchValue: read value %d bytes at offset %d failed where val_len = %d\n",
                vlen, cur_offset, *val_len);

        SAFE_FREE((*val), LOC_DB_0035);
        (*val) = NULL;
        (*val_len) = 0;
        return GDB_ERROR;
    }

    //dbg_log(SEC_0131_DB, 9)(LOGSTDOUT, "[DEBUG] gdbFetchValue: datRawFile Name : %s, offset %d\n", db->datRawFile->file_name, offset);
    //PRINT_BUFF("[DEBUG] gdbFetchValue: ", (*val), vlen);

    return GDB_SUCCESS;
}

GdbStatus
gdbFetchKV(const GDatabase *db, const offset_t offset, uint8_t **kv, uint32_t *kv_len)
{
    uint32_t dlen;

    offset_t cur_offset;

    cur_offset = offset;

    if(RAW_FILE_FAIL == rawFileRead32(db->datRawFile, &dlen, cur_offset))
    {
        dbg_log(SEC_0131_DB, 0)(LOGSTDOUT,"error:gdbFetchKV: read dlen at offset %d failed\n", cur_offset);
        return GDB_ERROR;
    }
    cur_offset += sizeof(uint32_t);

    (*kv) = (uint8_t *)SAFE_MALLOC(dlen, LOC_DB_0036);
    if(NULL == (*kv))
    {
        dbg_log(SEC_0131_DB, 0)(LOGSTDOUT,"error:gdbFetchKV: alloc %d bytes failed\n", dlen);
        return GDB_ERROR;
    }

    if(RAW_FILE_FAIL == rawFileRead8s(db->datRawFile, (*kv), dlen, kv_len, cur_offset) || dlen != (*kv_len))
    {
        dbg_log(SEC_0131_DB, 0)(LOGSTDOUT,"error:gdbFetchKV: read kv %d bytes at offset %d failed where kv_len = %d\n",
                dlen, cur_offset, *kv_len);

        SAFE_FREE((*kv), LOC_DB_0037);
        (*kv) = NULL;
        (*kv_len) = 0;
        return GDB_ERROR;
    }

    return GDB_SUCCESS;
}

GdbStatus
gdbUpdateValue(GDatabase *db, const offset_t offset, const uint8_t *value, const uint32_t val_len)
{
    uint32_t dlen;
    uint16_t klen;
    uint32_t vlen;

    offset_t cur_offset;

    cur_offset = offset;

    if(RAW_FILE_FAIL == rawFileRead32(db->datRawFile, &dlen, cur_offset))
    {
        dbg_log(SEC_0131_DB, 0)(LOGSTDOUT,"error:gdbUpdateValue: read dlen at offset %d failed\n", cur_offset);
        return GDB_ERROR;
    }
    cur_offset += sizeof(uint32_t);

    if(RAW_FILE_FAIL == rawFileRead16(db->datRawFile, &klen, cur_offset))
    {
        dbg_log(SEC_0131_DB, 0)(LOGSTDOUT,"error:gdbUpdateValue: read klen at offset %d failed\n", cur_offset);
        return GDB_ERROR;
    }
    cur_offset += sizeof(uint16_t);

    if(RAW_FILE_FAIL == rawFileRead32(db->datRawFile, &vlen, cur_offset))
    {
        dbg_log(SEC_0131_DB, 0)(LOGSTDOUT,"error:gdbUpdateValue: read vlen at offset %d failed\n", cur_offset);
        return GDB_ERROR;
    }
    cur_offset += sizeof(uint32_t);

    cur_offset += klen;/*skip key*/

    if(vlen != val_len)
    {
        dbg_log(SEC_0131_DB, 0)(LOGSTDOUT,"error:gdbUpdateValue: current vlen %d in dat file not equal to expecting len %d\n", vlen, val_len);
        return GDB_ERROR;
    }

    if(RAW_FILE_FAIL == rawFileUpdate8s(db->datRawFile, value, val_len, cur_offset))
    {
        dbg_log(SEC_0131_DB, 0)(LOGSTDOUT,"error:gdbUpdateValue: update value %d bytes at offset %d failed\n",
                          val_len, cur_offset);
        return GDB_ERROR;
    }

    return GDB_SUCCESS;
}

GdbStatus
gdbCompact(const GDatabase *db_src, GDatabase *db_des)
{
    uint8_t ret;

    MEM_CHECK(db_src->mainTree);
    MEM_CHECK(db_src->datRawFile);

    MEM_CHECK(db_des->mainTree);
    MEM_CHECK(db_des->datRawFile);

    ret = btreeCompact(db_src->mainTree, db_src->datRawFile,
                       db_des->mainTree, db_des->datRawFile);
    return (ret ? GDB_SUCCESS : GDB_ERROR);
}

GdbStatus
gdbRunthrough(LOG *log, const GDatabase *db, void (*runthrough)(LOG *, const offset_t , GDatabase *))
{
    btreeRunThrough(log, db->mainTree, runthrough);
    return GDB_SUCCESS;
}

GdbStatus
gdbTraversal(LOG *log, const GDatabase *db, void (*keyPrinter)(LOG *, const uint8_t *))
{
    btreePrettyPrint(log, db->mainTree, db->mainTree->root, 0, 0, keyPrinter);
    return GDB_SUCCESS;
}

GdbStatus
gdbFetchFirstKey(const GDatabase *db, uint8_t  **key, uint16_t *klen)
{
    BTreeTraversal *trav;
    offset_t offset;

    trav = btreeInitTraversal(db->mainTree);
    if(NULL == trav)
    {
        dbg_log(SEC_0131_DB, 0)(LOGSTDOUT, "error:gdbFetchFirstKey: init traversal of table %ld failed\n", db->table_id);
        return GDB_ERROR;
    }
    offset = btreeGetFirstOffset(trav);
    if(0 == offset)
    {
        dbg_log(SEC_0131_DB, 0)(LOGSTDOUT, "error:gdbFetchFirstKey: table %ld get last offset failed\n", db->table_id);
        btreeDestroyTraversal(trav);
        return GDB_ERROR;
    }

    if(GDB_ERROR == gdbFetchKey(db, offset, key, klen))
    {
        dbg_log(SEC_0131_DB, 0)(LOGSTDOUT, "error:gdbFetchFirstKey: table %ld fetch key at offset %d failed\n", db->table_id, offset);
        btreeDestroyTraversal(trav);
        return GDB_ERROR;
    }
    btreeDestroyTraversal(trav);
    return GDB_SUCCESS;
}

GdbStatus
gdbFetchFirstKV(const GDatabase *db, uint8_t  **kv, uint32_t *kv_len)
{
    BTreeTraversal *trav;
    offset_t offset;

    trav = btreeInitTraversal(db->mainTree);
    if(NULL == trav)
    {
        dbg_log(SEC_0131_DB, 0)(LOGSTDOUT, "error:gdbFetchFirstKV: init traversal of table %ld failed\n", db->table_id);
        return GDB_ERROR;
    }
    offset = btreeGetFirstOffset(trav);
    if(0 == offset)
    {
        dbg_log(SEC_0131_DB, 0)(LOGSTDOUT, "error:gdbFetchFirstKV: table %ld get last offset failed\n", db->table_id);
        btreeDestroyTraversal(trav);
        return GDB_ERROR;
    }

    if(GDB_ERROR == gdbFetchKV(db, offset, kv, kv_len))
    {
        dbg_log(SEC_0131_DB, 0)(LOGSTDOUT, "error:gdbFetchFirstKV: table %ld fetch key at offset %d failed\n", db->table_id, offset);
        btreeDestroyTraversal(trav);
        return GDB_ERROR;
    }
    btreeDestroyTraversal(trav);
    return GDB_SUCCESS;
}


GdbStatus
gdbFetchLastKey(const GDatabase *db, uint8_t  **key, uint16_t *klen)
{
    BTreeTraversal *trav;
    offset_t offset;

    trav = btreeInitTraversal(db->mainTree);
    if(NULL == trav)
    {
        dbg_log(SEC_0131_DB, 0)(LOGSTDOUT, "error:gdbFetchLastKey: init traversal of table %ld failed\n", db->table_id);
        return GDB_ERROR;
    }
    offset = btreeGetLastOffset(trav);
    if(0 == offset)
    {
        dbg_log(SEC_0131_DB, 0)(LOGSTDOUT, "error:gdbFetchLastKey: table %ld get last offset failed\n", db->table_id);
        btreeDestroyTraversal(trav);
        return GDB_ERROR;
    }

    if(GDB_ERROR == gdbFetchKey(db, offset, key, klen))
    {
        dbg_log(SEC_0131_DB, 0)(LOGSTDOUT, "error:gdbFetchLastKey: table %ld fetch key at offset %d failed\n", db->table_id, offset);
        btreeDestroyTraversal(trav);
        return GDB_ERROR;
    }
    btreeDestroyTraversal(trav);
    return GDB_SUCCESS;
}

GdbStatus
gdbFetchLastKV(const GDatabase *db, uint8_t  **kv, uint32_t *kv_len)
{
    BTreeTraversal *trav;
    offset_t offset;

    trav = btreeInitTraversal(db->mainTree);
    if(NULL == trav)
    {
        dbg_log(SEC_0131_DB, 0)(LOGSTDOUT, "error:gdbFetchLastKV: init traversal of table %ld failed\n", db->table_id);
        return GDB_ERROR;
    }
    offset = btreeGetLastOffset(trav);
    if(0 == offset)
    {
        dbg_log(SEC_0131_DB, 0)(LOGSTDOUT, "error:gdbFetchLastKV: table %ld get last offset failed\n", db->table_id);
        btreeDestroyTraversal(trav);
        return GDB_ERROR;
    }

    if(GDB_ERROR == gdbFetchKV(db, offset, kv, kv_len))
    {
        dbg_log(SEC_0131_DB, 0)(LOGSTDOUT, "error:gdbFetchLastKV: table %ld fetch key at offset %d failed\n", db->table_id, offset);
        btreeDestroyTraversal(trav);
        return GDB_ERROR;
    }
    btreeDestroyTraversal(trav);
    return GDB_SUCCESS;
}

GdbStatus
gdbCollectAllOffset(const GDatabase *db, offset_t **offset_list, uint32_t *offset_num)
{
    if(0 == btreeCollectAllOffset(db->mainTree, offset_list, offset_num))
    {
        dbg_log(SEC_0131_DB, 0)(LOGSTDOUT, "error:gdbCollectAllOffset: collect all offset from tree failed\n");
        return GDB_ERROR;
    }
    return GDB_SUCCESS;
}

GdbStatus
gdbKeyRegexScanKV(const GDatabase *db, int (*key_regex)(const uint8_t *, pcre *, pcre *, pcre *), pcre *row_re, pcre *colf_re, pcre *colq_re, CVECTOR *kv_vec)
{
    BTree *tree;
    BTreeTraversal *trav;
    offset_t offset;

    tree = db->mainTree;

    if (tree == NULL || key_regex == NULL)
    {
        return GDB_ERROR;
    }
    trav = btreeInitTraversal(tree);

    for (offset = btreeGetFirstOffset(trav);
         offset != 0;
         offset = btreeGetNextOffset(trav))
    {
        uint8_t   *kv;
        uint32_t   kv_len;
        uint8_t   *key;

        if(GDB_SUCCESS != gdbFetchKV(db, offset, &kv, &kv_len))
        {
            dbg_log(SEC_0131_DB, 0)(LOGSTDOUT, "error:gdbKeyRegexScanKV: fetch kv at offset %d failed\n", offset);
            return GDB_ERROR;
        }

        key = kv;
        if(0 != key_regex(key, row_re, colf_re, colq_re))
        {
            CBYTES *kv_bytes;
            /*matched*/
            dbg_log(SEC_0131_DB, 9)(LOGSTDOUT, "[DEBUG] gdbKeyRegexScanKV: matched at offset %d\n", offset);

            kv_bytes = cbytes_new(0);
            if(NULL == kv_bytes)
            {
                dbg_log(SEC_0131_DB, 0)(LOGSTDOUT, "error:gdbKeyRegexScanKV: new kv cbytes failed\n");
                SAFE_FREE(kv, LOC_DB_0038);
                return (GDB_ERROR);
            }

            cbytes_mount(kv_bytes, kv_len, kv);
            cvector_push(kv_vec, (void *)kv_bytes);
            continue;
        }

        SAFE_FREE(kv, LOC_DB_0039);
    }

    btreeDestroyTraversal(trav);
    return GDB_SUCCESS;
}

GdbStatus
gdbKeyRegexScanKVOffset(const GDatabase *db, int (*key_regex)(const uint8_t *, pcre *, pcre *, pcre *), pcre *row_re, pcre *colf_re, pcre *colq_re, CMAP *kvoffset_map)
{
    BTree *tree;
    BTreeTraversal *trav;
    offset_t offset;

    tree = db->mainTree;

    if (tree == NULL || key_regex == NULL)
    {
        return GDB_ERROR;
    }
    trav = btreeInitTraversal(tree);

    for (offset = btreeGetFirstOffset(trav);
         offset != 0;
         offset = btreeGetNextOffset(trav))
    {
        uint8_t   *kv;
        uint32_t   kv_len;
        uint8_t   *key;

        if(GDB_SUCCESS != gdbFetchKV(db, offset, &kv, &kv_len))
        {
            dbg_log(SEC_0131_DB, 0)(LOGSTDOUT, "error:gdbKeyRegexScanKVOffset: fetch kv at offset %d failed\n", offset);
            return GDB_ERROR;
        }

        key = kv;
        if(0 != key_regex(key, row_re, colf_re, colq_re))
        {
            CBYTES *kv_bytes;
            word_t  offset_word;
            /*matched*/
            dbg_log(SEC_0131_DB, 9)(LOGSTDOUT, "[DEBUG] gdbKeyRegexScanKVOffset: matched at offset %d\n", offset);

            kv_bytes = cbytes_new(0);
            if(NULL == kv_bytes)
            {
                dbg_log(SEC_0131_DB, 0)(LOGSTDOUT, "error:gdbKeyRegexScanKVOffset: new kv cbytes failed\n");
                SAFE_FREE(kv, LOC_DB_0040);
                return (GDB_ERROR);
            }

            cbytes_mount(kv_bytes, (UINT32)kv_len, (UINT8 *)kv);

            offset_word = offset;
            cmap_add(kvoffset_map, (void *)offset_word, (void *)kv_bytes, LOC_DB_0041);
            continue;
        }

        SAFE_FREE(kv, LOC_DB_0042);
    }

    btreeDestroyTraversal(trav);
    return GDB_SUCCESS;
}

GdbStatus
gdbKVRegexScanKV(const GDatabase *db, int (*kv_regex)(const uint8_t *, pcre *, pcre *, pcre *,pcre *), pcre *row_re, pcre *colf_re, pcre *colq_re, pcre *val_re, CVECTOR *kv_vec)
{
    BTree *tree;
    BTreeTraversal *trav;
    offset_t offset;

    tree = db->mainTree;

    if (tree == NULL || kv_regex == NULL)
    {
        return GDB_ERROR;
    }
    trav = btreeInitTraversal(tree);

    for (offset = btreeGetFirstOffset(trav);
         offset != 0;
         offset = btreeGetNextOffset(trav))
    {
        uint8_t   *kv;
        uint32_t   kv_len;
        uint8_t   *key;

        if(GDB_SUCCESS != gdbFetchKV(db, offset, &kv, &kv_len))
        {
            dbg_log(SEC_0131_DB, 0)(LOGSTDOUT, "error:gdbKVRegexScanKV: fetch kv at offset %d failed\n", offset);
            return GDB_ERROR;
        }

        key = kv;
        if(0 != kv_regex(key, row_re, colf_re, colq_re, val_re))
        {
            CBYTES *kv_bytes;
            /*matched*/
            dbg_log(SEC_0131_DB, 9)(LOGSTDOUT, "[DEBUG] gdbKVRegexScanKV: matched at offset %d\n", offset);

            kv_bytes = cbytes_new(0);
            if(NULL == kv_bytes)
            {
                dbg_log(SEC_0131_DB, 0)(LOGSTDOUT, "error:gdbKVRegexScanKV: new kv cbytes failed\n");
                SAFE_FREE(kv, LOC_DB_0043);
                return (GDB_ERROR);
            }

            cbytes_mount(kv_bytes, kv_len, kv);
            cvector_push(kv_vec, (void *)kv_bytes);
            continue;
        }

        SAFE_FREE(kv, LOC_DB_0044);
    }

    btreeDestroyTraversal(trav);
    return GDB_SUCCESS;
}

GdbStatus
gdbKVRegexScanKVOffset(const GDatabase *db, int (*kv_regex)(const uint8_t *, pcre *, pcre *, pcre *, pcre *), pcre *row_re, pcre *colf_re, pcre *colq_re, pcre *val_re, CMAP *kvoffset_map)
{
    BTree *tree;
    BTreeTraversal *trav;
    offset_t offset;

    tree = db->mainTree;

    if (tree == NULL || kv_regex == NULL)
    {
        return GDB_ERROR;
    }
    trav = btreeInitTraversal(tree);

    for (offset = btreeGetFirstOffset(trav);
         offset != 0;
         offset = btreeGetNextOffset(trav))
    {
        uint8_t   *kv;
        uint32_t   kv_len;
        uint8_t   *key;

        if(GDB_SUCCESS != gdbFetchKV(db, offset, &kv, &kv_len))
        {
            dbg_log(SEC_0131_DB, 0)(LOGSTDOUT, "error:gdbKVRegexScanKVOffset: fetch kv at offset %d failed\n", offset);
            return GDB_ERROR;
        }

        key = kv;
        if(0 != kv_regex(key, row_re, colf_re, colq_re, val_re))
        {
            CBYTES *kv_bytes;
            word_t  offset_word;
            /*matched*/
            dbg_log(SEC_0131_DB, 9)(LOGSTDOUT, "[DEBUG] gdbKVRegexScanKVOffset: matched at offset %d\n", offset);

            kv_bytes = cbytes_new(0);
            if(NULL == kv_bytes)
            {
                dbg_log(SEC_0131_DB, 0)(LOGSTDOUT, "error:gdbKVRegexScanKVOffset: new kv cbytes failed\n");
                SAFE_FREE(kv, LOC_DB_0045);
                return (GDB_ERROR);
            }

            cbytes_mount(kv_bytes, (UINT32)kv_len, (UINT8 *)kv);

            offset_word = offset;
            cmap_add(kvoffset_map, (void *)offset_word, (void *)kv_bytes, LOC_DB_0046);
            continue;
        }

        SAFE_FREE(kv, LOC_DB_0047);
    }

    btreeDestroyTraversal(trav);
    return GDB_SUCCESS;
}


#ifdef __cplusplus
}
#endif/*__cplusplus*/

