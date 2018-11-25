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

uint8_t
gdbGetFreeBlockList(GDatabase *db, GdbFreeBlock **blocks, uint32_t *count)
{
    GdbFreeBlock *blockList;
    uint32_t listSize;
    uint8_t *buffer;
    size_t   s;
    uint32_t i, counter = 0;
    offset_t __offset;

    if (blocks == NULL || count == NULL)
    {
        return 0;
    }
    *blocks = NULL;

    /* Seek to the start of the block list. */
    rawFileSeek(db->idxRawFile, DB_FREE_BLOCK_LIST_OFFSET, SEEK_SET);
    __offset = DB_FREE_BLOCK_LIST_OFFSET;
    if (rawFileRead(db->idxRawFile, __offset, &db->freeBlockCount, sizeof(uint32_t), 1, LOC_DB_0001) != 1)
    {
        db->freeBlockCount = 0;
    }
    else
    {
        __offset += sizeof(uint32_t);
    }
    db->freeBlockCount = gdb_ntoh_uint32(db->freeBlockCount);

    *count = db->freeBlockCount;

    if (db->freeBlockCount == 0)
    {
        return 0;
    }
    /* Get the total size of the free blocks list. */
    listSize = db->freeBlockCount * (sizeof(uint16_t) + sizeof(offset_t));

    /* Allocate the buffer. */
    MEM_CHECK(buffer = (uint8_t *)SAFE_MALLOC(listSize, LOC_DB_0002));

    /* Read in the list. */
    //rawFileSeek(db->idxRawFile, DB_FREE_BLOCK_LIST_OFFSET + sizeof(uint32_t), SEEK_SET);
    if ((s = rawFileRead(db->idxRawFile, __offset, buffer, 1, listSize, LOC_DB_0003)) != listSize)
    {
        dbg_log(SEC_0131_DB, 0)(LOGSTDOUT,"error:gdbGetFreeBlockList: Truncated block list.\n"
                          "Expected %d bytes, got %d bytes. Block list offset = %d\n"
                          "Free block count = %d. Filename = %s\n",
                          listSize, (uint32_t)s, DB_FREE_BLOCK_LIST_OFFSET, db->freeBlockCount,
                          db->filename);
        abort();
    }

    MEM_CHECK(blockList = (GdbFreeBlock *)SAFE_MALLOC(db->freeBlockCount * sizeof(GdbFreeBlock), LOC_DB_0004));

    for (i = 0; i < db->freeBlockCount; i++)
    {
        blockList[i].size   = gdbGet16(buffer, &counter);
        blockList[i].offset = gdbGetOffset(buffer, &counter);
    }

    *blocks = blockList;

    SAFE_FREE(buffer, LOC_DB_0005);

    return 1;
}

void
gdbWriteFreeBlockList(GDatabase *db, GdbFreeBlock *blocks, uint32_t count)
{
    uint32_t listSize;
    uint8_t *buffer;
    uint32_t i, counter = 0;
    offset_t __offset;

    if (db == NULL || blocks == NULL)
    {
        return;
    }
    /* Get the total size of the list. */
    listSize = sizeof(uint32_t) + count * (sizeof(uint16_t) + sizeof(offset_t));

    /* Allocate the buffer for the block list. */
    MEM_CHECK(buffer = (uint8_t *)SAFE_MALLOC(listSize, LOC_DB_0006));

    gdbPut32(buffer, &counter, count);

    for (i = 0; i < count; i++)
    {
        gdbPut16(buffer, &counter, blocks[i].size);
        gdbPutOffset(buffer, &counter, blocks[i].offset);
    }

    rawFileSeek(db->idxRawFile, DB_FREE_BLOCK_LIST_OFFSET, SEEK_SET);
    __offset = DB_FREE_BLOCK_LIST_OFFSET;

    rawFileWrite(db->idxRawFile, __offset, buffer, listSize, 1, LOC_DB_0007);

    SAFE_FREE(buffer, LOC_DB_0008);
}

void
gdbFreeBlockList(GdbFreeBlock *blocks)
{
    if (blocks == NULL)
    {
        return;
    }
    SAFE_FREE(blocks, LOC_DB_0009);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/


