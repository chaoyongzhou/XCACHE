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

GdbBlock *
gdbCacheAddBlockNoLock(GDatabase *db, GdbBlock *block)
{
    GdbBlock *tempBlock;
    uint32_t i;

    if (block->offset == 0)
    {
        dbg_log(SEC_0131_DB, 0)(LOGSTDOUT, "error:gdbCacheAddBlockNoLock: Trying to add a block to the list with offset 0.\n");
        abort();
    }

    if (block->inList == 1)/*already in cache list*/
    {
        return block;
    }

    /* See if it's already in the list. */
    tempBlock = gdbCacheGetBlockNoLock(db, block->offset);
    if (tempBlock != NULL)
    {
        dbg_log(SEC_0131_DB, 9)(LOGSTDOUT, "[DEBUG] gdbCacheAddBlockNoLock: get cached block %p with detail %p and offset %d, db %p (vs %p)\n",
                            block, block->detail, block->offset, block->db, db);
        return tempBlock;
    }

    if (db->openBlockCount >= db->openBlockSize)
    {
        GdbBlock **newBlocks;
        uint32_t   newSize;

        newSize = 2 * db->openBlockSize;

        MEM_CHECK(newBlocks = (GdbBlock **)SAFE_MALLOC(newSize * sizeof(GdbBlock *), LOC_DB_0103));
        memset(newBlocks, 0, newSize * sizeof(GdbBlock *));

        for (i = 0; i < db->openBlockSize; i++)
        {
            newBlocks[i] = db->openBlocks[i];
        }
        SAFE_FREE(db->openBlocks, LOC_DB_0104);

        db->openBlocks    = newBlocks;
        db->openBlockSize = newSize;
    }

    /* Find a place to put this. */
    for (i = 0; i < db->openBlockSize; i++)
    {
        if (db->openBlocks[i] == NULL)
        {
            db->openBlocks[i] = block;
            db->openBlockCount++;

            block->refCount++;
            block->inList = 1;

            return block;
        }
    }

    dbg_log(SEC_0131_DB, 0)(LOGSTDOUT, "error:gdbCacheAddBlockNoLock: Unable to place the open block in the block list!\n");
    return NULL;
}

GdbBlock *
gdbCacheAddBlock(GDatabase *db, GdbBlock *block)
{
    GdbBlock *block_cached;
    gdbLockFreeBlockList(db, DB_WRITE_LOCK, LOC_DB_0105);
    block_cached = gdbCacheAddBlockNoLock(db, block);
    //dbg_log(SEC_0131_DB, 9)(LOGSTDOUT, "[DEBUG] gdbCacheAddBlock: openBlockCount %d, openBlockSize %d\n", db->openBlockCount, db->openBlockSize);
    gdbUnlockFreeBlockList(db, LOC_DB_0106);
    return block_cached;
}

uint8_t
gdbCacheRemoveBlockNoLock(GDatabase *db, GdbBlock *block)
{
    uint32_t i;

    if (block->offset == 0)
    {
        dbg_log(SEC_0131_DB, 0)(LOGSTDOUT, "error:gdbCacheRemoveBlockNoLock: Trying to remove block from list with offset 0\n");
        abort();
    }

    if (db->openBlockCount == 0)
    {
        dbg_log(SEC_0131_DB, 1)(LOGSTDOUT, "warn:gdbCacheRemoveBlockNoLock: db->openBlockCount == 0\n");
        return 0;
    }

    for (i = 0; i < db->openBlockSize; i++)
    {
        if (db->openBlocks[i] != NULL &&
            db->openBlocks[i]->offset == block->offset)
        {
            db->openBlocks[i]->refCount--;

            if (db->openBlocks[i]->refCount <= 0)
            {
                db->openBlocks[i] = NULL;
                db->openBlockCount--;
                block->inList = 0;

                return 0;
            }

            return db->openBlocks[i]->refCount;
        }
    }

    dbg_log(SEC_0131_DB, 0)(LOGSTDOUT, "error:gdbCacheRemoveBlockNoLock: No open block found at offset %d!\n",
                        block->offset);

    return 0;
}

uint8_t
gdbCacheRemoveBlock(GDatabase *db, GdbBlock *block)
{
    uint8_t refCount;

    if (block->offset == 0)
    {
        dbg_log(SEC_0131_DB, 0)(LOGSTDOUT, "error:gdbCacheRemoveBlock: Trying to remove block from list with offset 0\n");
        abort();
    }

    gdbLockFreeBlockList(db, DB_WRITE_LOCK, LOC_DB_0107);
    refCount = gdbCacheRemoveBlockNoLock(db, block);
    gdbUnlockFreeBlockList(db, LOC_DB_0108);
    return refCount;
}

GdbBlock *
gdbCacheGetBlockNoLock(GDatabase *db, offset_t offset)
{
    uint32_t i;

    for (i = 0; i < db->openBlockSize; i++)
    {
        if (db->openBlocks[i] != NULL &&
            db->openBlocks[i]->offset == offset)
        {
            db->openBlocks[i]->refCount++;

            return db->openBlocks[i];
        }
    }

    return NULL;
}

GdbBlock *
gdbCacheGetBlock(GDatabase *db, offset_t offset)
{
    GdbBlock *block;

    gdbLockFreeBlockList(db, DB_READ_LOCK, LOC_DB_0109);
    block = gdbCacheGetBlockNoLock(db, offset);
    gdbUnlockFreeBlockList(db, LOC_DB_0110);
    return block;
}

void
gdbCachePrintBlockNoLock(LOG *log, const GDatabase *db)
{
    uint32_t i;

    for (i = 0; i < db->openBlockSize; i++)
    {
        if(db->openBlocks[i] != NULL)
        {
            sys_log(log, "[DEBUG] gdbCachePrintBlockNoLock: [%d] db %p, block %p, offset %d, refCount %d, detail %p\n", i,
                         db, db->openBlocks[i], db->openBlocks[i]->offset, db->openBlocks[i]->refCount, db->openBlocks[i]->detail
                         );
        }
    }
    return;
}


void
gdbCachePrintBlock(LOG *log, GDatabase *db)
{
    gdbLockFreeBlockList(db, DB_READ_LOCK, LOC_DB_0111);
    gdbCachePrintBlockNoLock(log, db);
    gdbUnlockFreeBlockList(db, LOC_DB_0112);
    return;
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/


