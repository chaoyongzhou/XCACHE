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

typedef struct
{
    uint16_t multiple;

    void *(*readBlock)(GdbBlock *block, const uint8_t *buffer, void *extra);
    void (*writeBlock)(GdbBlock *block, uint8_t **buffer, uint32_t *size);

    void *(*create)(GdbBlock *block, void *extra);
    void (*destroy)(void *data);

} GdbBlockTypeInfo;

static GdbBlockTypeInfo blockTypeInfo[] =
{
    /** Raw data block */
    { 64, NULL, NULL, NULL, NULL },

    /** B+Tree header block */
    { 128, btreeReadHeader, btreeWriteHeader, btreeCreateHeader, btreeDestroyHeader },

    /** B+Tree node block */
    /*WARNING: multiple is 16bits which up to 64K, hence here must be smaller than 64 * 1024*/
    { 32 * 1024, btreeReadNodeBlock, btreeWriteNodeBlock, btreeCreateNodeBlock, btreeDestroyNodeBlock },
};

static int
__blockCompare(const void *a, const void *b)
{
    const GdbFreeBlock *block1 = (const GdbFreeBlock *)a;
    const GdbFreeBlock *block2 = (const GdbFreeBlock *)b;

    if (block1->size   > block2->size)   return  1;
    if (block1->size   < block2->size)   return -1;
    if (block1->offset > block2->offset) return  1;
    if (block1->offset < block2->offset) return -1;

    return 0;
}

static int
__offsetCompare(const void *a, const void *b)
{
    offset_t o1 = *(offset_t *)a;
    offset_t o2 = *(offset_t *)b;

    if (o1 < o2) return -1;
    if (o1 > o2) return  1;

    return  0;
}

GdbBlock *
gdbNewBlock(GDatabase *db, uint8_t blockType, void *extra)
{
    GdbBlock *block;
    uint8_t typeIndex;

    if (db == NULL || !GDB_VALID_BLOCK_TYPE(blockType))
    {
        return NULL;
    }
    MEM_CHECK(block = (GdbBlock *)SAFE_MALLOC(sizeof(GdbBlock), LOC_DB_0010));
    memset(block, 0, sizeof(GdbBlock));

    block->type     = blockType;
    block->db       = db;
    block->inList   = 0;
    block->refCount = 0;

    GDB_SET_DIRTY(block);

    typeIndex = blockType - 1;

    block->multiple = blockTypeInfo[typeIndex].multiple;

    if (blockTypeInfo[typeIndex].create != NULL)
    {
        block->detail = blockTypeInfo[typeIndex].create(block, extra);
    }

    return block;
}

void
gdbDestroyBlockNoLock(GdbBlock *block)
{
    uint8_t typeIndex;

    if (block == NULL)
    {
        return;
    }
    if (gdbCacheRemoveBlockNoLock(block->db, block) > 0)
    {
        dbg_log(SEC_0131_DB, 9)(LOGSTDNULL, "[DEBUG] gdbDestroyBlockNoLock: rmv cached block %p with detail %p and offset %d, db %p, refCount %d\n",
                            block, block->detail, block->offset, block->db, block->refCount);
        return;
    }
    typeIndex = block->type - 1;

    if (block->detail != NULL)
    {
        if (blockTypeInfo[typeIndex].destroy != NULL)
        {
            blockTypeInfo[typeIndex].destroy(block->detail);
        }
        else
        {
            SAFE_FREE(block->detail, LOC_DB_0011);
        }
    }

    if (GDB_IS_DIRTY(block))
    {
        dbg_log(SEC_0131_DB, 0)(LOGSTDOUT, "error:gdbDestroyBlockNoLock: Dirty node at offset %d has not been written to disk.\n",
                            block->offset);
    }

    if (block->chain != NULL)
    {
        SAFE_FREE(block->chain, LOC_DB_0012);
    }
    SAFE_FREE(block, LOC_DB_0013);
}

void
gdbDestroyBlock(GdbBlock *block)
{
    uint8_t typeIndex;

    if (block == NULL)
    {
        return;
    }
    if (gdbCacheRemoveBlock(block->db, block) > 0)
    {
        dbg_log(SEC_0131_DB, 9)(LOGSTDNULL, "[DEBUG] gdbDestroyBlock: rmv cached block %p with detail %p and offset %d, db %p, refCount %d\n",
                            block, block->detail, block->offset, block->db, block->refCount);
        return;
    }
    typeIndex = block->type - 1;

    if (block->detail != NULL)
    {
        if (blockTypeInfo[typeIndex].destroy != NULL)
        {
            blockTypeInfo[typeIndex].destroy(block->detail);
        }
        else
        {
            SAFE_FREE(block->detail, LOC_DB_0014);
        }
    }

    if (GDB_IS_DIRTY(block))
    {
        dbg_log(SEC_0131_DB, 0)(LOGSTDOUT, "error:gdbDestroyBlock: Dirty node at offset %d has not been written to disk.\n",
                            block->offset);
    }

    if (block->chain != NULL)
    {
        SAFE_FREE(block->chain, LOC_DB_0015);
    }
    SAFE_FREE(block, LOC_DB_0016);
}

GdbBlock *
gdbReadBlockHeaderNoLock(GDatabase *db, offset_t offset, uint8_t blockType)
{
    GdbBlock *block;
    GdbBlock *block_cached;
    uint8_t   header[GDB_BLOCK_HEADER_SIZE];
    uint32_t  counter = 0;
    uint8_t   typeIndex;

    if (db == NULL || !GDB_VALID_OFFSET(offset) ||
        (blockType != GDB_BLOCK_ANY && !GDB_VALID_BLOCK_TYPE(blockType)))
    {
        return NULL;
    }
#if 0/*comment: checking cached block list will happen in gdbReadBlock*/
    /* See if the block is cached. */
    if ((block = gdbCacheGetBlockNoLock(db, offset)) != NULL)
    {
        if (blockType == GDB_BLOCK_ANY || blockType == block->type)
        {
            return block;
        }
        else
        {
            return NULL;
        }
    }
#endif
    /* Seek to the offset of the block. */
    rawFileSeek(db->idxRawFile, offset, SEEK_SET);
    if (rawFileRead(db->idxRawFile, offset, header, GDB_BLOCK_HEADER_SIZE, 1, LOC_DB_0017) != 1)
    {
        return NULL;
    }

    /* Allocate memory for the block. */
    MEM_CHECK(block = (GdbBlock *)SAFE_MALLOC(sizeof(GdbBlock), LOC_DB_0018));
    memset(block, 0, sizeof(GdbBlock));

    block->db = db;

    /* Store the info from the header. */
    block->type = gdbGet8(header, &counter);

    /* Make sure the type is valid. */
    if (!GDB_VALID_BLOCK_TYPE(block->type) ||
        (blockType != GDB_BLOCK_ANY && blockType != block->type))
    {
        SAFE_FREE(block, LOC_DB_0019);

        return NULL;
    }

    typeIndex = block->type - 1;

    block->offset = offset;

    block->multiple = blockTypeInfo[typeIndex].multiple;

    block->dataSize = gdbGet32(header, &counter);
    block->flags    = gdbGet16(header, &counter);
    block->next     = gdbGetOffset(header, &counter);
    block->listNext = gdbGetOffset(header, &counter);

    GDB_CLEAR_DIRTY(block);

    dbg_log(SEC_0131_DB, 9)(LOGSTDNULL, "[DEBUG] gdbReadBlockHeaderNoLock: add cached block %p with detail %p and offset %d, db %p\n",
                        block, block->detail, block->offset, block->db);

    block_cached = gdbCacheAddBlockNoLock(block->db, block);
    if(block_cached != block)
    {
        dbg_log(SEC_0131_DB, 1)(LOGSTDNULL, "warn:gdbReadBlockHeaderNoLock: add block %p to cache but return cached block %p\n", block, block_cached);
        gdbDestroyBlockNoLock(block);
        return block_cached;
    }

    return block;
}

GdbBlock *
gdbReadBlockHeader(GDatabase *db, offset_t offset, uint8_t blockType)
{
    GdbBlock *block;
    gdbLockFreeBlockList(db, DB_WRITE_LOCK, LOC_DB_0020);
    block = gdbReadBlockHeaderNoLock(db, offset, blockType);
    gdbUnlockFreeBlockList(db, LOC_DB_0021);
    return block;
}

void
gdbWriteBlockHeader(GdbBlock *block)
{
    GDatabase *db;
    uint8_t    header[GDB_BLOCK_HEADER_SIZE];
    uint32_t   counter = 0;

    if (block == NULL || !GDB_IS_DIRTY(block))
    {
        return;
    }
    db = block->db;

    if (block->offset == 0)
    {
        return;
    }
    /* Write the header to a buffer. */
    gdbPut8(header,  &counter, block->type);
    gdbPut32(header, &counter, block->dataSize);
    gdbPut16(header, &counter, block->flags);
    gdbPutOffset(header, &counter, block->next);
    gdbPutOffset(header, &counter, block->listNext);

    /* Write the header to disk. */
    rawFileSeek(db->idxRawFile, block->offset, SEEK_SET);
    rawFileWrite(db->idxRawFile, block->offset, header, GDB_BLOCK_HEADER_SIZE, 1, LOC_DB_0022);

    GDB_CLEAR_DIRTY(block);

    if (block->inList == 0)
    {
        dbg_log(SEC_0131_DB, 9)(LOGSTDNULL, "[DEBUG] gdbWriteBlockHeader: add cached block %p with detail %p and offset %d, db %p\n",
                            block, block->detail, block->offset, block->db);
        gdbCacheAddBlock(block->db, block);
    }
}


GdbBlock *
gdbReadBlock(GDatabase *db, offset_t offset, uint8_t blockType,
             void *extra)
{
    GdbBlock     *block;
    uint8_t      *buffer;
    uint32_t      pos, i;
    uint32_t      dataSize;
    uint8_t       typeIndex;
    offset_t      __offset;

    if (db == NULL)
    {
        dbg_log(SEC_0131_DB, 0)(LOGSTDOUT, "error:gdbReadBlock: db is null\n");
        return NULL;
    }

    if (!GDB_VALID_OFFSET(offset))
    {
        dbg_log(SEC_0131_DB, 0)(LOGSTDOUT, "error:gdbReadBlock: invalid offset %d < DB_FREE_BLOCK_LIST_OFFSET %d\n",
                           offset, (uint32_t)DB_FREE_BLOCK_LIST_OFFSET);
        return NULL;
    }

    if(blockType != GDB_BLOCK_ANY && !GDB_VALID_BLOCK_TYPE(blockType))
    {
        dbg_log(SEC_0131_DB, 0)(LOGSTDOUT, "error:gdbReadBlock: blockType %d != GDB_BLOCK_ANY(%d) and not belong to (%d, %d)\n",
                           blockType, GDB_BLOCK_ANY, GDB_BLOCK_MIN_TYPE, GDB_BLOCK_MAX_TYPE);
        return NULL;
    }
#if 0
    if (db == NULL || !GDB_VALID_OFFSET(offset) ||
        (blockType != GDB_BLOCK_ANY && !GDB_VALID_BLOCK_TYPE(blockType)))
    {
        return NULL;
    }
#endif

#if 1
    /*comment: the code segment CANNOT move to gdbReadBlockHeader(NoLock) because when gdbReadBlockHeader(NoLock) return back*/
    /*it will be hard to determine it comes from cached list or new created*/
    gdbLockFreeBlockList(db, DB_WRITE_LOCK, LOC_DB_0023);
    if ((block = gdbCacheGetBlockNoLock(db, offset)) != NULL)
    {
        gdbUnlockFreeBlockList(db, LOC_DB_0024);
        dbg_log(SEC_0131_DB, 9)(LOGSTDNULL, "[DEBUG] gdbReadBlock: get cached block %p with detail %p and offset %d (vs %d), db %p (vs %p)\n",
                            block, block->detail, block->offset, offset, block->db, db);
        if (blockType == GDB_BLOCK_ANY || blockType == block->type)
        {
            return block;
        }
        else
        {
            dbg_log(SEC_0131_DB, 0)(LOGSTDOUT, "error:gdbReadBlock: invalid blockType %d or mismatch block type %d\n",
                                blockType, block->type);
            return NULL;
        }
    }
#endif
    __offset = offset;

    block = gdbReadBlockHeaderNoLock(db, offset, blockType);
    if (block == NULL)
    {
        gdbUnlockFreeBlockList(db, LOC_DB_0025);
        dbg_log(SEC_0131_DB, 0)(LOGSTDOUT, "error:gdbReadBlock: Unable to read block at %d\n", offset);
        return NULL;
    }

    __offset += GDB_BLOCK_HEADER_SIZE;

    /* Get the number of needed blocks. */
    block->chainCount = gdbGetNeededBlockCount(block->dataSize, block->multiple);

    /* Build the chain array. */
    MEM_CHECK(block->chain = (offset_t *)SAFE_MALLOC(block->chainCount * sizeof(offset_t), LOC_DB_0026));
    memset(block->chain, 0, block->chainCount * sizeof(offset_t));

    block->chain[0] = offset;

    typeIndex = block->type - 1;

    /* Create the buffer. */
    MEM_CHECK(buffer = (uint8_t *)SAFE_MALLOC(block->dataSize, LOC_DB_0027));

    /* Read in the first block. */
    dataSize = (block->dataSize < block->multiple - GDB_BLOCK_HEADER_SIZE ?
               block->dataSize : block->multiple - GDB_BLOCK_HEADER_SIZE);

    rawFileSeek(db->idxRawFile, __offset, SEEK_SET);
    if (rawFileRead(db->idxRawFile, __offset, buffer, dataSize, 1, LOC_DB_0028) != 1)
    {
        dbg_log(SEC_0131_DB, 0)(LOGSTDOUT, "error:gdbReadBlock: Unable to read %d bytes from %s at offset %d where cur_size %d\n",
                            dataSize,db->idxRawFile->file_name, __offset,rawFileCurSize(db->idxRawFile));
        exit(1);
    }
    __offset += dataSize;

    pos = block->multiple - GDB_BLOCK_HEADER_SIZE;

    rawFileSeek(db->idxRawFile, __offset, SEEK_SET);
    if (block->next != 0)
    {
        offset_t nextOffset = block->next;
        offset_t prevOffset = block->offset;
        uint16_t blockDataSize = block->multiple - sizeof(offset_t);

        block->chain[1] = nextOffset;

        i = 2;

        /* Read in any overflow blocks. */
        while (nextOffset != 0)
        {
            if (prevOffset + block->multiple != nextOffset)
            {
                __offset = nextOffset;
            }
            prevOffset = nextOffset;

            rawFileSeek(db->idxRawFile, __offset, SEEK_SET);
            rawFileRead(db->idxRawFile, __offset, &nextOffset, sizeof(offset_t), 1, LOC_DB_0029);
            dbg_log(SEC_0131_DB, 9)(LOGSTDNULL, "[DEBUG] gdbReadBlock: fp %p: read nextOffset %d at offset %d\n", db->idxRawFile, gdb_ntoh_offset(nextOffset), __offset);
            __offset += sizeof(offset_t);

            nextOffset = gdb_ntoh_offset(nextOffset);

            if (prevOffset == nextOffset)
            {
                dbg_log(SEC_0131_DB, 0)(LOGSTDOUT, "error:gdbReadBlock: Infinite loop detected in database blocks in %s! Report this!\n",
                                    db->filename);
                abort();
            }

            if (i < block->chainCount)
            {
                block->chain[i++] = nextOffset;
            }

            dataSize = (block->dataSize - pos < blockDataSize ?
                        block->dataSize - pos : blockDataSize);
            rawFileSeek(db->idxRawFile, __offset, SEEK_SET);
            rawFileRead(db->idxRawFile, __offset, buffer + pos, 1, dataSize, LOC_DB_0030);
            __offset += dataSize;

            pos += blockDataSize;
        }
    }

    /* See if there is a read function assigned. */
    if (blockTypeInfo[typeIndex].readBlock != NULL)
    {
        /*comment: the block may belong to the cached block list, lock should reach here, */
        /*otherwise, may several readers will btreeNode info to this block which would cause memory leak*/
        /* Call the specific block type's read function. */
        block->detail = blockTypeInfo[typeIndex].readBlock(block, buffer, extra);

        SAFE_FREE(buffer, LOC_DB_0031);
    }
    else
    {
        /* Just use the buffer as the detailed info. */
        block->detail = buffer;
    }

    gdbUnlockFreeBlockList(db, LOC_DB_0032);
    return block;
}

void
gdbWriteBlock(GdbBlock *block)
{
    GDatabase    *db;
    uint8_t      *buffer;
    offset_t     *oldChain;
    uint8_t       typeIndex;
    uint32_t      oldChainCount;
    uint32_t      i, pos;
    uint32_t      dataSize;
    offset_t      __offset;

    if (block == NULL || !GDB_IS_DIRTY(block))
    {
        return;
    }
    /* Set a couple of vars we'll be using. */
    db        = block->db;
    typeIndex = block->type - 1;

    /* Save the old data. */
    oldChainCount = block->chainCount;
    oldChain      = block->chain;

    /* See if there is a write function assigned. */
    if (blockTypeInfo[typeIndex].writeBlock != NULL)
    {
        /* Write the block info to a buffer. */
        blockTypeInfo[typeIndex].writeBlock(block, &buffer, &block->dataSize);
    }
    else
    {
        buffer = (uint8_t *)block->detail;
    }

    if (buffer == NULL)
    {
        dbg_log(SEC_0131_DB, 0)(LOGSTDOUT, "error:gdbWriteBlock: buffer == NULL\n");
        exit(1);
    }

    /* Get the number of needed blocks. */
    block->chainCount = gdbGetNeededBlockCount(block->dataSize, block->multiple);

    if (oldChainCount == 0)
    {
        /* Reserve new blocks. */
        block->chain = gdbReserveBlockChain(db, block->chainCount, block->type);
    }
    else if (block->chainCount < oldChainCount)
    {
        /* The number of needed blocks is shorter than before. */
        MEM_CHECK(block->chain = (offset_t *)SAFE_MALLOC(block->chainCount * sizeof(offset_t), LOC_DB_0033));
        memcpy(block->chain, oldChain, block->chainCount * sizeof(offset_t));
    }
    else if (block->chainCount > oldChainCount)
    {
        offset_t *newChain;
        uint32_t j;

        /* The number of needed blocks is longer than before. */
        MEM_CHECK(block->chain = (offset_t *)SAFE_MALLOC(block->chainCount * sizeof(offset_t), LOC_DB_0034));

        newChain = gdbReserveBlockChain(db, block->chainCount - oldChainCount, block->type);

        memcpy(block->chain, oldChain, oldChainCount * sizeof(offset_t));

        for (i = oldChainCount, j = 0; i < block->chainCount; i++, j++)
        {
            block->chain[i] = newChain[j];
        }
        SAFE_FREE(newChain, LOC_DB_0035);
    }

    /*
     * Set the offset and next block, if this spills over into
     * additional blocks.
     */
    block->offset = block->chain[0];

    if (block->chainCount > 1)
    {
        block->next = block->chain[1];
    }
    else
    {
        block->next = 0;
    }
    /* Write the first block header */
    __offset = block->offset;
    gdbWriteBlockHeader(block);
    __offset += GDB_BLOCK_HEADER_SIZE;

    /* Write the first block. */
    dataSize = (block->dataSize < block->multiple - GDB_BLOCK_HEADER_SIZE ?
                block->dataSize : block->multiple - GDB_BLOCK_HEADER_SIZE);
    rawFileWrite(db->idxRawFile, __offset, buffer, 1, dataSize, LOC_DB_0036);
    __offset += dataSize;

    if (block->dataSize < block->multiple - GDB_BLOCK_HEADER_SIZE)
    {
        uint32_t count;
        count = block->multiple - GDB_BLOCK_HEADER_SIZE - block->dataSize;
        gdbPad(db->idxRawFile, __offset, count);
        __offset += count;
    }
    else
    {
        uint8_t *blockBuffer;

        MEM_CHECK(blockBuffer = (uint8_t *)SAFE_MALLOC(block->multiple, LOC_DB_0037));

        pos = block->multiple - GDB_BLOCK_HEADER_SIZE;

        /* Write any overflow blocks. */
        for (i = 1; i < block->chainCount; i++)
        {
            offset_t nextOffset;
            uint32_t relPos;

            nextOffset = ((i + 1 < block->chainCount) ? block->chain[i + 1] : 0);

            relPos = block->dataSize - pos;

            /* Reset the block buffer. */
            memset(blockBuffer, 0, block->multiple);

            dbg_log(SEC_0131_DB, 9)(LOGSTDNULL, "[DEBUG] gdbWriteBlock: fp %p: write nextOffset %d at offset %d\n", db->idxRawFile, nextOffset, __offset);
            /* Write to it. */
            nextOffset = gdb_hton_offset(nextOffset);

            memcpy(blockBuffer, &nextOffset, sizeof(offset_t));
            memcpy(blockBuffer + sizeof(offset_t), buffer + pos,
                   (relPos < block->multiple - sizeof(offset_t) ?
                    relPos : block->multiple - sizeof(offset_t)));

            /* Write the block buffer. */
            if (block->chain[i - 1] + block->multiple != block->chain[i])
            {
                rawFileSeek(db->idxRawFile, block->chain[i], SEEK_SET);
                __offset = block->chain[i];
            }
            rawFileWrite(db->idxRawFile, __offset, blockBuffer, 1, block->multiple, LOC_DB_0038);
            __offset += block->multiple;

            pos += block->multiple - sizeof(offset_t);
        }

        SAFE_FREE(blockBuffer, LOC_DB_0039);
    }

    if (oldChainCount != 0)
    {
        /* If the chain shrunk, free up the discarded blocks. */
        if (block->chainCount < oldChainCount)
        {
            gdbFreeBlockChain(db, &oldChain[block->chainCount], oldChainCount - block->chainCount, block->type);
        }

        if (oldChainCount != block->chainCount)
        {
            SAFE_FREE(oldChain, LOC_DB_0040);
        }
    }

    if (buffer != block->detail)
    {
        SAFE_FREE(buffer, LOC_DB_0041);
    }
}

uint8_t
gdbBlockTypeAt(GDatabase *db, offset_t offset)
{
    uint8_t   type;
    GdbBlock *block;

    if (db == NULL || !GDB_VALID_OFFSET(offset))
    {
        return GDB_BLOCK_ANY; /* Um. Kind of an error? */
    }
    if ((block = gdbCacheGetBlock(db, offset)) != NULL)
    {
        dbg_log(SEC_0131_DB, 9)(LOGSTDNULL, "[DEBUG] gdbBlockTypeAt: get cached block %p with detail %p and block %d (vs %d), db %p (vs %p)\n",
                            block, block->detail, block->offset, offset, block->db, db);
        return block->type;
    }
    rawFileSeek(db->idxRawFile, offset, SEEK_SET);
    if (rawFileRead(db->idxRawFile, offset, &type, 1, 1, LOC_DB_0042) != 1)
    {
        return GDB_BLOCK_ANY; /* Um. Kind of an error? */
    }
    return type;
}

offset_t *
gdbReserveBlockChain(GDatabase *db, uint16_t count, uint8_t blockType)
{
    GdbFreeBlock  *freeBlocks, *newFreeBlocks;
    offset_t      *chain;
    offset_t       offset;
    uint16_t       blockSize;
    uint32_t       blockCount, fillCount, newListCount;
    uint32_t       i, j;
    uint8_t        result;

    if (db == NULL || count == 0 || !GDB_VALID_BLOCK_TYPE(blockType))
    {
        return NULL;
    }

    /* Get the block size for this type. */
    blockSize = blockTypeInfo[blockType - 1].multiple;

    /* Create the chain. */
    MEM_CHECK(chain = (offset_t *)SAFE_MALLOC(count * sizeof(offset_t), LOC_DB_0043));

    /* Lock the free block list. */
    gdbLockFreeBlockList(db, DB_WRITE_LOCK, LOC_DB_0044);

    /* Get the free block list. */
    result = gdbGetFreeBlockList(db, &freeBlocks, &blockCount);

    if (result == 0)
    {
        gdbUnlockFreeBlockList(db, LOC_DB_0045);
        gdbFreeBlockList(freeBlocks);

        //rawFileSeek(db->idxRawFile, 0L, SEEK_END);
        offset = rawFileCurSize(db->idxRawFile);

        /* Fill in the chain with the reserved offsets. */
        for (i = 0; i < count; i++)
        {
            chain[i] = offset + (i * blockSize);
        }
        gdbPad(db->idxRawFile, offset, count * blockSize);

        return chain;
    }

    fillCount = 0;
    j = 0;

    /* Create the new array of free blocks. */
    MEM_CHECK(newFreeBlocks = (GdbFreeBlock *)SAFE_MALLOC(blockCount * sizeof(GdbFreeBlock), LOC_DB_0046));
    memset(newFreeBlocks, 0, blockCount * sizeof(GdbFreeBlock));

    for (i = 0; i < blockCount; i++)
    {
        if (fillCount < count && freeBlocks[i].size == blockSize)
        {
            chain[fillCount++] = freeBlocks[i].offset;
        }
        else
        {
            newFreeBlocks[j].offset = freeBlocks[i].offset;
            newFreeBlocks[j].size   = freeBlocks[i].size;

            j++;
        }
    }

    newListCount = j;

    if (fillCount != count)
    {
        if (fillCount > 0)
        {
            gdbWriteFreeBlockList(db, newFreeBlocks, newListCount);
        }
        gdbUnlockFreeBlockList(db, LOC_DB_0047);

        gdbFreeBlockList(newFreeBlocks);
        gdbFreeBlockList(freeBlocks);

        //rawFileSeek(db->idxRawFile, 0L, SEEK_END);
        //offset = rawFileTell(db->idxRawFile);
        offset = rawFileCurSize(db->idxRawFile);

        /* Fill in the chain with the reserved offsets. */
        for (i = fillCount, j = 0; i < count; i++, j++)
        {
            chain[i] = offset + (j * blockSize);
        }
        gdbPad(db->idxRawFile, offset, (count - fillCount) * blockSize);

        qsort(chain, count, sizeof(offset_t), __offsetCompare);

        return chain;
    }

    /* Write the new list to disk. */
    gdbWriteFreeBlockList(db, newFreeBlocks, newListCount);

    /* Unlock the list. */
    gdbUnlockFreeBlockList(db, LOC_DB_0048);

    /* Free up the memory for the lists. */
    gdbFreeBlockList(newFreeBlocks);
    gdbFreeBlockList(freeBlocks);

    /* Sort it. */
    qsort(chain, count, sizeof(offset_t), __offsetCompare);

    return chain;
}

void
gdbFreeBlockChain(GDatabase *db, offset_t *chain, uint16_t count,
                  uint8_t blockType)
{
    GdbFreeBlock  *freeBlocks;
    GdbFreeBlock  *tempBlocks;
    uint16_t       blockSize;
    uint32_t       blockCount;
    uint32_t       i, j;

    if (db == NULL || chain == NULL || count == 0 || !GDB_VALID_BLOCK_TYPE(blockType))
    {
        return;
    }

    /* Get the block size for this type. */
    blockSize = blockTypeInfo[blockType - 1].multiple;

    /* Lock the free block list. */
    gdbLockFreeBlockList(db, DB_WRITE_LOCK, LOC_DB_0049);

    /* Get the free block list. */
    gdbGetFreeBlockList(db, &freeBlocks, &blockCount);

    if (blockCount == 0)
    {
        count = DMIN(count, DB_FREE_BLOCK_MAX_NUM); /*DO NOT OVERFLOW!*/
        /* Block list is empty. */
        MEM_CHECK(freeBlocks = (GdbFreeBlock *)SAFE_MALLOC(count * sizeof(GdbFreeBlock), LOC_DB_0050));

        for (i = 0; i < count; i++)
        {
            freeBlocks[i].offset = chain[i];
            freeBlocks[i].size   = blockSize;
        }

        gdbWriteFreeBlockList(db, freeBlocks, count);

        gdbUnlockFreeBlockList(db, LOC_DB_0051);

        gdbFreeBlockList(freeBlocks);

        return;
    }

    count = DMIN(count, DB_FREE_BLOCK_MAX_NUM - blockCount); /*DO NOT OVERFLOW!*/
    if(0 == count)
    {
        gdbUnlockFreeBlockList(db, LOC_DB_0052);
        gdbFreeBlockList(freeBlocks);
        return;
    }

    /* We're going to add the block to the list by re-creating the list. */
    tempBlocks = freeBlocks;

    MEM_CHECK(freeBlocks = (GdbFreeBlock *)SAFE_MALLOC((blockCount + count) * sizeof(GdbFreeBlock), LOC_DB_0053));
    memcpy(freeBlocks, tempBlocks, blockCount * sizeof(GdbFreeBlock));

    for (i = blockCount, j = 0; i < blockCount + count; i++, j++)
    {
        freeBlocks[i].offset = chain[j];
        freeBlocks[i].size   = blockSize;
    }

    gdbFreeBlockList(tempBlocks);

    blockCount += count;

    qsort(freeBlocks, blockCount, sizeof(GdbFreeBlock), __blockCompare);

    gdbWriteFreeBlockList(db, freeBlocks, blockCount);

    gdbUnlockFreeBlockList(db, LOC_DB_0054);
    gdbFreeBlockList(freeBlocks);

    return;
}

offset_t
gdbReserveBlock(GDatabase *db, uint8_t blockType)
{
    offset_t *chain;
    offset_t  offset;

    if (db == NULL || !GDB_VALID_BLOCK_TYPE(blockType))
    {
        return 0;
    }
    chain = gdbReserveBlockChain(db, 1, blockType);

    if (chain == NULL)
    {
        return 0;
    }
    offset = chain[0];

    SAFE_FREE(chain, LOC_DB_0055);

    return offset;
}

void
gdbFreeBlock(GDatabase *db, offset_t offset, uint8_t blockType)
{
    if (db == NULL || !GDB_VALID_OFFSET(offset) ||
        !GDB_VALID_BLOCK_TYPE(blockType))
    {
        return;
    }

    gdbFreeBlockChain(db, &offset, 1, blockType);
}

uint32_t
gdbGetNeededBlockCount(uint32_t dataSize, uint16_t multiple)
{
    uint32_t count, i;

    if (dataSize == 0 || multiple == 0)
    {
        return 0;
    }
    dataSize += GDB_BLOCK_HEADER_SIZE;

    if (dataSize == multiple)
    {
        return 1;
    }
    count = 1;

    for (i = multiple; i < dataSize; i += multiple - sizeof(offset_t))
    {
        count++;
    }
    return count;
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

