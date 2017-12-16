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

BTree *
btreeOpen(GDatabase *db, offset_t offset)
{
    GdbBlock *block;

    if (db == NULL || db->idxRawFile == NULL || offset < DB_HEADER_BLOCK_SIZE)
    {
        return NULL;
    }
    block = gdbReadBlock(db, offset, GDB_BLOCK_BTREE_HEADER, NULL);
    if (block == NULL)
    {
        dbg_log(SEC_0130_BTREE, 0)(LOGSTDOUT, "error:btreeOpen: read btree header gdbblock at offset %d failed\n", offset);
        return NULL;
    }
    return (BTree *)block->detail;
}

void
btreeClose(BTree *tree)
{
    if (tree == NULL)
    {
        return;
    }
    gdbDestroyBlock(tree->block);
}

BTree *
btreeCreate(GDatabase *db, uint8_t order)
{
    GdbBlock *block;

    if (db == NULL || db->idxRawFile == NULL)
    {
        return NULL;
    }
    block = gdbNewBlock(db, GDB_BLOCK_BTREE_HEADER, (void *)&order);
    if (block == NULL)
    {
        return NULL;
    }
    gdbWriteBlock(block);

    return (BTree *)block->detail;
}

uint8_t
btreeIsEmpty(BTree *tree)
{
    if (tree == NULL)
    {
        return 1;
    }
    return (btreeGetSize(tree) == 0);
}

uint32_t
btreeGetSize(BTree *tree)
{
    if (tree == NULL)
    {
        return 0;
    }
    tree->size = btreeGetTreeSize(tree);

    return tree->size;
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

