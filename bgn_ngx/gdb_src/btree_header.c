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

void *
btreeReadHeader(GdbBlock *block, const uint8_t *buffer, void *extra)
{
    BTree *tree;
    uint32_t counter = 0;

    MEM_CHECK(tree = (BTree *)SAFE_MALLOC(sizeof(BTree), LOC_BTREE_0001));
    memset(tree, 0, sizeof(BTree));

    tree->block = block;

    tree->order    = gdbGet8(buffer,  &counter);
    tree->size     = gdbGet32(buffer, &counter);
    tree->root     = gdbGetOffset(buffer, &counter);
    tree->leftLeaf = gdbGetOffset(buffer, &counter);

    tree->minLeaf = (tree->order / 2);
    tree->minInt  = ((tree->order + 1) / 2) - 1;

    BTREE_CRWLOCK_INIT(tree, LOC_BTREE_0002);
    return tree;
}

void
btreeWriteHeader(GdbBlock *block, uint8_t **buffer, uint32_t *size)
{
    uint32_t counter = 0;
    BTree *tree;

    tree = (BTree *)block->detail;

    *size = BTREE_HEADER_DATA_SIZE;

    MEM_CHECK(*buffer = (uint8_t *)SAFE_MALLOC(BTREE_HEADER_DATA_SIZE, LOC_BTREE_0003));

    gdbPut8(*buffer,  &counter, tree->order);
    gdbPut32(*buffer, &counter, tree->size);
    gdbPutOffset(*buffer, &counter, tree->root);
    gdbPutOffset(*buffer, &counter, tree->leftLeaf);
}

void *
btreeCreateHeader(GdbBlock *block, void *extra)
{
    BTree *tree;

    MEM_CHECK(tree = (BTree *)SAFE_MALLOC(sizeof(BTree), LOC_BTREE_0004));
    memset(tree, 0, sizeof(BTree));

    tree->block = block;
    tree->order = *(uint8_t *)extra;

    tree->minLeaf = (tree->order / 2);
    tree->minInt  = ((tree->order + 1) / 2) - 1;

    BTREE_CRWLOCK_INIT(tree, LOC_BTREE_0005);

    return tree;
}

void
btreeDestroyHeader(void *tree)
{
    if (NULL != tree)
    {
        BTREE_CRWLOCK_CLEAN((BTree *)tree, LOC_BTREE_0006);
        SAFE_FREE(tree, LOC_BTREE_0007);
    }
    return;
}

void
btreeSetRootNode(BTree *tree, offset_t offset)
{
    RawFile *fp;
    GdbBlock *block;
    offset_t  __offset;

    if (tree == NULL)
    {
        return;
    }
    block = tree->block;

    fp = block->db->idxRawFile;

    tree->root = offset;

    rawFileSeek(fp, block->offset + GDB_BLOCK_HEADER_SIZE + BTREE_ROOT_OFFSET, SEEK_SET);
    __offset = block->offset + GDB_BLOCK_HEADER_SIZE + BTREE_ROOT_OFFSET;

    offset = gdb_hton_offset(offset);
    //dbg_log(SEC_0130_BTREE, 9)(LOGSTDOUT, "[DEBUG] btreeSetRootNode: btree %lx, fp %lx, __offset %d, root offset %d => %d\n", tree, fp, __offset, tree->root, offset);

    rawFileWrite(fp, __offset, &offset, sizeof(offset_t), 1, LOC_BTREE_0008);
}

void
btreeSetLeftLeaf(BTree *tree, offset_t offset)
{
    RawFile  *fp;
    GdbBlock *block;
    offset_t  __offset;

    if (tree == NULL)
    {
        return;
    }
    block = tree->block;

    fp = block->db->idxRawFile;

    tree->leftLeaf = offset;

    rawFileSeek(fp, block->offset + GDB_BLOCK_HEADER_SIZE + BTREE_LEFT_LEAF_OFFSET, SEEK_SET);
    __offset = block->offset + GDB_BLOCK_HEADER_SIZE + BTREE_LEFT_LEAF_OFFSET;

    offset = gdb_hton_offset(offset);

    rawFileWrite(fp, __offset, &offset, sizeof(offset_t), 1, LOC_BTREE_0009);
}

void
btreeSetTreeSize(BTree *tree, uint32_t size)
{
    RawFile *fp;
    GdbBlock *block;
    offset_t  __offset;

    if (tree == NULL)
    {
        return;
    }
    block = tree->block;

    fp = block->db->idxRawFile;

    tree->size = size;

    rawFileSeek(fp, block->offset + GDB_BLOCK_HEADER_SIZE + BTREE_SIZE_OFFSET, SEEK_SET);
    __offset = block->offset + GDB_BLOCK_HEADER_SIZE + BTREE_SIZE_OFFSET;

    size = gdb_hton_uint32(size);

    rawFileWrite(fp, __offset, &size, sizeof(uint32_t), 1, LOC_BTREE_0010);
}

offset_t
btreeGetRootNode(BTree *tree)
{
    RawFile  *fp;
    GdbBlock *block;
    offset_t  root_offset;
    offset_t  __offset;

    if (tree == NULL)
    {
        dbg_log(SEC_0130_BTREE, 0)(LOGSTDOUT, "error:btreeGetRootNode: tree is null\n");
        return 0;
    }
    block = tree->block;

    fp = block->db->idxRawFile;

    rawFileSeek(fp, block->offset + GDB_BLOCK_HEADER_SIZE + BTREE_ROOT_OFFSET, SEEK_SET);
    __offset = block->offset + GDB_BLOCK_HEADER_SIZE + BTREE_ROOT_OFFSET;
    if (rawFileRead(fp, __offset, &root_offset, sizeof(offset_t), 1, LOC_BTREE_0011) != 1)
    {
        dbg_log(SEC_0130_BTREE, 0)(LOGSTDOUT, "error:btreeGetRootNode: B+Tree: Unable to read the root node offset at block offset %d\n",
                            block->offset + GDB_BLOCK_HEADER_SIZE + BTREE_ROOT_OFFSET);
        exit(1);
    }

    tree->root = gdb_ntoh_offset(root_offset);
    //dbg_log(SEC_0130_BTREE, 9)(LOGSTDOUT, "[DEBUG] btreeGetRootNode: btree %lx, fp %lx, __offset %d, root offset %d => %d\n", tree, fp, __offset, root_offset, tree->root);

    return tree->root;
}

offset_t
btreeGetLeftLeaf(BTree *tree)
{
    RawFile *fp;
    GdbBlock *block;
    offset_t leaf_offset;
    offset_t  __offset;

    if (tree == NULL)
    {
        dbg_log(SEC_0130_BTREE, 0)(LOGSTDOUT, "error:btreeGetLeftLeaf: tree is null\n");
        return 0;
    }
    block = tree->block;

    fp = block->db->idxRawFile;

    rawFileSeek(fp, block->offset + GDB_BLOCK_HEADER_SIZE + BTREE_LEFT_LEAF_OFFSET, SEEK_SET);
    __offset = block->offset + GDB_BLOCK_HEADER_SIZE + BTREE_LEFT_LEAF_OFFSET;
    if (rawFileRead(fp, __offset, &leaf_offset, sizeof(offset_t), 1, LOC_BTREE_0012) != 1)
    {
        dbg_log(SEC_0130_BTREE, 0)(LOGSTDOUT, "error:btreeGetLeftLeaf: B+Tree: Unable to read the left leaf offset at %d\n",
                            block->offset + GDB_BLOCK_HEADER_SIZE + BTREE_LEFT_LEAF_OFFSET);
        exit(1);
    }

    tree->leftLeaf = gdb_ntoh_offset(leaf_offset);

    return tree->leftLeaf;
}

uint32_t
btreeGetTreeSize(BTree *tree)
{
    RawFile *fp;
    GdbBlock *block;
    uint32_t tree_size;
    offset_t  __offset;

    if (tree == NULL)
    {
        dbg_log(SEC_0130_BTREE, 0)(LOGSTDOUT, "error:btreeGetTreeSize: tree is null\n");
        return 0;
    }
    block = tree->block;

    fp = block->db->idxRawFile;

    rawFileSeek(fp, block->offset + GDB_BLOCK_HEADER_SIZE + BTREE_SIZE_OFFSET, SEEK_SET);
    __offset = block->offset + GDB_BLOCK_HEADER_SIZE + BTREE_SIZE_OFFSET;
    if (rawFileRead(fp, __offset, &tree_size, sizeof(uint32_t), 1, LOC_BTREE_0013) != 1)
    {
        dbg_log(SEC_0130_BTREE, 0)(LOGSTDOUT, "error:btreeGetTreeSize: B+Tree: Unable to read the tree size at offset (%d) at %d\n",
                            block->offset + GDB_BLOCK_HEADER_SIZE + BTREE_SIZE_OFFSET);
        exit(1);
    }

    tree->size = gdb_ntoh_uint32(tree_size);

    return tree->size;
}

void btreeDebug0(BTree *tree, const word_t location)
{
    RawFile *fp;
    GdbBlock *block;
    uint32_t size;
    uint8_t  order;
    uint32_t freeBlockCount;
    offset_t root;
    offset_t leftLeaf;
    offset_t  __offset;

    if(NULL == tree)
    {
        dbg_log(SEC_0130_BTREE, 9)(LOGSTDOUT, "[DEBUG] btreeDebug: tree is null at %s:%ld\n", MM_LOC_FILE_NAME(location),MM_LOC_LINE_NO(location));
        return;
    }

    block = tree->block;

    fp = block->db->idxRawFile;

    __offset = block->offset + GDB_BLOCK_HEADER_SIZE + BTREE_ORDER_OFFSET;
    if (rawFileRead(fp, __offset, &order, sizeof(uint8_t), 1, LOC_BTREE_0014) != 1)
    {
        dbg_log(SEC_0130_BTREE, 0)(LOGSTDOUT, "error:btreeDebug: B+Tree: Unable to read the tree order at offset (%d) at %d\n", __offset);
        exit(1);
    }

    __offset = block->offset + GDB_BLOCK_HEADER_SIZE + BTREE_SIZE_OFFSET;
    if (rawFileRead(fp, __offset, &size, sizeof(uint32_t), 1, LOC_BTREE_0015) != 1)
    {
        dbg_log(SEC_0130_BTREE, 0)(LOGSTDOUT, "error:btreeDebug: B+Tree: Unable to read the tree size at offset (%d) at %d\n", __offset);
        exit(1);
    }
    size = gdb_ntoh_uint32(size);

    __offset = block->offset + GDB_BLOCK_HEADER_SIZE + BTREE_ROOT_OFFSET;
    if (rawFileRead(fp, __offset, &root, sizeof(offset_t), 1, LOC_BTREE_0016) != 1)
    {
        dbg_log(SEC_0130_BTREE, 0)(LOGSTDOUT, "error:btreeDebug: B+Tree: Unable to read the tree root offset at offset (%d) at %d\n", __offset);
        exit(1);
    }
    root = gdb_ntoh_offset(root);

    __offset = block->offset + GDB_BLOCK_HEADER_SIZE + BTREE_LEFT_LEAF_OFFSET;
    if (rawFileRead(fp, __offset, &leftLeaf, sizeof(offset_t), 1, LOC_BTREE_0017) != 1)
    {
        dbg_log(SEC_0130_BTREE, 0)(LOGSTDOUT, "error:btreeDebug: B+Tree: Unable to read the tree left leaf offset at offset (%d) at %d\n", __offset);
        exit(1);
    }
    leftLeaf = gdb_ntoh_offset(leftLeaf);

    __offset = DB_FREE_BLOCK_LIST_OFFSET;
    if (rawFileRead(fp, __offset, &freeBlockCount, sizeof(uint32_t), 1, LOC_BTREE_0018) != 1)
    {
        dbg_log(SEC_0130_BTREE, 0)(LOGSTDOUT, "error:btreeDebug: B+Tree: Unable to read the freeBlockCount at offset (%d) at %d\n", __offset);
        exit(1);
    }
    freeBlockCount = gdb_ntoh_uint32(freeBlockCount);

    dbg_log(SEC_0130_BTREE, 9)(LOGSTDOUT, "[DEBUG] btreeDebug: tree %lx, block %lx, offset %d, fp %lx: order %d, size %d, root %d, leftLeaf %d, cur_size %d, freeBlockCount %d [%s] at %s:%ld\n",
                        tree, block, block->offset, fp,
                        order, size, root, leftLeaf,
                        fp->raw_data->cur_size,
                        freeBlockCount,  (freeBlockCount > 340? "NOK" : "OK"),
                        MM_LOC_FILE_NAME(location),MM_LOC_LINE_NO(location));

    return;
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

