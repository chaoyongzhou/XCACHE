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

#ifndef _DB_BLOCKLIST_H_
#define _DB_BLOCKLIST_H_

/**
 * Offset of the free block list.
 */
#define DB_FREE_BLOCK_LIST_OFFSET DB_HEADER_BLOCK_SIZE

#define DB_FREE_BLOCK_MAX_NUM     (6 * 1023)

/**
 * Size of the free block list.
 * note: the last 2 bytes not used
 */
#define DB_FREE_BLOCK_LIST_SIZE  (sizeof(uint32_t) + DB_FREE_BLOCK_MAX_NUM * (sizeof(uint16_t) + sizeof(uint32_t)) + sizeof(uint16_t))

/**
 * A free block.
 */
typedef struct
{
    uint16_t size; /**< The size of the block    */
    offset_t offset;     /**< The offset of the block. */

} GdbFreeBlock;

/**
 * Returns the free block list.
 *
 * @param db     The active database.
 * @param blocks A pointer to an array of GdbBlocks for holding the blocks.
 * @param count  A pointer to the number of blocks.
 *
 * @return 1 if a free block list is found, or 0 otherwise.
 */
uint8_t gdbGetFreeBlockList(GDatabase *db, GdbFreeBlock **blocks, uint32_t *count);

/**
 * Writes a block list.
 *
 * @param db     The active database.
 * @param blocks The blocks list.
 * @param count  The number of blocks in the list.
 */
void gdbWriteFreeBlockList(GDatabase *db, GdbFreeBlock *blocks, uint32_t count);

/**
 * Frees a block list.
 *
 * @param blocks The block list to free.
 */
void gdbFreeBlockList(GdbFreeBlock *blocks);

uint8_t gdbGetFreeBlockNum(GDatabase *db, uint32_t *count);

void gdbAppendFreeBlockList(GDatabase *db, GdbFreeBlock *blocks, uint32_t count);

void gdbAppendFreeBlockChain(GDatabase *db, offset_t *chain, uint32_t count, uint16_t blockSize);

#endif /* _DB_BLOCKLIST_H_ */

#ifdef __cplusplus
}
#endif/*__cplusplus*/

