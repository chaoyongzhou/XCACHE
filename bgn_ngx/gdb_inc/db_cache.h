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

#ifndef _DB_CACHE_H_
#define _DB_CACHE_H_

/**
 * Adds a block to the cache.
 *
 * If the block is already in the cache, the reference count will
 * be incremented.
 *
 * @param db    The database.
 * @param block The block to add to the cache.
 */
GdbBlock *gdbCacheAddBlockNoLock(GDatabase *db, GdbBlock *block);
GdbBlock *gdbCacheAddBlock(GDatabase *db, GdbBlock *block);

/**
 * Removes a block from the cache.
 *
 * If the block's reference count is greater than 1, the block will
 * stay in the cache and the reference count will be decremented.
 * If the reference count is 1, the block will be removed from the
 * cache.
 *
 * @param db    The database.
 * @param block The block to remove from the cache.
 *
 * @return The reference count on the block.
 */
uint8_t gdbCacheRemoveBlockNoLock(GDatabase *db, GdbBlock *block);
uint8_t gdbCacheRemoveBlock(GDatabase *db, GdbBlock *block);

/**
 * Returns a block from the cache.
 *
 * @param db     The database.
 * @param offset The offset of the block.
 *
 * @return The block at @a offset, or @c NULL if it's not in the cache.
 */
GdbBlock *gdbCacheGetBlockNoLock(GDatabase *db, offset_t offset);
GdbBlock *gdbCacheGetBlock(GDatabase *db, offset_t offset);

void gdbCachePrintBlockNoLock(LOG *log, const GDatabase *db);
void gdbCachePrintBlock(LOG *log, GDatabase *db);

#endif /* _DB_CACHE_H_ */

#ifdef __cplusplus
}
#endif/*__cplusplus*/
