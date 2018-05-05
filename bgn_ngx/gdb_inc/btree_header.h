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

#ifndef _BTREE_HEADER_H_
#define _BTREE_HEADER_H_

#include <stdio.h>

#include "db_blocks.h"

#define BTREE_HEADER_DATA_SIZE   13   /**< Header data size.               */

/** @name B+Tree header offsets */
/*@{*/
#define BTREE_ORDER_OFFSET         0  /**< B+Tree order.                   */
#define BTREE_SIZE_OFFSET          1  /**< Size of the B+Tree.             */
#define BTREE_ROOT_OFFSET          5  /**< Offset of the root node.        */
#define BTREE_LEFT_LEAF_OFFSET     9  /**< Offset of the left-most leaf.   */
/*@}*/

/**
 * Reads a B+Tree header from a buffer.
 *
 * This is meant to be called by the block functions. Don't call this
 * directly.
 *
 * @param block  The block.
 * @param buffer The buffer to read from.
 * @param extra  NULL.
 *
 * @return A BTree, or NULL on error.
 */
void *btreeReadHeader(GdbBlock *block, const uint8_t *buffer, void *extra);

/**
 * Writes a B+Tree header to a buffer.
 *
 * This is meant to be called by the block functions. Don't call this
 * directly.
 *
 * @param block  The block.
 * @param buffer The returned buffer.
 * @param size   The returned buffer size.
 */
void btreeWriteHeader(GdbBlock *block, uint8_t **buffer, uint32_t *size);

/**
 * Creates a B+Tree header.
 *
 * This is meant to be called by the block functions. Don't call this
 * directly.
 *
 * @param block The block.
 * @param extra NULL
 *
 * @return A BTree structure.
 */
void *btreeCreateHeader(GdbBlock *block, void *extra);

/**
 * Destroys a BTree structure in memory.
 *
 * This is meant to be called by the block functions. Don't call this
 * directly.
 *
 * @param tree The tree to destroy.
 */
void btreeDestroyHeader(void *tree);

/**
 * Sets the root node offset in the header.
 *
 * @param tree   The active B+Tree.
 * @param offset The offset of the root node.
 *
 * @see btreeGetRootNode();
 */
void btreeSetRootNode(BTree *tree, offset_t offset);

/**
 * Sets the left-most leaf's offset in the header.
 *
 * @param tree   The active B+Tree.
 * @param offset The offset of the left-most leaf.
 *
 * @see btreeGetLeftLeaf()
 */
void btreeSetLeftLeaf(BTree *tree, offset_t offset);

/**
 * Sets the size of the B+Tree in the header.
 *
 * @param tree The active B+Tree.
 * @param size The size of the B+Tree.
 *
 * @see btreeGetTreeSize()
 */
void btreeSetTreeSize(BTree *tree, uint32_t size);

/**
 * Returns the root node offset in the header.
 *
 * @param tree The active B+Tree.
 *
 * @return The root node offset.
 *
 * @see btreeSetRootNode()
 */
offset_t btreeGetRootNode(BTree *tree);

/**
 * Returns the left-most leaf's offset in the header.
 *
 * @param tree The active B+Tree.
 *
 * @return The left-most leaf's offset.
 *
 * @see btreeSetLeftLeaf()
 */
offset_t btreeGetLeftLeaf(BTree *Tree);

/**
 * Returns the size of the B+Tree in the header.
 *
 * @param tree The active B+Tree.
 *
 * @return The tree's size.
 *
 * @see btreeSetTreeSize()
 */
uint32_t btreeGetTreeSize(BTree *tree);

void btreeDebug0(BTree *tree, const word_t location);

#define btreeDebug(__tree, __location) do{}while(0)

#endif /* _BTREE_HEADER_H_ */

#ifdef __cplusplus
}
#endif/*__cplusplus*/
