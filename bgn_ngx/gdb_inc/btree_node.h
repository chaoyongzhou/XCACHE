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


#ifndef _BTREE_NODE_H_
#define _BTREE_NODE_H_

#include "btree.h"

/** @name Node flags. */
/*@{*/
#define BTREE_FLAG_LEAF     1  /**< Leaf node.     */
/*@}*/

/** @name Utility macros */
/*@{*/
#define BTREE_IS_LEAF(node) (GDB_GET_FLAG((node)->block, BTREE_FLAG_LEAF) == 1)
#define BTREE_SET_LEAF(node) GDB_SET_FLAG((node)->block, BTREE_FLAG_LEAF)
/*@}*/

/**
 * Reads a B+Tree node from a buffer.
 *
 * This is meant to be called by the block functions. Don't call this
 * directly.
 *
 * @param block  The block.
 * @param buffer The buffer to read from.
 * @param extra  The parent BTree structure.
 *
 * @return A BTreeNode, or NULL on error.
 */
void *btreeReadNodeBlock(GdbBlock *block, const uint8_t *buffer, void *extra);

/**
 * Writes a B+Tree node to a buffer.
 *
 * This is meant to be called by the block functions. Don't call this
 * directly.
 *
 * @param block  The block.
 * @param buffer The returned buffer.
 * @param size   The returned buffer size.
 */
void btreeWriteNodeBlock(GdbBlock *block, uint8_t **buffer, uint32_t *size);

/**
 * Creates a B+Tree node block.
 *
 * This is meant to be called by the block functions. Don't call this
 * directly.
 *
 * @param block The block.
 * @param extra The parent BTree structure.
 *
 * @return A BTreeNode structure, or NULL on error.
 */
void *btreeCreateNodeBlock(GdbBlock *block, void *extra);

/**
 * Destroys a BTreeNode structure in memory.
 *
 * This is meant to be called by the block functions. Don't call this
 * directly.
 *
 * @param node The node to destroy.
 */
void btreeDestroyNodeBlock(void *tree);

/**
 * Creates a new BTreeNode structure.
 *
 * @param tree The B+Tree.
 *
 * @return A new BTreeNode structure.
 */
BTreeNode *btreeNewNode(BTree *tree);

/**
 * Destroys a BTreeNode structure.
 *
 * @param node The node to destroy.
 */
void btreeDestroyNode(BTreeNode *node);

/**
 * Reads a node from the specified offset.
 *
 * @param tree   The active B+Tree.
 * @param offset The offset of the node to read in.
 *
 * @return The node.
 */
BTreeNode *btreeReadNode(BTree *tree, offset_t offset);

/**
 * Writes a node to disk.
 *
 * @param node The node to write.
 *
 * @return The offset the node was written to.
 */
offset_t btreeWriteNode(BTreeNode *node);

/**
 * Erases a node from disk.
 *
 * @param node The node to erase.
 */
void btreeEraseNode(BTreeNode *node);

void btreePrintNode(BTreeNode *node);

#endif /* _BTREE_NODE_H_ */

#ifdef __cplusplus
}
#endif/*__cplusplus*/
