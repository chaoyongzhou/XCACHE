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

#ifndef _BTREE_LOCK_H_
#define _BTREE_LOCK_H_

#include "btree.h"
#include "db_lock.h"

/**
 * Locks a node.
 *
 * If the node is already locked, this will wait until it is unlocked
 * before locking and returning.
 *
 * @param tree       The active B+Tree.
 * @param nodeOffset The offset of the node to lock.
 * @param type       The type of lock.
 *
 * @return 1 on success, 0 on failure.
 */
uint8_t btreeLockNode(BTree *tree, offset_t nodeOffset, GdbLockType type);

/**
 * Unlocks a node.
 *
 * @param tree       The active B+Tree.
 * @param nodeOffset The offset of the locked node.
 *
 * @return 1 on success, 0 on failure.
 */
uint8_t btreeUnlockNode(BTree *tree, offset_t nodeOffset);

/**
 * Locks the tree.
 *
 * If the tree is already locked, this will wait until it is unlocked
 * before locking and returning.
 *
 * @param tree The B+Tree to lock.
 * @param type The type of lock.
 *
 * @return 1 on success, 0 on failure.
 */
uint8_t btreeLockTree(BTree *tree, GdbLockType type);

/**
 * Unlocks the tree.
 *
 * @param tree The B+Tree to unlock.
 *
 * @return 1 on success, 0 on failure.
 */
uint8_t btreeUnlockTree(BTree *tree);

/**
 * Returns the current lock on a node.
 *
 * @param tree       The active B+Tree.
 * @param nodeOffset The offset of the node.
 *
 * @return The current lock on the node (or DB_UNLOCKED if none.)
 */
GdbLockType btreeGetNodeLock(BTree *tree, offset_t nodeOffset);

/**
 * Returns the current lock on the tree.
 *
 * @param tree The active B+Tree.
 *
 * @return The current lock on the tree (or DB_UNLOCKED if none.)
 */
GdbLockType btreeGetTreeLock(BTree *tree);

#endif /* _BTREE_LOCK_H_ */

#ifdef __cplusplus
}
#endif/*__cplusplus*/
