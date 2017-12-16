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

#ifndef _BTREE_H_
#define _BTREE_H_

#include <stdio.h>

typedef struct _BTree          BTree;          /**< A B+Tree.           */
typedef struct _BTreeNode      BTreeNode;      /**< A node in a B+Tree. */
typedef struct _BTreeTraversal BTreeTraversal; /**< A traversal.        */

#include "db_internal.h"
#include "db.h"
#include "poslist.h"

/**
 * A node in the B+Tree.
 */
struct _BTreeNode
{
    BTree *tree;               /**< Parent B+Tree.                     */
    GdbBlock *block;           /**< Parent block.                      */

    uint8_t keyCount;             /**< The number of keys in the node.    */

    offset_t *children;        /**< An array of children node offsets. */
    uint16_t *keySizes;  /**< An array of key sizes.             */
    uint8_t **keys;               /**< An array of keys.                  */
};

#define BTREE_CRWLOCK_SWITCH (SWITCH_ON)
/**
 * A B+Tree.
 */
struct _BTree
{
    GdbBlock *block;         /**< The B+Tree's block.                      */

    uint8_t order;     /**< The order of this tree.                  */
    uint32_t size;      /**< The size of the tree.                    */

    uint8_t minLeaf;   /**< Minimum key count in a leaf              */
    uint8_t minInt;    /**< Minimum key count in an internal node.   */

    offset_t root;           /**< The root node's offset.                  */
    offset_t leftLeaf;       /**< The left-most leaf's offset.             */

    offset_t _insFilePos;    /**< Current filePos on inserts. Don't touch! */
};

#if 1
#define BTREE_CRWLOCK_INIT(btree, location)     do{}while(0)
#define BTREE_CRWLOCK_CLEAN(btree, location)    do{}while(0)
#define BTREE_CRWLOCK_RDLOCK(btree, location)   do{}while(0)
#define BTREE_CRWLOCK_WRLOCK(btree, location)   do{}while(0)
#define BTREE_CRWLOCK_UNLOCK(btree, location)   do{}while(0)
#endif

/**
 * A traversal.
 */
struct _BTreeTraversal
{
    BTree     *tree;       /**< The active B+Tree.               */
    BTreeNode *node;       /**< The current node.                */
    uint16_t   pos;        /**< The position of the current key. */
};

/**
 * Opens a B+Tree from inside a database.
 *
 * @param db     The active database.
 * @param offset The offset of the tree.
 *
 * @return A BTree structure.
 */
BTree *btreeOpen(GDatabase *db, offset_t offset);

/**
 * Closes a B+Tree.
 *
 * @param tree The BTree structure to close.
 */
void btreeClose(BTree *tree);

/**
 * Creates a B+Tree inside a database.
 *
 * @param db     The active database.
 * @param order  The order of the tree.
 *
 * @return A BTree structure.
 */
BTree *btreeCreate(GDatabase *db, uint8_t order);

/**
 * Inserts an offset to a value with the specified key in a B+Tree.
 *
 * @param tree       The tree to insert into.
 * @param key        The key.
 * @param filePos    The file position containing the data.
 * @param replaceDup Replaces an entry if it already exists.
 *
 * @return The status of the insert operation.
 */
GdbStatus btreeInsert(BTree *tree, const uint8_t *key, offset_t filePos,
                      uint8_t replaceDup);

/**
 * Deletes a value from a B+Tree.
 *
 * @param tree The tree to delete the value in.
 * @param key  The key associated with the value to delete.
 *
 * @return 1 on success, 0 on failure.
 */
offset_t btreeDelete(BTree *tree, const uint8_t *key);

uint8_t btreeSplit(const BTree *src_tree, const RawFile *src_rawFile,
                    BTree *des_tree_left, RawFile *des_rawFile_left,
                    BTree *des_tree_right, RawFile *des_rawFile_right);

uint8_t btreeCompact(const BTree *src_tree, const RawFile *src_rawFile,
                    BTree *des_tree, RawFile *des_rawFile);

uint8_t btreeScan(const BTree *tree, const RawFile *rawFile, const uint8_t *des_key,
                     int (*keyCompare)(const uint8_t *, const uint8_t *),
                     offset_t *filePos);

/**
 * Traverses the tree with the specified user-defined function.
 *
 * @param tree    The tree to traverse.
 * @param process The function to call on each value.
 */
void btreeTraverse(LOG *log, BTree *tree, void (*process)(LOG *, const offset_t));

void btreeRunThrough(LOG *log, BTree *tree, void (*process)(LOG *, const offset_t, GDatabase *));


/**
 * Searches the tree for a value with the specified key.
 *
 * @param tree The tree to search.
 * @param key  The associated key.
 *
 * @return The offset data on the node if found, or 0 if not found.
 */
offset_t btreeSearch(BTree *tree, const uint8_t *key, int (*keyCompare)(const uint8_t *, const uint8_t *));
void     btreeMatch(BTree *tree, const uint8_t *key, OffsetList *offsetList, int (*keyCompare)(const uint8_t *, const uint8_t *));

/**
 * Returns whether or not the tree is empty.
 *
 * @param tree The tree.
 *
 * @return 1 if empty, 0 otherwise.
 */
uint8_t btreeIsEmpty(BTree *tree);

/**
 * Returns the size of the tree.
 *
 * @param tree The tree.
 *
 * @return The size of the tree.
 */
uint32_t btreeGetSize(BTree *tree);

/**
 * Pretty-prints the tree (for debugging purposes).
 *
 * @param tree       The tree to print.
 * @param rootOffset The root node offset.
 * @param i          The current indent level.
 */
void btreePrettyPrint(LOG *log, BTree *tree, offset_t rootOffset, uint8_t i, uint8_t verbose, void (*keyPrinter)(LOG *, const uint8_t *));

/**
 * Prepares a traversal.
 *
 * @param tree The tree.
 *
 * @return A BTreeTraversal structure.
 */
BTreeTraversal *btreeInitTraversal(const BTree *tree);

/**
 * Destroys a traversal.
 *
 * @param trav The traversal.
 *
 * @return NULL.
 */
BTreeTraversal *btreeDestroyTraversal(BTreeTraversal *trav);

/**
 * Returns the first offset in a traversal.
 *
 * @param trav The active traversal.
 *
 * @return The first offset, or 0 if empty.
 */
offset_t btreeGetFirstOffset(BTreeTraversal *trav);

/**
 * Returns the next offset in a traversal.
 *
 * @param trav The active traversal.
 *
 * @return The next offset, or 0 when done.
 */
offset_t btreeGetNextOffset(BTreeTraversal *trav);

offset_t btreeGetLastOffset(BTreeTraversal *trav);

uint8_t btreeCollectAllOffset(BTree *tree, offset_t **offset_list, uint32_t *offset_num);

#endif /* _BTREE_H_ */

#ifdef __cplusplus
}
#endif/*__cplusplus*/
