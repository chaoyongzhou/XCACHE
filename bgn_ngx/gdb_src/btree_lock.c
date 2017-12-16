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

uint8_t
btreeLockNode(BTree *tree, offset_t nodeOffset, GdbLockType type)
{
    if (tree == NULL || nodeOffset < DB_HEADER_BLOCK_SIZE)
    {
        return 0;
    }
    if (type == DB_UNLOCKED)
    {
        return btreeUnlockNode(tree, nodeOffset);
    }
    return 1;
}

uint8_t
btreeUnlockNode(BTree *tree, offset_t nodeOffset)
{
    return 0;
}

uint8_t
btreeLockTree(BTree *tree, GdbLockType type)
{
    if (tree == NULL)
    {
        return 0;
    }
    if (type == DB_UNLOCKED)
    {
        return btreeUnlockTree(tree);
    }
    return 0;
}

uint8_t
btreeUnlockTree(BTree *tree)
{
    return 0;
}

GdbLockType
btreeGetNodeLock(BTree *tree, offset_t nodeOffset)
{
    return DB_UNLOCKED;
}

GdbLockType
btreeGetTreeLock(BTree *tree)
{
    return DB_UNLOCKED;
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

