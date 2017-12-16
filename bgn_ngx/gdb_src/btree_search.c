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

static uint8_t
__search(BTree *tree, offset_t rootOffset, const uint8_t *key, int (*keyCompare)(const uint8_t *, const uint8_t *), offset_t *filePos)
{
    uint8_t i;
    BTreeNode *rootNode;
    uint8_t result;

    rootNode = btreeReadNode(tree, rootOffset);
    if(NULL == rootNode)
    {
        dbg_log(SEC_0130_BTREE, 0)(LOGSTDOUT, "error:__search: read node failed at offset %d\n", rootOffset);
        return 0;
    }

    for (i = 0;
         i < rootNode->keyCount && keyCompare(rootNode->keys[i], key) < 0;
         i++)
        ;

    if (BTREE_IS_LEAF(rootNode))
    {
        if (i < rootNode->keyCount && keyCompare(rootNode->keys[i], key) == 0)
        {
            *filePos = rootNode->children[i];

            btreeDestroyNode(rootNode);

            return 1;
        }

        dbg_log(SEC_0130_BTREE, 0)(LOGSTDOUT, "error:__search: on leaf i = %d, keyCount %d\n", i, rootNode->keyCount);

        btreeDestroyNode(rootNode);

        return 0;
    }

    result = __search(tree, rootNode->children[i], key, keyCompare, filePos);

    btreeDestroyNode(rootNode);

    return result;
}

offset_t
btreeSearch(BTree *tree, const uint8_t *key, int (*keyCompare)(const uint8_t *, const uint8_t *))
{
    offset_t filePos;
    uint8_t  found;

    if (tree == NULL)
    {
        dbg_log(SEC_0130_BTREE, 0)(LOGSTDOUT, "error:btreeSearch: tree is null\n");
        return 0;
    }

    if (key == NULL)
    {
        dbg_log(SEC_0130_BTREE, 0)(LOGSTDOUT, "error:btreeSearch: key is null\n");
        return 0;
    }

    filePos = 0;
    found   = 0;
#if 0
    /* Read in the tree data. */
    tree->root     = btreeGetRootNode(tree);
    tree->leftLeaf = btreeGetLeftLeaf(tree);
#endif
    dbg_log(SEC_0130_BTREE, 9)(LOGSTDNULL, "[DEBUG] btreeSearch: tree %lx, root offset %d, left leaf offset %d\n", tree, tree->root, tree->leftLeaf);

    if (btreeIsEmpty(tree) == 1)
    {
        dbg_log(SEC_0130_BTREE, 0)(LOGSTDOUT, "error:btreeSearch: btree is empty\n");
        return 0;
    }

    found = __search(tree, tree->root, key, keyCompare, &filePos);
    if (found != 0)
    {
        return filePos;
    }
    dbg_log(SEC_0130_BTREE, 0)(LOGSTDOUT, "error:btreeSearch: searched nothing\n");
    return 0;
}


static void
__match(BTree *tree, offset_t rootOffset, const uint8_t *key, OffsetList *offsetList, int (*keyCompare)(const uint8_t *, const uint8_t *))
{
    uint8_t i;
    BTreeNode *rootNode;

    rootNode = btreeReadNode(tree, rootOffset);
    if(NULL == rootNode)
    {
        dbg_log(SEC_0130_BTREE, 0)(LOGSTDOUT, "error:__match: read root node from offset %d failed\n", rootOffset);
        return ;
    }

    for (i = 0;
         i < rootNode->keyCount && keyCompare(rootNode->keys[i], key) < 0;
         i++)
        ;

    if (BTREE_IS_LEAF(rootNode))
    {
        for(; i < rootNode->keyCount && keyCompare(rootNode->keys[i], key) == 0; i ++)
        {
            //dbg_log(SEC_0130_BTREE, 5)(LOGSTDOUT,"__match: [0] got offset %d\n", rootNode->children[i]);
            offsetListAdd(offsetList, rootNode->children[i]);
        }

        btreeDestroyNode(rootNode);

        return ;
    }

    /*now rootNode->keys[i] <= key*/

    for(; i < rootNode->keyCount && keyCompare(rootNode->keys[i], key) >= 0; i ++)
    {
        /*now match the left subtree because key <= rootNode->keys[i]*/
        __match(tree, rootNode->children[i], key, offsetList, keyCompare);
    }

    if(i == rootNode->keyCount && i > 0 && keyCompare(rootNode->keys[i - 1], key) <= 0)
    {
        /*now match the most right subtree because rootNode->keys[ rootNode->keyCount - 1] <= key*/
        __match(tree, rootNode->children[i], key, offsetList, keyCompare);
    }

    btreeDestroyNode(rootNode);

    return;
}

void
btreeMatch(BTree *tree, const uint8_t *key, OffsetList *offsetList, int (*keyCompare)(const uint8_t *, const uint8_t *))
{
    if (tree == NULL || key == NULL)
        return;

    /* Read in the tree data. */
    tree->root     = btreeGetRootNode(tree);
    tree->leftLeaf = btreeGetLeftLeaf(tree);

    if (btreeIsEmpty(tree) == 1)
        return;

    __match(tree, tree->root, key, offsetList, keyCompare);
    return ;
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

