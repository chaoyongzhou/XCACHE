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
__splitNode(BTree *tree, BTreeNode *rootNode, uint8_t **key,
            offset_t *filePos, uint8_t *split, uint8_t replaceDup)
{
    uint8_t   *temp1, *temp2;
    BTreeNode *tempNode;
    offset_t   offset1 = 0, offset2;
    uint8_t    tempSize1, tempSize2;
    uint32_t   i, j, div;

    for (i = 0;
         i < (tree->order - 1) && keyCmp(*key, rootNode->keys[i]) > 0;
         i++)
        ;

    if (i < (tree->order - 1) && keyCmp(*key, rootNode->keys[i]) == 0)
    {
        if (replaceDup && BTREE_IS_LEAF(rootNode))
        {
            rootNode->children[i] = *filePos;
            GDB_SET_DIRTY(rootNode->block);
            btreeWriteNode(rootNode);
        }

        *split = 0;
        dbg_log(SEC_0130_BTREE, 0)(LOGSTDOUT, "error:__splitNode:found duplicate\n");
        return 0;
    }

    *split = 1;

    if (i < (tree->order - 1))
    {
        temp1                 = rootNode->keys[i];
        tempSize1             = rootNode->keySizes[i];
        rootNode->keys[i]     = keyDup(*key, LOC_BTREE_0161);
        rootNode->keySizes[i] = keyLen(*key);
        j = i;

        for (i++; i < (tree->order - 1); i++)
        {
            temp2     = rootNode->keys[i];
            tempSize2 = rootNode->keySizes[i];

            rootNode->keys[i]     = temp1;
            rootNode->keySizes[i] = tempSize1;

            temp1     = temp2;
            tempSize1 = tempSize2;
        }

        if (!BTREE_IS_LEAF(rootNode))
            j++;

        offset1 = rootNode->children[j];
        rootNode->children[j] = *filePos;

        for (j++; j <= (tree->order - 1); j++)
        {
            offset2 = rootNode->children[j];
            rootNode->children[j] = offset1;
            offset1 = offset2;
        }
    }
    else
    {
        temp1     = keyDup(*key, LOC_BTREE_0162);
        tempSize1 = keyLen(temp1);

        if (BTREE_IS_LEAF(rootNode))
        {
            offset1 = rootNode->children[tree->order - 1];
            rootNode->children[tree->order - 1] = *filePos;
        }
        else
            offset1 = *filePos;
    }

    if (BTREE_IS_LEAF(rootNode))
        div = (uint32_t)((tree->order + 1) / 2) - 1;
    else
        div = (uint32_t)(tree->order / 2);

    keyFree(*key, LOC_BTREE_0163);
    *key = keyDup(rootNode->keys[div], LOC_BTREE_0164);

    tempNode           = btreeNewNode(tree);
    tempNode->keyCount = tree->order - 1 - div;

    if (BTREE_IS_LEAF(rootNode))
        BTREE_SET_LEAF(tempNode);

    i = div + 1;

    for (j = 0; j < tempNode->keyCount - 1; j++, i++)
    {
        tempNode->keys[j]     = rootNode->keys[i];
        tempNode->keySizes[j] = rootNode->keySizes[i];
        tempNode->children[j] = rootNode->children[i];

        rootNode->keys[i]     = NULL;
        rootNode->keySizes[i] = 0;
        rootNode->children[i] = 0;
    }

    tempNode->keys[j]         = temp1;
    tempNode->keySizes[j]     = tempSize1;
    tempNode->children[j]     = rootNode->children[i];
    rootNode->children[i]     = 0;
    tempNode->children[j + 1] = offset1;

    *filePos = btreeWriteNode(tempNode);

    if (BTREE_IS_LEAF(rootNode))
    {
        rootNode->keyCount = div + 1;
        rootNode->children[rootNode->keyCount] = *filePos;
    }
    else
    {
        rootNode->keyCount = div;

        keyFree(rootNode->keys[rootNode->keyCount], LOC_BTREE_0165);
        rootNode->keys[rootNode->keyCount]     = NULL;
        rootNode->keySizes[rootNode->keyCount] = 0;
    }

    GDB_SET_DIRTY(rootNode->block);
    btreeWriteNode(rootNode);

    btreeDestroyNode(tempNode);

    return 1;
}

static void print_keys(BTreeNode *rootNode)
{
    uint8_t i;
    for(i = 0; i < rootNode->keyCount; i ++)
    {
        dbg_log(SEC_0130_BTREE, 5)(LOGSTDOUT,"%s,", rootNode->keys[i]);
    }
    dbg_log(SEC_0130_BTREE, 5)(LOGSTDOUT,"\n");
}

static void print_kvs(BTreeNode *rootNode)
{
    uint8_t i;
    for(i = 0; i < rootNode->keyCount; i ++)
    {
        keyPrintHs(LOGSTDOUT, rootNode->keys[i]);
        dbg_log(SEC_0130_BTREE, 5)(LOGSTDOUT,"\n");
    }

}


static uint8_t
__addKey(BTree *tree, BTreeNode *rootNode, uint8_t **key, offset_t *filePos,
         uint8_t *split, uint8_t replaceDup)
{
    uint8_t  *temp1, *temp2;
    offset_t  offset1, offset2;
    uint8_t   tempSize1, tempSize2;
    uint8_t   i, j;

    *split = 0;

    //dbg_log(SEC_0130_BTREE, 9)(LOGSTDOUT,"[DEBUG]  __addKey: beg: \n");
    //print_kvs(rootNode);

    for (i = 0;
         i < rootNode->keyCount && keyCmp(*key, rootNode->keys[i]) > 0;
         i++)
        ;

    if (i < rootNode->keyCount && keyCmp(*key, rootNode->keys[i]) == 0)
    {
        if (replaceDup && BTREE_IS_LEAF(rootNode))
        {
            rootNode->children[i] = *filePos;
            GDB_SET_DIRTY(rootNode->block);
            btreeWriteNode(rootNode);
        }

        //dbg_log(SEC_0130_BTREE, 9)(LOGSTDOUT,"[DEBUG]  __addKey: end[0]: \n");
        //print_kvs(rootNode);
        dbg_log(SEC_0130_BTREE, 0)(LOGSTDOUT, "error:__addKey:found duplicate\n");
        return 0;
    }

    rootNode->keyCount++;

    if (i < rootNode->keyCount)
    {
        temp1     = rootNode->keys[i];
        tempSize1 = rootNode->keySizes[i];

        rootNode->keys[i]     = keyDup(*key, LOC_BTREE_0166);
        rootNode->keySizes[i] = keyLen(*key);

        j = i;

        for (i++; i < rootNode->keyCount; i++)/*insert keyword*/
        {
            temp2     = rootNode->keys[i];
            tempSize2 = rootNode->keySizes[i];

            rootNode->keys[i]     = temp1;
            rootNode->keySizes[i] = tempSize1;

            temp1     = temp2;
            tempSize1 = tempSize2;
        }

        if (!BTREE_IS_LEAF(rootNode))
            j++;

        offset1 = rootNode->children[j];
        rootNode->children[j] = *filePos;

        for (j++; j <= rootNode->keyCount; j++)/*insert children/offset/pointer*/
        {
            offset2 = rootNode->children[j];
            rootNode->children[j] = offset1;
            offset1 = offset2;
        }
    }
    else
    {
        rootNode->keys[i]     = keyDup(*key, LOC_BTREE_0167);
        rootNode->keySizes[i] = keyLen(*key);

        if (BTREE_IS_LEAF(rootNode))
        {
            rootNode->children[i + 1] = rootNode->children[i];
            rootNode->children[i]     = *filePos;
        }
        else
            rootNode->children[i + 1] = *filePos;
    }

    GDB_SET_DIRTY(rootNode->block);
    btreeWriteNode(rootNode);

    //dbg_log(SEC_0130_BTREE, 9)(LOGSTDOUT,"[DEBUG]  __addKey: end[1]: \n");
    //print_kvs(rootNode);
    return 1;
}

static uint8_t
__insertKey(BTree *tree, offset_t rootOffset, uint8_t **key,
            offset_t *filePos, uint8_t *split, uint8_t replaceDup)
{
    uint8_t success = 0;
    BTreeNode *rootNode;

    if (rootOffset < DB_HEADER_BLOCK_SIZE)
    {
        dbg_log(SEC_0130_BTREE, 5)(LOGSTDOUT,
                _("error:__insertKey: rootOffset = %d in __insertKey('%s')\n"),
                rootOffset, *key);
        exit(1);
    }

    rootNode = btreeReadNode(tree, rootOffset);
    if(NULL == rootNode)
    {
        dbg_log(SEC_0130_BTREE, 0)(LOGSTDOUT, "error:__insertKey: read root node from offset %d failed\n", rootOffset);
        return (0);
    }

    if (BTREE_IS_LEAF(rootNode))
    {
        if (rootNode->keyCount < (tree->order - 1))
            success = __addKey(tree, rootNode, key, filePos, split, replaceDup);
        else
            success = __splitNode(tree, rootNode, key, filePos, split,
                                  replaceDup);

        btreeDestroyNode(rootNode);

        return success;
    }
    else
    {
        /* Internal node. */
        uint8_t i;

        for (i = 0;
             i < rootNode->keyCount && keyCmp(*key, rootNode->keys[i]) > 0;
             i++)
            ;

        success = __insertKey(tree, rootNode->children[i], key, filePos,
                              split, replaceDup);
    }

    if (success == 1 && *split == 1)
    {
        if (rootNode->keyCount < (tree->order - 1))
            __addKey(tree, rootNode, key, filePos, split, replaceDup);
        else
            __splitNode(tree, rootNode, key, filePos, split, replaceDup);
    }

    btreeDestroyNode(rootNode);

    return success;
}

GdbStatus
btreeInsert(BTree *tree, const uint8_t *key, offset_t filePos, uint8_t replaceDup)
{
    uint8_t  success, split;
    uint8_t *newKey;

    offset_t root;

    if (tree == NULL || key == NULL || filePos == 0 ||
        tree->block->db->mode == PM_MODE_READ_ONLY)
    {
        dbg_log(SEC_0130_BTREE, 9)(LOGSTDOUT,"[DEBUG]btreeInsert: tree %lx, key %lx, filePos %d, mode %o(PM_MODE_READ_ONLY %o)\n",
                tree, key, filePos, tree->block->db->mode, PM_MODE_READ_ONLY);
        return GDB_ERROR;
    }

#if 0
    dbg_log(SEC_0130_BTREE, 5)(LOGSTDOUT,"btreeInsert: ==> ");
    keyPrint(LOGSTDOUT, key);
    sys_print(LOGSTDOUT,"\n");
#endif

    newKey = keyDup(key, LOC_BTREE_0168);

    success = 0;
    split = 0;

    tree->_insFilePos = filePos;

    /* Read in the tree data. */
    tree->root     = btreeGetRootNode(tree);
    tree->leftLeaf = btreeGetLeftLeaf(tree);
    tree->size     = btreeGetTreeSize(tree);

    root = tree->root;

    if (tree->root != 0)
    {
        //dbg_log(SEC_0130_BTREE, 9)(LOGSTDOUT,"[DEBUG]btreeInsert: root is not zero\n");
        success = __insertKey(tree, tree->root, &newKey, &tree->_insFilePos,
                              &split, replaceDup);

        if (success == 0)
        {
            keyFree(newKey, LOC_BTREE_0169);
            return (replaceDup ? GDB_SUCCESS : GDB_DUPLICATE);
        }
    }

    btreeSetTreeSize(tree, tree->size + 1);

    if (tree->root == 0 || split == 1)
    {
        BTreeNode *node = btreeNewNode(tree);

        node->keys[0]     = keyDup(newKey, LOC_BTREE_0170);
        node->keySizes[0] = keyLen(newKey);
        node->keyCount    = 1;

        if (tree->root == 0)
        {
            //dbg_log(SEC_0130_BTREE, 9)(LOGSTDOUT,"[DEBUG]btreeInsert: root is zero, split = %d\n", split);

            node->children[0] = tree->_insFilePos;
            BTREE_SET_LEAF(node);

            btreeWriteNode(node);

            btreeSetLeftLeaf(tree, node->block->offset);
        }
        else
        {
            //dbg_log(SEC_0130_BTREE, 9)(LOGSTDOUT,"[DEBUG]btreeInsert: split = %d\n", split);
            node->children[0] = tree->root;
            node->children[1] = tree->_insFilePos;

            btreeWriteNode(node);
        }

        btreeSetRootNode(tree, node->block->offset);
        btreeDestroyNode(node);
    }

    keyFree(newKey, LOC_BTREE_0171);

    return GDB_SUCCESS;
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

