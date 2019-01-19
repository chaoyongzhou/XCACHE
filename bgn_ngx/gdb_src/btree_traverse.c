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

/*comment: handle all user datas on leaft node in order*/
void
btreeTraverse(LOG *log, BTree *tree, void (*process)(LOG *, const offset_t))
{
    BTreeTraversal *trav;
    offset_t offset;

    if (tree == NULL || process == NULL)
    {
        return;
    }
    trav = btreeInitTraversal(tree);

    for (offset = btreeGetFirstOffset(trav);
         offset != 0;
         offset = btreeGetNextOffset(trav))
    {
        process(log, offset);
    }

    btreeDestroyTraversal(trav);
}

void
btreeRunThrough(LOG *log, BTree *tree, void (*process)(LOG *, const offset_t, GDatabase *))
{
    BTreeTraversal *trav;
    offset_t offset;

    if (tree == NULL || process == NULL)
    {
        return;
    }
    trav = btreeInitTraversal(tree);

    for (offset = btreeGetFirstOffset(trav);
         offset != 0;
         offset = btreeGetNextOffset(trav))
    {
        process(log, offset, tree->block->db);
    }

    btreeDestroyTraversal(trav);
}

BTreeTraversal *
btreeInitTraversal(const BTree *tree)
{
    BTreeTraversal *trav;

    if (tree == NULL)
    {
        return NULL;
    }
    MEM_CHECK(trav = (BTreeTraversal *)SAFE_MALLOC(sizeof(BTreeTraversal), LOC_BTREE_0141));
    memset(trav, 0, sizeof(BTreeTraversal));

    trav->tree = (BTree *)tree;

    return trav;
}

BTreeTraversal *
btreeDestroyTraversal(BTreeTraversal *trav)
{
    if (trav == NULL)
    {
        return NULL;
    }
    if (trav->node != NULL)
    {
        btreeDestroyNode(trav->node);
        trav->node = NULL;
    }
    SAFE_FREE(trav, LOC_BTREE_0142);

    return NULL;
}

offset_t
btreeGetFirstOffset(BTreeTraversal *trav)
{
    if (trav == NULL)
    {
        return 0;
    }
    if (trav->node != NULL)
    {
        return btreeGetNextOffset(trav);
    }

    trav->tree->leftLeaf = btreeGetLeftLeaf(trav->tree);

    trav->node = btreeReadNode(trav->tree, trav->tree->leftLeaf);
    if (trav->node == NULL)
    {
        dbg_log(SEC_0130_BTREE, 0)(LOGSTDOUT, "error:btreeGetFirstOffset: read left leaf node from offset %d failed\n", trav->tree->leftLeaf);
        return (0);
    }
    trav->pos = 1;

    return trav->node->children[0];
}

offset_t
btreeGetNextOffset(BTreeTraversal *trav)
{
    offset_t offset;

    if (trav == NULL)
    {
        return 0;
    }
    /*comment: dead loop!!!*/
    if (trav->node == NULL)
    {
        //dbg_log(SEC_0130_BTREE, 5)(LOGSTDOUT,"#####################################\n");
        //return btreeGetNextOffset(trav);
        return 0;
    }

    if (trav->pos == trav->node->keyCount)
    {
        offset_t nextNodeOffset = trav->node->children[trav->pos];

        btreeDestroyNode(trav->node);
        trav->node = NULL;

        if (nextNodeOffset == 0)
        {
            return 0;
        }

        trav->node = btreeReadNode(trav->tree, nextNodeOffset);
        if (trav->node == NULL)
        {
            dbg_log(SEC_0130_BTREE, 0)(LOGSTDOUT, "error:btreeGetNextOffset: read next node from offset %d failed\n", nextNodeOffset);
            return (0);
        }
        trav->pos = 0;
    }

    offset = trav->node->children[trav->pos];

    trav->pos++;

    return offset;
}

offset_t
btreeGetLastOffset(BTreeTraversal *trav)
{
    offset_t nextNodeOffset;

    if (trav == NULL)
    {
        return 0;
    }

    if (trav->node == NULL)
    {
        trav->node = btreeReadNode(trav->tree, trav->tree->root);
        if (trav->node == NULL)
        {
            dbg_log(SEC_0130_BTREE, 0)(LOGSTDOUT, "error:btreeGetLastOffset: read root node from offset %d failed\n", trav->tree->root);
            return (0);
        }
        return btreeGetLastOffset(trav);
    }

    if(trav->node->children[trav->node->keyCount] == 0)
    {
        return trav->node->children[trav->node->keyCount - 1];
    }

    nextNodeOffset = trav->node->children[trav->node->keyCount];

    btreeDestroyNode(trav->node);
    trav->node = btreeReadNode(trav->tree, nextNodeOffset);
    if (trav->node == NULL)
    {
        dbg_log(SEC_0130_BTREE, 0)(LOGSTDOUT, "error:btreeGetLastOffset: read next node from offset %d failed\n", nextNodeOffset);
        return (0);
    }
    return btreeGetLastOffset(trav);
}

void
btreePrettyPrint(LOG *log, BTree *tree, offset_t rootOffset, uint8_t i, uint8_t verbose, void (*keyPrinter)(LOG *, const uint8_t *))
{
    uint8_t j;
    BTreeNode *rootNode;

    rootNode = btreeReadNode(tree, rootOffset);
    if (rootNode == NULL)
    {
        dbg_log(SEC_0130_BTREE, 0)(LOGSTDOUT, "error:btreePrettyPrint: read root node from offset %d failed\n", rootOffset);
        return ;
    }

    if(0 == i)
    {
        sys_log(log,"tree order: %d, tree size: %d\n", tree->order, tree->size);
    }

    if (rootNode == NULL)
    {
        sys_log(log, "error:btreePrettyPrint: rootNode (%d) is NULL\n", rootOffset);
        //exit(1);
        return;
    }

    for (j = i; j > 0; j--)
    {
        sys_print(log,"    ");
    }
    sys_print(log,"[.");

    for (j = 0; j < rootNode->keyCount; j++)
    {
        //sys_log(log," %s .", rootNode->keys[j]);
        sys_print(log," ");
        keyPrinter(log, rootNode->keys[j]);
        sys_print(log," .");
    }

    for (j = tree->order - rootNode->keyCount; j > 1; j--)
    {
        sys_print(log," _____ .");
    }

    sys_print(log,"] - %d\n", rootOffset);

    if (BTREE_IS_LEAF(rootNode))
    {
        /*debug*/
        if(verbose)
        {
            sys_print(log,"leaf node: ");
            for(j = 0; j <= rootNode->keyCount; j++)
            {
                sys_print(log,"%d ", rootNode->children[j]);
            }
            sys_print(log,"\n");
        }

        btreeDestroyNode(rootNode);
        return;
    }

    for (j = 0; j <= rootNode->keyCount; j++)
    {
        btreePrettyPrint(log, tree, rootNode->children[j], i + 1, verbose, keyPrinter);
    }

    btreeDestroyNode(rootNode);
    return;
}

uint8_t btreeCollectAllOffset(BTree *tree, offset_t **offset_list, uint32_t *offset_num)
{
    BTreeTraversal *trav;

    uint32_t  pos;
    offset_t  offset;
    offset_t *offset_ptr;

    if (tree == NULL)
    {
        dbg_log(SEC_0130_BTREE, 0)(LOGSTDOUT, "error:btreeCollectAllOffset: tree is null\n");
        return 0;
    }

    offset_ptr = (offset_t *)SAFE_MALLOC(tree->size * sizeof(offset_t), LOC_BTREE_0143);
    if(NULL == offset_ptr)
    {
        dbg_log(SEC_0130_BTREE, 0)(LOGSTDOUT, "error:btreeCollectAllOffset: alloc %u offset_t failed\n", tree->size);
        return 0;
    }

    (*offset_list) = offset_ptr;

    trav = btreeInitTraversal(tree);

    for (offset = btreeGetFirstOffset(trav), pos = 0;
         offset != 0;
         offset = btreeGetNextOffset(trav), pos ++)
    {
        *(offset_ptr + pos) = offset;
    }

    btreeDestroyTraversal(trav);

    /*check consistency*/
    if(pos != tree->size)
    {
        dbg_log(SEC_0130_BTREE, 0)(LOGSTDOUT, "error:btreeCollectAllOffset: found inconsistency where tree size %u but collected %u offset\n",
                           tree->size, pos);
    }

    (*offset_list) = offset_ptr;
    (*offset_num)  = pos;

    return 1;/*success*/
}


#ifdef __cplusplus
}
#endif/*__cplusplus*/

