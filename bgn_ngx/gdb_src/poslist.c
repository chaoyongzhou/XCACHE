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
#include "list_base.h"

OffsetList *offsetListNew(const uint16_t each_node_size, const word_t location)
{
    OffsetList *offsetList;

    MEM_CHECK(offsetList = (OffsetList *)SAFE_MALLOC(sizeof(OffsetList), LOC_POSLIST_0001));
    offsetListInit(offsetList, each_node_size, location);
    return (offsetList);
}

void offsetListInit(OffsetList *offsetList, const uint16_t each_node_size, const word_t location)
{
    INIT_LIST_BASE_HEAD(&(offsetList->head));
    offsetList->size = each_node_size;
    offsetList->num = 0;
    return;
}

void offsetListClean(OffsetList *offsetList, const word_t location)
{
    OffsetNode *offsetNode;
    while(NULL != (offsetNode = offsetListPopBackNode(offsetList)))
    {
        offsetNodeFree(offsetNode, location);
    }
    return;
}

void offsetListFree(OffsetList *offsetList, const word_t location)
{
    offsetListClean(offsetList, location);
    SAFE_FREE(offsetList, location);
    return;
}

uint8_t offsetListAdd(OffsetList *offsetList, const offset_t offset)
{
    OffsetNode *offsetNode;

    offsetNode = offsetListGetBackNode(offsetList);
    if(NULL != offsetNode && !offsetNodeIsFull(offsetNode))
    {
        return offsetNodeAdd(offsetNode, offset);
    }

    MEM_CHECK(offsetNode = offsetNodeNew(offsetList->size, LOC_POSLIST_0002));
    offsetListPushBackNode(offsetList, offsetNode);
    return offsetNodeAdd(offsetNode, offset);
}

void offsetListLoop(OffsetList *offsetList, void *extra, void (*process)(const offset_t offset, void *extra))
{
    OffsetNode *offsetNode;
    for(offsetNode = OFFSET_LIST_FIRST_NODE(offsetList);
        offsetNode != OFFSET_LIST_NULL_NODE(offsetList);
        offsetNode = OFFSET_NODE_NEXT(offsetNode))
    {
        offsetNodeLoop(offsetNode, extra, process);
    }
}


void offsetListPushBackNode(OffsetList *offsetList, OffsetNode *offsetNode)
{
    list_base_add_tail(&(offsetNode->node), &(offsetList->head));
    offsetList->num ++;
    return;
}

void offsetListPushFrontNode(OffsetList *offsetList, OffsetNode *offsetNode)
{
    list_base_add(&(offsetNode->node), &(offsetList->head));
    offsetList->num ++;
    return;
}

OffsetNode *offsetListPopBackNode(OffsetList *offsetList)
{
    OffsetNode *offsetNode;

    if(GDB_TRUE == list_base_empty(&(offsetList->head)))
    {
        return NULL;
    }

    offsetNode = OFFSET_LIST_FIRST_NODE(offsetList);
    OFFSET_NODE_DEL(offsetNode);
    offsetList->num --;

    return offsetNode;
}

OffsetNode *offsetListPopFrontNode(OffsetList *offsetList)
{
    OffsetNode *offsetNode;

    if(GDB_TRUE == list_base_empty(&(offsetList->head)))
    {
        return NULL;
    }

    offsetNode = OFFSET_LIST_LAST_NODE(offsetList);
    OFFSET_NODE_DEL(offsetNode);
    offsetList->num --;

    return offsetNode;
}

OffsetNode *offsetListGetBackNode(OffsetList *offsetList)
{
    OffsetNode *offsetNode;

    if(GDB_TRUE == list_base_empty(&(offsetList->head)))
    {
        return NULL;
    }

    offsetNode = OFFSET_LIST_FIRST_NODE(offsetList);
    return offsetNode;
}

OffsetNode *offsetListGetFrontNode(OffsetList *offsetList)
{
    OffsetNode *offsetNode;

    if(GDB_TRUE == list_base_empty(&(offsetList->head)))
    {
        return NULL;
    }

    offsetNode = OFFSET_LIST_LAST_NODE(offsetList);
    return offsetNode;
}

OffsetNode *offsetNodeNew(const uint16_t each_node_size, const word_t location)
{
    OffsetNode *offsetNode;

    MEM_CHECK(offsetNode = (OffsetNode *)SAFE_MALLOC(sizeof(OffsetNode), LOC_POSLIST_0003));
    offsetNodeInit(offsetNode, each_node_size, location);
    return (offsetNode);
}

void offsetNodeInit(OffsetNode *offsetNode, const uint16_t each_node_size, const word_t location)
{
    INIT_LIST_BASE_HEAD(&(offsetNode->node));
    MEM_CHECK(offsetNode->offsets = (offset_t *)SAFE_MALLOC(each_node_size * sizeof(offset_t), LOC_POSLIST_0004));
    BSET(offsetNode->offsets, 0, each_node_size * sizeof(offset_t));

    offsetNode->size = each_node_size;
    offsetNode->count = 0;

    return;
}

void offsetNodeClean(OffsetNode *offsetNode, const word_t location)
{
    INIT_LIST_BASE_HEAD(&(offsetNode->node));
    SAFE_FREE(offsetNode->offsets, location);
    offsetNode->offsets = NULL;

    offsetNode->size  = 0;
    offsetNode->count = 0;
    return;
}


void offsetNodeFree(OffsetNode *offsetNode, const word_t location)
{
    offsetNodeClean(offsetNode, location);
    SAFE_FREE(offsetNode, location);

    return;
}

uint8_t offsetNodeIsFull(OffsetNode *offsetNode)
{
    return (offsetNode->size == offsetNode->count);
}

uint8_t offsetNodeAdd(OffsetNode *offsetNode, const offset_t offset)
{
    if(offsetNodeIsFull(offsetNode))
    {
        return 0;/*false*/
    }
    offsetNode->offsets[offsetNode->count ++] = offset;
    return 1;
}

void offsetNodeLoop(OffsetNode *offsetNode, void *extra, void (*process)(const offset_t , void *))
{
    uint16_t idx;

    for(idx = 0; idx < offsetNode->count; idx ++)
    {
        process(offsetNode->offsets[idx], extra);
    }
    return;
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

