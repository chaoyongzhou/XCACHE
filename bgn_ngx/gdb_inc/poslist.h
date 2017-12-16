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

#ifndef _POSLIST_H_
#define _POSLIST_H_

#include "db.h"
#include "list_base.h"

typedef struct
{
    LIST_NODE node;

    uint16_t  size;    /**< The size of the offsets array.     */
    uint16_t  count;   /**< The number of offsets in the list. */
    offset_t *offsets; /**< The offsets array.                 */
} OffsetNode;

#define LIST_NODE_TO_OFFSET_NODE(listNode)    ((OffsetNode *)list_base_entry(listNode, OffsetNode, node))
#define OFFSET_NODE_TO_LIST_NODE(offsetNode)  (&((offsetNode)->node))

typedef struct
{
    LIST_NODE head;
    uint16_t  size; /**< The size of each offset node.     */
    uint16_t  num;  /**< The num of offset nodes.          */
}OffsetList;

typedef void (*OFFSET_PROCESS)(const offset_t offset, void *extra);

#define OFFSET_LIST_NULL_NODE(offsetList)  list_base_entry(&((offsetList)->head), OffsetNode, node)

#define OFFSET_LIST_FIRST_NODE(offsetList) list_base_entry((offsetList)->head.next, OffsetNode, node)

#define OFFSET_LIST_LAST_NODE(offsetList)  list_base_entry((offsetList)->head.prev, OffsetNode, node)

#define OFFSET_NODE_NEXT(offsetNode)       list_base_entry((offsetNode)->node.next, OffsetNode, node)

#define OFFSET_NODE_DEL(offsetNode)        list_base_del_init(OFFSET_NODE_TO_LIST_NODE(offsetNode))

OffsetList *offsetListNew(const uint16_t each_node_size, const word_t location);

void offsetListInit(OffsetList *offsetList, const uint16_t each_node_size, const word_t location);
void offsetListClean(OffsetList *offsetList, const word_t location);
void offsetListFree(OffsetList *offsetList, const word_t location);

uint8_t offsetListAdd(OffsetList *offsetList, const offset_t offset);

void offsetListLoop(OffsetList *offsetList, void *extra, void (*process)(const offset_t offset, void *extra));

void offsetListPushBackNode(OffsetList *offsetList, OffsetNode *offsetNode);

void offsetListPushFrontNode(OffsetList *offsetList, OffsetNode *offsetNode);

OffsetNode *offsetListPopBackNode(OffsetList *offsetList);

OffsetNode *offsetListPopFrontNode(OffsetList *offsetList);

OffsetNode *offsetListGetBackNode(OffsetList *offsetList);

OffsetNode *offsetListGetFrontNode(OffsetList *offsetList);

OffsetNode *offsetNodeNew(const uint16_t each_node_size, const word_t location);

void offsetNodeInit(OffsetNode *offsetNode, const uint16_t each_node_size, const word_t location);
void offsetNodeClean(OffsetNode *offsetNode, const word_t location);
void offsetNodeFree(OffsetNode *offsetNode, const word_t location);

uint8_t offsetNodeIsFull(OffsetNode *offsetNode);

uint8_t offsetNodeAdd(OffsetNode *offsetNode, const offset_t offset);

void offsetNodeLoop(OffsetNode *offsetNode, void *extra, void (*process)(const offset_t , void *));


#endif /* _POSLIST_H_ */

#ifdef __cplusplus
}
#endif/*__cplusplus*/
