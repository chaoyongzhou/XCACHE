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

#include "type.h"
#include "list_base.h"

/*
 * Insert a new entry between two known consecutive entries.
 *
 * This is only for internal list manipulation where we know
 * the prev/next_node entries already!
 */
void __list_base_add(LIST_NODE * new_node, LIST_NODE * prev_node, LIST_NODE * next_node)
{
    next_node->prev = new_node;
    new_node->next = next_node;
    new_node->prev = prev_node;
    prev_node->next = new_node;
}

/**
 * list_base_add - add a new entry
 * @new_node: new entry to be added
 * @head_node: list head_node to add it after
 *
 * Insert a new entry after the specified head_node.
 * This is good for implementing stacks.
 */
void list_base_add(LIST_NODE *new_node, LIST_NODE *head_node)
{
    __list_base_add(new_node, head_node, head_node->next);
}

/**
 * list_base_add_tail - add a new entry
 * @new_node: new entry to be added
 * @head_node: list head_node to add it before
 *
 * Insert a new entry before the specified head_node.
 * This is useful for implementing queues.
 */
void list_base_add_tail(LIST_NODE *new_node, LIST_NODE *head_node)
{
    __list_base_add(new_node, head_node->prev, head_node);
}

/*
 * Delete a list entry by making the prev_node/next_node entries
 * point to each other.
 *
 * This is only for internal list manipulation where we know
 * the prev_node/next_node entries already!
 */
void __list_base_del(LIST_NODE * prev_node,
                  LIST_NODE * next_node)
{
    next_node->prev = prev_node;
    prev_node->next = next_node;
}

/**
 * list_base_del - deletes entry from list.
 * @entry: the element to delete from the list.
 * Note: list_base_empty on entry does not return true after this, the entry is in an undefined state.
 */
void list_base_del(LIST_NODE *entry)
{
    __list_base_del(entry->prev, entry->next);
    entry->next = entry->prev = 0;
}

/**
 * list_base_del_init - deletes entry from list and reinitialize it.
 * @entry: the element to delete from the list.
 */
void list_base_del_init(LIST_NODE *entry)
{
    __list_base_del(entry->prev, entry->next);
    INIT_LIST_BASE_HEAD(entry);
}

/**
 * list_base_move - delete from one list and add as another's head_node
 * @list: the entry to move
 * @head_node: the head_node that will precede our entry
 */
void list_base_move(LIST_NODE *list, LIST_NODE *head_node)
{
        __list_base_del(list->prev, list->next);
        list_base_add(list, head_node);
}
/**
 * list_base_move_tail - delete from one list and add as another's tail
 * @list: the entry to move
 * @head_node: the head_node that will follow our entry
 */
void list_base_move_tail(LIST_NODE *list,LIST_NODE *head_node)
{
        __list_base_del(list->prev, list->next);
        list_base_add_tail(list, head_node);
}
/**
 * list_base_empty - tests whether a list is empty
 * @head_node: the list to test.
 */
EC_BOOL list_base_empty(const LIST_NODE *head_node)
{
    if ( head_node->next == head_node )
    {
        return ( EC_TRUE );
    }

    return ( EC_FALSE);
}

/**
 * list_base_splice - join two lists
 * @list: the new list to add.
 * @head_node: the place to add it in the first list.
 */
void __list_base_splice(LIST_NODE *list,LIST_NODE *head_node)
{
    LIST_NODE *first = list->next;
    LIST_NODE *last = list->prev;
    LIST_NODE *at = head_node->next;

    first->prev = head_node;
    head_node->next = first;

    last->next = at;
    at->prev = last;
}
void list_base_splice(LIST_NODE *list, LIST_NODE *head_node)
{
    if (!list_base_empty(list))
    {
        __list_base_splice(list, head_node);
    }
}

/**
 * list_base_splice_init - join two lists and reinitialise the emptied list.
 * @list: the new list to add.
 * @head_node: the place to add it in the first list.
 *
 * The list at @list is reinitialised
 */
void list_base_splice_init(LIST_NODE *list,LIST_NODE *head_node)
{
    if (!list_base_empty(list))
    {
        __list_base_splice(list, head_node);
        INIT_LIST_BASE_HEAD(list);
    }
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/


