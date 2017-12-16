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

#ifndef _LIST_BASE_H
#define _LIST_BASE_H

#include "type.h"

#define LIST_BASE_HEAD_INIT(name) { &(name), &(name) }

#define LIST_BASE_HEAD(name) \
    LIST_NODE name = LIST_BASE_HEAD_INIT(name)

#define INIT_LIST_BASE_HEAD(ptr) do { \
    (ptr)->next = (ptr); (ptr)->prev = (ptr); \
} while (0)

/**
 * list_base_entry - get the struct for this entry
 * @ptr:    the &LIST_NODE pointer.
 * @type:    the type of the struct this is embedded in.
 * @member:    the name of the list_base_struct within the struct.
 */
#define list_base_entry(ptr, type, member) \
    ((type *)((char *)(ptr)-(unsigned long)(&((type *)0)->member)))


/**
 * list_base_for_each_safe    -    iterate over a list safe against removal of list entry
 * @pos:    the &LIST_NODE to use as a loop counter.
 * @n:        another &LIST_NODE to use as temporary storage
 * @head:    the head for your list.
 */
#define list_base_for_each_safe(pos, n, new_node) \
    for (pos = (new_node)->next, n = pos->next; pos != (new_node); \
        pos = n, n = pos->next)

/*
 * Insert a new entry between two known consecutive entries.
 *
 * This is only for internal list manipulation where we know
 * the prev/next entries already!
 */
void __list_base_add(LIST_NODE * new_node, LIST_NODE * prev_node,LIST_NODE * next_node);


/**
 * list_base_add - add a new entry
 * @new: new entry to be added
 * @head: list head to add it after
 *
 * Insert a new entry after the specified head.
 * This is good for implementing stacks.
 */
void list_base_add(LIST_NODE *new_node, LIST_NODE *head_node);


/**
 * list_base_add_tail - add a new entry
 * @new: new entry to be added
 * @head: list head to add it before
 *
 * Insert a new entry before the specified head.
 * This is useful for implementing queues.
 */
void list_base_add_tail(LIST_NODE *new_node, LIST_NODE *head_node);


/*
 * Delete a list entry by making the prev/next entries
 * point to each other.
 *
 * This is only for internal list manipulation where we know
 * the prev/next entries already!
 */
void __list_base_del(LIST_NODE * prev_node,LIST_NODE * next_node);


/**
 * list_base_del - deletes entry from list.
 * @entry: the element to delete from the list.
 * Note: list_base_empty on entry does not return true after this, the entry is in an undefined state.
 */
void list_base_del(LIST_NODE *entry);

/**
 * list_base_del_init - deletes entry from list and reinitialize it.
 * @entry: the element to delete from the list.
 */
void list_base_del_init(LIST_NODE *entry);

/**
 * list_base_move - delete from one list and add as another's head
 * @list: the entry to move
 * @head: the head that will precede our entry
 */
void list_base_move(LIST_NODE *list, LIST_NODE *head_node);
/**
 * list_base_move_tail - delete from one list and add as another's tail
 * @list: the entry to move
 * @head: the head that will follow our entry
 */
void list_base_move_tail(LIST_NODE *list, LIST_NODE *head_node);

/**
 * list_base_empty - tests whether a list is empty
 * @head: the list to test.
 */
EC_BOOL list_base_empty(const LIST_NODE *head_node);

/**
 * list_base_splice - join two lists
 * @list: the new list to add.
 * @head: the place to add it in the first list.
 */
void __list_base_splice(LIST_NODE *list,LIST_NODE *head_node);

void list_base_splice(LIST_NODE *list, LIST_NODE *head_node);


/**
 * list_base_splice_init - join two lists and reinitialise the emptied list.
 * @list: the new list to add.
 * @head: the place to add it in the first list.
 *
 * The list at @list is reinitialised
 */
void list_base_splice_init(LIST_NODE *list,LIST_NODE *head_node);

#endif/*_LIST_BASE_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

