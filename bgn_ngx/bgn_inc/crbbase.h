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

#ifndef    _CRBBASE_H
#define    _CRBBASE_H

#include "type.h"

#define CRBBASE_RED            ((uint16_t)0)
#define CRBBASE_BLACK          ((uint16_t)1)

typedef struct _CRBBASE_NODE
{
    struct _CRBBASE_NODE *rb_parent;
    struct _CRBBASE_NODE *rb_right;
    struct _CRBBASE_NODE *rb_left;
    uint16_t              rb_color;
    uint16_t              rsvd01;
    uint32_t              used:1;
    uint32_t              rsvd02:31;
}CRBBASE_NODE;

#define CRBBASE_NODE_PARENT(node)          ((node)->rb_parent)
#define CRBBASE_NODE_RIGHT(node)           ((node)->rb_right)
#define CRBBASE_NODE_LEFT(node)            ((node)->rb_left)
#define CRBBASE_NODE_COLOR(node)           ((node)->rb_color)
#define CRBBASE_NODE_USED(node)            ((node)->used)

#define CRBBASE_NODE_DATA(node, offset)    ((void *)(((char *)(node)) - (offset)))

#define CRBBASE_NODE_IS_RED(node)           (CRBBASE_RED == CRBBASE_NODE_COLOR(node))
#define CRBBASE_NODE_IS_BLACK(node)         (CRBBASE_BLACK == CRBBASE_NODE_COLOR(node))

typedef int  (*CRBBASE_DATA_CMP)(const void *, const void *);

typedef void (*CRBBASE_DATA_FREE)(void *);
typedef void (*CRBBASE_DATA_PRINT)(LOG *, const void *);

typedef EC_BOOL (*CRBBASE_DATA_IS_EQUAL)(const void *, const void *);
typedef EC_BOOL (*CRBBASE_DATA_HANDLE)(const void *, void *);

typedef void *(*CRBBASE_DATA_NEW)();
typedef EC_BOOL (*CRBBASE_DATA_FLUSH)(const void *, int, UINT32 *);
typedef EC_BOOL (*CRBBASE_DATA_LOAD)(void *, int, UINT32 *);
typedef EC_BOOL (*CRBBASE_DATA_CLONE)(const void *, void *);

typedef struct
{
    uint32_t                node_num;
    uint32_t                node_offset;     /*CRBBASE_NODE offset in host structer*/
    struct _CRBBASE_NODE   *rb_node;
    CRBBASE_DATA_CMP        data_cmp_func;
    CRBBASE_DATA_FREE       data_free_func;
    CRBBASE_DATA_PRINT      data_print_func;
}CRBBASE_TREE;

#define CRBBASE_TREE_NODE_NUM(crbbasetree)          ((crbbasetree)->node_num)
#define CRBBASE_TREE_NODE_OFFSET(crbbasetree)       ((crbbasetree)->node_offset)
#define CRBBASE_TREE_ROOT(crbbasetree)              ((crbbasetree)->rb_node)
#define CRBBASE_TREE_DATA_CMP(crbbasetree)          ((crbbasetree)->data_cmp_func)
#define CRBBASE_TREE_DATA_FREE(crbbasetree)         ((crbbasetree)->data_free_func)
#define CRBBASE_TREE_DATA_PRINT(crbbasetree)        ((crbbasetree)->data_print_func)

void crbbase_node_init(CRBBASE_NODE *node);

void crbbase_node_clean(CRBBASE_NODE *node);

EC_BOOL crbbase_node_is_empty(const CRBBASE_NODE *node);

void crbbase_node_print(LOG *log, const CRBBASE_TREE *crbbasetree, const CRBBASE_NODE *node);

void crbbase_node_print_level(LOG *log, const CRBBASE_TREE *crbbasetree, const CRBBASE_NODE *node, const uint16_t level);

EC_BOOL crbbase_tree_is_empty(const CRBBASE_TREE *crbbasetree);

uint32_t crbbase_tree_node_count(const CRBBASE_TREE *crbbasetree);

uint32_t crbbase_tree_node_num(const CRBBASE_TREE *crbbasetree);

/*
 * This function returns the first node_pos (in sort order); of the tree.
 */
const CRBBASE_NODE * crbbase_tree_first_node(const CRBBASE_TREE *crbbasetree);

const CRBBASE_NODE * crbbase_tree_last_node(const CRBBASE_TREE *crbbasetree);

const CRBBASE_NODE * crbbase_tree_next_node(const CRBBASE_TREE *crbbasetree, const CRBBASE_NODE *node);

const CRBBASE_NODE * crbbase_tree_prev_node(const CRBBASE_TREE *crbbasetree, const CRBBASE_NODE *node);

void * crbbase_tree_first_data(const CRBBASE_TREE *crbbasetree);

void * crbbase_tree_last_data(const CRBBASE_TREE *crbbasetree);

void * crbbase_tree_next_data(const CRBBASE_TREE *crbbasetree, const void *data);

void * crbbase_tree_prev_data(const CRBBASE_TREE *crbbasetree, const void *data);

/*victim_pos should be free*/
void crbbase_tree_replace_node(CRBBASE_TREE *crbbasetree, CRBBASE_NODE *victim, CRBBASE_NODE *new_node);

/*return the searched pos*/
CRBBASE_NODE *crbbase_tree_search(CRBBASE_TREE *crbbasetree, const CRBBASE_NODE *data_node);

CRBBASE_NODE * crbbase_tree_insert(CRBBASE_TREE *crbbasetree, CRBBASE_NODE *new_node);

EC_BOOL crbbase_tree_delete(CRBBASE_TREE *crbbasetree, CRBBASE_NODE *node);

void   *crbbase_tree_erase(CRBBASE_TREE *crbbasetree, CRBBASE_NODE *node);

CRBBASE_NODE *crbbase_tree_lookup_data(const CRBBASE_TREE *crbbasetree, const void *data);

CRBBASE_NODE *crbbase_tree_search_data(const CRBBASE_TREE *crbbasetree, const void *data);

CRBBASE_NODE * crbbase_tree_insert_data(CRBBASE_TREE *crbbasetree, const void *data);

EC_BOOL crbbase_tree_delete_data(CRBBASE_TREE *crbbasetree, const void *data);

void *crbbase_tree_node_data(CRBBASE_TREE *crbbasetree, CRBBASE_NODE *node);

CRBBASE_TREE *crbbase_tree_new(const uint32_t node_offset, CRBBASE_DATA_CMP data_cmp, CRBBASE_DATA_FREE data_free, CRBBASE_DATA_PRINT data_print);

EC_BOOL crbbase_tree_init(CRBBASE_TREE *crbbasetree, const uint32_t node_offset, CRBBASE_DATA_CMP data_cmp, CRBBASE_DATA_FREE data_free, CRBBASE_DATA_PRINT data_print);

void crbbase_tree_clean(CRBBASE_TREE *crbbasetree);

void crbbase_tree_free(CRBBASE_TREE *crbbasetree);

uint32_t crbbase_tree_node_offset(const CRBBASE_TREE *crbbasetree);

EC_BOOL crbbase_tree_cmp(const CRBBASE_TREE *crbbasetree_1st, const CRBBASE_TREE *crbbasetree_2nd, EC_BOOL (*cmp)(const void *, const void *));

void crbbase_tree_print(LOG *log, const CRBBASE_TREE *crbbasetree);

void crbbase_tree_print_in_order(LOG *log, const CRBBASE_TREE *crbbasetree);

/*visit the root node first: root -> left -> right*/
void crbbase_preorder_print(LOG *log, const CRBBASE_TREE *crbbasetree);

/*visit the left subtree, then the root node: left -> root -> right*/
void crbbase_inorder_print(LOG *log, const CRBBASE_TREE *crbbasetree);

/*visit the root node last: left -> right -> root*/
void crbbase_postorder_print(LOG *log, const CRBBASE_TREE *crbbasetree);

/*visit the root node first: root -> left -> right*/
void crbbase_preorder_print_level(LOG *log, const CRBBASE_TREE *crbbasetree, const uint16_t level);

/*walk through: left -> root -> right*/
EC_BOOL crbbase_inorder_walk(const CRBBASE_TREE *crbbasetree, EC_BOOL (*walker)(const void *, void *), void *arg);

/*walk through: left -> right -> root*/
EC_BOOL crbbase_postorder_walk(const CRBBASE_TREE *crbbasetree, EC_BOOL (*walker)(const void *, void *), void *arg);

/*walk through: root -> left -> right*/
EC_BOOL crbbase_preorder_walk(const CRBBASE_TREE *crbbasetree, EC_BOOL (*walker)(const void *, void *), void *arg);

/*walk through: left -> root -> right*/
CRBBASE_NODE *crbbase_inorder_locate(CRBBASE_TREE *crbbasetree, void *data);

/*walk through: left -> right -> root*/
CRBBASE_NODE *crbbase_postorder_locate(CRBBASE_TREE *crbbasetree, void *data);

/*walk through: left -> root -> right*/
CRBBASE_NODE *crbbase_preorder_locate(CRBBASE_TREE *crbbasetree, void *data);

/*walk through: left -> root -> right*/
EC_BOOL crbbase_inorder_flush(const CRBBASE_TREE *crbbasetree, int fd, UINT32 *offset, EC_BOOL (*flush)(const void *, int, UINT32 *));
EC_BOOL crbbase_tree_flush(const CRBBASE_TREE *crbbasetree, int fd, UINT32 *offset, EC_BOOL (*flush)(const void *, int, UINT32 *));

EC_BOOL crbbase_tree_load(CRBBASE_TREE *crbbasetree, int fd, UINT32 *offset, void *(*data_new)(), EC_BOOL (*data_load)(void *, int, UINT32 *));

EC_BOOL crbbase_inorder_clone(const CRBBASE_TREE *crbbasetree_src, CRBBASE_TREE *crbbasetree_des, void *(*data_new)(), EC_BOOL (*data_clone)(const void *, void *));
EC_BOOL crbbase_tree_clone(const CRBBASE_TREE *crbbasetree_src, CRBBASE_TREE *crbbasetree_des, void *(*data_new)(), EC_BOOL (*data_clone)(const void *, void *));

EC_BOOL crbbase_tree_move(CRBBASE_TREE *crbbasetree_src, CRBBASE_TREE *crbbasetree_des);

#endif    /* _CRBBASE_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/

