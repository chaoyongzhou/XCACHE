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

#ifndef    _CRB_H
#define    _CRB_H

#include "type.h"

#define CRB_RED            ((uint16_t)0)
#define CRB_BLACK          ((uint16_t)1)

typedef struct _CRB_NODE
{
    struct _CRB_NODE *rb_parent;
    struct _CRB_NODE *rb_right;
    struct _CRB_NODE *rb_left;
    uint16_t          rb_color;
    uint16_t          rsvd[3];
    void *            data;
}CRB_NODE;

#define CRB_NODE_PARENT(node)          ((node)->rb_parent)
#define CRB_NODE_RIGHT(node)           ((node)->rb_right)
#define CRB_NODE_LEFT(node)            ((node)->rb_left)
#define CRB_NODE_COLOR(node)           ((node)->rb_color)
#define CRB_NODE_DATA(node)            ((node)->data)

#define CRB_NODE_IS_RED(node)           (CRB_RED == CRB_NODE_COLOR(node))
#define CRB_NODE_IS_BLACK(node)         (CRB_BLACK == CRB_NODE_COLOR(node))

typedef int  (*CRB_DATA_CMP)(const void *, const void *);

typedef void (*CRB_DATA_FREE)(void *);
typedef void (*CRB_DATA_PRINT)(LOG *, const void *);

typedef EC_BOOL (*CRB_DATA_IS_EQUAL)(const void *, const void *);
typedef EC_BOOL (*CRB_DATA_HANDLE)(const void *, void *);

typedef void *(*CRB_DATA_NEW)();
typedef EC_BOOL (*CRB_DATA_FLUSH)(const void *, int, UINT32 *);
typedef EC_BOOL (*CRB_DATA_LOAD)(void *, int, UINT32 *);
typedef EC_BOOL (*CRB_DATA_CLONE)(const void *, void *);

typedef struct
{
    uint32_t            node_num;
    uint32_t            rsvd;
    struct _CRB_NODE   *rb_node;
    CRB_DATA_CMP        data_cmp_func;
    CRB_DATA_FREE       data_free_func;
    CRB_DATA_PRINT      data_print_func;
}CRB_TREE;

#define CRB_TREE_NODE_NUM(crbtree)          ((crbtree)->node_num)
#define CRB_TREE_ROOT(crbtree)              ((crbtree)->rb_node)
#define CRB_TREE_DATA_CMP(crbtree)          ((crbtree)->data_cmp_func)
#define CRB_TREE_DATA_FREE(crbtree)         ((crbtree)->data_free_func)
#define CRB_TREE_DATA_PRINT(crbtree)        ((crbtree)->data_print_func)

CRB_NODE * crb_node_new();

void crb_node_init(CRB_NODE *node);

void crb_node_clean(CRB_NODE *node);

void crb_node_free(CRB_NODE *node);

void crb_node_print(LOG *log, const CRB_TREE *crbtree, const CRB_NODE *node);

void crb_node_print_level(LOG *log, const CRB_TREE *crbtree, const CRB_NODE *node, const uint16_t level);

EC_BOOL crb_tree_is_empty(const CRB_TREE *crbtree);

uint32_t crb_tree_node_count(const CRB_TREE *crbtree);

uint32_t crb_tree_node_num(const CRB_TREE *crbtree);

/*
 * This function returns the first node_pos (in sort order); of the tree.
 */
const CRB_NODE * crb_tree_first_node(const CRB_TREE *crbtree);

const CRB_NODE * crb_tree_last_node(const CRB_TREE *crbtree);

const CRB_NODE * crb_tree_next_node(const CRB_TREE *crbtree, const CRB_NODE *node);

const CRB_NODE * crb_tree_prev_node(const CRB_TREE *crbtree, const CRB_NODE *node);

void * crb_tree_first_data(const CRB_TREE *crbtree);

void * crb_tree_last_data(const CRB_TREE *crbtree);

void * crb_tree_next_data(const CRB_TREE *crbtree, const void *data);

void * crb_tree_prev_data(const CRB_TREE *crbtree, const void *data);

/*victim_pos should be free*/
void crb_tree_replace_node(CRB_TREE *crbtree, CRB_NODE *victim, CRB_NODE *new_node);

/*return the searched pos*/
CRB_NODE *crb_tree_search(CRB_TREE *crbtree, const CRB_NODE *data_node);

CRB_NODE * crb_tree_insert(CRB_TREE *crbtree, CRB_NODE *new_node);

EC_BOOL crb_tree_delete(CRB_TREE *crbtree, CRB_NODE *node);

void   *crb_tree_erase(CRB_TREE *crbtree, CRB_NODE *node);

CRB_NODE *crb_tree_lookup_data(const CRB_TREE *crbtree, const void *data);

CRB_NODE *crb_tree_search_data(const CRB_TREE *crbtree, const void *data);

CRB_NODE * crb_tree_insert_data(CRB_TREE *crbtree, const void *data);

EC_BOOL crb_tree_delete_data(CRB_TREE *crbtree, const void *data);

CRB_TREE *crb_tree_new(CRB_DATA_CMP data_cmp, CRB_DATA_FREE data_free, CRB_DATA_PRINT data_print);

EC_BOOL crb_tree_init(CRB_TREE *crbtree, CRB_DATA_CMP data_cmp, CRB_DATA_FREE data_free, CRB_DATA_PRINT data_print);

void crb_tree_clean(CRB_TREE *crbtree);

void crb_tree_free(CRB_TREE *crbtree);

EC_BOOL crb_tree_cmp(const CRB_TREE *crbtree_1st, const CRB_TREE *crbtree_2nd, EC_BOOL (*cmp)(const void *, const void *));

void crb_tree_print(LOG *log, const CRB_TREE *crbtree);

void crb_tree_print_in_order(LOG *log, const CRB_TREE *crbtree);

/*visit the root node first: root -> left -> right*/
void crb_preorder_print(LOG *log, const CRB_TREE *crbtree);

/*visit the left subtree, then the root node: left -> root -> right*/
void crb_inorder_print(LOG *log, const CRB_TREE *crbtree);

/*visit the root node last: left -> right -> root*/
void crb_postorder_print(LOG *log, const CRB_TREE *crbtree);

/*visit the root node first: root -> left -> right*/
void crb_preorder_print_level(LOG *log, const CRB_TREE *crbtree, const uint16_t level);

/*walk through: left -> root -> right*/
EC_BOOL crb_inorder_walk(const CRB_TREE *crbtree, EC_BOOL (*walker)(const void *, void *), void *arg);

/*walk through: left -> right -> root*/
EC_BOOL crb_postorder_walk(const CRB_TREE *crbtree, EC_BOOL (*walker)(const void *, void *), void *arg);

/*walk through: root -> left -> right*/
EC_BOOL crb_preorder_walk(const CRB_TREE *crbtree, EC_BOOL (*walker)(const void *, void *), void *arg);

/*walk through: left -> root -> right*/
EC_BOOL crb_inorder_flush(const CRB_TREE *crbtree, int fd, UINT32 *offset, EC_BOOL (*flush)(const void *, int, UINT32 *));
EC_BOOL crb_tree_flush(const CRB_TREE *crbtree, int fd, UINT32 *offset, EC_BOOL (*flush)(const void *, int, UINT32 *));

EC_BOOL crb_tree_load(CRB_TREE *crbtree, int fd, UINT32 *offset, void *(*data_new)(), EC_BOOL (*data_load)(void *, int, UINT32 *));

EC_BOOL crb_inorder_clone(const CRB_TREE *crbtree_src, CRB_TREE *crbtree_des, void *(*data_new)(), EC_BOOL (*data_clone)(const void *, void *));
EC_BOOL crb_tree_clone(const CRB_TREE *crbtree_src, CRB_TREE *crbtree_des, void *(*data_new)(), EC_BOOL (*data_clone)(const void *, void *));

#endif    /* _CRB_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/
