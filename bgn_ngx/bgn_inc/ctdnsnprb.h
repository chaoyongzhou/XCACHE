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

#ifndef    _CTDNSNPRB_H
#define    _CTDNSNPRB_H

#include "type.h"

#define CTDNSNPRB_RED            ((uint32_t)0)
#define CTDNSNPRB_BLACK          ((uint32_t)1)

#define CTDNSNPRB_NODE_NOT_USED  ((uint32_t)0)
#define CTDNSNPRB_NODE_USED      ((uint32_t)1)

#define CTDNSNPRB_ERR_POS        ((uint32_t)0x7FFFFFFF)/*31 bits*/

#define CTDNSNPRB_POOL_MAX_SIZE  ((uint32_t)(1 << 23))/* < 2^23, about 8,000,000*/

typedef struct
{
    uint32_t rb_parent_pos:31; /*value range: [0, 0x7FFFFFFF)*/
    uint32_t rb_used      : 1; /*CTDNSNPRB_USED or CTDNSNPRB_NOT_USED*/

    uint32_t rb_right_pos :31; /*value range: [0, 0x7FFFFFFF)*/
    uint32_t rsvd1        : 1;

    uint32_t rb_left_pos  :31; /*value range: [0, 0x7FFFFFFF)*/
    uint32_t rb_color     : 1; /*CTDNSNPRB_RED or CTDNSNPRB_BLACK*/

    union
    {
        uint32_t rb_next_pos  :31; /*save next position*/
        uint32_t rb_hash_data;     /*saved data*/
    }u;
}CTDNSNPRB_NODE; /*16B*/

#define CTDNSNPRB_NODE_PARENT_POS(node)       ((node)->rb_parent_pos)
#define CTDNSNPRB_NODE_RIGHT_POS(node)        ((node)->rb_right_pos)
#define CTDNSNPRB_NODE_LEFT_POS(node)         ((node)->rb_left_pos)
#define CTDNSNPRB_NODE_NEXT_POS(node)         ((node)->u.rb_next_pos)
#define CTDNSNPRB_NODE_DATA(node)             ((node)->u.rb_hash_data)
#define CTDNSNPRB_NODE_COLOR(node)            ((node)->rb_color)
#define CTDNSNPRB_NODE_USED_FLAG(node)        ((node)->rb_used)

#define CTDNSNPRB_NODE_IS_USED(node)          (CTDNSNPRB_NODE_USED == CTDNSNPRB_NODE_USED_FLAG(node))
#define CTDNSNPRB_NODE_IS_NOT_USED(node)      (CTDNSNPRB_NODE_NOT_USED == CTDNSNPRB_NODE_USED_FLAG(node))

#define CTDNSNPRB_NODE_IS_RED(node)           (CTDNSNPRB_RED == CTDNSNPRB_NODE_COLOR(node))
#define CTDNSNPRB_NODE_IS_BLACK(node)         (CTDNSNPRB_BLACK == CTDNSNPRB_NODE_COLOR(node))


typedef struct
{
    uint32_t          node_max_num; /*max node number in the pool*/
    uint32_t          node_used_num;/*used node number           */
    uint32_t          node_sizeof;  /*actual size of each node   */
    uint32_t          free_head;    /*unused CTDNSNPRB_TREE head   */
    uint32_t          root_pos;
    uint32_t          rsvd;
    CTDNSNPRB_NODE    rb_nodes[0];  /*rb_nodes table             */
}CTDNSNPRB_POOL;

#define CTDNSNPRB_POOL_ROOT_POS(pool)          ((pool)->root_pos)
#define CTDNSNPRB_POOL_FREE_HEAD(pool)         ((pool)->free_head)
#define CTDNSNPRB_POOL_NODE_MAX_NUM(pool)      ((pool)->node_max_num)
#define CTDNSNPRB_POOL_NODE_USED_NUM(pool)     ((pool)->node_used_num)
#define CTDNSNPRB_POOL_NODE_SIZEOF(pool)       ((pool)->node_sizeof)
#define CTDNSNPRB_POOL_NODE_TBL(pool)          ((pool)->rb_nodes)
#if 1
#define CTDNSNPRB_POOL_NODE(pool, this_pos)    \
    (CTDNSNPRB_POOL_NODE_MAX_NUM(pool) > (this_pos) ? ((CTDNSNPRB_NODE *)((void *)((pool)->rb_nodes) + (this_pos) * (CTDNSNPRB_POOL_NODE_SIZEOF(pool)))) : NULL_PTR)
#endif
#if 0
extern CTDNSNPRB_NODE *__ctdnsnprb_node(CTDNSNPRB_POOL *pool, const uint32_t node_pos);

#define CTDNSNPRB_POOL_NODE(pool, this_pos)  __ctdnsnprb_node(pool, this_pos)
#endif
/*new a CTDNSNPRB_NODE and return its position*/
uint32_t ctdnsnprb_node_new(CTDNSNPRB_POOL *pool);

/*free a CTDNSNPRB_NODE and return its position to the pool*/
void ctdnsnprb_node_free(CTDNSNPRB_POOL *pool, const uint32_t node_pos);

void ctdnsnprb_node_init(CTDNSNPRB_POOL *pool, const uint32_t node_pos);

void ctdnsnprb_node_clean(CTDNSNPRB_POOL *pool, const uint32_t node_pos);

void ctdnsnprb_node_set_next(CTDNSNPRB_POOL *pool, const uint32_t node_pos, const uint32_t next_pos);

EC_BOOL ctdnsnprb_node_is_used(const CTDNSNPRB_POOL *pool, const uint32_t node_pos);

void ctdnsnprb_node_print(LOG *log, const CTDNSNPRB_POOL *pool, const uint32_t node_pos);

void ctdnsnprb_node_print_level(LOG *log, const CTDNSNPRB_POOL *pool, const uint32_t node_pos, const uint32_t level);

/*free one rbtree represented by root = root_pos*/
void ctdnsnprb_tree_free(CTDNSNPRB_POOL *pool, const uint32_t root_pos);

/*init the whole rbtrees pool*/
EC_BOOL ctdnsnprb_pool_init(CTDNSNPRB_POOL *pool, const uint32_t node_max_num, const uint32_t node_sizeof);

/*clean the whole rbtrees pool*/
void ctdnsnprb_pool_clean(CTDNSNPRB_POOL *pool);

/*print the whole rbtrees pool*/
void ctdnsnprb_pool_print(LOG *log, const CTDNSNPRB_POOL *pool);

EC_BOOL ctdnsnprb_pool_is_empty(const CTDNSNPRB_POOL *pool);

EC_BOOL ctdnsnprb_pool_is_full(const CTDNSNPRB_POOL *pool);

/*visit the root node first: root -> left -> right*/
void ctdnsnprb_preorder_print(LOG *log, const CTDNSNPRB_POOL *pool, const uint32_t node_pos);

/*visit the left subtree, then the root node: left -> root -> right*/
void ctdnsnprb_inorder_print(LOG *log, const CTDNSNPRB_POOL *pool, const uint32_t node_pos);

/*visit the root node last: left -> right -> root*/
void ctdnsnprb_postorder_print(LOG *log, const CTDNSNPRB_POOL *pool, const uint32_t node_pos);

/*visit the root node first: root -> left -> right*/
void ctdnsnprb_preorder_print_level(LOG *log, const CTDNSNPRB_POOL *pool, const uint32_t node_pos, const uint32_t level);

void ctdnsnprb_tree_print(LOG *log, const CTDNSNPRB_POOL *pool, const uint32_t root_pos);

uint32_t ctdnsnprb_tree_count_node_num(const CTDNSNPRB_POOL *pool, const uint32_t root_pos);

uint32_t ctdnsnprb_tree_node_max_num(const CTDNSNPRB_POOL *pool);

uint32_t ctdnsnprb_tree_node_used_num(const CTDNSNPRB_POOL *pool);

uint32_t ctdnsnprb_tree_node_sizeof(const CTDNSNPRB_POOL *pool);

/* Find logical next and previous nodes in a tree */
uint32_t ctdnsnprb_tree_first_node(const CTDNSNPRB_POOL *pool, const uint32_t root_pos);
uint32_t ctdnsnprb_tree_last_node(const CTDNSNPRB_POOL *pool, const uint32_t root_pos);
uint32_t ctdnsnprb_tree_next_node(const CTDNSNPRB_POOL *pool, const uint32_t node_pos);
uint32_t ctdnsnprb_tree_prev_node(const CTDNSNPRB_POOL *pool, const uint32_t node_pos);

/* Fast replacement of a single node without remove/rebalance/add/rebalance */
void ctdnsnprb_tree_replace_node(CTDNSNPRB_POOL *pool, const uint32_t victim_pos, const uint32_t new_pos, uint32_t *root_pos);

uint32_t ctdnsnprb_tree_search_data(const CTDNSNPRB_POOL *pool, const uint32_t root_pos, const UINT32 tcid);

EC_BOOL ctdnsnprb_tree_insert_data(CTDNSNPRB_POOL *pool, uint32_t *root_pos, const UINT32 tcid, uint32_t *insert_pos);

EC_BOOL ctdnsnprb_tree_delete_data(CTDNSNPRB_POOL *pool, uint32_t *root_pos, const UINT32 tcid, uint32_t *delete_pos);

EC_BOOL ctdnsnprb_tree_delete(CTDNSNPRB_POOL *pool, uint32_t *root_pos, const uint32_t node_pos);

EC_BOOL ctdnsnprb_tree_erase(CTDNSNPRB_POOL *pool, const uint32_t node_pos, uint32_t *root_pos);

EC_BOOL ctdnsnprb_flush_size(const CTDNSNPRB_POOL *pool, UINT32 *size);

EC_BOOL ctdnsnprb_flush(const CTDNSNPRB_POOL *pool, int fd, UINT32 *offset);

EC_BOOL ctdnsnprb_load(CTDNSNPRB_POOL *pool, int fd, UINT32 *offset);

/* ---- debug ---- */
EC_BOOL ctdnsnprb_node_debug_cmp(const CTDNSNPRB_NODE *node_1st, const CTDNSNPRB_NODE *node_2nd, int (*node_cmp_data)(const CTDNSNPRB_NODE *, const CTDNSNPRB_NODE *));
EC_BOOL ctdnsnprb_debug_cmp(const CTDNSNPRB_POOL *pool_1st, const CTDNSNPRB_POOL *pool_2nd, int (*node_cmp_data)(const CTDNSNPRB_NODE *, const CTDNSNPRB_NODE *));

#endif    /* _CTDNSNPRB_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/
