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

#ifndef    _CPGRB_H
#define    _CPGRB_H

#include "type.h"

#define CPGRB_RED            ((uint16_t)0)
#define CPGRB_BLACK          ((uint16_t)1)

#define CPGRB_NODE_NOT_USED  ((uint16_t)0)
#define CPGRB_NODE_USED      ((uint16_t)1)

#define CPGRB_ERR_POS        ((uint16_t)0x7FFF)/*15 bits*/

#define CPGRB_POOL_MAX_SIZE  ((uint16_t)0x4000)/* < 2^14( 1TB = 2^14 64M-block, 64M = 2^14 4K-page = 2^13 8K-page)*/

typedef struct
{
    uint16_t rb_parent_pos:15;
    uint16_t rb_used      : 1; /*CPGRB_USED or CPGRB_NOT_USED*/

    uint16_t rb_right_pos :15;
    uint16_t rsvd1       : 1;

    uint16_t rb_left_pos  :15;
    uint16_t rsvd2        : 1;

    uint16_t rb_data      :15; /*save position data or next position*/
    uint16_t rb_color     : 1; /*CPGRB_RED or CPGRB_BLACK*/

}CPGRB_NODE; /*8B or 64b*/

#define rb_next_pos       rb_data

#define CPGRB_NODE_PARENT_POS(node)       ((node)->rb_parent_pos)
#define CPGRB_NODE_RIGHT_POS(node)        ((node)->rb_right_pos)
#define CPGRB_NODE_LEFT_POS(node)         ((node)->rb_left_pos)
#define CPGRB_NODE_NEXT_POS(node)         ((node)->rb_next_pos)
#define CPGRB_NODE_DATA(node)             ((node)->rb_data)
#define CPGRB_NODE_COLOR(node)            ((node)->rb_color)
#define CPGRB_NODE_USED_FLAG(node)        ((node)->rb_used)

#define CPGRB_NODE_IS_USED(node)          (CPGRB_NODE_USED == CPGRB_NODE_USED_FLAG(node))
#define CPGRB_NODE_IS_NOT_USED(node)      (CPGRB_NODE_NOT_USED == CPGRB_NODE_USED_FLAG(node))

#define CPGRB_NODE_IS_RED(node)           (CPGRB_RED == CPGRB_NODE_COLOR(node))
#define CPGRB_NODE_IS_BLACK(node)         (CPGRB_BLACK == CPGRB_NODE_COLOR(node))


typedef struct
{
    uint32_t    rsvd2;
    uint16_t    free_head;/*unused CPGRB_TREE head*/
    uint16_t    node_num;
    CPGRB_NODE  rb_node[ 0 ];  /*128KB,rb_nodes table*/
}CPGRB_POOL;

#define CPGRB_POOL_FREE_HEAD(pool)         ((pool)->free_head)
#define CPGRB_POOL_NODE_NUM(pool)          ((pool)->node_num)
#define CPGRB_POOL_NODE_TBL(pool)          ((pool)->rb_node)
#define CPGRB_POOL_NODE(pool, this_pos)    (CPGRB_POOL_NODE_NUM(pool) > (this_pos) ? ((pool)->rb_node + (this_pos)) : NULL_PTR)

/*search data in one rbtree represented by root = root_pos*/
uint16_t cpgrb_tree_search_data(CPGRB_POOL *pool, const uint16_t root_pos, uint16_t data);

/*insert data into one rbtree represented by root = root_pos*/
uint16_t cpgrb_tree_insert_data(CPGRB_POOL *pool, uint16_t *root_pos, const uint16_t data);

/*delete data from one rbtree represented by root = root_pos*/
EC_BOOL  cpgrb_tree_delete_data(CPGRB_POOL *pool, uint16_t *root_pos, const uint16_t data);

/*free one rbtree represented by root = root_pos*/
void cpgrb_tree_free(CPGRB_POOL *pool, const uint16_t root_pos);

/*init the whole rbtrees pool*/
EC_BOOL cpgrb_pool_init(CPGRB_POOL *pool, const uint16_t node_num);

/*clean the whole rbtrees pool*/
void cpgrb_pool_clean(CPGRB_POOL *pool);

/*clear without any space mallocation!*/
void cpgrb_pool_clear(CPGRB_POOL *pool);

/*print the whole rbtrees pool*/
void cpgrb_pool_print(LOG *log, const CPGRB_POOL *pool);

/*visit the root node first: root -> left -> right*/
void cpgrb_preorder_print(LOG *log, const CPGRB_POOL *pool, const uint16_t node_pos);

/*visit the left subtree, then the root node: left -> root -> right*/
void cpgrb_inorder_print(LOG *log, const CPGRB_POOL *pool, const uint16_t node_pos);

/*visit the root node last: left -> right -> root*/
void cpgrb_postorder_print(LOG *log, const CPGRB_POOL *pool, const uint16_t node_pos);

/*visit the root node first: root -> left -> right*/
void cpgrb_preorder_print_level(LOG *log, const CPGRB_POOL *pool, const uint16_t node_pos, const uint16_t level);

void cpgrb_tree_print(LOG *log, const CPGRB_POOL *pool, const uint16_t root_pos);

EC_BOOL cpgrb_tree_is_empty(const CPGRB_POOL *pool, const uint16_t root_pos);

uint16_t cpgrb_tree_node_num(const CPGRB_POOL *pool, const uint16_t root_pos);

/* Find logical next and previous nodes in a tree */
uint16_t cpgrb_tree_first_node(const CPGRB_POOL *pool, const uint16_t root_pos);
uint16_t cpgrb_tree_last_node(const CPGRB_POOL *pool, const uint16_t root_pos);
uint16_t cpgrb_tree_next_node(const CPGRB_POOL *pool, const uint16_t node_pos);
uint16_t cpgrb_tree_prev_node(const CPGRB_POOL *pool, const uint16_t node_pos);

/* Fast replacement of a single node without remove/rebalance/add/rebalance */
void cpgrb_tree_replace_node(CPGRB_POOL *pool, const uint16_t victim_pos, const uint16_t new_pos, uint16_t *root_pos);

EC_BOOL cpgrb_flush_size(const CPGRB_POOL *pool, UINT32 *size);

EC_BOOL cpgrb_flush(const CPGRB_POOL *pool, int fd, UINT32 *offset);

EC_BOOL cpgrb_load(CPGRB_POOL *pool, int fd, UINT32 *offset);

/* ---- debug ---- */
EC_BOOL cpgrb_node_debug_cmp(const CPGRB_NODE *node_1st, const CPGRB_NODE *node_2nd);
EC_BOOL cpgrb_debug_cmp(const CPGRB_POOL *pool_1st, const CPGRB_POOL *pool_2nd);

#endif    /* _CPGRB_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/
