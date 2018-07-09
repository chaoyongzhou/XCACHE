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

#ifndef    _CRFSNPRB_H
#define    _CRFSNPRB_H

#include "type.h"

#define CRFSNPRB_RED            ((uint32_t)0)
#define CRFSNPRB_BLACK          ((uint32_t)1)

#define CRFSNPRB_NODE_NOT_USED  ((uint32_t)0)
#define CRFSNPRB_NODE_USED      ((uint32_t)1)

#define CRFSNPRB_ROOT_POS       ((uint32_t)0)/*31 bits*/
#define CRFSNPRB_ERR_POS        ((uint32_t)0x7FFFFFFF)/*31 bits*/

#define CRFSNPRB_POOL_MAX_SIZE  ((uint32_t)(1 << 24))/* < 2^24, about 16,000,000*/

typedef struct
{
    uint32_t rb_parent_pos:31; /*value range: [0, 0x7FFFFFFF)*/
    uint32_t rb_used      : 1; /*CRFSNPRB_USED or CRFSNPRB_NOT_USED*/

    uint32_t rb_right_pos :31; /*value range: [0, 0x7FFFFFFF)*/
    uint32_t rsvd1        : 1;

    uint32_t rb_left_pos  :31; /*value range: [0, 0x7FFFFFFF)*/
    uint32_t rb_color     : 1; /*CRFSNPRB_RED or CRFSNPRB_BLACK*/

    union
    {
        uint32_t rb_next_pos  :31; /*save next position*/
        uint32_t rb_hash_data;     /*saved data*/
    }u;
}CRFSNPRB_NODE; /*16B*/

#define CRFSNPRB_NODE_PARENT_POS(node)       ((node)->rb_parent_pos)
#define CRFSNPRB_NODE_RIGHT_POS(node)        ((node)->rb_right_pos)
#define CRFSNPRB_NODE_LEFT_POS(node)         ((node)->rb_left_pos)
#define CRFSNPRB_NODE_NEXT_POS(node)         ((node)->u.rb_next_pos)
#define CRFSNPRB_NODE_DATA(node)             ((node)->u.rb_hash_data)
#define CRFSNPRB_NODE_COLOR(node)            ((node)->rb_color)
#define CRFSNPRB_NODE_USED_FLAG(node)        ((node)->rb_used)

#define CRFSNPRB_NODE_IS_USED(node)          (CRFSNPRB_NODE_USED == CRFSNPRB_NODE_USED_FLAG(node))
#define CRFSNPRB_NODE_IS_NOT_USED(node)      (CRFSNPRB_NODE_NOT_USED == CRFSNPRB_NODE_USED_FLAG(node))

#define CRFSNPRB_NODE_IS_RED(node)           (CRFSNPRB_RED == CRFSNPRB_NODE_COLOR(node))
#define CRFSNPRB_NODE_IS_BLACK(node)         (CRFSNPRB_BLACK == CRFSNPRB_NODE_COLOR(node))


typedef struct
{
    /*16B*/
    uint32_t        node_max_num; /*max node number in the pool*/
    uint32_t        node_used_num;/*used node number           */
    uint32_t        node_sizeof;  /*actual size of each node   */
    uint32_t        free_head;    /*unused CRFSNPRB_TREE head  */
    
    CRFSNPRB_NODE   rb_nodes[0];  /*rb_nodes table             */
}CRFSNPRB_POOL;

#define CRFSNPRB_POOL_FREE_HEAD(pool)         ((pool)->free_head)
#define CRFSNPRB_POOL_NODE_MAX_NUM(pool)      ((pool)->node_max_num)
#define CRFSNPRB_POOL_NODE_USED_NUM(pool)     ((pool)->node_used_num)
#define CRFSNPRB_POOL_NODE_SIZEOF(pool)       ((pool)->node_sizeof)
#define CRFSNPRB_POOL_NODE_TBL(pool)          ((pool)->rb_nodes)
#if 1
#define CRFSNPRB_POOL_NODE(pool, this_pos)    \
    (CRFSNPRB_POOL_NODE_MAX_NUM(pool) > (this_pos) ? ((CRFSNPRB_NODE *)((void *)((pool)->rb_nodes) + (this_pos) * (CRFSNPRB_POOL_NODE_SIZEOF(pool)))) : NULL_PTR)
#endif
#if 0
extern CRFSNPRB_NODE *__crfsnprb_node(CRFSNPRB_POOL *pool, const uint32_t node_pos);

#define CRFSNPRB_POOL_NODE(pool, this_pos)  __crfsnprb_node(pool, this_pos)
#endif
/*new a CRFSNPRB_NODE and return its position*/
uint32_t crfsnprb_node_new(CRFSNPRB_POOL *pool);

/*free a CRFSNPRB_NODE and return its position to the pool*/
void crfsnprb_node_free(CRFSNPRB_POOL *pool, const uint32_t node_pos);

void crfsnprb_node_init(CRFSNPRB_POOL *pool, const uint32_t node_pos);

void crfsnprb_node_clean(CRFSNPRB_POOL *pool, const uint32_t node_pos);

void crfsnprb_node_set_next(CRFSNPRB_POOL *pool, const uint32_t node_pos, const uint32_t next_pos);

EC_BOOL crfsnprb_node_is_used(const CRFSNPRB_POOL *pool, const uint32_t node_pos);

void crfsnprb_node_print(LOG *log, const CRFSNPRB_POOL *pool, const uint32_t node_pos);

void crfsnprb_node_print_level(LOG *log, const CRFSNPRB_POOL *pool, const uint32_t node_pos, const uint32_t level);

/*free one rbtree represented by root = root_pos*/
void crfsnprb_tree_free(CRFSNPRB_POOL *pool, const uint32_t root_pos);

/*init the whole rbtrees pool*/
EC_BOOL crfsnprb_pool_init(CRFSNPRB_POOL *pool, const uint32_t node_max_num, const uint32_t node_sizeof);

/*clean the whole rbtrees pool*/
void crfsnprb_pool_clean(CRFSNPRB_POOL *pool);

/*print the whole rbtrees pool*/
void crfsnprb_pool_print(LOG *log, const CRFSNPRB_POOL *pool);

EC_BOOL crfsnprb_pool_is_empty(const CRFSNPRB_POOL *pool);

EC_BOOL crfsnprb_pool_is_full(const CRFSNPRB_POOL *pool);

/*visit the root node first: root -> left -> right*/
void crfsnprb_preorder_print(LOG *log, const CRFSNPRB_POOL *pool, const uint32_t node_pos);

/*visit the left subtree, then the root node: left -> root -> right*/
void crfsnprb_inorder_print(LOG *log, const CRFSNPRB_POOL *pool, const uint32_t node_pos);

/*visit the root node last: left -> right -> root*/
void crfsnprb_postorder_print(LOG *log, const CRFSNPRB_POOL *pool, const uint32_t node_pos);

/*visit the root node first: root -> left -> right*/
void crfsnprb_preorder_print_level(LOG *log, const CRFSNPRB_POOL *pool, const uint32_t node_pos, const uint32_t level);

void crfsnprb_tree_print(LOG *log, const CRFSNPRB_POOL *pool, const uint32_t root_pos);

uint32_t crfsnprb_tree_count_node_num(const CRFSNPRB_POOL *pool, const uint32_t root_pos);

uint32_t crfsnprb_tree_node_max_num(const CRFSNPRB_POOL *pool);

uint32_t crfsnprb_tree_node_used_num(const CRFSNPRB_POOL *pool);

uint32_t crfsnprb_tree_node_sizeof(const CRFSNPRB_POOL *pool);

/* Find logical next and previous nodes in a tree */
uint32_t crfsnprb_tree_first_node(const CRFSNPRB_POOL *pool, const uint32_t root_pos);
uint32_t crfsnprb_tree_last_node(const CRFSNPRB_POOL *pool, const uint32_t root_pos);
uint32_t crfsnprb_tree_next_node(const CRFSNPRB_POOL *pool, const uint32_t node_pos);
uint32_t crfsnprb_tree_prev_node(const CRFSNPRB_POOL *pool, const uint32_t node_pos);

/* Fast replacement of a single node without remove/rebalance/add/rebalance */
void crfsnprb_tree_replace_node(CRFSNPRB_POOL *pool, const uint32_t victim_pos, const uint32_t new_pos, uint32_t *root_pos);

uint32_t crfsnprb_tree_search_data(const CRFSNPRB_POOL *pool, const uint32_t root_pos, const uint32_t data, const uint32_t klen, const uint8_t *key);

EC_BOOL crfsnprb_tree_insert_data(CRFSNPRB_POOL *pool, uint32_t *root_pos, const uint32_t data, const uint32_t klen, const uint8_t *key, uint32_t *insert_pos);

EC_BOOL crfsnprb_tree_delete_data(CRFSNPRB_POOL *pool, uint32_t *root_pos, const uint32_t data, const uint32_t klen, const uint8_t *key, uint32_t *delete_pos);

EC_BOOL crfsnprb_tree_delete(CRFSNPRB_POOL *pool, uint32_t *root_pos, const uint32_t node_pos);

EC_BOOL crfsnprb_tree_erase(CRFSNPRB_POOL *pool, const uint32_t node_pos, uint32_t *root_pos);

EC_BOOL crfsnprb_flush_size(const CRFSNPRB_POOL *pool, UINT32 *size);

EC_BOOL crfsnprb_flush(const CRFSNPRB_POOL *pool, int fd, UINT32 *offset);

EC_BOOL crfsnprb_load(CRFSNPRB_POOL *pool, int fd, UINT32 *offset);

/* ---- debug ---- */
EC_BOOL crfsnprb_node_debug_cmp(const CRFSNPRB_NODE *node_1st, const CRFSNPRB_NODE *node_2nd, int (*node_cmp_data)(const CRFSNPRB_NODE *, const CRFSNPRB_NODE *));
EC_BOOL crfsnprb_debug_cmp(const CRFSNPRB_POOL *pool_1st, const CRFSNPRB_POOL *pool_2nd, int (*node_cmp_data)(const CRFSNPRB_NODE *, const CRFSNPRB_NODE *));

#endif    /* _CRFSNPRB_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/
