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

#ifndef    _CHFSNPRB_H
#define    _CHFSNPRB_H

#include "type.h"

#define CHFSNPRB_RED            ((uint32_t)0)
#define CHFSNPRB_BLACK          ((uint32_t)1)

#define CHFSNPRB_NODE_NOT_USED  ((uint32_t)0)
#define CHFSNPRB_NODE_USED      ((uint32_t)1)

#define CHFSNPRB_ERR_POS        ((uint32_t)0x7FFFFFFF)/*31 bits*/

#define CHFSNPRB_POOL_MAX_SIZE  ((uint32_t)(1 << 25))/* < 2^25, about 32,000,000*/

typedef struct
{
    uint32_t rb_parent_pos:31;
    uint32_t rb_used      : 1; /*CHFSNPRB_USED or CHFSNPRB_NOT_USED*/
        
    uint32_t rb_right_pos :31;
    uint32_t rsvd1       : 1;

    uint32_t rb_left_pos  :31;
    uint32_t rb_color     : 1; /*CHFSNPRB_RED or CHFSNPRB_BLACK*/

    union
    {
        uint32_t rb_next_pos  :31; /*save next position*/
        uint32_t rb_hash_data;          /*saved data*/
    }u;
}CHFSNPRB_NODE; /*16B*/

#define CHFSNPRB_NODE_PARENT_POS(node)       ((node)->rb_parent_pos)
#define CHFSNPRB_NODE_RIGHT_POS(node)        ((node)->rb_right_pos)
#define CHFSNPRB_NODE_LEFT_POS(node)         ((node)->rb_left_pos)
#define CHFSNPRB_NODE_NEXT_POS(node)         ((node)->u.rb_next_pos)
#define CHFSNPRB_NODE_DATA(node)             ((node)->u.rb_hash_data)
#define CHFSNPRB_NODE_COLOR(node)            ((node)->rb_color)
#define CHFSNPRB_NODE_USED_FLAG(node)        ((node)->rb_used)

#define CHFSNPRB_NODE_IS_USED(node)          (CHFSNPRB_NODE_USED == CHFSNPRB_NODE_USED_FLAG(node))
#define CHFSNPRB_NODE_IS_NOT_USED(node)      (CHFSNPRB_NODE_NOT_USED == CHFSNPRB_NODE_USED_FLAG(node))

#define CHFSNPRB_NODE_IS_RED(node)           (CHFSNPRB_RED == CHFSNPRB_NODE_COLOR(node))
#define CHFSNPRB_NODE_IS_BLACK(node)         (CHFSNPRB_BLACK == CHFSNPRB_NODE_COLOR(node))


typedef struct
{    
    uint32_t        node_max_num; /*max node number in the pool*/
    uint32_t        node_used_num;/*used node number           */
    uint32_t        node_sizeof;  /*actual size of each node   */
    uint32_t        free_head;    /*unused CHFSNPRB_TREE head  */
    CHFSNPRB_NODE   rb_nodes[0];  /*rb_nodes table             */
}CHFSNPRB_POOL;

#define CHFSNPRB_POOL_FREE_HEAD(pool)         ((pool)->free_head)
#define CHFSNPRB_POOL_NODE_MAX_NUM(pool)      ((pool)->node_max_num)
#define CHFSNPRB_POOL_NODE_USED_NUM(pool)     ((pool)->node_used_num)
#define CHFSNPRB_POOL_NODE_SIZEOF(pool)       ((pool)->node_sizeof)
#define CHFSNPRB_POOL_NODE_TBL(pool)          ((pool)->rb_nodes)
#define CHFSNPRB_POOL_NODE(pool, this_pos)    \
    (CHFSNPRB_POOL_NODE_MAX_NUM(pool) > (this_pos) ? ((CHFSNPRB_NODE *)((void *)((pool)->rb_nodes) + (this_pos) * (CHFSNPRB_POOL_NODE_SIZEOF(pool)))) : NULL_PTR)

/*new a CHFSNPRB_NODE and return its position*/
uint32_t chfsnprb_node_new(CHFSNPRB_POOL *pool);

/*free a CHFSNPRB_NODE and return its position to the pool*/
void chfsnprb_node_free(CHFSNPRB_POOL *pool, const uint32_t node_pos);

void chfsnprb_node_init(CHFSNPRB_POOL *pool, const uint32_t node_pos);

void chfsnprb_node_clean(CHFSNPRB_POOL *pool, const uint32_t node_pos);

void chfsnprb_node_set_next(CHFSNPRB_POOL *pool, const uint32_t node_pos, const uint32_t next_pos);

EC_BOOL chfsnprb_node_is_used(const CHFSNPRB_POOL *pool, const uint32_t node_pos);

void chfsnprb_node_print(LOG *log, const CHFSNPRB_POOL *pool, const uint32_t node_pos);

void chfsnprb_node_print_level(LOG *log, const CHFSNPRB_POOL *pool, const uint32_t node_pos, const uint32_t level);

/*free one rbtree represented by root = root_pos*/
void chfsnprb_tree_free(CHFSNPRB_POOL *pool, const uint32_t root_pos);

/*init the whole rbtrees pool*/
EC_BOOL chfsnprb_pool_init(CHFSNPRB_POOL *pool, const uint32_t node_max_num, const uint32_t node_sizeof);

/*clean the whole rbtrees pool*/
void chfsnprb_pool_clean(CHFSNPRB_POOL *pool);

/*print the whole rbtrees pool*/
void chfsnprb_pool_print(LOG *log, const CHFSNPRB_POOL *pool);

EC_BOOL chfsnprb_pool_is_empty(const CHFSNPRB_POOL *pool);

EC_BOOL chfsnprb_pool_is_full(const CHFSNPRB_POOL *pool);

/*visit the root node first: root -> left -> right*/
void chfsnprb_preorder_print(LOG *log, const CHFSNPRB_POOL *pool, const uint32_t node_pos);

/*visit the left subtree, then the root node: left -> root -> right*/
void chfsnprb_inorder_print(LOG *log, const CHFSNPRB_POOL *pool, const uint32_t node_pos);

/*visit the root node last: left -> right -> root*/
void chfsnprb_postorder_print(LOG *log, const CHFSNPRB_POOL *pool, const uint32_t node_pos);

/*visit the root node first: root -> left -> right*/
void chfsnprb_preorder_print_level(LOG *log, const CHFSNPRB_POOL *pool, const uint32_t node_pos, const uint32_t level);

void chfsnprb_tree_print(LOG *log, const CHFSNPRB_POOL *pool, const uint32_t root_pos);

EC_BOOL chfsnprb_tree_erase(CHFSNPRB_POOL *pool, const uint32_t node_pos, uint32_t *root_pos);

uint32_t chfsnprb_tree_count_node_num(const CHFSNPRB_POOL *pool, const uint32_t root_pos);

uint32_t chfsnprb_tree_node_max_num(const CHFSNPRB_POOL *pool);

uint32_t chfsnprb_tree_node_used_num(const CHFSNPRB_POOL *pool);

uint32_t chfsnprb_tree_node_sizeof(const CHFSNPRB_POOL *pool);

/* Find logical next and previous nodes in a tree */
uint32_t chfsnprb_tree_first_node(const CHFSNPRB_POOL *pool, const uint32_t root_pos);
uint32_t chfsnprb_tree_last_node(const CHFSNPRB_POOL *pool, const uint32_t root_pos);
uint32_t chfsnprb_tree_next_node(const CHFSNPRB_POOL *pool, const uint32_t node_pos);
uint32_t chfsnprb_tree_prev_node(const CHFSNPRB_POOL *pool, const uint32_t node_pos);

/* Fast replacement of a single node without remove/rebalance/add/rebalance */
void chfsnprb_tree_replace_node(CHFSNPRB_POOL *pool, const uint32_t victim_pos, const uint32_t new_pos, uint32_t *root_pos);

uint32_t chfsnprb_tree_search_data(const CHFSNPRB_POOL *pool, const uint32_t root_pos, const uint32_t data, const uint32_t klen, const uint8_t *key);

EC_BOOL chfsnprb_tree_insert_data(CHFSNPRB_POOL *pool, uint32_t *root_pos, const uint32_t data, const uint32_t klen, const uint8_t *key, uint32_t *insert_pos);

EC_BOOL chfsnprb_tree_delete_data(CHFSNPRB_POOL *pool, uint32_t *root_pos, const uint32_t data, const uint32_t klen, const uint8_t *key, uint32_t *delete_pos);

EC_BOOL chfsnprb_tree_delete(CHFSNPRB_POOL *pool, uint32_t *root_pos, const uint32_t node_pos);

EC_BOOL chfsnprb_flush_size(const CHFSNPRB_POOL *pool, UINT32 *size);

EC_BOOL chfsnprb_flush(const CHFSNPRB_POOL *pool, int fd, UINT32 *offset);

EC_BOOL chfsnprb_load(CHFSNPRB_POOL *pool, int fd, UINT32 *offset);

/* ---- debug ---- */
EC_BOOL chfsnprb_node_debug_cmp(const CHFSNPRB_NODE *node_1st, const CHFSNPRB_NODE *node_2nd, int (*node_cmp_data)(const CHFSNPRB_NODE *, const CHFSNPRB_NODE *));
EC_BOOL chfsnprb_debug_cmp(const CHFSNPRB_POOL *pool_1st, const CHFSNPRB_POOL *pool_2nd, int (*node_cmp_data)(const CHFSNPRB_NODE *, const CHFSNPRB_NODE *));

#endif    /* _CHFSNPRB_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/
