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

#ifndef    _CSFSNPRB_H
#define    _CSFSNPRB_H

#include "type.h"

#define CSFSNPRB_RED            ((uint32_t)0)
#define CSFSNPRB_BLACK          ((uint32_t)1)

#define CSFSNPRB_NODE_NOT_USED  ((uint32_t)0)
#define CSFSNPRB_NODE_USED      ((uint32_t)1)

#define CSFSNPRB_ERR_POS        ((uint32_t)0x7FFFFFFF)/*31 bits*/

#define CSFSNPRB_POOL_MAX_SIZE  ((uint32_t)(1 << 25))/* < 2^25, about 32,000,000*/

typedef struct
{
    uint32_t rb_parent_pos:31;
    uint32_t rb_used      : 1; /*CSFSNPRB_USED or CSFSNPRB_NOT_USED*/
        
    uint32_t rb_right_pos :31;
    uint32_t rsvd1       : 1;

    uint32_t rb_left_pos  :31;
    uint32_t rb_color     : 1; /*CSFSNPRB_RED or CSFSNPRB_BLACK*/

    union
    {
        uint32_t rb_next_pos  :31; /*save next position*/
        uint32_t rb_hash_data;          /*saved data*/
    }u;
}CSFSNPRB_NODE; /*16B*/

#define CSFSNPRB_NODE_PARENT_POS(node)       ((node)->rb_parent_pos)
#define CSFSNPRB_NODE_RIGHT_POS(node)        ((node)->rb_right_pos)
#define CSFSNPRB_NODE_LEFT_POS(node)         ((node)->rb_left_pos)
#define CSFSNPRB_NODE_NEXT_POS(node)         ((node)->u.rb_next_pos)
#define CSFSNPRB_NODE_DATA(node)             ((node)->u.rb_hash_data)
#define CSFSNPRB_NODE_COLOR(node)            ((node)->rb_color)
#define CSFSNPRB_NODE_USED_FLAG(node)        ((node)->rb_used)

#define CSFSNPRB_NODE_IS_USED(node)          (CSFSNPRB_NODE_USED == CSFSNPRB_NODE_USED_FLAG(node))
#define CSFSNPRB_NODE_IS_NOT_USED(node)      (CSFSNPRB_NODE_NOT_USED == CSFSNPRB_NODE_USED_FLAG(node))

#define CSFSNPRB_NODE_IS_RED(node)           (CSFSNPRB_RED == CSFSNPRB_NODE_COLOR(node))
#define CSFSNPRB_NODE_IS_BLACK(node)         (CSFSNPRB_BLACK == CSFSNPRB_NODE_COLOR(node))


typedef struct
{    
    uint32_t        node_max_num; /*max node number in the pool*/
    uint32_t        node_used_num;/*used node number           */
    uint32_t        node_sizeof;  /*actual size of each node   */
    uint32_t        free_head;    /*unused CSFSNPRB_TREE head  */
    CSFSNPRB_NODE   rb_nodes[0];  /*rb_nodes table             */
}CSFSNPRB_POOL;

#define CSFSNPRB_POOL_FREE_HEAD(pool)         ((pool)->free_head)
#define CSFSNPRB_POOL_NODE_MAX_NUM(pool)      ((pool)->node_max_num)
#define CSFSNPRB_POOL_NODE_USED_NUM(pool)     ((pool)->node_used_num)
#define CSFSNPRB_POOL_NODE_SIZEOF(pool)       ((pool)->node_sizeof)
#define CSFSNPRB_POOL_NODE_TBL(pool)          ((pool)->rb_nodes)
#define CSFSNPRB_POOL_NODE(pool, this_pos)    \
    (CSFSNPRB_POOL_NODE_MAX_NUM(pool) > (this_pos) ? ((CSFSNPRB_NODE *)((void *)((pool)->rb_nodes) + (this_pos) * (CSFSNPRB_POOL_NODE_SIZEOF(pool)))) : NULL_PTR)

/*new a CSFSNPRB_NODE and return its position*/
uint32_t csfsnprb_node_new(CSFSNPRB_POOL *pool);

/*free a CSFSNPRB_NODE and return its position to the pool*/
void csfsnprb_node_free(CSFSNPRB_POOL *pool, const uint32_t node_pos);

void csfsnprb_node_init(CSFSNPRB_POOL *pool, const uint32_t node_pos);

void csfsnprb_node_clean(CSFSNPRB_POOL *pool, const uint32_t node_pos);

void csfsnprb_node_set_next(CSFSNPRB_POOL *pool, const uint32_t node_pos, const uint32_t next_pos);

EC_BOOL csfsnprb_node_is_used(const CSFSNPRB_POOL *pool, const uint32_t node_pos);

void csfsnprb_node_print(LOG *log, const CSFSNPRB_POOL *pool, const uint32_t node_pos);

void csfsnprb_node_print_level(LOG *log, const CSFSNPRB_POOL *pool, const uint32_t node_pos, const uint32_t level);

/*free one rbtree represented by root = root_pos*/
void csfsnprb_tree_free(CSFSNPRB_POOL *pool, const uint32_t root_pos);

/*init the whole rbtrees pool*/
EC_BOOL csfsnprb_pool_init(CSFSNPRB_POOL *pool, const uint32_t node_max_num, const uint32_t node_sizeof);

/*clean the whole rbtrees pool*/
void csfsnprb_pool_clean(CSFSNPRB_POOL *pool);

/*print the whole rbtrees pool*/
void csfsnprb_pool_print(LOG *log, const CSFSNPRB_POOL *pool);

EC_BOOL csfsnprb_pool_is_empty(const CSFSNPRB_POOL *pool);

EC_BOOL csfsnprb_pool_is_full(const CSFSNPRB_POOL *pool);

/*visit the root node first: root -> left -> right*/
void csfsnprb_preorder_print(LOG *log, const CSFSNPRB_POOL *pool, const uint32_t node_pos);

/*visit the left subtree, then the root node: left -> root -> right*/
void csfsnprb_inorder_print(LOG *log, const CSFSNPRB_POOL *pool, const uint32_t node_pos);

/*visit the root node last: left -> right -> root*/
void csfsnprb_postorder_print(LOG *log, const CSFSNPRB_POOL *pool, const uint32_t node_pos);

/*visit the root node first: root -> left -> right*/
void csfsnprb_preorder_print_level(LOG *log, const CSFSNPRB_POOL *pool, const uint32_t node_pos, const uint32_t level);

void csfsnprb_tree_print(LOG *log, const CSFSNPRB_POOL *pool, const uint32_t root_pos);

EC_BOOL csfsnprb_tree_erase(CSFSNPRB_POOL *pool, const uint32_t node_pos, uint32_t *root_pos);

uint32_t csfsnprb_tree_count_node_num(const CSFSNPRB_POOL *pool, const uint32_t root_pos);

uint32_t csfsnprb_tree_node_max_num(const CSFSNPRB_POOL *pool);

uint32_t csfsnprb_tree_node_used_num(const CSFSNPRB_POOL *pool);

uint32_t csfsnprb_tree_node_sizeof(const CSFSNPRB_POOL *pool);

/* Find logical next and previous nodes in a tree */
uint32_t csfsnprb_tree_first_node(const CSFSNPRB_POOL *pool, const uint32_t root_pos);
uint32_t csfsnprb_tree_last_node(const CSFSNPRB_POOL *pool, const uint32_t root_pos);
uint32_t csfsnprb_tree_next_node(const CSFSNPRB_POOL *pool, const uint32_t node_pos);
uint32_t csfsnprb_tree_prev_node(const CSFSNPRB_POOL *pool, const uint32_t node_pos);

/* Fast replacement of a single node without remove/rebalance/add/rebalance */
void csfsnprb_tree_replace_node(CSFSNPRB_POOL *pool, const uint32_t victim_pos, const uint32_t new_pos, uint32_t *root_pos);

uint32_t csfsnprb_tree_search_data(const CSFSNPRB_POOL *pool, const uint32_t root_pos, const uint32_t data, const uint32_t klen, const uint8_t *key);

EC_BOOL csfsnprb_tree_insert_data(CSFSNPRB_POOL *pool, uint32_t *root_pos, const uint32_t data, const uint32_t klen, const uint8_t *key, uint32_t *insert_pos);

EC_BOOL csfsnprb_tree_delete_data(CSFSNPRB_POOL *pool, uint32_t *root_pos, const uint32_t data, const uint32_t klen, const uint8_t *key, uint32_t *delete_pos);

EC_BOOL csfsnprb_tree_delete(CSFSNPRB_POOL *pool, uint32_t *root_pos, const uint32_t node_pos);

EC_BOOL csfsnprb_flush_size(const CSFSNPRB_POOL *pool, UINT32 *size);

EC_BOOL csfsnprb_flush(const CSFSNPRB_POOL *pool, int fd, UINT32 *offset);

EC_BOOL csfsnprb_load(CSFSNPRB_POOL *pool, int fd, UINT32 *offset);

/* ---- debug ---- */
EC_BOOL csfsnprb_node_debug_cmp(const CSFSNPRB_NODE *node_1st, const CSFSNPRB_NODE *node_2nd, int (*node_cmp_data)(const CSFSNPRB_NODE *, const CSFSNPRB_NODE *));
EC_BOOL csfsnprb_debug_cmp(const CSFSNPRB_POOL *pool_1st, const CSFSNPRB_POOL *pool_2nd, int (*node_cmp_data)(const CSFSNPRB_NODE *, const CSFSNPRB_NODE *));

#endif    /* _CSFSNPRB_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/
