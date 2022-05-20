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

#ifndef    _CXFSNPRB_H
#define    _CXFSNPRB_H

#include "type.h"

#define CXFSNPRB_RED            ((uint32_t)0)
#define CXFSNPRB_BLACK          ((uint32_t)1)

#define CXFSNPRB_NODE_NOT_USED  ((uint32_t)0)
#define CXFSNPRB_NODE_USED      ((uint32_t)1)

#define CXFSNPRB_ROOT_POS       ((uint32_t)0)/*31 bits*/
#define CXFSNPRB_ERR_POS        ((uint32_t)0x7FFFFFFF)/*31 bits*/

#define CXFSNPRB_POOL_MAX_SIZE  ((uint32_t)(1 << 25))/* < 2^25, about 32,000,000*/

typedef struct
{
    uint32_t rb_parent_pos:31; /*value range: [0, 0x7FFFFFFF)*/
    uint32_t rb_used      : 1; /*CXFSNPRB_USED or CXFSNPRB_NOT_USED*/

    uint32_t rb_right_pos :31; /*value range: [0, 0x7FFFFFFF)*/
    uint32_t rsvd1        : 1;

    uint32_t rb_left_pos  :31; /*value range: [0, 0x7FFFFFFF)*/
    uint32_t rb_color     : 1; /*CXFSNPRB_RED or CXFSNPRB_BLACK*/

    union
    {
        uint32_t rb_next_pos  :31; /*save next position*/
        uint32_t rb_hash_data;     /*saved data*/
    }u;
}CXFSNPRB_NODE; /*16B*/

#define CXFSNPRB_NODE_PARENT_POS(node)       ((node)->rb_parent_pos)
#define CXFSNPRB_NODE_RIGHT_POS(node)        ((node)->rb_right_pos)
#define CXFSNPRB_NODE_LEFT_POS(node)         ((node)->rb_left_pos)
#define CXFSNPRB_NODE_NEXT_POS(node)         ((node)->u.rb_next_pos)
#define CXFSNPRB_NODE_DATA(node)             ((node)->u.rb_hash_data)
#define CXFSNPRB_NODE_COLOR(node)            ((node)->rb_color)
#define CXFSNPRB_NODE_USED_FLAG(node)        ((node)->rb_used)

#define CXFSNPRB_NODE_IS_USED(node)          (CXFSNPRB_NODE_USED == CXFSNPRB_NODE_USED_FLAG(node))
#define CXFSNPRB_NODE_IS_NOT_USED(node)      (CXFSNPRB_NODE_NOT_USED == CXFSNPRB_NODE_USED_FLAG(node))

#define CXFSNPRB_NODE_IS_RED(node)           (CXFSNPRB_RED == CXFSNPRB_NODE_COLOR(node))
#define CXFSNPRB_NODE_IS_BLACK(node)         (CXFSNPRB_BLACK == CXFSNPRB_NODE_COLOR(node))


typedef struct
{
    /*16B*/
    uint32_t        node_max_num; /*max node number in the pool*/
    uint32_t        node_used_num;/*used node number           */
    uint32_t        node_sizeof;  /*actual size of each node   */
    uint32_t        free_head;    /*unused CXFSNPRB_TREE head  */

    CXFSNPRB_NODE   rb_nodes[0];  /*rb_nodes table             */
}CXFSNPRB_POOL;

#define CXFSNPRB_POOL_FREE_HEAD(pool)         ((pool)->free_head)
#define CXFSNPRB_POOL_NODE_MAX_NUM(pool)      ((pool)->node_max_num)
#define CXFSNPRB_POOL_NODE_USED_NUM(pool)     ((pool)->node_used_num)
#define CXFSNPRB_POOL_NODE_SIZEOF(pool)       ((pool)->node_sizeof)
#define CXFSNPRB_POOL_NODE_TBL(pool)          ((pool)->rb_nodes)
#if 1
#define CXFSNPRB_POOL_NODE(pool, this_pos)    \
    (CXFSNPRB_POOL_NODE_MAX_NUM(pool) > (this_pos) ? ((CXFSNPRB_NODE *)((void *)((pool)->rb_nodes) + (this_pos) * (CXFSNPRB_POOL_NODE_SIZEOF(pool)))) : NULL_PTR)
#endif
#if 0
extern CXFSNPRB_NODE *__cxfsnprb_node(CXFSNPRB_POOL *pool, const uint32_t node_pos);

#define CXFSNPRB_POOL_NODE(pool, this_pos)  __cxfsnprb_node(pool, this_pos)
#endif
/*new a CXFSNPRB_NODE and return its position*/
uint32_t cxfsnprb_node_new(CXFSNPRB_POOL *pool);

/*free a CXFSNPRB_NODE and return its position to the pool*/
void cxfsnprb_node_free(CXFSNPRB_POOL *pool, const uint32_t node_pos);

void cxfsnprb_node_init(CXFSNPRB_POOL *pool, const uint32_t node_pos);

void cxfsnprb_node_clean(CXFSNPRB_POOL *pool, const uint32_t node_pos);

void cxfsnprb_node_set_next(CXFSNPRB_POOL *pool, const uint32_t node_pos, const uint32_t next_pos);

EC_BOOL cxfsnprb_node_is_used(const CXFSNPRB_POOL *pool, const uint32_t node_pos);

void cxfsnprb_node_print(LOG *log, const CXFSNPRB_POOL *pool, const uint32_t node_pos);

void cxfsnprb_node_print_level(LOG *log, const CXFSNPRB_POOL *pool, const uint32_t node_pos, const uint32_t level);

/*free one rbtree represented by root = root_pos*/
void cxfsnprb_tree_free(CXFSNPRB_POOL *pool, const uint32_t root_pos);

/*init the whole rbtrees pool*/
EC_BOOL cxfsnprb_pool_init(CXFSNPRB_POOL *pool, const uint32_t node_max_num, const uint32_t node_sizeof);

/*clean the whole rbtrees pool*/
void cxfsnprb_pool_clean(CXFSNPRB_POOL *pool);

/*print the whole rbtrees pool*/
void cxfsnprb_pool_print(LOG *log, const CXFSNPRB_POOL *pool);

EC_BOOL cxfsnprb_pool_is_empty(const CXFSNPRB_POOL *pool);

EC_BOOL cxfsnprb_pool_is_full(const CXFSNPRB_POOL *pool);

/*visit the root node first: root -> left -> right*/
void cxfsnprb_preorder_print(LOG *log, const CXFSNPRB_POOL *pool, const uint32_t node_pos);

/*visit the left subtree, then the root node: left -> root -> right*/
void cxfsnprb_inorder_print(LOG *log, const CXFSNPRB_POOL *pool, const uint32_t node_pos);

/*visit the root node last: left -> right -> root*/
void cxfsnprb_postorder_print(LOG *log, const CXFSNPRB_POOL *pool, const uint32_t node_pos);

/*visit the root node first: root -> left -> right*/
void cxfsnprb_preorder_print_level(LOG *log, const CXFSNPRB_POOL *pool, const uint32_t node_pos, const uint32_t level);

void cxfsnprb_tree_print(LOG *log, const CXFSNPRB_POOL *pool, const uint32_t root_pos);

uint32_t cxfsnprb_tree_count_node_num(const CXFSNPRB_POOL *pool, const uint32_t root_pos);

uint32_t cxfsnprb_tree_node_max_num(const CXFSNPRB_POOL *pool);

uint32_t cxfsnprb_tree_node_used_num(const CXFSNPRB_POOL *pool);

uint32_t cxfsnprb_tree_node_sizeof(const CXFSNPRB_POOL *pool);

/* Find logical next and previous nodes in a tree */
uint32_t cxfsnprb_tree_first_node(const CXFSNPRB_POOL *pool, const uint32_t root_pos);
uint32_t cxfsnprb_tree_last_node(const CXFSNPRB_POOL *pool, const uint32_t root_pos);
uint32_t cxfsnprb_tree_next_node(const CXFSNPRB_POOL *pool, const uint32_t node_pos);
uint32_t cxfsnprb_tree_prev_node(const CXFSNPRB_POOL *pool, const uint32_t node_pos);

/* Fast replacement of a single node without remove/rebalance/add/rebalance */
void cxfsnprb_tree_replace_node(CXFSNPRB_POOL *pool, const uint32_t victim_pos, const uint32_t new_pos, uint32_t *root_pos);

uint32_t cxfsnprb_tree_search_data(const CXFSNPRB_POOL *pool, const uint32_t root_pos, const uint32_t data, const uint32_t klen, const uint8_t *key, const uint32_t dflag);

EC_BOOL cxfsnprb_tree_insert_data(CXFSNPRB_POOL *pool, uint32_t *root_pos, const uint32_t data, const uint32_t klen, const uint8_t *key, const uint32_t dflag, uint32_t *insert_pos);

EC_BOOL cxfsnprb_tree_delete_data(CXFSNPRB_POOL *pool, uint32_t *root_pos, const uint32_t data, const uint32_t klen, const uint8_t *key, const uint32_t dflag, uint32_t *delete_pos);

EC_BOOL cxfsnprb_tree_delete(CXFSNPRB_POOL *pool, uint32_t *root_pos, const uint32_t node_pos);

/*if found duplicate node, return EC_FALSE, otherwise return EC_TRUE*/
EC_BOOL cxfsnprb_tree_insert(CXFSNPRB_POOL *pool, uint32_t *root_pos, const uint32_t data, const uint32_t klen, const uint8_t *key, const uint32_t dflag, const uint32_t insert_pos);

EC_BOOL cxfsnprb_tree_erase(CXFSNPRB_POOL *pool, const uint32_t node_pos, uint32_t *root_pos);

EC_BOOL cxfsnprb_flush_size(const CXFSNPRB_POOL *pool, UINT32 *size);

EC_BOOL cxfsnprb_flush(const CXFSNPRB_POOL *pool, int fd, UINT32 *offset);

EC_BOOL cxfsnprb_load(CXFSNPRB_POOL *pool, int fd, UINT32 *offset);

/* ---- debug ---- */
EC_BOOL cxfsnprb_node_debug_cmp(const CXFSNPRB_NODE *node_1st, const CXFSNPRB_NODE *node_2nd, int (*node_cmp_data)(const CXFSNPRB_NODE *, const CXFSNPRB_NODE *));
EC_BOOL cxfsnprb_debug_cmp(const CXFSNPRB_POOL *pool_1st, const CXFSNPRB_POOL *pool_2nd, int (*node_cmp_data)(const CXFSNPRB_NODE *, const CXFSNPRB_NODE *));

#endif    /* _CXFSNPRB_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/
