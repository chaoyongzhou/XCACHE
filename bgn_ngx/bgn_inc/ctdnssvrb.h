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

#ifndef    _CTDNSSVRB_H
#define    _CTDNSSVRB_H

#include "type.h"

#define CTDNSSVRB_RED            ((uint32_t)0)
#define CTDNSSVRB_BLACK          ((uint32_t)1)

#define CTDNSSVRB_NODE_NOT_USED  ((uint32_t)0)
#define CTDNSSVRB_NODE_USED      ((uint32_t)1)

#define CTDNSSVRB_ERR_POS        ((uint32_t)0x7FFFFFFF)/*31 bits*/

#define CTDNSSVRB_POOL_MAX_SIZE  ((uint32_t)(1 << 23))/* < 2^23, about 8,000,000*/

typedef struct
{
    uint32_t rb_parent_pos:31; /*value range: [0, 0x7FFFFFFF)*/
    uint32_t rb_used      : 1; /*CTDNSSVRB_USED or CTDNSSVRB_NOT_USED*/
        
    uint32_t rb_right_pos :31; /*value range: [0, 0x7FFFFFFF)*/
    uint32_t rsvd1        : 1;

    uint32_t rb_left_pos  :31; /*value range: [0, 0x7FFFFFFF)*/
    uint32_t rb_color     : 1; /*CTDNSSVRB_RED or CTDNSSVRB_BLACK*/

    union
    {
        uint32_t rb_next_pos  :31; /*save next position*/
        uint32_t rb_hash_data;     /*saved data*/
    }u;
}CTDNSSVRB_NODE; /*16B*/

#define CTDNSSVRB_NODE_PARENT_POS(node)       ((node)->rb_parent_pos)
#define CTDNSSVRB_NODE_RIGHT_POS(node)        ((node)->rb_right_pos)
#define CTDNSSVRB_NODE_LEFT_POS(node)         ((node)->rb_left_pos)
#define CTDNSSVRB_NODE_NEXT_POS(node)         ((node)->u.rb_next_pos)
#define CTDNSSVRB_NODE_DATA(node)             ((node)->u.rb_hash_data)
#define CTDNSSVRB_NODE_COLOR(node)            ((node)->rb_color)
#define CTDNSSVRB_NODE_USED_FLAG(node)        ((node)->rb_used)

#define CTDNSSVRB_NODE_IS_USED(node)          (CTDNSSVRB_NODE_USED == CTDNSSVRB_NODE_USED_FLAG(node))
#define CTDNSSVRB_NODE_IS_NOT_USED(node)      (CTDNSSVRB_NODE_NOT_USED == CTDNSSVRB_NODE_USED_FLAG(node))

#define CTDNSSVRB_NODE_IS_RED(node)           (CTDNSSVRB_RED == CTDNSSVRB_NODE_COLOR(node))
#define CTDNSSVRB_NODE_IS_BLACK(node)         (CTDNSSVRB_BLACK == CTDNSSVRB_NODE_COLOR(node))


typedef struct
{    
    uint32_t          node_max_num; /*max node number in the pool*/
    uint32_t          node_used_num;/*used node number           */
    uint32_t          node_sizeof;  /*actual size of each node   */
    uint32_t          free_head;    /*unused CTDNSSVRB_TREE head   */
    uint32_t          root_pos;
    uint32_t          rsvd;
    CTDNSSVRB_NODE    rb_nodes[0];  /*rb_nodes table             */
}CTDNSSVRB_POOL;

#define CTDNSSVRB_POOL_ROOT_POS(pool)          ((pool)->root_pos)
#define CTDNSSVRB_POOL_FREE_HEAD(pool)         ((pool)->free_head)
#define CTDNSSVRB_POOL_NODE_MAX_NUM(pool)      ((pool)->node_max_num)
#define CTDNSSVRB_POOL_NODE_USED_NUM(pool)     ((pool)->node_used_num)
#define CTDNSSVRB_POOL_NODE_SIZEOF(pool)       ((pool)->node_sizeof)
#define CTDNSSVRB_POOL_NODE_TBL(pool)          ((pool)->rb_nodes)
#if 1
#define CTDNSSVRB_POOL_NODE(pool, this_pos)    \
    (CTDNSSVRB_POOL_NODE_MAX_NUM(pool) > (this_pos) ? ((CTDNSSVRB_NODE *)((void *)((pool)->rb_nodes) + (this_pos) * (CTDNSSVRB_POOL_NODE_SIZEOF(pool)))) : NULL_PTR)
#endif
#if 0
extern CTDNSSVRB_NODE *__ctdnssvrb_node(CTDNSSVRB_POOL *pool, const uint32_t node_pos);

#define CTDNSSVRB_POOL_NODE(pool, this_pos)  __ctdnssvrb_node(pool, this_pos)
#endif
/*new a CTDNSSVRB_NODE and return its position*/
uint32_t ctdnssvrb_node_new(CTDNSSVRB_POOL *pool);

/*free a CTDNSSVRB_NODE and return its position to the pool*/
void ctdnssvrb_node_free(CTDNSSVRB_POOL *pool, const uint32_t node_pos);

void ctdnssvrb_node_init(CTDNSSVRB_POOL *pool, const uint32_t node_pos);

void ctdnssvrb_node_clean(CTDNSSVRB_POOL *pool, const uint32_t node_pos);

void ctdnssvrb_node_set_next(CTDNSSVRB_POOL *pool, const uint32_t node_pos, const uint32_t next_pos);

EC_BOOL ctdnssvrb_node_is_used(const CTDNSSVRB_POOL *pool, const uint32_t node_pos);

void ctdnssvrb_node_print(LOG *log, const CTDNSSVRB_POOL *pool, const uint32_t node_pos);

void ctdnssvrb_node_print_level(LOG *log, const CTDNSSVRB_POOL *pool, const uint32_t node_pos, const uint32_t level);

/*free one rbtree represented by root = root_pos*/
void ctdnssvrb_tree_free(CTDNSSVRB_POOL *pool, const uint32_t root_pos);

/*init the whole rbtrees pool*/
EC_BOOL ctdnssvrb_pool_init(CTDNSSVRB_POOL *pool, const uint32_t node_max_num, const uint32_t node_sizeof);

/*clean the whole rbtrees pool*/
void ctdnssvrb_pool_clean(CTDNSSVRB_POOL *pool);

/*print the whole rbtrees pool*/
void ctdnssvrb_pool_print(LOG *log, const CTDNSSVRB_POOL *pool);

EC_BOOL ctdnssvrb_pool_is_empty(const CTDNSSVRB_POOL *pool);

EC_BOOL ctdnssvrb_pool_is_full(const CTDNSSVRB_POOL *pool);

/*visit the root node first: root -> left -> right*/
void ctdnssvrb_preorder_print(LOG *log, const CTDNSSVRB_POOL *pool, const uint32_t node_pos);

/*visit the left subtree, then the root node: left -> root -> right*/
void ctdnssvrb_inorder_print(LOG *log, const CTDNSSVRB_POOL *pool, const uint32_t node_pos);

/*visit the root node last: left -> right -> root*/
void ctdnssvrb_postorder_print(LOG *log, const CTDNSSVRB_POOL *pool, const uint32_t node_pos);

/*visit the root node first: root -> left -> right*/
void ctdnssvrb_preorder_print_level(LOG *log, const CTDNSSVRB_POOL *pool, const uint32_t node_pos, const uint32_t level);

void ctdnssvrb_tree_print(LOG *log, const CTDNSSVRB_POOL *pool, const uint32_t root_pos);

uint32_t ctdnssvrb_tree_count_node_num(const CTDNSSVRB_POOL *pool, const uint32_t root_pos);

uint32_t ctdnssvrb_tree_node_max_num(const CTDNSSVRB_POOL *pool);

uint32_t ctdnssvrb_tree_node_used_num(const CTDNSSVRB_POOL *pool);

uint32_t ctdnssvrb_tree_node_sizeof(const CTDNSSVRB_POOL *pool);

/* Find logical next and previous nodes in a tree */
uint32_t ctdnssvrb_tree_first_node(const CTDNSSVRB_POOL *pool, const uint32_t root_pos);
uint32_t ctdnssvrb_tree_last_node(const CTDNSSVRB_POOL *pool, const uint32_t root_pos);
uint32_t ctdnssvrb_tree_next_node(const CTDNSSVRB_POOL *pool, const uint32_t node_pos);
uint32_t ctdnssvrb_tree_prev_node(const CTDNSSVRB_POOL *pool, const uint32_t node_pos);

/* Fast replacement of a single node without remove/rebalance/add/rebalance */
void ctdnssvrb_tree_replace_node(CTDNSSVRB_POOL *pool, const uint32_t victim_pos, const uint32_t new_pos, uint32_t *root_pos);

uint32_t ctdnssvrb_tree_search_data(const CTDNSSVRB_POOL *pool, const uint32_t root_pos, const UINT32 tcid);

EC_BOOL ctdnssvrb_tree_insert_data(CTDNSSVRB_POOL *pool, uint32_t *root_pos, const UINT32 tcid, uint32_t *insert_pos);

EC_BOOL ctdnssvrb_tree_delete_data(CTDNSSVRB_POOL *pool, uint32_t *root_pos, const UINT32 tcid, uint32_t *delete_pos);

EC_BOOL ctdnssvrb_tree_delete(CTDNSSVRB_POOL *pool, uint32_t *root_pos, const uint32_t node_pos);

EC_BOOL ctdnssvrb_tree_erase(CTDNSSVRB_POOL *pool, const uint32_t node_pos, uint32_t *root_pos);

EC_BOOL ctdnssvrb_flush_size(const CTDNSSVRB_POOL *pool, UINT32 *size);

EC_BOOL ctdnssvrb_flush(const CTDNSSVRB_POOL *pool, int fd, UINT32 *offset);

EC_BOOL ctdnssvrb_load(CTDNSSVRB_POOL *pool, int fd, UINT32 *offset);

/* ---- debug ---- */
EC_BOOL ctdnssvrb_node_debug_cmp(const CTDNSSVRB_NODE *node_1st, const CTDNSSVRB_NODE *node_2nd, int (*node_cmp_data)(const CTDNSSVRB_NODE *, const CTDNSSVRB_NODE *));
EC_BOOL ctdnssvrb_debug_cmp(const CTDNSSVRB_POOL *pool_1st, const CTDNSSVRB_POOL *pool_2nd, int (*node_cmp_data)(const CTDNSSVRB_NODE *, const CTDNSSVRB_NODE *));

#endif    /* _CTDNSSVRB_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/
