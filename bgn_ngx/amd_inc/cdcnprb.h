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

#ifndef    _CDCNPRB_H
#define    _CDCNPRB_H

#include "type.h"

#define CDCNPRB_RED            ((uint32_t)0)
#define CDCNPRB_BLACK          ((uint32_t)1)

#define CDCNPRB_NODE_NOT_USED  ((uint32_t)0)
#define CDCNPRB_NODE_USED      ((uint32_t)1)

#define CDCNPRB_ROOT_POS       ((uint32_t)0)/*31 bits*/
#define CDCNPRB_ERR_POS        ((uint32_t)0x7FFFFFFF)/*31 bits*/

#define CDCNPRB_POOL_MAX_SIZE  ((uint32_t)(1 << 24))/* < 2^24, about 16,000,000*/

typedef struct
{
    uint32_t rb_parent_pos:31; /*value range: [0, 0x7FFFFFFF)*/
    uint32_t rb_used      : 1; /*CDCNPRB_USED or CDCNPRB_NOT_USED*/

    uint32_t rb_right_pos :31; /*value range: [0, 0x7FFFFFFF)*/
    uint32_t rsvd1        : 1;

    uint32_t rb_left_pos  :31; /*value range: [0, 0x7FFFFFFF)*/
    uint32_t rb_color     : 1; /*CDCNPRB_RED or CDCNPRB_BLACK*/

    union
    {
        uint32_t rb_next_pos  :31; /*save next position*/
        uint32_t rb_hash_data;     /*saved data*/
    }u;
}CDCNPRB_NODE; /*16B*/

#define CDCNPRB_NODE_PARENT_POS(node)       ((node)->rb_parent_pos)
#define CDCNPRB_NODE_RIGHT_POS(node)        ((node)->rb_right_pos)
#define CDCNPRB_NODE_LEFT_POS(node)         ((node)->rb_left_pos)
#define CDCNPRB_NODE_NEXT_POS(node)         ((node)->u.rb_next_pos)
#define CDCNPRB_NODE_DATA(node)             ((node)->u.rb_hash_data)
#define CDCNPRB_NODE_COLOR(node)            ((node)->rb_color)
#define CDCNPRB_NODE_USED_FLAG(node)        ((node)->rb_used)

#define CDCNPRB_NODE_IS_USED(node)          (CDCNPRB_NODE_USED == CDCNPRB_NODE_USED_FLAG(node))
#define CDCNPRB_NODE_IS_NOT_USED(node)      (CDCNPRB_NODE_NOT_USED == CDCNPRB_NODE_USED_FLAG(node))

#define CDCNPRB_NODE_IS_RED(node)           (CDCNPRB_RED == CDCNPRB_NODE_COLOR(node))
#define CDCNPRB_NODE_IS_BLACK(node)         (CDCNPRB_BLACK == CDCNPRB_NODE_COLOR(node))


typedef struct
{
    /*16B*/
    uint32_t        node_max_num; /*max node number in the pool*/
    uint32_t        node_used_num;/*used node number           */
    uint32_t        node_sizeof;  /*actual size of each node   */
    uint32_t        free_head;    /*unused CDCNPRB_TREE head  */

    CDCNPRB_NODE   rb_nodes[0];  /*rb_nodes table             */
}CDCNPRB_POOL;

#define CDCNPRB_POOL_FREE_HEAD(pool)         ((pool)->free_head)
#define CDCNPRB_POOL_NODE_MAX_NUM(pool)      ((pool)->node_max_num)
#define CDCNPRB_POOL_NODE_USED_NUM(pool)     ((pool)->node_used_num)
#define CDCNPRB_POOL_NODE_SIZEOF(pool)       ((pool)->node_sizeof)
#define CDCNPRB_POOL_NODE_TBL(pool)          ((pool)->rb_nodes)
#if 1
#define CDCNPRB_POOL_NODE(pool, this_pos)    \
    (CDCNPRB_POOL_NODE_MAX_NUM(pool) > (this_pos) ? ((CDCNPRB_NODE *)((void *)((pool)->rb_nodes) + (this_pos) * (CDCNPRB_POOL_NODE_SIZEOF(pool)))) : NULL_PTR)
#endif
#if 0
extern CDCNPRB_NODE *__cdcnprb_node(CDCNPRB_POOL *pool, const uint32_t node_pos);

#define CDCNPRB_POOL_NODE(pool, this_pos)  __cdcnprb_node(pool, this_pos)
#endif

typedef void (*CDCNPRB_INTERSECTED_KEY_HANDLER)(const void *node_key, const void *cover_key, const void *next_key);

typedef void (*CDCNPRB_WALKER)(void *, const void *, const uint32_t);

/*new a CDCNPRB_NODE and return its position*/
uint32_t cdcnprb_node_new(CDCNPRB_POOL *pool);

/*free a CDCNPRB_NODE and return its position to the pool*/
void cdcnprb_node_free(CDCNPRB_POOL *pool, const uint32_t node_pos);

void cdcnprb_node_init(CDCNPRB_POOL *pool, const uint32_t node_pos);

void cdcnprb_node_clean(CDCNPRB_POOL *pool, const uint32_t node_pos);

void cdcnprb_node_set_next(CDCNPRB_POOL *pool, const uint32_t node_pos, const uint32_t next_pos);

EC_BOOL cdcnprb_node_is_used(const CDCNPRB_POOL *pool, const uint32_t node_pos);

void cdcnprb_node_print(LOG *log, const CDCNPRB_POOL *pool, const uint32_t node_pos);

void cdcnprb_node_print_level(LOG *log, const CDCNPRB_POOL *pool, const uint32_t node_pos, const uint32_t level);

/*free one rbtree represented by root = root_pos*/
void cdcnprb_tree_free(CDCNPRB_POOL *pool, const uint32_t root_pos);

/*init the whole rbtrees pool*/
EC_BOOL cdcnprb_pool_init(CDCNPRB_POOL *pool, const uint32_t node_max_num, const uint32_t node_sizeof);

/*clean the whole rbtrees pool*/
void cdcnprb_pool_clean(CDCNPRB_POOL *pool);

/*print the whole rbtrees pool*/
void cdcnprb_pool_print(LOG *log, const CDCNPRB_POOL *pool);

EC_BOOL cdcnprb_pool_is_empty(const CDCNPRB_POOL *pool);

EC_BOOL cdcnprb_pool_is_full(const CDCNPRB_POOL *pool);

/*visit the root node first: root -> left -> right*/
void cdcnprb_preorder_print(LOG *log, const CDCNPRB_POOL *pool, const uint32_t node_pos);

/*visit the left subtree, then the root node: left -> root -> right*/
void cdcnprb_inorder_print(LOG *log, const CDCNPRB_POOL *pool, const uint32_t node_pos);

/*visit the root node last: left -> right -> root*/
void cdcnprb_postorder_print(LOG *log, const CDCNPRB_POOL *pool, const uint32_t node_pos);

/*visit the root node first: root -> left -> right*/
void cdcnprb_preorder_print_level(LOG *log, const CDCNPRB_POOL *pool, const uint32_t node_pos, const uint32_t level);

void cdcnprb_inorder_walk(const CDCNPRB_POOL *pool, const uint32_t node_pos, void (*walker)(void *, const void *, const uint32_t), void *arg1, const void *arg2);

void cdcnprb_tree_print(LOG *log, const CDCNPRB_POOL *pool, const uint32_t root_pos);

uint32_t cdcnprb_tree_count_node_num(const CDCNPRB_POOL *pool, const uint32_t root_pos);

uint32_t cdcnprb_tree_node_max_num(const CDCNPRB_POOL *pool);

uint32_t cdcnprb_tree_node_used_num(const CDCNPRB_POOL *pool);

uint32_t cdcnprb_tree_node_sizeof(const CDCNPRB_POOL *pool);

/* Find logical next and previous nodes in a tree */
uint32_t cdcnprb_tree_first_node(const CDCNPRB_POOL *pool, const uint32_t root_pos);
uint32_t cdcnprb_tree_last_node(const CDCNPRB_POOL *pool, const uint32_t root_pos);
uint32_t cdcnprb_tree_next_node(const CDCNPRB_POOL *pool, const uint32_t node_pos);
uint32_t cdcnprb_tree_prev_node(const CDCNPRB_POOL *pool, const uint32_t node_pos);

/*return the intersected pos*/
uint32_t cdcnprb_tree_find_intersected_data(const CDCNPRB_POOL *pool, const uint32_t root_pos, const void *cdcnp_key);

/*return the closest pos*/
uint32_t cdcnprb_tree_find_closest_data(const CDCNPRB_POOL *pool, const uint32_t root_pos, const void *cdcnp_key);

uint32_t cdcnprb_tree_search_data(const CDCNPRB_POOL *pool, const uint32_t root_pos, const void *cdcnp_key);

EC_BOOL cdcnprb_tree_insert_data(CDCNPRB_POOL *pool, uint32_t *root_pos, const void *cdcnp_key, uint32_t *insert_pos);

EC_BOOL cdcnprb_tree_delete_data(CDCNPRB_POOL *pool, uint32_t *root_pos, const void *cdcnp_key, uint32_t *delete_pos);

EC_BOOL cdcnprb_tree_delete(CDCNPRB_POOL *pool, uint32_t *root_pos, const uint32_t node_pos);

EC_BOOL cdcnprb_tree_erase(CDCNPRB_POOL *pool, const uint32_t node_pos, uint32_t *root_pos);


/* ---- debug ---- */
EC_BOOL cdcnprb_node_debug_cmp(const CDCNPRB_NODE *node_1st, const CDCNPRB_NODE *node_2nd, int (*node_cmp_data)(const CDCNPRB_NODE *, const CDCNPRB_NODE *));
EC_BOOL cdcnprb_debug_cmp(const CDCNPRB_POOL *pool_1st, const CDCNPRB_POOL *pool_2nd, int (*node_cmp_data)(const CDCNPRB_NODE *, const CDCNPRB_NODE *));

#endif    /* _CDCNPRB_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/
