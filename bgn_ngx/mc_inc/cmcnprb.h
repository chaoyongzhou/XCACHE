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

#ifndef    _CMCNPRB_H
#define    _CMCNPRB_H

#include "type.h"

#define CMCNPRB_RED            ((uint32_t)0)
#define CMCNPRB_BLACK          ((uint32_t)1)

#define CMCNPRB_NODE_NOT_USED  ((uint32_t)0)
#define CMCNPRB_NODE_USED      ((uint32_t)1)

#define CMCNPRB_ROOT_POS       ((uint32_t)0)/*31 bits*/
#define CMCNPRB_ERR_POS        ((uint32_t)0x7FFFFFFF)/*31 bits*/

#define CMCNPRB_POOL_MAX_SIZE  ((uint32_t)(1 << 24))/* < 2^24, about 16,000,000*/

typedef struct
{
    uint32_t rb_parent_pos:31; /*value range: [0, 0x7FFFFFFF)*/
    uint32_t rb_used      : 1; /*CMCNPRB_USED or CMCNPRB_NOT_USED*/

    uint32_t rb_right_pos :31; /*value range: [0, 0x7FFFFFFF)*/
    uint32_t rsvd1        : 1;

    uint32_t rb_left_pos  :31; /*value range: [0, 0x7FFFFFFF)*/
    uint32_t rb_color     : 1; /*CMCNPRB_RED or CMCNPRB_BLACK*/

    union
    {
        uint32_t rb_next_pos  :31; /*save next position*/
        uint32_t rb_hash_data;     /*saved data*/
    }u;
}CMCNPRB_NODE; /*16B*/

#define CMCNPRB_NODE_PARENT_POS(node)       ((node)->rb_parent_pos)
#define CMCNPRB_NODE_RIGHT_POS(node)        ((node)->rb_right_pos)
#define CMCNPRB_NODE_LEFT_POS(node)         ((node)->rb_left_pos)
#define CMCNPRB_NODE_NEXT_POS(node)         ((node)->u.rb_next_pos)
#define CMCNPRB_NODE_DATA(node)             ((node)->u.rb_hash_data)
#define CMCNPRB_NODE_COLOR(node)            ((node)->rb_color)
#define CMCNPRB_NODE_USED_FLAG(node)        ((node)->rb_used)

#define CMCNPRB_NODE_IS_USED(node)          (CMCNPRB_NODE_USED == CMCNPRB_NODE_USED_FLAG(node))
#define CMCNPRB_NODE_IS_NOT_USED(node)      (CMCNPRB_NODE_NOT_USED == CMCNPRB_NODE_USED_FLAG(node))

#define CMCNPRB_NODE_IS_RED(node)           (CMCNPRB_RED == CMCNPRB_NODE_COLOR(node))
#define CMCNPRB_NODE_IS_BLACK(node)         (CMCNPRB_BLACK == CMCNPRB_NODE_COLOR(node))


typedef struct
{
    /*16B*/
    uint32_t        node_max_num; /*max node number in the pool*/
    uint32_t        node_used_num;/*used node number           */
    uint32_t        node_sizeof;  /*actual size of each node   */
    uint32_t        free_head;    /*unused CMCNPRB_TREE head  */

    CMCNPRB_NODE   rb_nodes[0];  /*rb_nodes table             */
}CMCNPRB_POOL;

#define CMCNPRB_POOL_FREE_HEAD(pool)         ((pool)->free_head)
#define CMCNPRB_POOL_NODE_MAX_NUM(pool)      ((pool)->node_max_num)
#define CMCNPRB_POOL_NODE_USED_NUM(pool)     ((pool)->node_used_num)
#define CMCNPRB_POOL_NODE_SIZEOF(pool)       ((pool)->node_sizeof)
#define CMCNPRB_POOL_NODE_TBL(pool)          ((pool)->rb_nodes)
#if 1
#define CMCNPRB_POOL_NODE(pool, this_pos)    \
    (CMCNPRB_POOL_NODE_MAX_NUM(pool) > (this_pos) ? ((CMCNPRB_NODE *)((void *)((pool)->rb_nodes) + (this_pos) * (CMCNPRB_POOL_NODE_SIZEOF(pool)))) : NULL_PTR)
#endif
#if 0
extern CMCNPRB_NODE *__cmcnprb_node(CMCNPRB_POOL *pool, const uint32_t node_pos);

#define CMCNPRB_POOL_NODE(pool, this_pos)  __cmcnprb_node(pool, this_pos)
#endif

typedef void (*CMCNPRB_INTERSECTED_KEY_HANDLER)(const void *node_key, const void *cover_key, const void *next_key);

/*new a CMCNPRB_NODE and return its position*/
uint32_t cmcnprb_node_new(CMCNPRB_POOL *pool);

/*free a CMCNPRB_NODE and return its position to the pool*/
void cmcnprb_node_free(CMCNPRB_POOL *pool, const uint32_t node_pos);

void cmcnprb_node_init(CMCNPRB_POOL *pool, const uint32_t node_pos);

void cmcnprb_node_clean(CMCNPRB_POOL *pool, const uint32_t node_pos);

void cmcnprb_node_set_next(CMCNPRB_POOL *pool, const uint32_t node_pos, const uint32_t next_pos);

EC_BOOL cmcnprb_node_is_used(const CMCNPRB_POOL *pool, const uint32_t node_pos);

void cmcnprb_node_print(LOG *log, const CMCNPRB_POOL *pool, const uint32_t node_pos);

void cmcnprb_node_print_level(LOG *log, const CMCNPRB_POOL *pool, const uint32_t node_pos, const uint32_t level);

/*free one rbtree represented by root = root_pos*/
void cmcnprb_tree_free(CMCNPRB_POOL *pool, const uint32_t root_pos);

/*init the whole rbtrees pool*/
EC_BOOL cmcnprb_pool_init(CMCNPRB_POOL *pool, const uint32_t node_max_num, const uint32_t node_sizeof);

/*clean the whole rbtrees pool*/
void cmcnprb_pool_clean(CMCNPRB_POOL *pool);

/*print the whole rbtrees pool*/
void cmcnprb_pool_print(LOG *log, const CMCNPRB_POOL *pool);

EC_BOOL cmcnprb_pool_is_empty(const CMCNPRB_POOL *pool);

EC_BOOL cmcnprb_pool_is_full(const CMCNPRB_POOL *pool);

/*visit the root node first: root -> left -> right*/
void cmcnprb_preorder_print(LOG *log, const CMCNPRB_POOL *pool, const uint32_t node_pos);

/*visit the left subtree, then the root node: left -> root -> right*/
void cmcnprb_inorder_print(LOG *log, const CMCNPRB_POOL *pool, const uint32_t node_pos);

/*visit the root node last: left -> right -> root*/
void cmcnprb_postorder_print(LOG *log, const CMCNPRB_POOL *pool, const uint32_t node_pos);

/*visit the root node first: root -> left -> right*/
void cmcnprb_preorder_print_level(LOG *log, const CMCNPRB_POOL *pool, const uint32_t node_pos, const uint32_t level);

void cmcnprb_tree_print(LOG *log, const CMCNPRB_POOL *pool, const uint32_t root_pos);

uint32_t cmcnprb_tree_count_node_num(const CMCNPRB_POOL *pool, const uint32_t root_pos);

uint32_t cmcnprb_tree_node_max_num(const CMCNPRB_POOL *pool);

uint32_t cmcnprb_tree_node_used_num(const CMCNPRB_POOL *pool);

uint32_t cmcnprb_tree_node_sizeof(const CMCNPRB_POOL *pool);

/* Find logical next and previous nodes in a tree */
uint32_t cmcnprb_tree_first_node(const CMCNPRB_POOL *pool, const uint32_t root_pos);
uint32_t cmcnprb_tree_last_node(const CMCNPRB_POOL *pool, const uint32_t root_pos);
uint32_t cmcnprb_tree_next_node(const CMCNPRB_POOL *pool, const uint32_t node_pos);
uint32_t cmcnprb_tree_prev_node(const CMCNPRB_POOL *pool, const uint32_t node_pos);

/*return the intersected pos*/
uint32_t cmcnprb_tree_find_intersected_data(const CMCNPRB_POOL *pool, const uint32_t root_pos, const void *cmcnp_key);

/*return the closest pos*/
uint32_t cmcnprb_tree_find_closest_data(const CMCNPRB_POOL *pool, const uint32_t root_pos, const void *cmcnp_key);

uint32_t cmcnprb_tree_search_data(const CMCNPRB_POOL *pool, const uint32_t root_pos, const void *cmcnp_key);

EC_BOOL cmcnprb_tree_insert_data(CMCNPRB_POOL *pool, uint32_t *root_pos, const void *cmcnp_key, uint32_t *insert_pos);

EC_BOOL cmcnprb_tree_delete_data(CMCNPRB_POOL *pool, uint32_t *root_pos, const void *cmcnp_key, uint32_t *delete_pos);

EC_BOOL cmcnprb_tree_delete(CMCNPRB_POOL *pool, uint32_t *root_pos, const uint32_t node_pos);

EC_BOOL cmcnprb_tree_erase(CMCNPRB_POOL *pool, const uint32_t node_pos, uint32_t *root_pos);

EC_BOOL cmcnprb_flush_size(const CMCNPRB_POOL *pool, UINT32 *size);

EC_BOOL cmcnprb_flush(const CMCNPRB_POOL *pool, int fd, UINT32 *offset);

EC_BOOL cmcnprb_load(CMCNPRB_POOL *pool, int fd, UINT32 *offset);

/* ---- debug ---- */
EC_BOOL cmcnprb_node_debug_cmp(const CMCNPRB_NODE *node_1st, const CMCNPRB_NODE *node_2nd, int (*node_cmp_data)(const CMCNPRB_NODE *, const CMCNPRB_NODE *));
EC_BOOL cmcnprb_debug_cmp(const CMCNPRB_POOL *pool_1st, const CMCNPRB_POOL *pool_2nd, int (*node_cmp_data)(const CMCNPRB_NODE *, const CMCNPRB_NODE *));

#endif    /* _CMCNPRB_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/
