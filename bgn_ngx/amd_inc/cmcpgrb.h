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

#ifndef    _CMCPGRB_H
#define    _CMCPGRB_H

#include "type.h"

#define CMCPGRB_RED            ((uint16_t)0)
#define CMCPGRB_BLACK          ((uint16_t)1)

#define CMCPGRB_NODE_NOT_USED  ((uint16_t)0)
#define CMCPGRB_NODE_USED      ((uint16_t)1)

#define CMCPGRB_ERR_POS        ((uint16_t)0x7FFF)/*15 bits*/

#define CMCPGRB_POOL_MAX_SIZE  ((uint16_t)0x4000)/* < 2^14( 1TB = 2^14 64M-block, 64M = 2^14 4K-page = 2^13 8K-page)*/

typedef struct
{
    uint16_t rb_parent_pos:15;
    uint16_t rb_used      : 1; /*CMCPGRB_USED or CMCPGRB_NOT_USED*/

    uint16_t rb_right_pos :15;
    uint16_t rsvd1        : 1;

    uint16_t rb_left_pos  :15;
    uint16_t rsvd2        : 1;

    uint16_t rb_data      :15; /*save position data or next position*/
    uint16_t rb_color     : 1; /*CMCPGRB_RED or CMCPGRB_BLACK*/

}CMCPGRB_NODE; /*8B or 64b*/

#define rb_next_pos       rb_data

#define CMCPGRB_NODE_PARENT_POS(node)       ((node)->rb_parent_pos)
#define CMCPGRB_NODE_RIGHT_POS(node)        ((node)->rb_right_pos)
#define CMCPGRB_NODE_LEFT_POS(node)         ((node)->rb_left_pos)
#define CMCPGRB_NODE_NEXT_POS(node)         ((node)->rb_next_pos)
#define CMCPGRB_NODE_DATA(node)             ((node)->rb_data)
#define CMCPGRB_NODE_COLOR(node)            ((node)->rb_color)
#define CMCPGRB_NODE_USED_FLAG(node)        ((node)->rb_used)

#define CMCPGRB_NODE_IS_USED(node)          (CMCPGRB_NODE_USED == CMCPGRB_NODE_USED_FLAG(node))
#define CMCPGRB_NODE_IS_NOT_USED(node)      (CMCPGRB_NODE_NOT_USED == CMCPGRB_NODE_USED_FLAG(node))

#define CMCPGRB_NODE_IS_RED(node)           (CMCPGRB_RED == CMCPGRB_NODE_COLOR(node))
#define CMCPGRB_NODE_IS_BLACK(node)         (CMCPGRB_BLACK == CMCPGRB_NODE_COLOR(node))


typedef struct
{
    uint32_t      rsvd2;
    uint16_t      free_head;/*unused CMCPGRB_TREE head*/
    uint16_t      node_num;
    CMCPGRB_NODE  rb_node[ 0 ];/*rb_nodes table*/
}CMCPGRB_POOL;

#define CMCPGRB_POOL_FREE_HEAD(pool)         ((pool)->free_head)
#define CMCPGRB_POOL_NODE_NUM(pool)          ((pool)->node_num)
#define CMCPGRB_POOL_NODE_TBL(pool)          ((pool)->rb_node)
#define CMCPGRB_POOL_NODE(pool, this_pos)    (CMCPGRB_POOL_NODE_NUM(pool) > (this_pos) ? ((pool)->rb_node + (this_pos)) : NULL_PTR)

/*search data in one rbtree represented by root = root_pos*/
uint16_t cmcpgrb_tree_search_data(CMCPGRB_POOL *pool, const uint16_t root_pos, uint16_t data);

/*insert data into one rbtree represented by root = root_pos*/
uint16_t cmcpgrb_tree_insert_data(CMCPGRB_POOL *pool, uint16_t *root_pos, const uint16_t data);

/*delete data from one rbtree represented by root = root_pos*/
EC_BOOL  cmcpgrb_tree_delete_data(CMCPGRB_POOL *pool, uint16_t *root_pos, const uint16_t data);

/*free one rbtree represented by root = root_pos*/
void cmcpgrb_tree_free(CMCPGRB_POOL *pool, const uint16_t root_pos);

/*init the whole rbtrees pool*/
EC_BOOL cmcpgrb_pool_init(CMCPGRB_POOL *pool, const uint16_t node_num);

/*clean the whole rbtrees pool*/
void cmcpgrb_pool_clean(CMCPGRB_POOL *pool);

/*clear without any space mallocation!*/
void cmcpgrb_pool_clear(CMCPGRB_POOL *pool);

/*print the whole rbtrees pool*/
void cmcpgrb_pool_print(LOG *log, const CMCPGRB_POOL *pool);

/*visit the root node first: root -> left -> right*/
void cmcpgrb_preorder_print(LOG *log, const CMCPGRB_POOL *pool, const uint16_t node_pos);

/*visit the left subtree, then the root node: left -> root -> right*/
void cmcpgrb_inorder_print(LOG *log, const CMCPGRB_POOL *pool, const uint16_t node_pos);

/*visit the root node last: left -> right -> root*/
void cmcpgrb_postorder_print(LOG *log, const CMCPGRB_POOL *pool, const uint16_t node_pos);

/*visit the root node first: root -> left -> right*/
void cmcpgrb_preorder_print_level(LOG *log, const CMCPGRB_POOL *pool, const uint16_t node_pos, const uint16_t level);

void cmcpgrb_tree_print(LOG *log, const CMCPGRB_POOL *pool, const uint16_t root_pos);

EC_BOOL cmcpgrb_tree_is_empty(const CMCPGRB_POOL *pool, const uint16_t root_pos);

uint16_t cmcpgrb_tree_node_num(const CMCPGRB_POOL *pool, const uint16_t root_pos);

/* Find logical next and previous nodes in a tree */
uint16_t cmcpgrb_tree_first_node(const CMCPGRB_POOL *pool, const uint16_t root_pos);
uint16_t cmcpgrb_tree_last_node(const CMCPGRB_POOL *pool, const uint16_t root_pos);
uint16_t cmcpgrb_tree_next_node(const CMCPGRB_POOL *pool, const uint16_t node_pos);
uint16_t cmcpgrb_tree_prev_node(const CMCPGRB_POOL *pool, const uint16_t node_pos);

/* ---- debug ---- */
EC_BOOL cmcpgrb_node_debug_cmp(const CMCPGRB_NODE *node_1st, const CMCPGRB_NODE *node_2nd);
EC_BOOL cmcpgrb_debug_cmp(const CMCPGRB_POOL *pool_1st, const CMCPGRB_POOL *pool_2nd);

#endif    /* _CMCPGRB_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/
