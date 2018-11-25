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

#ifndef    _CDCPGRB_H
#define    _CDCPGRB_H

#include "type.h"

#define CDCPGRB_RED            ((uint16_t)0)
#define CDCPGRB_BLACK          ((uint16_t)1)

#define CDCPGRB_NODE_NOT_USED  ((uint16_t)0)
#define CDCPGRB_NODE_USED      ((uint16_t)1)

#define CDCPGRB_ERR_POS        ((uint16_t)0x7FFF)/*15 bits*/

#define CDCPGRB_POOL_MAX_SIZE  ((uint16_t)0x4000)/* < 2^14( 1TB = 2^14 64M-block, 64M = 2^14 4K-page = 2^13 8K-page)*/

typedef struct
{
    uint16_t rb_parent_pos:15;
    uint16_t rb_used      : 1; /*CDCPGRB_USED or CDCPGRB_NOT_USED*/

    uint16_t rb_right_pos :15;
    uint16_t rsvd1        : 1;

    uint16_t rb_left_pos  :15;
    uint16_t rsvd2        : 1;

    uint16_t rb_data      :15; /*save position data or next position*/
    uint16_t rb_color     : 1; /*CDCPGRB_RED or CDCPGRB_BLACK*/

}CDCPGRB_NODE; /*8B or 64b*/

#define rb_next_pos       rb_data

#define CDCPGRB_NODE_PARENT_POS(node)       ((node)->rb_parent_pos)
#define CDCPGRB_NODE_RIGHT_POS(node)        ((node)->rb_right_pos)
#define CDCPGRB_NODE_LEFT_POS(node)         ((node)->rb_left_pos)
#define CDCPGRB_NODE_NEXT_POS(node)         ((node)->rb_next_pos)
#define CDCPGRB_NODE_DATA(node)             ((node)->rb_data)
#define CDCPGRB_NODE_COLOR(node)            ((node)->rb_color)
#define CDCPGRB_NODE_USED_FLAG(node)        ((node)->rb_used)

#define CDCPGRB_NODE_IS_USED(node)          (CDCPGRB_NODE_USED == CDCPGRB_NODE_USED_FLAG(node))
#define CDCPGRB_NODE_IS_NOT_USED(node)      (CDCPGRB_NODE_NOT_USED == CDCPGRB_NODE_USED_FLAG(node))

#define CDCPGRB_NODE_IS_RED(node)           (CDCPGRB_RED == CDCPGRB_NODE_COLOR(node))
#define CDCPGRB_NODE_IS_BLACK(node)         (CDCPGRB_BLACK == CDCPGRB_NODE_COLOR(node))


typedef struct
{
    uint32_t      rsvd2;
    uint16_t      free_head;/*unused CDCPGRB_TREE head*/
    uint16_t      node_num;
    CDCPGRB_NODE  rb_node[ 0 ];/*rb_nodes table*/
}CDCPGRB_POOL;

#define CDCPGRB_POOL_FREE_HEAD(pool)         ((pool)->free_head)
#define CDCPGRB_POOL_NODE_NUM(pool)          ((pool)->node_num)
#define CDCPGRB_POOL_NODE_TBL(pool)          ((pool)->rb_node)
#define CDCPGRB_POOL_NODE(pool, this_pos)    (CDCPGRB_POOL_NODE_NUM(pool) > (this_pos) ? ((pool)->rb_node + (this_pos)) : NULL_PTR)

/*search data in one rbtree represented by root = root_pos*/
uint16_t cdcpgrb_tree_search_data(CDCPGRB_POOL *pool, const uint16_t root_pos, uint16_t data);

/*insert data into one rbtree represented by root = root_pos*/
uint16_t cdcpgrb_tree_insert_data(CDCPGRB_POOL *pool, uint16_t *root_pos, const uint16_t data);

/*delete data from one rbtree represented by root = root_pos*/
EC_BOOL  cdcpgrb_tree_delete_data(CDCPGRB_POOL *pool, uint16_t *root_pos, const uint16_t data);

/*free one rbtree represented by root = root_pos*/
void cdcpgrb_tree_free(CDCPGRB_POOL *pool, const uint16_t root_pos);

/*init the whole rbtrees pool*/
EC_BOOL cdcpgrb_pool_init(CDCPGRB_POOL *pool, const uint16_t node_num);

/*clean the whole rbtrees pool*/
void cdcpgrb_pool_clean(CDCPGRB_POOL *pool);

/*clear without any space mallocation!*/
void cdcpgrb_pool_clear(CDCPGRB_POOL *pool);

/*print the whole rbtrees pool*/
void cdcpgrb_pool_print(LOG *log, const CDCPGRB_POOL *pool);

/*visit the root node first: root -> left -> right*/
void cdcpgrb_preorder_print(LOG *log, const CDCPGRB_POOL *pool, const uint16_t node_pos);

/*visit the left subtree, then the root node: left -> root -> right*/
void cdcpgrb_inorder_print(LOG *log, const CDCPGRB_POOL *pool, const uint16_t node_pos);

/*visit the root node last: left -> right -> root*/
void cdcpgrb_postorder_print(LOG *log, const CDCPGRB_POOL *pool, const uint16_t node_pos);

/*visit the root node first: root -> left -> right*/
void cdcpgrb_preorder_print_level(LOG *log, const CDCPGRB_POOL *pool, const uint16_t node_pos, const uint16_t level);

void cdcpgrb_tree_print(LOG *log, const CDCPGRB_POOL *pool, const uint16_t root_pos);

EC_BOOL cdcpgrb_tree_is_empty(const CDCPGRB_POOL *pool, const uint16_t root_pos);

uint16_t cdcpgrb_tree_node_num(const CDCPGRB_POOL *pool, const uint16_t root_pos);

/* Find logical next and previous nodes in a tree */
uint16_t cdcpgrb_tree_first_node(const CDCPGRB_POOL *pool, const uint16_t root_pos);
uint16_t cdcpgrb_tree_last_node(const CDCPGRB_POOL *pool, const uint16_t root_pos);
uint16_t cdcpgrb_tree_next_node(const CDCPGRB_POOL *pool, const uint16_t node_pos);
uint16_t cdcpgrb_tree_prev_node(const CDCPGRB_POOL *pool, const uint16_t node_pos);

/* ---- debug ---- */
EC_BOOL cdcpgrb_node_debug_cmp(const CDCPGRB_NODE *node_1st, const CDCPGRB_NODE *node_2nd);
EC_BOOL cdcpgrb_debug_cmp(const CDCPGRB_POOL *pool_1st, const CDCPGRB_POOL *pool_2nd);

#endif    /* _CDCPGRB_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/
