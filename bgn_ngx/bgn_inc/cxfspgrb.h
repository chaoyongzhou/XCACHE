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

#ifndef    _CXFSPGRB_H
#define    _CXFSPGRB_H

#include "type.h"

#define CXFSPGRB_RED            ((uint16_t)0)
#define CXFSPGRB_BLACK          ((uint16_t)1)

#define CXFSPGRB_NODE_NOT_USED  ((uint16_t)0)
#define CXFSPGRB_NODE_USED      ((uint16_t)1)

#define CXFSPGRB_ERR_POS        ((uint16_t)0x7FFF)/*15 bits*/

#define CXFSPGRB_POOL_MAX_SIZE  ((uint16_t)0x4000)/* < 2^14( 1TB = 2^14 64M-block, 64M = 2^14 4K-page = 2^13 8K-page)*/

typedef struct
{
    uint16_t rb_parent_pos:15;
    uint16_t rb_used      : 1; /*CXFSPGRB_USED or CXFSPGRB_NOT_USED*/

    uint16_t rb_right_pos :15;
    uint16_t rsvd1        : 1;

    uint16_t rb_left_pos  :15;
    uint16_t rsvd2        : 1;

    uint16_t rb_data      :15; /*save position data or next position*/
    uint16_t rb_color     : 1; /*CXFSPGRB_RED or CXFSPGRB_BLACK*/

}CXFSPGRB_NODE; /*8B or 64b*/

#define rb_next_pos       rb_data

#define CXFSPGRB_NODE_PARENT_POS(node)       ((node)->rb_parent_pos)
#define CXFSPGRB_NODE_RIGHT_POS(node)        ((node)->rb_right_pos)
#define CXFSPGRB_NODE_LEFT_POS(node)         ((node)->rb_left_pos)
#define CXFSPGRB_NODE_NEXT_POS(node)         ((node)->rb_next_pos)
#define CXFSPGRB_NODE_DATA(node)             ((node)->rb_data)
#define CXFSPGRB_NODE_COLOR(node)            ((node)->rb_color)
#define CXFSPGRB_NODE_USED_FLAG(node)        ((node)->rb_used)

#define CXFSPGRB_NODE_IS_USED(node)          (CXFSPGRB_NODE_USED == CXFSPGRB_NODE_USED_FLAG(node))
#define CXFSPGRB_NODE_IS_NOT_USED(node)      (CXFSPGRB_NODE_NOT_USED == CXFSPGRB_NODE_USED_FLAG(node))

#define CXFSPGRB_NODE_IS_RED(node)           (CXFSPGRB_RED == CXFSPGRB_NODE_COLOR(node))
#define CXFSPGRB_NODE_IS_BLACK(node)         (CXFSPGRB_BLACK == CXFSPGRB_NODE_COLOR(node))


typedef struct
{
    uint32_t    rsvd2;
    uint16_t    free_head;/*unused CXFSPGRB_TREE head*/
    uint16_t    node_num;
    CXFSPGRB_NODE  rb_node[ 0 ];/*rb_nodes table*/
}CXFSPGRB_POOL;

#define CXFSPGRB_POOL_FREE_HEAD(pool)         ((pool)->free_head)
#define CXFSPGRB_POOL_NODE_NUM(pool)          ((pool)->node_num)
#define CXFSPGRB_POOL_NODE_TBL(pool)          ((pool)->rb_node)
#define CXFSPGRB_POOL_NODE(pool, this_pos)    (CXFSPGRB_POOL_NODE_NUM(pool) > (this_pos) ? ((pool)->rb_node + (this_pos)) : NULL_PTR)

/*search data in one rbtree represented by root = root_pos*/
uint16_t cxfspgrb_tree_search_data(CXFSPGRB_POOL *pool, const uint16_t root_pos, uint16_t data);

/*insert data into one rbtree represented by root = root_pos*/
uint16_t cxfspgrb_tree_insert_data(CXFSPGRB_POOL *pool, uint16_t *root_pos, const uint16_t data);

/*delete data from one rbtree represented by root = root_pos*/
EC_BOOL  cxfspgrb_tree_delete_data(CXFSPGRB_POOL *pool, uint16_t *root_pos, const uint16_t data);

/*free one rbtree represented by root = root_pos*/
void cxfspgrb_tree_free(CXFSPGRB_POOL *pool, const uint16_t root_pos);

/*init the whole rbtrees pool*/
EC_BOOL cxfspgrb_pool_init(CXFSPGRB_POOL *pool, const uint16_t node_num);

/*clean the whole rbtrees pool*/
void cxfspgrb_pool_clean(CXFSPGRB_POOL *pool);

/*clear without any space mallocation!*/
void cxfspgrb_pool_clear(CXFSPGRB_POOL *pool);

/*print the whole rbtrees pool*/
void cxfspgrb_pool_print(LOG *log, const CXFSPGRB_POOL *pool);

/*visit the root node first: root -> left -> right*/
void cxfspgrb_preorder_print(LOG *log, const CXFSPGRB_POOL *pool, const uint16_t node_pos);

/*visit the left subtree, then the root node: left -> root -> right*/
void cxfspgrb_inorder_print(LOG *log, const CXFSPGRB_POOL *pool, const uint16_t node_pos);

/*visit the root node last: left -> right -> root*/
void cxfspgrb_postorder_print(LOG *log, const CXFSPGRB_POOL *pool, const uint16_t node_pos);

/*visit the root node first: root -> left -> right*/
void cxfspgrb_preorder_print_level(LOG *log, const CXFSPGRB_POOL *pool, const uint16_t node_pos, const uint16_t level);

void cxfspgrb_tree_print(LOG *log, const CXFSPGRB_POOL *pool, const uint16_t root_pos);

EC_BOOL cxfspgrb_tree_is_empty(const CXFSPGRB_POOL *pool, const uint16_t root_pos);

uint16_t cxfspgrb_tree_node_num(const CXFSPGRB_POOL *pool, const uint16_t root_pos);

/* Find logical next and previous nodes in a tree */
uint16_t cxfspgrb_tree_first_node(const CXFSPGRB_POOL *pool, const uint16_t root_pos);
uint16_t cxfspgrb_tree_last_node(const CXFSPGRB_POOL *pool, const uint16_t root_pos);
uint16_t cxfspgrb_tree_next_node(const CXFSPGRB_POOL *pool, const uint16_t node_pos);
uint16_t cxfspgrb_tree_prev_node(const CXFSPGRB_POOL *pool, const uint16_t node_pos);

/* Fast replacement of a single node without remove/rebalance/add/rebalance */
void cxfspgrb_tree_replace_node(CXFSPGRB_POOL *pool, const uint16_t victim_pos, const uint16_t new_pos, uint16_t *root_pos);

EC_BOOL cxfspgrb_flush_size(const CXFSPGRB_POOL *pool, UINT32 *size);

EC_BOOL cxfspgrb_flush(const CXFSPGRB_POOL *pool, int fd, UINT32 *offset);

EC_BOOL cxfspgrb_load(CXFSPGRB_POOL *pool, int fd, UINT32 *offset);

/* ---- debug ---- */
EC_BOOL cxfspgrb_node_debug_cmp(const CXFSPGRB_NODE *node_1st, const CXFSPGRB_NODE *node_2nd);
EC_BOOL cxfspgrb_debug_cmp(const CXFSPGRB_POOL *pool_1st, const CXFSPGRB_POOL *pool_2nd);

#endif    /* _CXFSPGRB_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/
