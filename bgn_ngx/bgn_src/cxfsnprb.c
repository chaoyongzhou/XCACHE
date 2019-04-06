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

/*rbtree changed from linux kernel rbtree.c*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "type.h"
#include "mm.h"
#include "log.h"

#include "cmisc.h"

#include "db_internal.h"

#include "cxfsnprb.h"
#include "cxfsnp.inc"

/*new a CXFSNPRB_NODE and return its position*/
uint32_t cxfsnprb_node_new(CXFSNPRB_POOL *pool)
{
    uint32_t node_pos_t;
    CXFSNPRB_NODE *node;

    node_pos_t = CXFSNPRB_POOL_FREE_HEAD(pool);
    if(CXFSNPRB_ERR_POS == node_pos_t)
    {
        dbg_log(SEC_0198_CXFSNPRB, 0)(LOGSTDERR, "error:cxfsnprb_node_new: no free node in pool\n");
        return (CXFSNPRB_ERR_POS);
    }

    if(CXFSNPRB_POOL_FREE_HEAD(pool) >= CXFSNPRB_POOL_NODE_MAX_NUM(pool))
    {
        dbg_log(SEC_0198_CXFSNPRB, 0)(LOGSTDERR, "error:cxfsnprb_node_new: found conflict: free head %u >= max num %u\n",
                            CXFSNPRB_POOL_FREE_HEAD(pool), CXFSNPRB_POOL_NODE_MAX_NUM(pool));
        return (CXFSNPRB_ERR_POS);
    }

    ASSERT(CXFSNPRB_POOL_FREE_HEAD(pool) < CXFSNPRB_POOL_NODE_MAX_NUM(pool));

    node = CXFSNPRB_POOL_NODE(pool, node_pos_t);
#if 0
    dbg_log(SEC_0198_CXFSNPRB, 9)(LOGSTDNULL, "[DEBUG] cxfsnprb_node_new: pool %p, max %u, used %u, free head %u, next %u\n",
                       pool,
                       CXFSNPRB_POOL_NODE_MAX_NUM(pool),
                       CXFSNPRB_POOL_NODE_USED_NUM(pool),
                       CXFSNPRB_POOL_FREE_HEAD(pool),
                       CXFSNPRB_NODE_NEXT_POS(node));
#endif
    CXFSNPRB_POOL_FREE_HEAD(pool) = CXFSNPRB_NODE_NEXT_POS(node);
    CXFSNPRB_POOL_NODE_USED_NUM(pool) ++;

    CXFSNPRB_NODE_NEXT_POS(node)  = CXFSNPRB_ERR_POS;
    CXFSNPRB_NODE_USED_FLAG(node) = CXFSNPRB_NODE_USED;

    return (node_pos_t);
}

/*free a CXFSNPRB_NODE and return its position to the pool*/
void cxfsnprb_node_free(CXFSNPRB_POOL *pool, const uint32_t node_pos)
{
    if(CXFSNPRB_ERR_POS != node_pos)
    {
        CXFSNPRB_NODE *node;

        ASSERT(node_pos < CXFSNPRB_POOL_NODE_MAX_NUM(pool));

        node = CXFSNPRB_POOL_NODE(pool, node_pos);
        ASSERT(CXFSNPRB_NODE_IS_USED(node));

        CXFSNPRB_NODE_USED_FLAG(node)  = CXFSNPRB_NODE_NOT_USED;
        CXFSNPRB_NODE_PARENT_POS(node) = CXFSNPRB_ERR_POS;
        CXFSNPRB_NODE_RIGHT_POS(node)  = CXFSNPRB_ERR_POS;
        CXFSNPRB_NODE_LEFT_POS(node)   = CXFSNPRB_ERR_POS;
        CXFSNPRB_NODE_NEXT_POS(node)   = CXFSNPRB_POOL_FREE_HEAD(pool);
        CXFSNPRB_NODE_COLOR(node)      = CXFSNPRB_BLACK;

        CXFSNPRB_POOL_FREE_HEAD(pool)  = node_pos;
        CXFSNPRB_POOL_NODE_USED_NUM(pool) --;
    }
    return;
}

void cxfsnprb_node_init(CXFSNPRB_POOL *pool, const uint32_t node_pos)
{
    CXFSNPRB_NODE *node;

    node  = CXFSNPRB_POOL_NODE(pool, node_pos);

    CXFSNPRB_NODE_PARENT_POS(node) = CXFSNPRB_ERR_POS;
    CXFSNPRB_NODE_RIGHT_POS(node)  = CXFSNPRB_ERR_POS;
    CXFSNPRB_NODE_LEFT_POS(node)   = CXFSNPRB_ERR_POS;
    CXFSNPRB_NODE_USED_FLAG(node)  = CXFSNPRB_NODE_NOT_USED;
    CXFSNPRB_NODE_NEXT_POS(node)   = CXFSNPRB_ERR_POS;
    CXFSNPRB_NODE_COLOR(node)      = CXFSNPRB_BLACK;

    return;
}

void cxfsnprb_node_clean(CXFSNPRB_POOL *pool, const uint32_t node_pos)
{
    CXFSNPRB_NODE *node;

    ASSERT(node_pos < CXFSNPRB_POOL_NODE_MAX_NUM(pool));

    node = CXFSNPRB_POOL_NODE(pool, node_pos);

    CXFSNPRB_NODE_PARENT_POS(node) = CXFSNPRB_ERR_POS;
    CXFSNPRB_NODE_RIGHT_POS(node)  = CXFSNPRB_ERR_POS;
    CXFSNPRB_NODE_LEFT_POS(node)   = CXFSNPRB_ERR_POS;
    CXFSNPRB_NODE_USED_FLAG(node)  = CXFSNPRB_NODE_NOT_USED;
    CXFSNPRB_NODE_NEXT_POS(node)   = CXFSNPRB_ERR_POS;
    CXFSNPRB_NODE_COLOR(node)      = CXFSNPRB_BLACK;

    return;
}

void cxfsnprb_node_set_next(CXFSNPRB_POOL *pool, const uint32_t node_pos, const uint32_t next_pos)
{
    CXFSNPRB_NODE *node;

    node = CXFSNPRB_POOL_NODE(pool, node_pos);
    CXFSNPRB_NODE_NEXT_POS(node) = next_pos;

    return;
}

EC_BOOL cxfsnprb_node_is_used(const CXFSNPRB_POOL *pool, const uint32_t node_pos)
{
    const CXFSNPRB_NODE *node;
    node  = CXFSNPRB_POOL_NODE(pool, node_pos);

    if(CXFSNPRB_NODE_IS_USED(node))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

void cxfsnprb_node_print(LOG *log, const CXFSNPRB_POOL *pool, const uint32_t node_pos)
{
    const CXFSNPRB_NODE *node;
    node  = CXFSNPRB_POOL_NODE(pool, node_pos);

    sys_log(log, "%5d: parent = %5d, left = %5d, right = %5d, flg = %s, color = %s, %s = %5d\n",
                       node_pos,
                       CXFSNPRB_NODE_PARENT_POS(node),
                       CXFSNPRB_NODE_LEFT_POS(node),
                       CXFSNPRB_NODE_RIGHT_POS(node),
                       CXFSNPRB_NODE_IS_USED(node) ? "used" : "n.a.",
                       CXFSNPRB_NODE_IS_USED(node) ? (CXFSNPRB_NODE_IS_RED(node) ? "red  " : "black") : "#####",
                       CXFSNPRB_NODE_IS_USED(node) ? "data" : "next",
                       CXFSNPRB_NODE_IS_USED(node) ? CXFSNPRB_NODE_DATA(node) : CXFSNPRB_NODE_NEXT_POS(node)
                       );
    return;
}

void cxfsnprb_node_print_level(LOG *log, const CXFSNPRB_POOL *pool, const uint32_t node_pos, const uint32_t level)
{
    const CXFSNPRB_NODE *node;
    node  = CXFSNPRB_POOL_NODE(pool, node_pos);

    c_ident_print(log, level);
    sys_print(log, "%5d: parent = %5d, left = %5d, right = %5d, flg = %s, color = %s, %s = %5d\n",
                       node_pos,
                       CXFSNPRB_NODE_PARENT_POS(node),
                       CXFSNPRB_NODE_LEFT_POS(node),
                       CXFSNPRB_NODE_RIGHT_POS(node),
                       CXFSNPRB_NODE_IS_USED(node) ? "used" : "NOT used",
                       CXFSNPRB_NODE_IS_RED(node)  ? "red  " : "black",
                       CXFSNPRB_NODE_IS_USED(node) ? "data" : "next",
                       CXFSNPRB_NODE_IS_USED(node) ? CXFSNPRB_NODE_DATA(node) : CXFSNPRB_NODE_NEXT_POS(node)
                       );
    return;
}


STATIC_CAST static void __cxfsnprb_tree_rotate_left(CXFSNPRB_POOL *pool, const uint32_t node_pos, uint32_t *root_pos)
{
    CXFSNPRB_NODE *node;
    CXFSNPRB_NODE *right;

    uint32_t  right_pos;

    node  = CXFSNPRB_POOL_NODE(pool, node_pos);

    right_pos = CXFSNPRB_NODE_RIGHT_POS(node);
    right = CXFSNPRB_POOL_NODE(pool, right_pos);

    if(CXFSNPRB_ERR_POS != (CXFSNPRB_NODE_RIGHT_POS(node) = CXFSNPRB_NODE_LEFT_POS(right)))
    {
        CXFSNPRB_NODE *left;
        left = CXFSNPRB_POOL_NODE(pool, CXFSNPRB_NODE_LEFT_POS(right));
        CXFSNPRB_NODE_PARENT_POS(left) = node_pos;
    }
    CXFSNPRB_NODE_LEFT_POS(right) = node_pos;

    if(CXFSNPRB_ERR_POS != (CXFSNPRB_NODE_PARENT_POS(right) = CXFSNPRB_NODE_PARENT_POS(node)))
    {
        CXFSNPRB_NODE *parent;
        parent = CXFSNPRB_POOL_NODE(pool, CXFSNPRB_NODE_PARENT_POS(node));

        if (node_pos == CXFSNPRB_NODE_LEFT_POS(parent))
        {
            CXFSNPRB_NODE_LEFT_POS(parent) = right_pos;
        }
        else
        {
            CXFSNPRB_NODE_RIGHT_POS(parent) = right_pos;
        }
    }
    else
    {
        (*root_pos) = right_pos;
    }
    CXFSNPRB_NODE_PARENT_POS(node) = right_pos;
    return;
}

STATIC_CAST static void __cxfsnprb_tree_rotate_right(CXFSNPRB_POOL *pool, const uint32_t node_pos, uint32_t *root_pos)
{
    CXFSNPRB_NODE *node;
    CXFSNPRB_NODE *left;
    uint32_t  left_pos;

    node  = CXFSNPRB_POOL_NODE(pool, node_pos);

    left_pos = CXFSNPRB_NODE_LEFT_POS(node);
    left = CXFSNPRB_POOL_NODE(pool, left_pos);

    if (CXFSNPRB_ERR_POS != (CXFSNPRB_NODE_LEFT_POS(node) = CXFSNPRB_NODE_RIGHT_POS(left)))
    {
        CXFSNPRB_NODE *right;
        right = CXFSNPRB_POOL_NODE(pool, CXFSNPRB_NODE_RIGHT_POS(left));
        CXFSNPRB_NODE_PARENT_POS(right) = node_pos;
    }
    CXFSNPRB_NODE_RIGHT_POS(left) = node_pos;

    if (CXFSNPRB_ERR_POS != (CXFSNPRB_NODE_PARENT_POS(left) = CXFSNPRB_NODE_PARENT_POS(node)))
    {
        CXFSNPRB_NODE *parent;
        parent = CXFSNPRB_POOL_NODE(pool, CXFSNPRB_NODE_PARENT_POS(node));

        if (node_pos == CXFSNPRB_NODE_RIGHT_POS(parent))
        {
            CXFSNPRB_NODE_RIGHT_POS(parent) = left_pos;
        }
        else
        {
            CXFSNPRB_NODE_LEFT_POS(parent) = left_pos;
        }
    }
    else
    {
        (*root_pos) = left_pos;
    }
    CXFSNPRB_NODE_PARENT_POS(node) = left_pos;
    return;
}

STATIC_CAST static void __cxfsnprb_tree_insert_color(CXFSNPRB_POOL *pool, const uint32_t node_pos, uint32_t *root_pos)
{
    CXFSNPRB_NODE *node;
    CXFSNPRB_NODE *root;
    CXFSNPRB_NODE *parent;

    uint32_t  node_pos_t;

    node_pos_t = node_pos;
    node  = CXFSNPRB_POOL_NODE(pool, node_pos_t);

    while (NULL_PTR != (parent = CXFSNPRB_POOL_NODE(pool, CXFSNPRB_NODE_PARENT_POS(node))) /*parent is valid*/
         && CXFSNPRB_RED == CXFSNPRB_NODE_COLOR(parent))
    {
        uint32_t  parent_pos;
        uint32_t  gparent_pos;
        CXFSNPRB_NODE *gparent;

        parent_pos = CXFSNPRB_NODE_PARENT_POS(node);

        gparent_pos = CXFSNPRB_NODE_PARENT_POS(parent);
        ASSERT(CXFSNPRB_ERR_POS != gparent_pos);
        gparent = CXFSNPRB_POOL_NODE(pool, gparent_pos);

        if (parent_pos == CXFSNPRB_NODE_LEFT_POS(gparent))
        {
            {
                CXFSNPRB_NODE *uncle;
                if (NULL_PTR != (uncle = CXFSNPRB_POOL_NODE(pool, CXFSNPRB_NODE_RIGHT_POS(gparent))) /*uncle is valid*/
                   && CXFSNPRB_RED == CXFSNPRB_NODE_COLOR(uncle))
                {
                    CXFSNPRB_NODE_COLOR(uncle)   = CXFSNPRB_BLACK;
                    CXFSNPRB_NODE_COLOR(parent)  = CXFSNPRB_BLACK;
                    CXFSNPRB_NODE_COLOR(gparent) = CXFSNPRB_RED;

                    node = gparent;
                    node_pos_t = gparent_pos;
                    continue;
                }
            }

            if (CXFSNPRB_NODE_RIGHT_POS(parent) == node_pos_t)
            {
                __cxfsnprb_tree_rotate_left(pool, parent_pos, root_pos);
                XCHG(CXFSNPRB_NODE *, parent, node);
                XCHG(uint32_t, parent_pos, node_pos_t);
            }

            CXFSNPRB_NODE_COLOR(parent)  = CXFSNPRB_BLACK;
            CXFSNPRB_NODE_COLOR(gparent) = CXFSNPRB_RED;
            __cxfsnprb_tree_rotate_right(pool, gparent_pos, root_pos);
         }
         else
         {
            {
                CXFSNPRB_NODE *uncle;
                if (NULL_PTR != (uncle = CXFSNPRB_POOL_NODE(pool, CXFSNPRB_NODE_LEFT_POS(gparent))) /*uncle is valid*/
                    && CXFSNPRB_RED == CXFSNPRB_NODE_COLOR(uncle))
                {
                    CXFSNPRB_NODE_COLOR(uncle)   = CXFSNPRB_BLACK;
                    CXFSNPRB_NODE_COLOR(parent)  = CXFSNPRB_BLACK;
                    CXFSNPRB_NODE_COLOR(gparent) = CXFSNPRB_RED;

                    node = gparent;
                    node_pos_t = gparent_pos;
                    continue;
                }
            }

            if (CXFSNPRB_NODE_LEFT_POS(parent) == node_pos_t)
            {
                __cxfsnprb_tree_rotate_right(pool, parent_pos, root_pos);
                XCHG(CXFSNPRB_NODE *, parent, node);
                XCHG(uint32_t, parent_pos, node_pos_t);
            }

            CXFSNPRB_NODE_COLOR(parent)  = CXFSNPRB_BLACK;
            CXFSNPRB_NODE_COLOR(gparent) = CXFSNPRB_RED;
            __cxfsnprb_tree_rotate_left(pool, gparent_pos, root_pos);
        }
    }

    root = CXFSNPRB_POOL_NODE(pool, *root_pos);
    CXFSNPRB_NODE_COLOR(root) = CXFSNPRB_BLACK;
    return;
}

STATIC_CAST static void __cxfsnprb_tree_erase_color(CXFSNPRB_POOL *pool, const uint32_t node_pos, const uint32_t parent_pos, uint32_t *root_pos)
{
    CXFSNPRB_NODE *node;
    uint32_t  node_pos_t;
    uint32_t  parent_pos_t;

    node_pos_t   = node_pos;
    parent_pos_t = parent_pos;

    while ((NULL_PTR == (node = CXFSNPRB_POOL_NODE(pool, node_pos_t)) || CXFSNPRB_BLACK == CXFSNPRB_NODE_COLOR(node)) && node_pos_t != (*root_pos))
    {
        CXFSNPRB_NODE *parent;

        parent = CXFSNPRB_POOL_NODE(pool, parent_pos_t);

        if (CXFSNPRB_NODE_LEFT_POS(parent) == node_pos_t)
        {
            CXFSNPRB_NODE *other;
            CXFSNPRB_NODE *o_left;
            CXFSNPRB_NODE *o_right;
            uint32_t  other_pos;

            other_pos = CXFSNPRB_NODE_RIGHT_POS(parent);
            other = CXFSNPRB_POOL_NODE(pool, other_pos);

            if (CXFSNPRB_RED == CXFSNPRB_NODE_COLOR(other))
            {
                CXFSNPRB_NODE_COLOR(other)  = CXFSNPRB_BLACK;
                CXFSNPRB_NODE_COLOR(parent) = CXFSNPRB_RED;

                __cxfsnprb_tree_rotate_left(pool, parent_pos_t, root_pos);

                other_pos = CXFSNPRB_NODE_RIGHT_POS(parent);
                other = CXFSNPRB_POOL_NODE(pool, other_pos);
            }

            o_left = CXFSNPRB_POOL_NODE(pool, CXFSNPRB_NODE_LEFT_POS(other));
            o_right = CXFSNPRB_POOL_NODE(pool, CXFSNPRB_NODE_RIGHT_POS(other));

            if((NULL_PTR == o_left || CXFSNPRB_BLACK == CXFSNPRB_NODE_COLOR(o_left))
            && (NULL_PTR == o_right || CXFSNPRB_BLACK == CXFSNPRB_NODE_COLOR(o_right)))
            {
                CXFSNPRB_NODE_COLOR(other) = CXFSNPRB_RED;

                node_pos_t = parent_pos_t;
                node = CXFSNPRB_POOL_NODE(pool, node_pos_t);

                parent_pos_t = CXFSNPRB_NODE_PARENT_POS(node);
                parent = CXFSNPRB_POOL_NODE(pool, parent_pos_t);
            }
            else
            {
                if (NULL_PTR == o_right || CXFSNPRB_BLACK == CXFSNPRB_NODE_COLOR(o_right))
                {
                    if (NULL_PTR != o_left)
                    {
                        CXFSNPRB_NODE_COLOR(o_left) = CXFSNPRB_BLACK;
                    }
                    CXFSNPRB_NODE_COLOR(other) = CXFSNPRB_RED;

                    __cxfsnprb_tree_rotate_right(pool, other_pos, root_pos);

                    other_pos = CXFSNPRB_NODE_RIGHT_POS(parent);
                    other = CXFSNPRB_POOL_NODE(pool, other_pos);
                    /*note: other was changed here*/
                }

                CXFSNPRB_NODE_COLOR(other) = CXFSNPRB_NODE_COLOR(parent);
                CXFSNPRB_NODE_COLOR(parent) = CXFSNPRB_BLACK;

                /*due to other may be changed before, have to get o_right again here*/
                o_right = CXFSNPRB_POOL_NODE(pool, CXFSNPRB_NODE_RIGHT_POS(other));
                if (NULL_PTR != o_right)
                {
                    CXFSNPRB_NODE_COLOR(o_right) = CXFSNPRB_BLACK;
                }

                __cxfsnprb_tree_rotate_left(pool, parent_pos_t, root_pos);
                node_pos_t = (*root_pos);
                break;
            }
        }
        else
        {
            CXFSNPRB_NODE *other;
            CXFSNPRB_NODE *o_left;
            CXFSNPRB_NODE *o_right;
            uint32_t  other_pos;

            other_pos = CXFSNPRB_NODE_LEFT_POS(parent);
            other = CXFSNPRB_POOL_NODE(pool, other_pos);

            if (CXFSNPRB_RED == CXFSNPRB_NODE_COLOR(other))
            {
                CXFSNPRB_NODE_COLOR(other) = CXFSNPRB_BLACK;
                CXFSNPRB_NODE_COLOR(parent) = CXFSNPRB_RED;

                __cxfsnprb_tree_rotate_right(pool, parent_pos_t, root_pos);

                other_pos = CXFSNPRB_NODE_LEFT_POS(parent);
                other = CXFSNPRB_POOL_NODE(pool, other_pos);
            }

            o_left = CXFSNPRB_POOL_NODE(pool, CXFSNPRB_NODE_LEFT_POS(other));
            o_right = CXFSNPRB_POOL_NODE(pool, CXFSNPRB_NODE_RIGHT_POS(other));

            if ((NULL_PTR == o_left  || CXFSNPRB_BLACK == CXFSNPRB_NODE_COLOR(o_left))
             && (NULL_PTR == o_right || CXFSNPRB_BLACK == CXFSNPRB_NODE_COLOR(o_right)))
            {
                CXFSNPRB_NODE_COLOR(other) = CXFSNPRB_RED;

                node_pos_t = parent_pos_t;
                node = CXFSNPRB_POOL_NODE(pool, node_pos_t);

                parent_pos_t = CXFSNPRB_NODE_PARENT_POS(node);
                parent = CXFSNPRB_POOL_NODE(pool, parent_pos_t);
            }
            else
            {
                if (NULL_PTR == o_left  || CXFSNPRB_BLACK == CXFSNPRB_NODE_COLOR(o_left))
                {
                    if (NULL_PTR != o_right)
                    {
                        CXFSNPRB_NODE_COLOR(o_right) = CXFSNPRB_BLACK;
                    }

                    CXFSNPRB_NODE_COLOR(other) = CXFSNPRB_RED;

                    __cxfsnprb_tree_rotate_left(pool, other_pos, root_pos);

                    other_pos = CXFSNPRB_NODE_LEFT_POS(parent);
                    other = CXFSNPRB_POOL_NODE(pool, other_pos);
                    /*note: other was changed here*/
                }

                CXFSNPRB_NODE_COLOR(other) = CXFSNPRB_NODE_COLOR(parent);
                CXFSNPRB_NODE_COLOR(parent) = CXFSNPRB_BLACK;

                /*due to other may be changed before, have to get o_left again here*/
                o_left = CXFSNPRB_POOL_NODE(pool, CXFSNPRB_NODE_LEFT_POS(other));
                if (NULL_PTR != o_left)
                {
                    CXFSNPRB_NODE_COLOR(o_left) = CXFSNPRB_BLACK;
                }
                __cxfsnprb_tree_rotate_right(pool, parent_pos_t, root_pos);
                node_pos_t = (*root_pos);
                break;
            }
        }
    }

    node = CXFSNPRB_POOL_NODE(pool, node_pos_t);
    if (NULL_PTR != node)
    {
        CXFSNPRB_NODE_COLOR(node) = CXFSNPRB_BLACK;
    }
    return;
}

/*note: erase from tree but not recycle to free nodes pool*/
EC_BOOL cxfsnprb_tree_erase(CXFSNPRB_POOL *pool, const uint32_t node_pos, uint32_t *root_pos)
{
    CXFSNPRB_NODE *node;

    uint32_t node_pos_t;
    uint32_t child_pos;
    uint32_t parent_pos;
    uint32_t color;

    node_pos_t = node_pos;
    node = CXFSNPRB_POOL_NODE(pool, node_pos_t);

    ASSERT(NULL_PTR != node);
    ASSERT(CXFSNPRB_NODE_IS_USED(node));

    if (CXFSNPRB_ERR_POS == CXFSNPRB_NODE_LEFT_POS(node))
    {
        child_pos = CXFSNPRB_NODE_RIGHT_POS(node);
    }
    else if (CXFSNPRB_ERR_POS == CXFSNPRB_NODE_RIGHT_POS(node))
    {
        child_pos = CXFSNPRB_NODE_LEFT_POS(node);
    }
    else
    {
        CXFSNPRB_NODE *old;

        uint32_t old_pos;
        uint32_t left_pos;

        old_pos = node_pos_t;

        node_pos_t = CXFSNPRB_NODE_RIGHT_POS(node);
        node = CXFSNPRB_POOL_NODE(pool, node_pos_t);

        while (CXFSNPRB_ERR_POS != (left_pos = CXFSNPRB_NODE_LEFT_POS(node)))
        {
            node_pos_t = left_pos;
            node = CXFSNPRB_POOL_NODE(pool, node_pos_t);

        }

        child_pos  = CXFSNPRB_NODE_RIGHT_POS(node);
        parent_pos = CXFSNPRB_NODE_PARENT_POS(node);
        color      = CXFSNPRB_NODE_COLOR(node);

        if (CXFSNPRB_ERR_POS != child_pos)
        {
            CXFSNPRB_NODE *child;
            child = CXFSNPRB_POOL_NODE(pool, child_pos);
            CXFSNPRB_NODE_PARENT_POS(child) = parent_pos;
        }

        if (CXFSNPRB_ERR_POS != parent_pos)
        {
            CXFSNPRB_NODE *parent;

            parent = CXFSNPRB_POOL_NODE(pool, parent_pos);
            if (CXFSNPRB_NODE_LEFT_POS(parent) == node_pos_t)
            {
                CXFSNPRB_NODE_LEFT_POS(parent) = child_pos;
            }
            else
            {
                CXFSNPRB_NODE_RIGHT_POS(parent) = child_pos;
            }
        }
        else
        {
            (*root_pos) = child_pos;
        }

        if (CXFSNPRB_NODE_PARENT_POS(node) == old_pos)
        {
            parent_pos = node_pos_t;
        }

        old  = CXFSNPRB_POOL_NODE(pool, old_pos);

        CXFSNPRB_NODE_PARENT_POS(node) = CXFSNPRB_NODE_PARENT_POS(old);
        CXFSNPRB_NODE_COLOR(node)      = CXFSNPRB_NODE_COLOR(old);
        CXFSNPRB_NODE_RIGHT_POS(node)  = CXFSNPRB_NODE_RIGHT_POS(old);
        CXFSNPRB_NODE_LEFT_POS(node)   = CXFSNPRB_NODE_LEFT_POS(old);

        if (CXFSNPRB_ERR_POS != CXFSNPRB_NODE_PARENT_POS(old))
        {
            CXFSNPRB_NODE *old_parent;
            old_parent = CXFSNPRB_POOL_NODE(pool, CXFSNPRB_NODE_PARENT_POS(old));

            if (CXFSNPRB_NODE_LEFT_POS(old_parent) == old_pos)
            {
                CXFSNPRB_NODE_LEFT_POS(old_parent) = node_pos_t;
            }
            else
            {
                CXFSNPRB_NODE_RIGHT_POS(old_parent) = node_pos_t;
            }
        }
        else
        {
            (*root_pos) = node_pos_t;
        }

        {
            CXFSNPRB_NODE *old_left;

            old_left = CXFSNPRB_POOL_NODE(pool, CXFSNPRB_NODE_LEFT_POS(old));
            CXFSNPRB_NODE_PARENT_POS(old_left) = node_pos_t;
        }

        if (CXFSNPRB_ERR_POS != CXFSNPRB_NODE_RIGHT_POS(old))
        {
            CXFSNPRB_NODE *old_right;
            old_right = CXFSNPRB_POOL_NODE(pool, CXFSNPRB_NODE_RIGHT_POS(old));
            CXFSNPRB_NODE_PARENT_POS(old_right) = node_pos_t;
        }
        goto color;
    }

    parent_pos = CXFSNPRB_NODE_PARENT_POS(node);
    color = CXFSNPRB_NODE_COLOR(node);

    if (CXFSNPRB_ERR_POS != child_pos)
    {
        CXFSNPRB_NODE *child;
        child = CXFSNPRB_POOL_NODE(pool, child_pos);
        CXFSNPRB_NODE_PARENT_POS(child) = parent_pos;
    }

    if (CXFSNPRB_ERR_POS != parent_pos)
    {
        CXFSNPRB_NODE *parent;

        parent = CXFSNPRB_POOL_NODE(pool, parent_pos);
        if (CXFSNPRB_NODE_LEFT_POS(parent) == node_pos_t)
        {
            CXFSNPRB_NODE_LEFT_POS(parent) = child_pos;
        }
        else
        {
            CXFSNPRB_NODE_RIGHT_POS(parent) = child_pos;
        }
    }
    else
    {
        (*root_pos) = child_pos;
    }

 color:
    if (CXFSNPRB_BLACK == color)
    {
        __cxfsnprb_tree_erase_color(pool, child_pos, parent_pos, root_pos);
    }
    return (EC_TRUE);
}

STATIC_CAST static uint32_t __cxfsnprb_tree_count_node_num(const CXFSNPRB_POOL *pool, const uint32_t node_pos)
{
    const CXFSNPRB_NODE *node;

    if(CXFSNPRB_ERR_POS == node_pos)
    {
        return ((uint32_t)0);
    }

    node = CXFSNPRB_POOL_NODE(pool, node_pos);

    return (uint32_t)(1 + __cxfsnprb_tree_count_node_num(pool, CXFSNPRB_NODE_LEFT_POS(node)) + __cxfsnprb_tree_count_node_num(pool, CXFSNPRB_NODE_RIGHT_POS(node)));
}

uint32_t cxfsnprb_tree_count_node_num(const CXFSNPRB_POOL *pool, const uint32_t root_pos)
{
    return __cxfsnprb_tree_count_node_num(pool, root_pos);
}

uint32_t cxfsnprb_tree_node_max_num(const CXFSNPRB_POOL *pool)
{
    return CXFSNPRB_POOL_NODE_MAX_NUM(pool);
}

uint32_t cxfsnprb_tree_node_used_num(const CXFSNPRB_POOL *pool)
{
    return CXFSNPRB_POOL_NODE_USED_NUM(pool);
}

uint32_t cxfsnprb_tree_node_sizeof(const CXFSNPRB_POOL *pool)
{
    return CXFSNPRB_POOL_NODE_SIZEOF(pool);
}

/*
 * This function returns the first node_pos (in sort order) of the tree.
 */
uint32_t cxfsnprb_tree_first_node(const CXFSNPRB_POOL *pool, const uint32_t root_pos)
{
    uint32_t  node_pos;
    const CXFSNPRB_NODE *node;

    node_pos = root_pos;
    if (CXFSNPRB_ERR_POS == node_pos)
    {
        return (CXFSNPRB_ERR_POS);
    }

    node = CXFSNPRB_POOL_NODE(pool, node_pos);

    while (CXFSNPRB_ERR_POS != CXFSNPRB_NODE_LEFT_POS(node))
    {
        node_pos = CXFSNPRB_NODE_LEFT_POS(node);
        node = CXFSNPRB_POOL_NODE(pool, node_pos);
    }
    return (node_pos);
}

uint32_t cxfsnprb_tree_last_node(const CXFSNPRB_POOL *pool, const uint32_t root_pos)
{
    uint32_t  node_pos;
    const CXFSNPRB_NODE *node;

    node_pos = root_pos;
    if (CXFSNPRB_ERR_POS == node_pos)
    {
        return (CXFSNPRB_ERR_POS);
    }

    node = CXFSNPRB_POOL_NODE(pool, node_pos);

    while (CXFSNPRB_ERR_POS != CXFSNPRB_NODE_RIGHT_POS(node))
    {
        node_pos = CXFSNPRB_NODE_RIGHT_POS(node);
        node = CXFSNPRB_POOL_NODE(pool, node_pos);
    }

    return (node_pos);
}

uint32_t cxfsnprb_tree_next_node(const CXFSNPRB_POOL *pool, const uint32_t node_pos)
{
    uint32_t node_pos_t;
    const CXFSNPRB_NODE *node;
    const CXFSNPRB_NODE *parent;

    node_pos_t = node_pos;
    node = CXFSNPRB_POOL_NODE(pool, node_pos_t);
    /* If we have a right-hand child, go down and then left as far
       as we can. */
    if (CXFSNPRB_ERR_POS != CXFSNPRB_NODE_RIGHT_POS(node))
    {
        node_pos_t = CXFSNPRB_NODE_RIGHT_POS(node);
        node = CXFSNPRB_POOL_NODE(pool, node_pos_t);
        while (CXFSNPRB_ERR_POS != CXFSNPRB_NODE_LEFT_POS(node))
        {
            node_pos_t = CXFSNPRB_NODE_LEFT_POS(node);
            node = CXFSNPRB_POOL_NODE(pool, node_pos_t);
        }
        return (node_pos_t);
    }

    /* No right-hand children.  Everything down and left is
       smaller than us, so any 'next' node_pos_t must be in the general
       direction of our parent. Go up the tree; any time the
       ancestor is a right-hand child of its parent, keep going
       up. First time it's a left-hand child of its parent, said
       parent is our 'next' node_pos_t. */
    while (NULL_PTR != (parent = CXFSNPRB_POOL_NODE(pool, CXFSNPRB_NODE_PARENT_POS(node))) && node_pos_t == CXFSNPRB_NODE_RIGHT_POS(parent))
    {
        node_pos_t = CXFSNPRB_NODE_PARENT_POS(node);
        node = parent;
    }

    return (CXFSNPRB_NODE_PARENT_POS(node));
}

uint32_t cxfsnprb_tree_prev_node(const CXFSNPRB_POOL *pool, const uint32_t node_pos)
{
    uint32_t node_pos_t;
    const CXFSNPRB_NODE *node;
    const CXFSNPRB_NODE *parent;

    node_pos_t = node_pos;
    node = CXFSNPRB_POOL_NODE(pool, node_pos_t);

    /* If we have a left-hand child, go down and then right as far
       as we can. */
    if (CXFSNPRB_ERR_POS != CXFSNPRB_NODE_LEFT_POS(node))
    {
        node_pos_t = CXFSNPRB_NODE_LEFT_POS(node);
        node = CXFSNPRB_POOL_NODE(pool, node_pos_t);
        while (CXFSNPRB_ERR_POS != CXFSNPRB_NODE_RIGHT_POS(node))
        {
            node_pos_t = CXFSNPRB_NODE_RIGHT_POS(node);
            node = CXFSNPRB_POOL_NODE(pool, node_pos_t);
        }
        return (node_pos_t);
    }

    /* No left-hand children. Go up till we find an ancestor which
       is a right-hand child of its parent */
    while (NULL_PTR != (parent = CXFSNPRB_POOL_NODE(pool, CXFSNPRB_NODE_PARENT_POS(node))) && node_pos_t == CXFSNPRB_NODE_LEFT_POS(parent))
    {
        node_pos_t = CXFSNPRB_NODE_PARENT_POS(node);
        node = parent;
    }

    return (CXFSNPRB_NODE_PARENT_POS(node));
}

/*victim_pos should be free*/
void cxfsnprb_tree_replace_node(CXFSNPRB_POOL *pool, const uint32_t victim_pos, const uint32_t new_pos, uint32_t *root_pos)
{
    CXFSNPRB_NODE *victim;

    victim = CXFSNPRB_POOL_NODE(pool, victim_pos);

    /* Set the surrounding nodes to point to the replacement */
    if (CXFSNPRB_ERR_POS != CXFSNPRB_NODE_PARENT_POS(victim))
    {
        CXFSNPRB_NODE *parent;
        parent = CXFSNPRB_POOL_NODE(pool, CXFSNPRB_NODE_PARENT_POS(victim));

        if (victim_pos == CXFSNPRB_NODE_LEFT_POS(parent))
        {
            CXFSNPRB_NODE_LEFT_POS(parent) = new_pos;
        }
        else
        {
            CXFSNPRB_NODE_RIGHT_POS(parent) = new_pos;
        }
    }
    else
    {
        (*root_pos) = new_pos;
    }

    if (CXFSNPRB_ERR_POS != CXFSNPRB_NODE_LEFT_POS(victim))
    {
        CXFSNPRB_NODE *left;
        left = CXFSNPRB_POOL_NODE(pool, CXFSNPRB_NODE_LEFT_POS(victim));
        CXFSNPRB_NODE_PARENT_POS(left) = new_pos;
    }
    if (CXFSNPRB_ERR_POS != CXFSNPRB_NODE_RIGHT_POS(victim))
    {
        CXFSNPRB_NODE *right;
        right = CXFSNPRB_POOL_NODE(pool, CXFSNPRB_NODE_RIGHT_POS(victim));
        CXFSNPRB_NODE_PARENT_POS(right) = new_pos;
    }

    return;
}

/**
*
*   note:only for cxfsnp item!
*   return -1 if node < (data, key)
*   return  1 if node > (data, key)
*   return  0 if node == (data, key)
*
**/
STATIC_CAST static int __cxfsnprb_node_data_cmp(const CXFSNPRB_NODE *node, const uint32_t data, const uint32_t klen, const uint8_t *key)
{
    const CXFSNP_ITEM *item;

    if (CXFSNPRB_NODE_DATA(node) < data)
    {
        return (-1);
    }

    if (CXFSNPRB_NODE_DATA(node) > data)
    {
        return (1);
    }

    item = (const CXFSNP_ITEM *)CXFSNP_RB_NODE_ITEM(node);
    if(CXFSNP_ITEM_KLEN(item) < klen)
    {
        return (-1);
    }

    if(CXFSNP_ITEM_KLEN(item) > klen)
    {
        return (1);
    }

    return BCMP(CXFSNP_ITEM_KNAME(item), key, klen);
}

/*return the searched pos*/
uint32_t cxfsnprb_tree_search_data(const CXFSNPRB_POOL *pool, const uint32_t root_pos, const uint32_t data, const uint32_t klen, const uint8_t *key)
{
    uint32_t node_pos;

    node_pos = root_pos;

    while (CXFSNPRB_ERR_POS != node_pos)
    {
        const CXFSNPRB_NODE *node;
        int cmp_ret;

        node = CXFSNPRB_POOL_NODE(pool, node_pos);
        cmp_ret = __cxfsnprb_node_data_cmp(node, data, klen, key);

        if (0 < cmp_ret)/*node > (data, key)*/
        {
            node_pos = CXFSNPRB_NODE_LEFT_POS(node);
        }
        else if (0 > cmp_ret)/*node < (data, key)*/
        {
            node_pos = CXFSNPRB_NODE_RIGHT_POS(node);
        }
        else /*node == (data, key)*/
        {
            return (node_pos);
        }
    }

    return (CXFSNPRB_ERR_POS);
}

/*if found duplicate node, return EC_FALSE, otherwise return EC_TRUE*/
EC_BOOL cxfsnprb_tree_insert_data(CXFSNPRB_POOL *pool, uint32_t *root_pos, const uint32_t data, const uint32_t klen, const uint8_t *key, uint32_t *insert_pos)
{
    uint32_t  node_pos_t;
    uint32_t  new_pos_t;
    uint32_t  parent_pos_t;
    uint32_t  flag; /*0: on left subtree, 1: on right subtree*/

    node_pos_t   = (*root_pos);
    parent_pos_t = CXFSNPRB_ERR_POS;
    flag         = ~(uint32_t)0;

    while (CXFSNPRB_ERR_POS != node_pos_t)
    {
        CXFSNPRB_NODE *node;
        int cmp_ret;

        node = CXFSNPRB_POOL_NODE(pool, node_pos_t);
        cmp_ret = __cxfsnprb_node_data_cmp(node, data, klen, key);

        parent_pos_t = node_pos_t;

        if (0 < cmp_ret)/*node > (data, key)*/
        {
            node_pos_t = CXFSNPRB_NODE_LEFT_POS(node);
            flag = 0;
        }
        else if (0 > cmp_ret)/*node < (data, key)*/
        {
            node_pos_t = CXFSNPRB_NODE_RIGHT_POS(node);
            flag = 1;
        }
        else/*node == (data, key)*/
        {
            (*insert_pos) = node_pos_t;
            return (EC_FALSE);/*found duplicate*/
        }
    }


    /*not found data in the rbtree*/
    new_pos_t = cxfsnprb_node_new(pool);
    if(CXFSNPRB_ERR_POS == new_pos_t)
    {
        (*insert_pos) = CXFSNPRB_ERR_POS;
        return (EC_FALSE);
    }
    else
    {
        CXFSNPRB_NODE *node;

        node  = CXFSNPRB_POOL_NODE(pool, new_pos_t);
        CXFSNPRB_NODE_DATA(node) = data;

        CXFSNPRB_NODE_PARENT_POS(node) = parent_pos_t;
        CXFSNPRB_NODE_COLOR(node)      = CXFSNPRB_RED;
        CXFSNPRB_NODE_LEFT_POS(node)   = CXFSNPRB_ERR_POS;
        CXFSNPRB_NODE_RIGHT_POS(node)  = CXFSNPRB_ERR_POS;

        if(CXFSNPRB_ERR_POS == (*root_pos))
        {
            (*root_pos) = new_pos_t;
        }
        else
        {
            CXFSNPRB_NODE *parent;
            parent  = CXFSNPRB_POOL_NODE(pool, parent_pos_t);

            if(0 == flag)/*on left subtree*/
            {
                CXFSNPRB_NODE_LEFT_POS(parent) = new_pos_t;
            }
            else
            {
                CXFSNPRB_NODE_RIGHT_POS(parent) = new_pos_t;
            }
        }
        __cxfsnprb_tree_insert_color(pool, new_pos_t, root_pos);
    }

    (*insert_pos) = new_pos_t;
    return (EC_TRUE); /*it is new node*/
}

EC_BOOL cxfsnprb_tree_delete_data(CXFSNPRB_POOL *pool, uint32_t *root_pos, const uint32_t data, const uint32_t klen, const uint8_t *key, uint32_t *delete_pos)
{
    uint32_t node_pos;

    node_pos = cxfsnprb_tree_search_data(pool, *root_pos, data, klen, key);
    if(CXFSNPRB_ERR_POS == node_pos)
    {
        return (EC_FALSE);
    }

    cxfsnprb_tree_erase(pool, node_pos, root_pos);
    cxfsnprb_node_free(pool, node_pos);

    (*delete_pos) = node_pos;
    return (EC_TRUE);
}


EC_BOOL cxfsnprb_tree_delete(CXFSNPRB_POOL *pool, uint32_t *root_pos, const uint32_t node_pos)
{
    cxfsnprb_tree_erase(pool, node_pos, root_pos);
    cxfsnprb_node_free(pool, node_pos);
    return (EC_TRUE);
}


/*postorder: left -> right -> root*/
STATIC_CAST static void __cxfsnprb_tree_free(CXFSNPRB_POOL *pool, const uint32_t node_pos)
{
    CXFSNPRB_NODE *node;

    if(CXFSNPRB_ERR_POS == node_pos)
    {
        return;
    }

    node  = CXFSNPRB_POOL_NODE(pool, node_pos);
    if(CXFSNPRB_ERR_POS != CXFSNPRB_NODE_LEFT_POS(node))
    {
        __cxfsnprb_tree_free(pool, CXFSNPRB_NODE_LEFT_POS(node));
    }

    if(CXFSNPRB_ERR_POS != CXFSNPRB_NODE_RIGHT_POS(node))
    {
        __cxfsnprb_tree_free(pool, CXFSNPRB_NODE_RIGHT_POS(node));
    }

    cxfsnprb_node_free(pool, node_pos);

    return;
}
void cxfsnprb_tree_free(CXFSNPRB_POOL *pool, const uint32_t root_pos)
{
    __cxfsnprb_tree_free(pool, root_pos);
    return;
}

EC_BOOL cxfsnprb_pool_init(CXFSNPRB_POOL *pool, const uint32_t node_max_num, const uint32_t node_sizeof)
{
    uint32_t node_pos;

    if(CXFSNPRB_POOL_MAX_SIZE < node_max_num)
    {
        dbg_log(SEC_0198_CXFSNPRB, 0)(LOGSTDERR, "error:cxfsnprb_pool_init: node_max_num %u overflow!\n", node_max_num);
        return (EC_FALSE);
    }

    CXFSNPRB_POOL_NODE_MAX_NUM(pool)  = node_max_num;
    CXFSNPRB_POOL_NODE_USED_NUM(pool) = 0;
    CXFSNPRB_POOL_NODE_SIZEOF(pool)   = node_sizeof;

    for(node_pos = 0; node_pos < node_max_num; node_pos ++)
    {
        cxfsnprb_node_init(pool, node_pos);
        cxfsnprb_node_set_next(pool, node_pos, node_pos + 1);

        if(0 == ((node_pos + 1) % 100000))
        {
            dbg_log(SEC_0198_CXFSNPRB, 0)(LOGSTDOUT, "info:cxfsnprb_pool_init: init node %u - %u of max %u done\n",
                               node_pos - 99999, node_pos, node_max_num);
        }
    }
    dbg_log(SEC_0198_CXFSNPRB, 0)(LOGSTDOUT, "info:cxfsnprb_pool_init: init %u nodes done\n", node_max_num);
    cxfsnprb_node_set_next(pool, node_max_num - 1, CXFSNPRB_ERR_POS);/*overwrite the last one*/

    CXFSNPRB_POOL_FREE_HEAD(pool) = 0;/*the free nodes head*/
    return (EC_TRUE);
}

void cxfsnprb_pool_clean(CXFSNPRB_POOL *pool)
{
    CXFSNPRB_POOL_NODE_MAX_NUM(pool)  = 0;
    CXFSNPRB_POOL_FREE_HEAD(pool)     = CXFSNPRB_ERR_POS;
    return;
}

void cxfsnprb_pool_print(LOG *log, const CXFSNPRB_POOL *pool)
{
    uint32_t node_pos;
    uint32_t node_max_num;

    node_max_num = CXFSNPRB_POOL_NODE_MAX_NUM(pool);

    sys_log(log, "pool %lx, node_max_num %u, node_used_num %u, free_head %u, node_sizeof = %u\n",
                 pool,
                 node_max_num,
                 CXFSNPRB_POOL_NODE_USED_NUM(pool),
                 CXFSNPRB_POOL_FREE_HEAD(pool),
                 CXFSNPRB_POOL_NODE_SIZEOF(pool));

    if(0)
    {
        for(node_pos = 0; node_pos < node_max_num; node_pos ++)
        {
            if(EC_TRUE == cxfsnprb_node_is_used(pool, node_pos))
            {
                cxfsnprb_node_print(log, pool, node_pos);
            }
        }
    }
    return;
}


EC_BOOL cxfsnprb_pool_is_empty(const CXFSNPRB_POOL *pool)
{
    if (0 == CXFSNPRB_POOL_NODE_USED_NUM(pool))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL cxfsnprb_pool_is_full(const CXFSNPRB_POOL *pool)
{
    if (CXFSNPRB_POOL_NODE_MAX_NUM(pool) == CXFSNPRB_POOL_NODE_USED_NUM(pool))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

/*visit the root node first: root -> left -> right*/
void cxfsnprb_preorder_print(LOG *log, const CXFSNPRB_POOL *pool, const uint32_t node_pos)
{
    const CXFSNPRB_NODE *node;

    if(CXFSNPRB_ERR_POS == node_pos)
    {
        return;
    }

    node  = CXFSNPRB_POOL_NODE(pool, node_pos);
    cxfsnprb_node_print(log, pool, node_pos);

    if(CXFSNPRB_ERR_POS != CXFSNPRB_NODE_LEFT_POS(node))
    {
        cxfsnprb_preorder_print(log, pool, CXFSNPRB_NODE_LEFT_POS(node));
    }

    if(CXFSNPRB_ERR_POS != CXFSNPRB_NODE_RIGHT_POS(node))
    {
        cxfsnprb_preorder_print(log, pool, CXFSNPRB_NODE_RIGHT_POS(node));
    }

    return;
}

/*visit the left subtree, then the root node: left -> root -> right*/
void cxfsnprb_inorder_print(LOG *log, const CXFSNPRB_POOL *pool, const uint32_t node_pos)
{
    const CXFSNPRB_NODE *node;

    if(CXFSNPRB_ERR_POS == node_pos)
    {
        return;
    }

    node  = CXFSNPRB_POOL_NODE(pool, node_pos);
    if(CXFSNPRB_ERR_POS != CXFSNPRB_NODE_LEFT_POS(node))
    {
        cxfsnprb_inorder_print(log, pool, CXFSNPRB_NODE_LEFT_POS(node));
    }

    cxfsnprb_node_print(log, pool, node_pos);

    if(CXFSNPRB_ERR_POS != CXFSNPRB_NODE_RIGHT_POS(node))
    {
        cxfsnprb_inorder_print(log, pool, CXFSNPRB_NODE_RIGHT_POS(node));
    }

    return;
}

/*visit the root node last: left -> right -> root*/
void cxfsnprb_postorder_print(LOG *log, const CXFSNPRB_POOL *pool, const uint32_t node_pos)
{
    const CXFSNPRB_NODE *node;

    if(CXFSNPRB_ERR_POS == node_pos)
    {
        return;
    }

    node  = CXFSNPRB_POOL_NODE(pool, node_pos);
    if(CXFSNPRB_ERR_POS != CXFSNPRB_NODE_LEFT_POS(node))
    {
        cxfsnprb_postorder_print(log, pool, CXFSNPRB_NODE_LEFT_POS(node));
    }

    if(CXFSNPRB_ERR_POS != CXFSNPRB_NODE_RIGHT_POS(node))
    {
        cxfsnprb_postorder_print(log, pool, CXFSNPRB_NODE_RIGHT_POS(node));
    }

    cxfsnprb_node_print(log, pool, node_pos);

    return;
}


/*visit the root node first: root -> left -> right*/
void cxfsnprb_preorder_print_level(LOG *log, const CXFSNPRB_POOL *pool, const uint32_t node_pos, const uint32_t level)
{
    const CXFSNPRB_NODE *node;

    if(CXFSNPRB_ERR_POS == node_pos)
    {
        return;
    }

    node  = CXFSNPRB_POOL_NODE(pool, node_pos);
    cxfsnprb_node_print_level(log, pool, node_pos, level);

    if(CXFSNPRB_ERR_POS != CXFSNPRB_NODE_LEFT_POS(node))
    {
        cxfsnprb_preorder_print_level(log, pool, CXFSNPRB_NODE_LEFT_POS(node), level + 1);
    }

    if(CXFSNPRB_ERR_POS != CXFSNPRB_NODE_RIGHT_POS(node))
    {
        cxfsnprb_preorder_print_level(log, pool, CXFSNPRB_NODE_RIGHT_POS(node), level + 1);
    }

    return;
}

EC_BOOL cxfsnprb_flush_size(const CXFSNPRB_POOL *pool, UINT32 *size)
{
    (*size) += sizeof(CXFSNPRB_POOL) + CXFSNPRB_POOL_NODE_MAX_NUM(pool) * CXFSNPRB_POOL_NODE_SIZEOF(pool);
    return (EC_TRUE);
}

EC_BOOL cxfsnprb_flush(const CXFSNPRB_POOL *pool, int fd, UINT32 *offset)
{
    UINT32 osize;/*write once size*/

    /*flush free_head*/
    osize = sizeof(uint32_t);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(CXFSNPRB_POOL_FREE_HEAD(pool))))
    {
        dbg_log(SEC_0198_CXFSNPRB, 0)(LOGSTDOUT, "error:cxfsnprb_flush: write CXFSNPRB_POOL_FREE_HEAD at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*flush node_max_num*/
    osize  = sizeof(uint32_t);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(CXFSNPRB_POOL_NODE_MAX_NUM(pool))))
    {
        dbg_log(SEC_0198_CXFSNPRB, 0)(LOGSTDOUT, "error:cxfsnprb_flush: write CXFSNPRB_POOL_NODE_MAX_NUM at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*flush node_used_num*/
    osize  = sizeof(uint32_t);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(CXFSNPRB_POOL_NODE_USED_NUM(pool))))
    {
        dbg_log(SEC_0198_CXFSNPRB, 0)(LOGSTDOUT, "error:cxfsnprb_flush: write CXFSNPRB_POOL_NODE_USED_NUM at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*flush node_sizeof*/
    osize  = sizeof(uint32_t);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(CXFSNPRB_POOL_NODE_SIZEOF(pool))))
    {
        dbg_log(SEC_0198_CXFSNPRB, 0)(LOGSTDOUT, "error:cxfsnprb_flush: write CXFSNPRB_POOL_NODE_SIZEOF at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*flush rb_node table*/
    osize  = CXFSNPRB_POOL_NODE_MAX_NUM(pool) * CXFSNPRB_POOL_NODE_SIZEOF(pool);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)CXFSNPRB_POOL_NODE_TBL(pool)))
    {
        dbg_log(SEC_0198_CXFSNPRB, 0)(LOGSTDOUT, "error:cxfsnprb_flush: write CXFSNPRB_POOL_NODE_TBL at offset %ld of fd %d failed where CXFSNPRB_POOL_NODE_MAX_NUM is %u\n",
                            (*offset), fd, CXFSNPRB_POOL_NODE_MAX_NUM(pool));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cxfsnprb_load(CXFSNPRB_POOL *pool, int fd, UINT32 *offset)
{
    UINT32 osize;/*read once size*/
    uint32_t node_max_num;
    uint32_t node_used_num;
    uint32_t node_sizeof;

    /*load free_head*/
    osize = sizeof(uint32_t);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(CXFSNPRB_POOL_FREE_HEAD(pool))))
    {
        dbg_log(SEC_0198_CXFSNPRB, 0)(LOGSTDOUT, "error:cxfsnprb_load: load CXFSNPRB_POOL_FREE_HEAD at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*load node_max_num*/
    osize  = sizeof(uint32_t);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(node_max_num)))
    {
        dbg_log(SEC_0198_CXFSNPRB, 0)(LOGSTDOUT, "error:cxfsnprb_load: load CXFSNPRB_POOL_NODE_MAX_NUM at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }
    CXFSNPRB_POOL_NODE_MAX_NUM(pool) = node_max_num;

    /*load node_used_num*/
    osize  = sizeof(uint32_t);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(node_used_num)))
    {
        dbg_log(SEC_0198_CXFSNPRB, 0)(LOGSTDOUT, "error:cxfsnprb_load: load CXFSNPRB_POOL_NODE_USED_NUM at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }
    CXFSNPRB_POOL_NODE_MAX_NUM(pool) = node_used_num;

    /*load node_sizeof*/
    osize  = sizeof(uint32_t);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(node_sizeof)))
    {
        dbg_log(SEC_0198_CXFSNPRB, 0)(LOGSTDOUT, "error:cxfsnprb_load: load CXFSNPRB_POOL_NODE_SIZEOF at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }
    CXFSNPRB_POOL_NODE_SIZEOF(pool) = node_sizeof;

    /*load rb_node table*/
    osize  = CXFSNPRB_POOL_NODE_MAX_NUM(pool) * CXFSNPRB_POOL_NODE_SIZEOF(pool);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)CXFSNPRB_POOL_NODE_TBL(pool)))
    {
        dbg_log(SEC_0198_CXFSNPRB, 0)(LOGSTDOUT, "error:cxfsnprb_load: load CXFSNPRB_POOL_NODE_TBL at offset %ld of fd %d failed where CXFSNPRB_POOL_NODE_MAX_NUM is %u\n",
                            (*offset), fd, CXFSNPRB_POOL_NODE_MAX_NUM(pool));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

void cxfsnprb_tree_print(LOG *log, const CXFSNPRB_POOL *pool, const uint32_t root_pos)
{
    uint32_t node_pos;

    sys_log(log, "[root = %5d]\n", root_pos);
    for(node_pos = cxfsnprb_tree_first_node(pool, root_pos); CXFSNPRB_ERR_POS != node_pos; node_pos = cxfsnprb_tree_next_node(pool, node_pos))
    {
        cxfsnprb_node_print(log, pool, node_pos);
    }
    return;
}

/* ---- debug ---- */
EC_BOOL cxfsnprb_node_debug_cmp(const CXFSNPRB_NODE *node_1st, const CXFSNPRB_NODE *node_2nd, int (*node_cmp_data)(const CXFSNPRB_NODE *, const CXFSNPRB_NODE *))
{
    if(CXFSNPRB_NODE_USED_FLAG(node_1st) != CXFSNPRB_NODE_USED_FLAG(node_2nd))
    {
        dbg_log(SEC_0198_CXFSNPRB, 0)(LOGSTDERR, "error:cxfsnprb_node_debug_cmp: inconsistent CXFSNPRB_NODE_USED_FLAG: %u != %u\n",
                            CXFSNPRB_NODE_USED_FLAG(node_1st), CXFSNPRB_NODE_USED_FLAG(node_2nd));
        return (EC_FALSE);
    }
#if 0
    if(CXFSNPRB_NODE_NOT_USED == CXFSNPRB_NODE_USED_FLAG(node_1st))
    {
        return (EC_TRUE);
    }
#endif

    if(CXFSNPRB_NODE_COLOR(node_1st) != CXFSNPRB_NODE_COLOR(node_2nd))
    {
        dbg_log(SEC_0198_CXFSNPRB, 0)(LOGSTDERR, "error:cxfsnprb_node_debug_cmp: inconsistent CXFSNPRB_NODE_COLOR: %u != %u\n",
                            CXFSNPRB_NODE_COLOR(node_1st), CXFSNPRB_NODE_COLOR(node_2nd));
        return (EC_FALSE);
    }

    if(CXFSNPRB_NODE_PARENT_POS(node_1st) != CXFSNPRB_NODE_PARENT_POS(node_2nd))
    {
        dbg_log(SEC_0198_CXFSNPRB, 0)(LOGSTDERR, "error:cxfsnprb_node_debug_cmp: inconsistent CXFSNPRB_NODE_PARENT_POS: %u != %u\n",
                            CXFSNPRB_NODE_PARENT_POS(node_1st), CXFSNPRB_NODE_PARENT_POS(node_2nd));
        return (EC_FALSE);
    }

    if(CXFSNPRB_NODE_RIGHT_POS(node_1st) != CXFSNPRB_NODE_RIGHT_POS(node_2nd))
    {
        dbg_log(SEC_0198_CXFSNPRB, 0)(LOGSTDERR, "error:cxfsnprb_node_debug_cmp: inconsistent CXFSNPRB_NODE_RIGHT_POS: %u != %u\n",
                            CXFSNPRB_NODE_RIGHT_POS(node_1st), CXFSNPRB_NODE_RIGHT_POS(node_2nd));
        return (EC_FALSE);
    }

    if(CXFSNPRB_NODE_LEFT_POS(node_1st) != CXFSNPRB_NODE_LEFT_POS(node_2nd))
    {
        dbg_log(SEC_0198_CXFSNPRB, 0)(LOGSTDERR, "error:cxfsnprb_node_debug_cmp: inconsistent CXFSNPRB_NODE_LEFT_POS: %u != %u\n",
                            CXFSNPRB_NODE_LEFT_POS(node_1st), CXFSNPRB_NODE_LEFT_POS(node_2nd));
        return (EC_FALSE);
    }

    if(CXFSNPRB_NODE_USED == CXFSNPRB_NODE_USED_FLAG(node_1st))
    {
        if(0 != node_cmp_data(node_1st, node_2nd))
        {
            dbg_log(SEC_0198_CXFSNPRB, 0)(LOGSTDERR, "error:cxfsnprb_node_debug_cmp: inconsistent data part\n");
            return (EC_FALSE);
        }
    }
    else
    {
        if(CXFSNPRB_NODE_NEXT_POS(node_1st) != CXFSNPRB_NODE_NEXT_POS(node_2nd))
        {
            dbg_log(SEC_0198_CXFSNPRB, 0)(LOGSTDERR, "error:cxfsnprb_node_debug_cmp: inconsistent CXFSNPRB_NODE_NEXT_POS: %u != %u\n",
                                CXFSNPRB_NODE_NEXT_POS(node_1st), CXFSNPRB_NODE_NEXT_POS(node_2nd));
            return (EC_FALSE);
        }
    }
    return (EC_TRUE);
}

EC_BOOL cxfsnprb_debug_cmp(const CXFSNPRB_POOL *pool_1st, const CXFSNPRB_POOL *pool_2nd, int (*node_cmp_data)(const CXFSNPRB_NODE *, const CXFSNPRB_NODE *))
{
    uint32_t  node_max_num;
    uint32_t  node_pos;

    if(CXFSNPRB_POOL_FREE_HEAD(pool_1st) != CXFSNPRB_POOL_FREE_HEAD(pool_2nd))
    {
        dbg_log(SEC_0198_CXFSNPRB, 0)(LOGSTDERR, "error:cxfsnprb_debug_cmp: inconsistent CXFSNPRB_POOL_FREE_HEAD: %u != %u\n",
                            CXFSNPRB_POOL_FREE_HEAD(pool_1st), CXFSNPRB_POOL_FREE_HEAD(pool_2nd));
        return (EC_FALSE);
    }

    if(CXFSNPRB_POOL_NODE_MAX_NUM(pool_1st) != CXFSNPRB_POOL_NODE_MAX_NUM(pool_2nd))
    {
        dbg_log(SEC_0198_CXFSNPRB, 0)(LOGSTDERR, "error:cxfsnprb_debug_cmp: inconsistent CXFSNPRB_POOL_NODE_MAX_NUM: %u != %u\n",
                            CXFSNPRB_POOL_NODE_MAX_NUM(pool_1st), CXFSNPRB_POOL_NODE_MAX_NUM(pool_2nd));
        return (EC_FALSE);
    }

    if(CXFSNPRB_POOL_NODE_USED_NUM(pool_1st) != CXFSNPRB_POOL_NODE_USED_NUM(pool_2nd))
    {
        dbg_log(SEC_0198_CXFSNPRB, 0)(LOGSTDERR, "error:cxfsnprb_debug_cmp: inconsistent CXFSNPRB_POOL_NODE_USED_NUM: %u != %u\n",
                            CXFSNPRB_POOL_NODE_USED_NUM(pool_1st), CXFSNPRB_POOL_NODE_USED_NUM(pool_2nd));
        return (EC_FALSE);
    }

    if(CXFSNPRB_POOL_NODE_SIZEOF(pool_1st) != CXFSNPRB_POOL_NODE_SIZEOF(pool_2nd))
    {
        dbg_log(SEC_0198_CXFSNPRB, 0)(LOGSTDERR, "error:cxfsnprb_debug_cmp: inconsistent CXFSNPRB_POOL_NODE_SIZEOF: %u != %u\n",
                            CXFSNPRB_POOL_NODE_SIZEOF(pool_1st), CXFSNPRB_POOL_NODE_SIZEOF(pool_2nd));
        return (EC_FALSE);
    }

    node_max_num = CXFSNPRB_POOL_NODE_MAX_NUM(pool_1st);
    for(node_pos = 0; node_pos < node_max_num; node_pos ++)
    {
        CXFSNPRB_NODE *node_1st;
        CXFSNPRB_NODE *node_2nd;

        node_1st = CXFSNPRB_POOL_NODE(pool_1st, node_pos);
        node_2nd = CXFSNPRB_POOL_NODE(pool_2nd, node_pos);

        if(EC_FALSE == cxfsnprb_node_debug_cmp(node_1st, node_2nd, node_cmp_data))
        {
            dbg_log(SEC_0198_CXFSNPRB, 0)(LOGSTDERR, "error:cxfsnprb_debug_cmp: inconsistent node at pos %u\n", node_pos);
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}


#ifdef __cplusplus
}
#endif/*__cplusplus*/
