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

#include "crfsnprb.h"
#include "crfsnp.h"

/*new a CRFSNPRB_NODE and return its position*/
uint32_t crfsnprb_node_new(CRFSNPRB_POOL *pool)
{
    uint32_t node_pos_t;
    CRFSNPRB_NODE *node;

    node_pos_t = CRFSNPRB_POOL_FREE_HEAD(pool);
    if(CRFSNPRB_ERR_POS == node_pos_t)
    {
        dbg_log(SEC_0100_CRFSNPRB, 0)(LOGSTDERR, "error:crfsnprb_node_new: no free node in pool\n");
        return (CRFSNPRB_ERR_POS);
    }

    if(CRFSNPRB_POOL_FREE_HEAD(pool) >= CRFSNPRB_POOL_NODE_MAX_NUM(pool))
    {
        dbg_log(SEC_0100_CRFSNPRB, 0)(LOGSTDERR, "error:crfsnprb_node_new: found conflict: free head %u >= max num %u\n",
                            CRFSNPRB_POOL_FREE_HEAD(pool), CRFSNPRB_POOL_NODE_MAX_NUM(pool));
        return (CRFSNPRB_ERR_POS);
    }

    ASSERT(CRFSNPRB_POOL_FREE_HEAD(pool) < CRFSNPRB_POOL_NODE_MAX_NUM(pool));

    node = CRFSNPRB_POOL_NODE(pool, node_pos_t);
#if 0
    dbg_log(SEC_0100_CRFSNPRB, 9)(LOGSTDNULL, "[DEBUG] crfsnprb_node_new: pool %p, max %u, used %u, free head %u, next %u\n",
                       pool,
                       CRFSNPRB_POOL_NODE_MAX_NUM(pool),
                       CRFSNPRB_POOL_NODE_USED_NUM(pool),
                       CRFSNPRB_POOL_FREE_HEAD(pool),
                       CRFSNPRB_NODE_NEXT_POS(node));
#endif
    CRFSNPRB_POOL_FREE_HEAD(pool) = CRFSNPRB_NODE_NEXT_POS(node);
    CRFSNPRB_POOL_NODE_USED_NUM(pool) ++;

    CRFSNPRB_NODE_NEXT_POS(node)  = CRFSNPRB_ERR_POS;
    CRFSNPRB_NODE_USED_FLAG(node) = CRFSNPRB_NODE_USED;

    return (node_pos_t);
}

/*free a CRFSNPRB_NODE and return its position to the pool*/
void crfsnprb_node_free(CRFSNPRB_POOL *pool, const uint32_t node_pos)
{
    if(CRFSNPRB_ERR_POS != node_pos)
    {
        CRFSNPRB_NODE *node;

        ASSERT(node_pos < CRFSNPRB_POOL_NODE_MAX_NUM(pool));

        node = CRFSNPRB_POOL_NODE(pool, node_pos);
        ASSERT(CRFSNPRB_NODE_IS_USED(node));

        CRFSNPRB_NODE_USED_FLAG(node)  = CRFSNPRB_NODE_NOT_USED;
        CRFSNPRB_NODE_PARENT_POS(node) = CRFSNPRB_ERR_POS;
        CRFSNPRB_NODE_RIGHT_POS(node)  = CRFSNPRB_ERR_POS;
        CRFSNPRB_NODE_LEFT_POS(node)   = CRFSNPRB_ERR_POS;
        CRFSNPRB_NODE_NEXT_POS(node)   = CRFSNPRB_POOL_FREE_HEAD(pool);
        CRFSNPRB_NODE_COLOR(node)      = CRFSNPRB_BLACK;

        CRFSNPRB_POOL_FREE_HEAD(pool)  = node_pos;
        CRFSNPRB_POOL_NODE_USED_NUM(pool) --;
    }
    return;
}

void crfsnprb_node_init(CRFSNPRB_POOL *pool, const uint32_t node_pos)
{
    CRFSNPRB_NODE *node;

    node  = CRFSNPRB_POOL_NODE(pool, node_pos);

    CRFSNPRB_NODE_PARENT_POS(node) = CRFSNPRB_ERR_POS;
    CRFSNPRB_NODE_RIGHT_POS(node)  = CRFSNPRB_ERR_POS;
    CRFSNPRB_NODE_LEFT_POS(node)   = CRFSNPRB_ERR_POS;
    CRFSNPRB_NODE_USED_FLAG(node)  = CRFSNPRB_NODE_NOT_USED;
    CRFSNPRB_NODE_NEXT_POS(node)   = CRFSNPRB_ERR_POS;
    CRFSNPRB_NODE_COLOR(node)      = CRFSNPRB_BLACK;

    return;
}

void crfsnprb_node_clean(CRFSNPRB_POOL *pool, const uint32_t node_pos)
{
    CRFSNPRB_NODE *node;

    ASSERT(node_pos < CRFSNPRB_POOL_NODE_MAX_NUM(pool));

    node = CRFSNPRB_POOL_NODE(pool, node_pos);

    CRFSNPRB_NODE_PARENT_POS(node) = CRFSNPRB_ERR_POS;
    CRFSNPRB_NODE_RIGHT_POS(node)  = CRFSNPRB_ERR_POS;
    CRFSNPRB_NODE_LEFT_POS(node)   = CRFSNPRB_ERR_POS;
    CRFSNPRB_NODE_USED_FLAG(node)  = CRFSNPRB_NODE_NOT_USED;
    CRFSNPRB_NODE_NEXT_POS(node)   = CRFSNPRB_ERR_POS;
    CRFSNPRB_NODE_COLOR(node)      = CRFSNPRB_BLACK;

    return;
}

void crfsnprb_node_set_next(CRFSNPRB_POOL *pool, const uint32_t node_pos, const uint32_t next_pos)
{
    CRFSNPRB_NODE *node;

    node = CRFSNPRB_POOL_NODE(pool, node_pos);
    CRFSNPRB_NODE_NEXT_POS(node) = next_pos;

    return;
}

EC_BOOL crfsnprb_node_is_used(const CRFSNPRB_POOL *pool, const uint32_t node_pos)
{
    const CRFSNPRB_NODE *node;
    node  = CRFSNPRB_POOL_NODE(pool, node_pos);

    if(CRFSNPRB_NODE_IS_USED(node))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

void crfsnprb_node_print(LOG *log, const CRFSNPRB_POOL *pool, const uint32_t node_pos)
{
    const CRFSNPRB_NODE *node;
    node  = CRFSNPRB_POOL_NODE(pool, node_pos);

    sys_log(log, "%5d: parent = %5d, left = %5d, right = %5d, flg = %s, color = %s, %s = %5d\n",
                       node_pos,
                       CRFSNPRB_NODE_PARENT_POS(node),
                       CRFSNPRB_NODE_LEFT_POS(node),
                       CRFSNPRB_NODE_RIGHT_POS(node),
                       CRFSNPRB_NODE_IS_USED(node) ? "used" : "n.a.",
                       CRFSNPRB_NODE_IS_USED(node) ? (CRFSNPRB_NODE_IS_RED(node) ? "red  " : "black") : "#####",
                       CRFSNPRB_NODE_IS_USED(node) ? "data" : "next",
                       CRFSNPRB_NODE_IS_USED(node) ? CRFSNPRB_NODE_DATA(node) : CRFSNPRB_NODE_NEXT_POS(node)
                       );
    return;
}

void crfsnprb_node_print_level(LOG *log, const CRFSNPRB_POOL *pool, const uint32_t node_pos, const uint32_t level)
{
    const CRFSNPRB_NODE *node;
    node  = CRFSNPRB_POOL_NODE(pool, node_pos);

    c_ident_print(log, level);
    sys_print(log, "%5d: parent = %5d, left = %5d, right = %5d, flg = %s, color = %s, %s = %5d\n",
                       node_pos,
                       CRFSNPRB_NODE_PARENT_POS(node),
                       CRFSNPRB_NODE_LEFT_POS(node),
                       CRFSNPRB_NODE_RIGHT_POS(node),
                       CRFSNPRB_NODE_IS_USED(node) ? "used" : "NOT used",
                       CRFSNPRB_NODE_IS_RED(node)  ? "red  " : "black",
                       CRFSNPRB_NODE_IS_USED(node) ? "data" : "next",
                       CRFSNPRB_NODE_IS_USED(node) ? CRFSNPRB_NODE_DATA(node) : CRFSNPRB_NODE_NEXT_POS(node)
                       );
    return;
}


STATIC_CAST static void __crfsnprb_tree_rotate_left(CRFSNPRB_POOL *pool, const uint32_t node_pos, uint32_t *root_pos)
{
    CRFSNPRB_NODE *node;
    CRFSNPRB_NODE *right;

    uint32_t  right_pos;

    node  = CRFSNPRB_POOL_NODE(pool, node_pos);

    right_pos = CRFSNPRB_NODE_RIGHT_POS(node);
    right = CRFSNPRB_POOL_NODE(pool, right_pos);

    if(CRFSNPRB_ERR_POS != (CRFSNPRB_NODE_RIGHT_POS(node) = CRFSNPRB_NODE_LEFT_POS(right)))
    {
        CRFSNPRB_NODE *left;
        left = CRFSNPRB_POOL_NODE(pool, CRFSNPRB_NODE_LEFT_POS(right));
        CRFSNPRB_NODE_PARENT_POS(left) = node_pos;
    }
    CRFSNPRB_NODE_LEFT_POS(right) = node_pos;

    if(CRFSNPRB_ERR_POS != (CRFSNPRB_NODE_PARENT_POS(right) = CRFSNPRB_NODE_PARENT_POS(node)))
    {
        CRFSNPRB_NODE *parent;
        parent = CRFSNPRB_POOL_NODE(pool, CRFSNPRB_NODE_PARENT_POS(node));

        if (node_pos == CRFSNPRB_NODE_LEFT_POS(parent))
        {
            CRFSNPRB_NODE_LEFT_POS(parent) = right_pos;
        }
        else
        {
            CRFSNPRB_NODE_RIGHT_POS(parent) = right_pos;
        }
    }
    else
    {
        (*root_pos) = right_pos;
    }
    CRFSNPRB_NODE_PARENT_POS(node) = right_pos;
    return;
}

STATIC_CAST static void __crfsnprb_tree_rotate_right(CRFSNPRB_POOL *pool, const uint32_t node_pos, uint32_t *root_pos)
{
    CRFSNPRB_NODE *node;
    CRFSNPRB_NODE *left;
    uint32_t  left_pos;

    node  = CRFSNPRB_POOL_NODE(pool, node_pos);

    left_pos = CRFSNPRB_NODE_LEFT_POS(node);
    left = CRFSNPRB_POOL_NODE(pool, left_pos);

    if (CRFSNPRB_ERR_POS != (CRFSNPRB_NODE_LEFT_POS(node) = CRFSNPRB_NODE_RIGHT_POS(left)))
    {
        CRFSNPRB_NODE *right;
        right = CRFSNPRB_POOL_NODE(pool, CRFSNPRB_NODE_RIGHT_POS(left));
        CRFSNPRB_NODE_PARENT_POS(right) = node_pos;
    }
    CRFSNPRB_NODE_RIGHT_POS(left) = node_pos;

    if (CRFSNPRB_ERR_POS != (CRFSNPRB_NODE_PARENT_POS(left) = CRFSNPRB_NODE_PARENT_POS(node)))
    {
        CRFSNPRB_NODE *parent;
        parent = CRFSNPRB_POOL_NODE(pool, CRFSNPRB_NODE_PARENT_POS(node));

        if (node_pos == CRFSNPRB_NODE_RIGHT_POS(parent))
        {
            CRFSNPRB_NODE_RIGHT_POS(parent) = left_pos;
        }
        else
        {
            CRFSNPRB_NODE_LEFT_POS(parent) = left_pos;
        }
    }
    else
    {
        (*root_pos) = left_pos;
    }
    CRFSNPRB_NODE_PARENT_POS(node) = left_pos;
    return;
}

STATIC_CAST static void __crfsnprb_tree_insert_color(CRFSNPRB_POOL *pool, const uint32_t node_pos, uint32_t *root_pos)
{
    CRFSNPRB_NODE *node;
    CRFSNPRB_NODE *root;
    CRFSNPRB_NODE *parent;

    uint32_t  node_pos_t;

    node_pos_t = node_pos;
    node  = CRFSNPRB_POOL_NODE(pool, node_pos_t);

    while (NULL_PTR != (parent = CRFSNPRB_POOL_NODE(pool, CRFSNPRB_NODE_PARENT_POS(node))) /*parent is valid*/
         && CRFSNPRB_RED == CRFSNPRB_NODE_COLOR(parent))
    {
        uint32_t  parent_pos;
        uint32_t  gparent_pos;
        CRFSNPRB_NODE *gparent;

        parent_pos = CRFSNPRB_NODE_PARENT_POS(node);

        gparent_pos = CRFSNPRB_NODE_PARENT_POS(parent);
        ASSERT(CRFSNPRB_ERR_POS != gparent_pos);
        gparent = CRFSNPRB_POOL_NODE(pool, gparent_pos);

        if (parent_pos == CRFSNPRB_NODE_LEFT_POS(gparent))
        {
            {
                CRFSNPRB_NODE *uncle;
                if (NULL_PTR != (uncle = CRFSNPRB_POOL_NODE(pool, CRFSNPRB_NODE_RIGHT_POS(gparent))) /*uncle is valid*/
                   && CRFSNPRB_RED == CRFSNPRB_NODE_COLOR(uncle))
                {
                    CRFSNPRB_NODE_COLOR(uncle)   = CRFSNPRB_BLACK;
                    CRFSNPRB_NODE_COLOR(parent)  = CRFSNPRB_BLACK;
                    CRFSNPRB_NODE_COLOR(gparent) = CRFSNPRB_RED;

                    node = gparent;
                    node_pos_t = gparent_pos;
                    continue;
                }
            }

            if (CRFSNPRB_NODE_RIGHT_POS(parent) == node_pos_t)
            {
                __crfsnprb_tree_rotate_left(pool, parent_pos, root_pos);
                XCHG(CRFSNPRB_NODE *, parent, node);
                XCHG(uint32_t, parent_pos, node_pos_t);
            }

            CRFSNPRB_NODE_COLOR(parent)  = CRFSNPRB_BLACK;
            CRFSNPRB_NODE_COLOR(gparent) = CRFSNPRB_RED;
            __crfsnprb_tree_rotate_right(pool, gparent_pos, root_pos);
         }
         else
         {
            {
                CRFSNPRB_NODE *uncle;
                if (NULL_PTR != (uncle = CRFSNPRB_POOL_NODE(pool, CRFSNPRB_NODE_LEFT_POS(gparent))) /*uncle is valid*/
                    && CRFSNPRB_RED == CRFSNPRB_NODE_COLOR(uncle))
                {
                    CRFSNPRB_NODE_COLOR(uncle)   = CRFSNPRB_BLACK;
                    CRFSNPRB_NODE_COLOR(parent)  = CRFSNPRB_BLACK;
                    CRFSNPRB_NODE_COLOR(gparent) = CRFSNPRB_RED;

                    node = gparent;
                    node_pos_t = gparent_pos;
                    continue;
                }
            }

            if (CRFSNPRB_NODE_LEFT_POS(parent) == node_pos_t)
            {
                __crfsnprb_tree_rotate_right(pool, parent_pos, root_pos);
                XCHG(CRFSNPRB_NODE *, parent, node);
                XCHG(uint32_t, parent_pos, node_pos_t);
            }

            CRFSNPRB_NODE_COLOR(parent)  = CRFSNPRB_BLACK;
            CRFSNPRB_NODE_COLOR(gparent) = CRFSNPRB_RED;
            __crfsnprb_tree_rotate_left(pool, gparent_pos, root_pos);
        }
    }

    root = CRFSNPRB_POOL_NODE(pool, *root_pos);
    CRFSNPRB_NODE_COLOR(root) = CRFSNPRB_BLACK;
    return;
}

STATIC_CAST static void __crfsnprb_tree_erase_color(CRFSNPRB_POOL *pool, const uint32_t node_pos, const uint32_t parent_pos, uint32_t *root_pos)
{
    CRFSNPRB_NODE *node;
    uint32_t  node_pos_t;
    uint32_t  parent_pos_t;

    node_pos_t   = node_pos;
    parent_pos_t = parent_pos;

    while ((NULL_PTR == (node = CRFSNPRB_POOL_NODE(pool, node_pos_t)) || CRFSNPRB_BLACK == CRFSNPRB_NODE_COLOR(node)) && node_pos_t != (*root_pos))
    {
        CRFSNPRB_NODE *parent;

        parent = CRFSNPRB_POOL_NODE(pool, parent_pos_t);

        if (CRFSNPRB_NODE_LEFT_POS(parent) == node_pos_t)
        {
            CRFSNPRB_NODE *other;
            CRFSNPRB_NODE *o_left;
            CRFSNPRB_NODE *o_right;
            uint32_t  other_pos;

            other_pos = CRFSNPRB_NODE_RIGHT_POS(parent);
            other = CRFSNPRB_POOL_NODE(pool, other_pos);

            if (CRFSNPRB_RED == CRFSNPRB_NODE_COLOR(other))
            {
                CRFSNPRB_NODE_COLOR(other)  = CRFSNPRB_BLACK;
                CRFSNPRB_NODE_COLOR(parent) = CRFSNPRB_RED;

                __crfsnprb_tree_rotate_left(pool, parent_pos_t, root_pos);

                other_pos = CRFSNPRB_NODE_RIGHT_POS(parent);
                other = CRFSNPRB_POOL_NODE(pool, other_pos);
            }

            o_left = CRFSNPRB_POOL_NODE(pool, CRFSNPRB_NODE_LEFT_POS(other));
            o_right = CRFSNPRB_POOL_NODE(pool, CRFSNPRB_NODE_RIGHT_POS(other));

            if((NULL_PTR == o_left || CRFSNPRB_BLACK == CRFSNPRB_NODE_COLOR(o_left))
            && (NULL_PTR == o_right || CRFSNPRB_BLACK == CRFSNPRB_NODE_COLOR(o_right)))
            {
                CRFSNPRB_NODE_COLOR(other) = CRFSNPRB_RED;

                node_pos_t = parent_pos_t;
                node = CRFSNPRB_POOL_NODE(pool, node_pos_t);

                parent_pos_t = CRFSNPRB_NODE_PARENT_POS(node);
                parent = CRFSNPRB_POOL_NODE(pool, parent_pos_t);
            }
            else
            {
                if (NULL_PTR == o_right || CRFSNPRB_BLACK == CRFSNPRB_NODE_COLOR(o_right))
                {
                    if (NULL_PTR != o_left)
                    {
                        CRFSNPRB_NODE_COLOR(o_left) = CRFSNPRB_BLACK;
                    }
                    CRFSNPRB_NODE_COLOR(other) = CRFSNPRB_RED;

                    __crfsnprb_tree_rotate_right(pool, other_pos, root_pos);

                    other_pos = CRFSNPRB_NODE_RIGHT_POS(parent);
                    other = CRFSNPRB_POOL_NODE(pool, other_pos);
                    /*note: other was changed here*/
                }

                CRFSNPRB_NODE_COLOR(other) = CRFSNPRB_NODE_COLOR(parent);
                CRFSNPRB_NODE_COLOR(parent) = CRFSNPRB_BLACK;

                /*due to other may be changed before, have to get o_right again here*/
                o_right = CRFSNPRB_POOL_NODE(pool, CRFSNPRB_NODE_RIGHT_POS(other));
                if (NULL_PTR != o_right)
                {
                    CRFSNPRB_NODE_COLOR(o_right) = CRFSNPRB_BLACK;
                }

                __crfsnprb_tree_rotate_left(pool, parent_pos_t, root_pos);
                node_pos_t = (*root_pos);
                break;
            }
        }
        else
        {
            CRFSNPRB_NODE *other;
            CRFSNPRB_NODE *o_left;
            CRFSNPRB_NODE *o_right;
            uint32_t  other_pos;

            other_pos = CRFSNPRB_NODE_LEFT_POS(parent);
            other = CRFSNPRB_POOL_NODE(pool, other_pos);

            if (CRFSNPRB_RED == CRFSNPRB_NODE_COLOR(other))
            {
                CRFSNPRB_NODE_COLOR(other) = CRFSNPRB_BLACK;
                CRFSNPRB_NODE_COLOR(parent) = CRFSNPRB_RED;

                __crfsnprb_tree_rotate_right(pool, parent_pos_t, root_pos);

                other_pos = CRFSNPRB_NODE_LEFT_POS(parent);
                other = CRFSNPRB_POOL_NODE(pool, other_pos);
            }

            o_left = CRFSNPRB_POOL_NODE(pool, CRFSNPRB_NODE_LEFT_POS(other));
            o_right = CRFSNPRB_POOL_NODE(pool, CRFSNPRB_NODE_RIGHT_POS(other));

            if ((NULL_PTR == o_left  || CRFSNPRB_BLACK == CRFSNPRB_NODE_COLOR(o_left))
             && (NULL_PTR == o_right || CRFSNPRB_BLACK == CRFSNPRB_NODE_COLOR(o_right)))
            {
                CRFSNPRB_NODE_COLOR(other) = CRFSNPRB_RED;

                node_pos_t = parent_pos_t;
                node = CRFSNPRB_POOL_NODE(pool, node_pos_t);

                parent_pos_t = CRFSNPRB_NODE_PARENT_POS(node);
                parent = CRFSNPRB_POOL_NODE(pool, parent_pos_t);
            }
            else
            {
                if (NULL_PTR == o_left  || CRFSNPRB_BLACK == CRFSNPRB_NODE_COLOR(o_left))
                {
                    if (NULL_PTR != o_right)
                    {
                        CRFSNPRB_NODE_COLOR(o_right) = CRFSNPRB_BLACK;
                    }

                    CRFSNPRB_NODE_COLOR(other) = CRFSNPRB_RED;

                    __crfsnprb_tree_rotate_left(pool, other_pos, root_pos);

                    other_pos = CRFSNPRB_NODE_LEFT_POS(parent);
                    other = CRFSNPRB_POOL_NODE(pool, other_pos);
                    /*note: other was changed here*/
                }

                CRFSNPRB_NODE_COLOR(other) = CRFSNPRB_NODE_COLOR(parent);
                CRFSNPRB_NODE_COLOR(parent) = CRFSNPRB_BLACK;

                /*due to other may be changed before, have to get o_left again here*/
                o_left = CRFSNPRB_POOL_NODE(pool, CRFSNPRB_NODE_LEFT_POS(other));
                if (NULL_PTR != o_left)
                {
                    CRFSNPRB_NODE_COLOR(o_left) = CRFSNPRB_BLACK;
                }
                __crfsnprb_tree_rotate_right(pool, parent_pos_t, root_pos);
                node_pos_t = (*root_pos);
                break;
            }
        }
    }

    node = CRFSNPRB_POOL_NODE(pool, node_pos_t);
    if (NULL_PTR != node)
    {
        CRFSNPRB_NODE_COLOR(node) = CRFSNPRB_BLACK;
    }
    return;
}

/*note: erase from tree but not recycle to free nodes pool*/
EC_BOOL crfsnprb_tree_erase(CRFSNPRB_POOL *pool, const uint32_t node_pos, uint32_t *root_pos)
{
    CRFSNPRB_NODE *node;

    uint32_t node_pos_t;
    uint32_t child_pos;
    uint32_t parent_pos;
    uint32_t color;

    node_pos_t = node_pos;
    node = CRFSNPRB_POOL_NODE(pool, node_pos_t);

    ASSERT(NULL_PTR != node);
    ASSERT(CRFSNPRB_NODE_IS_USED(node));

    if (CRFSNPRB_ERR_POS == CRFSNPRB_NODE_LEFT_POS(node))
    {
        child_pos = CRFSNPRB_NODE_RIGHT_POS(node);
    }
    else if (CRFSNPRB_ERR_POS == CRFSNPRB_NODE_RIGHT_POS(node))
    {
        child_pos = CRFSNPRB_NODE_LEFT_POS(node);
    }
    else
    {
        CRFSNPRB_NODE *old;

        uint32_t old_pos;
        uint32_t left_pos;

        old_pos = node_pos_t;

        node_pos_t = CRFSNPRB_NODE_RIGHT_POS(node);
        node = CRFSNPRB_POOL_NODE(pool, node_pos_t);

        while (CRFSNPRB_ERR_POS != (left_pos = CRFSNPRB_NODE_LEFT_POS(node)))
        {
            node_pos_t = left_pos;
            node = CRFSNPRB_POOL_NODE(pool, node_pos_t);

        }

        child_pos  = CRFSNPRB_NODE_RIGHT_POS(node);
        parent_pos = CRFSNPRB_NODE_PARENT_POS(node);
        color      = CRFSNPRB_NODE_COLOR(node);

        if (CRFSNPRB_ERR_POS != child_pos)
        {
            CRFSNPRB_NODE *child;
            child = CRFSNPRB_POOL_NODE(pool, child_pos);
            CRFSNPRB_NODE_PARENT_POS(child) = parent_pos;
        }

        if (CRFSNPRB_ERR_POS != parent_pos)
        {
            CRFSNPRB_NODE *parent;

            parent = CRFSNPRB_POOL_NODE(pool, parent_pos);
            if (CRFSNPRB_NODE_LEFT_POS(parent) == node_pos_t)
            {
                CRFSNPRB_NODE_LEFT_POS(parent) = child_pos;
            }
            else
            {
                CRFSNPRB_NODE_RIGHT_POS(parent) = child_pos;
            }
        }
        else
        {
            (*root_pos) = child_pos;
        }

        if (CRFSNPRB_NODE_PARENT_POS(node) == old_pos)
        {
            parent_pos = node_pos_t;
        }

        old  = CRFSNPRB_POOL_NODE(pool, old_pos);

        CRFSNPRB_NODE_PARENT_POS(node) = CRFSNPRB_NODE_PARENT_POS(old);
        CRFSNPRB_NODE_COLOR(node)      = CRFSNPRB_NODE_COLOR(old);
        CRFSNPRB_NODE_RIGHT_POS(node)  = CRFSNPRB_NODE_RIGHT_POS(old);
        CRFSNPRB_NODE_LEFT_POS(node)   = CRFSNPRB_NODE_LEFT_POS(old);

        if (CRFSNPRB_ERR_POS != CRFSNPRB_NODE_PARENT_POS(old))
        {
            CRFSNPRB_NODE *old_parent;
            old_parent = CRFSNPRB_POOL_NODE(pool, CRFSNPRB_NODE_PARENT_POS(old));

            if (CRFSNPRB_NODE_LEFT_POS(old_parent) == old_pos)
            {
                CRFSNPRB_NODE_LEFT_POS(old_parent) = node_pos_t;
            }
            else
            {
                CRFSNPRB_NODE_RIGHT_POS(old_parent) = node_pos_t;
            }
        }
        else
        {
            (*root_pos) = node_pos_t;
        }

        {
            CRFSNPRB_NODE *old_left;

            old_left = CRFSNPRB_POOL_NODE(pool, CRFSNPRB_NODE_LEFT_POS(old));
            CRFSNPRB_NODE_PARENT_POS(old_left) = node_pos_t;
        }

        if (CRFSNPRB_ERR_POS != CRFSNPRB_NODE_RIGHT_POS(old))
        {
            CRFSNPRB_NODE *old_right;
            old_right = CRFSNPRB_POOL_NODE(pool, CRFSNPRB_NODE_RIGHT_POS(old));
            CRFSNPRB_NODE_PARENT_POS(old_right) = node_pos_t;
        }
        goto color;
    }

    parent_pos = CRFSNPRB_NODE_PARENT_POS(node);
    color = CRFSNPRB_NODE_COLOR(node);

    if (CRFSNPRB_ERR_POS != child_pos)
    {
        CRFSNPRB_NODE *child;
        child = CRFSNPRB_POOL_NODE(pool, child_pos);
        CRFSNPRB_NODE_PARENT_POS(child) = parent_pos;
    }

    if (CRFSNPRB_ERR_POS != parent_pos)
    {
        CRFSNPRB_NODE *parent;

        parent = CRFSNPRB_POOL_NODE(pool, parent_pos);
        if (CRFSNPRB_NODE_LEFT_POS(parent) == node_pos_t)
        {
            CRFSNPRB_NODE_LEFT_POS(parent) = child_pos;
        }
        else
        {
            CRFSNPRB_NODE_RIGHT_POS(parent) = child_pos;
        }
    }
    else
    {
        (*root_pos) = child_pos;
    }

 color:
    if (CRFSNPRB_BLACK == color)
    {
        __crfsnprb_tree_erase_color(pool, child_pos, parent_pos, root_pos);
    }
    return (EC_TRUE);
}

STATIC_CAST static uint32_t __crfsnprb_tree_count_node_num(const CRFSNPRB_POOL *pool, const uint32_t node_pos)
{
    const CRFSNPRB_NODE *node;

    if(CRFSNPRB_ERR_POS == node_pos)
    {
        return ((uint32_t)0);
    }

    node = CRFSNPRB_POOL_NODE(pool, node_pos);

    return (uint32_t)(1 + __crfsnprb_tree_count_node_num(pool, CRFSNPRB_NODE_LEFT_POS(node)) + __crfsnprb_tree_count_node_num(pool, CRFSNPRB_NODE_RIGHT_POS(node)));
}

uint32_t crfsnprb_tree_count_node_num(const CRFSNPRB_POOL *pool, const uint32_t root_pos)
{
    return __crfsnprb_tree_count_node_num(pool, root_pos);
}

uint32_t crfsnprb_tree_node_max_num(const CRFSNPRB_POOL *pool)
{
    return CRFSNPRB_POOL_NODE_MAX_NUM(pool);
}

uint32_t crfsnprb_tree_node_used_num(const CRFSNPRB_POOL *pool)
{
    return CRFSNPRB_POOL_NODE_USED_NUM(pool);
}

uint32_t crfsnprb_tree_node_sizeof(const CRFSNPRB_POOL *pool)
{
    return CRFSNPRB_POOL_NODE_SIZEOF(pool);
}

/*
 * This function returns the first node_pos (in sort order) of the tree.
 */
uint32_t crfsnprb_tree_first_node(const CRFSNPRB_POOL *pool, const uint32_t root_pos)
{
    uint32_t  node_pos;
    const CRFSNPRB_NODE *node;

    node_pos = root_pos;
    if (CRFSNPRB_ERR_POS == node_pos)
    {
        return (CRFSNPRB_ERR_POS);
    }

    node = CRFSNPRB_POOL_NODE(pool, node_pos);

    while (CRFSNPRB_ERR_POS != CRFSNPRB_NODE_LEFT_POS(node))
    {
        node_pos = CRFSNPRB_NODE_LEFT_POS(node);
        node = CRFSNPRB_POOL_NODE(pool, node_pos);
    }
    return (node_pos);
}

uint32_t crfsnprb_tree_last_node(const CRFSNPRB_POOL *pool, const uint32_t root_pos)
{
    uint32_t  node_pos;
    const CRFSNPRB_NODE *node;

    node_pos = root_pos;
    if (CRFSNPRB_ERR_POS == node_pos)
    {
        return (CRFSNPRB_ERR_POS);
    }

    node = CRFSNPRB_POOL_NODE(pool, node_pos);

    while (CRFSNPRB_ERR_POS != CRFSNPRB_NODE_RIGHT_POS(node))
    {
        node_pos = CRFSNPRB_NODE_RIGHT_POS(node);
        node = CRFSNPRB_POOL_NODE(pool, node_pos);
    }

    return (node_pos);
}

uint32_t crfsnprb_tree_next_node(const CRFSNPRB_POOL *pool, const uint32_t node_pos)
{
    uint32_t node_pos_t;
    const CRFSNPRB_NODE *node;
    const CRFSNPRB_NODE *parent;

    node_pos_t = node_pos;
    node = CRFSNPRB_POOL_NODE(pool, node_pos_t);
    /* If we have a right-hand child, go down and then left as far
       as we can. */
    if (CRFSNPRB_ERR_POS != CRFSNPRB_NODE_RIGHT_POS(node))
    {
        node_pos_t = CRFSNPRB_NODE_RIGHT_POS(node);
        node = CRFSNPRB_POOL_NODE(pool, node_pos_t);
        while (CRFSNPRB_ERR_POS != CRFSNPRB_NODE_LEFT_POS(node))
        {
            node_pos_t = CRFSNPRB_NODE_LEFT_POS(node);
            node = CRFSNPRB_POOL_NODE(pool, node_pos_t);
        }
        return (node_pos_t);
    }

    /* No right-hand children.  Everything down and left is
       smaller than us, so any 'next' node_pos_t must be in the general
       direction of our parent. Go up the tree; any time the
       ancestor is a right-hand child of its parent, keep going
       up. First time it's a left-hand child of its parent, said
       parent is our 'next' node_pos_t. */
    while (NULL_PTR != (parent = CRFSNPRB_POOL_NODE(pool, CRFSNPRB_NODE_PARENT_POS(node))) && node_pos_t == CRFSNPRB_NODE_RIGHT_POS(parent))
    {
        node_pos_t = CRFSNPRB_NODE_PARENT_POS(node);
        node = parent;
    }

    return (CRFSNPRB_NODE_PARENT_POS(node));
}

uint32_t crfsnprb_tree_prev_node(const CRFSNPRB_POOL *pool, const uint32_t node_pos)
{
    uint32_t node_pos_t;
    const CRFSNPRB_NODE *node;
    const CRFSNPRB_NODE *parent;

    node_pos_t = node_pos;
    node = CRFSNPRB_POOL_NODE(pool, node_pos_t);

    /* If we have a left-hand child, go down and then right as far
       as we can. */
    if (CRFSNPRB_ERR_POS != CRFSNPRB_NODE_LEFT_POS(node))
    {
        node_pos_t = CRFSNPRB_NODE_LEFT_POS(node);
        node = CRFSNPRB_POOL_NODE(pool, node_pos_t);
        while (CRFSNPRB_ERR_POS != CRFSNPRB_NODE_RIGHT_POS(node))
        {
            node_pos_t = CRFSNPRB_NODE_RIGHT_POS(node);
            node = CRFSNPRB_POOL_NODE(pool, node_pos_t);
        }
        return (node_pos_t);
    }

    /* No left-hand children. Go up till we find an ancestor which
       is a right-hand child of its parent */
    while (NULL_PTR != (parent = CRFSNPRB_POOL_NODE(pool, CRFSNPRB_NODE_PARENT_POS(node))) && node_pos_t == CRFSNPRB_NODE_LEFT_POS(parent))
    {
        node_pos_t = CRFSNPRB_NODE_PARENT_POS(node);
        node = parent;
    }

    return (CRFSNPRB_NODE_PARENT_POS(node));
}

/*victim_pos should be free*/
void crfsnprb_tree_replace_node(CRFSNPRB_POOL *pool, const uint32_t victim_pos, const uint32_t new_pos, uint32_t *root_pos)
{
    CRFSNPRB_NODE *victim;

    victim = CRFSNPRB_POOL_NODE(pool, victim_pos);

    /* Set the surrounding nodes to point to the replacement */
    if (CRFSNPRB_ERR_POS != CRFSNPRB_NODE_PARENT_POS(victim))
    {
        CRFSNPRB_NODE *parent;
        parent = CRFSNPRB_POOL_NODE(pool, CRFSNPRB_NODE_PARENT_POS(victim));

        if (victim_pos == CRFSNPRB_NODE_LEFT_POS(parent))
        {
            CRFSNPRB_NODE_LEFT_POS(parent) = new_pos;
        }
        else
        {
            CRFSNPRB_NODE_RIGHT_POS(parent) = new_pos;
        }
    }
    else
    {
        (*root_pos) = new_pos;
    }

    if (CRFSNPRB_ERR_POS != CRFSNPRB_NODE_LEFT_POS(victim))
    {
        CRFSNPRB_NODE *left;
        left = CRFSNPRB_POOL_NODE(pool, CRFSNPRB_NODE_LEFT_POS(victim));
        CRFSNPRB_NODE_PARENT_POS(left) = new_pos;
    }
    if (CRFSNPRB_ERR_POS != CRFSNPRB_NODE_RIGHT_POS(victim))
    {
        CRFSNPRB_NODE *right;
        right = CRFSNPRB_POOL_NODE(pool, CRFSNPRB_NODE_RIGHT_POS(victim));
        CRFSNPRB_NODE_PARENT_POS(right) = new_pos;
    }

    return;
}

/**
*
*   note:only for crfsnp item!
*   return -1 if node < (data, key)
*   return  1 if node > (data, key)
*   return  0 if node == (data, key)
*
**/
STATIC_CAST static int __crfsnprb_node_data_cmp(const CRFSNPRB_NODE *node, const uint32_t data, const uint32_t klen, const uint8_t *key)
{
    const CRFSNP_ITEM *item;

    if (CRFSNPRB_NODE_DATA(node) < data)
    {
        return (-1);
    }

    if (CRFSNPRB_NODE_DATA(node) > data)
    {
        return (1);
    }

    item = (const CRFSNP_ITEM *)CRFSNP_RB_NODE_ITEM(node);
    if(CRFSNP_ITEM_KLEN(item) < klen)
    {
        return (-1);
    }

    if(CRFSNP_ITEM_KLEN(item) > klen)
    {
        return (1);
    }

    return BCMP(CRFSNP_ITEM_KNAME(item), key, klen);
}

/*return the searched pos*/
uint32_t crfsnprb_tree_search_data(const CRFSNPRB_POOL *pool, const uint32_t root_pos, const uint32_t data, const uint32_t klen, const uint8_t *key)
{
    uint32_t node_pos;

    node_pos = root_pos;

    while (CRFSNPRB_ERR_POS != node_pos)
    {
        const CRFSNPRB_NODE *node;
        int cmp_ret;

        node = CRFSNPRB_POOL_NODE(pool, node_pos);
        cmp_ret = __crfsnprb_node_data_cmp(node, data, klen, key);

        if (0 < cmp_ret)/*node > (data, key)*/
        {
            node_pos = CRFSNPRB_NODE_LEFT_POS(node);
        }
        else if (0 > cmp_ret)/*node < (data, key)*/
        {
            node_pos = CRFSNPRB_NODE_RIGHT_POS(node);
        }
        else /*node == (data, key)*/
        {
            return (node_pos);
        }
    }

    return (CRFSNPRB_ERR_POS);
}

/*if found duplicate node, return EC_FALSE, otherwise return EC_TRUE*/
EC_BOOL crfsnprb_tree_insert_data(CRFSNPRB_POOL *pool, uint32_t *root_pos, const uint32_t data, const uint32_t klen, const uint8_t *key, uint32_t *insert_pos)
{
    uint32_t  node_pos_t;
    uint32_t  new_pos_t;
    uint32_t  parent_pos_t;
    uint32_t  flag; /*0: on left subtree, 1: on right subtree*/

    node_pos_t   = (*root_pos);
    parent_pos_t = CRFSNPRB_ERR_POS;
    flag         = ~(uint32_t)0;

    while (CRFSNPRB_ERR_POS != node_pos_t)
    {
        CRFSNPRB_NODE *node;
        int cmp_ret;

        node = CRFSNPRB_POOL_NODE(pool, node_pos_t);
        cmp_ret = __crfsnprb_node_data_cmp(node, data, klen, key);

        parent_pos_t = node_pos_t;

        if (0 < cmp_ret)/*node > (data, key)*/
        {
            node_pos_t = CRFSNPRB_NODE_LEFT_POS(node);
            flag = 0;
        }
        else if (0 > cmp_ret)/*node < (data, key)*/
        {
            node_pos_t = CRFSNPRB_NODE_RIGHT_POS(node);
            flag = 1;
        }
        else/*node == (data, key)*/
        {
            (*insert_pos) = node_pos_t;
            return (EC_FALSE);/*found duplicate*/
        }
    }


    /*not found data in the rbtree*/
    new_pos_t = crfsnprb_node_new(pool);
    if(CRFSNPRB_ERR_POS == new_pos_t)
    {
        (*insert_pos) = CRFSNPRB_ERR_POS;
        return (EC_FALSE);
    }
    else
    {
        CRFSNPRB_NODE *node;

        node  = CRFSNPRB_POOL_NODE(pool, new_pos_t);
        CRFSNPRB_NODE_DATA(node) = data;

        CRFSNPRB_NODE_PARENT_POS(node) = parent_pos_t;
        CRFSNPRB_NODE_COLOR(node)      = CRFSNPRB_RED;
        CRFSNPRB_NODE_LEFT_POS(node)   = CRFSNPRB_ERR_POS;
        CRFSNPRB_NODE_RIGHT_POS(node)  = CRFSNPRB_ERR_POS;

        if(CRFSNPRB_ERR_POS == (*root_pos))
        {
            (*root_pos) = new_pos_t;
        }
        else
        {
            CRFSNPRB_NODE *parent;
            parent  = CRFSNPRB_POOL_NODE(pool, parent_pos_t);

            if(0 == flag)/*on left subtree*/
            {
                CRFSNPRB_NODE_LEFT_POS(parent) = new_pos_t;
            }
            else
            {
                CRFSNPRB_NODE_RIGHT_POS(parent) = new_pos_t;
            }
        }
        __crfsnprb_tree_insert_color(pool, new_pos_t, root_pos);
    }

    (*insert_pos) = new_pos_t;
    return (EC_TRUE); /*it is new node*/
}

EC_BOOL crfsnprb_tree_delete_data(CRFSNPRB_POOL *pool, uint32_t *root_pos, const uint32_t data, const uint32_t klen, const uint8_t *key, uint32_t *delete_pos)
{
    uint32_t node_pos;

    node_pos = crfsnprb_tree_search_data(pool, *root_pos, data, klen, key);
    if(CRFSNPRB_ERR_POS == node_pos)
    {
        return (EC_FALSE);
    }

    crfsnprb_tree_erase(pool, node_pos, root_pos);
    crfsnprb_node_free(pool, node_pos);

    (*delete_pos) = node_pos;
    return (EC_TRUE);
}


EC_BOOL crfsnprb_tree_delete(CRFSNPRB_POOL *pool, uint32_t *root_pos, const uint32_t node_pos)
{
    crfsnprb_tree_erase(pool, node_pos, root_pos);
    crfsnprb_node_free(pool, node_pos);
    return (EC_TRUE);
}


/*postorder: left -> right -> root*/
STATIC_CAST static void __crfsnprb_tree_free(CRFSNPRB_POOL *pool, const uint32_t node_pos)
{
    CRFSNPRB_NODE *node;

    if(CRFSNPRB_ERR_POS == node_pos)
    {
        return;
    }

    node  = CRFSNPRB_POOL_NODE(pool, node_pos);
    if(CRFSNPRB_ERR_POS != CRFSNPRB_NODE_LEFT_POS(node))
    {
        __crfsnprb_tree_free(pool, CRFSNPRB_NODE_LEFT_POS(node));
    }

    if(CRFSNPRB_ERR_POS != CRFSNPRB_NODE_RIGHT_POS(node))
    {
        __crfsnprb_tree_free(pool, CRFSNPRB_NODE_RIGHT_POS(node));
    }

    crfsnprb_node_free(pool, node_pos);

    return;
}
void crfsnprb_tree_free(CRFSNPRB_POOL *pool, const uint32_t root_pos)
{
    __crfsnprb_tree_free(pool, root_pos);
    return;
}

EC_BOOL crfsnprb_pool_init(CRFSNPRB_POOL *pool, const uint32_t node_max_num, const uint32_t node_sizeof)
{
    uint32_t node_pos;

    if(CRFSNPRB_POOL_MAX_SIZE < node_max_num)
    {
        dbg_log(SEC_0100_CRFSNPRB, 0)(LOGSTDERR, "error:crfsnprb_pool_init: node_max_num %u overflow!\n", node_max_num);
        return (EC_FALSE);
    }

    CRFSNPRB_POOL_NODE_MAX_NUM(pool)  = node_max_num;
    CRFSNPRB_POOL_NODE_USED_NUM(pool) = 0;
    CRFSNPRB_POOL_NODE_SIZEOF(pool)   = node_sizeof;

    for(node_pos = 0; node_pos < node_max_num; node_pos ++)
    {
        crfsnprb_node_init(pool, node_pos);
        crfsnprb_node_set_next(pool, node_pos, node_pos + 1);

        if(0 == ((node_pos + 1) % 100000))
        {
            dbg_log(SEC_0100_CRFSNPRB, 0)(LOGSTDOUT, "info:crfsnprb_pool_init: init node %u - %u of max %u done\n",
                               node_pos - 99999, node_pos, node_max_num);
        }
    }
    dbg_log(SEC_0100_CRFSNPRB, 0)(LOGSTDOUT, "info:crfsnprb_pool_init: init %u nodes done\n", node_max_num);
    crfsnprb_node_set_next(pool, node_max_num - 1, CRFSNPRB_ERR_POS);/*overwrite the last one*/

    CRFSNPRB_POOL_FREE_HEAD(pool) = 0;/*the free nodes head*/
    return (EC_TRUE);
}

void crfsnprb_pool_clean(CRFSNPRB_POOL *pool)
{
    CRFSNPRB_POOL_NODE_MAX_NUM(pool)  = 0;
    CRFSNPRB_POOL_FREE_HEAD(pool)     = CRFSNPRB_ERR_POS;
    return;
}

void crfsnprb_pool_print(LOG *log, const CRFSNPRB_POOL *pool)
{
    uint32_t node_pos;
    uint32_t node_max_num;

    node_max_num = CRFSNPRB_POOL_NODE_MAX_NUM(pool);

    sys_log(log, "pool %lx, node_max_num %u, node_used_num %u, free_head %u, node_sizeof = %u\n",
                 pool,
                 node_max_num,
                 CRFSNPRB_POOL_NODE_USED_NUM(pool),
                 CRFSNPRB_POOL_FREE_HEAD(pool),
                 CRFSNPRB_POOL_NODE_SIZEOF(pool));

    if(0)
    {
        for(node_pos = 0; node_pos < node_max_num; node_pos ++)
        {
            if(EC_TRUE == crfsnprb_node_is_used(pool, node_pos))
            {
                crfsnprb_node_print(log, pool, node_pos);
            }
        }
    }
    return;
}


EC_BOOL crfsnprb_pool_is_empty(const CRFSNPRB_POOL *pool)
{
    if (0 == CRFSNPRB_POOL_NODE_USED_NUM(pool))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL crfsnprb_pool_is_full(const CRFSNPRB_POOL *pool)
{
    if (CRFSNPRB_POOL_NODE_MAX_NUM(pool) == CRFSNPRB_POOL_NODE_USED_NUM(pool))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

/*visit the root node first: root -> left -> right*/
void crfsnprb_preorder_print(LOG *log, const CRFSNPRB_POOL *pool, const uint32_t node_pos)
{
    const CRFSNPRB_NODE *node;

    if(CRFSNPRB_ERR_POS == node_pos)
    {
        return;
    }

    node  = CRFSNPRB_POOL_NODE(pool, node_pos);
    crfsnprb_node_print(log, pool, node_pos);

    if(CRFSNPRB_ERR_POS != CRFSNPRB_NODE_LEFT_POS(node))
    {
        crfsnprb_preorder_print(log, pool, CRFSNPRB_NODE_LEFT_POS(node));
    }

    if(CRFSNPRB_ERR_POS != CRFSNPRB_NODE_RIGHT_POS(node))
    {
        crfsnprb_preorder_print(log, pool, CRFSNPRB_NODE_RIGHT_POS(node));
    }

    return;
}

/*visit the left subtree, then the root node: left -> root -> right*/
void crfsnprb_inorder_print(LOG *log, const CRFSNPRB_POOL *pool, const uint32_t node_pos)
{
    const CRFSNPRB_NODE *node;

    if(CRFSNPRB_ERR_POS == node_pos)
    {
        return;
    }

    node  = CRFSNPRB_POOL_NODE(pool, node_pos);
    if(CRFSNPRB_ERR_POS != CRFSNPRB_NODE_LEFT_POS(node))
    {
        crfsnprb_inorder_print(log, pool, CRFSNPRB_NODE_LEFT_POS(node));
    }

    crfsnprb_node_print(log, pool, node_pos);

    if(CRFSNPRB_ERR_POS != CRFSNPRB_NODE_RIGHT_POS(node))
    {
        crfsnprb_inorder_print(log, pool, CRFSNPRB_NODE_RIGHT_POS(node));
    }

    return;
}

/*visit the root node last: left -> right -> root*/
void crfsnprb_postorder_print(LOG *log, const CRFSNPRB_POOL *pool, const uint32_t node_pos)
{
    const CRFSNPRB_NODE *node;

    if(CRFSNPRB_ERR_POS == node_pos)
    {
        return;
    }

    node  = CRFSNPRB_POOL_NODE(pool, node_pos);
    if(CRFSNPRB_ERR_POS != CRFSNPRB_NODE_LEFT_POS(node))
    {
        crfsnprb_postorder_print(log, pool, CRFSNPRB_NODE_LEFT_POS(node));
    }

    if(CRFSNPRB_ERR_POS != CRFSNPRB_NODE_RIGHT_POS(node))
    {
        crfsnprb_postorder_print(log, pool, CRFSNPRB_NODE_RIGHT_POS(node));
    }

    crfsnprb_node_print(log, pool, node_pos);

    return;
}


/*visit the root node first: root -> left -> right*/
void crfsnprb_preorder_print_level(LOG *log, const CRFSNPRB_POOL *pool, const uint32_t node_pos, const uint32_t level)
{
    const CRFSNPRB_NODE *node;

    if(CRFSNPRB_ERR_POS == node_pos)
    {
        return;
    }

    node  = CRFSNPRB_POOL_NODE(pool, node_pos);
    crfsnprb_node_print_level(log, pool, node_pos, level);

    if(CRFSNPRB_ERR_POS != CRFSNPRB_NODE_LEFT_POS(node))
    {
        crfsnprb_preorder_print_level(log, pool, CRFSNPRB_NODE_LEFT_POS(node), level + 1);
    }

    if(CRFSNPRB_ERR_POS != CRFSNPRB_NODE_RIGHT_POS(node))
    {
        crfsnprb_preorder_print_level(log, pool, CRFSNPRB_NODE_RIGHT_POS(node), level + 1);
    }

    return;
}

EC_BOOL crfsnprb_flush_size(const CRFSNPRB_POOL *pool, UINT32 *size)
{
    (*size) += sizeof(CRFSNPRB_POOL) + CRFSNPRB_POOL_NODE_MAX_NUM(pool) * CRFSNPRB_POOL_NODE_SIZEOF(pool);
    return (EC_TRUE);
}

EC_BOOL crfsnprb_flush(const CRFSNPRB_POOL *pool, int fd, UINT32 *offset)
{
    UINT32 osize;/*write once size*/

    /*flush free_head*/
    osize = sizeof(uint32_t);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(CRFSNPRB_POOL_FREE_HEAD(pool))))
    {
        dbg_log(SEC_0100_CRFSNPRB, 0)(LOGSTDOUT, "error:crfsnprb_flush: write CRFSNPRB_POOL_FREE_HEAD at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*flush node_max_num*/
    osize  = sizeof(uint32_t);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(CRFSNPRB_POOL_NODE_MAX_NUM(pool))))
    {
        dbg_log(SEC_0100_CRFSNPRB, 0)(LOGSTDOUT, "error:crfsnprb_flush: write CRFSNPRB_POOL_NODE_MAX_NUM at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*flush node_used_num*/
    osize  = sizeof(uint32_t);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(CRFSNPRB_POOL_NODE_USED_NUM(pool))))
    {
        dbg_log(SEC_0100_CRFSNPRB, 0)(LOGSTDOUT, "error:crfsnprb_flush: write CRFSNPRB_POOL_NODE_USED_NUM at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*flush node_sizeof*/
    osize  = sizeof(uint32_t);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(CRFSNPRB_POOL_NODE_SIZEOF(pool))))
    {
        dbg_log(SEC_0100_CRFSNPRB, 0)(LOGSTDOUT, "error:crfsnprb_flush: write CRFSNPRB_POOL_NODE_SIZEOF at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*flush rb_node table*/
    osize  = CRFSNPRB_POOL_NODE_MAX_NUM(pool) * CRFSNPRB_POOL_NODE_SIZEOF(pool);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)CRFSNPRB_POOL_NODE_TBL(pool)))
    {
        dbg_log(SEC_0100_CRFSNPRB, 0)(LOGSTDOUT, "error:crfsnprb_flush: write CRFSNPRB_POOL_NODE_TBL at offset %ld of fd %d failed where CRFSNPRB_POOL_NODE_MAX_NUM is %u\n",
                            (*offset), fd, CRFSNPRB_POOL_NODE_MAX_NUM(pool));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfsnprb_load(CRFSNPRB_POOL *pool, int fd, UINT32 *offset)
{
    UINT32 osize;/*read once size*/
    uint32_t node_max_num;
    uint32_t node_used_num;
    uint32_t node_sizeof;

    /*load free_head*/
    osize = sizeof(uint32_t);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(CRFSNPRB_POOL_FREE_HEAD(pool))))
    {
        dbg_log(SEC_0100_CRFSNPRB, 0)(LOGSTDOUT, "error:crfsnprb_load: load CRFSNPRB_POOL_FREE_HEAD at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*load node_max_num*/
    osize  = sizeof(uint32_t);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(node_max_num)))
    {
        dbg_log(SEC_0100_CRFSNPRB, 0)(LOGSTDOUT, "error:crfsnprb_load: load CRFSNPRB_POOL_NODE_MAX_NUM at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }
    CRFSNPRB_POOL_NODE_MAX_NUM(pool) = node_max_num;

    /*load node_used_num*/
    osize  = sizeof(uint32_t);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(node_used_num)))
    {
        dbg_log(SEC_0100_CRFSNPRB, 0)(LOGSTDOUT, "error:crfsnprb_load: load CRFSNPRB_POOL_NODE_USED_NUM at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }
    CRFSNPRB_POOL_NODE_MAX_NUM(pool) = node_used_num;

    /*load node_sizeof*/
    osize  = sizeof(uint32_t);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(node_sizeof)))
    {
        dbg_log(SEC_0100_CRFSNPRB, 0)(LOGSTDOUT, "error:crfsnprb_load: load CRFSNPRB_POOL_NODE_SIZEOF at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }
    CRFSNPRB_POOL_NODE_SIZEOF(pool) = node_sizeof;

    /*load rb_node table*/
    osize  = CRFSNPRB_POOL_NODE_MAX_NUM(pool) * CRFSNPRB_POOL_NODE_SIZEOF(pool);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)CRFSNPRB_POOL_NODE_TBL(pool)))
    {
        dbg_log(SEC_0100_CRFSNPRB, 0)(LOGSTDOUT, "error:crfsnprb_load: load CRFSNPRB_POOL_NODE_TBL at offset %ld of fd %d failed where CRFSNPRB_POOL_NODE_MAX_NUM is %u\n",
                            (*offset), fd, CRFSNPRB_POOL_NODE_MAX_NUM(pool));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

void crfsnprb_tree_print(LOG *log, const CRFSNPRB_POOL *pool, const uint32_t root_pos)
{
    uint32_t node_pos;

    sys_log(log, "[root = %5d]\n", root_pos);
    for(node_pos = crfsnprb_tree_first_node(pool, root_pos); CRFSNPRB_ERR_POS != node_pos; node_pos = crfsnprb_tree_next_node(pool, node_pos))
    {
        crfsnprb_node_print(log, pool, node_pos);
    }
    return;
}

/* ---- debug ---- */
EC_BOOL crfsnprb_node_debug_cmp(const CRFSNPRB_NODE *node_1st, const CRFSNPRB_NODE *node_2nd, int (*node_cmp_data)(const CRFSNPRB_NODE *, const CRFSNPRB_NODE *))
{
    if(CRFSNPRB_NODE_USED_FLAG(node_1st) != CRFSNPRB_NODE_USED_FLAG(node_2nd))
    {
        dbg_log(SEC_0100_CRFSNPRB, 0)(LOGSTDERR, "error:crfsnprb_node_debug_cmp: inconsistent CRFSNPRB_NODE_USED_FLAG: %u != %u\n",
                            CRFSNPRB_NODE_USED_FLAG(node_1st), CRFSNPRB_NODE_USED_FLAG(node_2nd));
        return (EC_FALSE);
    }
#if 0
    if(CRFSNPRB_NODE_NOT_USED == CRFSNPRB_NODE_USED_FLAG(node_1st))
    {
        return (EC_TRUE);
    }
#endif

    if(CRFSNPRB_NODE_COLOR(node_1st) != CRFSNPRB_NODE_COLOR(node_2nd))
    {
        dbg_log(SEC_0100_CRFSNPRB, 0)(LOGSTDERR, "error:crfsnprb_node_debug_cmp: inconsistent CRFSNPRB_NODE_COLOR: %u != %u\n",
                            CRFSNPRB_NODE_COLOR(node_1st), CRFSNPRB_NODE_COLOR(node_2nd));
        return (EC_FALSE);
    }

    if(CRFSNPRB_NODE_PARENT_POS(node_1st) != CRFSNPRB_NODE_PARENT_POS(node_2nd))
    {
        dbg_log(SEC_0100_CRFSNPRB, 0)(LOGSTDERR, "error:crfsnprb_node_debug_cmp: inconsistent CRFSNPRB_NODE_PARENT_POS: %u != %u\n",
                            CRFSNPRB_NODE_PARENT_POS(node_1st), CRFSNPRB_NODE_PARENT_POS(node_2nd));
        return (EC_FALSE);
    }

    if(CRFSNPRB_NODE_RIGHT_POS(node_1st) != CRFSNPRB_NODE_RIGHT_POS(node_2nd))
    {
        dbg_log(SEC_0100_CRFSNPRB, 0)(LOGSTDERR, "error:crfsnprb_node_debug_cmp: inconsistent CRFSNPRB_NODE_RIGHT_POS: %u != %u\n",
                            CRFSNPRB_NODE_RIGHT_POS(node_1st), CRFSNPRB_NODE_RIGHT_POS(node_2nd));
        return (EC_FALSE);
    }

    if(CRFSNPRB_NODE_LEFT_POS(node_1st) != CRFSNPRB_NODE_LEFT_POS(node_2nd))
    {
        dbg_log(SEC_0100_CRFSNPRB, 0)(LOGSTDERR, "error:crfsnprb_node_debug_cmp: inconsistent CRFSNPRB_NODE_LEFT_POS: %u != %u\n",
                            CRFSNPRB_NODE_LEFT_POS(node_1st), CRFSNPRB_NODE_LEFT_POS(node_2nd));
        return (EC_FALSE);
    }

    if(CRFSNPRB_NODE_USED == CRFSNPRB_NODE_USED_FLAG(node_1st))
    {
        if(0 != node_cmp_data(node_1st, node_2nd))
        {
            dbg_log(SEC_0100_CRFSNPRB, 0)(LOGSTDERR, "error:crfsnprb_node_debug_cmp: inconsistent data part\n");
            return (EC_FALSE);
        }
    }
    else
    {
        if(CRFSNPRB_NODE_NEXT_POS(node_1st) != CRFSNPRB_NODE_NEXT_POS(node_2nd))
        {
            dbg_log(SEC_0100_CRFSNPRB, 0)(LOGSTDERR, "error:crfsnprb_node_debug_cmp: inconsistent CRFSNPRB_NODE_NEXT_POS: %u != %u\n",
                                CRFSNPRB_NODE_NEXT_POS(node_1st), CRFSNPRB_NODE_NEXT_POS(node_2nd));
            return (EC_FALSE);
        }
    }
    return (EC_TRUE);
}

EC_BOOL crfsnprb_debug_cmp(const CRFSNPRB_POOL *pool_1st, const CRFSNPRB_POOL *pool_2nd, int (*node_cmp_data)(const CRFSNPRB_NODE *, const CRFSNPRB_NODE *))
{
    uint32_t  node_max_num;
    uint32_t  node_pos;

    if(CRFSNPRB_POOL_FREE_HEAD(pool_1st) != CRFSNPRB_POOL_FREE_HEAD(pool_2nd))
    {
        dbg_log(SEC_0100_CRFSNPRB, 0)(LOGSTDERR, "error:crfsnprb_debug_cmp: inconsistent CRFSNPRB_POOL_FREE_HEAD: %u != %u\n",
                            CRFSNPRB_POOL_FREE_HEAD(pool_1st), CRFSNPRB_POOL_FREE_HEAD(pool_2nd));
        return (EC_FALSE);
    }

    if(CRFSNPRB_POOL_NODE_MAX_NUM(pool_1st) != CRFSNPRB_POOL_NODE_MAX_NUM(pool_2nd))
    {
        dbg_log(SEC_0100_CRFSNPRB, 0)(LOGSTDERR, "error:crfsnprb_debug_cmp: inconsistent CRFSNPRB_POOL_NODE_MAX_NUM: %u != %u\n",
                            CRFSNPRB_POOL_NODE_MAX_NUM(pool_1st), CRFSNPRB_POOL_NODE_MAX_NUM(pool_2nd));
        return (EC_FALSE);
    }

    if(CRFSNPRB_POOL_NODE_USED_NUM(pool_1st) != CRFSNPRB_POOL_NODE_USED_NUM(pool_2nd))
    {
        dbg_log(SEC_0100_CRFSNPRB, 0)(LOGSTDERR, "error:crfsnprb_debug_cmp: inconsistent CRFSNPRB_POOL_NODE_USED_NUM: %u != %u\n",
                            CRFSNPRB_POOL_NODE_USED_NUM(pool_1st), CRFSNPRB_POOL_NODE_USED_NUM(pool_2nd));
        return (EC_FALSE);
    }

    if(CRFSNPRB_POOL_NODE_SIZEOF(pool_1st) != CRFSNPRB_POOL_NODE_SIZEOF(pool_2nd))
    {
        dbg_log(SEC_0100_CRFSNPRB, 0)(LOGSTDERR, "error:crfsnprb_debug_cmp: inconsistent CRFSNPRB_POOL_NODE_SIZEOF: %u != %u\n",
                            CRFSNPRB_POOL_NODE_SIZEOF(pool_1st), CRFSNPRB_POOL_NODE_SIZEOF(pool_2nd));
        return (EC_FALSE);
    }

    node_max_num = CRFSNPRB_POOL_NODE_MAX_NUM(pool_1st);
    for(node_pos = 0; node_pos < node_max_num; node_pos ++)
    {
        CRFSNPRB_NODE *node_1st;
        CRFSNPRB_NODE *node_2nd;

        node_1st = CRFSNPRB_POOL_NODE(pool_1st, node_pos);
        node_2nd = CRFSNPRB_POOL_NODE(pool_2nd, node_pos);

        if(EC_FALSE == crfsnprb_node_debug_cmp(node_1st, node_2nd, node_cmp_data))
        {
            dbg_log(SEC_0100_CRFSNPRB, 0)(LOGSTDERR, "error:crfsnprb_debug_cmp: inconsistent node at pos %u\n", node_pos);
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}


#ifdef __cplusplus
}
#endif/*__cplusplus*/
