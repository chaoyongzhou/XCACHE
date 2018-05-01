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

#include "chfsnprb.h"
#include "chfsnp.h"


/*new a CHFSNPRB_NODE and return its position*/
uint32_t chfsnprb_node_new(CHFSNPRB_POOL *pool)
{
    uint32_t node_pos_t;
    CHFSNPRB_NODE *node;

    node_pos_t = CHFSNPRB_POOL_FREE_HEAD(pool);
    if(CHFSNPRB_ERR_POS == node_pos_t)
    {
        dbg_log(SEC_0073_CHFSNPRB, 0)(LOGSTDERR, "error:chfsnprb_node_new: no free node in pool\n");
        return (CHFSNPRB_ERR_POS);
    }

    if(CHFSNPRB_POOL_FREE_HEAD(pool) >= CHFSNPRB_POOL_NODE_MAX_NUM(pool))
    {
        dbg_log(SEC_0073_CHFSNPRB, 0)(LOGSTDERR, "error:chfsnprb_node_new: found conflict: free head %u >= max num %u\n",
                            CHFSNPRB_POOL_FREE_HEAD(pool), CHFSNPRB_POOL_NODE_MAX_NUM(pool));
        return (CHFSNPRB_ERR_POS);
    }

    ASSERT(CHFSNPRB_POOL_FREE_HEAD(pool) < CHFSNPRB_POOL_NODE_MAX_NUM(pool));

    node = CHFSNPRB_POOL_NODE(pool, node_pos_t);
    CHFSNPRB_POOL_FREE_HEAD(pool) = CHFSNPRB_NODE_NEXT_POS(node);
    CHFSNPRB_POOL_NODE_USED_NUM(pool) ++;

    CHFSNPRB_NODE_NEXT_POS(node)  = CHFSNPRB_ERR_POS;
    CHFSNPRB_NODE_USED_FLAG(node) = CHFSNPRB_NODE_USED;

    return (node_pos_t);
}

/*free a CHFSNPRB_NODE and return its position to the pool*/
void chfsnprb_node_free(CHFSNPRB_POOL *pool, const uint32_t node_pos)
{
    if(CHFSNPRB_ERR_POS != node_pos)
    {
        CHFSNPRB_NODE *node;

        ASSERT(node_pos < CHFSNPRB_POOL_NODE_MAX_NUM(pool));

        node = CHFSNPRB_POOL_NODE(pool, node_pos);
        ASSERT(CHFSNPRB_NODE_IS_USED(node));

        CHFSNPRB_NODE_USED_FLAG(node)  = CHFSNPRB_NODE_NOT_USED;
        CHFSNPRB_NODE_PARENT_POS(node) = CHFSNPRB_ERR_POS;
        CHFSNPRB_NODE_RIGHT_POS(node)  = CHFSNPRB_ERR_POS;
        CHFSNPRB_NODE_LEFT_POS(node)   = CHFSNPRB_ERR_POS;
        CHFSNPRB_NODE_NEXT_POS(node)   = CHFSNPRB_POOL_FREE_HEAD(pool);
        CHFSNPRB_NODE_COLOR(node)      = CHFSNPRB_BLACK;

        CHFSNPRB_POOL_FREE_HEAD(pool)  = node_pos;
        CHFSNPRB_POOL_NODE_USED_NUM(pool) --;
    }
    return;
}

void chfsnprb_node_init(CHFSNPRB_POOL *pool, const uint32_t node_pos)
{
    CHFSNPRB_NODE *node;

    node  = CHFSNPRB_POOL_NODE(pool, node_pos);

    CHFSNPRB_NODE_PARENT_POS(node) = CHFSNPRB_ERR_POS;
    CHFSNPRB_NODE_RIGHT_POS(node)  = CHFSNPRB_ERR_POS;
    CHFSNPRB_NODE_LEFT_POS(node)   = CHFSNPRB_ERR_POS;
    CHFSNPRB_NODE_USED_FLAG(node)  = CHFSNPRB_NODE_NOT_USED;
    CHFSNPRB_NODE_NEXT_POS(node)   = CHFSNPRB_ERR_POS;
    CHFSNPRB_NODE_COLOR(node)      = CHFSNPRB_BLACK;

    return;
}

void chfsnprb_node_clean(CHFSNPRB_POOL *pool, const uint32_t node_pos)
{
    CHFSNPRB_NODE *node;

    ASSERT(node_pos < CHFSNPRB_POOL_NODE_MAX_NUM(pool));

    node  = CHFSNPRB_POOL_NODE(pool, node_pos);

    CHFSNPRB_NODE_PARENT_POS(node) = CHFSNPRB_ERR_POS;
    CHFSNPRB_NODE_RIGHT_POS(node)  = CHFSNPRB_ERR_POS;
    CHFSNPRB_NODE_LEFT_POS(node)   = CHFSNPRB_ERR_POS;
    CHFSNPRB_NODE_USED_FLAG(node)  = CHFSNPRB_NODE_NOT_USED;
    CHFSNPRB_NODE_NEXT_POS(node)   = CHFSNPRB_ERR_POS;
    CHFSNPRB_NODE_COLOR(node)      = CHFSNPRB_BLACK;

    return;
}

void chfsnprb_node_set_next(CHFSNPRB_POOL *pool, const uint32_t node_pos, const uint32_t next_pos)
{
    CHFSNPRB_NODE *node;

    node  = CHFSNPRB_POOL_NODE(pool, node_pos);
    CHFSNPRB_NODE_NEXT_POS(node) = next_pos;

    return;
}

EC_BOOL chfsnprb_node_is_used(const CHFSNPRB_POOL *pool, const uint32_t node_pos)
{
    const CHFSNPRB_NODE *node;
    node  = CHFSNPRB_POOL_NODE(pool, node_pos);

    if(CHFSNPRB_NODE_IS_USED(node))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

void chfsnprb_node_print(LOG *log, const CHFSNPRB_POOL *pool, const uint32_t node_pos)
{
    const CHFSNPRB_NODE *node;
    node  = CHFSNPRB_POOL_NODE(pool, node_pos);

    sys_log(log, "%5d: parent = %5d, left = %5d, right = %5d, flg = %s, color = %s, %s = %5d\n",
                       node_pos,
                       CHFSNPRB_NODE_PARENT_POS(node),
                       CHFSNPRB_NODE_LEFT_POS(node),
                       CHFSNPRB_NODE_RIGHT_POS(node),
                       CHFSNPRB_NODE_IS_USED(node) ? "used" : "n.a.",
                       CHFSNPRB_NODE_IS_USED(node) ? (CHFSNPRB_NODE_IS_RED(node) ? "red  " : "black") : "#####",
                       CHFSNPRB_NODE_IS_USED(node) ? "data" : "next",
                       CHFSNPRB_NODE_IS_USED(node) ? CHFSNPRB_NODE_DATA(node) : CHFSNPRB_NODE_NEXT_POS(node)
                       );
    return;
}

void chfsnprb_node_print_level(LOG *log, const CHFSNPRB_POOL *pool, const uint32_t node_pos, const uint32_t level)
{
    const CHFSNPRB_NODE *node;
    node  = CHFSNPRB_POOL_NODE(pool, node_pos);

    c_ident_print(log, level);
    sys_print(log, "%5d: parent = %5d, left = %5d, right = %5d, flg = %s, color = %s, %s = %5d\n",
                       node_pos,
                       CHFSNPRB_NODE_PARENT_POS(node),
                       CHFSNPRB_NODE_LEFT_POS(node),
                       CHFSNPRB_NODE_RIGHT_POS(node),
                       CHFSNPRB_NODE_IS_USED(node) ? "used" : "NOT used",
                       CHFSNPRB_NODE_IS_RED(node)  ? "red  " : "black",
                       CHFSNPRB_NODE_IS_USED(node) ? "data" : "next",
                       CHFSNPRB_NODE_IS_USED(node) ? CHFSNPRB_NODE_DATA(node) : CHFSNPRB_NODE_NEXT_POS(node)
                       );
    return;
}


STATIC_CAST static void __chfsnprb_tree_rotate_left(CHFSNPRB_POOL *pool, const uint32_t node_pos, uint32_t *root_pos)
{
    CHFSNPRB_NODE *node;
    CHFSNPRB_NODE *right;

    uint32_t  right_pos;

    node  = CHFSNPRB_POOL_NODE(pool, node_pos);

    right_pos = CHFSNPRB_NODE_RIGHT_POS(node);
    right = CHFSNPRB_POOL_NODE(pool, right_pos);

    if(CHFSNPRB_ERR_POS != (CHFSNPRB_NODE_RIGHT_POS(node) = CHFSNPRB_NODE_LEFT_POS(right)))
    {
        CHFSNPRB_NODE *left;
        left = CHFSNPRB_POOL_NODE(pool, CHFSNPRB_NODE_LEFT_POS(right));
        CHFSNPRB_NODE_PARENT_POS(left) = node_pos;
    }
    CHFSNPRB_NODE_LEFT_POS(right) = node_pos;

    if(CHFSNPRB_ERR_POS != (CHFSNPRB_NODE_PARENT_POS(right) = CHFSNPRB_NODE_PARENT_POS(node)))
    {
        CHFSNPRB_NODE *parent;
        parent = CHFSNPRB_POOL_NODE(pool, CHFSNPRB_NODE_PARENT_POS(node));

        if (node_pos == CHFSNPRB_NODE_LEFT_POS(parent))
        {
            CHFSNPRB_NODE_LEFT_POS(parent) = right_pos;
        }
        else
        {
            CHFSNPRB_NODE_RIGHT_POS(parent) = right_pos;
        }
    }
    else
    {
        (*root_pos) = right_pos;
    }
    CHFSNPRB_NODE_PARENT_POS(node) = right_pos;
    return;
}

STATIC_CAST static void __chfsnprb_tree_rotate_right(CHFSNPRB_POOL *pool, const uint32_t node_pos, uint32_t *root_pos)
{
    CHFSNPRB_NODE *node;
    CHFSNPRB_NODE *left;
    uint32_t  left_pos;

    node  = CHFSNPRB_POOL_NODE(pool, node_pos);

    left_pos = CHFSNPRB_NODE_LEFT_POS(node);
    left = CHFSNPRB_POOL_NODE(pool, left_pos);

    if (CHFSNPRB_ERR_POS != (CHFSNPRB_NODE_LEFT_POS(node) = CHFSNPRB_NODE_RIGHT_POS(left)))
    {
        CHFSNPRB_NODE *right;
        right = CHFSNPRB_POOL_NODE(pool, CHFSNPRB_NODE_RIGHT_POS(left));
        CHFSNPRB_NODE_PARENT_POS(right) = node_pos;
    }
    CHFSNPRB_NODE_RIGHT_POS(left) = node_pos;

    if (CHFSNPRB_ERR_POS != (CHFSNPRB_NODE_PARENT_POS(left) = CHFSNPRB_NODE_PARENT_POS(node)))
    {
        CHFSNPRB_NODE *parent;
        parent = CHFSNPRB_POOL_NODE(pool, CHFSNPRB_NODE_PARENT_POS(node));

        if (node_pos == CHFSNPRB_NODE_RIGHT_POS(parent))
        {
            CHFSNPRB_NODE_RIGHT_POS(parent) = left_pos;
        }
        else
        {
            CHFSNPRB_NODE_LEFT_POS(parent) = left_pos;
        }
    }
    else
    {
        (*root_pos) = left_pos;
    }
    CHFSNPRB_NODE_PARENT_POS(node) = left_pos;
    return;
}

STATIC_CAST static void __chfsnprb_tree_insert_color(CHFSNPRB_POOL *pool, const uint32_t node_pos, uint32_t *root_pos)
{
    CHFSNPRB_NODE *node;
    CHFSNPRB_NODE *root;
    CHFSNPRB_NODE *parent;

    uint32_t  node_pos_t;

    node_pos_t = node_pos;
    node  = CHFSNPRB_POOL_NODE(pool, node_pos_t);

    while (NULL_PTR != (parent = CHFSNPRB_POOL_NODE(pool, CHFSNPRB_NODE_PARENT_POS(node))) /*parent is valid*/
         && CHFSNPRB_RED == CHFSNPRB_NODE_COLOR(parent))
    {
        uint32_t  parent_pos;
        uint32_t  gparent_pos;
        CHFSNPRB_NODE *gparent;

        parent_pos = CHFSNPRB_NODE_PARENT_POS(node);

        gparent_pos = CHFSNPRB_NODE_PARENT_POS(parent);
        ASSERT(CHFSNPRB_ERR_POS != gparent_pos);
        gparent = CHFSNPRB_POOL_NODE(pool, gparent_pos);

        if (parent_pos == CHFSNPRB_NODE_LEFT_POS(gparent))
        {
            {
                CHFSNPRB_NODE *uncle;
                if (NULL_PTR != (uncle = CHFSNPRB_POOL_NODE(pool, CHFSNPRB_NODE_RIGHT_POS(gparent))) /*uncle is valid*/
                   && CHFSNPRB_RED == CHFSNPRB_NODE_COLOR(uncle))
                {
                    CHFSNPRB_NODE_COLOR(uncle)   = CHFSNPRB_BLACK;
                    CHFSNPRB_NODE_COLOR(parent)  = CHFSNPRB_BLACK;
                    CHFSNPRB_NODE_COLOR(gparent) = CHFSNPRB_RED;

                    node = gparent;
                    node_pos_t = gparent_pos;
                    continue;
                }
            }

            if (CHFSNPRB_NODE_RIGHT_POS(parent) == node_pos_t)
            {
                __chfsnprb_tree_rotate_left(pool, parent_pos, root_pos);
                XCHG(CHFSNPRB_NODE *, parent, node);
                XCHG(uint32_t, parent_pos, node_pos_t);
            }

            CHFSNPRB_NODE_COLOR(parent)  = CHFSNPRB_BLACK;
            CHFSNPRB_NODE_COLOR(gparent) = CHFSNPRB_RED;
            __chfsnprb_tree_rotate_right(pool, gparent_pos, root_pos);
         }
         else
         {
            {
                CHFSNPRB_NODE *uncle;
                if (NULL_PTR != (uncle = CHFSNPRB_POOL_NODE(pool, CHFSNPRB_NODE_LEFT_POS(gparent))) /*uncle is valid*/
                    && CHFSNPRB_RED == CHFSNPRB_NODE_COLOR(uncle))
                {
                    CHFSNPRB_NODE_COLOR(uncle)   = CHFSNPRB_BLACK;
                    CHFSNPRB_NODE_COLOR(parent)  = CHFSNPRB_BLACK;
                    CHFSNPRB_NODE_COLOR(gparent) = CHFSNPRB_RED;

                    node = gparent;
                    node_pos_t = gparent_pos;
                    continue;
                }
            }

            if (CHFSNPRB_NODE_LEFT_POS(parent) == node_pos_t)
            {
                __chfsnprb_tree_rotate_right(pool, parent_pos, root_pos);
                XCHG(CHFSNPRB_NODE *, parent, node);
                XCHG(uint32_t, parent_pos, node_pos_t);
            }

            CHFSNPRB_NODE_COLOR(parent)  = CHFSNPRB_BLACK;
            CHFSNPRB_NODE_COLOR(gparent) = CHFSNPRB_RED;
            __chfsnprb_tree_rotate_left(pool, gparent_pos, root_pos);
        }
    }

    root = CHFSNPRB_POOL_NODE(pool, *root_pos);
    CHFSNPRB_NODE_COLOR(root) = CHFSNPRB_BLACK;
    return;
}

STATIC_CAST static void __chfsnprb_tree_erase_color(CHFSNPRB_POOL *pool, const uint32_t node_pos, const uint32_t parent_pos, uint32_t *root_pos)
{
    CHFSNPRB_NODE *node;
    uint32_t  node_pos_t;
    uint32_t  parent_pos_t;

    node_pos_t   = node_pos;
    parent_pos_t = parent_pos;

    while ((NULL_PTR == (node = CHFSNPRB_POOL_NODE(pool, node_pos_t)) || CHFSNPRB_BLACK == CHFSNPRB_NODE_COLOR(node)) && node_pos_t != (*root_pos))
    {
        CHFSNPRB_NODE *parent;

        parent = CHFSNPRB_POOL_NODE(pool, parent_pos_t);

        if (CHFSNPRB_NODE_LEFT_POS(parent) == node_pos_t)
        {
            CHFSNPRB_NODE *other;
            CHFSNPRB_NODE *o_left;
            CHFSNPRB_NODE *o_right;
            uint32_t  other_pos;

            other_pos = CHFSNPRB_NODE_RIGHT_POS(parent);
            other = CHFSNPRB_POOL_NODE(pool, other_pos);

            if (CHFSNPRB_RED == CHFSNPRB_NODE_COLOR(other))
            {
                CHFSNPRB_NODE_COLOR(other)  = CHFSNPRB_BLACK;
                CHFSNPRB_NODE_COLOR(parent) = CHFSNPRB_RED;

                __chfsnprb_tree_rotate_left(pool, parent_pos_t, root_pos);

                other_pos = CHFSNPRB_NODE_RIGHT_POS(parent);
                other = CHFSNPRB_POOL_NODE(pool, other_pos);
            }

            o_left = CHFSNPRB_POOL_NODE(pool, CHFSNPRB_NODE_LEFT_POS(other));
            o_right = CHFSNPRB_POOL_NODE(pool, CHFSNPRB_NODE_RIGHT_POS(other));

            if((NULL_PTR == o_left || CHFSNPRB_BLACK == CHFSNPRB_NODE_COLOR(o_left))
            && (NULL_PTR == o_right || CHFSNPRB_BLACK == CHFSNPRB_NODE_COLOR(o_right)))
            {
                CHFSNPRB_NODE_COLOR(other) = CHFSNPRB_RED;

                node_pos_t = parent_pos_t;
                node = CHFSNPRB_POOL_NODE(pool, node_pos_t);

                parent_pos_t = CHFSNPRB_NODE_PARENT_POS(node);
                parent = CHFSNPRB_POOL_NODE(pool, parent_pos_t);
            }
            else
            {
                if (NULL_PTR == o_right || CHFSNPRB_BLACK == CHFSNPRB_NODE_COLOR(o_right))
                {
                    if (NULL_PTR != o_left)
                    {
                        CHFSNPRB_NODE_COLOR(o_left) = CHFSNPRB_BLACK;
                    }
                    CHFSNPRB_NODE_COLOR(other) = CHFSNPRB_RED;

                    __chfsnprb_tree_rotate_right(pool, other_pos, root_pos);

                    other_pos = CHFSNPRB_NODE_RIGHT_POS(parent);
                    other = CHFSNPRB_POOL_NODE(pool, other_pos);
                    /*note: other was changed here*/
                }

                CHFSNPRB_NODE_COLOR(other) = CHFSNPRB_NODE_COLOR(parent);
                CHFSNPRB_NODE_COLOR(parent) = CHFSNPRB_BLACK;

                /*due to other may be changed before, have to get o_right again here*/
                o_right = CHFSNPRB_POOL_NODE(pool, CHFSNPRB_NODE_RIGHT_POS(other));
                if (NULL_PTR != o_right)
                {
                    CHFSNPRB_NODE_COLOR(o_right) = CHFSNPRB_BLACK;
                }

                __chfsnprb_tree_rotate_left(pool, parent_pos_t, root_pos);
                node_pos_t = (*root_pos);
                break;
            }
        }
        else
        {
            CHFSNPRB_NODE *other;
            CHFSNPRB_NODE *o_left;
            CHFSNPRB_NODE *o_right;
            uint32_t  other_pos;

            other_pos = CHFSNPRB_NODE_LEFT_POS(parent);
            other = CHFSNPRB_POOL_NODE(pool, other_pos);

            if (CHFSNPRB_RED == CHFSNPRB_NODE_COLOR(other))
            {
                CHFSNPRB_NODE_COLOR(other) = CHFSNPRB_BLACK;
                CHFSNPRB_NODE_COLOR(parent) = CHFSNPRB_RED;

                __chfsnprb_tree_rotate_right(pool, parent_pos_t, root_pos);

                other_pos = CHFSNPRB_NODE_LEFT_POS(parent);
                other = CHFSNPRB_POOL_NODE(pool, other_pos);
            }

            o_left = CHFSNPRB_POOL_NODE(pool, CHFSNPRB_NODE_LEFT_POS(other));
            o_right = CHFSNPRB_POOL_NODE(pool, CHFSNPRB_NODE_RIGHT_POS(other));

            if ((NULL_PTR == o_left  || CHFSNPRB_BLACK == CHFSNPRB_NODE_COLOR(o_left))
             && (NULL_PTR == o_right || CHFSNPRB_BLACK == CHFSNPRB_NODE_COLOR(o_right)))
            {
                CHFSNPRB_NODE_COLOR(other) = CHFSNPRB_RED;

                node_pos_t = parent_pos_t;
                node = CHFSNPRB_POOL_NODE(pool, node_pos_t);

                parent_pos_t = CHFSNPRB_NODE_PARENT_POS(node);
                parent = CHFSNPRB_POOL_NODE(pool, parent_pos_t);
            }
            else
            {
                if (NULL_PTR == o_left  || CHFSNPRB_BLACK == CHFSNPRB_NODE_COLOR(o_left))
                {
                    if (NULL_PTR != o_right)
                    {
                        CHFSNPRB_NODE_COLOR(o_right) = CHFSNPRB_BLACK;
                    }

                    CHFSNPRB_NODE_COLOR(other) = CHFSNPRB_RED;

                    __chfsnprb_tree_rotate_left(pool, other_pos, root_pos);

                    other_pos = CHFSNPRB_NODE_LEFT_POS(parent);
                    other = CHFSNPRB_POOL_NODE(pool, other_pos);
                    /*note: other was changed here*/
                }

                CHFSNPRB_NODE_COLOR(other) = CHFSNPRB_NODE_COLOR(parent);
                CHFSNPRB_NODE_COLOR(parent) = CHFSNPRB_BLACK;

                /*due to other may be changed before, have to get o_left again here*/
                o_left = CHFSNPRB_POOL_NODE(pool, CHFSNPRB_NODE_LEFT_POS(other));
                if (NULL_PTR != o_left)
                {
                    CHFSNPRB_NODE_COLOR(o_left) = CHFSNPRB_BLACK;
                }
                __chfsnprb_tree_rotate_right(pool, parent_pos_t, root_pos);
                node_pos_t = (*root_pos);
                break;
            }
        }
    }

    node = CHFSNPRB_POOL_NODE(pool, node_pos_t);
    if (NULL_PTR != node)
    {
        CHFSNPRB_NODE_COLOR(node) = CHFSNPRB_BLACK;
    }
    return;
}

/*note: erase from tree but not recycle to free nodes pool*/
EC_BOOL chfsnprb_tree_erase(CHFSNPRB_POOL *pool, const uint32_t node_pos, uint32_t *root_pos)
{
    CHFSNPRB_NODE *node;

    uint32_t node_pos_t;
    uint32_t child_pos;
    uint32_t parent_pos;
    uint32_t color;

    node_pos_t = node_pos;
    node = CHFSNPRB_POOL_NODE(pool, node_pos_t);

    ASSERT(NULL_PTR != node);
    ASSERT(CHFSNPRB_NODE_IS_USED(node));

    if (CHFSNPRB_ERR_POS == CHFSNPRB_NODE_LEFT_POS(node))
    {
        child_pos = CHFSNPRB_NODE_RIGHT_POS(node);
    }
    else if (CHFSNPRB_ERR_POS == CHFSNPRB_NODE_RIGHT_POS(node))
    {
        child_pos = CHFSNPRB_NODE_LEFT_POS(node);
    }
    else
    {
        CHFSNPRB_NODE *old;

        uint32_t old_pos;
        uint32_t left_pos;

        old_pos = node_pos_t;

        node_pos_t = CHFSNPRB_NODE_RIGHT_POS(node);
        node = CHFSNPRB_POOL_NODE(pool, node_pos_t);

        while (CHFSNPRB_ERR_POS != (left_pos = CHFSNPRB_NODE_LEFT_POS(node)))
        {
            node_pos_t = left_pos;
            node = CHFSNPRB_POOL_NODE(pool, node_pos_t);
        }

        child_pos  = CHFSNPRB_NODE_RIGHT_POS(node);
        parent_pos = CHFSNPRB_NODE_PARENT_POS(node);
        color      = CHFSNPRB_NODE_COLOR(node);

        if (CHFSNPRB_ERR_POS != child_pos)
        {
            CHFSNPRB_NODE *child;
            child = CHFSNPRB_POOL_NODE(pool, child_pos);
            CHFSNPRB_NODE_PARENT_POS(child) = parent_pos;
        }

        if (CHFSNPRB_ERR_POS != parent_pos)
        {
            CHFSNPRB_NODE *parent;

            parent = CHFSNPRB_POOL_NODE(pool, parent_pos);
            if (CHFSNPRB_NODE_LEFT_POS(parent) == node_pos_t)
            {
                CHFSNPRB_NODE_LEFT_POS(parent) = child_pos;
            }
            else
            {
                CHFSNPRB_NODE_RIGHT_POS(parent) = child_pos;
            }
        }
        else
        {
            (*root_pos) = child_pos;
        }

        if (CHFSNPRB_NODE_PARENT_POS(node) == old_pos)
        {
            parent_pos = node_pos_t;
        }

        old  = CHFSNPRB_POOL_NODE(pool, old_pos);

        CHFSNPRB_NODE_PARENT_POS(node) = CHFSNPRB_NODE_PARENT_POS(old);
        CHFSNPRB_NODE_COLOR(node)      = CHFSNPRB_NODE_COLOR(old);
        CHFSNPRB_NODE_RIGHT_POS(node)  = CHFSNPRB_NODE_RIGHT_POS(old);
        CHFSNPRB_NODE_LEFT_POS(node)   = CHFSNPRB_NODE_LEFT_POS(old);

        if (CHFSNPRB_ERR_POS != CHFSNPRB_NODE_PARENT_POS(old))
        {
            CHFSNPRB_NODE *old_parent;
            old_parent = CHFSNPRB_POOL_NODE(pool, CHFSNPRB_NODE_PARENT_POS(old));

            if (CHFSNPRB_NODE_LEFT_POS(old_parent) == old_pos)
            {
                CHFSNPRB_NODE_LEFT_POS(old_parent) = node_pos_t;
            }
            else
            {
                CHFSNPRB_NODE_RIGHT_POS(old_parent) = node_pos_t;
            }
        }
        else
        {
            (*root_pos) = node_pos_t;
        }

        {
            CHFSNPRB_NODE *old_left;

            old_left = CHFSNPRB_POOL_NODE(pool, CHFSNPRB_NODE_LEFT_POS(old));
            CHFSNPRB_NODE_PARENT_POS(old_left) = node_pos_t;
        }

        if (CHFSNPRB_ERR_POS != CHFSNPRB_NODE_RIGHT_POS(old))
        {
            CHFSNPRB_NODE *old_right;
            old_right = CHFSNPRB_POOL_NODE(pool, CHFSNPRB_NODE_RIGHT_POS(old));
            CHFSNPRB_NODE_PARENT_POS(old_right) = node_pos_t;
        }
        goto color;
    }

    parent_pos = CHFSNPRB_NODE_PARENT_POS(node);
    color = CHFSNPRB_NODE_COLOR(node);

    if (CHFSNPRB_ERR_POS != child_pos)
    {
        CHFSNPRB_NODE *child;
        child = CHFSNPRB_POOL_NODE(pool, child_pos);
        CHFSNPRB_NODE_PARENT_POS(child) = parent_pos;
    }

    if (CHFSNPRB_ERR_POS != parent_pos)
    {
        CHFSNPRB_NODE *parent;

        parent = CHFSNPRB_POOL_NODE(pool, parent_pos);
        if (CHFSNPRB_NODE_LEFT_POS(parent) == node_pos_t)
        {
            CHFSNPRB_NODE_LEFT_POS(parent) = child_pos;
        }
        else
        {
            CHFSNPRB_NODE_RIGHT_POS(parent) = child_pos;
        }
    }
    else
    {
        (*root_pos) = child_pos;
    }

 color:
    if (CHFSNPRB_BLACK == color)
    {
        __chfsnprb_tree_erase_color(pool, child_pos, parent_pos, root_pos);
    }
    return (EC_TRUE);
}

STATIC_CAST static uint32_t __chfsnprb_tree_count_node_num(const CHFSNPRB_POOL *pool, const uint32_t node_pos)
{
    const CHFSNPRB_NODE *node;

    if(CHFSNPRB_ERR_POS == node_pos)
    {
        return ((uint32_t)0);
    }

    node = CHFSNPRB_POOL_NODE(pool, node_pos);

    return (uint32_t)(1 + __chfsnprb_tree_count_node_num(pool, CHFSNPRB_NODE_LEFT_POS(node)) + __chfsnprb_tree_count_node_num(pool, CHFSNPRB_NODE_RIGHT_POS(node)));
}

uint32_t chfsnprb_tree_count_node_num(const CHFSNPRB_POOL *pool, const uint32_t root_pos)
{
    return __chfsnprb_tree_count_node_num(pool, root_pos);
}

uint32_t chfsnprb_tree_node_max_num(const CHFSNPRB_POOL *pool)
{
    return CHFSNPRB_POOL_NODE_MAX_NUM(pool);
}

uint32_t chfsnprb_tree_node_used_num(const CHFSNPRB_POOL *pool)
{
    return CHFSNPRB_POOL_NODE_USED_NUM(pool);
}

uint32_t chfsnprb_tree_node_sizeof(const CHFSNPRB_POOL *pool)
{
    return CHFSNPRB_POOL_NODE_SIZEOF(pool);
}

/*
 * This function returns the first node_pos (in sort order) of the tree.
 */
uint32_t chfsnprb_tree_first_node(const CHFSNPRB_POOL *pool, const uint32_t root_pos)
{
    uint32_t  node_pos;
    const CHFSNPRB_NODE *node;

    node_pos = root_pos;
    if (CHFSNPRB_ERR_POS == node_pos)
    {
        return (CHFSNPRB_ERR_POS);
    }

    node = CHFSNPRB_POOL_NODE(pool, node_pos);

    while (CHFSNPRB_ERR_POS != CHFSNPRB_NODE_LEFT_POS(node))
    {
        node_pos = CHFSNPRB_NODE_LEFT_POS(node);
        node = CHFSNPRB_POOL_NODE(pool, node_pos);
    }
    return (node_pos);
}

uint32_t chfsnprb_tree_last_node(const CHFSNPRB_POOL *pool, const uint32_t root_pos)
{
    uint32_t  node_pos;
    const CHFSNPRB_NODE *node;

    node_pos = root_pos;
    if (CHFSNPRB_ERR_POS == node_pos)
    {
        return (CHFSNPRB_ERR_POS);
    }

    node = CHFSNPRB_POOL_NODE(pool, node_pos);

    while (CHFSNPRB_ERR_POS != CHFSNPRB_NODE_RIGHT_POS(node))
    {
        node_pos = CHFSNPRB_NODE_RIGHT_POS(node);
        node = CHFSNPRB_POOL_NODE(pool, node_pos);
    }

    return (node_pos);
}

uint32_t chfsnprb_tree_next_node(const CHFSNPRB_POOL *pool, const uint32_t node_pos)
{
    uint32_t node_pos_t;
    const CHFSNPRB_NODE *node;
    const CHFSNPRB_NODE *parent;

    node_pos_t = node_pos;
    node = CHFSNPRB_POOL_NODE(pool, node_pos_t);
    /* If we have a right-hand child, go down and then left as far
       as we can. */
    if (CHFSNPRB_ERR_POS != CHFSNPRB_NODE_RIGHT_POS(node))
    {
        node_pos_t = CHFSNPRB_NODE_RIGHT_POS(node);
        node = CHFSNPRB_POOL_NODE(pool, node_pos_t);
        while (CHFSNPRB_ERR_POS != CHFSNPRB_NODE_LEFT_POS(node))
        {
            node_pos_t = CHFSNPRB_NODE_LEFT_POS(node);
            node = CHFSNPRB_POOL_NODE(pool, node_pos_t);
        }
        return (node_pos_t);
    }

    /* No right-hand children.  Everything down and left is
       smaller than us, so any 'next' node_pos_t must be in the general
       direction of our parent. Go up the tree; any time the
       ancestor is a right-hand child of its parent, keep going
       up. First time it's a left-hand child of its parent, said
       parent is our 'next' node_pos_t. */
    while (NULL_PTR != (parent = CHFSNPRB_POOL_NODE(pool, CHFSNPRB_NODE_PARENT_POS(node))) && node_pos_t == CHFSNPRB_NODE_RIGHT_POS(parent))
    {
        node_pos_t = CHFSNPRB_NODE_PARENT_POS(node);
        node = parent;
    }

    return (CHFSNPRB_NODE_PARENT_POS(node));
}

uint32_t chfsnprb_tree_prev_node(const CHFSNPRB_POOL *pool, const uint32_t node_pos)
{
    uint32_t node_pos_t;
    const CHFSNPRB_NODE *node;
    const CHFSNPRB_NODE *parent;

    node_pos_t = node_pos;
    node = CHFSNPRB_POOL_NODE(pool, node_pos_t);

    /* If we have a left-hand child, go down and then right as far
       as we can. */
    if (CHFSNPRB_ERR_POS != CHFSNPRB_NODE_LEFT_POS(node))
    {
        node_pos_t = CHFSNPRB_NODE_LEFT_POS(node);
        node = CHFSNPRB_POOL_NODE(pool, node_pos_t);
        while (CHFSNPRB_ERR_POS != CHFSNPRB_NODE_RIGHT_POS(node))
        {
            node_pos_t = CHFSNPRB_NODE_RIGHT_POS(node);
            node = CHFSNPRB_POOL_NODE(pool, node_pos_t);
        }
        return (node_pos_t);
    }

    /* No left-hand children. Go up till we find an ancestor which
       is a right-hand child of its parent */
    while (NULL_PTR != (parent = CHFSNPRB_POOL_NODE(pool, CHFSNPRB_NODE_PARENT_POS(node))) && node_pos_t == CHFSNPRB_NODE_LEFT_POS(parent))
    {
        node_pos_t = CHFSNPRB_NODE_PARENT_POS(node);
        node = parent;
    }

    return (CHFSNPRB_NODE_PARENT_POS(node));
}

/*victim_pos should be free*/
void chfsnprb_tree_replace_node(CHFSNPRB_POOL *pool, const uint32_t victim_pos, const uint32_t new_pos, uint32_t *root_pos)
{
    CHFSNPRB_NODE *victim;

    victim = CHFSNPRB_POOL_NODE(pool, victim_pos);

    /* Set the surrounding nodes to point to the replacement */
    if (CHFSNPRB_ERR_POS != CHFSNPRB_NODE_PARENT_POS(victim))
    {
        CHFSNPRB_NODE *parent;
        parent = CHFSNPRB_POOL_NODE(pool, CHFSNPRB_NODE_PARENT_POS(victim));

        if (victim_pos == CHFSNPRB_NODE_LEFT_POS(parent))
        {
            CHFSNPRB_NODE_LEFT_POS(parent) = new_pos;
        }
        else
        {
            CHFSNPRB_NODE_RIGHT_POS(parent) = new_pos;
        }
    }
    else
    {
        (*root_pos) = new_pos;
    }

    if (CHFSNPRB_ERR_POS != CHFSNPRB_NODE_LEFT_POS(victim))
    {
        CHFSNPRB_NODE *left;
        left = CHFSNPRB_POOL_NODE(pool, CHFSNPRB_NODE_LEFT_POS(victim));
        CHFSNPRB_NODE_PARENT_POS(left) = new_pos;
    }
    if (CHFSNPRB_ERR_POS != CHFSNPRB_NODE_RIGHT_POS(victim))
    {
        CHFSNPRB_NODE *right;
        right = CHFSNPRB_POOL_NODE(pool, CHFSNPRB_NODE_RIGHT_POS(victim));
        CHFSNPRB_NODE_PARENT_POS(right) = new_pos;
    }

    return;
}

/**
*
*   note:only for chfsnp item!
*   return -1 if node < (data, key)
*   return  1 if node > (data, key)
*   return  0 if node == (data, key)
*
**/
STATIC_CAST static int __chfsnprb_node_data_cmp(const CHFSNPRB_NODE *node, const uint32_t data, const uint32_t klen, const uint8_t *key)
{
    const CHFSNP_ITEM *item;

    if (CHFSNPRB_NODE_DATA(node) < data)
    {
        return (-1);
    }

    if (CHFSNPRB_NODE_DATA(node) > data)
    {
        return (1);
    }

    item = (const CHFSNP_ITEM *)CHFSNP_RB_NODE_ITEM(node);
    if(CHFSNP_ITEM_KLEN(item) < klen)
    {
        return (-1);
    }

    if(CHFSNP_ITEM_KLEN(item) > klen)
    {
        return (1);
    }

    return BCMP(CHFSNP_ITEM_KEY(item), key, klen);
}

/*return the searched pos*/
uint32_t chfsnprb_tree_search_data(const CHFSNPRB_POOL *pool, const uint32_t root_pos, const uint32_t data, const uint32_t klen, const uint8_t *key)
{
    uint32_t node_pos;

    node_pos = root_pos;

    while (CHFSNPRB_ERR_POS != node_pos)
    {
        const CHFSNPRB_NODE *node;
        int cmp_ret;

        node = CHFSNPRB_POOL_NODE(pool, node_pos);
        cmp_ret = __chfsnprb_node_data_cmp(node, data, klen, key);

        if (0 < cmp_ret)/*node > (data, key)*/
        {
            node_pos = CHFSNPRB_NODE_LEFT_POS(node);
        }
        else if (0 > cmp_ret)/*node < (data, key)*/
        {
            node_pos = CHFSNPRB_NODE_RIGHT_POS(node);
        }
        else /*node == (data, key)*/
        {
            return (node_pos);
        }
    }

    return (CHFSNPRB_ERR_POS);
}

/*if found duplicate node, return EC_FALSE, otherwise return EC_TRUE*/
EC_BOOL chfsnprb_tree_insert_data(CHFSNPRB_POOL *pool, uint32_t *root_pos, const uint32_t data, const uint32_t klen, const uint8_t *key, uint32_t *insert_pos)
{
    uint32_t  node_pos_t;
    uint32_t  new_pos_t;
    uint32_t  parent_pos_t;
    uint32_t  flag; /*0: on left subtree, 1: on right subtree*/

    node_pos_t   = (*root_pos);
    parent_pos_t = CHFSNPRB_ERR_POS;
    flag         = ~(uint32_t)0;

    while (CHFSNPRB_ERR_POS != node_pos_t)
    {
        CHFSNPRB_NODE *node;
        int cmp_ret;

        node = CHFSNPRB_POOL_NODE(pool, node_pos_t);
        cmp_ret = __chfsnprb_node_data_cmp(node, data, klen, key);

        parent_pos_t = node_pos_t;

        if (0 < cmp_ret)/*node > (data, key)*/
        {
            node_pos_t = CHFSNPRB_NODE_LEFT_POS(node);
            flag = 0;
        }
        else if (0 > cmp_ret)/*node < (data, key)*/
        {
            node_pos_t = CHFSNPRB_NODE_RIGHT_POS(node);
            flag = 1;
        }
        else/*node == (data, key)*/
        {
            (*insert_pos) = node_pos_t;
            return (EC_FALSE);/*found duplicate*/
        }
    }


    /*not found data in the rbtree*/
    new_pos_t = chfsnprb_node_new(pool);
    if(CHFSNPRB_ERR_POS == new_pos_t)
    {
        (*insert_pos) = CHFSNPRB_ERR_POS;
        return (EC_FALSE);
    }
    else
    {
        CHFSNPRB_NODE *node;

        node  = CHFSNPRB_POOL_NODE(pool, new_pos_t);
        CHFSNPRB_NODE_DATA(node)       = data;

        CHFSNPRB_NODE_PARENT_POS(node) = parent_pos_t;
        CHFSNPRB_NODE_COLOR(node)      = CHFSNPRB_RED;
        CHFSNPRB_NODE_LEFT_POS(node)   = CHFSNPRB_ERR_POS;
        CHFSNPRB_NODE_RIGHT_POS(node)  = CHFSNPRB_ERR_POS;

        if(CHFSNPRB_ERR_POS == (*root_pos))
        {
            (*root_pos) = new_pos_t;
        }
        else
        {
            CHFSNPRB_NODE *parent;
            parent  = CHFSNPRB_POOL_NODE(pool, parent_pos_t);

            if(0 == flag)/*on left subtree*/
            {
                CHFSNPRB_NODE_LEFT_POS(parent) = new_pos_t;
            }
            else
            {
                CHFSNPRB_NODE_RIGHT_POS(parent) = new_pos_t;
            }
        }
        __chfsnprb_tree_insert_color(pool, new_pos_t, root_pos);
    }

    (*insert_pos) = new_pos_t;
    return (EC_TRUE); /*it is new node*/
}

EC_BOOL chfsnprb_tree_delete_data(CHFSNPRB_POOL *pool, uint32_t *root_pos, const uint32_t data, const uint32_t klen, const uint8_t *key, uint32_t *delete_pos)
{
    uint32_t node_pos;

    node_pos = chfsnprb_tree_search_data(pool, *root_pos, data, klen, key);
    if(CHFSNPRB_ERR_POS == node_pos)
    {
        return (EC_FALSE);
    }

    chfsnprb_tree_erase(pool, node_pos, root_pos);
    chfsnprb_node_free(pool, node_pos);

    (*delete_pos) = node_pos;
    return (EC_TRUE);
}


EC_BOOL chfsnprb_tree_delete(CHFSNPRB_POOL *pool, uint32_t *root_pos, const uint32_t node_pos)
{
    chfsnprb_tree_erase(pool, node_pos, root_pos);
    chfsnprb_node_free(pool, node_pos);
    return (EC_TRUE);
}


/*postorder: left -> right -> root*/
STATIC_CAST static void __chfsnprb_tree_free(CHFSNPRB_POOL *pool, const uint32_t node_pos)
{
    CHFSNPRB_NODE *node;

    if(CHFSNPRB_ERR_POS == node_pos)
    {
        return;
    }

    node  = CHFSNPRB_POOL_NODE(pool, node_pos);
    if(CHFSNPRB_ERR_POS != CHFSNPRB_NODE_LEFT_POS(node))
    {
        __chfsnprb_tree_free(pool, CHFSNPRB_NODE_LEFT_POS(node));
    }

    if(CHFSNPRB_ERR_POS != CHFSNPRB_NODE_RIGHT_POS(node))
    {
        __chfsnprb_tree_free(pool, CHFSNPRB_NODE_RIGHT_POS(node));
    }

    chfsnprb_node_free(pool, node_pos);

    return;
}
void chfsnprb_tree_free(CHFSNPRB_POOL *pool, const uint32_t root_pos)
{
    __chfsnprb_tree_free(pool, root_pos);
    return;
}

EC_BOOL chfsnprb_pool_init(CHFSNPRB_POOL *pool, const uint32_t node_max_num, const uint32_t node_sizeof)
{
    uint32_t node_pos;

    if(CHFSNPRB_POOL_MAX_SIZE < node_max_num)
    {
        dbg_log(SEC_0073_CHFSNPRB, 0)(LOGSTDERR, "error:chfsnprb_pool_init: node_max_num %u overflow!\n", node_max_num);
        return (EC_FALSE);
    }

    CHFSNPRB_POOL_NODE_MAX_NUM(pool)  = node_max_num;
    CHFSNPRB_POOL_NODE_USED_NUM(pool) = 0;
    CHFSNPRB_POOL_NODE_SIZEOF(pool)   = node_sizeof;

    for(node_pos = 0; node_pos < node_max_num; node_pos ++)
    {
        chfsnprb_node_init(pool, node_pos);
        chfsnprb_node_set_next(pool, node_pos, node_pos + 1);

        if(0 == ((node_pos + 1) % 100000))
        {
            dbg_log(SEC_0073_CHFSNPRB, 0)(LOGSTDOUT, "info:chfsnprb_pool_init: init node %u - %u of max %u done\n",
                               node_pos - 99999, node_pos, node_max_num);
        }
    }
    dbg_log(SEC_0073_CHFSNPRB, 0)(LOGSTDOUT, "info:chfsnprb_pool_init: init %u nodes done\n", node_max_num);
    chfsnprb_node_set_next(pool, node_max_num - 1, CHFSNPRB_ERR_POS);/*overwrite the last one*/

    CHFSNPRB_POOL_FREE_HEAD(pool) = 0;/*the free nodes head*/
    return (EC_TRUE);
}

void chfsnprb_pool_clean(CHFSNPRB_POOL *pool)
{
    CHFSNPRB_POOL_NODE_MAX_NUM(pool)  = 0;
    CHFSNPRB_POOL_FREE_HEAD(pool)     = CHFSNPRB_ERR_POS;
    return;
}

void chfsnprb_pool_print(LOG *log, const CHFSNPRB_POOL *pool)
{
    uint32_t node_pos;
    uint32_t node_max_num;

    node_max_num = CHFSNPRB_POOL_NODE_MAX_NUM(pool);

    sys_log(log, "pool %lx, node_max_num %u, node_used_num %u, free_head %u, node_sizeof = %u\n",
                 pool,
                 node_max_num,
                 CHFSNPRB_POOL_NODE_USED_NUM(pool),
                 CHFSNPRB_POOL_FREE_HEAD(pool),
                 CHFSNPRB_POOL_NODE_SIZEOF(pool));

    if(0)
    {
        for(node_pos = 0; node_pos < node_max_num; node_pos ++)
        {
            if(EC_TRUE == chfsnprb_node_is_used(pool, node_pos))
            {
                chfsnprb_node_print(log, pool, node_pos);
            }
        }
    }
    return;
}


EC_BOOL chfsnprb_pool_is_empty(const CHFSNPRB_POOL *pool)
{
    if (0 == CHFSNPRB_POOL_NODE_USED_NUM(pool))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL chfsnprb_pool_is_full(const CHFSNPRB_POOL *pool)
{
    if (CHFSNPRB_POOL_NODE_MAX_NUM(pool) == CHFSNPRB_POOL_NODE_USED_NUM(pool))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

/*visit the root node first: root -> left -> right*/
void chfsnprb_preorder_print(LOG *log, const CHFSNPRB_POOL *pool, const uint32_t node_pos)
{
    const CHFSNPRB_NODE *node;

    if(CHFSNPRB_ERR_POS == node_pos)
    {
        return;
    }

    node  = CHFSNPRB_POOL_NODE(pool, node_pos);
    chfsnprb_node_print(log, pool, node_pos);

    if(CHFSNPRB_ERR_POS != CHFSNPRB_NODE_LEFT_POS(node))
    {
        chfsnprb_preorder_print(log, pool, CHFSNPRB_NODE_LEFT_POS(node));
    }

    if(CHFSNPRB_ERR_POS != CHFSNPRB_NODE_RIGHT_POS(node))
    {
        chfsnprb_preorder_print(log, pool, CHFSNPRB_NODE_RIGHT_POS(node));
    }

    return;
}

/*visit the left subtree, then the root node: left -> root -> right*/
void chfsnprb_inorder_print(LOG *log, const CHFSNPRB_POOL *pool, const uint32_t node_pos)
{
    const CHFSNPRB_NODE *node;

    if(CHFSNPRB_ERR_POS == node_pos)
    {
        return;
    }

    node  = CHFSNPRB_POOL_NODE(pool, node_pos);
    if(CHFSNPRB_ERR_POS != CHFSNPRB_NODE_LEFT_POS(node))
    {
        chfsnprb_inorder_print(log, pool, CHFSNPRB_NODE_LEFT_POS(node));
    }

    chfsnprb_node_print(log, pool, node_pos);

    if(CHFSNPRB_ERR_POS != CHFSNPRB_NODE_RIGHT_POS(node))
    {
        chfsnprb_inorder_print(log, pool, CHFSNPRB_NODE_RIGHT_POS(node));
    }

    return;
}

/*visit the root node last: left -> right -> root*/
void chfsnprb_postorder_print(LOG *log, const CHFSNPRB_POOL *pool, const uint32_t node_pos)
{
    const CHFSNPRB_NODE *node;

    if(CHFSNPRB_ERR_POS == node_pos)
    {
        return;
    }

    node  = CHFSNPRB_POOL_NODE(pool, node_pos);
    if(CHFSNPRB_ERR_POS != CHFSNPRB_NODE_LEFT_POS(node))
    {
        chfsnprb_postorder_print(log, pool, CHFSNPRB_NODE_LEFT_POS(node));
    }

    if(CHFSNPRB_ERR_POS != CHFSNPRB_NODE_RIGHT_POS(node))
    {
        chfsnprb_postorder_print(log, pool, CHFSNPRB_NODE_RIGHT_POS(node));
    }

    chfsnprb_node_print(log, pool, node_pos);

    return;
}


/*visit the root node first: root -> left -> right*/
void chfsnprb_preorder_print_level(LOG *log, const CHFSNPRB_POOL *pool, const uint32_t node_pos, const uint32_t level)
{
    const CHFSNPRB_NODE *node;

    if(CHFSNPRB_ERR_POS == node_pos)
    {
        return;
    }

    node  = CHFSNPRB_POOL_NODE(pool, node_pos);
    chfsnprb_node_print_level(log, pool, node_pos, level);

    if(CHFSNPRB_ERR_POS != CHFSNPRB_NODE_LEFT_POS(node))
    {
        chfsnprb_preorder_print_level(log, pool, CHFSNPRB_NODE_LEFT_POS(node), level + 1);
    }

    if(CHFSNPRB_ERR_POS != CHFSNPRB_NODE_RIGHT_POS(node))
    {
        chfsnprb_preorder_print_level(log, pool, CHFSNPRB_NODE_RIGHT_POS(node), level + 1);
    }

    return;
}

EC_BOOL chfsnprb_flush_size(const CHFSNPRB_POOL *pool, UINT32 *size)
{
    (*size) += sizeof(CHFSNPRB_POOL) + CHFSNPRB_POOL_NODE_MAX_NUM(pool) * CHFSNPRB_POOL_NODE_SIZEOF(pool);
    return (EC_TRUE);
}

EC_BOOL chfsnprb_flush(const CHFSNPRB_POOL *pool, int fd, UINT32 *offset)
{
    UINT32 osize;/*write once size*/

    /*flush free_head*/
    osize = sizeof(uint32_t);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(CHFSNPRB_POOL_FREE_HEAD(pool))))
    {
        dbg_log(SEC_0073_CHFSNPRB, 0)(LOGSTDOUT, "error:chfsnprb_flush: write CHFSNPRB_POOL_FREE_HEAD at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*flush node_max_num*/
    osize  = sizeof(uint32_t);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(CHFSNPRB_POOL_NODE_MAX_NUM(pool))))
    {
        dbg_log(SEC_0073_CHFSNPRB, 0)(LOGSTDOUT, "error:chfsnprb_flush: write CHFSNPRB_POOL_NODE_MAX_NUM at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*flush node_used_num*/
    osize  = sizeof(uint32_t);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(CHFSNPRB_POOL_NODE_USED_NUM(pool))))
    {
        dbg_log(SEC_0073_CHFSNPRB, 0)(LOGSTDOUT, "error:chfsnprb_flush: write CHFSNPRB_POOL_NODE_USED_NUM at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*flush node_sizeof*/
    osize  = sizeof(uint32_t);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(CHFSNPRB_POOL_NODE_SIZEOF(pool))))
    {
        dbg_log(SEC_0073_CHFSNPRB, 0)(LOGSTDOUT, "error:chfsnprb_flush: write CHFSNPRB_POOL_NODE_SIZEOF at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*flush rb_node table*/
    osize  = CHFSNPRB_POOL_NODE_MAX_NUM(pool) * CHFSNPRB_POOL_NODE_SIZEOF(pool);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)CHFSNPRB_POOL_NODE_TBL(pool)))
    {
        dbg_log(SEC_0073_CHFSNPRB, 0)(LOGSTDOUT, "error:chfsnprb_flush: write CHFSNPRB_POOL_NODE_TBL at offset %ld of fd %d failed where CHFSNPRB_POOL_NODE_MAX_NUM is %u\n",
                            (*offset), fd, CHFSNPRB_POOL_NODE_MAX_NUM(pool));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL chfsnprb_load(CHFSNPRB_POOL *pool, int fd, UINT32 *offset)
{
    UINT32 osize;/*read once size*/
    uint32_t node_max_num;
    uint32_t node_used_num;
    uint32_t node_sizeof;

    /*load free_head*/
    osize = sizeof(uint32_t);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(CHFSNPRB_POOL_FREE_HEAD(pool))))
    {
        dbg_log(SEC_0073_CHFSNPRB, 0)(LOGSTDOUT, "error:chfsnprb_load: load CHFSNPRB_POOL_FREE_HEAD at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*load node_max_num*/
    osize  = sizeof(uint32_t);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(node_max_num)))
    {
        dbg_log(SEC_0073_CHFSNPRB, 0)(LOGSTDOUT, "error:chfsnprb_load: load CHFSNPRB_POOL_NODE_MAX_NUM at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }
    CHFSNPRB_POOL_NODE_MAX_NUM(pool) = node_max_num;

    /*load node_used_num*/
    osize  = sizeof(uint32_t);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(node_used_num)))
    {
        dbg_log(SEC_0073_CHFSNPRB, 0)(LOGSTDOUT, "error:chfsnprb_load: load CHFSNPRB_POOL_NODE_USED_NUM at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }
    CHFSNPRB_POOL_NODE_MAX_NUM(pool) = node_used_num;

    /*load node_sizeof*/
    osize  = sizeof(uint32_t);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(node_sizeof)))
    {
        dbg_log(SEC_0073_CHFSNPRB, 0)(LOGSTDOUT, "error:chfsnprb_load: load CHFSNPRB_POOL_NODE_SIZEOF at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }
    CHFSNPRB_POOL_NODE_SIZEOF(pool) = node_sizeof;

    /*load rb_node table*/
    osize  = CHFSNPRB_POOL_NODE_MAX_NUM(pool) * CHFSNPRB_POOL_NODE_SIZEOF(pool);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)CHFSNPRB_POOL_NODE_TBL(pool)))
    {
        dbg_log(SEC_0073_CHFSNPRB, 0)(LOGSTDOUT, "error:chfsnprb_load: load CHFSNPRB_POOL_NODE_TBL at offset %ld of fd %d failed where CHFSNPRB_POOL_NODE_MAX_NUM is %u\n",
                            (*offset), fd, CHFSNPRB_POOL_NODE_MAX_NUM(pool));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

void chfsnprb_tree_print(LOG *log, const CHFSNPRB_POOL *pool, const uint32_t root_pos)
{
    uint32_t node_pos;

    sys_log(log, "[root = %5d]\n", root_pos);
    for(node_pos = chfsnprb_tree_first_node(pool, root_pos); CHFSNPRB_ERR_POS != node_pos; node_pos = chfsnprb_tree_next_node(pool, node_pos))
    {
        chfsnprb_node_print(log, pool, node_pos);
    }
    return;
}

/* ---- debug ---- */
EC_BOOL chfsnprb_node_debug_cmp(const CHFSNPRB_NODE *node_1st, const CHFSNPRB_NODE *node_2nd, int (*node_cmp_data)(const CHFSNPRB_NODE *, const CHFSNPRB_NODE *))
{
    if(CHFSNPRB_NODE_USED_FLAG(node_1st) != CHFSNPRB_NODE_USED_FLAG(node_2nd))
    {
        dbg_log(SEC_0073_CHFSNPRB, 0)(LOGSTDERR, "error:chfsnprb_node_debug_cmp: inconsistent CHFSNPRB_NODE_USED_FLAG: %u != %u\n",
                            CHFSNPRB_NODE_USED_FLAG(node_1st), CHFSNPRB_NODE_USED_FLAG(node_2nd));
        return (EC_FALSE);
    }
#if 0
    if(CHFSNPRB_NODE_NOT_USED == CHFSNPRB_NODE_USED_FLAG(node_1st))
    {
        return (EC_TRUE);
    }
#endif

    if(CHFSNPRB_NODE_COLOR(node_1st) != CHFSNPRB_NODE_COLOR(node_2nd))
    {
        dbg_log(SEC_0073_CHFSNPRB, 0)(LOGSTDERR, "error:chfsnprb_node_debug_cmp: inconsistent CHFSNPRB_NODE_COLOR: %u != %u\n",
                            CHFSNPRB_NODE_COLOR(node_1st), CHFSNPRB_NODE_COLOR(node_2nd));
        return (EC_FALSE);
    }

    if(CHFSNPRB_NODE_PARENT_POS(node_1st) != CHFSNPRB_NODE_PARENT_POS(node_2nd))
    {
        dbg_log(SEC_0073_CHFSNPRB, 0)(LOGSTDERR, "error:chfsnprb_node_debug_cmp: inconsistent CHFSNPRB_NODE_PARENT_POS: %u != %u\n",
                            CHFSNPRB_NODE_PARENT_POS(node_1st), CHFSNPRB_NODE_PARENT_POS(node_2nd));
        return (EC_FALSE);
    }

    if(CHFSNPRB_NODE_RIGHT_POS(node_1st) != CHFSNPRB_NODE_RIGHT_POS(node_2nd))
    {
        dbg_log(SEC_0073_CHFSNPRB, 0)(LOGSTDERR, "error:chfsnprb_node_debug_cmp: inconsistent CHFSNPRB_NODE_RIGHT_POS: %u != %u\n",
                            CHFSNPRB_NODE_RIGHT_POS(node_1st), CHFSNPRB_NODE_RIGHT_POS(node_2nd));
        return (EC_FALSE);
    }

    if(CHFSNPRB_NODE_LEFT_POS(node_1st) != CHFSNPRB_NODE_LEFT_POS(node_2nd))
    {
        dbg_log(SEC_0073_CHFSNPRB, 0)(LOGSTDERR, "error:chfsnprb_node_debug_cmp: inconsistent CHFSNPRB_NODE_LEFT_POS: %u != %u\n",
                            CHFSNPRB_NODE_LEFT_POS(node_1st), CHFSNPRB_NODE_LEFT_POS(node_2nd));
        return (EC_FALSE);
    }

    if(CHFSNPRB_NODE_USED == CHFSNPRB_NODE_USED_FLAG(node_1st))
    {
        if(0 != node_cmp_data(node_1st, node_2nd))
        {
            dbg_log(SEC_0073_CHFSNPRB, 0)(LOGSTDERR, "error:chfsnprb_node_debug_cmp: inconsistent data part\n");
            return (EC_FALSE);
        }
    }
    else
    {
        if(CHFSNPRB_NODE_NEXT_POS(node_1st) != CHFSNPRB_NODE_NEXT_POS(node_2nd))
        {
            dbg_log(SEC_0073_CHFSNPRB, 0)(LOGSTDERR, "error:chfsnprb_node_debug_cmp: inconsistent CHFSNPRB_NODE_NEXT_POS: %u != %u\n",
                                CHFSNPRB_NODE_NEXT_POS(node_1st), CHFSNPRB_NODE_NEXT_POS(node_2nd));
            return (EC_FALSE);
        }
    }
    return (EC_TRUE);
}

EC_BOOL chfsnprb_debug_cmp(const CHFSNPRB_POOL *pool_1st, const CHFSNPRB_POOL *pool_2nd, int (*node_cmp_data)(const CHFSNPRB_NODE *, const CHFSNPRB_NODE *))
{
    uint32_t  node_max_num;
    uint32_t  node_pos;

    if(CHFSNPRB_POOL_FREE_HEAD(pool_1st) != CHFSNPRB_POOL_FREE_HEAD(pool_2nd))
    {
        dbg_log(SEC_0073_CHFSNPRB, 0)(LOGSTDERR, "error:chfsnprb_debug_cmp: inconsistent CHFSNPRB_POOL_FREE_HEAD: %u != %u\n",
                            CHFSNPRB_POOL_FREE_HEAD(pool_1st), CHFSNPRB_POOL_FREE_HEAD(pool_2nd));
        return (EC_FALSE);
    }

    if(CHFSNPRB_POOL_NODE_MAX_NUM(pool_1st) != CHFSNPRB_POOL_NODE_MAX_NUM(pool_2nd))
    {
        dbg_log(SEC_0073_CHFSNPRB, 0)(LOGSTDERR, "error:chfsnprb_debug_cmp: inconsistent CHFSNPRB_POOL_NODE_MAX_NUM: %u != %u\n",
                            CHFSNPRB_POOL_NODE_MAX_NUM(pool_1st), CHFSNPRB_POOL_NODE_MAX_NUM(pool_2nd));
        return (EC_FALSE);
    }

    if(CHFSNPRB_POOL_NODE_USED_NUM(pool_1st) != CHFSNPRB_POOL_NODE_USED_NUM(pool_2nd))
    {
        dbg_log(SEC_0073_CHFSNPRB, 0)(LOGSTDERR, "error:chfsnprb_debug_cmp: inconsistent CHFSNPRB_POOL_NODE_USED_NUM: %u != %u\n",
                            CHFSNPRB_POOL_NODE_USED_NUM(pool_1st), CHFSNPRB_POOL_NODE_USED_NUM(pool_2nd));
        return (EC_FALSE);
    }

    if(CHFSNPRB_POOL_NODE_SIZEOF(pool_1st) != CHFSNPRB_POOL_NODE_SIZEOF(pool_2nd))
    {
        dbg_log(SEC_0073_CHFSNPRB, 0)(LOGSTDERR, "error:chfsnprb_debug_cmp: inconsistent CHFSNPRB_POOL_NODE_SIZEOF: %u != %u\n",
                            CHFSNPRB_POOL_NODE_SIZEOF(pool_1st), CHFSNPRB_POOL_NODE_SIZEOF(pool_2nd));
        return (EC_FALSE);
    }

    node_max_num = CHFSNPRB_POOL_NODE_MAX_NUM(pool_1st);
    for(node_pos = 0; node_pos < node_max_num; node_pos ++)
    {
        CHFSNPRB_NODE *node_1st;
        CHFSNPRB_NODE *node_2nd;

        node_1st = CHFSNPRB_POOL_NODE(pool_1st, node_pos);
        node_2nd = CHFSNPRB_POOL_NODE(pool_2nd, node_pos);

        if(EC_FALSE == chfsnprb_node_debug_cmp(node_1st, node_2nd, node_cmp_data))
        {
            dbg_log(SEC_0073_CHFSNPRB, 0)(LOGSTDERR, "error:chfsnprb_debug_cmp: inconsistent node at pos %u\n", node_pos);
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}


#ifdef __cplusplus
}
#endif/*__cplusplus*/
