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

#include "cpgrb.h"


/*new a CPGRB_NODE and return its position*/
uint16_t cpgrb_node_new(CPGRB_POOL *pool)
{
    uint16_t node_pos_t;
    CPGRB_NODE *node;

    node_pos_t = CPGRB_POOL_FREE_HEAD(pool);
    if(CPGRB_ERR_POS == node_pos_t)
    {
        dbg_log(SEC_0000_CPGRB, 0)(LOGSTDERR, "error:cpgrb_node_new: no free node in pool %p where free_head = %d, node_num = %d\n",
                           pool, CPGRB_POOL_FREE_HEAD(pool), CPGRB_POOL_NODE_NUM(pool));
        return (CPGRB_ERR_POS);
    }

    node = CPGRB_POOL_NODE(pool, node_pos_t);
    CPGRB_POOL_FREE_HEAD(pool) = CPGRB_NODE_NEXT_POS(node);
    CPGRB_NODE_USED_FLAG(node) = CPGRB_NODE_USED;

    return (node_pos_t);
}

/*free a CPGRB_NODE and return its position to the pool*/
void cpgrb_node_free(CPGRB_POOL *pool, const uint16_t node_pos)
{
    if(CPGRB_ERR_POS != node_pos)
    {
        CPGRB_NODE *node;

        node = CPGRB_POOL_NODE(pool, node_pos);
        CPGRB_NODE_USED_FLAG(node)  = CPGRB_NODE_NOT_USED;
        CPGRB_NODE_PARENT_POS(node) = CPGRB_ERR_POS;
        CPGRB_NODE_RIGHT_POS(node)  = CPGRB_ERR_POS;
        CPGRB_NODE_LEFT_POS(node)   = CPGRB_ERR_POS;
        CPGRB_NODE_NEXT_POS(node)   = CPGRB_POOL_FREE_HEAD(pool);
        CPGRB_NODE_COLOR(node)      = CPGRB_BLACK;

        CPGRB_POOL_FREE_HEAD(pool)  = node_pos;
    }
    return;
}

void cpgrb_node_init(CPGRB_POOL *pool, const uint16_t node_pos)
{
    CPGRB_NODE *node;

    node  = CPGRB_POOL_NODE(pool, node_pos);

    CPGRB_NODE_PARENT_POS(node) = CPGRB_ERR_POS;
    CPGRB_NODE_RIGHT_POS(node)  = CPGRB_ERR_POS;
    CPGRB_NODE_LEFT_POS(node)   = CPGRB_ERR_POS;
    CPGRB_NODE_USED_FLAG(node)  = CPGRB_NODE_NOT_USED;
    CPGRB_NODE_NEXT_POS(node)   = CPGRB_ERR_POS;
    CPGRB_NODE_COLOR(node)      = CPGRB_BLACK;

    return;
}

void cpgrb_node_clean(CPGRB_POOL *pool, const uint16_t node_pos)
{
    CPGRB_NODE *node;

    node  = CPGRB_POOL_NODE(pool, node_pos);

    CPGRB_NODE_PARENT_POS(node) = CPGRB_ERR_POS;
    CPGRB_NODE_RIGHT_POS(node)  = CPGRB_ERR_POS;
    CPGRB_NODE_LEFT_POS(node)   = CPGRB_ERR_POS;
    CPGRB_NODE_USED_FLAG(node)  = CPGRB_NODE_NOT_USED;
    CPGRB_NODE_NEXT_POS(node)   = CPGRB_ERR_POS;
    CPGRB_NODE_COLOR(node)      = CPGRB_BLACK;

    return;
}

void cpgrb_node_set_next(CPGRB_POOL *pool, const uint16_t node_pos, const uint16_t next_pos)
{
    CPGRB_NODE *node;

    node  = CPGRB_POOL_NODE(pool, node_pos);
    CPGRB_NODE_NEXT_POS(node) = next_pos;

    return;
}

void cpgrb_node_print(LOG *log, const CPGRB_POOL *pool, const uint16_t node_pos)
{
    const CPGRB_NODE *node;
    node  = CPGRB_POOL_NODE(pool, node_pos);

    sys_log(log, "%5d: parent = %5d, left = %5d, right = %5d, flg = %s, color = %s, %s = %5d\n",
                       node_pos,
                       CPGRB_NODE_PARENT_POS(node),
                       CPGRB_NODE_LEFT_POS(node),
                       CPGRB_NODE_RIGHT_POS(node),
                       CPGRB_NODE_IS_USED(node) ? "used" : "n.a.",
                       CPGRB_NODE_IS_USED(node) ? (CPGRB_NODE_IS_RED(node) ? "red  " : "black") : "#####",
                       CPGRB_NODE_IS_USED(node) ? "data" : "next",
                       CPGRB_NODE_IS_USED(node) ? CPGRB_NODE_DATA(node) : CPGRB_NODE_NEXT_POS(node)
                       );
    return;
}

void cpgrb_node_print_level(LOG *log, const CPGRB_POOL *pool, const uint16_t node_pos, const uint16_t level)
{
    const CPGRB_NODE *node;
    node  = CPGRB_POOL_NODE(pool, node_pos);

    c_ident_print(log, level);
    sys_print(log, "%5d: parent = %5d, left = %5d, right = %5d, flg = %s, color = %s, %s = %5d\n",
                       node_pos,
                       CPGRB_NODE_PARENT_POS(node),
                       CPGRB_NODE_LEFT_POS(node),
                       CPGRB_NODE_RIGHT_POS(node),
                       CPGRB_NODE_IS_USED(node) ? "used" : "NOT used",
                       CPGRB_NODE_IS_RED(node)  ? "red  " : "black",
                       CPGRB_NODE_IS_USED(node) ? "data" : "next",
                       CPGRB_NODE_IS_USED(node) ? CPGRB_NODE_DATA(node) : CPGRB_NODE_NEXT_POS(node)
                       );
    return;
}


STATIC_CAST static void __cpgrb_tree_rotate_left(CPGRB_POOL *pool, const uint16_t node_pos, uint16_t *root_pos)
{
    CPGRB_NODE *node;
    CPGRB_NODE *right;

    uint16_t  right_pos;

    node  = CPGRB_POOL_NODE(pool, node_pos);

    right_pos = CPGRB_NODE_RIGHT_POS(node);
    right = CPGRB_POOL_NODE(pool, right_pos);

    if(CPGRB_ERR_POS != (CPGRB_NODE_RIGHT_POS(node) = CPGRB_NODE_LEFT_POS(right)))
    {
        CPGRB_NODE *left;
        left = CPGRB_POOL_NODE(pool, CPGRB_NODE_LEFT_POS(right));
        CPGRB_NODE_PARENT_POS(left) = node_pos;
    }
    CPGRB_NODE_LEFT_POS(right) = node_pos;

    if(CPGRB_ERR_POS != (CPGRB_NODE_PARENT_POS(right) = CPGRB_NODE_PARENT_POS(node)))
    {
        CPGRB_NODE *parent;
        parent = CPGRB_POOL_NODE(pool, CPGRB_NODE_PARENT_POS(node));

        if (node_pos == CPGRB_NODE_LEFT_POS(parent))
        {
            CPGRB_NODE_LEFT_POS(parent) = right_pos;
        }
        else
        {
            CPGRB_NODE_RIGHT_POS(parent) = right_pos;
        }
    }
    else
    {
        (*root_pos) = right_pos;
    }
    CPGRB_NODE_PARENT_POS(node) = right_pos;
    return;
}

STATIC_CAST static void __cpgrb_tree_rotate_right(CPGRB_POOL *pool, const uint16_t node_pos, uint16_t *root_pos)
{
    CPGRB_NODE *node;
    CPGRB_NODE *left;
    uint16_t  left_pos;

    node  = CPGRB_POOL_NODE(pool, node_pos);

    left_pos = CPGRB_NODE_LEFT_POS(node);
    left = CPGRB_POOL_NODE(pool, left_pos);

    if (CPGRB_ERR_POS != (CPGRB_NODE_LEFT_POS(node) = CPGRB_NODE_RIGHT_POS(left)))
    {
        CPGRB_NODE *right;
        right = CPGRB_POOL_NODE(pool, CPGRB_NODE_RIGHT_POS(left));
        CPGRB_NODE_PARENT_POS(right) = node_pos;
    }
    CPGRB_NODE_RIGHT_POS(left) = node_pos;

    if (CPGRB_ERR_POS != (CPGRB_NODE_PARENT_POS(left) = CPGRB_NODE_PARENT_POS(node)))
    {
        CPGRB_NODE *parent;
        parent = CPGRB_POOL_NODE(pool, CPGRB_NODE_PARENT_POS(node));

        if (node_pos == CPGRB_NODE_RIGHT_POS(parent))
        {
            CPGRB_NODE_RIGHT_POS(parent) = left_pos;
        }
        else
        {
            CPGRB_NODE_LEFT_POS(parent) = left_pos;
        }
    }
    else
    {
        (*root_pos) = left_pos;
    }
    CPGRB_NODE_PARENT_POS(node) = left_pos;
    return;
}

STATIC_CAST static void __cpgrb_tree_insert_color(CPGRB_POOL *pool, const uint16_t node_pos, uint16_t *root_pos)
{
    CPGRB_NODE *node;
    CPGRB_NODE *root;
    CPGRB_NODE *parent;

    uint16_t  node_pos_t;

    node_pos_t = node_pos;
    node  = CPGRB_POOL_NODE(pool, node_pos_t);

    while (NULL_PTR != (parent = CPGRB_POOL_NODE(pool, CPGRB_NODE_PARENT_POS(node))) /*parent is valid*/
         && CPGRB_RED == CPGRB_NODE_COLOR(parent))
    {
        uint16_t  parent_pos;
        uint16_t  gparent_pos;
        CPGRB_NODE *gparent;

        parent_pos = CPGRB_NODE_PARENT_POS(node);

        gparent_pos = CPGRB_NODE_PARENT_POS(parent);
        ASSERT(CPGRB_ERR_POS != gparent_pos);
        gparent = CPGRB_POOL_NODE(pool, gparent_pos);

        if (parent_pos == CPGRB_NODE_LEFT_POS(gparent))
        {
            {
                CPGRB_NODE *uncle;
                if (NULL_PTR != (uncle = CPGRB_POOL_NODE(pool, CPGRB_NODE_RIGHT_POS(gparent))) /*uncle is valid*/
                   && CPGRB_RED == CPGRB_NODE_COLOR(uncle))
                {
                    CPGRB_NODE_COLOR(uncle)   = CPGRB_BLACK;
                    CPGRB_NODE_COLOR(parent)  = CPGRB_BLACK;
                    CPGRB_NODE_COLOR(gparent) = CPGRB_RED;

                    node = gparent;
                    node_pos_t = gparent_pos;
                    continue;
                }
            }

            if (CPGRB_NODE_RIGHT_POS(parent) == node_pos_t)
            {
                __cpgrb_tree_rotate_left(pool, parent_pos, root_pos);
                XCHG(CPGRB_NODE *, parent, node);
                XCHG(uint16_t, parent_pos, node_pos_t);
            }

            CPGRB_NODE_COLOR(parent)  = CPGRB_BLACK;
            CPGRB_NODE_COLOR(gparent) = CPGRB_RED;
            __cpgrb_tree_rotate_right(pool, gparent_pos, root_pos);
         }
         else
         {
            {
                CPGRB_NODE *uncle;
                if (NULL_PTR != (uncle = CPGRB_POOL_NODE(pool, CPGRB_NODE_LEFT_POS(gparent))) /*uncle is valid*/
                    && CPGRB_RED == CPGRB_NODE_COLOR(uncle))
                {
                    CPGRB_NODE_COLOR(uncle)   = CPGRB_BLACK;
                    CPGRB_NODE_COLOR(parent)  = CPGRB_BLACK;
                    CPGRB_NODE_COLOR(gparent) = CPGRB_RED;

                    node = gparent;
                    node_pos_t = gparent_pos;
                    continue;
                }
            }

            if (CPGRB_NODE_LEFT_POS(parent) == node_pos_t)
            {
                __cpgrb_tree_rotate_right(pool, parent_pos, root_pos);
                XCHG(CPGRB_NODE *, parent, node);
                XCHG(uint16_t, parent_pos, node_pos_t);
            }

            CPGRB_NODE_COLOR(parent)  = CPGRB_BLACK;
            CPGRB_NODE_COLOR(gparent) = CPGRB_RED;
            __cpgrb_tree_rotate_left(pool, gparent_pos, root_pos);
        }
    }

    root = CPGRB_POOL_NODE(pool, *root_pos);
    CPGRB_NODE_COLOR(root) = CPGRB_BLACK;
    return;
}

STATIC_CAST static void __cpgrb_tree_erase_color(CPGRB_POOL *pool, const uint16_t node_pos, const uint16_t parent_pos, uint16_t *root_pos)
{
    CPGRB_NODE *node;
    uint16_t  node_pos_t;
    uint16_t  parent_pos_t;

    node_pos_t   = node_pos;
    parent_pos_t = parent_pos;

    while ((NULL_PTR == (node = CPGRB_POOL_NODE(pool, node_pos_t)) || CPGRB_BLACK == CPGRB_NODE_COLOR(node)) && node_pos_t != (*root_pos))
    {
        CPGRB_NODE *parent;

        parent = CPGRB_POOL_NODE(pool, parent_pos_t);

        if (CPGRB_NODE_LEFT_POS(parent) == node_pos_t)
        {
            CPGRB_NODE *other;
            CPGRB_NODE *o_left;
            CPGRB_NODE *o_right;
            uint16_t  other_pos;

            other_pos = CPGRB_NODE_RIGHT_POS(parent);
            other = CPGRB_POOL_NODE(pool, other_pos);

            if (CPGRB_RED == CPGRB_NODE_COLOR(other))
            {
                CPGRB_NODE_COLOR(other)  = CPGRB_BLACK;
                CPGRB_NODE_COLOR(parent) = CPGRB_RED;

                __cpgrb_tree_rotate_left(pool, parent_pos_t, root_pos);

                other_pos = CPGRB_NODE_RIGHT_POS(parent);
                other = CPGRB_POOL_NODE(pool, other_pos);
            }

            o_left = CPGRB_POOL_NODE(pool, CPGRB_NODE_LEFT_POS(other));
            o_right = CPGRB_POOL_NODE(pool, CPGRB_NODE_RIGHT_POS(other));

            if((NULL_PTR == o_left || CPGRB_BLACK == CPGRB_NODE_COLOR(o_left))
            && (NULL_PTR == o_right || CPGRB_BLACK == CPGRB_NODE_COLOR(o_right)))
            {
                CPGRB_NODE_COLOR(other) = CPGRB_RED;

                node_pos_t = parent_pos_t;
                node = CPGRB_POOL_NODE(pool, node_pos_t);

                parent_pos_t = CPGRB_NODE_PARENT_POS(node);
                parent = CPGRB_POOL_NODE(pool, parent_pos_t);
            }
            else
            {
                if (NULL_PTR == o_right || CPGRB_BLACK == CPGRB_NODE_COLOR(o_right))
                {
                    if (NULL_PTR != o_left)
                    {
                        CPGRB_NODE_COLOR(o_left) = CPGRB_BLACK;
                    }
                    CPGRB_NODE_COLOR(other) = CPGRB_RED;

                    __cpgrb_tree_rotate_right(pool, other_pos, root_pos);

                    other_pos = CPGRB_NODE_RIGHT_POS(parent);
                    other = CPGRB_POOL_NODE(pool, other_pos);
                    /*note: other was changed here*/
                }

                CPGRB_NODE_COLOR(other) = CPGRB_NODE_COLOR(parent);
                CPGRB_NODE_COLOR(parent) = CPGRB_BLACK;

                /*due to other may be changed before, have to get o_right again here*/
                o_right = CPGRB_POOL_NODE(pool, CPGRB_NODE_RIGHT_POS(other));
                if (NULL_PTR != o_right)
                {
                    CPGRB_NODE_COLOR(o_right) = CPGRB_BLACK;
                }

                __cpgrb_tree_rotate_left(pool, parent_pos_t, root_pos);
                node_pos_t = (*root_pos);
                break;
            }
        }
        else
        {
            CPGRB_NODE *other;
            CPGRB_NODE *o_left;
            CPGRB_NODE *o_right;
            uint16_t  other_pos;

            other_pos = CPGRB_NODE_LEFT_POS(parent);
            other = CPGRB_POOL_NODE(pool, other_pos);

            if (CPGRB_RED == CPGRB_NODE_COLOR(other))
            {
                CPGRB_NODE_COLOR(other) = CPGRB_BLACK;
                CPGRB_NODE_COLOR(parent) = CPGRB_RED;

                __cpgrb_tree_rotate_right(pool, parent_pos_t, root_pos);

                other_pos = CPGRB_NODE_LEFT_POS(parent);
                other = CPGRB_POOL_NODE(pool, other_pos);
            }

            o_left = CPGRB_POOL_NODE(pool, CPGRB_NODE_LEFT_POS(other));
            o_right = CPGRB_POOL_NODE(pool, CPGRB_NODE_RIGHT_POS(other));

            if ((NULL_PTR == o_left  || CPGRB_BLACK == CPGRB_NODE_COLOR(o_left))
             && (NULL_PTR == o_right || CPGRB_BLACK == CPGRB_NODE_COLOR(o_right)))
            {
                CPGRB_NODE_COLOR(other) = CPGRB_RED;

                node_pos_t = parent_pos_t;
                node = CPGRB_POOL_NODE(pool, node_pos_t);

                parent_pos_t = CPGRB_NODE_PARENT_POS(node);
                parent = CPGRB_POOL_NODE(pool, parent_pos_t);
            }
            else
            {
                if (NULL_PTR == o_left  || CPGRB_BLACK == CPGRB_NODE_COLOR(o_left))
                {
                    if (NULL_PTR != o_right)
                    {
                        CPGRB_NODE_COLOR(o_right) = CPGRB_BLACK;
                    }

                    CPGRB_NODE_COLOR(other) = CPGRB_RED;

                    __cpgrb_tree_rotate_left(pool, other_pos, root_pos);

                    other_pos = CPGRB_NODE_LEFT_POS(parent);
                    other = CPGRB_POOL_NODE(pool, other_pos);
                    /*note: other was changed here*/
                }

                CPGRB_NODE_COLOR(other) = CPGRB_NODE_COLOR(parent);
                CPGRB_NODE_COLOR(parent) = CPGRB_BLACK;

                /*due to other may be changed before, have to get o_left again here*/
                o_left = CPGRB_POOL_NODE(pool, CPGRB_NODE_LEFT_POS(other));
                if (NULL_PTR != o_left)
                {
                    CPGRB_NODE_COLOR(o_left) = CPGRB_BLACK;
                }
                __cpgrb_tree_rotate_right(pool, parent_pos_t, root_pos);
                node_pos_t = (*root_pos);
                break;
            }
        }
    }

    node = CPGRB_POOL_NODE(pool, node_pos_t);
    if (NULL_PTR != node)
    {
        CPGRB_NODE_COLOR(node) = CPGRB_BLACK;
    }
    return;
}

STATIC_CAST static void __cpgrb_tree_erase(CPGRB_POOL *pool, const uint16_t node_pos, uint16_t *root_pos)
{
    CPGRB_NODE *node;

    uint16_t node_pos_t;
    uint16_t child_pos;
    uint16_t parent_pos;
    uint16_t color;

    node_pos_t = node_pos;
    node = CPGRB_POOL_NODE(pool, node_pos_t);

    ASSERT(NULL_PTR != node);
    ASSERT(CPGRB_NODE_IS_USED(node));

    if (CPGRB_ERR_POS == CPGRB_NODE_LEFT_POS(node))
    {
        child_pos = CPGRB_NODE_RIGHT_POS(node);
    }
    else if (CPGRB_ERR_POS == CPGRB_NODE_RIGHT_POS(node))
    {
        child_pos = CPGRB_NODE_LEFT_POS(node);
    }
    else
    {
        CPGRB_NODE *old;

        uint16_t old_pos;
        uint16_t left_pos;

        old_pos = node_pos_t;

        node_pos_t = CPGRB_NODE_RIGHT_POS(node);
        node = CPGRB_POOL_NODE(pool, node_pos_t);

        while (CPGRB_ERR_POS != (left_pos = CPGRB_NODE_LEFT_POS(node)))
        {
            node_pos_t = left_pos;
            node = CPGRB_POOL_NODE(pool, node_pos_t);

        }

        child_pos  = CPGRB_NODE_RIGHT_POS(node);
        parent_pos = CPGRB_NODE_PARENT_POS(node);
        color      = CPGRB_NODE_COLOR(node);

        if (CPGRB_ERR_POS != child_pos)
        {
            CPGRB_NODE *child;
            child = CPGRB_POOL_NODE(pool, child_pos);
            CPGRB_NODE_PARENT_POS(child) = parent_pos;
        }

        if (CPGRB_ERR_POS != parent_pos)
        {
            CPGRB_NODE *parent;

            parent = CPGRB_POOL_NODE(pool, parent_pos);
            if (CPGRB_NODE_LEFT_POS(parent) == node_pos_t)
            {
                CPGRB_NODE_LEFT_POS(parent) = child_pos;
            }
            else
            {
                CPGRB_NODE_RIGHT_POS(parent) = child_pos;
            }
        }
        else
        {
            (*root_pos) = child_pos;
        }

        if (CPGRB_NODE_PARENT_POS(node) == old_pos)
        {
            parent_pos = node_pos_t;
        }

        //node = CPGRB_POOL_NODE(pool, node_pos_t);
        old  = CPGRB_POOL_NODE(pool, old_pos);

        CPGRB_NODE_PARENT_POS(node) = CPGRB_NODE_PARENT_POS(old);
        CPGRB_NODE_COLOR(node)      = CPGRB_NODE_COLOR(old);
        CPGRB_NODE_RIGHT_POS(node)  = CPGRB_NODE_RIGHT_POS(old);
        CPGRB_NODE_LEFT_POS(node)   = CPGRB_NODE_LEFT_POS(old);

        if (CPGRB_ERR_POS != CPGRB_NODE_PARENT_POS(old))
        {
            CPGRB_NODE *old_parent;
            old_parent = CPGRB_POOL_NODE(pool, CPGRB_NODE_PARENT_POS(old));

            if (CPGRB_NODE_LEFT_POS(old_parent) == old_pos)
            {
                CPGRB_NODE_LEFT_POS(old_parent) = node_pos_t;
            }
            else
            {
                CPGRB_NODE_RIGHT_POS(old_parent) = node_pos_t;
            }
        }
        else
        {
            (*root_pos) = node_pos_t;
        }

        {
            CPGRB_NODE *old_left;

            old_left = CPGRB_POOL_NODE(pool, CPGRB_NODE_LEFT_POS(old));
            CPGRB_NODE_PARENT_POS(old_left) = node_pos_t;
        }

        if (CPGRB_ERR_POS != CPGRB_NODE_RIGHT_POS(old))
        {
            CPGRB_NODE *old_right;
            old_right = CPGRB_POOL_NODE(pool, CPGRB_NODE_RIGHT_POS(old));
            CPGRB_NODE_PARENT_POS(old_right) = node_pos_t;
        }
        goto color;
    }

    parent_pos = CPGRB_NODE_PARENT_POS(node);
    color = CPGRB_NODE_COLOR(node);

    if (CPGRB_ERR_POS != child_pos)
    {
        CPGRB_NODE *child;
        child = CPGRB_POOL_NODE(pool, child_pos);
        CPGRB_NODE_PARENT_POS(child) = parent_pos;
    }

    if (CPGRB_ERR_POS != parent_pos)
    {
        CPGRB_NODE *parent;

        parent = CPGRB_POOL_NODE(pool, parent_pos);
        if (CPGRB_NODE_LEFT_POS(parent) == node_pos_t)
        {
            CPGRB_NODE_LEFT_POS(parent) = child_pos;
        }
        else
        {
            CPGRB_NODE_RIGHT_POS(parent) = child_pos;
        }
    }
    else
    {
        (*root_pos) = child_pos;
    }

 color:
    if (CPGRB_BLACK == color)
    {
        __cpgrb_tree_erase_color(pool, child_pos, parent_pos, root_pos);
    }
    return;
}

EC_BOOL cpgrb_tree_is_empty(const CPGRB_POOL *pool, const uint16_t root_pos)
{
    if (CPGRB_ERR_POS == root_pos)
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}


STATIC_CAST static uint16_t __cpgrb_tree_node_num(const CPGRB_POOL *pool, const uint16_t node_pos)
{
    const CPGRB_NODE *node;

    if(CPGRB_ERR_POS == node_pos)
    {
        return ((uint16_t)0);
    }

    node = CPGRB_POOL_NODE(pool, node_pos);

    return (uint16_t)(1 + __cpgrb_tree_node_num(pool, CPGRB_NODE_LEFT_POS(node)) + __cpgrb_tree_node_num(pool, CPGRB_NODE_RIGHT_POS(node)));
}

uint16_t cpgrb_tree_node_num(const CPGRB_POOL *pool, const uint16_t root_pos)
{
    return __cpgrb_tree_node_num(pool, root_pos);
}

/*
 * This function returns the first node_pos (in sort order) of the tree.
 */
uint16_t cpgrb_tree_first_node(const CPGRB_POOL *pool, const uint16_t root_pos)
{
    uint16_t  node_pos;
    const CPGRB_NODE *node;

    node_pos = root_pos;
    if (CPGRB_ERR_POS == node_pos)
    {
        return (CPGRB_ERR_POS);
    }

    node = CPGRB_POOL_NODE(pool, node_pos);

    while (CPGRB_ERR_POS != CPGRB_NODE_LEFT_POS(node))
    {
        node_pos = CPGRB_NODE_LEFT_POS(node);
        node = CPGRB_POOL_NODE(pool, node_pos);
    }
    return (node_pos);
}

uint16_t cpgrb_tree_last_node(const CPGRB_POOL *pool, const uint16_t root_pos)
{
    uint16_t  node_pos;
    const CPGRB_NODE *node;

    node_pos = root_pos;
    if (CPGRB_ERR_POS == node_pos)
    {
        return (CPGRB_ERR_POS);
    }

    node = CPGRB_POOL_NODE(pool, node_pos);

    while (CPGRB_ERR_POS != CPGRB_NODE_RIGHT_POS(node))
    {
        node_pos = CPGRB_NODE_RIGHT_POS(node);
        node = CPGRB_POOL_NODE(pool, node_pos);
    }

    return (node_pos);
}

uint16_t cpgrb_tree_next_node(const CPGRB_POOL *pool, const uint16_t node_pos)
{
    uint16_t node_pos_t;
    const CPGRB_NODE *node;
    const CPGRB_NODE *parent;

    node_pos_t = node_pos;
    node = CPGRB_POOL_NODE(pool, node_pos_t);
    /* If we have a right-hand child, go down and then left as far
       as we can. */
    if (CPGRB_ERR_POS != CPGRB_NODE_RIGHT_POS(node))
    {
        node_pos_t = CPGRB_NODE_RIGHT_POS(node);
        node = CPGRB_POOL_NODE(pool, node_pos_t);
        while (CPGRB_ERR_POS != CPGRB_NODE_LEFT_POS(node))
        {
            node_pos_t = CPGRB_NODE_LEFT_POS(node);
            node = CPGRB_POOL_NODE(pool, node_pos_t);
        }
        return (node_pos_t);
    }

    /* No right-hand children.  Everything down and left is
       smaller than us, so any 'next' node_pos_t must be in the general
       direction of our parent. Go up the tree; any time the
       ancestor is a right-hand child of its parent, keep going
       up. First time it's a left-hand child of its parent, said
       parent is our 'next' node_pos_t. */
    while (NULL_PTR != (parent = CPGRB_POOL_NODE(pool, CPGRB_NODE_PARENT_POS(node))) && node_pos_t == CPGRB_NODE_RIGHT_POS(parent))
    {
        node_pos_t = CPGRB_NODE_PARENT_POS(node);
        node = parent;
    }

    return (CPGRB_NODE_PARENT_POS(node));
}

uint16_t cpgrb_tree_prev_node(const CPGRB_POOL *pool, const uint16_t node_pos)
{
    uint16_t node_pos_t;
    const CPGRB_NODE *node;
    const CPGRB_NODE *parent;

    node_pos_t = node_pos;
    node = CPGRB_POOL_NODE(pool, node_pos_t);

    /* If we have a left-hand child, go down and then right as far
       as we can. */
    if (CPGRB_ERR_POS != CPGRB_NODE_LEFT_POS(node))
    {
        node_pos_t = CPGRB_NODE_LEFT_POS(node);
        node = CPGRB_POOL_NODE(pool, node_pos_t);
        while (CPGRB_ERR_POS != CPGRB_NODE_RIGHT_POS(node))
        {
            node_pos_t = CPGRB_NODE_RIGHT_POS(node);
            node = CPGRB_POOL_NODE(pool, node_pos_t);
        }
        return (node_pos_t);
    }

    /* No left-hand children. Go up till we find an ancestor which
       is a right-hand child of its parent */
    while (NULL_PTR != (parent = CPGRB_POOL_NODE(pool, CPGRB_NODE_PARENT_POS(node))) && node_pos_t == CPGRB_NODE_LEFT_POS(parent))
    {
        node_pos_t = CPGRB_NODE_PARENT_POS(node);
        node = parent;
    }

    return (CPGRB_NODE_PARENT_POS(node));
}

/*victim_pos should be free*/
void cpgrb_tree_replace_node(CPGRB_POOL *pool, const uint16_t victim_pos, const uint16_t new_pos, uint16_t *root_pos)
{
    CPGRB_NODE *victim;

    victim = CPGRB_POOL_NODE(pool, victim_pos);

    /* Set the surrounding nodes to point to the replacement */
    if (CPGRB_ERR_POS != CPGRB_NODE_PARENT_POS(victim))
    {
        CPGRB_NODE *parent;
        parent = CPGRB_POOL_NODE(pool, CPGRB_NODE_PARENT_POS(victim));

        if (victim_pos == CPGRB_NODE_LEFT_POS(parent))
        {
            CPGRB_NODE_LEFT_POS(parent) = new_pos;
        }
        else
        {
            CPGRB_NODE_RIGHT_POS(parent) = new_pos;
        }
    }
    else
    {
        (*root_pos) = new_pos;
    }

    if (CPGRB_ERR_POS != CPGRB_NODE_LEFT_POS(victim))
    {
        CPGRB_NODE *left;
        left = CPGRB_POOL_NODE(pool, CPGRB_NODE_LEFT_POS(victim));
        CPGRB_NODE_PARENT_POS(left) = new_pos;
    }
    if (CPGRB_ERR_POS != CPGRB_NODE_RIGHT_POS(victim))
    {
        CPGRB_NODE *right;
        right = CPGRB_POOL_NODE(pool, CPGRB_NODE_RIGHT_POS(victim));
        CPGRB_NODE_PARENT_POS(right) = new_pos;
    }

    return;
}

/*return the searched pos*/
uint16_t cpgrb_tree_search_data(CPGRB_POOL *pool, const uint16_t root_pos, uint16_t data)
{
    uint16_t node_pos;

    node_pos = root_pos;

    while (CPGRB_ERR_POS != node_pos)
    {
        CPGRB_NODE *node;

        node = CPGRB_POOL_NODE(pool, node_pos);

        if (data < CPGRB_NODE_DATA(node))
        {
            node_pos = CPGRB_NODE_LEFT_POS(node);
        }
        else if (data > CPGRB_NODE_DATA(node))
        {
            node_pos = CPGRB_NODE_RIGHT_POS(node);
        }
        else
        {
            return (node_pos);
        }
    }

    return (CPGRB_ERR_POS);
}


uint16_t cpgrb_tree_insert_data(CPGRB_POOL *pool, uint16_t *root_pos, const uint16_t data)
{
    uint16_t  node_pos_t;
    uint16_t  new_pos_t;
    uint16_t  parent_pos_t;
    uint16_t  flag; /*0: on left subtree, 1: on right subtree*/

    node_pos_t   = (*root_pos);
    parent_pos_t = CPGRB_ERR_POS;
    flag         = ~(uint16_t)0;

    while (CPGRB_ERR_POS != node_pos_t)
    {
        CPGRB_NODE *node;

        node = CPGRB_POOL_NODE(pool, node_pos_t);

        parent_pos_t = node_pos_t;

        if (data < CPGRB_NODE_DATA(node))
        {
            node_pos_t = CPGRB_NODE_LEFT_POS(node);
            flag = 0;
        }
        else if (data > CPGRB_NODE_DATA(node))
        {
            node_pos_t = CPGRB_NODE_RIGHT_POS(node);
            flag = 1;
        }
        else
        {
            return (node_pos_t);
        }
    }

    /*not found data in the rbtree*/
    new_pos_t = cpgrb_node_new(pool);
    if(CPGRB_ERR_POS == new_pos_t)
    {
        dbg_log(SEC_0000_CPGRB, 0)(LOGSTDOUT, "error:cpgrb_tree_insert_data: new cpgrb_node from pool %p failed\n", pool);
        return (CPGRB_ERR_POS);
    }
    else
    {
        CPGRB_NODE *node;

        node  = CPGRB_POOL_NODE(pool, new_pos_t);
        CPGRB_NODE_DATA(node) = data;

        CPGRB_NODE_PARENT_POS(node) = parent_pos_t;
        CPGRB_NODE_COLOR(node)      = CPGRB_RED;
        CPGRB_NODE_LEFT_POS(node)   = CPGRB_ERR_POS;
        CPGRB_NODE_RIGHT_POS(node)  = CPGRB_ERR_POS;

        if(CPGRB_ERR_POS == (*root_pos))
        {
            (*root_pos) = new_pos_t;
        }
        else
        {
            CPGRB_NODE *parent;
            parent  = CPGRB_POOL_NODE(pool, parent_pos_t);

            if(0 == flag)/*on left subtree*/
            {
                CPGRB_NODE_LEFT_POS(parent) = new_pos_t;
            }
            else
            {
                CPGRB_NODE_RIGHT_POS(parent) = new_pos_t;
            }
        }
        __cpgrb_tree_insert_color(pool, new_pos_t, root_pos);
    }

    return (new_pos_t);
}

EC_BOOL cpgrb_tree_delete_data(CPGRB_POOL *pool, uint16_t *root_pos, const uint16_t data)
{
    uint16_t node_pos;

    node_pos = cpgrb_tree_search_data(pool, *root_pos, data);
    if(CPGRB_ERR_POS == node_pos)
    {
        return (EC_FALSE);
    }

    __cpgrb_tree_erase(pool, node_pos, root_pos);
    cpgrb_node_free(pool, node_pos);
    return (EC_TRUE);
}

/*postorder: left -> right -> root*/
STATIC_CAST static void __cpgrb_tree_free(CPGRB_POOL *pool, const uint16_t node_pos)
{
    CPGRB_NODE *node;

    if(CPGRB_ERR_POS == node_pos)
    {
        return;
    }

    node  = CPGRB_POOL_NODE(pool, node_pos);
    if(CPGRB_ERR_POS != CPGRB_NODE_LEFT_POS(node))
    {
        __cpgrb_tree_free(pool, CPGRB_NODE_LEFT_POS(node));
    }

    if(CPGRB_ERR_POS != CPGRB_NODE_RIGHT_POS(node))
    {
        __cpgrb_tree_free(pool, CPGRB_NODE_RIGHT_POS(node));
    }

    cpgrb_node_free(pool, node_pos);

    return;
}
void cpgrb_tree_free(CPGRB_POOL *pool, const uint16_t root_pos)
{
    __cpgrb_tree_free(pool, root_pos);
    return;
}

EC_BOOL cpgrb_pool_init(CPGRB_POOL *pool, const uint16_t node_num)
{
    uint16_t node_pos;

    if(CPGRB_POOL_MAX_SIZE < node_num)
    {
        dbg_log(SEC_0000_CPGRB, 0)(LOGSTDERR, "error:cpgrb_pool_init: node_num %u overflow!\n", node_num);
        return (EC_FALSE);
    }

    CPGRB_POOL_NODE_NUM(pool) = node_num;

    for(node_pos = 0; node_pos < node_num; node_pos ++)
    {
        cpgrb_node_init(pool, node_pos);
        cpgrb_node_set_next(pool, node_pos, node_pos + 1);
    }
    cpgrb_node_set_next(pool, node_num - 1, CPGRB_ERR_POS);

    CPGRB_POOL_FREE_HEAD(pool) = 0;/*the free nodes head*/
    return (EC_TRUE);
}

void cpgrb_pool_clean(CPGRB_POOL *pool)
{
    CPGRB_POOL_NODE_NUM(pool)  = 0;
    CPGRB_POOL_FREE_HEAD(pool) = CPGRB_ERR_POS;
    return;
}

/*clear without any space mallocation!*/
void cpgrb_pool_clear(CPGRB_POOL *pool)
{
    CPGRB_POOL_NODE_NUM(pool)  = 0;
    CPGRB_POOL_FREE_HEAD(pool) = CPGRB_ERR_POS;
    return;
}

void cpgrb_pool_print(LOG *log, const CPGRB_POOL *pool)
{
    uint16_t node_pos;
    uint16_t node_num;

    node_num = CPGRB_POOL_NODE_NUM(pool);

    sys_log(log, "pool %lx, node_num %u, free_head %u\n",
                 pool,
                 node_num,
                 CPGRB_POOL_FREE_HEAD(pool));

    for(node_pos = 0; node_pos < node_num; node_pos ++)
    {
        cpgrb_node_print(log, pool, node_pos);
    }

    return;
}

/*visit the root node first: root -> left -> right*/
void cpgrb_preorder_print(LOG *log, const CPGRB_POOL *pool, const uint16_t node_pos)
{
    const CPGRB_NODE *node;

    if(CPGRB_ERR_POS == node_pos)
    {
        return;
    }

    node  = CPGRB_POOL_NODE(pool, node_pos);
    cpgrb_node_print(log, pool, node_pos);

    if(CPGRB_ERR_POS != CPGRB_NODE_LEFT_POS(node))
    {
        cpgrb_preorder_print(log, pool, CPGRB_NODE_LEFT_POS(node));
    }

    if(CPGRB_ERR_POS != CPGRB_NODE_RIGHT_POS(node))
    {
        cpgrb_preorder_print(log, pool, CPGRB_NODE_RIGHT_POS(node));
    }

    return;
}

/*visit the left subtree, then the root node: left -> root -> right*/
void cpgrb_inorder_print(LOG *log, const CPGRB_POOL *pool, const uint16_t node_pos)
{
    const CPGRB_NODE *node;

    if(CPGRB_ERR_POS == node_pos)
    {
        return;
    }

    node  = CPGRB_POOL_NODE(pool, node_pos);
    if(CPGRB_ERR_POS != CPGRB_NODE_LEFT_POS(node))
    {
        cpgrb_inorder_print(log, pool, CPGRB_NODE_LEFT_POS(node));
    }

    cpgrb_node_print(log, pool, node_pos);

    if(CPGRB_ERR_POS != CPGRB_NODE_RIGHT_POS(node))
    {
        cpgrb_inorder_print(log, pool, CPGRB_NODE_RIGHT_POS(node));
    }

    return;
}

/*visit the root node last: left -> right -> root*/
void cpgrb_postorder_print(LOG *log, const CPGRB_POOL *pool, const uint16_t node_pos)
{
    const CPGRB_NODE *node;

    if(CPGRB_ERR_POS == node_pos)
    {
        return;
    }

    node  = CPGRB_POOL_NODE(pool, node_pos);
    if(CPGRB_ERR_POS != CPGRB_NODE_LEFT_POS(node))
    {
        cpgrb_postorder_print(log, pool, CPGRB_NODE_LEFT_POS(node));
    }

    if(CPGRB_ERR_POS != CPGRB_NODE_RIGHT_POS(node))
    {
        cpgrb_postorder_print(log, pool, CPGRB_NODE_RIGHT_POS(node));
    }

    cpgrb_node_print(log, pool, node_pos);

    return;
}


/*visit the root node first: root -> left -> right*/
void cpgrb_preorder_print_level(LOG *log, const CPGRB_POOL *pool, const uint16_t node_pos, const uint16_t level)
{
    const CPGRB_NODE *node;

    if(CPGRB_ERR_POS == node_pos)
    {
        return;
    }

    node  = CPGRB_POOL_NODE(pool, node_pos);
    cpgrb_node_print_level(log, pool, node_pos, level);

    if(CPGRB_ERR_POS != CPGRB_NODE_LEFT_POS(node))
    {
        cpgrb_preorder_print_level(log, pool, CPGRB_NODE_LEFT_POS(node), level + 1);
    }

    if(CPGRB_ERR_POS != CPGRB_NODE_RIGHT_POS(node))
    {
        cpgrb_preorder_print_level(log, pool, CPGRB_NODE_RIGHT_POS(node), level + 1);
    }

    return;
}

EC_BOOL cpgrb_flush_size(const CPGRB_POOL *pool, UINT32 *size)
{
    (*size) += sizeof(CPGRB_POOL);
    return (EC_TRUE);
}

EC_BOOL cpgrb_flush(const CPGRB_POOL *pool, int fd, UINT32 *offset)
{
    UINT32 osize;/*write once size*/
    DEBUG(UINT32 offset_saved = *offset;);

    /*skip rsvd*/
    osize = sizeof(uint32_t);
    if(EC_FALSE == c_file_pad(fd, offset, osize, FILE_PAD_CHAR))
    {
        dbg_log(SEC_0000_CPGRB, 0)(LOGSTDOUT, "error:cpgrb_flush: pad %u bytes at offset %u of fd %d failed\n", osize, (*offset), fd);
        return (EC_FALSE);
    }

    /*flush free_head*/
    osize = sizeof(uint16_t);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(CPGRB_POOL_FREE_HEAD(pool))))
    {
        dbg_log(SEC_0000_CPGRB, 0)(LOGSTDOUT, "error:cpgrb_flush: write CPGRB_POOL_FREE_HEAD at offset %u of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*flush node_num*/
    osize  = sizeof(uint16_t);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(CPGRB_POOL_NODE_NUM(pool))))
    {
        dbg_log(SEC_0000_CPGRB, 0)(LOGSTDOUT, "error:cpgrb_flush: write CPGRB_POOL_NODE_NUM at offset %u of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*flush rb_node table*/
    osize  = CPGRB_POOL_NODE_NUM(pool) * sizeof(CPGRB_NODE);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)CPGRB_POOL_NODE_TBL(pool)))
    {
        dbg_log(SEC_0000_CPGRB, 0)(LOGSTDOUT, "error:cpgrb_flush: write CPGRB_POOL_NODE_TBL at offset %u of fd %d failed where CPGRB_POOL_NODE_NUM is %u\n",
                            (*offset), fd, CPGRB_POOL_NODE_NUM(pool));
        return (EC_FALSE);
    }

    osize = (CPGRB_POOL_MAX_SIZE - CPGRB_POOL_NODE_NUM(pool)) * sizeof(CPGRB_NODE);
    if(EC_FALSE == c_file_pad(fd, offset, osize, FILE_PAD_CHAR))
    {
        dbg_log(SEC_0000_CPGRB, 0)(LOGSTDOUT, "error:cpgrb_flush: pad %u at offset %u of fd %d failed\n", osize, (*offset), fd);
        return (EC_FALSE);
    }

    DEBUG(ASSERT(sizeof(CPGRB_POOL) == (*offset) - offset_saved));

    return (EC_TRUE);
}

EC_BOOL cpgrb_load(CPGRB_POOL *pool, int fd, UINT32 *offset)
{
    UINT32 osize;/*read once size*/
    uint16_t node_num;

    /*skip rsvd*/
    (*offset) += sizeof(uint32_t);

    /*load free_head*/
    osize = sizeof(uint16_t);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(CPGRB_POOL_FREE_HEAD(pool))))
    {
        dbg_log(SEC_0000_CPGRB, 0)(LOGSTDOUT, "error:cpgrb_load: load CPGRB_POOL_FREE_HEAD at offset %u of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*load node_num*/
    osize  = sizeof(uint16_t);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(node_num)))
    {
        dbg_log(SEC_0000_CPGRB, 0)(LOGSTDOUT, "error:cpgrb_load: load CPGRB_POOL_NODE_NUM at offset %u of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    CPGRB_POOL_NODE_NUM(pool) = node_num;

    /*load rb_node table*/
    osize  = CPGRB_POOL_NODE_NUM(pool) * sizeof(CPGRB_NODE);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)CPGRB_POOL_NODE_TBL(pool)))
    {
        dbg_log(SEC_0000_CPGRB, 0)(LOGSTDOUT, "error:cpgrb_load: load CPGRB_POOL_NODE_TBL at offset %u of fd %d failed where CPGRB_POOL_NODE_NUM is %u\n",
                            (*offset), fd, CPGRB_POOL_NODE_NUM(pool));
        return (EC_FALSE);
    }

    (*offset) += (CPGRB_POOL_MAX_SIZE - CPGRB_POOL_NODE_NUM(pool)) * sizeof(CPGRB_NODE);

    return (EC_TRUE);
}

void cpgrb_tree_print(LOG *log, const CPGRB_POOL *pool, const uint16_t root_pos)
{
    uint16_t node_pos;

    sys_log(log, "[root = %5d]\n", root_pos);
    for(node_pos = cpgrb_tree_first_node(pool, root_pos); CPGRB_ERR_POS != node_pos; node_pos = cpgrb_tree_next_node(pool, node_pos))
    {
        cpgrb_node_print(log, pool, node_pos);
    }
    return;
}

/* ---- debug ---- */
EC_BOOL cpgrb_node_debug_cmp(const CPGRB_NODE *node_1st, const CPGRB_NODE *node_2nd)
{
    if(CPGRB_NODE_USED_FLAG(node_1st) != CPGRB_NODE_USED_FLAG(node_2nd))
    {
        dbg_log(SEC_0000_CPGRB, 0)(LOGSTDERR, "error:cpgrb_node_debug_cmp: inconsistent CPGRB_NODE_USED_FLAG: %u != %u\n",
                            CPGRB_NODE_USED_FLAG(node_1st), CPGRB_NODE_USED_FLAG(node_2nd));
        return (EC_FALSE);
    }

    if(CPGRB_NODE_COLOR(node_1st) != CPGRB_NODE_COLOR(node_2nd))
    {
        dbg_log(SEC_0000_CPGRB, 0)(LOGSTDERR, "error:cpgrb_node_debug_cmp: inconsistent CPGRB_NODE_COLOR: %u != %u\n",
                            CPGRB_NODE_COLOR(node_1st), CPGRB_NODE_COLOR(node_2nd));
        return (EC_FALSE);
    }

    if(CPGRB_NODE_PARENT_POS(node_1st) != CPGRB_NODE_PARENT_POS(node_2nd))
    {
        dbg_log(SEC_0000_CPGRB, 0)(LOGSTDERR, "error:cpgrb_node_debug_cmp: inconsistent CPGRB_NODE_PARENT_POS: %u != %u\n",
                            CPGRB_NODE_PARENT_POS(node_1st), CPGRB_NODE_PARENT_POS(node_2nd));
        return (EC_FALSE);
    }

    if(CPGRB_NODE_RIGHT_POS(node_1st) != CPGRB_NODE_RIGHT_POS(node_2nd))
    {
        dbg_log(SEC_0000_CPGRB, 0)(LOGSTDERR, "error:cpgrb_node_debug_cmp: inconsistent CPGRB_NODE_RIGHT_POS: %u != %u\n",
                            CPGRB_NODE_RIGHT_POS(node_1st), CPGRB_NODE_RIGHT_POS(node_2nd));
        return (EC_FALSE);
    }

    if(CPGRB_NODE_LEFT_POS(node_1st) != CPGRB_NODE_LEFT_POS(node_2nd))
    {
        dbg_log(SEC_0000_CPGRB, 0)(LOGSTDERR, "error:cpgrb_node_debug_cmp: inconsistent CPGRB_NODE_LEFT_POS: %u != %u\n",
                            CPGRB_NODE_LEFT_POS(node_1st), CPGRB_NODE_LEFT_POS(node_2nd));
        return (EC_FALSE);
    }

    if(CPGRB_NODE_USED == CPGRB_NODE_USED_FLAG(node_1st))
    {
        if(CPGRB_NODE_DATA(node_1st) != CPGRB_NODE_DATA(node_2nd))
        {
            dbg_log(SEC_0000_CPGRB, 0)(LOGSTDERR, "error:cpgrb_node_debug_cmp: inconsistent CPGRB_NODE_DATA: %u != %u\n",
                                CPGRB_NODE_DATA(node_1st), CPGRB_NODE_DATA(node_2nd));
            return (EC_FALSE);
        }
    }
    else
    {
        if(CPGRB_NODE_NEXT_POS(node_1st) != CPGRB_NODE_NEXT_POS(node_2nd))
        {
            dbg_log(SEC_0000_CPGRB, 0)(LOGSTDERR, "error:cpgrb_node_debug_cmp: inconsistent CPGRB_NODE_NEXT_POS: %u != %u\n",
                                CPGRB_NODE_NEXT_POS(node_1st), CPGRB_NODE_NEXT_POS(node_2nd));
            return (EC_FALSE);
        }
    }
    return (EC_TRUE);
}

EC_BOOL cpgrb_debug_cmp(const CPGRB_POOL *pool_1st, const CPGRB_POOL *pool_2nd)
{
    uint16_t  node_num;
    uint16_t  node_pos;

    if(CPGRB_POOL_FREE_HEAD(pool_1st) != CPGRB_POOL_FREE_HEAD(pool_2nd))
    {
        dbg_log(SEC_0000_CPGRB, 0)(LOGSTDERR, "error:cpgrb_debug_cmp: inconsistent CPGRB_POOL_FREE_HEAD: %u != %u\n",
                            CPGRB_POOL_FREE_HEAD(pool_1st), CPGRB_POOL_FREE_HEAD(pool_2nd));
        return (EC_FALSE);
    }

    if(CPGRB_POOL_NODE_NUM(pool_1st) != CPGRB_POOL_NODE_NUM(pool_2nd))
    {
        dbg_log(SEC_0000_CPGRB, 0)(LOGSTDERR, "error:cpgrb_debug_cmp: inconsistent CPGRB_POOL_NODE_NUM: %u != %u\n",
                            CPGRB_POOL_NODE_NUM(pool_1st), CPGRB_POOL_NODE_NUM(pool_2nd));
        return (EC_FALSE);
    }

    node_num = CPGRB_POOL_NODE_NUM(pool_1st);
    for(node_pos = 0; node_pos < node_num; node_pos ++)
    {
        const CPGRB_NODE *node_1st;
        const CPGRB_NODE *node_2nd;

        node_1st = CPGRB_POOL_NODE(pool_1st, node_pos);
        node_2nd = CPGRB_POOL_NODE(pool_2nd, node_pos);

        if(EC_FALSE == cpgrb_node_debug_cmp(node_1st, node_2nd))
        {
            dbg_log(SEC_0000_CPGRB, 0)(LOGSTDERR, "error:cpgrb_debug_cmp: inconsistent node at pos %u\n", node_pos);
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}


#ifdef __cplusplus
}
#endif/*__cplusplus*/
