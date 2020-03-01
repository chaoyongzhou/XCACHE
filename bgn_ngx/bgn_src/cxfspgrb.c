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

#include "cxfspgrb.h"


/*new a CXFSPGRB_NODE and return its position*/
uint16_t cxfspgrb_node_new(CXFSPGRB_POOL *pool)
{
    uint16_t node_pos_t;
    CXFSPGRB_NODE *node;

    node_pos_t = CXFSPGRB_POOL_FREE_HEAD(pool);
    if(CXFSPGRB_ERR_POS == node_pos_t)
    {
        dbg_log(SEC_0204_CXFSPGRB, 0)(LOGSTDERR, "error:cxfspgrb_node_new: no free node in pool %p where free_head = %d, node_num = %d\n",
                           pool, CXFSPGRB_POOL_FREE_HEAD(pool), CXFSPGRB_POOL_NODE_NUM(pool));
        return (CXFSPGRB_ERR_POS);
    }

    node = CXFSPGRB_POOL_NODE(pool, node_pos_t);
    CXFSPGRB_POOL_FREE_HEAD(pool) = CXFSPGRB_NODE_NEXT_POS(node);
    CXFSPGRB_NODE_USED_FLAG(node) = CXFSPGRB_NODE_USED;

    return (node_pos_t);
}

/*free a CXFSPGRB_NODE and return its position to the pool*/
void cxfspgrb_node_free(CXFSPGRB_POOL *pool, const uint16_t node_pos)
{
    if(CXFSPGRB_ERR_POS != node_pos)
    {
        CXFSPGRB_NODE *node;

        node = CXFSPGRB_POOL_NODE(pool, node_pos);
        CXFSPGRB_NODE_USED_FLAG(node)  = CXFSPGRB_NODE_NOT_USED;
        CXFSPGRB_NODE_PARENT_POS(node) = CXFSPGRB_ERR_POS;
        CXFSPGRB_NODE_RIGHT_POS(node)  = CXFSPGRB_ERR_POS;
        CXFSPGRB_NODE_LEFT_POS(node)   = CXFSPGRB_ERR_POS;
        CXFSPGRB_NODE_NEXT_POS(node)   = CXFSPGRB_POOL_FREE_HEAD(pool);
        CXFSPGRB_NODE_COLOR(node)      = CXFSPGRB_BLACK;

        CXFSPGRB_POOL_FREE_HEAD(pool)  = node_pos;
    }
    return;
}

void cxfspgrb_node_init(CXFSPGRB_POOL *pool, const uint16_t node_pos)
{
    CXFSPGRB_NODE *node;

    node  = CXFSPGRB_POOL_NODE(pool, node_pos);

    CXFSPGRB_NODE_PARENT_POS(node) = CXFSPGRB_ERR_POS;
    CXFSPGRB_NODE_RIGHT_POS(node)  = CXFSPGRB_ERR_POS;
    CXFSPGRB_NODE_LEFT_POS(node)   = CXFSPGRB_ERR_POS;
    CXFSPGRB_NODE_USED_FLAG(node)  = CXFSPGRB_NODE_NOT_USED;
    CXFSPGRB_NODE_NEXT_POS(node)   = CXFSPGRB_ERR_POS;
    CXFSPGRB_NODE_COLOR(node)      = CXFSPGRB_BLACK;

    return;
}

void cxfspgrb_node_clean(CXFSPGRB_POOL *pool, const uint16_t node_pos)
{
    CXFSPGRB_NODE *node;

    node  = CXFSPGRB_POOL_NODE(pool, node_pos);

    CXFSPGRB_NODE_PARENT_POS(node) = CXFSPGRB_ERR_POS;
    CXFSPGRB_NODE_RIGHT_POS(node)  = CXFSPGRB_ERR_POS;
    CXFSPGRB_NODE_LEFT_POS(node)   = CXFSPGRB_ERR_POS;
    CXFSPGRB_NODE_USED_FLAG(node)  = CXFSPGRB_NODE_NOT_USED;
    CXFSPGRB_NODE_NEXT_POS(node)   = CXFSPGRB_ERR_POS;
    CXFSPGRB_NODE_COLOR(node)      = CXFSPGRB_BLACK;

    return;
}

void cxfspgrb_node_set_next(CXFSPGRB_POOL *pool, const uint16_t node_pos, const uint16_t next_pos)
{
    CXFSPGRB_NODE *node;

    node  = CXFSPGRB_POOL_NODE(pool, node_pos);
    CXFSPGRB_NODE_NEXT_POS(node) = next_pos;

    return;
}

void cxfspgrb_node_print(LOG *log, const CXFSPGRB_POOL *pool, const uint16_t node_pos)
{
    const CXFSPGRB_NODE *node;
    node  = CXFSPGRB_POOL_NODE(pool, node_pos);

    sys_log(log, "%5d: parent = %5d, left = %5d, right = %5d, flg = %s, color = %s, %s = %5d\n",
                       node_pos,
                       CXFSPGRB_NODE_PARENT_POS(node),
                       CXFSPGRB_NODE_LEFT_POS(node),
                       CXFSPGRB_NODE_RIGHT_POS(node),
                       CXFSPGRB_NODE_IS_USED(node) ? "used" : "n.a.",
                       CXFSPGRB_NODE_IS_USED(node) ? (CXFSPGRB_NODE_IS_RED(node) ? "red  " : "black") : "#####",
                       CXFSPGRB_NODE_IS_USED(node) ? "data" : "next",
                       CXFSPGRB_NODE_IS_USED(node) ? CXFSPGRB_NODE_DATA(node) : CXFSPGRB_NODE_NEXT_POS(node)
                       );
    return;
}

void cxfspgrb_node_print_level(LOG *log, const CXFSPGRB_POOL *pool, const uint16_t node_pos, const uint16_t level)
{
    const CXFSPGRB_NODE *node;
    node  = CXFSPGRB_POOL_NODE(pool, node_pos);

    c_ident_print(log, level);
    sys_print(log, "%5d: parent = %5d, left = %5d, right = %5d, flg = %s, color = %s, %s = %5d\n",
                       node_pos,
                       CXFSPGRB_NODE_PARENT_POS(node),
                       CXFSPGRB_NODE_LEFT_POS(node),
                       CXFSPGRB_NODE_RIGHT_POS(node),
                       CXFSPGRB_NODE_IS_USED(node) ? "used" : "NOT used",
                       CXFSPGRB_NODE_IS_RED(node)  ? "red  " : "black",
                       CXFSPGRB_NODE_IS_USED(node) ? "data" : "next",
                       CXFSPGRB_NODE_IS_USED(node) ? CXFSPGRB_NODE_DATA(node) : CXFSPGRB_NODE_NEXT_POS(node)
                       );
    return;
}


STATIC_CAST static void __cxfspgrb_tree_rotate_left(CXFSPGRB_POOL *pool, const uint16_t node_pos, uint16_t *root_pos)
{
    CXFSPGRB_NODE *node;
    CXFSPGRB_NODE *right;

    uint16_t  right_pos;

    node  = CXFSPGRB_POOL_NODE(pool, node_pos);

    right_pos = CXFSPGRB_NODE_RIGHT_POS(node);
    right = CXFSPGRB_POOL_NODE(pool, right_pos);

    if(CXFSPGRB_ERR_POS != (CXFSPGRB_NODE_RIGHT_POS(node) = CXFSPGRB_NODE_LEFT_POS(right)))
    {
        CXFSPGRB_NODE *left;
        left = CXFSPGRB_POOL_NODE(pool, CXFSPGRB_NODE_LEFT_POS(right));
        CXFSPGRB_NODE_PARENT_POS(left) = node_pos;
    }
    CXFSPGRB_NODE_LEFT_POS(right) = node_pos;

    if(CXFSPGRB_ERR_POS != (CXFSPGRB_NODE_PARENT_POS(right) = CXFSPGRB_NODE_PARENT_POS(node)))
    {
        CXFSPGRB_NODE *parent;
        parent = CXFSPGRB_POOL_NODE(pool, CXFSPGRB_NODE_PARENT_POS(node));

        if (node_pos == CXFSPGRB_NODE_LEFT_POS(parent))
        {
            CXFSPGRB_NODE_LEFT_POS(parent) = right_pos;
        }
        else
        {
            CXFSPGRB_NODE_RIGHT_POS(parent) = right_pos;
        }
    }
    else
    {
        (*root_pos) = right_pos;
    }
    CXFSPGRB_NODE_PARENT_POS(node) = right_pos;
    return;
}

STATIC_CAST static void __cxfspgrb_tree_rotate_right(CXFSPGRB_POOL *pool, const uint16_t node_pos, uint16_t *root_pos)
{
    CXFSPGRB_NODE *node;
    CXFSPGRB_NODE *left;
    uint16_t  left_pos;

    node  = CXFSPGRB_POOL_NODE(pool, node_pos);

    left_pos = CXFSPGRB_NODE_LEFT_POS(node);
    left = CXFSPGRB_POOL_NODE(pool, left_pos);

    if (CXFSPGRB_ERR_POS != (CXFSPGRB_NODE_LEFT_POS(node) = CXFSPGRB_NODE_RIGHT_POS(left)))
    {
        CXFSPGRB_NODE *right;
        right = CXFSPGRB_POOL_NODE(pool, CXFSPGRB_NODE_RIGHT_POS(left));
        CXFSPGRB_NODE_PARENT_POS(right) = node_pos;
    }
    CXFSPGRB_NODE_RIGHT_POS(left) = node_pos;

    if (CXFSPGRB_ERR_POS != (CXFSPGRB_NODE_PARENT_POS(left) = CXFSPGRB_NODE_PARENT_POS(node)))
    {
        CXFSPGRB_NODE *parent;
        parent = CXFSPGRB_POOL_NODE(pool, CXFSPGRB_NODE_PARENT_POS(node));

        if (node_pos == CXFSPGRB_NODE_RIGHT_POS(parent))
        {
            CXFSPGRB_NODE_RIGHT_POS(parent) = left_pos;
        }
        else
        {
            CXFSPGRB_NODE_LEFT_POS(parent) = left_pos;
        }
    }
    else
    {
        (*root_pos) = left_pos;
    }
    CXFSPGRB_NODE_PARENT_POS(node) = left_pos;
    return;
}

STATIC_CAST static void __cxfspgrb_tree_insert_color(CXFSPGRB_POOL *pool, const uint16_t node_pos, uint16_t *root_pos)
{
    CXFSPGRB_NODE *node;
    CXFSPGRB_NODE *root;
    CXFSPGRB_NODE *parent;

    uint16_t  node_pos_t;

    node_pos_t = node_pos;
    node  = CXFSPGRB_POOL_NODE(pool, node_pos_t);

    while (NULL_PTR != (parent = CXFSPGRB_POOL_NODE(pool, CXFSPGRB_NODE_PARENT_POS(node))) /*parent is valid*/
         && CXFSPGRB_RED == CXFSPGRB_NODE_COLOR(parent))
    {
        uint16_t  parent_pos;
        uint16_t  gparent_pos;
        CXFSPGRB_NODE *gparent;

        parent_pos = CXFSPGRB_NODE_PARENT_POS(node);

        gparent_pos = CXFSPGRB_NODE_PARENT_POS(parent);
        ASSERT(CXFSPGRB_ERR_POS != gparent_pos);
        gparent = CXFSPGRB_POOL_NODE(pool, gparent_pos);

        if (parent_pos == CXFSPGRB_NODE_LEFT_POS(gparent))
        {
            {
                CXFSPGRB_NODE *uncle;
                if (NULL_PTR != (uncle = CXFSPGRB_POOL_NODE(pool, CXFSPGRB_NODE_RIGHT_POS(gparent))) /*uncle is valid*/
                   && CXFSPGRB_RED == CXFSPGRB_NODE_COLOR(uncle))
                {
                    CXFSPGRB_NODE_COLOR(uncle)   = CXFSPGRB_BLACK;
                    CXFSPGRB_NODE_COLOR(parent)  = CXFSPGRB_BLACK;
                    CXFSPGRB_NODE_COLOR(gparent) = CXFSPGRB_RED;

                    node = gparent;
                    node_pos_t = gparent_pos;
                    continue;
                }
            }

            if (CXFSPGRB_NODE_RIGHT_POS(parent) == node_pos_t)
            {
                __cxfspgrb_tree_rotate_left(pool, parent_pos, root_pos);
                XCHG(CXFSPGRB_NODE *, parent, node);
                XCHG(uint16_t, parent_pos, node_pos_t);
            }

            CXFSPGRB_NODE_COLOR(parent)  = CXFSPGRB_BLACK;
            CXFSPGRB_NODE_COLOR(gparent) = CXFSPGRB_RED;
            __cxfspgrb_tree_rotate_right(pool, gparent_pos, root_pos);
         }
         else
         {
            {
                CXFSPGRB_NODE *uncle;
                if (NULL_PTR != (uncle = CXFSPGRB_POOL_NODE(pool, CXFSPGRB_NODE_LEFT_POS(gparent))) /*uncle is valid*/
                    && CXFSPGRB_RED == CXFSPGRB_NODE_COLOR(uncle))
                {
                    CXFSPGRB_NODE_COLOR(uncle)   = CXFSPGRB_BLACK;
                    CXFSPGRB_NODE_COLOR(parent)  = CXFSPGRB_BLACK;
                    CXFSPGRB_NODE_COLOR(gparent) = CXFSPGRB_RED;

                    node = gparent;
                    node_pos_t = gparent_pos;
                    continue;
                }
            }

            if (CXFSPGRB_NODE_LEFT_POS(parent) == node_pos_t)
            {
                __cxfspgrb_tree_rotate_right(pool, parent_pos, root_pos);
                XCHG(CXFSPGRB_NODE *, parent, node);
                XCHG(uint16_t, parent_pos, node_pos_t);
            }

            CXFSPGRB_NODE_COLOR(parent)  = CXFSPGRB_BLACK;
            CXFSPGRB_NODE_COLOR(gparent) = CXFSPGRB_RED;
            __cxfspgrb_tree_rotate_left(pool, gparent_pos, root_pos);
        }
    }

    root = CXFSPGRB_POOL_NODE(pool, *root_pos);
    CXFSPGRB_NODE_COLOR(root) = CXFSPGRB_BLACK;
    return;
}

STATIC_CAST static void __cxfspgrb_tree_erase_color(CXFSPGRB_POOL *pool, const uint16_t node_pos, const uint16_t parent_pos, uint16_t *root_pos)
{
    CXFSPGRB_NODE *node;
    uint16_t  node_pos_t;
    uint16_t  parent_pos_t;

    node_pos_t   = node_pos;
    parent_pos_t = parent_pos;

    while ((NULL_PTR == (node = CXFSPGRB_POOL_NODE(pool, node_pos_t)) || CXFSPGRB_BLACK == CXFSPGRB_NODE_COLOR(node)) && node_pos_t != (*root_pos))
    {
        CXFSPGRB_NODE *parent;

        parent = CXFSPGRB_POOL_NODE(pool, parent_pos_t);

        if (CXFSPGRB_NODE_LEFT_POS(parent) == node_pos_t)
        {
            CXFSPGRB_NODE *other;
            CXFSPGRB_NODE *o_left;
            CXFSPGRB_NODE *o_right;
            uint16_t  other_pos;

            other_pos = CXFSPGRB_NODE_RIGHT_POS(parent);
            other = CXFSPGRB_POOL_NODE(pool, other_pos);

            if (CXFSPGRB_RED == CXFSPGRB_NODE_COLOR(other))
            {
                CXFSPGRB_NODE_COLOR(other)  = CXFSPGRB_BLACK;
                CXFSPGRB_NODE_COLOR(parent) = CXFSPGRB_RED;

                __cxfspgrb_tree_rotate_left(pool, parent_pos_t, root_pos);

                other_pos = CXFSPGRB_NODE_RIGHT_POS(parent);
                other = CXFSPGRB_POOL_NODE(pool, other_pos);
            }

            o_left = CXFSPGRB_POOL_NODE(pool, CXFSPGRB_NODE_LEFT_POS(other));
            o_right = CXFSPGRB_POOL_NODE(pool, CXFSPGRB_NODE_RIGHT_POS(other));

            if((NULL_PTR == o_left || CXFSPGRB_BLACK == CXFSPGRB_NODE_COLOR(o_left))
            && (NULL_PTR == o_right || CXFSPGRB_BLACK == CXFSPGRB_NODE_COLOR(o_right)))
            {
                CXFSPGRB_NODE_COLOR(other) = CXFSPGRB_RED;

                node_pos_t = parent_pos_t;
                node = CXFSPGRB_POOL_NODE(pool, node_pos_t);

                parent_pos_t = CXFSPGRB_NODE_PARENT_POS(node);
                parent = CXFSPGRB_POOL_NODE(pool, parent_pos_t);
            }
            else
            {
                if (NULL_PTR == o_right || CXFSPGRB_BLACK == CXFSPGRB_NODE_COLOR(o_right))
                {
                    if (NULL_PTR != o_left)
                    {
                        CXFSPGRB_NODE_COLOR(o_left) = CXFSPGRB_BLACK;
                    }
                    CXFSPGRB_NODE_COLOR(other) = CXFSPGRB_RED;

                    __cxfspgrb_tree_rotate_right(pool, other_pos, root_pos);

                    other_pos = CXFSPGRB_NODE_RIGHT_POS(parent);
                    other = CXFSPGRB_POOL_NODE(pool, other_pos);
                    /*note: other was changed here*/
                }

                CXFSPGRB_NODE_COLOR(other) = CXFSPGRB_NODE_COLOR(parent);
                CXFSPGRB_NODE_COLOR(parent) = CXFSPGRB_BLACK;

                /*due to other may be changed before, have to get o_right again here*/
                o_right = CXFSPGRB_POOL_NODE(pool, CXFSPGRB_NODE_RIGHT_POS(other));
                if (NULL_PTR != o_right)
                {
                    CXFSPGRB_NODE_COLOR(o_right) = CXFSPGRB_BLACK;
                }

                __cxfspgrb_tree_rotate_left(pool, parent_pos_t, root_pos);
                node_pos_t = (*root_pos);
                break;
            }
        }
        else
        {
            CXFSPGRB_NODE *other;
            CXFSPGRB_NODE *o_left;
            CXFSPGRB_NODE *o_right;
            uint16_t  other_pos;

            other_pos = CXFSPGRB_NODE_LEFT_POS(parent);
            other = CXFSPGRB_POOL_NODE(pool, other_pos);

            if (CXFSPGRB_RED == CXFSPGRB_NODE_COLOR(other))
            {
                CXFSPGRB_NODE_COLOR(other) = CXFSPGRB_BLACK;
                CXFSPGRB_NODE_COLOR(parent) = CXFSPGRB_RED;

                __cxfspgrb_tree_rotate_right(pool, parent_pos_t, root_pos);

                other_pos = CXFSPGRB_NODE_LEFT_POS(parent);
                other = CXFSPGRB_POOL_NODE(pool, other_pos);
            }

            o_left = CXFSPGRB_POOL_NODE(pool, CXFSPGRB_NODE_LEFT_POS(other));
            o_right = CXFSPGRB_POOL_NODE(pool, CXFSPGRB_NODE_RIGHT_POS(other));

            if ((NULL_PTR == o_left  || CXFSPGRB_BLACK == CXFSPGRB_NODE_COLOR(o_left))
             && (NULL_PTR == o_right || CXFSPGRB_BLACK == CXFSPGRB_NODE_COLOR(o_right)))
            {
                CXFSPGRB_NODE_COLOR(other) = CXFSPGRB_RED;

                node_pos_t = parent_pos_t;
                node = CXFSPGRB_POOL_NODE(pool, node_pos_t);

                parent_pos_t = CXFSPGRB_NODE_PARENT_POS(node);
                parent = CXFSPGRB_POOL_NODE(pool, parent_pos_t);
            }
            else
            {
                if (NULL_PTR == o_left  || CXFSPGRB_BLACK == CXFSPGRB_NODE_COLOR(o_left))
                {
                    if (NULL_PTR != o_right)
                    {
                        CXFSPGRB_NODE_COLOR(o_right) = CXFSPGRB_BLACK;
                    }

                    CXFSPGRB_NODE_COLOR(other) = CXFSPGRB_RED;

                    __cxfspgrb_tree_rotate_left(pool, other_pos, root_pos);

                    other_pos = CXFSPGRB_NODE_LEFT_POS(parent);
                    other = CXFSPGRB_POOL_NODE(pool, other_pos);
                    /*note: other was changed here*/
                }

                CXFSPGRB_NODE_COLOR(other) = CXFSPGRB_NODE_COLOR(parent);
                CXFSPGRB_NODE_COLOR(parent) = CXFSPGRB_BLACK;

                /*due to other may be changed before, have to get o_left again here*/
                o_left = CXFSPGRB_POOL_NODE(pool, CXFSPGRB_NODE_LEFT_POS(other));
                if (NULL_PTR != o_left)
                {
                    CXFSPGRB_NODE_COLOR(o_left) = CXFSPGRB_BLACK;
                }
                __cxfspgrb_tree_rotate_right(pool, parent_pos_t, root_pos);
                node_pos_t = (*root_pos);
                break;
            }
        }
    }

    node = CXFSPGRB_POOL_NODE(pool, node_pos_t);
    if (NULL_PTR != node)
    {
        CXFSPGRB_NODE_COLOR(node) = CXFSPGRB_BLACK;
    }
    return;
}

STATIC_CAST static void __cxfspgrb_tree_erase(CXFSPGRB_POOL *pool, const uint16_t node_pos, uint16_t *root_pos)
{
    CXFSPGRB_NODE *node;

    uint16_t node_pos_t;
    uint16_t child_pos;
    uint16_t parent_pos;
    uint16_t color;

    node_pos_t = node_pos;
    node = CXFSPGRB_POOL_NODE(pool, node_pos_t);

    ASSERT(NULL_PTR != node);
    ASSERT(CXFSPGRB_NODE_IS_USED(node));

    if (CXFSPGRB_ERR_POS == CXFSPGRB_NODE_LEFT_POS(node))
    {
        child_pos = CXFSPGRB_NODE_RIGHT_POS(node);
    }
    else if (CXFSPGRB_ERR_POS == CXFSPGRB_NODE_RIGHT_POS(node))
    {
        child_pos = CXFSPGRB_NODE_LEFT_POS(node);
    }
    else
    {
        CXFSPGRB_NODE *old;

        uint16_t old_pos;
        uint16_t left_pos;

        old_pos = node_pos_t;

        node_pos_t = CXFSPGRB_NODE_RIGHT_POS(node);
        node = CXFSPGRB_POOL_NODE(pool, node_pos_t);

        while (CXFSPGRB_ERR_POS != (left_pos = CXFSPGRB_NODE_LEFT_POS(node)))
        {
            node_pos_t = left_pos;
            node = CXFSPGRB_POOL_NODE(pool, node_pos_t);

        }

        child_pos  = CXFSPGRB_NODE_RIGHT_POS(node);
        parent_pos = CXFSPGRB_NODE_PARENT_POS(node);
        color      = CXFSPGRB_NODE_COLOR(node);

        if (CXFSPGRB_ERR_POS != child_pos)
        {
            CXFSPGRB_NODE *child;
            child = CXFSPGRB_POOL_NODE(pool, child_pos);
            CXFSPGRB_NODE_PARENT_POS(child) = parent_pos;
        }

        if (CXFSPGRB_ERR_POS != parent_pos)
        {
            CXFSPGRB_NODE *parent;

            parent = CXFSPGRB_POOL_NODE(pool, parent_pos);
            if (CXFSPGRB_NODE_LEFT_POS(parent) == node_pos_t)
            {
                CXFSPGRB_NODE_LEFT_POS(parent) = child_pos;
            }
            else
            {
                CXFSPGRB_NODE_RIGHT_POS(parent) = child_pos;
            }
        }
        else
        {
            (*root_pos) = child_pos;
        }

        if (CXFSPGRB_NODE_PARENT_POS(node) == old_pos)
        {
            parent_pos = node_pos_t;
        }

        //node = CXFSPGRB_POOL_NODE(pool, node_pos_t);
        old  = CXFSPGRB_POOL_NODE(pool, old_pos);

        CXFSPGRB_NODE_PARENT_POS(node) = CXFSPGRB_NODE_PARENT_POS(old);
        CXFSPGRB_NODE_COLOR(node)      = CXFSPGRB_NODE_COLOR(old);
        CXFSPGRB_NODE_RIGHT_POS(node)  = CXFSPGRB_NODE_RIGHT_POS(old);
        CXFSPGRB_NODE_LEFT_POS(node)   = CXFSPGRB_NODE_LEFT_POS(old);

        if (CXFSPGRB_ERR_POS != CXFSPGRB_NODE_PARENT_POS(old))
        {
            CXFSPGRB_NODE *old_parent;
            old_parent = CXFSPGRB_POOL_NODE(pool, CXFSPGRB_NODE_PARENT_POS(old));

            if (CXFSPGRB_NODE_LEFT_POS(old_parent) == old_pos)
            {
                CXFSPGRB_NODE_LEFT_POS(old_parent) = node_pos_t;
            }
            else
            {
                CXFSPGRB_NODE_RIGHT_POS(old_parent) = node_pos_t;
            }
        }
        else
        {
            (*root_pos) = node_pos_t;
        }

        {
            CXFSPGRB_NODE *old_left;

            old_left = CXFSPGRB_POOL_NODE(pool, CXFSPGRB_NODE_LEFT_POS(old));
            CXFSPGRB_NODE_PARENT_POS(old_left) = node_pos_t;
        }

        if (CXFSPGRB_ERR_POS != CXFSPGRB_NODE_RIGHT_POS(old))
        {
            CXFSPGRB_NODE *old_right;
            old_right = CXFSPGRB_POOL_NODE(pool, CXFSPGRB_NODE_RIGHT_POS(old));
            CXFSPGRB_NODE_PARENT_POS(old_right) = node_pos_t;
        }
        goto color;
    }

    parent_pos = CXFSPGRB_NODE_PARENT_POS(node);
    color = CXFSPGRB_NODE_COLOR(node);

    if (CXFSPGRB_ERR_POS != child_pos)
    {
        CXFSPGRB_NODE *child;
        child = CXFSPGRB_POOL_NODE(pool, child_pos);
        CXFSPGRB_NODE_PARENT_POS(child) = parent_pos;
    }

    if (CXFSPGRB_ERR_POS != parent_pos)
    {
        CXFSPGRB_NODE *parent;

        parent = CXFSPGRB_POOL_NODE(pool, parent_pos);
        if (CXFSPGRB_NODE_LEFT_POS(parent) == node_pos_t)
        {
            CXFSPGRB_NODE_LEFT_POS(parent) = child_pos;
        }
        else
        {
            CXFSPGRB_NODE_RIGHT_POS(parent) = child_pos;
        }
    }
    else
    {
        (*root_pos) = child_pos;
    }

 color:
    if (CXFSPGRB_BLACK == color)
    {
        __cxfspgrb_tree_erase_color(pool, child_pos, parent_pos, root_pos);
    }
    return;
}

EC_BOOL cxfspgrb_tree_is_empty(const CXFSPGRB_POOL *pool, const uint16_t root_pos)
{
    if (CXFSPGRB_ERR_POS == root_pos)
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}


STATIC_CAST static uint16_t __cxfspgrb_tree_node_num(const CXFSPGRB_POOL *pool, const uint16_t node_pos)
{
    const CXFSPGRB_NODE *node;

    if(CXFSPGRB_ERR_POS == node_pos)
    {
        return ((uint16_t)0);
    }

    node = CXFSPGRB_POOL_NODE(pool, node_pos);

    return (uint16_t)(1 + __cxfspgrb_tree_node_num(pool, CXFSPGRB_NODE_LEFT_POS(node)) + __cxfspgrb_tree_node_num(pool, CXFSPGRB_NODE_RIGHT_POS(node)));
}

uint16_t cxfspgrb_tree_node_num(const CXFSPGRB_POOL *pool, const uint16_t root_pos)
{
    return __cxfspgrb_tree_node_num(pool, root_pos);
}

/*
 * This function returns the first node_pos (in sort order) of the tree.
 */
uint16_t cxfspgrb_tree_first_node(const CXFSPGRB_POOL *pool, const uint16_t root_pos)
{
    uint16_t  node_pos;
    const CXFSPGRB_NODE *node;

    node_pos = root_pos;
    if (CXFSPGRB_ERR_POS == node_pos)
    {
        return (CXFSPGRB_ERR_POS);
    }

    node = CXFSPGRB_POOL_NODE(pool, node_pos);

    while (CXFSPGRB_ERR_POS != CXFSPGRB_NODE_LEFT_POS(node))
    {
        node_pos = CXFSPGRB_NODE_LEFT_POS(node);
        node = CXFSPGRB_POOL_NODE(pool, node_pos);
    }
    return (node_pos);
}

uint16_t cxfspgrb_tree_last_node(const CXFSPGRB_POOL *pool, const uint16_t root_pos)
{
    uint16_t  node_pos;
    const CXFSPGRB_NODE *node;

    node_pos = root_pos;
    if (CXFSPGRB_ERR_POS == node_pos)
    {
        return (CXFSPGRB_ERR_POS);
    }

    node = CXFSPGRB_POOL_NODE(pool, node_pos);

    while (CXFSPGRB_ERR_POS != CXFSPGRB_NODE_RIGHT_POS(node))
    {
        node_pos = CXFSPGRB_NODE_RIGHT_POS(node);
        node = CXFSPGRB_POOL_NODE(pool, node_pos);
    }

    return (node_pos);
}

uint16_t cxfspgrb_tree_next_node(const CXFSPGRB_POOL *pool, const uint16_t node_pos)
{
    uint16_t node_pos_t;
    const CXFSPGRB_NODE *node;
    const CXFSPGRB_NODE *parent;

    node_pos_t = node_pos;
    node = CXFSPGRB_POOL_NODE(pool, node_pos_t);
    /* If we have a right-hand child, go down and then left as far
       as we can. */
    if (CXFSPGRB_ERR_POS != CXFSPGRB_NODE_RIGHT_POS(node))
    {
        node_pos_t = CXFSPGRB_NODE_RIGHT_POS(node);
        node = CXFSPGRB_POOL_NODE(pool, node_pos_t);
        while (CXFSPGRB_ERR_POS != CXFSPGRB_NODE_LEFT_POS(node))
        {
            node_pos_t = CXFSPGRB_NODE_LEFT_POS(node);
            node = CXFSPGRB_POOL_NODE(pool, node_pos_t);
        }
        return (node_pos_t);
    }

    /* No right-hand children.  Everything down and left is
       smaller than us, so any 'next' node_pos_t must be in the general
       direction of our parent. Go up the tree; any time the
       ancestor is a right-hand child of its parent, keep going
       up. First time it's a left-hand child of its parent, said
       parent is our 'next' node_pos_t. */
    while (NULL_PTR != (parent = CXFSPGRB_POOL_NODE(pool, CXFSPGRB_NODE_PARENT_POS(node))) && node_pos_t == CXFSPGRB_NODE_RIGHT_POS(parent))
    {
        node_pos_t = CXFSPGRB_NODE_PARENT_POS(node);
        node = parent;
    }

    return (CXFSPGRB_NODE_PARENT_POS(node));
}

uint16_t cxfspgrb_tree_prev_node(const CXFSPGRB_POOL *pool, const uint16_t node_pos)
{
    uint16_t node_pos_t;
    const CXFSPGRB_NODE *node;
    const CXFSPGRB_NODE *parent;

    node_pos_t = node_pos;
    node = CXFSPGRB_POOL_NODE(pool, node_pos_t);

    /* If we have a left-hand child, go down and then right as far
       as we can. */
    if (CXFSPGRB_ERR_POS != CXFSPGRB_NODE_LEFT_POS(node))
    {
        node_pos_t = CXFSPGRB_NODE_LEFT_POS(node);
        node = CXFSPGRB_POOL_NODE(pool, node_pos_t);
        while (CXFSPGRB_ERR_POS != CXFSPGRB_NODE_RIGHT_POS(node))
        {
            node_pos_t = CXFSPGRB_NODE_RIGHT_POS(node);
            node = CXFSPGRB_POOL_NODE(pool, node_pos_t);
        }
        return (node_pos_t);
    }

    /* No left-hand children. Go up till we find an ancestor which
       is a right-hand child of its parent */
    while (NULL_PTR != (parent = CXFSPGRB_POOL_NODE(pool, CXFSPGRB_NODE_PARENT_POS(node))) && node_pos_t == CXFSPGRB_NODE_LEFT_POS(parent))
    {
        node_pos_t = CXFSPGRB_NODE_PARENT_POS(node);
        node = parent;
    }

    return (CXFSPGRB_NODE_PARENT_POS(node));
}

/*victim_pos should be free*/
void cxfspgrb_tree_replace_node(CXFSPGRB_POOL *pool, const uint16_t victim_pos, const uint16_t new_pos, uint16_t *root_pos)
{
    CXFSPGRB_NODE *victim;

    victim = CXFSPGRB_POOL_NODE(pool, victim_pos);

    /* Set the surrounding nodes to point to the replacement */
    if (CXFSPGRB_ERR_POS != CXFSPGRB_NODE_PARENT_POS(victim))
    {
        CXFSPGRB_NODE *parent;
        parent = CXFSPGRB_POOL_NODE(pool, CXFSPGRB_NODE_PARENT_POS(victim));

        if (victim_pos == CXFSPGRB_NODE_LEFT_POS(parent))
        {
            CXFSPGRB_NODE_LEFT_POS(parent) = new_pos;
        }
        else
        {
            CXFSPGRB_NODE_RIGHT_POS(parent) = new_pos;
        }
    }
    else
    {
        (*root_pos) = new_pos;
    }

    if (CXFSPGRB_ERR_POS != CXFSPGRB_NODE_LEFT_POS(victim))
    {
        CXFSPGRB_NODE *left;
        left = CXFSPGRB_POOL_NODE(pool, CXFSPGRB_NODE_LEFT_POS(victim));
        CXFSPGRB_NODE_PARENT_POS(left) = new_pos;
    }
    if (CXFSPGRB_ERR_POS != CXFSPGRB_NODE_RIGHT_POS(victim))
    {
        CXFSPGRB_NODE *right;
        right = CXFSPGRB_POOL_NODE(pool, CXFSPGRB_NODE_RIGHT_POS(victim));
        CXFSPGRB_NODE_PARENT_POS(right) = new_pos;
    }

    return;
}

/*return the searched pos*/
uint16_t cxfspgrb_tree_search_data(CXFSPGRB_POOL *pool, const uint16_t root_pos, uint16_t data)
{
    uint16_t node_pos;

    node_pos = root_pos;

    while (CXFSPGRB_ERR_POS != node_pos)
    {
        CXFSPGRB_NODE *node;

        node = CXFSPGRB_POOL_NODE(pool, node_pos);

        if (data < CXFSPGRB_NODE_DATA(node))
        {
            node_pos = CXFSPGRB_NODE_LEFT_POS(node);
        }
        else if (data > CXFSPGRB_NODE_DATA(node))
        {
            node_pos = CXFSPGRB_NODE_RIGHT_POS(node);
        }
        else
        {
            return (node_pos);
        }
    }

    return (CXFSPGRB_ERR_POS);
}


uint16_t cxfspgrb_tree_insert_data(CXFSPGRB_POOL *pool, uint16_t *root_pos, const uint16_t data)
{
    uint16_t  node_pos_t;
    uint16_t  new_pos_t;
    uint16_t  parent_pos_t;
    uint16_t  flag; /*0: on left subtree, 1: on right subtree*/

    node_pos_t   = (*root_pos);
    parent_pos_t = CXFSPGRB_ERR_POS;
    flag         = ~(uint16_t)0;

    while (CXFSPGRB_ERR_POS != node_pos_t)
    {
        CXFSPGRB_NODE *node;

        node = CXFSPGRB_POOL_NODE(pool, node_pos_t);

        parent_pos_t = node_pos_t;

        if (data < CXFSPGRB_NODE_DATA(node))
        {
            node_pos_t = CXFSPGRB_NODE_LEFT_POS(node);
            flag = 0;
        }
        else if (data > CXFSPGRB_NODE_DATA(node))
        {
            node_pos_t = CXFSPGRB_NODE_RIGHT_POS(node);
            flag = 1;
        }
        else
        {
            return (node_pos_t);
        }
    }

    /*not found data in the rbtree*/
    new_pos_t = cxfspgrb_node_new(pool);
    if(CXFSPGRB_ERR_POS == new_pos_t)
    {
        dbg_log(SEC_0204_CXFSPGRB, 0)(LOGSTDOUT, "error:cxfspgrb_tree_insert_data: new cxfspgrb_node from pool %p failed\n", pool);
        return (CXFSPGRB_ERR_POS);
    }
    else
    {
        CXFSPGRB_NODE *node;

        node  = CXFSPGRB_POOL_NODE(pool, new_pos_t);
        CXFSPGRB_NODE_DATA(node) = data;

        CXFSPGRB_NODE_PARENT_POS(node) = parent_pos_t;
        CXFSPGRB_NODE_COLOR(node)      = CXFSPGRB_RED;
        CXFSPGRB_NODE_LEFT_POS(node)   = CXFSPGRB_ERR_POS;
        CXFSPGRB_NODE_RIGHT_POS(node)  = CXFSPGRB_ERR_POS;

        if(CXFSPGRB_ERR_POS == (*root_pos))
        {
            (*root_pos) = new_pos_t;
        }
        else
        {
            CXFSPGRB_NODE *parent;
            parent  = CXFSPGRB_POOL_NODE(pool, parent_pos_t);

            if(0 == flag)/*on left subtree*/
            {
                CXFSPGRB_NODE_LEFT_POS(parent) = new_pos_t;
            }
            else
            {
                CXFSPGRB_NODE_RIGHT_POS(parent) = new_pos_t;
            }
        }
        __cxfspgrb_tree_insert_color(pool, new_pos_t, root_pos);
    }

    return (new_pos_t);
}

EC_BOOL cxfspgrb_tree_delete_data(CXFSPGRB_POOL *pool, uint16_t *root_pos, const uint16_t data)
{
    uint16_t node_pos;

    node_pos = cxfspgrb_tree_search_data(pool, *root_pos, data);
    if(CXFSPGRB_ERR_POS == node_pos)
    {
        return (EC_FALSE);
    }

    __cxfspgrb_tree_erase(pool, node_pos, root_pos);
    cxfspgrb_node_free(pool, node_pos);
    return (EC_TRUE);
}

/*postorder: left -> right -> root*/
STATIC_CAST static void __cxfspgrb_tree_free(CXFSPGRB_POOL *pool, const uint16_t node_pos)
{
    CXFSPGRB_NODE *node;

    if(CXFSPGRB_ERR_POS == node_pos)
    {
        return;
    }

    node  = CXFSPGRB_POOL_NODE(pool, node_pos);
    if(CXFSPGRB_ERR_POS != CXFSPGRB_NODE_LEFT_POS(node))
    {
        __cxfspgrb_tree_free(pool, CXFSPGRB_NODE_LEFT_POS(node));
    }

    if(CXFSPGRB_ERR_POS != CXFSPGRB_NODE_RIGHT_POS(node))
    {
        __cxfspgrb_tree_free(pool, CXFSPGRB_NODE_RIGHT_POS(node));
    }

    cxfspgrb_node_free(pool, node_pos);

    return;
}
void cxfspgrb_tree_free(CXFSPGRB_POOL *pool, const uint16_t root_pos)
{
    __cxfspgrb_tree_free(pool, root_pos);
    return;
}

EC_BOOL cxfspgrb_pool_init(CXFSPGRB_POOL *pool, const uint16_t node_num)
{
    uint16_t node_pos;

    ASSERT(CXFSPGRB_POOL_MAX_SIZE >= node_num);

    CXFSPGRB_POOL_NODE_NUM(pool) = node_num;

    for(node_pos = 0; node_pos < node_num; node_pos ++)
    {
        cxfspgrb_node_init(pool, node_pos);
        cxfspgrb_node_set_next(pool, node_pos, node_pos + 1);
    }
    cxfspgrb_node_set_next(pool, node_num - 1, CXFSPGRB_ERR_POS);

    CXFSPGRB_POOL_FREE_HEAD(pool) = 0;/*the free nodes head*/
    return (EC_TRUE);
}

void cxfspgrb_pool_clean(CXFSPGRB_POOL *pool)
{
    CXFSPGRB_POOL_NODE_NUM(pool)  = 0;
    CXFSPGRB_POOL_FREE_HEAD(pool) = CXFSPGRB_ERR_POS;
    return;
}

/*clear without any space mallocation!*/
void cxfspgrb_pool_clear(CXFSPGRB_POOL *pool)
{
    CXFSPGRB_POOL_NODE_NUM(pool)  = 0;
    CXFSPGRB_POOL_FREE_HEAD(pool) = CXFSPGRB_ERR_POS;
    return;
}

void cxfspgrb_pool_print(LOG *log, const CXFSPGRB_POOL *pool)
{
    uint16_t node_pos;
    uint16_t node_num;

    node_num = CXFSPGRB_POOL_NODE_NUM(pool);

    sys_log(log, "pool %lx, node_num %u, free_head %u\n",
                 pool,
                 node_num,
                 CXFSPGRB_POOL_FREE_HEAD(pool));

    for(node_pos = 0; node_pos < node_num; node_pos ++)
    {
        cxfspgrb_node_print(log, pool, node_pos);
    }

    return;
}

/*visit the root node first: root -> left -> right*/
void cxfspgrb_preorder_print(LOG *log, const CXFSPGRB_POOL *pool, const uint16_t node_pos)
{
    const CXFSPGRB_NODE *node;

    if(CXFSPGRB_ERR_POS == node_pos)
    {
        return;
    }

    node  = CXFSPGRB_POOL_NODE(pool, node_pos);
    cxfspgrb_node_print(log, pool, node_pos);

    if(CXFSPGRB_ERR_POS != CXFSPGRB_NODE_LEFT_POS(node))
    {
        cxfspgrb_preorder_print(log, pool, CXFSPGRB_NODE_LEFT_POS(node));
    }

    if(CXFSPGRB_ERR_POS != CXFSPGRB_NODE_RIGHT_POS(node))
    {
        cxfspgrb_preorder_print(log, pool, CXFSPGRB_NODE_RIGHT_POS(node));
    }

    return;
}

/*visit the left subtree, then the root node: left -> root -> right*/
void cxfspgrb_inorder_print(LOG *log, const CXFSPGRB_POOL *pool, const uint16_t node_pos)
{
    const CXFSPGRB_NODE *node;

    if(CXFSPGRB_ERR_POS == node_pos)
    {
        return;
    }

    node  = CXFSPGRB_POOL_NODE(pool, node_pos);
    if(CXFSPGRB_ERR_POS != CXFSPGRB_NODE_LEFT_POS(node))
    {
        cxfspgrb_inorder_print(log, pool, CXFSPGRB_NODE_LEFT_POS(node));
    }

    cxfspgrb_node_print(log, pool, node_pos);

    if(CXFSPGRB_ERR_POS != CXFSPGRB_NODE_RIGHT_POS(node))
    {
        cxfspgrb_inorder_print(log, pool, CXFSPGRB_NODE_RIGHT_POS(node));
    }

    return;
}

/*visit the root node last: left -> right -> root*/
void cxfspgrb_postorder_print(LOG *log, const CXFSPGRB_POOL *pool, const uint16_t node_pos)
{
    const CXFSPGRB_NODE *node;

    if(CXFSPGRB_ERR_POS == node_pos)
    {
        return;
    }

    node  = CXFSPGRB_POOL_NODE(pool, node_pos);
    if(CXFSPGRB_ERR_POS != CXFSPGRB_NODE_LEFT_POS(node))
    {
        cxfspgrb_postorder_print(log, pool, CXFSPGRB_NODE_LEFT_POS(node));
    }

    if(CXFSPGRB_ERR_POS != CXFSPGRB_NODE_RIGHT_POS(node))
    {
        cxfspgrb_postorder_print(log, pool, CXFSPGRB_NODE_RIGHT_POS(node));
    }

    cxfspgrb_node_print(log, pool, node_pos);

    return;
}


/*visit the root node first: root -> left -> right*/
void cxfspgrb_preorder_print_level(LOG *log, const CXFSPGRB_POOL *pool, const uint16_t node_pos, const uint16_t level)
{
    const CXFSPGRB_NODE *node;

    if(CXFSPGRB_ERR_POS == node_pos)
    {
        return;
    }

    node  = CXFSPGRB_POOL_NODE(pool, node_pos);
    cxfspgrb_node_print_level(log, pool, node_pos, level);

    if(CXFSPGRB_ERR_POS != CXFSPGRB_NODE_LEFT_POS(node))
    {
        cxfspgrb_preorder_print_level(log, pool, CXFSPGRB_NODE_LEFT_POS(node), level + 1);
    }

    if(CXFSPGRB_ERR_POS != CXFSPGRB_NODE_RIGHT_POS(node))
    {
        cxfspgrb_preorder_print_level(log, pool, CXFSPGRB_NODE_RIGHT_POS(node), level + 1);
    }

    return;
}

EC_BOOL cxfspgrb_flush_size(const CXFSPGRB_POOL *pool, UINT32 *size)
{
    (*size) += sizeof(CXFSPGRB_POOL) + CXFSPGRB_POOL_NODE_NUM(pool) * sizeof(CXFSPGRB_NODE);
    return (EC_TRUE);
}

EC_BOOL cxfspgrb_flush(const CXFSPGRB_POOL *pool, int fd, UINT32 *offset)
{
    UINT32 osize;/*write once size*/

    /*skip rsvd*/
    osize = sizeof(uint32_t);
    if(EC_FALSE == c_file_pad(fd, offset, osize, FILE_PAD_CHAR))
    {
        dbg_log(SEC_0204_CXFSPGRB, 0)(LOGSTDOUT, "error:cxfspgrb_flush: pad %ld bytes at offset %ld of fd %d failed\n", osize, (*offset), fd);
        return (EC_FALSE);
    }

    /*flush free_head*/
    osize = sizeof(uint16_t);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(CXFSPGRB_POOL_FREE_HEAD(pool))))
    {
        dbg_log(SEC_0204_CXFSPGRB, 0)(LOGSTDOUT, "error:cxfspgrb_flush: write CXFSPGRB_POOL_FREE_HEAD at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*flush node_num*/
    osize  = sizeof(uint16_t);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(CXFSPGRB_POOL_NODE_NUM(pool))))
    {
        dbg_log(SEC_0204_CXFSPGRB, 0)(LOGSTDOUT, "error:cxfspgrb_flush: write CXFSPGRB_POOL_NODE_NUM at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*flush rb_node table*/
    osize  = CXFSPGRB_POOL_NODE_NUM(pool) * sizeof(CXFSPGRB_NODE);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)CXFSPGRB_POOL_NODE_TBL(pool)))
    {
        dbg_log(SEC_0204_CXFSPGRB, 0)(LOGSTDOUT, "error:cxfspgrb_flush: write CXFSPGRB_POOL_NODE_TBL at offset %ld of fd %d failed where CXFSPGRB_POOL_NODE_NUM is %u\n",
                            (*offset), fd, CXFSPGRB_POOL_NODE_NUM(pool));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cxfspgrb_load(CXFSPGRB_POOL *pool, int fd, UINT32 *offset)
{
    UINT32 osize;/*read once size*/
    uint16_t node_num;

    /*skip rsvd*/
    (*offset) += sizeof(uint32_t);

    /*load free_head*/
    osize = sizeof(uint16_t);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(CXFSPGRB_POOL_FREE_HEAD(pool))))
    {
        dbg_log(SEC_0204_CXFSPGRB, 0)(LOGSTDOUT, "error:cxfspgrb_load: load CXFSPGRB_POOL_FREE_HEAD at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*load node_num*/
    osize  = sizeof(uint16_t);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(node_num)))
    {
        dbg_log(SEC_0204_CXFSPGRB, 0)(LOGSTDOUT, "error:cxfspgrb_load: load CXFSPGRB_POOL_NODE_NUM at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    CXFSPGRB_POOL_NODE_NUM(pool) = node_num;

    /*load rb_node table*/
    osize  = CXFSPGRB_POOL_NODE_NUM(pool) * sizeof(CXFSPGRB_NODE);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)CXFSPGRB_POOL_NODE_TBL(pool)))
    {
        dbg_log(SEC_0204_CXFSPGRB, 0)(LOGSTDOUT, "error:cxfspgrb_load: load CXFSPGRB_POOL_NODE_TBL at offset %ld of fd %d failed where CXFSPGRB_POOL_NODE_NUM is %u\n",
                            (*offset), fd, CXFSPGRB_POOL_NODE_NUM(pool));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

void cxfspgrb_tree_print(LOG *log, const CXFSPGRB_POOL *pool, const uint16_t root_pos)
{
    uint16_t node_pos;

    sys_log(log, "[root = %5d]\n", root_pos);
    for(node_pos = cxfspgrb_tree_first_node(pool, root_pos); CXFSPGRB_ERR_POS != node_pos; node_pos = cxfspgrb_tree_next_node(pool, node_pos))
    {
        cxfspgrb_node_print(log, pool, node_pos);
    }
    return;
}

/* ---- debug ---- */
EC_BOOL cxfspgrb_node_debug_cmp(const CXFSPGRB_NODE *node_1st, const CXFSPGRB_NODE *node_2nd)
{
    if(CXFSPGRB_NODE_USED_FLAG(node_1st) != CXFSPGRB_NODE_USED_FLAG(node_2nd))
    {
        dbg_log(SEC_0204_CXFSPGRB, 0)(LOGSTDERR, "error:cxfspgrb_node_debug_cmp: inconsistent CXFSPGRB_NODE_USED_FLAG: %u != %u\n",
                            CXFSPGRB_NODE_USED_FLAG(node_1st), CXFSPGRB_NODE_USED_FLAG(node_2nd));
        return (EC_FALSE);
    }

    if(CXFSPGRB_NODE_COLOR(node_1st) != CXFSPGRB_NODE_COLOR(node_2nd))
    {
        dbg_log(SEC_0204_CXFSPGRB, 0)(LOGSTDERR, "error:cxfspgrb_node_debug_cmp: inconsistent CXFSPGRB_NODE_COLOR: %u != %u\n",
                            CXFSPGRB_NODE_COLOR(node_1st), CXFSPGRB_NODE_COLOR(node_2nd));
        return (EC_FALSE);
    }

    if(CXFSPGRB_NODE_PARENT_POS(node_1st) != CXFSPGRB_NODE_PARENT_POS(node_2nd))
    {
        dbg_log(SEC_0204_CXFSPGRB, 0)(LOGSTDERR, "error:cxfspgrb_node_debug_cmp: inconsistent CXFSPGRB_NODE_PARENT_POS: %u != %u\n",
                            CXFSPGRB_NODE_PARENT_POS(node_1st), CXFSPGRB_NODE_PARENT_POS(node_2nd));
        return (EC_FALSE);
    }

    if(CXFSPGRB_NODE_RIGHT_POS(node_1st) != CXFSPGRB_NODE_RIGHT_POS(node_2nd))
    {
        dbg_log(SEC_0204_CXFSPGRB, 0)(LOGSTDERR, "error:cxfspgrb_node_debug_cmp: inconsistent CXFSPGRB_NODE_RIGHT_POS: %u != %u\n",
                            CXFSPGRB_NODE_RIGHT_POS(node_1st), CXFSPGRB_NODE_RIGHT_POS(node_2nd));
        return (EC_FALSE);
    }

    if(CXFSPGRB_NODE_LEFT_POS(node_1st) != CXFSPGRB_NODE_LEFT_POS(node_2nd))
    {
        dbg_log(SEC_0204_CXFSPGRB, 0)(LOGSTDERR, "error:cxfspgrb_node_debug_cmp: inconsistent CXFSPGRB_NODE_LEFT_POS: %u != %u\n",
                            CXFSPGRB_NODE_LEFT_POS(node_1st), CXFSPGRB_NODE_LEFT_POS(node_2nd));
        return (EC_FALSE);
    }

    if(CXFSPGRB_NODE_USED == CXFSPGRB_NODE_USED_FLAG(node_1st))
    {
        if(CXFSPGRB_NODE_DATA(node_1st) != CXFSPGRB_NODE_DATA(node_2nd))
        {
            dbg_log(SEC_0204_CXFSPGRB, 0)(LOGSTDERR, "error:cxfspgrb_node_debug_cmp: inconsistent CXFSPGRB_NODE_DATA: %u != %u\n",
                                CXFSPGRB_NODE_DATA(node_1st), CXFSPGRB_NODE_DATA(node_2nd));
            return (EC_FALSE);
        }
    }
    else
    {
        if(CXFSPGRB_NODE_NEXT_POS(node_1st) != CXFSPGRB_NODE_NEXT_POS(node_2nd))
        {
            dbg_log(SEC_0204_CXFSPGRB, 0)(LOGSTDERR, "error:cxfspgrb_node_debug_cmp: inconsistent CXFSPGRB_NODE_NEXT_POS: %u != %u\n",
                                CXFSPGRB_NODE_NEXT_POS(node_1st), CXFSPGRB_NODE_NEXT_POS(node_2nd));
            return (EC_FALSE);
        }
    }
    return (EC_TRUE);
}

EC_BOOL cxfspgrb_debug_cmp(const CXFSPGRB_POOL *pool_1st, const CXFSPGRB_POOL *pool_2nd)
{
    uint16_t  node_num;
    uint16_t  node_pos;

    if(CXFSPGRB_POOL_FREE_HEAD(pool_1st) != CXFSPGRB_POOL_FREE_HEAD(pool_2nd))
    {
        dbg_log(SEC_0204_CXFSPGRB, 0)(LOGSTDERR, "error:cxfspgrb_debug_cmp: inconsistent CXFSPGRB_POOL_FREE_HEAD: %u != %u\n",
                            CXFSPGRB_POOL_FREE_HEAD(pool_1st), CXFSPGRB_POOL_FREE_HEAD(pool_2nd));
        return (EC_FALSE);
    }

    if(CXFSPGRB_POOL_NODE_NUM(pool_1st) != CXFSPGRB_POOL_NODE_NUM(pool_2nd))
    {
        dbg_log(SEC_0204_CXFSPGRB, 0)(LOGSTDERR, "error:cxfspgrb_debug_cmp: inconsistent CXFSPGRB_POOL_NODE_NUM: %u != %u\n",
                            CXFSPGRB_POOL_NODE_NUM(pool_1st), CXFSPGRB_POOL_NODE_NUM(pool_2nd));
        return (EC_FALSE);
    }

    node_num = CXFSPGRB_POOL_NODE_NUM(pool_1st);
    for(node_pos = 0; node_pos < node_num; node_pos ++)
    {
        const CXFSPGRB_NODE *node_1st;
        const CXFSPGRB_NODE *node_2nd;

        node_1st = CXFSPGRB_POOL_NODE(pool_1st, node_pos);
        node_2nd = CXFSPGRB_POOL_NODE(pool_2nd, node_pos);

        if(EC_FALSE == cxfspgrb_node_debug_cmp(node_1st, node_2nd))
        {
            dbg_log(SEC_0204_CXFSPGRB, 0)(LOGSTDERR, "error:cxfspgrb_debug_cmp: inconsistent node at pos %u\n", node_pos);
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}


#ifdef __cplusplus
}
#endif/*__cplusplus*/
