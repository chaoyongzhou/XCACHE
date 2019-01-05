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

#include "cmcpgrb.h"

#if (SWITCH_ON == CMC_ASSERT_SWITCH)
#define CMCPGRB_ASSERT(condition)   ASSERT(condition)
#endif/*(SWITCH_ON == CMC_ASSERT_SWITCH)*/

#if (SWITCH_OFF == CMC_ASSERT_SWITCH)
#define CMCPGRB_ASSERT(condition)   do{}while(0)
#endif/*(SWITCH_OFF == CMC_ASSERT_SWITCH)*/

/*new a CMCPGRB_NODE and return its position*/
uint16_t cmcpgrb_node_new(CMCPGRB_POOL *pool)
{
    uint16_t node_pos_t;
    CMCPGRB_NODE *node;

    node_pos_t = CMCPGRB_POOL_FREE_HEAD(pool);
    if(CMCPGRB_ERR_POS == node_pos_t)
    {
        dbg_log(SEC_0096_CMCPGRB, 0)(LOGSTDOUT, "error:cmcpgrb_node_new: no free node in pool %p where free_head = %d, node_num = %d\n",
                           pool, CMCPGRB_POOL_FREE_HEAD(pool), CMCPGRB_POOL_NODE_NUM(pool));
        return (CMCPGRB_ERR_POS);
    }

    node = CMCPGRB_POOL_NODE(pool, node_pos_t);
    CMCPGRB_POOL_FREE_HEAD(pool) = CMCPGRB_NODE_NEXT_POS(node);
    CMCPGRB_NODE_USED_FLAG(node) = CMCPGRB_NODE_USED;

    return (node_pos_t);
}

/*free a CMCPGRB_NODE and return its position to the pool*/
void cmcpgrb_node_free(CMCPGRB_POOL *pool, const uint16_t node_pos)
{
    if(CMCPGRB_ERR_POS != node_pos)
    {
        CMCPGRB_NODE *node;

        node = CMCPGRB_POOL_NODE(pool, node_pos);
        CMCPGRB_NODE_USED_FLAG(node)  = CMCPGRB_NODE_NOT_USED;
        CMCPGRB_NODE_PARENT_POS(node) = CMCPGRB_ERR_POS;
        CMCPGRB_NODE_RIGHT_POS(node)  = CMCPGRB_ERR_POS;
        CMCPGRB_NODE_LEFT_POS(node)   = CMCPGRB_ERR_POS;
        CMCPGRB_NODE_NEXT_POS(node)   = CMCPGRB_POOL_FREE_HEAD(pool);
        CMCPGRB_NODE_COLOR(node)      = CMCPGRB_BLACK;

        CMCPGRB_POOL_FREE_HEAD(pool)  = node_pos;
    }
    return;
}

void cmcpgrb_node_init(CMCPGRB_POOL *pool, const uint16_t node_pos)
{
    CMCPGRB_NODE *node;

    node  = CMCPGRB_POOL_NODE(pool, node_pos);

    CMCPGRB_NODE_PARENT_POS(node) = CMCPGRB_ERR_POS;
    CMCPGRB_NODE_RIGHT_POS(node)  = CMCPGRB_ERR_POS;
    CMCPGRB_NODE_LEFT_POS(node)   = CMCPGRB_ERR_POS;
    CMCPGRB_NODE_USED_FLAG(node)  = CMCPGRB_NODE_NOT_USED;
    CMCPGRB_NODE_NEXT_POS(node)   = CMCPGRB_ERR_POS;
    CMCPGRB_NODE_COLOR(node)      = CMCPGRB_BLACK;

    return;
}

void cmcpgrb_node_clean(CMCPGRB_POOL *pool, const uint16_t node_pos)
{
    CMCPGRB_NODE *node;

    node  = CMCPGRB_POOL_NODE(pool, node_pos);

    CMCPGRB_NODE_PARENT_POS(node) = CMCPGRB_ERR_POS;
    CMCPGRB_NODE_RIGHT_POS(node)  = CMCPGRB_ERR_POS;
    CMCPGRB_NODE_LEFT_POS(node)   = CMCPGRB_ERR_POS;
    CMCPGRB_NODE_USED_FLAG(node)  = CMCPGRB_NODE_NOT_USED;
    CMCPGRB_NODE_NEXT_POS(node)   = CMCPGRB_ERR_POS;
    CMCPGRB_NODE_COLOR(node)      = CMCPGRB_BLACK;

    return;
}

void cmcpgrb_node_set_next(CMCPGRB_POOL *pool, const uint16_t node_pos, const uint16_t next_pos)
{
    CMCPGRB_NODE *node;

    node  = CMCPGRB_POOL_NODE(pool, node_pos);
    CMCPGRB_NODE_NEXT_POS(node) = next_pos;

    return;
}

void cmcpgrb_node_print(LOG *log, const CMCPGRB_POOL *pool, const uint16_t node_pos)
{
    const CMCPGRB_NODE *node;
    node  = CMCPGRB_POOL_NODE(pool, node_pos);

    sys_log(log, "%5d: parent = %5d, left = %5d, right = %5d, flg = %s, color = %s, %s = %5d\n",
                       node_pos,
                       CMCPGRB_NODE_PARENT_POS(node),
                       CMCPGRB_NODE_LEFT_POS(node),
                       CMCPGRB_NODE_RIGHT_POS(node),
                       CMCPGRB_NODE_IS_USED(node) ? "used" : "n.a.",
                       CMCPGRB_NODE_IS_USED(node) ? (CMCPGRB_NODE_IS_RED(node) ? "red  " : "black") : "#####",
                       CMCPGRB_NODE_IS_USED(node) ? "data" : "next",
                       CMCPGRB_NODE_IS_USED(node) ? CMCPGRB_NODE_DATA(node) : CMCPGRB_NODE_NEXT_POS(node)
                       );
    return;
}

void cmcpgrb_node_print_level(LOG *log, const CMCPGRB_POOL *pool, const uint16_t node_pos, const uint16_t level)
{
    const CMCPGRB_NODE *node;
    node  = CMCPGRB_POOL_NODE(pool, node_pos);

    c_ident_print(log, level);
    sys_print(log, "%5d: parent = %5d, left = %5d, right = %5d, flg = %s, color = %s, %s = %5d\n",
                       node_pos,
                       CMCPGRB_NODE_PARENT_POS(node),
                       CMCPGRB_NODE_LEFT_POS(node),
                       CMCPGRB_NODE_RIGHT_POS(node),
                       CMCPGRB_NODE_IS_USED(node) ? "used" : "NOT used",
                       CMCPGRB_NODE_IS_RED(node)  ? "red  " : "black",
                       CMCPGRB_NODE_IS_USED(node) ? "data" : "next",
                       CMCPGRB_NODE_IS_USED(node) ? CMCPGRB_NODE_DATA(node) : CMCPGRB_NODE_NEXT_POS(node)
                       );
    return;
}


STATIC_CAST static void __cmcpgrb_tree_rotate_left(CMCPGRB_POOL *pool, const uint16_t node_pos, uint16_t *root_pos)
{
    CMCPGRB_NODE *node;
    CMCPGRB_NODE *right;

    uint16_t  right_pos;

    node  = CMCPGRB_POOL_NODE(pool, node_pos);

    right_pos = CMCPGRB_NODE_RIGHT_POS(node);
    right = CMCPGRB_POOL_NODE(pool, right_pos);

    if(CMCPGRB_ERR_POS != (CMCPGRB_NODE_RIGHT_POS(node) = CMCPGRB_NODE_LEFT_POS(right)))
    {
        CMCPGRB_NODE *left;
        left = CMCPGRB_POOL_NODE(pool, CMCPGRB_NODE_LEFT_POS(right));
        CMCPGRB_NODE_PARENT_POS(left) = node_pos;
    }
    CMCPGRB_NODE_LEFT_POS(right) = node_pos;

    if(CMCPGRB_ERR_POS != (CMCPGRB_NODE_PARENT_POS(right) = CMCPGRB_NODE_PARENT_POS(node)))
    {
        CMCPGRB_NODE *parent;
        parent = CMCPGRB_POOL_NODE(pool, CMCPGRB_NODE_PARENT_POS(node));

        if (node_pos == CMCPGRB_NODE_LEFT_POS(parent))
        {
            CMCPGRB_NODE_LEFT_POS(parent) = right_pos;
        }
        else
        {
            CMCPGRB_NODE_RIGHT_POS(parent) = right_pos;
        }
    }
    else
    {
        (*root_pos) = right_pos;
    }
    CMCPGRB_NODE_PARENT_POS(node) = right_pos;
    return;
}

STATIC_CAST static void __cmcpgrb_tree_rotate_right(CMCPGRB_POOL *pool, const uint16_t node_pos, uint16_t *root_pos)
{
    CMCPGRB_NODE *node;
    CMCPGRB_NODE *left;
    uint16_t  left_pos;

    node  = CMCPGRB_POOL_NODE(pool, node_pos);

    left_pos = CMCPGRB_NODE_LEFT_POS(node);
    left = CMCPGRB_POOL_NODE(pool, left_pos);

    if (CMCPGRB_ERR_POS != (CMCPGRB_NODE_LEFT_POS(node) = CMCPGRB_NODE_RIGHT_POS(left)))
    {
        CMCPGRB_NODE *right;
        right = CMCPGRB_POOL_NODE(pool, CMCPGRB_NODE_RIGHT_POS(left));
        CMCPGRB_NODE_PARENT_POS(right) = node_pos;
    }
    CMCPGRB_NODE_RIGHT_POS(left) = node_pos;

    if (CMCPGRB_ERR_POS != (CMCPGRB_NODE_PARENT_POS(left) = CMCPGRB_NODE_PARENT_POS(node)))
    {
        CMCPGRB_NODE *parent;
        parent = CMCPGRB_POOL_NODE(pool, CMCPGRB_NODE_PARENT_POS(node));

        if (node_pos == CMCPGRB_NODE_RIGHT_POS(parent))
        {
            CMCPGRB_NODE_RIGHT_POS(parent) = left_pos;
        }
        else
        {
            CMCPGRB_NODE_LEFT_POS(parent) = left_pos;
        }
    }
    else
    {
        (*root_pos) = left_pos;
    }
    CMCPGRB_NODE_PARENT_POS(node) = left_pos;
    return;
}

STATIC_CAST static void __cmcpgrb_tree_insert_color(CMCPGRB_POOL *pool, const uint16_t node_pos, uint16_t *root_pos)
{
    CMCPGRB_NODE *node;
    CMCPGRB_NODE *root;
    CMCPGRB_NODE *parent;

    uint16_t  node_pos_t;

    node_pos_t = node_pos;
    node  = CMCPGRB_POOL_NODE(pool, node_pos_t);

    while (NULL_PTR != (parent = CMCPGRB_POOL_NODE(pool, CMCPGRB_NODE_PARENT_POS(node))) /*parent is valid*/
         && CMCPGRB_RED == CMCPGRB_NODE_COLOR(parent))
    {
        uint16_t  parent_pos;
        uint16_t  gparent_pos;
        CMCPGRB_NODE *gparent;

        parent_pos = CMCPGRB_NODE_PARENT_POS(node);

        gparent_pos = CMCPGRB_NODE_PARENT_POS(parent);
        CMCPGRB_ASSERT(CMCPGRB_ERR_POS != gparent_pos);
        gparent = CMCPGRB_POOL_NODE(pool, gparent_pos);

        if (parent_pos == CMCPGRB_NODE_LEFT_POS(gparent))
        {
            {
                CMCPGRB_NODE *uncle;
                if (NULL_PTR != (uncle = CMCPGRB_POOL_NODE(pool, CMCPGRB_NODE_RIGHT_POS(gparent))) /*uncle is valid*/
                   && CMCPGRB_RED == CMCPGRB_NODE_COLOR(uncle))
                {
                    CMCPGRB_NODE_COLOR(uncle)   = CMCPGRB_BLACK;
                    CMCPGRB_NODE_COLOR(parent)  = CMCPGRB_BLACK;
                    CMCPGRB_NODE_COLOR(gparent) = CMCPGRB_RED;

                    node = gparent;
                    node_pos_t = gparent_pos;
                    continue;
                }
            }

            if (CMCPGRB_NODE_RIGHT_POS(parent) == node_pos_t)
            {
                __cmcpgrb_tree_rotate_left(pool, parent_pos, root_pos);
                XCHG(CMCPGRB_NODE *, parent, node);
                XCHG(uint16_t, parent_pos, node_pos_t);
            }

            CMCPGRB_NODE_COLOR(parent)  = CMCPGRB_BLACK;
            CMCPGRB_NODE_COLOR(gparent) = CMCPGRB_RED;
            __cmcpgrb_tree_rotate_right(pool, gparent_pos, root_pos);
         }
         else
         {
            {
                CMCPGRB_NODE *uncle;
                if (NULL_PTR != (uncle = CMCPGRB_POOL_NODE(pool, CMCPGRB_NODE_LEFT_POS(gparent))) /*uncle is valid*/
                    && CMCPGRB_RED == CMCPGRB_NODE_COLOR(uncle))
                {
                    CMCPGRB_NODE_COLOR(uncle)   = CMCPGRB_BLACK;
                    CMCPGRB_NODE_COLOR(parent)  = CMCPGRB_BLACK;
                    CMCPGRB_NODE_COLOR(gparent) = CMCPGRB_RED;

                    node = gparent;
                    node_pos_t = gparent_pos;
                    continue;
                }
            }

            if (CMCPGRB_NODE_LEFT_POS(parent) == node_pos_t)
            {
                __cmcpgrb_tree_rotate_right(pool, parent_pos, root_pos);
                XCHG(CMCPGRB_NODE *, parent, node);
                XCHG(uint16_t, parent_pos, node_pos_t);
            }

            CMCPGRB_NODE_COLOR(parent)  = CMCPGRB_BLACK;
            CMCPGRB_NODE_COLOR(gparent) = CMCPGRB_RED;
            __cmcpgrb_tree_rotate_left(pool, gparent_pos, root_pos);
        }
    }

    root = CMCPGRB_POOL_NODE(pool, *root_pos);
    CMCPGRB_NODE_COLOR(root) = CMCPGRB_BLACK;
    return;
}

STATIC_CAST static void __cmcpgrb_tree_erase_color(CMCPGRB_POOL *pool, const uint16_t node_pos, const uint16_t parent_pos, uint16_t *root_pos)
{
    CMCPGRB_NODE *node;
    uint16_t  node_pos_t;
    uint16_t  parent_pos_t;

    node_pos_t   = node_pos;
    parent_pos_t = parent_pos;

    while ((NULL_PTR == (node = CMCPGRB_POOL_NODE(pool, node_pos_t)) || CMCPGRB_BLACK == CMCPGRB_NODE_COLOR(node)) && node_pos_t != (*root_pos))
    {
        CMCPGRB_NODE *parent;

        parent = CMCPGRB_POOL_NODE(pool, parent_pos_t);

        if (CMCPGRB_NODE_LEFT_POS(parent) == node_pos_t)
        {
            CMCPGRB_NODE *other;
            CMCPGRB_NODE *o_left;
            CMCPGRB_NODE *o_right;
            uint16_t  other_pos;

            other_pos = CMCPGRB_NODE_RIGHT_POS(parent);
            other = CMCPGRB_POOL_NODE(pool, other_pos);

            if (CMCPGRB_RED == CMCPGRB_NODE_COLOR(other))
            {
                CMCPGRB_NODE_COLOR(other)  = CMCPGRB_BLACK;
                CMCPGRB_NODE_COLOR(parent) = CMCPGRB_RED;

                __cmcpgrb_tree_rotate_left(pool, parent_pos_t, root_pos);

                other_pos = CMCPGRB_NODE_RIGHT_POS(parent);
                other = CMCPGRB_POOL_NODE(pool, other_pos);
            }

            o_left = CMCPGRB_POOL_NODE(pool, CMCPGRB_NODE_LEFT_POS(other));
            o_right = CMCPGRB_POOL_NODE(pool, CMCPGRB_NODE_RIGHT_POS(other));

            if((NULL_PTR == o_left || CMCPGRB_BLACK == CMCPGRB_NODE_COLOR(o_left))
            && (NULL_PTR == o_right || CMCPGRB_BLACK == CMCPGRB_NODE_COLOR(o_right)))
            {
                CMCPGRB_NODE_COLOR(other) = CMCPGRB_RED;

                node_pos_t = parent_pos_t;
                node = CMCPGRB_POOL_NODE(pool, node_pos_t);

                parent_pos_t = CMCPGRB_NODE_PARENT_POS(node);
                parent = CMCPGRB_POOL_NODE(pool, parent_pos_t);
            }
            else
            {
                if (NULL_PTR == o_right || CMCPGRB_BLACK == CMCPGRB_NODE_COLOR(o_right))
                {
                    if (NULL_PTR != o_left)
                    {
                        CMCPGRB_NODE_COLOR(o_left) = CMCPGRB_BLACK;
                    }
                    CMCPGRB_NODE_COLOR(other) = CMCPGRB_RED;

                    __cmcpgrb_tree_rotate_right(pool, other_pos, root_pos);

                    other_pos = CMCPGRB_NODE_RIGHT_POS(parent);
                    other = CMCPGRB_POOL_NODE(pool, other_pos);
                    /*note: other was changed here*/
                }

                CMCPGRB_NODE_COLOR(other) = CMCPGRB_NODE_COLOR(parent);
                CMCPGRB_NODE_COLOR(parent) = CMCPGRB_BLACK;

                /*due to other may be changed before, have to get o_right again here*/
                o_right = CMCPGRB_POOL_NODE(pool, CMCPGRB_NODE_RIGHT_POS(other));
                if (NULL_PTR != o_right)
                {
                    CMCPGRB_NODE_COLOR(o_right) = CMCPGRB_BLACK;
                }

                __cmcpgrb_tree_rotate_left(pool, parent_pos_t, root_pos);
                node_pos_t = (*root_pos);
                break;
            }
        }
        else
        {
            CMCPGRB_NODE *other;
            CMCPGRB_NODE *o_left;
            CMCPGRB_NODE *o_right;
            uint16_t  other_pos;

            other_pos = CMCPGRB_NODE_LEFT_POS(parent);
            other = CMCPGRB_POOL_NODE(pool, other_pos);

            if (CMCPGRB_RED == CMCPGRB_NODE_COLOR(other))
            {
                CMCPGRB_NODE_COLOR(other) = CMCPGRB_BLACK;
                CMCPGRB_NODE_COLOR(parent) = CMCPGRB_RED;

                __cmcpgrb_tree_rotate_right(pool, parent_pos_t, root_pos);

                other_pos = CMCPGRB_NODE_LEFT_POS(parent);
                other = CMCPGRB_POOL_NODE(pool, other_pos);
            }

            o_left = CMCPGRB_POOL_NODE(pool, CMCPGRB_NODE_LEFT_POS(other));
            o_right = CMCPGRB_POOL_NODE(pool, CMCPGRB_NODE_RIGHT_POS(other));

            if ((NULL_PTR == o_left  || CMCPGRB_BLACK == CMCPGRB_NODE_COLOR(o_left))
             && (NULL_PTR == o_right || CMCPGRB_BLACK == CMCPGRB_NODE_COLOR(o_right)))
            {
                CMCPGRB_NODE_COLOR(other) = CMCPGRB_RED;

                node_pos_t = parent_pos_t;
                node = CMCPGRB_POOL_NODE(pool, node_pos_t);

                parent_pos_t = CMCPGRB_NODE_PARENT_POS(node);
                parent = CMCPGRB_POOL_NODE(pool, parent_pos_t);
            }
            else
            {
                if (NULL_PTR == o_left  || CMCPGRB_BLACK == CMCPGRB_NODE_COLOR(o_left))
                {
                    if (NULL_PTR != o_right)
                    {
                        CMCPGRB_NODE_COLOR(o_right) = CMCPGRB_BLACK;
                    }

                    CMCPGRB_NODE_COLOR(other) = CMCPGRB_RED;

                    __cmcpgrb_tree_rotate_left(pool, other_pos, root_pos);

                    other_pos = CMCPGRB_NODE_LEFT_POS(parent);
                    other = CMCPGRB_POOL_NODE(pool, other_pos);
                    /*note: other was changed here*/
                }

                CMCPGRB_NODE_COLOR(other) = CMCPGRB_NODE_COLOR(parent);
                CMCPGRB_NODE_COLOR(parent) = CMCPGRB_BLACK;

                /*due to other may be changed before, have to get o_left again here*/
                o_left = CMCPGRB_POOL_NODE(pool, CMCPGRB_NODE_LEFT_POS(other));
                if (NULL_PTR != o_left)
                {
                    CMCPGRB_NODE_COLOR(o_left) = CMCPGRB_BLACK;
                }
                __cmcpgrb_tree_rotate_right(pool, parent_pos_t, root_pos);
                node_pos_t = (*root_pos);
                break;
            }
        }
    }

    node = CMCPGRB_POOL_NODE(pool, node_pos_t);
    if (NULL_PTR != node)
    {
        CMCPGRB_NODE_COLOR(node) = CMCPGRB_BLACK;
    }
    return;
}

STATIC_CAST static void __cmcpgrb_tree_erase(CMCPGRB_POOL *pool, const uint16_t node_pos, uint16_t *root_pos)
{
    CMCPGRB_NODE *node;

    uint16_t node_pos_t;
    uint16_t child_pos;
    uint16_t parent_pos;
    uint16_t color;

    node_pos_t = node_pos;
    node = CMCPGRB_POOL_NODE(pool, node_pos_t);

    CMCPGRB_ASSERT(NULL_PTR != node);
    CMCPGRB_ASSERT(CMCPGRB_NODE_IS_USED(node));

    if (CMCPGRB_ERR_POS == CMCPGRB_NODE_LEFT_POS(node))
    {
        child_pos = CMCPGRB_NODE_RIGHT_POS(node);
    }
    else if (CMCPGRB_ERR_POS == CMCPGRB_NODE_RIGHT_POS(node))
    {
        child_pos = CMCPGRB_NODE_LEFT_POS(node);
    }
    else
    {
        CMCPGRB_NODE *old;

        uint16_t old_pos;
        uint16_t left_pos;

        old_pos = node_pos_t;

        node_pos_t = CMCPGRB_NODE_RIGHT_POS(node);
        node = CMCPGRB_POOL_NODE(pool, node_pos_t);

        while (CMCPGRB_ERR_POS != (left_pos = CMCPGRB_NODE_LEFT_POS(node)))
        {
            node_pos_t = left_pos;
            node = CMCPGRB_POOL_NODE(pool, node_pos_t);

        }

        child_pos  = CMCPGRB_NODE_RIGHT_POS(node);
        parent_pos = CMCPGRB_NODE_PARENT_POS(node);
        color      = CMCPGRB_NODE_COLOR(node);

        if (CMCPGRB_ERR_POS != child_pos)
        {
            CMCPGRB_NODE *child;
            child = CMCPGRB_POOL_NODE(pool, child_pos);
            CMCPGRB_NODE_PARENT_POS(child) = parent_pos;
        }

        if (CMCPGRB_ERR_POS != parent_pos)
        {
            CMCPGRB_NODE *parent;

            parent = CMCPGRB_POOL_NODE(pool, parent_pos);
            if (CMCPGRB_NODE_LEFT_POS(parent) == node_pos_t)
            {
                CMCPGRB_NODE_LEFT_POS(parent) = child_pos;
            }
            else
            {
                CMCPGRB_NODE_RIGHT_POS(parent) = child_pos;
            }
        }
        else
        {
            (*root_pos) = child_pos;
        }

        if (CMCPGRB_NODE_PARENT_POS(node) == old_pos)
        {
            parent_pos = node_pos_t;
        }

        //node = CMCPGRB_POOL_NODE(pool, node_pos_t);
        old  = CMCPGRB_POOL_NODE(pool, old_pos);

        CMCPGRB_NODE_PARENT_POS(node) = CMCPGRB_NODE_PARENT_POS(old);
        CMCPGRB_NODE_COLOR(node)      = CMCPGRB_NODE_COLOR(old);
        CMCPGRB_NODE_RIGHT_POS(node)  = CMCPGRB_NODE_RIGHT_POS(old);
        CMCPGRB_NODE_LEFT_POS(node)   = CMCPGRB_NODE_LEFT_POS(old);

        if (CMCPGRB_ERR_POS != CMCPGRB_NODE_PARENT_POS(old))
        {
            CMCPGRB_NODE *old_parent;
            old_parent = CMCPGRB_POOL_NODE(pool, CMCPGRB_NODE_PARENT_POS(old));

            if (CMCPGRB_NODE_LEFT_POS(old_parent) == old_pos)
            {
                CMCPGRB_NODE_LEFT_POS(old_parent) = node_pos_t;
            }
            else
            {
                CMCPGRB_NODE_RIGHT_POS(old_parent) = node_pos_t;
            }
        }
        else
        {
            (*root_pos) = node_pos_t;
        }

        {
            CMCPGRB_NODE *old_left;

            old_left = CMCPGRB_POOL_NODE(pool, CMCPGRB_NODE_LEFT_POS(old));
            CMCPGRB_NODE_PARENT_POS(old_left) = node_pos_t;
        }

        if (CMCPGRB_ERR_POS != CMCPGRB_NODE_RIGHT_POS(old))
        {
            CMCPGRB_NODE *old_right;
            old_right = CMCPGRB_POOL_NODE(pool, CMCPGRB_NODE_RIGHT_POS(old));
            CMCPGRB_NODE_PARENT_POS(old_right) = node_pos_t;
        }
        goto color;
    }

    parent_pos = CMCPGRB_NODE_PARENT_POS(node);
    color = CMCPGRB_NODE_COLOR(node);

    if (CMCPGRB_ERR_POS != child_pos)
    {
        CMCPGRB_NODE *child;
        child = CMCPGRB_POOL_NODE(pool, child_pos);
        CMCPGRB_NODE_PARENT_POS(child) = parent_pos;
    }

    if (CMCPGRB_ERR_POS != parent_pos)
    {
        CMCPGRB_NODE *parent;

        parent = CMCPGRB_POOL_NODE(pool, parent_pos);
        if (CMCPGRB_NODE_LEFT_POS(parent) == node_pos_t)
        {
            CMCPGRB_NODE_LEFT_POS(parent) = child_pos;
        }
        else
        {
            CMCPGRB_NODE_RIGHT_POS(parent) = child_pos;
        }
    }
    else
    {
        (*root_pos) = child_pos;
    }

 color:
    if (CMCPGRB_BLACK == color)
    {
        __cmcpgrb_tree_erase_color(pool, child_pos, parent_pos, root_pos);
    }
    return;
}

EC_BOOL cmcpgrb_tree_is_empty(const CMCPGRB_POOL *pool, const uint16_t root_pos)
{
    if (CMCPGRB_ERR_POS == root_pos)
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}


STATIC_CAST static uint16_t __cmcpgrb_tree_node_num(const CMCPGRB_POOL *pool, const uint16_t node_pos)
{
    const CMCPGRB_NODE *node;

    if(CMCPGRB_ERR_POS == node_pos)
    {
        return ((uint16_t)0);
    }

    node = CMCPGRB_POOL_NODE(pool, node_pos);

    return (uint16_t)(1 + __cmcpgrb_tree_node_num(pool, CMCPGRB_NODE_LEFT_POS(node)) + __cmcpgrb_tree_node_num(pool, CMCPGRB_NODE_RIGHT_POS(node)));
}

uint16_t cmcpgrb_tree_node_num(const CMCPGRB_POOL *pool, const uint16_t root_pos)
{
    return __cmcpgrb_tree_node_num(pool, root_pos);
}

/*
 * This function returns the first node_pos (in sort order) of the tree.
 */
uint16_t cmcpgrb_tree_first_node(const CMCPGRB_POOL *pool, const uint16_t root_pos)
{
    uint16_t  node_pos;
    const CMCPGRB_NODE *node;

    node_pos = root_pos;
    if (CMCPGRB_ERR_POS == node_pos)
    {
        return (CMCPGRB_ERR_POS);
    }

    node = CMCPGRB_POOL_NODE(pool, node_pos);

    while (CMCPGRB_ERR_POS != CMCPGRB_NODE_LEFT_POS(node))
    {
        node_pos = CMCPGRB_NODE_LEFT_POS(node);
        node = CMCPGRB_POOL_NODE(pool, node_pos);
    }
    return (node_pos);
}

uint16_t cmcpgrb_tree_last_node(const CMCPGRB_POOL *pool, const uint16_t root_pos)
{
    uint16_t  node_pos;
    const CMCPGRB_NODE *node;

    node_pos = root_pos;
    if (CMCPGRB_ERR_POS == node_pos)
    {
        return (CMCPGRB_ERR_POS);
    }

    node = CMCPGRB_POOL_NODE(pool, node_pos);

    while (CMCPGRB_ERR_POS != CMCPGRB_NODE_RIGHT_POS(node))
    {
        node_pos = CMCPGRB_NODE_RIGHT_POS(node);
        node = CMCPGRB_POOL_NODE(pool, node_pos);
    }

    return (node_pos);
}

uint16_t cmcpgrb_tree_next_node(const CMCPGRB_POOL *pool, const uint16_t node_pos)
{
    uint16_t node_pos_t;
    const CMCPGRB_NODE *node;
    const CMCPGRB_NODE *parent;

    node_pos_t = node_pos;
    node = CMCPGRB_POOL_NODE(pool, node_pos_t);
    /* If we have a right-hand child, go down and then left as far
       as we can. */
    if (CMCPGRB_ERR_POS != CMCPGRB_NODE_RIGHT_POS(node))
    {
        node_pos_t = CMCPGRB_NODE_RIGHT_POS(node);
        node = CMCPGRB_POOL_NODE(pool, node_pos_t);
        while (CMCPGRB_ERR_POS != CMCPGRB_NODE_LEFT_POS(node))
        {
            node_pos_t = CMCPGRB_NODE_LEFT_POS(node);
            node = CMCPGRB_POOL_NODE(pool, node_pos_t);
        }
        return (node_pos_t);
    }

    /* No right-hand children.  Everything down and left is
       smaller than us, so any 'next' node_pos_t must be in the general
       direction of our parent. Go up the tree; any time the
       ancestor is a right-hand child of its parent, keep going
       up. First time it's a left-hand child of its parent, said
       parent is our 'next' node_pos_t. */
    while (NULL_PTR != (parent = CMCPGRB_POOL_NODE(pool, CMCPGRB_NODE_PARENT_POS(node))) && node_pos_t == CMCPGRB_NODE_RIGHT_POS(parent))
    {
        node_pos_t = CMCPGRB_NODE_PARENT_POS(node);
        node = parent;
    }

    return (CMCPGRB_NODE_PARENT_POS(node));
}

uint16_t cmcpgrb_tree_prev_node(const CMCPGRB_POOL *pool, const uint16_t node_pos)
{
    uint16_t node_pos_t;
    const CMCPGRB_NODE *node;
    const CMCPGRB_NODE *parent;

    node_pos_t = node_pos;
    node = CMCPGRB_POOL_NODE(pool, node_pos_t);

    /* If we have a left-hand child, go down and then right as far
       as we can. */
    if (CMCPGRB_ERR_POS != CMCPGRB_NODE_LEFT_POS(node))
    {
        node_pos_t = CMCPGRB_NODE_LEFT_POS(node);
        node = CMCPGRB_POOL_NODE(pool, node_pos_t);
        while (CMCPGRB_ERR_POS != CMCPGRB_NODE_RIGHT_POS(node))
        {
            node_pos_t = CMCPGRB_NODE_RIGHT_POS(node);
            node = CMCPGRB_POOL_NODE(pool, node_pos_t);
        }
        return (node_pos_t);
    }

    /* No left-hand children. Go up till we find an ancestor which
       is a right-hand child of its parent */
    while (NULL_PTR != (parent = CMCPGRB_POOL_NODE(pool, CMCPGRB_NODE_PARENT_POS(node))) && node_pos_t == CMCPGRB_NODE_LEFT_POS(parent))
    {
        node_pos_t = CMCPGRB_NODE_PARENT_POS(node);
        node = parent;
    }

    return (CMCPGRB_NODE_PARENT_POS(node));
}

/*return the searched pos*/
uint16_t cmcpgrb_tree_search_data(CMCPGRB_POOL *pool, const uint16_t root_pos, uint16_t data)
{
    uint16_t node_pos;

    node_pos = root_pos;

    while (CMCPGRB_ERR_POS != node_pos)
    {
        CMCPGRB_NODE *node;

        node = CMCPGRB_POOL_NODE(pool, node_pos);

        if (data < CMCPGRB_NODE_DATA(node))
        {
            node_pos = CMCPGRB_NODE_LEFT_POS(node);
        }
        else if (data > CMCPGRB_NODE_DATA(node))
        {
            node_pos = CMCPGRB_NODE_RIGHT_POS(node);
        }
        else
        {
            return (node_pos);
        }
    }

    return (CMCPGRB_ERR_POS);
}


uint16_t cmcpgrb_tree_insert_data(CMCPGRB_POOL *pool, uint16_t *root_pos, const uint16_t data)
{
    uint16_t  node_pos_t;
    uint16_t  new_pos_t;
    uint16_t  parent_pos_t;
    uint16_t  flag; /*0: on left subtree, 1: on right subtree*/

    node_pos_t   = (*root_pos);
    parent_pos_t = CMCPGRB_ERR_POS;
    flag         = ~(uint16_t)0;

    while (CMCPGRB_ERR_POS != node_pos_t)
    {
        CMCPGRB_NODE *node;

        node = CMCPGRB_POOL_NODE(pool, node_pos_t);

        parent_pos_t = node_pos_t;

        if (data < CMCPGRB_NODE_DATA(node))
        {
            node_pos_t = CMCPGRB_NODE_LEFT_POS(node);
            flag = 0;
        }
        else if (data > CMCPGRB_NODE_DATA(node))
        {
            node_pos_t = CMCPGRB_NODE_RIGHT_POS(node);
            flag = 1;
        }
        else
        {
            return (node_pos_t);
        }
    }

    /*not found data in the rbtree*/
    new_pos_t = cmcpgrb_node_new(pool);
    if(CMCPGRB_ERR_POS == new_pos_t)
    {
        dbg_log(SEC_0096_CMCPGRB, 0)(LOGSTDOUT, "error:cmcpgrb_tree_insert_data: new cmcpgrb_node from pool %p failed\n", pool);
        return (CMCPGRB_ERR_POS);
    }
    else
    {
        CMCPGRB_NODE *node;

        node  = CMCPGRB_POOL_NODE(pool, new_pos_t);
        CMCPGRB_NODE_DATA(node) = data;

        CMCPGRB_NODE_PARENT_POS(node) = parent_pos_t;
        CMCPGRB_NODE_COLOR(node)      = CMCPGRB_RED;
        CMCPGRB_NODE_LEFT_POS(node)   = CMCPGRB_ERR_POS;
        CMCPGRB_NODE_RIGHT_POS(node)  = CMCPGRB_ERR_POS;

        if(CMCPGRB_ERR_POS == (*root_pos))
        {
            (*root_pos) = new_pos_t;
        }
        else
        {
            CMCPGRB_NODE *parent;
            parent  = CMCPGRB_POOL_NODE(pool, parent_pos_t);

            if(0 == flag)/*on left subtree*/
            {
                CMCPGRB_NODE_LEFT_POS(parent) = new_pos_t;
            }
            else
            {
                CMCPGRB_NODE_RIGHT_POS(parent) = new_pos_t;
            }
        }
        __cmcpgrb_tree_insert_color(pool, new_pos_t, root_pos);
    }

    return (new_pos_t);
}

EC_BOOL cmcpgrb_tree_delete_data(CMCPGRB_POOL *pool, uint16_t *root_pos, const uint16_t data)
{
    uint16_t node_pos;

    node_pos = cmcpgrb_tree_search_data(pool, *root_pos, data);
    if(CMCPGRB_ERR_POS == node_pos)
    {
        return (EC_FALSE);
    }

    __cmcpgrb_tree_erase(pool, node_pos, root_pos);
    cmcpgrb_node_free(pool, node_pos);
    return (EC_TRUE);
}

/*postorder: left -> right -> root*/
STATIC_CAST static void __cmcpgrb_tree_free(CMCPGRB_POOL *pool, const uint16_t node_pos)
{
    CMCPGRB_NODE *node;

    if(CMCPGRB_ERR_POS == node_pos)
    {
        return;
    }

    node  = CMCPGRB_POOL_NODE(pool, node_pos);
    if(CMCPGRB_ERR_POS != CMCPGRB_NODE_LEFT_POS(node))
    {
        __cmcpgrb_tree_free(pool, CMCPGRB_NODE_LEFT_POS(node));
    }

    if(CMCPGRB_ERR_POS != CMCPGRB_NODE_RIGHT_POS(node))
    {
        __cmcpgrb_tree_free(pool, CMCPGRB_NODE_RIGHT_POS(node));
    }

    cmcpgrb_node_free(pool, node_pos);

    return;
}
void cmcpgrb_tree_free(CMCPGRB_POOL *pool, const uint16_t root_pos)
{
    __cmcpgrb_tree_free(pool, root_pos);
    return;
}

EC_BOOL cmcpgrb_pool_init(CMCPGRB_POOL *pool, const uint16_t node_num)
{
    uint16_t node_pos;

    CMCPGRB_ASSERT(CMCPGRB_POOL_MAX_SIZE >= node_num);

    CMCPGRB_POOL_NODE_NUM(pool) = node_num;

    for(node_pos = 0; node_pos < node_num; node_pos ++)
    {
        cmcpgrb_node_init(pool, node_pos);
        cmcpgrb_node_set_next(pool, node_pos, node_pos + 1);
    }
    cmcpgrb_node_set_next(pool, node_num - 1, CMCPGRB_ERR_POS);

    CMCPGRB_POOL_FREE_HEAD(pool) = 0;/*the free nodes head*/
    return (EC_TRUE);
}

void cmcpgrb_pool_clean(CMCPGRB_POOL *pool)
{
    CMCPGRB_POOL_NODE_NUM(pool)  = 0;
    CMCPGRB_POOL_FREE_HEAD(pool) = CMCPGRB_ERR_POS;
    return;
}

/*clear without any space mallocation!*/
void cmcpgrb_pool_clear(CMCPGRB_POOL *pool)
{
    CMCPGRB_POOL_NODE_NUM(pool)  = 0;
    CMCPGRB_POOL_FREE_HEAD(pool) = CMCPGRB_ERR_POS;
    return;
}

void cmcpgrb_pool_print(LOG *log, const CMCPGRB_POOL *pool)
{
    uint16_t node_pos;
    uint16_t node_num;

    node_num = CMCPGRB_POOL_NODE_NUM(pool);

    sys_log(log, "pool %lx, node_num %u, free_head %u\n",
                 pool,
                 node_num,
                 CMCPGRB_POOL_FREE_HEAD(pool));

    for(node_pos = 0; node_pos < node_num; node_pos ++)
    {
        cmcpgrb_node_print(log, pool, node_pos);
    }

    return;
}

/*visit the root node first: root -> left -> right*/
void cmcpgrb_preorder_print(LOG *log, const CMCPGRB_POOL *pool, const uint16_t node_pos)
{
    const CMCPGRB_NODE *node;

    if(CMCPGRB_ERR_POS == node_pos)
    {
        return;
    }

    node  = CMCPGRB_POOL_NODE(pool, node_pos);
    cmcpgrb_node_print(log, pool, node_pos);

    if(CMCPGRB_ERR_POS != CMCPGRB_NODE_LEFT_POS(node))
    {
        cmcpgrb_preorder_print(log, pool, CMCPGRB_NODE_LEFT_POS(node));
    }

    if(CMCPGRB_ERR_POS != CMCPGRB_NODE_RIGHT_POS(node))
    {
        cmcpgrb_preorder_print(log, pool, CMCPGRB_NODE_RIGHT_POS(node));
    }

    return;
}

/*visit the left subtree, then the root node: left -> root -> right*/
void cmcpgrb_inorder_print(LOG *log, const CMCPGRB_POOL *pool, const uint16_t node_pos)
{
    const CMCPGRB_NODE *node;

    if(CMCPGRB_ERR_POS == node_pos)
    {
        return;
    }

    node  = CMCPGRB_POOL_NODE(pool, node_pos);
    if(CMCPGRB_ERR_POS != CMCPGRB_NODE_LEFT_POS(node))
    {
        cmcpgrb_inorder_print(log, pool, CMCPGRB_NODE_LEFT_POS(node));
    }

    cmcpgrb_node_print(log, pool, node_pos);

    if(CMCPGRB_ERR_POS != CMCPGRB_NODE_RIGHT_POS(node))
    {
        cmcpgrb_inorder_print(log, pool, CMCPGRB_NODE_RIGHT_POS(node));
    }

    return;
}

/*visit the root node last: left -> right -> root*/
void cmcpgrb_postorder_print(LOG *log, const CMCPGRB_POOL *pool, const uint16_t node_pos)
{
    const CMCPGRB_NODE *node;

    if(CMCPGRB_ERR_POS == node_pos)
    {
        return;
    }

    node  = CMCPGRB_POOL_NODE(pool, node_pos);
    if(CMCPGRB_ERR_POS != CMCPGRB_NODE_LEFT_POS(node))
    {
        cmcpgrb_postorder_print(log, pool, CMCPGRB_NODE_LEFT_POS(node));
    }

    if(CMCPGRB_ERR_POS != CMCPGRB_NODE_RIGHT_POS(node))
    {
        cmcpgrb_postorder_print(log, pool, CMCPGRB_NODE_RIGHT_POS(node));
    }

    cmcpgrb_node_print(log, pool, node_pos);

    return;
}


/*visit the root node first: root -> left -> right*/
void cmcpgrb_preorder_print_level(LOG *log, const CMCPGRB_POOL *pool, const uint16_t node_pos, const uint16_t level)
{
    const CMCPGRB_NODE *node;

    if(CMCPGRB_ERR_POS == node_pos)
    {
        return;
    }

    node  = CMCPGRB_POOL_NODE(pool, node_pos);
    cmcpgrb_node_print_level(log, pool, node_pos, level);

    if(CMCPGRB_ERR_POS != CMCPGRB_NODE_LEFT_POS(node))
    {
        cmcpgrb_preorder_print_level(log, pool, CMCPGRB_NODE_LEFT_POS(node), level + 1);
    }

    if(CMCPGRB_ERR_POS != CMCPGRB_NODE_RIGHT_POS(node))
    {
        cmcpgrb_preorder_print_level(log, pool, CMCPGRB_NODE_RIGHT_POS(node), level + 1);
    }

    return;
}

void cmcpgrb_tree_print(LOG *log, const CMCPGRB_POOL *pool, const uint16_t root_pos)
{
    uint16_t node_pos;

    sys_log(log, "[root = %5d]\n", root_pos);
    for(node_pos = cmcpgrb_tree_first_node(pool, root_pos); CMCPGRB_ERR_POS != node_pos; node_pos = cmcpgrb_tree_next_node(pool, node_pos))
    {
        cmcpgrb_node_print(log, pool, node_pos);
    }
    return;
}

/* ---- debug ---- */
EC_BOOL cmcpgrb_node_debug_cmp(const CMCPGRB_NODE *node_1st, const CMCPGRB_NODE *node_2nd)
{
    if(CMCPGRB_NODE_USED_FLAG(node_1st) != CMCPGRB_NODE_USED_FLAG(node_2nd))
    {
        dbg_log(SEC_0096_CMCPGRB, 0)(LOGSTDOUT, "error:cmcpgrb_node_debug_cmp: inconsistent CMCPGRB_NODE_USED_FLAG: %u != %u\n",
                            CMCPGRB_NODE_USED_FLAG(node_1st), CMCPGRB_NODE_USED_FLAG(node_2nd));
        return (EC_FALSE);
    }

    if(CMCPGRB_NODE_COLOR(node_1st) != CMCPGRB_NODE_COLOR(node_2nd))
    {
        dbg_log(SEC_0096_CMCPGRB, 0)(LOGSTDOUT, "error:cmcpgrb_node_debug_cmp: inconsistent CMCPGRB_NODE_COLOR: %u != %u\n",
                            CMCPGRB_NODE_COLOR(node_1st), CMCPGRB_NODE_COLOR(node_2nd));
        return (EC_FALSE);
    }

    if(CMCPGRB_NODE_PARENT_POS(node_1st) != CMCPGRB_NODE_PARENT_POS(node_2nd))
    {
        dbg_log(SEC_0096_CMCPGRB, 0)(LOGSTDOUT, "error:cmcpgrb_node_debug_cmp: inconsistent CMCPGRB_NODE_PARENT_POS: %u != %u\n",
                            CMCPGRB_NODE_PARENT_POS(node_1st), CMCPGRB_NODE_PARENT_POS(node_2nd));
        return (EC_FALSE);
    }

    if(CMCPGRB_NODE_RIGHT_POS(node_1st) != CMCPGRB_NODE_RIGHT_POS(node_2nd))
    {
        dbg_log(SEC_0096_CMCPGRB, 0)(LOGSTDOUT, "error:cmcpgrb_node_debug_cmp: inconsistent CMCPGRB_NODE_RIGHT_POS: %u != %u\n",
                            CMCPGRB_NODE_RIGHT_POS(node_1st), CMCPGRB_NODE_RIGHT_POS(node_2nd));
        return (EC_FALSE);
    }

    if(CMCPGRB_NODE_LEFT_POS(node_1st) != CMCPGRB_NODE_LEFT_POS(node_2nd))
    {
        dbg_log(SEC_0096_CMCPGRB, 0)(LOGSTDOUT, "error:cmcpgrb_node_debug_cmp: inconsistent CMCPGRB_NODE_LEFT_POS: %u != %u\n",
                            CMCPGRB_NODE_LEFT_POS(node_1st), CMCPGRB_NODE_LEFT_POS(node_2nd));
        return (EC_FALSE);
    }

    if(CMCPGRB_NODE_USED == CMCPGRB_NODE_USED_FLAG(node_1st))
    {
        if(CMCPGRB_NODE_DATA(node_1st) != CMCPGRB_NODE_DATA(node_2nd))
        {
            dbg_log(SEC_0096_CMCPGRB, 0)(LOGSTDOUT, "error:cmcpgrb_node_debug_cmp: inconsistent CMCPGRB_NODE_DATA: %u != %u\n",
                                CMCPGRB_NODE_DATA(node_1st), CMCPGRB_NODE_DATA(node_2nd));
            return (EC_FALSE);
        }
    }
    else
    {
        if(CMCPGRB_NODE_NEXT_POS(node_1st) != CMCPGRB_NODE_NEXT_POS(node_2nd))
        {
            dbg_log(SEC_0096_CMCPGRB, 0)(LOGSTDOUT, "error:cmcpgrb_node_debug_cmp: inconsistent CMCPGRB_NODE_NEXT_POS: %u != %u\n",
                                CMCPGRB_NODE_NEXT_POS(node_1st), CMCPGRB_NODE_NEXT_POS(node_2nd));
            return (EC_FALSE);
        }
    }
    return (EC_TRUE);
}

EC_BOOL cmcpgrb_debug_cmp(const CMCPGRB_POOL *pool_1st, const CMCPGRB_POOL *pool_2nd)
{
    uint16_t  node_num;
    uint16_t  node_pos;

    if(CMCPGRB_POOL_FREE_HEAD(pool_1st) != CMCPGRB_POOL_FREE_HEAD(pool_2nd))
    {
        dbg_log(SEC_0096_CMCPGRB, 0)(LOGSTDOUT, "error:cmcpgrb_debug_cmp: inconsistent CMCPGRB_POOL_FREE_HEAD: %u != %u\n",
                            CMCPGRB_POOL_FREE_HEAD(pool_1st), CMCPGRB_POOL_FREE_HEAD(pool_2nd));
        return (EC_FALSE);
    }

    if(CMCPGRB_POOL_NODE_NUM(pool_1st) != CMCPGRB_POOL_NODE_NUM(pool_2nd))
    {
        dbg_log(SEC_0096_CMCPGRB, 0)(LOGSTDOUT, "error:cmcpgrb_debug_cmp: inconsistent CMCPGRB_POOL_NODE_NUM: %u != %u\n",
                            CMCPGRB_POOL_NODE_NUM(pool_1st), CMCPGRB_POOL_NODE_NUM(pool_2nd));
        return (EC_FALSE);
    }

    node_num = CMCPGRB_POOL_NODE_NUM(pool_1st);
    for(node_pos = 0; node_pos < node_num; node_pos ++)
    {
        const CMCPGRB_NODE *node_1st;
        const CMCPGRB_NODE *node_2nd;

        node_1st = CMCPGRB_POOL_NODE(pool_1st, node_pos);
        node_2nd = CMCPGRB_POOL_NODE(pool_2nd, node_pos);

        if(EC_FALSE == cmcpgrb_node_debug_cmp(node_1st, node_2nd))
        {
            dbg_log(SEC_0096_CMCPGRB, 0)(LOGSTDOUT, "error:cmcpgrb_debug_cmp: inconsistent node at pos %u\n", node_pos);
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}


#ifdef __cplusplus
}
#endif/*__cplusplus*/
