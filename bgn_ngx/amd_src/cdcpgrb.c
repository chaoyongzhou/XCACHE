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

#include "cdcpgrb.h"


/*new a CDCPGRB_NODE and return its position*/
uint16_t cdcpgrb_node_new(CDCPGRB_POOL *pool)
{
    uint16_t node_pos_t;
    CDCPGRB_NODE *node;

    node_pos_t = CDCPGRB_POOL_FREE_HEAD(pool);
    if(CDCPGRB_ERR_POS == node_pos_t)
    {
        dbg_log(SEC_0185_CDCPGRB, 0)(LOGSTDOUT, "error:cdcpgrb_node_new: no free node in pool %p where free_head = %d, node_num = %d\n",
                           pool, CDCPGRB_POOL_FREE_HEAD(pool), CDCPGRB_POOL_NODE_NUM(pool));
        return (CDCPGRB_ERR_POS);
    }

    node = CDCPGRB_POOL_NODE(pool, node_pos_t);
    CDCPGRB_POOL_FREE_HEAD(pool) = CDCPGRB_NODE_NEXT_POS(node);
    CDCPGRB_NODE_USED_FLAG(node) = CDCPGRB_NODE_USED;

    return (node_pos_t);
}

/*free a CDCPGRB_NODE and return its position to the pool*/
void cdcpgrb_node_free(CDCPGRB_POOL *pool, const uint16_t node_pos)
{
    if(CDCPGRB_ERR_POS != node_pos)
    {
        CDCPGRB_NODE *node;

        node = CDCPGRB_POOL_NODE(pool, node_pos);
        CDCPGRB_NODE_USED_FLAG(node)  = CDCPGRB_NODE_NOT_USED;
        CDCPGRB_NODE_PARENT_POS(node) = CDCPGRB_ERR_POS;
        CDCPGRB_NODE_RIGHT_POS(node)  = CDCPGRB_ERR_POS;
        CDCPGRB_NODE_LEFT_POS(node)   = CDCPGRB_ERR_POS;
        CDCPGRB_NODE_NEXT_POS(node)   = CDCPGRB_POOL_FREE_HEAD(pool);
        CDCPGRB_NODE_COLOR(node)      = CDCPGRB_BLACK;

        CDCPGRB_POOL_FREE_HEAD(pool)  = node_pos;
    }
    return;
}

void cdcpgrb_node_init(CDCPGRB_POOL *pool, const uint16_t node_pos)
{
    CDCPGRB_NODE *node;

    node  = CDCPGRB_POOL_NODE(pool, node_pos);

    CDCPGRB_NODE_PARENT_POS(node) = CDCPGRB_ERR_POS;
    CDCPGRB_NODE_RIGHT_POS(node)  = CDCPGRB_ERR_POS;
    CDCPGRB_NODE_LEFT_POS(node)   = CDCPGRB_ERR_POS;
    CDCPGRB_NODE_USED_FLAG(node)  = CDCPGRB_NODE_NOT_USED;
    CDCPGRB_NODE_NEXT_POS(node)   = CDCPGRB_ERR_POS;
    CDCPGRB_NODE_COLOR(node)      = CDCPGRB_BLACK;

    return;
}

void cdcpgrb_node_clean(CDCPGRB_POOL *pool, const uint16_t node_pos)
{
    CDCPGRB_NODE *node;

    node  = CDCPGRB_POOL_NODE(pool, node_pos);

    CDCPGRB_NODE_PARENT_POS(node) = CDCPGRB_ERR_POS;
    CDCPGRB_NODE_RIGHT_POS(node)  = CDCPGRB_ERR_POS;
    CDCPGRB_NODE_LEFT_POS(node)   = CDCPGRB_ERR_POS;
    CDCPGRB_NODE_USED_FLAG(node)  = CDCPGRB_NODE_NOT_USED;
    CDCPGRB_NODE_NEXT_POS(node)   = CDCPGRB_ERR_POS;
    CDCPGRB_NODE_COLOR(node)      = CDCPGRB_BLACK;

    return;
}

void cdcpgrb_node_set_next(CDCPGRB_POOL *pool, const uint16_t node_pos, const uint16_t next_pos)
{
    CDCPGRB_NODE *node;

    node  = CDCPGRB_POOL_NODE(pool, node_pos);
    CDCPGRB_NODE_NEXT_POS(node) = next_pos;

    return;
}

void cdcpgrb_node_print(LOG *log, const CDCPGRB_POOL *pool, const uint16_t node_pos)
{
    const CDCPGRB_NODE *node;
    node  = CDCPGRB_POOL_NODE(pool, node_pos);

    sys_log(log, "%5d: parent = %5d, left = %5d, right = %5d, flg = %s, color = %s, %s = %5d\n",
                       node_pos,
                       CDCPGRB_NODE_PARENT_POS(node),
                       CDCPGRB_NODE_LEFT_POS(node),
                       CDCPGRB_NODE_RIGHT_POS(node),
                       CDCPGRB_NODE_IS_USED(node) ? "used" : "n.a.",
                       CDCPGRB_NODE_IS_USED(node) ? (CDCPGRB_NODE_IS_RED(node) ? "red  " : "black") : "#####",
                       CDCPGRB_NODE_IS_USED(node) ? "data" : "next",
                       CDCPGRB_NODE_IS_USED(node) ? CDCPGRB_NODE_DATA(node) : CDCPGRB_NODE_NEXT_POS(node)
                       );
    return;
}

void cdcpgrb_node_print_level(LOG *log, const CDCPGRB_POOL *pool, const uint16_t node_pos, const uint16_t level)
{
    const CDCPGRB_NODE *node;
    node  = CDCPGRB_POOL_NODE(pool, node_pos);

    c_ident_print(log, level);
    sys_print(log, "%5d: parent = %5d, left = %5d, right = %5d, flg = %s, color = %s, %s = %5d\n",
                       node_pos,
                       CDCPGRB_NODE_PARENT_POS(node),
                       CDCPGRB_NODE_LEFT_POS(node),
                       CDCPGRB_NODE_RIGHT_POS(node),
                       CDCPGRB_NODE_IS_USED(node) ? "used" : "NOT used",
                       CDCPGRB_NODE_IS_RED(node)  ? "red  " : "black",
                       CDCPGRB_NODE_IS_USED(node) ? "data" : "next",
                       CDCPGRB_NODE_IS_USED(node) ? CDCPGRB_NODE_DATA(node) : CDCPGRB_NODE_NEXT_POS(node)
                       );
    return;
}


STATIC_CAST static void __cdcpgrb_tree_rotate_left(CDCPGRB_POOL *pool, const uint16_t node_pos, uint16_t *root_pos)
{
    CDCPGRB_NODE *node;
    CDCPGRB_NODE *right;

    uint16_t  right_pos;

    node  = CDCPGRB_POOL_NODE(pool, node_pos);

    right_pos = CDCPGRB_NODE_RIGHT_POS(node);
    right = CDCPGRB_POOL_NODE(pool, right_pos);

    if(CDCPGRB_ERR_POS != (CDCPGRB_NODE_RIGHT_POS(node) = CDCPGRB_NODE_LEFT_POS(right)))
    {
        CDCPGRB_NODE *left;
        left = CDCPGRB_POOL_NODE(pool, CDCPGRB_NODE_LEFT_POS(right));
        CDCPGRB_NODE_PARENT_POS(left) = node_pos;
    }
    CDCPGRB_NODE_LEFT_POS(right) = node_pos;

    if(CDCPGRB_ERR_POS != (CDCPGRB_NODE_PARENT_POS(right) = CDCPGRB_NODE_PARENT_POS(node)))
    {
        CDCPGRB_NODE *parent;
        parent = CDCPGRB_POOL_NODE(pool, CDCPGRB_NODE_PARENT_POS(node));

        if (node_pos == CDCPGRB_NODE_LEFT_POS(parent))
        {
            CDCPGRB_NODE_LEFT_POS(parent) = right_pos;
        }
        else
        {
            CDCPGRB_NODE_RIGHT_POS(parent) = right_pos;
        }
    }
    else
    {
        (*root_pos) = right_pos;
    }
    CDCPGRB_NODE_PARENT_POS(node) = right_pos;
    return;
}

STATIC_CAST static void __cdcpgrb_tree_rotate_right(CDCPGRB_POOL *pool, const uint16_t node_pos, uint16_t *root_pos)
{
    CDCPGRB_NODE *node;
    CDCPGRB_NODE *left;
    uint16_t  left_pos;

    node  = CDCPGRB_POOL_NODE(pool, node_pos);

    left_pos = CDCPGRB_NODE_LEFT_POS(node);
    left = CDCPGRB_POOL_NODE(pool, left_pos);

    if (CDCPGRB_ERR_POS != (CDCPGRB_NODE_LEFT_POS(node) = CDCPGRB_NODE_RIGHT_POS(left)))
    {
        CDCPGRB_NODE *right;
        right = CDCPGRB_POOL_NODE(pool, CDCPGRB_NODE_RIGHT_POS(left));
        CDCPGRB_NODE_PARENT_POS(right) = node_pos;
    }
    CDCPGRB_NODE_RIGHT_POS(left) = node_pos;

    if (CDCPGRB_ERR_POS != (CDCPGRB_NODE_PARENT_POS(left) = CDCPGRB_NODE_PARENT_POS(node)))
    {
        CDCPGRB_NODE *parent;
        parent = CDCPGRB_POOL_NODE(pool, CDCPGRB_NODE_PARENT_POS(node));

        if (node_pos == CDCPGRB_NODE_RIGHT_POS(parent))
        {
            CDCPGRB_NODE_RIGHT_POS(parent) = left_pos;
        }
        else
        {
            CDCPGRB_NODE_LEFT_POS(parent) = left_pos;
        }
    }
    else
    {
        (*root_pos) = left_pos;
    }
    CDCPGRB_NODE_PARENT_POS(node) = left_pos;
    return;
}

STATIC_CAST static void __cdcpgrb_tree_insert_color(CDCPGRB_POOL *pool, const uint16_t node_pos, uint16_t *root_pos)
{
    CDCPGRB_NODE *node;
    CDCPGRB_NODE *root;
    CDCPGRB_NODE *parent;

    uint16_t  node_pos_t;

    node_pos_t = node_pos;
    node  = CDCPGRB_POOL_NODE(pool, node_pos_t);

    while (NULL_PTR != (parent = CDCPGRB_POOL_NODE(pool, CDCPGRB_NODE_PARENT_POS(node))) /*parent is valid*/
         && CDCPGRB_RED == CDCPGRB_NODE_COLOR(parent))
    {
        uint16_t  parent_pos;
        uint16_t  gparent_pos;
        CDCPGRB_NODE *gparent;

        parent_pos = CDCPGRB_NODE_PARENT_POS(node);

        gparent_pos = CDCPGRB_NODE_PARENT_POS(parent);
        ASSERT(CDCPGRB_ERR_POS != gparent_pos);
        gparent = CDCPGRB_POOL_NODE(pool, gparent_pos);

        if (parent_pos == CDCPGRB_NODE_LEFT_POS(gparent))
        {
            {
                CDCPGRB_NODE *uncle;
                if (NULL_PTR != (uncle = CDCPGRB_POOL_NODE(pool, CDCPGRB_NODE_RIGHT_POS(gparent))) /*uncle is valid*/
                   && CDCPGRB_RED == CDCPGRB_NODE_COLOR(uncle))
                {
                    CDCPGRB_NODE_COLOR(uncle)   = CDCPGRB_BLACK;
                    CDCPGRB_NODE_COLOR(parent)  = CDCPGRB_BLACK;
                    CDCPGRB_NODE_COLOR(gparent) = CDCPGRB_RED;

                    node = gparent;
                    node_pos_t = gparent_pos;
                    continue;
                }
            }

            if (CDCPGRB_NODE_RIGHT_POS(parent) == node_pos_t)
            {
                __cdcpgrb_tree_rotate_left(pool, parent_pos, root_pos);
                XCHG(CDCPGRB_NODE *, parent, node);
                XCHG(uint16_t, parent_pos, node_pos_t);
            }

            CDCPGRB_NODE_COLOR(parent)  = CDCPGRB_BLACK;
            CDCPGRB_NODE_COLOR(gparent) = CDCPGRB_RED;
            __cdcpgrb_tree_rotate_right(pool, gparent_pos, root_pos);
         }
         else
         {
            {
                CDCPGRB_NODE *uncle;
                if (NULL_PTR != (uncle = CDCPGRB_POOL_NODE(pool, CDCPGRB_NODE_LEFT_POS(gparent))) /*uncle is valid*/
                    && CDCPGRB_RED == CDCPGRB_NODE_COLOR(uncle))
                {
                    CDCPGRB_NODE_COLOR(uncle)   = CDCPGRB_BLACK;
                    CDCPGRB_NODE_COLOR(parent)  = CDCPGRB_BLACK;
                    CDCPGRB_NODE_COLOR(gparent) = CDCPGRB_RED;

                    node = gparent;
                    node_pos_t = gparent_pos;
                    continue;
                }
            }

            if (CDCPGRB_NODE_LEFT_POS(parent) == node_pos_t)
            {
                __cdcpgrb_tree_rotate_right(pool, parent_pos, root_pos);
                XCHG(CDCPGRB_NODE *, parent, node);
                XCHG(uint16_t, parent_pos, node_pos_t);
            }

            CDCPGRB_NODE_COLOR(parent)  = CDCPGRB_BLACK;
            CDCPGRB_NODE_COLOR(gparent) = CDCPGRB_RED;
            __cdcpgrb_tree_rotate_left(pool, gparent_pos, root_pos);
        }
    }

    root = CDCPGRB_POOL_NODE(pool, *root_pos);
    CDCPGRB_NODE_COLOR(root) = CDCPGRB_BLACK;
    return;
}

STATIC_CAST static void __cdcpgrb_tree_erase_color(CDCPGRB_POOL *pool, const uint16_t node_pos, const uint16_t parent_pos, uint16_t *root_pos)
{
    CDCPGRB_NODE *node;
    uint16_t  node_pos_t;
    uint16_t  parent_pos_t;

    node_pos_t   = node_pos;
    parent_pos_t = parent_pos;

    while ((NULL_PTR == (node = CDCPGRB_POOL_NODE(pool, node_pos_t)) || CDCPGRB_BLACK == CDCPGRB_NODE_COLOR(node)) && node_pos_t != (*root_pos))
    {
        CDCPGRB_NODE *parent;

        parent = CDCPGRB_POOL_NODE(pool, parent_pos_t);

        if (CDCPGRB_NODE_LEFT_POS(parent) == node_pos_t)
        {
            CDCPGRB_NODE *other;
            CDCPGRB_NODE *o_left;
            CDCPGRB_NODE *o_right;
            uint16_t  other_pos;

            other_pos = CDCPGRB_NODE_RIGHT_POS(parent);
            other = CDCPGRB_POOL_NODE(pool, other_pos);

            if (CDCPGRB_RED == CDCPGRB_NODE_COLOR(other))
            {
                CDCPGRB_NODE_COLOR(other)  = CDCPGRB_BLACK;
                CDCPGRB_NODE_COLOR(parent) = CDCPGRB_RED;

                __cdcpgrb_tree_rotate_left(pool, parent_pos_t, root_pos);

                other_pos = CDCPGRB_NODE_RIGHT_POS(parent);
                other = CDCPGRB_POOL_NODE(pool, other_pos);
            }

            o_left = CDCPGRB_POOL_NODE(pool, CDCPGRB_NODE_LEFT_POS(other));
            o_right = CDCPGRB_POOL_NODE(pool, CDCPGRB_NODE_RIGHT_POS(other));

            if((NULL_PTR == o_left || CDCPGRB_BLACK == CDCPGRB_NODE_COLOR(o_left))
            && (NULL_PTR == o_right || CDCPGRB_BLACK == CDCPGRB_NODE_COLOR(o_right)))
            {
                CDCPGRB_NODE_COLOR(other) = CDCPGRB_RED;

                node_pos_t = parent_pos_t;
                node = CDCPGRB_POOL_NODE(pool, node_pos_t);

                parent_pos_t = CDCPGRB_NODE_PARENT_POS(node);
                parent = CDCPGRB_POOL_NODE(pool, parent_pos_t);
            }
            else
            {
                if (NULL_PTR == o_right || CDCPGRB_BLACK == CDCPGRB_NODE_COLOR(o_right))
                {
                    if (NULL_PTR != o_left)
                    {
                        CDCPGRB_NODE_COLOR(o_left) = CDCPGRB_BLACK;
                    }
                    CDCPGRB_NODE_COLOR(other) = CDCPGRB_RED;

                    __cdcpgrb_tree_rotate_right(pool, other_pos, root_pos);

                    other_pos = CDCPGRB_NODE_RIGHT_POS(parent);
                    other = CDCPGRB_POOL_NODE(pool, other_pos);
                    /*note: other was changed here*/
                }

                CDCPGRB_NODE_COLOR(other) = CDCPGRB_NODE_COLOR(parent);
                CDCPGRB_NODE_COLOR(parent) = CDCPGRB_BLACK;

                /*due to other may be changed before, have to get o_right again here*/
                o_right = CDCPGRB_POOL_NODE(pool, CDCPGRB_NODE_RIGHT_POS(other));
                if (NULL_PTR != o_right)
                {
                    CDCPGRB_NODE_COLOR(o_right) = CDCPGRB_BLACK;
                }

                __cdcpgrb_tree_rotate_left(pool, parent_pos_t, root_pos);
                node_pos_t = (*root_pos);
                break;
            }
        }
        else
        {
            CDCPGRB_NODE *other;
            CDCPGRB_NODE *o_left;
            CDCPGRB_NODE *o_right;
            uint16_t  other_pos;

            other_pos = CDCPGRB_NODE_LEFT_POS(parent);
            other = CDCPGRB_POOL_NODE(pool, other_pos);

            if (CDCPGRB_RED == CDCPGRB_NODE_COLOR(other))
            {
                CDCPGRB_NODE_COLOR(other) = CDCPGRB_BLACK;
                CDCPGRB_NODE_COLOR(parent) = CDCPGRB_RED;

                __cdcpgrb_tree_rotate_right(pool, parent_pos_t, root_pos);

                other_pos = CDCPGRB_NODE_LEFT_POS(parent);
                other = CDCPGRB_POOL_NODE(pool, other_pos);
            }

            o_left = CDCPGRB_POOL_NODE(pool, CDCPGRB_NODE_LEFT_POS(other));
            o_right = CDCPGRB_POOL_NODE(pool, CDCPGRB_NODE_RIGHT_POS(other));

            if ((NULL_PTR == o_left  || CDCPGRB_BLACK == CDCPGRB_NODE_COLOR(o_left))
             && (NULL_PTR == o_right || CDCPGRB_BLACK == CDCPGRB_NODE_COLOR(o_right)))
            {
                CDCPGRB_NODE_COLOR(other) = CDCPGRB_RED;

                node_pos_t = parent_pos_t;
                node = CDCPGRB_POOL_NODE(pool, node_pos_t);

                parent_pos_t = CDCPGRB_NODE_PARENT_POS(node);
                parent = CDCPGRB_POOL_NODE(pool, parent_pos_t);
            }
            else
            {
                if (NULL_PTR == o_left  || CDCPGRB_BLACK == CDCPGRB_NODE_COLOR(o_left))
                {
                    if (NULL_PTR != o_right)
                    {
                        CDCPGRB_NODE_COLOR(o_right) = CDCPGRB_BLACK;
                    }

                    CDCPGRB_NODE_COLOR(other) = CDCPGRB_RED;

                    __cdcpgrb_tree_rotate_left(pool, other_pos, root_pos);

                    other_pos = CDCPGRB_NODE_LEFT_POS(parent);
                    other = CDCPGRB_POOL_NODE(pool, other_pos);
                    /*note: other was changed here*/
                }

                CDCPGRB_NODE_COLOR(other) = CDCPGRB_NODE_COLOR(parent);
                CDCPGRB_NODE_COLOR(parent) = CDCPGRB_BLACK;

                /*due to other may be changed before, have to get o_left again here*/
                o_left = CDCPGRB_POOL_NODE(pool, CDCPGRB_NODE_LEFT_POS(other));
                if (NULL_PTR != o_left)
                {
                    CDCPGRB_NODE_COLOR(o_left) = CDCPGRB_BLACK;
                }
                __cdcpgrb_tree_rotate_right(pool, parent_pos_t, root_pos);
                node_pos_t = (*root_pos);
                break;
            }
        }
    }

    node = CDCPGRB_POOL_NODE(pool, node_pos_t);
    if (NULL_PTR != node)
    {
        CDCPGRB_NODE_COLOR(node) = CDCPGRB_BLACK;
    }
    return;
}

STATIC_CAST static void __cdcpgrb_tree_erase(CDCPGRB_POOL *pool, const uint16_t node_pos, uint16_t *root_pos)
{
    CDCPGRB_NODE *node;

    uint16_t node_pos_t;
    uint16_t child_pos;
    uint16_t parent_pos;
    uint16_t color;

    node_pos_t = node_pos;
    node = CDCPGRB_POOL_NODE(pool, node_pos_t);

    ASSERT(NULL_PTR != node);
    ASSERT(CDCPGRB_NODE_IS_USED(node));

    if (CDCPGRB_ERR_POS == CDCPGRB_NODE_LEFT_POS(node))
    {
        child_pos = CDCPGRB_NODE_RIGHT_POS(node);
    }
    else if (CDCPGRB_ERR_POS == CDCPGRB_NODE_RIGHT_POS(node))
    {
        child_pos = CDCPGRB_NODE_LEFT_POS(node);
    }
    else
    {
        CDCPGRB_NODE *old;

        uint16_t old_pos;
        uint16_t left_pos;

        old_pos = node_pos_t;

        node_pos_t = CDCPGRB_NODE_RIGHT_POS(node);
        node = CDCPGRB_POOL_NODE(pool, node_pos_t);

        while (CDCPGRB_ERR_POS != (left_pos = CDCPGRB_NODE_LEFT_POS(node)))
        {
            node_pos_t = left_pos;
            node = CDCPGRB_POOL_NODE(pool, node_pos_t);

        }

        child_pos  = CDCPGRB_NODE_RIGHT_POS(node);
        parent_pos = CDCPGRB_NODE_PARENT_POS(node);
        color      = CDCPGRB_NODE_COLOR(node);

        if (CDCPGRB_ERR_POS != child_pos)
        {
            CDCPGRB_NODE *child;
            child = CDCPGRB_POOL_NODE(pool, child_pos);
            CDCPGRB_NODE_PARENT_POS(child) = parent_pos;
        }

        if (CDCPGRB_ERR_POS != parent_pos)
        {
            CDCPGRB_NODE *parent;

            parent = CDCPGRB_POOL_NODE(pool, parent_pos);
            if (CDCPGRB_NODE_LEFT_POS(parent) == node_pos_t)
            {
                CDCPGRB_NODE_LEFT_POS(parent) = child_pos;
            }
            else
            {
                CDCPGRB_NODE_RIGHT_POS(parent) = child_pos;
            }
        }
        else
        {
            (*root_pos) = child_pos;
        }

        if (CDCPGRB_NODE_PARENT_POS(node) == old_pos)
        {
            parent_pos = node_pos_t;
        }

        //node = CDCPGRB_POOL_NODE(pool, node_pos_t);
        old  = CDCPGRB_POOL_NODE(pool, old_pos);

        CDCPGRB_NODE_PARENT_POS(node) = CDCPGRB_NODE_PARENT_POS(old);
        CDCPGRB_NODE_COLOR(node)      = CDCPGRB_NODE_COLOR(old);
        CDCPGRB_NODE_RIGHT_POS(node)  = CDCPGRB_NODE_RIGHT_POS(old);
        CDCPGRB_NODE_LEFT_POS(node)   = CDCPGRB_NODE_LEFT_POS(old);

        if (CDCPGRB_ERR_POS != CDCPGRB_NODE_PARENT_POS(old))
        {
            CDCPGRB_NODE *old_parent;
            old_parent = CDCPGRB_POOL_NODE(pool, CDCPGRB_NODE_PARENT_POS(old));

            if (CDCPGRB_NODE_LEFT_POS(old_parent) == old_pos)
            {
                CDCPGRB_NODE_LEFT_POS(old_parent) = node_pos_t;
            }
            else
            {
                CDCPGRB_NODE_RIGHT_POS(old_parent) = node_pos_t;
            }
        }
        else
        {
            (*root_pos) = node_pos_t;
        }

        {
            CDCPGRB_NODE *old_left;

            old_left = CDCPGRB_POOL_NODE(pool, CDCPGRB_NODE_LEFT_POS(old));
            CDCPGRB_NODE_PARENT_POS(old_left) = node_pos_t;
        }

        if (CDCPGRB_ERR_POS != CDCPGRB_NODE_RIGHT_POS(old))
        {
            CDCPGRB_NODE *old_right;
            old_right = CDCPGRB_POOL_NODE(pool, CDCPGRB_NODE_RIGHT_POS(old));
            CDCPGRB_NODE_PARENT_POS(old_right) = node_pos_t;
        }
        goto color;
    }

    parent_pos = CDCPGRB_NODE_PARENT_POS(node);
    color = CDCPGRB_NODE_COLOR(node);

    if (CDCPGRB_ERR_POS != child_pos)
    {
        CDCPGRB_NODE *child;
        child = CDCPGRB_POOL_NODE(pool, child_pos);
        CDCPGRB_NODE_PARENT_POS(child) = parent_pos;
    }

    if (CDCPGRB_ERR_POS != parent_pos)
    {
        CDCPGRB_NODE *parent;

        parent = CDCPGRB_POOL_NODE(pool, parent_pos);
        if (CDCPGRB_NODE_LEFT_POS(parent) == node_pos_t)
        {
            CDCPGRB_NODE_LEFT_POS(parent) = child_pos;
        }
        else
        {
            CDCPGRB_NODE_RIGHT_POS(parent) = child_pos;
        }
    }
    else
    {
        (*root_pos) = child_pos;
    }

 color:
    if (CDCPGRB_BLACK == color)
    {
        __cdcpgrb_tree_erase_color(pool, child_pos, parent_pos, root_pos);
    }
    return;
}

EC_BOOL cdcpgrb_tree_is_empty(const CDCPGRB_POOL *pool, const uint16_t root_pos)
{
    if (CDCPGRB_ERR_POS == root_pos)
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}


STATIC_CAST static uint16_t __cdcpgrb_tree_node_num(const CDCPGRB_POOL *pool, const uint16_t node_pos)
{
    const CDCPGRB_NODE *node;

    if(CDCPGRB_ERR_POS == node_pos)
    {
        return ((uint16_t)0);
    }

    node = CDCPGRB_POOL_NODE(pool, node_pos);

    return (uint16_t)(1 + __cdcpgrb_tree_node_num(pool, CDCPGRB_NODE_LEFT_POS(node)) + __cdcpgrb_tree_node_num(pool, CDCPGRB_NODE_RIGHT_POS(node)));
}

uint16_t cdcpgrb_tree_node_num(const CDCPGRB_POOL *pool, const uint16_t root_pos)
{
    return __cdcpgrb_tree_node_num(pool, root_pos);
}

/*
 * This function returns the first node_pos (in sort order) of the tree.
 */
uint16_t cdcpgrb_tree_first_node(const CDCPGRB_POOL *pool, const uint16_t root_pos)
{
    uint16_t  node_pos;
    const CDCPGRB_NODE *node;

    node_pos = root_pos;
    if (CDCPGRB_ERR_POS == node_pos)
    {
        return (CDCPGRB_ERR_POS);
    }

    node = CDCPGRB_POOL_NODE(pool, node_pos);

    while (CDCPGRB_ERR_POS != CDCPGRB_NODE_LEFT_POS(node))
    {
        node_pos = CDCPGRB_NODE_LEFT_POS(node);
        node = CDCPGRB_POOL_NODE(pool, node_pos);
    }
    return (node_pos);
}

uint16_t cdcpgrb_tree_last_node(const CDCPGRB_POOL *pool, const uint16_t root_pos)
{
    uint16_t  node_pos;
    const CDCPGRB_NODE *node;

    node_pos = root_pos;
    if (CDCPGRB_ERR_POS == node_pos)
    {
        return (CDCPGRB_ERR_POS);
    }

    node = CDCPGRB_POOL_NODE(pool, node_pos);

    while (CDCPGRB_ERR_POS != CDCPGRB_NODE_RIGHT_POS(node))
    {
        node_pos = CDCPGRB_NODE_RIGHT_POS(node);
        node = CDCPGRB_POOL_NODE(pool, node_pos);
    }

    return (node_pos);
}

uint16_t cdcpgrb_tree_next_node(const CDCPGRB_POOL *pool, const uint16_t node_pos)
{
    uint16_t node_pos_t;
    const CDCPGRB_NODE *node;
    const CDCPGRB_NODE *parent;

    node_pos_t = node_pos;
    node = CDCPGRB_POOL_NODE(pool, node_pos_t);
    /* If we have a right-hand child, go down and then left as far
       as we can. */
    if (CDCPGRB_ERR_POS != CDCPGRB_NODE_RIGHT_POS(node))
    {
        node_pos_t = CDCPGRB_NODE_RIGHT_POS(node);
        node = CDCPGRB_POOL_NODE(pool, node_pos_t);
        while (CDCPGRB_ERR_POS != CDCPGRB_NODE_LEFT_POS(node))
        {
            node_pos_t = CDCPGRB_NODE_LEFT_POS(node);
            node = CDCPGRB_POOL_NODE(pool, node_pos_t);
        }
        return (node_pos_t);
    }

    /* No right-hand children.  Everything down and left is
       smaller than us, so any 'next' node_pos_t must be in the general
       direction of our parent. Go up the tree; any time the
       ancestor is a right-hand child of its parent, keep going
       up. First time it's a left-hand child of its parent, said
       parent is our 'next' node_pos_t. */
    while (NULL_PTR != (parent = CDCPGRB_POOL_NODE(pool, CDCPGRB_NODE_PARENT_POS(node))) && node_pos_t == CDCPGRB_NODE_RIGHT_POS(parent))
    {
        node_pos_t = CDCPGRB_NODE_PARENT_POS(node);
        node = parent;
    }

    return (CDCPGRB_NODE_PARENT_POS(node));
}

uint16_t cdcpgrb_tree_prev_node(const CDCPGRB_POOL *pool, const uint16_t node_pos)
{
    uint16_t node_pos_t;
    const CDCPGRB_NODE *node;
    const CDCPGRB_NODE *parent;

    node_pos_t = node_pos;
    node = CDCPGRB_POOL_NODE(pool, node_pos_t);

    /* If we have a left-hand child, go down and then right as far
       as we can. */
    if (CDCPGRB_ERR_POS != CDCPGRB_NODE_LEFT_POS(node))
    {
        node_pos_t = CDCPGRB_NODE_LEFT_POS(node);
        node = CDCPGRB_POOL_NODE(pool, node_pos_t);
        while (CDCPGRB_ERR_POS != CDCPGRB_NODE_RIGHT_POS(node))
        {
            node_pos_t = CDCPGRB_NODE_RIGHT_POS(node);
            node = CDCPGRB_POOL_NODE(pool, node_pos_t);
        }
        return (node_pos_t);
    }

    /* No left-hand children. Go up till we find an ancestor which
       is a right-hand child of its parent */
    while (NULL_PTR != (parent = CDCPGRB_POOL_NODE(pool, CDCPGRB_NODE_PARENT_POS(node))) && node_pos_t == CDCPGRB_NODE_LEFT_POS(parent))
    {
        node_pos_t = CDCPGRB_NODE_PARENT_POS(node);
        node = parent;
    }

    return (CDCPGRB_NODE_PARENT_POS(node));
}

/*return the searched pos*/
uint16_t cdcpgrb_tree_search_data(CDCPGRB_POOL *pool, const uint16_t root_pos, uint16_t data)
{
    uint16_t node_pos;

    node_pos = root_pos;

    while (CDCPGRB_ERR_POS != node_pos)
    {
        CDCPGRB_NODE *node;

        node = CDCPGRB_POOL_NODE(pool, node_pos);

        if (data < CDCPGRB_NODE_DATA(node))
        {
            node_pos = CDCPGRB_NODE_LEFT_POS(node);
        }
        else if (data > CDCPGRB_NODE_DATA(node))
        {
            node_pos = CDCPGRB_NODE_RIGHT_POS(node);
        }
        else
        {
            return (node_pos);
        }
    }

    return (CDCPGRB_ERR_POS);
}


uint16_t cdcpgrb_tree_insert_data(CDCPGRB_POOL *pool, uint16_t *root_pos, const uint16_t data)
{
    uint16_t  node_pos_t;
    uint16_t  new_pos_t;
    uint16_t  parent_pos_t;
    uint16_t  flag; /*0: on left subtree, 1: on right subtree*/

    node_pos_t   = (*root_pos);
    parent_pos_t = CDCPGRB_ERR_POS;
    flag         = ~(uint16_t)0;

    while (CDCPGRB_ERR_POS != node_pos_t)
    {
        CDCPGRB_NODE *node;

        node = CDCPGRB_POOL_NODE(pool, node_pos_t);

        parent_pos_t = node_pos_t;

        if (data < CDCPGRB_NODE_DATA(node))
        {
            node_pos_t = CDCPGRB_NODE_LEFT_POS(node);
            flag = 0;
        }
        else if (data > CDCPGRB_NODE_DATA(node))
        {
            node_pos_t = CDCPGRB_NODE_RIGHT_POS(node);
            flag = 1;
        }
        else
        {
            return (node_pos_t);
        }
    }

    /*not found data in the rbtree*/
    new_pos_t = cdcpgrb_node_new(pool);
    if(CDCPGRB_ERR_POS == new_pos_t)
    {
        dbg_log(SEC_0185_CDCPGRB, 0)(LOGSTDOUT, "error:cdcpgrb_tree_insert_data: new cdcpgrb_node from pool %p failed\n", pool);
        return (CDCPGRB_ERR_POS);
    }
    else
    {
        CDCPGRB_NODE *node;

        node  = CDCPGRB_POOL_NODE(pool, new_pos_t);
        CDCPGRB_NODE_DATA(node) = data;

        CDCPGRB_NODE_PARENT_POS(node) = parent_pos_t;
        CDCPGRB_NODE_COLOR(node)      = CDCPGRB_RED;
        CDCPGRB_NODE_LEFT_POS(node)   = CDCPGRB_ERR_POS;
        CDCPGRB_NODE_RIGHT_POS(node)  = CDCPGRB_ERR_POS;

        if(CDCPGRB_ERR_POS == (*root_pos))
        {
            (*root_pos) = new_pos_t;
        }
        else
        {
            CDCPGRB_NODE *parent;
            parent  = CDCPGRB_POOL_NODE(pool, parent_pos_t);

            if(0 == flag)/*on left subtree*/
            {
                CDCPGRB_NODE_LEFT_POS(parent) = new_pos_t;
            }
            else
            {
                CDCPGRB_NODE_RIGHT_POS(parent) = new_pos_t;
            }
        }
        __cdcpgrb_tree_insert_color(pool, new_pos_t, root_pos);
    }

    return (new_pos_t);
}

EC_BOOL cdcpgrb_tree_delete_data(CDCPGRB_POOL *pool, uint16_t *root_pos, const uint16_t data)
{
    uint16_t node_pos;

    node_pos = cdcpgrb_tree_search_data(pool, *root_pos, data);
    if(CDCPGRB_ERR_POS == node_pos)
    {
        return (EC_FALSE);
    }

    __cdcpgrb_tree_erase(pool, node_pos, root_pos);
    cdcpgrb_node_free(pool, node_pos);
    return (EC_TRUE);
}

/*postorder: left -> right -> root*/
STATIC_CAST static void __cdcpgrb_tree_free(CDCPGRB_POOL *pool, const uint16_t node_pos)
{
    CDCPGRB_NODE *node;

    if(CDCPGRB_ERR_POS == node_pos)
    {
        return;
    }

    node  = CDCPGRB_POOL_NODE(pool, node_pos);
    if(CDCPGRB_ERR_POS != CDCPGRB_NODE_LEFT_POS(node))
    {
        __cdcpgrb_tree_free(pool, CDCPGRB_NODE_LEFT_POS(node));
    }

    if(CDCPGRB_ERR_POS != CDCPGRB_NODE_RIGHT_POS(node))
    {
        __cdcpgrb_tree_free(pool, CDCPGRB_NODE_RIGHT_POS(node));
    }

    cdcpgrb_node_free(pool, node_pos);

    return;
}
void cdcpgrb_tree_free(CDCPGRB_POOL *pool, const uint16_t root_pos)
{
    __cdcpgrb_tree_free(pool, root_pos);
    return;
}

EC_BOOL cdcpgrb_pool_init(CDCPGRB_POOL *pool, const uint16_t node_num)
{
    uint16_t node_pos;

    ASSERT(CDCPGRB_POOL_MAX_SIZE >= node_num);

    CDCPGRB_POOL_NODE_NUM(pool) = node_num;

    for(node_pos = 0; node_pos < node_num; node_pos ++)
    {
        cdcpgrb_node_init(pool, node_pos);
        cdcpgrb_node_set_next(pool, node_pos, node_pos + 1);
    }
    cdcpgrb_node_set_next(pool, node_num - 1, CDCPGRB_ERR_POS);

    CDCPGRB_POOL_FREE_HEAD(pool) = 0;/*the free nodes head*/
    return (EC_TRUE);
}

void cdcpgrb_pool_clean(CDCPGRB_POOL *pool)
{
    CDCPGRB_POOL_NODE_NUM(pool)  = 0;
    CDCPGRB_POOL_FREE_HEAD(pool) = CDCPGRB_ERR_POS;
    return;
}

/*clear without any space mallocation!*/
void cdcpgrb_pool_clear(CDCPGRB_POOL *pool)
{
    CDCPGRB_POOL_NODE_NUM(pool)  = 0;
    CDCPGRB_POOL_FREE_HEAD(pool) = CDCPGRB_ERR_POS;
    return;
}

void cdcpgrb_pool_print(LOG *log, const CDCPGRB_POOL *pool)
{
    uint16_t node_pos;
    uint16_t node_num;

    node_num = CDCPGRB_POOL_NODE_NUM(pool);

    sys_log(log, "pool %lx, node_num %u, free_head %u\n",
                 pool,
                 node_num,
                 CDCPGRB_POOL_FREE_HEAD(pool));

    for(node_pos = 0; node_pos < node_num; node_pos ++)
    {
        cdcpgrb_node_print(log, pool, node_pos);
    }

    return;
}

/*visit the root node first: root -> left -> right*/
void cdcpgrb_preorder_print(LOG *log, const CDCPGRB_POOL *pool, const uint16_t node_pos)
{
    const CDCPGRB_NODE *node;

    if(CDCPGRB_ERR_POS == node_pos)
    {
        return;
    }

    node  = CDCPGRB_POOL_NODE(pool, node_pos);
    cdcpgrb_node_print(log, pool, node_pos);

    if(CDCPGRB_ERR_POS != CDCPGRB_NODE_LEFT_POS(node))
    {
        cdcpgrb_preorder_print(log, pool, CDCPGRB_NODE_LEFT_POS(node));
    }

    if(CDCPGRB_ERR_POS != CDCPGRB_NODE_RIGHT_POS(node))
    {
        cdcpgrb_preorder_print(log, pool, CDCPGRB_NODE_RIGHT_POS(node));
    }

    return;
}

/*visit the left subtree, then the root node: left -> root -> right*/
void cdcpgrb_inorder_print(LOG *log, const CDCPGRB_POOL *pool, const uint16_t node_pos)
{
    const CDCPGRB_NODE *node;

    if(CDCPGRB_ERR_POS == node_pos)
    {
        return;
    }

    node  = CDCPGRB_POOL_NODE(pool, node_pos);
    if(CDCPGRB_ERR_POS != CDCPGRB_NODE_LEFT_POS(node))
    {
        cdcpgrb_inorder_print(log, pool, CDCPGRB_NODE_LEFT_POS(node));
    }

    cdcpgrb_node_print(log, pool, node_pos);

    if(CDCPGRB_ERR_POS != CDCPGRB_NODE_RIGHT_POS(node))
    {
        cdcpgrb_inorder_print(log, pool, CDCPGRB_NODE_RIGHT_POS(node));
    }

    return;
}

/*visit the root node last: left -> right -> root*/
void cdcpgrb_postorder_print(LOG *log, const CDCPGRB_POOL *pool, const uint16_t node_pos)
{
    const CDCPGRB_NODE *node;

    if(CDCPGRB_ERR_POS == node_pos)
    {
        return;
    }

    node  = CDCPGRB_POOL_NODE(pool, node_pos);
    if(CDCPGRB_ERR_POS != CDCPGRB_NODE_LEFT_POS(node))
    {
        cdcpgrb_postorder_print(log, pool, CDCPGRB_NODE_LEFT_POS(node));
    }

    if(CDCPGRB_ERR_POS != CDCPGRB_NODE_RIGHT_POS(node))
    {
        cdcpgrb_postorder_print(log, pool, CDCPGRB_NODE_RIGHT_POS(node));
    }

    cdcpgrb_node_print(log, pool, node_pos);

    return;
}


/*visit the root node first: root -> left -> right*/
void cdcpgrb_preorder_print_level(LOG *log, const CDCPGRB_POOL *pool, const uint16_t node_pos, const uint16_t level)
{
    const CDCPGRB_NODE *node;

    if(CDCPGRB_ERR_POS == node_pos)
    {
        return;
    }

    node  = CDCPGRB_POOL_NODE(pool, node_pos);
    cdcpgrb_node_print_level(log, pool, node_pos, level);

    if(CDCPGRB_ERR_POS != CDCPGRB_NODE_LEFT_POS(node))
    {
        cdcpgrb_preorder_print_level(log, pool, CDCPGRB_NODE_LEFT_POS(node), level + 1);
    }

    if(CDCPGRB_ERR_POS != CDCPGRB_NODE_RIGHT_POS(node))
    {
        cdcpgrb_preorder_print_level(log, pool, CDCPGRB_NODE_RIGHT_POS(node), level + 1);
    }

    return;
}

void cdcpgrb_tree_print(LOG *log, const CDCPGRB_POOL *pool, const uint16_t root_pos)
{
    uint16_t node_pos;

    sys_log(log, "[root = %5d]\n", root_pos);
    for(node_pos = cdcpgrb_tree_first_node(pool, root_pos); CDCPGRB_ERR_POS != node_pos; node_pos = cdcpgrb_tree_next_node(pool, node_pos))
    {
        cdcpgrb_node_print(log, pool, node_pos);
    }
    return;
}

/* ---- debug ---- */
EC_BOOL cdcpgrb_node_debug_cmp(const CDCPGRB_NODE *node_1st, const CDCPGRB_NODE *node_2nd)
{
    if(CDCPGRB_NODE_USED_FLAG(node_1st) != CDCPGRB_NODE_USED_FLAG(node_2nd))
    {
        dbg_log(SEC_0185_CDCPGRB, 0)(LOGSTDOUT, "error:cdcpgrb_node_debug_cmp: inconsistent CDCPGRB_NODE_USED_FLAG: %u != %u\n",
                            CDCPGRB_NODE_USED_FLAG(node_1st), CDCPGRB_NODE_USED_FLAG(node_2nd));
        return (EC_FALSE);
    }

    if(CDCPGRB_NODE_COLOR(node_1st) != CDCPGRB_NODE_COLOR(node_2nd))
    {
        dbg_log(SEC_0185_CDCPGRB, 0)(LOGSTDOUT, "error:cdcpgrb_node_debug_cmp: inconsistent CDCPGRB_NODE_COLOR: %u != %u\n",
                            CDCPGRB_NODE_COLOR(node_1st), CDCPGRB_NODE_COLOR(node_2nd));
        return (EC_FALSE);
    }

    if(CDCPGRB_NODE_PARENT_POS(node_1st) != CDCPGRB_NODE_PARENT_POS(node_2nd))
    {
        dbg_log(SEC_0185_CDCPGRB, 0)(LOGSTDOUT, "error:cdcpgrb_node_debug_cmp: inconsistent CDCPGRB_NODE_PARENT_POS: %u != %u\n",
                            CDCPGRB_NODE_PARENT_POS(node_1st), CDCPGRB_NODE_PARENT_POS(node_2nd));
        return (EC_FALSE);
    }

    if(CDCPGRB_NODE_RIGHT_POS(node_1st) != CDCPGRB_NODE_RIGHT_POS(node_2nd))
    {
        dbg_log(SEC_0185_CDCPGRB, 0)(LOGSTDOUT, "error:cdcpgrb_node_debug_cmp: inconsistent CDCPGRB_NODE_RIGHT_POS: %u != %u\n",
                            CDCPGRB_NODE_RIGHT_POS(node_1st), CDCPGRB_NODE_RIGHT_POS(node_2nd));
        return (EC_FALSE);
    }

    if(CDCPGRB_NODE_LEFT_POS(node_1st) != CDCPGRB_NODE_LEFT_POS(node_2nd))
    {
        dbg_log(SEC_0185_CDCPGRB, 0)(LOGSTDOUT, "error:cdcpgrb_node_debug_cmp: inconsistent CDCPGRB_NODE_LEFT_POS: %u != %u\n",
                            CDCPGRB_NODE_LEFT_POS(node_1st), CDCPGRB_NODE_LEFT_POS(node_2nd));
        return (EC_FALSE);
    }

    if(CDCPGRB_NODE_USED == CDCPGRB_NODE_USED_FLAG(node_1st))
    {
        if(CDCPGRB_NODE_DATA(node_1st) != CDCPGRB_NODE_DATA(node_2nd))
        {
            dbg_log(SEC_0185_CDCPGRB, 0)(LOGSTDOUT, "error:cdcpgrb_node_debug_cmp: inconsistent CDCPGRB_NODE_DATA: %u != %u\n",
                                CDCPGRB_NODE_DATA(node_1st), CDCPGRB_NODE_DATA(node_2nd));
            return (EC_FALSE);
        }
    }
    else
    {
        if(CDCPGRB_NODE_NEXT_POS(node_1st) != CDCPGRB_NODE_NEXT_POS(node_2nd))
        {
            dbg_log(SEC_0185_CDCPGRB, 0)(LOGSTDOUT, "error:cdcpgrb_node_debug_cmp: inconsistent CDCPGRB_NODE_NEXT_POS: %u != %u\n",
                                CDCPGRB_NODE_NEXT_POS(node_1st), CDCPGRB_NODE_NEXT_POS(node_2nd));
            return (EC_FALSE);
        }
    }
    return (EC_TRUE);
}

EC_BOOL cdcpgrb_debug_cmp(const CDCPGRB_POOL *pool_1st, const CDCPGRB_POOL *pool_2nd)
{
    uint16_t  node_num;
    uint16_t  node_pos;

    if(CDCPGRB_POOL_FREE_HEAD(pool_1st) != CDCPGRB_POOL_FREE_HEAD(pool_2nd))
    {
        dbg_log(SEC_0185_CDCPGRB, 0)(LOGSTDOUT, "error:cdcpgrb_debug_cmp: inconsistent CDCPGRB_POOL_FREE_HEAD: %u != %u\n",
                            CDCPGRB_POOL_FREE_HEAD(pool_1st), CDCPGRB_POOL_FREE_HEAD(pool_2nd));
        return (EC_FALSE);
    }

    if(CDCPGRB_POOL_NODE_NUM(pool_1st) != CDCPGRB_POOL_NODE_NUM(pool_2nd))
    {
        dbg_log(SEC_0185_CDCPGRB, 0)(LOGSTDOUT, "error:cdcpgrb_debug_cmp: inconsistent CDCPGRB_POOL_NODE_NUM: %u != %u\n",
                            CDCPGRB_POOL_NODE_NUM(pool_1st), CDCPGRB_POOL_NODE_NUM(pool_2nd));
        return (EC_FALSE);
    }

    node_num = CDCPGRB_POOL_NODE_NUM(pool_1st);
    for(node_pos = 0; node_pos < node_num; node_pos ++)
    {
        const CDCPGRB_NODE *node_1st;
        const CDCPGRB_NODE *node_2nd;

        node_1st = CDCPGRB_POOL_NODE(pool_1st, node_pos);
        node_2nd = CDCPGRB_POOL_NODE(pool_2nd, node_pos);

        if(EC_FALSE == cdcpgrb_node_debug_cmp(node_1st, node_2nd))
        {
            dbg_log(SEC_0185_CDCPGRB, 0)(LOGSTDOUT, "error:cdcpgrb_debug_cmp: inconsistent node at pos %u\n", node_pos);
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}


#ifdef __cplusplus
}
#endif/*__cplusplus*/
