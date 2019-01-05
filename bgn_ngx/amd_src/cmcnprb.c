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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "type.h"
#include "mm.h"
#include "log.h"

#include "cmisc.h"

#include "cmcnprb.h"
#include "cmcnp.inc"

#if (SWITCH_ON == CMC_ASSERT_SWITCH)
#define CMCNPRB_ASSERT(condition)   ASSERT(condition)
#endif/*(SWITCH_ON == CMC_ASSERT_SWITCH)*/

#if (SWITCH_OFF == CMC_ASSERT_SWITCH)
#define CMCNPRB_ASSERT(condition)   do{}while(0)
#endif/*(SWITCH_OFF == CMC_ASSERT_SWITCH)*/

/*new a CMCNPRB_NODE and return its position*/
uint32_t cmcnprb_node_new(CMCNPRB_POOL *pool)
{
    uint32_t node_pos_t;
    CMCNPRB_NODE *node;

    node_pos_t = CMCNPRB_POOL_FREE_HEAD(pool);
    if(CMCNPRB_ERR_POS == node_pos_t)
    {
        dbg_log(SEC_0113_CMCNPRB, 0)(LOGSTDERR, "error:cmcnprb_node_new: no free node in pool\n");
        return (CMCNPRB_ERR_POS);
    }

    if(CMCNPRB_POOL_FREE_HEAD(pool) >= CMCNPRB_POOL_NODE_MAX_NUM(pool))
    {
        dbg_log(SEC_0113_CMCNPRB, 0)(LOGSTDERR, "error:cmcnprb_node_new: found conflict: free head %u >= max num %u\n",
                            CMCNPRB_POOL_FREE_HEAD(pool), CMCNPRB_POOL_NODE_MAX_NUM(pool));
        return (CMCNPRB_ERR_POS);
    }

    CMCNPRB_ASSERT(CMCNPRB_POOL_FREE_HEAD(pool) < CMCNPRB_POOL_NODE_MAX_NUM(pool));

    node = CMCNPRB_POOL_NODE(pool, node_pos_t);
#if 0
    dbg_log(SEC_0113_CMCNPRB, 9)(LOGSTDNULL, "[DEBUG] cmcnprb_node_new: pool %p, max %u, used %u, free head %u, next %u\n",
                       pool,
                       CMCNPRB_POOL_NODE_MAX_NUM(pool),
                       CMCNPRB_POOL_NODE_USED_NUM(pool),
                       CMCNPRB_POOL_FREE_HEAD(pool),
                       CMCNPRB_NODE_NEXT_POS(node));
#endif
    CMCNPRB_POOL_FREE_HEAD(pool) = CMCNPRB_NODE_NEXT_POS(node);
    CMCNPRB_POOL_NODE_USED_NUM(pool) ++;

    CMCNPRB_NODE_NEXT_POS(node)  = CMCNPRB_ERR_POS;
    CMCNPRB_NODE_USED_FLAG(node) = CMCNPRB_NODE_USED;

    return (node_pos_t);
}

/*free a CMCNPRB_NODE and return its position to the pool*/
void cmcnprb_node_free(CMCNPRB_POOL *pool, const uint32_t node_pos)
{
    if(CMCNPRB_ERR_POS != node_pos)
    {
        CMCNPRB_NODE *node;

        CMCNPRB_ASSERT(node_pos < CMCNPRB_POOL_NODE_MAX_NUM(pool));

        node = CMCNPRB_POOL_NODE(pool, node_pos);
        CMCNPRB_ASSERT(CMCNPRB_NODE_IS_USED(node));

        CMCNPRB_NODE_USED_FLAG(node)  = CMCNPRB_NODE_NOT_USED;
        CMCNPRB_NODE_PARENT_POS(node) = CMCNPRB_ERR_POS;
        CMCNPRB_NODE_RIGHT_POS(node)  = CMCNPRB_ERR_POS;
        CMCNPRB_NODE_LEFT_POS(node)   = CMCNPRB_ERR_POS;
        CMCNPRB_NODE_NEXT_POS(node)   = CMCNPRB_POOL_FREE_HEAD(pool);
        CMCNPRB_NODE_COLOR(node)      = CMCNPRB_BLACK;

        CMCNPRB_POOL_FREE_HEAD(pool)  = node_pos;
        CMCNPRB_POOL_NODE_USED_NUM(pool) --;
    }
    return;
}

void cmcnprb_node_init(CMCNPRB_POOL *pool, const uint32_t node_pos)
{
    CMCNPRB_NODE *node;

    node  = CMCNPRB_POOL_NODE(pool, node_pos);

    CMCNPRB_NODE_PARENT_POS(node) = CMCNPRB_ERR_POS;
    CMCNPRB_NODE_RIGHT_POS(node)  = CMCNPRB_ERR_POS;
    CMCNPRB_NODE_LEFT_POS(node)   = CMCNPRB_ERR_POS;
    CMCNPRB_NODE_USED_FLAG(node)  = CMCNPRB_NODE_NOT_USED;
    CMCNPRB_NODE_NEXT_POS(node)   = CMCNPRB_ERR_POS;
    CMCNPRB_NODE_COLOR(node)      = CMCNPRB_BLACK;

    return;
}

void cmcnprb_node_clean(CMCNPRB_POOL *pool, const uint32_t node_pos)
{
    CMCNPRB_NODE *node;

    CMCNPRB_ASSERT(node_pos < CMCNPRB_POOL_NODE_MAX_NUM(pool));

    node = CMCNPRB_POOL_NODE(pool, node_pos);

    CMCNPRB_NODE_PARENT_POS(node) = CMCNPRB_ERR_POS;
    CMCNPRB_NODE_RIGHT_POS(node)  = CMCNPRB_ERR_POS;
    CMCNPRB_NODE_LEFT_POS(node)   = CMCNPRB_ERR_POS;
    CMCNPRB_NODE_USED_FLAG(node)  = CMCNPRB_NODE_NOT_USED;
    CMCNPRB_NODE_NEXT_POS(node)   = CMCNPRB_ERR_POS;
    CMCNPRB_NODE_COLOR(node)      = CMCNPRB_BLACK;

    return;
}

void cmcnprb_node_set_next(CMCNPRB_POOL *pool, const uint32_t node_pos, const uint32_t next_pos)
{
    CMCNPRB_NODE *node;

    node = CMCNPRB_POOL_NODE(pool, node_pos);
    CMCNPRB_NODE_NEXT_POS(node) = next_pos;

    return;
}

EC_BOOL cmcnprb_node_is_used(const CMCNPRB_POOL *pool, const uint32_t node_pos)
{
    const CMCNPRB_NODE *node;
    node  = CMCNPRB_POOL_NODE(pool, node_pos);

    if(CMCNPRB_NODE_IS_USED(node))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

void cmcnprb_node_print(LOG *log, const CMCNPRB_POOL *pool, const uint32_t node_pos)
{
    const CMCNPRB_NODE *node;
    node  = CMCNPRB_POOL_NODE(pool, node_pos);

    sys_log(log, "%5d: parent = %5d, left = %5d, right = %5d, flg = %s, color = %s, %s = %5d\n",
                       node_pos,
                       CMCNPRB_NODE_PARENT_POS(node),
                       CMCNPRB_NODE_LEFT_POS(node),
                       CMCNPRB_NODE_RIGHT_POS(node),
                       CMCNPRB_NODE_IS_USED(node) ? "used" : "n.a.",
                       CMCNPRB_NODE_IS_USED(node) ? (CMCNPRB_NODE_IS_RED(node) ? "red  " : "black") : "#####",
                       CMCNPRB_NODE_IS_USED(node) ? "data" : "next",
                       CMCNPRB_NODE_IS_USED(node) ? CMCNPRB_NODE_DATA(node) : CMCNPRB_NODE_NEXT_POS(node)
                       );
    return;
}

void cmcnprb_node_print_level(LOG *log, const CMCNPRB_POOL *pool, const uint32_t node_pos, const uint32_t level)
{
    const CMCNPRB_NODE *node;
    node  = CMCNPRB_POOL_NODE(pool, node_pos);

    c_ident_print(log, level);
    sys_print(log, "%5d: parent = %5d, left = %5d, right = %5d, flg = %s, color = %s, %s = %5d\n",
                       node_pos,
                       CMCNPRB_NODE_PARENT_POS(node),
                       CMCNPRB_NODE_LEFT_POS(node),
                       CMCNPRB_NODE_RIGHT_POS(node),
                       CMCNPRB_NODE_IS_USED(node) ? "used" : "NOT used",
                       CMCNPRB_NODE_IS_RED(node)  ? "red  " : "black",
                       CMCNPRB_NODE_IS_USED(node) ? "data" : "next",
                       CMCNPRB_NODE_IS_USED(node) ? CMCNPRB_NODE_DATA(node) : CMCNPRB_NODE_NEXT_POS(node)
                       );
    return;
}


STATIC_CAST static void __cmcnprb_tree_rotate_left(CMCNPRB_POOL *pool, const uint32_t node_pos, uint32_t *root_pos)
{
    CMCNPRB_NODE *node;
    CMCNPRB_NODE *right;

    uint32_t  right_pos;

    node  = CMCNPRB_POOL_NODE(pool, node_pos);

    right_pos = CMCNPRB_NODE_RIGHT_POS(node);
    right = CMCNPRB_POOL_NODE(pool, right_pos);

    if(CMCNPRB_ERR_POS != (CMCNPRB_NODE_RIGHT_POS(node) = CMCNPRB_NODE_LEFT_POS(right)))
    {
        CMCNPRB_NODE *left;
        left = CMCNPRB_POOL_NODE(pool, CMCNPRB_NODE_LEFT_POS(right));
        CMCNPRB_NODE_PARENT_POS(left) = node_pos;
    }
    CMCNPRB_NODE_LEFT_POS(right) = node_pos;

    if(CMCNPRB_ERR_POS != (CMCNPRB_NODE_PARENT_POS(right) = CMCNPRB_NODE_PARENT_POS(node)))
    {
        CMCNPRB_NODE *parent;
        parent = CMCNPRB_POOL_NODE(pool, CMCNPRB_NODE_PARENT_POS(node));

        if (node_pos == CMCNPRB_NODE_LEFT_POS(parent))
        {
            CMCNPRB_NODE_LEFT_POS(parent) = right_pos;
        }
        else
        {
            CMCNPRB_NODE_RIGHT_POS(parent) = right_pos;
        }
    }
    else
    {
        (*root_pos) = right_pos;
    }
    CMCNPRB_NODE_PARENT_POS(node) = right_pos;
    return;
}

STATIC_CAST static void __cmcnprb_tree_rotate_right(CMCNPRB_POOL *pool, const uint32_t node_pos, uint32_t *root_pos)
{
    CMCNPRB_NODE *node;
    CMCNPRB_NODE *left;
    uint32_t  left_pos;

    node  = CMCNPRB_POOL_NODE(pool, node_pos);

    left_pos = CMCNPRB_NODE_LEFT_POS(node);
    left = CMCNPRB_POOL_NODE(pool, left_pos);

    if (CMCNPRB_ERR_POS != (CMCNPRB_NODE_LEFT_POS(node) = CMCNPRB_NODE_RIGHT_POS(left)))
    {
        CMCNPRB_NODE *right;
        right = CMCNPRB_POOL_NODE(pool, CMCNPRB_NODE_RIGHT_POS(left));
        CMCNPRB_NODE_PARENT_POS(right) = node_pos;
    }
    CMCNPRB_NODE_RIGHT_POS(left) = node_pos;

    if (CMCNPRB_ERR_POS != (CMCNPRB_NODE_PARENT_POS(left) = CMCNPRB_NODE_PARENT_POS(node)))
    {
        CMCNPRB_NODE *parent;
        parent = CMCNPRB_POOL_NODE(pool, CMCNPRB_NODE_PARENT_POS(node));

        if (node_pos == CMCNPRB_NODE_RIGHT_POS(parent))
        {
            CMCNPRB_NODE_RIGHT_POS(parent) = left_pos;
        }
        else
        {
            CMCNPRB_NODE_LEFT_POS(parent) = left_pos;
        }
    }
    else
    {
        (*root_pos) = left_pos;
    }
    CMCNPRB_NODE_PARENT_POS(node) = left_pos;
    return;
}

STATIC_CAST static void __cmcnprb_tree_insert_color(CMCNPRB_POOL *pool, const uint32_t node_pos, uint32_t *root_pos)
{
    CMCNPRB_NODE *node;
    CMCNPRB_NODE *root;
    CMCNPRB_NODE *parent;

    uint32_t  node_pos_t;

    node_pos_t = node_pos;
    node  = CMCNPRB_POOL_NODE(pool, node_pos_t);

    while (NULL_PTR != (parent = CMCNPRB_POOL_NODE(pool, CMCNPRB_NODE_PARENT_POS(node))) /*parent is valid*/
         && CMCNPRB_RED == CMCNPRB_NODE_COLOR(parent))
    {
        uint32_t  parent_pos;
        uint32_t  gparent_pos;
        CMCNPRB_NODE *gparent;

        parent_pos = CMCNPRB_NODE_PARENT_POS(node);

        gparent_pos = CMCNPRB_NODE_PARENT_POS(parent);
        CMCNPRB_ASSERT(CMCNPRB_ERR_POS != gparent_pos);
        gparent = CMCNPRB_POOL_NODE(pool, gparent_pos);

        if (parent_pos == CMCNPRB_NODE_LEFT_POS(gparent))
        {
            {
                CMCNPRB_NODE *uncle;
                if (NULL_PTR != (uncle = CMCNPRB_POOL_NODE(pool, CMCNPRB_NODE_RIGHT_POS(gparent))) /*uncle is valid*/
                   && CMCNPRB_RED == CMCNPRB_NODE_COLOR(uncle))
                {
                    CMCNPRB_NODE_COLOR(uncle)   = CMCNPRB_BLACK;
                    CMCNPRB_NODE_COLOR(parent)  = CMCNPRB_BLACK;
                    CMCNPRB_NODE_COLOR(gparent) = CMCNPRB_RED;

                    node = gparent;
                    node_pos_t = gparent_pos;
                    continue;
                }
            }

            if (CMCNPRB_NODE_RIGHT_POS(parent) == node_pos_t)
            {
                __cmcnprb_tree_rotate_left(pool, parent_pos, root_pos);
                XCHG(CMCNPRB_NODE *, parent, node);
                XCHG(uint32_t, parent_pos, node_pos_t);
            }

            CMCNPRB_NODE_COLOR(parent)  = CMCNPRB_BLACK;
            CMCNPRB_NODE_COLOR(gparent) = CMCNPRB_RED;
            __cmcnprb_tree_rotate_right(pool, gparent_pos, root_pos);
         }
         else
         {
            {
                CMCNPRB_NODE *uncle;
                if (NULL_PTR != (uncle = CMCNPRB_POOL_NODE(pool, CMCNPRB_NODE_LEFT_POS(gparent))) /*uncle is valid*/
                    && CMCNPRB_RED == CMCNPRB_NODE_COLOR(uncle))
                {
                    CMCNPRB_NODE_COLOR(uncle)   = CMCNPRB_BLACK;
                    CMCNPRB_NODE_COLOR(parent)  = CMCNPRB_BLACK;
                    CMCNPRB_NODE_COLOR(gparent) = CMCNPRB_RED;

                    node = gparent;
                    node_pos_t = gparent_pos;
                    continue;
                }
            }

            if (CMCNPRB_NODE_LEFT_POS(parent) == node_pos_t)
            {
                __cmcnprb_tree_rotate_right(pool, parent_pos, root_pos);
                XCHG(CMCNPRB_NODE *, parent, node);
                XCHG(uint32_t, parent_pos, node_pos_t);
            }

            CMCNPRB_NODE_COLOR(parent)  = CMCNPRB_BLACK;
            CMCNPRB_NODE_COLOR(gparent) = CMCNPRB_RED;
            __cmcnprb_tree_rotate_left(pool, gparent_pos, root_pos);
        }
    }

    root = CMCNPRB_POOL_NODE(pool, *root_pos);
    CMCNPRB_NODE_COLOR(root) = CMCNPRB_BLACK;
    return;
}

STATIC_CAST static void __cmcnprb_tree_erase_color(CMCNPRB_POOL *pool, const uint32_t node_pos, const uint32_t parent_pos, uint32_t *root_pos)
{
    CMCNPRB_NODE *node;
    uint32_t  node_pos_t;
    uint32_t  parent_pos_t;

    node_pos_t   = node_pos;
    parent_pos_t = parent_pos;

    while ((NULL_PTR == (node = CMCNPRB_POOL_NODE(pool, node_pos_t)) || CMCNPRB_BLACK == CMCNPRB_NODE_COLOR(node)) && node_pos_t != (*root_pos))
    {
        CMCNPRB_NODE *parent;

        parent = CMCNPRB_POOL_NODE(pool, parent_pos_t);

        if (CMCNPRB_NODE_LEFT_POS(parent) == node_pos_t)
        {
            CMCNPRB_NODE *other;
            CMCNPRB_NODE *o_left;
            CMCNPRB_NODE *o_right;
            uint32_t  other_pos;

            other_pos = CMCNPRB_NODE_RIGHT_POS(parent);
            other = CMCNPRB_POOL_NODE(pool, other_pos);

            if (CMCNPRB_RED == CMCNPRB_NODE_COLOR(other))
            {
                CMCNPRB_NODE_COLOR(other)  = CMCNPRB_BLACK;
                CMCNPRB_NODE_COLOR(parent) = CMCNPRB_RED;

                __cmcnprb_tree_rotate_left(pool, parent_pos_t, root_pos);

                other_pos = CMCNPRB_NODE_RIGHT_POS(parent);
                other = CMCNPRB_POOL_NODE(pool, other_pos);
            }

            o_left = CMCNPRB_POOL_NODE(pool, CMCNPRB_NODE_LEFT_POS(other));
            o_right = CMCNPRB_POOL_NODE(pool, CMCNPRB_NODE_RIGHT_POS(other));

            if((NULL_PTR == o_left || CMCNPRB_BLACK == CMCNPRB_NODE_COLOR(o_left))
            && (NULL_PTR == o_right || CMCNPRB_BLACK == CMCNPRB_NODE_COLOR(o_right)))
            {
                CMCNPRB_NODE_COLOR(other) = CMCNPRB_RED;

                node_pos_t = parent_pos_t;
                node = CMCNPRB_POOL_NODE(pool, node_pos_t);

                parent_pos_t = CMCNPRB_NODE_PARENT_POS(node);
                parent = CMCNPRB_POOL_NODE(pool, parent_pos_t);
            }
            else
            {
                if (NULL_PTR == o_right || CMCNPRB_BLACK == CMCNPRB_NODE_COLOR(o_right))
                {
                    if (NULL_PTR != o_left)
                    {
                        CMCNPRB_NODE_COLOR(o_left) = CMCNPRB_BLACK;
                    }
                    CMCNPRB_NODE_COLOR(other) = CMCNPRB_RED;

                    __cmcnprb_tree_rotate_right(pool, other_pos, root_pos);

                    other_pos = CMCNPRB_NODE_RIGHT_POS(parent);
                    other = CMCNPRB_POOL_NODE(pool, other_pos);
                    /*note: other was changed here*/
                }

                CMCNPRB_NODE_COLOR(other) = CMCNPRB_NODE_COLOR(parent);
                CMCNPRB_NODE_COLOR(parent) = CMCNPRB_BLACK;

                /*due to other may be changed before, have to get o_right again here*/
                o_right = CMCNPRB_POOL_NODE(pool, CMCNPRB_NODE_RIGHT_POS(other));
                if (NULL_PTR != o_right)
                {
                    CMCNPRB_NODE_COLOR(o_right) = CMCNPRB_BLACK;
                }

                __cmcnprb_tree_rotate_left(pool, parent_pos_t, root_pos);
                node_pos_t = (*root_pos);
                break;
            }
        }
        else
        {
            CMCNPRB_NODE *other;
            CMCNPRB_NODE *o_left;
            CMCNPRB_NODE *o_right;
            uint32_t  other_pos;

            other_pos = CMCNPRB_NODE_LEFT_POS(parent);
            other = CMCNPRB_POOL_NODE(pool, other_pos);

            if (CMCNPRB_RED == CMCNPRB_NODE_COLOR(other))
            {
                CMCNPRB_NODE_COLOR(other) = CMCNPRB_BLACK;
                CMCNPRB_NODE_COLOR(parent) = CMCNPRB_RED;

                __cmcnprb_tree_rotate_right(pool, parent_pos_t, root_pos);

                other_pos = CMCNPRB_NODE_LEFT_POS(parent);
                other = CMCNPRB_POOL_NODE(pool, other_pos);
            }

            o_left = CMCNPRB_POOL_NODE(pool, CMCNPRB_NODE_LEFT_POS(other));
            o_right = CMCNPRB_POOL_NODE(pool, CMCNPRB_NODE_RIGHT_POS(other));

            if ((NULL_PTR == o_left  || CMCNPRB_BLACK == CMCNPRB_NODE_COLOR(o_left))
             && (NULL_PTR == o_right || CMCNPRB_BLACK == CMCNPRB_NODE_COLOR(o_right)))
            {
                CMCNPRB_NODE_COLOR(other) = CMCNPRB_RED;

                node_pos_t = parent_pos_t;
                node = CMCNPRB_POOL_NODE(pool, node_pos_t);

                parent_pos_t = CMCNPRB_NODE_PARENT_POS(node);
                parent = CMCNPRB_POOL_NODE(pool, parent_pos_t);
            }
            else
            {
                if (NULL_PTR == o_left  || CMCNPRB_BLACK == CMCNPRB_NODE_COLOR(o_left))
                {
                    if (NULL_PTR != o_right)
                    {
                        CMCNPRB_NODE_COLOR(o_right) = CMCNPRB_BLACK;
                    }

                    CMCNPRB_NODE_COLOR(other) = CMCNPRB_RED;

                    __cmcnprb_tree_rotate_left(pool, other_pos, root_pos);

                    other_pos = CMCNPRB_NODE_LEFT_POS(parent);
                    other = CMCNPRB_POOL_NODE(pool, other_pos);
                    /*note: other was changed here*/
                }

                CMCNPRB_NODE_COLOR(other) = CMCNPRB_NODE_COLOR(parent);
                CMCNPRB_NODE_COLOR(parent) = CMCNPRB_BLACK;

                /*due to other may be changed before, have to get o_left again here*/
                o_left = CMCNPRB_POOL_NODE(pool, CMCNPRB_NODE_LEFT_POS(other));
                if (NULL_PTR != o_left)
                {
                    CMCNPRB_NODE_COLOR(o_left) = CMCNPRB_BLACK;
                }
                __cmcnprb_tree_rotate_right(pool, parent_pos_t, root_pos);
                node_pos_t = (*root_pos);
                break;
            }
        }
    }

    node = CMCNPRB_POOL_NODE(pool, node_pos_t);
    if (NULL_PTR != node)
    {
        CMCNPRB_NODE_COLOR(node) = CMCNPRB_BLACK;
    }
    return;
}

/*note: erase from tree but not recycle to free nodes pool*/
EC_BOOL cmcnprb_tree_erase(CMCNPRB_POOL *pool, const uint32_t node_pos, uint32_t *root_pos)
{
    CMCNPRB_NODE *node;

    uint32_t node_pos_t;
    uint32_t child_pos;
    uint32_t parent_pos;
    uint32_t color;

    node_pos_t = node_pos;
    node = CMCNPRB_POOL_NODE(pool, node_pos_t);

    CMCNPRB_ASSERT(NULL_PTR != node);
    CMCNPRB_ASSERT(CMCNPRB_NODE_IS_USED(node));

    if (CMCNPRB_ERR_POS == CMCNPRB_NODE_LEFT_POS(node))
    {
        child_pos = CMCNPRB_NODE_RIGHT_POS(node);
    }
    else if (CMCNPRB_ERR_POS == CMCNPRB_NODE_RIGHT_POS(node))
    {
        child_pos = CMCNPRB_NODE_LEFT_POS(node);
    }
    else
    {
        CMCNPRB_NODE *old;

        uint32_t old_pos;
        uint32_t left_pos;

        old_pos = node_pos_t;

        node_pos_t = CMCNPRB_NODE_RIGHT_POS(node);
        node = CMCNPRB_POOL_NODE(pool, node_pos_t);

        while (CMCNPRB_ERR_POS != (left_pos = CMCNPRB_NODE_LEFT_POS(node)))
        {
            node_pos_t = left_pos;
            node = CMCNPRB_POOL_NODE(pool, node_pos_t);

        }

        child_pos  = CMCNPRB_NODE_RIGHT_POS(node);
        parent_pos = CMCNPRB_NODE_PARENT_POS(node);
        color      = CMCNPRB_NODE_COLOR(node);

        if (CMCNPRB_ERR_POS != child_pos)
        {
            CMCNPRB_NODE *child;
            child = CMCNPRB_POOL_NODE(pool, child_pos);
            CMCNPRB_NODE_PARENT_POS(child) = parent_pos;
        }

        if (CMCNPRB_ERR_POS != parent_pos)
        {
            CMCNPRB_NODE *parent;

            parent = CMCNPRB_POOL_NODE(pool, parent_pos);
            if (CMCNPRB_NODE_LEFT_POS(parent) == node_pos_t)
            {
                CMCNPRB_NODE_LEFT_POS(parent) = child_pos;
            }
            else
            {
                CMCNPRB_NODE_RIGHT_POS(parent) = child_pos;
            }
        }
        else
        {
            (*root_pos) = child_pos;
        }

        if (CMCNPRB_NODE_PARENT_POS(node) == old_pos)
        {
            parent_pos = node_pos_t;
        }

        old  = CMCNPRB_POOL_NODE(pool, old_pos);

        CMCNPRB_NODE_PARENT_POS(node) = CMCNPRB_NODE_PARENT_POS(old);
        CMCNPRB_NODE_COLOR(node)      = CMCNPRB_NODE_COLOR(old);
        CMCNPRB_NODE_RIGHT_POS(node)  = CMCNPRB_NODE_RIGHT_POS(old);
        CMCNPRB_NODE_LEFT_POS(node)   = CMCNPRB_NODE_LEFT_POS(old);

        if (CMCNPRB_ERR_POS != CMCNPRB_NODE_PARENT_POS(old))
        {
            CMCNPRB_NODE *old_parent;
            old_parent = CMCNPRB_POOL_NODE(pool, CMCNPRB_NODE_PARENT_POS(old));

            if (CMCNPRB_NODE_LEFT_POS(old_parent) == old_pos)
            {
                CMCNPRB_NODE_LEFT_POS(old_parent) = node_pos_t;
            }
            else
            {
                CMCNPRB_NODE_RIGHT_POS(old_parent) = node_pos_t;
            }
        }
        else
        {
            (*root_pos) = node_pos_t;
        }

        {
            CMCNPRB_NODE *old_left;

            old_left = CMCNPRB_POOL_NODE(pool, CMCNPRB_NODE_LEFT_POS(old));
            CMCNPRB_NODE_PARENT_POS(old_left) = node_pos_t;
        }

        if (CMCNPRB_ERR_POS != CMCNPRB_NODE_RIGHT_POS(old))
        {
            CMCNPRB_NODE *old_right;
            old_right = CMCNPRB_POOL_NODE(pool, CMCNPRB_NODE_RIGHT_POS(old));
            CMCNPRB_NODE_PARENT_POS(old_right) = node_pos_t;
        }
        goto color;
    }

    parent_pos = CMCNPRB_NODE_PARENT_POS(node);
    color = CMCNPRB_NODE_COLOR(node);

    if (CMCNPRB_ERR_POS != child_pos)
    {
        CMCNPRB_NODE *child;
        child = CMCNPRB_POOL_NODE(pool, child_pos);
        CMCNPRB_NODE_PARENT_POS(child) = parent_pos;
    }

    if (CMCNPRB_ERR_POS != parent_pos)
    {
        CMCNPRB_NODE *parent;

        parent = CMCNPRB_POOL_NODE(pool, parent_pos);
        if (CMCNPRB_NODE_LEFT_POS(parent) == node_pos_t)
        {
            CMCNPRB_NODE_LEFT_POS(parent) = child_pos;
        }
        else
        {
            CMCNPRB_NODE_RIGHT_POS(parent) = child_pos;
        }
    }
    else
    {
        (*root_pos) = child_pos;
    }

 color:
    if (CMCNPRB_BLACK == color)
    {
        __cmcnprb_tree_erase_color(pool, child_pos, parent_pos, root_pos);
    }
    return (EC_TRUE);
}

STATIC_CAST static uint32_t __cmcnprb_tree_count_node_num(const CMCNPRB_POOL *pool, const uint32_t node_pos)
{
    const CMCNPRB_NODE *node;

    if(CMCNPRB_ERR_POS == node_pos)
    {
        return ((uint32_t)0);
    }

    node = CMCNPRB_POOL_NODE(pool, node_pos);

    return (uint32_t)(1 + __cmcnprb_tree_count_node_num(pool, CMCNPRB_NODE_LEFT_POS(node)) + __cmcnprb_tree_count_node_num(pool, CMCNPRB_NODE_RIGHT_POS(node)));
}

uint32_t cmcnprb_tree_count_node_num(const CMCNPRB_POOL *pool, const uint32_t root_pos)
{
    return __cmcnprb_tree_count_node_num(pool, root_pos);
}

uint32_t cmcnprb_tree_node_max_num(const CMCNPRB_POOL *pool)
{
    return CMCNPRB_POOL_NODE_MAX_NUM(pool);
}

uint32_t cmcnprb_tree_node_used_num(const CMCNPRB_POOL *pool)
{
    return CMCNPRB_POOL_NODE_USED_NUM(pool);
}

uint32_t cmcnprb_tree_node_sizeof(const CMCNPRB_POOL *pool)
{
    return CMCNPRB_POOL_NODE_SIZEOF(pool);
}

/*
 * This function returns the first node_pos (in sort order) of the tree.
 */
uint32_t cmcnprb_tree_first_node(const CMCNPRB_POOL *pool, const uint32_t root_pos)
{
    uint32_t  node_pos;
    const CMCNPRB_NODE *node;

    node_pos = root_pos;
    if (CMCNPRB_ERR_POS == node_pos)
    {
        return (CMCNPRB_ERR_POS);
    }

    node = CMCNPRB_POOL_NODE(pool, node_pos);

    while (CMCNPRB_ERR_POS != CMCNPRB_NODE_LEFT_POS(node))
    {
        node_pos = CMCNPRB_NODE_LEFT_POS(node);
        node = CMCNPRB_POOL_NODE(pool, node_pos);
    }
    return (node_pos);
}

uint32_t cmcnprb_tree_last_node(const CMCNPRB_POOL *pool, const uint32_t root_pos)
{
    uint32_t  node_pos;
    const CMCNPRB_NODE *node;

    node_pos = root_pos;
    if (CMCNPRB_ERR_POS == node_pos)
    {
        return (CMCNPRB_ERR_POS);
    }

    node = CMCNPRB_POOL_NODE(pool, node_pos);

    while (CMCNPRB_ERR_POS != CMCNPRB_NODE_RIGHT_POS(node))
    {
        node_pos = CMCNPRB_NODE_RIGHT_POS(node);
        node = CMCNPRB_POOL_NODE(pool, node_pos);
    }

    return (node_pos);
}

uint32_t cmcnprb_tree_next_node(const CMCNPRB_POOL *pool, const uint32_t node_pos)
{
    uint32_t node_pos_t;
    const CMCNPRB_NODE *node;
    const CMCNPRB_NODE *parent;

    node_pos_t = node_pos;
    node = CMCNPRB_POOL_NODE(pool, node_pos_t);
    /* If we have a right-hand child, go down and then left as far
       as we can. */
    if (CMCNPRB_ERR_POS != CMCNPRB_NODE_RIGHT_POS(node))
    {
        node_pos_t = CMCNPRB_NODE_RIGHT_POS(node);
        node = CMCNPRB_POOL_NODE(pool, node_pos_t);
        while (CMCNPRB_ERR_POS != CMCNPRB_NODE_LEFT_POS(node))
        {
            node_pos_t = CMCNPRB_NODE_LEFT_POS(node);
            node = CMCNPRB_POOL_NODE(pool, node_pos_t);
        }
        return (node_pos_t);
    }

    /* No right-hand children.  Everything down and left is
       smaller than us, so any 'next' node_pos_t must be in the general
       direction of our parent. Go up the tree; any time the
       ancestor is a right-hand child of its parent, keep going
       up. First time it's a left-hand child of its parent, said
       parent is our 'next' node_pos_t. */
    while (NULL_PTR != (parent = CMCNPRB_POOL_NODE(pool, CMCNPRB_NODE_PARENT_POS(node))) && node_pos_t == CMCNPRB_NODE_RIGHT_POS(parent))
    {
        node_pos_t = CMCNPRB_NODE_PARENT_POS(node);
        node = parent;
    }

    return (CMCNPRB_NODE_PARENT_POS(node));
}

uint32_t cmcnprb_tree_prev_node(const CMCNPRB_POOL *pool, const uint32_t node_pos)
{
    uint32_t node_pos_t;
    const CMCNPRB_NODE *node;
    const CMCNPRB_NODE *parent;

    node_pos_t = node_pos;
    node = CMCNPRB_POOL_NODE(pool, node_pos_t);

    /* If we have a left-hand child, go down and then right as far
       as we can. */
    if (CMCNPRB_ERR_POS != CMCNPRB_NODE_LEFT_POS(node))
    {
        node_pos_t = CMCNPRB_NODE_LEFT_POS(node);
        node = CMCNPRB_POOL_NODE(pool, node_pos_t);
        while (CMCNPRB_ERR_POS != CMCNPRB_NODE_RIGHT_POS(node))
        {
            node_pos_t = CMCNPRB_NODE_RIGHT_POS(node);
            node = CMCNPRB_POOL_NODE(pool, node_pos_t);
        }
        return (node_pos_t);
    }

    /* No left-hand children. Go up till we find an ancestor which
       is a right-hand child of its parent */
    while (NULL_PTR != (parent = CMCNPRB_POOL_NODE(pool, CMCNPRB_NODE_PARENT_POS(node))) && node_pos_t == CMCNPRB_NODE_LEFT_POS(parent))
    {
        node_pos_t = CMCNPRB_NODE_PARENT_POS(node);
        node = parent;
    }

    return (CMCNPRB_NODE_PARENT_POS(node));
}

/**
*
*   note:only for cmcnp item!
*   node key : [s1, e1)
*   cmcnp key: [s2, e2)
*
*   return -1 if s2 < s1
*   return  1 if s2 >= e1
*   return  0 if s1 <= s2 < e1
*
*   note: s_page_in means s_page of cmcnp_key falls into node key
*
**/
STATIC_CAST static int __cmcnprb_node_data_cmp__s_page_in(const CMCNPRB_NODE *node, const CMCNP_KEY *cmcnp_key)
{
    const CMCNP_ITEM *item;
    const CMCNP_KEY  *key;

    item = (const CMCNP_ITEM *)CMCNP_RB_NODE_ITEM(node);
    key  = CMCNP_ITEM_KEY(item);

    if(CMCNP_KEY_S_PAGE(cmcnp_key) < CMCNP_KEY_S_PAGE(key))
    {
        dbg_log(SEC_0113_CMCNPRB, 9)(LOGSTDOUT, "[DEBUG] __cmcnprb_node_data_cmp__s_page_in: "
                                                "node  key: [%u, %u), cmcnp key: [%u, %u) => -1\n",
                                                CMCNP_KEY_S_PAGE(key), CMCNP_KEY_E_PAGE(key),
                                                CMCNP_KEY_S_PAGE(cmcnp_key), CMCNP_KEY_E_PAGE(cmcnp_key));

        return (-1);
    }

    if(CMCNP_KEY_S_PAGE(cmcnp_key) >= CMCNP_KEY_E_PAGE(key))
    {
        dbg_log(SEC_0113_CMCNPRB, 9)(LOGSTDOUT, "[DEBUG] __cmcnprb_node_data_cmp__s_page_in: "
                                                "node  key: [%u, %u), cmcnp key: [%u, %u) => 1\n",
                                                CMCNP_KEY_S_PAGE(key), CMCNP_KEY_E_PAGE(key),
                                                CMCNP_KEY_S_PAGE(cmcnp_key), CMCNP_KEY_E_PAGE(cmcnp_key));
        return (1);
    }

    dbg_log(SEC_0113_CMCNPRB, 9)(LOGSTDOUT, "[DEBUG] __cmcnprb_node_data_cmp__s_page_in: "
                                            "node  key: [%u, %u), cmcnp key: [%u, %u) => 0\n",
                                            CMCNP_KEY_S_PAGE(key), CMCNP_KEY_E_PAGE(key),
                                            CMCNP_KEY_S_PAGE(cmcnp_key), CMCNP_KEY_E_PAGE(cmcnp_key));

    return (0);
}

/**
*
*   note:only for cmcnp item!
*   node key : [s1, e1)
*   cmcnp key: [s2, e2)
*
*   return -1 if e2 <= s1
*   return  1 if e2 > e1
*   return  0 if s1 < e2 <= e1
*
*   note: e_page_in means e_page of cmcnp_key falls into node key
*
**/
STATIC_CAST static int __cmcnprb_node_data_cmp__e_page_in(const CMCNPRB_NODE *node, const CMCNP_KEY *cmcnp_key)
{
    const CMCNP_ITEM *item;
    const CMCNP_KEY  *key;

    item = (const CMCNP_ITEM *)CMCNP_RB_NODE_ITEM(node);
    key  = CMCNP_ITEM_KEY(item);

    if(CMCNP_KEY_E_PAGE(cmcnp_key) <= CMCNP_KEY_S_PAGE(key))
    {
        return (-1);
    }

    if(CMCNP_KEY_E_PAGE(cmcnp_key) >  CMCNP_KEY_E_PAGE(key))
    {
        return (1);
    }

    return (0);
}

/**
*
*   note:only for cmcnp item!
*   node key : [s1, e1)
*   cmcnp key: [s2, e2)
*
*   return -1 if s2 < s1
*   return  1 if s2 >= e1
*   return  0 if s1 <= s2 < e1
*
*   note: s_page_closest means s_page of cmcnp_key is the closest to which node on left side
*
**/
//TODO:
STATIC_CAST static int __cmcnprb_node_data_cmp__s_page_closest(const CMCNPRB_NODE *node, const CMCNP_KEY *cmcnp_key)
{
    const CMCNP_ITEM *item;
    const CMCNP_KEY  *key;

    item = (const CMCNP_ITEM *)CMCNP_RB_NODE_ITEM(node);
    key  = CMCNP_ITEM_KEY(item);

    if(CMCNP_KEY_S_PAGE(cmcnp_key) < CMCNP_KEY_S_PAGE(key))
    {
        return (-1);
    }

    if(CMCNP_KEY_S_PAGE(cmcnp_key) >= CMCNP_KEY_E_PAGE(key))
    {
        return (1);
    }

    return (0);
}

/**
*
*   note:only for cmcnp item!
*   node key : [s1, e1)
*   cmcnp key: [s2, e2)
*
*   return -1 if e2 <= s1
*   return  1 if s2 >= e1
*   return  0 if e2 > s1 && s2 < e1
*
*   note: page_intersection means cmcnp_key and node has intersection
*
**/
STATIC_CAST static int __cmcnprb_node_data_cmp__page_intersection(const CMCNPRB_NODE *node, const CMCNP_KEY *cmcnp_key)
{
    const CMCNP_ITEM *item;
    const CMCNP_KEY  *key;

    item = (const CMCNP_ITEM *)CMCNP_RB_NODE_ITEM(node);
    key  = CMCNP_ITEM_KEY(item);

    if(CMCNP_KEY_E_PAGE(cmcnp_key) <= CMCNP_KEY_S_PAGE(key))
    {
        return (-1);
    }

    if(CMCNP_KEY_S_PAGE(cmcnp_key) >= CMCNP_KEY_E_PAGE(key))
    {
        return (1);
    }

    return (0);
}

/*return the intersected pos*/
uint32_t cmcnprb_tree_find_intersected_data(const CMCNPRB_POOL *pool, const uint32_t root_pos, const void *cmcnp_key)
{
    uint32_t node_pos;

    node_pos = root_pos;

    while (CMCNPRB_ERR_POS != node_pos)
    {
        const CMCNPRB_NODE *node;
        int cmp_ret;

        node = CMCNPRB_POOL_NODE(pool, node_pos);
        cmp_ret = __cmcnprb_node_data_cmp__page_intersection(node, (const CMCNP_KEY *)cmcnp_key);

        if (0 < cmp_ret)/*node(s_page, e_page) > key(s_page, e_page)*/
        {
            node_pos = CMCNPRB_NODE_LEFT_POS(node);
        }
        else if (0 > cmp_ret)/*node(s_page, e_page) < key(s_page, e_page)*/
        {
            node_pos = CMCNPRB_NODE_RIGHT_POS(node);
        }
        else /*node(s_page, e_page) == key(s_page, e_page)*/
        {
            return (node_pos);
        }
    }

    return (CMCNPRB_ERR_POS);
}

/*return the closest pos*/
uint32_t cmcnprb_tree_find_closest_data(const CMCNPRB_POOL *pool, const uint32_t root_pos, const void *cmcnp_key)
{
    uint32_t node_pos;
    uint32_t diff_closest_page;
    uint32_t node_closest_pos;

    diff_closest_page = ((uint32_t)~0);
    node_closest_pos  = CMCNPRB_ERR_POS;

    node_pos = root_pos;

    while (CMCNPRB_ERR_POS != node_pos)
    {
        const CMCNPRB_NODE *node;
        int cmp_ret;

        node = CMCNPRB_POOL_NODE(pool, node_pos);
        cmp_ret = __cmcnprb_node_data_cmp__s_page_closest(node, (const CMCNP_KEY *)cmcnp_key);

        if (0 < cmp_ret)/*node(s_page, e_page) > key(s_page, e_page)*/
        {
            node_pos = CMCNPRB_NODE_LEFT_POS(node);
        }
        else if (0 > cmp_ret)/*node(s_page, e_page) < key(s_page, e_page)*/
        {
            const CMCNP_ITEM *item;
            const CMCNP_KEY  *key;

            uint32_t diff_page;

            item = (const CMCNP_ITEM *)CMCNP_RB_NODE_ITEM(node);
            key  = CMCNP_ITEM_KEY(item);

            diff_page = CMCNP_KEY_S_PAGE(key) - CMCNP_KEY_S_PAGE((const CMCNP_KEY *)cmcnp_key);
            if(diff_closest_page > diff_page)
            {
                diff_closest_page = diff_page;
                node_closest_pos  = node_pos;
            }

            node_pos = CMCNPRB_NODE_RIGHT_POS(node);
        }
        else /*node(s_page, e_page) == key(s_page, e_page)*/
        {
            return (node_pos);
        }
    }

    return (node_closest_pos);
}

/*return the searched pos*/
uint32_t cmcnprb_tree_search_data(const CMCNPRB_POOL *pool, const uint32_t root_pos, const void *cmcnp_key)
{
    uint32_t node_pos;

    node_pos = root_pos;

    while (CMCNPRB_ERR_POS != node_pos)
    {
        const CMCNPRB_NODE *node;
        int cmp_ret;

        node = CMCNPRB_POOL_NODE(pool, node_pos);
        cmp_ret = __cmcnprb_node_data_cmp__s_page_in(node, (const CMCNP_KEY *)cmcnp_key);

        if (0 < cmp_ret)/*node(s_page, e_page) > key(s_page, e_page)*/
        {
            node_pos = CMCNPRB_NODE_LEFT_POS(node);
        }
        else if (0 > cmp_ret)/*node(s_page, e_page) < key(s_page, e_page)*/
        {
            node_pos = CMCNPRB_NODE_RIGHT_POS(node);
        }
        else /*node(s_page, e_page) == key(s_page, e_page)*/
        {
            return (node_pos);
        }
    }

    return (CMCNPRB_ERR_POS);
}

/*if found duplicate node, return EC_FALSE, otherwise return EC_TRUE*/
EC_BOOL cmcnprb_tree_insert_data(CMCNPRB_POOL *pool, uint32_t *root_pos, const void *cmcnp_key, uint32_t *insert_pos)
{
    uint32_t  node_pos_t;
    uint32_t  new_pos_t;
    uint32_t  parent_pos_t;
    uint32_t  flag; /*0: on left subtree, 1: on right subtree*/

    node_pos_t   = (*root_pos);
    parent_pos_t = CMCNPRB_ERR_POS;
    flag         = ~(uint32_t)0;

    while (CMCNPRB_ERR_POS != node_pos_t)
    {
        CMCNPRB_NODE *node;
        int cmp_ret;

        node = CMCNPRB_POOL_NODE(pool, node_pos_t);
        cmp_ret = __cmcnprb_node_data_cmp__s_page_in(node, (const CMCNP_KEY *)cmcnp_key);

        parent_pos_t = node_pos_t;

        if (0 < cmp_ret)/*node(s_page, e_page) > key(s_page, e_page)*/
        {
            node_pos_t = CMCNPRB_NODE_LEFT_POS(node);
            flag = 0;
        }
        else if (0 > cmp_ret)/*node(s_page, e_page) < key(s_page, e_page)*/
        {
            node_pos_t = CMCNPRB_NODE_RIGHT_POS(node);
            flag = 1;
        }
        else/*node(s_page, e_page) == key(s_page, e_page)*/
        {
            (*insert_pos) = node_pos_t;
            return (EC_FALSE);/*found duplicate*/
        }
    }


    /*not found data in the rbtree*/
    new_pos_t = cmcnprb_node_new(pool);
    if(CMCNPRB_ERR_POS == new_pos_t)
    {
        (*insert_pos) = CMCNPRB_ERR_POS;
        return (EC_FALSE);
    }
    else
    {
        CMCNPRB_NODE *node;

        node  = CMCNPRB_POOL_NODE(pool, new_pos_t);
        //CMCNPRB_NODE_DATA(node) = block_no;

        CMCNPRB_NODE_PARENT_POS(node) = parent_pos_t;
        CMCNPRB_NODE_COLOR(node)      = CMCNPRB_RED;
        CMCNPRB_NODE_LEFT_POS(node)   = CMCNPRB_ERR_POS;
        CMCNPRB_NODE_RIGHT_POS(node)  = CMCNPRB_ERR_POS;

        if(CMCNPRB_ERR_POS == (*root_pos))
        {
            (*root_pos) = new_pos_t;
        }
        else
        {
            CMCNPRB_NODE *parent;
            parent  = CMCNPRB_POOL_NODE(pool, parent_pos_t);

            if(0 == flag)/*on left subtree*/
            {
                CMCNPRB_NODE_LEFT_POS(parent) = new_pos_t;
            }
            else
            {
                CMCNPRB_NODE_RIGHT_POS(parent) = new_pos_t;
            }
        }
        __cmcnprb_tree_insert_color(pool, new_pos_t, root_pos);
    }

    (*insert_pos) = new_pos_t;
    return (EC_TRUE); /*it is new node*/
}

EC_BOOL cmcnprb_tree_delete_data(CMCNPRB_POOL *pool, uint32_t *root_pos, const void *cmcnp_key, uint32_t *delete_pos)
{
    uint32_t node_pos;

    node_pos = cmcnprb_tree_search_data(pool, *root_pos, cmcnp_key);
    if(CMCNPRB_ERR_POS == node_pos)
    {
        return (EC_FALSE);
    }

    cmcnprb_tree_erase(pool, node_pos, root_pos);
    cmcnprb_node_free(pool, node_pos);

    (*delete_pos) = node_pos;
    return (EC_TRUE);
}


EC_BOOL cmcnprb_tree_delete(CMCNPRB_POOL *pool, uint32_t *root_pos, const uint32_t node_pos)
{
    cmcnprb_tree_erase(pool, node_pos, root_pos);
    cmcnprb_node_free(pool, node_pos);
    return (EC_TRUE);
}


/*postorder: left -> right -> root*/
STATIC_CAST static void __cmcnprb_tree_free(CMCNPRB_POOL *pool, const uint32_t node_pos)
{
    CMCNPRB_NODE *node;

    if(CMCNPRB_ERR_POS == node_pos)
    {
        return;
    }

    node  = CMCNPRB_POOL_NODE(pool, node_pos);
    if(CMCNPRB_ERR_POS != CMCNPRB_NODE_LEFT_POS(node))
    {
        __cmcnprb_tree_free(pool, CMCNPRB_NODE_LEFT_POS(node));
    }

    if(CMCNPRB_ERR_POS != CMCNPRB_NODE_RIGHT_POS(node))
    {
        __cmcnprb_tree_free(pool, CMCNPRB_NODE_RIGHT_POS(node));
    }

    cmcnprb_node_free(pool, node_pos);

    return;
}
void cmcnprb_tree_free(CMCNPRB_POOL *pool, const uint32_t root_pos)
{
    __cmcnprb_tree_free(pool, root_pos);
    return;
}

EC_BOOL cmcnprb_pool_init(CMCNPRB_POOL *pool, const uint32_t node_max_num, const uint32_t node_sizeof)
{
    uint32_t node_pos;

    if(CMCNPRB_POOL_MAX_SIZE < node_max_num)
    {
        dbg_log(SEC_0113_CMCNPRB, 0)(LOGSTDERR, "error:cmcnprb_pool_init: node_max_num %u overflow!\n", node_max_num);
        return (EC_FALSE);
    }

    CMCNPRB_POOL_NODE_MAX_NUM(pool)  = node_max_num;
    CMCNPRB_POOL_NODE_USED_NUM(pool) = 0;
    CMCNPRB_POOL_NODE_SIZEOF(pool)   = node_sizeof;

    for(node_pos = 0; node_pos < node_max_num; node_pos ++)
    {
        cmcnprb_node_init(pool, node_pos);
        cmcnprb_node_set_next(pool, node_pos, node_pos + 1);

        if(0 == ((node_pos + 1) % 100000))
        {
            dbg_log(SEC_0113_CMCNPRB, 9)(LOGSTDOUT, "info:cmcnprb_pool_init: init node %u - %u of max %u done\n",
                               node_pos - 99999, node_pos, node_max_num);
        }
    }
    dbg_log(SEC_0113_CMCNPRB, 0)(LOGSTDOUT, "info:cmcnprb_pool_init: init %u nodes done\n", node_max_num);
    cmcnprb_node_set_next(pool, node_max_num - 1, CMCNPRB_ERR_POS);/*overwrite the last one*/

    CMCNPRB_POOL_FREE_HEAD(pool) = 0;/*the free nodes head*/
    return (EC_TRUE);
}

void cmcnprb_pool_clean(CMCNPRB_POOL *pool)
{
    CMCNPRB_POOL_NODE_MAX_NUM(pool)  = 0;
    CMCNPRB_POOL_FREE_HEAD(pool)     = CMCNPRB_ERR_POS;
    return;
}

void cmcnprb_pool_print(LOG *log, const CMCNPRB_POOL *pool)
{
    uint32_t node_pos;
    uint32_t node_max_num;

    node_max_num = CMCNPRB_POOL_NODE_MAX_NUM(pool);

    sys_log(log, "pool %lx, node_max_num %u, node_used_num %u, free_head %u, node_sizeof = %u\n",
                 pool,
                 node_max_num,
                 CMCNPRB_POOL_NODE_USED_NUM(pool),
                 CMCNPRB_POOL_FREE_HEAD(pool),
                 CMCNPRB_POOL_NODE_SIZEOF(pool));

    if(0)
    {
        for(node_pos = 0; node_pos < node_max_num; node_pos ++)
        {
            if(EC_TRUE == cmcnprb_node_is_used(pool, node_pos))
            {
                cmcnprb_node_print(log, pool, node_pos);
            }
        }
    }
    return;
}


EC_BOOL cmcnprb_pool_is_empty(const CMCNPRB_POOL *pool)
{
    if (0 == CMCNPRB_POOL_NODE_USED_NUM(pool))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL cmcnprb_pool_is_full(const CMCNPRB_POOL *pool)
{
    if (CMCNPRB_POOL_NODE_MAX_NUM(pool) == CMCNPRB_POOL_NODE_USED_NUM(pool))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

/*visit the root node first: root -> left -> right*/
void cmcnprb_preorder_print(LOG *log, const CMCNPRB_POOL *pool, const uint32_t node_pos)
{
    const CMCNPRB_NODE *node;

    if(CMCNPRB_ERR_POS == node_pos)
    {
        return;
    }

    node  = CMCNPRB_POOL_NODE(pool, node_pos);
    cmcnprb_node_print(log, pool, node_pos);

    if(CMCNPRB_ERR_POS != CMCNPRB_NODE_LEFT_POS(node))
    {
        cmcnprb_preorder_print(log, pool, CMCNPRB_NODE_LEFT_POS(node));
    }

    if(CMCNPRB_ERR_POS != CMCNPRB_NODE_RIGHT_POS(node))
    {
        cmcnprb_preorder_print(log, pool, CMCNPRB_NODE_RIGHT_POS(node));
    }

    return;
}

/*visit the left subtree, then the root node: left -> root -> right*/
void cmcnprb_inorder_print(LOG *log, const CMCNPRB_POOL *pool, const uint32_t node_pos)
{
    const CMCNPRB_NODE *node;

    if(CMCNPRB_ERR_POS == node_pos)
    {
        return;
    }

    node  = CMCNPRB_POOL_NODE(pool, node_pos);
    if(CMCNPRB_ERR_POS != CMCNPRB_NODE_LEFT_POS(node))
    {
        cmcnprb_inorder_print(log, pool, CMCNPRB_NODE_LEFT_POS(node));
    }

    cmcnprb_node_print(log, pool, node_pos);

    if(CMCNPRB_ERR_POS != CMCNPRB_NODE_RIGHT_POS(node))
    {
        cmcnprb_inorder_print(log, pool, CMCNPRB_NODE_RIGHT_POS(node));
    }

    return;
}

/*visit the root node last: left -> right -> root*/
void cmcnprb_postorder_print(LOG *log, const CMCNPRB_POOL *pool, const uint32_t node_pos)
{
    const CMCNPRB_NODE *node;

    if(CMCNPRB_ERR_POS == node_pos)
    {
        return;
    }

    node  = CMCNPRB_POOL_NODE(pool, node_pos);
    if(CMCNPRB_ERR_POS != CMCNPRB_NODE_LEFT_POS(node))
    {
        cmcnprb_postorder_print(log, pool, CMCNPRB_NODE_LEFT_POS(node));
    }

    if(CMCNPRB_ERR_POS != CMCNPRB_NODE_RIGHT_POS(node))
    {
        cmcnprb_postorder_print(log, pool, CMCNPRB_NODE_RIGHT_POS(node));
    }

    cmcnprb_node_print(log, pool, node_pos);

    return;
}


/*visit the root node first: root -> left -> right*/
void cmcnprb_preorder_print_level(LOG *log, const CMCNPRB_POOL *pool, const uint32_t node_pos, const uint32_t level)
{
    const CMCNPRB_NODE *node;

    if(CMCNPRB_ERR_POS == node_pos)
    {
        return;
    }

    node  = CMCNPRB_POOL_NODE(pool, node_pos);
    cmcnprb_node_print_level(log, pool, node_pos, level);

    if(CMCNPRB_ERR_POS != CMCNPRB_NODE_LEFT_POS(node))
    {
        cmcnprb_preorder_print_level(log, pool, CMCNPRB_NODE_LEFT_POS(node), level + 1);
    }

    if(CMCNPRB_ERR_POS != CMCNPRB_NODE_RIGHT_POS(node))
    {
        cmcnprb_preorder_print_level(log, pool, CMCNPRB_NODE_RIGHT_POS(node), level + 1);
    }

    return;
}

void cmcnprb_inorder_walk(const CMCNPRB_POOL *pool, const uint32_t node_pos, void (*walker)(void *, const void *, const uint32_t), void *arg1, const void *arg2)
{
    const CMCNPRB_NODE *node;

    if(CMCNPRB_ERR_POS == node_pos)
    {
        return;
    }

    node  = CMCNPRB_POOL_NODE(pool, node_pos);
    if(CMCNPRB_ERR_POS != CMCNPRB_NODE_LEFT_POS(node))
    {
        cmcnprb_inorder_walk(pool, CMCNPRB_NODE_LEFT_POS(node), walker, arg1, arg2);
    }

    walker(arg1, arg2, node_pos);

    if(CMCNPRB_ERR_POS != CMCNPRB_NODE_RIGHT_POS(node))
    {
        cmcnprb_inorder_walk(pool, CMCNPRB_NODE_RIGHT_POS(node), walker, arg1, arg2);
    }

    return;
}

EC_BOOL cmcnprb_flush_size(const CMCNPRB_POOL *pool, UINT32 *size)
{
    (*size) += sizeof(CMCNPRB_POOL) + CMCNPRB_POOL_NODE_MAX_NUM(pool) * CMCNPRB_POOL_NODE_SIZEOF(pool);
    return (EC_TRUE);
}

EC_BOOL cmcnprb_flush(const CMCNPRB_POOL *pool, int fd, UINT32 *offset)
{
    UINT32 osize;/*write once size*/

    /*flush free_head*/
    osize = sizeof(uint32_t);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(CMCNPRB_POOL_FREE_HEAD(pool))))
    {
        dbg_log(SEC_0113_CMCNPRB, 0)(LOGSTDOUT, "error:cmcnprb_flush: write CMCNPRB_POOL_FREE_HEAD at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*flush node_max_num*/
    osize  = sizeof(uint32_t);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(CMCNPRB_POOL_NODE_MAX_NUM(pool))))
    {
        dbg_log(SEC_0113_CMCNPRB, 0)(LOGSTDOUT, "error:cmcnprb_flush: write CMCNPRB_POOL_NODE_MAX_NUM at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*flush node_used_num*/
    osize  = sizeof(uint32_t);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(CMCNPRB_POOL_NODE_USED_NUM(pool))))
    {
        dbg_log(SEC_0113_CMCNPRB, 0)(LOGSTDOUT, "error:cmcnprb_flush: write CMCNPRB_POOL_NODE_USED_NUM at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*flush node_sizeof*/
    osize  = sizeof(uint32_t);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(CMCNPRB_POOL_NODE_SIZEOF(pool))))
    {
        dbg_log(SEC_0113_CMCNPRB, 0)(LOGSTDOUT, "error:cmcnprb_flush: write CMCNPRB_POOL_NODE_SIZEOF at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*flush rb_node table*/
    osize  = CMCNPRB_POOL_NODE_MAX_NUM(pool) * CMCNPRB_POOL_NODE_SIZEOF(pool);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)CMCNPRB_POOL_NODE_TBL(pool)))
    {
        dbg_log(SEC_0113_CMCNPRB, 0)(LOGSTDOUT, "error:cmcnprb_flush: write CMCNPRB_POOL_NODE_TBL at offset %ld of fd %d failed where CMCNPRB_POOL_NODE_MAX_NUM is %u\n",
                            (*offset), fd, CMCNPRB_POOL_NODE_MAX_NUM(pool));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cmcnprb_load(CMCNPRB_POOL *pool, int fd, UINT32 *offset)
{
    UINT32 osize;/*read once size*/
    uint32_t node_max_num;
    uint32_t node_used_num;
    uint32_t node_sizeof;

    /*load free_head*/
    osize = sizeof(uint32_t);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(CMCNPRB_POOL_FREE_HEAD(pool))))
    {
        dbg_log(SEC_0113_CMCNPRB, 0)(LOGSTDOUT, "error:cmcnprb_load: load CMCNPRB_POOL_FREE_HEAD at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*load node_max_num*/
    osize  = sizeof(uint32_t);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(node_max_num)))
    {
        dbg_log(SEC_0113_CMCNPRB, 0)(LOGSTDOUT, "error:cmcnprb_load: load CMCNPRB_POOL_NODE_MAX_NUM at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }
    CMCNPRB_POOL_NODE_MAX_NUM(pool) = node_max_num;

    /*load node_used_num*/
    osize  = sizeof(uint32_t);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(node_used_num)))
    {
        dbg_log(SEC_0113_CMCNPRB, 0)(LOGSTDOUT, "error:cmcnprb_load: load CMCNPRB_POOL_NODE_USED_NUM at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }
    CMCNPRB_POOL_NODE_MAX_NUM(pool) = node_used_num;

    /*load node_sizeof*/
    osize  = sizeof(uint32_t);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(node_sizeof)))
    {
        dbg_log(SEC_0113_CMCNPRB, 0)(LOGSTDOUT, "error:cmcnprb_load: load CMCNPRB_POOL_NODE_SIZEOF at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }
    CMCNPRB_POOL_NODE_SIZEOF(pool) = node_sizeof;

    /*load rb_node table*/
    osize  = CMCNPRB_POOL_NODE_MAX_NUM(pool) * CMCNPRB_POOL_NODE_SIZEOF(pool);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)CMCNPRB_POOL_NODE_TBL(pool)))
    {
        dbg_log(SEC_0113_CMCNPRB, 0)(LOGSTDOUT, "error:cmcnprb_load: load CMCNPRB_POOL_NODE_TBL at offset %ld of fd %d failed where CMCNPRB_POOL_NODE_MAX_NUM is %u\n",
                            (*offset), fd, CMCNPRB_POOL_NODE_MAX_NUM(pool));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

void cmcnprb_tree_print(LOG *log, const CMCNPRB_POOL *pool, const uint32_t root_pos)
{
    uint32_t node_pos;

    sys_log(log, "[root = %5d]\n", root_pos);
    for(node_pos = cmcnprb_tree_first_node(pool, root_pos); CMCNPRB_ERR_POS != node_pos; node_pos = cmcnprb_tree_next_node(pool, node_pos))
    {
        cmcnprb_node_print(log, pool, node_pos);
    }
    return;
}

/* ---- debug ---- */
EC_BOOL cmcnprb_node_debug_cmp(const CMCNPRB_NODE *node_1st, const CMCNPRB_NODE *node_2nd, int (*node_cmp_data)(const CMCNPRB_NODE *, const CMCNPRB_NODE *))
{
    if(CMCNPRB_NODE_USED_FLAG(node_1st) != CMCNPRB_NODE_USED_FLAG(node_2nd))
    {
        dbg_log(SEC_0113_CMCNPRB, 0)(LOGSTDERR, "error:cmcnprb_node_debug_cmp: inconsistent CMCNPRB_NODE_USED_FLAG: %u != %u\n",
                            CMCNPRB_NODE_USED_FLAG(node_1st), CMCNPRB_NODE_USED_FLAG(node_2nd));
        return (EC_FALSE);
    }
#if 0
    if(CMCNPRB_NODE_NOT_USED == CMCNPRB_NODE_USED_FLAG(node_1st))
    {
        return (EC_TRUE);
    }
#endif

    if(CMCNPRB_NODE_COLOR(node_1st) != CMCNPRB_NODE_COLOR(node_2nd))
    {
        dbg_log(SEC_0113_CMCNPRB, 0)(LOGSTDERR, "error:cmcnprb_node_debug_cmp: inconsistent CMCNPRB_NODE_COLOR: %u != %u\n",
                            CMCNPRB_NODE_COLOR(node_1st), CMCNPRB_NODE_COLOR(node_2nd));
        return (EC_FALSE);
    }

    if(CMCNPRB_NODE_PARENT_POS(node_1st) != CMCNPRB_NODE_PARENT_POS(node_2nd))
    {
        dbg_log(SEC_0113_CMCNPRB, 0)(LOGSTDERR, "error:cmcnprb_node_debug_cmp: inconsistent CMCNPRB_NODE_PARENT_POS: %u != %u\n",
                            CMCNPRB_NODE_PARENT_POS(node_1st), CMCNPRB_NODE_PARENT_POS(node_2nd));
        return (EC_FALSE);
    }

    if(CMCNPRB_NODE_RIGHT_POS(node_1st) != CMCNPRB_NODE_RIGHT_POS(node_2nd))
    {
        dbg_log(SEC_0113_CMCNPRB, 0)(LOGSTDERR, "error:cmcnprb_node_debug_cmp: inconsistent CMCNPRB_NODE_RIGHT_POS: %u != %u\n",
                            CMCNPRB_NODE_RIGHT_POS(node_1st), CMCNPRB_NODE_RIGHT_POS(node_2nd));
        return (EC_FALSE);
    }

    if(CMCNPRB_NODE_LEFT_POS(node_1st) != CMCNPRB_NODE_LEFT_POS(node_2nd))
    {
        dbg_log(SEC_0113_CMCNPRB, 0)(LOGSTDERR, "error:cmcnprb_node_debug_cmp: inconsistent CMCNPRB_NODE_LEFT_POS: %u != %u\n",
                            CMCNPRB_NODE_LEFT_POS(node_1st), CMCNPRB_NODE_LEFT_POS(node_2nd));
        return (EC_FALSE);
    }

    if(CMCNPRB_NODE_USED == CMCNPRB_NODE_USED_FLAG(node_1st))
    {
        if(0 != node_cmp_data(node_1st, node_2nd))
        {
            dbg_log(SEC_0113_CMCNPRB, 0)(LOGSTDERR, "error:cmcnprb_node_debug_cmp: inconsistent data part\n");
            return (EC_FALSE);
        }
    }
    else
    {
        if(CMCNPRB_NODE_NEXT_POS(node_1st) != CMCNPRB_NODE_NEXT_POS(node_2nd))
        {
            dbg_log(SEC_0113_CMCNPRB, 0)(LOGSTDERR, "error:cmcnprb_node_debug_cmp: inconsistent CMCNPRB_NODE_NEXT_POS: %u != %u\n",
                                CMCNPRB_NODE_NEXT_POS(node_1st), CMCNPRB_NODE_NEXT_POS(node_2nd));
            return (EC_FALSE);
        }
    }
    return (EC_TRUE);
}

EC_BOOL cmcnprb_debug_cmp(const CMCNPRB_POOL *pool_1st, const CMCNPRB_POOL *pool_2nd, int (*node_cmp_data)(const CMCNPRB_NODE *, const CMCNPRB_NODE *))
{
    uint32_t  node_max_num;
    uint32_t  node_pos;

    if(CMCNPRB_POOL_FREE_HEAD(pool_1st) != CMCNPRB_POOL_FREE_HEAD(pool_2nd))
    {
        dbg_log(SEC_0113_CMCNPRB, 0)(LOGSTDERR, "error:cmcnprb_debug_cmp: inconsistent CMCNPRB_POOL_FREE_HEAD: %u != %u\n",
                            CMCNPRB_POOL_FREE_HEAD(pool_1st), CMCNPRB_POOL_FREE_HEAD(pool_2nd));
        return (EC_FALSE);
    }

    if(CMCNPRB_POOL_NODE_MAX_NUM(pool_1st) != CMCNPRB_POOL_NODE_MAX_NUM(pool_2nd))
    {
        dbg_log(SEC_0113_CMCNPRB, 0)(LOGSTDERR, "error:cmcnprb_debug_cmp: inconsistent CMCNPRB_POOL_NODE_MAX_NUM: %u != %u\n",
                            CMCNPRB_POOL_NODE_MAX_NUM(pool_1st), CMCNPRB_POOL_NODE_MAX_NUM(pool_2nd));
        return (EC_FALSE);
    }

    if(CMCNPRB_POOL_NODE_USED_NUM(pool_1st) != CMCNPRB_POOL_NODE_USED_NUM(pool_2nd))
    {
        dbg_log(SEC_0113_CMCNPRB, 0)(LOGSTDERR, "error:cmcnprb_debug_cmp: inconsistent CMCNPRB_POOL_NODE_USED_NUM: %u != %u\n",
                            CMCNPRB_POOL_NODE_USED_NUM(pool_1st), CMCNPRB_POOL_NODE_USED_NUM(pool_2nd));
        return (EC_FALSE);
    }

    if(CMCNPRB_POOL_NODE_SIZEOF(pool_1st) != CMCNPRB_POOL_NODE_SIZEOF(pool_2nd))
    {
        dbg_log(SEC_0113_CMCNPRB, 0)(LOGSTDERR, "error:cmcnprb_debug_cmp: inconsistent CMCNPRB_POOL_NODE_SIZEOF: %u != %u\n",
                            CMCNPRB_POOL_NODE_SIZEOF(pool_1st), CMCNPRB_POOL_NODE_SIZEOF(pool_2nd));
        return (EC_FALSE);
    }

    node_max_num = CMCNPRB_POOL_NODE_MAX_NUM(pool_1st);
    for(node_pos = 0; node_pos < node_max_num; node_pos ++)
    {
        CMCNPRB_NODE *node_1st;
        CMCNPRB_NODE *node_2nd;

        node_1st = CMCNPRB_POOL_NODE(pool_1st, node_pos);
        node_2nd = CMCNPRB_POOL_NODE(pool_2nd, node_pos);

        if(EC_FALSE == cmcnprb_node_debug_cmp(node_1st, node_2nd, node_cmp_data))
        {
            dbg_log(SEC_0113_CMCNPRB, 0)(LOGSTDERR, "error:cmcnprb_debug_cmp: inconsistent node at pos %u\n", node_pos);
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}


#ifdef __cplusplus
}
#endif/*__cplusplus*/
