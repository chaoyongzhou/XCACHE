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

#include "cdcnprb.h"
#include "cdcnp.inc"

#if (SWITCH_ON == CDC_ASSERT_SWITCH)
#define CDCNPRB_ASSERT(condition)   ASSERT(condition)
#endif/*(SWITCH_ON == CDC_ASSERT_SWITCH)*/

#if (SWITCH_OFF == CDC_ASSERT_SWITCH)
#define CDCNPRB_ASSERT(condition)   do{}while(0)
#endif/*(SWITCH_OFF == CDC_ASSERT_SWITCH)*/

/*new a CDCNPRB_NODE and return its position*/
uint32_t cdcnprb_node_new(CDCNPRB_POOL *pool)
{
    uint32_t node_pos_t;
    CDCNPRB_NODE *node;

    node_pos_t = CDCNPRB_POOL_FREE_HEAD(pool);
    if(CDCNPRB_ERR_POS == node_pos_t)
    {
        dbg_log(SEC_0181_CDCNPRB, 0)(LOGSTDERR, "error:cdcnprb_node_new: no free node in pool\n");
        return (CDCNPRB_ERR_POS);
    }

    if(CDCNPRB_POOL_FREE_HEAD(pool) >= CDCNPRB_POOL_NODE_MAX_NUM(pool))
    {
        dbg_log(SEC_0181_CDCNPRB, 0)(LOGSTDERR, "error:cdcnprb_node_new: found conflict: free head %u >= max num %u\n",
                            CDCNPRB_POOL_FREE_HEAD(pool), CDCNPRB_POOL_NODE_MAX_NUM(pool));
        return (CDCNPRB_ERR_POS);
    }

    CDCNPRB_ASSERT(CDCNPRB_POOL_FREE_HEAD(pool) < CDCNPRB_POOL_NODE_MAX_NUM(pool));

    node = CDCNPRB_POOL_NODE(pool, node_pos_t);
#if 0
    dbg_log(SEC_0181_CDCNPRB, 9)(LOGSTDNULL, "[DEBUG] cdcnprb_node_new: pool %p, max %u, used %u, free head %u, next %u\n",
                       pool,
                       CDCNPRB_POOL_NODE_MAX_NUM(pool),
                       CDCNPRB_POOL_NODE_USED_NUM(pool),
                       CDCNPRB_POOL_FREE_HEAD(pool),
                       CDCNPRB_NODE_NEXT_POS(node));
#endif
    CDCNPRB_POOL_FREE_HEAD(pool) = CDCNPRB_NODE_NEXT_POS(node);
    CDCNPRB_POOL_NODE_USED_NUM(pool) ++;

    CDCNPRB_NODE_NEXT_POS(node)  = CDCNPRB_ERR_POS;
    CDCNPRB_NODE_USED_FLAG(node) = CDCNPRB_NODE_USED;

    return (node_pos_t);
}

/*free a CDCNPRB_NODE and return its position to the pool*/
void cdcnprb_node_free(CDCNPRB_POOL *pool, const uint32_t node_pos)
{
    if(CDCNPRB_ERR_POS != node_pos)
    {
        CDCNPRB_NODE *node;

        CDCNPRB_ASSERT(node_pos < CDCNPRB_POOL_NODE_MAX_NUM(pool));

        node = CDCNPRB_POOL_NODE(pool, node_pos);
        CDCNPRB_ASSERT(CDCNPRB_NODE_IS_USED(node));

        CDCNPRB_NODE_USED_FLAG(node)  = CDCNPRB_NODE_NOT_USED;
        CDCNPRB_NODE_PARENT_POS(node) = CDCNPRB_ERR_POS;
        CDCNPRB_NODE_RIGHT_POS(node)  = CDCNPRB_ERR_POS;
        CDCNPRB_NODE_LEFT_POS(node)   = CDCNPRB_ERR_POS;
        CDCNPRB_NODE_NEXT_POS(node)   = CDCNPRB_POOL_FREE_HEAD(pool);
        CDCNPRB_NODE_COLOR(node)      = CDCNPRB_BLACK;

        CDCNPRB_POOL_FREE_HEAD(pool)  = node_pos;
        CDCNPRB_POOL_NODE_USED_NUM(pool) --;
    }
    return;
}

void cdcnprb_node_init(CDCNPRB_POOL *pool, const uint32_t node_pos)
{
    CDCNPRB_NODE *node;

    node  = CDCNPRB_POOL_NODE(pool, node_pos);

    CDCNPRB_NODE_PARENT_POS(node) = CDCNPRB_ERR_POS;
    CDCNPRB_NODE_RIGHT_POS(node)  = CDCNPRB_ERR_POS;
    CDCNPRB_NODE_LEFT_POS(node)   = CDCNPRB_ERR_POS;
    CDCNPRB_NODE_USED_FLAG(node)  = CDCNPRB_NODE_NOT_USED;
    CDCNPRB_NODE_NEXT_POS(node)   = CDCNPRB_ERR_POS;
    CDCNPRB_NODE_COLOR(node)      = CDCNPRB_BLACK;

    return;
}

void cdcnprb_node_clean(CDCNPRB_POOL *pool, const uint32_t node_pos)
{
    CDCNPRB_NODE *node;

    CDCNPRB_ASSERT(node_pos < CDCNPRB_POOL_NODE_MAX_NUM(pool));

    node = CDCNPRB_POOL_NODE(pool, node_pos);

    CDCNPRB_NODE_PARENT_POS(node) = CDCNPRB_ERR_POS;
    CDCNPRB_NODE_RIGHT_POS(node)  = CDCNPRB_ERR_POS;
    CDCNPRB_NODE_LEFT_POS(node)   = CDCNPRB_ERR_POS;
    CDCNPRB_NODE_USED_FLAG(node)  = CDCNPRB_NODE_NOT_USED;
    CDCNPRB_NODE_NEXT_POS(node)   = CDCNPRB_ERR_POS;
    CDCNPRB_NODE_COLOR(node)      = CDCNPRB_BLACK;

    return;
}

void cdcnprb_node_set_next(CDCNPRB_POOL *pool, const uint32_t node_pos, const uint32_t next_pos)
{
    CDCNPRB_NODE *node;

    node = CDCNPRB_POOL_NODE(pool, node_pos);
    CDCNPRB_NODE_NEXT_POS(node) = next_pos;

    return;
}

EC_BOOL cdcnprb_node_is_used(const CDCNPRB_POOL *pool, const uint32_t node_pos)
{
    const CDCNPRB_NODE *node;
    node  = CDCNPRB_POOL_NODE(pool, node_pos);

    if(CDCNPRB_NODE_IS_USED(node))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

void cdcnprb_node_print(LOG *log, const CDCNPRB_POOL *pool, const uint32_t node_pos)
{
    const CDCNPRB_NODE *node;
    node  = CDCNPRB_POOL_NODE(pool, node_pos);

    sys_log(log, "%5d: parent = %5d, left = %5d, right = %5d, flg = %s, color = %s, %s = %5d\n",
                       node_pos,
                       CDCNPRB_NODE_PARENT_POS(node),
                       CDCNPRB_NODE_LEFT_POS(node),
                       CDCNPRB_NODE_RIGHT_POS(node),
                       CDCNPRB_NODE_IS_USED(node) ? "used" : "n.a.",
                       CDCNPRB_NODE_IS_USED(node) ? (CDCNPRB_NODE_IS_RED(node) ? "red  " : "black") : "#####",
                       CDCNPRB_NODE_IS_USED(node) ? "data" : "next",
                       CDCNPRB_NODE_IS_USED(node) ? CDCNPRB_NODE_DATA(node) : CDCNPRB_NODE_NEXT_POS(node)
                       );
    return;
}

void cdcnprb_node_print_level(LOG *log, const CDCNPRB_POOL *pool, const uint32_t node_pos, const uint32_t level)
{
    const CDCNPRB_NODE *node;
    node  = CDCNPRB_POOL_NODE(pool, node_pos);

    c_ident_print(log, level);
    sys_print(log, "%5d: parent = %5d, left = %5d, right = %5d, flg = %s, color = %s, %s = %5d\n",
                       node_pos,
                       CDCNPRB_NODE_PARENT_POS(node),
                       CDCNPRB_NODE_LEFT_POS(node),
                       CDCNPRB_NODE_RIGHT_POS(node),
                       CDCNPRB_NODE_IS_USED(node) ? "used" : "NOT used",
                       CDCNPRB_NODE_IS_RED(node)  ? "red  " : "black",
                       CDCNPRB_NODE_IS_USED(node) ? "data" : "next",
                       CDCNPRB_NODE_IS_USED(node) ? CDCNPRB_NODE_DATA(node) : CDCNPRB_NODE_NEXT_POS(node)
                       );
    return;
}


STATIC_CAST static void __cdcnprb_tree_rotate_left(CDCNPRB_POOL *pool, const uint32_t node_pos, uint32_t *root_pos)
{
    CDCNPRB_NODE *node;
    CDCNPRB_NODE *right;

    uint32_t  right_pos;

    node  = CDCNPRB_POOL_NODE(pool, node_pos);

    right_pos = CDCNPRB_NODE_RIGHT_POS(node);
    right = CDCNPRB_POOL_NODE(pool, right_pos);

    if(CDCNPRB_ERR_POS != (CDCNPRB_NODE_RIGHT_POS(node) = CDCNPRB_NODE_LEFT_POS(right)))
    {
        CDCNPRB_NODE *left;
        left = CDCNPRB_POOL_NODE(pool, CDCNPRB_NODE_LEFT_POS(right));
        CDCNPRB_NODE_PARENT_POS(left) = node_pos;
    }
    CDCNPRB_NODE_LEFT_POS(right) = node_pos;

    if(CDCNPRB_ERR_POS != (CDCNPRB_NODE_PARENT_POS(right) = CDCNPRB_NODE_PARENT_POS(node)))
    {
        CDCNPRB_NODE *parent;
        parent = CDCNPRB_POOL_NODE(pool, CDCNPRB_NODE_PARENT_POS(node));

        if (node_pos == CDCNPRB_NODE_LEFT_POS(parent))
        {
            CDCNPRB_NODE_LEFT_POS(parent) = right_pos;
        }
        else
        {
            CDCNPRB_NODE_RIGHT_POS(parent) = right_pos;
        }
    }
    else
    {
        (*root_pos) = right_pos;
    }
    CDCNPRB_NODE_PARENT_POS(node) = right_pos;
    return;
}

STATIC_CAST static void __cdcnprb_tree_rotate_right(CDCNPRB_POOL *pool, const uint32_t node_pos, uint32_t *root_pos)
{
    CDCNPRB_NODE *node;
    CDCNPRB_NODE *left;
    uint32_t  left_pos;

    node  = CDCNPRB_POOL_NODE(pool, node_pos);

    left_pos = CDCNPRB_NODE_LEFT_POS(node);
    left = CDCNPRB_POOL_NODE(pool, left_pos);

    if (CDCNPRB_ERR_POS != (CDCNPRB_NODE_LEFT_POS(node) = CDCNPRB_NODE_RIGHT_POS(left)))
    {
        CDCNPRB_NODE *right;
        right = CDCNPRB_POOL_NODE(pool, CDCNPRB_NODE_RIGHT_POS(left));
        CDCNPRB_NODE_PARENT_POS(right) = node_pos;
    }
    CDCNPRB_NODE_RIGHT_POS(left) = node_pos;

    if (CDCNPRB_ERR_POS != (CDCNPRB_NODE_PARENT_POS(left) = CDCNPRB_NODE_PARENT_POS(node)))
    {
        CDCNPRB_NODE *parent;
        parent = CDCNPRB_POOL_NODE(pool, CDCNPRB_NODE_PARENT_POS(node));

        if (node_pos == CDCNPRB_NODE_RIGHT_POS(parent))
        {
            CDCNPRB_NODE_RIGHT_POS(parent) = left_pos;
        }
        else
        {
            CDCNPRB_NODE_LEFT_POS(parent) = left_pos;
        }
    }
    else
    {
        (*root_pos) = left_pos;
    }
    CDCNPRB_NODE_PARENT_POS(node) = left_pos;
    return;
}

STATIC_CAST static void __cdcnprb_tree_insert_color(CDCNPRB_POOL *pool, const uint32_t node_pos, uint32_t *root_pos)
{
    CDCNPRB_NODE *node;
    CDCNPRB_NODE *root;
    CDCNPRB_NODE *parent;

    uint32_t  node_pos_t;

    node_pos_t = node_pos;
    node  = CDCNPRB_POOL_NODE(pool, node_pos_t);

    while (NULL_PTR != (parent = CDCNPRB_POOL_NODE(pool, CDCNPRB_NODE_PARENT_POS(node))) /*parent is valid*/
         && CDCNPRB_RED == CDCNPRB_NODE_COLOR(parent))
    {
        uint32_t  parent_pos;
        uint32_t  gparent_pos;
        CDCNPRB_NODE *gparent;

        parent_pos = CDCNPRB_NODE_PARENT_POS(node);

        gparent_pos = CDCNPRB_NODE_PARENT_POS(parent);
        CDCNPRB_ASSERT(CDCNPRB_ERR_POS != gparent_pos);
        gparent = CDCNPRB_POOL_NODE(pool, gparent_pos);

        if (parent_pos == CDCNPRB_NODE_LEFT_POS(gparent))
        {
            {
                CDCNPRB_NODE *uncle;
                if (NULL_PTR != (uncle = CDCNPRB_POOL_NODE(pool, CDCNPRB_NODE_RIGHT_POS(gparent))) /*uncle is valid*/
                   && CDCNPRB_RED == CDCNPRB_NODE_COLOR(uncle))
                {
                    CDCNPRB_NODE_COLOR(uncle)   = CDCNPRB_BLACK;
                    CDCNPRB_NODE_COLOR(parent)  = CDCNPRB_BLACK;
                    CDCNPRB_NODE_COLOR(gparent) = CDCNPRB_RED;

                    node = gparent;
                    node_pos_t = gparent_pos;
                    continue;
                }
            }

            if (CDCNPRB_NODE_RIGHT_POS(parent) == node_pos_t)
            {
                __cdcnprb_tree_rotate_left(pool, parent_pos, root_pos);
                XCHG(CDCNPRB_NODE *, parent, node);
                XCHG(uint32_t, parent_pos, node_pos_t);
            }

            CDCNPRB_NODE_COLOR(parent)  = CDCNPRB_BLACK;
            CDCNPRB_NODE_COLOR(gparent) = CDCNPRB_RED;
            __cdcnprb_tree_rotate_right(pool, gparent_pos, root_pos);
         }
         else
         {
            {
                CDCNPRB_NODE *uncle;
                if (NULL_PTR != (uncle = CDCNPRB_POOL_NODE(pool, CDCNPRB_NODE_LEFT_POS(gparent))) /*uncle is valid*/
                    && CDCNPRB_RED == CDCNPRB_NODE_COLOR(uncle))
                {
                    CDCNPRB_NODE_COLOR(uncle)   = CDCNPRB_BLACK;
                    CDCNPRB_NODE_COLOR(parent)  = CDCNPRB_BLACK;
                    CDCNPRB_NODE_COLOR(gparent) = CDCNPRB_RED;

                    node = gparent;
                    node_pos_t = gparent_pos;
                    continue;
                }
            }

            if (CDCNPRB_NODE_LEFT_POS(parent) == node_pos_t)
            {
                __cdcnprb_tree_rotate_right(pool, parent_pos, root_pos);
                XCHG(CDCNPRB_NODE *, parent, node);
                XCHG(uint32_t, parent_pos, node_pos_t);
            }

            CDCNPRB_NODE_COLOR(parent)  = CDCNPRB_BLACK;
            CDCNPRB_NODE_COLOR(gparent) = CDCNPRB_RED;
            __cdcnprb_tree_rotate_left(pool, gparent_pos, root_pos);
        }
    }

    root = CDCNPRB_POOL_NODE(pool, *root_pos);
    CDCNPRB_NODE_COLOR(root) = CDCNPRB_BLACK;
    return;
}

STATIC_CAST static void __cdcnprb_tree_erase_color(CDCNPRB_POOL *pool, const uint32_t node_pos, const uint32_t parent_pos, uint32_t *root_pos)
{
    CDCNPRB_NODE *node;
    uint32_t  node_pos_t;
    uint32_t  parent_pos_t;

    node_pos_t   = node_pos;
    parent_pos_t = parent_pos;

    while ((NULL_PTR == (node = CDCNPRB_POOL_NODE(pool, node_pos_t)) || CDCNPRB_BLACK == CDCNPRB_NODE_COLOR(node)) && node_pos_t != (*root_pos))
    {
        CDCNPRB_NODE *parent;

        parent = CDCNPRB_POOL_NODE(pool, parent_pos_t);

        if (CDCNPRB_NODE_LEFT_POS(parent) == node_pos_t)
        {
            CDCNPRB_NODE *other;
            CDCNPRB_NODE *o_left;
            CDCNPRB_NODE *o_right;
            uint32_t  other_pos;

            other_pos = CDCNPRB_NODE_RIGHT_POS(parent);
            other = CDCNPRB_POOL_NODE(pool, other_pos);

            if (CDCNPRB_RED == CDCNPRB_NODE_COLOR(other))
            {
                CDCNPRB_NODE_COLOR(other)  = CDCNPRB_BLACK;
                CDCNPRB_NODE_COLOR(parent) = CDCNPRB_RED;

                __cdcnprb_tree_rotate_left(pool, parent_pos_t, root_pos);

                other_pos = CDCNPRB_NODE_RIGHT_POS(parent);
                other = CDCNPRB_POOL_NODE(pool, other_pos);
            }

            o_left = CDCNPRB_POOL_NODE(pool, CDCNPRB_NODE_LEFT_POS(other));
            o_right = CDCNPRB_POOL_NODE(pool, CDCNPRB_NODE_RIGHT_POS(other));

            if((NULL_PTR == o_left || CDCNPRB_BLACK == CDCNPRB_NODE_COLOR(o_left))
            && (NULL_PTR == o_right || CDCNPRB_BLACK == CDCNPRB_NODE_COLOR(o_right)))
            {
                CDCNPRB_NODE_COLOR(other) = CDCNPRB_RED;

                node_pos_t = parent_pos_t;
                node = CDCNPRB_POOL_NODE(pool, node_pos_t);

                parent_pos_t = CDCNPRB_NODE_PARENT_POS(node);
                parent = CDCNPRB_POOL_NODE(pool, parent_pos_t);
            }
            else
            {
                if (NULL_PTR == o_right || CDCNPRB_BLACK == CDCNPRB_NODE_COLOR(o_right))
                {
                    if (NULL_PTR != o_left)
                    {
                        CDCNPRB_NODE_COLOR(o_left) = CDCNPRB_BLACK;
                    }
                    CDCNPRB_NODE_COLOR(other) = CDCNPRB_RED;

                    __cdcnprb_tree_rotate_right(pool, other_pos, root_pos);

                    other_pos = CDCNPRB_NODE_RIGHT_POS(parent);
                    other = CDCNPRB_POOL_NODE(pool, other_pos);
                    /*note: other was changed here*/
                }

                CDCNPRB_NODE_COLOR(other) = CDCNPRB_NODE_COLOR(parent);
                CDCNPRB_NODE_COLOR(parent) = CDCNPRB_BLACK;

                /*due to other may be changed before, have to get o_right again here*/
                o_right = CDCNPRB_POOL_NODE(pool, CDCNPRB_NODE_RIGHT_POS(other));
                if (NULL_PTR != o_right)
                {
                    CDCNPRB_NODE_COLOR(o_right) = CDCNPRB_BLACK;
                }

                __cdcnprb_tree_rotate_left(pool, parent_pos_t, root_pos);
                node_pos_t = (*root_pos);
                break;
            }
        }
        else
        {
            CDCNPRB_NODE *other;
            CDCNPRB_NODE *o_left;
            CDCNPRB_NODE *o_right;
            uint32_t  other_pos;

            other_pos = CDCNPRB_NODE_LEFT_POS(parent);
            other = CDCNPRB_POOL_NODE(pool, other_pos);

            if (CDCNPRB_RED == CDCNPRB_NODE_COLOR(other))
            {
                CDCNPRB_NODE_COLOR(other) = CDCNPRB_BLACK;
                CDCNPRB_NODE_COLOR(parent) = CDCNPRB_RED;

                __cdcnprb_tree_rotate_right(pool, parent_pos_t, root_pos);

                other_pos = CDCNPRB_NODE_LEFT_POS(parent);
                other = CDCNPRB_POOL_NODE(pool, other_pos);
            }

            o_left = CDCNPRB_POOL_NODE(pool, CDCNPRB_NODE_LEFT_POS(other));
            o_right = CDCNPRB_POOL_NODE(pool, CDCNPRB_NODE_RIGHT_POS(other));

            if ((NULL_PTR == o_left  || CDCNPRB_BLACK == CDCNPRB_NODE_COLOR(o_left))
             && (NULL_PTR == o_right || CDCNPRB_BLACK == CDCNPRB_NODE_COLOR(o_right)))
            {
                CDCNPRB_NODE_COLOR(other) = CDCNPRB_RED;

                node_pos_t = parent_pos_t;
                node = CDCNPRB_POOL_NODE(pool, node_pos_t);

                parent_pos_t = CDCNPRB_NODE_PARENT_POS(node);
                parent = CDCNPRB_POOL_NODE(pool, parent_pos_t);
            }
            else
            {
                if (NULL_PTR == o_left  || CDCNPRB_BLACK == CDCNPRB_NODE_COLOR(o_left))
                {
                    if (NULL_PTR != o_right)
                    {
                        CDCNPRB_NODE_COLOR(o_right) = CDCNPRB_BLACK;
                    }

                    CDCNPRB_NODE_COLOR(other) = CDCNPRB_RED;

                    __cdcnprb_tree_rotate_left(pool, other_pos, root_pos);

                    other_pos = CDCNPRB_NODE_LEFT_POS(parent);
                    other = CDCNPRB_POOL_NODE(pool, other_pos);
                    /*note: other was changed here*/
                }

                CDCNPRB_NODE_COLOR(other) = CDCNPRB_NODE_COLOR(parent);
                CDCNPRB_NODE_COLOR(parent) = CDCNPRB_BLACK;

                /*due to other may be changed before, have to get o_left again here*/
                o_left = CDCNPRB_POOL_NODE(pool, CDCNPRB_NODE_LEFT_POS(other));
                if (NULL_PTR != o_left)
                {
                    CDCNPRB_NODE_COLOR(o_left) = CDCNPRB_BLACK;
                }
                __cdcnprb_tree_rotate_right(pool, parent_pos_t, root_pos);
                node_pos_t = (*root_pos);
                break;
            }
        }
    }

    node = CDCNPRB_POOL_NODE(pool, node_pos_t);
    if (NULL_PTR != node)
    {
        CDCNPRB_NODE_COLOR(node) = CDCNPRB_BLACK;
    }
    return;
}

/*note: erase from tree but not recycle to free nodes pool*/
EC_BOOL cdcnprb_tree_erase(CDCNPRB_POOL *pool, const uint32_t node_pos, uint32_t *root_pos)
{
    CDCNPRB_NODE *node;

    uint32_t node_pos_t;
    uint32_t child_pos;
    uint32_t parent_pos;
    uint32_t color;

    node_pos_t = node_pos;
    node = CDCNPRB_POOL_NODE(pool, node_pos_t);

    CDCNPRB_ASSERT(NULL_PTR != node);
    CDCNPRB_ASSERT(CDCNPRB_NODE_IS_USED(node));

    if (CDCNPRB_ERR_POS == CDCNPRB_NODE_LEFT_POS(node))
    {
        child_pos = CDCNPRB_NODE_RIGHT_POS(node);
    }
    else if (CDCNPRB_ERR_POS == CDCNPRB_NODE_RIGHT_POS(node))
    {
        child_pos = CDCNPRB_NODE_LEFT_POS(node);
    }
    else
    {
        CDCNPRB_NODE *old;

        uint32_t old_pos;
        uint32_t left_pos;

        old_pos = node_pos_t;

        node_pos_t = CDCNPRB_NODE_RIGHT_POS(node);
        node = CDCNPRB_POOL_NODE(pool, node_pos_t);

        while (CDCNPRB_ERR_POS != (left_pos = CDCNPRB_NODE_LEFT_POS(node)))
        {
            node_pos_t = left_pos;
            node = CDCNPRB_POOL_NODE(pool, node_pos_t);

        }

        child_pos  = CDCNPRB_NODE_RIGHT_POS(node);
        parent_pos = CDCNPRB_NODE_PARENT_POS(node);
        color      = CDCNPRB_NODE_COLOR(node);

        if (CDCNPRB_ERR_POS != child_pos)
        {
            CDCNPRB_NODE *child;
            child = CDCNPRB_POOL_NODE(pool, child_pos);
            CDCNPRB_NODE_PARENT_POS(child) = parent_pos;
        }

        if (CDCNPRB_ERR_POS != parent_pos)
        {
            CDCNPRB_NODE *parent;

            parent = CDCNPRB_POOL_NODE(pool, parent_pos);
            if (CDCNPRB_NODE_LEFT_POS(parent) == node_pos_t)
            {
                CDCNPRB_NODE_LEFT_POS(parent) = child_pos;
            }
            else
            {
                CDCNPRB_NODE_RIGHT_POS(parent) = child_pos;
            }
        }
        else
        {
            (*root_pos) = child_pos;
        }

        if (CDCNPRB_NODE_PARENT_POS(node) == old_pos)
        {
            parent_pos = node_pos_t;
        }

        old  = CDCNPRB_POOL_NODE(pool, old_pos);

        CDCNPRB_NODE_PARENT_POS(node) = CDCNPRB_NODE_PARENT_POS(old);
        CDCNPRB_NODE_COLOR(node)      = CDCNPRB_NODE_COLOR(old);
        CDCNPRB_NODE_RIGHT_POS(node)  = CDCNPRB_NODE_RIGHT_POS(old);
        CDCNPRB_NODE_LEFT_POS(node)   = CDCNPRB_NODE_LEFT_POS(old);

        if (CDCNPRB_ERR_POS != CDCNPRB_NODE_PARENT_POS(old))
        {
            CDCNPRB_NODE *old_parent;
            old_parent = CDCNPRB_POOL_NODE(pool, CDCNPRB_NODE_PARENT_POS(old));

            if (CDCNPRB_NODE_LEFT_POS(old_parent) == old_pos)
            {
                CDCNPRB_NODE_LEFT_POS(old_parent) = node_pos_t;
            }
            else
            {
                CDCNPRB_NODE_RIGHT_POS(old_parent) = node_pos_t;
            }
        }
        else
        {
            (*root_pos) = node_pos_t;
        }

        {
            CDCNPRB_NODE *old_left;

            old_left = CDCNPRB_POOL_NODE(pool, CDCNPRB_NODE_LEFT_POS(old));
            CDCNPRB_NODE_PARENT_POS(old_left) = node_pos_t;
        }

        if (CDCNPRB_ERR_POS != CDCNPRB_NODE_RIGHT_POS(old))
        {
            CDCNPRB_NODE *old_right;
            old_right = CDCNPRB_POOL_NODE(pool, CDCNPRB_NODE_RIGHT_POS(old));
            CDCNPRB_NODE_PARENT_POS(old_right) = node_pos_t;
        }
        goto color;
    }

    parent_pos = CDCNPRB_NODE_PARENT_POS(node);
    color = CDCNPRB_NODE_COLOR(node);

    if (CDCNPRB_ERR_POS != child_pos)
    {
        CDCNPRB_NODE *child;
        child = CDCNPRB_POOL_NODE(pool, child_pos);
        CDCNPRB_NODE_PARENT_POS(child) = parent_pos;
    }

    if (CDCNPRB_ERR_POS != parent_pos)
    {
        CDCNPRB_NODE *parent;

        parent = CDCNPRB_POOL_NODE(pool, parent_pos);
        if (CDCNPRB_NODE_LEFT_POS(parent) == node_pos_t)
        {
            CDCNPRB_NODE_LEFT_POS(parent) = child_pos;
        }
        else
        {
            CDCNPRB_NODE_RIGHT_POS(parent) = child_pos;
        }
    }
    else
    {
        (*root_pos) = child_pos;
    }

 color:
    if (CDCNPRB_BLACK == color)
    {
        __cdcnprb_tree_erase_color(pool, child_pos, parent_pos, root_pos);
    }
    return (EC_TRUE);
}

STATIC_CAST static uint32_t __cdcnprb_tree_count_node_num(const CDCNPRB_POOL *pool, const uint32_t node_pos)
{
    const CDCNPRB_NODE *node;

    if(CDCNPRB_ERR_POS == node_pos)
    {
        return ((uint32_t)0);
    }

    node = CDCNPRB_POOL_NODE(pool, node_pos);

    return (uint32_t)(1 + __cdcnprb_tree_count_node_num(pool, CDCNPRB_NODE_LEFT_POS(node)) + __cdcnprb_tree_count_node_num(pool, CDCNPRB_NODE_RIGHT_POS(node)));
}

uint32_t cdcnprb_tree_count_node_num(const CDCNPRB_POOL *pool, const uint32_t root_pos)
{
    return __cdcnprb_tree_count_node_num(pool, root_pos);
}

uint32_t cdcnprb_tree_node_max_num(const CDCNPRB_POOL *pool)
{
    return CDCNPRB_POOL_NODE_MAX_NUM(pool);
}

uint32_t cdcnprb_tree_node_used_num(const CDCNPRB_POOL *pool)
{
    return CDCNPRB_POOL_NODE_USED_NUM(pool);
}

uint32_t cdcnprb_tree_node_sizeof(const CDCNPRB_POOL *pool)
{
    return CDCNPRB_POOL_NODE_SIZEOF(pool);
}

/*
 * This function returns the first node_pos (in sort order) of the tree.
 */
uint32_t cdcnprb_tree_first_node(const CDCNPRB_POOL *pool, const uint32_t root_pos)
{
    uint32_t  node_pos;
    const CDCNPRB_NODE *node;

    node_pos = root_pos;
    if (CDCNPRB_ERR_POS == node_pos)
    {
        return (CDCNPRB_ERR_POS);
    }

    node = CDCNPRB_POOL_NODE(pool, node_pos);

    while (CDCNPRB_ERR_POS != CDCNPRB_NODE_LEFT_POS(node))
    {
        node_pos = CDCNPRB_NODE_LEFT_POS(node);
        node = CDCNPRB_POOL_NODE(pool, node_pos);
    }
    return (node_pos);
}

uint32_t cdcnprb_tree_last_node(const CDCNPRB_POOL *pool, const uint32_t root_pos)
{
    uint32_t  node_pos;
    const CDCNPRB_NODE *node;

    node_pos = root_pos;
    if (CDCNPRB_ERR_POS == node_pos)
    {
        return (CDCNPRB_ERR_POS);
    }

    node = CDCNPRB_POOL_NODE(pool, node_pos);

    while (CDCNPRB_ERR_POS != CDCNPRB_NODE_RIGHT_POS(node))
    {
        node_pos = CDCNPRB_NODE_RIGHT_POS(node);
        node = CDCNPRB_POOL_NODE(pool, node_pos);
    }

    return (node_pos);
}

uint32_t cdcnprb_tree_next_node(const CDCNPRB_POOL *pool, const uint32_t node_pos)
{
    uint32_t node_pos_t;
    const CDCNPRB_NODE *node;
    const CDCNPRB_NODE *parent;

    node_pos_t = node_pos;
    node = CDCNPRB_POOL_NODE(pool, node_pos_t);
    /* If we have a right-hand child, go down and then left as far
       as we can. */
    if (CDCNPRB_ERR_POS != CDCNPRB_NODE_RIGHT_POS(node))
    {
        node_pos_t = CDCNPRB_NODE_RIGHT_POS(node);
        node = CDCNPRB_POOL_NODE(pool, node_pos_t);
        while (CDCNPRB_ERR_POS != CDCNPRB_NODE_LEFT_POS(node))
        {
            node_pos_t = CDCNPRB_NODE_LEFT_POS(node);
            node = CDCNPRB_POOL_NODE(pool, node_pos_t);
        }
        return (node_pos_t);
    }

    /* No right-hand children.  Everything down and left is
       smaller than us, so any 'next' node_pos_t must be in the general
       direction of our parent. Go up the tree; any time the
       ancestor is a right-hand child of its parent, keep going
       up. First time it's a left-hand child of its parent, said
       parent is our 'next' node_pos_t. */
    while (NULL_PTR != (parent = CDCNPRB_POOL_NODE(pool, CDCNPRB_NODE_PARENT_POS(node))) && node_pos_t == CDCNPRB_NODE_RIGHT_POS(parent))
    {
        node_pos_t = CDCNPRB_NODE_PARENT_POS(node);
        node = parent;
    }

    return (CDCNPRB_NODE_PARENT_POS(node));
}

uint32_t cdcnprb_tree_prev_node(const CDCNPRB_POOL *pool, const uint32_t node_pos)
{
    uint32_t node_pos_t;
    const CDCNPRB_NODE *node;
    const CDCNPRB_NODE *parent;

    node_pos_t = node_pos;
    node = CDCNPRB_POOL_NODE(pool, node_pos_t);

    /* If we have a left-hand child, go down and then right as far
       as we can. */
    if (CDCNPRB_ERR_POS != CDCNPRB_NODE_LEFT_POS(node))
    {
        node_pos_t = CDCNPRB_NODE_LEFT_POS(node);
        node = CDCNPRB_POOL_NODE(pool, node_pos_t);
        while (CDCNPRB_ERR_POS != CDCNPRB_NODE_RIGHT_POS(node))
        {
            node_pos_t = CDCNPRB_NODE_RIGHT_POS(node);
            node = CDCNPRB_POOL_NODE(pool, node_pos_t);
        }
        return (node_pos_t);
    }

    /* No left-hand children. Go up till we find an ancestor which
       is a right-hand child of its parent */
    while (NULL_PTR != (parent = CDCNPRB_POOL_NODE(pool, CDCNPRB_NODE_PARENT_POS(node))) && node_pos_t == CDCNPRB_NODE_LEFT_POS(parent))
    {
        node_pos_t = CDCNPRB_NODE_PARENT_POS(node);
        node = parent;
    }

    return (CDCNPRB_NODE_PARENT_POS(node));
}

/**
*
*   note:only for cdcnp item!
*   node key : [s1, e1)
*   cdcnp key: [s2, e2)
*
*   return -1 if s2 < s1
*   return  1 if s2 >= e1
*   return  0 if s1 <= s2 < e1
*
*   note: s_page_in means s_page of cdcnp_key falls into node key
*
**/
STATIC_CAST static int __cdcnprb_node_data_cmp__s_page_in(const CDCNPRB_NODE *node, const CDCNP_KEY *cdcnp_key)
{
    const CDCNP_ITEM *item;
    const CDCNP_KEY  *key;

    item = (const CDCNP_ITEM *)CDCNP_RB_NODE_ITEM(node);
    key  = CDCNP_ITEM_KEY(item);

    if(CDCNP_KEY_S_PAGE(cdcnp_key) < CDCNP_KEY_S_PAGE(key))
    {
        dbg_log(SEC_0181_CDCNPRB, 9)(LOGSTDOUT, "[DEBUG] __cdcnprb_node_data_cmp__s_page_in: "
                                                "node  key: [%u, %u), cdcnp key: [%u, %u) => -1\n",
                                                CDCNP_KEY_S_PAGE(key), CDCNP_KEY_E_PAGE(key),
                                                CDCNP_KEY_S_PAGE(cdcnp_key), CDCNP_KEY_E_PAGE(cdcnp_key));

        return (-1);
    }

    if(CDCNP_KEY_S_PAGE(cdcnp_key) >= CDCNP_KEY_E_PAGE(key))
    {
        dbg_log(SEC_0181_CDCNPRB, 9)(LOGSTDOUT, "[DEBUG] __cdcnprb_node_data_cmp__s_page_in: "
                                                "node  key: [%u, %u), cdcnp key: [%u, %u) => 1\n",
                                                CDCNP_KEY_S_PAGE(key), CDCNP_KEY_E_PAGE(key),
                                                CDCNP_KEY_S_PAGE(cdcnp_key), CDCNP_KEY_E_PAGE(cdcnp_key));
        return (1);
    }

    dbg_log(SEC_0181_CDCNPRB, 9)(LOGSTDOUT, "[DEBUG] __cdcnprb_node_data_cmp__s_page_in: "
                                            "node  key: [%u, %u), cdcnp key: [%u, %u) => 0\n",
                                            CDCNP_KEY_S_PAGE(key), CDCNP_KEY_E_PAGE(key),
                                            CDCNP_KEY_S_PAGE(cdcnp_key), CDCNP_KEY_E_PAGE(cdcnp_key));

    return (0);
}

/**
*
*   note:only for cdcnp item!
*   node key : [s1, e1)
*   cdcnp key: [s2, e2)
*
*   return -1 if e2 <= s1
*   return  1 if e2 > e1
*   return  0 if s1 < e2 <= e1
*
*   note: e_page_in means e_page of cdcnp_key falls into node key
*
**/
STATIC_CAST static int __cdcnprb_node_data_cmp__e_page_in(const CDCNPRB_NODE *node, const CDCNP_KEY *cdcnp_key)
{
    const CDCNP_ITEM *item;
    const CDCNP_KEY  *key;

    item = (const CDCNP_ITEM *)CDCNP_RB_NODE_ITEM(node);
    key  = CDCNP_ITEM_KEY(item);

    if(CDCNP_KEY_E_PAGE(cdcnp_key) <= CDCNP_KEY_S_PAGE(key))
    {
        return (-1);
    }

    if(CDCNP_KEY_E_PAGE(cdcnp_key) >  CDCNP_KEY_E_PAGE(key))
    {
        return (1);
    }

    return (0);
}

/**
*
*   note:only for cdcnp item!
*   node key : [s1, e1)
*   cdcnp key: [s2, e2)
*
*   return -1 if s2 < s1
*   return  1 if s2 >= e1
*   return  0 if s1 <= s2 < e1
*
*   note: s_page_closest means s_page of cdcnp_key is the closest to which node on left side
*
**/
//TODO:
STATIC_CAST static int __cdcnprb_node_data_cmp__s_page_closest(const CDCNPRB_NODE *node, const CDCNP_KEY *cdcnp_key)
{
    const CDCNP_ITEM *item;
    const CDCNP_KEY  *key;

    item = (const CDCNP_ITEM *)CDCNP_RB_NODE_ITEM(node);
    key  = CDCNP_ITEM_KEY(item);

    if(CDCNP_KEY_S_PAGE(cdcnp_key) < CDCNP_KEY_S_PAGE(key))
    {
        return (-1);
    }

    if(CDCNP_KEY_S_PAGE(cdcnp_key) >= CDCNP_KEY_E_PAGE(key))
    {
        return (1);
    }

    return (0);
}

/**
*
*   note:only for cdcnp item!
*   node key : [s1, e1)
*   cdcnp key: [s2, e2)
*
*   return -1 if e2 <= s1
*   return  1 if s2 >= e1
*   return  0 if e2 > s1 && s2 < e1
*
*   note: page_intersection means cdcnp_key and node has intersection
*
**/
STATIC_CAST static int __cdcnprb_node_data_cmp__page_intersection(const CDCNPRB_NODE *node, const CDCNP_KEY *cdcnp_key)
{
    const CDCNP_ITEM *item;
    const CDCNP_KEY  *key;

    item = (const CDCNP_ITEM *)CDCNP_RB_NODE_ITEM(node);
    key  = CDCNP_ITEM_KEY(item);

    if(CDCNP_KEY_E_PAGE(cdcnp_key) <= CDCNP_KEY_S_PAGE(key))
    {
        return (-1);
    }

    if(CDCNP_KEY_S_PAGE(cdcnp_key) >= CDCNP_KEY_E_PAGE(key))
    {
        return (1);
    }

    return (0);
}

/*return the intersected pos*/
uint32_t cdcnprb_tree_find_intersected_data(const CDCNPRB_POOL *pool, const uint32_t root_pos, const void *cdcnp_key)
{
    uint32_t node_pos;

    node_pos = root_pos;

    while (CDCNPRB_ERR_POS != node_pos)
    {
        const CDCNPRB_NODE *node;
        int cmp_ret;

        node = CDCNPRB_POOL_NODE(pool, node_pos);
        cmp_ret = __cdcnprb_node_data_cmp__page_intersection(node, (const CDCNP_KEY *)cdcnp_key);

        if (0 < cmp_ret)/*node(s_page, e_page) > key(s_page, e_page)*/
        {
            node_pos = CDCNPRB_NODE_LEFT_POS(node);
        }
        else if (0 > cmp_ret)/*node(s_page, e_page) < key(s_page, e_page)*/
        {
            node_pos = CDCNPRB_NODE_RIGHT_POS(node);
        }
        else /*node(s_page, e_page) == key(s_page, e_page)*/
        {
            return (node_pos);
        }
    }

    return (CDCNPRB_ERR_POS);
}

/*return the closest pos*/
uint32_t cdcnprb_tree_find_closest_data(const CDCNPRB_POOL *pool, const uint32_t root_pos, const void *cdcnp_key)
{
    uint32_t node_pos;
    uint32_t diff_closest_page;
    uint32_t node_closest_pos;

    diff_closest_page = ((uint32_t)~0);
    node_closest_pos  = CDCNPRB_ERR_POS;

    node_pos = root_pos;

    while (CDCNPRB_ERR_POS != node_pos)
    {
        const CDCNPRB_NODE *node;
        int cmp_ret;

        node = CDCNPRB_POOL_NODE(pool, node_pos);
        cmp_ret = __cdcnprb_node_data_cmp__s_page_closest(node, (const CDCNP_KEY *)cdcnp_key);

        if (0 < cmp_ret)/*node(s_page, e_page) > key(s_page, e_page)*/
        {
            node_pos = CDCNPRB_NODE_LEFT_POS(node);
        }
        else if (0 > cmp_ret)/*node(s_page, e_page) < key(s_page, e_page)*/
        {
            const CDCNP_ITEM *item;
            const CDCNP_KEY  *key;

            uint32_t diff_page;

            item = (const CDCNP_ITEM *)CDCNP_RB_NODE_ITEM(node);
            key  = CDCNP_ITEM_KEY(item);

            diff_page = CDCNP_KEY_S_PAGE(key) - CDCNP_KEY_S_PAGE((const CDCNP_KEY *)cdcnp_key);
            if(diff_closest_page > diff_page)
            {
                diff_closest_page = diff_page;
                node_closest_pos  = node_pos;
            }

            node_pos = CDCNPRB_NODE_RIGHT_POS(node);
        }
        else /*node(s_page, e_page) == key(s_page, e_page)*/
        {
            return (node_pos);
        }
    }

    return (node_closest_pos);
}

/*return the searched pos*/
uint32_t cdcnprb_tree_search_data(const CDCNPRB_POOL *pool, const uint32_t root_pos, const void *cdcnp_key)
{
    uint32_t node_pos;

    node_pos = root_pos;

    while (CDCNPRB_ERR_POS != node_pos)
    {
        const CDCNPRB_NODE *node;
        int cmp_ret;

        node = CDCNPRB_POOL_NODE(pool, node_pos);
        cmp_ret = __cdcnprb_node_data_cmp__s_page_in(node, (const CDCNP_KEY *)cdcnp_key);

        if (0 < cmp_ret)/*node(s_page, e_page) > key(s_page, e_page)*/
        {
            node_pos = CDCNPRB_NODE_LEFT_POS(node);
        }
        else if (0 > cmp_ret)/*node(s_page, e_page) < key(s_page, e_page)*/
        {
            node_pos = CDCNPRB_NODE_RIGHT_POS(node);
        }
        else /*node(s_page, e_page) == key(s_page, e_page)*/
        {
            return (node_pos);
        }
    }

    return (CDCNPRB_ERR_POS);
}

/*if found duplicate node, return EC_FALSE, otherwise return EC_TRUE*/
EC_BOOL cdcnprb_tree_insert_data(CDCNPRB_POOL *pool, uint32_t *root_pos, const void *cdcnp_key, uint32_t *insert_pos)
{
    uint32_t  node_pos_t;
    uint32_t  new_pos_t;
    uint32_t  parent_pos_t;
    uint32_t  flag; /*0: on left subtree, 1: on right subtree*/

    node_pos_t   = (*root_pos);
    parent_pos_t = CDCNPRB_ERR_POS;
    flag         = ~(uint32_t)0;

    while (CDCNPRB_ERR_POS != node_pos_t)
    {
        CDCNPRB_NODE *node;
        int cmp_ret;

        node = CDCNPRB_POOL_NODE(pool, node_pos_t);
        cmp_ret = __cdcnprb_node_data_cmp__s_page_in(node, (const CDCNP_KEY *)cdcnp_key);

        parent_pos_t = node_pos_t;

        if (0 < cmp_ret)/*node(s_page, e_page) > key(s_page, e_page)*/
        {
            node_pos_t = CDCNPRB_NODE_LEFT_POS(node);
            flag = 0;
        }
        else if (0 > cmp_ret)/*node(s_page, e_page) < key(s_page, e_page)*/
        {
            node_pos_t = CDCNPRB_NODE_RIGHT_POS(node);
            flag = 1;
        }
        else/*node(s_page, e_page) == key(s_page, e_page)*/
        {
            (*insert_pos) = node_pos_t;
            return (EC_FALSE);/*found duplicate*/
        }
    }


    /*not found data in the rbtree*/
    new_pos_t = cdcnprb_node_new(pool);
    if(CDCNPRB_ERR_POS == new_pos_t)
    {
        (*insert_pos) = CDCNPRB_ERR_POS;
        return (EC_FALSE);
    }
    else
    {
        CDCNPRB_NODE *node;

        node  = CDCNPRB_POOL_NODE(pool, new_pos_t);
        //CDCNPRB_NODE_DATA(node) = block_no;

        CDCNPRB_NODE_PARENT_POS(node) = parent_pos_t;
        CDCNPRB_NODE_COLOR(node)      = CDCNPRB_RED;
        CDCNPRB_NODE_LEFT_POS(node)   = CDCNPRB_ERR_POS;
        CDCNPRB_NODE_RIGHT_POS(node)  = CDCNPRB_ERR_POS;

        if(CDCNPRB_ERR_POS == (*root_pos))
        {
            (*root_pos) = new_pos_t;
        }
        else
        {
            CDCNPRB_NODE *parent;
            parent  = CDCNPRB_POOL_NODE(pool, parent_pos_t);

            if(0 == flag)/*on left subtree*/
            {
                CDCNPRB_NODE_LEFT_POS(parent) = new_pos_t;
            }
            else
            {
                CDCNPRB_NODE_RIGHT_POS(parent) = new_pos_t;
            }
        }
        __cdcnprb_tree_insert_color(pool, new_pos_t, root_pos);
    }

    (*insert_pos) = new_pos_t;
    return (EC_TRUE); /*it is new node*/
}

EC_BOOL cdcnprb_tree_delete_data(CDCNPRB_POOL *pool, uint32_t *root_pos, const void *cdcnp_key, uint32_t *delete_pos)
{
    uint32_t node_pos;

    node_pos = cdcnprb_tree_search_data(pool, *root_pos, cdcnp_key);
    if(CDCNPRB_ERR_POS == node_pos)
    {
        return (EC_FALSE);
    }

    cdcnprb_tree_erase(pool, node_pos, root_pos);
    cdcnprb_node_free(pool, node_pos);

    (*delete_pos) = node_pos;
    return (EC_TRUE);
}


EC_BOOL cdcnprb_tree_delete(CDCNPRB_POOL *pool, uint32_t *root_pos, const uint32_t node_pos)
{
    cdcnprb_tree_erase(pool, node_pos, root_pos);
    cdcnprb_node_free(pool, node_pos);
    return (EC_TRUE);
}


/*postorder: left -> right -> root*/
STATIC_CAST static void __cdcnprb_tree_free(CDCNPRB_POOL *pool, const uint32_t node_pos)
{
    CDCNPRB_NODE *node;

    if(CDCNPRB_ERR_POS == node_pos)
    {
        return;
    }

    node  = CDCNPRB_POOL_NODE(pool, node_pos);
    if(CDCNPRB_ERR_POS != CDCNPRB_NODE_LEFT_POS(node))
    {
        __cdcnprb_tree_free(pool, CDCNPRB_NODE_LEFT_POS(node));
    }

    if(CDCNPRB_ERR_POS != CDCNPRB_NODE_RIGHT_POS(node))
    {
        __cdcnprb_tree_free(pool, CDCNPRB_NODE_RIGHT_POS(node));
    }

    cdcnprb_node_free(pool, node_pos);

    return;
}
void cdcnprb_tree_free(CDCNPRB_POOL *pool, const uint32_t root_pos)
{
    __cdcnprb_tree_free(pool, root_pos);
    return;
}

EC_BOOL cdcnprb_pool_init(CDCNPRB_POOL *pool, const uint32_t node_max_num, const uint32_t node_sizeof)
{
    uint32_t node_pos;

    if(CDCNPRB_POOL_MAX_SIZE < node_max_num)
    {
        dbg_log(SEC_0181_CDCNPRB, 0)(LOGSTDERR, "error:cdcnprb_pool_init: node_max_num %u overflow!\n", node_max_num);
        return (EC_FALSE);
    }

    CDCNPRB_POOL_NODE_MAX_NUM(pool)  = node_max_num;
    CDCNPRB_POOL_NODE_USED_NUM(pool) = 0;
    CDCNPRB_POOL_NODE_SIZEOF(pool)   = node_sizeof;

    for(node_pos = 0; node_pos < node_max_num; node_pos ++)
    {
        cdcnprb_node_init(pool, node_pos);
        cdcnprb_node_set_next(pool, node_pos, node_pos + 1);

        if(0 == ((node_pos + 1) % 100000))
        {
            dbg_log(SEC_0181_CDCNPRB, 9)(LOGSTDOUT, "info:cdcnprb_pool_init: init node %u - %u of max %u done\n",
                               node_pos - 99999, node_pos, node_max_num);
        }
    }
    dbg_log(SEC_0181_CDCNPRB, 0)(LOGSTDOUT, "info:cdcnprb_pool_init: init %u nodes done\n", node_max_num);
    cdcnprb_node_set_next(pool, node_max_num - 1, CDCNPRB_ERR_POS);/*overwrite the last one*/

    CDCNPRB_POOL_FREE_HEAD(pool) = 0;/*the free nodes head*/
    return (EC_TRUE);
}

void cdcnprb_pool_clean(CDCNPRB_POOL *pool)
{
    CDCNPRB_POOL_NODE_MAX_NUM(pool)  = 0;
    CDCNPRB_POOL_FREE_HEAD(pool)     = CDCNPRB_ERR_POS;
    return;
}

void cdcnprb_pool_print(LOG *log, const CDCNPRB_POOL *pool)
{
    uint32_t node_pos;
    uint32_t node_max_num;

    node_max_num = CDCNPRB_POOL_NODE_MAX_NUM(pool);

    sys_log(log, "pool %lx, node_max_num %u, node_used_num %u, free_head %u, node_sizeof = %u\n",
                 pool,
                 node_max_num,
                 CDCNPRB_POOL_NODE_USED_NUM(pool),
                 CDCNPRB_POOL_FREE_HEAD(pool),
                 CDCNPRB_POOL_NODE_SIZEOF(pool));

    if(0)
    {
        for(node_pos = 0; node_pos < node_max_num; node_pos ++)
        {
            if(EC_TRUE == cdcnprb_node_is_used(pool, node_pos))
            {
                cdcnprb_node_print(log, pool, node_pos);
            }
        }
    }
    return;
}


EC_BOOL cdcnprb_pool_is_empty(const CDCNPRB_POOL *pool)
{
    if (0 == CDCNPRB_POOL_NODE_USED_NUM(pool))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL cdcnprb_pool_is_full(const CDCNPRB_POOL *pool)
{
    if (CDCNPRB_POOL_NODE_MAX_NUM(pool) == CDCNPRB_POOL_NODE_USED_NUM(pool))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

/*visit the root node first: root -> left -> right*/
void cdcnprb_preorder_print(LOG *log, const CDCNPRB_POOL *pool, const uint32_t node_pos)
{
    const CDCNPRB_NODE *node;

    if(CDCNPRB_ERR_POS == node_pos)
    {
        return;
    }

    node  = CDCNPRB_POOL_NODE(pool, node_pos);
    cdcnprb_node_print(log, pool, node_pos);

    if(CDCNPRB_ERR_POS != CDCNPRB_NODE_LEFT_POS(node))
    {
        cdcnprb_preorder_print(log, pool, CDCNPRB_NODE_LEFT_POS(node));
    }

    if(CDCNPRB_ERR_POS != CDCNPRB_NODE_RIGHT_POS(node))
    {
        cdcnprb_preorder_print(log, pool, CDCNPRB_NODE_RIGHT_POS(node));
    }

    return;
}

/*visit the left subtree, then the root node: left -> root -> right*/
void cdcnprb_inorder_print(LOG *log, const CDCNPRB_POOL *pool, const uint32_t node_pos)
{
    const CDCNPRB_NODE *node;

    if(CDCNPRB_ERR_POS == node_pos)
    {
        return;
    }

    node  = CDCNPRB_POOL_NODE(pool, node_pos);
    if(CDCNPRB_ERR_POS != CDCNPRB_NODE_LEFT_POS(node))
    {
        cdcnprb_inorder_print(log, pool, CDCNPRB_NODE_LEFT_POS(node));
    }

    cdcnprb_node_print(log, pool, node_pos);

    if(CDCNPRB_ERR_POS != CDCNPRB_NODE_RIGHT_POS(node))
    {
        cdcnprb_inorder_print(log, pool, CDCNPRB_NODE_RIGHT_POS(node));
    }

    return;
}

/*visit the root node last: left -> right -> root*/
void cdcnprb_postorder_print(LOG *log, const CDCNPRB_POOL *pool, const uint32_t node_pos)
{
    const CDCNPRB_NODE *node;

    if(CDCNPRB_ERR_POS == node_pos)
    {
        return;
    }

    node  = CDCNPRB_POOL_NODE(pool, node_pos);
    if(CDCNPRB_ERR_POS != CDCNPRB_NODE_LEFT_POS(node))
    {
        cdcnprb_postorder_print(log, pool, CDCNPRB_NODE_LEFT_POS(node));
    }

    if(CDCNPRB_ERR_POS != CDCNPRB_NODE_RIGHT_POS(node))
    {
        cdcnprb_postorder_print(log, pool, CDCNPRB_NODE_RIGHT_POS(node));
    }

    cdcnprb_node_print(log, pool, node_pos);

    return;
}


/*visit the root node first: root -> left -> right*/
void cdcnprb_preorder_print_level(LOG *log, const CDCNPRB_POOL *pool, const uint32_t node_pos, const uint32_t level)
{
    const CDCNPRB_NODE *node;

    if(CDCNPRB_ERR_POS == node_pos)
    {
        return;
    }

    node  = CDCNPRB_POOL_NODE(pool, node_pos);
    cdcnprb_node_print_level(log, pool, node_pos, level);

    if(CDCNPRB_ERR_POS != CDCNPRB_NODE_LEFT_POS(node))
    {
        cdcnprb_preorder_print_level(log, pool, CDCNPRB_NODE_LEFT_POS(node), level + 1);
    }

    if(CDCNPRB_ERR_POS != CDCNPRB_NODE_RIGHT_POS(node))
    {
        cdcnprb_preorder_print_level(log, pool, CDCNPRB_NODE_RIGHT_POS(node), level + 1);
    }

    return;
}

void cdcnprb_inorder_walk(const CDCNPRB_POOL *pool, const uint32_t node_pos, void (*walker)(void *, const void *, const uint32_t), void *arg1, const void *arg2)
{
    const CDCNPRB_NODE *node;

    if(CDCNPRB_ERR_POS == node_pos)
    {
        return;
    }

    node  = CDCNPRB_POOL_NODE(pool, node_pos);
    if(CDCNPRB_ERR_POS != CDCNPRB_NODE_LEFT_POS(node))
    {
        cdcnprb_inorder_walk(pool, CDCNPRB_NODE_LEFT_POS(node), walker, arg1, arg2);
    }

    walker(arg1, arg2, node_pos);

    if(CDCNPRB_ERR_POS != CDCNPRB_NODE_RIGHT_POS(node))
    {
        cdcnprb_inorder_walk(pool, CDCNPRB_NODE_RIGHT_POS(node), walker, arg1, arg2);
    }

    return;
}

void cdcnprb_tree_print(LOG *log, const CDCNPRB_POOL *pool, const uint32_t root_pos)
{
    uint32_t node_pos;

    sys_log(log, "[root = %5d]\n", root_pos);
    for(node_pos = cdcnprb_tree_first_node(pool, root_pos); CDCNPRB_ERR_POS != node_pos; node_pos = cdcnprb_tree_next_node(pool, node_pos))
    {
        cdcnprb_node_print(log, pool, node_pos);
    }
    return;
}

/* ---- debug ---- */
EC_BOOL cdcnprb_node_debug_cmp(const CDCNPRB_NODE *node_1st, const CDCNPRB_NODE *node_2nd, int (*node_cmp_data)(const CDCNPRB_NODE *, const CDCNPRB_NODE *))
{
    if(CDCNPRB_NODE_USED_FLAG(node_1st) != CDCNPRB_NODE_USED_FLAG(node_2nd))
    {
        dbg_log(SEC_0181_CDCNPRB, 0)(LOGSTDERR, "error:cdcnprb_node_debug_cmp: inconsistent CDCNPRB_NODE_USED_FLAG: %u != %u\n",
                            CDCNPRB_NODE_USED_FLAG(node_1st), CDCNPRB_NODE_USED_FLAG(node_2nd));
        return (EC_FALSE);
    }
#if 0
    if(CDCNPRB_NODE_NOT_USED == CDCNPRB_NODE_USED_FLAG(node_1st))
    {
        return (EC_TRUE);
    }
#endif

    if(CDCNPRB_NODE_COLOR(node_1st) != CDCNPRB_NODE_COLOR(node_2nd))
    {
        dbg_log(SEC_0181_CDCNPRB, 0)(LOGSTDERR, "error:cdcnprb_node_debug_cmp: inconsistent CDCNPRB_NODE_COLOR: %u != %u\n",
                            CDCNPRB_NODE_COLOR(node_1st), CDCNPRB_NODE_COLOR(node_2nd));
        return (EC_FALSE);
    }

    if(CDCNPRB_NODE_PARENT_POS(node_1st) != CDCNPRB_NODE_PARENT_POS(node_2nd))
    {
        dbg_log(SEC_0181_CDCNPRB, 0)(LOGSTDERR, "error:cdcnprb_node_debug_cmp: inconsistent CDCNPRB_NODE_PARENT_POS: %u != %u\n",
                            CDCNPRB_NODE_PARENT_POS(node_1st), CDCNPRB_NODE_PARENT_POS(node_2nd));
        return (EC_FALSE);
    }

    if(CDCNPRB_NODE_RIGHT_POS(node_1st) != CDCNPRB_NODE_RIGHT_POS(node_2nd))
    {
        dbg_log(SEC_0181_CDCNPRB, 0)(LOGSTDERR, "error:cdcnprb_node_debug_cmp: inconsistent CDCNPRB_NODE_RIGHT_POS: %u != %u\n",
                            CDCNPRB_NODE_RIGHT_POS(node_1st), CDCNPRB_NODE_RIGHT_POS(node_2nd));
        return (EC_FALSE);
    }

    if(CDCNPRB_NODE_LEFT_POS(node_1st) != CDCNPRB_NODE_LEFT_POS(node_2nd))
    {
        dbg_log(SEC_0181_CDCNPRB, 0)(LOGSTDERR, "error:cdcnprb_node_debug_cmp: inconsistent CDCNPRB_NODE_LEFT_POS: %u != %u\n",
                            CDCNPRB_NODE_LEFT_POS(node_1st), CDCNPRB_NODE_LEFT_POS(node_2nd));
        return (EC_FALSE);
    }

    if(CDCNPRB_NODE_USED == CDCNPRB_NODE_USED_FLAG(node_1st))
    {
        if(0 != node_cmp_data(node_1st, node_2nd))
        {
            dbg_log(SEC_0181_CDCNPRB, 0)(LOGSTDERR, "error:cdcnprb_node_debug_cmp: inconsistent data part\n");
            return (EC_FALSE);
        }
    }
    else
    {
        if(CDCNPRB_NODE_NEXT_POS(node_1st) != CDCNPRB_NODE_NEXT_POS(node_2nd))
        {
            dbg_log(SEC_0181_CDCNPRB, 0)(LOGSTDERR, "error:cdcnprb_node_debug_cmp: inconsistent CDCNPRB_NODE_NEXT_POS: %u != %u\n",
                                CDCNPRB_NODE_NEXT_POS(node_1st), CDCNPRB_NODE_NEXT_POS(node_2nd));
            return (EC_FALSE);
        }
    }
    return (EC_TRUE);
}

EC_BOOL cdcnprb_debug_cmp(const CDCNPRB_POOL *pool_1st, const CDCNPRB_POOL *pool_2nd, int (*node_cmp_data)(const CDCNPRB_NODE *, const CDCNPRB_NODE *))
{
    uint32_t  node_max_num;
    uint32_t  node_pos;

    if(CDCNPRB_POOL_FREE_HEAD(pool_1st) != CDCNPRB_POOL_FREE_HEAD(pool_2nd))
    {
        dbg_log(SEC_0181_CDCNPRB, 0)(LOGSTDERR, "error:cdcnprb_debug_cmp: inconsistent CDCNPRB_POOL_FREE_HEAD: %u != %u\n",
                            CDCNPRB_POOL_FREE_HEAD(pool_1st), CDCNPRB_POOL_FREE_HEAD(pool_2nd));
        return (EC_FALSE);
    }

    if(CDCNPRB_POOL_NODE_MAX_NUM(pool_1st) != CDCNPRB_POOL_NODE_MAX_NUM(pool_2nd))
    {
        dbg_log(SEC_0181_CDCNPRB, 0)(LOGSTDERR, "error:cdcnprb_debug_cmp: inconsistent CDCNPRB_POOL_NODE_MAX_NUM: %u != %u\n",
                            CDCNPRB_POOL_NODE_MAX_NUM(pool_1st), CDCNPRB_POOL_NODE_MAX_NUM(pool_2nd));
        return (EC_FALSE);
    }

    if(CDCNPRB_POOL_NODE_USED_NUM(pool_1st) != CDCNPRB_POOL_NODE_USED_NUM(pool_2nd))
    {
        dbg_log(SEC_0181_CDCNPRB, 0)(LOGSTDERR, "error:cdcnprb_debug_cmp: inconsistent CDCNPRB_POOL_NODE_USED_NUM: %u != %u\n",
                            CDCNPRB_POOL_NODE_USED_NUM(pool_1st), CDCNPRB_POOL_NODE_USED_NUM(pool_2nd));
        return (EC_FALSE);
    }

    if(CDCNPRB_POOL_NODE_SIZEOF(pool_1st) != CDCNPRB_POOL_NODE_SIZEOF(pool_2nd))
    {
        dbg_log(SEC_0181_CDCNPRB, 0)(LOGSTDERR, "error:cdcnprb_debug_cmp: inconsistent CDCNPRB_POOL_NODE_SIZEOF: %u != %u\n",
                            CDCNPRB_POOL_NODE_SIZEOF(pool_1st), CDCNPRB_POOL_NODE_SIZEOF(pool_2nd));
        return (EC_FALSE);
    }

    node_max_num = CDCNPRB_POOL_NODE_MAX_NUM(pool_1st);
    for(node_pos = 0; node_pos < node_max_num; node_pos ++)
    {
        CDCNPRB_NODE *node_1st;
        CDCNPRB_NODE *node_2nd;

        node_1st = CDCNPRB_POOL_NODE(pool_1st, node_pos);
        node_2nd = CDCNPRB_POOL_NODE(pool_2nd, node_pos);

        if(EC_FALSE == cdcnprb_node_debug_cmp(node_1st, node_2nd, node_cmp_data))
        {
            dbg_log(SEC_0181_CDCNPRB, 0)(LOGSTDERR, "error:cdcnprb_debug_cmp: inconsistent node at pos %u\n", node_pos);
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}


#ifdef __cplusplus
}
#endif/*__cplusplus*/
