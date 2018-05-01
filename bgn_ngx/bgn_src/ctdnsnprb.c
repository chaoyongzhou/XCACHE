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

#include "type.h"
#include "mm.h"
#include "log.h"

#include "cmisc.h"

#include "db_internal.h"

#include "ctdnsnprb.h"
#include "ctdns.h"

/*new a CTDNSNPRB_NODE and return its position*/
uint32_t ctdnsnprb_node_new(CTDNSNPRB_POOL *pool)
{
    uint32_t node_pos_t;
    CTDNSNPRB_NODE *node;

    node_pos_t = CTDNSNPRB_POOL_FREE_HEAD(pool);
    if(CTDNSNPRB_ERR_POS == node_pos_t)
    {
        dbg_log(SEC_0021_CTDNSNPRB, 0)(LOGSTDERR, "error:ctdnsnprb_node_new: no free node in pool\n");
        return (CTDNSNPRB_ERR_POS);
    }

    if(CTDNSNPRB_POOL_FREE_HEAD(pool) >= CTDNSNPRB_POOL_NODE_MAX_NUM(pool))
    {
        dbg_log(SEC_0021_CTDNSNPRB, 0)(LOGSTDERR, "error:ctdnsnprb_node_new: found conflict: free head %u >= max num %u\n",
                            CTDNSNPRB_POOL_FREE_HEAD(pool), CTDNSNPRB_POOL_NODE_MAX_NUM(pool));
        return (CTDNSNPRB_ERR_POS);
    }

    ASSERT(CTDNSNPRB_POOL_FREE_HEAD(pool) < CTDNSNPRB_POOL_NODE_MAX_NUM(pool));

    node = CTDNSNPRB_POOL_NODE(pool, node_pos_t);
#if 0
    dbg_log(SEC_0021_CTDNSNPRB, 9)(LOGSTDNULL, "[DEBUG] ctdnsnprb_node_new: pool %p, max %u, used %u, free head %u, next %u\n",
                       pool,
                       CTDNSNPRB_POOL_NODE_MAX_NUM(pool),
                       CTDNSNPRB_POOL_NODE_USED_NUM(pool),
                       CTDNSNPRB_POOL_FREE_HEAD(pool),
                       CTDNSNPRB_NODE_NEXT_POS(node));
#endif
    CTDNSNPRB_POOL_FREE_HEAD(pool) = CTDNSNPRB_NODE_NEXT_POS(node);
    CTDNSNPRB_POOL_NODE_USED_NUM(pool) ++;

    CTDNSNPRB_NODE_NEXT_POS(node)  = CTDNSNPRB_ERR_POS;
    CTDNSNPRB_NODE_USED_FLAG(node) = CTDNSNPRB_NODE_USED;

    return (node_pos_t);
}

/*free a CTDNSNPRB_NODE and return its position to the pool*/
void ctdnsnprb_node_free(CTDNSNPRB_POOL *pool, const uint32_t node_pos)
{
    if(CTDNSNPRB_ERR_POS != node_pos)
    {
        CTDNSNPRB_NODE *node;

        ASSERT(node_pos < CTDNSNPRB_POOL_NODE_MAX_NUM(pool));

        node = CTDNSNPRB_POOL_NODE(pool, node_pos);
        ASSERT(CTDNSNPRB_NODE_IS_USED(node));

        CTDNSNPRB_NODE_USED_FLAG(node)  = CTDNSNPRB_NODE_NOT_USED;
        CTDNSNPRB_NODE_PARENT_POS(node) = CTDNSNPRB_ERR_POS;
        CTDNSNPRB_NODE_RIGHT_POS(node)  = CTDNSNPRB_ERR_POS;
        CTDNSNPRB_NODE_LEFT_POS(node)   = CTDNSNPRB_ERR_POS;
        CTDNSNPRB_NODE_NEXT_POS(node)   = CTDNSNPRB_POOL_FREE_HEAD(pool);
        CTDNSNPRB_NODE_COLOR(node)      = CTDNSNPRB_BLACK;

        CTDNSNPRB_POOL_FREE_HEAD(pool)  = node_pos;
        CTDNSNPRB_POOL_NODE_USED_NUM(pool) --;
    }
    return;
}

void ctdnsnprb_node_init(CTDNSNPRB_POOL *pool, const uint32_t node_pos)
{
    CTDNSNPRB_NODE *node;

    node  = CTDNSNPRB_POOL_NODE(pool, node_pos);

    CTDNSNPRB_NODE_PARENT_POS(node) = CTDNSNPRB_ERR_POS;
    CTDNSNPRB_NODE_RIGHT_POS(node)  = CTDNSNPRB_ERR_POS;
    CTDNSNPRB_NODE_LEFT_POS(node)   = CTDNSNPRB_ERR_POS;
    CTDNSNPRB_NODE_USED_FLAG(node)  = CTDNSNPRB_NODE_NOT_USED;
    CTDNSNPRB_NODE_NEXT_POS(node)   = CTDNSNPRB_ERR_POS;
    CTDNSNPRB_NODE_COLOR(node)      = CTDNSNPRB_BLACK;

    return;
}

void ctdnsnprb_node_clean(CTDNSNPRB_POOL *pool, const uint32_t node_pos)
{
    CTDNSNPRB_NODE *node;

    ASSERT(node_pos < CTDNSNPRB_POOL_NODE_MAX_NUM(pool));

    node = CTDNSNPRB_POOL_NODE(pool, node_pos);

    CTDNSNPRB_NODE_PARENT_POS(node) = CTDNSNPRB_ERR_POS;
    CTDNSNPRB_NODE_RIGHT_POS(node)  = CTDNSNPRB_ERR_POS;
    CTDNSNPRB_NODE_LEFT_POS(node)   = CTDNSNPRB_ERR_POS;
    CTDNSNPRB_NODE_USED_FLAG(node)  = CTDNSNPRB_NODE_NOT_USED;
    CTDNSNPRB_NODE_NEXT_POS(node)   = CTDNSNPRB_ERR_POS;
    CTDNSNPRB_NODE_COLOR(node)      = CTDNSNPRB_BLACK;

    return;
}

void ctdnsnprb_node_set_next(CTDNSNPRB_POOL *pool, const uint32_t node_pos, const uint32_t next_pos)
{
    CTDNSNPRB_NODE *node;

    node = CTDNSNPRB_POOL_NODE(pool, node_pos);
    CTDNSNPRB_NODE_NEXT_POS(node) = next_pos;

    return;
}

EC_BOOL ctdnsnprb_node_is_used(const CTDNSNPRB_POOL *pool, const uint32_t node_pos)
{
    const CTDNSNPRB_NODE *node;
    node  = CTDNSNPRB_POOL_NODE(pool, node_pos);

    if(CTDNSNPRB_NODE_IS_USED(node))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

void ctdnsnprb_node_print(LOG *log, const CTDNSNPRB_POOL *pool, const uint32_t node_pos)
{
    const CTDNSNPRB_NODE *node;
    node  = CTDNSNPRB_POOL_NODE(pool, node_pos);

    sys_log(log, "%5d: parent = %5d, left = %5d, right = %5d, flg = %s, color = %s, %s = %5d\n",
                       node_pos,
                       CTDNSNPRB_NODE_PARENT_POS(node),
                       CTDNSNPRB_NODE_LEFT_POS(node),
                       CTDNSNPRB_NODE_RIGHT_POS(node),
                       CTDNSNPRB_NODE_IS_USED(node) ? "used" : "n.a.",
                       CTDNSNPRB_NODE_IS_USED(node) ? (CTDNSNPRB_NODE_IS_RED(node) ? "red  " : "black") : "#####",
                       CTDNSNPRB_NODE_IS_USED(node) ? "data" : "next",
                       CTDNSNPRB_NODE_IS_USED(node) ? CTDNSNPRB_NODE_DATA(node) : CTDNSNPRB_NODE_NEXT_POS(node)
                       );
    return;
}

void ctdnsnprb_node_print_level(LOG *log, const CTDNSNPRB_POOL *pool, const uint32_t node_pos, const uint32_t level)
{
    const CTDNSNPRB_NODE *node;
    node  = CTDNSNPRB_POOL_NODE(pool, node_pos);

    c_ident_print(log, level);
    sys_print(log, "%5d: parent = %5d, left = %5d, right = %5d, flg = %s, color = %s, %s = %5d\n",
                       node_pos,
                       CTDNSNPRB_NODE_PARENT_POS(node),
                       CTDNSNPRB_NODE_LEFT_POS(node),
                       CTDNSNPRB_NODE_RIGHT_POS(node),
                       CTDNSNPRB_NODE_IS_USED(node) ? "used" : "NOT used",
                       CTDNSNPRB_NODE_IS_RED(node)  ? "red  " : "black",
                       CTDNSNPRB_NODE_IS_USED(node) ? "data" : "next",
                       CTDNSNPRB_NODE_IS_USED(node) ? CTDNSNPRB_NODE_DATA(node) : CTDNSNPRB_NODE_NEXT_POS(node)
                       );
    return;
}


STATIC_CAST static void __ctdnsnprb_tree_rotate_left(CTDNSNPRB_POOL *pool, const uint32_t node_pos, uint32_t *root_pos)
{
    CTDNSNPRB_NODE *node;
    CTDNSNPRB_NODE *right;

    uint32_t  right_pos;

    node  = CTDNSNPRB_POOL_NODE(pool, node_pos);

    right_pos = CTDNSNPRB_NODE_RIGHT_POS(node);
    right = CTDNSNPRB_POOL_NODE(pool, right_pos);

    if(CTDNSNPRB_ERR_POS != (CTDNSNPRB_NODE_RIGHT_POS(node) = CTDNSNPRB_NODE_LEFT_POS(right)))
    {
        CTDNSNPRB_NODE *left;
        left = CTDNSNPRB_POOL_NODE(pool, CTDNSNPRB_NODE_LEFT_POS(right));
        CTDNSNPRB_NODE_PARENT_POS(left) = node_pos;
    }
    CTDNSNPRB_NODE_LEFT_POS(right) = node_pos;

    if(CTDNSNPRB_ERR_POS != (CTDNSNPRB_NODE_PARENT_POS(right) = CTDNSNPRB_NODE_PARENT_POS(node)))
    {
        CTDNSNPRB_NODE *parent;
        parent = CTDNSNPRB_POOL_NODE(pool, CTDNSNPRB_NODE_PARENT_POS(node));

        if (node_pos == CTDNSNPRB_NODE_LEFT_POS(parent))
        {
            CTDNSNPRB_NODE_LEFT_POS(parent) = right_pos;
        }
        else
        {
            CTDNSNPRB_NODE_RIGHT_POS(parent) = right_pos;
        }
    }
    else
    {
        (*root_pos) = right_pos;
    }
    CTDNSNPRB_NODE_PARENT_POS(node) = right_pos;
    return;
}

STATIC_CAST static void __ctdnsnprb_tree_rotate_right(CTDNSNPRB_POOL *pool, const uint32_t node_pos, uint32_t *root_pos)
{
    CTDNSNPRB_NODE *node;
    CTDNSNPRB_NODE *left;
    uint32_t  left_pos;

    node  = CTDNSNPRB_POOL_NODE(pool, node_pos);

    left_pos = CTDNSNPRB_NODE_LEFT_POS(node);
    left = CTDNSNPRB_POOL_NODE(pool, left_pos);

    if (CTDNSNPRB_ERR_POS != (CTDNSNPRB_NODE_LEFT_POS(node) = CTDNSNPRB_NODE_RIGHT_POS(left)))
    {
        CTDNSNPRB_NODE *right;
        right = CTDNSNPRB_POOL_NODE(pool, CTDNSNPRB_NODE_RIGHT_POS(left));
        CTDNSNPRB_NODE_PARENT_POS(right) = node_pos;
    }
    CTDNSNPRB_NODE_RIGHT_POS(left) = node_pos;

    if (CTDNSNPRB_ERR_POS != (CTDNSNPRB_NODE_PARENT_POS(left) = CTDNSNPRB_NODE_PARENT_POS(node)))
    {
        CTDNSNPRB_NODE *parent;
        parent = CTDNSNPRB_POOL_NODE(pool, CTDNSNPRB_NODE_PARENT_POS(node));

        if (node_pos == CTDNSNPRB_NODE_RIGHT_POS(parent))
        {
            CTDNSNPRB_NODE_RIGHT_POS(parent) = left_pos;
        }
        else
        {
            CTDNSNPRB_NODE_LEFT_POS(parent) = left_pos;
        }
    }
    else
    {
        (*root_pos) = left_pos;
    }
    CTDNSNPRB_NODE_PARENT_POS(node) = left_pos;
    return;
}

STATIC_CAST static void __ctdnsnprb_tree_insert_color(CTDNSNPRB_POOL *pool, const uint32_t node_pos, uint32_t *root_pos)
{
    CTDNSNPRB_NODE *node;
    CTDNSNPRB_NODE *root;
    CTDNSNPRB_NODE *parent;

    uint32_t  node_pos_t;

    node_pos_t = node_pos;
    node  = CTDNSNPRB_POOL_NODE(pool, node_pos_t);

    while (NULL_PTR != (parent = CTDNSNPRB_POOL_NODE(pool, CTDNSNPRB_NODE_PARENT_POS(node))) /*parent is valid*/
         && CTDNSNPRB_RED == CTDNSNPRB_NODE_COLOR(parent))
    {
        uint32_t  parent_pos;
        uint32_t  gparent_pos;
        CTDNSNPRB_NODE *gparent;

        parent_pos = CTDNSNPRB_NODE_PARENT_POS(node);

        gparent_pos = CTDNSNPRB_NODE_PARENT_POS(parent);
        ASSERT(CTDNSNPRB_ERR_POS != gparent_pos);
        gparent = CTDNSNPRB_POOL_NODE(pool, gparent_pos);

        if (parent_pos == CTDNSNPRB_NODE_LEFT_POS(gparent))
        {
            {
                CTDNSNPRB_NODE *uncle;
                if (NULL_PTR != (uncle = CTDNSNPRB_POOL_NODE(pool, CTDNSNPRB_NODE_RIGHT_POS(gparent))) /*uncle is valid*/
                   && CTDNSNPRB_RED == CTDNSNPRB_NODE_COLOR(uncle))
                {
                    CTDNSNPRB_NODE_COLOR(uncle)   = CTDNSNPRB_BLACK;
                    CTDNSNPRB_NODE_COLOR(parent)  = CTDNSNPRB_BLACK;
                    CTDNSNPRB_NODE_COLOR(gparent) = CTDNSNPRB_RED;

                    node = gparent;
                    node_pos_t = gparent_pos;
                    continue;
                }
            }

            if (CTDNSNPRB_NODE_RIGHT_POS(parent) == node_pos_t)
            {
                __ctdnsnprb_tree_rotate_left(pool, parent_pos, root_pos);
                XCHG(CTDNSNPRB_NODE *, parent, node);
                XCHG(uint32_t, parent_pos, node_pos_t);
            }

            CTDNSNPRB_NODE_COLOR(parent)  = CTDNSNPRB_BLACK;
            CTDNSNPRB_NODE_COLOR(gparent) = CTDNSNPRB_RED;
            __ctdnsnprb_tree_rotate_right(pool, gparent_pos, root_pos);
         }
         else
         {
            {
                CTDNSNPRB_NODE *uncle;
                if (NULL_PTR != (uncle = CTDNSNPRB_POOL_NODE(pool, CTDNSNPRB_NODE_LEFT_POS(gparent))) /*uncle is valid*/
                    && CTDNSNPRB_RED == CTDNSNPRB_NODE_COLOR(uncle))
                {
                    CTDNSNPRB_NODE_COLOR(uncle)   = CTDNSNPRB_BLACK;
                    CTDNSNPRB_NODE_COLOR(parent)  = CTDNSNPRB_BLACK;
                    CTDNSNPRB_NODE_COLOR(gparent) = CTDNSNPRB_RED;

                    node = gparent;
                    node_pos_t = gparent_pos;
                    continue;
                }
            }

            if (CTDNSNPRB_NODE_LEFT_POS(parent) == node_pos_t)
            {
                __ctdnsnprb_tree_rotate_right(pool, parent_pos, root_pos);
                XCHG(CTDNSNPRB_NODE *, parent, node);
                XCHG(uint32_t, parent_pos, node_pos_t);
            }

            CTDNSNPRB_NODE_COLOR(parent)  = CTDNSNPRB_BLACK;
            CTDNSNPRB_NODE_COLOR(gparent) = CTDNSNPRB_RED;
            __ctdnsnprb_tree_rotate_left(pool, gparent_pos, root_pos);
        }
    }

    root = CTDNSNPRB_POOL_NODE(pool, *root_pos);
    CTDNSNPRB_NODE_COLOR(root) = CTDNSNPRB_BLACK;
    return;
}

STATIC_CAST static void __ctdnsnprb_tree_erase_color(CTDNSNPRB_POOL *pool, const uint32_t node_pos, const uint32_t parent_pos, uint32_t *root_pos)
{
    CTDNSNPRB_NODE *node;
    uint32_t  node_pos_t;
    uint32_t  parent_pos_t;

    node_pos_t   = node_pos;
    parent_pos_t = parent_pos;

    while ((NULL_PTR == (node = CTDNSNPRB_POOL_NODE(pool, node_pos_t)) || CTDNSNPRB_BLACK == CTDNSNPRB_NODE_COLOR(node)) && node_pos_t != (*root_pos))
    {
        CTDNSNPRB_NODE *parent;

        parent = CTDNSNPRB_POOL_NODE(pool, parent_pos_t);

        if (CTDNSNPRB_NODE_LEFT_POS(parent) == node_pos_t)
        {
            CTDNSNPRB_NODE *other;
            CTDNSNPRB_NODE *o_left;
            CTDNSNPRB_NODE *o_right;
            uint32_t  other_pos;

            other_pos = CTDNSNPRB_NODE_RIGHT_POS(parent);
            other = CTDNSNPRB_POOL_NODE(pool, other_pos);

            if (CTDNSNPRB_RED == CTDNSNPRB_NODE_COLOR(other))
            {
                CTDNSNPRB_NODE_COLOR(other)  = CTDNSNPRB_BLACK;
                CTDNSNPRB_NODE_COLOR(parent) = CTDNSNPRB_RED;

                __ctdnsnprb_tree_rotate_left(pool, parent_pos_t, root_pos);

                other_pos = CTDNSNPRB_NODE_RIGHT_POS(parent);
                other = CTDNSNPRB_POOL_NODE(pool, other_pos);
            }

            o_left = CTDNSNPRB_POOL_NODE(pool, CTDNSNPRB_NODE_LEFT_POS(other));
            o_right = CTDNSNPRB_POOL_NODE(pool, CTDNSNPRB_NODE_RIGHT_POS(other));

            if((NULL_PTR == o_left || CTDNSNPRB_BLACK == CTDNSNPRB_NODE_COLOR(o_left))
            && (NULL_PTR == o_right || CTDNSNPRB_BLACK == CTDNSNPRB_NODE_COLOR(o_right)))
            {
                CTDNSNPRB_NODE_COLOR(other) = CTDNSNPRB_RED;

                node_pos_t = parent_pos_t;
                node = CTDNSNPRB_POOL_NODE(pool, node_pos_t);

                parent_pos_t = CTDNSNPRB_NODE_PARENT_POS(node);
                parent = CTDNSNPRB_POOL_NODE(pool, parent_pos_t);
            }
            else
            {
                if (NULL_PTR == o_right || CTDNSNPRB_BLACK == CTDNSNPRB_NODE_COLOR(o_right))
                {
                    if (NULL_PTR != o_left)
                    {
                        CTDNSNPRB_NODE_COLOR(o_left) = CTDNSNPRB_BLACK;
                    }
                    CTDNSNPRB_NODE_COLOR(other) = CTDNSNPRB_RED;

                    __ctdnsnprb_tree_rotate_right(pool, other_pos, root_pos);

                    other_pos = CTDNSNPRB_NODE_RIGHT_POS(parent);
                    other = CTDNSNPRB_POOL_NODE(pool, other_pos);
                    /*note: other was changed here*/
                }

                CTDNSNPRB_NODE_COLOR(other) = CTDNSNPRB_NODE_COLOR(parent);
                CTDNSNPRB_NODE_COLOR(parent) = CTDNSNPRB_BLACK;

                /*due to other may be changed before, have to get o_right again here*/
                o_right = CTDNSNPRB_POOL_NODE(pool, CTDNSNPRB_NODE_RIGHT_POS(other));
                if (NULL_PTR != o_right)
                {
                    CTDNSNPRB_NODE_COLOR(o_right) = CTDNSNPRB_BLACK;
                }

                __ctdnsnprb_tree_rotate_left(pool, parent_pos_t, root_pos);
                node_pos_t = (*root_pos);
                break;
            }
        }
        else
        {
            CTDNSNPRB_NODE *other;
            CTDNSNPRB_NODE *o_left;
            CTDNSNPRB_NODE *o_right;
            uint32_t  other_pos;

            other_pos = CTDNSNPRB_NODE_LEFT_POS(parent);
            other = CTDNSNPRB_POOL_NODE(pool, other_pos);

            if (CTDNSNPRB_RED == CTDNSNPRB_NODE_COLOR(other))
            {
                CTDNSNPRB_NODE_COLOR(other) = CTDNSNPRB_BLACK;
                CTDNSNPRB_NODE_COLOR(parent) = CTDNSNPRB_RED;

                __ctdnsnprb_tree_rotate_right(pool, parent_pos_t, root_pos);

                other_pos = CTDNSNPRB_NODE_LEFT_POS(parent);
                other = CTDNSNPRB_POOL_NODE(pool, other_pos);
            }

            o_left = CTDNSNPRB_POOL_NODE(pool, CTDNSNPRB_NODE_LEFT_POS(other));
            o_right = CTDNSNPRB_POOL_NODE(pool, CTDNSNPRB_NODE_RIGHT_POS(other));

            if ((NULL_PTR == o_left  || CTDNSNPRB_BLACK == CTDNSNPRB_NODE_COLOR(o_left))
             && (NULL_PTR == o_right || CTDNSNPRB_BLACK == CTDNSNPRB_NODE_COLOR(o_right)))
            {
                CTDNSNPRB_NODE_COLOR(other) = CTDNSNPRB_RED;

                node_pos_t = parent_pos_t;
                node = CTDNSNPRB_POOL_NODE(pool, node_pos_t);

                parent_pos_t = CTDNSNPRB_NODE_PARENT_POS(node);
                parent = CTDNSNPRB_POOL_NODE(pool, parent_pos_t);
            }
            else
            {
                if (NULL_PTR == o_left  || CTDNSNPRB_BLACK == CTDNSNPRB_NODE_COLOR(o_left))
                {
                    if (NULL_PTR != o_right)
                    {
                        CTDNSNPRB_NODE_COLOR(o_right) = CTDNSNPRB_BLACK;
                    }

                    CTDNSNPRB_NODE_COLOR(other) = CTDNSNPRB_RED;

                    __ctdnsnprb_tree_rotate_left(pool, other_pos, root_pos);

                    other_pos = CTDNSNPRB_NODE_LEFT_POS(parent);
                    other = CTDNSNPRB_POOL_NODE(pool, other_pos);
                    /*note: other was changed here*/
                }

                CTDNSNPRB_NODE_COLOR(other) = CTDNSNPRB_NODE_COLOR(parent);
                CTDNSNPRB_NODE_COLOR(parent) = CTDNSNPRB_BLACK;

                /*due to other may be changed before, have to get o_left again here*/
                o_left = CTDNSNPRB_POOL_NODE(pool, CTDNSNPRB_NODE_LEFT_POS(other));
                if (NULL_PTR != o_left)
                {
                    CTDNSNPRB_NODE_COLOR(o_left) = CTDNSNPRB_BLACK;
                }
                __ctdnsnprb_tree_rotate_right(pool, parent_pos_t, root_pos);
                node_pos_t = (*root_pos);
                break;
            }
        }
    }

    node = CTDNSNPRB_POOL_NODE(pool, node_pos_t);
    if (NULL_PTR != node)
    {
        CTDNSNPRB_NODE_COLOR(node) = CTDNSNPRB_BLACK;
    }
    return;
}

/*note: erase from tree but not recycle to free nodes pool*/
EC_BOOL ctdnsnprb_tree_erase(CTDNSNPRB_POOL *pool, const uint32_t node_pos, uint32_t *root_pos)
{
    CTDNSNPRB_NODE *node;

    uint32_t node_pos_t;
    uint32_t child_pos;
    uint32_t parent_pos;
    uint32_t color;

    node_pos_t = node_pos;
    node = CTDNSNPRB_POOL_NODE(pool, node_pos_t);

    ASSERT(NULL_PTR != node);
    ASSERT(CTDNSNPRB_NODE_IS_USED(node));

    if (CTDNSNPRB_ERR_POS == CTDNSNPRB_NODE_LEFT_POS(node))
    {
        child_pos = CTDNSNPRB_NODE_RIGHT_POS(node);
    }
    else if (CTDNSNPRB_ERR_POS == CTDNSNPRB_NODE_RIGHT_POS(node))
    {
        child_pos = CTDNSNPRB_NODE_LEFT_POS(node);
    }
    else
    {
        CTDNSNPRB_NODE *old;

        uint32_t old_pos;
        uint32_t left_pos;

        old_pos = node_pos_t;

        node_pos_t = CTDNSNPRB_NODE_RIGHT_POS(node);
        node = CTDNSNPRB_POOL_NODE(pool, node_pos_t);

        while (CTDNSNPRB_ERR_POS != (left_pos = CTDNSNPRB_NODE_LEFT_POS(node)))
        {
            node_pos_t = left_pos;
            node = CTDNSNPRB_POOL_NODE(pool, node_pos_t);

        }

        child_pos  = CTDNSNPRB_NODE_RIGHT_POS(node);
        parent_pos = CTDNSNPRB_NODE_PARENT_POS(node);
        color      = CTDNSNPRB_NODE_COLOR(node);

        if (CTDNSNPRB_ERR_POS != child_pos)
        {
            CTDNSNPRB_NODE *child;
            child = CTDNSNPRB_POOL_NODE(pool, child_pos);
            CTDNSNPRB_NODE_PARENT_POS(child) = parent_pos;
        }

        if (CTDNSNPRB_ERR_POS != parent_pos)
        {
            CTDNSNPRB_NODE *parent;

            parent = CTDNSNPRB_POOL_NODE(pool, parent_pos);
            if (CTDNSNPRB_NODE_LEFT_POS(parent) == node_pos_t)
            {
                CTDNSNPRB_NODE_LEFT_POS(parent) = child_pos;
            }
            else
            {
                CTDNSNPRB_NODE_RIGHT_POS(parent) = child_pos;
            }
        }
        else
        {
            (*root_pos) = child_pos;
        }

        if (CTDNSNPRB_NODE_PARENT_POS(node) == old_pos)
        {
            parent_pos = node_pos_t;
        }

        old  = CTDNSNPRB_POOL_NODE(pool, old_pos);

        CTDNSNPRB_NODE_PARENT_POS(node) = CTDNSNPRB_NODE_PARENT_POS(old);
        CTDNSNPRB_NODE_COLOR(node)      = CTDNSNPRB_NODE_COLOR(old);
        CTDNSNPRB_NODE_RIGHT_POS(node)  = CTDNSNPRB_NODE_RIGHT_POS(old);
        CTDNSNPRB_NODE_LEFT_POS(node)   = CTDNSNPRB_NODE_LEFT_POS(old);

        if (CTDNSNPRB_ERR_POS != CTDNSNPRB_NODE_PARENT_POS(old))
        {
            CTDNSNPRB_NODE *old_parent;
            old_parent = CTDNSNPRB_POOL_NODE(pool, CTDNSNPRB_NODE_PARENT_POS(old));

            if (CTDNSNPRB_NODE_LEFT_POS(old_parent) == old_pos)
            {
                CTDNSNPRB_NODE_LEFT_POS(old_parent) = node_pos_t;
            }
            else
            {
                CTDNSNPRB_NODE_RIGHT_POS(old_parent) = node_pos_t;
            }
        }
        else
        {
            (*root_pos) = node_pos_t;
        }

        {
            CTDNSNPRB_NODE *old_left;

            old_left = CTDNSNPRB_POOL_NODE(pool, CTDNSNPRB_NODE_LEFT_POS(old));
            CTDNSNPRB_NODE_PARENT_POS(old_left) = node_pos_t;
        }

        if (CTDNSNPRB_ERR_POS != CTDNSNPRB_NODE_RIGHT_POS(old))
        {
            CTDNSNPRB_NODE *old_right;
            old_right = CTDNSNPRB_POOL_NODE(pool, CTDNSNPRB_NODE_RIGHT_POS(old));
            CTDNSNPRB_NODE_PARENT_POS(old_right) = node_pos_t;
        }
        goto color;
    }

    parent_pos = CTDNSNPRB_NODE_PARENT_POS(node);
    color = CTDNSNPRB_NODE_COLOR(node);

    if (CTDNSNPRB_ERR_POS != child_pos)
    {
        CTDNSNPRB_NODE *child;
        child = CTDNSNPRB_POOL_NODE(pool, child_pos);
        CTDNSNPRB_NODE_PARENT_POS(child) = parent_pos;
    }

    if (CTDNSNPRB_ERR_POS != parent_pos)
    {
        CTDNSNPRB_NODE *parent;

        parent = CTDNSNPRB_POOL_NODE(pool, parent_pos);
        if (CTDNSNPRB_NODE_LEFT_POS(parent) == node_pos_t)
        {
            CTDNSNPRB_NODE_LEFT_POS(parent) = child_pos;
        }
        else
        {
            CTDNSNPRB_NODE_RIGHT_POS(parent) = child_pos;
        }
    }
    else
    {
        (*root_pos) = child_pos;
    }

 color:
    if (CTDNSNPRB_BLACK == color)
    {
        __ctdnsnprb_tree_erase_color(pool, child_pos, parent_pos, root_pos);
    }
    return (EC_TRUE);
}

STATIC_CAST static uint32_t __ctdnsnprb_tree_count_node_num(const CTDNSNPRB_POOL *pool, const uint32_t node_pos)
{
    const CTDNSNPRB_NODE *node;

    if(CTDNSNPRB_ERR_POS == node_pos)
    {
        return ((uint32_t)0);
    }

    node = CTDNSNPRB_POOL_NODE(pool, node_pos);

    return (uint32_t)(1 + __ctdnsnprb_tree_count_node_num(pool, CTDNSNPRB_NODE_LEFT_POS(node)) + __ctdnsnprb_tree_count_node_num(pool, CTDNSNPRB_NODE_RIGHT_POS(node)));
}

uint32_t ctdnsnprb_tree_count_node_num(const CTDNSNPRB_POOL *pool, const uint32_t root_pos)
{
    return __ctdnsnprb_tree_count_node_num(pool, root_pos);
}

uint32_t ctdnsnprb_tree_node_max_num(const CTDNSNPRB_POOL *pool)
{
    return CTDNSNPRB_POOL_NODE_MAX_NUM(pool);
}

uint32_t ctdnsnprb_tree_node_used_num(const CTDNSNPRB_POOL *pool)
{
    return CTDNSNPRB_POOL_NODE_USED_NUM(pool);
}

uint32_t ctdnsnprb_tree_node_sizeof(const CTDNSNPRB_POOL *pool)
{
    return CTDNSNPRB_POOL_NODE_SIZEOF(pool);
}

/*
 * This function returns the first node_pos (in sort order) of the tree.
 */
uint32_t ctdnsnprb_tree_first_node(const CTDNSNPRB_POOL *pool, const uint32_t root_pos)
{
    uint32_t  node_pos;
    const CTDNSNPRB_NODE *node;

    node_pos = root_pos;
    if (CTDNSNPRB_ERR_POS == node_pos)
    {
        return (CTDNSNPRB_ERR_POS);
    }

    node = CTDNSNPRB_POOL_NODE(pool, node_pos);

    while (CTDNSNPRB_ERR_POS != CTDNSNPRB_NODE_LEFT_POS(node))
    {
        node_pos = CTDNSNPRB_NODE_LEFT_POS(node);
        node = CTDNSNPRB_POOL_NODE(pool, node_pos);
    }
    return (node_pos);
}

uint32_t ctdnsnprb_tree_last_node(const CTDNSNPRB_POOL *pool, const uint32_t root_pos)
{
    uint32_t  node_pos;
    const CTDNSNPRB_NODE *node;

    node_pos = root_pos;
    if (CTDNSNPRB_ERR_POS == node_pos)
    {
        return (CTDNSNPRB_ERR_POS);
    }

    node = CTDNSNPRB_POOL_NODE(pool, node_pos);

    while (CTDNSNPRB_ERR_POS != CTDNSNPRB_NODE_RIGHT_POS(node))
    {
        node_pos = CTDNSNPRB_NODE_RIGHT_POS(node);
        node = CTDNSNPRB_POOL_NODE(pool, node_pos);
    }

    return (node_pos);
}

uint32_t ctdnsnprb_tree_next_node(const CTDNSNPRB_POOL *pool, const uint32_t node_pos)
{
    uint32_t node_pos_t;
    const CTDNSNPRB_NODE *node;
    const CTDNSNPRB_NODE *parent;

    node_pos_t = node_pos;
    node = CTDNSNPRB_POOL_NODE(pool, node_pos_t);
    /* If we have a right-hand child, go down and then left as far
       as we can. */
    if (CTDNSNPRB_ERR_POS != CTDNSNPRB_NODE_RIGHT_POS(node))
    {
        node_pos_t = CTDNSNPRB_NODE_RIGHT_POS(node);
        node = CTDNSNPRB_POOL_NODE(pool, node_pos_t);
        while (CTDNSNPRB_ERR_POS != CTDNSNPRB_NODE_LEFT_POS(node))
        {
            node_pos_t = CTDNSNPRB_NODE_LEFT_POS(node);
            node = CTDNSNPRB_POOL_NODE(pool, node_pos_t);
        }
        return (node_pos_t);
    }

    /* No right-hand children.  Everything down and left is
       smaller than us, so any 'next' node_pos_t must be in the general
       direction of our parent. Go up the tree; any time the
       ancestor is a right-hand child of its parent, keep going
       up. First time it's a left-hand child of its parent, said
       parent is our 'next' node_pos_t. */
    while (NULL_PTR != (parent = CTDNSNPRB_POOL_NODE(pool, CTDNSNPRB_NODE_PARENT_POS(node))) && node_pos_t == CTDNSNPRB_NODE_RIGHT_POS(parent))
    {
        node_pos_t = CTDNSNPRB_NODE_PARENT_POS(node);
        node = parent;
    }

    return (CTDNSNPRB_NODE_PARENT_POS(node));
}

uint32_t ctdnsnprb_tree_prev_node(const CTDNSNPRB_POOL *pool, const uint32_t node_pos)
{
    uint32_t node_pos_t;
    const CTDNSNPRB_NODE *node;
    const CTDNSNPRB_NODE *parent;

    node_pos_t = node_pos;
    node = CTDNSNPRB_POOL_NODE(pool, node_pos_t);

    /* If we have a left-hand child, go down and then right as far
       as we can. */
    if (CTDNSNPRB_ERR_POS != CTDNSNPRB_NODE_LEFT_POS(node))
    {
        node_pos_t = CTDNSNPRB_NODE_LEFT_POS(node);
        node = CTDNSNPRB_POOL_NODE(pool, node_pos_t);
        while (CTDNSNPRB_ERR_POS != CTDNSNPRB_NODE_RIGHT_POS(node))
        {
            node_pos_t = CTDNSNPRB_NODE_RIGHT_POS(node);
            node = CTDNSNPRB_POOL_NODE(pool, node_pos_t);
        }
        return (node_pos_t);
    }

    /* No left-hand children. Go up till we find an ancestor which
       is a right-hand child of its parent */
    while (NULL_PTR != (parent = CTDNSNPRB_POOL_NODE(pool, CTDNSNPRB_NODE_PARENT_POS(node))) && node_pos_t == CTDNSNPRB_NODE_LEFT_POS(parent))
    {
        node_pos_t = CTDNSNPRB_NODE_PARENT_POS(node);
        node = parent;
    }

    return (CTDNSNPRB_NODE_PARENT_POS(node));
}

/*victim_pos should be free*/
void ctdnsnprb_tree_replace_node(CTDNSNPRB_POOL *pool, const uint32_t victim_pos, const uint32_t new_pos, uint32_t *root_pos)
{
    CTDNSNPRB_NODE *victim;

    victim = CTDNSNPRB_POOL_NODE(pool, victim_pos);

    /* Set the surrounding nodes to point to the replacement */
    if (CTDNSNPRB_ERR_POS != CTDNSNPRB_NODE_PARENT_POS(victim))
    {
        CTDNSNPRB_NODE *parent;
        parent = CTDNSNPRB_POOL_NODE(pool, CTDNSNPRB_NODE_PARENT_POS(victim));

        if (victim_pos == CTDNSNPRB_NODE_LEFT_POS(parent))
        {
            CTDNSNPRB_NODE_LEFT_POS(parent) = new_pos;
        }
        else
        {
            CTDNSNPRB_NODE_RIGHT_POS(parent) = new_pos;
        }
    }
    else
    {
        (*root_pos) = new_pos;
    }

    if (CTDNSNPRB_ERR_POS != CTDNSNPRB_NODE_LEFT_POS(victim))
    {
        CTDNSNPRB_NODE *left;
        left = CTDNSNPRB_POOL_NODE(pool, CTDNSNPRB_NODE_LEFT_POS(victim));
        CTDNSNPRB_NODE_PARENT_POS(left) = new_pos;
    }
    if (CTDNSNPRB_ERR_POS != CTDNSNPRB_NODE_RIGHT_POS(victim))
    {
        CTDNSNPRB_NODE *right;
        right = CTDNSNPRB_POOL_NODE(pool, CTDNSNPRB_NODE_RIGHT_POS(victim));
        CTDNSNPRB_NODE_PARENT_POS(right) = new_pos;
    }

    return;
}


#if 1
STATIC_CAST static int __ctdnsnprb_node_tcid_cmp(const CTDNSNPRB_NODE *node, const UINT32 tcid)
{
    const CTDNSNP_ITEM *item;

    item = (const CTDNSNP_ITEM *)CTDNSNP_RB_NODE_ITEM(node);
    if(CTDNSNP_ITEM_TCID(item) < tcid)
    {
        return (-1);
    }

    if(CTDNSNP_ITEM_TCID(item) > tcid)
    {
        return (1);
    }

    return (0);
}
#endif


/*return the searched pos*/
uint32_t ctdnsnprb_tree_search_data(const CTDNSNPRB_POOL *pool, const uint32_t root_pos, const UINT32 tcid)
{
    uint32_t node_pos;

    node_pos = root_pos;

    while (CTDNSNPRB_ERR_POS != node_pos)
    {
        const CTDNSNPRB_NODE *node;
        int cmp_ret;

        node = CTDNSNPRB_POOL_NODE(pool, node_pos);
        cmp_ret = __ctdnsnprb_node_tcid_cmp(node, tcid);

        if (0 < cmp_ret)
        {
            node_pos = CTDNSNPRB_NODE_LEFT_POS(node);
        }
        else if (0 > cmp_ret)
        {
            node_pos = CTDNSNPRB_NODE_RIGHT_POS(node);
        }
        else
        {
            return (node_pos);
        }
    }

    return (CTDNSNPRB_ERR_POS);
}

/*if found duplicate node, return EC_FALSE, otherwise return EC_TRUE*/
EC_BOOL ctdnsnprb_tree_insert_data(CTDNSNPRB_POOL *pool, uint32_t *root_pos, const UINT32 tcid, uint32_t *insert_pos)
{
    uint32_t  node_pos_t;
    uint32_t  new_pos_t;
    uint32_t  parent_pos_t;
    uint32_t  flag; /*0: on left subtree, 1: on right subtree*/

    node_pos_t   = (*root_pos);
    parent_pos_t = CTDNSNPRB_ERR_POS;
    flag         = ~(uint32_t)0;

    while (CTDNSNPRB_ERR_POS != node_pos_t)
    {
        CTDNSNPRB_NODE *node;
        int cmp_ret;

        node = CTDNSNPRB_POOL_NODE(pool, node_pos_t);
        cmp_ret = __ctdnsnprb_node_tcid_cmp(node, tcid);

        parent_pos_t = node_pos_t;

        if (0 < cmp_ret)
        {
            node_pos_t = CTDNSNPRB_NODE_LEFT_POS(node);
            flag = 0;
        }
        else if (0 > cmp_ret)
        {
            node_pos_t = CTDNSNPRB_NODE_RIGHT_POS(node);
            flag = 1;
        }
        else
        {
            (*insert_pos) = node_pos_t;
            return (EC_FALSE);/*found duplicate*/
        }
    }


    /*not found data in the rbtree*/
    new_pos_t = ctdnsnprb_node_new(pool);
    if(CTDNSNPRB_ERR_POS == new_pos_t)
    {
        (*insert_pos) = CTDNSNPRB_ERR_POS;
        return (EC_FALSE);
    }
    else
    {
        CTDNSNPRB_NODE *node;

        node  = CTDNSNPRB_POOL_NODE(pool, new_pos_t);
        CTDNSNPRB_NODE_DATA(node) = 0;/*xxx*/

        CTDNSNPRB_NODE_PARENT_POS(node) = parent_pos_t;
        CTDNSNPRB_NODE_COLOR(node)      = CTDNSNPRB_RED;
        CTDNSNPRB_NODE_LEFT_POS(node)   = CTDNSNPRB_ERR_POS;
        CTDNSNPRB_NODE_RIGHT_POS(node)  = CTDNSNPRB_ERR_POS;

        if(CTDNSNPRB_ERR_POS == (*root_pos))
        {
            (*root_pos) = new_pos_t;
        }
        else
        {
            CTDNSNPRB_NODE *parent;
            parent  = CTDNSNPRB_POOL_NODE(pool, parent_pos_t);

            if(0 == flag)/*on left subtree*/
            {
                CTDNSNPRB_NODE_LEFT_POS(parent) = new_pos_t;
            }
            else
            {
                CTDNSNPRB_NODE_RIGHT_POS(parent) = new_pos_t;
            }
        }
        __ctdnsnprb_tree_insert_color(pool, new_pos_t, root_pos);
    }

    (*insert_pos) = new_pos_t;
    return (EC_TRUE); /*it is new node*/
}

EC_BOOL ctdnsnprb_tree_delete_data(CTDNSNPRB_POOL *pool, uint32_t *root_pos, const UINT32 tcid, uint32_t *delete_pos)
{
    uint32_t node_pos;

    node_pos = ctdnsnprb_tree_search_data(pool, *root_pos, tcid);
    if(CTDNSNPRB_ERR_POS == node_pos)
    {
        return (EC_FALSE);
    }

    ctdnsnprb_tree_erase(pool, node_pos, root_pos);
    ctdnsnprb_node_free(pool, node_pos);

    (*delete_pos) = node_pos;
    return (EC_TRUE);
}


EC_BOOL ctdnsnprb_tree_delete(CTDNSNPRB_POOL *pool, uint32_t *root_pos, const uint32_t node_pos)
{
    ctdnsnprb_tree_erase(pool, node_pos, root_pos);
    ctdnsnprb_node_free(pool, node_pos);
    return (EC_TRUE);
}


/*postorder: left -> right -> root*/
STATIC_CAST static void __ctdnsnprb_tree_free(CTDNSNPRB_POOL *pool, const uint32_t node_pos)
{
    CTDNSNPRB_NODE *node;

    if(CTDNSNPRB_ERR_POS == node_pos)
    {
        return;
    }

    node  = CTDNSNPRB_POOL_NODE(pool, node_pos);
    if(CTDNSNPRB_ERR_POS != CTDNSNPRB_NODE_LEFT_POS(node))
    {
        __ctdnsnprb_tree_free(pool, CTDNSNPRB_NODE_LEFT_POS(node));
    }

    if(CTDNSNPRB_ERR_POS != CTDNSNPRB_NODE_RIGHT_POS(node))
    {
        __ctdnsnprb_tree_free(pool, CTDNSNPRB_NODE_RIGHT_POS(node));
    }

    ctdnsnprb_node_free(pool, node_pos);

    return;
}
void ctdnsnprb_tree_free(CTDNSNPRB_POOL *pool, const uint32_t root_pos)
{
    __ctdnsnprb_tree_free(pool, root_pos);
    return;
}

EC_BOOL ctdnsnprb_pool_init(CTDNSNPRB_POOL *pool, const uint32_t node_max_num, const uint32_t node_sizeof)
{
    uint32_t node_pos;

    if(CTDNSNPRB_POOL_MAX_SIZE < node_max_num)
    {
        dbg_log(SEC_0021_CTDNSNPRB, 0)(LOGSTDERR, "error:ctdnsnprb_pool_init: node_max_num %u overflow!\n", node_max_num);
        return (EC_FALSE);
    }

    CTDNSNPRB_POOL_NODE_MAX_NUM(pool)  = node_max_num;
    CTDNSNPRB_POOL_NODE_USED_NUM(pool) = 0;
    CTDNSNPRB_POOL_NODE_SIZEOF(pool)   = node_sizeof;

    for(node_pos = 0; node_pos < node_max_num; node_pos ++)
    {
        ctdnsnprb_node_init(pool, node_pos);
        ctdnsnprb_node_set_next(pool, node_pos, node_pos + 1);

        if(0 == ((node_pos + 1) % 100000))
        {
            dbg_log(SEC_0021_CTDNSNPRB, 0)(LOGSTDOUT, "info:ctdnsnprb_pool_init: init node %u - %u of max %u done\n",
                               node_pos - 99999, node_pos, node_max_num);
        }
    }
    dbg_log(SEC_0021_CTDNSNPRB, 0)(LOGSTDOUT, "info:ctdnsnprb_pool_init: init %u nodes done\n", node_max_num);
    ctdnsnprb_node_set_next(pool, node_max_num - 1, CTDNSNPRB_ERR_POS);/*overwrite the last one*/

    CTDNSNPRB_POOL_FREE_HEAD(pool) = 0;/*the free nodes head*/
    CTDNSNPRB_POOL_ROOT_POS(pool)  = CTDNSNPRB_ERR_POS;
    return (EC_TRUE);
}

void ctdnsnprb_pool_clean(CTDNSNPRB_POOL *pool)
{
    CTDNSNPRB_POOL_NODE_MAX_NUM(pool)  = 0;
    CTDNSNPRB_POOL_FREE_HEAD(pool)     = CTDNSNPRB_ERR_POS;
    CTDNSNPRB_POOL_ROOT_POS(pool)      = CTDNSNPRB_ERR_POS;
    return;
}

void ctdnsnprb_pool_print(LOG *log, const CTDNSNPRB_POOL *pool)
{
    uint32_t node_pos;
    uint32_t node_max_num;

    node_max_num = CTDNSNPRB_POOL_NODE_MAX_NUM(pool);

    sys_log(log, "pool %lx, node_max_num %u, node_used_num %u, root_pos %u, free_head %u, node_sizeof = %u\n",
                 pool,
                 node_max_num,
                 CTDNSNPRB_POOL_NODE_USED_NUM(pool),
                 CTDNSNPRB_POOL_ROOT_POS(pool),
                 CTDNSNPRB_POOL_FREE_HEAD(pool),
                 CTDNSNPRB_POOL_NODE_SIZEOF(pool));

    if(0)
    {
        for(node_pos = 0; node_pos < node_max_num; node_pos ++)
        {
            if(EC_TRUE == ctdnsnprb_node_is_used(pool, node_pos))
            {
                ctdnsnprb_node_print(log, pool, node_pos);
            }
        }
    }
    return;
}


EC_BOOL ctdnsnprb_pool_is_empty(const CTDNSNPRB_POOL *pool)
{
    if (0 == CTDNSNPRB_POOL_NODE_USED_NUM(pool))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL ctdnsnprb_pool_is_full(const CTDNSNPRB_POOL *pool)
{
    if (CTDNSNPRB_POOL_NODE_MAX_NUM(pool) == CTDNSNPRB_POOL_NODE_USED_NUM(pool))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

/*visit the root node first: root -> left -> right*/
void ctdnsnprb_preorder_print(LOG *log, const CTDNSNPRB_POOL *pool, const uint32_t node_pos)
{
    const CTDNSNPRB_NODE *node;

    if(CTDNSNPRB_ERR_POS == node_pos)
    {
        return;
    }

    node  = CTDNSNPRB_POOL_NODE(pool, node_pos);
    ctdnsnprb_node_print(log, pool, node_pos);

    if(CTDNSNPRB_ERR_POS != CTDNSNPRB_NODE_LEFT_POS(node))
    {
        ctdnsnprb_preorder_print(log, pool, CTDNSNPRB_NODE_LEFT_POS(node));
    }

    if(CTDNSNPRB_ERR_POS != CTDNSNPRB_NODE_RIGHT_POS(node))
    {
        ctdnsnprb_preorder_print(log, pool, CTDNSNPRB_NODE_RIGHT_POS(node));
    }

    return;
}

/*visit the left subtree, then the root node: left -> root -> right*/
void ctdnsnprb_inorder_print(LOG *log, const CTDNSNPRB_POOL *pool, const uint32_t node_pos)
{
    const CTDNSNPRB_NODE *node;

    if(CTDNSNPRB_ERR_POS == node_pos)
    {
        return;
    }

    node  = CTDNSNPRB_POOL_NODE(pool, node_pos);
    if(CTDNSNPRB_ERR_POS != CTDNSNPRB_NODE_LEFT_POS(node))
    {
        ctdnsnprb_inorder_print(log, pool, CTDNSNPRB_NODE_LEFT_POS(node));
    }

    ctdnsnprb_node_print(log, pool, node_pos);

    if(CTDNSNPRB_ERR_POS != CTDNSNPRB_NODE_RIGHT_POS(node))
    {
        ctdnsnprb_inorder_print(log, pool, CTDNSNPRB_NODE_RIGHT_POS(node));
    }

    return;
}

/*visit the root node last: left -> right -> root*/
void ctdnsnprb_postorder_print(LOG *log, const CTDNSNPRB_POOL *pool, const uint32_t node_pos)
{
    const CTDNSNPRB_NODE *node;

    if(CTDNSNPRB_ERR_POS == node_pos)
    {
        return;
    }

    node  = CTDNSNPRB_POOL_NODE(pool, node_pos);
    if(CTDNSNPRB_ERR_POS != CTDNSNPRB_NODE_LEFT_POS(node))
    {
        ctdnsnprb_postorder_print(log, pool, CTDNSNPRB_NODE_LEFT_POS(node));
    }

    if(CTDNSNPRB_ERR_POS != CTDNSNPRB_NODE_RIGHT_POS(node))
    {
        ctdnsnprb_postorder_print(log, pool, CTDNSNPRB_NODE_RIGHT_POS(node));
    }

    ctdnsnprb_node_print(log, pool, node_pos);

    return;
}


/*visit the root node first: root -> left -> right*/
void ctdnsnprb_preorder_print_level(LOG *log, const CTDNSNPRB_POOL *pool, const uint32_t node_pos, const uint32_t level)
{
    const CTDNSNPRB_NODE *node;

    if(CTDNSNPRB_ERR_POS == node_pos)
    {
        return;
    }

    node  = CTDNSNPRB_POOL_NODE(pool, node_pos);
    ctdnsnprb_node_print_level(log, pool, node_pos, level);

    if(CTDNSNPRB_ERR_POS != CTDNSNPRB_NODE_LEFT_POS(node))
    {
        ctdnsnprb_preorder_print_level(log, pool, CTDNSNPRB_NODE_LEFT_POS(node), level + 1);
    }

    if(CTDNSNPRB_ERR_POS != CTDNSNPRB_NODE_RIGHT_POS(node))
    {
        ctdnsnprb_preorder_print_level(log, pool, CTDNSNPRB_NODE_RIGHT_POS(node), level + 1);
    }

    return;
}

EC_BOOL ctdnsnprb_flush_size(const CTDNSNPRB_POOL *pool, UINT32 *size)
{
    (*size) += sizeof(CTDNSNPRB_POOL) + CTDNSNPRB_POOL_NODE_MAX_NUM(pool) * CTDNSNPRB_POOL_NODE_SIZEOF(pool);
    return (EC_TRUE);
}

EC_BOOL ctdnsnprb_flush(const CTDNSNPRB_POOL *pool, int fd, UINT32 *offset)
{
    UINT32 osize;/*write once size*/

    /*flush root_pos*/
    osize = sizeof(uint32_t);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(CTDNSNPRB_POOL_ROOT_POS(pool))))
    {
        dbg_log(SEC_0021_CTDNSNPRB, 0)(LOGSTDOUT, "error:ctdnsnprb_flush: write CTDNSNPRB_POOL_ROOT_POS at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*flush free_head*/
    osize = sizeof(uint32_t);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(CTDNSNPRB_POOL_FREE_HEAD(pool))))
    {
        dbg_log(SEC_0021_CTDNSNPRB, 0)(LOGSTDOUT, "error:ctdnsnprb_flush: write CTDNSNPRB_POOL_FREE_HEAD at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*flush node_max_num*/
    osize  = sizeof(uint32_t);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(CTDNSNPRB_POOL_NODE_MAX_NUM(pool))))
    {
        dbg_log(SEC_0021_CTDNSNPRB, 0)(LOGSTDOUT, "error:ctdnsnprb_flush: write CTDNSNPRB_POOL_NODE_MAX_NUM at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*flush node_used_num*/
    osize  = sizeof(uint32_t);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(CTDNSNPRB_POOL_NODE_USED_NUM(pool))))
    {
        dbg_log(SEC_0021_CTDNSNPRB, 0)(LOGSTDOUT, "error:ctdnsnprb_flush: write CTDNSNPRB_POOL_NODE_USED_NUM at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*flush node_sizeof*/
    osize  = sizeof(uint32_t);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(CTDNSNPRB_POOL_NODE_SIZEOF(pool))))
    {
        dbg_log(SEC_0021_CTDNSNPRB, 0)(LOGSTDOUT, "error:ctdnsnprb_flush: write CTDNSNPRB_POOL_NODE_SIZEOF at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*flush rb_node table*/
    osize  = CTDNSNPRB_POOL_NODE_MAX_NUM(pool) * CTDNSNPRB_POOL_NODE_SIZEOF(pool);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)CTDNSNPRB_POOL_NODE_TBL(pool)))
    {
        dbg_log(SEC_0021_CTDNSNPRB, 0)(LOGSTDOUT, "error:ctdnsnprb_flush: write CTDNSNPRB_POOL_NODE_TBL at offset %ld of fd %d failed where CTDNSNPRB_POOL_NODE_MAX_NUM is %u\n",
                            (*offset), fd, CTDNSNPRB_POOL_NODE_MAX_NUM(pool));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL ctdnsnprb_load(CTDNSNPRB_POOL *pool, int fd, UINT32 *offset)
{
    UINT32 osize;/*read once size*/
    uint32_t node_max_num;
    uint32_t node_used_num;
    uint32_t node_sizeof;

    /*load root_pos*/
    osize = sizeof(uint32_t);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(CTDNSNPRB_POOL_ROOT_POS(pool))))
    {
        dbg_log(SEC_0021_CTDNSNPRB, 0)(LOGSTDOUT, "error:ctdnsnprb_load: load CTDNSNPRB_POOL_ROOT_POS at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*load free_head*/
    osize = sizeof(uint32_t);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(CTDNSNPRB_POOL_FREE_HEAD(pool))))
    {
        dbg_log(SEC_0021_CTDNSNPRB, 0)(LOGSTDOUT, "error:ctdnsnprb_load: load CTDNSNPRB_POOL_FREE_HEAD at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*load node_max_num*/
    osize  = sizeof(uint32_t);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(node_max_num)))
    {
        dbg_log(SEC_0021_CTDNSNPRB, 0)(LOGSTDOUT, "error:ctdnsnprb_load: load CTDNSNPRB_POOL_NODE_MAX_NUM at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }
    CTDNSNPRB_POOL_NODE_MAX_NUM(pool) = node_max_num;

    /*load node_used_num*/
    osize  = sizeof(uint32_t);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(node_used_num)))
    {
        dbg_log(SEC_0021_CTDNSNPRB, 0)(LOGSTDOUT, "error:ctdnsnprb_load: load CTDNSNPRB_POOL_NODE_USED_NUM at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }
    CTDNSNPRB_POOL_NODE_MAX_NUM(pool) = node_used_num;

    /*load node_sizeof*/
    osize  = sizeof(uint32_t);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(node_sizeof)))
    {
        dbg_log(SEC_0021_CTDNSNPRB, 0)(LOGSTDOUT, "error:ctdnsnprb_load: load CTDNSNPRB_POOL_NODE_SIZEOF at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }
    CTDNSNPRB_POOL_NODE_SIZEOF(pool) = node_sizeof;

    /*load rb_node table*/
    osize  = CTDNSNPRB_POOL_NODE_MAX_NUM(pool) * CTDNSNPRB_POOL_NODE_SIZEOF(pool);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)CTDNSNPRB_POOL_NODE_TBL(pool)))
    {
        dbg_log(SEC_0021_CTDNSNPRB, 0)(LOGSTDOUT, "error:ctdnsnprb_load: load CTDNSNPRB_POOL_NODE_TBL at offset %ld of fd %d failed where CTDNSNPRB_POOL_NODE_MAX_NUM is %u\n",
                            (*offset), fd, CTDNSNPRB_POOL_NODE_MAX_NUM(pool));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

void ctdnsnprb_tree_print(LOG *log, const CTDNSNPRB_POOL *pool, const uint32_t root_pos)
{
    uint32_t node_pos;

    sys_log(log, "[root = %5d]\n", root_pos);
    for(node_pos = ctdnsnprb_tree_first_node(pool, root_pos); CTDNSNPRB_ERR_POS != node_pos; node_pos = ctdnsnprb_tree_next_node(pool, node_pos))
    {
        ctdnsnprb_node_print(log, pool, node_pos);
    }
    return;
}

/* ---- debug ---- */
EC_BOOL ctdnsnprb_node_debug_cmp(const CTDNSNPRB_NODE *node_1st, const CTDNSNPRB_NODE *node_2nd, int (*node_cmp_data)(const CTDNSNPRB_NODE *, const CTDNSNPRB_NODE *))
{
    if(CTDNSNPRB_NODE_USED_FLAG(node_1st) != CTDNSNPRB_NODE_USED_FLAG(node_2nd))
    {
        dbg_log(SEC_0021_CTDNSNPRB, 0)(LOGSTDERR, "error:ctdnsnprb_node_debug_cmp: inconsistent CTDNSNPRB_NODE_USED_FLAG: %u != %u\n",
                            CTDNSNPRB_NODE_USED_FLAG(node_1st), CTDNSNPRB_NODE_USED_FLAG(node_2nd));
        return (EC_FALSE);
    }
#if 0
    if(CTDNSNPRB_NODE_NOT_USED == CTDNSNPRB_NODE_USED_FLAG(node_1st))
    {
        return (EC_TRUE);
    }
#endif

    if(CTDNSNPRB_NODE_COLOR(node_1st) != CTDNSNPRB_NODE_COLOR(node_2nd))
    {
        dbg_log(SEC_0021_CTDNSNPRB, 0)(LOGSTDERR, "error:ctdnsnprb_node_debug_cmp: inconsistent CTDNSNPRB_NODE_COLOR: %u != %u\n",
                            CTDNSNPRB_NODE_COLOR(node_1st), CTDNSNPRB_NODE_COLOR(node_2nd));
        return (EC_FALSE);
    }

    if(CTDNSNPRB_NODE_PARENT_POS(node_1st) != CTDNSNPRB_NODE_PARENT_POS(node_2nd))
    {
        dbg_log(SEC_0021_CTDNSNPRB, 0)(LOGSTDERR, "error:ctdnsnprb_node_debug_cmp: inconsistent CTDNSNPRB_NODE_PARENT_POS: %u != %u\n",
                            CTDNSNPRB_NODE_PARENT_POS(node_1st), CTDNSNPRB_NODE_PARENT_POS(node_2nd));
        return (EC_FALSE);
    }

    if(CTDNSNPRB_NODE_RIGHT_POS(node_1st) != CTDNSNPRB_NODE_RIGHT_POS(node_2nd))
    {
        dbg_log(SEC_0021_CTDNSNPRB, 0)(LOGSTDERR, "error:ctdnsnprb_node_debug_cmp: inconsistent CTDNSNPRB_NODE_RIGHT_POS: %u != %u\n",
                            CTDNSNPRB_NODE_RIGHT_POS(node_1st), CTDNSNPRB_NODE_RIGHT_POS(node_2nd));
        return (EC_FALSE);
    }

    if(CTDNSNPRB_NODE_LEFT_POS(node_1st) != CTDNSNPRB_NODE_LEFT_POS(node_2nd))
    {
        dbg_log(SEC_0021_CTDNSNPRB, 0)(LOGSTDERR, "error:ctdnsnprb_node_debug_cmp: inconsistent CTDNSNPRB_NODE_LEFT_POS: %u != %u\n",
                            CTDNSNPRB_NODE_LEFT_POS(node_1st), CTDNSNPRB_NODE_LEFT_POS(node_2nd));
        return (EC_FALSE);
    }

    if(CTDNSNPRB_NODE_USED == CTDNSNPRB_NODE_USED_FLAG(node_1st))
    {
        if(0 != node_cmp_data(node_1st, node_2nd))
        {
            dbg_log(SEC_0021_CTDNSNPRB, 0)(LOGSTDERR, "error:ctdnsnprb_node_debug_cmp: inconsistent data part\n");
            return (EC_FALSE);
        }
    }
    else
    {
        if(CTDNSNPRB_NODE_NEXT_POS(node_1st) != CTDNSNPRB_NODE_NEXT_POS(node_2nd))
        {
            dbg_log(SEC_0021_CTDNSNPRB, 0)(LOGSTDERR, "error:ctdnsnprb_node_debug_cmp: inconsistent CTDNSNPRB_NODE_NEXT_POS: %u != %u\n",
                                CTDNSNPRB_NODE_NEXT_POS(node_1st), CTDNSNPRB_NODE_NEXT_POS(node_2nd));
            return (EC_FALSE);
        }
    }
    return (EC_TRUE);
}

EC_BOOL ctdnsnprb_debug_cmp(const CTDNSNPRB_POOL *pool_1st, const CTDNSNPRB_POOL *pool_2nd, int (*node_cmp_data)(const CTDNSNPRB_NODE *, const CTDNSNPRB_NODE *))
{
    uint32_t  node_max_num;
    uint32_t  node_pos;

    if(CTDNSNPRB_POOL_ROOT_POS(pool_1st) != CTDNSNPRB_POOL_ROOT_POS(pool_2nd))
    {
        dbg_log(SEC_0021_CTDNSNPRB, 0)(LOGSTDERR, "error:ctdnsnprb_debug_cmp: inconsistent CTDNSNPRB_POOL_ROOT_POS: %u != %u\n",
                            CTDNSNPRB_POOL_ROOT_POS(pool_1st), CTDNSNPRB_POOL_ROOT_POS(pool_2nd));
        return (EC_FALSE);
    }

    if(CTDNSNPRB_POOL_FREE_HEAD(pool_1st) != CTDNSNPRB_POOL_FREE_HEAD(pool_2nd))
    {
        dbg_log(SEC_0021_CTDNSNPRB, 0)(LOGSTDERR, "error:ctdnsnprb_debug_cmp: inconsistent CTDNSNPRB_POOL_FREE_HEAD: %u != %u\n",
                            CTDNSNPRB_POOL_FREE_HEAD(pool_1st), CTDNSNPRB_POOL_FREE_HEAD(pool_2nd));
        return (EC_FALSE);
    }

    if(CTDNSNPRB_POOL_NODE_MAX_NUM(pool_1st) != CTDNSNPRB_POOL_NODE_MAX_NUM(pool_2nd))
    {
        dbg_log(SEC_0021_CTDNSNPRB, 0)(LOGSTDERR, "error:ctdnsnprb_debug_cmp: inconsistent CTDNSNPRB_POOL_NODE_MAX_NUM: %u != %u\n",
                            CTDNSNPRB_POOL_NODE_MAX_NUM(pool_1st), CTDNSNPRB_POOL_NODE_MAX_NUM(pool_2nd));
        return (EC_FALSE);
    }

    if(CTDNSNPRB_POOL_NODE_USED_NUM(pool_1st) != CTDNSNPRB_POOL_NODE_USED_NUM(pool_2nd))
    {
        dbg_log(SEC_0021_CTDNSNPRB, 0)(LOGSTDERR, "error:ctdnsnprb_debug_cmp: inconsistent CTDNSNPRB_POOL_NODE_USED_NUM: %u != %u\n",
                            CTDNSNPRB_POOL_NODE_USED_NUM(pool_1st), CTDNSNPRB_POOL_NODE_USED_NUM(pool_2nd));
        return (EC_FALSE);
    }

    if(CTDNSNPRB_POOL_NODE_SIZEOF(pool_1st) != CTDNSNPRB_POOL_NODE_SIZEOF(pool_2nd))
    {
        dbg_log(SEC_0021_CTDNSNPRB, 0)(LOGSTDERR, "error:ctdnsnprb_debug_cmp: inconsistent CTDNSNPRB_POOL_NODE_SIZEOF: %u != %u\n",
                            CTDNSNPRB_POOL_NODE_SIZEOF(pool_1st), CTDNSNPRB_POOL_NODE_SIZEOF(pool_2nd));
        return (EC_FALSE);
    }

    node_max_num = CTDNSNPRB_POOL_NODE_MAX_NUM(pool_1st);
    for(node_pos = 0; node_pos < node_max_num; node_pos ++)
    {
        CTDNSNPRB_NODE *node_1st;
        CTDNSNPRB_NODE *node_2nd;

        node_1st = CTDNSNPRB_POOL_NODE(pool_1st, node_pos);
        node_2nd = CTDNSNPRB_POOL_NODE(pool_2nd, node_pos);

        if(EC_FALSE == ctdnsnprb_node_debug_cmp(node_1st, node_2nd, node_cmp_data))
        {
            dbg_log(SEC_0021_CTDNSNPRB, 0)(LOGSTDERR, "error:ctdnsnprb_debug_cmp: inconsistent node at pos %u\n", node_pos);
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}


#ifdef __cplusplus
}
#endif/*__cplusplus*/
