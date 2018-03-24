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

#include "ctdnssv.inc"
#include "ctdnssvrb.h"

/*new a CTDNSSVRB_NODE and return its position*/
uint32_t ctdnssvrb_node_new(CTDNSSVRB_POOL *pool)
{
    uint32_t node_pos_t;
    CTDNSSVRB_NODE *node;

    node_pos_t = CTDNSSVRB_POOL_FREE_HEAD(pool);
    if(CTDNSSVRB_ERR_POS == node_pos_t)
    {
        dbg_log(SEC_0039_CTDNSSVRB, 0)(LOGSTDERR, "error:ctdnssvrb_node_new: no free node in pool\n");
        return (CTDNSSVRB_ERR_POS);
    }

    if(CTDNSSVRB_POOL_FREE_HEAD(pool) >= CTDNSSVRB_POOL_NODE_MAX_NUM(pool))
    {
        dbg_log(SEC_0039_CTDNSSVRB, 0)(LOGSTDERR, "error:ctdnssvrb_node_new: found conflict: free head %u >= max num %u\n",
                            CTDNSSVRB_POOL_FREE_HEAD(pool), CTDNSSVRB_POOL_NODE_MAX_NUM(pool));
        return (CTDNSSVRB_ERR_POS);
    }

    ASSERT(CTDNSSVRB_POOL_FREE_HEAD(pool) < CTDNSSVRB_POOL_NODE_MAX_NUM(pool));

    node = CTDNSSVRB_POOL_NODE(pool, node_pos_t);
#if 0
    dbg_log(SEC_0039_CTDNSSVRB, 9)(LOGSTDNULL, "[DEBUG] ctdnssvrb_node_new: pool %p, max %u, used %u, free head %u, next %u\n",
                       pool,
                       CTDNSSVRB_POOL_NODE_MAX_NUM(pool),
                       CTDNSSVRB_POOL_NODE_USED_NUM(pool),
                       CTDNSSVRB_POOL_FREE_HEAD(pool),
                       CTDNSSVRB_NODE_NEXT_POS(node));
#endif
    CTDNSSVRB_POOL_FREE_HEAD(pool) = CTDNSSVRB_NODE_NEXT_POS(node);
    CTDNSSVRB_POOL_NODE_USED_NUM(pool) ++;

    CTDNSSVRB_NODE_NEXT_POS(node)  = CTDNSSVRB_ERR_POS;
    CTDNSSVRB_NODE_USED_FLAG(node) = CTDNSSVRB_NODE_USED;

    return (node_pos_t);
}

/*free a CTDNSSVRB_NODE and return its position to the pool*/
void ctdnssvrb_node_free(CTDNSSVRB_POOL *pool, const uint32_t node_pos)
{
    if(CTDNSSVRB_ERR_POS != node_pos)
    {
        CTDNSSVRB_NODE *node;

        ASSERT(node_pos < CTDNSSVRB_POOL_NODE_MAX_NUM(pool));

        node = CTDNSSVRB_POOL_NODE(pool, node_pos);
        ASSERT(CTDNSSVRB_NODE_IS_USED(node));

        CTDNSSVRB_NODE_USED_FLAG(node)  = CTDNSSVRB_NODE_NOT_USED;
        CTDNSSVRB_NODE_PARENT_POS(node) = CTDNSSVRB_ERR_POS;
        CTDNSSVRB_NODE_RIGHT_POS(node)  = CTDNSSVRB_ERR_POS;
        CTDNSSVRB_NODE_LEFT_POS(node)   = CTDNSSVRB_ERR_POS;
        CTDNSSVRB_NODE_NEXT_POS(node)   = CTDNSSVRB_POOL_FREE_HEAD(pool);
        CTDNSSVRB_NODE_COLOR(node)      = CTDNSSVRB_BLACK;

        CTDNSSVRB_POOL_FREE_HEAD(pool)  = node_pos;
        CTDNSSVRB_POOL_NODE_USED_NUM(pool) --;
    }
    return;
}

void ctdnssvrb_node_init(CTDNSSVRB_POOL *pool, const uint32_t node_pos)
{
    CTDNSSVRB_NODE *node;

    node  = CTDNSSVRB_POOL_NODE(pool, node_pos);

    CTDNSSVRB_NODE_PARENT_POS(node) = CTDNSSVRB_ERR_POS;
    CTDNSSVRB_NODE_RIGHT_POS(node)  = CTDNSSVRB_ERR_POS;
    CTDNSSVRB_NODE_LEFT_POS(node)   = CTDNSSVRB_ERR_POS;
    CTDNSSVRB_NODE_USED_FLAG(node)  = CTDNSSVRB_NODE_NOT_USED;
    CTDNSSVRB_NODE_NEXT_POS(node)   = CTDNSSVRB_ERR_POS;
    CTDNSSVRB_NODE_COLOR(node)      = CTDNSSVRB_BLACK;

    return;
}

void ctdnssvrb_node_clean(CTDNSSVRB_POOL *pool, const uint32_t node_pos)
{
    CTDNSSVRB_NODE *node;

    ASSERT(node_pos < CTDNSSVRB_POOL_NODE_MAX_NUM(pool));

    node = CTDNSSVRB_POOL_NODE(pool, node_pos);

    CTDNSSVRB_NODE_PARENT_POS(node) = CTDNSSVRB_ERR_POS;
    CTDNSSVRB_NODE_RIGHT_POS(node)  = CTDNSSVRB_ERR_POS;
    CTDNSSVRB_NODE_LEFT_POS(node)   = CTDNSSVRB_ERR_POS;
    CTDNSSVRB_NODE_USED_FLAG(node)  = CTDNSSVRB_NODE_NOT_USED;
    CTDNSSVRB_NODE_NEXT_POS(node)   = CTDNSSVRB_ERR_POS;
    CTDNSSVRB_NODE_COLOR(node)      = CTDNSSVRB_BLACK;

    return;
}

void ctdnssvrb_node_set_next(CTDNSSVRB_POOL *pool, const uint32_t node_pos, const uint32_t next_pos)
{
    CTDNSSVRB_NODE *node;

    node = CTDNSSVRB_POOL_NODE(pool, node_pos);
    CTDNSSVRB_NODE_NEXT_POS(node) = next_pos;

    return;
}

EC_BOOL ctdnssvrb_node_is_used(const CTDNSSVRB_POOL *pool, const uint32_t node_pos)
{
    const CTDNSSVRB_NODE *node;
    node  = CTDNSSVRB_POOL_NODE(pool, node_pos);

    if(CTDNSSVRB_NODE_IS_USED(node))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

void ctdnssvrb_node_print(LOG *log, const CTDNSSVRB_POOL *pool, const uint32_t node_pos)
{
    const CTDNSSVRB_NODE *node;
    node  = CTDNSSVRB_POOL_NODE(pool, node_pos);

    sys_log(log, "%5d: parent = %5d, left = %5d, right = %5d, flg = %s, color = %s, %s = %5d\n",
                       node_pos,
                       CTDNSSVRB_NODE_PARENT_POS(node),
                       CTDNSSVRB_NODE_LEFT_POS(node),
                       CTDNSSVRB_NODE_RIGHT_POS(node),
                       CTDNSSVRB_NODE_IS_USED(node) ? "used" : "n.a.",
                       CTDNSSVRB_NODE_IS_USED(node) ? (CTDNSSVRB_NODE_IS_RED(node) ? "red  " : "black") : "#####",
                       CTDNSSVRB_NODE_IS_USED(node) ? "data" : "next",
                       CTDNSSVRB_NODE_IS_USED(node) ? CTDNSSVRB_NODE_DATA(node) : CTDNSSVRB_NODE_NEXT_POS(node)
                       );
    return;
}

void ctdnssvrb_node_print_level(LOG *log, const CTDNSSVRB_POOL *pool, const uint32_t node_pos, const uint32_t level)
{
    const CTDNSSVRB_NODE *node;
    node  = CTDNSSVRB_POOL_NODE(pool, node_pos);

    c_ident_print(log, level);
    sys_print(log, "%5d: parent = %5d, left = %5d, right = %5d, flg = %s, color = %s, %s = %5d\n",
                       node_pos,
                       CTDNSSVRB_NODE_PARENT_POS(node),
                       CTDNSSVRB_NODE_LEFT_POS(node),
                       CTDNSSVRB_NODE_RIGHT_POS(node),
                       CTDNSSVRB_NODE_IS_USED(node) ? "used" : "NOT used",
                       CTDNSSVRB_NODE_IS_RED(node)  ? "red  " : "black",
                       CTDNSSVRB_NODE_IS_USED(node) ? "data" : "next",
                       CTDNSSVRB_NODE_IS_USED(node) ? CTDNSSVRB_NODE_DATA(node) : CTDNSSVRB_NODE_NEXT_POS(node)
                       );
    return;
}


STATIC_CAST static void __ctdnssvrb_tree_rotate_left(CTDNSSVRB_POOL *pool, const uint32_t node_pos, uint32_t *root_pos)
{
    CTDNSSVRB_NODE *node;
    CTDNSSVRB_NODE *right;

    uint32_t  right_pos;

    node  = CTDNSSVRB_POOL_NODE(pool, node_pos);

    right_pos = CTDNSSVRB_NODE_RIGHT_POS(node);
    right = CTDNSSVRB_POOL_NODE(pool, right_pos);

    if(CTDNSSVRB_ERR_POS != (CTDNSSVRB_NODE_RIGHT_POS(node) = CTDNSSVRB_NODE_LEFT_POS(right)))
    {
        CTDNSSVRB_NODE *left;
        left = CTDNSSVRB_POOL_NODE(pool, CTDNSSVRB_NODE_LEFT_POS(right));
        CTDNSSVRB_NODE_PARENT_POS(left) = node_pos;
    }
    CTDNSSVRB_NODE_LEFT_POS(right) = node_pos;

    if(CTDNSSVRB_ERR_POS != (CTDNSSVRB_NODE_PARENT_POS(right) = CTDNSSVRB_NODE_PARENT_POS(node)))
    {
        CTDNSSVRB_NODE *parent;
        parent = CTDNSSVRB_POOL_NODE(pool, CTDNSSVRB_NODE_PARENT_POS(node));

        if (node_pos == CTDNSSVRB_NODE_LEFT_POS(parent))
        {
            CTDNSSVRB_NODE_LEFT_POS(parent) = right_pos;
        }
        else
        {
            CTDNSSVRB_NODE_RIGHT_POS(parent) = right_pos;
        }
    }
    else
    {
        (*root_pos) = right_pos;
    }
    CTDNSSVRB_NODE_PARENT_POS(node) = right_pos;
    return;
}

STATIC_CAST static void __ctdnssvrb_tree_rotate_right(CTDNSSVRB_POOL *pool, const uint32_t node_pos, uint32_t *root_pos)
{
    CTDNSSVRB_NODE *node;
    CTDNSSVRB_NODE *left;
    uint32_t  left_pos;

    node  = CTDNSSVRB_POOL_NODE(pool, node_pos);

    left_pos = CTDNSSVRB_NODE_LEFT_POS(node);
    left = CTDNSSVRB_POOL_NODE(pool, left_pos);

    if (CTDNSSVRB_ERR_POS != (CTDNSSVRB_NODE_LEFT_POS(node) = CTDNSSVRB_NODE_RIGHT_POS(left)))
    {
        CTDNSSVRB_NODE *right;
        right = CTDNSSVRB_POOL_NODE(pool, CTDNSSVRB_NODE_RIGHT_POS(left));
        CTDNSSVRB_NODE_PARENT_POS(right) = node_pos;
    }
    CTDNSSVRB_NODE_RIGHT_POS(left) = node_pos;

    if (CTDNSSVRB_ERR_POS != (CTDNSSVRB_NODE_PARENT_POS(left) = CTDNSSVRB_NODE_PARENT_POS(node)))
    {
        CTDNSSVRB_NODE *parent;
        parent = CTDNSSVRB_POOL_NODE(pool, CTDNSSVRB_NODE_PARENT_POS(node));

        if (node_pos == CTDNSSVRB_NODE_RIGHT_POS(parent))
        {
            CTDNSSVRB_NODE_RIGHT_POS(parent) = left_pos;
        }
        else
        {
            CTDNSSVRB_NODE_LEFT_POS(parent) = left_pos;
        }
    }
    else
    {
        (*root_pos) = left_pos;
    }
    CTDNSSVRB_NODE_PARENT_POS(node) = left_pos;
    return;
}

STATIC_CAST static void __ctdnssvrb_tree_insert_color(CTDNSSVRB_POOL *pool, const uint32_t node_pos, uint32_t *root_pos)
{
    CTDNSSVRB_NODE *node;
    CTDNSSVRB_NODE *root;
    CTDNSSVRB_NODE *parent;

    uint32_t  node_pos_t;

    node_pos_t = node_pos;
    node  = CTDNSSVRB_POOL_NODE(pool, node_pos_t);

    while (NULL_PTR != (parent = CTDNSSVRB_POOL_NODE(pool, CTDNSSVRB_NODE_PARENT_POS(node))) /*parent is valid*/
         && CTDNSSVRB_RED == CTDNSSVRB_NODE_COLOR(parent))
    {
        uint32_t  parent_pos;
        uint32_t  gparent_pos;
        CTDNSSVRB_NODE *gparent;

        parent_pos = CTDNSSVRB_NODE_PARENT_POS(node);

        gparent_pos = CTDNSSVRB_NODE_PARENT_POS(parent);
        ASSERT(CTDNSSVRB_ERR_POS != gparent_pos);
        gparent = CTDNSSVRB_POOL_NODE(pool, gparent_pos);

        if (parent_pos == CTDNSSVRB_NODE_LEFT_POS(gparent))
        {
            {
                CTDNSSVRB_NODE *uncle;
                if (NULL_PTR != (uncle = CTDNSSVRB_POOL_NODE(pool, CTDNSSVRB_NODE_RIGHT_POS(gparent))) /*uncle is valid*/
                   && CTDNSSVRB_RED == CTDNSSVRB_NODE_COLOR(uncle))
                {
                    CTDNSSVRB_NODE_COLOR(uncle)   = CTDNSSVRB_BLACK;
                    CTDNSSVRB_NODE_COLOR(parent)  = CTDNSSVRB_BLACK;
                    CTDNSSVRB_NODE_COLOR(gparent) = CTDNSSVRB_RED;

                    node = gparent;
                    node_pos_t = gparent_pos;
                    continue;
                }
            }

            if (CTDNSSVRB_NODE_RIGHT_POS(parent) == node_pos_t)
            {
                __ctdnssvrb_tree_rotate_left(pool, parent_pos, root_pos);
                XCHG(CTDNSSVRB_NODE *, parent, node);
                XCHG(uint32_t, parent_pos, node_pos_t);
            }

            CTDNSSVRB_NODE_COLOR(parent)  = CTDNSSVRB_BLACK;
            CTDNSSVRB_NODE_COLOR(gparent) = CTDNSSVRB_RED;
            __ctdnssvrb_tree_rotate_right(pool, gparent_pos, root_pos);
         }
         else
         {
            {
                CTDNSSVRB_NODE *uncle;
                if (NULL_PTR != (uncle = CTDNSSVRB_POOL_NODE(pool, CTDNSSVRB_NODE_LEFT_POS(gparent))) /*uncle is valid*/
                    && CTDNSSVRB_RED == CTDNSSVRB_NODE_COLOR(uncle))
                {
                    CTDNSSVRB_NODE_COLOR(uncle)   = CTDNSSVRB_BLACK;
                    CTDNSSVRB_NODE_COLOR(parent)  = CTDNSSVRB_BLACK;
                    CTDNSSVRB_NODE_COLOR(gparent) = CTDNSSVRB_RED;

                    node = gparent;
                    node_pos_t = gparent_pos;
                    continue;
                }
            }

            if (CTDNSSVRB_NODE_LEFT_POS(parent) == node_pos_t)
            {
                __ctdnssvrb_tree_rotate_right(pool, parent_pos, root_pos);
                XCHG(CTDNSSVRB_NODE *, parent, node);
                XCHG(uint32_t, parent_pos, node_pos_t);
            }

            CTDNSSVRB_NODE_COLOR(parent)  = CTDNSSVRB_BLACK;
            CTDNSSVRB_NODE_COLOR(gparent) = CTDNSSVRB_RED;
            __ctdnssvrb_tree_rotate_left(pool, gparent_pos, root_pos);
        }
    }

    root = CTDNSSVRB_POOL_NODE(pool, *root_pos);
    CTDNSSVRB_NODE_COLOR(root) = CTDNSSVRB_BLACK;
    return;
}

STATIC_CAST static void __ctdnssvrb_tree_erase_color(CTDNSSVRB_POOL *pool, const uint32_t node_pos, const uint32_t parent_pos, uint32_t *root_pos)
{
    CTDNSSVRB_NODE *node;
    uint32_t  node_pos_t;
    uint32_t  parent_pos_t;

    node_pos_t   = node_pos;
    parent_pos_t = parent_pos;

    while ((NULL_PTR == (node = CTDNSSVRB_POOL_NODE(pool, node_pos_t)) || CTDNSSVRB_BLACK == CTDNSSVRB_NODE_COLOR(node)) && node_pos_t != (*root_pos))
    {
        CTDNSSVRB_NODE *parent;

        parent = CTDNSSVRB_POOL_NODE(pool, parent_pos_t);

        if (CTDNSSVRB_NODE_LEFT_POS(parent) == node_pos_t)
        {
            CTDNSSVRB_NODE *other;
            CTDNSSVRB_NODE *o_left;
            CTDNSSVRB_NODE *o_right;
            uint32_t  other_pos;

            other_pos = CTDNSSVRB_NODE_RIGHT_POS(parent);
            other = CTDNSSVRB_POOL_NODE(pool, other_pos);

            if (CTDNSSVRB_RED == CTDNSSVRB_NODE_COLOR(other))
            {
                CTDNSSVRB_NODE_COLOR(other)  = CTDNSSVRB_BLACK;
                CTDNSSVRB_NODE_COLOR(parent) = CTDNSSVRB_RED;

                __ctdnssvrb_tree_rotate_left(pool, parent_pos_t, root_pos);

                other_pos = CTDNSSVRB_NODE_RIGHT_POS(parent);
                other = CTDNSSVRB_POOL_NODE(pool, other_pos);
            }

            o_left = CTDNSSVRB_POOL_NODE(pool, CTDNSSVRB_NODE_LEFT_POS(other));
            o_right = CTDNSSVRB_POOL_NODE(pool, CTDNSSVRB_NODE_RIGHT_POS(other));

            if((NULL_PTR == o_left || CTDNSSVRB_BLACK == CTDNSSVRB_NODE_COLOR(o_left))
            && (NULL_PTR == o_right || CTDNSSVRB_BLACK == CTDNSSVRB_NODE_COLOR(o_right)))
            {
                CTDNSSVRB_NODE_COLOR(other) = CTDNSSVRB_RED;

                node_pos_t = parent_pos_t;
                node = CTDNSSVRB_POOL_NODE(pool, node_pos_t);

                parent_pos_t = CTDNSSVRB_NODE_PARENT_POS(node);
                parent = CTDNSSVRB_POOL_NODE(pool, parent_pos_t);
            }
            else
            {
                if (NULL_PTR == o_right || CTDNSSVRB_BLACK == CTDNSSVRB_NODE_COLOR(o_right))
                {
                    if (NULL_PTR != o_left)
                    {
                        CTDNSSVRB_NODE_COLOR(o_left) = CTDNSSVRB_BLACK;
                    }
                    CTDNSSVRB_NODE_COLOR(other) = CTDNSSVRB_RED;

                    __ctdnssvrb_tree_rotate_right(pool, other_pos, root_pos);

                    other_pos = CTDNSSVRB_NODE_RIGHT_POS(parent);
                    other = CTDNSSVRB_POOL_NODE(pool, other_pos);
                    /*note: other was changed here*/
                }

                CTDNSSVRB_NODE_COLOR(other) = CTDNSSVRB_NODE_COLOR(parent);
                CTDNSSVRB_NODE_COLOR(parent) = CTDNSSVRB_BLACK;

                /*due to other may be changed before, have to get o_right again here*/
                o_right = CTDNSSVRB_POOL_NODE(pool, CTDNSSVRB_NODE_RIGHT_POS(other));
                if (NULL_PTR != o_right)
                {
                    CTDNSSVRB_NODE_COLOR(o_right) = CTDNSSVRB_BLACK;
                }

                __ctdnssvrb_tree_rotate_left(pool, parent_pos_t, root_pos);
                node_pos_t = (*root_pos);
                break;
            }
        }
        else
        {
            CTDNSSVRB_NODE *other;
            CTDNSSVRB_NODE *o_left;
            CTDNSSVRB_NODE *o_right;
            uint32_t  other_pos;

            other_pos = CTDNSSVRB_NODE_LEFT_POS(parent);
            other = CTDNSSVRB_POOL_NODE(pool, other_pos);

            if (CTDNSSVRB_RED == CTDNSSVRB_NODE_COLOR(other))
            {
                CTDNSSVRB_NODE_COLOR(other) = CTDNSSVRB_BLACK;
                CTDNSSVRB_NODE_COLOR(parent) = CTDNSSVRB_RED;

                __ctdnssvrb_tree_rotate_right(pool, parent_pos_t, root_pos);

                other_pos = CTDNSSVRB_NODE_LEFT_POS(parent);
                other = CTDNSSVRB_POOL_NODE(pool, other_pos);
            }

            o_left = CTDNSSVRB_POOL_NODE(pool, CTDNSSVRB_NODE_LEFT_POS(other));
            o_right = CTDNSSVRB_POOL_NODE(pool, CTDNSSVRB_NODE_RIGHT_POS(other));

            if ((NULL_PTR == o_left  || CTDNSSVRB_BLACK == CTDNSSVRB_NODE_COLOR(o_left))
             && (NULL_PTR == o_right || CTDNSSVRB_BLACK == CTDNSSVRB_NODE_COLOR(o_right)))
            {
                CTDNSSVRB_NODE_COLOR(other) = CTDNSSVRB_RED;

                node_pos_t = parent_pos_t;
                node = CTDNSSVRB_POOL_NODE(pool, node_pos_t);

                parent_pos_t = CTDNSSVRB_NODE_PARENT_POS(node);
                parent = CTDNSSVRB_POOL_NODE(pool, parent_pos_t);
            }
            else
            {
                if (NULL_PTR == o_left  || CTDNSSVRB_BLACK == CTDNSSVRB_NODE_COLOR(o_left))
                {
                    if (NULL_PTR != o_right)
                    {
                        CTDNSSVRB_NODE_COLOR(o_right) = CTDNSSVRB_BLACK;
                    }

                    CTDNSSVRB_NODE_COLOR(other) = CTDNSSVRB_RED;

                    __ctdnssvrb_tree_rotate_left(pool, other_pos, root_pos);

                    other_pos = CTDNSSVRB_NODE_LEFT_POS(parent);
                    other = CTDNSSVRB_POOL_NODE(pool, other_pos);
                    /*note: other was changed here*/
                }

                CTDNSSVRB_NODE_COLOR(other) = CTDNSSVRB_NODE_COLOR(parent);
                CTDNSSVRB_NODE_COLOR(parent) = CTDNSSVRB_BLACK;

                /*due to other may be changed before, have to get o_left again here*/
                o_left = CTDNSSVRB_POOL_NODE(pool, CTDNSSVRB_NODE_LEFT_POS(other));
                if (NULL_PTR != o_left)
                {
                    CTDNSSVRB_NODE_COLOR(o_left) = CTDNSSVRB_BLACK;
                }
                __ctdnssvrb_tree_rotate_right(pool, parent_pos_t, root_pos);
                node_pos_t = (*root_pos);
                break;
            }
        }
    }

    node = CTDNSSVRB_POOL_NODE(pool, node_pos_t);
    if (NULL_PTR != node)
    {
        CTDNSSVRB_NODE_COLOR(node) = CTDNSSVRB_BLACK;
    }
    return;
}

/*note: erase from tree but not recycle to free nodes pool*/
EC_BOOL ctdnssvrb_tree_erase(CTDNSSVRB_POOL *pool, const uint32_t node_pos, uint32_t *root_pos)
{
    CTDNSSVRB_NODE *node;

    uint32_t node_pos_t;
    uint32_t child_pos;
    uint32_t parent_pos;
    uint32_t color;

    node_pos_t = node_pos;
    node = CTDNSSVRB_POOL_NODE(pool, node_pos_t);

    ASSERT(NULL_PTR != node);
    ASSERT(CTDNSSVRB_NODE_IS_USED(node));

    if (CTDNSSVRB_ERR_POS == CTDNSSVRB_NODE_LEFT_POS(node))
    {
        child_pos = CTDNSSVRB_NODE_RIGHT_POS(node);
    }
    else if (CTDNSSVRB_ERR_POS == CTDNSSVRB_NODE_RIGHT_POS(node))
    {
        child_pos = CTDNSSVRB_NODE_LEFT_POS(node);
    }
    else
    {
        CTDNSSVRB_NODE *old;

        uint32_t old_pos;
        uint32_t left_pos;

        old_pos = node_pos_t;

        node_pos_t = CTDNSSVRB_NODE_RIGHT_POS(node);
        node = CTDNSSVRB_POOL_NODE(pool, node_pos_t);

        while (CTDNSSVRB_ERR_POS != (left_pos = CTDNSSVRB_NODE_LEFT_POS(node)))
        {
            node_pos_t = left_pos;
            node = CTDNSSVRB_POOL_NODE(pool, node_pos_t);

        }

        child_pos  = CTDNSSVRB_NODE_RIGHT_POS(node);
        parent_pos = CTDNSSVRB_NODE_PARENT_POS(node);
        color      = CTDNSSVRB_NODE_COLOR(node);

        if (CTDNSSVRB_ERR_POS != child_pos)
        {
            CTDNSSVRB_NODE *child;
            child = CTDNSSVRB_POOL_NODE(pool, child_pos);
            CTDNSSVRB_NODE_PARENT_POS(child) = parent_pos;
        }

        if (CTDNSSVRB_ERR_POS != parent_pos)
        {
            CTDNSSVRB_NODE *parent;

            parent = CTDNSSVRB_POOL_NODE(pool, parent_pos);
            if (CTDNSSVRB_NODE_LEFT_POS(parent) == node_pos_t)
            {
                CTDNSSVRB_NODE_LEFT_POS(parent) = child_pos;
            }
            else
            {
                CTDNSSVRB_NODE_RIGHT_POS(parent) = child_pos;
            }
        }
        else
        {
            (*root_pos) = child_pos;
        }

        if (CTDNSSVRB_NODE_PARENT_POS(node) == old_pos)
        {
            parent_pos = node_pos_t;
        }

        old  = CTDNSSVRB_POOL_NODE(pool, old_pos);

        CTDNSSVRB_NODE_PARENT_POS(node) = CTDNSSVRB_NODE_PARENT_POS(old);
        CTDNSSVRB_NODE_COLOR(node)      = CTDNSSVRB_NODE_COLOR(old);
        CTDNSSVRB_NODE_RIGHT_POS(node)  = CTDNSSVRB_NODE_RIGHT_POS(old);
        CTDNSSVRB_NODE_LEFT_POS(node)   = CTDNSSVRB_NODE_LEFT_POS(old);

        if (CTDNSSVRB_ERR_POS != CTDNSSVRB_NODE_PARENT_POS(old))
        {
            CTDNSSVRB_NODE *old_parent;
            old_parent = CTDNSSVRB_POOL_NODE(pool, CTDNSSVRB_NODE_PARENT_POS(old));

            if (CTDNSSVRB_NODE_LEFT_POS(old_parent) == old_pos)
            {
                CTDNSSVRB_NODE_LEFT_POS(old_parent) = node_pos_t;
            }
            else
            {
                CTDNSSVRB_NODE_RIGHT_POS(old_parent) = node_pos_t;
            }
        }
        else
        {
            (*root_pos) = node_pos_t;
        }

        {
            CTDNSSVRB_NODE *old_left;

            old_left = CTDNSSVRB_POOL_NODE(pool, CTDNSSVRB_NODE_LEFT_POS(old));
            CTDNSSVRB_NODE_PARENT_POS(old_left) = node_pos_t;
        }

        if (CTDNSSVRB_ERR_POS != CTDNSSVRB_NODE_RIGHT_POS(old))
        {
            CTDNSSVRB_NODE *old_right;
            old_right = CTDNSSVRB_POOL_NODE(pool, CTDNSSVRB_NODE_RIGHT_POS(old));
            CTDNSSVRB_NODE_PARENT_POS(old_right) = node_pos_t;
        }
        goto color;
    }

    parent_pos = CTDNSSVRB_NODE_PARENT_POS(node);
    color = CTDNSSVRB_NODE_COLOR(node);

    if (CTDNSSVRB_ERR_POS != child_pos)
    {
        CTDNSSVRB_NODE *child;
        child = CTDNSSVRB_POOL_NODE(pool, child_pos);
        CTDNSSVRB_NODE_PARENT_POS(child) = parent_pos;
    }

    if (CTDNSSVRB_ERR_POS != parent_pos)
    {
        CTDNSSVRB_NODE *parent;

        parent = CTDNSSVRB_POOL_NODE(pool, parent_pos);
        if (CTDNSSVRB_NODE_LEFT_POS(parent) == node_pos_t)
        {
            CTDNSSVRB_NODE_LEFT_POS(parent) = child_pos;
        }
        else
        {
            CTDNSSVRB_NODE_RIGHT_POS(parent) = child_pos;
        }
    }
    else
    {
        (*root_pos) = child_pos;
    }

 color:
    if (CTDNSSVRB_BLACK == color)
    {
        __ctdnssvrb_tree_erase_color(pool, child_pos, parent_pos, root_pos);
    }
    return (EC_TRUE);
}

STATIC_CAST static uint32_t __ctdnssvrb_tree_count_node_num(const CTDNSSVRB_POOL *pool, const uint32_t node_pos)
{
    const CTDNSSVRB_NODE *node;

    if(CTDNSSVRB_ERR_POS == node_pos)
    {
        return ((uint32_t)0);
    }

    node = CTDNSSVRB_POOL_NODE(pool, node_pos);

    return (uint32_t)(1 + __ctdnssvrb_tree_count_node_num(pool, CTDNSSVRB_NODE_LEFT_POS(node)) + __ctdnssvrb_tree_count_node_num(pool, CTDNSSVRB_NODE_RIGHT_POS(node)));
}

uint32_t ctdnssvrb_tree_count_node_num(const CTDNSSVRB_POOL *pool, const uint32_t root_pos)
{
    return __ctdnssvrb_tree_count_node_num(pool, root_pos);
}

uint32_t ctdnssvrb_tree_node_max_num(const CTDNSSVRB_POOL *pool)
{
    return CTDNSSVRB_POOL_NODE_MAX_NUM(pool);
}

uint32_t ctdnssvrb_tree_node_used_num(const CTDNSSVRB_POOL *pool)
{
    return CTDNSSVRB_POOL_NODE_USED_NUM(pool);
}

uint32_t ctdnssvrb_tree_node_sizeof(const CTDNSSVRB_POOL *pool)
{
    return CTDNSSVRB_POOL_NODE_SIZEOF(pool);
}

/*
 * This function returns the first node_pos (in sort order) of the tree.
 */
uint32_t ctdnssvrb_tree_first_node(const CTDNSSVRB_POOL *pool, const uint32_t root_pos)
{
    uint32_t  node_pos;
    const CTDNSSVRB_NODE *node;

    node_pos = root_pos;
    if (CTDNSSVRB_ERR_POS == node_pos)
    {
        return (CTDNSSVRB_ERR_POS);
    }

    node = CTDNSSVRB_POOL_NODE(pool, node_pos);

    while (CTDNSSVRB_ERR_POS != CTDNSSVRB_NODE_LEFT_POS(node))
    {
        node_pos = CTDNSSVRB_NODE_LEFT_POS(node);
        node = CTDNSSVRB_POOL_NODE(pool, node_pos);
    }
    return (node_pos);
}

uint32_t ctdnssvrb_tree_last_node(const CTDNSSVRB_POOL *pool, const uint32_t root_pos)
{
    uint32_t  node_pos;
    const CTDNSSVRB_NODE *node;

    node_pos = root_pos;
    if (CTDNSSVRB_ERR_POS == node_pos)
    {
        return (CTDNSSVRB_ERR_POS);
    }

    node = CTDNSSVRB_POOL_NODE(pool, node_pos);

    while (CTDNSSVRB_ERR_POS != CTDNSSVRB_NODE_RIGHT_POS(node))
    {
        node_pos = CTDNSSVRB_NODE_RIGHT_POS(node);
        node = CTDNSSVRB_POOL_NODE(pool, node_pos);
    }

    return (node_pos);
}

uint32_t ctdnssvrb_tree_next_node(const CTDNSSVRB_POOL *pool, const uint32_t node_pos)
{
    uint32_t node_pos_t;
    const CTDNSSVRB_NODE *node;
    const CTDNSSVRB_NODE *parent;

    node_pos_t = node_pos;
    node = CTDNSSVRB_POOL_NODE(pool, node_pos_t);
    /* If we have a right-hand child, go down and then left as far
       as we can. */
    if (CTDNSSVRB_ERR_POS != CTDNSSVRB_NODE_RIGHT_POS(node))
    {
        node_pos_t = CTDNSSVRB_NODE_RIGHT_POS(node);
        node = CTDNSSVRB_POOL_NODE(pool, node_pos_t);
        while (CTDNSSVRB_ERR_POS != CTDNSSVRB_NODE_LEFT_POS(node))
        {
            node_pos_t = CTDNSSVRB_NODE_LEFT_POS(node);
            node = CTDNSSVRB_POOL_NODE(pool, node_pos_t);
        }
        return (node_pos_t);
    }

    /* No right-hand children.  Everything down and left is
       smaller than us, so any 'next' node_pos_t must be in the general
       direction of our parent. Go up the tree; any time the
       ancestor is a right-hand child of its parent, keep going
       up. First time it's a left-hand child of its parent, said
       parent is our 'next' node_pos_t. */
    while (NULL_PTR != (parent = CTDNSSVRB_POOL_NODE(pool, CTDNSSVRB_NODE_PARENT_POS(node))) && node_pos_t == CTDNSSVRB_NODE_RIGHT_POS(parent))
    {
        node_pos_t = CTDNSSVRB_NODE_PARENT_POS(node);
        node = parent;
    }

    return (CTDNSSVRB_NODE_PARENT_POS(node));
}

uint32_t ctdnssvrb_tree_prev_node(const CTDNSSVRB_POOL *pool, const uint32_t node_pos)
{
    uint32_t node_pos_t;
    const CTDNSSVRB_NODE *node;
    const CTDNSSVRB_NODE *parent;

    node_pos_t = node_pos;
    node = CTDNSSVRB_POOL_NODE(pool, node_pos_t);

    /* If we have a left-hand child, go down and then right as far
       as we can. */
    if (CTDNSSVRB_ERR_POS != CTDNSSVRB_NODE_LEFT_POS(node))
    {
        node_pos_t = CTDNSSVRB_NODE_LEFT_POS(node);
        node = CTDNSSVRB_POOL_NODE(pool, node_pos_t);
        while (CTDNSSVRB_ERR_POS != CTDNSSVRB_NODE_RIGHT_POS(node))
        {
            node_pos_t = CTDNSSVRB_NODE_RIGHT_POS(node);
            node = CTDNSSVRB_POOL_NODE(pool, node_pos_t);
        }
        return (node_pos_t);
    }

    /* No left-hand children. Go up till we find an ancestor which
       is a right-hand child of its parent */
    while (NULL_PTR != (parent = CTDNSSVRB_POOL_NODE(pool, CTDNSSVRB_NODE_PARENT_POS(node))) && node_pos_t == CTDNSSVRB_NODE_LEFT_POS(parent))
    {
        node_pos_t = CTDNSSVRB_NODE_PARENT_POS(node);
        node = parent;
    }

    return (CTDNSSVRB_NODE_PARENT_POS(node));
}

/*victim_pos should be free*/
void ctdnssvrb_tree_replace_node(CTDNSSVRB_POOL *pool, const uint32_t victim_pos, const uint32_t new_pos, uint32_t *root_pos)
{
    CTDNSSVRB_NODE *victim;

    victim = CTDNSSVRB_POOL_NODE(pool, victim_pos);

    /* Set the surrounding nodes to point to the replacement */
    if (CTDNSSVRB_ERR_POS != CTDNSSVRB_NODE_PARENT_POS(victim))
    {
        CTDNSSVRB_NODE *parent;
        parent = CTDNSSVRB_POOL_NODE(pool, CTDNSSVRB_NODE_PARENT_POS(victim));

        if (victim_pos == CTDNSSVRB_NODE_LEFT_POS(parent))
        {
            CTDNSSVRB_NODE_LEFT_POS(parent) = new_pos;
        }
        else
        {
            CTDNSSVRB_NODE_RIGHT_POS(parent) = new_pos;
        }
    }
    else
    {
        (*root_pos) = new_pos;
    }

    if (CTDNSSVRB_ERR_POS != CTDNSSVRB_NODE_LEFT_POS(victim))
    {
        CTDNSSVRB_NODE *left;
        left = CTDNSSVRB_POOL_NODE(pool, CTDNSSVRB_NODE_LEFT_POS(victim));
        CTDNSSVRB_NODE_PARENT_POS(left) = new_pos;
    }
    if (CTDNSSVRB_ERR_POS != CTDNSSVRB_NODE_RIGHT_POS(victim))
    {
        CTDNSSVRB_NODE *right;
        right = CTDNSSVRB_POOL_NODE(pool, CTDNSSVRB_NODE_RIGHT_POS(victim));
        CTDNSSVRB_NODE_PARENT_POS(right) = new_pos;
    }

    return;
}


#if 1
STATIC_CAST static int __ctdnssvrb_node_tcid_cmp(const CTDNSSVRB_NODE *node, const UINT32 tcid)
{
    const CTDNSSV_ITEM *item;

    item = (const CTDNSSV_ITEM *)CTDNSSV_RB_NODE_ITEM(node);
    if(CTDNSSV_ITEM_TCID(item) < tcid)
    {
        return (-1);
    }

    if(CTDNSSV_ITEM_TCID(item) > tcid)
    {
        return (1);
    }

    return (0);
}
#endif


/*return the searched pos*/
uint32_t ctdnssvrb_tree_search_data(const CTDNSSVRB_POOL *pool, const uint32_t root_pos, const UINT32 tcid)
{
    uint32_t node_pos;

    node_pos = root_pos;

    while (CTDNSSVRB_ERR_POS != node_pos)
    {
        const CTDNSSVRB_NODE *node;
        int cmp_ret;

        node = CTDNSSVRB_POOL_NODE(pool, node_pos);
        cmp_ret = __ctdnssvrb_node_tcid_cmp(node, tcid);

        if (0 < cmp_ret)
        {
            node_pos = CTDNSSVRB_NODE_LEFT_POS(node);
        }
        else if (0 > cmp_ret)
        {
            node_pos = CTDNSSVRB_NODE_RIGHT_POS(node);
        }
        else
        {
            return (node_pos);
        }
    }

    return (CTDNSSVRB_ERR_POS);
}

/*if found duplicate node, return EC_FALSE, otherwise return EC_TRUE*/
EC_BOOL ctdnssvrb_tree_insert_data(CTDNSSVRB_POOL *pool, uint32_t *root_pos, const UINT32 tcid, uint32_t *insert_pos)
{
    uint32_t  node_pos_t;
    uint32_t  new_pos_t;
    uint32_t  parent_pos_t;
    uint32_t  flag; /*0: on left subtree, 1: on right subtree*/

    node_pos_t   = (*root_pos);
    parent_pos_t = CTDNSSVRB_ERR_POS;
    flag         = ~(uint32_t)0;

    while (CTDNSSVRB_ERR_POS != node_pos_t)
    {
        CTDNSSVRB_NODE *node;
        int cmp_ret;

        node = CTDNSSVRB_POOL_NODE(pool, node_pos_t);
        cmp_ret = __ctdnssvrb_node_tcid_cmp(node, tcid);

        parent_pos_t = node_pos_t;

        if (0 < cmp_ret)
        {
            node_pos_t = CTDNSSVRB_NODE_LEFT_POS(node);
            flag = 0;
        }
        else if (0 > cmp_ret)
        {
            node_pos_t = CTDNSSVRB_NODE_RIGHT_POS(node);
            flag = 1;
        }
        else
        {
            (*insert_pos) = node_pos_t;
            return (EC_FALSE);/*found duplicate*/
        }
    }


    /*not found data in the rbtree*/
    new_pos_t = ctdnssvrb_node_new(pool);
    if(CTDNSSVRB_ERR_POS == new_pos_t)
    {
        (*insert_pos) = CTDNSSVRB_ERR_POS;
        return (EC_FALSE);
    }
    else
    {
        CTDNSSVRB_NODE *node;

        node  = CTDNSSVRB_POOL_NODE(pool, new_pos_t);
        CTDNSSVRB_NODE_DATA(node) = 0;/*xxx*/

        CTDNSSVRB_NODE_PARENT_POS(node) = parent_pos_t;
        CTDNSSVRB_NODE_COLOR(node)      = CTDNSSVRB_RED;
        CTDNSSVRB_NODE_LEFT_POS(node)   = CTDNSSVRB_ERR_POS;
        CTDNSSVRB_NODE_RIGHT_POS(node)  = CTDNSSVRB_ERR_POS;

        if(CTDNSSVRB_ERR_POS == (*root_pos))
        {
            (*root_pos) = new_pos_t;
        }
        else
        {
            CTDNSSVRB_NODE *parent;
            parent  = CTDNSSVRB_POOL_NODE(pool, parent_pos_t);

            if(0 == flag)/*on left subtree*/
            {
                CTDNSSVRB_NODE_LEFT_POS(parent) = new_pos_t;
            }
            else
            {
                CTDNSSVRB_NODE_RIGHT_POS(parent) = new_pos_t;
            }
        }
        __ctdnssvrb_tree_insert_color(pool, new_pos_t, root_pos);
    }

    (*insert_pos) = new_pos_t;
    return (EC_TRUE); /*it is new node*/
}

EC_BOOL ctdnssvrb_tree_delete_data(CTDNSSVRB_POOL *pool, uint32_t *root_pos, const UINT32 tcid, uint32_t *delete_pos)
{
    uint32_t node_pos;

    node_pos = ctdnssvrb_tree_search_data(pool, *root_pos, tcid);
    if(CTDNSSVRB_ERR_POS == node_pos)
    {
        return (EC_FALSE);
    }

    ctdnssvrb_tree_erase(pool, node_pos, root_pos);
    ctdnssvrb_node_free(pool, node_pos);

    (*delete_pos) = node_pos;
    return (EC_TRUE);
}


EC_BOOL ctdnssvrb_tree_delete(CTDNSSVRB_POOL *pool, uint32_t *root_pos, const uint32_t node_pos)
{
    ctdnssvrb_tree_erase(pool, node_pos, root_pos);
    ctdnssvrb_node_free(pool, node_pos);
    return (EC_TRUE);
}


/*postorder: left -> right -> root*/
STATIC_CAST static void __ctdnssvrb_tree_free(CTDNSSVRB_POOL *pool, const uint32_t node_pos)
{
    CTDNSSVRB_NODE *node;

    if(CTDNSSVRB_ERR_POS == node_pos)
    {
        return;
    }

    node  = CTDNSSVRB_POOL_NODE(pool, node_pos);
    if(CTDNSSVRB_ERR_POS != CTDNSSVRB_NODE_LEFT_POS(node))
    {
        __ctdnssvrb_tree_free(pool, CTDNSSVRB_NODE_LEFT_POS(node));
    }

    if(CTDNSSVRB_ERR_POS != CTDNSSVRB_NODE_RIGHT_POS(node))
    {
        __ctdnssvrb_tree_free(pool, CTDNSSVRB_NODE_RIGHT_POS(node));
    }

    ctdnssvrb_node_free(pool, node_pos);

    return;
}
void ctdnssvrb_tree_free(CTDNSSVRB_POOL *pool, const uint32_t root_pos)
{
    __ctdnssvrb_tree_free(pool, root_pos);
    return;
}

EC_BOOL ctdnssvrb_pool_init(CTDNSSVRB_POOL *pool, const uint32_t node_max_num, const uint32_t node_sizeof)
{
    uint32_t node_pos;

    if(CTDNSSVRB_POOL_MAX_SIZE < node_max_num)
    {
        dbg_log(SEC_0039_CTDNSSVRB, 0)(LOGSTDERR, "error:ctdnssvrb_pool_init: node_max_num %u overflow!\n", node_max_num);
        return (EC_FALSE);
    }

    CTDNSSVRB_POOL_NODE_MAX_NUM(pool)  = node_max_num;
    CTDNSSVRB_POOL_NODE_USED_NUM(pool) = 0;
    CTDNSSVRB_POOL_NODE_SIZEOF(pool)   = node_sizeof;

    for(node_pos = 0; node_pos < node_max_num; node_pos ++)
    {
        ctdnssvrb_node_init(pool, node_pos);
        ctdnssvrb_node_set_next(pool, node_pos, node_pos + 1);

        if(0 == ((node_pos + 1) % 100000))
        {
            dbg_log(SEC_0039_CTDNSSVRB, 0)(LOGSTDOUT, "info:ctdnssvrb_pool_init: init node %u - %u of max %u done\n",
                               node_pos - 99999, node_pos, node_max_num);
        }
    }
    dbg_log(SEC_0039_CTDNSSVRB, 0)(LOGSTDOUT, "info:ctdnssvrb_pool_init: init %u nodes done\n", node_max_num);
    ctdnssvrb_node_set_next(pool, node_max_num - 1, CTDNSSVRB_ERR_POS);/*overwrite the last one*/

    CTDNSSVRB_POOL_FREE_HEAD(pool) = 0;/*the free nodes head*/
    CTDNSSVRB_POOL_ROOT_POS(pool)  = CTDNSSVRB_ERR_POS;
    return (EC_TRUE);
}

void ctdnssvrb_pool_clean(CTDNSSVRB_POOL *pool)
{
    CTDNSSVRB_POOL_NODE_MAX_NUM(pool)  = 0;
    CTDNSSVRB_POOL_FREE_HEAD(pool)     = CTDNSSVRB_ERR_POS;
    CTDNSSVRB_POOL_ROOT_POS(pool)      = CTDNSSVRB_ERR_POS;
    return;
}

void ctdnssvrb_pool_print(LOG *log, const CTDNSSVRB_POOL *pool)
{
    uint32_t node_pos;
    uint32_t node_max_num;

    node_max_num = CTDNSSVRB_POOL_NODE_MAX_NUM(pool);

    sys_log(log, "pool %lx, node_max_num %u, node_used_num %u, root_pos %u, free_head %u, node_sizeof = %u\n",
                 pool,
                 node_max_num,
                 CTDNSSVRB_POOL_NODE_USED_NUM(pool),
                 CTDNSSVRB_POOL_ROOT_POS(pool),
                 CTDNSSVRB_POOL_FREE_HEAD(pool),
                 CTDNSSVRB_POOL_NODE_SIZEOF(pool));

    if(0)
    {
        for(node_pos = 0; node_pos < node_max_num; node_pos ++)
        {
            if(EC_TRUE == ctdnssvrb_node_is_used(pool, node_pos))
            {
                ctdnssvrb_node_print(log, pool, node_pos);
            }
        }
    }
    return;
}


EC_BOOL ctdnssvrb_pool_is_empty(const CTDNSSVRB_POOL *pool)
{
    if (0 == CTDNSSVRB_POOL_NODE_USED_NUM(pool))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL ctdnssvrb_pool_is_full(const CTDNSSVRB_POOL *pool)
{
    if (CTDNSSVRB_POOL_NODE_MAX_NUM(pool) == CTDNSSVRB_POOL_NODE_USED_NUM(pool))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

/*visit the root node first: root -> left -> right*/
void ctdnssvrb_preorder_print(LOG *log, const CTDNSSVRB_POOL *pool, const uint32_t node_pos)
{
    const CTDNSSVRB_NODE *node;

    if(CTDNSSVRB_ERR_POS == node_pos)
    {
        return;
    }

    node  = CTDNSSVRB_POOL_NODE(pool, node_pos);
    ctdnssvrb_node_print(log, pool, node_pos);

    if(CTDNSSVRB_ERR_POS != CTDNSSVRB_NODE_LEFT_POS(node))
    {
        ctdnssvrb_preorder_print(log, pool, CTDNSSVRB_NODE_LEFT_POS(node));
    }

    if(CTDNSSVRB_ERR_POS != CTDNSSVRB_NODE_RIGHT_POS(node))
    {
        ctdnssvrb_preorder_print(log, pool, CTDNSSVRB_NODE_RIGHT_POS(node));
    }

    return;
}

/*visit the left subtree, then the root node: left -> root -> right*/
void ctdnssvrb_inorder_print(LOG *log, const CTDNSSVRB_POOL *pool, const uint32_t node_pos)
{
    const CTDNSSVRB_NODE *node;

    if(CTDNSSVRB_ERR_POS == node_pos)
    {
        return;
    }

    node  = CTDNSSVRB_POOL_NODE(pool, node_pos);
    if(CTDNSSVRB_ERR_POS != CTDNSSVRB_NODE_LEFT_POS(node))
    {
        ctdnssvrb_inorder_print(log, pool, CTDNSSVRB_NODE_LEFT_POS(node));
    }

    ctdnssvrb_node_print(log, pool, node_pos);

    if(CTDNSSVRB_ERR_POS != CTDNSSVRB_NODE_RIGHT_POS(node))
    {
        ctdnssvrb_inorder_print(log, pool, CTDNSSVRB_NODE_RIGHT_POS(node));
    }

    return;
}

/*visit the root node last: left -> right -> root*/
void ctdnssvrb_postorder_print(LOG *log, const CTDNSSVRB_POOL *pool, const uint32_t node_pos)
{
    const CTDNSSVRB_NODE *node;

    if(CTDNSSVRB_ERR_POS == node_pos)
    {
        return;
    }

    node  = CTDNSSVRB_POOL_NODE(pool, node_pos);
    if(CTDNSSVRB_ERR_POS != CTDNSSVRB_NODE_LEFT_POS(node))
    {
        ctdnssvrb_postorder_print(log, pool, CTDNSSVRB_NODE_LEFT_POS(node));
    }

    if(CTDNSSVRB_ERR_POS != CTDNSSVRB_NODE_RIGHT_POS(node))
    {
        ctdnssvrb_postorder_print(log, pool, CTDNSSVRB_NODE_RIGHT_POS(node));
    }

    ctdnssvrb_node_print(log, pool, node_pos);

    return;
}


/*visit the root node first: root -> left -> right*/
void ctdnssvrb_preorder_print_level(LOG *log, const CTDNSSVRB_POOL *pool, const uint32_t node_pos, const uint32_t level)
{
    const CTDNSSVRB_NODE *node;

    if(CTDNSSVRB_ERR_POS == node_pos)
    {
        return;
    }

    node  = CTDNSSVRB_POOL_NODE(pool, node_pos);
    ctdnssvrb_node_print_level(log, pool, node_pos, level);

    if(CTDNSSVRB_ERR_POS != CTDNSSVRB_NODE_LEFT_POS(node))
    {
        ctdnssvrb_preorder_print_level(log, pool, CTDNSSVRB_NODE_LEFT_POS(node), level + 1);
    }

    if(CTDNSSVRB_ERR_POS != CTDNSSVRB_NODE_RIGHT_POS(node))
    {
        ctdnssvrb_preorder_print_level(log, pool, CTDNSSVRB_NODE_RIGHT_POS(node), level + 1);
    }

    return;
}

EC_BOOL ctdnssvrb_flush_size(const CTDNSSVRB_POOL *pool, UINT32 *size)
{
    (*size) += sizeof(CTDNSSVRB_POOL) + CTDNSSVRB_POOL_NODE_MAX_NUM(pool) * CTDNSSVRB_POOL_NODE_SIZEOF(pool);
    return (EC_TRUE);
}

EC_BOOL ctdnssvrb_flush(const CTDNSSVRB_POOL *pool, int fd, UINT32 *offset)
{
    UINT32 osize;/*write once size*/

    /*flush root_pos*/
    osize = sizeof(uint32_t);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(CTDNSSVRB_POOL_ROOT_POS(pool))))
    {
        dbg_log(SEC_0039_CTDNSSVRB, 0)(LOGSTDOUT, "error:ctdnssvrb_flush: write CTDNSSVRB_POOL_ROOT_POS at offset %u of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*flush free_head*/
    osize = sizeof(uint32_t);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(CTDNSSVRB_POOL_FREE_HEAD(pool))))
    {
        dbg_log(SEC_0039_CTDNSSVRB, 0)(LOGSTDOUT, "error:ctdnssvrb_flush: write CTDNSSVRB_POOL_FREE_HEAD at offset %u of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*flush node_max_num*/
    osize  = sizeof(uint32_t);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(CTDNSSVRB_POOL_NODE_MAX_NUM(pool))))
    {
        dbg_log(SEC_0039_CTDNSSVRB, 0)(LOGSTDOUT, "error:ctdnssvrb_flush: write CTDNSSVRB_POOL_NODE_MAX_NUM at offset %u of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*flush node_used_num*/
    osize  = sizeof(uint32_t);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(CTDNSSVRB_POOL_NODE_USED_NUM(pool))))
    {
        dbg_log(SEC_0039_CTDNSSVRB, 0)(LOGSTDOUT, "error:ctdnssvrb_flush: write CTDNSSVRB_POOL_NODE_USED_NUM at offset %u of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*flush node_sizeof*/
    osize  = sizeof(uint32_t);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(CTDNSSVRB_POOL_NODE_SIZEOF(pool))))
    {
        dbg_log(SEC_0039_CTDNSSVRB, 0)(LOGSTDOUT, "error:ctdnssvrb_flush: write CTDNSSVRB_POOL_NODE_SIZEOF at offset %u of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*flush rb_node table*/
    osize  = CTDNSSVRB_POOL_NODE_MAX_NUM(pool) * CTDNSSVRB_POOL_NODE_SIZEOF(pool);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)CTDNSSVRB_POOL_NODE_TBL(pool)))
    {
        dbg_log(SEC_0039_CTDNSSVRB, 0)(LOGSTDOUT, "error:ctdnssvrb_flush: write CTDNSSVRB_POOL_NODE_TBL at offset %u of fd %d failed where CTDNSSVRB_POOL_NODE_MAX_NUM is %u\n",
                            (*offset), fd, CTDNSSVRB_POOL_NODE_MAX_NUM(pool));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL ctdnssvrb_load(CTDNSSVRB_POOL *pool, int fd, UINT32 *offset)
{
    UINT32 osize;/*read once size*/
    uint32_t node_max_num;
    uint32_t node_used_num;
    uint32_t node_sizeof;

    /*load root_pos*/
    osize = sizeof(uint32_t);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(CTDNSSVRB_POOL_ROOT_POS(pool))))
    {
        dbg_log(SEC_0039_CTDNSSVRB, 0)(LOGSTDOUT, "error:ctdnssvrb_load: load CTDNSSVRB_POOL_ROOT_POS at offset %u of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*load free_head*/
    osize = sizeof(uint32_t);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(CTDNSSVRB_POOL_FREE_HEAD(pool))))
    {
        dbg_log(SEC_0039_CTDNSSVRB, 0)(LOGSTDOUT, "error:ctdnssvrb_load: load CTDNSSVRB_POOL_FREE_HEAD at offset %u of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*load node_max_num*/
    osize  = sizeof(uint32_t);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(node_max_num)))
    {
        dbg_log(SEC_0039_CTDNSSVRB, 0)(LOGSTDOUT, "error:ctdnssvrb_load: load CTDNSSVRB_POOL_NODE_MAX_NUM at offset %u of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }
    CTDNSSVRB_POOL_NODE_MAX_NUM(pool) = node_max_num;

    /*load node_used_num*/
    osize  = sizeof(uint32_t);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(node_used_num)))
    {
        dbg_log(SEC_0039_CTDNSSVRB, 0)(LOGSTDOUT, "error:ctdnssvrb_load: load CTDNSSVRB_POOL_NODE_USED_NUM at offset %u of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }
    CTDNSSVRB_POOL_NODE_MAX_NUM(pool) = node_used_num;

    /*load node_sizeof*/
    osize  = sizeof(uint32_t);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(node_sizeof)))
    {
        dbg_log(SEC_0039_CTDNSSVRB, 0)(LOGSTDOUT, "error:ctdnssvrb_load: load CTDNSSVRB_POOL_NODE_SIZEOF at offset %u of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }
    CTDNSSVRB_POOL_NODE_SIZEOF(pool) = node_sizeof;

    /*load rb_node table*/
    osize  = CTDNSSVRB_POOL_NODE_MAX_NUM(pool) * CTDNSSVRB_POOL_NODE_SIZEOF(pool);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)CTDNSSVRB_POOL_NODE_TBL(pool)))
    {
        dbg_log(SEC_0039_CTDNSSVRB, 0)(LOGSTDOUT, "error:ctdnssvrb_load: load CTDNSSVRB_POOL_NODE_TBL at offset %u of fd %d failed where CTDNSSVRB_POOL_NODE_MAX_NUM is %u\n",
                            (*offset), fd, CTDNSSVRB_POOL_NODE_MAX_NUM(pool));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

void ctdnssvrb_tree_print(LOG *log, const CTDNSSVRB_POOL *pool, const uint32_t root_pos)
{
    uint32_t node_pos;

    sys_log(log, "[root = %5d]\n", root_pos);
    for(node_pos = ctdnssvrb_tree_first_node(pool, root_pos); CTDNSSVRB_ERR_POS != node_pos; node_pos = ctdnssvrb_tree_next_node(pool, node_pos))
    {
        ctdnssvrb_node_print(log, pool, node_pos);
    }
    return;
}

/* ---- debug ---- */
EC_BOOL ctdnssvrb_node_debug_cmp(const CTDNSSVRB_NODE *node_1st, const CTDNSSVRB_NODE *node_2nd, int (*node_cmp_data)(const CTDNSSVRB_NODE *, const CTDNSSVRB_NODE *))
{
    if(CTDNSSVRB_NODE_USED_FLAG(node_1st) != CTDNSSVRB_NODE_USED_FLAG(node_2nd))
    {
        dbg_log(SEC_0039_CTDNSSVRB, 0)(LOGSTDERR, "error:ctdnssvrb_node_debug_cmp: inconsistent CTDNSSVRB_NODE_USED_FLAG: %u != %u\n",
                            CTDNSSVRB_NODE_USED_FLAG(node_1st), CTDNSSVRB_NODE_USED_FLAG(node_2nd));
        return (EC_FALSE);
    }
#if 0
    if(CTDNSSVRB_NODE_NOT_USED == CTDNSSVRB_NODE_USED_FLAG(node_1st))
    {
        return (EC_TRUE);
    }
#endif

    if(CTDNSSVRB_NODE_COLOR(node_1st) != CTDNSSVRB_NODE_COLOR(node_2nd))
    {
        dbg_log(SEC_0039_CTDNSSVRB, 0)(LOGSTDERR, "error:ctdnssvrb_node_debug_cmp: inconsistent CTDNSSVRB_NODE_COLOR: %u != %u\n",
                            CTDNSSVRB_NODE_COLOR(node_1st), CTDNSSVRB_NODE_COLOR(node_2nd));
        return (EC_FALSE);
    }

    if(CTDNSSVRB_NODE_PARENT_POS(node_1st) != CTDNSSVRB_NODE_PARENT_POS(node_2nd))
    {
        dbg_log(SEC_0039_CTDNSSVRB, 0)(LOGSTDERR, "error:ctdnssvrb_node_debug_cmp: inconsistent CTDNSSVRB_NODE_PARENT_POS: %u != %u\n",
                            CTDNSSVRB_NODE_PARENT_POS(node_1st), CTDNSSVRB_NODE_PARENT_POS(node_2nd));
        return (EC_FALSE);
    }

    if(CTDNSSVRB_NODE_RIGHT_POS(node_1st) != CTDNSSVRB_NODE_RIGHT_POS(node_2nd))
    {
        dbg_log(SEC_0039_CTDNSSVRB, 0)(LOGSTDERR, "error:ctdnssvrb_node_debug_cmp: inconsistent CTDNSSVRB_NODE_RIGHT_POS: %u != %u\n",
                            CTDNSSVRB_NODE_RIGHT_POS(node_1st), CTDNSSVRB_NODE_RIGHT_POS(node_2nd));
        return (EC_FALSE);
    }

    if(CTDNSSVRB_NODE_LEFT_POS(node_1st) != CTDNSSVRB_NODE_LEFT_POS(node_2nd))
    {
        dbg_log(SEC_0039_CTDNSSVRB, 0)(LOGSTDERR, "error:ctdnssvrb_node_debug_cmp: inconsistent CTDNSSVRB_NODE_LEFT_POS: %u != %u\n",
                            CTDNSSVRB_NODE_LEFT_POS(node_1st), CTDNSSVRB_NODE_LEFT_POS(node_2nd));
        return (EC_FALSE);
    }

    if(CTDNSSVRB_NODE_USED == CTDNSSVRB_NODE_USED_FLAG(node_1st))
    {
        if(0 != node_cmp_data(node_1st, node_2nd))
        {
            dbg_log(SEC_0039_CTDNSSVRB, 0)(LOGSTDERR, "error:ctdnssvrb_node_debug_cmp: inconsistent data part\n");
            return (EC_FALSE);
        }
    }
    else
    {
        if(CTDNSSVRB_NODE_NEXT_POS(node_1st) != CTDNSSVRB_NODE_NEXT_POS(node_2nd))
        {
            dbg_log(SEC_0039_CTDNSSVRB, 0)(LOGSTDERR, "error:ctdnssvrb_node_debug_cmp: inconsistent CTDNSSVRB_NODE_NEXT_POS: %u != %u\n",
                                CTDNSSVRB_NODE_NEXT_POS(node_1st), CTDNSSVRB_NODE_NEXT_POS(node_2nd));
            return (EC_FALSE);
        }
    }
    return (EC_TRUE);
}

EC_BOOL ctdnssvrb_debug_cmp(const CTDNSSVRB_POOL *pool_1st, const CTDNSSVRB_POOL *pool_2nd, int (*node_cmp_data)(const CTDNSSVRB_NODE *, const CTDNSSVRB_NODE *))
{
    uint32_t  node_max_num;
    uint32_t  node_pos;

    if(CTDNSSVRB_POOL_ROOT_POS(pool_1st) != CTDNSSVRB_POOL_ROOT_POS(pool_2nd))
    {
        dbg_log(SEC_0039_CTDNSSVRB, 0)(LOGSTDERR, "error:ctdnssvrb_debug_cmp: inconsistent CTDNSSVRB_POOL_ROOT_POS: %u != %u\n",
                            CTDNSSVRB_POOL_ROOT_POS(pool_1st), CTDNSSVRB_POOL_ROOT_POS(pool_2nd));
        return (EC_FALSE);
    }

    if(CTDNSSVRB_POOL_FREE_HEAD(pool_1st) != CTDNSSVRB_POOL_FREE_HEAD(pool_2nd))
    {
        dbg_log(SEC_0039_CTDNSSVRB, 0)(LOGSTDERR, "error:ctdnssvrb_debug_cmp: inconsistent CTDNSSVRB_POOL_FREE_HEAD: %u != %u\n",
                            CTDNSSVRB_POOL_FREE_HEAD(pool_1st), CTDNSSVRB_POOL_FREE_HEAD(pool_2nd));
        return (EC_FALSE);
    }

    if(CTDNSSVRB_POOL_NODE_MAX_NUM(pool_1st) != CTDNSSVRB_POOL_NODE_MAX_NUM(pool_2nd))
    {
        dbg_log(SEC_0039_CTDNSSVRB, 0)(LOGSTDERR, "error:ctdnssvrb_debug_cmp: inconsistent CTDNSSVRB_POOL_NODE_MAX_NUM: %u != %u\n",
                            CTDNSSVRB_POOL_NODE_MAX_NUM(pool_1st), CTDNSSVRB_POOL_NODE_MAX_NUM(pool_2nd));
        return (EC_FALSE);
    }

    if(CTDNSSVRB_POOL_NODE_USED_NUM(pool_1st) != CTDNSSVRB_POOL_NODE_USED_NUM(pool_2nd))
    {
        dbg_log(SEC_0039_CTDNSSVRB, 0)(LOGSTDERR, "error:ctdnssvrb_debug_cmp: inconsistent CTDNSSVRB_POOL_NODE_USED_NUM: %u != %u\n",
                            CTDNSSVRB_POOL_NODE_USED_NUM(pool_1st), CTDNSSVRB_POOL_NODE_USED_NUM(pool_2nd));
        return (EC_FALSE);
    }

    if(CTDNSSVRB_POOL_NODE_SIZEOF(pool_1st) != CTDNSSVRB_POOL_NODE_SIZEOF(pool_2nd))
    {
        dbg_log(SEC_0039_CTDNSSVRB, 0)(LOGSTDERR, "error:ctdnssvrb_debug_cmp: inconsistent CTDNSSVRB_POOL_NODE_SIZEOF: %u != %u\n",
                            CTDNSSVRB_POOL_NODE_SIZEOF(pool_1st), CTDNSSVRB_POOL_NODE_SIZEOF(pool_2nd));
        return (EC_FALSE);
    }

    node_max_num = CTDNSSVRB_POOL_NODE_MAX_NUM(pool_1st);
    for(node_pos = 0; node_pos < node_max_num; node_pos ++)
    {
        CTDNSSVRB_NODE *node_1st;
        CTDNSSVRB_NODE *node_2nd;

        node_1st = CTDNSSVRB_POOL_NODE(pool_1st, node_pos);
        node_2nd = CTDNSSVRB_POOL_NODE(pool_2nd, node_pos);

        if(EC_FALSE == ctdnssvrb_node_debug_cmp(node_1st, node_2nd, node_cmp_data))
        {
            dbg_log(SEC_0039_CTDNSSVRB, 0)(LOGSTDERR, "error:ctdnssvrb_debug_cmp: inconsistent node at pos %u\n", node_pos);
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}


#ifdef __cplusplus
}
#endif/*__cplusplus*/
