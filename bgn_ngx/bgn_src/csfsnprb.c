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

#include "csfsnprb.h"
#include "csfsnp.h"


/*new a CSFSNPRB_NODE and return its position*/
uint32_t csfsnprb_node_new(CSFSNPRB_POOL *pool)
{
    uint32_t node_pos_t;
    CSFSNPRB_NODE *node;
 
    node_pos_t = CSFSNPRB_POOL_FREE_HEAD(pool);
    if(CSFSNPRB_ERR_POS == node_pos_t)
    {
        dbg_log(SEC_0172_CSFSNPRB, 0)(LOGSTDERR, "error:csfsnprb_node_new: no free node in pool\n");
        return (CSFSNPRB_ERR_POS);
    }

    if(CSFSNPRB_POOL_FREE_HEAD(pool) >= CSFSNPRB_POOL_NODE_MAX_NUM(pool))
    {
        dbg_log(SEC_0172_CSFSNPRB, 0)(LOGSTDERR, "error:csfsnprb_node_new: found conflict: free head %u >= max num %u\n",
                            CSFSNPRB_POOL_FREE_HEAD(pool), CSFSNPRB_POOL_NODE_MAX_NUM(pool));
        return (CSFSNPRB_ERR_POS);
    }

    ASSERT(CSFSNPRB_POOL_FREE_HEAD(pool) < CSFSNPRB_POOL_NODE_MAX_NUM(pool)); 
 
    node = CSFSNPRB_POOL_NODE(pool, node_pos_t);
    CSFSNPRB_POOL_FREE_HEAD(pool) = CSFSNPRB_NODE_NEXT_POS(node);
    CSFSNPRB_POOL_NODE_USED_NUM(pool) ++;
 
    CSFSNPRB_NODE_NEXT_POS(node)  = CSFSNPRB_ERR_POS;
    CSFSNPRB_NODE_USED_FLAG(node) = CSFSNPRB_NODE_USED;

    return (node_pos_t);
}

/*free a CSFSNPRB_NODE and return its position to the pool*/
void csfsnprb_node_free(CSFSNPRB_POOL *pool, const uint32_t node_pos)
{
    if(CSFSNPRB_ERR_POS != node_pos)
    {
        CSFSNPRB_NODE *node;

        ASSERT(node_pos < CSFSNPRB_POOL_NODE_MAX_NUM(pool));

        node = CSFSNPRB_POOL_NODE(pool, node_pos);
        ASSERT(CSFSNPRB_NODE_IS_USED(node));
     
        CSFSNPRB_NODE_USED_FLAG(node)  = CSFSNPRB_NODE_NOT_USED;
        CSFSNPRB_NODE_PARENT_POS(node) = CSFSNPRB_ERR_POS;
        CSFSNPRB_NODE_RIGHT_POS(node)  = CSFSNPRB_ERR_POS;
        CSFSNPRB_NODE_LEFT_POS(node)   = CSFSNPRB_ERR_POS;     
        CSFSNPRB_NODE_NEXT_POS(node)   = CSFSNPRB_POOL_FREE_HEAD(pool);
        CSFSNPRB_NODE_COLOR(node)      = CSFSNPRB_BLACK;
     
        CSFSNPRB_POOL_FREE_HEAD(pool)  = node_pos;
        CSFSNPRB_POOL_NODE_USED_NUM(pool) --;
    }
    return;
}

void csfsnprb_node_init(CSFSNPRB_POOL *pool, const uint32_t node_pos)
{
    CSFSNPRB_NODE *node;

    node  = CSFSNPRB_POOL_NODE(pool, node_pos); 
 
    CSFSNPRB_NODE_PARENT_POS(node) = CSFSNPRB_ERR_POS;
    CSFSNPRB_NODE_RIGHT_POS(node)  = CSFSNPRB_ERR_POS;
    CSFSNPRB_NODE_LEFT_POS(node)   = CSFSNPRB_ERR_POS;
    CSFSNPRB_NODE_USED_FLAG(node)  = CSFSNPRB_NODE_NOT_USED;
    CSFSNPRB_NODE_NEXT_POS(node)   = CSFSNPRB_ERR_POS;
    CSFSNPRB_NODE_COLOR(node)      = CSFSNPRB_BLACK;
 
    return;
}

void csfsnprb_node_clean(CSFSNPRB_POOL *pool, const uint32_t node_pos)
{
    CSFSNPRB_NODE *node;

    ASSERT(node_pos < CSFSNPRB_POOL_NODE_MAX_NUM(pool));

    node  = CSFSNPRB_POOL_NODE(pool, node_pos); 
 
    CSFSNPRB_NODE_PARENT_POS(node) = CSFSNPRB_ERR_POS;
    CSFSNPRB_NODE_RIGHT_POS(node)  = CSFSNPRB_ERR_POS;
    CSFSNPRB_NODE_LEFT_POS(node)   = CSFSNPRB_ERR_POS;
    CSFSNPRB_NODE_USED_FLAG(node)  = CSFSNPRB_NODE_NOT_USED;
    CSFSNPRB_NODE_NEXT_POS(node)   = CSFSNPRB_ERR_POS;
    CSFSNPRB_NODE_COLOR(node)      = CSFSNPRB_BLACK;

    return;
}

void csfsnprb_node_set_next(CSFSNPRB_POOL *pool, const uint32_t node_pos, const uint32_t next_pos)
{
    CSFSNPRB_NODE *node;

    node  = CSFSNPRB_POOL_NODE(pool, node_pos);
    CSFSNPRB_NODE_NEXT_POS(node) = next_pos;

    return;
}

EC_BOOL csfsnprb_node_is_used(const CSFSNPRB_POOL *pool, const uint32_t node_pos)
{
    const CSFSNPRB_NODE *node;
    node  = CSFSNPRB_POOL_NODE(pool, node_pos);

    if(CSFSNPRB_NODE_IS_USED(node))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

void csfsnprb_node_print(LOG *log, const CSFSNPRB_POOL *pool, const uint32_t node_pos)
{
    const CSFSNPRB_NODE *node;
    node  = CSFSNPRB_POOL_NODE(pool, node_pos);

    sys_log(log, "%5d: parent = %5d, left = %5d, right = %5d, flg = %s, color = %s, %s = %5d\n",
                       node_pos,
                       CSFSNPRB_NODE_PARENT_POS(node),
                       CSFSNPRB_NODE_LEFT_POS(node),
                       CSFSNPRB_NODE_RIGHT_POS(node),
                       CSFSNPRB_NODE_IS_USED(node) ? "used" : "n.a.",
                       CSFSNPRB_NODE_IS_USED(node) ? (CSFSNPRB_NODE_IS_RED(node) ? "red  " : "black") : "#####",
                       CSFSNPRB_NODE_IS_USED(node) ? "data" : "next",
                       CSFSNPRB_NODE_IS_USED(node) ? CSFSNPRB_NODE_DATA(node) : CSFSNPRB_NODE_NEXT_POS(node)
                       );
    return;
}

void csfsnprb_node_print_level(LOG *log, const CSFSNPRB_POOL *pool, const uint32_t node_pos, const uint32_t level)
{
    const CSFSNPRB_NODE *node;
    node  = CSFSNPRB_POOL_NODE(pool, node_pos);

    c_ident_print(log, level);
    sys_print(log, "%5d: parent = %5d, left = %5d, right = %5d, flg = %s, color = %s, %s = %5d\n",
                       node_pos,
                       CSFSNPRB_NODE_PARENT_POS(node),
                       CSFSNPRB_NODE_LEFT_POS(node),
                       CSFSNPRB_NODE_RIGHT_POS(node),
                       CSFSNPRB_NODE_IS_USED(node) ? "used" : "NOT used",
                       CSFSNPRB_NODE_IS_RED(node)  ? "red  " : "black",
                       CSFSNPRB_NODE_IS_USED(node) ? "data" : "next",
                       CSFSNPRB_NODE_IS_USED(node) ? CSFSNPRB_NODE_DATA(node) : CSFSNPRB_NODE_NEXT_POS(node)
                       );
    return;                    
}


static void __csfsnprb_tree_rotate_left(CSFSNPRB_POOL *pool, const uint32_t node_pos, uint32_t *root_pos)
{
    CSFSNPRB_NODE *node;
    CSFSNPRB_NODE *right;

    uint32_t  right_pos;

    node  = CSFSNPRB_POOL_NODE(pool, node_pos);

    right_pos = CSFSNPRB_NODE_RIGHT_POS(node);
    right = CSFSNPRB_POOL_NODE(pool, right_pos);

    if(CSFSNPRB_ERR_POS != (CSFSNPRB_NODE_RIGHT_POS(node) = CSFSNPRB_NODE_LEFT_POS(right)))
    {
        CSFSNPRB_NODE *left;
        left = CSFSNPRB_POOL_NODE(pool, CSFSNPRB_NODE_LEFT_POS(right));
        CSFSNPRB_NODE_PARENT_POS(left) = node_pos;
    }
    CSFSNPRB_NODE_LEFT_POS(right) = node_pos;

    if(CSFSNPRB_ERR_POS != (CSFSNPRB_NODE_PARENT_POS(right) = CSFSNPRB_NODE_PARENT_POS(node)))
    {
        CSFSNPRB_NODE *parent;
        parent = CSFSNPRB_POOL_NODE(pool, CSFSNPRB_NODE_PARENT_POS(node));
     
        if (node_pos == CSFSNPRB_NODE_LEFT_POS(parent))
        {
            CSFSNPRB_NODE_LEFT_POS(parent) = right_pos;
        }
        else
        {
            CSFSNPRB_NODE_RIGHT_POS(parent) = right_pos;
        }
    }
    else
    {
        (*root_pos) = right_pos;
    }
    CSFSNPRB_NODE_PARENT_POS(node) = right_pos;
    return;
}

static void __csfsnprb_tree_rotate_right(CSFSNPRB_POOL *pool, const uint32_t node_pos, uint32_t *root_pos)
{
    CSFSNPRB_NODE *node;
    CSFSNPRB_NODE *left;
    uint32_t  left_pos;

    node  = CSFSNPRB_POOL_NODE(pool, node_pos);

    left_pos = CSFSNPRB_NODE_LEFT_POS(node);
    left = CSFSNPRB_POOL_NODE(pool, left_pos);

    if (CSFSNPRB_ERR_POS != (CSFSNPRB_NODE_LEFT_POS(node) = CSFSNPRB_NODE_RIGHT_POS(left)))
    {
        CSFSNPRB_NODE *right;
        right = CSFSNPRB_POOL_NODE(pool, CSFSNPRB_NODE_RIGHT_POS(left));
        CSFSNPRB_NODE_PARENT_POS(right) = node_pos;
    }
    CSFSNPRB_NODE_RIGHT_POS(left) = node_pos;

    if (CSFSNPRB_ERR_POS != (CSFSNPRB_NODE_PARENT_POS(left) = CSFSNPRB_NODE_PARENT_POS(node)))
    {
        CSFSNPRB_NODE *parent;
        parent = CSFSNPRB_POOL_NODE(pool, CSFSNPRB_NODE_PARENT_POS(node));
 
        if (node_pos == CSFSNPRB_NODE_RIGHT_POS(parent))
        {
            CSFSNPRB_NODE_RIGHT_POS(parent) = left_pos;
        }
        else
        {
            CSFSNPRB_NODE_LEFT_POS(parent) = left_pos;
        }
    }
    else
    {
        (*root_pos) = left_pos;
    }
    CSFSNPRB_NODE_PARENT_POS(node) = left_pos;
    return;
}

static void __csfsnprb_tree_insert_color(CSFSNPRB_POOL *pool, const uint32_t node_pos, uint32_t *root_pos)
{
    CSFSNPRB_NODE *node;
    CSFSNPRB_NODE *root;
    CSFSNPRB_NODE *parent; 
 
    uint32_t  node_pos_t;

    node_pos_t = node_pos;
    node  = CSFSNPRB_POOL_NODE(pool, node_pos_t);

    while (NULL_PTR != (parent = CSFSNPRB_POOL_NODE(pool, CSFSNPRB_NODE_PARENT_POS(node))) /*parent is valid*/
         && CSFSNPRB_RED == CSFSNPRB_NODE_COLOR(parent))
    {
        uint32_t  parent_pos;
        uint32_t  gparent_pos;
        CSFSNPRB_NODE *gparent;

        parent_pos = CSFSNPRB_NODE_PARENT_POS(node);

        gparent_pos = CSFSNPRB_NODE_PARENT_POS(parent);
        ASSERT(CSFSNPRB_ERR_POS != gparent_pos);
        gparent = CSFSNPRB_POOL_NODE(pool, gparent_pos);

        if (parent_pos == CSFSNPRB_NODE_LEFT_POS(gparent))
        {
            {
                CSFSNPRB_NODE *uncle;
                if (NULL_PTR != (uncle = CSFSNPRB_POOL_NODE(pool, CSFSNPRB_NODE_RIGHT_POS(gparent))) /*uncle is valid*/
                   && CSFSNPRB_RED == CSFSNPRB_NODE_COLOR(uncle))
                {
                    CSFSNPRB_NODE_COLOR(uncle)   = CSFSNPRB_BLACK;
                    CSFSNPRB_NODE_COLOR(parent)  = CSFSNPRB_BLACK;
                    CSFSNPRB_NODE_COLOR(gparent) = CSFSNPRB_RED;
                 
                    node = gparent;
                    node_pos_t = gparent_pos;
                    continue;
                }
            }

            if (CSFSNPRB_NODE_RIGHT_POS(parent) == node_pos_t)
            {
                __csfsnprb_tree_rotate_left(pool, parent_pos, root_pos);
                XCHG(CSFSNPRB_NODE *, parent, node);
                XCHG(uint32_t, parent_pos, node_pos_t);
            }

            CSFSNPRB_NODE_COLOR(parent)  = CSFSNPRB_BLACK;
            CSFSNPRB_NODE_COLOR(gparent) = CSFSNPRB_RED;
            __csfsnprb_tree_rotate_right(pool, gparent_pos, root_pos);
         }
         else
         {     
            {
                CSFSNPRB_NODE *uncle;
                if (NULL_PTR != (uncle = CSFSNPRB_POOL_NODE(pool, CSFSNPRB_NODE_LEFT_POS(gparent))) /*uncle is valid*/
                    && CSFSNPRB_RED == CSFSNPRB_NODE_COLOR(uncle))
                {
                    CSFSNPRB_NODE_COLOR(uncle)   = CSFSNPRB_BLACK;
                    CSFSNPRB_NODE_COLOR(parent)  = CSFSNPRB_BLACK;
                    CSFSNPRB_NODE_COLOR(gparent) = CSFSNPRB_RED;
                 
                    node = gparent;
                    node_pos_t = gparent_pos;
                    continue;
                }
            }

            if (CSFSNPRB_NODE_LEFT_POS(parent) == node_pos_t)
            {
                __csfsnprb_tree_rotate_right(pool, parent_pos, root_pos);
                XCHG(CSFSNPRB_NODE *, parent, node);
                XCHG(uint32_t, parent_pos, node_pos_t);
            }

            CSFSNPRB_NODE_COLOR(parent)  = CSFSNPRB_BLACK;
            CSFSNPRB_NODE_COLOR(gparent) = CSFSNPRB_RED;
            __csfsnprb_tree_rotate_left(pool, gparent_pos, root_pos);
        }
    }

    root = CSFSNPRB_POOL_NODE(pool, *root_pos);
    CSFSNPRB_NODE_COLOR(root) = CSFSNPRB_BLACK;
    return;
}

static void __csfsnprb_tree_erase_color(CSFSNPRB_POOL *pool, const uint32_t node_pos, const uint32_t parent_pos, uint32_t *root_pos)
{ 
    CSFSNPRB_NODE *node; 
    uint32_t  node_pos_t;
    uint32_t  parent_pos_t;

    node_pos_t   = node_pos;
    parent_pos_t = parent_pos;

    while ((NULL_PTR == (node = CSFSNPRB_POOL_NODE(pool, node_pos_t)) || CSFSNPRB_BLACK == CSFSNPRB_NODE_COLOR(node)) && node_pos_t != (*root_pos))
    {
        CSFSNPRB_NODE *parent;

        parent = CSFSNPRB_POOL_NODE(pool, parent_pos_t);
     
        if (CSFSNPRB_NODE_LEFT_POS(parent) == node_pos_t)
        {
            CSFSNPRB_NODE *other;
            CSFSNPRB_NODE *o_left;
            CSFSNPRB_NODE *o_right;
            uint32_t  other_pos;
     
            other_pos = CSFSNPRB_NODE_RIGHT_POS(parent);
            other = CSFSNPRB_POOL_NODE(pool, other_pos);
         
            if (CSFSNPRB_RED == CSFSNPRB_NODE_COLOR(other))
            {
                CSFSNPRB_NODE_COLOR(other)  = CSFSNPRB_BLACK;
                CSFSNPRB_NODE_COLOR(parent) = CSFSNPRB_RED;
             
                __csfsnprb_tree_rotate_left(pool, parent_pos_t, root_pos);

                other_pos = CSFSNPRB_NODE_RIGHT_POS(parent);
                other = CSFSNPRB_POOL_NODE(pool, other_pos);
            }

            o_left = CSFSNPRB_POOL_NODE(pool, CSFSNPRB_NODE_LEFT_POS(other));
            o_right = CSFSNPRB_POOL_NODE(pool, CSFSNPRB_NODE_RIGHT_POS(other));

            if((NULL_PTR == o_left || CSFSNPRB_BLACK == CSFSNPRB_NODE_COLOR(o_left))
            && (NULL_PTR == o_right || CSFSNPRB_BLACK == CSFSNPRB_NODE_COLOR(o_right)))
            {
                CSFSNPRB_NODE_COLOR(other) = CSFSNPRB_RED;
             
                node_pos_t = parent_pos_t;
                node = CSFSNPRB_POOL_NODE(pool, node_pos_t);
             
                parent_pos_t = CSFSNPRB_NODE_PARENT_POS(node);
                parent = CSFSNPRB_POOL_NODE(pool, parent_pos_t);
            }
            else
            {
                if (NULL_PTR == o_right || CSFSNPRB_BLACK == CSFSNPRB_NODE_COLOR(o_right))
                {
                    if (NULL_PTR != o_left)
                    {
                        CSFSNPRB_NODE_COLOR(o_left) = CSFSNPRB_BLACK;
                    }
                    CSFSNPRB_NODE_COLOR(other) = CSFSNPRB_RED;
                 
                    __csfsnprb_tree_rotate_right(pool, other_pos, root_pos);
                 
                    other_pos = CSFSNPRB_NODE_RIGHT_POS(parent);
                    other = CSFSNPRB_POOL_NODE(pool, other_pos);
                    /*note: other was changed here*/
                }
             
                CSFSNPRB_NODE_COLOR(other) = CSFSNPRB_NODE_COLOR(parent);
                CSFSNPRB_NODE_COLOR(parent) = CSFSNPRB_BLACK;

                /*due to other may be changed before, have to get o_right again here*/
                o_right = CSFSNPRB_POOL_NODE(pool, CSFSNPRB_NODE_RIGHT_POS(other));
                if (NULL_PTR != o_right)
                {
                    CSFSNPRB_NODE_COLOR(o_right) = CSFSNPRB_BLACK;
                }
             
                __csfsnprb_tree_rotate_left(pool, parent_pos_t, root_pos);
                node_pos_t = (*root_pos);
                break;
            }
        }
        else
        {
            CSFSNPRB_NODE *other;
            CSFSNPRB_NODE *o_left;
            CSFSNPRB_NODE *o_right;
            uint32_t  other_pos;
         
            other_pos = CSFSNPRB_NODE_LEFT_POS(parent);
            other = CSFSNPRB_POOL_NODE(pool, other_pos);
         
            if (CSFSNPRB_RED == CSFSNPRB_NODE_COLOR(other))
            {
                CSFSNPRB_NODE_COLOR(other) = CSFSNPRB_BLACK;
                CSFSNPRB_NODE_COLOR(parent) = CSFSNPRB_RED;
             
                __csfsnprb_tree_rotate_right(pool, parent_pos_t, root_pos);
             
                other_pos = CSFSNPRB_NODE_LEFT_POS(parent);
                other = CSFSNPRB_POOL_NODE(pool, other_pos);
            }

            o_left = CSFSNPRB_POOL_NODE(pool, CSFSNPRB_NODE_LEFT_POS(other));
            o_right = CSFSNPRB_POOL_NODE(pool, CSFSNPRB_NODE_RIGHT_POS(other));
         
            if ((NULL_PTR == o_left  || CSFSNPRB_BLACK == CSFSNPRB_NODE_COLOR(o_left))
             && (NULL_PTR == o_right || CSFSNPRB_BLACK == CSFSNPRB_NODE_COLOR(o_right)))
            {
                CSFSNPRB_NODE_COLOR(other) = CSFSNPRB_RED;
             
                node_pos_t = parent_pos_t;
                node = CSFSNPRB_POOL_NODE(pool, node_pos_t);
             
                parent_pos_t = CSFSNPRB_NODE_PARENT_POS(node);
                parent = CSFSNPRB_POOL_NODE(pool, parent_pos_t);
            }
            else
            {
                if (NULL_PTR == o_left  || CSFSNPRB_BLACK == CSFSNPRB_NODE_COLOR(o_left))
                {
                    if (NULL_PTR != o_right)
                    {
                        CSFSNPRB_NODE_COLOR(o_right) = CSFSNPRB_BLACK;
                    }
                 
                    CSFSNPRB_NODE_COLOR(other) = CSFSNPRB_RED;
                 
                    __csfsnprb_tree_rotate_left(pool, other_pos, root_pos);
                 
                    other_pos = CSFSNPRB_NODE_LEFT_POS(parent);
                    other = CSFSNPRB_POOL_NODE(pool, other_pos);
                    /*note: other was changed here*/
                }
             
                CSFSNPRB_NODE_COLOR(other) = CSFSNPRB_NODE_COLOR(parent);
                CSFSNPRB_NODE_COLOR(parent) = CSFSNPRB_BLACK;

                /*due to other may be changed before, have to get o_left again here*/
                o_left = CSFSNPRB_POOL_NODE(pool, CSFSNPRB_NODE_LEFT_POS(other));
                if (NULL_PTR != o_left)
                {
                    CSFSNPRB_NODE_COLOR(o_left) = CSFSNPRB_BLACK;
                }
                __csfsnprb_tree_rotate_right(pool, parent_pos_t, root_pos);
                node_pos_t = (*root_pos);
                break;
            }
        }
    }

    node = CSFSNPRB_POOL_NODE(pool, node_pos_t);
    if (NULL_PTR != node)
    {
        CSFSNPRB_NODE_COLOR(node) = CSFSNPRB_BLACK;
    }
    return;
}

/*note: erase from tree but not recycle to free nodes pool*/
EC_BOOL csfsnprb_tree_erase(CSFSNPRB_POOL *pool, const uint32_t node_pos, uint32_t *root_pos)
{
    CSFSNPRB_NODE *node;

    uint32_t node_pos_t;
    uint32_t child_pos;
    uint32_t parent_pos;
    uint32_t color;

    node_pos_t = node_pos;
    node = CSFSNPRB_POOL_NODE(pool, node_pos_t);

    ASSERT(NULL_PTR != node);
    ASSERT(CSFSNPRB_NODE_IS_USED(node));

    if (CSFSNPRB_ERR_POS == CSFSNPRB_NODE_LEFT_POS(node))
    {
        child_pos = CSFSNPRB_NODE_RIGHT_POS(node);
    }
    else if (CSFSNPRB_ERR_POS == CSFSNPRB_NODE_RIGHT_POS(node))
    {
        child_pos = CSFSNPRB_NODE_LEFT_POS(node);
    }
    else
    {
        CSFSNPRB_NODE *old;
     
        uint32_t old_pos;
        uint32_t left_pos;

        old_pos = node_pos_t;
     
        node_pos_t = CSFSNPRB_NODE_RIGHT_POS(node);
        node = CSFSNPRB_POOL_NODE(pool, node_pos_t);
     
        while (CSFSNPRB_ERR_POS != (left_pos = CSFSNPRB_NODE_LEFT_POS(node)))
        {
            node_pos_t = left_pos;
            node = CSFSNPRB_POOL_NODE(pool, node_pos_t);
        }
     
        child_pos  = CSFSNPRB_NODE_RIGHT_POS(node);
        parent_pos = CSFSNPRB_NODE_PARENT_POS(node);
        color      = CSFSNPRB_NODE_COLOR(node);

        if (CSFSNPRB_ERR_POS != child_pos)
        {
            CSFSNPRB_NODE *child;
            child = CSFSNPRB_POOL_NODE(pool, child_pos);
            CSFSNPRB_NODE_PARENT_POS(child) = parent_pos;
        }
     
        if (CSFSNPRB_ERR_POS != parent_pos)
        {
            CSFSNPRB_NODE *parent;
         
            parent = CSFSNPRB_POOL_NODE(pool, parent_pos);
            if (CSFSNPRB_NODE_LEFT_POS(parent) == node_pos_t)
            {
                CSFSNPRB_NODE_LEFT_POS(parent) = child_pos;
            }
            else
            {
                CSFSNPRB_NODE_RIGHT_POS(parent) = child_pos;
            }
        }
        else
        {
            (*root_pos) = child_pos;
        }

        if (CSFSNPRB_NODE_PARENT_POS(node) == old_pos)
        {
            parent_pos = node_pos_t;
        }

        old  = CSFSNPRB_POOL_NODE(pool, old_pos);
     
        CSFSNPRB_NODE_PARENT_POS(node) = CSFSNPRB_NODE_PARENT_POS(old);
        CSFSNPRB_NODE_COLOR(node)      = CSFSNPRB_NODE_COLOR(old);
        CSFSNPRB_NODE_RIGHT_POS(node)  = CSFSNPRB_NODE_RIGHT_POS(old);
        CSFSNPRB_NODE_LEFT_POS(node)   = CSFSNPRB_NODE_LEFT_POS(old);

        if (CSFSNPRB_ERR_POS != CSFSNPRB_NODE_PARENT_POS(old))
        {
            CSFSNPRB_NODE *old_parent;
            old_parent = CSFSNPRB_POOL_NODE(pool, CSFSNPRB_NODE_PARENT_POS(old));
         
            if (CSFSNPRB_NODE_LEFT_POS(old_parent) == old_pos)
            {
                CSFSNPRB_NODE_LEFT_POS(old_parent) = node_pos_t;
            }
            else
            {
                CSFSNPRB_NODE_RIGHT_POS(old_parent) = node_pos_t;
            }
        }
        else
        {
            (*root_pos) = node_pos_t;
        }

        {
            CSFSNPRB_NODE *old_left;

            old_left = CSFSNPRB_POOL_NODE(pool, CSFSNPRB_NODE_LEFT_POS(old));
            CSFSNPRB_NODE_PARENT_POS(old_left) = node_pos_t;
        }     

        if (CSFSNPRB_ERR_POS != CSFSNPRB_NODE_RIGHT_POS(old))
        {
            CSFSNPRB_NODE *old_right;
            old_right = CSFSNPRB_POOL_NODE(pool, CSFSNPRB_NODE_RIGHT_POS(old));
            CSFSNPRB_NODE_PARENT_POS(old_right) = node_pos_t;
        }
        goto color;
    }

    parent_pos = CSFSNPRB_NODE_PARENT_POS(node);
    color = CSFSNPRB_NODE_COLOR(node);

    if (CSFSNPRB_ERR_POS != child_pos)
    {
        CSFSNPRB_NODE *child;
        child = CSFSNPRB_POOL_NODE(pool, child_pos); 
        CSFSNPRB_NODE_PARENT_POS(child) = parent_pos;
    }
 
    if (CSFSNPRB_ERR_POS != parent_pos)
    {
        CSFSNPRB_NODE *parent;
     
        parent = CSFSNPRB_POOL_NODE(pool, parent_pos); 
        if (CSFSNPRB_NODE_LEFT_POS(parent) == node_pos_t)
        {
            CSFSNPRB_NODE_LEFT_POS(parent) = child_pos;
        }
        else
        {
            CSFSNPRB_NODE_RIGHT_POS(parent) = child_pos;
        }
    }
    else
    {
        (*root_pos) = child_pos;
    }

 color:
    if (CSFSNPRB_BLACK == color)
    {
        __csfsnprb_tree_erase_color(pool, child_pos, parent_pos, root_pos);
    }
    return (EC_TRUE);
}

static uint32_t __csfsnprb_tree_count_node_num(const CSFSNPRB_POOL *pool, const uint32_t node_pos)
{
    const CSFSNPRB_NODE *node;

    if(CSFSNPRB_ERR_POS == node_pos)
    {
        return ((uint32_t)0);
    }

    node = CSFSNPRB_POOL_NODE(pool, node_pos); 

    return (uint32_t)(1 + __csfsnprb_tree_count_node_num(pool, CSFSNPRB_NODE_LEFT_POS(node)) + __csfsnprb_tree_count_node_num(pool, CSFSNPRB_NODE_RIGHT_POS(node)));
}

uint32_t csfsnprb_tree_count_node_num(const CSFSNPRB_POOL *pool, const uint32_t root_pos)
{
    return __csfsnprb_tree_count_node_num(pool, root_pos);
}

uint32_t csfsnprb_tree_node_max_num(const CSFSNPRB_POOL *pool)
{
    return CSFSNPRB_POOL_NODE_MAX_NUM(pool);
}

uint32_t csfsnprb_tree_node_used_num(const CSFSNPRB_POOL *pool)
{
    return CSFSNPRB_POOL_NODE_USED_NUM(pool);
}

uint32_t csfsnprb_tree_node_sizeof(const CSFSNPRB_POOL *pool)
{
    return CSFSNPRB_POOL_NODE_SIZEOF(pool);
}

/*
 * This function returns the first node_pos (in sort order) of the tree.
 */
uint32_t csfsnprb_tree_first_node(const CSFSNPRB_POOL *pool, const uint32_t root_pos)
{
    uint32_t  node_pos;
    const CSFSNPRB_NODE *node;

    node_pos = root_pos;
    if (CSFSNPRB_ERR_POS == node_pos)
    {
        return (CSFSNPRB_ERR_POS);
    }

    node = CSFSNPRB_POOL_NODE(pool, node_pos);
 
    while (CSFSNPRB_ERR_POS != CSFSNPRB_NODE_LEFT_POS(node))
    {
        node_pos = CSFSNPRB_NODE_LEFT_POS(node);
        node = CSFSNPRB_POOL_NODE(pool, node_pos);
    }
    return (node_pos);
}

uint32_t csfsnprb_tree_last_node(const CSFSNPRB_POOL *pool, const uint32_t root_pos)
{
    uint32_t  node_pos;
    const CSFSNPRB_NODE *node;

    node_pos = root_pos;
    if (CSFSNPRB_ERR_POS == node_pos)
    {
        return (CSFSNPRB_ERR_POS);
    }
 
    node = CSFSNPRB_POOL_NODE(pool, node_pos);
 
    while (CSFSNPRB_ERR_POS != CSFSNPRB_NODE_RIGHT_POS(node))
    {
        node_pos = CSFSNPRB_NODE_RIGHT_POS(node);
        node = CSFSNPRB_POOL_NODE(pool, node_pos);
    }
 
    return (node_pos);
}

uint32_t csfsnprb_tree_next_node(const CSFSNPRB_POOL *pool, const uint32_t node_pos)
{
    uint32_t node_pos_t;
    const CSFSNPRB_NODE *node;
    const CSFSNPRB_NODE *parent;

    node_pos_t = node_pos;
    node = CSFSNPRB_POOL_NODE(pool, node_pos_t);
    /* If we have a right-hand child, go down and then left as far
       as we can. */
    if (CSFSNPRB_ERR_POS != CSFSNPRB_NODE_RIGHT_POS(node))
    {
        node_pos_t = CSFSNPRB_NODE_RIGHT_POS(node);
        node = CSFSNPRB_POOL_NODE(pool, node_pos_t);
        while (CSFSNPRB_ERR_POS != CSFSNPRB_NODE_LEFT_POS(node))
        {
            node_pos_t = CSFSNPRB_NODE_LEFT_POS(node);
            node = CSFSNPRB_POOL_NODE(pool, node_pos_t);
        }
        return (node_pos_t);
    }

    /* No right-hand children.  Everything down and left is
       smaller than us, so any 'next' node_pos_t must be in the general
       direction of our parent. Go up the tree; any time the
       ancestor is a right-hand child of its parent, keep going
       up. First time it's a left-hand child of its parent, said
       parent is our 'next' node_pos_t. */
    while (NULL_PTR != (parent = CSFSNPRB_POOL_NODE(pool, CSFSNPRB_NODE_PARENT_POS(node))) && node_pos_t == CSFSNPRB_NODE_RIGHT_POS(parent))
    {
        node_pos_t = CSFSNPRB_NODE_PARENT_POS(node);
        node = parent;
    }
 
    return (CSFSNPRB_NODE_PARENT_POS(node));
}

uint32_t csfsnprb_tree_prev_node(const CSFSNPRB_POOL *pool, const uint32_t node_pos)
{
    uint32_t node_pos_t;
    const CSFSNPRB_NODE *node;
    const CSFSNPRB_NODE *parent;

    node_pos_t = node_pos;
    node = CSFSNPRB_POOL_NODE(pool, node_pos_t);
 
    /* If we have a left-hand child, go down and then right as far
       as we can. */
    if (CSFSNPRB_ERR_POS != CSFSNPRB_NODE_LEFT_POS(node))
    {
        node_pos_t = CSFSNPRB_NODE_LEFT_POS(node);
        node = CSFSNPRB_POOL_NODE(pool, node_pos_t);
        while (CSFSNPRB_ERR_POS != CSFSNPRB_NODE_RIGHT_POS(node))
        {
            node_pos_t = CSFSNPRB_NODE_RIGHT_POS(node);
            node = CSFSNPRB_POOL_NODE(pool, node_pos_t);
        }
        return (node_pos_t);
    }

    /* No left-hand children. Go up till we find an ancestor which
       is a right-hand child of its parent */
    while (NULL_PTR != (parent = CSFSNPRB_POOL_NODE(pool, CSFSNPRB_NODE_PARENT_POS(node))) && node_pos_t == CSFSNPRB_NODE_LEFT_POS(parent))
    {
        node_pos_t = CSFSNPRB_NODE_PARENT_POS(node);
        node = parent;
    }

    return (CSFSNPRB_NODE_PARENT_POS(node));
}

/*victim_pos should be free*/
void csfsnprb_tree_replace_node(CSFSNPRB_POOL *pool, const uint32_t victim_pos, const uint32_t new_pos, uint32_t *root_pos)
{
    CSFSNPRB_NODE *victim; 

    victim = CSFSNPRB_POOL_NODE(pool, victim_pos); 

    /* Set the surrounding nodes to point to the replacement */
    if (CSFSNPRB_ERR_POS != CSFSNPRB_NODE_PARENT_POS(victim))
    {
        CSFSNPRB_NODE *parent;
        parent = CSFSNPRB_POOL_NODE(pool, CSFSNPRB_NODE_PARENT_POS(victim));
     
        if (victim_pos == CSFSNPRB_NODE_LEFT_POS(parent))
        {
            CSFSNPRB_NODE_LEFT_POS(parent) = new_pos;
        }
        else
        {
            CSFSNPRB_NODE_RIGHT_POS(parent) = new_pos;
        }
    }
    else
    {
        (*root_pos) = new_pos;
    }
 
    if (CSFSNPRB_ERR_POS != CSFSNPRB_NODE_LEFT_POS(victim))
    {
        CSFSNPRB_NODE *left;
        left = CSFSNPRB_POOL_NODE(pool, CSFSNPRB_NODE_LEFT_POS(victim));
        CSFSNPRB_NODE_PARENT_POS(left) = new_pos;
    }
    if (CSFSNPRB_ERR_POS != CSFSNPRB_NODE_RIGHT_POS(victim))
    {
        CSFSNPRB_NODE *right;
        right = CSFSNPRB_POOL_NODE(pool, CSFSNPRB_NODE_RIGHT_POS(victim));
        CSFSNPRB_NODE_PARENT_POS(right) = new_pos;
    }

    return;
}

/**
*
*   note:only for csfsnp item!
*   return -1 if node < (data, key)
*   return  1 if node > (data, key)
*   return  0 if node == (data, key)
*
**/
static int __csfsnprb_node_data_cmp(const CSFSNPRB_NODE *node, const uint32_t data, const uint32_t klen, const uint8_t *key)
{
    const CSFSNP_ITEM *item;
 
    if (CSFSNPRB_NODE_DATA(node) < data)
    {
        return (-1);
    }
 
    if (CSFSNPRB_NODE_DATA(node) > data)
    {
        return (1);
    }

    item = (const CSFSNP_ITEM *)CSFSNP_RB_NODE_ITEM(node);
    if(CSFSNP_ITEM_KLEN(item) < klen)
    {
        return (-1);
    }

    if(CSFSNP_ITEM_KLEN(item) > klen)
    {
        return (1);
    }

    return BCMP(CSFSNP_ITEM_KEY(item), key, klen);
}

/*return the searched pos*/
uint32_t csfsnprb_tree_search_data(const CSFSNPRB_POOL *pool, const uint32_t root_pos, const uint32_t data, const uint32_t klen, const uint8_t *key)
{
    uint32_t node_pos;

    node_pos = root_pos;
 
    while (CSFSNPRB_ERR_POS != node_pos)
    {
        const CSFSNPRB_NODE *node;
        int cmp_ret;
     
        node = CSFSNPRB_POOL_NODE(pool, node_pos);     
        cmp_ret = __csfsnprb_node_data_cmp(node, data, klen, key);
     
        if (0 < cmp_ret)/*node > (data, key)*/
        {
            node_pos = CSFSNPRB_NODE_LEFT_POS(node);
        }
        else if (0 > cmp_ret)/*node < (data, key)*/
        {
            node_pos = CSFSNPRB_NODE_RIGHT_POS(node);
        }
        else /*node == (data, key)*/
        {
            return (node_pos);
        }
    }

    return (CSFSNPRB_ERR_POS);
}

/*if found duplicate node, return EC_FALSE, otherwise return EC_TRUE*/
EC_BOOL csfsnprb_tree_insert_data(CSFSNPRB_POOL *pool, uint32_t *root_pos, const uint32_t data, const uint32_t klen, const uint8_t *key, uint32_t *insert_pos)
{
    uint32_t  node_pos_t;
    uint32_t  new_pos_t;
    uint32_t  parent_pos_t;
    uint32_t  flag; /*0: on left subtree, 1: on right subtree*/

    node_pos_t   = (*root_pos);
    parent_pos_t = CSFSNPRB_ERR_POS;
    flag         = ~(uint32_t)0;

    while (CSFSNPRB_ERR_POS != node_pos_t)
    {
        CSFSNPRB_NODE *node;
        int cmp_ret;
     
        node = CSFSNPRB_POOL_NODE(pool, node_pos_t);
        cmp_ret = __csfsnprb_node_data_cmp(node, data, klen, key);

        parent_pos_t = node_pos_t;
     
        if (0 < cmp_ret)/*node > (data, key)*/
        {
            node_pos_t = CSFSNPRB_NODE_LEFT_POS(node);
            flag = 0;
        }
        else if (0 > cmp_ret)/*node < (data, key)*/
        {
            node_pos_t = CSFSNPRB_NODE_RIGHT_POS(node);
            flag = 1;
        }
        else/*node == (data, key)*/
        {
            (*insert_pos) = node_pos_t;
            return (EC_FALSE);/*found duplicate*/
        }
    }


    /*not found data in the rbtree*/
    new_pos_t = csfsnprb_node_new(pool);
    if(CSFSNPRB_ERR_POS == new_pos_t)
    {
        (*insert_pos) = CSFSNPRB_ERR_POS;
        return (EC_FALSE); 
    }
    else
    {
        CSFSNPRB_NODE *node;     

        node  = CSFSNPRB_POOL_NODE(pool, new_pos_t);
        CSFSNPRB_NODE_DATA(node)       = data;
     
        CSFSNPRB_NODE_PARENT_POS(node) = parent_pos_t;
        CSFSNPRB_NODE_COLOR(node)      = CSFSNPRB_RED;
        CSFSNPRB_NODE_LEFT_POS(node)   = CSFSNPRB_ERR_POS;
        CSFSNPRB_NODE_RIGHT_POS(node)  = CSFSNPRB_ERR_POS;     
 
        if(CSFSNPRB_ERR_POS == (*root_pos))
        {
            (*root_pos) = new_pos_t;
        }
        else
        {
            CSFSNPRB_NODE *parent;
            parent  = CSFSNPRB_POOL_NODE(pool, parent_pos_t);

            if(0 == flag)/*on left subtree*/
            {
                CSFSNPRB_NODE_LEFT_POS(parent) = new_pos_t;
            }
            else
            {
                CSFSNPRB_NODE_RIGHT_POS(parent) = new_pos_t;
            }
        }
        __csfsnprb_tree_insert_color(pool, new_pos_t, root_pos);
    }

    (*insert_pos) = new_pos_t;
    return (EC_TRUE); /*it is new node*/
}

EC_BOOL csfsnprb_tree_delete_data(CSFSNPRB_POOL *pool, uint32_t *root_pos, const uint32_t data, const uint32_t klen, const uint8_t *key, uint32_t *delete_pos)
{
    uint32_t node_pos;

    node_pos = csfsnprb_tree_search_data(pool, *root_pos, data, klen, key);
    if(CSFSNPRB_ERR_POS == node_pos)
    {
        return (EC_FALSE);
    }

    csfsnprb_tree_erase(pool, node_pos, root_pos);
    csfsnprb_node_free(pool, node_pos);

    (*delete_pos) = node_pos;
    return (EC_TRUE);
}


EC_BOOL csfsnprb_tree_delete(CSFSNPRB_POOL *pool, uint32_t *root_pos, const uint32_t node_pos)
{
    csfsnprb_tree_erase(pool, node_pos, root_pos);
    csfsnprb_node_free(pool, node_pos);
    return (EC_TRUE);
}


/*postorder: left -> right -> root*/
static void __csfsnprb_tree_free(CSFSNPRB_POOL *pool, const uint32_t node_pos)
{
    CSFSNPRB_NODE *node;

    if(CSFSNPRB_ERR_POS == node_pos)
    {
        return;
    }
 
    node  = CSFSNPRB_POOL_NODE(pool, node_pos); 
    if(CSFSNPRB_ERR_POS != CSFSNPRB_NODE_LEFT_POS(node))
    {
        __csfsnprb_tree_free(pool, CSFSNPRB_NODE_LEFT_POS(node));
    } 

    if(CSFSNPRB_ERR_POS != CSFSNPRB_NODE_RIGHT_POS(node))
    {
        __csfsnprb_tree_free(pool, CSFSNPRB_NODE_RIGHT_POS(node));
    } 

    csfsnprb_node_free(pool, node_pos);
 
    return;
}
void csfsnprb_tree_free(CSFSNPRB_POOL *pool, const uint32_t root_pos)
{
    __csfsnprb_tree_free(pool, root_pos);
    return;
}

EC_BOOL csfsnprb_pool_init(CSFSNPRB_POOL *pool, const uint32_t node_max_num, const uint32_t node_sizeof)
{
    uint32_t node_pos;

    if(CSFSNPRB_POOL_MAX_SIZE < node_max_num)
    {
        dbg_log(SEC_0172_CSFSNPRB, 0)(LOGSTDERR, "error:csfsnprb_pool_init: node_max_num %u overflow!\n", node_max_num);
        return (EC_FALSE);
    }

    CSFSNPRB_POOL_NODE_MAX_NUM(pool)  = node_max_num;
    CSFSNPRB_POOL_NODE_USED_NUM(pool) = 0;
    CSFSNPRB_POOL_NODE_SIZEOF(pool)   = node_sizeof;

    for(node_pos = 0; node_pos < node_max_num; node_pos ++)
    {
        csfsnprb_node_init(pool, node_pos);
        csfsnprb_node_set_next(pool, node_pos, node_pos + 1);

        if(0 == ((node_pos + 1) % 100000))
        {
            dbg_log(SEC_0172_CSFSNPRB, 0)(LOGSTDOUT, "info:csfsnprb_pool_init: init node %u - %u of max %u done\n",
                               node_pos - 99999, node_pos, node_max_num);
        }       
    }
    dbg_log(SEC_0172_CSFSNPRB, 0)(LOGSTDOUT, "info:csfsnprb_pool_init: init %u nodes done\n", node_max_num);
    csfsnprb_node_set_next(pool, node_max_num - 1, CSFSNPRB_ERR_POS);/*overwrite the last one*/
 
    CSFSNPRB_POOL_FREE_HEAD(pool) = 0;/*the free nodes head*/
    return (EC_TRUE);
}

void csfsnprb_pool_clean(CSFSNPRB_POOL *pool)
{
    CSFSNPRB_POOL_NODE_MAX_NUM(pool)  = 0;
    CSFSNPRB_POOL_FREE_HEAD(pool)     = CSFSNPRB_ERR_POS;
    return;
}

void csfsnprb_pool_print(LOG *log, const CSFSNPRB_POOL *pool)
{
    uint32_t node_pos;
    uint32_t node_max_num;

    node_max_num = CSFSNPRB_POOL_NODE_MAX_NUM(pool);

    sys_log(log, "pool %lx, node_max_num %u, node_used_num %u, free_head %u, node_sizeof = %u\n",
                 pool,
                 node_max_num,
                 CSFSNPRB_POOL_NODE_USED_NUM(pool),
                 CSFSNPRB_POOL_FREE_HEAD(pool),
                 CSFSNPRB_POOL_NODE_SIZEOF(pool));

    if(0)
    {
        for(node_pos = 0; node_pos < node_max_num; node_pos ++)
        {
            if(EC_TRUE == csfsnprb_node_is_used(pool, node_pos))
            {
                csfsnprb_node_print(log, pool, node_pos);
            }
        }
    }
    return;
}


EC_BOOL csfsnprb_pool_is_empty(const CSFSNPRB_POOL *pool)
{
    if (0 == CSFSNPRB_POOL_NODE_USED_NUM(pool))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL csfsnprb_pool_is_full(const CSFSNPRB_POOL *pool)
{
    if (CSFSNPRB_POOL_NODE_MAX_NUM(pool) == CSFSNPRB_POOL_NODE_USED_NUM(pool))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

/*visit the root node first: root -> left -> right*/
void csfsnprb_preorder_print(LOG *log, const CSFSNPRB_POOL *pool, const uint32_t node_pos)
{
    const CSFSNPRB_NODE *node;

    if(CSFSNPRB_ERR_POS == node_pos)
    {
        return;
    }
 
    node  = CSFSNPRB_POOL_NODE(pool, node_pos); 
    csfsnprb_node_print(log, pool, node_pos);

    if(CSFSNPRB_ERR_POS != CSFSNPRB_NODE_LEFT_POS(node))
    {
        csfsnprb_preorder_print(log, pool, CSFSNPRB_NODE_LEFT_POS(node));
    }

    if(CSFSNPRB_ERR_POS != CSFSNPRB_NODE_RIGHT_POS(node))
    {
        csfsnprb_preorder_print(log, pool, CSFSNPRB_NODE_RIGHT_POS(node));
    } 
 
    return;
}

/*visit the left subtree, then the root node: left -> root -> right*/
void csfsnprb_inorder_print(LOG *log, const CSFSNPRB_POOL *pool, const uint32_t node_pos)
{
    const CSFSNPRB_NODE *node;

    if(CSFSNPRB_ERR_POS == node_pos)
    {
        return;
    }
 
    node  = CSFSNPRB_POOL_NODE(pool, node_pos); 
    if(CSFSNPRB_ERR_POS != CSFSNPRB_NODE_LEFT_POS(node))
    {
        csfsnprb_inorder_print(log, pool, CSFSNPRB_NODE_LEFT_POS(node));
    }

    csfsnprb_node_print(log, pool, node_pos);

    if(CSFSNPRB_ERR_POS != CSFSNPRB_NODE_RIGHT_POS(node))
    {
        csfsnprb_inorder_print(log, pool, CSFSNPRB_NODE_RIGHT_POS(node));
    } 
 
    return;
}

/*visit the root node last: left -> right -> root*/
void csfsnprb_postorder_print(LOG *log, const CSFSNPRB_POOL *pool, const uint32_t node_pos)
{
    const CSFSNPRB_NODE *node;

    if(CSFSNPRB_ERR_POS == node_pos)
    {
        return;
    }
 
    node  = CSFSNPRB_POOL_NODE(pool, node_pos); 
    if(CSFSNPRB_ERR_POS != CSFSNPRB_NODE_LEFT_POS(node))
    {
        csfsnprb_postorder_print(log, pool, CSFSNPRB_NODE_LEFT_POS(node));
    } 

    if(CSFSNPRB_ERR_POS != CSFSNPRB_NODE_RIGHT_POS(node))
    {
        csfsnprb_postorder_print(log, pool, CSFSNPRB_NODE_RIGHT_POS(node));
    } 

    csfsnprb_node_print(log, pool, node_pos);
 
    return;
}


/*visit the root node first: root -> left -> right*/
void csfsnprb_preorder_print_level(LOG *log, const CSFSNPRB_POOL *pool, const uint32_t node_pos, const uint32_t level)
{
    const CSFSNPRB_NODE *node;

    if(CSFSNPRB_ERR_POS == node_pos)
    {
        return;
    }
 
    node  = CSFSNPRB_POOL_NODE(pool, node_pos); 
    csfsnprb_node_print_level(log, pool, node_pos, level);

    if(CSFSNPRB_ERR_POS != CSFSNPRB_NODE_LEFT_POS(node))
    {
        csfsnprb_preorder_print_level(log, pool, CSFSNPRB_NODE_LEFT_POS(node), level + 1);
    }

    if(CSFSNPRB_ERR_POS != CSFSNPRB_NODE_RIGHT_POS(node))
    {
        csfsnprb_preorder_print_level(log, pool, CSFSNPRB_NODE_RIGHT_POS(node), level + 1);
    } 
 
    return;
}

EC_BOOL csfsnprb_flush_size(const CSFSNPRB_POOL *pool, UINT32 *size)
{
    (*size) += sizeof(CSFSNPRB_POOL) + CSFSNPRB_POOL_NODE_MAX_NUM(pool) * CSFSNPRB_POOL_NODE_SIZEOF(pool);
    return (EC_TRUE);
}

EC_BOOL csfsnprb_flush(const CSFSNPRB_POOL *pool, int fd, UINT32 *offset)
{
    UINT32 osize;/*write once size*/

    /*flush free_head*/
    osize = sizeof(uint32_t);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(CSFSNPRB_POOL_FREE_HEAD(pool))))
    {
        dbg_log(SEC_0172_CSFSNPRB, 0)(LOGSTDOUT, "error:csfsnprb_flush: write CSFSNPRB_POOL_FREE_HEAD at offset %u of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*flush node_max_num*/
    osize  = sizeof(uint32_t);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(CSFSNPRB_POOL_NODE_MAX_NUM(pool))))
    {
        dbg_log(SEC_0172_CSFSNPRB, 0)(LOGSTDOUT, "error:csfsnprb_flush: write CSFSNPRB_POOL_NODE_MAX_NUM at offset %u of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    } 

    /*flush node_used_num*/
    osize  = sizeof(uint32_t);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(CSFSNPRB_POOL_NODE_USED_NUM(pool))))
    {
        dbg_log(SEC_0172_CSFSNPRB, 0)(LOGSTDOUT, "error:csfsnprb_flush: write CSFSNPRB_POOL_NODE_USED_NUM at offset %u of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }  

    /*flush node_sizeof*/
    osize  = sizeof(uint32_t);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(CSFSNPRB_POOL_NODE_SIZEOF(pool))))
    {
        dbg_log(SEC_0172_CSFSNPRB, 0)(LOGSTDOUT, "error:csfsnprb_flush: write CSFSNPRB_POOL_NODE_SIZEOF at offset %u of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*flush rb_node table*/
    osize  = CSFSNPRB_POOL_NODE_MAX_NUM(pool) * CSFSNPRB_POOL_NODE_SIZEOF(pool); 
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)CSFSNPRB_POOL_NODE_TBL(pool)))
    {
        dbg_log(SEC_0172_CSFSNPRB, 0)(LOGSTDOUT, "error:csfsnprb_flush: write CSFSNPRB_POOL_NODE_TBL at offset %u of fd %d failed where CSFSNPRB_POOL_NODE_MAX_NUM is %u\n",
                            (*offset), fd, CSFSNPRB_POOL_NODE_MAX_NUM(pool));
        return (EC_FALSE);
    }
 
    return (EC_TRUE);
}

EC_BOOL csfsnprb_load(CSFSNPRB_POOL *pool, int fd, UINT32 *offset)
{
    UINT32 osize;/*read once size*/
    uint32_t node_max_num;
    uint32_t node_used_num;
    uint32_t node_sizeof;

    /*load free_head*/
    osize = sizeof(uint32_t);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(CSFSNPRB_POOL_FREE_HEAD(pool))))
    {
        dbg_log(SEC_0172_CSFSNPRB, 0)(LOGSTDOUT, "error:csfsnprb_load: load CSFSNPRB_POOL_FREE_HEAD at offset %u of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*load node_max_num*/
    osize  = sizeof(uint32_t);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(node_max_num)))
    {
        dbg_log(SEC_0172_CSFSNPRB, 0)(LOGSTDOUT, "error:csfsnprb_load: load CSFSNPRB_POOL_NODE_MAX_NUM at offset %u of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }
    CSFSNPRB_POOL_NODE_MAX_NUM(pool) = node_max_num;

    /*load node_used_num*/
    osize  = sizeof(uint32_t);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(node_used_num)))
    {
        dbg_log(SEC_0172_CSFSNPRB, 0)(LOGSTDOUT, "error:csfsnprb_load: load CSFSNPRB_POOL_NODE_USED_NUM at offset %u of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }
    CSFSNPRB_POOL_NODE_MAX_NUM(pool) = node_used_num; 

    /*load node_sizeof*/
    osize  = sizeof(uint32_t);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(node_sizeof)))
    {
        dbg_log(SEC_0172_CSFSNPRB, 0)(LOGSTDOUT, "error:csfsnprb_load: load CSFSNPRB_POOL_NODE_SIZEOF at offset %u of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }
    CSFSNPRB_POOL_NODE_SIZEOF(pool) = node_sizeof;

    /*load rb_node table*/
    osize  = CSFSNPRB_POOL_NODE_MAX_NUM(pool) * CSFSNPRB_POOL_NODE_SIZEOF(pool); 
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)CSFSNPRB_POOL_NODE_TBL(pool)))
    {
        dbg_log(SEC_0172_CSFSNPRB, 0)(LOGSTDOUT, "error:csfsnprb_load: load CSFSNPRB_POOL_NODE_TBL at offset %u of fd %d failed where CSFSNPRB_POOL_NODE_MAX_NUM is %u\n",
                            (*offset), fd, CSFSNPRB_POOL_NODE_MAX_NUM(pool));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

void csfsnprb_tree_print(LOG *log, const CSFSNPRB_POOL *pool, const uint32_t root_pos)
{
    uint32_t node_pos;

    sys_log(log, "[root = %5d]\n", root_pos);
    for(node_pos = csfsnprb_tree_first_node(pool, root_pos); CSFSNPRB_ERR_POS != node_pos; node_pos = csfsnprb_tree_next_node(pool, node_pos))
    {
        csfsnprb_node_print(log, pool, node_pos);
    }
    return;
}

/* ---- debug ---- */
EC_BOOL csfsnprb_node_debug_cmp(const CSFSNPRB_NODE *node_1st, const CSFSNPRB_NODE *node_2nd, int (*node_cmp_data)(const CSFSNPRB_NODE *, const CSFSNPRB_NODE *))
{
    if(CSFSNPRB_NODE_USED_FLAG(node_1st) != CSFSNPRB_NODE_USED_FLAG(node_2nd))
    {
        dbg_log(SEC_0172_CSFSNPRB, 0)(LOGSTDERR, "error:csfsnprb_node_debug_cmp: inconsistent CSFSNPRB_NODE_USED_FLAG: %u != %u\n",
                            CSFSNPRB_NODE_USED_FLAG(node_1st), CSFSNPRB_NODE_USED_FLAG(node_2nd));
        return (EC_FALSE);
    }
#if 0
    if(CSFSNPRB_NODE_NOT_USED == CSFSNPRB_NODE_USED_FLAG(node_1st))
    {
        return (EC_TRUE);
    }
#endif 

    if(CSFSNPRB_NODE_COLOR(node_1st) != CSFSNPRB_NODE_COLOR(node_2nd))
    {
        dbg_log(SEC_0172_CSFSNPRB, 0)(LOGSTDERR, "error:csfsnprb_node_debug_cmp: inconsistent CSFSNPRB_NODE_COLOR: %u != %u\n",
                            CSFSNPRB_NODE_COLOR(node_1st), CSFSNPRB_NODE_COLOR(node_2nd));
        return (EC_FALSE);
    }

    if(CSFSNPRB_NODE_PARENT_POS(node_1st) != CSFSNPRB_NODE_PARENT_POS(node_2nd))
    {
        dbg_log(SEC_0172_CSFSNPRB, 0)(LOGSTDERR, "error:csfsnprb_node_debug_cmp: inconsistent CSFSNPRB_NODE_PARENT_POS: %u != %u\n",
                            CSFSNPRB_NODE_PARENT_POS(node_1st), CSFSNPRB_NODE_PARENT_POS(node_2nd));
        return (EC_FALSE);
    }

    if(CSFSNPRB_NODE_RIGHT_POS(node_1st) != CSFSNPRB_NODE_RIGHT_POS(node_2nd))
    {
        dbg_log(SEC_0172_CSFSNPRB, 0)(LOGSTDERR, "error:csfsnprb_node_debug_cmp: inconsistent CSFSNPRB_NODE_RIGHT_POS: %u != %u\n",
                            CSFSNPRB_NODE_RIGHT_POS(node_1st), CSFSNPRB_NODE_RIGHT_POS(node_2nd));
        return (EC_FALSE);
    }

    if(CSFSNPRB_NODE_LEFT_POS(node_1st) != CSFSNPRB_NODE_LEFT_POS(node_2nd))
    {
        dbg_log(SEC_0172_CSFSNPRB, 0)(LOGSTDERR, "error:csfsnprb_node_debug_cmp: inconsistent CSFSNPRB_NODE_LEFT_POS: %u != %u\n",
                            CSFSNPRB_NODE_LEFT_POS(node_1st), CSFSNPRB_NODE_LEFT_POS(node_2nd));
        return (EC_FALSE);
    } 

    if(CSFSNPRB_NODE_USED == CSFSNPRB_NODE_USED_FLAG(node_1st))
    {
        if(0 != node_cmp_data(node_1st, node_2nd))
        {
            dbg_log(SEC_0172_CSFSNPRB, 0)(LOGSTDERR, "error:csfsnprb_node_debug_cmp: inconsistent data part\n");
            return (EC_FALSE);
        }
    }
    else
    {
        if(CSFSNPRB_NODE_NEXT_POS(node_1st) != CSFSNPRB_NODE_NEXT_POS(node_2nd))
        {
            dbg_log(SEC_0172_CSFSNPRB, 0)(LOGSTDERR, "error:csfsnprb_node_debug_cmp: inconsistent CSFSNPRB_NODE_NEXT_POS: %u != %u\n",
                                CSFSNPRB_NODE_NEXT_POS(node_1st), CSFSNPRB_NODE_NEXT_POS(node_2nd));
            return (EC_FALSE);
        } 
    }
    return (EC_TRUE);
}

EC_BOOL csfsnprb_debug_cmp(const CSFSNPRB_POOL *pool_1st, const CSFSNPRB_POOL *pool_2nd, int (*node_cmp_data)(const CSFSNPRB_NODE *, const CSFSNPRB_NODE *))
{
    uint32_t  node_max_num;
    uint32_t  node_pos;
 
    if(CSFSNPRB_POOL_FREE_HEAD(pool_1st) != CSFSNPRB_POOL_FREE_HEAD(pool_2nd))
    {
        dbg_log(SEC_0172_CSFSNPRB, 0)(LOGSTDERR, "error:csfsnprb_debug_cmp: inconsistent CSFSNPRB_POOL_FREE_HEAD: %u != %u\n",
                            CSFSNPRB_POOL_FREE_HEAD(pool_1st), CSFSNPRB_POOL_FREE_HEAD(pool_2nd));
        return (EC_FALSE);
    }

    if(CSFSNPRB_POOL_NODE_MAX_NUM(pool_1st) != CSFSNPRB_POOL_NODE_MAX_NUM(pool_2nd))
    {
        dbg_log(SEC_0172_CSFSNPRB, 0)(LOGSTDERR, "error:csfsnprb_debug_cmp: inconsistent CSFSNPRB_POOL_NODE_MAX_NUM: %u != %u\n",
                            CSFSNPRB_POOL_NODE_MAX_NUM(pool_1st), CSFSNPRB_POOL_NODE_MAX_NUM(pool_2nd));
        return (EC_FALSE);
    }

    if(CSFSNPRB_POOL_NODE_USED_NUM(pool_1st) != CSFSNPRB_POOL_NODE_USED_NUM(pool_2nd))
    {
        dbg_log(SEC_0172_CSFSNPRB, 0)(LOGSTDERR, "error:csfsnprb_debug_cmp: inconsistent CSFSNPRB_POOL_NODE_USED_NUM: %u != %u\n",
                            CSFSNPRB_POOL_NODE_USED_NUM(pool_1st), CSFSNPRB_POOL_NODE_USED_NUM(pool_2nd));
        return (EC_FALSE);
    } 

    if(CSFSNPRB_POOL_NODE_SIZEOF(pool_1st) != CSFSNPRB_POOL_NODE_SIZEOF(pool_2nd))
    {
        dbg_log(SEC_0172_CSFSNPRB, 0)(LOGSTDERR, "error:csfsnprb_debug_cmp: inconsistent CSFSNPRB_POOL_NODE_SIZEOF: %u != %u\n",
                            CSFSNPRB_POOL_NODE_SIZEOF(pool_1st), CSFSNPRB_POOL_NODE_SIZEOF(pool_2nd));
        return (EC_FALSE);
    }

    node_max_num = CSFSNPRB_POOL_NODE_MAX_NUM(pool_1st);
    for(node_pos = 0; node_pos < node_max_num; node_pos ++)
    {
        CSFSNPRB_NODE *node_1st;
        CSFSNPRB_NODE *node_2nd;

        node_1st = CSFSNPRB_POOL_NODE(pool_1st, node_pos);
        node_2nd = CSFSNPRB_POOL_NODE(pool_2nd, node_pos);

        if(EC_FALSE == csfsnprb_node_debug_cmp(node_1st, node_2nd, node_cmp_data))
        {
            dbg_log(SEC_0172_CSFSNPRB, 0)(LOGSTDERR, "error:csfsnprb_debug_cmp: inconsistent node at pos %u\n", node_pos);
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}


#ifdef __cplusplus
}
#endif/*__cplusplus*/
