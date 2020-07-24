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

#include "crbbase.h"

/*for safe reason, when data handler is not given, set to default null function*/
STATIC_CAST static void __crbbase_data_null_default(void *data)
{
    return;
}

/*for safe reason, when data handler is not given, set to default print function*/
STATIC_CAST static void __crbbase_data_print_default(LOG *log, const void *data)
{
    sys_log(log, "data = %u\n", data);
    return;
}

STATIC_CAST static int __crbbase_data_cmp_default(const void *data_1, const void *data_2)
{
    if(data_1 > data_2)
    {
        return (1);
    }

    if(data_1 < data_2)
    {
        return (-1);
    }

    return (0);
}

void crbbase_node_init(CRBBASE_NODE *node)
{
    CRBBASE_NODE_PARENT(node) = NULL_PTR;
    CRBBASE_NODE_RIGHT(node)  = NULL_PTR;
    CRBBASE_NODE_LEFT(node)   = NULL_PTR;
    CRBBASE_NODE_COLOR(node)  = CRBBASE_BLACK;
    CRBBASE_NODE_USED(node)   = BIT_FALSE;
    return;
}

void crbbase_node_clean(CRBBASE_NODE *node)
{
    CRBBASE_NODE_PARENT(node) = NULL_PTR;
    CRBBASE_NODE_RIGHT(node)  = NULL_PTR;
    CRBBASE_NODE_LEFT(node)   = NULL_PTR;
    CRBBASE_NODE_COLOR(node)  = CRBBASE_BLACK;
    CRBBASE_NODE_USED(node)   = BIT_FALSE;

    return;
}

EC_BOOL crbbase_node_is_empty(const CRBBASE_NODE *node)
{
    if(BIT_FALSE == CRBBASE_NODE_USED(node))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

void crbbase_node_print(LOG *log, const CRBBASE_TREE *crbbasetree, const CRBBASE_NODE *node)
{
    void *data;

    data = (void *)CRBBASE_NODE_DATA(node, CRBBASE_TREE_NODE_OFFSET(crbbasetree));

    if(do_log(SEC_0087_CRBBASE, 9))
    {
        sys_log(log, "node %p: parent = %p, left = %p, right = %p, color = %s, used %u, data = %p\n",
                           node,
                           CRBBASE_NODE_PARENT(node),
                           CRBBASE_NODE_LEFT(node),
                           CRBBASE_NODE_RIGHT(node),
                           (CRBBASE_NODE_IS_RED(node) ? "red  " : "black"),
                           CRBBASE_NODE_USED(node),
                           data
                           );
    }
    CRBBASE_TREE_DATA_PRINT(crbbasetree)(log, data);
    return;
}

void crbbase_node_print_level(LOG *log, const CRBBASE_TREE *crbbasetree, const CRBBASE_NODE *node, const uint16_t level)
{
    void *data;

    data = (void *)CRBBASE_NODE_DATA(node, CRBBASE_TREE_NODE_OFFSET(crbbasetree));

    c_ident_print(log, level);
    sys_print(log, "%p: parent = %p, left = %p, right = %p, color = %s, used %u, data = %p\n",
                       node,
                       CRBBASE_NODE_PARENT(node),
                       CRBBASE_NODE_LEFT(node),
                       CRBBASE_NODE_RIGHT(node),
                       CRBBASE_NODE_IS_RED(node)  ? "red  " : "black",
                       CRBBASE_NODE_USED(node),
                       data
                       );
    c_ident_print(log, level);
    CRBBASE_TREE_DATA_PRINT(crbbasetree)(log, data);
    return;
}


STATIC_CAST static void __crbbase_tree_rotate_left(CRBBASE_TREE *crbbasetree, CRBBASE_NODE *node)
{
    CRBBASE_NODE *right;

    right = CRBBASE_NODE_RIGHT(node);

    if(NULL_PTR != (CRBBASE_NODE_RIGHT(node) = CRBBASE_NODE_LEFT(right)))
    {
        CRBBASE_NODE *left;
        left = CRBBASE_NODE_LEFT(right);
        CRBBASE_NODE_PARENT(left) = node;
    }
    CRBBASE_NODE_LEFT(right) = node;

    if(NULL_PTR != (CRBBASE_NODE_PARENT(right) = CRBBASE_NODE_PARENT(node)))
    {
        CRBBASE_NODE *parent;
        parent = CRBBASE_NODE_PARENT(node);

        if (node == CRBBASE_NODE_LEFT(parent))
        {
            CRBBASE_NODE_LEFT(parent) = right;
        }
        else
        {
            CRBBASE_NODE_RIGHT(parent) = right;
        }
    }
    else
    {
        CRBBASE_TREE_ROOT(crbbasetree) = right;
    }
    CRBBASE_NODE_PARENT(node) = right;
    return;
}

STATIC_CAST static void __crbbase_tree_rotate_right(CRBBASE_TREE *crbbasetree, CRBBASE_NODE *node)
{
    CRBBASE_NODE *left;

    left = CRBBASE_NODE_LEFT(node);

    if (NULL_PTR != (CRBBASE_NODE_LEFT(node) = CRBBASE_NODE_RIGHT(left)))
    {
        CRBBASE_NODE *right;
        right = CRBBASE_NODE_RIGHT(left);
        CRBBASE_NODE_PARENT(right) = node;
    }
    CRBBASE_NODE_RIGHT(left) = node;

    if (NULL_PTR != (CRBBASE_NODE_PARENT(left) = CRBBASE_NODE_PARENT(node)))
    {
        CRBBASE_NODE *parent;
        parent = CRBBASE_NODE_PARENT(node);

        if (node == CRBBASE_NODE_RIGHT(parent))
        {
            CRBBASE_NODE_RIGHT(parent) = left;
        }
        else
        {
            CRBBASE_NODE_LEFT(parent) = left;
        }
    }
    else
    {
        CRBBASE_TREE_ROOT(crbbasetree) = left;
    }
    CRBBASE_NODE_PARENT(node) = left;
    return;
}

STATIC_CAST static void __crbbase_tree_insert_color(CRBBASE_TREE *crbbasetree, CRBBASE_NODE *node)
{
    CRBBASE_NODE *parent;

    while (NULL_PTR != (parent = CRBBASE_NODE_PARENT(node)) /*parent is valid*/
         && CRBBASE_RED == CRBBASE_NODE_COLOR(parent))
    {
        CRBBASE_NODE *gparent;

        parent = CRBBASE_NODE_PARENT(node);

        gparent = CRBBASE_NODE_PARENT(parent);
        ASSERT(NULL_PTR != gparent);

        if (parent == CRBBASE_NODE_LEFT(gparent))
        {
            {
                CRBBASE_NODE *uncle;
                if (NULL_PTR != (uncle = CRBBASE_NODE_RIGHT(gparent)) /*uncle is valid*/
                   && CRBBASE_RED == CRBBASE_NODE_COLOR(uncle))
                {
                    CRBBASE_NODE_COLOR(uncle)   = CRBBASE_BLACK;
                    CRBBASE_NODE_COLOR(parent)  = CRBBASE_BLACK;
                    CRBBASE_NODE_COLOR(gparent) = CRBBASE_RED;

                    node = gparent;
                    continue;
                }
            }

            if (CRBBASE_NODE_RIGHT(parent) == node)
            {
                __crbbase_tree_rotate_left(crbbasetree, parent);
                XCHG(CRBBASE_NODE *, parent, node);
            }

            CRBBASE_NODE_COLOR(parent)  = CRBBASE_BLACK;
            CRBBASE_NODE_COLOR(gparent) = CRBBASE_RED;
            __crbbase_tree_rotate_right(crbbasetree, gparent);
         }
         else
         {
            {
                CRBBASE_NODE *uncle;
                if (NULL_PTR != (uncle = CRBBASE_NODE_LEFT(gparent)) /*uncle is valid*/
                    && CRBBASE_RED == CRBBASE_NODE_COLOR(uncle))
                {
                    CRBBASE_NODE_COLOR(uncle)   = CRBBASE_BLACK;
                    CRBBASE_NODE_COLOR(parent)  = CRBBASE_BLACK;
                    CRBBASE_NODE_COLOR(gparent) = CRBBASE_RED;

                    node = gparent;
                    continue;
                }
            }

            if (CRBBASE_NODE_LEFT(parent) == node)
            {
                __crbbase_tree_rotate_right(crbbasetree, parent);
                XCHG(CRBBASE_NODE *, parent, node);
            }

            CRBBASE_NODE_COLOR(parent)  = CRBBASE_BLACK;
            CRBBASE_NODE_COLOR(gparent) = CRBBASE_RED;
            __crbbase_tree_rotate_left(crbbasetree, gparent);
        }
    }

    CRBBASE_NODE_COLOR(CRBBASE_TREE_ROOT(crbbasetree)) = CRBBASE_BLACK;
    return;
}

STATIC_CAST static void __crbbase_tree_erase_color(CRBBASE_TREE *crbbasetree, CRBBASE_NODE *node, CRBBASE_NODE *parent)
{
    while ((NULL_PTR == node || CRBBASE_BLACK == CRBBASE_NODE_COLOR(node)) && node != CRBBASE_TREE_ROOT(crbbasetree))
    {
        if (CRBBASE_NODE_LEFT(parent) == node)
        {
            CRBBASE_NODE *other;
            CRBBASE_NODE *o_left;
            CRBBASE_NODE *o_right;

            other = CRBBASE_NODE_RIGHT(parent);

            if (CRBBASE_RED == CRBBASE_NODE_COLOR(other))
            {
                CRBBASE_NODE_COLOR(other)  = CRBBASE_BLACK;
                CRBBASE_NODE_COLOR(parent) = CRBBASE_RED;

                __crbbase_tree_rotate_left(crbbasetree, parent);

                other = CRBBASE_NODE_RIGHT(parent);
            }

            o_left = CRBBASE_NODE_LEFT(other);
            o_right = CRBBASE_NODE_RIGHT(other);

            if((NULL_PTR == o_left || CRBBASE_BLACK == CRBBASE_NODE_COLOR(o_left))
            && (NULL_PTR == o_right || CRBBASE_BLACK == CRBBASE_NODE_COLOR(o_right)))
            {
                CRBBASE_NODE_COLOR(other) = CRBBASE_RED;

                node = parent;
                parent = CRBBASE_NODE_PARENT(node);
            }
            else
            {
                if (NULL_PTR == o_right || CRBBASE_BLACK == CRBBASE_NODE_COLOR(o_right))
                {
                    if (NULL_PTR != o_left)
                    {
                        CRBBASE_NODE_COLOR(o_left) = CRBBASE_BLACK;
                    }
                    CRBBASE_NODE_COLOR(other) = CRBBASE_RED;

                    __crbbase_tree_rotate_right(crbbasetree, other);

                    other = CRBBASE_NODE_RIGHT(parent);
                    /*note: other was changed here*/
                }

                CRBBASE_NODE_COLOR(other) = CRBBASE_NODE_COLOR(parent);
                CRBBASE_NODE_COLOR(parent) = CRBBASE_BLACK;

                /*due to other may be changed before, have to get o_right again here*/
                o_right = CRBBASE_NODE_RIGHT(other);
                if (NULL_PTR != o_right)
                {
                    CRBBASE_NODE_COLOR(o_right) = CRBBASE_BLACK;
                }

                __crbbase_tree_rotate_left(crbbasetree, parent);
                node = CRBBASE_TREE_ROOT(crbbasetree);
                break;
            }
        }
        else
        {
            CRBBASE_NODE *other;
            CRBBASE_NODE *o_left;
            CRBBASE_NODE *o_right;

            other = CRBBASE_NODE_LEFT(parent);

            if (CRBBASE_RED == CRBBASE_NODE_COLOR(other))
            {
                CRBBASE_NODE_COLOR(other) = CRBBASE_BLACK;
                CRBBASE_NODE_COLOR(parent) = CRBBASE_RED;

                __crbbase_tree_rotate_right(crbbasetree, parent);

                other = CRBBASE_NODE_LEFT(parent);
            }

            o_left = CRBBASE_NODE_LEFT(other);
            o_right = CRBBASE_NODE_RIGHT(other);

            if ((NULL_PTR == o_left  || CRBBASE_BLACK == CRBBASE_NODE_COLOR(o_left))
             && (NULL_PTR == o_right || CRBBASE_BLACK == CRBBASE_NODE_COLOR(o_right)))
            {
                CRBBASE_NODE_COLOR(other) = CRBBASE_RED;

                node = parent;
                parent = CRBBASE_NODE_PARENT(node);
            }
            else
            {
                if (NULL_PTR == o_left  || CRBBASE_BLACK == CRBBASE_NODE_COLOR(o_left))
                {
                    if (NULL_PTR != o_right)
                    {
                        CRBBASE_NODE_COLOR(o_right) = CRBBASE_BLACK;
                    }

                    CRBBASE_NODE_COLOR(other) = CRBBASE_RED;

                    __crbbase_tree_rotate_left(crbbasetree, other);

                    other = CRBBASE_NODE_LEFT(parent);
                    /*note: other was changed here*/
                }

                CRBBASE_NODE_COLOR(other) = CRBBASE_NODE_COLOR(parent);
                CRBBASE_NODE_COLOR(parent) = CRBBASE_BLACK;

                /*due to other may be changed before, have to get o_left again here*/
                o_left = CRBBASE_NODE_LEFT(other);
                if (NULL_PTR != o_left)
                {
                    CRBBASE_NODE_COLOR(o_left) = CRBBASE_BLACK;
                }
                __crbbase_tree_rotate_right(crbbasetree, parent);
                node = CRBBASE_TREE_ROOT(crbbasetree);
                break;
            }
        }
    }

    if (NULL_PTR != node)
    {
        CRBBASE_NODE_COLOR(node) = CRBBASE_BLACK;
    }
    return;
}

STATIC_CAST static void __crbbase_tree_erase(CRBBASE_TREE *crbbasetree, CRBBASE_NODE *node)
{
    CRBBASE_NODE * child;
    CRBBASE_NODE * parent;
    uint16_t color;

    ASSERT(NULL_PTR != node);

    if (NULL_PTR == CRBBASE_NODE_LEFT(node))
    {
        child = CRBBASE_NODE_RIGHT(node);
    }
    else if (NULL_PTR == CRBBASE_NODE_RIGHT(node))
    {
        child = CRBBASE_NODE_LEFT(node);
    }
    else
    {
        CRBBASE_NODE *old;
        CRBBASE_NODE *left;

        old = node;
        node = CRBBASE_NODE_RIGHT(node);

        while (NULL_PTR != (left = CRBBASE_NODE_LEFT(node)))
        {
            node = left;
        }

        child  = CRBBASE_NODE_RIGHT(node);
        parent = CRBBASE_NODE_PARENT(node);
        color  = CRBBASE_NODE_COLOR(node);

        if (NULL_PTR != child)
        {
            CRBBASE_NODE_PARENT(child) = parent;
        }

        if (NULL_PTR != parent)
        {
            if (CRBBASE_NODE_LEFT(parent) == node)
            {
                CRBBASE_NODE_LEFT(parent) = child;
            }
            else
            {
                CRBBASE_NODE_RIGHT(parent) = child;
            }
        }
        else
        {
            CRBBASE_TREE_ROOT(crbbasetree) = child;
        }

        if (CRBBASE_NODE_PARENT(node) == old)
        {
            parent = node;
        }

        CRBBASE_NODE_PARENT(node) = CRBBASE_NODE_PARENT(old);
        CRBBASE_NODE_COLOR(node)  = CRBBASE_NODE_COLOR(old);
        CRBBASE_NODE_RIGHT(node)  = CRBBASE_NODE_RIGHT(old);
        CRBBASE_NODE_LEFT(node)   = CRBBASE_NODE_LEFT(old);

        if (NULL_PTR != CRBBASE_NODE_PARENT(old))
        {
            CRBBASE_NODE *old_parent;
            old_parent = CRBBASE_NODE_PARENT(old);

            if (CRBBASE_NODE_LEFT(old_parent) == old)
            {
                CRBBASE_NODE_LEFT(old_parent) = node;
            }
            else
            {
                CRBBASE_NODE_RIGHT(old_parent) = node;
            }
        }
        else
        {
            CRBBASE_TREE_ROOT(crbbasetree) = node;
        }

        {
            CRBBASE_NODE *old_left;

            old_left = CRBBASE_NODE_LEFT(old);
            CRBBASE_NODE_PARENT(old_left) = node;
        }

        if (NULL_PTR != CRBBASE_NODE_RIGHT(old))
        {
            CRBBASE_NODE *old_right;
            old_right = CRBBASE_NODE_RIGHT(old);
            CRBBASE_NODE_PARENT(old_right) = node;
        }
        goto color;
    }

    parent = CRBBASE_NODE_PARENT(node);
    color = CRBBASE_NODE_COLOR(node);

    if (NULL_PTR != child)
    {
        CRBBASE_NODE_PARENT(child) = parent;
    }

    if (NULL_PTR != parent)
    {
        if (CRBBASE_NODE_LEFT(parent) == node)
        {
            CRBBASE_NODE_LEFT(parent) = child;
        }
        else
        {
            CRBBASE_NODE_RIGHT(parent) = child;
        }
    }
    else
    {
        CRBBASE_TREE_ROOT(crbbasetree) = child;
    }

 color:
    if (CRBBASE_BLACK == color)
    {
        __crbbase_tree_erase_color(crbbasetree, child, parent);
    }
    return;
}

EC_BOOL crbbase_tree_is_empty(const CRBBASE_TREE *crbbasetree)
{
    if (0 == CRBBASE_TREE_NODE_NUM(crbbasetree) || NULL_PTR == CRBBASE_TREE_ROOT(crbbasetree))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

STATIC_CAST static uint32_t __crbbase_tree_node_count(const CRBBASE_TREE *crbbasetree, const CRBBASE_NODE *node)
{
    if(NULL_PTR == node)
    {
        return ((uint32_t)0);
    }

    return (uint32_t)(1 + __crbbase_tree_node_count(crbbasetree, CRBBASE_NODE_LEFT(node)) + __crbbase_tree_node_count(crbbasetree, CRBBASE_NODE_RIGHT(node)));
}

uint32_t crbbase_tree_node_count(const CRBBASE_TREE *crbbasetree)
{
    return __crbbase_tree_node_count(crbbasetree, CRBBASE_TREE_ROOT(crbbasetree));
}

uint32_t crbbase_tree_node_num(const CRBBASE_TREE *crbbasetree)
{
    return CRBBASE_TREE_NODE_NUM(crbbasetree);
}

/*
 * This function returns the first node_pos (in sort order) of the tree.
 */
const CRBBASE_NODE * crbbase_tree_first_node(const CRBBASE_TREE *crbbasetree)
{
    const CRBBASE_NODE *node;

    node = CRBBASE_TREE_ROOT(crbbasetree);
    if (NULL_PTR == node)
    {
        return (NULL_PTR);
    }

    while (NULL_PTR != CRBBASE_NODE_LEFT(node))
    {
        node = CRBBASE_NODE_LEFT(node);
    }
    return (node);
}

const CRBBASE_NODE * crbbase_tree_last_node(const CRBBASE_TREE *crbbasetree)
{
    const CRBBASE_NODE *node;

    node = CRBBASE_TREE_ROOT(crbbasetree);
    if (NULL_PTR == node)
    {
        return (NULL_PTR);
    }

    while (NULL_PTR != CRBBASE_NODE_RIGHT(node))
    {
        node = CRBBASE_NODE_RIGHT(node);
    }

    return (node);
}

const CRBBASE_NODE * crbbase_tree_next_node(const CRBBASE_TREE *crbbasetree, const CRBBASE_NODE *node)
{
    const CRBBASE_NODE *node_t;
    const CRBBASE_NODE *parent;

    node_t = node;

    /* If we have a right-hand child, go down and then left as far
       as we can. */
    if (NULL_PTR != CRBBASE_NODE_RIGHT(node_t))
    {
        node_t = CRBBASE_NODE_RIGHT(node_t);
        while (NULL_PTR != CRBBASE_NODE_LEFT(node_t))
        {
            node_t = CRBBASE_NODE_LEFT(node_t);
        }
        return (node_t);
    }

    /* No right-hand children.  Everything down and left is
       smaller than us, so any 'next' node_t must be in the general
       direction of our parent. Go up the tree; any time the
       ancestor is a right-hand child of its parent, keep going
       up. First time it's a left-hand child of its parent, said
       parent is our 'next' node_t. */
    while (NULL_PTR != (parent = CRBBASE_NODE_PARENT(node_t)) && node_t == CRBBASE_NODE_RIGHT(parent))
    {
        node_t = parent;
    }

    return (CRBBASE_NODE_PARENT(node_t));
}

const CRBBASE_NODE * crbbase_tree_prev_node(const CRBBASE_TREE *crbbasetree, const CRBBASE_NODE *node)
{
    const CRBBASE_NODE *node_t;
    const CRBBASE_NODE *parent;

    node_t = node;

    /* If we have a left-hand child, go down and then right as far
       as we can. */
    if (NULL_PTR != CRBBASE_NODE_LEFT(node_t))
    {
        node_t = CRBBASE_NODE_LEFT(node_t);
        while (NULL_PTR != CRBBASE_NODE_RIGHT(node_t))
        {
            node_t = CRBBASE_NODE_RIGHT(node_t);
        }
        return (node_t);
    }

    /* No left-hand children. Go up till we find an ancestor which
       is a right-hand child of its parent */
    while (NULL_PTR != (parent = CRBBASE_NODE_PARENT(node_t)) && node_t == CRBBASE_NODE_LEFT(parent))
    {
        node_t = parent;
    }

    return (CRBBASE_NODE_PARENT(node_t));
}

void * crbbase_tree_first_data(const CRBBASE_TREE *crbbasetree)
{
    const CRBBASE_NODE *node;

    node = crbbase_tree_first_node(crbbasetree);
    if(NULL_PTR == node)
    {
        return (NULL_PTR);
    }
    return (void *)CRBBASE_NODE_DATA(node, CRBBASE_TREE_NODE_OFFSET(crbbasetree));
}

void * crbbase_tree_last_data(const CRBBASE_TREE *crbbasetree)
{
    const CRBBASE_NODE *node;

    node = crbbase_tree_last_node(crbbasetree);
    if(NULL_PTR == node)
    {
        return (NULL_PTR);
    }
    return (void *)CRBBASE_NODE_DATA(node, CRBBASE_TREE_NODE_OFFSET(crbbasetree));
}

void * crbbase_tree_next_data(const CRBBASE_TREE *crbbasetree, const void *data)
{
    const CRBBASE_NODE *node;

    node = crbbase_tree_search_data(crbbasetree, data);
    if(NULL_PTR == node)
    {
        return (NULL_PTR);
    }

    node = crbbase_tree_next_node(crbbasetree, node);
    if(NULL_PTR == node)
    {
        return (NULL_PTR);
    }
    return (void *)CRBBASE_NODE_DATA(node, CRBBASE_TREE_NODE_OFFSET(crbbasetree));
}

void * crbbase_tree_prev_data(const CRBBASE_TREE *crbbasetree, const void *data)
{
    const CRBBASE_NODE *node;

    node = crbbase_tree_search_data(crbbasetree, data);
    if(NULL_PTR == node)
    {
        return (NULL_PTR);
    }

    node = crbbase_tree_prev_node(crbbasetree, node);
    if(NULL_PTR == node)
    {
        return (NULL_PTR);
    }
    return (void *)CRBBASE_NODE_DATA(node, CRBBASE_TREE_NODE_OFFSET(crbbasetree));
}

/*victim_pos should be free*/
void crbbase_tree_replace_node(CRBBASE_TREE *crbbasetree, CRBBASE_NODE *victim, CRBBASE_NODE *new_node)
{
    /* Set the surrounding nodes to point to the replacement */
    if (NULL_PTR != CRBBASE_NODE_PARENT(victim))
    {
        CRBBASE_NODE *parent;
        parent = CRBBASE_NODE_PARENT(victim);

        if (victim == CRBBASE_NODE_LEFT(parent))
        {
            CRBBASE_NODE_LEFT(parent) = new_node;
        }
        else
        {
            CRBBASE_NODE_RIGHT(parent) = new_node;
        }
    }
    else
    {
        CRBBASE_TREE_ROOT(crbbasetree) = new_node;
    }

    if (NULL_PTR != CRBBASE_NODE_LEFT(victim))
    {
        CRBBASE_NODE *left;
        left = CRBBASE_NODE_LEFT(victim);
        CRBBASE_NODE_PARENT(left) = new_node;
    }
    if (NULL_PTR != CRBBASE_NODE_RIGHT(victim))
    {
        CRBBASE_NODE *right;
        right = CRBBASE_NODE_RIGHT(victim);
        CRBBASE_NODE_PARENT(right) = new_node;
    }

    return;
}

/*return the searched pos*/
CRBBASE_NODE *crbbase_tree_search(CRBBASE_TREE *crbbasetree, const CRBBASE_NODE *node)
{
    CRBBASE_NODE *node_t;
    void     *data;

    data   = CRBBASE_NODE_DATA(node, CRBBASE_TREE_NODE_OFFSET(crbbasetree));
    node_t = CRBBASE_TREE_ROOT(crbbasetree);

    while (NULL_PTR != node_t)
    {
        int cmp;

        cmp = CRBBASE_TREE_DATA_CMP(crbbasetree)(
                    CRBBASE_NODE_DATA(node_t, CRBBASE_TREE_NODE_OFFSET(crbbasetree)),
                    data);
        if (0 < cmp) /*data < CRBBASE_NODE_DATA(node_t)*/
        {
            node_t = CRBBASE_NODE_LEFT(node_t);
        }
        else if (0 > cmp)/*data > CRBBASE_NODE_DATA(node_t)*/
        {
            node_t = CRBBASE_NODE_RIGHT(node_t);
        }
        else
        {
            return (node_t);
        }
    }

    return (NULL_PTR);
}

CRBBASE_NODE * crbbase_tree_insert(CRBBASE_TREE *crbbasetree, CRBBASE_NODE *new_node)
{
    CRBBASE_NODE *node;
    CRBBASE_NODE *parent;
    uint16_t  flag; /*0: on left subtree, 1: on right subtree*/

    node   = CRBBASE_TREE_ROOT(crbbasetree);
    parent = NULL_PTR;
    flag   = ~(uint16_t)0;

    while (NULL_PTR != node)
    {
        int cmp;

        cmp = CRBBASE_TREE_DATA_CMP(crbbasetree)(
                        CRBBASE_NODE_DATA(node, CRBBASE_TREE_NODE_OFFSET(crbbasetree)),
                        CRBBASE_NODE_DATA(new_node, CRBBASE_TREE_NODE_OFFSET(crbbasetree)));

        parent = node;

        if (0 < cmp)/*data < CRBBASE_NODE_DATA(node)*/
        {
            node = CRBBASE_NODE_LEFT(node);
            flag = 0;
        }
        else if (0 > cmp)/*data > CRBBASE_NODE_DATA(node)*/
        {
            node = CRBBASE_NODE_RIGHT(node);
            flag = 1;
        }
        else
        {
            return (node);
        }
    }

    /*not found data in the rbtree*/
    CRBBASE_NODE_PARENT(new_node) = parent;
    CRBBASE_NODE_COLOR(new_node)  = CRBBASE_RED;
    CRBBASE_NODE_LEFT(new_node)   = NULL_PTR;
    CRBBASE_NODE_RIGHT(new_node)  = NULL_PTR;

    if(NULL_PTR == CRBBASE_TREE_ROOT(crbbasetree))
    {
        CRBBASE_TREE_ROOT(crbbasetree) = new_node;
    }
    else
    {
        if(0 == flag)/*on left subtree*/
        {
            CRBBASE_NODE_LEFT(parent) = new_node;
        }
        else
        {
            CRBBASE_NODE_RIGHT(parent) = new_node;
        }
    }
    __crbbase_tree_insert_color(crbbasetree, new_node);
    CRBBASE_NODE_USED(new_node) = BIT_TRUE;

    CRBBASE_TREE_NODE_NUM(crbbasetree) ++;

    return (new_node);
}

EC_BOOL crbbase_tree_delete(CRBBASE_TREE *crbbasetree, CRBBASE_NODE *node)
{
    __crbbase_tree_erase(crbbasetree, node);

    crbbase_node_clean(node);

    CRBBASE_TREE_DATA_FREE(crbbasetree)(CRBBASE_NODE_DATA(node, CRBBASE_TREE_NODE_OFFSET(crbbasetree)));/*callback free handler*/

    CRBBASE_TREE_NODE_NUM(crbbasetree) --;

    return (EC_TRUE);
}

void *crbbase_tree_erase(CRBBASE_TREE *crbbasetree, CRBBASE_NODE *node)
{
    void *data;

    __crbbase_tree_erase(crbbasetree, node);

    crbbase_node_clean(node);

    data = CRBBASE_NODE_DATA(node, CRBBASE_TREE_NODE_OFFSET(crbbasetree));

    CRBBASE_TREE_NODE_NUM(crbbasetree) --;

    return (data);
}

CRBBASE_NODE *crbbase_tree_lookup_data(const CRBBASE_TREE *crbbasetree, const void *data)
{
    CRBBASE_NODE *node;
    CRBBASE_NODE *result;

    result = NULL_PTR;
    node = CRBBASE_TREE_ROOT(crbbasetree);

    while (NULL_PTR != node)
    {
        int cmp;

        cmp = CRBBASE_TREE_DATA_CMP(crbbasetree)(
                    CRBBASE_NODE_DATA(node, CRBBASE_TREE_NODE_OFFSET(crbbasetree)),
                    data);
        if (0 < cmp) /*data < CRBBASE_NODE_DATA(node)*/
        {
            result = node;/*update result*/
            node = CRBBASE_NODE_LEFT(node);
        }
        else if (0 > cmp)/*data > CRBBASE_NODE_DATA(node)*/
        {
            node = CRBBASE_NODE_RIGHT(node);
        }
        else
        {
            return (node);
        }
    }

    if(NULL_PTR != result)
    {
        return (result);
    }

    /*circle to left-most node*/
    node = CRBBASE_TREE_ROOT(crbbasetree);
    if(NULL_PTR == node)
    {
        return (NULL_PTR);
    }

    while(NULL_PTR != CRBBASE_NODE_LEFT(node))
    {
        node = CRBBASE_NODE_LEFT(node);
    }

    return (node);
}

CRBBASE_NODE *crbbase_tree_search_data(const CRBBASE_TREE *crbbasetree, const void *data)
{
    CRBBASE_NODE *node;

    node = CRBBASE_TREE_ROOT(crbbasetree);

    while (NULL_PTR != node)
    {
        int cmp;

        cmp = CRBBASE_TREE_DATA_CMP(crbbasetree)(
                        CRBBASE_NODE_DATA(node, CRBBASE_TREE_NODE_OFFSET(crbbasetree)),
                        data);
        if (0 < cmp) /*data < CRBBASE_NODE_DATA(node)*/
        {
            node = CRBBASE_NODE_LEFT(node);
        }
        else if (0 > cmp)/*data > CRBBASE_NODE_DATA(node)*/
        {
            node = CRBBASE_NODE_RIGHT(node);
        }
        else
        {
            return (node);
        }
    }

    return (NULL_PTR);
}

CRBBASE_NODE * crbbase_tree_insert_data(CRBBASE_TREE *crbbasetree, const void *data)
{
    CRBBASE_NODE *node_tmp;
    CRBBASE_NODE *node_new;

    node_tmp = (CRBBASE_NODE *)(((char *)data) + CRBBASE_TREE_NODE_OFFSET(crbbasetree));

    node_new = crbbase_tree_insert(crbbasetree, node_tmp);

    return (node_new);
}

EC_BOOL crbbase_tree_delete_data(CRBBASE_TREE *crbbasetree, const void *data)
{
    CRBBASE_NODE *node;

    node = crbbase_tree_search_data(crbbasetree, data);
    if(NULL_PTR == node)
    {
        return (EC_TRUE);
    }

    return crbbase_tree_delete(crbbasetree, node);
}

void *crbbase_tree_node_data(CRBBASE_TREE *crbbasetree, CRBBASE_NODE *node)
{
    return CRBBASE_NODE_DATA(node, CRBBASE_TREE_NODE_OFFSET(crbbasetree));
}

/*postorder: left -> right -> root*/
STATIC_CAST static void __crbbase_tree_free(CRBBASE_TREE *crbbasetree, CRBBASE_NODE *node)
{
    if(NULL_PTR == node)
    {
        return;
    }

    if(NULL_PTR != CRBBASE_NODE_LEFT(node))
    {
        __crbbase_tree_free(crbbasetree, CRBBASE_NODE_LEFT(node));
    }

    if(NULL_PTR != CRBBASE_NODE_RIGHT(node))
    {
        __crbbase_tree_free(crbbasetree, CRBBASE_NODE_RIGHT(node));
    }

    CRBBASE_TREE_DATA_FREE(crbbasetree)(CRBBASE_NODE_DATA(node, CRBBASE_TREE_NODE_OFFSET(crbbasetree)));
    CRBBASE_TREE_NODE_NUM(crbbasetree) --;

    return;
}

CRBBASE_TREE *crbbase_tree_new(const uint32_t node_offset, CRBBASE_DATA_CMP data_cmp, CRBBASE_DATA_FREE data_free, CRBBASE_DATA_PRINT data_print)
{
    CRBBASE_TREE *crbbasetree;

    alloc_static_mem(MM_CRBBASE_TREE, &crbbasetree, LOC_CRBBASE_0001);
    if(NULL_PTR == crbbasetree)
    {
        dbg_log(SEC_0087_CRBBASE, 0)(LOGSTDOUT, "error:crbbase_tree_new: new crbbasetree failed\n");
        return (NULL_PTR);
    }
    crbbase_tree_init(crbbasetree, node_offset, data_cmp, data_free, data_print);
    return (crbbasetree);
}

EC_BOOL crbbase_tree_init(CRBBASE_TREE *crbbasetree, const uint32_t node_offset, CRBBASE_DATA_CMP data_cmp, CRBBASE_DATA_FREE data_free, CRBBASE_DATA_PRINT data_print)
{
    CRBBASE_TREE_NODE_NUM(crbbasetree)    = 0;
    CRBBASE_TREE_NODE_OFFSET(crbbasetree) = node_offset;
    CRBBASE_TREE_ROOT(crbbasetree)        = NULL_PTR;
    CRBBASE_TREE_DATA_CMP(crbbasetree)    = (NULL_PTR == data_cmp)   ? __crbbase_data_cmp_default   : data_cmp;
    CRBBASE_TREE_DATA_FREE(crbbasetree)   = (NULL_PTR == data_free)  ? __crbbase_data_null_default  : data_free;
    CRBBASE_TREE_DATA_PRINT(crbbasetree)  = (NULL_PTR == data_print) ? __crbbase_data_print_default : data_print;

    return (EC_TRUE);
}

void crbbase_tree_clean(CRBBASE_TREE *crbbasetree)
{
    if(NULL_PTR != crbbasetree)
    {
        __crbbase_tree_free(crbbasetree, CRBBASE_TREE_ROOT(crbbasetree));
        CRBBASE_TREE_ROOT(crbbasetree) = NULL_PTR;
    }
    return;
}

void crbbase_tree_free(CRBBASE_TREE *crbbasetree)
{
    if(NULL_PTR != crbbasetree)
    {
        crbbase_tree_clean(crbbasetree);
        free_static_mem(MM_CRBBASE_TREE, crbbasetree, LOC_CRBBASE_0002);
    }
    return;
}

uint32_t crbbase_tree_node_offset(const CRBBASE_TREE *crbbasetree)
{
    return CRBBASE_TREE_NODE_OFFSET(crbbasetree);
}

EC_BOOL crbbase_tree_cmp(const CRBBASE_TREE *crbbasetree_1st, const CRBBASE_TREE *crbbasetree_2nd, EC_BOOL (*cmp)(const void *, const void *))
{
    const CRBBASE_NODE *crbbase_node_1st;
    const CRBBASE_NODE *crbbase_node_2nd;

    if(CRBBASE_TREE_NODE_NUM(crbbasetree_1st) != CRBBASE_TREE_NODE_NUM(crbbasetree_2nd))
    {
        dbg_log(SEC_0087_CRBBASE, 9)(LOGSTDOUT, "[DEBUG] crbbase_tree_cmp: node_num: %u != %u\n",
                           CRBBASE_TREE_NODE_NUM(crbbasetree_1st),
                           CRBBASE_TREE_NODE_NUM(crbbasetree_2nd));
        return (EC_FALSE);
    }

    crbbase_node_1st = crbbase_tree_first_node(crbbasetree_1st);
    crbbase_node_2nd = crbbase_tree_first_node(crbbasetree_2nd);

    while(NULL_PTR != crbbase_node_1st && NULL_PTR != crbbase_node_2nd)
    {
        if(EC_FALSE == cmp(
                CRBBASE_NODE_DATA(crbbase_node_1st, CRBBASE_TREE_NODE_OFFSET(crbbasetree_1st)),
                CRBBASE_NODE_DATA(crbbase_node_2nd, CRBBASE_TREE_NODE_OFFSET(crbbasetree_2nd))))
        {
            return (EC_FALSE);
        }

        crbbase_node_1st = crbbase_tree_next_node(crbbasetree_1st, crbbase_node_1st);
        crbbase_node_2nd = crbbase_tree_next_node(crbbasetree_2nd, crbbase_node_2nd);
    }

    if(NULL_PTR != crbbase_node_1st || NULL_PTR != crbbase_node_2nd)
    {
        dbg_log(SEC_0087_CRBBASE, 9)(LOGSTDOUT, "[DEBUG] crbbase_tree_cmp: crbbase_node_1st %p, crbbase_node_2nd %p\n",
                           crbbase_node_1st, crbbase_node_2nd);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

void crbbase_tree_print(LOG *log, const CRBBASE_TREE *crbbasetree)
{
    sys_log(log, "crbbase_tree_print: crbbasetree %p, node_num %u\n",
                 crbbasetree,
                 CRBBASE_TREE_NODE_NUM(crbbasetree));

    crbbase_inorder_print(log, crbbasetree);
    return;
}

void crbbase_tree_print_in_order(LOG *log, const CRBBASE_TREE *crbbasetree)
{
    const CRBBASE_NODE *node;

    sys_log(log, "[root = %p]\n", CRBBASE_TREE_ROOT(crbbasetree));

    for(node = crbbase_tree_first_node(crbbasetree); NULL_PTR != node; node = crbbase_tree_next_node(crbbasetree, node))
    {
        crbbase_node_print(log, crbbasetree, node);
    }
    return;
}

/*visit the root node first: root -> left -> right*/
STATIC_CAST static void __crbbase_preorder_print(LOG *log, const CRBBASE_TREE *crbbasetree, const CRBBASE_NODE *node)
{
    if(NULL_PTR == node)
    {
        return;
    }

    crbbase_node_print(log, crbbasetree, node);

    if(NULL_PTR != CRBBASE_NODE_LEFT(node))
    {
        __crbbase_preorder_print(log, crbbasetree, CRBBASE_NODE_LEFT(node));
    }

    if(NULL_PTR != CRBBASE_NODE_RIGHT(node))
    {
        __crbbase_preorder_print(log, crbbasetree, CRBBASE_NODE_RIGHT(node));
    }

    return;
}

void crbbase_preorder_print(LOG *log, const CRBBASE_TREE *crbbasetree)
{
    __crbbase_preorder_print(log, crbbasetree, CRBBASE_TREE_ROOT(crbbasetree));
    return;
}

/*visit the left subtree, then the root node: left -> root -> right*/
STATIC_CAST static void __crbbase_inorder_print(LOG *log, const CRBBASE_TREE *crbbasetree, const CRBBASE_NODE *node)
{
    if(NULL_PTR == node)
    {
        return;
    }

    if(NULL_PTR != CRBBASE_NODE_LEFT(node))
    {
        __crbbase_inorder_print(log, crbbasetree, CRBBASE_NODE_LEFT(node));
    }

    crbbase_node_print(log, crbbasetree, node);

    if(NULL_PTR != CRBBASE_NODE_RIGHT(node))
    {
        __crbbase_inorder_print(log, crbbasetree, CRBBASE_NODE_RIGHT(node));
    }

    return;
}

void crbbase_inorder_print(LOG *log, const CRBBASE_TREE *crbbasetree)
{
    __crbbase_inorder_print(log, crbbasetree, CRBBASE_TREE_ROOT(crbbasetree));
    return;
}

/*visit the root node last: left -> right -> root*/
STATIC_CAST static void __crbbase_postorder_print(LOG *log, const CRBBASE_TREE *crbbasetree, const CRBBASE_NODE *node)
{
    if(NULL_PTR == node)
    {
        return;
    }

    if(NULL_PTR != CRBBASE_NODE_LEFT(node))
    {
        __crbbase_postorder_print(log, crbbasetree, CRBBASE_NODE_LEFT(node));
    }

    if(NULL_PTR != CRBBASE_NODE_RIGHT(node))
    {
        __crbbase_postorder_print(log, crbbasetree, CRBBASE_NODE_RIGHT(node));
    }

    crbbase_node_print(log, crbbasetree, node);

    return;
}

void crbbase_postorder_print(LOG *log, const CRBBASE_TREE *crbbasetree)
{
    __crbbase_postorder_print(log, crbbasetree, CRBBASE_TREE_ROOT(crbbasetree));
    return;
}

/*visit the root node first: root -> left -> right*/
STATIC_CAST static void __crbbase_preorder_print_level(LOG *log, const CRBBASE_TREE *crbbasetree, const CRBBASE_NODE *node, const uint16_t level)
{
    if(NULL_PTR == node)
    {
        return;
    }

    crbbase_node_print_level(log, crbbasetree, node, level);

    if(NULL_PTR != CRBBASE_NODE_LEFT(node))
    {
        __crbbase_preorder_print_level(log, crbbasetree, CRBBASE_NODE_LEFT(node), level + 1);
    }

    if(NULL_PTR != CRBBASE_NODE_RIGHT(node))
    {
        __crbbase_preorder_print_level(log, crbbasetree, CRBBASE_NODE_RIGHT(node), level + 1);
    }

    return;
}

void crbbase_preorder_print_level(LOG *log, const CRBBASE_TREE *crbbasetree, const uint16_t level)
{
    __crbbase_preorder_print_level(log, crbbasetree, CRBBASE_TREE_ROOT(crbbasetree), level);
    return;
}

STATIC_CAST static EC_BOOL __crbbase_inorder_walk(const CRBBASE_TREE *crbbasetree, const CRBBASE_NODE *node, EC_BOOL (*walker)(const void *, void *), void *arg)
{
    if(NULL_PTR == node)
    {
        return (EC_TRUE);
    }

    if(NULL_PTR != CRBBASE_NODE_LEFT(node))
    {
        if(EC_FALSE == __crbbase_inorder_walk(crbbasetree, CRBBASE_NODE_LEFT(node), walker, arg))
        {
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == walker(CRBBASE_NODE_DATA(node, CRBBASE_TREE_NODE_OFFSET(crbbasetree)), arg))
    {
        return (EC_FALSE);
    }

    if(NULL_PTR != CRBBASE_NODE_RIGHT(node))
    {
        if(EC_FALSE == __crbbase_inorder_walk(crbbasetree, CRBBASE_NODE_RIGHT(node), walker, arg))
        {
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __crbbase_postorder_walk(const CRBBASE_TREE *crbbasetree, const CRBBASE_NODE *node, EC_BOOL (*walker)(const void *, void *), void *arg)
{
    if(NULL_PTR == node)
    {
        return (EC_TRUE);
    }

    if(NULL_PTR != CRBBASE_NODE_LEFT(node))
    {
        if(EC_FALSE == __crbbase_postorder_walk(crbbasetree, CRBBASE_NODE_LEFT(node), walker, arg))
        {
            return (EC_FALSE);
        }
    }

    if(NULL_PTR != CRBBASE_NODE_RIGHT(node))
    {
        if(EC_FALSE == __crbbase_postorder_walk(crbbasetree, CRBBASE_NODE_RIGHT(node), walker, arg))
        {
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == walker(CRBBASE_NODE_DATA(node, CRBBASE_TREE_NODE_OFFSET(crbbasetree)), arg))
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __crbbase_preorder_walk(const CRBBASE_TREE *crbbasetree, const CRBBASE_NODE *node, EC_BOOL (*walker)(const void *, void *), void *arg)
{
    if(NULL_PTR == node)
    {
        return (EC_TRUE);
    }

    if(EC_FALSE == walker(CRBBASE_NODE_DATA(node, CRBBASE_TREE_NODE_OFFSET(crbbasetree)), arg))
    {
        return (EC_FALSE);
    }

    if(NULL_PTR != CRBBASE_NODE_LEFT(node))
    {
        if(EC_FALSE == __crbbase_preorder_walk(crbbasetree, CRBBASE_NODE_LEFT(node), walker, arg))
        {
            return (EC_FALSE);
        }
    }

    if(NULL_PTR != CRBBASE_NODE_RIGHT(node))
    {
        if(EC_FALSE == __crbbase_preorder_walk(crbbasetree, CRBBASE_NODE_RIGHT(node), walker, arg))
        {
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}


/*walk through*/
EC_BOOL crbbase_inorder_walk(const CRBBASE_TREE *crbbasetree, EC_BOOL (*walker)(const void *, void *), void *arg)
{
    return __crbbase_inorder_walk(crbbasetree, CRBBASE_TREE_ROOT(crbbasetree), walker, arg);
}

EC_BOOL crbbase_postorder_walk(const CRBBASE_TREE *crbbasetree, EC_BOOL (*walker)(const void *, void *), void *arg)
{
    return __crbbase_postorder_walk(crbbasetree, CRBBASE_TREE_ROOT(crbbasetree), walker, arg);
}

EC_BOOL crbbase_preorder_walk(const CRBBASE_TREE *crbbasetree, EC_BOOL (*walker)(const void *, void *), void *arg)
{
    return __crbbase_preorder_walk(crbbasetree, CRBBASE_TREE_ROOT(crbbasetree), walker, arg);
}

STATIC_CAST static CRBBASE_NODE *__crbbase_inorder_locate(CRBBASE_TREE *crbbasetree, CRBBASE_NODE *node, void *data)
{
    if(NULL_PTR != node)
    {
        CRBBASE_NODE    *node_t;

        if(NULL_PTR != CRBBASE_NODE_LEFT(node))
        {
            node_t = __crbbase_inorder_locate(crbbasetree, CRBBASE_NODE_LEFT(node), data);
            if(NULL_PTR != node_t)
            {
                return (node_t);
            }
        }

        if(CRBBASE_NODE_DATA(node, CRBBASE_TREE_NODE_OFFSET(crbbasetree)) == data)
        {
            return (node);
        }

        if(NULL_PTR != CRBBASE_NODE_RIGHT(node))
        {
            node_t = __crbbase_inorder_locate(crbbasetree, CRBBASE_NODE_RIGHT(node), data);
            if(NULL_PTR != node_t)
            {
                return (node_t);
            }
        }
    }

    return (NULL_PTR);
}

STATIC_CAST static CRBBASE_NODE *__crbbase_postorder_locate(CRBBASE_TREE *crbbasetree, CRBBASE_NODE *node, void *data)
{
    if(NULL_PTR != node)
    {
        CRBBASE_NODE    *node_t;

        if(NULL_PTR != CRBBASE_NODE_LEFT(node))
        {
            node_t = __crbbase_postorder_locate(crbbasetree, CRBBASE_NODE_LEFT(node), data);
            if(NULL_PTR != node_t)
            {
                return (node_t);
            }
        }

        if(NULL_PTR != CRBBASE_NODE_RIGHT(node))
        {
            node_t = __crbbase_postorder_locate(crbbasetree, CRBBASE_NODE_RIGHT(node), data);
            if(NULL_PTR != node_t)
            {
                return (node_t);
            }
        }

        if(CRBBASE_NODE_DATA(node, CRBBASE_TREE_NODE_OFFSET(crbbasetree)) == data)
        {
            return (node);
        }
    }
    return (NULL_PTR);
}

STATIC_CAST static CRBBASE_NODE *__crbbase_preorder_locate(CRBBASE_TREE *crbbasetree, CRBBASE_NODE *node, void *data)
{
    if(NULL_PTR != node)
    {
        CRBBASE_NODE    *node_t;

        if(CRBBASE_NODE_DATA(node, CRBBASE_TREE_NODE_OFFSET(crbbasetree)) == data)
        {
            return (node);
        }

        if(NULL_PTR != CRBBASE_NODE_LEFT(node))
        {
            node_t = __crbbase_preorder_locate(crbbasetree, CRBBASE_NODE_LEFT(node), data);
            if(NULL_PTR != node_t)
            {
                return (node_t);
            }
        }

        if(NULL_PTR != CRBBASE_NODE_RIGHT(node))
        {
            node_t = __crbbase_preorder_locate(crbbasetree, CRBBASE_NODE_RIGHT(node), data);
            if(NULL_PTR != node_t)
            {
                return (node_t);
            }
        }
    }
    return (EC_TRUE);
}

CRBBASE_NODE *crbbase_inorder_locate(CRBBASE_TREE *crbbasetree, void *data)
{
    return __crbbase_inorder_locate(crbbasetree, CRBBASE_TREE_ROOT(crbbasetree), data);
}

CRBBASE_NODE *crbbase_postorder_locate(CRBBASE_TREE *crbbasetree, void *data)
{
    return __crbbase_postorder_locate(crbbasetree, CRBBASE_TREE_ROOT(crbbasetree), data);
}

CRBBASE_NODE *crbbase_preorder_locate(CRBBASE_TREE *crbbasetree, void *data)
{
    return __crbbase_preorder_locate(crbbasetree, CRBBASE_TREE_ROOT(crbbasetree), data);
}

STATIC_CAST static EC_BOOL __crbbase_inorder_flush(const CRBBASE_TREE *crbbasetree, const CRBBASE_NODE *node, int fd, UINT32 *offset, EC_BOOL (*data_flush)(const void *, int, UINT32 *))
{
    if(NULL_PTR == node)
    {
        return (EC_TRUE);
    }

    if(NULL_PTR != CRBBASE_NODE_LEFT(node))
    {
        if(EC_FALSE == __crbbase_inorder_flush(crbbasetree, CRBBASE_NODE_LEFT(node), fd, offset, data_flush))
        {
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == data_flush(CRBBASE_NODE_DATA(node, CRBBASE_TREE_NODE_OFFSET(crbbasetree)), fd, offset))
    {
        return (EC_FALSE);
    }

    if(NULL_PTR != CRBBASE_NODE_RIGHT(node))
    {
        if(EC_FALSE == __crbbase_inorder_flush(crbbasetree, CRBBASE_NODE_RIGHT(node), fd, offset, data_flush))
        {
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

EC_BOOL crbbase_inorder_flush(const CRBBASE_TREE *crbbasetree, int fd, UINT32 *offset, EC_BOOL (*data_flush)(const void *, int, UINT32 *))
{
    return __crbbase_inorder_flush(crbbasetree, CRBBASE_TREE_ROOT(crbbasetree), fd, offset, data_flush);
}

EC_BOOL crbbase_tree_flush(const CRBBASE_TREE *crbbasetree, int fd, UINT32 *offset, EC_BOOL (*data_flush)(const void *, int, UINT32 *))
{
    UINT32     osize;/*write once size*/

    osize = sizeof(uint32_t);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(CRBBASE_TREE_NODE_NUM(crbbasetree))))
    {
        dbg_log(SEC_0087_CRBBASE, 0)(LOGSTDOUT, "error:crbbase_tree_flush: data_flush node num at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    return crbbase_inorder_flush(crbbasetree, fd, offset, data_flush);
}

EC_BOOL crbbase_tree_load(CRBBASE_TREE *crbbasetree, int fd, UINT32 *offset, void *(*data_new)(), EC_BOOL (*data_load)(void *, int, UINT32 *))
{
    UINT32     osize;
    uint32_t   node_num;
    uint32_t   node_pos;

    osize = sizeof(uint32_t);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(node_num)))
    {
        dbg_log(SEC_0087_CRBBASE, 0)(LOGSTDOUT, "error:crbbase_tree_load: load node num at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    for(node_pos = 0; node_pos < node_num; node_pos ++)
    {
        void     *data;
        CRBBASE_NODE *crbbase_node;

        data = data_new();
        if(NULL_PTR == data)
        {
            dbg_log(SEC_0087_CRBBASE, 0)(LOGSTDOUT, "error:crbbase_tree_load: new data when reach offset %ld of fd %d failed\n", (*offset), fd);
            return (EC_FALSE);
        }

        if(EC_FALSE == data_load(data, fd, offset))
        {
            dbg_log(SEC_0087_CRBBASE, 0)(LOGSTDOUT, "error:crbbase_tree_load: load data at offset %ld of fd %d failed\n", (*offset), fd);
            CRBBASE_TREE_DATA_FREE(crbbasetree)(data);
            return (EC_FALSE);
        }

        crbbase_node = crbbase_tree_insert_data(crbbasetree, data);
        if(NULL_PTR == crbbase_node)
        {
            dbg_log(SEC_0087_CRBBASE, 0)(LOGSTDOUT, "error:crbbase_tree_load: insert data at offset %ld of fd %d failed\n", (*offset), fd);
            CRBBASE_TREE_DATA_FREE(crbbasetree)(data);
            return (EC_FALSE);
        }

        /*fix*/
        if(data != CRBBASE_NODE_DATA(crbbase_node, CRBBASE_TREE_NODE_OFFSET(crbbasetree)))
        {
            CRBBASE_TREE_DATA_FREE(crbbasetree)(data);
        }
    }

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __crbbase_inorder_clone(const CRBBASE_TREE *crbbasetree_src, const CRBBASE_NODE *node, CRBBASE_TREE *crbbasetree_des, void *(*data_new)(), EC_BOOL (*data_clone)(const void *, void *))
{
    void *data;
    CRBBASE_NODE *crbbase_node;

    if(NULL_PTR == node)
    {
        return (EC_TRUE);
    }

    if(NULL_PTR != CRBBASE_NODE_LEFT(node))
    {
        if(EC_FALSE == __crbbase_inorder_clone(crbbasetree_src, CRBBASE_NODE_LEFT(node), crbbasetree_des, data_new, data_clone))
        {
            return (EC_FALSE);
        }
    }

    data = data_new();
    if(NULL_PTR == data)
    {
        dbg_log(SEC_0087_CRBBASE, 0)(LOGSTDOUT, "error:__crbbase_inorder_clone: new data failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == data_clone(CRBBASE_NODE_DATA(node, CRBBASE_TREE_NODE_OFFSET(crbbasetree_src)), data))
    {
        CRBBASE_TREE_DATA_FREE(crbbasetree_des)(data);
        return (EC_FALSE);
    }

    crbbase_node = crbbase_tree_insert_data(crbbasetree_des, data);
    if(NULL_PTR == crbbase_node)
    {
        dbg_log(SEC_0087_CRBBASE, 0)(LOGSTDOUT, "error:__crbbase_inorder_clone: insert data failed\n");
        CRBBASE_TREE_DATA_FREE(crbbasetree_des)(data);
        return (EC_FALSE);
    }

    /*fix*/
    if(data != CRBBASE_NODE_DATA(crbbase_node, CRBBASE_TREE_NODE_OFFSET(crbbasetree_src)))
    {
        CRBBASE_TREE_DATA_FREE(crbbasetree_des)(data);
    }

    if(NULL_PTR != CRBBASE_NODE_RIGHT(node))
    {
        if(EC_FALSE == __crbbase_inorder_clone(crbbasetree_src, CRBBASE_NODE_RIGHT(node), crbbasetree_des, data_new, data_clone))
        {
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

EC_BOOL crbbase_inorder_clone(const CRBBASE_TREE *crbbasetree_src, CRBBASE_TREE *crbbasetree_des, void *(*data_new)(), EC_BOOL (*data_clone)(const void *, void *))
{
    CRBBASE_TREE_NODE_OFFSET(crbbasetree_des) = CRBBASE_TREE_NODE_OFFSET(crbbasetree_src);
    return __crbbase_inorder_clone(crbbasetree_src, CRBBASE_TREE_ROOT(crbbasetree_src), crbbasetree_des, data_new, data_clone);
}

EC_BOOL crbbase_tree_clone(const CRBBASE_TREE *crbbasetree_src, CRBBASE_TREE *crbbasetree_des, void *(*data_new)(), EC_BOOL (*data_clone)(const void *, void *))
{
    CRBBASE_TREE_NODE_OFFSET(crbbasetree_des) = CRBBASE_TREE_NODE_OFFSET(crbbasetree_src);
    return crbbase_inorder_clone(crbbasetree_src, crbbasetree_des, data_new, data_clone);
}

EC_BOOL crbbase_tree_move(CRBBASE_TREE *crbbasetree_src, CRBBASE_TREE *crbbasetree_des)
{
    CRBBASE_TREE_NODE_NUM(crbbasetree_des)    = CRBBASE_TREE_NODE_NUM(crbbasetree_src);
    CRBBASE_TREE_NODE_OFFSET(crbbasetree_des) = CRBBASE_TREE_NODE_OFFSET(crbbasetree_src);
    CRBBASE_TREE_ROOT(crbbasetree_des)        = CRBBASE_TREE_ROOT(crbbasetree_src);
    CRBBASE_TREE_DATA_CMP(crbbasetree_des)    = CRBBASE_TREE_DATA_CMP(crbbasetree_src);
    CRBBASE_TREE_DATA_FREE(crbbasetree_des)   = CRBBASE_TREE_DATA_FREE(crbbasetree_src);
    CRBBASE_TREE_DATA_PRINT(crbbasetree_des)  = CRBBASE_TREE_DATA_PRINT(crbbasetree_src);

    CRBBASE_TREE_NODE_NUM(crbbasetree_src)    = 0;
    CRBBASE_TREE_ROOT(crbbasetree_src)        = NULL_PTR;
    CRBBASE_TREE_DATA_CMP(crbbasetree_src)    = NULL_PTR;
    CRBBASE_TREE_DATA_FREE(crbbasetree_src)   = NULL_PTR;
    CRBBASE_TREE_DATA_PRINT(crbbasetree_src)  = NULL_PTR;

    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/
