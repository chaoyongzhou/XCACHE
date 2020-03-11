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

#include "clist.h"
#include "cmap.h"

#include "cmutex.h"
#include "cmpic.inc"

CMAP_NODE *cmap_node_new(void *key, void *val, const UINT32 location)
{
    CMAP_NODE *cmap_node;
    alloc_static_mem(MM_CMAP_NODE, &cmap_node, location);
    if(NULL_PTR != cmap_node)
    {
        cmap_node_init(cmap_node, key, val);
    }
    return (cmap_node);
}

EC_BOOL    cmap_node_init(CMAP_NODE *cmap_node, void *key, void *val)
{
    CMAP_NODE_KEY(cmap_node) = key;
    CMAP_NODE_VAL(cmap_node) = val;
    return (EC_TRUE);
}

EC_BOOL    cmap_node_clean(CMAP_NODE *cmap_node, CMAP_KEY_FREE key_free, CMAP_VAL_FREE val_free, const UINT32 location)
{
    if(NULL_PTR != cmap_node)
    {
        if(NULL_PTR != key_free && NULL_PTR != CMAP_NODE_KEY(cmap_node))
        {
            key_free(CMAP_NODE_KEY(cmap_node), location);
            CMAP_NODE_KEY(cmap_node) = NULL_PTR;
        }

        if(NULL_PTR != val_free && NULL_PTR != CMAP_NODE_VAL(cmap_node))
        {
            val_free(CMAP_NODE_VAL(cmap_node), location);
            CMAP_NODE_VAL(cmap_node) = NULL_PTR;
        }
    }
    return (EC_TRUE);
}

EC_BOOL    cmap_node_free(CMAP_NODE *cmap_node, CMAP_KEY_FREE key_free, CMAP_VAL_FREE val_free, const UINT32 location)
{
    if(NULL_PTR != cmap_node)
    {
        cmap_node_clean(cmap_node, key_free, val_free, location);
        free_static_mem(MM_CMAP_NODE, cmap_node, location);
    }
    return (EC_TRUE);
}

EC_BOOL    cmap_node_mount(CMAP_NODE *cmap_node, void *key, void *val)
{
    CMAP_NODE_KEY(cmap_node) = key;
    CMAP_NODE_VAL(cmap_node) = val;
    return (EC_TRUE);
}

EC_BOOL    cmap_node_umount(CMAP_NODE *cmap_node)
{
    CMAP_NODE_KEY(cmap_node) = NULL_PTR;
    CMAP_NODE_VAL(cmap_node) = NULL_PTR;
    return (EC_TRUE);
}

EC_BOOL    cmap_node_cmp_key(const CMAP_NODE *cmap_node, const void *key, CMAP_KEY_CMP key_cmp)
{
    if(NULL_PTR != cmap_node && EC_TRUE == key_cmp(CMAP_NODE_KEY(cmap_node), key))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL    cmap_node_cmp_val(const CMAP_NODE *cmap_node, const void *val, CMAP_VAL_CMP val_cmp)
{
    if(NULL_PTR != cmap_node && EC_TRUE == val_cmp(CMAP_NODE_VAL(cmap_node), val))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL    cmap_node_clone(const CMAP_NODE *cmap_node_src, CMAP_NODE *cmap_node_des,
                                 CMAP_KEY_NEW   key_new  , CMAP_VAL_NEW   val_new,
                                 CMAP_KEY_FREE  key_free , CMAP_VAL_FREE  val_free,
                                 CMAP_KEY_CLONE key_clone, CMAP_VAL_CLONE val_clone,
                                 UINT32 location)
{
    CMAP_NODE_KEY(cmap_node_des) = key_new();
    if(NULL_PTR == CMAP_NODE_KEY(cmap_node_des))
    {
        return (EC_FALSE);
    }

    CMAP_NODE_VAL(cmap_node_des) = val_new();
    if(NULL_PTR == CMAP_NODE_VAL(cmap_node_des))
    {
        key_free(CMAP_NODE_KEY(cmap_node_des), location);
        CMAP_NODE_KEY(cmap_node_des) = NULL_PTR;
        return (EC_FALSE);
    }

    if(EC_FALSE == key_clone(CMAP_NODE_KEY(cmap_node_src), CMAP_NODE_KEY(cmap_node_des)))
    {
        key_free(CMAP_NODE_KEY(cmap_node_des), location);
        CMAP_NODE_KEY(cmap_node_des) = NULL_PTR;

        val_free(CMAP_NODE_VAL(cmap_node_des), location);
        CMAP_NODE_VAL(cmap_node_des) = NULL_PTR;

        return (EC_FALSE);
    }

    if(EC_FALSE == val_clone(CMAP_NODE_VAL(cmap_node_src), CMAP_NODE_VAL(cmap_node_des)))
    {
        key_free(CMAP_NODE_KEY(cmap_node_des), location);
        CMAP_NODE_KEY(cmap_node_des) = NULL_PTR;

        val_free(CMAP_NODE_VAL(cmap_node_des), location);
        CMAP_NODE_VAL(cmap_node_des) = NULL_PTR;

        return (EC_FALSE);
    }

    return (EC_TRUE);
}

CMAP *  cmap_new(CMAP_KEY_FREE key_free, CMAP_VAL_FREE val_free, const UINT32 location)
{
    CMAP *cmap;
    alloc_static_mem(MM_CMAP, &cmap, location);
    if(NULL_PTR != cmap)
    {
        cmap_init(cmap, key_free, val_free, location);
    }
    return (cmap);
}

EC_BOOL cmap_init(CMAP *cmap, CMAP_KEY_FREE key_free, CMAP_VAL_FREE val_free, const UINT32 location)
{
    clist_init(CMAP_NODES(cmap), MM_IGNORE, location);
    CMAP_KEY_FREE_FUNC(cmap) = key_free;
    CMAP_VAL_FREE_FUNC(cmap) = val_free;
    return (EC_TRUE);
}

EC_BOOL cmap_clean(CMAP *cmap, const UINT32 location)
{
    CLIST_DATA *clist_data;

    CLIST_LOCK(CMAP_NODES(cmap), location);
    CLIST_LOOP_NEXT(CMAP_NODES(cmap), clist_data)
    {
        CLIST_DATA *clist_data_rmv;
        CMAP_NODE *cmap_node;

        cmap_node = (CMAP_NODE *)CLIST_DATA_DATA(clist_data);
        cmap_node_free(cmap_node, CMAP_KEY_FREE_FUNC(cmap), CMAP_VAL_FREE_FUNC(cmap), location);

        clist_data_rmv = clist_data;
        clist_data = CLIST_DATA_PREV(clist_data);
        clist_rmv_no_lock(CMAP_NODES(cmap), clist_data_rmv);
    }
    CLIST_UNLOCK(CMAP_NODES(cmap), location);

    return (EC_TRUE);
}

EC_BOOL cmap_free(CMAP *cmap, const UINT32 location)
{
    if(NULL_PTR != cmap)
    {
        cmap_clean(cmap, location);
        free_static_mem(MM_CMAP, cmap, location);
    }
    return (EC_TRUE);
}

EC_BOOL cmap_add(CMAP *cmap, void *key, void *val, const UINT32 location)
{
    CMAP_NODE *cmap_node;

    cmap_node = cmap_node_new(key, val, location);
    if(NULL_PTR == cmap_node)
    {
        dbg_log(SEC_0020_CMAP, 0)(LOGSTDOUT, "error:cmap_add: new cmap_node failed\n");
        return (EC_FALSE);
    }
    clist_push_back(CMAP_NODES(cmap), (void *)cmap_node);
    return (EC_TRUE);
}

void *  cmap_get_val_by_key(const CMAP *cmap, const void *key, CMAP_KEY_CMP key_cmp)
{
    CLIST_DATA *clist_data;

    CLIST_LOCK(CMAP_NODES(cmap), LOC_CMAP_0001);
    CLIST_LOOP_NEXT(CMAP_NODES(cmap), clist_data)
    {
        CMAP_NODE *cmap_node;

        cmap_node = (CMAP_NODE *)CLIST_DATA_DATA(clist_data);
        if(NULL_PTR != cmap_node && EC_TRUE == key_cmp(CMAP_NODE_KEY(cmap_node), key))
        {
            CLIST_UNLOCK(CMAP_NODES(cmap), LOC_CMAP_0002);
            return CMAP_NODE_VAL(cmap_node);
        }
    }
    CLIST_UNLOCK(CMAP_NODES(cmap), LOC_CMAP_0003);

    return (NULL_PTR);
}

void *  cmap_get_key_by_val(const CMAP *cmap, const void *val, CMAP_VAL_CMP val_cmp)
{
    CLIST_DATA *clist_data;

    CLIST_LOCK(CMAP_NODES(cmap), LOC_CMAP_0004);
    CLIST_LOOP_NEXT(CMAP_NODES(cmap), clist_data)
    {
        CMAP_NODE *cmap_node;

        cmap_node = (CMAP_NODE *)CLIST_DATA_DATA(clist_data);
        if(NULL_PTR != cmap_node && EC_TRUE == val_cmp(CMAP_NODE_VAL(cmap_node), val))
        {
            CLIST_UNLOCK(CMAP_NODES(cmap), LOC_CMAP_0005);
            return CMAP_NODE_KEY(cmap_node);
        }
    }
    CLIST_UNLOCK(CMAP_NODES(cmap), LOC_CMAP_0006);

    return (NULL_PTR);
}

UINT32  cmap_size(const CMAP *cmap)
{
    return clist_size(CMAP_NODES(cmap));
}

EC_BOOL cmap_clone(const CMAP *cmap_src, CMAP *cmap_des,
                   CMAP_KEY_NEW   key_new  , CMAP_VAL_NEW   val_new,
                   CMAP_KEY_CLONE key_clone, CMAP_VAL_CLONE val_clone,
                   UINT32 location)
{
    CLIST_DATA  *clist_data;

    ASSERT(CMAP_KEY_FREE_FUNC(cmap_src) == CMAP_KEY_FREE_FUNC(cmap_des));
    ASSERT(CMAP_VAL_FREE_FUNC(cmap_src) == CMAP_VAL_FREE_FUNC(cmap_des));

    CLIST_LOOP_NEXT(CMAP_NODES(cmap_src), clist_data)
    {
        CMAP_NODE *cmap_node_src;
        CMAP_NODE *cmap_node_des;

        cmap_node_src = (CMAP_NODE *)CLIST_DATA_DATA(clist_data);

        cmap_node_des = cmap_node_new(NULL_PTR, NULL_PTR, location);
        if(NULL_PTR == cmap_node_des)
        {
            return (EC_FALSE);
        }

        if(EC_FALSE == cmap_node_clone(cmap_node_src, cmap_node_des,
                                        key_new, val_new,
                                        CMAP_KEY_FREE_FUNC(cmap_des), CMAP_VAL_FREE_FUNC(cmap_des),
                                        key_clone, val_clone,
                                        location))
        {
            cmap_node_free(cmap_node_des,
                            CMAP_KEY_FREE_FUNC(cmap_des), CMAP_VAL_FREE_FUNC(cmap_des),
                            location);
            return (EC_FALSE);
        }

        clist_push_back(CMAP_NODES(cmap_des), (void *)cmap_node_des);
    }

    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

