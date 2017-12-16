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
#include "cmpic.inc"

#include "clist.h"
#include "chashnode.h"

CHASH_NODE *chash_node_new(const UINT32 klen, const UINT32 vlen, const UINT8 *key, const UINT8 *value)
{
    CHASH_NODE *chash_node;

    alloc_static_mem(MM_CHASH_NODE, &chash_node, LOC_CHASHNODE_0001);
    chash_node_init(chash_node, klen, vlen, key, value);

    return (chash_node);
}

EC_BOOL chash_node_init(CHASH_NODE *chash_node, const UINT32 klen, const UINT32 vlen, const UINT8 *key, const UINT8 *value)
{
    CHASH_NODE_KLEN(chash_node)  = klen;
    CHASH_NODE_VLEN(chash_node)  = vlen;
    CHASH_NODE_KEY(chash_node)   = (UINT8 *)key;
    CHASH_NODE_VALUE(chash_node) = (UINT8 *)value;

    return (EC_TRUE);
}

EC_BOOL chash_node_clean(CHASH_NODE *chash_node)
{
    CHASH_NODE_KLEN(chash_node)  = 0;
    CHASH_NODE_VLEN(chash_node)  = 0;
    CHASH_NODE_KEY(chash_node)   = NULL_PTR;
    CHASH_NODE_VALUE(chash_node) = NULL_PTR;

    return (EC_TRUE);
}

EC_BOOL chash_node_free(CHASH_NODE *chash_node)
{
    chash_node_clean(chash_node);
    free_static_mem(MM_CHASH_NODE, chash_node, LOC_CHASHNODE_0002);
    return (EC_TRUE);
}

void chash_node_print(LOG *log, const CHASH_NODE *chash_node)
{
    UINT32 kpos;
    UINT32 vpos;

    sys_log(log, "chash_node %lx: key = ", chash_node);
    for(kpos = 0; kpos < CHASH_NODE_KLEN(chash_node); kpos ++)
    {
        sys_print(log, "%02x", CHASH_NODE_KEY(chash_node)[ kpos ]);
    }
    sys_print(log, "\n");

    sys_log(log, "chash_node %lx: value = ", chash_node);
    for(vpos = 0; vpos < CHASH_NODE_VLEN(chash_node); vpos ++)
    {
        sys_print(log, "%02x", CHASH_NODE_VALUE(chash_node)[ vpos ]);
    }
    sys_print(log, "\n");

    return;
}

CLIST *chash_list_new()
{
    CLIST *chash_list;

    alloc_static_mem(MM_CLIST, &chash_list, LOC_CHASHNODE_0003);
    chash_list_init(chash_list);
    return (chash_list);
}

EC_BOOL chash_list_init(CLIST *chash_list)
{
    clist_init(chash_list, MM_IGNORE, LOC_CHASHNODE_0004);
    return (EC_TRUE);
}

EC_BOOL chash_list_clean(CLIST *chash_list)
{
    clist_clean(chash_list, (CLIST_DATA_DATA_CLEANER)chash_node_free);
    return (EC_TRUE);
}

EC_BOOL chash_list_free(CLIST *chash_list)
{
    chash_list_clean(chash_list);
    free_static_mem(MM_CLIST, chash_list, LOC_CHASHNODE_0005);
    return (EC_TRUE);
}

EC_BOOL chash_list_update(CLIST *chash_list, const UINT32 klen, const UINT32 vlen, const UINT8 *key, const UINT8 *value, int (*key_compare_func)(const UINT32, const UINT32, const UINT8 *, const UINT8 *))
{
    CLIST_DATA *clist_data;

    CLIST_LOCK(chash_list, LOC_CHASHNODE_0006);
    CLIST_LOOP_NEXT(chash_list, clist_data)
    {
        CHASH_NODE *chash_node;

        chash_node = (CHASH_NODE *)CLIST_DATA_DATA(clist_data);
        if(0 == key_compare_func(CHASH_NODE_KLEN(chash_node), klen, CHASH_NODE_KEY(chash_node), key))
        {
            CHASH_NODE_VALUE(chash_node) = (UINT8 *)value;
            CHASH_NODE_VLEN(chash_node)  = vlen;

            CLIST_UNLOCK(chash_list, LOC_CHASHNODE_0007);
            return (EC_TRUE);
        }
    }
    CLIST_UNLOCK(chash_list, LOC_CHASHNODE_0008);
    return (EC_FALSE);
}

EC_BOOL chash_list_append(CLIST *chash_list, const UINT32 klen, const UINT32 vlen, const UINT8 *key, const UINT8 *value)
{
    CHASH_NODE *chash_node;

    chash_node = chash_node_new(klen, vlen, key, value);
    clist_push_back(chash_list, (void *)chash_node);
    return (EC_TRUE);
}

EC_BOOL chash_list_remove(CLIST *chash_list, const UINT32 klen, const UINT8 *key, int (*key_compare_func)(const UINT32, const UINT32, const UINT8 *, const UINT8 *))
{
    CLIST_DATA *clist_data;

    CLIST_LOCK(chash_list, LOC_CHASHNODE_0009);
    CLIST_LOOP_NEXT(chash_list, clist_data)
    {
        CHASH_NODE *chash_node;

        chash_node = (CHASH_NODE *)CLIST_DATA_DATA(clist_data);
        if(0 == key_compare_func(CHASH_NODE_KLEN(chash_node), klen, CHASH_NODE_KEY(chash_node), key))
        {
            clist_erase_no_lock(chash_list, clist_data);
            chash_node_free(chash_node);

            CLIST_UNLOCK(chash_list, LOC_CHASHNODE_0010);
            return (EC_TRUE);
        }
    }
    CLIST_UNLOCK(chash_list, LOC_CHASHNODE_0011);
    return (EC_FALSE);
}

EC_BOOL chash_list_fetch(CLIST *chash_list, const UINT32 klen, const UINT8 *key, UINT32 *vlen, UINT8 **value, int (*key_compare_func)(const UINT32, const UINT32, const UINT8 *, const UINT8 *))
{
    CLIST_DATA *clist_data;

    CLIST_LOCK(chash_list, LOC_CHASHNODE_0012);
    CLIST_LOOP_NEXT(chash_list, clist_data)
    {
        CHASH_NODE *chash_node;

        chash_node = (CHASH_NODE *)CLIST_DATA_DATA(clist_data);
        if(0 == key_compare_func(CHASH_NODE_KLEN(chash_node), klen, CHASH_NODE_KEY(chash_node), key))
        {
            (*value) = CHASH_NODE_VALUE(chash_node);
            (*vlen)  = CHASH_NODE_VLEN(chash_node);

            CLIST_UNLOCK(chash_list, LOC_CHASHNODE_0013);
            return (EC_TRUE);
        }
    }
    CLIST_UNLOCK(chash_list, LOC_CHASHNODE_0014);
    return (EC_FALSE);
}

void chash_list_print(LOG *log, const CLIST *chash_list)
{
    clist_print(log, chash_list, (CLIST_DATA_DATA_PRINT)chash_node_print);
    return;
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

