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

#ifndef _CMAP_H
#define _CMAP_H

#include "type.h"
#include "list_base.h"
#include "cstring.h"
#include "cmutex.h"

typedef EC_BOOL (*CMAP_KEY_FREE)(void *, const UINT32);
typedef EC_BOOL (*CMAP_VAL_FREE)(void *, const UINT32);

typedef EC_BOOL (*CMAP_KEY_CMP)(const void *, const void *);
typedef EC_BOOL (*CMAP_VAL_CMP)(const void *, const void *);

typedef struct
{
    void *key;
    void *val;
}CMAP_NODE;

#define CMAP_NODE_KEY(cmap_node)        ((cmap_node)->key)
#define CMAP_NODE_VAL(cmap_node)        ((cmap_node)->val)

typedef struct
{
    CLIST   nodes;/*item is CMAP_NODE*/

    EC_BOOL (*key_free)(void *, const UINT32);
    EC_BOOL (*val_free)(void *, const UINT32);
}CMAP;

#define CMAP_NODES(cmap)                (&((cmap)->nodes))
#define CMAP_KEY_FREE_FUNC(cmap)        ((cmap)->key_free)
#define CMAP_VAL_FREE_FUNC(cmap)        ((cmap)->val_free)

CMAP_NODE *cmap_node_new(void *key, void *val, const UINT32 location);
EC_BOOL    cmap_node_init(CMAP_NODE *cmap_node, void *key, void *val);
EC_BOOL    cmap_node_clean(CMAP_NODE *cmap_node, CMAP_KEY_FREE key_free, CMAP_VAL_FREE val_free, const UINT32 location);
EC_BOOL    cmap_node_free(CMAP_NODE *cmap_node, CMAP_KEY_FREE key_free, CMAP_VAL_FREE val_free, const UINT32 location);
EC_BOOL    cmap_node_mount(CMAP_NODE *cmap_node, void *key, void *val);
EC_BOOL    cmap_node_umount(CMAP_NODE *cmap_node);
EC_BOOL    cmap_node_cmp_key(const CMAP_NODE *cmap_node, const void *key, CMAP_KEY_CMP key_cmp);
EC_BOOL    cmap_node_cmp_val(const CMAP_NODE *cmap_node, const void *val, CMAP_VAL_CMP val_cmp);

CMAP *  cmap_new(CMAP_KEY_FREE key_free, CMAP_VAL_FREE val_free, const UINT32 location);
EC_BOOL cmap_init(CMAP *cmap, CMAP_KEY_FREE key_free, CMAP_VAL_FREE val_free, const UINT32 location);
EC_BOOL cmap_clean(CMAP *cmap, const UINT32 location);
EC_BOOL cmap_free(CMAP *cmap, const UINT32 location);
EC_BOOL cmap_add(CMAP *cmap, void *key, void *val, const UINT32 location);
void *  cmap_get_val_by_key(const CMAP *cmap, const void *key, CMAP_KEY_CMP key_cmp);
void *  cmap_get_key_by_val(const CMAP *cmap, const void *val, CMAP_VAL_CMP val_cmp);
UINT32  cmap_size(const CMAP *cmap);

#endif /*_CMAP_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/
