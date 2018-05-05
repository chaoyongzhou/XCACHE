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

#ifndef _CHASHNODE_H
#define _CHASHNODE_H

#include "type.h"
#include "log.h"
#include "clist.h"

typedef struct
{
    UINT32 klen;
    UINT32 vlen;

    UINT8 *key;
    UINT8 *value;
}CHASH_NODE;

#define CHASH_NODE_KLEN(chash_node)     ((chash_node)->klen)
#define CHASH_NODE_VLEN(chash_node)     ((chash_node)->vlen)
#define CHASH_NODE_KEY(chash_node)      ((chash_node)->key)
#define CHASH_NODE_VALUE(chash_node)    ((chash_node)->value)

CHASH_NODE *chash_node_new(const UINT32 klen, const UINT32 vlen, const UINT8 *key, const UINT8 *value);

EC_BOOL chash_node_init(CHASH_NODE *chash_node, const UINT32 klen, const UINT32 vlen, const UINT8 *key, const UINT8 *value);

EC_BOOL chash_node_clean(CHASH_NODE *chash_node);

EC_BOOL chash_node_free(CHASH_NODE *chash_node);

void chash_node_print(LOG *log, const CHASH_NODE *chash_node);

CLIST *chash_list_new();

EC_BOOL chash_list_init(CLIST *chash_list);

EC_BOOL chash_list_clean(CLIST *chash_list);

EC_BOOL chash_list_free(CLIST *chash_list);

EC_BOOL chash_list_update(CLIST *chash_list, const UINT32 klen, const UINT32 vlen, const UINT8 *key, const UINT8 *value, int (*key_compare_func)(const UINT32, const UINT32, const UINT8 *, const UINT8 *));

EC_BOOL chash_list_append(CLIST *chash_list, const UINT32 klen, const UINT32 vlen, const UINT8 *key, const UINT8 *value);

EC_BOOL chash_list_remove(CLIST *chash_list, const UINT32 klen, const UINT8 *key, int (*key_compare_func)(const UINT32, const UINT32, const UINT8 *, const UINT8 *));

EC_BOOL chash_list_fetch(CLIST *chash_list, const UINT32 klen, const UINT8 *key, UINT32 *vlen, UINT8 **value, int (*key_compare_func)(const UINT32, const UINT32, const UINT8 *, const UINT8 *));

void chash_list_print(LOG *log, const CLIST *chash_list);

#endif /*_CHASHNODE_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

