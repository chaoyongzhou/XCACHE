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

#ifndef _CHASHVEC_H
#define _CHASHVEC_H

#include "type.h"
#include "log.h"
#include "chashnode.h"

typedef UINT32 (*HASH_COMPUTE_FUNC)(const UINT32, const UINT8 *);
typedef int    (*KEY_COMPARE_FUNC)(const UINT32, const UINT32, const UINT8 *, const UINT8 *);

typedef struct
{
    HASH_COMPUTE_FUNC  hash_compute_func;
    KEY_COMPARE_FUNC   key_compare_func;

    UINT32   hash_size;

    CVECTOR  hash_list_vec;
}CHASH_VEC;

#define CHASH_VEC_HASH_COMPUTE_FUNC(chash_vec)    ((chash_vec)->hash_compute_func)
#define CHASH_VEC_KEY_COMPARE_FUNC(chash_vec)     ((chash_vec)->key_compare_func)
#define CHASH_VEC_HASH_SIZE(chash_vec)            ((chash_vec)->hash_size)
#define CHASH_VEC_HASH_LIST_VEC(chash_vec)        (&((chash_vec)->hash_list_vec))

CHASH_VEC *chash_vec_new(HASH_COMPUTE_FUNC hash_compute_func, KEY_COMPARE_FUNC key_compare_func, const UINT32 hash_size);

EC_BOOL chash_vec_init(CHASH_VEC *chash_vec, HASH_COMPUTE_FUNC hash_compute_func, KEY_COMPARE_FUNC key_compare_func, const UINT32 hash_size);

EC_BOOL chash_vec_clean(CHASH_VEC *chash_vec);

EC_BOOL chash_vec_free(CHASH_VEC *chash_vec);

EC_BOOL chash_vec_insert(CHASH_VEC *chash_vec, const UINT32 klen, const UINT32 vlen, const UINT8 *key, const UINT8 *value);

EC_BOOL chash_vec_remove(CHASH_VEC *chash_vec, const UINT32 klen, const UINT8 *key);

EC_BOOL chash_vec_fetch(CHASH_VEC *chash_vec, const UINT32 klen, const UINT8 *key, UINT32 *vlen, UINT8 **value);

void chash_vec_print(LOG *log, const CHASH_VEC *chash_vec);


#endif /*_CHASHVEC_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

