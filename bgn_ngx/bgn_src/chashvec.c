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
#include "chashvec.h"

CHASH_VEC *chash_vec_new(HASH_COMPUTE_FUNC hash_compute_func, KEY_COMPARE_FUNC key_compare_func, const UINT32 hash_size)
{
    CHASH_VEC *chash_vec;

    alloc_static_mem(MM_CHASH_VEC, &chash_vec, LOC_CHASHVEC_0001);
    chash_vec_init(chash_vec, hash_compute_func, key_compare_func, hash_size);

    return (chash_vec);
}

EC_BOOL chash_vec_init(CHASH_VEC *chash_vec, HASH_COMPUTE_FUNC hash_compute_func, KEY_COMPARE_FUNC key_compare_func, const UINT32 hash_size)
{
    UINT32 chash_list_pos;

    CHASH_VEC_HASH_COMPUTE_FUNC(chash_vec) = hash_compute_func;
    CHASH_VEC_KEY_COMPARE_FUNC(chash_vec)  = key_compare_func;
    CHASH_VEC_HASH_SIZE(chash_vec) = hash_size;

    cvector_init(CHASH_VEC_HASH_LIST_VEC(chash_vec), hash_size, MM_CLIST, CVECTOR_LOCK_ENABLE, LOC_CHASHVEC_0002);
    for(chash_list_pos = 0; chash_list_pos < hash_size; chash_list_pos ++)
    {
        CLIST *chash_list;

        alloc_static_mem(MM_CLIST, &chash_list, LOC_CHASHVEC_0003);
        chash_list_init(chash_list);

        cvector_push(CHASH_VEC_HASH_LIST_VEC(chash_vec), (void *)chash_list);
    }

    return (EC_TRUE);
}

EC_BOOL chash_vec_clean(CHASH_VEC *chash_vec)
{
    cvector_clean(CHASH_VEC_HASH_LIST_VEC(chash_vec), (CVECTOR_DATA_CLEANER)chash_list_free, LOC_CHASHVEC_0004);

    CHASH_VEC_HASH_COMPUTE_FUNC(chash_vec) = NULL_PTR;
    CHASH_VEC_KEY_COMPARE_FUNC(chash_vec)  = NULL_PTR;
    CHASH_VEC_HASH_SIZE(chash_vec) = 0;

    return (EC_TRUE);
}

EC_BOOL chash_vec_free(CHASH_VEC *chash_vec)
{
    chash_vec_clean(chash_vec);
    free_static_mem(MM_CHASH_VEC, chash_vec, LOC_CHASHVEC_0005);
    return (EC_TRUE);
}


EC_BOOL chash_vec_insert(CHASH_VEC *chash_vec, const UINT32 klen, const UINT32 vlen, const UINT8 *key, const UINT8 *value)
{
    UINT32 chash_list_pos;
    CLIST *chash_list;

    chash_list_pos = (CHASH_VEC_HASH_COMPUTE_FUNC(chash_vec)(klen, key) % CHASH_VEC_HASH_SIZE(chash_vec));
    chash_list = (CLIST *)cvector_get(CHASH_VEC_HASH_LIST_VEC(chash_vec), chash_list_pos);
    if(NULL == chash_list)
    {
        dbg_log(SEC_0115_CHASHVEC, 0)(LOGSTDOUT, "error:chash_vec_insert: chash list at pos %ld is null\n", chash_list_pos);
        return (EC_FALSE);
    }

    if(EC_FALSE == chash_list_update(chash_list, klen, vlen, key, value, CHASH_VEC_KEY_COMPARE_FUNC(chash_vec)))
    {
        chash_list_append(chash_list, klen, vlen, key, value);
    }

    return (EC_TRUE);
}

EC_BOOL chash_vec_remove(CHASH_VEC *chash_vec, const UINT32 klen, const UINT8 *key)
{
    UINT32 chash_list_pos;
    CLIST *chash_list;

    chash_list_pos = (CHASH_VEC_HASH_COMPUTE_FUNC(chash_vec)(klen, key) % CHASH_VEC_HASH_SIZE(chash_vec));
    chash_list = (CLIST *)cvector_get(CHASH_VEC_HASH_LIST_VEC(chash_vec), chash_list_pos);
    if(NULL == chash_list)
    {
        dbg_log(SEC_0115_CHASHVEC, 0)(LOGSTDOUT, "error:chash_vec_remove: chash list at pos %ld is null\n", chash_list_pos);
        return (EC_FALSE);
    }

    return chash_list_remove(chash_list, klen, key, CHASH_VEC_KEY_COMPARE_FUNC(chash_vec));
}

EC_BOOL chash_vec_fetch(CHASH_VEC *chash_vec, const UINT32 klen, const UINT8 *key, UINT32 *vlen, UINT8 **value)
{
    UINT32 chash_list_pos;
    CLIST *chash_list;

    chash_list_pos = (CHASH_VEC_HASH_COMPUTE_FUNC(chash_vec)(klen, key) % CHASH_VEC_HASH_SIZE(chash_vec));
    chash_list = (CLIST *)cvector_get(CHASH_VEC_HASH_LIST_VEC(chash_vec), chash_list_pos);
    if(NULL == chash_list)
    {
        dbg_log(SEC_0115_CHASHVEC, 0)(LOGSTDOUT, "error:chash_vec_fetch: chash list at pos %ld is null\n", chash_list_pos);
        return (EC_FALSE);
    }

    return chash_list_fetch(chash_list, klen, key, vlen, value, CHASH_VEC_KEY_COMPARE_FUNC(chash_vec));
}

void chash_vec_print(LOG *log, const CHASH_VEC *chash_vec)
{
    cvector_print(log, CHASH_VEC_HASH_LIST_VEC(chash_vec), (CVECTOR_DATA_PRINT)chash_list_print);
    return;
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

