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

#include "cstring.h"
#include "cstrkv.h"

#include "cmpic.inc"

CSTRKV *cstrkv_new(const char *key, const char *val)
{
    CSTRKV *cstrkv;

    alloc_static_mem(MM_CSTRKV, &cstrkv, LOC_CSTRKV_0001);
    ASSERT(NULL_PTR != cstrkv);

    cstrkv_init(cstrkv, key, val);
    return(cstrkv);
}

EC_BOOL cstrkv_init(CSTRKV *cstrkv, const char *key, const char *val)
{
    cstring_init(CSTRKV_KEY(cstrkv), (const uint8_t *)key);
    cstring_init(CSTRKV_VAL(cstrkv), (const uint8_t *)val);

    CSTRKV_TAG(cstrkv) = CSTRKV_TAG_ERR;

    return (EC_TRUE);
}

EC_BOOL cstrkv_init_0(CSTRKV *cstrkv)
{
    cstring_init(CSTRKV_KEY(cstrkv), NULL_PTR);
    cstring_init(CSTRKV_VAL(cstrkv), NULL_PTR);

    CSTRKV_TAG(cstrkv) = CSTRKV_TAG_ERR;

    return (EC_TRUE);
}

EC_BOOL cstrkv_clean(CSTRKV *cstrkv)
{
    if(NULL_PTR != cstrkv)
    {
        cstring_clean(CSTRKV_KEY(cstrkv));
        cstring_clean(CSTRKV_VAL(cstrkv));

        CSTRKV_TAG(cstrkv) = CSTRKV_TAG_ERR;
    }

    return (EC_TRUE);
}

EC_BOOL cstrkv_free(CSTRKV *cstrkv)
{
    if (NULL_PTR != cstrkv)
    {
        cstrkv_clean(cstrkv);
        free_static_mem(MM_CSTRKV, cstrkv, LOC_CSTRKV_0002);
    }

    return (EC_TRUE);
}

EC_BOOL cstrkv_cmp(const CSTRKV *cstrkv_1, const CSTRKV *cstrkv_2)
{
    if(0 == cstring_cmp(CSTRKV_KEY(cstrkv_1), CSTRKV_KEY(cstrkv_2))
    && 0 == cstring_cmp(CSTRKV_VAL(cstrkv_1), CSTRKV_VAL(cstrkv_2)))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL cstrkv_cmp_key(const CSTRKV *cstrkv_1, const CSTRKV *cstrkv_2)
{
    if(0 == cstring_cmp(CSTRKV_KEY(cstrkv_1), CSTRKV_KEY(cstrkv_2)))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL cstrkv_cmp_val(const CSTRKV *cstrkv_1, const CSTRKV *cstrkv_2)
{
    if(0 == cstring_cmp(CSTRKV_VAL(cstrkv_1), CSTRKV_VAL(cstrkv_2)))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL cstrkv_ignore_case_cmp(const CSTRKV *cstrkv_1, const CSTRKV *cstrkv_2)
{
    if(0 == cstring_cmp_ignore_case(CSTRKV_KEY(cstrkv_1), CSTRKV_KEY(cstrkv_2))
    && 0 == cstring_cmp_ignore_case(CSTRKV_VAL(cstrkv_1), CSTRKV_VAL(cstrkv_2)))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL cstrkv_ignore_case_cmp_key(const CSTRKV *cstrkv_1, const CSTRKV *cstrkv_2)
{
    if(0 == cstring_cmp_ignore_case(CSTRKV_KEY(cstrkv_1), CSTRKV_KEY(cstrkv_2)))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL cstrkv_ignore_case_cmp_val(const CSTRKV *cstrkv_1, const CSTRKV *cstrkv_2)
{
    if(0 == cstring_cmp_ignore_case(CSTRKV_VAL(cstrkv_1), CSTRKV_VAL(cstrkv_2)))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL cstrkv_set_tag(CSTRKV *cstrkv, const UINT32 tag)
{
    CSTRKV_TAG(cstrkv) = tag;
    return (EC_TRUE);
}

EC_BOOL cstrkv_is_tag(const CSTRKV *cstrkv, const UINT32 tag)
{
    if(tag == CSTRKV_TAG(cstrkv))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL cstrkv_has_tag(const CSTRKV *cstrkv)
{
    if(CSTRKV_TAG_ERR != CSTRKV_TAG(cstrkv))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL cstrkv_set_key_str(CSTRKV *cstrkv, const char *key)
{
    cstring_append_str(CSTRKV_KEY(cstrkv), (const uint8_t *)key);
    return (EC_TRUE);
}

EC_BOOL cstrkv_set_key_bytes(CSTRKV *cstrkv, const uint8_t *key, const uint32_t key_len, const UINT32 location)
{
    cstring_append_chars(CSTRKV_KEY(cstrkv), key_len, key, location);
    return (EC_TRUE);
}

EC_BOOL cstrkv_set_val_str(CSTRKV *cstrkv, const char *val)
{
    cstring_append_str(CSTRKV_VAL(cstrkv), (const uint8_t *)val);
    return (EC_TRUE);
}

EC_BOOL cstrkv_set_val_bytes(CSTRKV *cstrkv, const uint8_t *val, const uint32_t val_len, const UINT32 location)
{
    cstring_append_chars(CSTRKV_VAL(cstrkv), val_len, val, location);
    return (EC_TRUE);
}

void cstrkv_print(LOG *log, const CSTRKV *cstrkv)
{
    sys_log(log, "cstrkv_print: ['%s'] = '%s'\n", CSTRKV_KEY_STR(cstrkv), CSTRKV_VAL_STR(cstrkv));
    return;
}

void cstrkv_print_plain(LOG *log, const CSTRKV *cstrkv)
{
    sys_print(log, "%s: %s\n", CSTRKV_KEY_STR(cstrkv), CSTRKV_VAL_STR(cstrkv));
    return;
}

CSTRKV_MGR *cstrkv_mgr_new()
{
    CSTRKV_MGR *cstrkv_mgr;

    alloc_static_mem(MM_CSTRKV_MGR, &cstrkv_mgr, LOC_CSTRKV_0003);
    ASSERT(NULL_PTR != cstrkv_mgr);

    cstrkv_mgr_init(cstrkv_mgr);
    return(cstrkv_mgr);
}

EC_BOOL cstrkv_mgr_init(CSTRKV_MGR *cstrkv_mgr)
{
    clist_init(CSTRKV_MGR_LIST(cstrkv_mgr), MM_CSTRKV, LOC_CSTRKV_0004);

    return (EC_TRUE);
}

static EC_BOOL __cstrkv_free(CSTRKV *cstrkv)/*for debug only*/
{
    return cstrkv_free(cstrkv);
}
EC_BOOL cstrkv_mgr_clean(CSTRKV_MGR *cstrkv_mgr)
{
    clist_clean(CSTRKV_MGR_LIST(cstrkv_mgr), (CLIST_DATA_DATA_CLEANER)__cstrkv_free);

    return (EC_TRUE);
}

EC_BOOL cstrkv_mgr_free(CSTRKV_MGR *cstrkv_mgr)
{
    if (NULL_PTR != cstrkv_mgr)
    {
        cstrkv_mgr_clean(cstrkv_mgr);
        free_static_mem(MM_CSTRKV_MGR, cstrkv_mgr, LOC_CSTRKV_0005);
    }

    return (EC_TRUE);
}

UINT32  cstrkv_mgr_size(const CSTRKV_MGR *cstrkv_mgr)
{
    return clist_size(CSTRKV_MGR_LIST(cstrkv_mgr));
}

EC_BOOL cstrkv_mgr_del_ignore_case(CSTRKV_MGR *cstrkv_mgr, const CSTRKV *cstrkv)
{
    CSTRKV      *cstrkv_deleted;
    
    cstrkv_deleted = clist_del(CSTRKV_MGR_LIST(cstrkv_mgr), (void *)cstrkv, (CLIST_DATA_DATA_CMP)cstrkv_ignore_case_cmp);
    if(NULL_PTR != cstrkv_deleted)
    {
        cstrkv_free(cstrkv_deleted);
    }
    return (EC_TRUE);
}

EC_BOOL cstrkv_mgr_del_key_ignore_case(CSTRKV_MGR *cstrkv_mgr, const CSTRKV *cstrkv)
{
    CSTRKV      *cstrkv_deleted;
    
    cstrkv_deleted = clist_del(CSTRKV_MGR_LIST(cstrkv_mgr), (void *)cstrkv, (CLIST_DATA_DATA_CMP)cstrkv_ignore_case_cmp_key);
    if(NULL_PTR != cstrkv_deleted)
    {
        cstrkv_free(cstrkv_deleted);
    }
    return (EC_TRUE);
}

EC_BOOL cstrkv_mgr_del(CSTRKV_MGR *cstrkv_mgr, const CSTRKV *cstrkv)
{
    CSTRKV      *cstrkv_deleted;
    
    cstrkv_deleted = clist_del(CSTRKV_MGR_LIST(cstrkv_mgr), (void *)cstrkv, (CLIST_DATA_DATA_CMP)cstrkv_cmp);
    if(NULL_PTR != cstrkv_deleted)
    {
        cstrkv_free(cstrkv_deleted);
    }
    return (EC_TRUE);
}

EC_BOOL cstrkv_mgr_del_key(CSTRKV_MGR *cstrkv_mgr, const CSTRKV *cstrkv)
{
    CSTRKV      *cstrkv_deleted;
    
    cstrkv_deleted = clist_del(CSTRKV_MGR_LIST(cstrkv_mgr), (void *)cstrkv, (CLIST_DATA_DATA_CMP)cstrkv_cmp_key);
    if(NULL_PTR != cstrkv_deleted)
    {
        cstrkv_free(cstrkv_deleted);
    }
    
    return (EC_TRUE);
}

EC_BOOL cstrkv_mgr_del_val(CSTRKV_MGR *cstrkv_mgr, const CSTRKV *cstrkv)
{
    CSTRKV      *cstrkv_deleted;
    
    cstrkv_deleted = clist_del(CSTRKV_MGR_LIST(cstrkv_mgr), (void *)cstrkv, (CLIST_DATA_DATA_CMP)cstrkv_cmp_val);
    if(NULL_PTR != cstrkv_deleted)
    {
        cstrkv_free(cstrkv_deleted);
    }
    
    return (EC_TRUE);
}

EC_BOOL cstrkv_mgr_del_kv_str(CSTRKV_MGR *cstrkv_mgr, const char *key, const char *val)
{
    CSTRKV cstrkv;

    cstring_set_str(CSTRKV_KEY(&cstrkv), (UINT8 *)key);
    cstring_set_str(CSTRKV_VAL(&cstrkv), (UINT8 *)val);
    return cstrkv_mgr_del(cstrkv_mgr, &cstrkv);
}

EC_BOOL cstrkv_mgr_del_kv_str_ignore_case(CSTRKV_MGR *cstrkv_mgr, const char *key, const char *val)
{
    CSTRKV cstrkv;

    cstring_set_str(CSTRKV_KEY(&cstrkv), (UINT8 *)key);
    cstring_set_str(CSTRKV_VAL(&cstrkv), (UINT8 *)val);
    return cstrkv_mgr_del_ignore_case(cstrkv_mgr, &cstrkv);
}

EC_BOOL cstrkv_mgr_del_key_str(CSTRKV_MGR *cstrkv_mgr, const char *key)
{
    CSTRKV cstrkv;

    cstring_set_str(CSTRKV_KEY(&cstrkv), (UINT8 *)key);
    return cstrkv_mgr_del_key(cstrkv_mgr, &cstrkv);
}

EC_BOOL cstrkv_mgr_del_key_str_ignore_case(CSTRKV_MGR *cstrkv_mgr, const char *key)
{
    CSTRKV cstrkv;

    cstring_set_str(CSTRKV_KEY(&cstrkv), (UINT8 *)key);
    return cstrkv_mgr_del_key_ignore_case(cstrkv_mgr, &cstrkv);
}

EC_BOOL cstrkv_mgr_del_val_str(CSTRKV_MGR *cstrkv_mgr, const char *val)
{
    CSTRKV cstrkv;

    cstring_set_str(CSTRKV_VAL(&cstrkv), (UINT8 *)val);
    return cstrkv_mgr_del_val(cstrkv_mgr, &cstrkv);
}

EC_BOOL cstrkv_mgr_add_kv(CSTRKV_MGR *cstrkv_mgr, const CSTRKV *cstrkv)
{
    clist_push_back(CSTRKV_MGR_LIST(cstrkv_mgr), (void *)cstrkv);
    return (EC_TRUE);
}

EC_BOOL cstrkv_mgr_add_kv_chars(CSTRKV_MGR *cstrkv_mgr, const char *key, const uint32_t klen, const char *val, const uint32_t vlen)
{
    CSTRKV *cstrkv;
 
    cstrkv = cstrkv_new(NULL_PTR, NULL_PTR);
    if(NULL_PTR == cstrkv)
    {
        dbg_log(SEC_0008_CSTRKV, 0)(LOGSTDOUT, "error:cstrkv_mgr_add_kv_chars: new cstrkv of key %.*s, val %.*s failed\n", klen, key, vlen, val);
        return (EC_FALSE);
    }

    cstring_append_chars(CSTRKV_KEY(cstrkv), klen, (const uint8_t *)key, LOC_CSTRKV_0006);
    cstring_append_chars(CSTRKV_VAL(cstrkv), vlen, (const uint8_t *)val, LOC_CSTRKV_0007);

    return cstrkv_mgr_add_kv(cstrkv_mgr, cstrkv);
}

EC_BOOL cstrkv_mgr_add_kv_str(CSTRKV_MGR *cstrkv_mgr, const char *key, const char *val)
{
    CSTRKV *cstrkv;
 
    cstrkv = cstrkv_new(key, val);
    if(NULL_PTR == cstrkv)
    {
        dbg_log(SEC_0008_CSTRKV, 0)(LOGSTDOUT, "error:cstrkv_mgr_add_kv_str: new cstrkv of key %s, val %s failed\n", key, val);
        return (EC_FALSE);
    }

    return cstrkv_mgr_add_kv(cstrkv_mgr, cstrkv);
}

CSTRING *cstrkv_mgr_get_val_cstr(const CSTRKV_MGR *cstrkv_mgr, const char *key)
{
    CLIST_DATA *clist_data;
    CSTRING     key_cstr;

    cstring_set_str(&key_cstr, (const UINT8 *)key);

    CLIST_LOOP_NEXT(CSTRKV_MGR_LIST(cstrkv_mgr), clist_data)
    {
        CSTRKV *cstrkv;

        cstrkv = (CSTRKV *)CLIST_DATA_DATA(clist_data);
        if(EC_TRUE == cstring_is_equal(CSTRKV_KEY(cstrkv), &key_cstr))
        {
            return ((CSTRING *)CSTRKV_VAL(cstrkv));
        }
    }

    return (NULL_PTR);
}

CSTRING *cstrkv_mgr_get_val_cstr_ignore_case(const CSTRKV_MGR *cstrkv_mgr, const char *key)
{
    CLIST_DATA *clist_data;

    CLIST_LOOP_NEXT(CSTRKV_MGR_LIST(cstrkv_mgr), clist_data)
    {
        CSTRKV *cstrkv;

        cstrkv = (CSTRKV *)CLIST_DATA_DATA(clist_data);
        if(EC_TRUE == cstring_is_str_ignore_case(CSTRKV_KEY(cstrkv), (uint8_t *)key))
        {
            return ((CSTRING *)CSTRKV_VAL(cstrkv));
        }
    }

    return (NULL_PTR);
}

char *cstrkv_mgr_get_val_str(const CSTRKV_MGR *cstrkv_mgr, const char *key)
{
    CLIST_DATA *clist_data;
    CSTRING     key_cstr;

    cstring_set_str(&key_cstr, (const UINT8 *)key);

    CLIST_LOOP_NEXT(CSTRKV_MGR_LIST(cstrkv_mgr), clist_data)
    {
        CSTRKV *cstrkv;

        cstrkv = (CSTRKV *)CLIST_DATA_DATA(clist_data);
        if(EC_TRUE == cstring_is_equal(CSTRKV_KEY(cstrkv), &key_cstr))
        {
            return ((char *)CSTRKV_VAL_STR(cstrkv));
        }
    }

    return (NULL_PTR);
}

char *cstrkv_mgr_get_val_str_ignore_case(const CSTRKV_MGR *cstrkv_mgr, const char *key)
{
    CLIST_DATA *clist_data;

    CLIST_LOOP_NEXT(CSTRKV_MGR_LIST(cstrkv_mgr), clist_data)
    {
        CSTRKV *cstrkv;

        cstrkv = (CSTRKV *)CLIST_DATA_DATA(clist_data);
        if(EC_TRUE == cstring_is_str_ignore_case(CSTRKV_KEY(cstrkv), (UINT8 *)key))
        {
            return ((char *)CSTRKV_VAL_STR(cstrkv));
        }
    }

    return (NULL_PTR);
}

EC_BOOL cstrkv_mgr_exist_kv_ignore_case(const CSTRKV_MGR *cstrkv_mgr, const char *key, const char *val)
{
    char *v;

    v = cstrkv_mgr_get_val_str_ignore_case(cstrkv_mgr, key);
    if(NULL_PTR == v)
    {
        return (EC_FALSE);
    }

    if(NULL_PTR == val || 0 == STRCASECMP(val, v))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

CSTRING *cstrkv_mgr_fetch_key_cstr(const CSTRKV_MGR *cstrkv_mgr, const char *val)
{
    CLIST_DATA *clist_data;
    CSTRING     val_cstr;

    cstring_set_str(&val_cstr, (const UINT8 *)val);

    CLIST_LOOP_NEXT(CSTRKV_MGR_LIST(cstrkv_mgr), clist_data)
    {
        CSTRKV *cstrkv;

        cstrkv = (CSTRKV *)CLIST_DATA_DATA(clist_data);
        if(EC_TRUE == cstring_is_equal(CSTRKV_VAL(cstrkv), &val_cstr))
        {
            return ((CSTRING *)CSTRKV_KEY(cstrkv));
        }
    }

    return (NULL_PTR);
}

char *cstrkv_mgr_fetch_key_str(const CSTRKV_MGR *cstrkv_mgr, const char *val)
{
    CLIST_DATA *clist_data;
    CSTRING     val_cstr;

    cstring_set_str(&val_cstr, (const UINT8 *)val);

    CLIST_LOOP_NEXT(CSTRKV_MGR_LIST(cstrkv_mgr), clist_data)
    {
        CSTRKV *cstrkv;

        cstrkv = (CSTRKV *)CLIST_DATA_DATA(clist_data);
        if(EC_TRUE == cstring_is_equal(CSTRKV_VAL(cstrkv), &val_cstr))
        {
            return ((char *)CSTRKV_KEY_STR(cstrkv));
        }
    }

    return (NULL_PTR);
}

EC_BOOL cstrkv_mgr_exist_key(const CSTRKV_MGR *cstrkv_mgr, const char *key)
{
    CLIST_DATA *clist_data;
    CSTRING     key_cstr;

    cstring_set_str(&key_cstr, (const UINT8 *)key);

    CLIST_LOOP_NEXT(CSTRKV_MGR_LIST(cstrkv_mgr), clist_data)
    {
        CSTRKV *cstrkv;

        cstrkv = (CSTRKV *)CLIST_DATA_DATA(clist_data);
        if(EC_TRUE == cstring_is_equal(CSTRKV_KEY(cstrkv), &key_cstr))
        {
            return (EC_TRUE);
        }
    }

    return (EC_FALSE);
}


EC_BOOL cstrkv_mgr_exist_val(const CSTRKV_MGR *cstrkv_mgr, const char *val)
{
    CLIST_DATA *clist_data;
    CSTRING     val_cstr;

    cstring_set_str(&val_cstr, (const UINT8 *)val);

    CLIST_LOOP_NEXT(CSTRKV_MGR_LIST(cstrkv_mgr), clist_data)
    {
        CSTRKV *cstrkv;

        cstrkv = (CSTRKV *)CLIST_DATA_DATA(clist_data);
        if(EC_TRUE == cstring_is_equal(CSTRKV_VAL(cstrkv), &val_cstr))
        {
            return (EC_TRUE);
        }
    }

    return (EC_FALSE);
}

EC_BOOL cstrkv_mgr_exist_kv(const CSTRKV_MGR *cstrkv_mgr, const char *key, const char *val)
{
    char *v;

    v = cstrkv_mgr_get_val_str(cstrkv_mgr, key);
    if(NULL_PTR == v)
    {
        return (EC_FALSE);
    }

    if(NULL_PTR == val || 0 == STRCMP(val, v))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL cstrkv_mgr_merge_duplication(CSTRKV_MGR *cstrkv_mgr)
{
    CSTRKV_MGR        cstrkv_mgr_t;
    CSTRKV           *cstrkv;

    cstrkv_mgr_init(&cstrkv_mgr_t);
    cstrkv_mgr_handover(cstrkv_mgr, &cstrkv_mgr_t);

    while(NULL_PTR != (cstrkv = clist_pop_front(CSTRKV_MGR_LIST(&cstrkv_mgr_t))))
    {
        CSTRING     *v;

        /*search by k*/
        v = cstrkv_mgr_get_val_cstr_ignore_case(cstrkv_mgr, (char *)CSTRKV_KEY_STR(cstrkv));
        if(NULL_PTR == v)
        {
            clist_push_back(CSTRKV_MGR_LIST(cstrkv_mgr), (void *)cstrkv);
            continue;
        }

        /*compare v*/
        if(EC_FALSE == cstring_is_equal_ignore_case(v, CSTRKV_VAL(cstrkv)))
        {
            /*same k and different v => merge  */
            cstring_append_str(v, (UINT8 *)", ");
            cstring_append_cstr(v, CSTRKV_VAL(cstrkv));

            cstrkv_free(cstrkv);
        }
        else
        {
            /*same k and same v      => discard*/
            cstrkv_free(cstrkv);
        }
    }

    cstrkv_mgr_clean(&cstrkv_mgr_t);
    return (EC_TRUE);
}

CSTRKV *cstrkv_mgr_last_kv(const CSTRKV_MGR *cstrkv_mgr)
{
    return (CSTRKV *)clist_back(CSTRKV_MGR_LIST(cstrkv_mgr));
}

CSTRKV *cstrkv_mgr_first_kv(const CSTRKV_MGR *cstrkv_mgr)
{
    return (CSTRKV *)clist_front(CSTRKV_MGR_LIST(cstrkv_mgr));
}

EC_BOOL cstrkv_mgr_handover(CSTRKV_MGR *cstrkv_mgr_src, CSTRKV_MGR *cstrkv_mgr_des)
{
    clist_handover(CSTRKV_MGR_LIST(cstrkv_mgr_src), CSTRKV_MGR_LIST(cstrkv_mgr_des));
    return (EC_TRUE);
}

void cstrkv_mgr_print(LOG *log, const CSTRKV_MGR *cstrkv_mgr)
{
    CLIST_DATA *clist_data;

    CLIST_LOOP_NEXT(CSTRKV_MGR_LIST(cstrkv_mgr), clist_data)
    {
        CSTRKV *cstrkv;

        cstrkv = (CSTRKV *)CLIST_DATA_DATA(clist_data);
        cstrkv_print(log, cstrkv);
    }

    return;
}

void cstrkv_mgr_print_plain(LOG *log, const CSTRKV_MGR *cstrkv_mgr)
{
    CLIST_DATA *clist_data;

    CLIST_LOOP_NEXT(CSTRKV_MGR_LIST(cstrkv_mgr), clist_data)
    {
        CSTRKV *cstrkv;

        cstrkv = (CSTRKV *)CLIST_DATA_DATA(clist_data);
        cstrkv_print_plain(log, cstrkv);
    }

    return;
}

EC_BOOL cstrkv_mgr_walk(const CSTRKV_MGR *cstrkv_mgr, void *data, EC_BOOL (*walker)(void *, const CSTRKV *))
{
    CLIST_DATA *clist_data;

    CLIST_LOOP_NEXT(CSTRKV_MGR_LIST(cstrkv_mgr), clist_data)
    {
        CSTRKV *cstrkv;

        cstrkv = (CSTRKV *)CLIST_DATA_DATA(clist_data);
        if(EC_FALSE == walker(data, cstrkv))
        {
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

static EC_BOOL __cstrkv_mgr_clone_cstrkv(CSTRKV_MGR *cstrkv_mgr, const CSTRKV *cstrkv_src)
{
    CSTRKV *cstrkv_des;

    cstrkv_des = cstrkv_new((char *)CSTRKV_KEY_STR(cstrkv_src), (char *)CSTRKV_VAL_STR(cstrkv_src));
    if(NULL_PTR == cstrkv_des)
    {
        return (EC_FALSE);
    }

    return cstrkv_mgr_add_kv(cstrkv_mgr, cstrkv_des);
}

EC_BOOL cstrkv_mgr_clone(const CSTRKV_MGR *cstrkv_mgr_src, CSTRKV_MGR *cstrkv_mgr_des)
{
    return cstrkv_mgr_walk(cstrkv_mgr_src, (void *)cstrkv_mgr_des, (CSTRKV_MGR_WALKER)__cstrkv_mgr_clone_cstrkv);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

