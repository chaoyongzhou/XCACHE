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

#ifndef _CSTRKV_H
#define _CSTRKV_H

#include "type.h"
#include "mm.h"
#include "log.h"

#include "clist.h"

#include "cstring.h"

#define CSTRKV_TAG_ERR          ((UINT32)-1)

typedef struct
{
    CSTRING  key;
    CSTRING  val;

    UINT32   tag; /*extra part. patch when merge http headers. generally no useful!*/
}CSTRKV;

#define CSTRKV_KEY(cstrkv)      (&((cstrkv)->key))
#define CSTRKV_VAL(cstrkv)      (&((cstrkv)->val))
#define CSTRKV_TAG(cstrkv)      ((cstrkv)->tag)

#define CSTRKV_KEY_STR(cstrkv)  (cstring_get_str(CSTRKV_KEY(cstrkv)))
#define CSTRKV_VAL_STR(cstrkv)  (cstring_get_str(CSTRKV_VAL(cstrkv)))

#define CSTRKV_KEY_LEN(cstrkv)  (cstring_get_len(CSTRKV_KEY(cstrkv)))
#define CSTRKV_VAL_LEN(cstrkv)  (cstring_get_len(CSTRKV_VAL(cstrkv)))

typedef struct
{
    CLIST    kv_list;
}CSTRKV_MGR;

#define CSTRKV_MGR_LIST(cstrkv_mgr)         (&((cstrkv_mgr)->kv_list))

typedef EC_BOOL ( *CSTRKV_MGR_WALKER)(void *, const CSTRKV *);

CSTRKV *cstrkv_new(const char *key, const char *val);

EC_BOOL cstrkv_init(CSTRKV *cstrkv, const char *key, const char *val); 

EC_BOOL cstrkv_init_0(CSTRKV *cstrkv);

EC_BOOL cstrkv_clean(CSTRKV *cstrkv); 

EC_BOOL cstrkv_free(CSTRKV *cstrkv); 

EC_BOOL cstrkv_cmp(const CSTRKV *cstrkv_1, const CSTRKV *cstrkv_2);

EC_BOOL cstrkv_cmp_key(const CSTRKV *cstrkv_1, const CSTRKV *cstrkv_2);

EC_BOOL cstrkv_cmp_val(const CSTRKV *cstrkv_1, const CSTRKV *cstrkv_2);

EC_BOOL cstrkv_ignore_case_cmp(const CSTRKV *cstrkv_1, const CSTRKV *cstrkv_2);

EC_BOOL cstrkv_ignore_case_cmp_key(const CSTRKV *cstrkv_1, const CSTRKV *cstrkv_2);

EC_BOOL cstrkv_ignore_case_cmp_val(const CSTRKV *cstrkv_1, const CSTRKV *cstrkv_2);

EC_BOOL cstrkv_set_tag(CSTRKV *cstrkv, const UINT32 tag);

EC_BOOL cstrkv_is_tag(const CSTRKV *cstrkv, const UINT32 tag);

EC_BOOL cstrkv_has_tag(const CSTRKV *cstrkv);

EC_BOOL cstrkv_set_key_str(CSTRKV *cstrkv, const char *key);

EC_BOOL cstrkv_set_key_bytes(CSTRKV *cstrkv, const uint8_t *key, const uint32_t key_len);

EC_BOOL cstrkv_set_val_str(CSTRKV *cstrkv, const char *val);

EC_BOOL cstrkv_set_val_bytes(CSTRKV *cstrkv, const uint8_t *val, const uint32_t val_len);

void cstrkv_print(LOG *log, const CSTRKV *cstrkv);

void cstrkv_print_plain(LOG *log, const CSTRKV *cstrkv);

CSTRKV_MGR *cstrkv_mgr_new();

EC_BOOL cstrkv_mgr_init(CSTRKV_MGR *cstrkv_mgr); 

EC_BOOL cstrkv_mgr_clean(CSTRKV_MGR *cstrkv_mgr); 

EC_BOOL cstrkv_mgr_free(CSTRKV_MGR *cstrkv_mgr); 

UINT32  cstrkv_mgr_size(const CSTRKV_MGR *cstrkv_mgr);

EC_BOOL cstrkv_mgr_del(CSTRKV_MGR *cstrkv_mgr, const CSTRKV *cstrkv);
EC_BOOL cstrkv_mgr_del_key(CSTRKV_MGR *cstrkv_mgr, const CSTRKV *cstrkv);
EC_BOOL cstrkv_mgr_del_val(CSTRKV_MGR *cstrkv_mgr, const CSTRKV *cstrkv);

EC_BOOL cstrkv_mgr_del_ignore_case(CSTRKV_MGR *cstrkv_mgr, const CSTRKV *cstrkv);
EC_BOOL cstrkv_mgr_del_key_ignore_case(CSTRKV_MGR *cstrkv_mgr, const CSTRKV *cstrkv);
EC_BOOL cstrkv_mgr_del_key_str_ignore_case(CSTRKV_MGR *cstrkv_mgr, const char *key);

EC_BOOL cstrkv_mgr_del_kv_str(CSTRKV_MGR *cstrkv_mgr, const char *key, const char *val);
EC_BOOL cstrkv_mgr_del_kv_str_ignore_case(CSTRKV_MGR *cstrkv_mgr, const char *key, const char *val);

EC_BOOL cstrkv_mgr_del_key_str(CSTRKV_MGR *cstrkv_mgr, const char *key);
EC_BOOL cstrkv_mgr_del_val_str(CSTRKV_MGR *cstrkv_mgr, const char *val);

EC_BOOL cstrkv_mgr_add_kv(CSTRKV_MGR *cstrkv_mgr, const CSTRKV *cstrkv);

EC_BOOL cstrkv_mgr_add_kv_chars(CSTRKV_MGR *cstrkv_mgr, const char *key, const uint32_t klen, const char *val, const uint32_t vlen);

EC_BOOL cstrkv_mgr_add_kv_str(CSTRKV_MGR *cstrkv_mgr, const char *key, const char *val);

CSTRING *cstrkv_mgr_get_val_cstr(const CSTRKV_MGR *cstrkv_mgr, const char *key);

CSTRING *cstrkv_mgr_get_val_cstr_ignore_case(const CSTRKV_MGR *cstrkv_mgr, const char *key);

char *cstrkv_mgr_get_val_str(const CSTRKV_MGR *cstrkv_mgr, const char *key);

char *cstrkv_mgr_get_val_str_ignore_case(const CSTRKV_MGR *cstrkv_mgr, const char *key);

EC_BOOL cstrkv_mgr_exist_kv_ignore_case(const CSTRKV_MGR *cstrkv_mgr, const char *key, const char *val);

CSTRING *cstrkv_mgr_fetch_key_cstr(const CSTRKV_MGR *cstrkv_mgr, const char *val);

char *cstrkv_mgr_fetch_key_str(const CSTRKV_MGR *cstrkv_mgr, const char *val);

EC_BOOL cstrkv_mgr_exist_key(const CSTRKV_MGR *cstrkv_mgr, const char *key);

EC_BOOL cstrkv_mgr_exist_val(const CSTRKV_MGR *cstrkv_mgr, const char *val);

EC_BOOL cstrkv_mgr_exist_kv(const CSTRKV_MGR *cstrkv_mgr, const char *key, const char *val);

EC_BOOL cstrkv_mgr_merge_duplication(CSTRKV_MGR *cstrkv_mgr);

CSTRKV *cstrkv_mgr_last_kv(const CSTRKV_MGR *cstrkv_mgr);

CSTRKV *cstrkv_mgr_first_kv(const CSTRKV_MGR *cstrkv_mgr);

EC_BOOL cstrkv_mgr_handover(CSTRKV_MGR *cstrkv_mgr_src, CSTRKV_MGR *cstrkv_mgr_des);

void cstrkv_mgr_print(LOG *log, const CSTRKV_MGR *cstrkv_mgr);

void cstrkv_mgr_print_plain(LOG *log, const CSTRKV_MGR *cstrkv_mgr);

EC_BOOL cstrkv_mgr_walk(const CSTRKV_MGR *cstrkv_mgr, void *data, EC_BOOL (*walker)(void *, const CSTRKV *));

EC_BOOL cstrkv_mgr_clone(const CSTRKV_MGR *cstrkv_mgr_src, CSTRKV_MGR *cstrkv_mgr_des);

#endif/*_CSTRKV_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/


