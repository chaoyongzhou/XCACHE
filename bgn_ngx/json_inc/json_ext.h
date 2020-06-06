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

#ifndef _JSON_EXT_H
#define _JSON_EXT_H

#include "json_debug.h"
#include "linkhash.h"
#include "arraylist.h"
#include "json_util.h"
#include "json_object.h"
#include "json_pointer.h"
#include "json_tokener.h"
#include "json_object_iterator.h"
#include "json_c_version.h"

struct json_object* json_object_add_k_int64(struct json_object *jso, const char *k, const int64_t v);

struct json_object* json_object_add_k_int32(struct json_object *jso, const char *k, const int32_t v);

struct json_object* json_object_add_k_double(struct json_object *jso, const char *k, const double v);

struct json_object* json_object_add_kv(struct json_object *jso, const char *k, const char *v);

struct json_object* json_object_add_obj(struct json_object* jso, const char *key, struct json_object *val);

struct json_object* json_object_get_obj(struct json_object* jso, const char *key);

struct json_object *json_object_array_add_string(struct json_object *jso, const char * v);

struct json_object *json_object_array_add_int64(struct json_object *jso, const int64_t v);

struct json_object *json_object_array_add_int32(struct json_object *jso, const int32_t v);

int json_object_free_object(struct json_object *jso);

typedef struct json_object CJSON_OBJ;

#endif/*_JSON_EXT_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/
