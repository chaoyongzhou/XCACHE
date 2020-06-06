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

#include "json_debug.h"
#include "linkhash.h"
#include "arraylist.h"
#include "json_util.h"
#include "json_object.h"
#include "json_pointer.h"
#include "json_tokener.h"
#include "json_object_iterator.h"
#include "json_c_version.h"

#include "json_ext.h"

struct json_object* json_object_add_k_int64(struct json_object *jso, const char *k, const int64_t v)
{
    struct json_object *v_jso;

    v_jso = json_object_new_int64(v);
    if(NULL == v_jso)
    {
        return (NULL);
    }

    if(0 != json_object_object_add(jso, k, v_jso))
    {
        json_object_put(v_jso);
        return (NULL);
    }

    return (v_jso);
}

struct json_object* json_object_add_k_int32(struct json_object *jso, const char *k, const int32_t v)
{
    struct json_object *v_jso;

    v_jso = json_object_new_int(v);
    if(NULL == v_jso)
    {
        return (NULL);
    }

    if(0 != json_object_object_add(jso, k, v_jso))
    {
        json_object_put(v_jso);
        return (NULL);
    }

    return (v_jso);
}

struct json_object* json_object_add_k_double(struct json_object *jso, const char *k, const double v)
{
    struct json_object *v_jso;

    v_jso = json_object_new_double(v);
    if(NULL == v_jso)
    {
        return (NULL);
    }

    if(0 != json_object_object_add(jso, k, v_jso))
    {
        json_object_put(v_jso);
        return (NULL);
    }

    return (v_jso);
}

struct json_object* json_object_add_kv(struct json_object *jso, const char *k, const char *v)
{
    struct json_object *v_jso;

    v_jso = json_object_new_string((const char *)v);
    if(NULL == v_jso)
    {
        return (NULL);
    }

    if(0 != json_object_object_add(jso, k, v_jso))
    {
        json_object_put(v_jso);
        return (NULL);
    }

    return (v_jso);
}

struct json_object* json_object_add_obj(struct json_object* jso, const char *key, struct json_object *val)
{
    if(0 != json_object_object_add(jso, key, val))
    {
        return (NULL);
    }

    return (jso);
}

struct json_object* json_object_get_obj(struct json_object* jso, const char *key)
{
    return json_object_object_get(jso, key);
}


struct json_object *json_object_array_add_string(struct json_object *jso, const char * v)
{
    struct json_object *v_jso;

    v_jso = json_object_new_string(v);
    if(NULL == v_jso)
    {
        return (NULL);
    }

    if(0 != json_object_array_add(jso, v_jso))
    {
        json_object_put(v_jso);
        return (NULL);
    }

    return (v_jso);
}

struct json_object *json_object_array_add_int64(struct json_object *jso, const int64_t v)
{
    struct json_object *v_jso;

    v_jso = json_object_new_int64(v);
    if(NULL == v_jso)
    {
        return (NULL);
    }

    if(0 != json_object_array_add(jso, v_jso))
    {
        json_object_put(v_jso);
        return (NULL);
    }

    return (v_jso);
}

struct json_object *json_object_array_add_int32(struct json_object *jso, const int32_t v)
{
    struct json_object *v_jso;

    v_jso = json_object_new_int(v);
    if(NULL == v_jso)
    {
        return (NULL);
    }

    if(0 != json_object_array_add(jso, v_jso))
    {
        json_object_put(v_jso);
        return (NULL);
    }

    return (v_jso);
}

int json_object_free_object(struct json_object *jso)
{
    return json_object_put(jso);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/
