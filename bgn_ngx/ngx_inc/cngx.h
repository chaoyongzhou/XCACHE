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

#if (SWITCH_ON == NGX_BGN_SWITCH)

#ifndef _CNGX_H
#define _CNGX_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
//#include <ndk_array.h>
//#include <ndk_string.h>

#include "type.h"
#include "cstring.h"
#include "clist.h"
#include "cvector.h"

#include "chttp.h"

#define  CNGX_BGN_MOD_SO_PATH_DEFAULT             ("/usr/local/xcache/lib")

#define  CNGX_SEND_BODY_NO_MORE_FLAG              ((unsigned)0x0001)
#define  CNGX_SEND_BODY_FLUSH_FLAG                ((unsigned)0x0002)
#define  CNGX_SEND_BODY_IN_MEM_FLAG               ((unsigned)0x0004)
#define  CNGX_SEND_BODY_RECYCLED_FLAG             ((unsigned)0x0008)

#define  CNGX_CACHE_SEG_SIZE_DEFAULT              (256 * 1024)    /*default seg size is 256KB*/
#define  CNGX_CACHE_SEG_MAX_NUM_DEFAULT           (1024 * 4 * 64) /*default seg max num*/

#define  CNGX_ORIG_PORT_DEFAULT                   (80)         /*default orig server port*/

#define  CNGX_ORIG_REDIRECT_TIMES_DEFAULT         (3)

/*cngx debug*/
#define  CNGX_BGN_MOD_DBG_SWITCH_HDR              ("X-BGN-MOD-DBG")
#define  CNGX_BGN_MOD_DBG_NAME_HDR                ("X-BGN-MOD-DBG-NAME")
#define  CNGX_BGN_MOD_DBG_ERROR_HDR               ("X-BGN-MOD-DBG-ERROR")
#define  CNGX_BGN_MOD_DBG_INFO_HDR                ("X-BGN-MOD-DBG-INFO")
#define  CNGX_BGN_MOD_DBG_EXPIRE_HDR              ("X-BGN-MOD-DBG-EXPIRES")
#define  CNGX_BGN_MOD_DBG_X_PROCEDURE_TAG         ("X-PROCEDURE")
#define  CNGX_BGN_MOD_DBG_X_MODULE_TAG            ("X-BGN-MODULE")
#define  CNGX_BGN_MOD_DBG_X_PROXY_TAG             ("X-PROXY")
#define  CNGX_BGN_MOD_DBG_X_PROXY_VAL             ("X-CACHE")
#define  CNGX_BGN_MOD_DBG_X_METHOD_CACHABLE_TAG   ("X-METHOD-CACHABLE")

/*cngx var configuration*/
#define  CNGX_VAR_BGN_MODE_SO_PATH                ("c_bgn_mod_so_path")

#define  CNGX_VAR_CACHE_HTTP_METHOD               ("c_cache_http_method")
#define  CNGX_VAR_CACHE_HTTP_CODES                ("c_cache_http_codes")
#define  CNGX_VAR_NCACHE_HTTP_CODES               ("c_ncache_http_codes")
#define  CNGX_VAR_CACHE_RSP_HEADERS               ("c_cache_rsp_headers")
#define  CNGX_VAR_NCACHE_RSP_HEADERS              ("c_ncache_rsp_headers")

#define  CNGX_VAR_CACHE_SEG_SIZE                  ("c_cache_seg_size")          /*default: 256KB*/ 
#define  CNGX_VAR_CACHE_SEG_MAX_NUM               ("c_cache_seg_max_num")       /*default: 1024 * 4 * 64*/ 
#define  CNGX_VAR_CACHE_PATH                      ("c_cache_path")              /*default: ngx.var.http_host .. ngx.var.request_uri*/
#define  CNGX_VAR_CACHE_STATUS                    ("c_cache_status")

#define  CNGX_VAR_DIRECT_ORIG_SWITCH              ("c_orig_direct_switch")      /*default: off*/ 
#define  CNGX_VAR_ORIG_FORCE_SWITCH               ("c_orig_force_switch")       /*default: off*/          
#define  CNGX_VAR_ORIG_REDIRECT_MAX_TIMES         ("c_orig_redirect_max_times") /*default: 3*/
#define  CNGX_VAR_ORIG_REDIRECT_SPECIFIC          ("c_orig_redirect_specific")  /*default: null. format: <src status> => <des status> => <redirect url>[|...]*/
#define  CNGX_VAR_ORIG_SERVER                     ("c_orig_server")             /*default: ngx.var.host or ngx.var.http_host*/
#define  CNGX_VAR_ORIG_HOST                       ("c_orig_host")               /*default: ngx.var.http_host*/
#define  CNGX_VAR_ORIG_PORT                       ("c_orig_port")               /*default: ngx.var.server_port*/
#define  CNGX_VAR_ORIG_URI                        ("c_orig_uri")                /*default: ngx.var.request_uri*/
//#define  CNGX_VAR_ORIG_GZIP_SWITCH                ("c_orig_gzip_switch")        /*default: off*/
#define  CNGX_VAR_ORIG_EXPIRES_OVERRIDE_NSEC      ("c_orig_expires_override_nsec")
#define  CNGX_VAR_ORIG_EXPIRES_CACHE_CODE         ("c_orig_expires_cache_code")
#define  CNGX_VAR_ORIG_KEEPALIVE_SWITCH           ("c_orig_keepalive_switch")    /*default: on*/ 

#define  CNGX_VAR_HEADER_MERGE_SWITCH             ("c_header_merge_switch")

#define  CNGX_VAR_MP4_BUFFER_SIZE                 ("c_mp4_buffer_size")
#define  CNGX_VAR_MP4_MAX_BUFFER_SIZE             ("c_mp4_max_buffer_size")

/*cache status definition*/
#define  CNGX_CACHE_STATUS_HIT                    ("TCP_HIT")
#define  CNGX_CACHE_STATUS_MISS                   ("TCP_MISS")
#define  CNGX_CACHE_STATUS_REFRESH_HIT            ("TCP_REFRESH_HIT")
#define  CNGX_CACHE_STATUS_REFRESH_MISS           ("TCP_REFRESH_MISS")

/*nginx http options*/
typedef struct
{
    uint32_t           cacheable_method:1;/*bit bool*/
    uint32_t           only_if_cached  :1;/*bit bool*/
    uint32_t           rsvd01:30;
    uint32_t           rsvd02;
    
}CNGX_OPTION;

#define CNGX_OPTION_CACHEABLE_METHOD(cngx_option)   ((cngx_option)->cacheable_method)
#define CNGX_OPTION_ONLY_IF_CACHED(cngx_option)     ((cngx_option)->only_if_cached)

typedef struct
{
    off_t              start;
    off_t              end;
}CNGX_RANGE;

#define CNGX_RANGE_START(cngx_range)                ((cngx_range)->start)
#define CNGX_RANGE_END(cngx_range)                  ((cngx_range)->end)


typedef EC_BOOL    (*CNGX_HTTP_BGN_MOD_REG_FUNC   )();
typedef EC_BOOL    (*CNGX_HTTP_BGN_MOD_UNREG_FUNC )();
typedef UINT32     (*CNGX_HTTP_BGN_MOD_START_FUNC )(ngx_http_request_t *r);
typedef void       (*CNGX_HTTP_BGN_MOD_END_FUNC   )(const UINT32 modi);
typedef EC_BOOL    (*CNGX_HTTP_BGN_MOD_GETRC_FUNC )(const UINT32 modi, ngx_int_t *, UINT32 *);
typedef EC_BOOL    (*CNGX_HTTP_BGN_MOD_HANDLE_FUNC)(const UINT32 modi);

#define CNGX_HTTP_BGN_MOD_NAME_HASH(name, len)        (JS_hash(len, name))

#define CNGX_HTTP_BGN_MOD_FUNC_NAME_MAX_SIZE          (256)

typedef struct {
    void                             *dl_lib;
    CSTRING                           dl_path;
    
    CSTRING                           name;/*module name*/
    UINT32                            type;/*module type, like as MD_XXX*/
    
    UINT32                            hash;/*hash of module name*/

    CNGX_HTTP_BGN_MOD_REG_FUNC        reg;
    CNGX_HTTP_BGN_MOD_UNREG_FUNC      unreg;
    CNGX_HTTP_BGN_MOD_START_FUNC      start;
    CNGX_HTTP_BGN_MOD_END_FUNC        end;
    CNGX_HTTP_BGN_MOD_GETRC_FUNC      getrc;
    CNGX_HTTP_BGN_MOD_HANDLE_FUNC     handle;
}CNGX_HTTP_BGN_MOD;

#define CNGX_HTTP_BGN_MOD_DL_LIB(cngx_http_bgn_mod)             ((cngx_http_bgn_mod)->dl_lib)
#define CNGX_HTTP_BGN_MOD_DL_PATH(cngx_http_bgn_mod)            (&((cngx_http_bgn_mod)->dl_path))

#define CNGX_HTTP_BGN_MOD_NAME(cngx_http_bgn_mod)               (&((cngx_http_bgn_mod)->name))
#define CNGX_HTTP_BGN_MOD_TYPE(cngx_http_bgn_mod)               ((cngx_http_bgn_mod)->type)

#define CNGX_HTTP_BGN_MOD_HASH(cngx_http_bgn_mod)               ((cngx_http_bgn_mod)->hash)

#define CNGX_HTTP_BGN_MOD_REG(cngx_http_bgn_mod)                ((cngx_http_bgn_mod)->reg)
#define CNGX_HTTP_BGN_MOD_UNREG(cngx_http_bgn_mod)              ((cngx_http_bgn_mod)->unreg)
#define CNGX_HTTP_BGN_MOD_START(cngx_http_bgn_mod)              ((cngx_http_bgn_mod)->start)
#define CNGX_HTTP_BGN_MOD_END(cngx_http_bgn_mod)                ((cngx_http_bgn_mod)->end)
#define CNGX_HTTP_BGN_MOD_GETRC(cngx_http_bgn_mod)              ((cngx_http_bgn_mod)->getrc)
#define CNGX_HTTP_BGN_MOD_HANDLE(cngx_http_bgn_mod)             ((cngx_http_bgn_mod)->handle)


CNGX_RANGE *cngx_range_new();

EC_BOOL cngx_range_init(CNGX_RANGE *cngx_range);

EC_BOOL cngx_range_clean(CNGX_RANGE *cngx_range);

EC_BOOL cngx_range_free(CNGX_RANGE *cngx_range);

EC_BOOL cngx_range_parse(ngx_http_request_t *r, const off_t content_length, CLIST *cngx_ranges);

void    cngx_range_print(LOG *log, const CNGX_RANGE *cngx_range);

EC_BOOL cngx_set_header_out_status(ngx_http_request_t *r, const ngx_uint_t status);

EC_BOOL cngx_set_header_out_content_length(ngx_http_request_t *r, const uint32_t content_length);

EC_BOOL cngx_disable_write_delayed(ngx_http_request_t *r);

EC_BOOL cngx_enable_write_delayed(ngx_http_request_t *r);

EC_BOOL cngx_disable_postpone_output(ngx_http_request_t *r);

EC_BOOL cngx_set_header_only(ngx_http_request_t *r);

EC_BOOL cngx_set_header_out_kv(ngx_http_request_t *r, const char *key, const char *val);

EC_BOOL cngx_set_header_out_cstrkv(ngx_http_request_t *r, const CSTRKV *cstrkv);

EC_BOOL cngx_add_header_out_kv(ngx_http_request_t *r, const char *key, const char *val);

EC_BOOL cngx_add_header_out_cstrkv(ngx_http_request_t *r, const CSTRKV *cstrkv);

EC_BOOL cngx_del_header_out_key(ngx_http_request_t *r, const char *key);

EC_BOOL cngx_get_var_uint32_t(ngx_http_request_t *r, const char *key, uint32_t *val, const uint32_t def);

EC_BOOL cngx_set_var_uint32_t(ngx_http_request_t *r, const char *key, const uint32_t val);

EC_BOOL cngx_get_var_size(ngx_http_request_t *r, const char *key, ssize_t *val, const ssize_t def);

EC_BOOL cngx_set_var_size(ngx_http_request_t *r, const char *key, const ssize_t val);

EC_BOOL cngx_get_var_switch(ngx_http_request_t *r, const char *key, UINT32 *val, const UINT32 def);

EC_BOOL cngx_set_var_switch(ngx_http_request_t *r, const char *key, const UINT32 val);

EC_BOOL cngx_get_var_str(ngx_http_request_t *r, const char *key, char **val, const char *def);

EC_BOOL cngx_set_var_str(ngx_http_request_t *r, const char *key, const char *val);

EC_BOOL cngx_del_var_str(ngx_http_request_t *r, const char *key);

EC_BOOL cngx_get_cache_seg_size(ngx_http_request_t *r, uint32_t *cache_seg_size);

EC_BOOL cngx_get_cache_seg_max_num(ngx_http_request_t *r, uint32_t *cache_seg_max_num);

EC_BOOL cngx_get_req_method_str(const ngx_http_request_t *r, char **val);

EC_BOOL cngx_get_req_info_debug(ngx_http_request_t *r);

EC_BOOL cngx_get_req_uri(const ngx_http_request_t *r, char **val);

EC_BOOL cngx_get_req_arg(const ngx_http_request_t *r, char **val);

EC_BOOL cngx_get_req_url(ngx_http_request_t *r, CSTRING *req_url, EC_BOOL need_args);

EC_BOOL cngx_rearm_req_uri(ngx_http_request_t *r);

EC_BOOL cngx_get_req_port(const ngx_http_request_t *r, char **val);

EC_BOOL cngx_discard_req_body(ngx_http_request_t *r);

EC_BOOL cngx_read_req_body(ngx_http_request_t *r);

EC_BOOL cngx_get_req_body(ngx_http_request_t *r, CBYTES *body);

EC_BOOL cngx_is_debug_switch_on(ngx_http_request_t *r);

EC_BOOL cngx_is_method(ngx_http_request_t *r, const char *method);

EC_BOOL cngx_is_cacheable_method(ngx_http_request_t *r);

EC_BOOL cngx_is_direct_orig_switch_on(ngx_http_request_t *r);

EC_BOOL cngx_is_force_orig_switch_on(ngx_http_request_t *r); 

EC_BOOL cngx_is_merge_header_switch_on(ngx_http_request_t *r);

EC_BOOL cngx_is_orig_keepalive_switch_on(ngx_http_request_t *r);

EC_BOOL cngx_set_chunked(ngx_http_request_t *r);

EC_BOOL cngx_set_keepalive(ngx_http_request_t *r);

EC_BOOL cngx_get_flv_start(ngx_http_request_t *r, UINT32 *flv_start);

EC_BOOL cngx_get_mp4_start_length(ngx_http_request_t *r, UINT32 *mp4_start, UINT32 *mp4_length);

EC_BOOL cngx_get_redirect_specific(ngx_http_request_t *r, const uint32_t src_rsp_status, uint32_t *des_rsp_status, char **des_redirect_url);

EC_BOOL cngx_import_header_out(ngx_http_request_t *r, const CHTTP_RSP *chttp_rsp);

/*for debug*/
EC_BOOL cngx_export_method(const ngx_http_request_t *r, CHTTP_REQ *chttp_req);

/*for debug*/
EC_BOOL cngx_export_uri(const ngx_http_request_t *r, CHTTP_REQ *chttp_req);

EC_BOOL cngx_export_header_in(const ngx_http_request_t *r, CHTTP_REQ *chttp_req);

EC_BOOL cngx_has_header_in_key(const ngx_http_request_t *r, const char *k);

EC_BOOL cngx_has_header_in(const ngx_http_request_t *r, const char *k, const char *v);

EC_BOOL cngx_get_header_in(const ngx_http_request_t *r, const char *k, char **v); 

EC_BOOL cngx_set_cache_status(ngx_http_request_t *r, const char *cache_status);

EC_BOOL cngx_finalize(ngx_http_request_t *r, ngx_int_t status);

void    cngx_send_again(ngx_http_request_t *r);

EC_BOOL cngx_send_wait(ngx_http_request_t *r, ngx_msec_t send_timeout);

EC_BOOL cngx_send_blocking(ngx_http_request_t *r);

EC_BOOL cngx_send_header(ngx_http_request_t *r, ngx_int_t *ngx_rc);

EC_BOOL cngx_need_send_header(ngx_http_request_t *r);

EC_BOOL cngx_send_body(ngx_http_request_t *r, const uint8_t *body, const uint32_t len, const unsigned flag, ngx_int_t *ngx_rc);

EC_BOOL cngx_set_store_cache_rsp_headers(ngx_http_request_t *r, CHTTP_STORE *chttp_store);

EC_BOOL cngx_set_store_cache_http_codes(ngx_http_request_t *r, CHTTP_STORE *chttp_store);

EC_BOOL cngx_set_store_ncache_http_codes(ngx_http_request_t *r, CHTTP_STORE *chttp_store);

EC_BOOL cngx_set_store_expires_cache_code(ngx_http_request_t *r, CHTTP_STORE *chttp_store);

EC_BOOL cngx_set_store_expires_override(ngx_http_request_t *r, CHTTP_STORE *chttp_store);

EC_BOOL cngx_set_store_redirect_max_times(ngx_http_request_t *r, CHTTP_STORE *chttp_store);

EC_BOOL cngx_set_store_cache_path(ngx_http_request_t *r, CSTRING *store_path);

EC_BOOL cngx_set_store(ngx_http_request_t *r, CHTTP_STORE *chttp_store);

/*options*/
EC_BOOL cngx_option_init(CNGX_OPTION *cngx_option);
EC_BOOL cngx_option_clean(CNGX_OPTION *cngx_option);
EC_BOOL cngx_option_set_cacheable_method(ngx_http_request_t *r, CNGX_OPTION *cngx_option);
EC_BOOL cngx_option_set_only_if_cached(ngx_http_request_t *r, CNGX_OPTION *cngx_option);

/*------------------------------ NGX BGN MODULE MANAGEMENT ------------------------------*/
CNGX_HTTP_BGN_MOD *cngx_http_bgn_mod_new();

EC_BOOL cngx_http_bgn_mod_init(CNGX_HTTP_BGN_MOD *cngx_http_bgn_mod);

EC_BOOL cngx_http_bgn_mod_clean(CNGX_HTTP_BGN_MOD *cngx_http_bgn_mod);

EC_BOOL cngx_http_bgn_mod_free(CNGX_HTTP_BGN_MOD *cngx_http_bgn_mod);

EC_BOOL cngx_http_bgn_mod_hash(CNGX_HTTP_BGN_MOD *cngx_http_bgn_mod);

EC_BOOL cngx_http_bgn_mod_set_name(CNGX_HTTP_BGN_MOD *cngx_http_bgn_mod, const char *name, const uint32_t len);

void    cngx_http_bgn_mod_print(LOG *log, const CNGX_HTTP_BGN_MOD *cngx_http_bgn_mod);

int     cngx_http_bgn_mod_cmp(const CNGX_HTTP_BGN_MOD *cngx_http_bgn_mod_1st, const CNGX_HTTP_BGN_MOD *cngx_http_bgn_mod_2nd);

EC_BOOL cngx_http_bgn_mod_table_init();

EC_BOOL cngx_http_bgn_mod_table_add(CNGX_HTTP_BGN_MOD *cngx_http_bgn_mod);

CNGX_HTTP_BGN_MOD *cngx_http_bgn_mod_table_search(const char *name, const uint32_t len);

CNGX_HTTP_BGN_MOD *cngx_http_bgn_mod_table_get(const char *name, const uint32_t len);

EC_BOOL cngx_http_bgn_mod_table_del(const char *name, const uint32_t len);

void    cngx_http_bgn_mod_table_print(LOG *log);

CNGX_HTTP_BGN_MOD *cngx_http_bgn_mod_dl_load(const char *so_path, const uint32_t so_path_len, const char *mod_name, const uint32_t mod_name_len);

EC_BOOL cngx_http_bgn_mod_dl_unload(const char *name, const uint32_t len);


#endif /*_CNGX_H*/

#endif/*(SWITCH_ON == NGX_BGN_SWITCH)*/
#ifdef __cplusplus
}
#endif/*__cplusplus*/

