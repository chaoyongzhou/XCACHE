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

#include "type.h"
#include "mm.h"
#include "log.h"
#include "cstring.h"
#include "clist.h"

#include "cbc.h"
#include "cmisc.h"

#include "task.h"

#include "csocket.h"

#include "cmpie.h"

#include "crb.h"

#include "cload.h"

#include "cbc.h"

#include "ccache.h"

#include "crfsmon.h"

#include "crefresh.h"

#include "cngx.h"
#include "chttp.h"

#include "json.h"

#include "findex.inc"

#define CREFRESH_MD_CAPACITY()                  (cbc_md_capacity(MD_CREFRESH))

#define CREFRESH_MD_GET(crefresh_md_id)     ((CREFRESH_MD *)cbc_md_get(MD_CREFRESH, (crefresh_md_id)))

#define CREFRESH_MD_ID_CHECK_INVALID(crefresh_md_id)  \
    ((CMPI_ANY_MODI != (crefresh_md_id)) && ((NULL_PTR == CREFRESH_MD_GET(crefresh_md_id)) || (0 == (CREFRESH_MD_GET(crefresh_md_id)->usedcounter))))

/**
*   for test only
*
*   to query the status of CREFRESH Module
*
**/
void crefresh_print_module_status(const UINT32 crefresh_md_id, LOG *log)
{
    CREFRESH_MD *crefresh_md;
    UINT32      this_crefresh_md_id;

    for( this_crefresh_md_id = 0; this_crefresh_md_id < CREFRESH_MD_CAPACITY(); this_crefresh_md_id ++ )
    {
        crefresh_md = CREFRESH_MD_GET(this_crefresh_md_id);

        if(NULL_PTR != crefresh_md && 0 < crefresh_md->usedcounter )
        {
            sys_log(log,"CREFRESH Module # %u : %u refered\n",
                    this_crefresh_md_id,
                    crefresh_md->usedcounter);
        }
    }

    return ;
}

/**
*
* register CREFRESH module
*
**/
EC_BOOL crefresh_reg()
{
    /*register mm*/
    /*do nothing*/

    /*register module*/
    return cbc_md_reg(MD_CREFRESH , 1);
}

/**
*
* unregister CREFRESH module
*
**/
EC_BOOL crefresh_unreg()
{
    /*unregister mm*/
    /*do nothing*/

    /*unregister module*/
    return cbc_md_unreg(MD_CREFRESH);
}

/**
*
* start CREFRESH module
*
**/
UINT32 crefresh_start(ngx_http_request_t *r)
{
    CREFRESH_MD *crefresh_md;
    UINT32      crefresh_md_id;

    TASK_BRD   *task_brd;

    uint32_t    cache_seg_size;

    task_brd = task_brd_default_get();
   
    crefresh_md_id = cbc_md_new(MD_CREFRESH, sizeof(CREFRESH_MD));
    if(CMPI_ERROR_MODI == crefresh_md_id)
    {
        return (CMPI_ERROR_MODI);
    }

    /* initialize new one CREFRESH module */
    crefresh_md = (CREFRESH_MD *)cbc_md_get(MD_CREFRESH, crefresh_md_id);
    crefresh_md->usedcounter   = 0;

    /* create a new module node */
    init_static_mem();  

    /* init */
    cngx_get_cache_seg_size(r, &cache_seg_size);
    clist_init(CREFRESH_MD_CACHE_PATH_LIST(crefresh_md), MM_CSTRING, LOC_CREFRESH_0001);
   
    CREFRESH_MD_NGX_HTTP_REQ(crefresh_md) = r;

    /*TODO: load all variables into module*/

    CREFRESH_MD_CNGX_DEBUG_SWITCH_ON_FLAG(crefresh_md) = BIT_FALSE;

    CREFRESH_MD_CONTENT_LENGTH(crefresh_md)   = 0;

    CREFRESH_MD_SENT_BODY_SIZE(crefresh_md)   = 0; 

    CREFRESH_MD_NGX_LOC(crefresh_md)          = LOC_NONE_END;
    CREFRESH_MD_NGX_RC(crefresh_md)           = NGX_OK;

    crefresh_md->usedcounter = 1;

    csig_atexit_register((CSIG_ATEXIT_HANDLER)crefresh_end, crefresh_md_id);

    dbg_log(SEC_0179_CREFRESH, 9)(LOGSTDOUT, "[DEBUG] crefresh_start: start CREFRESH module #%u\n", crefresh_md_id);

    return ( crefresh_md_id );
}

/**
*
* end CREFRESH module
*
**/
void crefresh_end(const UINT32 crefresh_md_id)
{
    CREFRESH_MD *crefresh_md;

    csig_atexit_unregister((CSIG_ATEXIT_HANDLER)crefresh_end, crefresh_md_id);

    crefresh_md = CREFRESH_MD_GET(crefresh_md_id);
    if(NULL_PTR == crefresh_md)
    {
        dbg_log(SEC_0179_CREFRESH, 0)(LOGSTDOUT, "error:crefresh_end: crefresh_md_id = %u not exist.\n", crefresh_md_id);
        dbg_exit(MD_CREFRESH, crefresh_md_id);
    }
   
    /* if the module is occupied by others,then decrease counter only */
    if ( 1 < crefresh_md->usedcounter )
    {
        crefresh_md->usedcounter --;
        return ;
    }

    if ( 0 == crefresh_md->usedcounter )
    {
        dbg_log(SEC_0179_CREFRESH, 0)(LOGSTDOUT, "error:crefresh_end: crefresh_md_id = %u is not started.\n", crefresh_md_id);
        dbg_exit(MD_CREFRESH, crefresh_md_id);
    }

    clist_clean(CREFRESH_MD_CACHE_PATH_LIST(crefresh_md), (CLIST_DATA_DATA_CLEANER)cstring_free);

    CREFRESH_MD_NGX_HTTP_REQ(crefresh_md) = NULL_PTR;

    CREFRESH_MD_CNGX_DEBUG_SWITCH_ON_FLAG(crefresh_md) = BIT_FALSE;

    CREFRESH_MD_CONTENT_LENGTH(crefresh_md) = 0;

    CREFRESH_MD_SENT_BODY_SIZE(crefresh_md) = 0; 

    CREFRESH_MD_NGX_LOC(crefresh_md)        = LOC_NONE_END;
    CREFRESH_MD_NGX_RC(crefresh_md)         = NGX_OK;
   
    /* free module */
    crefresh_md->usedcounter = 0;

    dbg_log(SEC_0179_CREFRESH, 9)(LOGSTDOUT, "crefresh_end: stop CREFRESH module #%u\n", crefresh_md_id);
    cbc_md_free(MD_CREFRESH, crefresh_md_id);

    return ;
}

EC_BOOL crefresh_get_ngx_rc(const UINT32 crefresh_md_id, ngx_int_t *rc, UINT32 *location)
{
    CREFRESH_MD                  *crefresh_md;
   
#if ( SWITCH_ON == CREFRESH_DEBUG_SWITCH )
    if ( CREFRESH_MD_ID_CHECK_INVALID(crefresh_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crefresh_get_ngx_rc: crefresh module #0x%lx not started.\n",
                crefresh_md_id);
        dbg_exit(MD_CREFRESH, crefresh_md_id);
    }
#endif/*CREFRESH_DEBUG_SWITCH*/

    crefresh_md = CREFRESH_MD_GET(crefresh_md_id);

    if(NULL_PTR != rc)
    {
        (*rc) = CREFRESH_MD_NGX_RC(crefresh_md);
    }

    if(NULL_PTR != location)
    {
        (*location) = CREFRESH_MD_NGX_LOC(crefresh_md);
    }
    return (EC_TRUE);
}

/*only for failure!*/
EC_BOOL crefresh_set_ngx_rc(const UINT32 crefresh_md_id, const ngx_int_t rc, const UINT32 location)
{
    CREFRESH_MD                  *crefresh_md;
   
#if ( SWITCH_ON == CREFRESH_DEBUG_SWITCH )
    if ( CREFRESH_MD_ID_CHECK_INVALID(crefresh_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crefresh_set_ngx_rc: crefresh module #0x%lx not started.\n",
                crefresh_md_id);
        dbg_exit(MD_CREFRESH, crefresh_md_id);
    }
#endif/*CREFRESH_DEBUG_SWITCH*/

    crefresh_md = CREFRESH_MD_GET(crefresh_md_id);

    /*do not override*/
    if(NGX_OK != CREFRESH_MD_NGX_RC(crefresh_md))
    {
        dbg_log(SEC_0179_CREFRESH, 9)(LOGSTDOUT, "[DEBUG] crefresh_override_ngx_rc: "
                                                "ignore rc %d due to its %d now\n", 
                                                rc, CREFRESH_MD_NGX_RC(crefresh_md));    
        return (EC_TRUE);
    }
    
    CREFRESH_MD_NGX_RC(crefresh_md)  = rc;
    CREFRESH_MD_NGX_LOC(crefresh_md) = location;

    dbg_log(SEC_0179_CREFRESH, 9)(LOGSTDOUT, "[DEBUG] crefresh_set_ngx_rc: "
                                            "set rc %d\n", 
                                            rc);

    return (EC_TRUE);
}

/*only for failure!*/
EC_BOOL crefresh_override_ngx_rc(const UINT32 crefresh_md_id, const ngx_int_t rc, const UINT32 location)
{
    CREFRESH_MD                  *crefresh_md;
   
#if ( SWITCH_ON == CREFRESH_DEBUG_SWITCH )
    if ( CREFRESH_MD_ID_CHECK_INVALID(crefresh_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crefresh_override_ngx_rc: crefresh module #0x%lx not started.\n",
                crefresh_md_id);
        dbg_exit(MD_CREFRESH, crefresh_md_id);
    }
#endif/*CREFRESH_DEBUG_SWITCH*/

    crefresh_md = CREFRESH_MD_GET(crefresh_md_id);

    if(rc == CREFRESH_MD_NGX_RC(crefresh_md))
    {
        dbg_log(SEC_0179_CREFRESH, 9)(LOGSTDOUT, "[DEBUG] crefresh_override_ngx_rc: "
                                                "ignore same rc %d\n", 
                                                rc);    
        return (EC_TRUE);
    }

    if(NGX_OK != CREFRESH_MD_NGX_RC(crefresh_md))
    {
        dbg_log(SEC_0179_CREFRESH, 9)(LOGSTDOUT, "[DEBUG] crefresh_override_ngx_rc: "
                                                "modify rc %d => %d\n", 
                                                CREFRESH_MD_NGX_RC(crefresh_md), rc);    
        CREFRESH_MD_NGX_RC(crefresh_md)  = rc;
        CREFRESH_MD_NGX_LOC(crefresh_md) = location;

        return (EC_TRUE);
    }
    
    dbg_log(SEC_0179_CREFRESH, 9)(LOGSTDOUT, "[DEBUG] crefresh_override_ngx_rc: "
                                            "set rc %d\n", 
                                            rc);

    CREFRESH_MD_NGX_RC(crefresh_md)  = rc;
    CREFRESH_MD_NGX_LOC(crefresh_md) = location;
    
    return (EC_TRUE);
}

EC_BOOL crefresh_parse_cache_path_list(const UINT32 crefresh_md_id, CBYTES *cbytes)
{
    CREFRESH_MD                  *crefresh_md;
   
    ngx_http_request_t           *r;
    CJSON_OBJ                    *body_obj;

    CJSON_OBJ                    *path_objs;

    size_t                        path_obj_idx;
    size_t                        path_obj_len;    
        
#if ( SWITCH_ON == CREFRESH_DEBUG_SWITCH )
    if ( CREFRESH_MD_ID_CHECK_INVALID(crefresh_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crefresh_parse_cache_path_list: crefresh module #0x%lx not started.\n",
                crefresh_md_id);
        dbg_exit(MD_CREFRESH, crefresh_md_id);
    }
#endif/*CREFRESH_DEBUG_SWITCH*/

    crefresh_md = CREFRESH_MD_GET(crefresh_md_id);

    r = CREFRESH_MD_NGX_HTTP_REQ(crefresh_md);

    body_obj = json_tokener_parse((const char *)CBYTES_BUF(cbytes));
    if(NULL_PTR == body_obj)
    {
        dbg_log(SEC_0179_CREFRESH, 0)(LOGSTDOUT, "error:crefresh_parse_cache_path_list: json parse '%.*s' failed\n",
                    (uint32_t)CBYTES_LEN(cbytes), (char *)CBYTES_BUF(cbytes));    

        return (EC_FALSE);
    }

    path_objs = body_obj;

    path_obj_len = json_object_array_length(path_objs);
    dbg_log(SEC_0179_CREFRESH, 9)(LOGSTDOUT, "[DEBUG] crefresh_parse_cache_path_list: "
                                             "path_obj_len = %d\n", 
                                             path_obj_len);
                                        
    for(path_obj_idx = 0; path_obj_idx < path_obj_len; path_obj_idx ++)
    {
        CJSON_OBJ       *path_obj;
        const char      *path_str;

        CSTRING         *cache_path;
       
        path_obj = json_object_array_get_idx(path_objs, path_obj_idx);
        if(NULL_PTR == path_obj)
        {
            continue;
        }

        path_str = json_object_get_string(path_obj);
        if(NULL_PTR == path_str)
        {
            continue;
        }

        cache_path = cstring_new((const UINT8 *)path_str, LOC_CREFRESH_0002);
        if(NULL_PTR == cache_path)
        {
            dbg_log(SEC_0179_CREFRESH, 0)(LOGSTDOUT, "error:crefresh_parse_cache_path_list: new cstring '%s' failed\n",
                            path_str);

            json_object_free_object(body_obj);/*note: not json_tokener_free*/
            return (EC_FALSE);                
        }

        clist_push_back(CREFRESH_MD_CACHE_PATH_LIST(crefresh_md), (void *)cache_path);
        dbg_log(SEC_0179_CREFRESH, 9)(LOGSTDOUT, "[DEBUG] crefresh_parse_cache_path_list: push cache_path '%s'\n",
                            (char *)cstring_get_str(cache_path));
    }
    
    json_object_free_object(body_obj);/*note: not json_tokener_free*/
    
    return (EC_TRUE);    
}

EC_BOOL crefresh_get_cache_path_list(const UINT32 crefresh_md_id)
{
    CREFRESH_MD                  *crefresh_md;
   
    ngx_http_request_t           *r;
    char                         *uri_str;
    CBYTES                       *req_body;
        
#if ( SWITCH_ON == CREFRESH_DEBUG_SWITCH )
    if ( CREFRESH_MD_ID_CHECK_INVALID(crefresh_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crefresh_get_cache_path_list: crefresh module #0x%lx not started.\n",
                crefresh_md_id);
        dbg_exit(MD_CREFRESH, crefresh_md_id);
    }
#endif/*CREFRESH_DEBUG_SWITCH*/

    crefresh_md = CREFRESH_MD_GET(crefresh_md_id);

    r = CREFRESH_MD_NGX_HTTP_REQ(crefresh_md);

    if(EC_FALSE == cngx_get_req_uri(r, &uri_str))
    {
        dbg_log(SEC_0179_CREFRESH, 0)(LOGSTDOUT, "error:crefresh_get_cache_path_list: "
                                                 "fetch req uri failed\n");
        return (EC_FALSE);
    }

    if(0 != STRCMP(uri_str, (const char *)"/"))
    {
        CSTRING     *cache_path;

        cache_path = cstring_new((const UINT8 *)uri_str, LOC_CREFRESH_0003);
        if(NULL_PTR == cache_path)
        {
            dbg_log(SEC_0179_CREFRESH, 0)(LOGSTDOUT, "error:crefresh_get_cache_path_list: new cstring '%s' failed\n",
                            uri_str);
            safe_free(uri_str, LOC_CREFRESH_0004);
            return (EC_FALSE);                
        }

        clist_push_back(CREFRESH_MD_CACHE_PATH_LIST(crefresh_md), (void *)cache_path);
        dbg_log(SEC_0179_CREFRESH, 9)(LOGSTDOUT, "[DEBUG] crefresh_get_cache_path_list: push cache_path '%s'\n",
                            (char *)cstring_get_str(cache_path));
    }

    safe_free(uri_str, LOC_CREFRESH_0005);

    if(EC_FALSE == cngx_read_req_body(r))
    {
        dbg_log(SEC_0179_CREFRESH, 0)(LOGSTDOUT, "error:crefresh_get_cache_path_list: read req body failed\n");
        return (EC_FALSE);                
    }

    req_body = cbytes_new(0);
    if(NULL_PTR == req_body)
    {
        dbg_log(SEC_0179_CREFRESH, 0)(LOGSTDOUT, "error:crefresh_get_cache_path_list: new cbytes failed\n");
        return (EC_FALSE);                
    }

    if(EC_FALSE == cngx_get_req_body(r, req_body))
    {
        dbg_log(SEC_0179_CREFRESH, 0)(LOGSTDOUT, "error:crefresh_get_cache_path_list: get req body failed\n");
        cbytes_free(req_body);
        return (EC_FALSE);                
    }
    dbg_log(SEC_0179_CREFRESH, 9)(LOGSTDOUT, "[DEBUG] crefresh_get_cache_path_list: get req body: '%.*s'\n",
                        (uint32_t)CBYTES_LEN(req_body), (char *)CBYTES_BUF(req_body));

    if(EC_FALSE == cbytes_is_empty(req_body))
    {
        if(EC_FALSE == crefresh_parse_cache_path_list(crefresh_md_id, req_body))
        {
            dbg_log(SEC_0179_CREFRESH, 0)(LOGSTDOUT, "error:crefresh_get_cache_path_list: parse req body: '%.*s' failed\n",
                        (uint32_t)CBYTES_LEN(req_body), (char *)CBYTES_BUF(req_body));    

            cbytes_free(req_body);           
            return (EC_FALSE);
        }
    }
    cbytes_free(req_body);

    dbg_log(SEC_0179_CREFRESH, 9)(LOGSTDOUT, "[DEBUG] crefresh_get_cache_path_list: done\n");
    
    return (EC_TRUE);
}

/**
*
* content handler
*
**/
EC_BOOL crefresh_content_handler(const UINT32 crefresh_md_id)
{
    CREFRESH_MD                  *crefresh_md;
   
    ngx_http_request_t          *r;

#if ( SWITCH_ON == CREFRESH_DEBUG_SWITCH )
    if ( CREFRESH_MD_ID_CHECK_INVALID(crefresh_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crefresh_content_handler: crefresh module #0x%lx not started.\n",
                crefresh_md_id);
        dbg_exit(MD_CREFRESH, crefresh_md_id);
    }
#endif/*CREFRESH_DEBUG_SWITCH*/

    crefresh_md = CREFRESH_MD_GET(crefresh_md_id);
  
    r = CREFRESH_MD_NGX_HTTP_REQ(crefresh_md);
   
    dbg_log(SEC_0179_CREFRESH, 9)(LOGSTDOUT, "[DEBUG] crefresh_content_handler: enter\n");

    /*priority: if set debug on when module starting, ignore switch in cngx http req header*/
    if(BIT_FALSE == CREFRESH_MD_CNGX_DEBUG_SWITCH_ON_FLAG(crefresh_md)
    && EC_TRUE == cngx_is_debug_switch_on(r))
    {
        CREFRESH_MD_CNGX_DEBUG_SWITCH_ON_FLAG(crefresh_md) = BIT_TRUE;
    }
    
    if(EC_FALSE == crefresh_get_cache_path_list(crefresh_md_id))
    {
        dbg_log(SEC_0179_CREFRESH, 0)(LOGSTDOUT, "error:crefresh_content_handler: get cache_path_list failed\n");

        crefresh_set_ngx_rc(crefresh_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CREFRESH_0006); 
        return (EC_FALSE);
    }
    dbg_log(SEC_0179_CREFRESH, 9)(LOGSTDOUT, "[DEBUG] crefresh_content_handler: get cache_path_list done\n");    

    crefresh_content_send_request(crefresh_md_id);

    cngx_set_header_out_status(r, NGX_HTTP_OK);
    cngx_set_header_out_content_length(r, 0);
    
    crefresh_content_send_response(crefresh_md_id);
    
    return (EC_TRUE);
}

EC_BOOL crefresh_content_send_request(const UINT32 crefresh_md_id)
{
    CREFRESH_MD                 *crefresh_md;
   
    //ngx_http_request_t          *r;
    CLIST_DATA                  *clist_data;
    
#if ( SWITCH_ON == CREFRESH_DEBUG_SWITCH )
    if ( CREFRESH_MD_ID_CHECK_INVALID(crefresh_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crefresh_content_send_request: crefresh module #0x%lx not started.\n",
                crefresh_md_id);
        dbg_exit(MD_CREFRESH, crefresh_md_id);
    }
#endif/*CREFRESH_DEBUG_SWITCH*/

    crefresh_md = CREFRESH_MD_GET(crefresh_md_id);

    //r = CREFRESH_MD_NGX_HTTP_REQ(crefresh_md);

    CLIST_LOOP_NEXT(CREFRESH_MD_CACHE_PATH_LIST(crefresh_md), clist_data)
    {
        CSTRING         *cache_path;

        cache_path = (CSTRING *)CLIST_DATA_DATA(clist_data);
        ccache_dir_delete(cache_path);

        dbg_log(SEC_0179_CREFRESH, 9)(LOGSTDOUT, "[DEBUG] crefresh_content_send_request: ddir '%s' done\n",
                        (char *)cstring_get_str(cache_path));    

    }

    return (EC_TRUE);
}

EC_BOOL crefresh_content_send_response(const UINT32 crefresh_md_id)
{
    CREFRESH_MD                 *crefresh_md;
   
    ngx_http_request_t          *r;
    
#if ( SWITCH_ON == CREFRESH_DEBUG_SWITCH )
    if ( CREFRESH_MD_ID_CHECK_INVALID(crefresh_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crefresh_content_send_response: crefresh module #0x%lx not started.\n",
                crefresh_md_id);
        dbg_exit(MD_CREFRESH, crefresh_md_id);
    }
#endif/*CREFRESH_DEBUG_SWITCH*/

    crefresh_md = CREFRESH_MD_GET(crefresh_md_id);

    r = CREFRESH_MD_NGX_HTTP_REQ(crefresh_md);
 
    /*send header*/
    if(EC_TRUE == cngx_need_send_header(r))
    {
        cngx_disable_write_delayed(r);

        cngx_set_header_only(r);/*xxx*/
        
        if(EC_FALSE == cngx_send_header(r, &(CREFRESH_MD_NGX_RC(crefresh_md))))
        {
            dbg_log(SEC_0179_CREFRESH, 0)(LOGSTDOUT, "error:crefresh_content_send_response: "
                                                     "send header failed\n");

            return (EC_FALSE);
        }
        dbg_log(SEC_0179_CREFRESH, 9)(LOGSTDOUT, "[DEBUG] crefresh_content_send_response: "
                                                 "send header done\n");
    }
    
    /*send body*/

    /*TODO:*/
    ngx_http_output_filter(r, NULL_PTR);
    
    dbg_log(SEC_0179_CREFRESH, 9)(LOGSTDOUT, "[DEBUG] crefresh_content_send_response: "
                                             "send body done => complete %ld bytes\n",
                                             CREFRESH_MD_SENT_BODY_SIZE(crefresh_md));    
    return (EC_TRUE);
}

#endif/*(SWITCH_ON == NGX_BGN_SWITCH)*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/


