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

#include <dirent.h>
#include <unistd.h>

#include "type.h"
#include "mm.h"
#include "log.h"
#include "cmpic.inc"
#include "clist.h"
#include "cstring.h"
#include "cmisc.h"

#include "ctdnssv.h"
#include "ctdnssvmgr.h"

CTDNSSV_MGR *ctdnssv_mgr_new()
{
    CTDNSSV_MGR *ctdnssv_mgr;

    alloc_static_mem(MM_CTDNSSV_MGR, &ctdnssv_mgr, LOC_CTDNSSVMGR_0001);
    if(NULL_PTR != ctdnssv_mgr)
    {
        ctdnssv_mgr_init(ctdnssv_mgr);
    }

    return (ctdnssv_mgr);
}

EC_BOOL ctdnssv_mgr_init(CTDNSSV_MGR *ctdnssv_mgr)
{
    cstring_init(CTDNSSV_MGR_SP_ROOT_DIR(ctdnssv_mgr), NULL_PTR); 
    clist_init(CTDNSSV_MGR_SP_SERVICES(ctdnssv_mgr), MM_CTDNSSV, LOC_CTDNSSVMGR_0002);
 
    return (EC_TRUE);
}

EC_BOOL ctdnssv_mgr_clean(CTDNSSV_MGR *ctdnssv_mgr)
{
    cstring_clean(CTDNSSV_MGR_SP_ROOT_DIR(ctdnssv_mgr)); 
    clist_clean(CTDNSSV_MGR_SP_SERVICES(ctdnssv_mgr), (CLIST_DATA_DATA_CLEANER)ctdnssv_free);    

    return (EC_TRUE);
}

EC_BOOL ctdnssv_mgr_free(CTDNSSV_MGR *ctdnssv_mgr)
{
    if(NULL_PTR != ctdnssv_mgr)
    {
        ctdnssv_mgr_clean(ctdnssv_mgr);
        free_static_mem(MM_CTDNSSV_MGR, ctdnssv_mgr, LOC_CTDNSSVMGR_0003);
    }
    return (EC_TRUE);
}

CTDNSSV *ctdnssv_mgr_search_sp(CTDNSSV_MGR *ctdnssv_mgr, const CSTRING *service_name)
{
    CLIST_DATA    *clist_data;
    
    CLIST_LOOP_NEXT(CTDNSSV_MGR_SP_SERVICES(ctdnssv_mgr), clist_data)
    {
        CTDNSSV     *ctdnssv;

        ctdnssv = CLIST_DATA_DATA(clist_data);

        if(EC_TRUE == ctdnssv_is_service(ctdnssv, service_name))
        {
            return (ctdnssv);
        }
    }
    return (NULL_PTR);
}

CTDNSSV *ctdnssv_mgr_open_sp(CTDNSSV_MGR *ctdnssv_mgr, const CSTRING *service_name)
{
    CTDNSSV *ctdnssv;

    ctdnssv = ctdnssv_mgr_search_sp(ctdnssv_mgr, service_name);
    if(NULL_PTR != ctdnssv)
    {
        dbg_log(SEC_0055_CTDNSSVMGR, 9)(LOGSTDOUT, "[DEBUG] ctdnssv_mgr_open_sp: found sp '%s'\n", 
                            (char *)cstring_get_str(service_name));    
        return (ctdnssv);
    }

    ctdnssv = ctdnssv_open((char *)cstring_get_str(service_name));
    if(NULL_PTR == ctdnssv)
    {
        dbg_log(SEC_0055_CTDNSSVMGR, 0)(LOGSTDOUT, "error:ctdnssv_mgr_open_sp: open sp %s failed\n", 
                        (char *)cstring_get_str(service_name));
        return (NULL_PTR);
    }

    clist_push_back(CTDNSSV_MGR_SP_SERVICES(ctdnssv_mgr), (void *)ctdnssv);
    
    dbg_log(SEC_0055_CTDNSSVMGR, 9)(LOGSTDOUT, "[DEBUG] ctdnssv_mgr_open_sp: open sp %s done\n", 
                        (char *)cstring_get_str(service_name));
    return (ctdnssv);
}

CTDNSSV *ctdnssv_mgr_delete_sp(CTDNSSV_MGR *ctdnssv_mgr, const CSTRING *service_name)
{
    CLIST_DATA    *clist_data;
    
    CLIST_LOOP_NEXT(CTDNSSV_MGR_SP_SERVICES(ctdnssv_mgr), clist_data)
    {
        CTDNSSV     *ctdnssv;

        ctdnssv = CLIST_DATA_DATA(clist_data);

        if(EC_TRUE == ctdnssv_is_service(ctdnssv, service_name))
        {
            clist_erase(CTDNSSV_MGR_SP_SERVICES(ctdnssv_mgr), clist_data);
            return (ctdnssv);
        }
    }
    return (NULL_PTR);
}

EC_BOOL ctdnssv_mgr_close_sp(CTDNSSV_MGR *ctdnssv_mgr, const CSTRING *service_name)
{
    CTDNSSV *ctdnssv;

    ctdnssv = ctdnssv_mgr_delete_sp(ctdnssv_mgr, service_name);
    if(NULL_PTR == ctdnssv)
    {
        dbg_log(SEC_0055_CTDNSSVMGR, 1)(LOGSTDOUT, "warn:ctdnssv_mgr_close_sp: sp %s not open yet\n", 
                        (char *)cstring_get_str(service_name));
        return (EC_TRUE);
    }

    ctdnssv_close(ctdnssv);
    return (EC_TRUE);
}

CTDNSSV *ctdnssv_mgr_create_sp(CTDNSSV_MGR *ctdnssv_mgr, const CSTRING *service_name)
{
    CTDNSSV         *ctdnssv;
    
    ctdnssv = ctdnssv_create((char *)CTDNSSV_MGR_SP_ROOT_DIR_STR(ctdnssv_mgr), 
                             (char *)cstring_get_str(service_name), 
                             CTDNSSV_SP_MODEL_DEFAULT);

    if(NULL_PTR == ctdnssv)
    {
        return (NULL_PTR);
    }
    clist_push_back(CTDNSSV_MGR_SP_SERVICES(ctdnssv_mgr), (void *)ctdnssv);
    return (ctdnssv);
}

EC_BOOL ctdnssv_mgr_open_sp_all(CTDNSSV_MGR *ctdnssv_mgr)
{
    char            *root_dir;
    DIR             *dir;
    struct dirent   *ptr;

    root_dir = (char *)CTDNSSV_MGR_SP_ROOT_DIR_STR(ctdnssv_mgr);

    dir = opendir(root_dir);
    if(NULL_PTR == dir)
    {
        dbg_log(SEC_0055_CTDNSSVMGR, 0)(LOGSTDOUT, "error:ctdnssv_mgr_open_sp_all: open dir %s failed\n", 
                        root_dir);
        return (EC_FALSE);
    }

    while(NULL_PTR != (ptr = readdir(dir)))
    {  
        uint32_t        d_name_len;
        
        if(0 == strcmp(ptr->d_name,".") 
        || 0 == strcmp(ptr->d_name,".."))
        {
            continue;
        }

        if(4 == ptr->d_type)  /*dir*/
        {
            continue;
        }

        d_name_len = strlen(ptr->d_name);
        if(d_name_len <= sizeof(CTDNSSV_POSTFIX) - 1
        || 0 != strcmp(ptr->d_name + d_name_len - (sizeof(CTDNSSV_POSTFIX) - 1), CTDNSSV_POSTFIX))
        {
            continue;
        }
        
        if(8  == ptr->d_type     /*file*/
        || 10 == ptr->d_type     /*link*/ 
        )  
        {
            CTDNSSV          *ctdnssv;
            char             *service_fname;
            UINT32            service_fname_len;

            service_fname_len = strlen(root_dir) + 1 + d_name_len + 1;
            service_fname     = safe_malloc(service_fname_len, LOC_CTDNSSVMGR_0004);
            if(NULL_PTR == service_fname)
            {
                dbg_log(SEC_0055_CTDNSSVMGR, 0)(LOGSTDOUT, "error:ctdnssv_mgr_open_sp_all: malloc %ld bytes failed\n", 
                                service_fname_len);
                                
                closedir(dir);
                return (EC_FALSE);
            }
            snprintf(service_fname, service_fname_len, "%s/%s", root_dir, ptr->d_name);

            ctdnssv = ctdnssv_open(service_fname);
            if(NULL_PTR == ctdnssv)
            {
                dbg_log(SEC_0055_CTDNSSVMGR, 0)(LOGSTDOUT, "error:ctdnssv_mgr_open_sp_all: open service file '%s' failed\n", 
                                service_fname);
                                
                safe_free(service_fname, LOC_CTDNSSVMGR_0005);
                continue;
            }

            dbg_log(SEC_0055_CTDNSSVMGR, 9)(LOGSTDOUT, "[DEBUG] ctdnssv_mgr_open_sp_all: open service file '%s' => service '%.*s' done\n", 
                            service_fname,
                            CTDNSSV_SNAME_LEN(ctdnssv),
                            CTDNSSV_SNAME(ctdnssv));            

            clist_push_back(CTDNSSV_MGR_SP_SERVICES(ctdnssv_mgr), (void *)ctdnssv);
        }
    }

    closedir(dir);
    
    return (EC_TRUE);
}

EC_BOOL ctdnssv_mgr_close_sp_all(CTDNSSV_MGR *ctdnssv_mgr)
{
    CTDNSSV *ctdnssv;

    while(NULL_PTR != (ctdnssv = clist_pop_front(CTDNSSV_MGR_SP_SERVICES(ctdnssv_mgr))))
    {
        dbg_log(SEC_0055_CTDNSSVMGR, 0)(LOGSTDOUT, "error:ctdnssv_mgr_close_sp_all: close sp %.*s failed\n",
                        CTDNSSV_SNAME_LEN(ctdnssv), CTDNSSV_SNAME(ctdnssv));
                        
        ctdnssv_close(ctdnssv);
    }
   
    return (EC_TRUE);
}

void ctdnssv_mgr_print(LOG *log, const CTDNSSV_MGR *ctdnssv_mgr)
{
    sys_log(log, "ctdnssv mgr:%p\n", ctdnssv_mgr);
    
    sys_log(log, "ctdnssv mgr sp root dir  : %s\n", (char *)CTDNSSV_MGR_SP_ROOT_DIR_STR(ctdnssv_mgr));
 
    clist_print(log, CTDNSSV_MGR_SP_SERVICES(ctdnssv_mgr), (CLIST_DATA_DATA_PRINT)ctdnssv_print);

    return;
}

EC_BOOL ctdnssv_mgr_load(CTDNSSV_MGR *ctdnssv_mgr)
{
    if(EC_FALSE == ctdnssv_mgr_open_sp_all(ctdnssv_mgr))
    {
        dbg_log(SEC_0055_CTDNSSVMGR, 0)(LOGSTDOUT, "error:ctdnssv_mgr_load: load all sp failed from dir %s\n", 
                        (char *)CTDNSSV_MGR_SP_ROOT_DIR_STR(ctdnssv_mgr));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL ctdnssv_mgr_sync_sp(CTDNSSV_MGR *ctdnssv_mgr, const CSTRING *service_name)
{
    CTDNSSV *ctdnssv;

    ctdnssv = ctdnssv_mgr_search_sp(ctdnssv_mgr, service_name);
    if(NULL_PTR != ctdnssv)
    {
        return ctdnssv_sync(ctdnssv);
    }
    return (EC_TRUE);
}

EC_BOOL ctdnssv_mgr_flush(CTDNSSV_MGR *ctdnssv_mgr)
{
    CLIST_DATA      *clist_data;

    CLIST_LOOP_NEXT(CTDNSSV_MGR_SP_SERVICES(ctdnssv_mgr), clist_data)
    {
        CTDNSSV *ctdnssv;

        ctdnssv = CLIST_DATA_DATA(clist_data);
        ctdnssv_sync(ctdnssv);
    }
    
    return (EC_TRUE);
}

EC_BOOL ctdnssv_mgr_show_sp(LOG *log, CTDNSSV_MGR *ctdnssv_mgr, const CSTRING *service_name)
{
    CTDNSSV *ctdnssv;

    ctdnssv = ctdnssv_mgr_search_sp(ctdnssv_mgr, service_name);
    if(NULL_PTR == ctdnssv)
    {     
        /*try to open the sp and print it*/
        ctdnssv = ctdnssv_mgr_open_sp(ctdnssv_mgr, service_name);
        if(NULL_PTR == ctdnssv)
        {
            dbg_log(SEC_0055_CTDNSSVMGR, 0)(LOGSTDOUT, "error:ctdnssv_mgr_show_sp: open sp %s failed\n", 
                        (const char *)cstring_get_str(service_name));
            return (EC_FALSE);
        }

        ctdnssv_print(log, ctdnssv);

        ctdnssv_close(ctdnssv);
    }
    else
    {    
        ctdnssv_print(log, ctdnssv);
    }

    return (EC_TRUE);
}

CTDNSSV_MGR *ctdnssv_mgr_create(const CSTRING *ctdnssv_sp_root_dir)
{
    CTDNSSV_MGR *ctdnssv_mgr;
    uint32_t     ctdnssv_item_max_num;

    ctdnssv_model_item_max_num(CTDNSSV_SP_MODEL_DEFAULT, &ctdnssv_item_max_num);

    ctdnssv_mgr = ctdnssv_mgr_new();

    cstring_clone(ctdnssv_sp_root_dir, CTDNSSV_MGR_SP_ROOT_DIR(ctdnssv_mgr));

    return (ctdnssv_mgr);
}

CTDNSSV_MGR * ctdnssv_mgr_open(const CSTRING *ctdnssv_sp_root_dir)
{
    CTDNSSV_MGR *ctdnssv_mgr;

    ctdnssv_mgr = ctdnssv_mgr_new();
    if(NULL_PTR == ctdnssv_mgr)
    {
        dbg_log(SEC_0055_CTDNSSVMGR, 0)(LOGSTDOUT, "error:ctdnssv_mgr_open: new ctdnssv mgr failed\n");
        return (NULL_PTR);
    }

    cstring_clone(ctdnssv_sp_root_dir, CTDNSSV_MGR_SP_ROOT_DIR(ctdnssv_mgr));

    if(EC_FALSE == ctdnssv_mgr_load(ctdnssv_mgr))
    {
        dbg_log(SEC_0055_CTDNSSVMGR, 0)(LOGSTDOUT, "error:ctdnssv_mgr_open: load failed\n");
        ctdnssv_mgr_free(ctdnssv_mgr);
        return (NULL_PTR);
    }
    
    dbg_log(SEC_0055_CTDNSSVMGR, 9)(LOGSTDOUT, "[DEBUG] ctdnssv_mgr_open: ctdnssv mgr loaded from %s\n", 
                (char *)cstring_get_str(ctdnssv_sp_root_dir));
    return (ctdnssv_mgr);
}

EC_BOOL ctdnssv_mgr_close(CTDNSSV_MGR *ctdnssv_mgr)
{ 
    if(NULL_PTR != ctdnssv_mgr)
    {
        ctdnssv_mgr_flush(ctdnssv_mgr);
        ctdnssv_mgr_free(ctdnssv_mgr);
    }
    return (EC_TRUE);
}

EC_BOOL ctdnssv_mgr_exists(CTDNSSV_MGR *ctdnssv_mgr, const CSTRING *service_name)
{
    CTDNSSV *ctdnssv;

    ctdnssv = ctdnssv_mgr_open_sp(ctdnssv_mgr, service_name);
    if(NULL_PTR == ctdnssv)
    {
        return (EC_FALSE);
    }    
    return (EC_TRUE);
}

EC_BOOL ctdnssv_mgr_set(CTDNSSV_MGR *ctdnssv_mgr, const UINT32 tcid, const UINT32 ipaddr, const UINT32 port, const CSTRING *service_name)
{
    CTDNSSV         *ctdnssv;
    CTDNSSV_ITEM    *ctdnssv_item;

    ctdnssv = ctdnssv_mgr_open_sp(ctdnssv_mgr, service_name);
    if(NULL_PTR == ctdnssv)
    {
        ctdnssv = ctdnssv_mgr_create_sp(ctdnssv_mgr, service_name);
        if(NULL_PTR == ctdnssv)
        {
            dbg_log(SEC_0055_CTDNSSVMGR, 0)(LOGSTDOUT, "error:ctdnssv_mgr_set: create sp '%s' failed\n", 
                            (const char *)cstring_get_str(service_name));
            return (EC_FALSE);
        }        
    }
    
    ctdnssv_item = ctdnssv_set(ctdnssv, tcid, ipaddr, port);
    if(NULL_PTR == ctdnssv_item)
    {
        dbg_log(SEC_0055_CTDNSSVMGR, 0)(LOGSTDOUT, "error:ctdnssv_mgr_set: set (tcid %s, ip %s) to sp '%s' failed\n",
                            c_word_to_ipv4(tcid),c_word_to_ipv4(ipaddr),
                            (const char *)cstring_get_str(service_name));
        return (EC_FALSE);
    }

    if(do_log(SEC_0055_CTDNSSVMGR, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] ctdnssv_mgr_set: set item done:\n");
        ctdnssv_item_print(LOGSTDOUT, ctdnssv_item);
    }
    return (EC_TRUE);
}

EC_BOOL ctdnssv_mgr_get(CTDNSSV_MGR *ctdnssv_mgr, const CSTRING *service_name, const UINT32 max_num, CTDNSSV_NODE_MGR *ctdnssv_node_mgr)
{
    CTDNSSV *ctdnssv;

    ctdnssv = ctdnssv_mgr_open_sp(ctdnssv_mgr, service_name);
    if(NULL_PTR == ctdnssv)
    {
        dbg_log(SEC_0055_CTDNSSVMGR, 0)(LOGSTDOUT, "error:ctdnssv_mgr_get: no sp '%s'\n", 
                        (const char *)cstring_get_str(service_name));
        return (EC_FALSE);
    }

    return ctdnssv_finger(ctdnssv, max_num, ctdnssv_node_mgr);
}

EC_BOOL ctdnssv_mgr_delete_one(CTDNSSV_MGR *ctdnssv_mgr, const CSTRING *service_name, const UINT32 tcid)
{
    CTDNSSV           *ctdnssv;

    ctdnssv = ctdnssv_mgr_open_sp(ctdnssv_mgr, service_name);
    if(NULL_PTR == ctdnssv)
    {
        return (EC_TRUE);
    }

    return ctdnssv_delete(ctdnssv, tcid);
}

EC_BOOL ctdnssv_mgr_delete(CTDNSSV_MGR *ctdnssv_mgr, const UINT32 tcid)
{
    CLIST_DATA      *clist_data;
    
    CLIST_LOOP_NEXT(CTDNSSV_MGR_SP_SERVICES(ctdnssv_mgr), clist_data)
    {
        CTDNSSV           *ctdnssv;
        
        ctdnssv = CLIST_DATA_DATA(clist_data);
        ctdnssv_delete(ctdnssv, tcid); /*delete tcid from service*/
    }
    return (EC_TRUE);
}

EC_BOOL ctdnssv_mgr_node_num_of_sp(CTDNSSV_MGR *ctdnssv_mgr, const CSTRING *service_name, UINT32 *node_num)
{
    CTDNSSV  *ctdnssv;
    
    ctdnssv = ctdnssv_mgr_open_sp(ctdnssv_mgr, service_name);
    if(NULL_PTR == ctdnssv)
    {
        dbg_log(SEC_0055_CTDNSSVMGR, 0)(LOGSTDOUT, "error:ctdnssv_mgr_tcid_num_of_sp: open sp '%s' failed\n", 
                        (const char *)cstring_get_str(service_name));
        return (EC_FALSE);
    }

    return ctdnssv_node_num(ctdnssv, node_num);
}

EC_BOOL ctdnssv_mgr_node_num(CTDNSSV_MGR *ctdnssv_mgr, UINT32 *node_num)
{
    CLIST_DATA      *clist_data;
    
    CLIST_LOOP_NEXT(CTDNSSV_MGR_SP_SERVICES(ctdnssv_mgr), clist_data)
    {
        CTDNSSV           *ctdnssv;
        UINT32             node_num_t;
        
        ctdnssv = CLIST_DATA_DATA(clist_data);
        node_num_t = 0;
        
        ctdnssv_node_num(ctdnssv, &node_num_t); /*delete tcid from service*/
        (*node_num) += node_num_t;
    }
    return (EC_TRUE);
}


#ifdef __cplusplus
}
#endif/*__cplusplus*/

