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
#include "cstring.h"

#include "cvector.h"
#include "chashalgo.h"
#include "cmd5.h"

#include "cbc.h"

#include "cmisc.h"

#include "task.h"

#include "cmpie.h"

#include "crb.h"
#include "chttp.h"
#include "chttps.h"
#include "crfs.h"
#include "ctdns.h"
#include "cp2p.h"
//#include "cp2phttp.h"

#include "findex.inc"

#define CP2P_MD_CAPACITY()                  (cbc_md_capacity(MD_CP2P))

#define CP2P_MD_GET(cp2p_md_id)     ((CP2P_MD *)cbc_md_get(MD_CP2P, (cp2p_md_id)))

#define CP2P_MD_ID_CHECK_INVALID(cp2p_md_id)  \
    ((CMPI_ANY_MODI != (cp2p_md_id)) && ((NULL_PTR == CP2P_MD_GET(cp2p_md_id)) || (0 == (CP2P_MD_GET(cp2p_md_id)->usedcounter))))

/**
*   for test only
*
*   to query the status of CP2P Module
*
**/
void cp2p_print_module_status(const UINT32 cp2p_md_id, LOG *log)
{
    CP2P_MD *cp2p_md;
    UINT32   this_cp2p_md_id;

    for( this_cp2p_md_id = 0; this_cp2p_md_id < CP2P_MD_CAPACITY(); this_cp2p_md_id ++ )
    {
        cp2p_md = CP2P_MD_GET(this_cp2p_md_id);

        if ( NULL_PTR != cp2p_md && 0 < cp2p_md->usedcounter )
        {
            sys_log(log,"CP2P Module # %ld : %ld refered\n",
                    this_cp2p_md_id,
                    cp2p_md->usedcounter);
        }
    }

    return ;
}

/**
*
*   free all static memory occupied by the appointed CP2P module
*
*
**/
UINT32 cp2p_free_module_static_mem(const UINT32 cp2p_md_id)
{
    CP2P_MD  *cp2p_md;

#if ( SWITCH_ON == CP2P_DEBUG_SWITCH )
    if ( CP2P_MD_ID_CHECK_INVALID(cp2p_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cp2p_free_module_static_mem: cp2p module #0x%lx not started.\n",
                cp2p_md_id);
        /*note: here do not exit but return only*/
        return ((UINT32)-1);
    }
#endif/*CP2P_DEBUG_SWITCH*/

    cp2p_md = CP2P_MD_GET(cp2p_md_id);

    free_module_static_mem(MD_CP2P, cp2p_md_id);

    return 0;
}

/**
*
* start CP2P module
*
**/
UINT32 cp2p_start(const CSTRING * crfs_root_dir, const CSTRING * ctdns_root_dir)
{
    CP2P_MD    *cp2p_md;
    UINT32      cp2p_md_id;

    UINT32      crfs_md_id;
    UINT32      ctdns_md_id;

    TASK_BRD   *task_brd;
    
    task_brd = task_brd_default_get();

    cbc_md_reg(MD_CP2P , 1);
    cbc_md_reg(MD_CRFS , 1);
    cbc_md_reg(MD_CTDNS, 1);
 
    cp2p_md_id = cbc_md_new(MD_CP2P, sizeof(CP2P_MD));
    if(CMPI_ERROR_MODI == cp2p_md_id)
    {
        return (CMPI_ERROR_MODI);
    }
 
    /* initialize new one CP2P module */
    cp2p_md = (CP2P_MD *)cbc_md_get(MD_CP2P, cp2p_md_id);
    cp2p_md->usedcounter   = 0;

    /* create a new module node */
    init_static_mem(); 

    /*TODO:*/
    CP2P_MD_CRFS_MODI(cp2p_md)  = CMPI_ERROR_MODI;
    CP2P_MD_CTDNS_MODI(cp2p_md) = CMPI_ERROR_MODI;
    
    cp2p_md->usedcounter = 1;

    crfs_md_id = crfs_start(crfs_root_dir);
    if(CMPI_ERROR_MODI == crfs_md_id)
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_start: start CRFS failed\n");
        cp2p_end(cp2p_md_id);
        return (CMPI_ERROR_MODI);
    }
    CP2P_MD_CRFS_MODI(cp2p_md) = crfs_md_id;

    ctdns_md_id = ctdns_start(ctdns_root_dir);
    if(CMPI_ERROR_MODI == ctdns_md_id)
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_start: start CTDNS failed\n");
        cp2p_end(cp2p_md_id);
        return (CMPI_ERROR_MODI);
    }
    CP2P_MD_CTDNS_MODI(cp2p_md) = ctdns_md_id;    

    csig_atexit_register((CSIG_ATEXIT_HANDLER)cp2p_end, cp2p_md_id);

    dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "[DEBUG] cp2p_start: "
                                         "start CP2P module #%ld\n", 
                                         cp2p_md_id);


#if 0
    if(SWITCH_ON == CP2PHTTP_SWITCH && CMPI_FWD_RANK == CMPI_LOCAL_RANK)
    {
        /*note: only the first CP2P module is allowed to launch tdns http server*/
        /*http server*/
        if(EC_TRUE == task_brd_default_check_csrv_enabled() && 0 == cp2p_md_id)
        {
            if(EC_FALSE == chttp_defer_request_queue_init())
            {
                dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_start: init cp2phttp defer request queue failed\n");
                cp2p_end(cp2p_md_id);
                return (CMPI_ERROR_MODI);
            }

            cp2phttp_log_start();
            task_brd_default_bind_http_srv_modi(cp2p_md_id);
            chttp_rest_list_push((const char *)CP2PHTTP_REST_API_NAME, cp2phttp_commit_request);

            dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "[DEBUG] cp2p_start: "
                                                    "start p2p http server\n");
        }
        else
        {
            dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "[DEBUG] cp2p_start: "
                                                    "NOT start p2p http server\n");        
        }
    } 
#endif
    return ( cp2p_md_id );
}

/**
*
* end CP2P module
*
**/
void cp2p_end(const UINT32 cp2p_md_id)
{
    CP2P_MD *cp2p_md;

    csig_atexit_unregister((CSIG_ATEXIT_HANDLER)cp2p_end, cp2p_md_id);

    cp2p_md = CP2P_MD_GET(cp2p_md_id);
    if(NULL_PTR == cp2p_md)
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_end: "
                                             "cp2p_md_id = %ld not exist.\n", 
                                             cp2p_md_id);
        dbg_exit(MD_CP2P, cp2p_md_id);
    }
 
    /* if the module is occupied by others,then decrease counter only */
    if ( 1 < cp2p_md->usedcounter )
    {
        cp2p_md->usedcounter --;
        return ;
    }

    if ( 0 == cp2p_md->usedcounter )
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_end: "
                                             "cp2p_md_id = %ld is not started.\n", 
                                             cp2p_md_id);
        dbg_exit(MD_CP2P, cp2p_md_id);
    }
   
    /* free module : */
    //cp2p_free_module_static_mem(cp2p_md_id);

    if(CMPI_ERROR_MODI != CP2P_MD_CRFS_MODI(cp2p_md))
    {
        crfs_end(CP2P_MD_CRFS_MODI(cp2p_md));
        CP2P_MD_CRFS_MODI(cp2p_md)  = CMPI_ERROR_MODI;
    }

    if(CMPI_ERROR_MODI != CP2P_MD_CTDNS_MODI(cp2p_md))
    {
        ctdns_end(CP2P_MD_CTDNS_MODI(cp2p_md));
        CP2P_MD_CTDNS_MODI(cp2p_md) = CMPI_ERROR_MODI;
    }

    cp2p_md->usedcounter = 0;

    dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "cp2p_end: stop CP2P module #%ld\n", cp2p_md_id);
    cbc_md_free(MD_CP2P, cp2p_md_id);

    return ;
}

/*------------------------------------------------ interface of file delivery ------------------------------------------------*/
CP2P_FILE *cp2p_file_new()
{
    CP2P_FILE *cp2p_file;
    
    alloc_static_mem(MM_CP2P_FILE, &cp2p_file, LOC_CP2P_0001);
    if(NULL_PTR != cp2p_file)
    {
        cp2p_file_init(cp2p_file);
    }
    return (cp2p_file);
}

EC_BOOL cp2p_file_init(CP2P_FILE *cp2p_file)
{
    cstring_init(CP2P_SERVICE_NAME(cp2p_file), NULL_PTR);
    cstring_init(CP2P_SRC_FILE_NAME(cp2p_file), NULL_PTR);
    cstring_init(CP2P_DES_FILE_NAME(cp2p_file), NULL_PTR);
    
    CP2P_SRC_FILE_SIZE(cp2p_file)    = 0;
    cmd5_digest_init(CP2P_SRC_FILE_MD5(cp2p_file));

    return (EC_TRUE);
}

EC_BOOL cp2p_file_clean(CP2P_FILE *cp2p_file)
{
    cstring_clean(CP2P_SERVICE_NAME(cp2p_file));
    cstring_clean(CP2P_SRC_FILE_NAME(cp2p_file));
    cstring_clean(CP2P_DES_FILE_NAME(cp2p_file));

    CP2P_SRC_FILE_SIZE(cp2p_file)    = 0;
    cmd5_digest_clean(CP2P_SRC_FILE_MD5(cp2p_file));
    
    return (EC_TRUE);
}

EC_BOOL cp2p_file_free(CP2P_FILE *cp2p_file)
{
    if(NULL_PTR != cp2p_file)
    {
        cp2p_file_clean(cp2p_file);
        free_static_mem(MM_CP2P_FILE, cp2p_file, LOC_CP2P_0002);
    }
    return (EC_TRUE);
}

int cp2p_file_cmp(const CP2P_FILE *cp2p_file_1st, const CP2P_FILE *cp2p_file_2nd)
{
    int     ret;

    if(CP2P_SRC_FILE_SIZE(cp2p_file_1st) > CP2P_SRC_FILE_SIZE(cp2p_file_2nd))
    {
        return (1);
    }
    if(CP2P_SRC_FILE_SIZE(cp2p_file_1st) < CP2P_SRC_FILE_SIZE(cp2p_file_2nd))
    {
        return (-1);
    }    

    ret = cstring_cmp(CP2P_SERVICE_NAME(cp2p_file_1st), CP2P_SERVICE_NAME(cp2p_file_2nd));
    if(0 != ret)
    {
        return (ret);
    }    

    ret = cmd5_digest_cmp(CP2P_SRC_FILE_MD5(cp2p_file_1st), CP2P_SRC_FILE_MD5(cp2p_file_2nd));
    if(0 != ret)
    {
        return (ret);
    }

    ret = cstring_cmp(CP2P_DES_FILE_NAME(cp2p_file_1st), CP2P_DES_FILE_NAME(cp2p_file_2nd));
    if(0 != ret)
    {
        return (ret);
    }    
    
    return cstring_cmp(CP2P_SRC_FILE_NAME(cp2p_file_1st), CP2P_SRC_FILE_NAME(cp2p_file_2nd));
}

void cp2p_file_print(LOG *log, const CP2P_FILE *cp2p_file)
{
    if(NULL_PTR != cp2p_file)
    {
        sys_log(log, "cp2p_file_print %p: service '%s', src '%s', des '%s', size %ld, md5 '%s'\n",
                     cp2p_file,
                     (char *)CP2P_SERVICE_NAME_STR(cp2p_file),
                     (char *)CP2P_SRC_FILE_NAME_STR(cp2p_file),
                     (char *)CP2P_DES_FILE_NAME_STR(cp2p_file),
                     CP2P_SRC_FILE_SIZE(cp2p_file),
                     c_md5_to_hex_str(CMD5_DIGEST_SUM(CP2P_SRC_FILE_MD5(cp2p_file))));
    }

    return;
}

static CSTRING * __cp2p_download_gen_file_name(const CSTRING *service_name, const CSTRING *src_file)
{
    CSTRING     *file_name;

    file_name = cstring_new(NULL_PTR, LOC_CP2P_0003);
    if(NULL_PTR == file_name)
    {
        return (NULL_PTR);
    }
    cstring_format(file_name, "/%s%s", 
                              (char *)cstring_get_str(service_name),
                              (char *)cstring_get_str(src_file));
    return (file_name);
}

/**
*
*  compare the expected downloading file and local file
*  
*
**/
EC_BOOL cp2p_download_file_exists(const UINT32 cp2p_md_id, const CP2P_FILE *cp2p_file)
{
    CP2P_MD          *cp2p_md;
    
    const char       *file_path;
    UINT32            fsize;
    CMD5_DIGEST       cmd5_digest;
    int               fd;
    
#if ( SWITCH_ON == CP2P_DEBUG_SWITCH )
    if ( CP2P_MD_ID_CHECK_INVALID(cp2p_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cp2p_download_file_exists: cp2p module #0x%lx not started.\n",
                cp2p_md_id);
        cp2p_print_module_status(cp2p_md_id, LOGSTDOUT);
        dbg_exit(MD_CP2P, cp2p_md_id);
    }
#endif/*CP2P_DEBUG_SWITCH*/

    cp2p_md = CP2P_MD_GET(cp2p_md_id);

    file_path = (const char *)CP2P_DES_FILE_NAME_STR(cp2p_file);
    if(EC_FALSE == c_file_access(file_path, F_OK))
    {
        dbg_log(SEC_0059_CP2P, 9)(LOGSTDOUT, "[DEBUG] cp2p_download_file_exists: "
                                             "file '%s' not exist\n",
                                             file_path);     
        return (EC_FALSE);
    }
    
    fd = c_file_open(file_path, O_RDONLY, 0666);
    if(ERR_FD == fd)
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_download_file_exists: "
                                             "open file '%s' failed\n",
                                             file_path);    
        return (EC_FALSE);        
    }

    if(EC_FALSE == c_file_size(fd, &fsize))
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_download_file_exists: "
                                             "size of file '%s' failed\n",
                                             file_path);    
        c_file_close(fd);
        return (EC_FALSE);        
    }

    if(fsize != CP2P_SRC_FILE_SIZE(cp2p_file))
    {
        dbg_log(SEC_0059_CP2P, 9)(LOGSTDOUT, "[DEBUG] cp2p_download_file_exists: "
                                             "file '%s', local file size %ld != p2p file size %ld\n",
                                             file_path,
                                             fsize,
                                             CP2P_SRC_FILE_SIZE(cp2p_file));    
        c_file_close(fd);
        return (EC_FALSE);
    }

    cmd5_digest_init(&cmd5_digest);
    if(EC_FALSE == c_file_md5(fd, CMD5_DIGEST_SUM(&cmd5_digest)))
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_download_file_exists: "
                                             "md5 of file '%s' failed\n",
                                             file_path);    
        c_file_close(fd);
        return (EC_FALSE);        
    }
    c_file_close(fd);

    if(EC_FALSE == cmd5_digest_is_equal(&cmd5_digest, CP2P_SRC_FILE_MD5(cp2p_file)))
    {
        dbg_log(SEC_0059_CP2P, 9)(LOGSTDOUT, "[DEBUG] cp2p_download_file_ep: "
                                             "file '%s', local file md5 '%s' != p2p file md5 '%s'\n",
                                             file_path,
                                             cmd5_digest_hex_str(&cmd5_digest),
                                             cmd5_digest_hex_str(CP2P_SRC_FILE_MD5(cp2p_file)));    
        return (EC_FALSE);
    }

    dbg_log(SEC_0059_CP2P, 9)(LOGSTDOUT, "[DEBUG] cp2p_download_file_ep: "
                                         "file '%s' exists same already\n",
                                         file_path);
    return (EC_TRUE);
}

/**
*
*  download file, store it to disk as des dir and notify src after completion
*  
*  note: need de-duplication
*
**/
EC_BOOL cp2p_download_file_ep(const UINT32 cp2p_md_id, const UINT32 src_tcid, const CP2P_FILE *cp2p_file)
{
    CP2P_MD          *cp2p_md;

    MOD_NODE          recv_mod_node;
    
    const CSTRING    *des_file_path;
    CSTRING          *rfs_file_path;
    CBYTES           *rfs_file_content;
    UINT32            expires_timestamp;
    EC_BOOL           need_expired_content;
    EC_BOOL           ret;    

    CMD5_DIGEST       cmd5_digest;
    
    UINT32            des_offset;
    int               des_fd;
    
#if ( SWITCH_ON == CP2P_DEBUG_SWITCH )
    if ( CP2P_MD_ID_CHECK_INVALID(cp2p_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cp2p_download_file_ep: cp2p module #0x%lx not started.\n",
                cp2p_md_id);
        cp2p_print_module_status(cp2p_md_id, LOGSTDOUT);
        dbg_exit(MD_CP2P, cp2p_md_id);
    }
#endif/*CP2P_DEBUG_SWITCH*/

    cp2p_md = CP2P_MD_GET(cp2p_md_id);

    des_file_path = CP2P_DES_FILE_NAME(cp2p_file);
    
    if(EC_TRUE == cp2p_download_file_exists(cp2p_md_id, cp2p_file))
    {
        dbg_log(SEC_0059_CP2P, 9)(LOGSTDOUT, "[DEBUG] cp2p_download_file_ep: "
                                             "file '%s' already exists\n",
                                             (char *)cstring_get_str(des_file_path));    
        return (EC_TRUE);
    }

    rfs_file_path = __cp2p_download_gen_file_name(CP2P_SERVICE_NAME(cp2p_file), CP2P_SRC_FILE_NAME(cp2p_file));
    if(NULL_PTR == rfs_file_path)
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_download_file_ep: "
                                             "gen download file name failed\n");    
        return (EC_FALSE);
    }
    
    rfs_file_content = cbytes_new(0);
    if(NULL_PTR == rfs_file_content)
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_download_file_ep: "
                                             "new cbytes failed\n");    
        cstring_free(rfs_file_path);
        return (EC_FALSE);
    } 

    need_expired_content = EC_TRUE;

    dbg_log(SEC_0059_CP2P, 9)(LOGSTDOUT, "[DEBUG] cp2p_download_file_ep: "
                                         "download '%s' from RFS tcid %s\n", 
                                         (char *)cstring_get_str(rfs_file_path),
                                         c_word_to_ipv4(src_tcid));

    MOD_NODE_TCID(&recv_mod_node) = src_tcid;
    MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&recv_mod_node) = 0;  

    ret = EC_FALSE;
    task_p2p(cp2p_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP, 
             &recv_mod_node, 
             &ret, FI_crfs_read, CMPI_ERROR_MODI, rfs_file_path, rfs_file_content, &expires_timestamp, need_expired_content);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_download_file_ep: "
                                             "download '%s' from RFS tcid %s failed\n", 
                                             (char *)cstring_get_str(rfs_file_path),
                                             c_word_to_ipv4(src_tcid));
                                             
        cstring_free(rfs_file_path);         
        cbytes_free(rfs_file_content);
        return (EC_FALSE);    
    }

    dbg_log(SEC_0059_CP2P, 9)(LOGSTDOUT, "[DEBUG] cp2p_download_file_ep: "
                                         "download '%s' from RFS tcid %s done\n", 
                                         (char *)cstring_get_str(rfs_file_path),
                                         c_word_to_ipv4(src_tcid));    

    /*check consistency: file size*/
    if(CP2P_SRC_FILE_SIZE(cp2p_file) != CBYTES_LEN(rfs_file_content))
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_download_file_ep: "
                                             "downloaded '%s' size %ld != src file size %ld\n", 
                                             (char *)cstring_get_str(rfs_file_path),
                                             CBYTES_LEN(rfs_file_content),
                                             CP2P_SRC_FILE_SIZE(cp2p_file));    
        cstring_free(rfs_file_path);
        cbytes_free(rfs_file_content); 
        return (EC_FALSE);
    }
    dbg_log(SEC_0059_CP2P, 9)(LOGSTDOUT, "[DEBUG] cp2p_download_file_ep: "
                                         "downloaded '%s' size %ld is OK\n", 
                                         (char *)cstring_get_str(rfs_file_path),
                                         CBYTES_LEN(rfs_file_content));     

    /*check consistency: file md5*/
    cmd5_digest_init(&cmd5_digest);
    cmd5_sum((uint32_t)CBYTES_LEN(rfs_file_content), CBYTES_BUF(rfs_file_content), CMD5_DIGEST_SUM(&cmd5_digest));
    
    if(EC_FALSE == cmd5_digest_is_equal(CP2P_SRC_FILE_MD5(cp2p_file), &cmd5_digest))
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_download_file_ep: "
                                             "downloaded '%s' md5 '%s' != src file md5 '%s'\n", 
                                             (char *)cstring_get_str(rfs_file_path),
                                             cmd5_digest_hex_str(&cmd5_digest),
                                             cmd5_digest_hex_str(CP2P_SRC_FILE_MD5(cp2p_file)));    
        cstring_free(rfs_file_path);
        cbytes_free(rfs_file_content);  
        return (EC_FALSE);
    }    
    dbg_log(SEC_0059_CP2P, 9)(LOGSTDOUT, "[DEBUG] cp2p_download_file_ep: "
                                         "downloaded '%s' md5 '%s' is OK\n", 
                                         (char *)cstring_get_str(rfs_file_path),
                                         cmd5_digest_hex_str(&cmd5_digest));    
                                         
    cstring_free(rfs_file_path);
    
    /*store to local disk*/
    des_fd = c_file_open((char *)cstring_get_str(des_file_path), O_RDWR | O_CREAT, 0666);
    if(ERR_FD == des_fd)
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_download_file_ep: "
                                             "open file '%s' to write failed\n", 
                                             (char *)cstring_get_str(des_file_path));      
        cbytes_free(rfs_file_content);
        return (EC_FALSE);
    }

    des_offset = 0;
    if(EC_FALSE == c_file_flush(des_fd, &des_offset, CBYTES_LEN(rfs_file_content), CBYTES_BUF(rfs_file_content)))
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_download_file_ep: "
                                             "flush %ld bytes to file '%s' failed\n", 
                                             CBYTES_LEN(rfs_file_content),   
                                             (char *)cstring_get_str(des_file_path));      
        c_file_close(des_fd);
        cbytes_free(rfs_file_content);
        return (EC_FALSE);
    }

    if(des_offset != CBYTES_LEN(rfs_file_content))
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_download_file_ep: "
                                             "flush %ld bytes to file '%s' failed due to offset = %ld \n", 
                                             CBYTES_LEN(rfs_file_content),   
                                             (char *)cstring_get_str(des_file_path),
                                             des_offset);      
        c_file_close(des_fd);
        cbytes_free(rfs_file_content);
        return (EC_FALSE);
    }

    c_file_close(des_fd);
    cbytes_free(rfs_file_content);

    dbg_log(SEC_0059_CP2P, 9)(LOGSTDOUT, "[DEBUG] cp2p_download_file_ep: "
                                         "flush %ld bytes to file '%s' done\n", 
                                         des_offset,   
                                         (char *)cstring_get_str(des_file_path));          
    return (EC_TRUE);
}

/**
*
*  download file, store it to (RFS) storage and notify src after completion
*
**/
EC_BOOL cp2p_download_file(const UINT32 cp2p_md_id, const UINT32 src_tcid, const CP2P_FILE *cp2p_file)
{
    CP2P_MD          *cp2p_md;

    MOD_NODE          recv_mod_node;

    CSTRING          *file_path;
    CBYTES           *file_content;
    UINT32            expires_timestamp;
    EC_BOOL           need_expired_content;
    EC_BOOL           ret;

    CMD5_DIGEST       cmd5_digest;

    UINT32            expire_nsec;

    CTDNSSV_NODE_MGR *ctdnssv_node_mgr;
    CLIST_DATA       *clist_data;
    
#if ( SWITCH_ON == CP2P_DEBUG_SWITCH )
    if ( CP2P_MD_ID_CHECK_INVALID(cp2p_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cp2p_download_file: cp2p module #0x%lx not started.\n",
                cp2p_md_id);
        cp2p_print_module_status(cp2p_md_id, LOGSTDOUT);
        dbg_exit(MD_CP2P, cp2p_md_id);
    }
#endif/*CP2P_DEBUG_SWITCH*/

    cp2p_md = CP2P_MD_GET(cp2p_md_id);

    dbg_log(SEC_0059_CP2P, 9)(LOGSTDOUT, "[DEBUG] cp2p_download_file: "
                                         "src tcid %s, "
                                         "file (service '%s', src '%s', des '%s', size %ld, md5 '%s')\n", 
                                         c_word_to_ipv4(src_tcid),
                                         (char *)CP2P_SERVICE_NAME_STR(cp2p_file),
                                         (char *)CP2P_SRC_FILE_NAME_STR(cp2p_file),
                                         (char *)CP2P_DES_FILE_NAME_STR(cp2p_file),
                                         CP2P_SRC_FILE_SIZE(cp2p_file),
                                         c_md5_to_hex_str(CMD5_DIGEST_SUM(CP2P_SRC_FILE_MD5(cp2p_file))));    

    /*download file from src and store it to storage*/

    file_path = __cp2p_download_gen_file_name(CP2P_SERVICE_NAME(cp2p_file), CP2P_SRC_FILE_NAME(cp2p_file));
    if(NULL_PTR == file_path)
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_download_file: "
                                             "gen download file name failed\n");    
        return (EC_FALSE);
    }

    file_content = cbytes_new(0);
    if(NULL_PTR == file_content)
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_download_file: "
                                             "new cbytes failed\n");    
        cstring_free(file_path);
        return (EC_FALSE);
    }    

    need_expired_content = EC_TRUE;

    dbg_log(SEC_0059_CP2P, 9)(LOGSTDOUT, "[DEBUG] cp2p_download_file: "
                                         "download '%s' from RFS tcid %s\n", 
                                         (char *)cstring_get_str(file_path),
                                         c_word_to_ipv4(src_tcid));

    MOD_NODE_TCID(&recv_mod_node) = src_tcid;
    MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&recv_mod_node) = 0;  

    ret = EC_FALSE;
    task_p2p(cp2p_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP, 
             &recv_mod_node, 
             &ret, FI_crfs_read, CMPI_ERROR_MODI, file_path, file_content, &expires_timestamp, need_expired_content);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_download_file: "
                                             "download '%s' from RFS tcid %s failed\n", 
                                             (char *)cstring_get_str(file_path),
                                             c_word_to_ipv4(src_tcid));    
        cstring_free(file_path);
        cbytes_free(file_content);    
        return (EC_FALSE);
    }

    dbg_log(SEC_0059_CP2P, 9)(LOGSTDOUT, "[DEBUG] cp2p_download_file: "
                                         "download '%s' from RFS tcid %s done\n", 
                                         (char *)cstring_get_str(file_path),
                                         c_word_to_ipv4(src_tcid));
                                         
    /*check consistency: file size*/
    if(CP2P_SRC_FILE_SIZE(cp2p_file) != CBYTES_LEN(file_content))
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_download_file: "
                                             "downloaded '%s' size %ld != src file size %ld\n", 
                                             (char *)cstring_get_str(file_path),
                                             CBYTES_LEN(file_content),
                                             CP2P_SRC_FILE_SIZE(cp2p_file));    
        cstring_free(file_path);
        cbytes_free(file_content); 
        return (EC_FALSE);
    }
    dbg_log(SEC_0059_CP2P, 9)(LOGSTDOUT, "[DEBUG] cp2p_download_file: "
                                         "downloaded '%s' size %ld is OK\n", 
                                         (char *)cstring_get_str(file_path),
                                         CBYTES_LEN(file_content));     

    /*check consistency: file md5*/
    cmd5_digest_init(&cmd5_digest);
    cmd5_sum((uint32_t)CBYTES_LEN(file_content), CBYTES_BUF(file_content), CMD5_DIGEST_SUM(&cmd5_digest));
    
    if(EC_FALSE == cmd5_digest_is_equal(CP2P_SRC_FILE_MD5(cp2p_file), &cmd5_digest))
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_download_file: "
                                             "downloaded '%s' md5 '%s' != src file md5 '%s'\n", 
                                             (char *)cstring_get_str(file_path),
                                             c_md5_to_hex_str(CMD5_DIGEST_SUM(&cmd5_digest)),
                                             c_md5_to_hex_str(CMD5_DIGEST_SUM(CP2P_SRC_FILE_MD5(cp2p_file))));    
        cstring_free(file_path);
        cbytes_free(file_content); 
        return (EC_FALSE);
    }    
    dbg_log(SEC_0059_CP2P, 9)(LOGSTDOUT, "[DEBUG] cp2p_download_file: "
                                         "downloaded '%s' md5 '%s' is OK\n", 
                                         (char *)cstring_get_str(file_path),
                                         c_md5_to_hex_str(CMD5_DIGEST_SUM(&cmd5_digest)));     

    /*store to storage*/
    expire_nsec = 0;
    if(EC_FALSE == crfs_update(CP2P_MD_CRFS_MODI(cp2p_md), file_path, file_content, expire_nsec))
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_download_file: "
                                             "write '%s' to storage failed\n", 
                                             (char *)cstring_get_str(file_path));    
        cstring_free(file_path);
        cbytes_free(file_content); 
        return (EC_FALSE);
    }
    dbg_log(SEC_0059_CP2P, 9)(LOGSTDOUT, "[DEBUG] cp2p_download_file: "
                                         "downloaded '%s' storing is OK\n", 
                                         (char *)cstring_get_str(file_path));     
    
    cstring_free(file_path);
    cbytes_free(file_content);

    /*notify reachable edges to download*/
    ctdnssv_node_mgr = ctdnssv_node_mgr_new();
    if(NULL_PTR == ctdnssv_node_mgr)
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_download_file: "
                                             "new ctdnssv_node_mgr failed\n");    
        return (EC_FALSE);
    }
    
    if(EC_FALSE == ctdns_finger_service(CP2P_MD_CTDNS_MODI(cp2p_md), 
                                CP2P_SERVICE_NAME(cp2p_file), CP2P_NODES_MAX_NUM, ctdnssv_node_mgr))
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_download_file: "
                                             "finger service '%s' failed\n",
                                             (char *)CP2P_SERVICE_NAME_STR(cp2p_file));    
        ctdnssv_node_mgr_free(ctdnssv_node_mgr);
        return (EC_FALSE);
    }

    CLIST_LOOP_NEXT(CTDNSSV_NODE_MGR_NODES(ctdnssv_node_mgr), clist_data)
    {
        CTDNSSV_NODE        *ctdnssv_node;

        ctdnssv_node = CLIST_DATA_DATA(clist_data);

        MOD_NODE_TCID(&recv_mod_node) = CTDNSSV_NODE_TCID(ctdnssv_node);
        MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
        MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
        MOD_NODE_MODI(&recv_mod_node) = 0;/*only one p2p module*/

        dbg_log(SEC_0059_CP2P, 9)(LOGSTDOUT, "[DEBUG] cp2p_download_file: "
                                             "file (service '%s', src '%s', des '%s', size %ld, md5 '%s') "
                                             "=> notify tcid %s to download\n", 
                                             (char *)CP2P_SERVICE_NAME_STR(cp2p_file),
                                             (char *)CP2P_SRC_FILE_NAME_STR(cp2p_file),
                                             (char *)CP2P_DES_FILE_NAME_STR(cp2p_file),
                                             CP2P_SRC_FILE_SIZE(cp2p_file),
                                             c_md5_to_hex_str(CMD5_DIGEST_SUM(CP2P_SRC_FILE_MD5(cp2p_file))),
                                             MOD_NODE_TCID_STR(&recv_mod_node));  
        task_p2p_no_wait(cp2p_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP, 
                         &recv_mod_node, 
                         NULL_PTR, FI_cp2p_download_file_ep, CMPI_ERROR_MODI, CMPI_LOCAL_TCID, cp2p_file);
    }
    ctdnssv_node_mgr_free(ctdnssv_node_mgr);
    
    dbg_log(SEC_0059_CP2P, 9)(LOGSTDOUT, "[DEBUG] cp2p_download_file: "
                                         "file (service '%s', src '%s', des '%s', size %ld, md5 '%s') "
                                         "=> notify src download completion\n", 
                                         (char *)CP2P_SERVICE_NAME_STR(cp2p_file),
                                         (char *)CP2P_SRC_FILE_NAME_STR(cp2p_file),
                                         (char *)CP2P_DES_FILE_NAME_STR(cp2p_file),
                                         CP2P_SRC_FILE_SIZE(cp2p_file),
                                         cmd5_digest_hex_str(CP2P_SRC_FILE_MD5(cp2p_file)));   


    MOD_NODE_TCID(&recv_mod_node) = src_tcid;
    MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&recv_mod_node) = 0;/*only one p2p module*/
    
    task_p2p_no_wait(cp2p_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP, 
                     &recv_mod_node, 
                     NULL_PTR, FI_cp2p_download_completion, CMPI_ERROR_MODI, CMPI_LOCAL_TCID, cp2p_file);

    return (EC_TRUE);
}

/**
*
*  notify completion of downloading file
*
**/
EC_BOOL cp2p_download_completion(const UINT32 cp2p_md_id, const UINT32 des_tcid, const CP2P_FILE *cp2p_file)
{
    CP2P_MD          *cp2p_md;
    
#if ( SWITCH_ON == CP2P_DEBUG_SWITCH )
    if ( CP2P_MD_ID_CHECK_INVALID(cp2p_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cp2p_download_completion: cp2p module #0x%lx not started.\n",
                cp2p_md_id);
        cp2p_print_module_status(cp2p_md_id, LOGSTDOUT);
        dbg_exit(MD_CP2P, cp2p_md_id);
    }
#endif/*CP2P_DEBUG_SWITCH*/

    cp2p_md = CP2P_MD_GET(cp2p_md_id);

    dbg_log(SEC_0059_CP2P, 9)(LOGSTDOUT, "[DEBUG] cp2p_download_completion: "
                                         "tcid %s report: "
                                         "file (service '%s', src '%s', des '%s', size %ld, md5 '%s') "
                                         "=> done\n", 
                                         c_word_to_ipv4(des_tcid),
                                         (char *)CP2P_SERVICE_NAME_STR(cp2p_file),
                                         (char *)CP2P_SRC_FILE_NAME_STR(cp2p_file),
                                         (char *)CP2P_DES_FILE_NAME_STR(cp2p_file),
                                         CP2P_SRC_FILE_SIZE(cp2p_file),
                                         c_md5_to_hex_str(CMD5_DIGEST_SUM(CP2P_SRC_FILE_MD5(cp2p_file))));  
                                         
    return (EC_TRUE);
}

/**
*
*  notify of downloading file
*
**/
EC_BOOL cp2p_download_notify(const UINT32 cp2p_md_id, const UINT32 src_tcid, const CP2P_FILE *cp2p_file)
{
    CP2P_MD          *cp2p_md;

    MOD_NODE          recv_mod_node;
    
#if ( SWITCH_ON == CP2P_DEBUG_SWITCH )
    if ( CP2P_MD_ID_CHECK_INVALID(cp2p_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cp2p_download_notify: cp2p module #0x%lx not started.\n",
                cp2p_md_id);
        cp2p_print_module_status(cp2p_md_id, LOGSTDOUT);
        dbg_exit(MD_CP2P, cp2p_md_id);
    }
#endif/*CP2P_DEBUG_SWITCH*/

    cp2p_md = CP2P_MD_GET(cp2p_md_id);

    MOD_NODE_TCID(&recv_mod_node) = CMPI_LOCAL_TCID;
    MOD_NODE_COMM(&recv_mod_node) = CMPI_LOCAL_COMM;
    MOD_NODE_RANK(&recv_mod_node) = CMPI_LOCAL_RANK;
    MOD_NODE_MODI(&recv_mod_node) = cp2p_md_id;
    
    task_p2p_no_wait(cp2p_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP, 
                     &recv_mod_node, 
                     NULL_PTR, FI_cp2p_download_file, CMPI_ERROR_MODI, src_tcid, cp2p_file);
                     
    return (EC_TRUE);
}

/**
*
*  broadcast notification of downloading file to all members of service
*
**/
EC_BOOL cp2p_download_broadcast(const UINT32 cp2p_md_id, const CP2P_FILE *cp2p_file)
{
    CP2P_MD          *cp2p_md;
    
#if ( SWITCH_ON == CP2P_DEBUG_SWITCH )
    if ( CP2P_MD_ID_CHECK_INVALID(cp2p_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cp2p_download_broadcast: cp2p module #0x%lx not started.\n",
                cp2p_md_id);
        cp2p_print_module_status(cp2p_md_id, LOGSTDOUT);
        dbg_exit(MD_CP2P, cp2p_md_id);
    }
#endif/*CP2P_DEBUG_SWITCH*/

    cp2p_md = CP2P_MD_GET(cp2p_md_id);

    return (EC_TRUE);
}

/**
*
*  upload file to RFS storage
*
**/
EC_BOOL cp2p_upload_file(const UINT32 cp2p_md_id, const CSTRING *src_file, const CSTRING *service_name, const CSTRING *des_file)
{
    CP2P_MD          *cp2p_md;

    const char       *src_file_path_str;
    UINT32            src_file_size;
    CBYTES           *src_file_bytes;
    UINT32            src_file_offset;

    CSTRING          *des_file_path;
    UINT32            des_file_expire_nsec;
    int               src_file_fd;
    
#if ( SWITCH_ON == CP2P_DEBUG_SWITCH )
    if ( CP2P_MD_ID_CHECK_INVALID(cp2p_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cp2p_upload_file: cp2p module #0x%lx not started.\n",
                cp2p_md_id);
        cp2p_print_module_status(cp2p_md_id, LOGSTDOUT);
        dbg_exit(MD_CP2P, cp2p_md_id);
    }
#endif/*CP2P_DEBUG_SWITCH*/

    cp2p_md = CP2P_MD_GET(cp2p_md_id);

    src_file_path_str = (const char *)cstring_get_str(src_file);
    if(EC_FALSE == c_file_access(src_file_path_str, F_OK))
    {
        dbg_log(SEC_0059_CP2P, 9)(LOGSTDOUT, "[DEBUG] cp2p_upload_file: "
                                             "file '%s' not exist\n",
                                             src_file_path_str);     
        return (EC_FALSE);
    }
    
    src_file_fd = c_file_open(src_file_path_str, O_RDONLY, 0666);
    if(ERR_FD == src_file_fd)
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_upload_file: "
                                             "open file '%s' failed\n",
                                             src_file_path_str);    
        return (EC_FALSE);        
    }

    if(EC_FALSE == c_file_size(src_file_fd, &src_file_size))
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_upload_file: "
                                             "size of file '%s' failed\n",
                                             src_file_path_str);    
        c_file_close(src_file_fd);
        return (EC_FALSE);        
    }

    dbg_log(SEC_0059_CP2P, 9)(LOGSTDOUT, "[DEBUG] cp2p_upload_file: "
                                         "file '%s', size %ld\n",
                                         src_file_path_str,
                                         src_file_size);      

    src_file_bytes = cbytes_new(src_file_size);
    if(NULL_PTR == src_file_bytes)
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_upload_file: "
                                             "new cbytes with size %ld failed\n",
                                             src_file_size);    
        c_file_close(src_file_fd);
        return (EC_FALSE);        
    }

    src_file_offset = 0;

    if(EC_FALSE == c_file_load(src_file_fd, &src_file_offset, src_file_size, CBYTES_BUF(src_file_bytes)))
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_upload_file: "
                                             "load file '%s' failed\n",
                                             src_file_path_str);    
        cbytes_free(src_file_bytes);
        c_file_close(src_file_fd);
        return (EC_FALSE);        
    }

    if(src_file_offset != src_file_size)
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_upload_file: "
                                             "load file '%s', expect %ld but read %ld bytes\n",
                                             src_file_path_str,
                                             src_file_size,
                                             src_file_offset);    
        cbytes_free(src_file_bytes);
        c_file_close(src_file_fd);
        return (EC_FALSE);        
    }
    c_file_close(src_file_fd);

    des_file_path = __cp2p_download_gen_file_name(service_name, des_file);
    if(NULL_PTR == des_file_path)
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_upload_file: "
                                             "gen download file name failed\n");    
        cbytes_free(src_file_bytes);
        return (EC_FALSE);
    }

    des_file_expire_nsec = 0;
    if(EC_FALSE == crfs_update(CP2P_MD_CRFS_MODI(cp2p_md), des_file_path, src_file_bytes, des_file_expire_nsec))
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_upload_file: "
                                             "update '%s' to storage failed\n", 
                                             (char *)cstring_get_str(des_file_path));    
        cbytes_free(src_file_bytes);
        cstring_free(des_file_path);
        return (EC_FALSE);
    }
    dbg_log(SEC_0059_CP2P, 9)(LOGSTDOUT, "[DEBUG] cp2p_download_file: "
                                         "update '%s' to storage is OK\n", 
                                         (char *)cstring_get_str(des_file_path));     
    
    

    dbg_log(SEC_0059_CP2P, 9)(LOGSTDOUT, "[DEBUG] cp2p_download_file: "
                                         "upload '%s' to storage '%s' done\n", 
                                         (char *)cstring_get_str(src_file),
                                         (char *)cstring_get_str(des_file_path));       
    cbytes_free(src_file_bytes);
    cstring_free(des_file_path);
    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/


