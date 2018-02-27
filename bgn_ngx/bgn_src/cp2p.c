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
#include "ctdnshttp.h"
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
    CP2P_MD_NETWORK_LEVEL(cp2p_md)  = TASK_BRD_NETWORK_LEVEL(task_brd);
    CP2P_MD_NETWORK_TCID(cp2p_md)   = TASK_BRD_TCID(task_brd);
    CP2P_MD_CRFS_MODI(cp2p_md)      = CMPI_ERROR_MODI;
    CP2P_MD_CTDNS_MODI(cp2p_md)     = CMPI_ERROR_MODI;
    
    cp2p_md->usedcounter = 1;

    crfs_md_id = crfs_start(crfs_root_dir);
    if(CMPI_ERROR_MODI == crfs_md_id)
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_start: start CRFS failed\n");
        cp2p_end(cp2p_md_id);
        return (CMPI_ERROR_MODI);
    }
    CP2P_MD_CRFS_MODI(cp2p_md) = crfs_md_id;

    /* create rfs np and dn */
    if(EC_FALSE == crfs_is_npp(crfs_md_id))
    {
        CSTRING     *crfsnp_db_root_dir;
        UINT32       crfsnp_max_num;

        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "[DEBUG] cp2p_start: create rfs npp\n");
        
        crfsnp_db_root_dir = cstring_make("%s/rfs%02ld", (char *)cstring_get_str(crfs_root_dir), crfs_md_id);
        if(NULL_PTR == crfsnp_db_root_dir)
        {
            dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_start: new crfsnp_db_root_dir failed\n");
            cp2p_end(cp2p_md_id);
            return (CMPI_ERROR_MODI);
        }

        crfsnp_max_num = 1;
        if(EC_FALSE == crfs_create_npp(crfs_md_id, CRFSNP_128M_MODEL, crfsnp_max_num, 
                                       CHASH_RS_ALGO_ID, crfsnp_db_root_dir))
        {
            dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_start: create rfs npp failed\n");
            cstring_free(crfsnp_db_root_dir);
            cp2p_end(cp2p_md_id);
            return (CMPI_ERROR_MODI);
        }
        cstring_free(crfsnp_db_root_dir);
    }
    
    if(EC_FALSE == crfs_is_dn(crfs_md_id))
    {
        CSTRING     *crfsdn_db_root_dir;
        UINT32       crfs_disk_no;

        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "[DEBUG] cp2p_start: create rfs dn\n");

        crfsdn_db_root_dir = cstring_make("%s/rfs%02ld", (char *)cstring_get_str(crfs_root_dir), crfs_md_id);
        if(NULL_PTR == crfsdn_db_root_dir)
        {
            dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_start: new crfsdn_db_root_dir failed\n");
            cp2p_end(cp2p_md_id);
            return (CMPI_ERROR_MODI);
        }      

        if(EC_FALSE == crfs_create_dn(crfs_md_id, crfsdn_db_root_dir))
        {
            dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_start: create rfs dn failed\n");
            cstring_free(crfsdn_db_root_dir);
            cp2p_end(cp2p_md_id);
            return (CMPI_ERROR_MODI);
        }
        cstring_free(crfsdn_db_root_dir);

        crfs_disk_no = 0;
        if(EC_FALSE == crfs_add_disk(crfs_md_id, crfs_disk_no))
        {
            dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_start: add rfs disk failed\n");
            cp2p_end(cp2p_md_id);
            return (CMPI_ERROR_MODI);
        }
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "[DEBUG] cp2p_start: create rfs dn done\n");
    }

    ctdns_md_id = ctdns_start(ctdns_root_dir);
    if(CMPI_ERROR_MODI == ctdns_md_id)
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_start: start CTDNS failed\n");
        cp2p_end(cp2p_md_id);
        return (CMPI_ERROR_MODI);
    }
    CP2P_MD_CTDNS_MODI(cp2p_md) = ctdns_md_id;    

    /* create tdns np */
    if(EC_FALSE == ctdns_has_npp(ctdns_md_id))
    {
        CSTRING    *ctdnsnp_db_root_dir;
        UINT32      ctdnsnp_model;
        UINT32      ctdnsnp_max_num;

        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "[DEBUG] cp2p_start: create tdns\n");

        ctdnsnp_db_root_dir = cstring_make("%s/tdns%02ld", (char *)cstring_get_str(ctdns_root_dir), ctdns_md_id);
        if(NULL_PTR == ctdnsnp_db_root_dir)
        {
            dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_start: new ctdnsnp_db_root_dir failed\n");
            cp2p_end(cp2p_md_id);
            return (CMPI_ERROR_MODI);
        }

        ctdnsnp_model   = CTDNSNP_032M_MODEL;
        ctdnsnp_max_num = 1;
        if(EC_FALSE == ctdns_create_npp(ctdns_md_id, ctdnsnp_model, ctdnsnp_max_num, ctdnsnp_db_root_dir))
        {
            dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_start: creat tdns np failed\n");
            cstring_free(ctdnsnp_db_root_dir);
            cp2p_end(cp2p_md_id);
            return (CMPI_ERROR_MODI);
        }
        cstring_free(ctdnsnp_db_root_dir);
    }

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

    CP2P_MD_NETWORK_LEVEL(cp2p_md)  = CMPI_ERROR_NETWORK;
    CP2P_MD_NETWORK_TCID(cp2p_md)   = CMPI_ERROR_TCID;
    
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
    cstring_init(CP2P_FILE_SERVICE_NAME(cp2p_file), NULL_PTR);

    cstring_init(CP2P_FILE_SRC_NAME(cp2p_file), NULL_PTR);
    cstring_init(CP2P_FILE_DES_NAME(cp2p_file), NULL_PTR);
    
    CP2P_FILE_SRC_SIZE(cp2p_file)    = 0;
    cmd5_digest_init(CP2P_FILE_SRC_MD5(cp2p_file));

    CP2P_FILE_REPORT_TCID(cp2p_file) = CMPI_ERROR_TCID;
    return (EC_TRUE);
}

EC_BOOL cp2p_file_clean(CP2P_FILE *cp2p_file)
{
    cstring_clean(CP2P_FILE_SERVICE_NAME(cp2p_file));
    
    cstring_clean(CP2P_FILE_SRC_NAME(cp2p_file));
    cstring_clean(CP2P_FILE_DES_NAME(cp2p_file));

    CP2P_FILE_SRC_SIZE(cp2p_file)    = 0;
    cmd5_digest_clean(CP2P_FILE_SRC_MD5(cp2p_file));

    CP2P_FILE_REPORT_TCID(cp2p_file) = CMPI_ERROR_TCID;
    
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

EC_BOOL cp2p_file_clone(const CP2P_FILE *cp2p_file_src, CP2P_FILE *cp2p_file_des)
{
    if(NULL_PTR != cp2p_file_src && NULL_PTR != cp2p_file_des)
    {
        cstring_clone(CP2P_FILE_SERVICE_NAME(cp2p_file_src), CP2P_FILE_SERVICE_NAME(cp2p_file_des));

        cstring_clone(CP2P_FILE_SRC_NAME(cp2p_file_src), CP2P_FILE_SRC_NAME(cp2p_file_des));
        cstring_clone(CP2P_FILE_DES_NAME(cp2p_file_src), CP2P_FILE_DES_NAME(cp2p_file_des));

        CP2P_FILE_SRC_SIZE(cp2p_file_des) = CP2P_FILE_SRC_SIZE(cp2p_file_src);

        cmd5_digest_clone(CP2P_FILE_SRC_MD5(cp2p_file_src), CP2P_FILE_SRC_MD5(cp2p_file_des));
    }
    return (EC_TRUE);
}

int cp2p_file_cmp(const CP2P_FILE *cp2p_file_1st, const CP2P_FILE *cp2p_file_2nd)
{
    int     ret;

    if(CP2P_FILE_SRC_SIZE(cp2p_file_1st) > CP2P_FILE_SRC_SIZE(cp2p_file_2nd))
    {
        return (1);
    }
    if(CP2P_FILE_SRC_SIZE(cp2p_file_1st) < CP2P_FILE_SRC_SIZE(cp2p_file_2nd))
    {
        return (-1);
    }    

    ret = cstring_cmp(CP2P_FILE_SERVICE_NAME(cp2p_file_1st), CP2P_FILE_SERVICE_NAME(cp2p_file_2nd));
    if(0 != ret)
    {
        return (ret);
    }    

    ret = cmd5_digest_cmp(CP2P_FILE_SRC_MD5(cp2p_file_1st), CP2P_FILE_SRC_MD5(cp2p_file_2nd));
    if(0 != ret)
    {
        return (ret);
    }

    ret = cstring_cmp(CP2P_FILE_DES_NAME(cp2p_file_1st), CP2P_FILE_DES_NAME(cp2p_file_2nd));
    if(0 != ret)
    {
        return (ret);
    }    
    
    return cstring_cmp(CP2P_FILE_SRC_NAME(cp2p_file_1st), CP2P_FILE_SRC_NAME(cp2p_file_2nd));
}

EC_BOOL cp2p_file_is(const CP2P_FILE *cp2p_file, const CBYTES *file_content)
{
    CMD5_DIGEST     cmd5_digest;
    
    /*check consistency: file size*/
    if(CP2P_FILE_SRC_SIZE(cp2p_file) != CBYTES_LEN(file_content))
    {
        return (EC_FALSE);
    }

    /*check consistency: file md5*/
    cmd5_digest_init(&cmd5_digest);
    cmd5_sum((uint32_t)CBYTES_LEN(file_content), CBYTES_BUF(file_content), CMD5_DIGEST_SUM(&cmd5_digest));
    
    if(EC_FALSE == cmd5_digest_is_equal(CP2P_FILE_SRC_MD5(cp2p_file), &cmd5_digest))
    {
        return (EC_FALSE);
    }
    
    return (EC_TRUE);
}

void cp2p_file_print(LOG *log, const CP2P_FILE *cp2p_file)
{
    if(NULL_PTR != cp2p_file)
    {
        sys_log(log, "cp2p_file_print %p: service '%s', "
                     "file (src '%s', des '%s', size %ld, md5 '%s')\n",
                     cp2p_file, 
                     (char *)CP2P_FILE_SERVICE_NAME_STR(cp2p_file), 
                     (char *)CP2P_FILE_SRC_NAME_STR(cp2p_file),
                     (char *)CP2P_FILE_DES_NAME_STR(cp2p_file),
                     CP2P_FILE_SRC_SIZE(cp2p_file),
                     CP2P_FILE_SRC_MD5_DIGEST_STR(cp2p_file));
    }

    return;
}

/**
*
*  generate file name in storage
*  
*
**/
static CSTRING * __cp2p_file_name_gen(const CSTRING *service_name, const CSTRING *src_file)
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
EC_BOOL cp2p_file_exists_local(const UINT32 cp2p_md_id, const CP2P_FILE *cp2p_file)
{
    CP2P_MD          *cp2p_md;
    
    const char       *file_path_str;
    UINT32            fsize;
    CMD5_DIGEST       cmd5_digest;
    int               fd;
    
#if ( SWITCH_ON == CP2P_DEBUG_SWITCH )
    if ( CP2P_MD_ID_CHECK_INVALID(cp2p_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cp2p_file_exists_local: cp2p module #0x%lx not started.\n",
                cp2p_md_id);
        cp2p_print_module_status(cp2p_md_id, LOGSTDOUT);
        dbg_exit(MD_CP2P, cp2p_md_id);
    }
#endif/*CP2P_DEBUG_SWITCH*/

    cp2p_md = CP2P_MD_GET(cp2p_md_id);

    file_path_str = (const char *)CP2P_FILE_DES_NAME_STR(cp2p_file);
    if(EC_FALSE == c_file_access(file_path_str, F_OK))
    {
        dbg_log(SEC_0059_CP2P, 9)(LOGSTDOUT, "[DEBUG] cp2p_file_exists_local: "
                                             "file '%s' not exist\n",
                                             file_path_str);     
        return (EC_FALSE);
    }
    
    fd = c_file_open(file_path_str, O_RDONLY, 0666);
    if(ERR_FD == fd)
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_file_exists_local: "
                                             "open file '%s' failed\n",
                                             file_path_str);    
        return (EC_FALSE);        
    }

    if(EC_FALSE == c_file_size(fd, &fsize))
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_file_exists_local: "
                                             "size of file '%s' failed\n",
                                             file_path_str);    
        c_file_close(fd);
        return (EC_FALSE);        
    }

    if(fsize != CP2P_FILE_SRC_SIZE(cp2p_file))
    {
        dbg_log(SEC_0059_CP2P, 9)(LOGSTDOUT, "[DEBUG] cp2p_file_exists_local: "
                                             "file '%s', local file size %ld != p2p file size %ld\n",
                                             file_path_str,
                                             fsize,
                                             CP2P_FILE_SRC_SIZE(cp2p_file));    
        c_file_close(fd);
        return (EC_FALSE);
    }

    cmd5_digest_init(&cmd5_digest);
    if(EC_FALSE == c_file_md5(fd, CMD5_DIGEST_SUM(&cmd5_digest)))
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_file_exists_local: "
                                             "md5 of file '%s' failed\n",
                                             file_path_str);    
        c_file_close(fd);
        return (EC_FALSE);        
    }
    c_file_close(fd);

    if(EC_FALSE == cmd5_digest_is_equal(&cmd5_digest, CP2P_FILE_SRC_MD5(cp2p_file)))
    {
        dbg_log(SEC_0059_CP2P, 9)(LOGSTDOUT, "[DEBUG] cp2p_file_exists_local: "
                                             "file '%s', local file md5 '%s' != p2p file md5 '%s'\n",
                                             file_path_str,
                                             cmd5_digest_hex_str(&cmd5_digest),
                                             cmd5_digest_hex_str(CP2P_FILE_SRC_MD5(cp2p_file)));    
        return (EC_FALSE);
    }

    dbg_log(SEC_0059_CP2P, 9)(LOGSTDOUT, "[DEBUG] cp2p_file_exists_local: "
                                         "file '%s' exists already\n",
                                         file_path_str);
    return (EC_TRUE);
}

/**
*
*  check p2p file existing in storage
*
*
**/
EC_BOOL cp2p_file_exists(const UINT32 cp2p_md_id, const CP2P_FILE *cp2p_file)
{
    CP2P_MD          *cp2p_md;

    CSTRING          *file_path;
    UINT32            file_size;
    CMD5_DIGEST       cmd5_digest;
    
#if ( SWITCH_ON == CP2P_DEBUG_SWITCH )
    if ( CP2P_MD_ID_CHECK_INVALID(cp2p_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cp2p_file_exists: cp2p module #0x%lx not started.\n",
                cp2p_md_id);
        cp2p_print_module_status(cp2p_md_id, LOGSTDOUT);
        dbg_exit(MD_CP2P, cp2p_md_id);
    }
#endif/*CP2P_DEBUG_SWITCH*/

    cp2p_md = CP2P_MD_GET(cp2p_md_id);

    file_path = __cp2p_file_name_gen(CP2P_FILE_SERVICE_NAME(cp2p_file), CP2P_FILE_SRC_NAME(cp2p_file));
    if(NULL_PTR == file_path)
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_file_exists: "
                                             "gen download file name failed\n");    
        return (EC_FALSE);
    }

    cmd5_digest_init(&cmd5_digest);

    if(EC_FALSE == crfs_is_file(CP2P_MD_CRFS_MODI(cp2p_md), file_path))
    {
        dbg_log(SEC_0059_CP2P, 9)(LOGSTDOUT, "[DEBUG] cp2p_file_exists: "
                                             "file '%s' not exist\n",
                                             (char *)cstring_get_str(file_path));     
        cstring_free(file_path);
        return (EC_FALSE);
    }

    if(EC_FALSE == crfs_file_size(CP2P_MD_CRFS_MODI(cp2p_md), file_path, &file_size))
    {
        dbg_log(SEC_0059_CP2P, 9)(LOGSTDOUT, "[DEBUG] cp2p_file_exists: "
                                             "get size of '%s' failed\n",
                                             (char *)cstring_get_str(file_path));     
        cstring_free(file_path);
        return (EC_FALSE);
    }

    if(CP2P_FILE_SRC_SIZE(cp2p_file) != file_size)
    {
        dbg_log(SEC_0059_CP2P, 9)(LOGSTDOUT, "[DEBUG] cp2p_file_exists: "
                                             "file '%s' size %ld != p2p file size %ld\n",
                                             (char *)cstring_get_str(file_path), file_size, CP2P_FILE_SRC_SIZE(cp2p_file));     
        cstring_free(file_path);
        return (EC_FALSE);
    }
    
    if(EC_FALSE == crfs_file_md5sum(CP2P_MD_CRFS_MODI(cp2p_md), file_path, &cmd5_digest))
    {
        dbg_log(SEC_0059_CP2P, 9)(LOGSTDOUT, "[DEBUG] cp2p_file_exists: "
                                             "get md5 of '%s' failed\n",
                                             (char *)cstring_get_str(file_path));     
        cstring_free(file_path);
        return (EC_FALSE);
    }

    if(EC_FALSE == cmd5_digest_is_equal(CP2P_FILE_SRC_MD5(cp2p_file), &cmd5_digest))
    {
        dbg_log(SEC_0059_CP2P, 9)(LOGSTDOUT, "[DEBUG] cp2p_file_exists: "
                                             "file '%s', storage file md5 '%s' != p2p file md5 '%s'\n",
                                             (char *)cstring_get_str(file_path),
                                             cmd5_digest_hex_str(&cmd5_digest),
                                             cmd5_digest_hex_str(CP2P_FILE_SRC_MD5(cp2p_file)));     
        cstring_free(file_path);
        return (EC_FALSE);
    }        
    
    cstring_free(file_path);
    return (EC_TRUE);
}

/**
*
*  notify edges under current network to push p2p file
*
**/
EC_BOOL cp2p_file_push_notify(const UINT32 cp2p_md_id, const UINT32 des_network, const UINT32 des_tcid, const CP2P_FILE *cp2p_file)
{
    CP2P_MD          *cp2p_md;

    TASK_MGR         *task_mgr;
    
    CTDNSSV_NODE_MGR *ctdnssv_node_mgr;
    CLIST_DATA       *clist_data;
        
#if ( SWITCH_ON == CP2P_DEBUG_SWITCH )
    if ( CP2P_MD_ID_CHECK_INVALID(cp2p_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cp2p_file_push_notify: cp2p module #0x%lx not started.\n",
                cp2p_md_id);
        cp2p_print_module_status(cp2p_md_id, LOGSTDOUT);
        dbg_exit(MD_CP2P, cp2p_md_id);
    }
#endif/*CP2P_DEBUG_SWITCH*/

    cp2p_md = CP2P_MD_GET(cp2p_md_id);

    ctdnssv_node_mgr = ctdnssv_node_mgr_new();
    if(NULL_PTR == ctdnssv_node_mgr)
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_file_push_notify: "
                                             "new ctdnssv_node_mgr failed\n");    
        return (EC_FALSE);
    }
    
    if(EC_FALSE == ctdns_finger_edge_service(CP2P_MD_CTDNS_MODI(cp2p_md), 
                                        CP2P_FILE_SERVICE_NAME(cp2p_file), 
                                        CP2P_NODES_MAX_NUM, 
                                        ctdnssv_node_mgr))
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_file_push_notify: "
                                             "finger service '%s' failed\n",
                                             (char *)CP2P_FILE_SERVICE_NAME_STR(cp2p_file));    
        ctdnssv_node_mgr_free(ctdnssv_node_mgr);
        return (EC_FALSE);
    }

    if(EC_TRUE == ctdnssv_node_mgr_is_empty(ctdnssv_node_mgr))
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_file_push_notify: "
                                             "no edge node for service '%s'\n",
                                             (char *)CP2P_FILE_SERVICE_NAME_STR(cp2p_file));    
        ctdnssv_node_mgr_free(ctdnssv_node_mgr);
        return (EC_FALSE);
    }

    /*try one by one*/
    task_mgr = task_new(NULL_PTR, TASK_PRIO_NORMAL, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP);
    CLIST_LOOP_NEXT(CTDNSSV_NODE_MGR_NODES(ctdnssv_node_mgr), clist_data)
    {
        CTDNSSV_NODE        *ctdnssv_node;
        MOD_NODE             recv_mod_node;

        ctdnssv_node = CLIST_DATA_DATA(clist_data);

        MOD_NODE_TCID(&recv_mod_node) = CTDNSSV_NODE_TCID(ctdnssv_node);
        MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
        MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
        MOD_NODE_MODI(&recv_mod_node) = 0;/*only one p2p module*/

        if(do_log(SEC_0059_CP2P, 9))
        {
            dbg_log(SEC_0059_CP2P, 9)(LOGSTDOUT, "[DEBUG] cp2p_file_push_notify: "
                                                 "notify service '%s' edge node '%s' to push p2p file "
                                                 "to network %ld, des tcid '%s'\n",
                                                 (char *)CP2P_FILE_SERVICE_NAME_STR(cp2p_file),
                                                 c_word_to_ipv4(CTDNSSV_NODE_TCID(ctdnssv_node)),
                                                 des_network,
                                                 c_word_to_ipv4(des_tcid)); 
            cp2p_file_print(LOGSTDOUT, cp2p_file);
        }
        
        task_p2p_inc(task_mgr, 
                    cp2p_md_id, 
                    &recv_mod_node,
                    NULL_PTR, FI_cp2p_file_push, CMPI_ERROR_MODI, des_network, des_tcid, cp2p_file);
    }
    ctdnssv_node_mgr_free(ctdnssv_node_mgr);  
    
    task_no_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);
                     
    return (EC_TRUE);
}

/**
*
*  notify edges under current network to flush p2p file
*
**/
EC_BOOL cp2p_file_flush_notify(const UINT32 cp2p_md_id, const UINT32 des_network, const UINT32 des_tcid, const CP2P_FILE *cp2p_file)
{
    CP2P_MD          *cp2p_md;

    TASK_MGR         *task_mgr;
    
    CTDNSSV_NODE_MGR *ctdnssv_node_mgr;
    CLIST_DATA       *clist_data;
        
#if ( SWITCH_ON == CP2P_DEBUG_SWITCH )
    if ( CP2P_MD_ID_CHECK_INVALID(cp2p_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cp2p_file_flush_notify: cp2p module #0x%lx not started.\n",
                cp2p_md_id);
        cp2p_print_module_status(cp2p_md_id, LOGSTDOUT);
        dbg_exit(MD_CP2P, cp2p_md_id);
    }
#endif/*CP2P_DEBUG_SWITCH*/

    cp2p_md = CP2P_MD_GET(cp2p_md_id);

    ctdnssv_node_mgr = ctdnssv_node_mgr_new();
    if(NULL_PTR == ctdnssv_node_mgr)
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_file_flush_notify: "
                                             "new ctdnssv_node_mgr failed\n");    
        return (EC_FALSE);
    }
    
    if(EC_FALSE == ctdns_finger_edge_service(CP2P_MD_CTDNS_MODI(cp2p_md), 
                                             CP2P_FILE_SERVICE_NAME(cp2p_file), 
                                             CP2P_NODES_MAX_NUM, 
                                             ctdnssv_node_mgr))
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_file_flush_notify: "
                                             "finger edge service '%s' failed\n",
                                             (char *)CP2P_FILE_SERVICE_NAME_STR(cp2p_file));    
        ctdnssv_node_mgr_free(ctdnssv_node_mgr);
        return (EC_FALSE);
    }

    if(EC_TRUE == ctdnssv_node_mgr_is_empty(ctdnssv_node_mgr))
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_file_flush_notify: "
                                             "no upper node for service '%s'\n",
                                             (char *)CP2P_FILE_SERVICE_NAME_STR(cp2p_file));    
        ctdnssv_node_mgr_free(ctdnssv_node_mgr);
        return (EC_FALSE);
    }

    /*try one by one*/
    task_mgr = task_new(NULL_PTR, TASK_PRIO_NORMAL, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP);
    CLIST_LOOP_NEXT(CTDNSSV_NODE_MGR_NODES(ctdnssv_node_mgr), clist_data)
    {
        CTDNSSV_NODE        *ctdnssv_node;
        MOD_NODE             recv_mod_node;

        ctdnssv_node = CLIST_DATA_DATA(clist_data);

        MOD_NODE_TCID(&recv_mod_node) = CTDNSSV_NODE_TCID(ctdnssv_node);
        MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
        MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
        MOD_NODE_MODI(&recv_mod_node) = 0;/*only one p2p module*/

        if(do_log(SEC_0059_CP2P, 9))
        {
            dbg_log(SEC_0059_CP2P, 9)(LOGSTDOUT, "[DEBUG] cp2p_file_flush_notify: "
                                                 "notify service '%s' edge node '%s' to flush p2p file "
                                                 "to network %ld, des tcid '%s'\n",
                                                 (char *)CP2P_FILE_SERVICE_NAME_STR(cp2p_file),
                                                 c_word_to_ipv4(CTDNSSV_NODE_TCID(ctdnssv_node)),
                                                 des_network,
                                                 c_word_to_ipv4(des_tcid)); 
            cp2p_file_print(LOGSTDOUT, cp2p_file);
        }
        
        task_p2p_inc(task_mgr, 
                    cp2p_md_id, 
                    &recv_mod_node,
                    NULL_PTR, FI_cp2p_file_flush, CMPI_ERROR_MODI, des_network, des_tcid, cp2p_file);
    }
    ctdnssv_node_mgr_free(ctdnssv_node_mgr);  
    
    task_no_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);
                     
    return (EC_TRUE);
}

/**
*
*  notify upper nodes of current network to report p2p file is ready or deleted
*
**/
EC_BOOL cp2p_file_report_notify(const UINT32 cp2p_md_id, const UINT32 des_network, const UINT32 des_tcid, const CP2P_FILE *cp2p_file)
{
    CP2P_MD          *cp2p_md;

    TASK_MGR         *task_mgr;
    
    CTDNSSV_NODE_MGR *ctdnssv_node_mgr;
    CLIST_DATA       *clist_data;
        
#if ( SWITCH_ON == CP2P_DEBUG_SWITCH )
    if ( CP2P_MD_ID_CHECK_INVALID(cp2p_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cp2p_file_report_notify: cp2p module #0x%lx not started.\n",
                cp2p_md_id);
        cp2p_print_module_status(cp2p_md_id, LOGSTDOUT);
        dbg_exit(MD_CP2P, cp2p_md_id);
    }
#endif/*CP2P_DEBUG_SWITCH*/

    cp2p_md = CP2P_MD_GET(cp2p_md_id);

    ctdnssv_node_mgr = ctdnssv_node_mgr_new();
    if(NULL_PTR == ctdnssv_node_mgr)
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_file_report_notify: "
                                             "new ctdnssv_node_mgr failed\n");    
        return (EC_FALSE);
    }
    
    if(EC_FALSE == ctdns_finger_upper_service(CP2P_MD_CTDNS_MODI(cp2p_md), 
                                        CP2P_FILE_SERVICE_NAME(cp2p_file), 
                                        CP2P_NODES_MAX_NUM, 
                                        ctdnssv_node_mgr))
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_file_report_notify: "
                                             "finger upper service '%s' failed\n",
                                             (char *)CP2P_FILE_SERVICE_NAME_STR(cp2p_file));    
        ctdnssv_node_mgr_free(ctdnssv_node_mgr);
        return (EC_FALSE);
    }

    if(EC_TRUE == ctdnssv_node_mgr_is_empty(ctdnssv_node_mgr))
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_file_report_notify: "
                                             "no upper node for service '%s'\n",
                                             (char *)CP2P_FILE_SERVICE_NAME_STR(cp2p_file));    
        ctdnssv_node_mgr_free(ctdnssv_node_mgr);
        return (EC_FALSE);
    }

    /*try one by one*/
    task_mgr = task_new(NULL_PTR, TASK_PRIO_NORMAL, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP);
    CLIST_LOOP_NEXT(CTDNSSV_NODE_MGR_NODES(ctdnssv_node_mgr), clist_data)
    {
        CTDNSSV_NODE        *ctdnssv_node;
        MOD_NODE             recv_mod_node;

        ctdnssv_node = CLIST_DATA_DATA(clist_data);

        MOD_NODE_TCID(&recv_mod_node) = CTDNSSV_NODE_TCID(ctdnssv_node);
        MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
        MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
        MOD_NODE_MODI(&recv_mod_node) = 0;/*only one p2p module*/

        if(do_log(SEC_0059_CP2P, 9))
        {
            dbg_log(SEC_0059_CP2P, 9)(LOGSTDOUT, "[DEBUG] cp2p_file_report_notify: "
                                                 "notify service '%s' upper node '%s' to report p2p file "
                                                 "which is ready on network %ld, des tcid '%s'\n",
                                                 (char *)CP2P_FILE_SERVICE_NAME_STR(cp2p_file),
                                                 c_word_to_ipv4(CTDNSSV_NODE_TCID(ctdnssv_node)),
                                                 des_network,
                                                 c_word_to_ipv4(des_tcid)); 
            cp2p_file_print(LOGSTDOUT, cp2p_file);
        }
        
        task_p2p_inc(task_mgr, 
                    cp2p_md_id, 
                    &recv_mod_node,
                    NULL_PTR, FI_cp2p_file_report, CMPI_ERROR_MODI, des_network, des_tcid, cp2p_file);
    }
    ctdnssv_node_mgr_free(ctdnssv_node_mgr);  
    
    task_no_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);
                     
    return (EC_TRUE);
}

/**
*
*  notify edge nodes under current network to delete p2p file
*
**/
EC_BOOL cp2p_file_delete_notify(const UINT32 cp2p_md_id, const UINT32 des_network, const UINT32 des_tcid, const CP2P_FILE *cp2p_file)
{
    CP2P_MD          *cp2p_md;

    TASK_MGR         *task_mgr;
    
    CTDNSSV_NODE_MGR *ctdnssv_node_mgr;
    CLIST_DATA       *clist_data;
        
#if ( SWITCH_ON == CP2P_DEBUG_SWITCH )
    if ( CP2P_MD_ID_CHECK_INVALID(cp2p_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cp2p_file_delete_notify: cp2p module #0x%lx not started.\n",
                cp2p_md_id);
        cp2p_print_module_status(cp2p_md_id, LOGSTDOUT);
        dbg_exit(MD_CP2P, cp2p_md_id);
    }
#endif/*CP2P_DEBUG_SWITCH*/

    cp2p_md = CP2P_MD_GET(cp2p_md_id);

    ctdnssv_node_mgr = ctdnssv_node_mgr_new();
    if(NULL_PTR == ctdnssv_node_mgr)
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_file_delete_notify: "
                                             "new ctdnssv_node_mgr failed\n");    
        return (EC_FALSE);
    }

    if(EC_FALSE == ctdns_finger_edge_service(CP2P_MD_CTDNS_MODI(cp2p_md), 
                                        CP2P_FILE_SERVICE_NAME(cp2p_file), 
                                        CP2P_NODES_MAX_NUM, 
                                        ctdnssv_node_mgr))
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_file_delete_notify: "
                                             "finger edge service '%s' failed\n",
                                             (char *)CP2P_FILE_SERVICE_NAME_STR(cp2p_file));    
        ctdnssv_node_mgr_free(ctdnssv_node_mgr);
        return (EC_FALSE);
    }

    if(EC_TRUE == ctdnssv_node_mgr_is_empty(ctdnssv_node_mgr))
    {
        dbg_log(SEC_0059_CP2P, 9)(LOGSTDOUT, "[DEBUG] cp2p_file_delete_notify: "
                                             "no edge node for service '%s'\n",
                                             (char *)CP2P_FILE_SERVICE_NAME_STR(cp2p_file));    
        ctdnssv_node_mgr_free(ctdnssv_node_mgr);
        return (EC_TRUE);
    }

    /*try one by one*/
    task_mgr = task_new(NULL_PTR, TASK_PRIO_NORMAL, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP);
    CLIST_LOOP_NEXT(CTDNSSV_NODE_MGR_NODES(ctdnssv_node_mgr), clist_data)
    {
        CTDNSSV_NODE        *ctdnssv_node;
        MOD_NODE             recv_mod_node;

        ctdnssv_node = CLIST_DATA_DATA(clist_data);

        MOD_NODE_TCID(&recv_mod_node) = CTDNSSV_NODE_TCID(ctdnssv_node);
        MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
        MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
        MOD_NODE_MODI(&recv_mod_node) = 0;/*only one p2p module*/

        if(do_log(SEC_0059_CP2P, 9))
        {
            dbg_log(SEC_0059_CP2P, 9)(LOGSTDOUT, "[DEBUG] cp2p_file_delete_notify: "
                                                 "notify service '%s' edge node '%s' to delete p2p file "
                                                 "which is on network %ld, des tcid '%s'\n",
                                                 (char *)CP2P_FILE_SERVICE_NAME_STR(cp2p_file),
                                                 c_word_to_ipv4(CTDNSSV_NODE_TCID(ctdnssv_node)),
                                                 des_network,
                                                 c_word_to_ipv4(des_tcid)); 
            cp2p_file_print(LOGSTDOUT, cp2p_file);
        }
        
        task_p2p_inc(task_mgr, 
                    cp2p_md_id, 
                    &recv_mod_node,
                    NULL_PTR, FI_cp2p_file_delete, CMPI_ERROR_MODI, des_network, des_tcid, cp2p_file);
    }
    ctdnssv_node_mgr_free(ctdnssv_node_mgr);  
    
    task_no_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);
                     
    return (EC_TRUE);
}

/**
*
*  download p2p file from tcid
*
*
**/
EC_BOOL cp2p_file_download(const UINT32 cp2p_md_id, const UINT32 src_tcid, const CP2P_FILE *cp2p_file)
{
    CP2P_MD          *cp2p_md;

    MOD_NODE          recv_mod_node;

    CSTRING          *file_path;
    CBYTES           *file_content;
    EC_BOOL           ret;
    
#if ( SWITCH_ON == CP2P_DEBUG_SWITCH )
    if ( CP2P_MD_ID_CHECK_INVALID(cp2p_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cp2p_file_download: cp2p module #0x%lx not started.\n",
                cp2p_md_id);
        cp2p_print_module_status(cp2p_md_id, LOGSTDOUT);
        dbg_exit(MD_CP2P, cp2p_md_id);
    }
#endif/*CP2P_DEBUG_SWITCH*/

    cp2p_md = CP2P_MD_GET(cp2p_md_id);


    /*download file from src and store it to storage*/

    file_path = __cp2p_file_name_gen(CP2P_FILE_SERVICE_NAME(cp2p_file), CP2P_FILE_SRC_NAME(cp2p_file));
    if(NULL_PTR == file_path)
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_file_download: "
                                             "gen download file name failed\n");    
        return (EC_FALSE);
    }

    file_content = cbytes_new(0);
    if(NULL_PTR == file_content)
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_file_download: "
                                             "new cbytes failed\n");    
        cstring_free(file_path);
        return (EC_FALSE);
    }    

    dbg_log(SEC_0059_CP2P, 9)(LOGSTDOUT, "[DEBUG] cp2p_file_download: "
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
             &ret, FI_crfs_read, CMPI_ERROR_MODI, file_path, file_content);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_file_download: "
                                             "download '%s' from RFS tcid %s failed\n", 
                                             (char *)cstring_get_str(file_path),
                                             c_word_to_ipv4(src_tcid));    
        cstring_free(file_path);
        cbytes_free(file_content);    
        return (EC_FALSE);
    }

    dbg_log(SEC_0059_CP2P, 9)(LOGSTDOUT, "[DEBUG] cp2p_file_download: "
                                         "download '%s' from RFS tcid %s done\n", 
                                         (char *)cstring_get_str(file_path),
                                         c_word_to_ipv4(src_tcid));
                                         
    /*check consistency: file size*/
    if(EC_FALSE == cp2p_file_is(cp2p_file, file_content))
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_file_download: "
                                             "downloaded file '%s' from tcid '%s' is inconsistent\n",
                                             (char *)cstring_get_str(file_path),
                                             c_word_to_ipv4(src_tcid));    
        cstring_free(file_path);
        cbytes_free(file_content); 
        return (EC_FALSE);
    }

    /*store to storage*/
    if(EC_FALSE == crfs_update(CP2P_MD_CRFS_MODI(cp2p_md), file_path, file_content))
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_file_download: "
                                             "write '%s' to storage failed\n", 
                                             (char *)cstring_get_str(file_path));    
        cstring_free(file_path);
        cbytes_free(file_content); 
        return (EC_FALSE);
    }
    dbg_log(SEC_0059_CP2P, 9)(LOGSTDOUT, "[DEBUG] cp2p_file_download: "
                                         "downloaded '%s' storing is OK\n", 
                                         (char *)cstring_get_str(file_path));      
    
    if(do_log(SEC_0059_CP2P, 9))
    {
        dbg_log(SEC_0059_CP2P, 9)(LOGSTDOUT, "[DEBUG] cp2p_file_download: "
                                             "downloaded file '%s' from tcid '%s' is OK\n",
                                             (char *)cstring_get_str(file_path),
                                             c_word_to_ipv4(src_tcid));      
        cp2p_file_print(LOGSTDOUT, cp2p_file);
    }

    cstring_free(file_path);
    cbytes_free(file_content);    

    return (EC_TRUE);
}

/**
*
*  push p2p file to storage
*
*  note: des_tcid maybe ANY TCID
*
**/
EC_BOOL cp2p_file_push(const UINT32 cp2p_md_id, const UINT32 des_network, const UINT32 des_tcid, const CP2P_FILE *cp2p_file)
{
    CP2P_MD          *cp2p_md;
    
#if ( SWITCH_ON == CP2P_DEBUG_SWITCH )
    if ( CP2P_MD_ID_CHECK_INVALID(cp2p_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cp2p_file_push: cp2p module #0x%lx not started.\n",
                cp2p_md_id);
        cp2p_print_module_status(cp2p_md_id, LOGSTDOUT);
        dbg_exit(MD_CP2P, cp2p_md_id);
    }
#endif/*CP2P_DEBUG_SWITCH*/

    cp2p_md = CP2P_MD_GET(cp2p_md_id);

    if(do_log(SEC_0059_CP2P, 9))
    {
        dbg_log(SEC_0059_CP2P, 9)(LOGSTDOUT, "[DEBUG] cp2p_file_push: cp2p_file:\n");
        cp2p_file_print(LOGSTDOUT, cp2p_file);
    }  

    if(CMPI_TOP_NETWORK == CP2P_MD_NETWORK_LEVEL(cp2p_md))
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_file_push: "
                                             "here is top network!\n");    
        return (EC_FALSE);
    }    

    if(CMPI_ANY_NETWORK != des_network
    && CP2P_MD_NETWORK_LEVEL(cp2p_md) > des_network)
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_file_push: "
                                             "cur network level %ld > des_network %ld\n",
                                             CP2P_MD_NETWORK_LEVEL(cp2p_md),
                                             des_network);    
        return (EC_FALSE);
    }

    if(CMPI_TOP_NETWORK + 1 == CP2P_MD_NETWORK_LEVEL(cp2p_md))
    {
        if(EC_FALSE == cp2p_file_exists(cp2p_md_id, cp2p_file))
        {
            dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_file_push: "
                                                 "p2p file not exist\n");
            cp2p_file_print(LOGSTDOUT, cp2p_file);
            return (EC_FALSE);
        }
    }    
    else
    {
        /*CMPI_TOP_NETWORK + 1 < CP2P_MD_NETWORK_LEVEL(cp2p_md)*/

        /*anyway, pull it*/
        if(EC_FALSE == cp2p_file_pull(cp2p_md_id, cp2p_file))
        {
            dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_file_push: "
                                                 "pull file failed\n");    
            return (EC_FALSE);
        }
    }

    if(CMPI_ANY_NETWORK == des_network
    || CP2P_MD_NETWORK_LEVEL(cp2p_md) < des_network)
    {
        /*notify edges of current network to download*/   
        return cp2p_file_push_notify(cp2p_md_id, des_network, des_tcid, cp2p_file);
    }

    /*now reach the specific network*/

    if(CMPI_ANY_TCID == des_tcid)
    {
        return (EC_TRUE);
    }

    if(CP2P_MD_NETWORK_TCID(cp2p_md) != des_tcid)
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_file_push: "
                                             "here tcid '%s' != des_tcid '%s'\n",
                                             c_word_to_ipv4(CP2P_MD_NETWORK_TCID(cp2p_md)),
                                             c_word_to_ipv4(des_tcid));    
        return (EC_FALSE);
    }

    if(do_log(SEC_0059_CP2P, 9))
    {
        dbg_log(SEC_0059_CP2P, 9)(LOGSTDOUT, "[DEBUG] cp2p_file_push: "
                                             "push p2p file on network %ld, des tcid '%s' succ\n",
                                             des_network,
                                             c_word_to_ipv4(des_tcid));
        cp2p_file_print(LOGSTDOUT, cp2p_file);
    }  
    
    return (EC_TRUE);
}

/**
*
*  pull p2p file from upper
*
*
**/
EC_BOOL cp2p_file_pull(const UINT32 cp2p_md_id, const CP2P_FILE *cp2p_file)
{
    CP2P_MD          *cp2p_md;
    
    CTDNSSV_NODE_MGR *ctdnssv_node_mgr;
    CLIST_DATA       *clist_data;
    
#if ( SWITCH_ON == CP2P_DEBUG_SWITCH )
    if ( CP2P_MD_ID_CHECK_INVALID(cp2p_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cp2p_file_pull: cp2p module #0x%lx not started.\n",
                cp2p_md_id);
        cp2p_print_module_status(cp2p_md_id, LOGSTDOUT);
        dbg_exit(MD_CP2P, cp2p_md_id);
    }
#endif/*CP2P_DEBUG_SWITCH*/

    cp2p_md = CP2P_MD_GET(cp2p_md_id);

    if(EC_TRUE == cp2p_file_exists(cp2p_md_id, cp2p_file))
    {
        return (EC_TRUE);
    }

    if(CMPI_TOP_NETWORK == CP2P_MD_NETWORK_LEVEL(cp2p_md))
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_file_pull: "
                                             "top network has no the p2p file\n");     
        cp2p_file_print(LOGSTDOUT, cp2p_file);
        return (EC_FALSE);
    }

    ctdnssv_node_mgr = ctdnssv_node_mgr_new();
    if(NULL_PTR == ctdnssv_node_mgr)
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_file_pull: "
                                             "new ctdnssv_node_mgr failed\n");    
        return (EC_FALSE);
    }
    
    if(EC_FALSE == ctdns_finger_upper_service(CP2P_MD_CTDNS_MODI(cp2p_md), 
                                        CP2P_FILE_SERVICE_NAME(cp2p_file), 
                                        CP2P_NODES_MAX_NUM, 
                                        ctdnssv_node_mgr))
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_file_pull: "
                                             "finger upper service '%s' failed\n",
                                             (char *)CP2P_FILE_SERVICE_NAME_STR(cp2p_file));    
        ctdnssv_node_mgr_free(ctdnssv_node_mgr);
        return (EC_FALSE);
    }

    if(EC_TRUE == ctdnssv_node_mgr_is_empty(ctdnssv_node_mgr))
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_file_pull: "
                                             "no upper node for service '%s'\n",
                                             (char *)CP2P_FILE_SERVICE_NAME_STR(cp2p_file));    
        ctdnssv_node_mgr_free(ctdnssv_node_mgr);
        return (EC_FALSE);
    }

    /*try one by one*/
    CLIST_LOOP_NEXT(CTDNSSV_NODE_MGR_NODES(ctdnssv_node_mgr), clist_data)
    {
        CTDNSSV_NODE        *ctdnssv_node;
        MOD_NODE             recv_mod_node;
        EC_BOOL              ret;

        ctdnssv_node = CLIST_DATA_DATA(clist_data);

        MOD_NODE_TCID(&recv_mod_node) = CTDNSSV_NODE_TCID(ctdnssv_node);
        MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
        MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
        MOD_NODE_MODI(&recv_mod_node) = 0;/*only one p2p module*/

        /*blocking mode*/
        ret = EC_FALSE;
        task_p2p(cp2p_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP, 
                         &recv_mod_node, 
                         &ret, FI_cp2p_file_pull, CMPI_ERROR_MODI, cp2p_file);
                         
        if(EC_TRUE == cp2p_file_download(cp2p_md_id, CTDNSSV_NODE_TCID(ctdnssv_node), cp2p_file))
        {     
            ctdnssv_node_mgr_free(ctdnssv_node_mgr);
            return (EC_TRUE);
        }
    }
    ctdnssv_node_mgr_free(ctdnssv_node_mgr);
    
    return (EC_FALSE);
}

/**
*
*  dump p2p file to local disk if the file exists in storage
*
*
**/
EC_BOOL cp2p_file_dump(const UINT32 cp2p_md_id, const CP2P_FILE *cp2p_file)
{
    CP2P_MD          *cp2p_md;
    
    const CSTRING    *des_file_path;
    
    CSTRING          *rfs_file_path;
    CBYTES           *rfs_file_content;
    
    UINT32            des_offset;
    int               des_fd;
    
#if ( SWITCH_ON == CP2P_DEBUG_SWITCH )
    if ( CP2P_MD_ID_CHECK_INVALID(cp2p_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cp2p_file_dump: cp2p module #0x%lx not started.\n",
                cp2p_md_id);
        cp2p_print_module_status(cp2p_md_id, LOGSTDOUT);
        dbg_exit(MD_CP2P, cp2p_md_id);
    }
#endif/*CP2P_DEBUG_SWITCH*/

    cp2p_md = CP2P_MD_GET(cp2p_md_id);

    des_file_path = CP2P_FILE_DES_NAME(cp2p_file);
  
    rfs_file_path = __cp2p_file_name_gen(CP2P_FILE_SERVICE_NAME(cp2p_file), CP2P_FILE_SRC_NAME(cp2p_file));
    if(NULL_PTR == rfs_file_path)
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_file_dump: "
                                             "gen download file name failed\n");    
        return (EC_FALSE);
    }
    
    rfs_file_content = cbytes_new(0);
    if(NULL_PTR == rfs_file_content)
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_file_dump: "
                                             "new cbytes failed\n");    
        cstring_free(rfs_file_path);
        return (EC_FALSE);
    } 

    if(EC_FALSE == crfs_read(CP2P_MD_CRFS_MODI(cp2p_md), rfs_file_path, rfs_file_content))
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_file_dump: "
                                             "read '%s' from storage failed\n", 
                                             (char *)cstring_get_str(rfs_file_path));
                                             
        cstring_free(rfs_file_path);         
        cbytes_free(rfs_file_content);
        return (EC_FALSE);    
    }
                                     
    cstring_free(rfs_file_path);
    
    /*store to local disk*/
    des_fd = c_file_open((char *)cstring_get_str(des_file_path), O_RDWR | O_CREAT, 0666);
    if(ERR_FD == des_fd)
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_file_dump: "
                                             "open file '%s' to write failed\n", 
                                             (char *)cstring_get_str(des_file_path));      
        cbytes_free(rfs_file_content);
        return (EC_FALSE);
    }

    des_offset = 0;
    if(EC_FALSE == c_file_flush(des_fd, &des_offset, CBYTES_LEN(rfs_file_content), CBYTES_BUF(rfs_file_content)))
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_file_dump: "
                                             "flush %ld bytes to file '%s' failed\n", 
                                             CBYTES_LEN(rfs_file_content),   
                                             (char *)cstring_get_str(des_file_path));      
        c_file_close(des_fd);
        cbytes_free(rfs_file_content);
        return (EC_FALSE);
    }

    if(des_offset != CBYTES_LEN(rfs_file_content))
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_file_dump: "
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

    if(do_log(SEC_0059_CP2P, 9))
    {
        dbg_log(SEC_0059_CP2P, 9)(LOGSTDOUT, "[DEBUG] cp2p_file_dump: "
                                             "dump p2p file to file '%s' done\n",
                                             (char *)cstring_get_str(des_file_path));
        cp2p_file_print(LOGSTDOUT, cp2p_file);
    }       
    return (EC_TRUE);
}

/**
*
*  flush p2p file to local disk
*
*  if the p2p file does not exist in storage, pull it
*
**/
EC_BOOL cp2p_file_flush(const UINT32 cp2p_md_id, const UINT32 des_network, const UINT32 des_tcid, const CP2P_FILE *cp2p_file)
{
    CP2P_MD          *cp2p_md;
    
    const CSTRING    *des_file_path;
    
#if ( SWITCH_ON == CP2P_DEBUG_SWITCH )
    if ( CP2P_MD_ID_CHECK_INVALID(cp2p_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cp2p_file_flush: cp2p module #0x%lx not started.\n",
                cp2p_md_id);
        cp2p_print_module_status(cp2p_md_id, LOGSTDOUT);
        dbg_exit(MD_CP2P, cp2p_md_id);
    }
#endif/*CP2P_DEBUG_SWITCH*/

    cp2p_md = CP2P_MD_GET(cp2p_md_id);

    if(CMPI_ANY_NETWORK != des_network)
    {
        if(CP2P_MD_NETWORK_LEVEL(cp2p_md) > des_network)
        {
            dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_file_flush: "
                                                 "cur network level %ld > des_network %ld\n",
                                                 CP2P_MD_NETWORK_LEVEL(cp2p_md),
                                                 des_network);    
            return (EC_FALSE);
        }

        if(CP2P_MD_NETWORK_LEVEL(cp2p_md) < des_network)
        {
            /*notify edges of current network to flush*/   
            return cp2p_file_flush_notify(cp2p_md_id, des_network, des_tcid, cp2p_file);
        }    

        /*now reach the specific network*/

        if(CMPI_ANY_TCID != des_tcid
        && CP2P_MD_NETWORK_TCID(cp2p_md) != des_tcid)
        {
            dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_file_flush: "
                                                 "here tcid '%s' != des_tcid '%s'\n",
                                                 c_word_to_ipv4(CP2P_MD_NETWORK_TCID(cp2p_md)),
                                                 c_word_to_ipv4(des_tcid));    
            return (EC_FALSE);
        }
    }
    else
    {
        /*now reach the specific network*/

        if(CMPI_ANY_TCID != des_tcid
        && CP2P_MD_NETWORK_TCID(cp2p_md) != des_tcid)
        {
            dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_file_flush: "
                                                 "here tcid '%s' != des_tcid '%s'\n",
                                                 c_word_to_ipv4(CP2P_MD_NETWORK_TCID(cp2p_md)),
                                                 c_word_to_ipv4(des_tcid));    
                                                 
            return cp2p_file_flush_notify(cp2p_md_id, des_network, des_tcid, cp2p_file); 
        }    
    }
    /*now flush*/

    des_file_path = CP2P_FILE_DES_NAME(cp2p_file);
    
    if(EC_TRUE == cp2p_file_exists_local(cp2p_md_id, cp2p_file))
    {
        dbg_log(SEC_0059_CP2P, 9)(LOGSTDOUT, "[DEBUG] cp2p_file_flush: "
                                             "local file '%s' already exists\n",
                                             (char *)cstring_get_str(des_file_path));    
        return (EC_TRUE);
    }

    if(EC_FALSE == cp2p_file_pull(cp2p_md_id, cp2p_file))
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_file_flush: "
                                             "pull p2p file failed\n");    
        return (EC_FALSE);
    }

    if(EC_FALSE == cp2p_file_dump(cp2p_md_id, cp2p_file))
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_file_flush: "
                                             "dump p2p file failed\n");    
        return (EC_FALSE);
    }

    if(do_log(SEC_0059_CP2P, 9))
    {
        dbg_log(SEC_0059_CP2P, 9)(LOGSTDOUT, "[DEBUG] cp2p_file_push: "
                                             "flush p2p file to local file '%s' on network %ld, des tcid '%s' succ\n",
                                             (char *)cstring_get_str(des_file_path),
                                             des_network,
                                             c_word_to_ipv4(des_tcid));
        cp2p_file_print(LOGSTDOUT, cp2p_file);
    }     

    if(CMPI_ANY_NETWORK == des_network)
    {
        /*notify edges of current network to flush*/ 
        return cp2p_file_flush_notify(cp2p_md_id, des_network, des_tcid, cp2p_file);    
    }
        
    return (EC_TRUE);
}

/**
*
*  report to src tcid that p2p file is ready
*
*
**/
EC_BOOL cp2p_file_report(const UINT32 cp2p_md_id, const UINT32 des_network, const UINT32 des_tcid, const CP2P_FILE *cp2p_file)
{
    CP2P_MD          *cp2p_md;
        
#if ( SWITCH_ON == CP2P_DEBUG_SWITCH )
    if ( CP2P_MD_ID_CHECK_INVALID(cp2p_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cp2p_file_report: cp2p module #0x%lx not started.\n",
                cp2p_md_id);
        cp2p_print_module_status(cp2p_md_id, LOGSTDOUT);
        dbg_exit(MD_CP2P, cp2p_md_id);
    }
#endif/*CP2P_DEBUG_SWITCH*/

    cp2p_md = CP2P_MD_GET(cp2p_md_id);
    if(CMPI_ERROR_TCID == CP2P_FILE_REPORT_TCID(cp2p_file))
    {
        return (EC_TRUE);
    }

    if(EC_FALSE == ctdns_exists_tcid(CP2P_MD_CTDNS_MODI(cp2p_md), CP2P_FILE_REPORT_TCID(cp2p_file)))
    {
        return cp2p_file_report_notify(cp2p_md_id, des_network, des_tcid, cp2p_file);
    }

    if(do_log(SEC_0059_CP2P, 9))
    {
        dbg_log(SEC_0059_CP2P, 9)(LOGSTDOUT, "[DEBUG] cp2p_file_report: "
                                             "network %ld, tcid %s report p2p file:\n",
                                             des_network, 
                                             c_word_to_ipv4(des_tcid));     
        
        cp2p_file_print(LOGSTDOUT, cp2p_file);
    }
    
    return (EC_TRUE);
}

/**
*
*  load a local file to storage
*
**/
EC_BOOL cp2p_file_load(const UINT32 cp2p_md_id, const CSTRING *src_file, const CSTRING *service_name, const CSTRING *des_file)
{
    CP2P_MD          *cp2p_md;

    const char       *src_file_path_str;
    CBYTES           *src_file_bytes;

    CSTRING          *des_file_path;
    
#if ( SWITCH_ON == CP2P_DEBUG_SWITCH )
    if ( CP2P_MD_ID_CHECK_INVALID(cp2p_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cp2p_file_load: cp2p module #0x%lx not started.\n",
                cp2p_md_id);
        cp2p_print_module_status(cp2p_md_id, LOGSTDOUT);
        dbg_exit(MD_CP2P, cp2p_md_id);
    }
#endif/*CP2P_DEBUG_SWITCH*/

    cp2p_md = CP2P_MD_GET(cp2p_md_id);

    src_file_path_str = (const char *)cstring_get_str(src_file);

    src_file_bytes = c_file_load_whole(src_file_path_str);
    if(NULL_PTR == src_file_bytes)
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_file_load: "
                                             "load file '%s' failed\n",
                                             src_file_path_str);    
        return (EC_FALSE);        
    }

    des_file_path = __cp2p_file_name_gen(service_name, des_file);
    if(NULL_PTR == des_file_path)
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_file_load: "
                                             "gen download file name failed\n");    
        cbytes_free(src_file_bytes);
        return (EC_FALSE);
    }

    if(EC_FALSE == crfs_update(CP2P_MD_CRFS_MODI(cp2p_md), des_file_path, src_file_bytes))
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_file_load: "
                                             "update '%s' to storage failed\n", 
                                             (char *)cstring_get_str(des_file_path));    
        cbytes_free(src_file_bytes);
        cstring_free(des_file_path);
        return (EC_FALSE);
    }
    dbg_log(SEC_0059_CP2P, 9)(LOGSTDOUT, "[DEBUG] cp2p_file_load: "
                                         "update '%s' to storage is OK\n", 
                                         (char *)cstring_get_str(des_file_path));     
    
    

    dbg_log(SEC_0059_CP2P, 9)(LOGSTDOUT, "[DEBUG] cp2p_file_load: "
                                         "upload '%s' to storage '%s' done\n", 
                                         (char *)cstring_get_str(src_file),
                                         (char *)cstring_get_str(des_file_path));       
    cbytes_free(src_file_bytes);
    cstring_free(des_file_path);
    return (EC_TRUE);
}

/**
*
*  upload a local file to storage
*
**/
EC_BOOL cp2p_file_upload(const UINT32 cp2p_md_id, const CBYTES *src_file_content, const CSTRING *service_name, const CSTRING *des_file)
{
    CP2P_MD          *cp2p_md;

    CSTRING          *des_file_path;
    
#if ( SWITCH_ON == CP2P_DEBUG_SWITCH )
    if ( CP2P_MD_ID_CHECK_INVALID(cp2p_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cp2p_file_upload: cp2p module #0x%lx not started.\n",
                cp2p_md_id);
        cp2p_print_module_status(cp2p_md_id, LOGSTDOUT);
        dbg_exit(MD_CP2P, cp2p_md_id);
    }
#endif/*CP2P_DEBUG_SWITCH*/

    cp2p_md = CP2P_MD_GET(cp2p_md_id);

    des_file_path = __cp2p_file_name_gen(service_name, des_file);
    if(NULL_PTR == des_file_path)
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_file_upload: "
                                             "gen download file name failed\n");    
        return (EC_FALSE);
    }

    if(EC_FALSE == crfs_update(CP2P_MD_CRFS_MODI(cp2p_md), des_file_path, src_file_content))
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_file_upload: "
                                             "update '%s' to storage failed\n", 
                                             (char *)cstring_get_str(des_file_path));    
        cstring_free(des_file_path);
        return (EC_FALSE);
    }
    dbg_log(SEC_0059_CP2P, 9)(LOGSTDOUT, "[DEBUG] cp2p_file_upload: "
                                         "update '%s' with size %ld to storage is done\n", 
                                         (char *)cstring_get_str(des_file_path),
                                         cbytes_len(src_file_content));     
       
    cstring_free(des_file_path);
    return (EC_TRUE);
}

/**
*
*  delete p2p file from src tcid
*
*
**/
EC_BOOL cp2p_file_delete(const UINT32 cp2p_md_id, const UINT32 des_network, const UINT32 des_tcid, const CP2P_FILE *cp2p_file)
{
    CP2P_MD          *cp2p_md;
        
#if ( SWITCH_ON == CP2P_DEBUG_SWITCH )
    if ( CP2P_MD_ID_CHECK_INVALID(cp2p_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cp2p_file_delete: cp2p module #0x%lx not started.\n",
                cp2p_md_id);
        cp2p_print_module_status(cp2p_md_id, LOGSTDOUT);
        dbg_exit(MD_CP2P, cp2p_md_id);
    }
#endif/*CP2P_DEBUG_SWITCH*/

    cp2p_md = CP2P_MD_GET(cp2p_md_id);

    if(CMPI_ANY_NETWORK == des_network)
    {
        if(CMPI_ANY_TCID == des_tcid || CP2P_MD_NETWORK_TCID(cp2p_md) == des_tcid)
        {
            CSTRING     *rfs_file_path;
#if 0
            if(EC_FALSE == cp2p_file_exists(cp2p_md_id, cp2p_file))
            {
                dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_file_delete: "
                                                     "p2p file not exist\n");
                cp2p_file_print(LOGSTDOUT, cp2p_file);
                return (EC_FALSE);
            }            
#endif            
            rfs_file_path = __cp2p_file_name_gen(CP2P_FILE_SERVICE_NAME(cp2p_file), CP2P_FILE_SRC_NAME(cp2p_file));
            if(NULL_PTR == rfs_file_path)
            {
                dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_file_delete: "
                                                     "gen file name failed\n");    
                return (EC_FALSE);
            }        
            crfs_delete_file(CP2P_MD_CRFS_MODI(cp2p_md), rfs_file_path);
            cstring_free(rfs_file_path);
        }
        
        return cp2p_file_delete_notify(cp2p_md_id, des_network, des_tcid, cp2p_file);
    }

    if(CP2P_MD_NETWORK_LEVEL(cp2p_md) > des_network)
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_file_delete: "
                                             "cur network level %ld > des_network %ld\n",
                                             CP2P_MD_NETWORK_LEVEL(cp2p_md),
                                             des_network);    
        return (EC_FALSE);
    }    

    if(CP2P_MD_NETWORK_LEVEL(cp2p_md) < des_network)
    {
        return cp2p_file_delete_notify(cp2p_md_id, des_network, des_tcid, cp2p_file);
    }

    if(CMPI_ANY_TCID == des_tcid || CP2P_MD_NETWORK_TCID(cp2p_md) == des_tcid)
    {
        CSTRING     *rfs_file_path;
#if 0
        if(EC_FALSE == cp2p_file_exists(cp2p_md_id, cp2p_file))
        {
            dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_file_delete: "
                                                 "p2p file not exist\n");
            cp2p_file_print(LOGSTDOUT, cp2p_file);
            return (EC_FALSE);
        }            
#endif
        rfs_file_path = __cp2p_file_name_gen(CP2P_FILE_SERVICE_NAME(cp2p_file), CP2P_FILE_SRC_NAME(cp2p_file));
        if(NULL_PTR == rfs_file_path)
        {
            dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_file_delete: "
                                                 "gen file name failed\n");    
            return (EC_FALSE);
        }        
        crfs_delete_file(CP2P_MD_CRFS_MODI(cp2p_md), rfs_file_path);
        cstring_free(rfs_file_path);

        if(do_log(SEC_0059_CP2P, 9))
        {
            dbg_log(SEC_0059_CP2P, 9)(LOGSTDOUT, "[DEBUG] cp2p_file_delete: "
                                                 "delete p2p file on network %ld, des tcid '%s' succ\n",
                                                 des_network,
                                                 c_word_to_ipv4(des_tcid));
            cp2p_file_print(LOGSTDOUT, cp2p_file);
        }        
        
        return (EC_TRUE);
    }

    if(do_log(SEC_0059_CP2P, 9))
    {
        dbg_log(SEC_0059_CP2P, 9)(LOGSTDOUT, "[DEBUG] cp2p_file_delete: "
                                             "cur network %ld, tcid '%s' != des network %ld, tcid '%s' "
                                             "ignore deleting p2p file\n",
                                             CP2P_MD_NETWORK_LEVEL(cp2p_md),
                                             c_word_to_ipv4(CP2P_MD_NETWORK_TCID(cp2p_md)),
                                             des_network,
                                             c_word_to_ipv4(des_tcid));
                                             
        cp2p_file_print(LOGSTDOUT, cp2p_file);
    }
     
    return (EC_TRUE);
}

/*------------------------------------------------ interface of command execution ------------------------------------------------*/
CP2P_CMD *cp2p_cmd_new()
{
    CP2P_CMD *cp2p_cmd;
    
    alloc_static_mem(MM_CP2P_CMD, &cp2p_cmd, LOC_CP2P_0004);
    if(NULL_PTR != cp2p_cmd)
    {
        cp2p_cmd_init(cp2p_cmd);
    }
    return (cp2p_cmd);
}

EC_BOOL cp2p_cmd_init(CP2P_CMD *cp2p_cmd)
{
    cstring_init(CP2P_CMD_SERVICE_NAME(cp2p_cmd), NULL_PTR);
    cstring_init(CP2P_CMD_COMMAND_LINE(cp2p_cmd), NULL_PTR);

    return (EC_TRUE);
}

EC_BOOL cp2p_cmd_clean(CP2P_CMD *cp2p_cmd)
{
    cstring_clean(CP2P_CMD_SERVICE_NAME(cp2p_cmd));
    cstring_clean(CP2P_CMD_COMMAND_LINE(cp2p_cmd));
    
    return (EC_TRUE);
}

EC_BOOL cp2p_cmd_free(CP2P_CMD *cp2p_cmd)
{
    if(NULL_PTR != cp2p_cmd)
    {
        cp2p_cmd_clean(cp2p_cmd);
        free_static_mem(MM_CP2P_CMD, cp2p_cmd, LOC_CP2P_0005);
    }
    return (EC_TRUE);
}

int cp2p_cmd_cmp(const CP2P_CMD *cp2p_cmd_1st, const CP2P_CMD *cp2p_cmd_2nd)
{
    int     ret;

    ret = cstring_cmp(CP2P_CMD_SERVICE_NAME(cp2p_cmd_1st), CP2P_CMD_SERVICE_NAME(cp2p_cmd_2nd));
    if(0 != ret)
    {
        return (ret);
    }    
    
    return cstring_cmp(CP2P_CMD_COMMAND_LINE(cp2p_cmd_1st), CP2P_CMD_COMMAND_LINE(cp2p_cmd_2nd));
}

void cp2p_cmd_print(LOG *log, const CP2P_CMD *cp2p_cmd)
{
    if(NULL_PTR != cp2p_cmd)
    {
        sys_log(log, "cp2p_cmd_print %p: service '%s', cmd '%s'\n",
                     cp2p_cmd,
                     (char *)CP2P_CMD_SERVICE_NAME_STR(cp2p_cmd),
                     (char *)CP2P_CMD_COMMAND_LINE_STR(cp2p_cmd));
    }

    return;
}

/**
*
*  execute command
*
*
**/
EC_BOOL cp2p_cmd_execute(const UINT32 cp2p_md_id, const CP2P_CMD *cp2p_cmd)
{
    CP2P_MD          *cp2p_md;
    
    UINT32            super_md_id;
    CBYTES            result_cbytes;
    
#if ( SWITCH_ON == CP2P_DEBUG_SWITCH )
    if ( CP2P_MD_ID_CHECK_INVALID(cp2p_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cp2p_cmd_execute: cp2p module #0x%lx not started.\n",
                cp2p_md_id);
        cp2p_print_module_status(cp2p_md_id, LOGSTDOUT);
        dbg_exit(MD_CP2P, cp2p_md_id);
    }
#endif/*CP2P_DEBUG_SWITCH*/

    cp2p_md = CP2P_MD_GET(cp2p_md_id);

    super_md_id = 0;

    cbytes_init(&result_cbytes);

    dbg_log(SEC_0059_CP2P, 9)(LOGSTDOUT, "[DEBUG] cp2p_cmd_execute: service %s, cmd: \"%s\"\n", 
                                         (char *)CP2P_CMD_SERVICE_NAME_STR(cp2p_cmd),
                                         (char *)CP2P_CMD_COMMAND_LINE_STR(cp2p_cmd));
    
    super_exec_shell(super_md_id, CP2P_CMD_COMMAND_LINE(cp2p_cmd), &result_cbytes);

    dbg_log(SEC_0059_CP2P, 9)(LOGSTDOUT, "[DEBUG] cp2p_cmd_execute: service %s, cmd: \"%s\", output len %ld\n", 
                                         (char *)CP2P_CMD_SERVICE_NAME_STR(cp2p_cmd),
                                         (char *)CP2P_CMD_COMMAND_LINE_STR(cp2p_cmd), 
                                          cbytes_len(&result_cbytes));
                        
    cbytes_clean(&result_cbytes);

    return (EC_TRUE);
}

/**
*
*  notify edges under current network to deliver p2p cmd
*
**/
EC_BOOL cp2p_cmd_deliver_notify(const UINT32 cp2p_md_id, const UINT32 des_network, const UINT32 des_tcid, const CP2P_CMD *cp2p_cmd)
{
    CP2P_MD          *cp2p_md;

    CTDNSSV_NODE_MGR *ctdnssv_node_mgr;
    CLIST_DATA       *clist_data;
    
#if ( SWITCH_ON == CP2P_DEBUG_SWITCH )
    if ( CP2P_MD_ID_CHECK_INVALID(cp2p_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cp2p_cmd_deliver_notify: cp2p module #0x%lx not started.\n",
                cp2p_md_id);
        cp2p_print_module_status(cp2p_md_id, LOGSTDOUT);
        dbg_exit(MD_CP2P, cp2p_md_id);
    }
#endif/*CP2P_DEBUG_SWITCH*/

    cp2p_md = CP2P_MD_GET(cp2p_md_id);
 
    /*notify reachable edges to execute cmd*/
    ctdnssv_node_mgr = ctdnssv_node_mgr_new();
    if(NULL_PTR == ctdnssv_node_mgr)
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_cmd_deliver_notify: "
                                             "new ctdnssv_node_mgr failed\n");    
        return (EC_FALSE);
    }
    
    if(EC_FALSE == ctdns_finger_edge_service(CP2P_MD_CTDNS_MODI(cp2p_md), 
                                             CP2P_CMD_SERVICE_NAME(cp2p_cmd), 
                                             CP2P_NODES_MAX_NUM, 
                                             ctdnssv_node_mgr))
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_cmd_deliver_notify: "
                                             "finger service '%s' failed\n",
                                             (char *)CP2P_CMD_SERVICE_NAME_STR(cp2p_cmd));    
        ctdnssv_node_mgr_free(ctdnssv_node_mgr);
        return (EC_FALSE);
    }

    CLIST_LOOP_NEXT(CTDNSSV_NODE_MGR_NODES(ctdnssv_node_mgr), clist_data)
    {
        CTDNSSV_NODE        *ctdnssv_node;
        MOD_NODE             recv_mod_node;

        ctdnssv_node = CLIST_DATA_DATA(clist_data);

        MOD_NODE_TCID(&recv_mod_node) = CTDNSSV_NODE_TCID(ctdnssv_node);
        MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
        MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
        MOD_NODE_MODI(&recv_mod_node) = 0;/*only one p2p module*/

        dbg_log(SEC_0059_CP2P, 9)(LOGSTDOUT, "[DEBUG] cp2p_cmd_deliver_notify: "
                                             "cmd (service '%s', cmd '%s') "
                                             "=> deliver cmd to tcid %s\n", 
                                             (char *)CP2P_CMD_SERVICE_NAME_STR(cp2p_cmd),
                                             (char *)CP2P_CMD_COMMAND_LINE_STR(cp2p_cmd),
                                             MOD_NODE_TCID_STR(&recv_mod_node));  
        task_p2p_no_wait(cp2p_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP, 
                         &recv_mod_node, 
                         NULL_PTR, FI_cp2p_cmd_deliver, CMPI_ERROR_MODI, des_network, des_tcid, cp2p_cmd);
    }
    ctdnssv_node_mgr_free(ctdnssv_node_mgr);
  
    return (EC_TRUE);
}

/**
*
*  deliver command
*
**/
EC_BOOL cp2p_cmd_deliver(const UINT32 cp2p_md_id, const UINT32 des_network, const UINT32 des_tcid, const CP2P_CMD *cp2p_cmd)
{
    CP2P_MD          *cp2p_md;
    
#if ( SWITCH_ON == CP2P_DEBUG_SWITCH )
    if ( CP2P_MD_ID_CHECK_INVALID(cp2p_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cp2p_cmd_deliver: cp2p module #0x%lx not started.\n",
                cp2p_md_id);
        cp2p_print_module_status(cp2p_md_id, LOGSTDOUT);
        dbg_exit(MD_CP2P, cp2p_md_id);
    }
#endif/*CP2P_DEBUG_SWITCH*/

    cp2p_md = CP2P_MD_GET(cp2p_md_id);

    if(CMPI_ANY_NETWORK == CP2P_MD_NETWORK_LEVEL(cp2p_md))
    {
        dbg_log(SEC_0059_CP2P, 9)(LOGSTDOUT, "[DEBUG] cp2p_cmd_deliver: "
                                             "cmd (service '%s', cmd '%s')\n", 
                                             (char *)CP2P_CMD_SERVICE_NAME_STR(cp2p_cmd),
                                             (char *)CP2P_CMD_COMMAND_LINE_STR(cp2p_cmd));
                                         
        cp2p_cmd_deliver_notify(cp2p_md_id, des_network, des_tcid, cp2p_cmd);
        
        return cp2p_cmd_execute(cp2p_md_id, cp2p_cmd);
    }

    if(CP2P_MD_NETWORK_LEVEL(cp2p_md) > des_network)
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_cmd_deliver: "
                                             "cur network level %ld > des_network %ld\n",
                                             CP2P_MD_NETWORK_LEVEL(cp2p_md),
                                             des_network);    
        return (EC_FALSE);
    }

    if(CP2P_MD_NETWORK_LEVEL(cp2p_md) == des_network)
    {
        if(CMPI_ANY_TCID != des_tcid)
        {
            dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_cmd_deliver: "
                                                 "here tcid '%s' != des_tcid '%s'\n",
                                                 c_word_to_ipv4(CP2P_MD_NETWORK_TCID(cp2p_md)),
                                                 c_word_to_ipv4(des_tcid));    
            return (EC_FALSE);
        }
    
        dbg_log(SEC_0059_CP2P, 9)(LOGSTDOUT, "[DEBUG] cp2p_cmd_deliver: "
                                             "cmd (service '%s', cmd '%s')\n", 
                                             (char *)CP2P_CMD_SERVICE_NAME_STR(cp2p_cmd),
                                             (char *)CP2P_CMD_COMMAND_LINE_STR(cp2p_cmd));
                                         
        /*now reach the specific network*/
        return cp2p_cmd_execute(cp2p_md_id, cp2p_cmd);
    }    

    /*notify edges of current network to deliver cmd*/ 
    return cp2p_cmd_deliver_notify(cp2p_md_id, des_network, des_tcid, cp2p_cmd);
}

/*------------------------------------------------ interface of misc ------------------------------------------------*/

/**
*
*  report p2p online
*
**/
EC_BOOL cp2p_online_report(const UINT32 cp2p_md_id, const CSTRING *service_name)
{
    CP2P_MD          *cp2p_md;

    CHTTP_REQ         chttp_req;
    CHTTP_RSP         chttp_rsp;

    const char       *tdns_srv_host;
    UINT32            tdns_srv_ipaddr;
    UINT32            tdns_srv_port;
   
#if ( SWITCH_ON == CP2P_DEBUG_SWITCH )
    if ( CP2P_MD_ID_CHECK_INVALID(cp2p_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cp2p_online_report: cp2p module #0x%lx not started.\n",
                cp2p_md_id);
        cp2p_print_module_status(cp2p_md_id, LOGSTDOUT);
        dbg_exit(MD_CP2P, cp2p_md_id);
    }
#endif/*CP2P_DEBUG_SWITCH*/

    cp2p_md = CP2P_MD_GET(cp2p_md_id);

    tdns_srv_host = (const char *)CTDNSHTTP_HOST_DEFAULT;
    tdns_srv_port = c_str_to_word(CTDNSHTTP_PORT_DEFAULT);
    
    chttp_req_init(&chttp_req);
    chttp_rsp_init(&chttp_rsp);

    if(EC_FALSE == c_dns_resolve(tdns_srv_host, &tdns_srv_ipaddr))
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_online_report: dns resolve '%s' failed\n",
                        tdns_srv_host);
        return (EC_FALSE);
    }
    
    chttp_req_set_ipaddr_word(&chttp_req, tdns_srv_ipaddr);
    chttp_req_set_port_word(&chttp_req, tdns_srv_port);    

    chttp_req_set_method(&chttp_req, (const char *)"GET");
    chttp_req_set_uri(&chttp_req, (const char *)"/tdns/online");

    chttp_req_add_header(&chttp_req, (const char *)"network", c_word_to_str(CP2P_MD_NETWORK_LEVEL(cp2p_md)));
    chttp_req_add_header(&chttp_req, (const char *)"tcid"   , c_word_to_ipv4(CP2P_MD_NETWORK_TCID(cp2p_md)));
    chttp_req_add_header(&chttp_req, (const char *)"service", (char *)cstring_get_str(service_name));

    chttp_req_add_header(&chttp_req, (const char *)"Host", (const char *)tdns_srv_host);
    chttp_req_add_header(&chttp_req, (const char *)"Accept"    , (const char *)"*/*");
    chttp_req_add_header(&chttp_req, (const char *)"Connection", (const char *)"keep-alive");
    chttp_req_add_header(&chttp_req, (const char *)"Content-Length", (const char *)"0");

    if(EC_FALSE == chttp_request(&chttp_req, NULL_PTR, &chttp_rsp, NULL_PTR))
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_online_report: http request failed\n");

        chttp_req_clean(&chttp_req);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    if(CHTTP_OK != CHTTP_RSP_STATUS(&chttp_rsp))
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_online_report: invalid rsp status %u\n",
                        CHTTP_RSP_STATUS(&chttp_rsp));

        chttp_req_clean(&chttp_req);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    chttp_req_clean(&chttp_req);
    chttp_rsp_clean(&chttp_rsp);

    dbg_log(SEC_0059_CP2P, 9)(LOGSTDOUT, "[DEBUG] cp2p_online_report: report online done\n");    
    
    return (EC_TRUE);
}

/**
*
*  notify edges under current network to refresh cache
*
**/
EC_BOOL cp2p_refresh_cache_notify(const UINT32 cp2p_md_id, const UINT32 des_network, const UINT32 des_tcid, const CSTRING *service, const CSTRING *path)
{
    CP2P_MD          *cp2p_md;

    TASK_MGR         *task_mgr;
    
    CTDNSSV_NODE_MGR *ctdnssv_node_mgr;
    CLIST_DATA       *clist_data;
        
#if ( SWITCH_ON == CP2P_DEBUG_SWITCH )
    if ( CP2P_MD_ID_CHECK_INVALID(cp2p_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cp2p_refresh_cache_notify: cp2p module #0x%lx not started.\n",
                cp2p_md_id);
        cp2p_print_module_status(cp2p_md_id, LOGSTDOUT);
        dbg_exit(MD_CP2P, cp2p_md_id);
    }
#endif/*CP2P_DEBUG_SWITCH*/

    cp2p_md = CP2P_MD_GET(cp2p_md_id);

    ctdnssv_node_mgr = ctdnssv_node_mgr_new();
    if(NULL_PTR == ctdnssv_node_mgr)
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_refresh_cache_notify: "
                                             "new ctdnssv_node_mgr failed\n");    
        return (EC_FALSE);
    }
    
    if(EC_FALSE == ctdns_finger_edge_service(CP2P_MD_CTDNS_MODI(cp2p_md), 
                                        service, 
                                        CP2P_NODES_MAX_NUM, 
                                        ctdnssv_node_mgr))
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_refresh_cache_notify: "
                                             "finger service '%s' failed\n",
                                             (char *)cstring_get_str(service));    
        ctdnssv_node_mgr_free(ctdnssv_node_mgr);
        return (EC_FALSE);
    }

    if(EC_TRUE == ctdnssv_node_mgr_is_empty(ctdnssv_node_mgr))
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_refresh_cache_notify: "
                                             "no edge node for service '%s'\n",
                                             (char *)cstring_get_str(service));    
        ctdnssv_node_mgr_free(ctdnssv_node_mgr);
        return (EC_FALSE);
    }

    /*try one by one*/
    task_mgr = task_new(NULL_PTR, TASK_PRIO_NORMAL, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP);
    CLIST_LOOP_NEXT(CTDNSSV_NODE_MGR_NODES(ctdnssv_node_mgr), clist_data)
    {
        CTDNSSV_NODE        *ctdnssv_node;
        MOD_NODE             recv_mod_node;

        ctdnssv_node = CLIST_DATA_DATA(clist_data);

        MOD_NODE_TCID(&recv_mod_node) = CTDNSSV_NODE_TCID(ctdnssv_node);
        MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
        MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
        MOD_NODE_MODI(&recv_mod_node) = 0;/*only one p2p module*/

        if(do_log(SEC_0059_CP2P, 9))
        {
            dbg_log(SEC_0059_CP2P, 9)(LOGSTDOUT, "[DEBUG] cp2p_refresh_cache_notify: "
                                                 "notify service '%s' edge node '%s' to refresh cache '%s' "
                                                 "to network %ld, des tcid '%s'\n",
                                                 (char *)cstring_get_str(service),
                                                 c_word_to_ipv4(CTDNSSV_NODE_TCID(ctdnssv_node)),
                                                 (char *)cstring_get_str(path),
                                                 des_network,
                                                 c_word_to_ipv4(des_tcid)); 
        }
        
        task_p2p_inc(task_mgr, 
                    cp2p_md_id, 
                    &recv_mod_node,
                    NULL_PTR, FI_cp2p_refresh_cache, CMPI_ERROR_MODI, des_network, des_tcid, service, path);
    }
    ctdnssv_node_mgr_free(ctdnssv_node_mgr);  
    
    task_no_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);
                     
    return (EC_TRUE);
}

/**
*
*  refresh local cache
*
**/
EC_BOOL cp2p_refresh_local_cache(const UINT32 cp2p_md_id, const CSTRING *path)
{
    CP2P_MD          *cp2p_md;

    CHTTP_REQ         chttp_req;
    CHTTP_RSP         chttp_rsp;
   
#if ( SWITCH_ON == CP2P_DEBUG_SWITCH )
    if ( CP2P_MD_ID_CHECK_INVALID(cp2p_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cp2p_refresh_local_cache: cp2p module #0x%lx not started.\n",
                cp2p_md_id);
        cp2p_print_module_status(cp2p_md_id, LOGSTDOUT);
        dbg_exit(MD_CP2P, cp2p_md_id);
    }
#endif/*CP2P_DEBUG_SWITCH*/

    cp2p_md = CP2P_MD_GET(cp2p_md_id);
    
    chttp_req_init(&chttp_req);
    chttp_rsp_init(&chttp_rsp);
    
    chttp_req_set_ipaddr(&chttp_req, (const char *)"127.0.0.1");
    chttp_req_set_port(&chttp_req, (const char *)"80");    

    chttp_req_set_method(&chttp_req, (const char *)"GET");
    chttp_req_set_uri(&chttp_req, (const char *)cstring_get_str(path));

    chttp_req_add_header(&chttp_req, (const char *)"Host", (const char *)"www.refresh.com");
    chttp_req_add_header(&chttp_req, (const char *)"Accept"    , (const char *)"*/*");
    chttp_req_add_header(&chttp_req, (const char *)"Connection", (const char *)"keep-alive");
    chttp_req_add_header(&chttp_req, (const char *)"Content-Length", (const char *)"0");

    if(EC_FALSE == chttp_request(&chttp_req, NULL_PTR, &chttp_rsp, NULL_PTR))
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_refresh_local_cache: http request failed\n");

        chttp_req_clean(&chttp_req);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    if(CHTTP_OK != CHTTP_RSP_STATUS(&chttp_rsp))
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_refresh_local_cache: invalid rsp status %u\n",
                        CHTTP_RSP_STATUS(&chttp_rsp));

        chttp_req_clean(&chttp_req);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    chttp_req_clean(&chttp_req);
    chttp_rsp_clean(&chttp_rsp);

    dbg_log(SEC_0059_CP2P, 9)(LOGSTDOUT, "[DEBUG] cp2p_refresh_local_cache: refresh '%s' done\n",
                    (const char *)cstring_get_str(path));    
    
    return (EC_TRUE);
}

/**
*
*  refresh cache
*
**/
EC_BOOL cp2p_refresh_cache(const UINT32 cp2p_md_id, const UINT32 des_network, const UINT32 des_tcid, const CSTRING *service, const CSTRING *path)
{
    CP2P_MD          *cp2p_md;
        
#if ( SWITCH_ON == CP2P_DEBUG_SWITCH )
    if ( CP2P_MD_ID_CHECK_INVALID(cp2p_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cp2p_refresh_cache: cp2p module #0x%lx not started.\n",
                cp2p_md_id);
        cp2p_print_module_status(cp2p_md_id, LOGSTDOUT);
        dbg_exit(MD_CP2P, cp2p_md_id);
    }
#endif/*CP2P_DEBUG_SWITCH*/

    cp2p_md = CP2P_MD_GET(cp2p_md_id);

    if(CMPI_ANY_NETWORK == des_network)
    {
        if(CMPI_ANY_TCID == des_tcid || CP2P_MD_NETWORK_TCID(cp2p_md) == des_tcid)
        {
            cp2p_refresh_local_cache(cp2p_md_id, path);
        }
        
        return cp2p_refresh_cache_notify(cp2p_md_id, des_network, des_tcid, service, path);
    }

    if(CP2P_MD_NETWORK_LEVEL(cp2p_md) > des_network)
    {
        dbg_log(SEC_0059_CP2P, 0)(LOGSTDOUT, "error:cp2p_refresh_cache: "
                                             "cur network level %ld > des_network %ld\n",
                                             CP2P_MD_NETWORK_LEVEL(cp2p_md),
                                             des_network);    
        return (EC_FALSE);
    }    

    if(CP2P_MD_NETWORK_LEVEL(cp2p_md) < des_network)
    {
        return cp2p_refresh_cache_notify(cp2p_md_id, des_network, des_tcid, service, path);
    }

    if(CMPI_ANY_TCID == des_tcid || CP2P_MD_NETWORK_TCID(cp2p_md) == des_tcid)
    {   
        return cp2p_refresh_local_cache(cp2p_md_id, path);
    }

    if(do_log(SEC_0059_CP2P, 9))
    {
        dbg_log(SEC_0059_CP2P, 9)(LOGSTDOUT, "[DEBUG] cp2p_refresh_cache: "
                                             "cur network %ld, tcid '%s' != des network %ld, tcid '%s' "
                                             "ignore refreshing cache '%s' of service '%s'\n",
                                             CP2P_MD_NETWORK_LEVEL(cp2p_md),
                                             c_word_to_ipv4(CP2P_MD_NETWORK_TCID(cp2p_md)),
                                             des_network,
                                             c_word_to_ipv4(des_tcid),
                                             (char *)cstring_get_str(path),
                                             (char *)cstring_get_str(service));
    }
     
    return (EC_TRUE);
}


#ifdef __cplusplus
}
#endif/*__cplusplus*/


