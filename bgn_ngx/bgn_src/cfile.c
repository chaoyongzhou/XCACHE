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
#include "cfile.h"

#include "findex.inc"

#define CFILE_MD_CAPACITY()                  (cbc_md_capacity(MD_CFILE))

#define CFILE_MD_GET(cfile_md_id)     ((CFILE_MD *)cbc_md_get(MD_CFILE, (cfile_md_id)))

#define CFILE_MD_ID_CHECK_INVALID(cfile_md_id)  \
    ((CMPI_ANY_MODI != (cfile_md_id)) && ((NULL_PTR == CFILE_MD_GET(cfile_md_id)) || (0 == (CFILE_MD_GET(cfile_md_id)->usedcounter))))

/**
*   for test only
*
*   to query the status of CFILE Module
*
**/
void cfile_print_module_status(const UINT32 cfile_md_id, LOG *log)
{
    CFILE_MD *cfile_md;
    UINT32   this_cfile_md_id;

    for( this_cfile_md_id = 0; this_cfile_md_id < CFILE_MD_CAPACITY(); this_cfile_md_id ++ )
    {
        cfile_md = CFILE_MD_GET(this_cfile_md_id);

        if ( NULL_PTR != cfile_md && 0 < cfile_md->usedcounter )
        {
            sys_log(log,"CFILE Module # %ld : %ld refered\n",
                    this_cfile_md_id,
                    cfile_md->usedcounter);
        }
    }

    return ;
}

/**
*
*   free all static memory occupied by the appointed CFILE module
*
*
**/
UINT32 cfile_free_module_static_mem(const UINT32 cfile_md_id)
{
    //CFILE_MD  *cfile_md;

#if ( SWITCH_ON == CFILE_DEBUG_SWITCH )
    if ( CFILE_MD_ID_CHECK_INVALID(cfile_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cfile_free_module_static_mem: cfile module #0x%lx not started.\n",
                cfile_md_id);
        /*note: here do not exit but return only*/
        return ((UINT32)-1);
    }
#endif/*CFILE_DEBUG_SWITCH*/

    //cfile_md = CFILE_MD_GET(cfile_md_id);

    free_module_static_mem(MD_CFILE, cfile_md_id);

    return 0;
}

/**
*
* start CFILE module
*
**/
UINT32 cfile_start()
{
    CFILE_MD    *cfile_md;
    UINT32       cfile_md_id;

    //TASK_BRD    *task_brd;

    //task_brd = task_brd_default_get();

    cbc_md_reg(MD_CFILE , 1);

    cfile_md_id = cbc_md_new(MD_CFILE, sizeof(CFILE_MD));
    if(CMPI_ERROR_MODI == cfile_md_id)
    {
        return (CMPI_ERROR_MODI);
    }

    /* initialize new one CFILE module */
    cfile_md = (CFILE_MD *)cbc_md_get(MD_CFILE, cfile_md_id);
    cfile_md->usedcounter   = 0;

    /* create a new module node */
    init_static_mem();

    /*TODO:*/

    cfile_md->usedcounter = 1;

    csig_atexit_register((CSIG_ATEXIT_HANDLER)cfile_end, cfile_md_id);

    dbg_log(SEC_0069_CFILE, 0)(LOGSTDOUT, "[DEBUG] cfile_start: "
                                          "start CFILE module #%ld\n",
                                          cfile_md_id);

    return ( cfile_md_id );
}

/**
*
* end CFILE module
*
**/
void cfile_end(const UINT32 cfile_md_id)
{
    CFILE_MD *cfile_md;

    csig_atexit_unregister((CSIG_ATEXIT_HANDLER)cfile_end, cfile_md_id);

    cfile_md = CFILE_MD_GET(cfile_md_id);
    if(NULL_PTR == cfile_md)
    {
        dbg_log(SEC_0069_CFILE, 0)(LOGSTDOUT, "error:cfile_end: "
                                              "cfile_md_id = %ld not exist.\n",
                                              cfile_md_id);
        dbg_exit(MD_CFILE, cfile_md_id);
    }

    /* if the module is occupied by others,then decrease counter only */
    if ( 1 < cfile_md->usedcounter )
    {
        cfile_md->usedcounter --;
        return ;
    }

    if ( 0 == cfile_md->usedcounter )
    {
        dbg_log(SEC_0069_CFILE, 0)(LOGSTDOUT, "error:cfile_end: "
                                              "cfile_md_id = %ld is not started.\n",
                                              cfile_md_id);
        dbg_exit(MD_CFILE, cfile_md_id);
    }

    /* free module : */
    //cfile_free_module_static_mem(cfile_md_id);

    cfile_md->usedcounter = 0;

    dbg_log(SEC_0069_CFILE, 0)(LOGSTDOUT, "cfile_end: stop CFILE module #%ld\n", cfile_md_id);
    cbc_md_free(MD_CFILE, cfile_md_id);

    return ;
}

/**
*
*  check file existing
*
*
**/
EC_BOOL cfile_exists(const UINT32 cfile_md_id, const CSTRING *file_path)
{
#if ( SWITCH_ON == CFILE_DEBUG_SWITCH )
    if ( CFILE_MD_ID_CHECK_INVALID(cfile_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cfile_exists: cfile module #0x%lx not started.\n",
                cfile_md_id);
        cfile_print_module_status(cfile_md_id, LOGSTDOUT);
        dbg_exit(MD_CFILE, cfile_md_id);
    }
#endif/*CFILE_DEBUG_SWITCH*/

    if(EC_TRUE == cstring_is_empty(file_path))
    {
        dbg_log(SEC_0069_CFILE, 9)(LOGSTDOUT, "[DEBUG] cfile_exists: "
                                              "file path is empty\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_access((char *)cstring_get_str(file_path), F_OK))
    {
        dbg_log(SEC_0069_CFILE, 9)(LOGSTDOUT, "[DEBUG] cfile_exists: "
                                              "file '%s' not exist\n",
                                              (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    dbg_log(SEC_0069_CFILE, 9)(LOGSTDOUT, "[DEBUG] cfile_exists: "
                                          "file '%s' exist\n",
                                          (char *)cstring_get_str(file_path));

    return (EC_TRUE);
}

/**
*
*  file size
*
*
**/
EC_BOOL cfile_size(const UINT32 cfile_md_id, const CSTRING *file_path, UINT32 *file_size)
{
    int               fd;

#if ( SWITCH_ON == CFILE_DEBUG_SWITCH )
    if ( CFILE_MD_ID_CHECK_INVALID(cfile_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cfile_size: cfile module #0x%lx not started.\n",
                cfile_md_id);
        cfile_print_module_status(cfile_md_id, LOGSTDOUT);
        dbg_exit(MD_CFILE, cfile_md_id);
    }
#endif/*CFILE_DEBUG_SWITCH*/

    if(EC_TRUE == cstring_is_empty(file_path))
    {
        dbg_log(SEC_0069_CFILE, 0)(LOGSTDOUT, "error:cfile_size: "
                                              "file path is empty\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_access((char *)cstring_get_str(file_path), F_OK))
    {
        dbg_log(SEC_0069_CFILE, 0)(LOGSTDOUT, "error:cfile_size: "
                                              "file '%s' not exist\n",
                                              (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    fd = c_file_open((char *)cstring_get_str(file_path), O_RDONLY, 0666);
    if(ERR_FD == fd)
    {
        dbg_log(SEC_0069_CFILE, 0)(LOGSTDOUT, "error:cfile_size: "
                                              "open file '%s' failed\n",
                                              (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_size(fd, file_size))
    {
        dbg_log(SEC_0069_CFILE, 0)(LOGSTDOUT, "error:cfile_size: "
                                              "file '%s' size failed\n",
                                              (char *)cstring_get_str(file_path));
        c_file_close(fd);
        return (EC_FALSE);
    }

    c_file_close(fd);

    dbg_log(SEC_0069_CFILE, 9)(LOGSTDOUT, "[DEBUG] cfile_exists: "
                                          "file '%s' size = %ld\n",
                                          (char *)cstring_get_str(file_path), (*file_size));

    return (EC_TRUE);
}

/**
*
*  file md5
*
*
**/
EC_BOOL cfile_md5(const UINT32 cfile_md_id, const CSTRING *file_path, CMD5_DIGEST *file_md5sum)
{
    int               fd;

#if ( SWITCH_ON == CFILE_DEBUG_SWITCH )
    if ( CFILE_MD_ID_CHECK_INVALID(cfile_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cfile_md5: cfile module #0x%lx not started.\n",
                cfile_md_id);
        cfile_print_module_status(cfile_md_id, LOGSTDOUT);
        dbg_exit(MD_CFILE, cfile_md_id);
    }
#endif/*CFILE_DEBUG_SWITCH*/

    if(EC_TRUE == cstring_is_empty(file_path))
    {
        dbg_log(SEC_0069_CFILE, 0)(LOGSTDOUT, "error:cfile_md5: "
                                              "file path is empty\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_access((char *)cstring_get_str(file_path), F_OK))
    {
        dbg_log(SEC_0069_CFILE, 0)(LOGSTDOUT, "error:cfile_md5: "
                                              "file '%s' not exist\n",
                                              (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    fd = c_file_open((char *)cstring_get_str(file_path), O_RDONLY, 0666);
    if(ERR_FD == fd)
    {
        dbg_log(SEC_0069_CFILE, 0)(LOGSTDOUT, "error:cfile_md5: "
                                              "open file '%s' failed\n",
                                              (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_md5(fd, CMD5_DIGEST_SUM(file_md5sum)))
    {
        dbg_log(SEC_0069_CFILE, 0)(LOGSTDOUT, "error:cfile_md5: "
                                              "md5sum file '%s' failed\n",
                                              (char *)cstring_get_str(file_path));
        c_file_close(fd);
        return (EC_FALSE);
    }

    c_file_close(fd);

    dbg_log(SEC_0069_CFILE, 9)(LOGSTDOUT, "error:cfile_md5: "
                                          "file '%s' => md5 %s\n",
                                          (char *)cstring_get_str(file_path),
                                          cmd5_digest_hex_str(file_md5sum));

    return (EC_TRUE);
}
/**
*
*  load whole file
*
*
**/
EC_BOOL cfile_load(const UINT32 cfile_md_id, const CSTRING *file_path, CBYTES *file_content)
{
    CBYTES           *file_content_t;

    UINT32            data_len;
    UINT8            *data_buf;

#if ( SWITCH_ON == CFILE_DEBUG_SWITCH )
    if ( CFILE_MD_ID_CHECK_INVALID(cfile_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cfile_load: cfile module #0x%lx not started.\n",
                cfile_md_id);
        cfile_print_module_status(cfile_md_id, LOGSTDOUT);
        dbg_exit(MD_CFILE, cfile_md_id);
    }
#endif/*CFILE_DEBUG_SWITCH*/

    if(EC_TRUE == cstring_is_empty(file_path))
    {
        dbg_log(SEC_0069_CFILE, 0)(LOGSTDOUT, "error:cfile_load: "
                                              "file path is empty\n");
        return (EC_FALSE);
    }

    file_content_t = c_file_load_whole((char *)cstring_get_str(file_path));
    if(NULL_PTR == file_content_t)
    {
        dbg_log(SEC_0069_CFILE, 0)(LOGSTDOUT, "error:cfile_load: "
                                              "load file '%s' failed\n",
                                              (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    cbytes_umount(file_content_t, &data_len, &data_buf);
    cbytes_mount(file_content, data_len, data_buf);

    cbytes_free(file_content_t);

    dbg_log(SEC_0069_CFILE, 9)(LOGSTDOUT, "[DEBUG] cfile_load: "
                                          "load file '%s' done where len = %ld\n",
                                          (char *)cstring_get_str(file_path), data_len);
    return (EC_TRUE);
}

/**
*
*  update file content
*
*
**/
EC_BOOL cfile_update(const UINT32 cfile_md_id, const CSTRING *file_path, const CBYTES *file_content)
{
    int               fd;

    UINT32            data_len;
    UINT8            *data_buf;

#if ( SWITCH_ON == CFILE_DEBUG_SWITCH )
    if ( CFILE_MD_ID_CHECK_INVALID(cfile_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cfile_update: cfile module #0x%lx not started.\n",
                cfile_md_id);
        cfile_print_module_status(cfile_md_id, LOGSTDOUT);
        dbg_exit(MD_CFILE, cfile_md_id);
    }
#endif/*CFILE_DEBUG_SWITCH*/

    if(EC_TRUE == cstring_is_empty(file_path))
    {
        dbg_log(SEC_0069_CFILE, 0)(LOGSTDOUT, "error:cfile_update: "
                                              "file path is empty\n");
        return (EC_FALSE);
    }

    fd = c_file_open((char *)cstring_get_str(file_path), O_RDWR | O_CREAT, 0666);
    if(ERR_FD == fd)
    {
        dbg_log(SEC_0069_CFILE, 0)(LOGSTDOUT, "error:cfile_update: "
                                              "open file '%s' failed\n",
                                              (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    data_len = CBYTES_LEN(file_content);
    data_buf = CBYTES_BUF(file_content);

    if(EC_FALSE == c_file_truncate(fd, data_len))
    {
        dbg_log(SEC_0069_CFILE, 0)(LOGSTDOUT, "error:cfile_update: "
                                              "truncate file '%s' to size %ld failed\n",
                                              (char *)cstring_get_str(file_path), data_len);
        c_file_close(fd);
        return (EC_FALSE);
    }

    if(0 < data_len)
    {
        UINT32 offset;

        offset = 0;

        if(EC_FALSE == c_file_flush(fd, &offset, data_len, data_buf))
        {
            dbg_log(SEC_0069_CFILE, 0)(LOGSTDOUT, "error:cfile_update: "
                                                  "flush file '%s' with data size %ld failed\n",
                                                  (char *)cstring_get_str(file_path), data_len);
            c_file_close(fd);
            return (EC_FALSE);
        }
    }

    c_file_close(fd);

    dbg_log(SEC_0069_CFILE, 9)(LOGSTDOUT, "[DEBUG] cfile_update: "
                                          "update file '%s' with size %ld done\n",
                                          (char *)cstring_get_str(file_path), data_len);

    return (EC_TRUE);
}

/**
*
*  remove file
*
*
**/
EC_BOOL cfile_remove(const UINT32 cfile_md_id, const CSTRING *file_path)
{
#if ( SWITCH_ON == CFILE_DEBUG_SWITCH )
    if ( CFILE_MD_ID_CHECK_INVALID(cfile_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cfile_remove: cfile module #0x%lx not started.\n",
                cfile_md_id);
        cfile_print_module_status(cfile_md_id, LOGSTDOUT);
        dbg_exit(MD_CFILE, cfile_md_id);
    }
#endif/*CFILE_DEBUG_SWITCH*/

    if(EC_TRUE == cstring_is_empty(file_path))
    {
        dbg_log(SEC_0069_CFILE, 0)(LOGSTDOUT, "error:cfile_remove: "
                                              "file path is empty\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_remove((char *)cstring_get_str(file_path)))
    {
        dbg_log(SEC_0069_CFILE, 0)(LOGSTDOUT, "error:cfile_remove: "
                                              "remove file '%s' failed\n",
                                              (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    dbg_log(SEC_0069_CFILE, 9)(LOGSTDOUT, "[DEBUG] cfile_remove: "
                                          "remove file '%s' done\n",
                                          (char *)cstring_get_str(file_path));
    return (EC_TRUE);
}

/**
*
*  rename/move file
*
*
**/
EC_BOOL cfile_rename(const UINT32 cfile_md_id, const CSTRING *src_file_path, const CSTRING *des_file_path)
{
#if ( SWITCH_ON == CFILE_DEBUG_SWITCH )
    if ( CFILE_MD_ID_CHECK_INVALID(cfile_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cfile_rename: cfile module #0x%lx not started.\n",
                cfile_md_id);
        cfile_print_module_status(cfile_md_id, LOGSTDOUT);
        dbg_exit(MD_CFILE, cfile_md_id);
    }
#endif/*CFILE_DEBUG_SWITCH*/

    if(EC_TRUE == cstring_is_empty(src_file_path))
    {
        dbg_log(SEC_0069_CFILE, 0)(LOGSTDOUT, "error:cfile_rename: "
                                              "src file path is empty\n");
        return (EC_FALSE);
    }

    if(EC_TRUE == cstring_is_empty(des_file_path))
    {
        dbg_log(SEC_0069_CFILE, 0)(LOGSTDOUT, "error:cfile_rename: "
                                              "des file path is empty\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_rename((char *)cstring_get_str(src_file_path),
                                 (char *)cstring_get_str(des_file_path)))
    {
        dbg_log(SEC_0069_CFILE, 0)(LOGSTDOUT, "error:cfile_rename: "
                                              "rename file '%s' to '%s' failed\n",
                                              (char *)cstring_get_str(src_file_path),
                                              (char *)cstring_get_str(des_file_path));
        return (EC_FALSE);
    }

    dbg_log(SEC_0069_CFILE, 9)(LOGSTDOUT, "[DEBUG] cfile_rename: "
                                          "rename file '%s' to '%s' done\n",
                                          (char *)cstring_get_str(src_file_path),
                                          (char *)cstring_get_str(des_file_path));
    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/


