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
#include "task.h"
#include "crb.h"
#include "cepoll.h"

#include "cfile.h"

#include "ctrans.h"

#include "camd.h"

#include "findex.inc"

#define CTRANS_MD_CAPACITY()                  (cbc_md_capacity(MD_CTRANS))

#define CTRANS_MD_GET(ctrans_md_id)     ((CTRANS_MD *)cbc_md_get(MD_CTRANS, (ctrans_md_id)))

#define CTRANS_MD_ID_CHECK_INVALID(ctrans_md_id)  \
    ((CMPI_ANY_MODI != (ctrans_md_id)) && ((NULL_PTR == CTRANS_MD_GET(ctrans_md_id)) || (0 == (CTRANS_MD_GET(ctrans_md_id)->usedcounter))))

/**
*   for test only
*
*   to query the status of CTRANS Module
*
**/
void ctrans_print_module_status(const UINT32 ctrans_md_id, LOG *log)
{
    CTRANS_MD *ctrans_md;
    UINT32   this_ctrans_md_id;

    for( this_ctrans_md_id = 0; this_ctrans_md_id < CTRANS_MD_CAPACITY(); this_ctrans_md_id ++ )
    {
        ctrans_md = CTRANS_MD_GET(this_ctrans_md_id);

        if ( NULL_PTR != ctrans_md && 0 < ctrans_md->usedcounter )
        {
            sys_log(log,"CTRANS Module # %ld : %ld refered\n",
                    this_ctrans_md_id,
                    ctrans_md->usedcounter);
        }
    }

    return ;
}

/**
*
*   free all static memory occupied by the appointed CTRANS module
*
*
**/
UINT32 ctrans_free_module_static_mem(const UINT32 ctrans_md_id)
{
    //CTRANS_MD  *ctrans_md;

#if ( SWITCH_ON == CTRANS_DEBUG_SWITCH )
    if ( CTRANS_MD_ID_CHECK_INVALID(ctrans_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:ctrans_free_module_static_mem: ctrans module #0x%lx not started.\n",
                ctrans_md_id);
        /*note: here do not exit but return only*/
        return ((UINT32)-1);
    }
#endif/*CTRANS_DEBUG_SWITCH*/

    //ctrans_md = CTRANS_MD_GET(ctrans_md_id);

    free_module_static_mem(MD_CTRANS, ctrans_md_id);

    return 0;
}

/**
*
* start CTRANS module
*
**/
UINT32 ctrans_start(const UINT32 des_tcid, const UINT32 seg_size, const UINT32 seg_concurrence)
{
    CTRANS_MD    *ctrans_md;
    UINT32        ctrans_md_id;
    UINT32        ctrans_seg_size;
    UINT32        ctrans_seg_concurrence;

    //TASK_BRD    *task_brd;

    //task_brd = task_brd_default_get();

    cbc_md_reg(MD_CTRANS , 1);

    ctrans_md_id = cbc_md_new(MD_CTRANS, sizeof(CTRANS_MD));
    if(CMPI_ERROR_MODI == ctrans_md_id)
    {
        return (CMPI_ERROR_MODI);
    }

    /* initialize new one CTRANS module */
    ctrans_md = (CTRANS_MD *)cbc_md_get(MD_CTRANS, ctrans_md_id);
    ctrans_md->usedcounter   = 0;

    /* create a new module node */
    init_static_mem();

    if(0 == seg_size)
    {
        ctrans_seg_size = CTRANS_SEG_SIZE_DEFAULT;

        dbg_log(SEC_0140_CTRANS, 0)(LOGSTDOUT, "warn:ctrans_start: "
                                               "adjust seg_size %ld => %ld\n",
                                               seg_size, ctrans_seg_size);
    }
    else
    {
        ctrans_seg_size = seg_size;
    }

    if(0 == seg_concurrence)
    {
        ctrans_seg_concurrence = CTRANS_SEG_CONCURRENCE_DEFAULT;

        dbg_log(SEC_0140_CTRANS, 0)(LOGSTDOUT, "warn:ctrans_start: "
                                               "adjust seg_concurrence %ld => %ld\n",
                                               seg_concurrence, ctrans_seg_concurrence);
    }
    else
    {
        ctrans_seg_concurrence = seg_concurrence;
    }

    CTRANS_MD_LOCAL_CFILE_MODI(ctrans_md)       = CMPI_ERROR_MODI;
    CTRANS_MD_REMOTE_TCID(ctrans_md)            = des_tcid;
    CTRANS_MD_REMOTE_CFILE_MODI(ctrans_md)      = 0/*default*/;
    CTRANS_MD_SEG_SIZE(ctrans_md)               = ctrans_seg_size;
    CTRANS_MD_SEG_CONCURRENCE(ctrans_md)        = ctrans_seg_concurrence;

    ctrans_md->usedcounter = 1;

    CTRANS_MD_LOCAL_CFILE_MODI(ctrans_md) = cfile_start();
    if(CMPI_ERROR_MODI == CTRANS_MD_LOCAL_CFILE_MODI(ctrans_md))
    {
        dbg_log(SEC_0140_CTRANS, 0)(LOGSTDOUT, "error:ctrans_start: "
                                               "start CFILE module failed\n");
        ctrans_end(ctrans_md_id);
        return (CMPI_ERROR_MODI);
    }

    csig_atexit_register((CSIG_ATEXIT_HANDLER)ctrans_end, ctrans_md_id);

    dbg_log(SEC_0140_CTRANS, 0)(LOGSTDOUT, "[DEBUG] ctrans_start: "
                                           "start CTRANS module #%ld\n",
                                           ctrans_md_id);

    return ( ctrans_md_id );
}

/**
*
* end CTRANS module
*
**/
void ctrans_end(const UINT32 ctrans_md_id)
{
    CTRANS_MD *ctrans_md;

    csig_atexit_unregister((CSIG_ATEXIT_HANDLER)ctrans_end, ctrans_md_id);

    ctrans_md = CTRANS_MD_GET(ctrans_md_id);
    if(NULL_PTR == ctrans_md)
    {
        dbg_log(SEC_0140_CTRANS, 0)(LOGSTDOUT, "error:ctrans_end: "
                                               "ctrans_md_id = %ld not exist.\n",
                                               ctrans_md_id);
        dbg_exit(MD_CTRANS, ctrans_md_id);
    }

    /* if the module is occupied by others,then decrease counter only */
    if ( 1 < ctrans_md->usedcounter )
    {
        ctrans_md->usedcounter --;
        return ;
    }

    if ( 0 == ctrans_md->usedcounter )
    {
        dbg_log(SEC_0140_CTRANS, 0)(LOGSTDOUT, "error:ctrans_end: "
                                               "ctrans_md_id = %ld is not started.\n",
                                               ctrans_md_id);
        dbg_exit(MD_CTRANS, ctrans_md_id);
    }

    /* free module : */
    //ctrans_free_module_static_mem(ctrans_md_id);

    if(CMPI_ERROR_MODI != CTRANS_MD_LOCAL_CFILE_MODI(ctrans_md))
    {
        cfile_end(CTRANS_MD_LOCAL_CFILE_MODI(ctrans_md));
        CTRANS_MD_LOCAL_CFILE_MODI(ctrans_md) = CMPI_ERROR_MODI;
    }

    CTRANS_MD_REMOTE_TCID(ctrans_md)            = CMPI_ERROR_TCID;
    CTRANS_MD_REMOTE_CFILE_MODI(ctrans_md)      = CMPI_ERROR_MODI;
    CTRANS_MD_SEG_SIZE(ctrans_md)               = CTRANS_SEG_SIZE_DEFAULT;

    ctrans_md->usedcounter = 0;

    dbg_log(SEC_0140_CTRANS, 0)(LOGSTDOUT, "ctrans_end: stop CTRANS module #%ld\n", ctrans_md_id);
    cbc_md_free(MD_CTRANS, ctrans_md_id);

    return ;
}

STATIC_CAST CAMD_MD *__ctrans_start_camd(const UINT32 ctrans_md_id, const CSTRING *src_file_path)
{
    CAMD_MD         *camd_md;
    UINT32           src_file_size;
    int              src_fd;

    src_fd = c_file_open((char *)cstring_get_str(src_file_path), O_RDWR | O_DIRECT, 0666);
    if(ERR_FD == src_fd)
    {
        dbg_log(SEC_0140_CTRANS, 0)(LOGSTDOUT, "error:__ctrans_start_camd: "
                                               "open file '%s' failed\n",
                                               (char *)cstring_get_str(src_file_path));
        return (NULL_PTR);
    }

    if(EC_FALSE == c_file_size(src_fd, &src_file_size))
    {
        dbg_log(SEC_0140_CTRANS, 0)(LOGSTDOUT, "error:__ctrans_start_camd: "
                                               "size of file '%s' failed\n",
                                               (char *)cstring_get_str(src_file_path));
        c_file_close(src_fd);
        return (NULL_PTR);
    }

    camd_md = camd_start(NULL_PTR,                      /*camd_shm_root_dir */
                         ERR_FD,                        /*sata_meta_fd      */
                         src_fd, src_file_size,         /*sata disk         */
                         0,                             /*mem_disk_size     */
                         ERR_FD,                        /*ssd_meta_fd       */
                         ERR_FD, 0, 0                   /*ssd disk          */
                         );

    if(NULL_PTR == camd_md)
    {
        dbg_log(SEC_0140_CTRANS, 0)(LOGSTDOUT, "error:__ctrans_start_camd: "
                                               "start camd failed\n");
        c_file_close(src_fd);
        return (NULL_PTR);
    }
    dbg_log(SEC_0140_CTRANS, 9)(LOGSTDOUT, "[DEBUG] __ctrans_start_camd: "
                                           "start camd done\n");

    if(NULL_PTR != task_brd_default_get())
    {
        task_brd_process_add(task_brd_default_get(),
                    (TASK_BRD_CALLBACK)camd_process,
                    (void *)camd_md);

        if(NULL_PTR != task_brd_default_get_cepoll()
        && ERR_FD != camd_get_eventfd(camd_md))
        {
            cepoll_set_event(task_brd_default_get_cepoll(),
                              camd_get_eventfd(camd_md),
                              CEPOLL_RD_EVENT,
                              (const char *)"camd_event_handler",
                              (CEPOLL_EVENT_HANDLER)camd_event_handler,
                              (void *)camd_md);
        }

        if(NULL_PTR != task_brd_default_get_cepoll()
        && ERR_FD != camd_cdio_get_eventfd(camd_md))
        {
            cepoll_set_event(task_brd_default_get_cepoll(),
                              camd_cdio_get_eventfd(camd_md),
                              CEPOLL_RD_EVENT,
                              (const char *)"camd_cdio_event_handler",
                              (CEPOLL_EVENT_HANDLER)camd_cdio_event_handler,
                              (void *)camd_md);
        }
    }

    return (camd_md);
}

STATIC_CAST EC_BOOL __ctrans_end_camd(CAMD_MD *camd_md)
{
    int src_fd;

    src_fd = CAMD_MD_SATA_DISK_FD(camd_md);

    if(NULL_PTR != task_brd_default_get())
    {
        task_brd_process_del(task_brd_default_get(),
                    (TASK_BRD_CALLBACK)camd_process,
                    (void *)camd_md);

        if(NULL_PTR != task_brd_default_get_cepoll()
        && ERR_FD != camd_get_eventfd(camd_md))
        {
            cepoll_del_event(task_brd_default_get_cepoll(),
                              camd_get_eventfd(camd_md),
                              CEPOLL_RD_EVENT);
        }

        if(NULL_PTR != task_brd_default_get_cepoll()
        && ERR_FD != camd_cdio_get_eventfd(camd_md))
        {
            cepoll_del_event(task_brd_default_get_cepoll(),
                              camd_cdio_get_eventfd(camd_md),
                              CEPOLL_RD_EVENT);
        }
    }

    camd_end(camd_md);

    c_file_close(src_fd);

    return (EC_TRUE);
}

/**
*
* transfer file segment
*
**/
EC_BOOL ctrans_seg(const UINT32 ctrans_md_id, const CSTRING *src_file_path, const CSTRING *des_file_path, const UINT32 seg_offset, const UINT32 seg_size)
{
    CTRANS_MD       *ctrans_md;

    CMD5_DIGEST      src_seg_md5sum;
    CMD5_DIGEST      des_seg_md5sum;

    MOD_NODE         recv_mod_node;
    EC_BOOL          ret;
    CBYTES           seg_content;

    CAMD_MD         *camd_md;
    UINT32           seg_offset_t;

#if ( SWITCH_ON == CTRANS_DEBUG_SWITCH )
    if ( CTRANS_MD_ID_CHECK_INVALID(ctrans_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:ctrans_seg: ctrans module #0x%lx not started.\n",
                ctrans_md_id);
        ctrans_print_module_status(ctrans_md_id, LOGSTDOUT);
        dbg_exit(MD_CTRANS, ctrans_md_id);
    }
#endif/*CTRANS_DEBUG_SWITCH*/

    ctrans_md = CTRANS_MD_GET(ctrans_md_id);
    ASSERT(CMPI_ERROR_TCID != CTRANS_MD_REMOTE_TCID(ctrans_md));
    ASSERT(CMPI_ERROR_MODI != CTRANS_MD_REMOTE_CFILE_MODI(ctrans_md));

    camd_md = __ctrans_start_camd(ctrans_md_id, src_file_path);
    if(NULL_PTR == camd_md)
    {
        dbg_log(SEC_0140_CTRANS, 0)(LOGSTDOUT, "error:ctrans_seg: "
                                               "start camd failed, src file %s\n",
                                               (char *)cstring_get_str(src_file_path));
        return (EC_FALSE);
    }

    /*load local segment*/

    cbytes_init(&seg_content);
    cbytes_expand_to(&seg_content, seg_size);

    seg_offset_t = seg_offset;
    if(EC_FALSE == camd_file_read(camd_md, CAMD_MD_SATA_DISK_FD(camd_md),
                        &seg_offset_t, seg_size, CBYTES_BUF(&seg_content)))
    {
        dbg_log(SEC_0140_CTRANS, 0)(LOGSTDOUT, "error:ctrans_seg: "
                                               "load file '%s', offset %ld, size %ld failed\n",
                                               (char *)cstring_get_str(src_file_path),
                                               seg_offset, seg_size);

        __ctrans_end_camd(camd_md);

        cbytes_clean(&seg_content);

        return (EC_FALSE);
    }

    if(seg_offset + seg_size != seg_offset_t)
    {
        dbg_log(SEC_0140_CTRANS, 0)(LOGSTDOUT, "error:ctrans_seg: "
                                               "read file %s failed, "
                                               "last offset %ld != seg offset %ld + seg size %ld\n",
                                               (char *)cstring_get_str(src_file_path),
                                               seg_offset_t, seg_offset, seg_size);

        __ctrans_end_camd(camd_md);

        cbytes_clean(&seg_content);

        return (EC_FALSE);
    }

    __ctrans_end_camd(camd_md);

    /*compute remote md5*/
    MOD_NODE_TCID(&recv_mod_node) = CTRANS_MD_REMOTE_TCID(ctrans_md);
    MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&recv_mod_node) = CMPI_ANY_RANK;
    MOD_NODE_MODI(&recv_mod_node) = CTRANS_MD_REMOTE_CFILE_MODI(ctrans_md);

    ret = EC_FALSE;
    task_p2p(ctrans_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
            &recv_mod_node,
            &ret,
            FI_cfile_seg_md5, CMPI_ERROR_MODI, des_file_path, seg_offset, seg_size, &des_seg_md5sum);

    /*compare md5*/
    /*if segment is same, then skip it*/
    if(EC_TRUE == ret)
    {
        /*compute local md5*/
        cmd5_sum((uint32_t)CBYTES_LEN(&seg_content), CBYTES_BUF(&seg_content),
                    CMD5_DIGEST_SUM(&src_seg_md5sum));

        if(0 == cmd5_digest_cmp(&src_seg_md5sum, &des_seg_md5sum))
        {
            dbg_log(SEC_0140_CTRANS, 9)(LOGSTDOUT, "[DEBUG] ctrans_seg: "
                                                   "md5 file '%s'->'%s', "
                                                   "offset %ld, size %ld matched => skip\n",
                                                   (char *)cstring_get_str(src_file_path),
                                                   (char *)cstring_get_str(des_file_path),
                                                   seg_offset, seg_size);

            cbytes_clean(&seg_content);
            return (EC_TRUE);
        }

        dbg_log(SEC_0140_CTRANS, 9)(LOGSTDOUT, "[DEBUG] ctrans_seg: "
                                               "md5 file '%s'->'%s', "
                                               "offset %ld, size %ld mismatched => override\n",
                                               (char *)cstring_get_str(src_file_path),
                                               (char *)cstring_get_str(des_file_path),
                                               seg_offset, seg_size);
    }

    /*update remote segment*/
    ret = EC_FALSE;
    task_p2p(ctrans_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
            &recv_mod_node,
            &ret,
            FI_cfile_seg_update, CMPI_ERROR_MODI, des_file_path, seg_offset, seg_size, &seg_content);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0140_CTRANS, 0)(LOGSTDOUT, "error:ctrans_seg: "
                                               "update file '%s', offset %ld, size %ld failed\n",
                                               (char *)cstring_get_str(des_file_path),
                                               seg_offset, seg_size);

        cbytes_clean(&seg_content);
        return (EC_FALSE);
    }

    cbytes_clean(&seg_content);

    dbg_log(SEC_0140_CTRANS, 9)(LOGSTDOUT, "[DEBUG] ctrans_seg: "
                                           "transfer file '%s'->'%s', offset %ld, size %ld => done\n",
                                           (char *)cstring_get_str(src_file_path),
                                           (char *)cstring_get_str(des_file_path),
                                           seg_offset, seg_size);
    return (EC_TRUE);
}

/**
*
*  file size
*
*
**/
EC_BOOL ctrans_file_size(const UINT32 ctrans_md_id, const CSTRING *file_path, UINT32 *file_size)
{
    int               fd;

#if ( SWITCH_ON == CTRANS_DEBUG_SWITCH )
    if ( CTRANS_MD_ID_CHECK_INVALID(ctrans_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:ctrans_file_size: ctrans module #0x%lx not started.\n",
                ctrans_md_id);
        ctrans_print_module_status(ctrans_md_id, LOGSTDOUT);
        dbg_exit(MD_CTRANS, ctrans_md_id);
    }
#endif/*CTRANS_DEBUG_SWITCH*/

    if(EC_TRUE == cstring_is_empty(file_path))
    {
        dbg_log(SEC_0140_CTRANS, 0)(LOGSTDOUT, "error:ctrans_file_size: "
                                               "file path is empty\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_access((char *)cstring_get_str(file_path), F_OK))
    {
        dbg_log(SEC_0140_CTRANS, 0)(LOGSTDOUT, "error:ctrans_file_size: "
                                               "file '%s' not exist\n",
                                               (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    fd = c_file_open((char *)cstring_get_str(file_path), O_RDONLY, 0666);
    if(ERR_FD == fd)
    {
        dbg_log(SEC_0140_CTRANS, 0)(LOGSTDOUT, "error:ctrans_file_size: "
                                               "open file '%s' failed\n",
                                               (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_size(fd, file_size))
    {
        dbg_log(SEC_0140_CTRANS, 0)(LOGSTDOUT, "error:ctrans_file_size: "
                                               "file '%s' size failed\n",
                                               (char *)cstring_get_str(file_path));
        c_file_close(fd);
        return (EC_FALSE);
    }

    c_file_close(fd);

    dbg_log(SEC_0140_CTRANS, 9)(LOGSTDOUT, "[DEBUG] ctrans_exists: "
                                           "file '%s' size = %ld\n",
                                           (char *)cstring_get_str(file_path), (*file_size));

    return (EC_TRUE);
}

/**
*
* transfer file
*
**/
EC_BOOL ctrans_file(const UINT32 ctrans_md_id, const CSTRING *src_file_path, const CSTRING *des_file_path)
{
    CTRANS_MD *ctrans_md;

    UINT32     src_file_size;
    UINT32     seg_offset;

#if ( SWITCH_ON == CTRANS_DEBUG_SWITCH )
    if ( CTRANS_MD_ID_CHECK_INVALID(ctrans_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:ctrans_file: ctrans module #0x%lx not started.\n",
                ctrans_md_id);
        ctrans_print_module_status(ctrans_md_id, LOGSTDOUT);
        dbg_exit(MD_CTRANS, ctrans_md_id);
    }
#endif/*CTRANS_DEBUG_SWITCH*/

    ctrans_md = CTRANS_MD_GET(ctrans_md_id);

    if(EC_FALSE == cfile_size(CTRANS_MD_LOCAL_CFILE_MODI(ctrans_md), src_file_path, &src_file_size))
    {
        dbg_log(SEC_0140_CTRANS, 0)(LOGSTDOUT, "error:ctrans_file: "
                                               "size of file '%s', failed\n",
                                               (char *)cstring_get_str(src_file_path));

        return (EC_FALSE);
    }

    dbg_log(SEC_0140_CTRANS, 9)(LOGSTDOUT, "[DEBUG] ctrans_file: "
                                           "transfer '%s'->'%s', size %ld starting\n",
                                           (char *)cstring_get_str(src_file_path),
                                           (char *)cstring_get_str(des_file_path),
                                           src_file_size);

    ASSERT(0 < CTRANS_MD_SEG_SIZE(ctrans_md));

    for(seg_offset = 0; seg_offset < src_file_size;/*do nothing*/)
    {
        MOD_NODE                 recv_mod_node;
        UINT32                   seg_concurrence;
        TASK_MGR                *task_mgr;
        CLIST                    ret_list;
        EC_BOOL                  result;

        MOD_NODE_TCID(&recv_mod_node) = CMPI_LOCAL_TCID;
        MOD_NODE_COMM(&recv_mod_node) = CMPI_LOCAL_COMM;
        MOD_NODE_RANK(&recv_mod_node) = CMPI_LOCAL_RANK;
        MOD_NODE_MODI(&recv_mod_node) = ctrans_md_id;

        task_mgr = task_new(NULL_PTR, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);

        clist_init(&ret_list, MM_UINT32, LOC_CTRANS_0001);
        result = EC_TRUE; /*default*/

        /*transfer file segments*/
        for(seg_concurrence = 0;
            seg_offset < src_file_size && seg_concurrence < CTRANS_MD_SEG_CONCURRENCE(ctrans_md);
            seg_offset += CTRANS_MD_SEG_SIZE(ctrans_md), seg_concurrence ++)
        {
            UINT32     seg_size;
            EC_BOOL   *ret;

            if(seg_offset + CTRANS_MD_SEG_SIZE(ctrans_md) >= src_file_size)
            {
                seg_size = src_file_size - seg_offset;
            }
            else
            {
                seg_size = CTRANS_MD_SEG_SIZE(ctrans_md);
            }

            alloc_static_mem(MM_UINT32, &ret, LOC_CTRANS_0002);
            (*ret) = EC_FALSE;

            clist_push_back(&ret_list, (void *)ret);

            task_p2p_inc(task_mgr, ctrans_md_id, &recv_mod_node,
                ret, FI_ctrans_seg, CMPI_ERROR_MODI, src_file_path, des_file_path, seg_offset, seg_size);
        }

        task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

        for(;EC_FALSE == clist_is_empty(&ret_list);)
        {
            EC_BOOL   *ret;

            ret = clist_pop_front(&ret_list);
            if(NULL_PTR == ret)
            {
                continue;
            }

            if(EC_FALSE == (*ret))
            {
                result = EC_FALSE;
            }
            free_static_mem(MM_UINT32, ret, LOC_CTRANS_0003);
        }

        if(EC_FALSE == result)
        {
            dbg_log(SEC_0140_CTRANS, 0)(LOGSTDOUT, "error:ctrans_file: "
                                                   "transfer '%s'->'%s' failed\n",
                                                   (char *)cstring_get_str(src_file_path),
                                                   (char *)cstring_get_str(des_file_path));
            return (EC_FALSE);
        }
    }

    /*check file size*/
    if(1)
    {
        MOD_NODE                 recv_mod_node;
        UINT32                   des_file_size;
        EC_BOOL                  ret;

        MOD_NODE_TCID(&recv_mod_node) = CTRANS_MD_REMOTE_TCID(ctrans_md);
        MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
        MOD_NODE_RANK(&recv_mod_node) = CMPI_ANY_RANK;
        MOD_NODE_MODI(&recv_mod_node) = CTRANS_MD_REMOTE_CFILE_MODI(ctrans_md);

        ret = EC_FALSE;
        task_p2p(ctrans_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                &recv_mod_node,
                &ret,
                FI_cfile_size, CMPI_ERROR_MODI, des_file_path, &des_file_size);

        if(EC_FALSE == ret)
        {
            dbg_log(SEC_0140_CTRANS, 0)(LOGSTDOUT, "error:ctrans_file: "
                                                   "size of remote '%s' failed\n",
                                                   (char *)cstring_get_str(des_file_path));
            return (EC_FALSE);
        }

        if(src_file_size != des_file_size)
        {
            dbg_log(SEC_0140_CTRANS, 0)(LOGSTDOUT, "error:ctrans_file: "
                                                   "src '%s', size %ld != des '%s', size %ld\n",
                                                   (char *)cstring_get_str(src_file_path),
                                                   src_file_size,
                                                   (char *)cstring_get_str(des_file_path),
                                                   des_file_size);
            return (EC_FALSE);
        }

        dbg_log(SEC_0140_CTRANS, 9)(LOGSTDOUT, "[DEBUG] ctrans_file: "
                                               "'%s'->'%s', size %ld matched\n",
                                               (char *)cstring_get_str(src_file_path),
                                               (char *)cstring_get_str(des_file_path),
                                               des_file_size);
    }

    dbg_log(SEC_0140_CTRANS, 9)(LOGSTDOUT, "[DEBUG] ctrans_file: "
                                           "transfer '%s'->'%s' done\n",
                                           (char *)cstring_get_str(src_file_path),
                                           (char *)cstring_get_str(des_file_path));
    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/


