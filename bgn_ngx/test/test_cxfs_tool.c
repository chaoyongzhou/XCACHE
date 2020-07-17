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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <math.h>
#include <signal.h>
#include <sched.h>

#include "type.h"

#include "mm.h"
#include "log.h"
#include "debug.h"

#include "clist.h"
#include "cvector.h"

#include "cmisc.h"

#include "cbc.h"
#include "rank.h"
#include "task.h"
#include "taskc.h"
#include "tasks.h"

#include "cmpic.inc"
#include "cmpie.h"
#include "tcnode.h"
#include "super.h"

#include "cxml.h"
#include "cparacfg.inc"
#include "cparacfg.h"

#include "csig.h"
#include "api_ui.h"

#include "cthread.h"

#include "cdevice.h"
#include "csys.h"
#include "ccode.h"
#include "cbase64code.h"

#include "api_cmd.h"
#include "api_cmd_ui.h"

#include "cload.h"
#include "creg.h"
#include "csrv.h"
#include "cproc.h"

#include "findex.inc"

#include "cxfs.h"


void init(const char *xml_cfg, const char *tcid_str)
{
    TASK_BRD *task_brd;

    CSTRING  *xml_cfg_cstr;

    init_host_endian();
    cmisc_init(LOC_TASK_0100);

    /*prepare stdout,stderr, stdin devices*/
    log_start();

    init_static_mem();

    task_brd = task_brd_default_new();

    if(NULL_PTR != xml_cfg)
    {
        xml_cfg_cstr = cstring_new((const UINT8 *)xml_cfg, LOC_NONE_BASE);
        ASSERT(NULL_PTR != xml_cfg_cstr);
    }
    else
    {
        xml_cfg_cstr = NULL_PTR;
    }

    task_brd_init(task_brd,
                    NULL_PTR, /*argc*/
                    NULL_PTR, /*argv*/
                    CMPI_ERROR_NETWORK, /*network_level*/
                    xml_cfg_cstr,       /*sys_cfg_xml_fname_cstr*/
                    NULL_PTR,           /*basic_cfg_xml_fname_cstr*/
                    NULL_PTR,           /*script_fname_cstr*/
                    NULL_PTR,           /*log_path_cstr*/
                    NULL_PTR);          /*ssl_path_cstr*/

    if(NULL_PTR != xml_cfg_cstr)
    {
        if(NULL_PTR != tcid_str)
        {
            TASK_BRD_COMM(task_brd)     = CMPI_ANY_COMM;
            TASK_BRD_SIZE(task_brd)     = 1;
            TASK_BRD_TCID(task_brd)     = c_ipv4_to_word(tcid_str);
            TASK_BRD_RANK(task_brd)     = CMPI_FWD_RANK;
        }
        else
        {
            TASK_BRD_COMM(task_brd)     = CMPI_ANY_COMM;
            TASK_BRD_SIZE(task_brd)     = 1;
            TASK_BRD_TCID(task_brd)     = CMPI_ANY_TCID; /*xxx*/
            TASK_BRD_RANK(task_brd)     = CMPI_ANY_RANK; /*xxx*/
        }

        task_brd_load(task_brd);
        task_brd_shortcut_config(task_brd);

        sys_log(LOGCONSOLE, "[DEBUG] init: load config xml done\n");

        sys_log(LOGCONSOLE, "[DEBUG] init: reset CXFSDN_CAMD_MEM_DISK_SIZE from %ld to 0\n",
                            CXFSDN_CAMD_MEM_DISK_SIZE);
        CPARACFG_DEFAULT_SET(CXFSDN_CAMD_MEM_DISK_SIZE, 0);

        sys_log(LOGCONSOLE, "[DEBUG] init: reset CXFSDN_CAMD_SWITCH to on\n");
        CPARACFG_DEFAULT_SET(CXFSDN_CAMD_SWITCH, SWITCH_ON);

        cparacfg_print(LOGCONSOLE, TASK_BRD_CPARACFG(task_brd));
    }

    /*taskover some signals*/
    TASK_BRD_CSIG(task_brd) = csig_new();
    if(NULL_PTR == TASK_BRD_CSIG(task_brd))
    {
        sys_log(LOGCONSOLE, "error:init: new csig failed\n");
        task_brd_default_abort();
    }
    csig_takeover(TASK_BRD_CSIG(task_brd));

    /*set os or process limite*/
    task_brd_os_setting(task_brd);

    cbc_new(MD_END); /*set the max number of supported modules*/
    cbc_md_reg(MD_CXFS    , 1);

    return;
}

void deinit()
{
    task_brd_free(task_brd_default_get());
    cbc_free();
    return;
}

static EC_BOOL __cxfs_test_check_str_in(const char *string, const char *tags_str)
{
    return c_str_is_in(string, ":", tags_str);
}

#define __cxfs_test_no_md_continue(__cxfs_md_id) \
    if(CMPI_ERROR_MODI == (__cxfs_md_id)) {\
        sys_log(LOGCONSOLE, "error:no cxfs module, pls open or create it at first\n");\
        continue;\
    }

void set_log_level(UINT32 loglevel)
{
    extern UINT32 g_log_level[ SEC_NONE_END ];

    log_level_tab_set_all(g_log_level, SEC_NONE_END, loglevel);
    return;
}

void print_log_level()
{
    extern UINT32 g_log_level[ SEC_NONE_END ];

    log_level_tab_print(LOGCONSOLE, g_log_level, SEC_NONE_END);
    return;
}

EC_BOOL __cxfs_test_erase_disk(const int disk_fd, const UINT32 offset, const UINT32 len)
{
    UINT8  *buff;
    UINT32  offset_t;

    ASSERT(0 < len);

    buff = safe_malloc(len, LOC_NONE_BASE);
    if(NULL_PTR == buff)
    {
        sys_log(LOGCONSOLE, "error:__cxfs_test_erase_disk: "
                            "disk fd %d, malloc %ld failed\n",
                            disk_fd, len);
        return (EC_FALSE);
    }
    BSET(buff, 0, len);

    offset_t = offset;

    if(EC_FALSE == c_file_pwrite(disk_fd, &offset_t,len, buff))
    {
        sys_log(LOGCONSOLE, "error:__cxfs_test_erase_disk: "
                            "erase disk fd %d, offset %ld, len %ld failed\n",
                            disk_fd, offset, len);

        safe_free(buff, LOC_NONE_BASE);

        return (EC_FALSE);
    }

    sys_log(LOGCONSOLE, "[DEBUG] __cxfs_test_erase_disk: "
                        "erase disk fd %d, offset %ld, len %ld done\n",
                        disk_fd, offset, len);

    safe_free(buff, LOC_NONE_BASE);

    return (EC_FALSE);
}

/*meta offset = sata_disk_size -  (sata_disk_size % vdisk_size + vdisk_size)*/
EC_BOOL __cxfs_test_erase_sata_disk(const char *sata_disk_path)
{
    UINT32      sata_disk_size;

    UINT32      cfg_offset;
    UINT32      cfg_len;
    UINT32      vdisk_size;

    int         sata_disk_fd;

    sata_disk_size = 0;

    sata_disk_fd   = ERR_FD;

    /*sata*/
    if(NULL_PTR == sata_disk_path)
    {
        sys_log(LOGCONSOLE, "error:__cxfs_test_erase_sata_disk: "
                            "sata path is null\n");

        return (EC_FALSE);
    }
    else
    {
        if(EC_FALSE == c_file_exist(sata_disk_path)
        && EC_FALSE == c_dev_exist(sata_disk_path))
        {
            sys_log(LOGCONSOLE, "error:__cxfs_test_erase_sata_disk: "
                                "no sata '%s'\n",
                                sata_disk_path);
            return (EC_FALSE);
        }

        sata_disk_fd = c_file_open(sata_disk_path, O_RDWR, 0666);
        if(ERR_FD == sata_disk_fd)
        {
            sys_log(LOGCONSOLE, "error:__cxfs_test_erase_sata_disk: "
                                "open sata '%s' failed\n",
                                sata_disk_path);

            return (EC_FALSE);
        }

        if(EC_FALSE == c_file_size(sata_disk_fd, &sata_disk_size))
        {
            sys_log(LOGCONSOLE, "error:__cxfs_test_erase_sata_disk: "
                                "size of sata '%s' failed\n",
                                sata_disk_path);

            c_file_close(sata_disk_fd);
            return (EC_FALSE);
        }

        sys_log(LOGCONSOLE, "[DEBUG] __cxfs_test_erase_sata_disk: "
                            "open sata '%s' done\n",
                            sata_disk_path);
    }


    /*32G*/
    vdisk_size  = (((UINT32)CXFSPGD_MAX_BLOCK_NUM) * ((UINT32)CXFSPGB_CACHE_MAX_BYTE_SIZE));
    if(sata_disk_size < 2 * vdisk_size)
    {
        sys_log(LOGCONSOLE, "error:__cxfs_test_erase_sata_disk: "
                            "sata '%s', sata disk size %ld v.s. vdisk_size %ld => too small\n",
                            sata_disk_path, sata_disk_size, vdisk_size);

        c_file_close(sata_disk_fd);
        return (EC_FALSE);
    }

    cfg_offset = sata_disk_size - (sata_disk_size % vdisk_size + vdisk_size);
    cfg_len    = CXFSCFG_SIZE;

    sys_log(LOGCONSOLE, "[DEBUG] __cxfs_test_erase_sata_disk: "
                        "sata '%s', sata disk size %ld, vdisk_size %ld "
                        "=> cfg offset %ld, cfg len %ld\n",
                        sata_disk_path, sata_disk_size, vdisk_size,
                        cfg_offset, cfg_len);

    if(EC_FALSE == c_file_ppad(sata_disk_fd, &cfg_offset, cfg_len, 0x00))
    {
        sys_log(LOGCONSOLE, "error:__cxfs_test_erase_sata_disk: "
                            "sata '%s' erase cfg failed\n",
                            sata_disk_path);

        c_file_close(sata_disk_fd);
        return (EC_FALSE);
    }

    sys_log(LOGCONSOLE, "[DEBUG] __cxfs_test_erase_sata_disk: "
                        "sata '%s' erase cfg failed\n",
                        sata_disk_path);

    c_file_close(sata_disk_fd);
    return (EC_TRUE);
}

/*meta offset = 0*/
EC_BOOL __cxfs_test_erase_sata_meta(const char *sata_disk_path)
{
    char       *sata_meta_path;
    UINT32      sata_meta_size;

    UINT32      cfg_offset;
    UINT32      cfg_len;

    int         sata_meta_fd;

    sata_meta_size = 0;

    sata_meta_fd   = ERR_FD;

    /*sata meta*/
    sata_meta_path = c_str_cat(sata_disk_path, (const char *)".meta");
    if(NULL_PTR == sata_meta_path)
    {
        sys_log(LOGCONSOLE, "error:__cxfs_test_erase_sata_meta: "
                            "make sata meta path '%s.meta' failed\n",
                            sata_disk_path);

        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_exist(sata_meta_path)
    && EC_FALSE == c_dev_exist(sata_meta_path))
    {
        sys_log(LOGCONSOLE, "error:__cxfs_test_erase_sata_meta: "
                            "no sata meta '%s'\n",
                            sata_meta_path);

        c_str_free(sata_meta_path);

        return (EC_FALSE);
    }
    else
    {
        sata_meta_fd = c_file_open(sata_meta_path, O_RDWR, 0666);
        if(ERR_FD == sata_meta_fd)
        {
            sys_log(LOGCONSOLE, "error:__cxfs_test_erase_sata_meta: "
                                "open sata '%s' failed\n",
                                sata_meta_path);

            c_str_free(sata_meta_path);
            return (EC_FALSE);
        }

        if(EC_FALSE == c_file_size(sata_meta_fd, &sata_meta_size))
        {
            sys_log(LOGCONSOLE, "error:__cxfs_test_erase_sata_meta: "
                                "size of sata meta '%s' failed\n",
                                sata_meta_path);

            c_file_close(sata_meta_fd);
            c_str_free(sata_meta_path);
            return (EC_FALSE);
        }

        sys_log(LOGCONSOLE, "[DEBUG] __cxfs_test_erase_sata_meta: "
                            "open sata meta '%s' done\n",
                            sata_meta_path);
    }

    cfg_offset = 0;
    cfg_len    = CXFSCFG_SIZE;

    sys_log(LOGCONSOLE, "[DEBUG] __cxfs_test_erase_sata_meta: "
                        "sata meta '%s' => cfg offset %ld, cfg len %ld\n",
                        sata_meta_path,
                        cfg_offset, cfg_len);

    if(EC_FALSE == c_file_ppad(sata_meta_fd, &cfg_offset, cfg_len, 0x00))
    {
        sys_log(LOGCONSOLE, "error:__cxfs_test_erase_sata_meta: "
                            "sata meta '%s' erase cfg failed\n",
                            sata_meta_path);

        c_file_close(sata_meta_fd);
        c_str_free(sata_meta_path);
        return (EC_FALSE);
    }

    sys_log(LOGCONSOLE, "[DEBUG] __cxfs_test_erase_sata_meta: "
                        "sata meta '%s' erase cfg failed\n",
                        sata_meta_path);

    c_file_close(sata_meta_fd);
    c_str_free(sata_meta_path);

    return (EC_TRUE);
}

EC_BOOL __cxfs_test_erase_sata(const char *sata_disk_path)
{
    char       *sata_meta_path;

    /*sata*/
    if(NULL_PTR == sata_disk_path)
    {
        sys_log(LOGCONSOLE, "error:__cxfs_test_erase_sata: "
                            "sata path is null\n");

        return (EC_FALSE);
    }

    /*sata meta*/
    sata_meta_path = c_str_cat(sata_disk_path, (const char *)".meta");
    if(NULL_PTR == sata_meta_path)
    {
        sys_log(LOGCONSOLE, "error:__cxfs_test_erase_sata: "
                            "make sata meta path '%s.meta' failed\n",
                            sata_disk_path);

        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_exist(sata_meta_path)
    && EC_FALSE == c_dev_exist(sata_meta_path))
    {
        sys_log(LOGCONSOLE, "[DEBUG] __cxfs_test_erase_sata: "
                            "no sata meta '%s'\n",
                            sata_meta_path);

        c_str_free(sata_meta_path);
        return __cxfs_test_erase_sata_disk(sata_disk_path);
    }

    c_str_free(sata_meta_path);

    return __cxfs_test_erase_sata_meta(sata_disk_path);
}

/*meta offset = ssd_disk_size -  (ssd_disk_size % vdisk_size + vdisk_size)*/
EC_BOOL __cxfs_test_erase_ssd_disk(const char *ssd_disk_path)
{
    UINT32      ssd_disk_size;

    UINT32      cfg_offset;
    UINT32      cfg_len;
    UINT32      vdisk_size;

    int         ssd_disk_fd;

    ssd_disk_size = 0;

    ssd_disk_fd   = ERR_FD;

    /*ssd*/
    if(NULL_PTR == ssd_disk_path)
    {
        sys_log(LOGCONSOLE, "error:__cxfs_test_erase_ssd_disk: "
                            "ssd path is null\n");

        return (EC_FALSE);
    }
    else
    {
        if(EC_FALSE == c_file_exist(ssd_disk_path)
        && EC_FALSE == c_dev_exist(ssd_disk_path))
        {
            sys_log(LOGCONSOLE, "error:__cxfs_test_erase_ssd_disk: "
                                "no ssd '%s'\n",
                                ssd_disk_path);
            return (EC_FALSE);
        }

        ssd_disk_fd = c_file_open(ssd_disk_path, O_RDWR, 0666);
        if(ERR_FD == ssd_disk_fd)
        {
            sys_log(LOGCONSOLE, "error:__cxfs_test_erase_ssd_disk: "
                                "open ssd '%s' failed\n",
                                ssd_disk_path);

            return (EC_FALSE);
        }

        if(EC_FALSE == c_file_size(ssd_disk_fd, &ssd_disk_size))
        {
            sys_log(LOGCONSOLE, "error:__cxfs_test_erase_ssd_disk: "
                                "size of ssd '%s' failed\n",
                                ssd_disk_path);

            c_file_close(ssd_disk_fd);
            return (EC_FALSE);
        }

        sys_log(LOGCONSOLE, "[DEBUG] __cxfs_test_erase_ssd_disk: "
                            "open ssd '%s' done\n",
                            ssd_disk_path);
    }


    /*8G*/
    vdisk_size  = (((UINT32)1) << CDCPGD_SIZE_NBITS);
    if(ssd_disk_size < 2 * vdisk_size)
    {
        sys_log(LOGCONSOLE, "error:__cxfs_test_erase_ssd_disk: "
                            "ssd '%s', ssd disk size %ld v.s. vdisk_size %ld => too small\n",
                            ssd_disk_path, ssd_disk_size, vdisk_size);

        c_file_close(ssd_disk_fd);
        return (EC_FALSE);
    }

    cfg_offset = ssd_disk_size - (ssd_disk_size % vdisk_size + vdisk_size);
    cfg_len    = CXFSCFG_SIZE;

    sys_log(LOGCONSOLE, "[DEBUG] __cxfs_test_erase_ssd_disk: "
                        "ssd '%s', ssd disk size %ld, vdisk_size %ld => cfg offset %ld, cfg len %ld\n",
                        ssd_disk_path, ssd_disk_size, vdisk_size,
                        cfg_offset, cfg_len);

    if(EC_FALSE == c_file_ppad(ssd_disk_fd, &cfg_offset, cfg_len, 0x00))
    {
        sys_log(LOGCONSOLE, "error:__cxfs_test_erase_ssd_disk: "
                            "ssd '%s' erase cfg failed\n",
                            ssd_disk_path);

        c_file_close(ssd_disk_fd);
        return (EC_FALSE);
    }

    sys_log(LOGCONSOLE, "[DEBUG] __cxfs_test_erase_ssd_disk: "
                        "ssd '%s' erase cfg failed\n",
                        ssd_disk_path);

    c_file_close(ssd_disk_fd);
    return (EC_TRUE);
}

/*meta offset = 0*/
EC_BOOL __cxfs_test_erase_ssd_meta(const char *ssd_disk_path)
{
    char       *ssd_meta_path;
    UINT32      ssd_meta_size;

    UINT32      cfg_offset;
    UINT32      cfg_len;

    int         ssd_meta_fd;

    ssd_meta_size = 0;

    ssd_meta_fd   = ERR_FD;

    /*ssd meta*/
    ssd_meta_path = c_str_cat(ssd_disk_path, (const char *)".meta");
    if(NULL_PTR == ssd_meta_path)
    {
        sys_log(LOGCONSOLE, "error:__cxfs_test_erase_ssd_meta: "
                            "make ssd meta path '%s.meta' failed\n",
                            ssd_disk_path);

        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_exist(ssd_meta_path)
    && EC_FALSE == c_dev_exist(ssd_meta_path))
    {
        sys_log(LOGCONSOLE, "error:__cxfs_test_erase_ssd_meta: "
                            "no ssd meta '%s'\n",
                            ssd_meta_path);

        c_str_free(ssd_meta_path);

        return (EC_FALSE);
    }
    else
    {
        ssd_meta_fd = c_file_open(ssd_meta_path, O_RDWR, 0666);
        if(ERR_FD == ssd_meta_fd)
        {
            sys_log(LOGCONSOLE, "error:__cxfs_test_erase_ssd_meta: "
                                "open ssd '%s' failed\n",
                                ssd_meta_path);

            c_str_free(ssd_meta_path);
            return (EC_FALSE);
        }

        if(EC_FALSE == c_file_size(ssd_meta_fd, &ssd_meta_size))
        {
            sys_log(LOGCONSOLE, "error:__cxfs_test_erase_ssd_meta: "
                                "size of ssd meta '%s' failed\n",
                                ssd_meta_path);

            c_file_close(ssd_meta_fd);
            c_str_free(ssd_meta_path);
            return (EC_FALSE);
        }

        sys_log(LOGCONSOLE, "[DEBUG] __cxfs_test_erase_ssd_meta: "
                            "open ssd meta '%s' done\n",
                            ssd_meta_path);
    }

    cfg_offset = 0;
    cfg_len    = CXFSCFG_SIZE;

    sys_log(LOGCONSOLE, "[DEBUG] __cxfs_test_erase_ssd_meta: "
                        "ssd meta '%s' => cfg offset %ld, cfg len %ld\n",
                        ssd_meta_path,
                        cfg_offset, cfg_len);

    if(EC_FALSE == c_file_ppad(ssd_meta_fd, &cfg_offset, cfg_len, 0x00))
    {
        sys_log(LOGCONSOLE, "error:__cxfs_test_erase_ssd_meta: "
                            "ssd meta '%s' erase cfg failed\n",
                            ssd_meta_path);

        c_file_close(ssd_meta_fd);
        c_str_free(ssd_meta_path);
        return (EC_FALSE);
    }

    sys_log(LOGCONSOLE, "[DEBUG] __cxfs_test_erase_ssd_meta: "
                        "ssd meta '%s' erase cfg failed\n",
                        ssd_meta_path);

    c_file_close(ssd_meta_fd);
    c_str_free(ssd_meta_path);

    return (EC_TRUE);
}

EC_BOOL __cxfs_test_erase_ssd(const char *ssd_disk_path)
{
    char       *ssd_meta_path;

    /*ssd*/
    if(NULL_PTR == ssd_disk_path)
    {
        sys_log(LOGCONSOLE, "error:__cxfs_test_erase_ssd: "
                            "ssd path is null\n");

        return (EC_FALSE);
    }

    /*ssd meta*/
    ssd_meta_path = c_str_cat(ssd_disk_path, (const char *)".meta");
    if(NULL_PTR == ssd_meta_path)
    {
        sys_log(LOGCONSOLE, "error:__cxfs_test_erase_ssd: "
                            "make ssd meta path '%s.meta' failed\n",
                            ssd_disk_path);

        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_exist(ssd_meta_path)
    && EC_FALSE == c_dev_exist(ssd_meta_path))
    {
        sys_log(LOGCONSOLE, "[DEBUG] __cxfs_test_erase_ssd: "
                            "no ssd meta '%s'\n",
                            ssd_meta_path);

        c_str_free(ssd_meta_path);
        return __cxfs_test_erase_ssd_disk(ssd_disk_path);
    }

    c_str_free(ssd_meta_path);

    return __cxfs_test_erase_ssd_meta(ssd_disk_path);
}

int __cxfs_test_suite_0(int argc, char **argv, char *xml_fname, char *tcid_str)
{
    char  cmd_line[1024];
    int   cmd_line_len = sizeof(cmd_line)/sizeof(cmd_line[0]);

    char *cmd_his_tbl[128];
    int   cmd_his_max = sizeof(cmd_his_tbl)/sizeof(cmd_his_tbl[0]);
    int   cmd_his_size = 0;

    int   idx;

    CSTRING *cxfs_sata_dir;
    CSTRING *cxfs_ssd_dir;

    const char *usage[] = {
        "open xfs <sata dir> [<ssd dir>] # e.g. open xfs /data/cache/rnode1 /data/cache/ssd1",
        "close xfs",
        "create np <model> <np num>    # e.g. create np 9 1",
        "create dn                     # e.g. create dn",
        "create sata bad bitmap",
        "dump np",
        "dump dn",
        "add disk <disk no>            # e.g. add disk 4",
        "add disks <disk num>          # e.g. add disks 4",
        "set loglevel <level>          # e.g. set loglevel 5",
        "[show|diag] mem",
        "[quit|help]"
        "[show|diag] mem",
        "<quit|help>"
    };
    int usage_size = sizeof(usage)/sizeof(usage[0]);
    //const char  *prompt = "choice> ";
    UINT32 cxfs_md_id;

    init(xml_fname, tcid_str);

    c_history_init(cmd_his_tbl, cmd_his_max, &cmd_his_size);
    sys_log_redirect_setup(LOGSTDOUT, LOGCONSOLE);

    //c_usage_print(LOGCONSOLE, usage, usage_size);

    cxfs_sata_dir = NULL_PTR;
    cxfs_ssd_dir  = NULL_PTR;
    cxfs_md_id    = CMPI_ERROR_MODI;

    sys_log(LOGCONSOLE, "[DEBUG] argc = %d\n", argc);

    for(idx = 0; idx < argc; idx ++)
    {
        char *seg[8];
        uint16_t seg_num;

        BSET(cmd_line,'\0',cmd_line_len);

        //fputs(prompt, stdout);
        //fgets(cmd_line, cmd_line_len - 1, stdin);

        //cmd_line[cmd_line_len] = 0;
        //cmd_line[strlen(cmd_line) - 1] = '\0';

        snprintf(cmd_line, cmd_line_len - 1, "%s", argv[idx]);

        sys_log(LOGCONSOLE, "cmd: %s\n", cmd_line);

        if(0 == strlen(cmd_line))
        {
            continue;
        }

        c_history_push(cmd_his_tbl, cmd_his_max, &cmd_his_size, c_str_dup(cmd_line));

        seg_num = c_str_split(cmd_line, " \t\n\r", seg, sizeof(seg)/sizeof(seg[0]));

        if(1 == seg_num && EC_TRUE == __cxfs_test_check_str_in(seg[0], "print:p"))
        {
            __cxfs_test_no_md_continue(cxfs_md_id);
            cxfs_print_module_status(cxfs_md_id, LOGCONSOLE);
            continue;
        }

        if(2 == seg_num && EC_TRUE == __cxfs_test_check_str_in(seg[0], "print:p")
                        && EC_TRUE == __cxfs_test_check_str_in(seg[1], "np"))
        {
            __cxfs_test_no_md_continue(cxfs_md_id);
            cxfs_show_npp(cxfs_md_id, LOGCONSOLE);
            continue;
        }

        if(2 == seg_num && EC_TRUE == __cxfs_test_check_str_in(seg[0], "print:p")
                        && EC_TRUE == __cxfs_test_check_str_in(seg[1], "dn"))
        {
            __cxfs_test_no_md_continue(cxfs_md_id);
            cxfs_show_dn(cxfs_md_id, LOGCONSOLE);
            continue;
        }

        if(4 == seg_num && EC_TRUE == __cxfs_test_check_str_in(seg[0], "create:cr:c")
                        && EC_TRUE == __cxfs_test_check_str_in(seg[1], "np"))
        {
            UINT32  cxfsnp_model;
            UINT32  cxfsnp_max_num;

            __cxfs_test_no_md_continue(cxfs_md_id);

            cxfsnp_model             = c_str_to_word(seg[2]);
            cxfsnp_max_num           = c_str_to_word(seg[3]);

            if(EC_FALSE == cxfs_create_npp(cxfs_md_id, cxfsnp_model, cxfsnp_max_num, 1/*hash algo*/))
            {
                sys_log(LOGCONSOLE, "error:create cxfs npp failed\n");
            }
            else
            {
                sys_log(LOGCONSOLE, "[DEBUG] create cxfs npp done\n");
            }
           continue;
        }

        if(2 == seg_num && EC_TRUE == __cxfs_test_check_str_in(seg[0], "dump")
                        && EC_TRUE == __cxfs_test_check_str_in(seg[1], "np"))
        {
            __cxfs_test_no_md_continue(cxfs_md_id);

            if(EC_FALSE == cxfs_dump_npp(cxfs_md_id, 1/*standby*/))
            {
                sys_log(LOGCONSOLE, "error:dump cxfs npp failed\n");
            }
            else
            {
                sys_log(LOGCONSOLE, "[DEBUG] dump cxfs npp done\n");
            }
           continue;
        }

        if(2 == seg_num && EC_TRUE == __cxfs_test_check_str_in(seg[0], "create:cr:c")
                        && EC_TRUE == __cxfs_test_check_str_in(seg[1], "dn"))
        {
            __cxfs_test_no_md_continue(cxfs_md_id);

            if(EC_FALSE == cxfs_create_dn(cxfs_md_id))
            {
                sys_log(LOGCONSOLE, "error:create cxfs dn failed\n");
            }
            else
            {
                sys_log(LOGCONSOLE, "[DEBUG] create cxfs dn done\n");
            }
            continue;
        }

        if(2 == seg_num && EC_TRUE == __cxfs_test_check_str_in(seg[0], "dump")
                        && EC_TRUE == __cxfs_test_check_str_in(seg[1], "dn"))
        {
            __cxfs_test_no_md_continue(cxfs_md_id);

            if(EC_FALSE == cxfs_dump_dn(cxfs_md_id, 1 /*standby*/))
            {
                sys_log(LOGCONSOLE, "error:dump cxfs dn failed\n");
            }
            else
            {
                sys_log(LOGCONSOLE, "[DEBUG] dump cxfs dn done\n");
            }
            continue;
        }

        if(4 == seg_num && EC_TRUE == __cxfs_test_check_str_in(seg[0], "create:cr:c")
                        && EC_TRUE == __cxfs_test_check_str_in(seg[1], "sata")
                        && EC_TRUE == __cxfs_test_check_str_in(seg[2], "bad")
                        && EC_TRUE == __cxfs_test_check_str_in(seg[3], "bitmap"))
        {
            if(EC_FALSE == cxfs_create_sata_bad_bitmap(cxfs_md_id))
            {
                sys_log(LOGCONSOLE, "error:create cxfs sata bad bitmap failed\n");
            }
            else
            {
                sys_log(LOGCONSOLE, "[DEBUG] create cxfs sata bad bitmap done\n");
            }
           continue;
        }

        if(3 == seg_num && EC_TRUE == __cxfs_test_check_str_in(seg[0], "add:a")
                        && EC_TRUE == __cxfs_test_check_str_in(seg[1], "disk:dsk:d"))
        {
            UINT32 disk_no;

            __cxfs_test_no_md_continue(cxfs_md_id);

            disk_no = c_str_to_word(seg[2]);

            if(EC_FALSE == cxfs_add_disk(cxfs_md_id, disk_no))
            {
                sys_log(LOGCONSOLE, "error:add disk %ld failed\n", disk_no);
            }
            else
            {
                sys_log(LOGCONSOLE, "[DEBUG] add disk %ld done\n", disk_no);
            }

            continue;
        }

        if(3 == seg_num && EC_TRUE == __cxfs_test_check_str_in(seg[0], "add:a")
                        && EC_TRUE == __cxfs_test_check_str_in(seg[1], "disks:dsks:ds"))
        {
            UINT32 disk_num;
            UINT32 disk_no;

            __cxfs_test_no_md_continue(cxfs_md_id);

            disk_num = c_str_to_word(seg[2]);

            for(disk_no = 0; disk_no < disk_num; disk_no ++)
            {
                if(EC_FALSE == cxfs_add_disk(cxfs_md_id, disk_no))
                {
                    sys_log(LOGCONSOLE, "error:add disk %ld failed\n", disk_no);
                }
                else
                {
                    sys_log(LOGCONSOLE, "[DEBUG] add disk %ld done\n", disk_no);
                }
            }

            continue;
        }

        if(4 == seg_num && EC_TRUE == __cxfs_test_check_str_in(seg[0], "open:o")
                        && EC_TRUE == __cxfs_test_check_str_in(seg[1], "xfs"))
        {
            if(CMPI_ERROR_MODI != cxfs_md_id)
            {
                sys_log(LOGCONSOLE, "error:cxfs md %u was open, pls close it at first\n", cxfs_md_id);
                continue;
            }

            ASSERT(NULL_PTR == cxfs_sata_dir);
            ASSERT(NULL_PTR == cxfs_ssd_dir);

            cxfs_sata_dir = cstring_new((UINT8 *)seg[2], 0);
            cxfs_ssd_dir  = cstring_new((UINT8 *)seg[3], 0);

            if(EC_FALSE == __cxfs_test_erase_sata((char *)cstring_get_str(cxfs_sata_dir)))
            {
                sys_log(LOGCONSOLE, "error:erase cxfs meta of sata '%s' failed\n",
                                    (char *)cstring_get_str(cxfs_sata_dir));

                continue;
            }
            sys_log(LOGCONSOLE, "[DEBUG] erase cxfs meta of sata '%s' failed\n",
                                (char *)cstring_get_str(cxfs_sata_dir));

            if(EC_FALSE == __cxfs_test_erase_ssd((char *)cstring_get_str(cxfs_ssd_dir)))
            {
                sys_log(LOGCONSOLE, "error:erase cxfs meta of ssd '%s' failed\n",
                                    (char *)cstring_get_str(cxfs_ssd_dir));

                continue;
            }
            sys_log(LOGCONSOLE, "[DEBUG] erase cxfs meta of ssd '%s' failed\n",
                                (char *)cstring_get_str(cxfs_ssd_dir));

            cxfs_md_id = cxfs_start(cxfs_sata_dir, cxfs_ssd_dir);
            if(CMPI_ERROR_MODI == cxfs_md_id)
            {
                sys_log(LOGCONSOLE, "error:open cxfs failed\n");
            }
            else
            {
                sys_log(LOGCONSOLE, "[DEBUG] open cxfs done\n");
            }

            continue;
        }

        if(3 == seg_num && EC_TRUE == __cxfs_test_check_str_in(seg[0], "open:o")
                        && EC_TRUE == __cxfs_test_check_str_in(seg[1], "xfs"))
        {
            if(CMPI_ERROR_MODI != cxfs_md_id)
            {
                sys_log(LOGCONSOLE, "error:cxfs md %u was open, pls close it at first\n", cxfs_md_id);
                continue;
            }

            ASSERT(NULL_PTR == cxfs_sata_dir);

            cxfs_sata_dir = cstring_new((UINT8 *)seg[2], 0);

            if(EC_FALSE == __cxfs_test_erase_sata((char *)cstring_get_str(cxfs_sata_dir)))
            {
                sys_log(LOGCONSOLE, "error:erase cxfs meta of sata '%s' failed\n",
                                    (char *)cstring_get_str(cxfs_sata_dir));

                continue;
            }
            sys_log(LOGCONSOLE, "[DEBUG] erase cxfs meta of sata '%s' failed\n",
                                (char *)cstring_get_str(cxfs_sata_dir));

            cxfs_md_id = cxfs_start(cxfs_sata_dir, NULL_PTR);
            if(CMPI_ERROR_MODI == cxfs_md_id)
            {
                sys_log(LOGCONSOLE, "error:open cxfs failed\n");
            }
            else
            {
                sys_log(LOGCONSOLE, "[DEBUG] open cxfs done\n");
            }
            continue;
        }

        if(2 == seg_num && EC_TRUE == __cxfs_test_check_str_in(seg[0], "close:c")
                        && EC_TRUE == __cxfs_test_check_str_in(seg[1], "xfs"))
        {
            __cxfs_test_no_md_continue(cxfs_md_id);

            cxfs_end(cxfs_md_id);
            cxfs_md_id = CMPI_ERROR_MODI;

            if(NULL_PTR != cxfs_sata_dir)
            {
                cstring_free(cxfs_sata_dir);
                cxfs_sata_dir = NULL_PTR;
            }

            if(NULL_PTR != cxfs_ssd_dir)
            {
                cstring_free(cxfs_ssd_dir);
                cxfs_ssd_dir = NULL_PTR;
            }

            continue;
        }

        if(3 == seg_num && EC_TRUE == __cxfs_test_check_str_in(seg[0], "set:s")
                        && EC_TRUE == __cxfs_test_check_str_in(seg[1], "loglevel:log:l"))
        {
            uint32_t level;
            level = c_str_to_word(seg[2]);
            set_log_level(level);
            sys_log(LOGCONSOLE, "[DEBUG] set log level to %ld\n", level);
            continue;
        }

        if(2 == seg_num && EC_TRUE == __cxfs_test_check_str_in(seg[0], "print:p")
                        && EC_TRUE == __cxfs_test_check_str_in(seg[1], "loglevel:log:l"))
        {
            print_log_level();
            continue;
        }

        if(1 == seg_num && EC_TRUE == __cxfs_test_check_str_in(seg[0], "help:h"))
        {
            c_usage_print(LOGCONSOLE, usage, usage_size);
            continue;
        }
        if(2 == seg_num && EC_TRUE == __cxfs_test_check_str_in(seg[0], "show") && EC_TRUE == __cxfs_test_check_str_in(seg[1], "mem"))
        {
            print_static_mem_status(LOGCONSOLE);
            continue;
        }
        if(2 == seg_num && EC_TRUE == __cxfs_test_check_str_in(seg[0], "diag") && EC_TRUE == __cxfs_test_check_str_in(seg[1], "mem"))
        {
            print_static_mem_diag_info(LOGCONSOLE);
            continue;
        }
        if(1 == seg_num && EC_TRUE == __cxfs_test_check_str_in(seg[0], "history:his"))
        {
            c_history_print(LOGCONSOLE, cmd_his_tbl, cmd_his_max, cmd_his_size);
            continue;
        }
        if(1 == seg_num && EC_TRUE == __cxfs_test_check_str_in(seg[0], "quit:q:exit:e"))
        {
            break;
        }
    }

    c_history_clean(cmd_his_tbl, cmd_his_max, cmd_his_size);

    if(CMPI_ERROR_MODI != cxfs_md_id)
    {
        cxfs_end(cxfs_md_id);
        cxfs_md_id = CMPI_ERROR_MODI;
    }

    if(NULL_PTR != cxfs_sata_dir)
    {
        cstring_free(cxfs_sata_dir);
        cxfs_sata_dir = NULL_PTR;
    }

    if(NULL_PTR != cxfs_ssd_dir)
    {
        cstring_free(cxfs_ssd_dir);
        cxfs_ssd_dir = NULL_PTR;
    }

    deinit();

    print_static_mem_status(LOGCONSOLE);
    print_static_mem_diag_info(LOGCONSOLE);

    return (0);
}

int main(int argc, char **argv)
{
    /*usage: $prog [<log level setting>] [<config xml>] [<tcid>] */
    if(4 == argc)
    {
        char *cmd[32];
        uint16_t cmd_num;

        cmd_num = c_str_split(argv[1], ";", cmd, sizeof(cmd)/sizeof(cmd[0]));
        return __cxfs_test_suite_0(cmd_num, cmd, argv[2], argv[3]);
    }

    if(3 == argc)
    {
        char *cmd[32];
        uint16_t cmd_num;

        cmd_num = c_str_split(argv[1], ";", cmd, sizeof(cmd)/sizeof(cmd[0]));
        return __cxfs_test_suite_0(cmd_num, cmd, argv[2], NULL_PTR);
    }

    if(2 == argc)
    {
        char *cmd[32];
        uint16_t cmd_num;

        cmd_num = c_str_split(argv[1], ";", cmd, sizeof(cmd)/sizeof(cmd[0]));
        return __cxfs_test_suite_0(cmd_num, cmd, NULL_PTR, NULL_PTR);
    }

    return __cxfs_test_suite_0(argc, argv, NULL_PTR, NULL_PTR);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

