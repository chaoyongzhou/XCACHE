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
#include <stdarg.h>
#include <unistd.h>
#include <time.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "typeconst.h"
#include "type.h"
#include "mm.h"
#include "cmisc.h"
#include "task.h"
#include "mod.h"
#include "log.h"
#include "debug.h"
#include "rank.h"

#include "cstring.h"
#include "cvector.h"

#include "super.h"
#include "tbd.h"
#include "crun.h"

#include "cthread.h"

#include "cmpic.inc"
#include "findex.inc"

#include "chashalgo.h"
#include "cbytes.h"

#include "cxfs.h"
#include "cxfsnp.h"
#include "demo_hsxfs.h"


#define CXFS_TEST_TCID_STR  ((char *)"10.10.10.1")
#define CXFS_TEST_RANK      ((UINT32)0)
#define CXFS_TEST_MODI      ((UINT32)0)

#define CCURL_TEST_RANK     ((UINT32)0)
#define CCURL_TEST_MODI     ((UINT32)0)
#define CCURL_TEST_STEP     ((UINT32)128)

static CBYTES   *g_cbytes[32];
static UINT32    g_cbytes_max_len = sizeof(g_cbytes)/sizeof(g_cbytes[0]);

static DEMO_HSXFS_CFG   g_hsxfs_cfg = {NULL_PTR, NULL_PTR, BIT_FALSE};
static CSTRING         *g_node_type = NULL_PTR;

static DEMO_HSXFS_ARG   g_demo_hsxfs_arg = {CMPI_ANY_TCID, 0, 0, NULL_PTR};


STATIC_CAST static EC_BOOL __test_cxfs_init_g_cbytes(const UINT32 max_num)
{
    UINT32 pos;
    UINT32 max_cfg_num;

    max_cfg_num = sizeof(g_cxfs_file_cfg_tbl)/sizeof(g_cxfs_file_cfg_tbl[0]);
    if(max_num > max_cfg_num)
    {
        dbg_log(SEC_0137_DEMO, 0)(LOGSTDOUT, "error:__test_cxfs_init_g_cbytes: max_num %ld but max_cfg_num %ld\n", max_num, max_cfg_num);
        return (EC_FALSE);
    }

    if(max_num > g_cbytes_max_len)
    {
        dbg_log(SEC_0137_DEMO, 0)(LOGSTDOUT, "error:__test_cxfs_init_g_cbytes: max_num %ld but g_cbytes_max_len %ld\n", max_num, g_cbytes_max_len);
        return (EC_FALSE);
    }

    for(pos = 0; pos < g_cbytes_max_len; pos ++)
    {
        g_cbytes[ pos ] = NULL_PTR;
    }

    for(pos = 0; pos < max_num; pos ++)
    {
        char   *file_name;
        UINT32  file_size;
        CBYTES *cbytes;
        int fd;

        file_name = g_cxfs_file_cfg_tbl[ pos ].file_name;
        file_size = g_cxfs_file_cfg_tbl[ pos ].file_size;

        if(0 != access(file_name, F_OK))
        {
            dbg_log(SEC_0137_DEMO, 0)(LOGSTDOUT, "error:__test_cxfs_init_g_cbytes: file %s not exist or inaccessable\n", file_name);
            return (EC_FALSE);
        }

        fd = c_file_open(file_name, O_RDONLY, 0666);
        if(-1 == fd)
        {
            dbg_log(SEC_0137_DEMO, 0)(LOGSTDOUT, "error:__test_cxfs_init_g_cbytes: open file %s to read failed\n", file_name);
            return (EC_FALSE);
        }

        cbytes = cbytes_new(file_size);
        if((ssize_t)file_size != read(fd, cbytes_buf(cbytes), file_size))
        {
            dbg_log(SEC_0137_DEMO, 0)(LOGSTDOUT, "error:__test_cxfs_init_g_cbytes: read file %s with size %ld failed\n", file_name, file_size);
            cbytes_free(cbytes);
            c_file_close(fd);
            return (EC_FALSE);
        }

        g_cbytes[ pos ] = cbytes;

        c_file_close(fd);
    }

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __test_cxfs_clean_g_cbytes(const UINT32 max_num)
{
    UINT32 pos;
    if(max_num > g_cbytes_max_len)
    {
        dbg_log(SEC_0137_DEMO, 0)(LOGSTDOUT, "error:__test_cxfs_clean_g_cbytes: max_num %ld but g_cbytes_max_len %ld\n", max_num, g_cbytes_max_len);
        return (EC_FALSE);
    }

    for(pos = 0; pos < max_num; pos ++)
    {
        CBYTES   *cbytes;

        cbytes = g_cbytes[ pos ];
        if(NULL_PTR != cbytes)
        {
            cbytes_free(cbytes);
            g_cbytes[ pos ] = NULL_PTR;
        }
    }
    return (EC_TRUE);
}

STATIC_CAST static CBYTES *__test_cxfs_fetch_g_cbytes(const UINT32 max_num, const UINT32 pos)
{
    if(max_num > g_cbytes_max_len)
    {
        dbg_log(SEC_0137_DEMO, 0)(LOGSTDOUT, "error:__test_cxfs_fetch_g_cbytes: max_num %ld but g_cbytes_max_len %ld\n", max_num, g_cbytes_max_len);
        return (NULL_PTR);
    }

    return g_cbytes[ pos ];
}

EC_BOOL test_case_81_cxfs_md5sum(const char *home, const UINT32 cxfs_tcid, const UINT32 cxfs_rank, const UINT32 cxfs_modi, const UINT32 max_test_data_files, UINT32 *counter, UINT32 *file_num_counter, UINT32 *byte_num_counter)
{
    void *mod_mgr;
    void *task_mgr;

    UINT32 index;

    CSTRING     *path[CXFS_TEST_READ_MAX_FILES];
    CMD5_DIGEST *md5sum[CXFS_TEST_READ_MAX_FILES];/*read from dn*/
    CMD5_DIGEST *md5sum_des[CXFS_TEST_READ_MAX_FILES];/*benchmark*/
    EC_BOOL      ret[CXFS_TEST_READ_MAX_FILES];

    EC_BOOL     continue_flag;


    for(index = 0; index < CXFS_TEST_READ_MAX_FILES; index ++)
    {
        path[ index ]          = NULL_PTR;
        md5sum[ index ]     = NULL_PTR;
        md5sum_des[ index ] = NULL_PTR;
        ret[ index ]           = EC_FALSE;
    }

    mod_mgr = mod_mgr_new(CMPI_ERROR_MODI, LOAD_BALANCING_LOOP);
    mod_mgr_incl(cxfs_tcid, CMPI_ANY_COMM, cxfs_rank, cxfs_modi, mod_mgr);

    task_mgr = task_new(mod_mgr, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);

    for(index = 0; index < CXFS_TEST_READ_MAX_FILES; index ++, (*counter) ++)
    {
        CBYTES *cbytes;

        path[ index ] = cstring_new(NULL_PTR, 0);
        cstring_format(path[ index ], "%s/%ld.dat", home, (*counter));

        md5sum[ index ]     = cmd5_digest_new();
        md5sum_des[ index ] = cmd5_digest_new();

        cbytes = __test_cxfs_fetch_g_cbytes(max_test_data_files, ((*counter) % max_test_data_files));
        cmd5_sum((uint32_t)cbytes_len(cbytes), cbytes_buf(cbytes), CMD5_DIGEST_SUM(md5sum_des[ index ]));

        ret[ index ] = EC_FALSE;

        (*file_num_counter) ++;
        (*byte_num_counter) += cbytes_len(__test_cxfs_fetch_g_cbytes(max_test_data_files, ((*counter) % max_test_data_files)));

        task_inc(task_mgr, &(ret[ index ]), FI_cxfs_file_md5sum, CMPI_ERROR_MODI, path[ index ], md5sum[ index ]);
    }

    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NEED_RESCHEDULE_FLAG, NULL_PTR);

    continue_flag = EC_TRUE;

    for(index = 0; index < CXFS_TEST_READ_MAX_FILES; index ++)
    {
        if(NULL_PTR != md5sum[ index ])
        {
            if(EC_TRUE == cmd5_digest_is_equal(md5sum[ index ], md5sum_des[ index ]))
            {
                dbg_log(SEC_0137_DEMO, 5)(LOGSTDOUT, "[SUCC] path: %s\n",
                                  (char *)cstring_get_str(path[ index ]));
            }
            else
            {
                continue_flag = EC_FALSE;

                dbg_log(SEC_0137_DEMO, 0)(LOGCONSOLE, "[FAIL] path: %s\n",
                                  (char *)cstring_get_str(path[ index ]));
            }
        }

        if(NULL_PTR != path[ index ])
        {
            cstring_free(path[ index ]);
            path[ index ] = NULL_PTR;
        }

        if(NULL_PTR != md5sum[ index ])
        {
            cmd5_digest_free(md5sum[ index ]);
            md5sum[ index ] = NULL_PTR;
        }

        if(NULL_PTR != md5sum_des[ index ])
        {
            cmd5_digest_free(md5sum_des[ index ]);
            md5sum_des[ index ] = NULL_PTR;
        }
    }

    mod_mgr_free(mod_mgr);
    return (continue_flag);
}

EC_BOOL test_case_82_cxfs_read(const char *home, const UINT32 cxfs_tcid, const UINT32 cxfs_rank, const UINT32 cxfs_modi, const UINT32 max_test_data_files, UINT32 *counter, UINT32 *file_num_counter, UINT32 *byte_num_counter)
{
    void *mod_mgr;
    void *task_mgr;

    UINT32 index;

    CSTRING    *path[CXFS_TEST_READ_MAX_FILES];
    CBYTES     *cbytes[CXFS_TEST_READ_MAX_FILES];/*read from dn*/
    CBYTES     *cbytes_des[CXFS_TEST_READ_MAX_FILES];/*benchmark*/
    EC_BOOL     ret[CXFS_TEST_READ_MAX_FILES];

    EC_BOOL     continue_flag;

    for(index = 0; index < CXFS_TEST_READ_MAX_FILES; index ++)
    {
        path[ index ]          = NULL_PTR;
        cbytes[ index ]     = NULL_PTR;
        cbytes_des[ index ] = NULL_PTR;
        ret[ index ]           = EC_FALSE;
    }

    mod_mgr = mod_mgr_new(CMPI_ERROR_MODI, LOAD_BALANCING_LOOP);
    mod_mgr_incl(cxfs_tcid, CMPI_ANY_COMM, cxfs_rank, cxfs_modi, mod_mgr);

    task_mgr = task_new(mod_mgr, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);

    for(index = 0; index < CXFS_TEST_READ_MAX_FILES; index ++, (*counter) ++)
    {
        path[ index ] = cstring_new(NULL_PTR, 0);
        cstring_format(path[ index ], "%s/%ld.dat", home, (*counter));

        cbytes[ index ]     = cbytes_new(0);
        cbytes_des[ index ] = __test_cxfs_fetch_g_cbytes(max_test_data_files, ((*counter) % max_test_data_files));

        ret[ index ] = EC_FALSE;

        (*file_num_counter) ++;
        (*byte_num_counter) += cbytes_len(cbytes_des[ index ]);

        task_inc(task_mgr, &(ret[ index ]), FI_cxfs_read, CMPI_ERROR_MODI, path[ index ], cbytes[ index ]);
    }

    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NEED_RESCHEDULE_FLAG, NULL_PTR);

    continue_flag = EC_TRUE;

    for(index = 0; index < CXFS_TEST_READ_MAX_FILES; index ++)
    {
        if(NULL_PTR != cbytes[ index ])
        {
            if(EC_TRUE == cbytes_ncmp(cbytes[ index ], cbytes_des[ index ], 16))
            {
                dbg_log(SEC_0137_DEMO, 5)(LOGSTDOUT, "[SUCC] path: %s, len = %ld ",
                                  (char *)cstring_get_str(path[ index ]),
                                  cbytes_len(cbytes[ index ]));
                sys_print(LOGSTDOUT, "text = %.*s\n",
                                  cbytes_len(cbytes[ index ]) > 16 ? 16 : cbytes_len(cbytes[ index ]), /*output up to 16 chars*/
                                  (char *)cbytes_buf(cbytes[ index ]));
            }
            else
            {
                continue_flag = EC_FALSE;

                dbg_log(SEC_0137_DEMO, 0)(LOGCONSOLE, "[FAIL] path: %s, read len = %ld ",
                                  (char *)cstring_get_str(path[ index ]),
                                  cbytes_len(cbytes[ index ]));
                sys_print(LOGCONSOLE, "text = %.*s <--> ",
                                  cbytes_len(cbytes[ index ]) > 16 ? 16 : cbytes_len(cbytes[ index ]), /*output up to 16 chars*/
                                  (char *)cbytes_buf(cbytes[ index ]));

                sys_print(LOGCONSOLE, "expect len = %ld ",
                                    cbytes_len(cbytes_des[ index ]));
                sys_print(LOGCONSOLE, "text = %.*s\n",
                                    cbytes_len(cbytes_des[ index ]) > 16 ? 16 : cbytes_len(cbytes_des[ index ]),
                                    (char *)cbytes_buf(cbytes_des[ index ]));
            }
        }

        if(NULL_PTR != path[ index ])
        {
            cstring_free(path[ index ]);
            path[ index ] = NULL_PTR;
        }

        if(NULL_PTR != cbytes[ index ])
        {
            cbytes_free(cbytes[ index ]);
            cbytes[ index ] = NULL_PTR;
        }

        if(NULL_PTR != cbytes_des[ index ])
        {
            cbytes_des[ index ] = NULL_PTR;
        }
    }

    mod_mgr_free(mod_mgr);
    return (continue_flag);
}


EC_BOOL test_case_83_cxfs_write(const char *home, const UINT32 cxfs_tcid, const UINT32 cxfs_rank, const UINT32 cxfs_modi, const UINT32 max_test_data_files, UINT32 *counter, UINT32 *file_num_counter, UINT32 *byte_num_counter)
{
    void       *task_mgr;
    MOD_NODE    recv_mod_node;

    UINT32      index;

    EC_BOOL     continue_flag;

    CSTRING    *path[CXFS_TEST_WRITE_MAX_FILES];
    EC_BOOL     ret[CXFS_TEST_WRITE_MAX_FILES];

    MOD_NODE_TCID(&recv_mod_node) = cxfs_tcid;
    MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&recv_mod_node) = cxfs_rank;
    MOD_NODE_MODI(&recv_mod_node) = cxfs_modi;

    for(index = 0; index < CXFS_TEST_WRITE_MAX_FILES; index ++)
    {
        path[ index ]      = NULL_PTR;
        ret[ index ]       = EC_FALSE;
    }

    task_mgr = task_new(NULL_PTR, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    for(index = 0; index < CXFS_TEST_WRITE_MAX_FILES; index ++, (*counter) ++)
    {
        void *cbytes;

        path[ index ] = cstring_new(NULL_PTR, 0);
        cstring_format(path[ index ], "%s/%ld.dat", home, (*counter));


        ret[ index ] = EC_FALSE;
        cbytes = __test_cxfs_fetch_g_cbytes(max_test_data_files, ((*counter) % max_test_data_files));
        if(NULL_PTR == cbytes)
        {
            dbg_log(SEC_0137_DEMO, 0)(LOGSTDOUT, "error:test_case_83_cxfs_write: cxfs buff is null where index = %ld, max_test_data_files = %ld\n", index, max_test_data_files);
            cstring_free(path[ index ]);
            path[ index ] = NULL_PTR;
            break;
        }

        (*file_num_counter) ++;
        (*byte_num_counter) += cbytes_len(cbytes);

        task_p2p_inc(task_mgr, CMPI_ANY_MODI, &recv_mod_node,
                    &(ret[ index ]), FI_cxfs_write, CMPI_ERROR_MODI, path[ index ], cbytes);
    }

    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    continue_flag = EC_TRUE;

    for(index = 0; index < CXFS_TEST_WRITE_MAX_FILES; index ++)
    {
        if(EC_FALSE == ret[ index ] && NULL_PTR != path[ index ])
        {
            continue_flag = EC_FALSE;
            dbg_log(SEC_0137_DEMO, 0)(LOGCONSOLE, "test_case_83_cxfs_write: [FAIL] %s\n", (char *)cstring_get_str(path[ index ]));
        }

        if(NULL_PTR != path[ index ])
        {
            cstring_free(path[ index ]);
            path[ index ] = NULL_PTR;
        }
    }

    return (continue_flag);
}

EC_BOOL test_case_84_cxfs_delete(const char *home, const UINT32 cxfs_tcid, const UINT32 cxfs_rank, const UINT32 cxfs_modi, UINT32 *counter, UINT32 *file_num_counter)
{
    void *mod_mgr;
    void *task_mgr;

    UINT32 index;

    EC_BOOL continue_flag;

    CSTRING    *path[CXFS_TEST_WRITE_MAX_FILES];
    EC_BOOL     ret[CXFS_TEST_WRITE_MAX_FILES];

    for(index = 0; index < CXFS_TEST_WRITE_MAX_FILES; index ++)
    {
        path[ index ]      = NULL_PTR;
        ret[ index ]       = EC_FALSE;
    }

    mod_mgr = mod_mgr_new(CMPI_ERROR_MODI, LOAD_BALANCING_LOOP);
    mod_mgr_incl(cxfs_tcid, CMPI_ANY_COMM, cxfs_rank, cxfs_modi, mod_mgr);

    /*---------  multiple process verfication BEG ---------*/
    //mod_mgr = mod_mgr_new(CMPI_ERROR_MODI, LOAD_BALANCING_QUE);
    //mod_mgr_incl(cxfs_tcid, CMPI_ANY_COMM, 0, cxfs_modi, mod_mgr);
    //mod_mgr_incl(cxfs_tcid, CMPI_ANY_COMM, 1, cxfs_modi, mod_mgr);
    /*---------  multiple process verfication END ---------*/

    task_mgr = task_new(mod_mgr, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    for(index = 0; index < CXFS_TEST_WRITE_MAX_FILES; index ++, (*counter) ++)
    {
        path[ index ] = cstring_new(NULL_PTR, 0);
        cstring_format(path[ index ], "%s/%ld.dat", home, (*counter));

        ret[ index ] = EC_FALSE;

        (*file_num_counter) ++;
        task_inc(task_mgr, &(ret[ index ]), FI_cxfs_delete_file, CMPI_ERROR_MODI, path[ index ]);
    }

    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    continue_flag = EC_TRUE;

    for(index = 0; index < CXFS_TEST_WRITE_MAX_FILES; index ++)
    {
        if(EC_FALSE == ret[ index ] && NULL_PTR != path[ index ])
        {
            //continue_flag = EC_FALSE;
            dbg_log(SEC_0137_DEMO, 0)(LOGCONSOLE, "test_case_84_cxfs_delete: [FAIL] %s\n", (char *)cstring_get_str(path[ index ]));
        }
        if(NULL_PTR != path[ index ])
        {
            cstring_free(path[ index ]);
            path[ index ] = NULL_PTR;
        }
    }

    mod_mgr_free(mod_mgr);

    return (continue_flag);
}

/*check replica files*/
EC_BOOL test_case_85_cxfs_check_file_content(const char *home, const UINT32 cxfs_tcid, const UINT32 cxfs_rank, const UINT32 cxfs_modi, const UINT32 max_test_data_files, UINT32 *counter)
{
    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 index;

    CSTRING    *path[CXFS_TEST_READ_MAX_FILES];
    EC_BOOL     ret[CXFS_TEST_READ_MAX_FILES];

    EC_BOOL     continue_flag;

    for(index = 0; index < CXFS_TEST_READ_MAX_FILES; index ++)
    {
        path[ index ]      = NULL_PTR;
        ret[ index ]       = EC_FALSE;
    }

    mod_mgr = mod_mgr_new(CMPI_ERROR_MODI, LOAD_BALANCING_LOOP);
    mod_mgr_incl(cxfs_tcid, CMPI_ANY_COMM, cxfs_rank, cxfs_modi, mod_mgr);

    task_mgr = task_new(mod_mgr, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    for(index = 0; index < CXFS_TEST_READ_MAX_FILES; index ++, (*counter) ++)
    {
        CBYTES *cbytes_des;
        cbytes_des = __test_cxfs_fetch_g_cbytes(max_test_data_files, ((*counter) % max_test_data_files));

        path[ index ] = cstring_new(NULL_PTR, 0);
        cstring_format(path[ index ], "%s/%ld.dat", home, (*counter));

        ret[ index ] = EC_FALSE;

        task_inc(task_mgr, &(ret[ index ]),
                        FI_cxfs_check_file_is, CMPI_ERROR_MODI, path[ index ], cbytes_des);
    }

    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NEED_RESCHEDULE_FLAG, NULL_PTR);

    continue_flag = EC_TRUE;

    for(index = 0; index < CXFS_TEST_READ_MAX_FILES; index ++)
    {
        if(EC_TRUE == ret[ index ])
        {
            dbg_log(SEC_0137_DEMO, 5)(LOGSTDOUT, "[SUCC] path: %s\n", (char *)cstring_get_str(path[ index ]));
        }
        else
        {
            continue_flag = EC_FALSE;
            dbg_log(SEC_0137_DEMO, 0)(LOGCONSOLE, "[FAIL] path: %s\n", (char *)cstring_get_str(path[ index ]));
        }

        if(NULL_PTR != path[ index ])
        {
            cstring_free(path[ index ]);
            path[ index ] = NULL_PTR;
        }

        if(NULL_PTR != path[ index ])
        {
            cstring_free(path[ index ]);
            path[ index ] = NULL_PTR;
        }
    }

    mod_mgr_free(mod_mgr);

    return (continue_flag);
}

EC_BOOL test_case_86_cxfs_writer(const UINT32 cxfs_tcid, const UINT32 cxfs_rank, const UINT32 cxfs_modi, const UINT32 max_test_data_files, const char *root_dir_in_db)
{
    UINT32  outer_loop;
    UINT32  inner_loop;
    EC_BOOL continue_flag;

    UINT32  file_num_counter;
    UINT32  byte_num_counter;

    if(EC_FALSE == __test_cxfs_init_g_cbytes(max_test_data_files))
    {
        dbg_log(SEC_0137_DEMO, 0)(LOGSTDOUT, "error:test_case_86_cxfs_writer:__test_cxfs_init_g_cbytes failed where max_test_data_files = %ld\n", max_test_data_files);

        __test_cxfs_clean_g_cbytes(max_test_data_files);
        return (EC_FALSE);
    }

    file_num_counter = 0;
    byte_num_counter = 0;

    continue_flag = EC_TRUE;

    for(outer_loop = 0; outer_loop < CXFS_TEST_LOOP_MAX_TIMES && EC_TRUE == continue_flag; outer_loop ++)
    {
        char home[64];
        UINT32 counter;

        UINT32 dir0;
        UINT32 dir1;
        UINT32 dir2;

        dbg_log(SEC_0137_DEMO, 0)(LOGCONSOLE, "[DEBUG] test_case_86_cxfs_writer: outer_loop = %ld, file_num = %ld, byte_num = %ld\n", outer_loop, file_num_counter, byte_num_counter);

        dir0 = (outer_loop % CXFS_MAX_FILE_NUM_PER_LOOP);
        dir1 = ((outer_loop / CXFS_MAX_FILE_NUM_PER_LOOP) % CXFS_MAX_FILE_NUM_PER_LOOP);
        dir2 = ((outer_loop / CXFS_MAX_FILE_NUM_PER_LOOP) / CXFS_MAX_FILE_NUM_PER_LOOP);

        snprintf(home, sizeof(home), "%s/%ld/%ld/%ld", root_dir_in_db, dir2, dir1, dir0);

        counter = 0;
        for(inner_loop = 0; inner_loop < ((CXFS_MAX_FILE_NUM_PER_LOOP + CXFS_TEST_WRITE_MAX_FILES - 1) / CXFS_TEST_WRITE_MAX_FILES) && EC_TRUE == continue_flag; inner_loop ++)
        {
            continue_flag = test_case_83_cxfs_write(home, cxfs_tcid, cxfs_rank, cxfs_modi, max_test_data_files, &counter, &file_num_counter, &byte_num_counter);
        }
    }

    __test_cxfs_clean_g_cbytes(max_test_data_files);

    dbg_log(SEC_0137_DEMO, 0)(LOGCONSOLE, "[DEBUG] test_case_86_cxfs_writer: end\n");

    return (continue_flag);
}

EC_BOOL test_case_87_cxfs_reader(const UINT32 cxfs_tcid, const UINT32 cxfs_rank, const UINT32 cxfs_modi, const UINT32 max_test_data_files, const char *root_dir_in_db)
{
    UINT32 outer_loop;
    UINT32 inner_loop;

    EC_BOOL continue_flag;

    UINT32  file_num_counter;
    UINT32  byte_num_counter;

    if(EC_FALSE == __test_cxfs_init_g_cbytes(max_test_data_files))
    {
        dbg_log(SEC_0137_DEMO, 0)(LOGSTDOUT, "error:test_case_87_cxfs_reader:__test_cxfs_init_g_cbytes failed where max_test_data_files = %ld\n", max_test_data_files);

        __test_cxfs_clean_g_cbytes(max_test_data_files);
        return (EC_FALSE);
    }

    file_num_counter = 0;
    byte_num_counter = 0;

    continue_flag = EC_TRUE;
    for(outer_loop = 0; outer_loop < CXFS_TEST_LOOP_MAX_TIMES && EC_TRUE == continue_flag; outer_loop ++)
    {
        char home[64];
        UINT32 counter;

        UINT32 dir0;
        UINT32 dir1;
        UINT32 dir2;

        dbg_log(SEC_0137_DEMO, 0)(LOGCONSOLE, "[DEBUG] test_case_87_cxfs_reader: outer_loop = %ld, file_num = %ld, byte_num = %ld\n", outer_loop, file_num_counter, byte_num_counter);

        dir0 = (outer_loop % CXFS_MAX_FILE_NUM_PER_LOOP);
        dir1 = ((outer_loop / CXFS_MAX_FILE_NUM_PER_LOOP) % CXFS_MAX_FILE_NUM_PER_LOOP);
        dir2 = ((outer_loop / CXFS_MAX_FILE_NUM_PER_LOOP) / CXFS_MAX_FILE_NUM_PER_LOOP);

        snprintf(home, sizeof(home), "%s/%ld/%ld/%ld", root_dir_in_db, dir2, dir1, dir0);

        counter = 0;
        for(inner_loop = 0; inner_loop < ((CXFS_MAX_FILE_NUM_PER_LOOP + CXFS_TEST_READ_MAX_FILES - 1) / CXFS_TEST_READ_MAX_FILES) && EC_TRUE == continue_flag; inner_loop ++)
        {
            continue_flag = test_case_82_cxfs_read(home, cxfs_tcid, cxfs_rank, cxfs_modi, max_test_data_files, &counter, &file_num_counter, &byte_num_counter);
        }
    }

    __test_cxfs_clean_g_cbytes(max_test_data_files);

    dbg_log(SEC_0137_DEMO, 0)(LOGCONSOLE, "[DEBUG] test_case_87_cxfs_reader: end\n");

    return (continue_flag);
}

EC_BOOL test_case_88_cxfs_file_content_checker(const UINT32 cxfs_tcid, const UINT32 cxfs_rank, const UINT32 cxfs_modi, const UINT32 max_test_data_files, const char *root_dir_in_db)
{
    UINT32 outer_loop;
    UINT32 inner_loop;

    EC_BOOL continue_flag;

    if(EC_FALSE == __test_cxfs_init_g_cbytes(max_test_data_files))
    {
        dbg_log(SEC_0137_DEMO, 0)(LOGSTDOUT, "error:test_case_88_cxfs_file_content_checker:__test_cxfs_init_g_cbytes failed where max_test_data_files = %ld\n", max_test_data_files);

        __test_cxfs_clean_g_cbytes(max_test_data_files);
        return (EC_FALSE);
    }

    continue_flag = EC_TRUE;
    for(outer_loop = 0; outer_loop < CXFS_TEST_LOOP_MAX_TIMES && EC_TRUE == continue_flag; outer_loop ++)
    {
        char home[64];
        UINT32 counter;

        UINT32 dir0;
        UINT32 dir1;
        UINT32 dir2;

        dbg_log(SEC_0137_DEMO, 0)(LOGCONSOLE, "[DEBUG] test_case_88_cxfs_file_content_checker: outer_loop = %ld\n", outer_loop);

        dir0 = (outer_loop % CXFS_MAX_FILE_NUM_PER_LOOP);
        dir1 = ((outer_loop / CXFS_MAX_FILE_NUM_PER_LOOP) % CXFS_MAX_FILE_NUM_PER_LOOP);
        dir2 = ((outer_loop / CXFS_MAX_FILE_NUM_PER_LOOP) / CXFS_MAX_FILE_NUM_PER_LOOP);

        snprintf(home, sizeof(home), "%s/%ld/%ld/%ld", root_dir_in_db, dir2, dir1, dir0);

        counter = 0;
        for(inner_loop = 0; inner_loop < ((CXFS_MAX_FILE_NUM_PER_LOOP + CXFS_TEST_READ_MAX_FILES - 1) / CXFS_TEST_READ_MAX_FILES) && EC_TRUE == continue_flag; inner_loop ++)
        {
            continue_flag = test_case_85_cxfs_check_file_content(home, cxfs_tcid, cxfs_rank, cxfs_modi, max_test_data_files, &counter);
        }
    }

    __test_cxfs_clean_g_cbytes(max_test_data_files);

    dbg_log(SEC_0137_DEMO, 0)(LOGCONSOLE, "[DEBUG] test_case_88_cxfs_file_content_checker: end\n");

    return (EC_TRUE);
}

EC_BOOL test_case_89_cxfs_delete(const UINT32 cxfs_tcid, const UINT32 cxfs_rank, const UINT32 cxfs_modi, const char *root_dir_in_db)
{
    UINT32  outer_loop;
    UINT32  inner_loop;
    EC_BOOL continue_flag;

    UINT32  file_num_counter;

    file_num_counter = 0;

    continue_flag = EC_TRUE;

    for(outer_loop = 0; outer_loop < CXFS_TEST_LOOP_MAX_TIMES && EC_TRUE == continue_flag; outer_loop ++)
    {
        char home[64];
        UINT32 counter;

        UINT32 dir0;
        UINT32 dir1;
        UINT32 dir2;

        dbg_log(SEC_0137_DEMO, 0)(LOGCONSOLE, "[DEBUG] test_case_89_cxfs_delete: outer_loop = %ld, file_num = %ld\n", outer_loop, file_num_counter);

        dir0 = (outer_loop % CXFS_MAX_FILE_NUM_PER_LOOP);
        dir1 = ((outer_loop / CXFS_MAX_FILE_NUM_PER_LOOP) % CXFS_MAX_FILE_NUM_PER_LOOP);
        dir2 = ((outer_loop / CXFS_MAX_FILE_NUM_PER_LOOP) / CXFS_MAX_FILE_NUM_PER_LOOP);

        snprintf(home, sizeof(home), "%s/%ld/%ld/%ld", root_dir_in_db, dir2, dir1, dir0);

        counter = 0;
        for(inner_loop = 0; inner_loop < ((CXFS_MAX_FILE_NUM_PER_LOOP + CXFS_TEST_WRITE_MAX_FILES - 1) / CXFS_TEST_WRITE_MAX_FILES) && EC_TRUE == continue_flag; inner_loop ++)
        {
            continue_flag = test_case_84_cxfs_delete(home, cxfs_tcid, cxfs_rank, cxfs_modi, &counter, &file_num_counter);
        }
    }

    dbg_log(SEC_0137_DEMO, 0)(LOGCONSOLE, "[DEBUG] test_case_89_cxfs_delete: end\n");

    return (continue_flag);
}

EC_BOOL test_case_90_cxfs_md5sum_checker(const UINT32 cxfs_tcid, const UINT32 cxfs_rank, const UINT32 cxfs_modi, const UINT32 max_test_data_files, const char *root_dir_in_db)
{
    UINT32 outer_loop;
    UINT32 inner_loop;

    EC_BOOL continue_flag;

    UINT32  file_num_counter;
    UINT32  byte_num_counter;

    if(EC_FALSE == __test_cxfs_init_g_cbytes(max_test_data_files))
    {
        dbg_log(SEC_0137_DEMO, 0)(LOGSTDOUT, "error:test_case_90_cxfs_md5sum_checker:__test_cxfs_init_g_cbytes failed where max_test_data_files = %ld\n", max_test_data_files);

        __test_cxfs_clean_g_cbytes(max_test_data_files);
        return (EC_FALSE);
    }

    file_num_counter = 0;
    byte_num_counter = 0;

    continue_flag = EC_TRUE;
    for(outer_loop = 0; outer_loop < CXFS_TEST_LOOP_MAX_TIMES && EC_TRUE == continue_flag; outer_loop ++)
    {
        char home[64];
        UINT32 counter;

        UINT32 dir0;
        UINT32 dir1;
        UINT32 dir2;

        dbg_log(SEC_0137_DEMO, 0)(LOGCONSOLE, "[DEBUG] test_case_90_cxfs_md5sum_checker: outer_loop = %ld, file_num = %ld, byte_num = %ld\n", outer_loop, file_num_counter, byte_num_counter);

        dir0 = (outer_loop % CXFS_MAX_FILE_NUM_PER_LOOP);
        dir1 = ((outer_loop / CXFS_MAX_FILE_NUM_PER_LOOP) % CXFS_MAX_FILE_NUM_PER_LOOP);
        dir2 = ((outer_loop / CXFS_MAX_FILE_NUM_PER_LOOP) / CXFS_MAX_FILE_NUM_PER_LOOP);

        snprintf(home, sizeof(home), "%s/%ld/%ld/%ld", root_dir_in_db, dir2, dir1, dir0);

        counter = 0;
        for(inner_loop = 0; inner_loop < ((CXFS_MAX_FILE_NUM_PER_LOOP + CXFS_TEST_READ_MAX_FILES - 1) / CXFS_TEST_READ_MAX_FILES) && EC_TRUE == continue_flag; inner_loop ++)
        {
            continue_flag = test_case_81_cxfs_md5sum(home, cxfs_tcid, cxfs_rank, cxfs_modi, max_test_data_files, &counter, &file_num_counter, &byte_num_counter);
        }
    }

    __test_cxfs_clean_g_cbytes(max_test_data_files);

    dbg_log(SEC_0137_DEMO, 0)(LOGCONSOLE, "[DEBUG] test_case_90_cxfs_md5sum_checker: end\n");

    return (continue_flag);
}

/*runner over thread*/
EC_BOOL __test_cxfs_runner(DEMO_HSXFS_CFG *hsxfs_cfg)
{
    UINT32              cxfs_modi;
    MOD_NODE            recv_mod_node;

    if(BIT_FALSE == hsxfs_cfg->xfs_retrive_flag)
    {
        cxfs_modi = cxfs_start(hsxfs_cfg->xfs_sata_path, hsxfs_cfg->xfs_ssd_path);
    }
    else
    {
        cxfs_modi = cxfs_retrieve(hsxfs_cfg->xfs_sata_path, hsxfs_cfg->xfs_ssd_path);
    }

    ASSERT(CMPI_ERROR_MODI != cxfs_modi);

    MOD_NODE_TCID(&recv_mod_node) = CMPI_LOCAL_TCID;
    MOD_NODE_COMM(&recv_mod_node) = CMPI_LOCAL_COMM;
    MOD_NODE_RANK(&recv_mod_node) = CMPI_LOCAL_RANK;
    MOD_NODE_MODI(&recv_mod_node) = cxfs_modi;

    task_brd_set_paused();

    task_p2p_no_wait(cxfs_modi, TASK_DEFAULT_LIVE, TASK_PRIO_PREEMPT, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP,
                    &recv_mod_node,
                    NULL_PTR, FI_cxfs_reg_ngx, CMPI_ERROR_MODI);

    task_brd_set_not_paused();

    dbg_log(SEC_0137_DEMO, 0)(LOGSTDOUT, "[DEBUG] __test_cxfs_runner: cxfs_modi = %ld\n", cxfs_modi);

    return (EC_TRUE);
}



void __test_cxfs_launch(DEMO_HSXFS_CFG *hsxfs_cfg)
{
    cthread_new(CTHREAD_DETACHABLE | CTHREAD_SYSTEM_LEVEL,
                 (const char *)"__test_cxfs_runner",
                 (UINT32)__test_cxfs_runner,
                 (UINT32)0,/*core # (ignore)*/
                 (UINT32)1,/*para num*/
                 hsxfs_cfg
                 );
    return;
}

EC_BOOL __test_cxfs_write_supplier(DEMO_HSXFS_ARG *demo_hsxfs_arg)
{
    UINT32 cxfs_tcid;
    UINT32 cxfs_rank;
    UINT32 cxfs_modi;
    const char  *home_dir;

    cxfs_tcid = demo_hsxfs_arg->tcid;
    cxfs_rank = demo_hsxfs_arg->rank;
    cxfs_modi = demo_hsxfs_arg->modi;
    home_dir  = demo_hsxfs_arg->home_dir;

    test_case_86_cxfs_writer(cxfs_tcid, cxfs_rank, cxfs_modi, g_cxfs_cbytes_used_num, home_dir);

    return (EC_TRUE);
}


EC_BOOL __test_cxfs_read_consumer(DEMO_HSXFS_ARG *demo_hsxfs_arg)
{
    UINT32 cxfs_tcid;
    UINT32 cxfs_rank;
    UINT32 cxfs_modi;
    const char  *home_dir;

    cxfs_tcid = demo_hsxfs_arg->tcid;
    cxfs_rank = demo_hsxfs_arg->rank;
    cxfs_modi = demo_hsxfs_arg->modi;
    home_dir  = demo_hsxfs_arg->home_dir;

    test_case_87_cxfs_reader(cxfs_tcid, cxfs_rank, cxfs_modi, g_cxfs_cbytes_used_num, home_dir);

    return (EC_TRUE);
}

EC_BOOL __test_cxfs_delete_consumer(DEMO_HSXFS_ARG *demo_hsxfs_arg)
{
    UINT32 cxfs_tcid;
    UINT32 cxfs_rank;
    UINT32 cxfs_modi;
    const char  *home_dir;

    cxfs_tcid = demo_hsxfs_arg->tcid;
    cxfs_rank = demo_hsxfs_arg->rank;
    cxfs_modi = demo_hsxfs_arg->modi;
    home_dir  = demo_hsxfs_arg->home_dir;

    test_case_89_cxfs_delete(cxfs_tcid, cxfs_rank, cxfs_modi, home_dir);

    return (EC_TRUE);
}


EC_BOOL __test_cxfs_check_content_consumer(DEMO_HSXFS_ARG *demo_hsxfs_arg)
{
    UINT32 cxfs_tcid;
    UINT32 cxfs_rank;
    UINT32 cxfs_modi;
    const char  *home_dir;

    cxfs_tcid = demo_hsxfs_arg->tcid;
    cxfs_rank = demo_hsxfs_arg->rank;
    cxfs_modi = demo_hsxfs_arg->modi;
    home_dir  = demo_hsxfs_arg->home_dir;

    test_case_88_cxfs_file_content_checker(cxfs_tcid, cxfs_rank, cxfs_modi, g_cxfs_cbytes_used_num, home_dir);

    return (EC_TRUE);
}


EC_BOOL __test_cxfs_check_content_md5sum(DEMO_HSXFS_ARG *demo_hsxfs_arg)
{
    UINT32 cxfs_tcid;
    UINT32 cxfs_rank;
    UINT32 cxfs_modi;
    const char  *home_dir;

    cxfs_tcid = demo_hsxfs_arg->tcid;
    cxfs_rank = demo_hsxfs_arg->rank;
    cxfs_modi = demo_hsxfs_arg->modi;
    home_dir  = demo_hsxfs_arg->home_dir;

    test_case_90_cxfs_md5sum_checker(cxfs_tcid, cxfs_rank, cxfs_modi, g_cxfs_cbytes_used_num, home_dir);

    return (EC_TRUE);
}

EC_BOOL __test_case_9x_fetch_path_cstr(const CVECTOR *url_cstr_vec, CVECTOR *path_cstr_vec)
{
    UINT32 idx;
    UINT32 num;

    num = cvector_size(url_cstr_vec);
    for(idx = 0; idx < num; idx ++)
    {
        CSTRING *url_cstr;
        CSTRING *path_cstr;

        url_cstr = (CSTRING *)cvector_get(url_cstr_vec, idx);
        if(NULL_PTR == url_cstr)
        {
            continue;
        }

        dbg_log(SEC_0137_DEMO, 9)(LOGSTDNULL, "[DEBUG] url '%s'\n",
                           (char *)cstring_get_str(url_cstr));
        path_cstr = cstring_new(cstring_get_str(url_cstr) + strlen("http://") - 1, LOC_DEMO_0003);
        ASSERT(NULL_PTR != path_cstr);
        cvector_push(path_cstr_vec, path_cstr);

        dbg_log(SEC_0137_DEMO, 9)(LOGSTDNULL, "[DEBUG] url '%s' => path '%s'\n",
                            (char *)cstring_get_str(url_cstr),
                            (char *)cstring_get_str(path_cstr));
    }

    return (EC_TRUE);
}

EC_BOOL __test_case_9x_move_cstr_to_cbytes(const CVECTOR *body_cstr_vec, CVECTOR *body_cbytes_vec)
{
    UINT32 idx;
    UINT32 num;

    num = cvector_size(body_cstr_vec);
    for(idx = 0; idx < num; idx ++)
    {
        CSTRING *body_cstr;
        CBYTES  *body_cbytes;

        body_cstr = (CSTRING *)cvector_get(body_cstr_vec, idx);
        if(NULL_PTR == body_cstr)
        {
            continue;
        }

        body_cbytes = cbytes_new(0);
        ASSERT(NULL_PTR != body_cbytes);

        cbytes_mount(body_cbytes, cstring_get_len(body_cstr), cstring_get_str(body_cstr), BIT_FALSE);
        cstring_init(body_cstr, NULL_PTR);

        cvector_push(body_cbytes_vec, body_cbytes);
    }

    return (EC_TRUE);
}

/*parse args for cxfs*/
EC_BOOL __test_cxfs_parse_args(int argc, char **argv)
{
    int idx;

    for(idx = 0; idx < argc; idx ++)
    {
        if(0 == strcasecmp(argv[idx], "-node_type") && idx + 1 < argc)
        {
            g_node_type = cstring_new((UINT8 *)argv[idx + 1], LOC_NONE_BASE);
            ASSERT(NULL_PTR != g_node_type);
            continue;
        }

        if(0 == strcasecmp(argv[idx], "-xfs_sata_path") && idx + 1 < argc)
        {
            g_hsxfs_cfg.xfs_sata_path = cstring_new((UINT8 *)argv[idx + 1], LOC_NONE_BASE);
            ASSERT(NULL_PTR != g_hsxfs_cfg.xfs_sata_path);
            continue;
        }

        if(0 == strcasecmp(argv[idx], "-xfs_ssd_path") && idx + 1 < argc)
        {
            g_hsxfs_cfg.xfs_ssd_path = cstring_new((UINT8 *)argv[idx + 1], LOC_NONE_BASE);
            ASSERT(NULL_PTR != g_hsxfs_cfg.xfs_ssd_path);
            continue;
        }

        if(0 == strcasecmp(argv[idx], "-retrieve") /*&& idx + 1 < argc*/)
        {
            g_hsxfs_cfg.xfs_retrive_flag = BIT_TRUE;
            continue;
        }

        if(0 == strcasecmp(argv[idx], "-xfs_tcid") && idx + 1 < argc)
        {
            g_demo_hsxfs_arg.tcid = c_ipv4_to_word(argv[idx + 1]);/*xfs tcid*/
            continue;
        }

        if(0 == strcasecmp(argv[idx], "-xfs_rank") && idx + 1 < argc)
        {
            g_demo_hsxfs_arg.rank = atol(argv[idx + 1]);/*xfs rank*/
            continue;
        }

        if(0 == strcasecmp(argv[idx], "-xfs_modi") && idx + 1 < argc)
        {
            g_demo_hsxfs_arg.modi = atol(argv[idx + 1]);/*xfs rank*/
            continue;
        }

        if(0 == strcasecmp(argv[idx], "-xfs_home_dir") && idx + 1 < argc)
        {
            g_demo_hsxfs_arg.home_dir = c_str_dup(argv[idx + 1]);/*xfs home dir*/
            continue;
        }
    }

     return (EC_TRUE);
}


int main_cxfs_ok(int argc, char **argv)
{
    //UINT32 cxfs_rank;
    UINT32 tester_rank;

    DEMO_HSXFS_ARG hsxfs_arg_tbl[] =  {
        /*[0] XFS 10.10.10.1*/{c_ipv4_to_word((const char *)"10.10.10.1"), CXFS_TEST_RANK, CXFS_TEST_MODI, (const char *)"/h1"},
        /*[1] XFS 10.10.20.1*/{c_ipv4_to_word((const char *)"10.10.20.1"), CXFS_TEST_RANK, CXFS_TEST_MODI, (const char *)"/h2"},
        /*[2] XFS 10.10.30.1*/{c_ipv4_to_word((const char *)"10.10.30.1"), CXFS_TEST_RANK, CXFS_TEST_MODI, (const char *)"/h3"},
        /*[3] XFS 10.10.40.1*/{c_ipv4_to_word((const char *)"10.10.40.1"), CXFS_TEST_RANK, CXFS_TEST_MODI, (const char *)"/h4"},
        /*[4] XFS 10.10.50.1*/{c_ipv4_to_word((const char *)"10.10.50.1"), CXFS_TEST_RANK, CXFS_TEST_MODI, (const char *)"/h5"},
        /*[5] XFS 10.10.60.1*/{c_ipv4_to_word((const char *)"10.10.60.1"), CXFS_TEST_RANK, CXFS_TEST_MODI, (const char *)"/h6"},
        /*[6] XFS 10.10.70.1*/{c_ipv4_to_word((const char *)"10.10.70.1"), CXFS_TEST_RANK, CXFS_TEST_MODI, (const char *)"/h7"},
        /*[7] XFS 10.10.80.1*/{c_ipv4_to_word((const char *)"10.10.80.1"), CXFS_TEST_RANK, CXFS_TEST_MODI, (const char *)"/h8"},
    };
    DEMO_HSXFS_ARG *demo_hsxfs_arg = NULL_PTR;

    task_brd_default_init(argc, argv);
    //c_sleep(3, LOC_DEMO_0004);
    //dbg_log(SEC_0137_DEMO, 9)(LOGSTDOUT, "[DEBUG] main_cxfs: sleep to wait tcp enter established ... shit!\n");
    if(EC_FALSE == task_brd_default_check_validity())
    {
        dbg_log(SEC_0137_DEMO, 0)(LOGSTDOUT, "error:main_cxfs: validity checking failed\n");
        task_brd_default_abort();
        return (-1);
    }

    __test_cxfs_parse_args(argc, argv);

    //cxfs_rank = CXFS_TEST_RANK;
    tester_rank = 0;

    /*define specific runner for each (tcid, rank)*/
    task_brd_default_add_runner(c_ipv4_to_word("10.10.10.1"), CMPI_ANY_RANK  , (const char *)"__test_cxfs_runner", (TASK_RUNNER_FUNC)__test_cxfs_runner, (void *)&g_hsxfs_cfg);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.20.1"), CMPI_ANY_RANK  , (const char *)"__test_cxfs_runner", (TASK_RUNNER_FUNC)__test_cxfs_runner, (void *)&g_hsxfs_cfg);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.30.1"), CMPI_ANY_RANK  , (const char *)"__test_cxfs_runner", (TASK_RUNNER_FUNC)__test_cxfs_runner, (void *)&g_hsxfs_cfg);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.40.1"), CMPI_ANY_RANK  , (const char *)"__test_cxfs_runner", (TASK_RUNNER_FUNC)__test_cxfs_runner, (void *)&g_hsxfs_cfg);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.50.1"), CMPI_ANY_RANK  , (const char *)"__test_cxfs_runner", (TASK_RUNNER_FUNC)__test_cxfs_runner, (void *)&g_hsxfs_cfg);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.60.1"), CMPI_ANY_RANK  , (const char *)"__test_cxfs_runner", (TASK_RUNNER_FUNC)__test_cxfs_runner, (void *)&g_hsxfs_cfg);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.70.1"), CMPI_ANY_RANK  , (const char *)"__test_cxfs_runner", (TASK_RUNNER_FUNC)__test_cxfs_runner, (void *)&g_hsxfs_cfg);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.80.1"), CMPI_ANY_RANK  , (const char *)"__test_cxfs_runner", (TASK_RUNNER_FUNC)__test_cxfs_runner, (void *)&g_hsxfs_cfg);

    /*XFS 10.10.10.1*/
    demo_hsxfs_arg = &hsxfs_arg_tbl[ 0 ];
    task_brd_default_add_runner(c_ipv4_to_word("10.10.10.2"), tester_rank, (const char *)"__test_cxfs_write_supplier", (TASK_RUNNER_FUNC)__test_cxfs_write_supplier, (void *)demo_hsxfs_arg);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.10.3"), tester_rank, (const char *)"__test_cxfs_read_consumer", (TASK_RUNNER_FUNC)__test_cxfs_read_consumer, (void *)demo_hsxfs_arg);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.10.4"), tester_rank, (const char *)"__test_cxfs_delete_consumer", (TASK_RUNNER_FUNC)__test_cxfs_delete_consumer, (void *)demo_hsxfs_arg);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.10.5"), tester_rank, (const char *)"__test_cxfs_check_content_md5sum", (TASK_RUNNER_FUNC)__test_cxfs_check_content_md5sum, (void *)demo_hsxfs_arg);

    task_brd_default_add_runner(c_ipv4_to_word("10.10.10.12"), tester_rank, (const char *)"__test_cxfs_write_supplier", (TASK_RUNNER_FUNC)__test_cxfs_write_supplier, (void *)demo_hsxfs_arg);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.10.13"), tester_rank, (const char *)"__test_cxfs_read_consumer", (TASK_RUNNER_FUNC)__test_cxfs_read_consumer, (void *)demo_hsxfs_arg);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.10.15"), tester_rank, (const char *)"__test_cxfs_delete_consumer", (TASK_RUNNER_FUNC)__test_cxfs_delete_consumer, (void *)demo_hsxfs_arg);

    task_brd_default_add_runner(c_ipv4_to_word("10.10.10.101"), tester_rank, (const char *)"__test_cxfs_check_content_consumer", (TASK_RUNNER_FUNC)__test_cxfs_check_content_consumer, (void *)demo_hsxfs_arg);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.10.102"), tester_rank, (const char *)"__test_cxfs_check_content_consumer", (TASK_RUNNER_FUNC)__test_cxfs_check_content_consumer, (void *)demo_hsxfs_arg);

    /*XFS 10.10.20.1*/
    demo_hsxfs_arg = &hsxfs_arg_tbl[ 1 ];
    task_brd_default_add_runner(c_ipv4_to_word("10.10.20.2"), tester_rank, (const char *)"__test_cxfs_write_supplier", (TASK_RUNNER_FUNC)__test_cxfs_write_supplier, (void *)demo_hsxfs_arg);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.20.3"), tester_rank, (const char *)"__test_cxfs_read_consumer", (TASK_RUNNER_FUNC)__test_cxfs_read_consumer, (void *)demo_hsxfs_arg);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.20.4"), tester_rank, (const char *)"__test_cxfs_delete_consumer", (TASK_RUNNER_FUNC)__test_cxfs_delete_consumer, (void *)demo_hsxfs_arg);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.20.5"), tester_rank, (const char *)"__test_cxfs_check_content_md5sum", (TASK_RUNNER_FUNC)__test_cxfs_check_content_md5sum, (void *)demo_hsxfs_arg);

    task_brd_default_add_runner(c_ipv4_to_word("10.10.20.12"), tester_rank, (const char *)"__test_cxfs_write_supplier", (TASK_RUNNER_FUNC)__test_cxfs_write_supplier, (void *)demo_hsxfs_arg);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.20.13"), tester_rank, (const char *)"__test_cxfs_read_consumer", (TASK_RUNNER_FUNC)__test_cxfs_read_consumer, (void *)demo_hsxfs_arg);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.20.15"), tester_rank, (const char *)"__test_cxfs_delete_consumer", (TASK_RUNNER_FUNC)__test_cxfs_delete_consumer, (void *)demo_hsxfs_arg);

    task_brd_default_add_runner(c_ipv4_to_word("10.10.20.101"), tester_rank, (const char *)"__test_cxfs_check_content_consumer", (TASK_RUNNER_FUNC)__test_cxfs_check_content_consumer, (void *)demo_hsxfs_arg);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.20.102"), tester_rank, (const char *)"__test_cxfs_check_content_consumer", (TASK_RUNNER_FUNC)__test_cxfs_check_content_consumer, (void *)demo_hsxfs_arg);

    /*XFS 10.10.30.1*/
    demo_hsxfs_arg = &hsxfs_arg_tbl[ 2 ];
    task_brd_default_add_runner(c_ipv4_to_word("10.10.30.2"), tester_rank, (const char *)"__test_cxfs_write_supplier", (TASK_RUNNER_FUNC)__test_cxfs_write_supplier, (void *)demo_hsxfs_arg);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.30.3"), tester_rank, (const char *)"__test_cxfs_read_consumer", (TASK_RUNNER_FUNC)__test_cxfs_read_consumer, (void *)demo_hsxfs_arg);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.30.4"), tester_rank, (const char *)"__test_cxfs_delete_consumer", (TASK_RUNNER_FUNC)__test_cxfs_delete_consumer, (void *)demo_hsxfs_arg);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.30.5"), tester_rank, (const char *)"__test_cxfs_check_content_md5sum", (TASK_RUNNER_FUNC)__test_cxfs_check_content_md5sum, (void *)demo_hsxfs_arg);

    task_brd_default_add_runner(c_ipv4_to_word("10.10.30.12"), tester_rank, (const char *)"__test_cxfs_write_supplier", (TASK_RUNNER_FUNC)__test_cxfs_write_supplier, (void *)demo_hsxfs_arg);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.30.13"), tester_rank, (const char *)"__test_cxfs_read_consumer", (TASK_RUNNER_FUNC)__test_cxfs_read_consumer, (void *)demo_hsxfs_arg);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.30.15"), tester_rank, (const char *)"__test_cxfs_delete_consumer", (TASK_RUNNER_FUNC)__test_cxfs_delete_consumer, (void *)demo_hsxfs_arg);

    task_brd_default_add_runner(c_ipv4_to_word("10.10.30.101"), tester_rank, (const char *)"__test_cxfs_check_content_consumer", (TASK_RUNNER_FUNC)__test_cxfs_check_content_consumer, (void *)demo_hsxfs_arg);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.30.102"), tester_rank, (const char *)"__test_cxfs_check_content_consumer", (TASK_RUNNER_FUNC)__test_cxfs_check_content_consumer, (void *)demo_hsxfs_arg);

    /*XFS 10.10.40.1*/
    demo_hsxfs_arg = &hsxfs_arg_tbl[ 3 ];
    task_brd_default_add_runner(c_ipv4_to_word("10.10.40.2"), tester_rank, (const char *)"__test_cxfs_write_supplier", (TASK_RUNNER_FUNC)__test_cxfs_write_supplier, (void *)demo_hsxfs_arg);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.40.3"), tester_rank, (const char *)"__test_cxfs_read_consumer", (TASK_RUNNER_FUNC)__test_cxfs_read_consumer, (void *)demo_hsxfs_arg);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.40.4"), tester_rank, (const char *)"__test_cxfs_delete_consumer", (TASK_RUNNER_FUNC)__test_cxfs_delete_consumer, (void *)demo_hsxfs_arg);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.40.5"), tester_rank, (const char *)"__test_cxfs_check_content_md5sum", (TASK_RUNNER_FUNC)__test_cxfs_check_content_md5sum, (void *)demo_hsxfs_arg);

    task_brd_default_add_runner(c_ipv4_to_word("10.10.40.12"), tester_rank, (const char *)"__test_cxfs_write_supplier", (TASK_RUNNER_FUNC)__test_cxfs_write_supplier, (void *)demo_hsxfs_arg);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.40.13"), tester_rank, (const char *)"__test_cxfs_read_consumer", (TASK_RUNNER_FUNC)__test_cxfs_read_consumer, (void *)demo_hsxfs_arg);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.40.15"), tester_rank, (const char *)"__test_cxfs_delete_consumer", (TASK_RUNNER_FUNC)__test_cxfs_delete_consumer, (void *)demo_hsxfs_arg);

    task_brd_default_add_runner(c_ipv4_to_word("10.10.40.101"), tester_rank, (const char *)"__test_cxfs_check_content_consumer", (TASK_RUNNER_FUNC)__test_cxfs_check_content_consumer, (void *)demo_hsxfs_arg);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.40.102"), tester_rank, (const char *)"__test_cxfs_check_content_consumer", (TASK_RUNNER_FUNC)__test_cxfs_check_content_consumer, (void *)demo_hsxfs_arg);

    /*XFS 10.10.50.1*/
    demo_hsxfs_arg = &hsxfs_arg_tbl[ 4 ];
    task_brd_default_add_runner(c_ipv4_to_word("10.10.50.2"), tester_rank, (const char *)"__test_cxfs_write_supplier", (TASK_RUNNER_FUNC)__test_cxfs_write_supplier, (void *)demo_hsxfs_arg);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.50.3"), tester_rank, (const char *)"__test_cxfs_read_consumer", (TASK_RUNNER_FUNC)__test_cxfs_read_consumer, (void *)demo_hsxfs_arg);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.50.4"), tester_rank, (const char *)"__test_cxfs_delete_consumer", (TASK_RUNNER_FUNC)__test_cxfs_delete_consumer, (void *)demo_hsxfs_arg);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.50.5"), tester_rank, (const char *)"__test_cxfs_check_content_md5sum", (TASK_RUNNER_FUNC)__test_cxfs_check_content_md5sum, (void *)demo_hsxfs_arg);

    task_brd_default_add_runner(c_ipv4_to_word("10.10.50.12"), tester_rank, (const char *)"__test_cxfs_write_supplier", (TASK_RUNNER_FUNC)__test_cxfs_write_supplier, (void *)demo_hsxfs_arg);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.50.13"), tester_rank, (const char *)"__test_cxfs_read_consumer", (TASK_RUNNER_FUNC)__test_cxfs_read_consumer, (void *)demo_hsxfs_arg);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.50.15"), tester_rank, (const char *)"__test_cxfs_delete_consumer", (TASK_RUNNER_FUNC)__test_cxfs_delete_consumer, (void *)demo_hsxfs_arg);

    task_brd_default_add_runner(c_ipv4_to_word("10.10.50.101"), tester_rank, (const char *)"__test_cxfs_check_content_consumer", (TASK_RUNNER_FUNC)__test_cxfs_check_content_consumer, (void *)demo_hsxfs_arg);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.50.102"), tester_rank, (const char *)"__test_cxfs_check_content_consumer", (TASK_RUNNER_FUNC)__test_cxfs_check_content_consumer, (void *)demo_hsxfs_arg);

    /*XFS 10.10.60.1*/
    demo_hsxfs_arg = &hsxfs_arg_tbl[ 5 ];
    task_brd_default_add_runner(c_ipv4_to_word("10.10.60.2"), tester_rank, (const char *)"__test_cxfs_write_supplier", (TASK_RUNNER_FUNC)__test_cxfs_write_supplier, (void *)demo_hsxfs_arg);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.60.3"), tester_rank, (const char *)"__test_cxfs_read_consumer", (TASK_RUNNER_FUNC)__test_cxfs_read_consumer, (void *)demo_hsxfs_arg);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.60.4"), tester_rank, (const char *)"__test_cxfs_delete_consumer", (TASK_RUNNER_FUNC)__test_cxfs_delete_consumer, (void *)demo_hsxfs_arg);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.60.5"), tester_rank, (const char *)"__test_cxfs_check_content_md5sum", (TASK_RUNNER_FUNC)__test_cxfs_check_content_md5sum, (void *)demo_hsxfs_arg);

    task_brd_default_add_runner(c_ipv4_to_word("10.10.60.12"), tester_rank, (const char *)"__test_cxfs_write_supplier", (TASK_RUNNER_FUNC)__test_cxfs_write_supplier, (void *)demo_hsxfs_arg);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.60.13"), tester_rank, (const char *)"__test_cxfs_read_consumer", (TASK_RUNNER_FUNC)__test_cxfs_read_consumer, (void *)demo_hsxfs_arg);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.60.15"), tester_rank, (const char *)"__test_cxfs_delete_consumer", (TASK_RUNNER_FUNC)__test_cxfs_delete_consumer, (void *)demo_hsxfs_arg);

    task_brd_default_add_runner(c_ipv4_to_word("10.10.60.101"), tester_rank, (const char *)"__test_cxfs_check_content_consumer", (TASK_RUNNER_FUNC)__test_cxfs_check_content_consumer, (void *)demo_hsxfs_arg);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.60.102"), tester_rank, (const char *)"__test_cxfs_check_content_consumer", (TASK_RUNNER_FUNC)__test_cxfs_check_content_consumer, (void *)demo_hsxfs_arg);

    /*XFS 10.10.70.1*/
    demo_hsxfs_arg = &hsxfs_arg_tbl[ 6 ];
    task_brd_default_add_runner(c_ipv4_to_word("10.10.70.2"), tester_rank, (const char *)"__test_cxfs_write_supplier", (TASK_RUNNER_FUNC)__test_cxfs_write_supplier, (void *)demo_hsxfs_arg);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.70.3"), tester_rank, (const char *)"__test_cxfs_read_consumer", (TASK_RUNNER_FUNC)__test_cxfs_read_consumer, (void *)demo_hsxfs_arg);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.70.4"), tester_rank, (const char *)"__test_cxfs_delete_consumer", (TASK_RUNNER_FUNC)__test_cxfs_delete_consumer, (void *)demo_hsxfs_arg);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.70.5"), tester_rank, (const char *)"__test_cxfs_check_content_md5sum", (TASK_RUNNER_FUNC)__test_cxfs_check_content_md5sum, (void *)demo_hsxfs_arg);

    task_brd_default_add_runner(c_ipv4_to_word("10.10.70.12"), tester_rank, (const char *)"__test_cxfs_write_supplier", (TASK_RUNNER_FUNC)__test_cxfs_write_supplier, (void *)demo_hsxfs_arg);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.70.13"), tester_rank, (const char *)"__test_cxfs_read_consumer", (TASK_RUNNER_FUNC)__test_cxfs_read_consumer, (void *)demo_hsxfs_arg);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.70.15"), tester_rank, (const char *)"__test_cxfs_delete_consumer", (TASK_RUNNER_FUNC)__test_cxfs_delete_consumer, (void *)demo_hsxfs_arg);

    task_brd_default_add_runner(c_ipv4_to_word("10.10.70.101"), tester_rank, (const char *)"__test_cxfs_check_content_consumer", (TASK_RUNNER_FUNC)__test_cxfs_check_content_consumer, (void *)demo_hsxfs_arg);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.70.102"), tester_rank, (const char *)"__test_cxfs_check_content_consumer", (TASK_RUNNER_FUNC)__test_cxfs_check_content_consumer, (void *)demo_hsxfs_arg);

    /*XFS 10.10.80.1*/
    demo_hsxfs_arg = &hsxfs_arg_tbl[ 7 ];
    task_brd_default_add_runner(c_ipv4_to_word("10.10.80.2"), tester_rank, (const char *)"__test_cxfs_write_supplier", (TASK_RUNNER_FUNC)__test_cxfs_write_supplier, (void *)demo_hsxfs_arg);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.80.3"), tester_rank, (const char *)"__test_cxfs_read_consumer", (TASK_RUNNER_FUNC)__test_cxfs_read_consumer, (void *)demo_hsxfs_arg);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.80.4"), tester_rank, (const char *)"__test_cxfs_delete_consumer", (TASK_RUNNER_FUNC)__test_cxfs_delete_consumer, (void *)demo_hsxfs_arg);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.80.5"), tester_rank, (const char *)"__test_cxfs_check_content_md5sum", (TASK_RUNNER_FUNC)__test_cxfs_check_content_md5sum, (void *)demo_hsxfs_arg);

    task_brd_default_add_runner(c_ipv4_to_word("10.10.80.12"), tester_rank, (const char *)"__test_cxfs_write_supplier", (TASK_RUNNER_FUNC)__test_cxfs_write_supplier, (void *)demo_hsxfs_arg);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.80.13"), tester_rank, (const char *)"__test_cxfs_read_consumer", (TASK_RUNNER_FUNC)__test_cxfs_read_consumer, (void *)demo_hsxfs_arg);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.80.15"), tester_rank, (const char *)"__test_cxfs_delete_consumer", (TASK_RUNNER_FUNC)__test_cxfs_delete_consumer, (void *)demo_hsxfs_arg);

    task_brd_default_add_runner(c_ipv4_to_word("10.10.80.101"), tester_rank, (const char *)"__test_cxfs_check_content_consumer", (TASK_RUNNER_FUNC)__test_cxfs_check_content_consumer, (void *)demo_hsxfs_arg);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.80.102"), tester_rank, (const char *)"__test_cxfs_check_content_consumer", (TASK_RUNNER_FUNC)__test_cxfs_check_content_consumer, (void *)demo_hsxfs_arg);

#if 0
    task_brd_default_add_runner(c_ipv4_to_word("10.10.10.31"), tester_rank, __test_xfs_forward);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.10.32"), tester_rank, __test_xfs_forward);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.10.33"), tester_rank, __test_xfs_forward);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.10.34"), tester_rank, __test_xfs_forward);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.10.35"), tester_rank, __test_xfs_forward);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.10.36"), tester_rank, __test_xfs_forward);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.10.37"), tester_rank, __test_xfs_forward);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.10.38"), tester_rank, __test_xfs_forward);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.10.39"), tester_rank, __test_xfs_forward);

    task_brd_default_add_runner(c_ipv4_to_word("10.10.10.41"), tester_rank, __test_xfs_forward);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.10.42"), tester_rank, __test_xfs_forward);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.10.43"), tester_rank, __test_xfs_forward);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.10.44"), tester_rank, __test_xfs_forward);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.10.45"), tester_rank, __test_xfs_forward);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.10.46"), tester_rank, __test_xfs_forward);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.10.47"), tester_rank, __test_xfs_forward);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.10.48"), tester_rank, __test_xfs_forward);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.10.49"), tester_rank, __test_xfs_forward);

    task_brd_default_add_runner(c_ipv4_to_word("10.10.10.51"), tester_rank, __test_xfs_forward);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.10.52"), tester_rank, __test_xfs_forward);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.10.53"), tester_rank, __test_xfs_forward);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.10.54"), tester_rank, __test_xfs_forward);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.10.55"), tester_rank, __test_xfs_forward);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.10.56"), tester_rank, __test_xfs_forward);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.10.57"), tester_rank, __test_xfs_forward);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.10.58"), tester_rank, __test_xfs_forward);
    task_brd_default_add_runner(c_ipv4_to_word("10.10.10.59"), tester_rank, __test_xfs_forward);
#endif

    //task_brd_range_add_runner(c_ipv4_to_word("10.10.10.31"), c_ipv4_to_word("10.10.10.100"), tester_rank, __test_xfs_forward);
    //task_brd_range_add_runner(c_ipv4_to_word("10.10.10.31"), c_ipv4_to_word("10.10.10.100"), tester_rank, __test_xfs_cmp_finger);
    //task_brd_range_add_runner(c_ipv4_to_word("10.10.10.31"), c_ipv4_to_word("10.10.10.100"), tester_rank, __test_xfs_cleanup);

    /*start the defined runner on current (tcid, rank)*/
    task_brd_default_start_runner();

    return (0);
}

int main_cxfs(int argc, char **argv)
{
    task_brd_default_init(argc, argv);
    //c_sleep(3, LOC_DEMO_0005);
    //dbg_log(SEC_0137_DEMO, 9)(LOGSTDOUT, "[DEBUG] main_cxfs: sleep to wait tcp enter established ... shit!\n");
    if(EC_FALSE == task_brd_default_check_validity())
    {
        dbg_log(SEC_0137_DEMO, 0)(LOGSTDOUT, "error:main_cxfs: validity checking failed\n");
        task_brd_default_abort();
        return (-1);
    }

    dbg_log(SEC_0137_DEMO, 9)(LOGSTDOUT, "[DEBUG] main_cxfs: __test_cxfs_parse_args beg\n");
    __test_cxfs_parse_args(argc, argv);
    dbg_log(SEC_0137_DEMO, 9)(LOGSTDOUT, "[DEBUG] main_cxfs: __test_cxfs_parse_args end\n");

    if(NULL_PTR != g_node_type)
    {
        if(EC_TRUE == cstring_is_str(g_node_type, (const UINT8 *)"xfs"))
        {
            ASSERT(NULL_PTR != g_hsxfs_cfg.xfs_sata_path);
            //ASSERT(NULL_PTR != g_hsxfs_cfg.xfs_ssd_path);
            task_brd_default_add_runner(CMPI_ANY_TCID, CMPI_ANY_RANK, (const char *)"__test_cxfs_runner",
                                        (TASK_RUNNER_FUNC)/*__test_cxfs_runner*/__test_cxfs_launch, (void *)&g_hsxfs_cfg);
        }
        /*e.g., ./xfs -tcid 10.10.8.18 -xfs_tcid 10.10.67.18 -xfs_rank 0 -xfs_modi 0 -xfs_home_dir /h1 -node_type writer -logp ./log*/
        else if(EC_TRUE == cstring_is_str(g_node_type, (const UINT8 *)"writer"))
        {
            ASSERT(CMPI_ANY_TCID != g_demo_hsxfs_arg.tcid);
            ASSERT(NULL_PTR != g_demo_hsxfs_arg.home_dir);
            task_brd_default_fork_runner(CMPI_ANY_TCID, CMPI_ANY_RANK, (const char *)"__test_cxfs_write_supplier",
                                        (TASK_RUNNER_FUNC)__test_cxfs_write_supplier, (void *)&g_demo_hsxfs_arg);
        }
        /*e.g., ./xfs -tcid 10.10.8.19 -xfs_tcid 10.10.67.18 -xfs_rank 0 -xfs_modi 0 -xfs_home_dir /h1 -node_type reader -logp ./log*/
        else if(EC_TRUE == cstring_is_str(g_node_type, (const UINT8 *)"reader"))
        {
            ASSERT(CMPI_ANY_TCID != g_demo_hsxfs_arg.tcid);
            ASSERT(NULL_PTR != g_demo_hsxfs_arg.home_dir);
            task_brd_default_fork_runner(CMPI_ANY_TCID, CMPI_ANY_RANK, (const char *)"__test_cxfs_read_consumer",
                                        (TASK_RUNNER_FUNC)__test_cxfs_read_consumer, (void *)&g_demo_hsxfs_arg);
        }
        else if(EC_TRUE == cstring_is_str(g_node_type, (const UINT8 *)"delete"))
        {
            ASSERT(CMPI_ANY_TCID != g_demo_hsxfs_arg.tcid);
            ASSERT(NULL_PTR != g_demo_hsxfs_arg.home_dir);
            task_brd_default_fork_runner(CMPI_ANY_TCID, CMPI_ANY_RANK, (const char *)"__test_cxfs_delete_consumer",
                                        (TASK_RUNNER_FUNC)__test_cxfs_delete_consumer, (void *)&g_demo_hsxfs_arg);
        }
        else if(EC_TRUE == cstring_is_str(g_node_type, (const UINT8 *)"check_md5"))
        {
            ASSERT(CMPI_ANY_TCID != g_demo_hsxfs_arg.tcid);
            ASSERT(NULL_PTR != g_demo_hsxfs_arg.home_dir);
            task_brd_default_fork_runner(CMPI_ANY_TCID, CMPI_ANY_RANK, (const char *)"__test_cxfs_check_content_md5sum",
                                        (TASK_RUNNER_FUNC)__test_cxfs_check_content_md5sum, (void *)&g_demo_hsxfs_arg);
        }
        else if(EC_TRUE == cstring_is_str(g_node_type, (const UINT8 *)"check_content"))
        {
            ASSERT(CMPI_ANY_TCID != g_demo_hsxfs_arg.tcid);
            ASSERT(NULL_PTR != g_demo_hsxfs_arg.home_dir);
            task_brd_default_fork_runner(CMPI_ANY_TCID, CMPI_ANY_RANK, (const char *)"__test_cxfs_check_content_consumer",
                                        (TASK_RUNNER_FUNC)__test_cxfs_check_content_consumer, (void *)&g_demo_hsxfs_arg);
        }
    }

    /*start the defined runner on current (tcid, rank)*/
    task_brd_default_start_runner();

    //task_brd_default_end();
    return (0);
}

int main(int argc, char **argv)
{
    return main_cxfs(argc, argv);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

