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
#include "cbc.h"
#include "cstring.h"
#include "cvector.h"

#include "super.h"
#include "tbd.h"
#include "crun.h"

#include "cmpic.inc"
#include "findex.inc"

#include "chashalgo.h"
#include "cbytes.h"

#include "cfile.h"
#include "ctrans.h"
#include "demo_trans.h"


static EC_BOOL   g_trans_srv_flag           = EC_FALSE;
static UINT32    g_trans_seg_size           = CTRANS_SEG_SIZE_DEFAULT;
static UINT32    g_trans_seg_concurrence    = CTRANS_SEG_CONCURRENCE_DEFAULT;
static CSTRING  *g_trans_log_level          = NULL_PTR;
static UINT32    g_remote_tcid              = CMPI_ERROR_TCID;
static CSTRING  *g_src_file_name            = NULL_PTR;
static CSTRING  *g_des_file_name            = NULL_PTR;
static uint32_t  g_verbose                  = BIT_FALSE;
static uint32_t  g_debug_log                = BIT_FALSE;

#define dlog      (BIT_FALSE == g_debug_log) ? (void )0 : printf

EC_BOOL __test_ctrans_server_runner(void *arg)
{
    UINT32 cfile_modi;

    cfile_modi = cfile_start();
    ASSERT(CMPI_ERROR_MODI != cfile_modi);

    dbg_log(SEC_0137_DEMO, 9)(LOGSTDOUT, "[DEBUG] __test_ctrans_server_runner: "
                                         "cfile_modi = %ld\n",
                                         cfile_modi);

    return (EC_TRUE);
}

EC_BOOL __test_ctrans_client_runner(void *arg)
{
    UINT32 ctrans_modi;

    UINT32 waiting_msec_once;
    UINT32 waiting_msec_max;
    UINT32 waiting_msec_sum;

    uint64_t s_msec;
    uint64_t e_msec;

    waiting_msec_once = 10; /*msec*/
    waiting_msec_max  = 30 * 1000; /*30 seconds*/
    waiting_msec_sum  = 0;

    s_msec = c_get_cur_time_msec();

    for(waiting_msec_sum = 0;
        waiting_msec_sum < waiting_msec_max &&
        EC_FALSE == task_brd_check_tcid_connected(task_brd_default_get(), g_remote_tcid);
        waiting_msec_sum += waiting_msec_once)
    {
        dbg_log(SEC_0137_DEMO, 0)(LOGSTDOUT, "[DEBUG] __test_ctrans_client_runner: "
                                             "not connect tcid %s yet\n",
                                             c_word_to_ipv4(g_remote_tcid));

        coroutine_usleep(waiting_msec_once, LOC_NONE_BASE);
    }

    if(EC_FALSE == task_brd_check_tcid_connected(task_brd_default_get(), g_remote_tcid))
    {
        dbg_log(SEC_0137_DEMO, 0)(LOGSTDOUT, "error:__test_ctrans_client_runner: "
                                             "unable to connect tcid %s\n",
                                             c_word_to_ipv4(g_remote_tcid));
        task_brd_default_abort();
        return (EC_FALSE);
    }

    e_msec = c_get_cur_time_msec();

    if(s_msec < e_msec)
    {
        dbg_log(SEC_0137_DEMO, 0)(LOGSTDOUT, "[DEBUG] __test_ctrans_client_runner: "
                                             "connect tcid %s cost %ld ms\n",
                                             c_word_to_ipv4(g_remote_tcid),
                                             e_msec - s_msec);
    }

    ctrans_modi = ctrans_start(g_remote_tcid, g_trans_seg_size, g_trans_seg_concurrence);
    ASSERT(CMPI_ERROR_MODI != ctrans_modi);

    if(EC_FALSE == ctrans_file(ctrans_modi, g_src_file_name, g_des_file_name))
    {
        ctrans_end(ctrans_modi);

        dbg_log(SEC_0137_DEMO, 0)(LOGSTDOUT, "error:__test_ctrans_client_runner: "
                                             "transfer '%s' to '%s':'%s' failed\n",
                                             (char *)cstring_get_str(g_src_file_name),
                                             (char *)cstring_get_str(g_des_file_name),
                                             c_word_to_ipv4(g_remote_tcid));

        dbg_log(SEC_0137_DEMO, 0)(LOGCONSOLE, "error:__test_ctrans_client_runner: "
                                              "transfer '%s' to '%s':'%s' failed\n",
                                              (char *)cstring_get_str(g_src_file_name),
                                              (char *)cstring_get_str(g_des_file_name),
                                              c_word_to_ipv4(g_remote_tcid));

        task_brd_default_abort();
        return (EC_FALSE);
    }

    ctrans_end(ctrans_modi);

    dbg_log(SEC_0137_DEMO, 0)(LOGSTDOUT, "[DEBUG] __test_ctrans_client_runner: "
                                         "transfer '%s' to '%s':'%s' done\n",
                                         (char *)cstring_get_str(g_src_file_name),
                                         (char *)cstring_get_str(g_des_file_name),
                                         c_word_to_ipv4(g_remote_tcid));

    dbg_log(SEC_0137_DEMO, 0)(LOGCONSOLE, "[DEBUG] __test_ctrans_client_runner: "
                                          "transfer '%s' to '%s':'%s' done\n",
                                          (char *)cstring_get_str(g_src_file_name),
                                          (char *)cstring_get_str(g_des_file_name),
                                          c_word_to_ipv4(g_remote_tcid));

    task_brd_default_abort();
    return (EC_TRUE);
}

EC_BOOL __test_ctrans_exist_arg(int argc, char **argv, const char *arg)
{
    int idx;

    for(idx = 0; idx < argc; idx ++)
    {
        if(0 == strcasecmp(argv[idx], arg))
        {
            return (EC_TRUE);
        }
    }

    return (EC_FALSE);
}

/*parse args for ctrans*/
/*usage: <prog> <[-c srvip -p srvport -i <src file name> -o <des file name>] | [-s -p port] [-d]> */
EC_BOOL __test_ctrans_parse_args(int argc, char **argv)
{
    int idx;

    for(idx = 0; idx < argc; idx ++)
    {
        if(0 == strcasecmp(argv[idx], "-s")) /*server*/
        {
            g_trans_srv_flag = EC_TRUE;
            continue;
        }

        if(0 == strcasecmp(argv[idx], "-des") && idx + 1 < argc)
        {
            g_trans_srv_flag = EC_FALSE;

            g_remote_tcid = c_ipv4_to_word(argv[idx + 1]);
            continue;
        }

        if(0 == strcasecmp(argv[idx], "-in") && idx + 1 < argc)
        {
            g_src_file_name = cstring_new((UINT8 *)argv[idx + 1], LOC_NONE_BASE);
            continue;
        }

        if(0 == strcasecmp(argv[idx], "-out") && idx + 1 < argc)
        {
            g_des_file_name = cstring_new((UINT8 *)argv[idx + 1], LOC_NONE_BASE);
            continue;
        }

        if(0 == strcasecmp(argv[idx], "-seg") && idx + 1 < argc)
        {
            g_trans_seg_size = (UINT32)c_space_size_str_to_uint64_t(argv[idx + 1]);
            continue;
        }

        if(0 == strcasecmp(argv[ idx ], "-concurrence") && idx + 1 < argc)
        {
            g_trans_seg_concurrence = c_str_to_word(argv[ idx + 1 ]);
            continue;
        }

        if(0 == strcasecmp(argv[idx], "-loglevel") && idx + 1 < argc)
        {
            g_trans_log_level = cstring_new((UINT8 *)argv[idx + 1], LOC_NONE_BASE);
            continue;
        }
    }

    return (EC_TRUE);
}

EC_BOOL __test_ctrans_clone_arg(const char *arg_k, const char *arg_v, int argc_max_t, int *argc_t, char **argv_t)
{
    if(NULL_PTR == arg_k)
    {
        return (EC_FALSE);
    }

    if(NULL_PTR == arg_v)
    {
        if((*argc_t) >= argc_max_t)
        {
            return (EC_FALSE);
        }

        /*clone key*/
        argv_t[ (*argc_t) ] = strdup(arg_k);
        if(NULL_PTR == argv_t[ (*argc_t) ])
        {
            return (EC_FALSE);
        }

        (*argc_t) ++;
    }
    else
    {
        if((*argc_t) + 1 >= argc_max_t)
        {
            return (EC_FALSE);
        }

        /*clone key*/
        argv_t[ (*argc_t) ] = strdup(arg_k);
        if(NULL_PTR == argv_t[ (*argc_t) ])
        {
            return (EC_FALSE);
        }
        (*argc_t) ++;

        /*clone val*/
        argv_t[ (*argc_t) ] = strdup(arg_v);
        if(NULL_PTR == argv_t[ (*argc_t) ])
        {
            return (EC_FALSE);
        }
        (*argc_t) ++;
    }

    /*terminate with NULL*/
    if((*argc_t) + 1 >= argc_max_t)
    {
        return (EC_FALSE);
    }

    argv_t[ (*argc_t) ] = NULL_PTR;

    return (EC_TRUE);
}

/*
 *
 * src command format: -s -srv <ip>:<port> [-d] [-v] [-loglevel <log level>] [-sconfig <config xml>]
 * des command format: -s -tcid <tcid> -sconfig <config xml> [-d]
 *
 */
EC_BOOL __test_ctrans_gen_server_conf(int argc, char **argv, int argc_max_t, int *argc_t, char **argv_t)
{
    const char *sconfig_default = "/dev/shm/config_trans_server.xml";
    char       *fname;
    FILE       *fp;

    char       *srv_ip_arg;
    char       *srv_port_arg;
    uint32_t    idx;

    fname           = NULL_PTR;
    fp              = NULL_PTR;
    srv_ip_arg      = NULL_PTR;
    srv_port_arg    = NULL_PTR;

    for(idx = 0; idx < argc; idx ++)
    {
        if(0 == strcasecmp(argv[idx], "-s"))/*server*/
        {
            if(EC_FALSE == __test_ctrans_clone_arg((const char *)"-s", NULL_PTR,
                                        argc_max_t, argc_t, argv_t))
            {
                return (EC_FALSE);
            }
            continue;
        }

        if(0 == strcasecmp(argv[ idx ], "-srv") && idx + 1 < argc)
        {
            char       *seg_args[2];
            UINT32      seg_num;

            seg_num = c_str_split(argv[ idx + 1 ], ":",
                                 (char **)seg_args,
                                 sizeof(seg_args)/sizeof(seg_args[0]));
            if(2 != seg_num)
            {
                return (EC_FALSE);
            }

            srv_ip_arg   = seg_args[0];
            srv_port_arg = seg_args[1];

            if(EC_FALSE == __test_ctrans_clone_arg((const char *)"-tcid", srv_ip_arg,
                                        argc_max_t, argc_t, argv_t))
            {
                return (EC_FALSE);
            }

            continue;
        }

        if(0 == strcasecmp(argv[ idx ], "-sconfig") && idx + 1 < argc)
        {
            fname = argv[ idx + 1];
            continue;
        }

        if(0 == strcasecmp(argv[ idx ], "-d"))
        {
            if(EC_FALSE == __test_ctrans_clone_arg((const char *)"-d", NULL_PTR,
                                        argc_max_t, argc_t, argv_t))
            {
                return (EC_FALSE);
            }
            continue;
        }

        if(0 == strcasecmp(argv[ idx ], "-loglevel") && idx + 1 < argc)
        {
            if(EC_FALSE == __test_ctrans_clone_arg((const char *)"-loglevel", argv[ idx + 1 ],
                                            argc_max_t, argc_t, argv_t))
            {
                return (EC_FALSE);
            }
            continue;
        }

        if(0 == strcasecmp(argv[ idx ], "-verbose")
        || 0 == strcasecmp(argv[ idx ], "-v")
        || 0 == strcasecmp(argv[ idx ], "-debug"))
        {
            g_verbose = BIT_TRUE;
            continue;
        }
    }

    if(NULL_PTR == srv_ip_arg || NULL_PTR == srv_port_arg)
    {
        return (EC_FALSE);
    }

    /*sconfig*/
    if(NULL_PTR == fname)
    {
        fname = (char *)sconfig_default;
    }

    if(EC_FALSE == __test_ctrans_clone_arg((const char *)"-sconfig", fname,
                                    argc_max_t, argc_t, argv_t))
    {
        return (EC_FALSE);
    }

    /*make config*/

    fp = fopen(fname, "w");
    if(NULL_PTR == fp)
    {
        return (EC_FALSE);
    }

    fprintf(fp,
                "<sysConfig>\n"
                "  <taskConfig>\n"
                "    <tasks tcid=\"%s\"  maski=\"0\" maske=\"0\" srvipaddr=\"%s\" srvport=\"%s\"/>\n"
                "  </taskConfig>\n"
                "  <parasConfig>\n"
                "    <paraConfig tcid=\"%s\" rank=\"0\">\n"
                "      <logConfig logLevel=\"all:0\"/>\n"
                "    </paraConfig>\n"
                "  </parasConfig>\n"
                "</sysConfig>\n",

                srv_ip_arg,     /*tcid*/
                srv_ip_arg,     /*tcid*/
                srv_port_arg,   /*port*/
                srv_ip_arg      /*tcid*/
                );

    fclose(fp);

    return (EC_TRUE);
}

/*
 *
 * src command format: [-c] -src sfile -des dip:dport:dfile [-seg <segment size>] [-loglevel <log level>] [-sconfig <config xml>]
 * des command format: [-c] -tcid <tcid> -des <tcid> -sconfig <config xml> -in <src file name> -out <des file name> [-seg <size>]
 *
 */
EC_BOOL __test_ctrans_gen_client_conf(int argc, char **argv, int argc_max_t, int *argc_t, char **argv_t)
{
    const char *sconfig_default = "/dev/shm/config_trans_client.xml";
    char       *fname;
    FILE       *fp;

    char       *src_file_arg;
    char       *des_file_arg;

    char       *des_ip_arg;
    char       *des_port_arg;

    char        src_tcid_buf[16];
    char       *src_tcid_arg;
    uint32_t    src_tcid;       /*random src tcid*/

    uint32_t    idx;

    fname        = NULL_PTR;
    fp           = NULL_PTR;

    src_file_arg = NULL_PTR;
    des_file_arg = NULL_PTR;

    des_ip_arg   = NULL_PTR;
    des_port_arg = NULL_PTR;

    for(idx = 0; idx < argc; idx ++)
    {
        if(0 == strcasecmp(argv[idx], "-c"))/*client*/
        {
            if(EC_FALSE == __test_ctrans_clone_arg((const char *)"-c", NULL_PTR,
                                        argc_max_t, argc_t, argv_t))
            {
                return (EC_FALSE);
            }
            continue;
        }

        if(0 == strcasecmp(argv[ idx ], "-src") && idx + 1 < argc)
        {
            src_file_arg = argv[ idx +1 ];
            if(EC_FALSE == __test_ctrans_clone_arg((const char *)"-in", argv[ idx +1 ],
                                        argc_max_t, argc_t, argv_t))
            {
                return (EC_FALSE);
            }

            continue;
        }

        if(0 == strcasecmp(argv[ idx ], "-des") && idx + 1 < argc)
        {
            char       *seg_args[3];
            UINT32      seg_num;

            seg_num = c_str_split(argv[ idx + 1 ], ":@#",
                                 (char **)seg_args,
                                 sizeof(seg_args)/sizeof(seg_args[0]));
            if(3 != seg_num)
            {
                return (EC_FALSE);
            }

            des_ip_arg   = seg_args[0];
            des_port_arg = seg_args[1];
            des_file_arg = seg_args[2]; /*reset des_file_arg*/

            if(EC_FALSE == __test_ctrans_clone_arg((const char *)"-out", des_file_arg,
                                        argc_max_t, argc_t, argv_t))
            {
                return (EC_FALSE);
            }

            if(EC_FALSE == __test_ctrans_clone_arg((const char *)"-des", des_ip_arg,
                                        argc_max_t, argc_t, argv_t))
            {
                return (EC_FALSE);
            }

            continue;
        }

        if(0 == strcasecmp(argv[ idx ], "-seg") && idx + 1 < argc)
        {
            if(EC_FALSE == __test_ctrans_clone_arg((const char *)"-seg", argv[ idx + 1 ],
                                            argc_max_t, argc_t, argv_t))
            {
                return (EC_FALSE);
            }
            continue;
        }

        if(0 == strcasecmp(argv[ idx ], "-concurrence") && idx + 1 < argc)
        {
            if(EC_FALSE == __test_ctrans_clone_arg((const char *)"-concurrence", argv[ idx + 1 ],
                                            argc_max_t, argc_t, argv_t))
            {
                return (EC_FALSE);
            }
            continue;
        }

        if(0 == strcasecmp(argv[ idx ], "-sconfig") && idx + 1 < argc)
        {
            fname = argv[ idx + 1];
            continue;
        }

        if(0 == strcasecmp(argv[ idx ], "-loglevel") && idx + 1 < argc)
        {
            if(EC_FALSE == __test_ctrans_clone_arg((const char *)"-loglevel", argv[ idx + 1 ],
                                            argc_max_t, argc_t, argv_t))
            {
                return (EC_FALSE);
            }
            continue;
        }

        if(0 == strcasecmp(argv[ idx ], "-d"))
        {
            if(EC_FALSE == __test_ctrans_clone_arg((const char *)"-d", NULL_PTR,
                                        argc_max_t, argc_t, argv_t))
            {
                return (EC_FALSE);
            }
            continue;
        }

        if(0 == strcasecmp(argv[ idx ], "-verbose")
        || 0 == strcasecmp(argv[ idx ], "-v")
        || 0 == strcasecmp(argv[ idx ], "-debug"))
        {
            g_verbose = BIT_TRUE;
            continue;
        }
    }

    if(NULL_PTR == src_file_arg || NULL_PTR == des_file_arg)
    {
        return (EC_FALSE);
    }

    /*set src ip as random*/
    src_tcid_arg = (char *)src_tcid_buf;
    src_tcid     = (uint32_t)(c_get_cur_time_msec() & 0xFFFFFFFF);
    snprintf(src_tcid_arg, sizeof(src_tcid_buf),
                            "%u.%u.%u.%u",
                           ((src_tcid >> 24) & 0xFF),
                           ((src_tcid >> 16) & 0xFF),
                           ((src_tcid >>  8) & 0xFF),
                           ((src_tcid >>  0) & 0xFF));

    if(EC_FALSE == __test_ctrans_clone_arg((const char *)"-tcid", src_tcid_arg,
                                    argc_max_t, argc_t, argv_t))
    {
        return (EC_FALSE);
    }

    /*sconfig*/
    if(NULL_PTR == fname)
    {
        fname = (char *)sconfig_default;
    }

    if(EC_FALSE == __test_ctrans_clone_arg((const char *)"-sconfig", fname,
                                    argc_max_t, argc_t, argv_t))
    {
        return (EC_FALSE);
    }

    /*make config file*/
    fp = fopen(fname, "w");
    if(NULL_PTR == fp)
    {
        return (EC_FALSE);
    }

    fprintf(fp,
                "<sysConfig>\n"
                "  <taskConfig>\n"
                "    <tasks tcid=\"%s\"  maski=\"0\" maske=\"0\" srvipaddr=\"%s\" srvport=\"%s\" cluster=\"1\"/>\n"
                "    <tasks tcid=\"%s\"  maski=\"0\" maske=\"0\" cluster=\"1\"/>\n"
                "  </taskConfig>\n"
                "  <clusters>\n"
                "    <cluster id=\"1\" name=\"trans\" model=\"master_slave\">\n"
                "      <node role=\"master\"  tcid=\"%s\"   rank=\"0\"/>\n"
                "      <node role=\"slave\"  tcid=\"%s\"   rank=\"0\"/>\n"
                "    </cluster>\n"
                "  </clusters>\n"
                "  <parasConfig>\n"
                "    <paraConfig tcid=\"%s\" rank=\"0\">\n"
                "      <logConfig logLevel=\"all:0\"/>\n"
                "    </paraConfig>\n"
                "    <paraConfig tcid=\"%s\" rank=\"0\">\n"
                "      <logConfig logLevel=\"all:0\"/>\n"
                "    </paraConfig>\n"
                "  </parasConfig>\n"
                "</sysConfig>\n",

                des_ip_arg,     /*des tcid*/
                des_ip_arg,     /*des tcid*/
                des_port_arg,   /*des port*/
                src_tcid_arg,   /*src tcid*/

                des_ip_arg,     /*des tcid*/
                src_tcid_arg,   /*src tcid*/

                des_ip_arg,     /*des tcid*/
                src_tcid_arg    /*src tcid*/
                );

    fclose(fp);

    return (EC_TRUE);
}

EC_BOOL __test_ctrans_gen_conf(int argc, char **argv, int argc_max_t, int *argc_t, char **argv_t)
{
    int idx;

    for(idx = 0; idx < argc; idx ++)
    {
        if(0 == strcasecmp(argv[idx], "-s")) /*server*/
        {
            return __test_ctrans_gen_server_conf(argc, argv, argc_max_t, argc_t, argv_t);
        }

        if(0 == strcasecmp(argv[idx], "-c")) /*client*/
        {
            return __test_ctrans_gen_client_conf(argc, argv, argc_max_t, argc_t, argv_t);
        }
    }

    return __test_ctrans_gen_client_conf(argc, argv, argc_max_t, argc_t, argv_t);
}


/*
 * server:
 * src command format: -s -srv <ip>:<port> [-d] [-v]
 * des command format: -s -tcid <tcid> -sconfig <config xml> [-d]
 *
 *
 * client:
 * src command format: [-c] sfile dip:dport@dfile [<segment size>] [-v]
 * des command format: [-c] -tcid <tcid> -des <tcid> -sconfig <config xml>
 *                          -in <src file name> -out <des file name> [-seg <size>]
 *
 */
EC_BOOL __test_ctrans_usage(char *prog)
{
    fprintf(stdout, "usage:\n");

    fprintf(stdout, "client command:\n");
    fprintf(stdout, "\t%s "
                    "[-c] "
                    "-src <src file name> "
                    "-des <des ip>:<des port>:<des file name> "
                    "[-seg <seg size>] "
                    "[-concurrence <concurrent coroutine num>] "
                    "[-loglevel <log levels>] "
                    "[-v] "
                    "[-d] "
                    "\n",
                    prog);
    fprintf(stdout, "e.g.,   %s "
                    "-c "
                    "-src /home/a.dat "
                    "-des 192.168.2.2:798:/tmp/b.dat "
                    "-seg 1M "
                    "\n",
                    prog);

    fprintf(stdout, "\n");

    fprintf(stdout, "server command:\n");
    fprintf(stdout, "\t%s "
                    "-s "
                    "-srv <ip>:<port> "
                    "[-loglevel <log levels>] "
                    "[-v] "
                    "[-d] "
                    "\n",
                    prog);
    fprintf(stdout, "e.g.,   %s "
                    "-s "
                    "-srv 192.168.1.1:798 "
                    "-d "
                    "\n",
                    prog);

    fprintf(stdout, "\n");

    fflush(stdout);

    return (EC_TRUE);
}

void __test_ctrans_print_args(int argc, char **argv)
{
    int pos;

    fprintf(stdout, "[DEBUG] argc : %d\n", argc);

    for(pos = 0; pos < argc; pos ++)
    {
        fprintf(stdout, "[DEBUG] para %d# : %s\n", pos, argv[ pos ]);
    }

    fflush(stdout);

    return;
}


int main_ctrans(int argc, char **argv)
{
    task_brd_default_init(argc, argv);

    if(EC_FALSE == task_brd_default_check_validity())
    {
        dbg_log(SEC_0137_DEMO, 0)(LOGSTDOUT, "error:main_ctrans: validity checking failed\n");
        task_brd_default_abort();
        return (-1);
    }

    if(EC_FALSE == __test_ctrans_parse_args(argc, argv))
    {
        __test_ctrans_usage(argv[0]);
        task_brd_default_abort();
        return (-1);
    }

    if(NULL_PTR != g_trans_log_level)
    {
        log_set_level((char *)cstring_get_str(g_trans_log_level));
    }

    if(EC_TRUE == g_trans_srv_flag) /*server*/
    {
        task_brd_default_add_runner(CMPI_ANY_TCID, CMPI_ANY_RANK,
                                    (const char *)"__test_ctrans_server_runner",
                                    (TASK_RUNNER_FUNC)__test_ctrans_server_runner, NULL_PTR);
    }
    else /*client*/
    {
        task_brd_default_fork_runner(CMPI_ANY_TCID, CMPI_ANY_RANK,
                                    (const char *)"__test_ctrans_client_runner",
                                    (TASK_RUNNER_FUNC)__test_ctrans_client_runner, NULL_PTR);
    }

    /*start the defined runner on current (tcid, rank)*/
    task_brd_default_start_runner();

    return (0);
}


int main(int argc, char **argv)
{
    char        *argv_t[32];
    int          argc_t;

    argc_t = 0; /*init*/

    if(EC_TRUE == __test_ctrans_exist_arg(argc, argv, "-debug_log"))
    {
        g_debug_log = BIT_TRUE;
    }

    if(EC_TRUE == __test_ctrans_exist_arg(argc, argv, "-h")
    || EC_TRUE == __test_ctrans_exist_arg(argc, argv, "-help"))
    {
        __test_ctrans_usage(argv[0]);
        return (0);
    }

    if(EC_FALSE == __test_ctrans_gen_conf(argc, argv,
                                        sizeof(argv_t)/sizeof(argv_t[0]),
                                        &argc_t, (char **)argv_t))
    {
        __test_ctrans_usage(argv[0]);
        return (0);
    }

    if(BIT_TRUE == g_verbose)
    {
        __test_ctrans_print_args(argc_t, (char **)argv_t);
    }

    return main_ctrans(argc_t, (char **)argv_t);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

