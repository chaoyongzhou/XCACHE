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

#include "cthread.h"

#include "cmpic.inc"


/*parse args for console*/
EC_BOOL __test_console_parse_args(int argc, char **argv)
{
    return (EC_TRUE);
}

int main_console(int argc, char **argv)
{
    task_brd_default_init(argc, argv);

    if(EC_FALSE == task_brd_default_check_validity())
    {
        dbg_log(SEC_0137_DEMO, 0)(LOGSTDOUT, "error:main_console: validity checking failed\n");
        task_brd_default_abort();
        return (-1);
    }

    dbg_log(SEC_0137_DEMO, 9)(LOGSTDOUT, "[DEBUG] main_console: __test_console_parse_args beg\n");
    __test_console_parse_args(argc, argv);
    dbg_log(SEC_0137_DEMO, 9)(LOGSTDOUT, "[DEBUG] main_console: __test_console_parse_args end\n");


    /*start the defined runner on current (tcid, rank)*/
    task_brd_default_start_runner();

    //task_brd_default_end();
    return (0);
}

int main(int argc, char **argv)
{
    return main_console(argc, argv);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

