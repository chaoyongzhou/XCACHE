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

#ifndef _CSIG_H
#define _CSIG_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>

#include <sys/time.h>
#include <signal.h>

#include "type.h"
#include "clistbase.h"


#define CSIG_SHELL_CMD_LINE_BUFF_SIZE   (1024)
#define CSIG_SHELL_CMD_OUTPUT_BUFF_SIZE (1024)

#define CSIG_MAX_NUM          (256)
#define CSIG_ATEXIT_MAX_NUM   (8192)

#define CSIG_HANDLE_UNDEF ((uint32_t) 0)
#define CSIG_HANDLE_NOW   ((uint32_t) 1)
#define CSIG_HANDLE_DEFER ((uint32_t) 2)

typedef EC_BOOL (*CSIG_ATEXIT_HANDLER)(UINT32);

typedef struct
{
    CLISTBASE_NODE       node;

    CSIG_ATEXIT_HANDLER  handler;
    UINT32               arg;
}CSIG_ATEXIT;

#define CSIG_ATEXIT_NODE_OFFSET ((UINT32)(&((CSIG_ATEXIT *)0)->node))

typedef EC_BOOL (*CSIG_CHLD_HANDLER)(void);

typedef struct
{
    CSIG_CHLD_HANDLER  handler;
}CSIG_CHLD;

typedef struct
{
    uint32_t count;
    uint32_t flag; /*range in {CSIG_HANDLE_NOW, CSIG_HANDLE_DEFER}*/
    void (*handler)(int signo);
}CSIG_ACTION;

typedef struct
{
    int             signal_queue_len;            /* length of signal queue, <= MAX_SIGNAL (1 entry per signal max) */
    int             signal_queue[ CSIG_MAX_NUM ];/* in-order queue of received signals */

    CSIG_ACTION     signal_action[ CSIG_MAX_NUM ];
    sigset_t        blocked_sig;

    CSIG_ATEXIT     atexit_table[CSIG_ATEXIT_MAX_NUM];

    CLISTBASE       atexit_free_list;
    CLISTBASE       atexit_used_list;

    CSIG_CHLD       child_quit;
}CSIG;

CSIG *csig_new();

EC_BOOL csig_init(CSIG *csig);

void csig_handler(int signo);

void csig_register(int signo, void (*handler)(int), const uint32_t flag);

void csigaction_register(int signo, void (*handler)(int));

EC_BOOL csig_atexit_register(CSIG_ATEXIT_HANDLER atexit_handler, UINT32 arg);

EC_BOOL csig_atexit_unregister(CSIG_ATEXIT_HANDLER atexit_handler, UINT32 arg);

EC_BOOL csig_chld_register(CSIG_CHLD_HANDLER chld_handler);

EC_BOOL csig_chld_unregister();

EC_BOOL csig_takeover(CSIG *csig);

void csig_process_queue();

void csig_print_queue(LOG *log);

void csig_atexit_process_queue();

void csig_set_itimer(const int which_timer, const long useconds);
void csig_reg_action(const int which_sig, void(*sig_handle) (int));

#if 0
void csig_takeover_mpi();
#endif

void csig_gdb_gcore_dump(pid_t pid);

void csig_core_dump(int signo);
void csig_os_default(int signo);
void csig_ignore(int signo);
void csig_stop(int signo);
void csig_interrupt(int signo);
void csig_terminate(int signo);
void csig_quit_now(int signo);
void csig_abort_now(int signo);
void csig_chld_process(int signo);

#endif /*_CSIG_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

