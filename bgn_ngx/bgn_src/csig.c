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

#include <sys/time.h>
#include <signal.h>

#include "type.h"
#include "mm.h"
#include "log.h"
#include "csig.h"
#include "cmisc.h"

#include "debug.h"
#include "ccoredumper.h"
#include "task.inc"
#include "task.h"
#include "cmutex.h"

/*********************************************************************************************************************************************************************
man 7 signal
=============

IGNAL(7)                                                             Linux Programmer Manual                                                             SIGNAL(7)

NAME
       signal - list of available signals

DESCRIPTION
       Linux supports both POSIX reliable signals (hereinafter "standard signals") and POSIX real-time signals.

   Standard Signals
       Linux  supports the standard signals listed below. Several signal numbers are architecture dependent, as indicated in the "Value" column.  (Where three values
       are given, the first one is usually valid for alpha and sparc, the middle one for i386, ppc and sh, and the last one for mips.  A - denotes that a  signal  is
       absent on the corresponding architecture.)

       The entries in the "Action" column of the table specify the default action for the signal, as follows:

       Term   Default action is to terminate the process.

       Ign    Default action is to ignore the signal.

       Core   Default action is to terminate the process and dump core.

       Stop   Default action is to stop the process.

       First the signals described in the original POSIX.1 standard.

       Signal     Value     Action   Comment
       -------------------------------------------------------------------------
       SIGHUP        1       Term    Hangup detected on controlling terminal
                                     or death of controlling process
       SIGINT        2       Term    Interrupt from keyboard
       SIGQUIT       3       Core    Quit from keyboard
       SIGILL        4       Core    Illegal Instruction
       SIGABRT       6       Core    Abort signal from abort(3)
       SIGFPE        8       Core    Floating point exception
       SIGKILL       9       Term    Kill signal
       SIGSEGV      11       Core    Invalid memory reference
       SIGPIPE      13       Term    Broken pipe: write to pipe with no readers
       SIGALRM      14       Term    Timer signal from alarm(2)
       SIGTERM      15       Term    Termination signal
       SIGUSR1   30,10,16    Term    User-defined signal 1
       SIGUSR2   31,12,17    Term    User-defined signal 2
       SIGCHLD   20,17,18    Ign     Child stopped or terminated
       SIGCONT   19,18,25            Continue if stopped
       SIGSTOP   17,19,23    Stop    Stop process
       SIGTSTP   18,20,24    Stop    Stop typed at tty
       SIGTTIN   21,21,26    Stop    tty input for background process
       SIGTTOU   22,22,27    Stop    tty output for background process

       The signals SIGKILL and SIGSTOP cannot be caught, blocked, or ignored.

       Next the signals not in the POSIX.1 standard but described in SUSv2 and SUSv3 / POSIX 1003.1-2001.

       Signal       Value     Action   Comment
       -------------------------------------------------------------------------
       SIGBUS      10,7,10     Core    Bus error (bad memory access)
       SIGPOLL                 Term    Pollable event (Sys V). Synonym of SIGIO
       SIGPROF     27,27,29    Term    Profiling timer expired
       SIGSYS      12,-,12     Core    Bad argument to routine (SVID)
       SIGTRAP        5        Core    Trace/breakpoint trap
       SIGURG      16,23,21    Ign     Urgent condition on socket (4.2 BSD)
       SIGVTALRM   26,26,28    Term    Virtual alarm clock (4.2 BSD)
       SIGXCPU     24,24,30    Core    CPU time limit exceeded (4.2 BSD)
       SIGXFSZ     25,25,31    Core    File size limit exceeded (4.2 BSD)

       Up  to  and  including Linux 2.2, the default behaviour for SIGSYS, SIGXCPU, SIGXFSZ, and (on architectures other than SPARC and MIPS) SIGBUS was to terminate
       the process (without a core dump).  (On some other Unices the default action for SIGXCPU and SIGXFSZ is to terminate the process without a core dump.)   Linux
       2.4 conforms to the POSIX 1003.1-2001 requirements for these signals, terminating the process with a core dump.

       Next various other signals.

       Signal       Value     Action   Comment
       --------------------------------------------------------------------
       SIGIOT         6        Core    IOT trap. A synonym for SIGABRT
       SIGEMT       7,-,7      Term
       SIGSTKFLT    -,16,-     Term    Stack fault on coprocessor (unused)
       SIGIO       23,29,22    Term    I/O now possible (4.2 BSD)
       SIGCLD       -,-,18     Ign     A synonym for SIGCHLD
       SIGPWR      29,30,19    Term    Power failure (System V)
       SIGINFO      29,-,-             A synonym for SIGPWR
       SIGLOST      -,-,-      Term    File lock lost
       SIGWINCH    28,28,20    Ign     Window resize signal (4.3 BSD, Sun)
       SIGUNUSED    -,31,-     Term    Unused signal (will be SIGSYS)

       (Signal 29 is SIGINFO / SIGPWR on an alpha but SIGLOST on a sparc.)

       SIGEMT  is  not  specified  in POSIX 1003.1-2001, but neverthless appears on most other Unices, where its default action is typically to terminate the process
       with a core dump.
*********************************************************************************************************************************************************************/
STATIC_CAST static EC_BOOL __csig_atexit_cmp(CSIG_ATEXIT *csig_atexit_1st, CSIG_ATEXIT *csig_atexit_2nd)
{
    if(csig_atexit_1st->handler == csig_atexit_2nd->handler
    && csig_atexit_1st->arg     == csig_atexit_2nd->arg)
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

CSIG *csig_new()
{
    CSIG  *csig;

    csig = safe_malloc(sizeof(CSIG), LOC_CSIG_0001);
    if(NULL_PTR == csig)
    {
        dbg_log(SEC_0014_CSIG, 0)(LOGSTDOUT, "error:csig_new: no memory\n");
        return (NULL_PTR);
    }

    csig_init(csig);

    return (csig);
}

EC_BOOL csig_init(CSIG *csig)
{
    int      signo;
    int      idx;

    csig->signal_queue_len = 0;
    for(idx = 0; idx < CSIG_MAX_NUM; idx ++)
    {
        csig->signal_queue[ idx ] = 0;
    }

    for(signo = 0; signo < CSIG_MAX_NUM; signo ++)
    {
        csig->signal_action[ signo ].count   = 0;
        csig->signal_action[ signo ].flag    = CSIG_HANDLE_UNDEF;
        csig->signal_action[ signo ].handler = NULL_PTR;
    }

    sigfillset(&(csig->blocked_sig));

    /*init atexit table and list data table*/
    for(idx = 0; idx < CSIG_ATEXIT_MAX_NUM; idx ++)
    {
        CSIG_ATEXIT     *csig_atexit;
        CLISTBASE_NODE  *clistbase_node;

        csig_atexit = &(csig->atexit_table[ idx ]);
        csig_atexit->handler = NULL_PTR;
        csig_atexit->arg     = NULL_PTR;

        clistbase_node = &(csig_atexit->node);

        ASSERT((void *)csig_atexit == (void *)clistbase_node);
        CLISTBASE_NODE_INIT(clistbase_node);

        dbg_log(SEC_0014_CSIG, 9)(LOGSTDOUT, "[DEBUG] csig_init: "
                                             "[%d] bind: clistbase_node: %p, csig_atexit: %p\n",
                                             idx, clistbase_node, csig_atexit);
    }

    /*init free list and used list*/
    clistbase_init(&(csig->atexit_free_list));
    clistbase_init(&(csig->atexit_used_list));

    /*setup free list*/
    for(idx = 0; idx < CSIG_ATEXIT_MAX_NUM; idx ++)
    {
        CSIG_ATEXIT     *csig_atexit;

        csig_atexit = &(csig->atexit_table[ idx ]);
        clistbase_push_back(&(csig->atexit_free_list), (void *)csig_atexit);

        dbg_log(SEC_0014_CSIG, 9)(LOGSTDOUT, "[DEBUG] csig_init: "
                                             "[%d] push free: csig_atexit: %p\n",
                                             idx, csig_atexit);
    }

    if(1)
    {
        CSIG_CHLD       *child_quit;

        child_quit = &(csig->child_quit);
        child_quit->handler = NULL_PTR;
    }

    return (EC_TRUE);
}

void csig_handler(int signo)
{
    TASK_BRD *task_brd;
    CSIG *csig;

    task_brd = task_brd_default_get();
    csig = TASK_BRD_CSIG(task_brd);

    if (0 > signo || CSIG_MAX_NUM < signo || NULL_PTR == csig->signal_action[ signo ].handler)
    {
        /* unhandled signal */
        dbg_log(SEC_0014_CSIG, 1)(LOGSTDOUT, "warn:csig_handler: received unhandled signal %d which has been disabled.\n", signo);
        signal(signo, SIG_IGN);
        return;
    }

    if(CSIG_HANDLE_NOW == csig->signal_action[ signo ].flag)
    {

        signal(signo, csig_handler); /* re-arm signal */
        csig->signal_action[ signo ].handler(signo);
        return;
    }

    if (0 == csig->signal_action[ signo ].count)
    {
        /* signal was not queued yet */
        if (CSIG_MAX_NUM > csig->signal_queue_len)
        {
            csig->signal_queue[ csig->signal_queue_len ] = signo;
            csig->signal_queue_len ++;

            dbg_log(SEC_0014_CSIG, 9)(LOGSTDOUT, "[DEBUG] csig_handler: push signo %d => signal_queue_len %d\n", signo, csig->signal_queue_len);
        }
        else
        {
            dbg_log(SEC_0014_CSIG, 1)(LOGSTDOUT, "warn:csig_handler: received signal %d but signal queue is unexpectedly full.\n", signo);
        }
    }
    csig->signal_action[ signo ].count ++;
    signal(signo, csig_handler); /* re-arm signal */

    return;
}


/* Register a handler for signal <sig>. Set it to NULL, SIG_DFL or SIG_IGN to
 * remove the handler. The signal's queue is flushed and the signal is really
 * registered (or unregistered) for the process. The interface is the same as
 * for standard signal delivery, except that the handler does not need to rearm
 * the signal itself (it can disable it however).
 */
void csig_register(int signo, void (*handler)(int), const uint32_t flag)
{
    TASK_BRD    *task_brd;
    CSIG        *csig;
    CSIG_ACTION *csig_action;

    task_brd = task_brd_default_get();
    csig = TASK_BRD_CSIG(task_brd);

    if (0 > signo || CSIG_MAX_NUM < signo)
    {
        dbg_log(SEC_0014_CSIG, 0)(LOGSTDOUT, "error:csig_register: failed to register signal %d : out of range [0..%d].\n", signo, CSIG_MAX_NUM);
        return;
    }

    csig_action = &(csig->signal_action[ signo ]);

    if (NULL_PTR == handler)
    {
        handler = SIG_IGN;
    }

    if (SIG_IGN != handler && SIG_DFL != handler)
    {
        csig_action->flag    = flag;
        csig_action->count   = 0;
        csig_action->handler = handler;
        signal(signo, csig_handler);
    }
    else
    {
        csig_action->flag    = flag;
        csig_action->count   = 0;
        csig_action->handler = NULL_PTR;
        signal(signo, handler);
    }
    return;
}

void csigaction_register(int signo, void (*handler)(int))
{
    struct sigaction sa;

    sa.sa_handler = handler;
    sigemptyset(&sa.sa_mask);                /*additional signals to block*/
    sa.sa_flags = SA_RESTART;               /*restart the system call ,interrupted by signal*/
    sigaction(signo, &sa, NULL_PTR);

    return;
}

EC_BOOL csig_atexit_register(CSIG_ATEXIT_HANDLER atexit_handler, UINT32 arg)
{
    TASK_BRD        *task_brd;
    CSIG            *csig;
    CSIG_ATEXIT     *csig_atexit;

    if(NULL_PTR == atexit_handler)
    {
        dbg_log(SEC_0014_CSIG, 0)(LOGSTDOUT, "error:csig_atexit_register: atexit_handler is null\n");
        return (EC_FALSE);
    }

    task_brd = task_brd_default_get();
    csig = TASK_BRD_CSIG(task_brd);

    csig_atexit = clistbase_pop_front(&(csig->atexit_free_list));
    if(NULL_PTR == csig_atexit)
    {
        dbg_log(SEC_0014_CSIG, 0)(LOGSTDOUT, "error:csig_atexit_register: atexit table is already full\n");
        return (EC_FALSE);
    }

    //ASSERT((void *)csig_atexit == (void *)&(csig_atexit->node));

    dbg_log(SEC_0014_CSIG, 9)(LOGSTDOUT, "[DEBUG] csig_atexit_register: pop free: "
                                         "csig_atexit: %p, clistbase_node: %p\n",
                                         csig_atexit, &(csig_atexit->node));

    csig_atexit->handler = atexit_handler;
    csig_atexit->arg     = arg;

    clistbase_push_back(&(csig->atexit_used_list), (void *)csig_atexit);

    return (EC_TRUE);
}

EC_BOOL csig_atexit_unregister(CSIG_ATEXIT_HANDLER atexit_handler, UINT32 arg)
{
    TASK_BRD        *task_brd;
    CSIG            *csig;

    CSIG_ATEXIT      csig_atexit_tmp;
    CSIG_ATEXIT     *csig_atexit_searched;
    CLISTBASE_NODE  *clistbase_node_searched;

    task_brd = task_brd_default_get();
    csig = TASK_BRD_CSIG(task_brd);

    csig_atexit_tmp.handler = atexit_handler;
    csig_atexit_tmp.arg     = arg;

    clistbase_node_searched = clistbase_search_back(&(csig->atexit_used_list), (void *)&csig_atexit_tmp,
                            (CLISTBASE_NODE_DATA_CMP)__csig_atexit_cmp);

    if(NULL_PTR == clistbase_node_searched)
    {
        return (EC_TRUE);
    }

    clistbase_erase(&(csig->atexit_used_list), clistbase_node_searched);

    csig_atexit_searched = CLISTBASE_NODE_DATA(clistbase_node_searched);
    csig_atexit_searched->handler = NULL_PTR;
    csig_atexit_searched->arg     = 0;

    clistbase_push_back(&(csig->atexit_free_list), (void *)clistbase_node_searched);

    return (EC_TRUE);
}

EC_BOOL csig_chld_register(CSIG_CHLD_HANDLER chld_handler)
{
    TASK_BRD        *task_brd;
    CSIG            *csig;
    CSIG_CHLD       *csig_chld;

    if(NULL_PTR == chld_handler)
    {
        dbg_log(SEC_0014_CSIG, 0)(LOGSTDOUT, "error:csig_chld_register: chld_handler is null\n");
        return (EC_FALSE);
    }

    task_brd = task_brd_default_get();
    csig = TASK_BRD_CSIG(task_brd);

    csig_chld = &(csig->child_quit);
    csig_chld->handler = chld_handler;

    return (EC_TRUE);
}

EC_BOOL csig_chld_unregister()
{
    TASK_BRD        *task_brd;
    CSIG            *csig;
    CSIG_CHLD       *csig_chld;

    task_brd = task_brd_default_get();
    csig = TASK_BRD_CSIG(task_brd);

    csig_chld = &(csig->child_quit);
    csig_chld->handler = NULL_PTR;

    return (EC_TRUE);
}

EC_BOOL csig_takeover(CSIG *csig)
{
#if (SWITCH_OFF == NGX_BGN_SWITCH)
    csigaction_register(SIGUSR2, csig_ignore);/*sigaction*/

    csig_register(SIGUSR1, csig_ignore    , CSIG_HANDLE_DEFER);
    csig_register(SIGHUP , csig_ignore    , CSIG_HANDLE_DEFER);/*when user terminal hup*/
    csig_register(SIGINT , csig_interrupt , CSIG_HANDLE_DEFER);/*CTRL + C*/
    csig_register(SIGTERM, csig_terminate , CSIG_HANDLE_DEFER);/*terminate process, defer, kill -15*/

    csig_register(SIGFPE , csig_core_dump , CSIG_HANDLE_NOW  );
    csig_register(SIGILL , csig_core_dump , CSIG_HANDLE_NOW  );
    csig_register(SIGQUIT, csig_os_default, CSIG_HANDLE_NOW  ); /*CTRL + \, default is to create core file*/
    csig_register(SIGSEGV, csig_core_dump , CSIG_HANDLE_NOW  );
    csig_register(SIGTRAP, csig_ignore    , CSIG_HANDLE_DEFER);
    csig_register(SIGSYS , csig_core_dump , CSIG_HANDLE_DEFER);
    csig_register(SIGBUS , csig_quit_now  , CSIG_HANDLE_NOW  );
    csig_register(SIGXCPU, csig_core_dump , CSIG_HANDLE_DEFER);

    csig_register(SIGPIPE, csig_ignore    , CSIG_HANDLE_DEFER);
    csig_register(SIGTTOU, csig_stop      , CSIG_HANDLE_DEFER);
    csig_register(SIGTTIN, csig_stop      , CSIG_HANDLE_DEFER);

    /*takeover SIGABRT due to that it does not call atexit callback*/
    csig_register(SIGABRT, csig_abort_now , CSIG_HANDLE_NOW  );

    csig_register(SIGCHLD, csig_chld_process, CSIG_HANDLE_NOW);

    /********************************************************************************
    *
    *  note:
    *      SIGKILL, SIGSTOP cannot be captured, blocked or ignored by application
    *      kill -15 <pid> would be another choice to terminate a process.
    *
    *      15) SIGTERM
    *
    *  REF TO: http://www.cnii.com.cn/20050801/ca351116.htm
    *
    ********************************************************************************/
    //csig_register(SIGKILL, csig_stop      , CSIG_HANDLE_NOW  );
#endif/*(SWITCH_OFF == NGX_BGN_SWITCH)*/
    atexit(csig_atexit_process_queue);

    return (EC_TRUE);
}


/* Call handlers of all pending signals and clear counts and queue length. The
 * handlers may unregister themselves by calling signal_register() while they
 * are called, just like it is done with normal signal handlers.
 * Note that it is more efficient to call the inline version which checks the
 * queue length before getting here.
 */
STATIC_CAST static void __csig_process_queue()
{
    TASK_BRD    *task_brd;
    CSIG        *csig;

    int          signo;
    int          cur_pos;
    CSIG_ACTION *csig_action;
    sigset_t     old_sig;

    task_brd = task_brd_default_get();
    csig = TASK_BRD_CSIG(task_brd);

    if(0 < csig->signal_queue_len)
    {
        dbg_log(SEC_0014_CSIG, 9)(LOGSTDOUT, "[DEBUG] __csig_process_queue: signal_queue_len = %d\n", csig->signal_queue_len);
        /* block signal delivery during processing */
        sigprocmask(SIG_SETMASK, &(csig->blocked_sig), &old_sig);

        for(cur_pos = 0; cur_pos < csig->signal_queue_len; cur_pos++)
        {
            signo       = csig->signal_queue[cur_pos];
            csig_action = &(csig->signal_action[ signo ]);

            if(0 < csig_action->count)
            {
                dbg_log(SEC_0014_CSIG, 9)(LOGSTDOUT, "[DEBUG] __csig_process_queue: signo %d, count %u\n", signo, csig_action->count);
                if(NULL_PTR != csig_action->handler)
                {
                    csig_action->handler(signo);
                }
                csig_action->count = 0;
            }
        }

        csig->signal_queue_len = 0;

        /* restore signal delivery */
        sigprocmask(SIG_SETMASK, &old_sig, NULL_PTR);
    }

    return;
}

void csig_process_queue()
{
    TASK_BRD    *task_brd;
    CSIG        *csig;

    task_brd = task_brd_default_get();
    csig = TASK_BRD_CSIG(task_brd);

    if (0 < csig->signal_queue_len)
    {
        __csig_process_queue();
    }
    return;
}

STATIC_CAST static void __csig_print_queue(LOG *log)
{
    TASK_BRD *task_brd;
    CSIG *csig;

    int signo;
    int cur_pos;
    CSIG_ACTION *csig_action;

    task_brd = task_brd_default_get();
    csig     = TASK_BRD_CSIG(task_brd);

    for(cur_pos = 0; cur_pos < csig->signal_queue_len; cur_pos++)
    {
        signo       = csig->signal_queue[cur_pos];
        csig_action = &(csig->signal_action[ signo ]);

        if(0 < csig_action->count)
        {
            sys_log(log, "__csig_print_queue: signal %d, count %d\n", signo, csig_action->count);
        }
    }

    return;
}

void csig_print_queue(LOG *log)
{
    TASK_BRD    *task_brd;
    CSIG        *csig;

    task_brd = task_brd_default_get();
    csig = TASK_BRD_CSIG(task_brd);

    if (0 < csig->signal_queue_len)
    {
        __csig_print_queue(log);
    }
    return;
}

STATIC_CAST static void __csig_atexit_process_queue()
{
    TASK_BRD        *task_brd;
    CSIG            *csig;
    CSIG_ATEXIT     *csig_atexit;

    task_brd = task_brd_default_get();
    csig = TASK_BRD_CSIG(task_brd);

    while(NULL_PTR != (csig_atexit = clistbase_pop_back(&(csig->atexit_used_list))))
    {
        CSIG_ATEXIT_HANDLER  handler;
        UINT32               arg;

        if(NULL_PTR != csig_atexit->handler)
        {
            handler = csig_atexit->handler;
            arg     = csig_atexit->arg;

            csig_atexit->handler = NULL_PTR;
            csig_atexit->arg     = 0;

            handler(arg);
        }

        clistbase_push_back(&(csig->atexit_free_list), (void *)csig_atexit);
    }

    return;
}

void csig_atexit_process_queue()
{
    TASK_BRD    *task_brd;
    CSIG        *csig;

    task_brd = task_brd_default_get();
    csig     = TASK_BRD_CSIG(task_brd);

    if (EC_FALSE == clistbase_is_empty(&(csig->atexit_used_list)))
    {
        __csig_atexit_process_queue();
    }
    return;
}

void csig_set_itimer(const int which_timer, const long useconds)
{
    struct itimerval itimer;

    itimer.it_value.tv_sec = (long)(useconds / 1000);
    itimer.it_value.tv_usec = (long)(useconds % 1000);
    itimer.it_interval = itimer.it_value;

    setitimer(/*ITIMER_REAL*/which_timer, &itimer, NULL_PTR); /*ITIMER_REAL timer, when timer is reached, send out SIGALRM*/
    return;
}

void csig_reg_action(const int which_sig, void(*sig_handle) (int))
{
    struct sigaction sigact;

    sigact.sa_handler = sig_handle; /*register signal handler*/
    sigact.sa_flags = 0;

    sigemptyset(&sigact.sa_mask); /*initialize signal set*/

    sigaction(which_sig, &sigact, NULL_PTR); /*register signal*/

    /**
     * unblock all the signals, because if the current process is
     * spawned in the previous signal handler, all the signals are
     * blocked. In order to make it sense of signals, we should
     * unblock them. Certainly, you should call this function as
     * early as possible. :)
     **/
    sigprocmask(SIG_UNBLOCK, &sigact.sa_mask, NULL_PTR);

    return;
}

/**
*   core filename format parameters:
*   %%    %
*   %p    pid
*   %u    uid
*   %g    gid
*   %s    signal which triggered the core dump
*   %t    time of core dump
*   %h    hostname
*   %e    executable filename
*   %c    ulimit -c
*
* core filename format definition:
*   echo "/tmp/cores/core-%e-%p-%t-%s " > /proc/sys/kernel/core_pattern
*
* append pid to core filename enabling:
*   echo "1" > /proc/sys/kernel/core_uses_pid
*
* set core file size to unlimited
*   ulimit -c unlimited
*
* gcore is one part of gdb tool suite
* gcore create a core dump of certain process by
*   gcore -o <core filename> <pid>
*
* gdb check the core file by
*   gdb <executable filename> <core filename>
*
**/

void csig_gdb_gcore_dump(pid_t pid)
{
    FILE * rstream;
    char   cmd_line[CSIG_SHELL_CMD_LINE_BUFF_SIZE];
    char   cmd_output[CSIG_SHELL_CMD_OUTPUT_BUFF_SIZE];

    struct tm *cur_time;

    /*check gcore of gdb existing*/
    snprintf(cmd_line, CSIG_SHELL_CMD_LINE_BUFF_SIZE - 4, "which gcore 2>/dev/null");
    dbg_log(SEC_0014_CSIG, 5)(LOGSTDOUT, "csig_gcore_dump: execute shell command: %s\n", cmd_line);

    rstream = popen((char *)cmd_line, "r");
    fgets(cmd_output, CSIG_SHELL_CMD_OUTPUT_BUFF_SIZE - 4, rstream);
    pclose( rstream );

    if(0 == strlen(cmd_output))
    {
        dbg_log(SEC_0014_CSIG, 0)(LOGSTDERR, "csig_gcore_dump: no result for shell command: %s\n", cmd_line);
        return;
    }

    /*get time string*/
    cur_time = c_localtime_r(NULL_PTR);

    /*encapsulate cmd line*/
    snprintf(cmd_line, CSIG_SHELL_CMD_LINE_BUFF_SIZE - 4, "gcore -o core-%d-%4d%02d%02d-%02d%02d%02d %d",
                        pid,
                        TIME_IN_YMDHMS(cur_time),
                        pid
           );
    dbg_log(SEC_0014_CSIG, 5)(LOGSTDOUT, "csig_gcore_dump: execute shell command: %s\n", cmd_line);

    /*execute cmd line*/
    rstream = popen((char *)cmd_line, "r");
    pclose( rstream );

    return;
}

#if 0
void csig_core_dump(int signo)
{
    char   core_file[CSIG_SHELL_CMD_LINE_BUFF_SIZE];

    struct tm *cur_time;
    time_t timestamp;

    //struct CoredumperCompressor *compressor;
    dbg_log(SEC_0014_CSIG, 0)(LOGSTDOUT, "error:csig_core_dump: signal %d trigger core dump ......\n", signo);

    /*get time string*/
    cur_time = c_localtime_r(NULL_PTR);

    /*encapsulate cmd line*/
    snprintf(core_file, CSIG_SHELL_CMD_LINE_BUFF_SIZE - 4, "core-%d-%4d%02d%02d-%02d:%02d:%02d",
                        getpid(),
                        TIME_IN_YMDHMS(cur_time)
           );


    //csig_gdb_gcore_dump(getpid());
    //signal(signo, SIG_DFL);/*restore to OS default handler!*/
    //ccoredumper_write_compressed("corexx", -1, COREDUMPER_COMPRESSED, &compressor);
    ccoredumper_write(core_file);
    raise(signo);

    return;
}
#endif

#if 0
/*ok*/
void csig_core_dump(int signo)
{
    dbg_log(SEC_0014_CSIG, 0)(LOGSTDOUT, "error:csig_core_dump: signal %d trigger core dump ......\n", signo);

    csig_gdb_gcore_dump(getpid());
    signal(signo, SIG_DFL);/*restore to OS default handler!*/
    raise(signo);

    return;
}
#endif

void csig_core_dump(int signo)
{
    c_backtrace_dump(LOGSTDOUT);

    dbg_log(SEC_0014_CSIG, 0)(LOGSTDOUT, "error:csig_core_dump: signal %d trigger core dump ......\n", signo);

    csig_atexit_process_queue();/*Oops!*/

    if(0)
    {
        TASK_BRD *task_brd;
        task_brd = task_brd_default_get();
        croutine_pool_print(LOGSTDOUT, TASK_BRD_CROUTINE_POOL(task_brd));
    }

    if(0)/*debug*/
    {
        for(;;)
        {
            dbg_log(SEC_0014_CSIG, 9)(LOGSTDOUT, "[DEBUG] csig_core_dump: wait for gdb ...\n");
            c_sleep(300, LOC_CSIG_0002);
        }
    }
    abort();
#if 0
    //dbg_exit(MD_END, CMPI_ERROR_MODI);

    signal(signo, SIG_DFL);/*restore to OS default handler!*/
    raise(signo);
#endif
    return;
}


void csig_os_default(int signo)
{
    dbg_log(SEC_0014_CSIG, 1)(LOGSTDOUT, "warn:csig_os_default: process %d, signal %d restore default action\n", getpid(), signo);

    signal(signo, SIG_DFL);/*restore to OS default handler!*/
    raise(signo);
    return;
}
void csig_ignore(int signo)
{
    dbg_log(SEC_0014_CSIG, 1)(LOGSTDOUT, "warn:csig_ignore: process %d, signal %d was ignored\n", getpid(), signo);

    //signal(signo, SIG_DFL);/*restore to OS default handler!*/
    //raise(signo);
    return;
}

void csig_interrupt(int signo)
{
    TASK_BRD *task_brd;

    dbg_log(SEC_0014_CSIG, 0)(LOGSTDOUT, "error:csig_interrupt: process %d, signal %d trigger interruption ......\n", getpid(), signo);

    c_backtrace_dump(LOGSTDOUT);

    csig_atexit_process_queue();/*Oops!*/

    task_brd = task_brd_default_get();
    TASK_BRD_ABORT_FLAG(task_brd) = CPROC_IS_ABORTED;

    //csig_register(signo, SIG_DFL);
    signal(signo, SIG_DFL);/*restore to OS default handler!*/
    raise(signo);
    return;
}

void csig_stop(int signo)
{
    TASK_BRD *task_brd;

    dbg_log(SEC_0014_CSIG, 0)(LOGSTDOUT, "error:csig_stop: process %d, signal %d trigger stopping ......\n", getpid(), signo);

    csig_atexit_process_queue();/*Oops!*/

    task_brd = task_brd_default_get();
    TASK_BRD_ABORT_FLAG(task_brd) = CPROC_IS_ABORTED;

    signal(signo, SIG_DFL);/*restore to OS default handler!*/
    raise(signo);
    return;
}

void csig_terminate(int signo)
{
    TASK_BRD *task_brd;

    c_backtrace_dump(LOGSTDOUT);

    dbg_log(SEC_0014_CSIG, 0)(LOGSTDOUT, "error:csig_terminate: process %d, signal %d trigger terminating ......\n", getpid(), signo);

    csig_atexit_process_queue();/*Oops!*/

    task_brd = task_brd_default_get();
    TASK_BRD_ABORT_FLAG(task_brd) = CPROC_IS_ABORTED;

    signal(signo, SIG_DFL);/*restore to OS default handler!*/
    raise(signo);
    return;
}

void csig_quit_now(int signo)
{
    c_backtrace_dump(LOGSTDOUT);

    dbg_log(SEC_0014_CSIG, 0)(LOGSTDOUT, "error:csig_quit_now: signal %d trigger core dump ......\n", signo);

    //csig_atexit_process_queue();/*Oops!*/

    abort();
    return;
}

void csig_abort_now(int signo)
{
    dbg_log(SEC_0014_CSIG, 0)(LOGSTDOUT, "error:csig_abort_now: signal %d trigger atexit process ......\n", signo);

    csig_atexit_process_queue();

    signal(signo, SIG_DFL);/*restore to OS default handler!*/
    raise(signo);
}

void csig_chld_process(int signo)
{
    TASK_BRD        *task_brd;
    CSIG            *csig;
    CSIG_CHLD       *csig_chld;

    task_brd = task_brd_default_get();
    csig = TASK_BRD_CSIG(task_brd);

    csig_chld = &(csig->child_quit);
    if(NULL_PTR != csig_chld->handler)
    {
        csig_chld->handler();
    }
}

#if 0
/*taskover sig handler of MPI!*/
void csig_takeover_mpi()
{
    struct sigaction sig_act;
    UINT32 csig_idx;

    memset(&sig_act, 0, sizeof(sig_act));
    sig_act.sa_handler = csig_core_dump;
    //sigfillset(&act.sa_mask);
    sigemptyset(&sig_act.sa_mask);

    for (csig_idx = 0; csig_idx < sizeof(g_csig_action_tbl)/sizeof(g_csig_action_tbl[0]); csig_idx ++)
    {
        CSIG_ACTION *csig_action;

        csig_action = &(g_csig_action_tbl[ csig_idx ]);
        sigaction(CSIG_ACTION_SIGNAL(csig_action), &sig_act, NULL_PTR);
    }
    /* unblock all the signals, because if the current process is
     * spawned in the previous signal handler, all the signals are
     * blocked. In order to make it sense of signals, we should
     * unblock them. Certainly, you should call this function as
     * early as possible. :) */
    sigprocmask(SIG_UNBLOCK, &sig_act.sa_mask, NULL_PTR);
    return;
}
#endif

#ifdef __cplusplus
}
#endif/*__cplusplus*/

