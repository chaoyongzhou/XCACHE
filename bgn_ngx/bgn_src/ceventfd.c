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
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/eventfd.h>

#include "type.h"
#include "mm.h"
#include "log.h"

#include "task.h"
#include "cepoll.h"
#include "ceventfd.h"

/*
 * refer: http://man7.org/linux/man-pages/man2/eventfd.2.html
 *
 *      eventfd() creates an "eventfd object" that can be used as an event
 *      wait/notify mechanism by user-space applications, and by the kernel
 *      to notify user-space applications of events.  The object contains an
 *      unsigned 64-bit integer (uint64_t) counter that is maintained by the
 *      kernel.  This counter is initialized with the value specified in the
 *      argument initval.
**/

CEVENTFD_NODE *ceventfd_node_new()
{
    CEVENTFD_NODE      *ceventfd_node;

    alloc_static_mem(MM_CEVENTFD_NODE, &ceventfd_node, LOC_CEVENTFD_0001);
    if(NULL_PTR == ceventfd_node)
    {
        dbg_log(SEC_0073_CEVENTFD, 0)(LOGSTDOUT, "error:ceventfd_node_new: "
                                                 "no memory\n");
        return (NULL_PTR);
    }

    if(EC_FALSE == ceventfd_node_init(ceventfd_node))
    {
        dbg_log(SEC_0073_CEVENTFD, 0)(LOGSTDOUT, "error:ceventfd_node_new: "
                                                 "init failed\n");
        free_static_mem(MM_CEVENTFD_NODE, ceventfd_node, LOC_CEVENTFD_0002);
        return (NULL_PTR);
    }

    return (ceventfd_node);
}

EC_BOOL ceventfd_node_init(CEVENTFD_NODE *ceventfd_node)
{
    if(NULL_PTR != ceventfd_node)
    {
        CEVENTFD_NODE_FD(ceventfd_node) = syscall(__NR_eventfd2, 0, O_NONBLOCK | O_CLOEXEC);
        if(ERR_FD == CEVENTFD_NODE_FD(ceventfd_node))
        {
            return (EC_FALSE);
        }
        CEVENTFD_NODE_FLAG(ceventfd_node)   = BIT_FALSE;
    }
    return (EC_TRUE);
}

EC_BOOL ceventfd_node_clean(CEVENTFD_NODE *ceventfd_node)
{
    if(NULL_PTR != ceventfd_node)
    {
        if(ERR_FD != CEVENTFD_NODE_FD(ceventfd_node))
        {
            if(BIT_TRUE == CEVENTFD_NODE_FLAG(ceventfd_node))
            {
                cepoll_del_event(task_brd_default_get_cepoll(),
                                 CEVENTFD_NODE_FD(ceventfd_node),
                                 CEPOLL_RD_EVENT);

                CEVENTFD_NODE_FLAG(ceventfd_node) = BIT_FALSE;
            }

            close(CEVENTFD_NODE_FD(ceventfd_node));
            CEVENTFD_NODE_FD(ceventfd_node) = ERR_FD;
        }
    }

    return (EC_TRUE);
}

void    ceventfd_node_free(CEVENTFD_NODE *ceventfd_node)
{
    if(NULL_PTR != ceventfd_node)
    {
        ceventfd_node_clean(ceventfd_node);
        free_static_mem(MM_CEVENTFD_NODE, ceventfd_node, LOC_CEVENTFD_0003);
    }
    return;
}

EC_BOOL ceventfd_node_dummy(CEVENTFD_NODE *ceventfd_node)
{
    static uint64_t    data;    /*must be 8 bytes*/
    ssize_t            recv_len;

    if(ERR_FD == CEVENTFD_NODE_FD(ceventfd_node))
    {
        dbg_log(SEC_0073_CEVENTFD, 0)(LOGSTDOUT, "error:ceventfd_node_dummy: "
                                                 "no event fd\n");
        return (EC_FALSE);
    }

    recv_len = read(CEVENTFD_NODE_FD(ceventfd_node), (void *)&data, 8);
    if(0 > recv_len)
    {
        dbg_log(SEC_0073_CEVENTFD, 0)(LOGSTDOUT, "error:ceventfd_node_dummy: "
                                                 "event fd %d, recv %ld bytes, "
                                                 "errno = %d, errstr = %s\n",
                                                 CEVENTFD_NODE_FD(ceventfd_node), recv_len,
                                                 errno, strerror(errno));

        return (EC_FALSE);
    }

    dbg_log(SEC_0073_CEVENTFD, 5)(LOGSTDOUT, "[DEBUG] ceventfd_node_dummy: "
                                             "event fd %d, recv %ld bytes, data %ld\n",
                                             CEVENTFD_NODE_FD(ceventfd_node), recv_len, data);
    return (EC_TRUE);
}

EC_BOOL ceventfd_node_notify(CEVENTFD_NODE *ceventfd_node)
{
    static  uint64_t     data = 1; /*must be 8 bytes and data would be added to counter of eventfd2*/
    ssize_t              sent_len;

    if(ERR_FD == CEVENTFD_NODE_FD(ceventfd_node))
    {
        dbg_log(SEC_0073_CEVENTFD, 0)(LOGSTDOUT, "error:ceventfd_node_notify: "
                                                 "no event fd\n");
        return (EC_FALSE);
    }

    if(BIT_FALSE == CEVENTFD_NODE_FLAG(ceventfd_node))
    {
        cepoll_set_event(task_brd_default_get_cepoll(),
                          CEVENTFD_NODE_FD(ceventfd_node),
                          CEPOLL_RD_EVENT,
                          (const char *)"ceventfd_node_dummy",
                          (CEPOLL_EVENT_HANDLER)ceventfd_node_dummy,
                          (void *)ceventfd_node);

        CEVENTFD_NODE_FLAG(ceventfd_node) = BIT_TRUE;

        dbg_log(SEC_0073_CEVENTFD, 5)(LOGSTDOUT, "[DEBUG] ceventfd_node_notify: "
                                                 "add read event done\n");
    }

    sent_len = write(CEVENTFD_NODE_FD(ceventfd_node), (void *)&data, 8);
    if(0 > sent_len)
    {
        dbg_log(SEC_0073_CEVENTFD, 0)(LOGSTDOUT, "error:ceventfd_node_notify: "
                                                 "event fd %d, sent %ld bytes, "
                                                 "errno = %d, errstr = %s\n",
                                                 CEVENTFD_NODE_FD(ceventfd_node), sent_len,
                                                 errno, strerror(errno));

        return (EC_FALSE);
    }

    dbg_log(SEC_0073_CEVENTFD, 5)(LOGSTDOUT, "[DEBUG] ceventfd_node_notify: "
                                             "event fd %d, sent %ld bytes\n",
                                             CEVENTFD_NODE_FD(ceventfd_node), sent_len);

    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/
