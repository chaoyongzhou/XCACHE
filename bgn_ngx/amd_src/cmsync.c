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
#include "cmisc.h"

#include "cmsync.h"

CMSYNC_NODE *cmsync_node_new()
{
    CMSYNC_NODE *cmsync_node;

    alloc_static_mem(MM_CMSYNC_NODE, &cmsync_node, LOC_CMSYNC_0001);
    if(NULL_PTR == cmsync_node)
    {
        dbg_log(SEC_0212_CMSYNC, 0)(LOGSTDOUT, "error:cmsync_node_new: "
                                               "alloc memory failed\n");
        return (NULL_PTR);
    }

    cmsync_node_init(cmsync_node);
    return (cmsync_node);
}

EC_BOOL cmsync_node_init(CMSYNC_NODE *cmsync_node)
{
    CMSYNC_NODE_S_ADDR(cmsync_node)         = NULL_PTR;
    CMSYNC_NODE_E_ADDR(cmsync_node)         = NULL_PTR;
    CMSYNC_NODE_C_ADDR(cmsync_node)         = NULL_PTR;

    return (EC_TRUE);
}

EC_BOOL cmsync_node_clean(CMSYNC_NODE *cmsync_node)
{
    if(NULL_PTR != cmsync_node)
    {
        CMSYNC_NODE_S_ADDR(cmsync_node)         = NULL_PTR;
        CMSYNC_NODE_E_ADDR(cmsync_node)         = NULL_PTR;
        CMSYNC_NODE_C_ADDR(cmsync_node)         = NULL_PTR;
    }

    return (EC_TRUE);
}

EC_BOOL cmsync_node_free(CMSYNC_NODE *cmsync_node)
{
    if(NULL_PTR != cmsync_node)
    {
        cmsync_node_clean(cmsync_node);
        free_static_mem(MM_CMSYNC_NODE, cmsync_node, LOC_CMSYNC_0002);
    }
    return (EC_TRUE);
}

void cmsync_node_print(LOG *log, const CMSYNC_NODE *cmsync_node)
{
    if(NULL_PTR != cmsync_node)
    {
        sys_log(log, "[DEBUG] cmsync_node_print: "
                     "cmsync_node %p: range [%p, %p), cur %p\n",
                     cmsync_node,
                     CMSYNC_NODE_S_ADDR(cmsync_node),
                     CMSYNC_NODE_E_ADDR(cmsync_node),
                     CMSYNC_NODE_C_ADDR(cmsync_node));
    }
    return;
}

CMSYNC_NODE *cmsync_node_create(void *addr, const UINT32 size)
{
    CMSYNC_NODE *cmsync_node;

    if(NULL_PTR == addr || 0 == size)
    {
        dbg_log(SEC_0212_CMSYNC, 0)(LOGSTDOUT, "error:cmsync_node_create: "
                                               "invalid addr %p or size %ld\n",
                                               addr, size);
        return (NULL_PTR);
    }

    cmsync_node = cmsync_node_new();
    if(NULL_PTR == cmsync_node)
    {
        dbg_log(SEC_0212_CMSYNC, 0)(LOGSTDOUT, "error:cmsync_node_create: "
                                               "new cmsync_node failed\n");
        return (NULL_PTR);
    }

    CMSYNC_NODE_S_ADDR(cmsync_node) = addr;
    CMSYNC_NODE_E_ADDR(cmsync_node) = CMSYNC_NODE_S_ADDR(cmsync_node) + size;
    CMSYNC_NODE_C_ADDR(cmsync_node) = CMSYNC_NODE_S_ADDR(cmsync_node);

    dbg_log(SEC_0212_CMSYNC, 9)(LOGSTDOUT, "[DEBUG] cmsync_node_create: "
                                           "create node [%p, %p) done\n",
                                           CMSYNC_NODE_S_ADDR(cmsync_node),
                                           CMSYNC_NODE_E_ADDR(cmsync_node));

    return (cmsync_node);
}

EC_BOOL cmsync_node_start(CMSYNC_NODE *cmsync_node)
{
    if(0 != mprotect(CMSYNC_NODE_S_ADDR(cmsync_node),
                     CMSYNC_NODE_E_ADDR(cmsync_node) - CMSYNC_NODE_S_ADDR(cmsync_node),
                     PROT_READ))
    {
        dbg_log(SEC_0212_CMSYNC, 0)(LOGSTDOUT, "error:cmsync_node_start: "
                                               "protect [%p, %p) to read-only failed, errno = %d, errstr = %s\n",
                                               CMSYNC_NODE_S_ADDR(cmsync_node),
                                               CMSYNC_NODE_E_ADDR(cmsync_node),
                                               errno, strerror(errno));
        return (EC_FALSE);
    }

    dbg_log(SEC_0212_CMSYNC, 9)(LOGSTDOUT, "[DEBUG] cmsync_node_start: "
                                           "protect [%p, %p) to read-only done\n",
                                           CMSYNC_NODE_S_ADDR(cmsync_node),
                                           CMSYNC_NODE_E_ADDR(cmsync_node));

    return (EC_TRUE);
}

EC_BOOL cmsync_node_end(CMSYNC_NODE *cmsync_node)
{
    if(0 != mprotect(CMSYNC_NODE_S_ADDR(cmsync_node),
                     CMSYNC_NODE_E_ADDR(cmsync_node) - CMSYNC_NODE_S_ADDR(cmsync_node),
                     PROT_READ | PROT_WRITE))
    {
        dbg_log(SEC_0212_CMSYNC, 0)(LOGSTDOUT, "error:cmsync_node_end: "
                                               "protect [%p, %p) to rw failed, errno = %d, errstr = %s\n",
                                               CMSYNC_NODE_S_ADDR(cmsync_node),
                                               CMSYNC_NODE_E_ADDR(cmsync_node),
                                               errno, strerror(errno));
        return (EC_FALSE);
    }

    CMSYNC_NODE_C_ADDR(cmsync_node) = CMSYNC_NODE_S_ADDR(cmsync_node); /*reset*/

    dbg_log(SEC_0212_CMSYNC, 9)(LOGSTDOUT, "[DEBUG] cmsync_node_end: "
                                           "protect [%p, %p) to rw done\n",
                                           CMSYNC_NODE_S_ADDR(cmsync_node),
                                           CMSYNC_NODE_E_ADDR(cmsync_node));

    return (EC_TRUE);
}

EC_BOOL cmsync_node_process(CMSYNC_NODE *cmsync_node, const UINT32 size)
{
    UINT32  len;

    len = DMIN(size, CMSYNC_NODE_E_ADDR(cmsync_node) - CMSYNC_NODE_C_ADDR(cmsync_node));

    if(0 < len)
    {
        if(0 != msync(CMSYNC_NODE_C_ADDR(cmsync_node), len, MS_SYNC))
        {
            dbg_log(SEC_0191_CXFSDN, 0)(LOGSTDOUT, "error:cmsync_node_process: "
                                                   "node %p, sync %p, len %ld of [%p, %p) failed, "
                                                   "errno = %d, errstr = %s\n",
                                                   cmsync_node,
                                                   CMSYNC_NODE_C_ADDR(cmsync_node),
                                                   len,
                                                   CMSYNC_NODE_S_ADDR(cmsync_node),
                                                   CMSYNC_NODE_E_ADDR(cmsync_node),
                                                   errno, strerror(errno));
            return (EC_FALSE);
        }

        dbg_log(SEC_0191_CXFSDN, 9)(LOGSTDOUT, "[DEBUG] cmsync_node_process: "
                                               "node %p, sync %p, len %ld of [%p, %p) => %p done\n",
                                               cmsync_node,
                                               CMSYNC_NODE_C_ADDR(cmsync_node),
                                               len,
                                               CMSYNC_NODE_S_ADDR(cmsync_node),
                                               CMSYNC_NODE_E_ADDR(cmsync_node),
                                               CMSYNC_NODE_C_ADDR(cmsync_node) + len);

        CMSYNC_NODE_C_ADDR(cmsync_node) += len;

        return (EC_TRUE);
    }

    return (EC_TRUE);
}

UINT32 cmsync_node_space(const CMSYNC_NODE *cmsync_node)
{
    UINT32      space;

    space = CMSYNC_NODE_E_ADDR(cmsync_node) - CMSYNC_NODE_S_ADDR(cmsync_node);
    return (space);
}

UINT32 cmsync_node_left(const CMSYNC_NODE *cmsync_node)
{
    UINT32      left;

    left = CMSYNC_NODE_E_ADDR(cmsync_node) - CMSYNC_NODE_C_ADDR(cmsync_node);
    return (left);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

