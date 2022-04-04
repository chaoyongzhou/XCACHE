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

#include "type.h"
#include "mm.h"
#include "log.h"

#include "cmisc.h"
#include "cmpic.inc"

#include "cparacfg.inc"
#include "cparacfg.h"

#include "json.h"

CPARACFG_NODE *cparacfg_node_new()
{
    CPARACFG_NODE *cparacfg_node;
    alloc_static_mem(MM_CPARACFG_NODE, &cparacfg_node, LOC_CPARACFG_0001);
    if(NULL_PTR != cparacfg_node)
    {
        cparacfg_node_init(cparacfg_node);
    }
    return (cparacfg_node);
}

EC_BOOL cparacfg_node_init(CPARACFG_NODE *cparacfg_node)
{
    if(NULL_PTR != cparacfg_node)
    {
        BSET(cparacfg_node, 0x00, sizeof(CPARACFG_NODE));
    }
    return (EC_TRUE);
}

EC_BOOL cparacfg_node_clean(CPARACFG_NODE *cparacfg_node)
{
    if(NULL_PTR != cparacfg_node)
    {
        if(EC_TRUE == cparacfg_node_is_type(cparacfg_node, "CSTRING")
        && NULL_PTR != CPARACFG_NODE_DATA_CSTR(cparacfg_node))
        {
            cstring_free(CPARACFG_NODE_DATA_CSTR(cparacfg_node));
            CPARACFG_NODE_DATA_CSTR(cparacfg_node) = NULL_PTR;
        }

        CPARACFG_NODE_MACRO_NAME(cparacfg_node) = NULL_PTR;
        CPARACFG_NODE_TYPE_NAME(cparacfg_node) = NULL_PTR;

        BSET(cparacfg_node, 0x00, sizeof(CPARACFG_NODE));
    }

    return (EC_TRUE);
}

EC_BOOL cparacfg_node_free(CPARACFG_NODE *cparacfg_node)
{
    if(NULL_PTR != cparacfg_node)
    {
        cparacfg_node_clean(cparacfg_node);
        free_static_mem(MM_CPARACFG_NODE, cparacfg_node, LOC_CPARACFG_0002);
    }
    return (EC_TRUE);
}

EC_BOOL cparacfg_node_is_type(const CPARACFG_NODE *cparacfg_node, const char *type_name)
{
    if(NULL_PTR != CPARACFG_NODE_TYPE_NAME(cparacfg_node)
    && 0 == STRCMP(CPARACFG_NODE_TYPE_NAME(cparacfg_node), type_name))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

void cparacfg_node_print(LOG *log, const CPARACFG_NODE *cparacfg_node)
{
    if(NULL_PTR != cparacfg_node)
    {
        if(EC_TRUE == cparacfg_node_is_type(cparacfg_node, "int"))
        {
            sys_log(log, "cparacfg_node_print: cparacfg_node %p, "
                         "macro %s, type %s, val %d\n",
                         cparacfg_node,
                         CPARACFG_NODE_MACRO_NAME(cparacfg_node),
                         CPARACFG_NODE_TYPE_NAME(cparacfg_node),
                         CPARACFG_NODE_DATA_INT(cparacfg_node));
            return;
        }

        if(EC_TRUE == cparacfg_node_is_type(cparacfg_node, "uint8_t"))
        {
            sys_log(log, "cparacfg_node_print: cparacfg_node %p, "
                         "macro %s, type %s, val %u\n",
                         cparacfg_node,
                         CPARACFG_NODE_MACRO_NAME(cparacfg_node),
                         CPARACFG_NODE_TYPE_NAME(cparacfg_node),
                         CPARACFG_NODE_DATA_U8(cparacfg_node));
            return;
        }

        if(EC_TRUE == cparacfg_node_is_type(cparacfg_node, "uint16_t"))
        {
            sys_log(log, "cparacfg_node_print: cparacfg_node %p, "
                         "macro %s, type %s, val %u\n",
                         cparacfg_node,
                         CPARACFG_NODE_MACRO_NAME(cparacfg_node),
                         CPARACFG_NODE_TYPE_NAME(cparacfg_node),
                         CPARACFG_NODE_DATA_U16(cparacfg_node));
            return;
        }

        if(EC_TRUE == cparacfg_node_is_type(cparacfg_node, "uint32_t"))
        {
            sys_log(log, "cparacfg_node_print: cparacfg_node %p, "
                         "macro %s, type %s, val %u\n",
                         cparacfg_node,
                         CPARACFG_NODE_MACRO_NAME(cparacfg_node),
                         CPARACFG_NODE_TYPE_NAME(cparacfg_node),
                         CPARACFG_NODE_DATA_U32(cparacfg_node));
            return;
        }

        if(EC_TRUE == cparacfg_node_is_type(cparacfg_node, "uint64_t"))
        {
            sys_log(log, "cparacfg_node_print: cparacfg_node %p, "
                         "macro %s, type %s, val %lu\n",
                         cparacfg_node,
                         CPARACFG_NODE_MACRO_NAME(cparacfg_node),
                         CPARACFG_NODE_TYPE_NAME(cparacfg_node),
                         CPARACFG_NODE_DATA_U64(cparacfg_node));
            return;
        }

        if(EC_TRUE == cparacfg_node_is_type(cparacfg_node, "UINT32"))
        {
            sys_log(log, "cparacfg_node_print: cparacfg_node %p, "
                         "macro %s, type %s, val %ld\n",
                         cparacfg_node,
                         CPARACFG_NODE_MACRO_NAME(cparacfg_node),
                         CPARACFG_NODE_TYPE_NAME(cparacfg_node),
                         CPARACFG_NODE_DATA_WORD(cparacfg_node));
            return;
        }

        if(EC_TRUE == cparacfg_node_is_type(cparacfg_node, "REAL"))
        {
            sys_log(log, "cparacfg_node_print: cparacfg_node %p, "
                         "macro %s, type %s, val %.2f\n",
                         cparacfg_node,
                         CPARACFG_NODE_MACRO_NAME(cparacfg_node),
                         CPARACFG_NODE_TYPE_NAME(cparacfg_node),
                         CPARACFG_NODE_DATA_REAL(cparacfg_node));
            return;
        }

        if(EC_TRUE == cparacfg_node_is_type(cparacfg_node, "CSTRING"))
        {
            sys_log(log, "cparacfg_node_print: cparacfg_node %p, "
                         "macro %s, type %s, val %s\n",
                         cparacfg_node,
                         CPARACFG_NODE_MACRO_NAME(cparacfg_node),
                         CPARACFG_NODE_TYPE_NAME(cparacfg_node),
                         (char *)cstring_get_str(CPARACFG_NODE_DATA_CSTR(cparacfg_node)));
            return;
        }

        if(EC_TRUE == cparacfg_node_is_type(cparacfg_node, "SWITCH"))
        {
            sys_log(log, "cparacfg_node_print: cparacfg_node %p, "
                         "macro %s, type %s, val %s\n",
                         cparacfg_node,
                         CPARACFG_NODE_MACRO_NAME(cparacfg_node),
                         CPARACFG_NODE_TYPE_NAME(cparacfg_node),
                         c_switch_to_str(CPARACFG_NODE_DATA_SWITCH(cparacfg_node)));
            return;
        }

        sys_log(log, "cparacfg_node_print: cparacfg_node %p, "
                     "macro %s, type %s, val %lx\n",
                     cparacfg_node,
                     CPARACFG_NODE_MACRO_NAME(cparacfg_node),
                     CPARACFG_NODE_TYPE_NAME(cparacfg_node),
                     CPARACFG_NODE_DATA_U64(cparacfg_node));
    }
    return;
}

void cparacfg_node_print_plain(LOG *log, const CPARACFG_NODE *cparacfg_node)
{
    if(NULL_PTR != cparacfg_node)
    {
        if(EC_TRUE == cparacfg_node_is_type(cparacfg_node, "int"))
        {
            sys_print(log, "%32s = %d\n",
                           CPARACFG_NODE_MACRO_NAME(cparacfg_node),
                           CPARACFG_NODE_DATA_INT(cparacfg_node));
            return;
        }

        if(EC_TRUE == cparacfg_node_is_type(cparacfg_node, "uint8_t"))
        {
            sys_print(log, "%32s = %u\n",
                           CPARACFG_NODE_MACRO_NAME(cparacfg_node),
                           CPARACFG_NODE_DATA_U8(cparacfg_node));
            return;
        }

        if(EC_TRUE == cparacfg_node_is_type(cparacfg_node, "uint16_t"))
        {
            sys_log(log, "%32s = %u\n",
                         CPARACFG_NODE_MACRO_NAME(cparacfg_node),
                         CPARACFG_NODE_DATA_U16(cparacfg_node));
            return;
        }

        if(EC_TRUE == cparacfg_node_is_type(cparacfg_node, "uint32_t"))
        {
            sys_log(log, "%32s = %u\n",
                         CPARACFG_NODE_MACRO_NAME(cparacfg_node),
                         CPARACFG_NODE_DATA_U32(cparacfg_node));
            return;
        }

        if(EC_TRUE == cparacfg_node_is_type(cparacfg_node, "uint64_t"))
        {
            sys_log(log, "%32s = %lu\n",
                         CPARACFG_NODE_MACRO_NAME(cparacfg_node),
                         CPARACFG_NODE_DATA_U64(cparacfg_node));
            return;
        }

        if(EC_TRUE == cparacfg_node_is_type(cparacfg_node, "UINT32"))
        {
            sys_log(log, "%32s = %ld\n",
                         CPARACFG_NODE_MACRO_NAME(cparacfg_node),
                         CPARACFG_NODE_DATA_WORD(cparacfg_node));
            return;
        }

        if(EC_TRUE == cparacfg_node_is_type(cparacfg_node, "REAL"))
        {
            sys_log(log, "%32s = %.2f\n",
                         CPARACFG_NODE_MACRO_NAME(cparacfg_node),
                         CPARACFG_NODE_DATA_REAL(cparacfg_node));
            return;
        }

        if(EC_TRUE == cparacfg_node_is_type(cparacfg_node, "CSTRING"))
        {
            sys_log(log, "%32s = %s\n",
                         CPARACFG_NODE_MACRO_NAME(cparacfg_node),
                         (char *)cstring_get_str(CPARACFG_NODE_DATA_CSTR(cparacfg_node)));
            return;
        }

        if(EC_TRUE == cparacfg_node_is_type(cparacfg_node, "SWITCH"))
        {
            sys_log(log, "%32s = %s\n",
                         CPARACFG_NODE_MACRO_NAME(cparacfg_node),
                         c_switch_to_str(CPARACFG_NODE_DATA_SWITCH(cparacfg_node)));
            return;
        }

        sys_log(log, "%32s = %lx\n",
                     CPARACFG_NODE_MACRO_NAME(cparacfg_node),
                     CPARACFG_NODE_DATA_U64(cparacfg_node));
    }
    return;
}

EC_BOOL cparacfg_node_clone(const CPARACFG_NODE *cparacfg_node_src, CPARACFG_NODE *cparacfg_node_des)
{
    if(NULL_PTR != cparacfg_node_src && NULL_PTR != cparacfg_node_des)
    {
        CPARACFG_NODE_MACRO_NAME(cparacfg_node_des) = CPARACFG_NODE_MACRO_NAME(cparacfg_node_src);
        CPARACFG_NODE_TYPE_NAME(cparacfg_node_des)  = CPARACFG_NODE_TYPE_NAME(cparacfg_node_src);


        if(EC_TRUE == cparacfg_node_is_type(cparacfg_node_src, "int"))
        {
            CPARACFG_NODE_DATA_INT(cparacfg_node_des) = CPARACFG_NODE_DATA_INT(cparacfg_node_src);
            return (EC_TRUE);
        }

        if(EC_TRUE == cparacfg_node_is_type(cparacfg_node_src, "uint8_t"))
        {
            CPARACFG_NODE_DATA_U8(cparacfg_node_des) = CPARACFG_NODE_DATA_U8(cparacfg_node_src);
            return (EC_TRUE);
        }

        if(EC_TRUE == cparacfg_node_is_type(cparacfg_node_src, "uint16_t"))
        {
            CPARACFG_NODE_DATA_U16(cparacfg_node_des) = CPARACFG_NODE_DATA_U16(cparacfg_node_src);
            return (EC_TRUE);
        }

        if(EC_TRUE == cparacfg_node_is_type(cparacfg_node_src, "uint32_t"))
        {
            CPARACFG_NODE_DATA_U32(cparacfg_node_des) = CPARACFG_NODE_DATA_U32(cparacfg_node_src);
            return (EC_TRUE);
        }

        if(EC_TRUE == cparacfg_node_is_type(cparacfg_node_src, "uint64_t"))
        {
            CPARACFG_NODE_DATA_U64(cparacfg_node_des) = CPARACFG_NODE_DATA_U64(cparacfg_node_src);
            return (EC_TRUE);
        }

        if(EC_TRUE == cparacfg_node_is_type(cparacfg_node_src, "UINT32"))
        {
            CPARACFG_NODE_DATA_WORD(cparacfg_node_des) = CPARACFG_NODE_DATA_WORD(cparacfg_node_src);
            return (EC_TRUE);
        }

        if(EC_TRUE == cparacfg_node_is_type(cparacfg_node_src, "REAL"))
        {
            CPARACFG_NODE_DATA_REAL(cparacfg_node_des) = CPARACFG_NODE_DATA_REAL(cparacfg_node_src);
            return (EC_TRUE);
        }

        if(EC_TRUE == cparacfg_node_is_type(cparacfg_node_src, "CSTRING"))
        {
            CPARACFG_NODE_DATA_CSTR(cparacfg_node_des) = cstring_dup(CPARACFG_NODE_DATA_CSTR(cparacfg_node_src));
            if(NULL_PTR == CPARACFG_NODE_DATA_CSTR(cparacfg_node_des))
            {
                dbg_log(SEC_0052_CPARACFG, 0)(LOGSTDOUT, "cparacfg_node_clone: "
                                 "clone macro %s, type %s, val %s failed\n",
                                 CPARACFG_NODE_MACRO_NAME(cparacfg_node_src),
                                 CPARACFG_NODE_TYPE_NAME(cparacfg_node_src),
                                 (char *)cstring_get_str(CPARACFG_NODE_DATA_CSTR(cparacfg_node_src)));
            }
            return (EC_TRUE);
        }

        if(EC_TRUE == cparacfg_node_is_type(cparacfg_node_src, "SWITCH"))
        {
            CPARACFG_NODE_DATA_SWITCH(cparacfg_node_des) = CPARACFG_NODE_DATA_SWITCH(cparacfg_node_src);
            return (EC_TRUE);
        }

        dbg_log(SEC_0052_CPARACFG, 0)(LOGSTDOUT, "cparacfg_node_clone: "
                         "clone macro %s, invalid type %s, val %lx failed\n",
                         CPARACFG_NODE_MACRO_NAME(cparacfg_node_src),
                         CPARACFG_NODE_TYPE_NAME(cparacfg_node_src),
                         CPARACFG_NODE_DATA_U64(cparacfg_node_src));
    }

    return (EC_FALSE);
}

CPARACFG *cparacfg_new(const UINT32 this_tcid, const UINT32 this_rank)
{
    CPARACFG *cparacfg;
    alloc_static_mem(MM_CPARACFG, &cparacfg, LOC_CPARACFG_0003);
    if(NULL_PTR != cparacfg)
    {
        cparacfg_init(cparacfg, this_tcid, this_rank);
    }

    return (cparacfg);
}

EC_BOOL cparacfg_clean(CPARACFG *cparacfg)
{
    UINT32      idx;

    for(idx = 0; idx < CPARACFG_NODE_MAX_NUM; idx ++)
    {
        CPARACFG_NODE       *cparacfg_node;

        cparacfg_node = CPARACFG_NODE(cparacfg, idx);
        if(NULL_PTR == cparacfg_node)
        {
            continue;
        }

        cparacfg_node_free(cparacfg_node);
        CPARACFG_NODE(cparacfg, idx) = NULL_PTR;
    }
    return (EC_TRUE);
}

EC_BOOL cparacfg_free(CPARACFG *cparacfg)
{
    if(NULL_PTR != cparacfg)
    {
        cparacfg_clean(cparacfg);
        free_static_mem(MM_CPARACFG, cparacfg, LOC_CPARACFG_0004);
    }
    return (EC_TRUE);
}

EC_BOOL cparacfg_init(CPARACFG *cparacfg, const UINT32 this_tcid, const UINT32 this_rank)
{
    BSET((void *)cparacfg, 0x00, sizeof(CPARACFG));

    #define CPARACFG_ADD_NODE(cparacfg, idx, macro_name, type_name) \
        cparacfg_add_node(cparacfg, idx, #macro_name, #type_name, (void *)(uint64_t)CPARACFG_##macro_name##_DEF)

    CPARACFG_ADD_NODE(cparacfg,   0, THIS_TCID                                   , UINT32    );
    CPARACFG_ADD_NODE(cparacfg,   1, THIS_RANK                                   , UINT32    );
    CPARACFG_ADD_NODE(cparacfg,   2, PROC_CORE_ID                                , UINT32    );
    CPARACFG_ADD_NODE(cparacfg,   3, TASK_REQ_THREAD_MAX_NUM                     , UINT32    );
    CPARACFG_ADD_NODE(cparacfg,   4, TASK_RSP_THREAD_MAX_NUM                     , UINT32    );
    CPARACFG_ADD_NODE(cparacfg,   5, CTHREAD_STACK_MAX_SIZE                      , UINT32    );
    CPARACFG_ADD_NODE(cparacfg,   6, CTHREAD_STACK_GUARD_SIZE                    , UINT32    );
    CPARACFG_ADD_NODE(cparacfg,   7, TASK_SLOW_DOWN_MSEC                         , UINT32    );
    CPARACFG_ADD_NODE(cparacfg,   8, TASK_LIVE_NSEC                              , UINT32    );
    CPARACFG_ADD_NODE(cparacfg,   9, TASK_ZOMBIE_NSEC                            , UINT32    );
    CPARACFG_ADD_NODE(cparacfg,  10, CSOCKET_SO_SNDBUFF_SIZE                     , int       );
    CPARACFG_ADD_NODE(cparacfg,  11, CSOCKET_SO_RCVBUFF_SIZE                     , int       );
    CPARACFG_ADD_NODE(cparacfg,  12, CSOCKET_SO_SNDLOWAT_SIZE                    , int       );
    CPARACFG_ADD_NODE(cparacfg,  13, CSOCKET_SO_RCVLOWAT_SIZE                    , int       );
    CPARACFG_ADD_NODE(cparacfg,  14, CSOCKET_SO_SNDTIMEO_NSEC                    , int       );
    CPARACFG_ADD_NODE(cparacfg,  15, CSOCKET_SO_RCVTIMEO_NSEC                    , int       );
    CPARACFG_ADD_NODE(cparacfg,  16, CSOCKET_SO_KEEPALIVE_SWITCH                 , SWITCH    );
    CPARACFG_ADD_NODE(cparacfg,  17, CSOCKET_TCP_KEEPIDLE_NSEC                   , int       );
    CPARACFG_ADD_NODE(cparacfg,  18, CSOCKET_TCP_KEEPINTVL_NSEC                  , int       );
    CPARACFG_ADD_NODE(cparacfg,  19, CSOCKET_TCP_KEEPCNT_TIMES                   , int       );
    CPARACFG_ADD_NODE(cparacfg,  20, CSOCKET_UNIX_DOMAIN_SWITCH                  , SWITCH    );
    CPARACFG_ADD_NODE(cparacfg,  21, CSOCKET_SEND_ONCE_MAX_SIZE                  , UINT32    );
    CPARACFG_ADD_NODE(cparacfg,  22, CSOCKET_RECV_ONCE_MAX_SIZE                  , UINT32    );
    CPARACFG_ADD_NODE(cparacfg,  23, CSOCKET_CNODE_NUM                           , UINT32    );
    CPARACFG_ADD_NODE(cparacfg,  24, CSOCKET_HEARTBEAT_INTVL_NSEC                , UINT32    );
    CPARACFG_ADD_NODE(cparacfg,  25, FILE_LOG_MAX_RECORDS                        , UINT32    );
    CPARACFG_ADD_NODE(cparacfg,  26, CEPOLL_EVENT_MAX_NUM                        , UINT32    );
    CPARACFG_ADD_NODE(cparacfg,  27, SRV_ACCEPT_MAX_NUM                          , UINT32    );
    CPARACFG_ADD_NODE(cparacfg,  28, CONN_TIMEOUT_NSEC                           , UINT32    );
    CPARACFG_ADD_NODE(cparacfg,  29, CONN_TIMEOUT_MAX_NUM_PER_LOOP               , UINT32    );
    CPARACFG_ADD_NODE(cparacfg,  30, CDNS_TIMEOUT_NSEC                           , UINT32    );
    CPARACFG_ADD_NODE(cparacfg,  31, DNS_CACHE_SWITCH                            , SWITCH    );
    CPARACFG_ADD_NODE(cparacfg,  32, DNS_CACHE_EXPIRED_NSEC                      , UINT32    );
    CPARACFG_ADD_NODE(cparacfg,  33, HIGH_PRECISION_TIME_SWITCH                  , SWITCH    );
    CPARACFG_ADD_NODE(cparacfg,  34, CXFSNP_MAX_USED_RATIO                       , REAL      );
    CPARACFG_ADD_NODE(cparacfg,  35, CXFSDN_MAX_USED_RATIO                       , REAL      );
    CPARACFG_ADD_NODE(cparacfg,  36, CXFSNP_TRY_RETIRE_MAX_NUM                   , UINT32    );
    CPARACFG_ADD_NODE(cparacfg,  37, CXFSNP_TRY_RECYCLE_MAX_NUM                  , UINT32    );
    CPARACFG_ADD_NODE(cparacfg,  38, CXFSNP_CACHE_IN_MEM_SWITCH                  , SWITCH    );
    CPARACFG_ADD_NODE(cparacfg,  39, CXFSDN_CACHE_IN_MEM_SWITCH                  , SWITCH    );
    CPARACFG_ADD_NODE(cparacfg,  40, CXFSDN_CAMD_SWITCH                          , SWITCH    );
    CPARACFG_ADD_NODE(cparacfg,  41, CXFSDN_CAMD_MEM_DISK_SIZE                   , UINT32    );
    CPARACFG_ADD_NODE(cparacfg,  42, CXFS_LRU_MODEL_SWITCH                       , SWITCH    );
    CPARACFG_ADD_NODE(cparacfg,  43, CXFS_FIFO_MODEL_SWITCH                      , SWITCH    );
    CPARACFG_ADD_NODE(cparacfg,  44, CXFS_CAMD_OVERHEAD_SWITCH                   , SWITCH    );
    CPARACFG_ADD_NODE(cparacfg,  45, CXFS_CAMD_DISCARD_RATIO                     , UINT32    );
    CPARACFG_ADD_NODE(cparacfg,  46, CXFSNBD_DEVICE_SIZE                         , UINT32    );
    CPARACFG_ADD_NODE(cparacfg,  47, CXFSNBD_BLOCK_SIZE                          , UINT32    );
    CPARACFG_ADD_NODE(cparacfg,  48, CXFSNBD_TIMEOUT_NSEC                        , UINT32    );
    CPARACFG_ADD_NODE(cparacfg,  49, CMON_CONHASH_SWITCH                         , SWITCH    );
    CPARACFG_ADD_NODE(cparacfg,  50, CMON_CONHASH_REPLICAS                       , uint16_t  );
    CPARACFG_ADD_NODE(cparacfg,  51, CMON_MAGLEV_SWITCH                          , SWITCH    );
    CPARACFG_ADD_NODE(cparacfg,  52, CMON_HOT_PATH_SWITCH                        , SWITCH    );
    CPARACFG_ADD_NODE(cparacfg,  53, NGX_LUA_OUTPUT_BLOCKING_LOWAT               , uint32_t  );
    CPARACFG_ADD_NODE(cparacfg,  54, NGX_EPOLL_TIMEOUT_MSEC                      , uint32_t  );
    CPARACFG_ADD_NODE(cparacfg,  55, NGX_HTTP_REQ_NUM_PER_LOOP                   , uint32_t  );
    CPARACFG_ADD_NODE(cparacfg,  56, XFS_HTTP_REQ_NUM_PER_LOOP                   , uint32_t  );
    CPARACFG_ADD_NODE(cparacfg,  57, SSL_CERTIFICATE_FILE_NAME_CSTR              , CSTRING   );
    CPARACFG_ADD_NODE(cparacfg,  58, SSL_PRIVATE_KEY_FILE_NAME_CSTR              , CSTRING   );
    CPARACFG_ADD_NODE(cparacfg,  59, CUNIXPACKET_AGENT_HTTP_REQ_SERVER_CSTR      , CSTRING   );
    CPARACFG_ADD_NODE(cparacfg,  60, CUNIXPACKET_AGENT_HTTP_REQ_DOMAIN_CSTR      , CSTRING   );
    CPARACFG_ADD_NODE(cparacfg,  61, CUNIXPACKET_AGENT_HTTP_REQ_URI_CSTR         , CSTRING   );
    CPARACFG_ADD_NODE(cparacfg,  62, CUNIXPACKET_AGENT_HTTP_REQ_OP_CSTR          , CSTRING   );
    CPARACFG_ADD_NODE(cparacfg,  63, CUNIXPACKET_AGENT_HTTP_REQ_ACL_TOKEN_CSTR   , CSTRING   );
    CPARACFG_ADD_NODE(cparacfg,  64, CUNIXPACKET_AGENT_HTTP_REQ_EXPIRED_NSEC     , UINT32    );
    CPARACFG_ADD_NODE(cparacfg,  65, CUNIXPACKET_AGENT_UDS_PACKET_MAX_SIZE       , uint32_t  );
    CPARACFG_ADD_NODE(cparacfg,  66, CUNIXPACKET_AGENT_UDS_PACKET_BUF_SIZE       , uint32_t  );
    CPARACFG_ADD_NODE(cparacfg,  67, CUNIXPACKET_AGENT_UDS_PACKET_CACHE_MAX_NUM  , uint32_t  );
    CPARACFG_ADD_NODE(cparacfg,  68, CUNIXPACKET_AGENT_UDS_PACKET_SENT_MAX_NUM   , uint32_t  );
    CPARACFG_ADD_NODE(cparacfg,  69, CUNIXPACKET_AGENT_UDS_PACKET_RECV_MAX_NUM   , uint32_t  );
    CPARACFG_ADD_NODE(cparacfg,  70, TDNS_RESOLVE_SWITCH                         , SWITCH    );
    CPARACFG_ADD_NODE(cparacfg,  71, TDNS_RESOLVE_TIMEOUT_NSEC                   , UINT32    );
    CPARACFG_ADD_NODE(cparacfg,  72, CAMD_SSD_AIO_REQ_MAX_NUM                    , UINT32    );
    CPARACFG_ADD_NODE(cparacfg,  73, CAMD_SATA_AIO_REQ_MAX_NUM                   , UINT32    );
    CPARACFG_ADD_NODE(cparacfg,  74, CAMD_SATA_DEGRADE_SSD_SWITCH                , SWITCH    );
    CPARACFG_ADD_NODE(cparacfg,  75, CAMD_SSD_UPGRADE_MEM_SWITCH                 , SWITCH    );
    CPARACFG_ADD_NODE(cparacfg,  76, CAMD_SATA_UPGRADE_MEM_SWITCH                , SWITCH    );
    CPARACFG_ADD_NODE(cparacfg,  77, CAMD_CHECK_PAGE_USED_SWITCH                 , SWITCH    );
    CPARACFG_ADD_NODE(cparacfg,  78, CMC_TRY_RETIRE_MAX_NUM                      , UINT32    );
    CPARACFG_ADD_NODE(cparacfg,  79, CMC_TRY_RECYCLE_MAX_NUM                     , UINT32    );
    CPARACFG_ADD_NODE(cparacfg,  80, CMC_SCAN_RETIRE_MAX_NUM                     , UINT32    );
    CPARACFG_ADD_NODE(cparacfg,  81, CMC_FLOW_CONTROL_SWITCH                     , SWITCH    );
    CPARACFG_ADD_NODE(cparacfg,  82, CMC_PROCESS_DEGRADE_MAX_NUM                 , UINT32    );
    CPARACFG_ADD_NODE(cparacfg,  83, CMC_SCAN_DEGRADE_MAX_NUM                    , UINT32    );
    CPARACFG_ADD_NODE(cparacfg,  84, CMC_DEGRADE_HI_RATIO                        , REAL      );
    CPARACFG_ADD_NODE(cparacfg,  85, CMC_DEGRADE_MD_RATIO                        , REAL      );
    CPARACFG_ADD_NODE(cparacfg,  86, CMC_DEGRADE_LO_RATIO                        , REAL      );
    CPARACFG_ADD_NODE(cparacfg,  87, CMC_LRU_MODEL_SWITCH                        , SWITCH    );
    CPARACFG_ADD_NODE(cparacfg,  88, CMC_FIFO_MODEL_SWITCH                       , SWITCH    );
    CPARACFG_ADD_NODE(cparacfg,  89, CDC_TRY_RETIRE_MAX_NUM                      , UINT32    );
    CPARACFG_ADD_NODE(cparacfg,  90, CDC_TRY_RECYCLE_MAX_NUM                     , UINT32    );
    CPARACFG_ADD_NODE(cparacfg,  91, CDC_SCAN_RETIRE_MAX_NUM                     , UINT32    );
    CPARACFG_ADD_NODE(cparacfg,  92, CDC_READ_CACHE_SWITCH                       , SWITCH    );
    CPARACFG_ADD_NODE(cparacfg,  93, CDC_FLOW_CONTROL_SWITCH                     , SWITCH    );
    CPARACFG_ADD_NODE(cparacfg,  94, CDC_PROCESS_DEGRADE_MAX_NUM                 , UINT32    );
    CPARACFG_ADD_NODE(cparacfg,  95, CDC_SCAN_DEGRADE_MAX_NUM                    , UINT32    );
    CPARACFG_ADD_NODE(cparacfg,  96, CDC_DEGRADE_HI_RATIO                        , REAL      );
    CPARACFG_ADD_NODE(cparacfg,  97, CDC_DEGRADE_MD_RATIO                        , REAL      );
    CPARACFG_ADD_NODE(cparacfg,  98, CDC_DEGRADE_LO_RATIO                        , REAL      );
    CPARACFG_ADD_NODE(cparacfg,  99, CDC_LRU_MODEL_SWITCH                        , SWITCH    );
    CPARACFG_ADD_NODE(cparacfg, 100, CDC_FIFO_MODEL_SWITCH                       , SWITCH    );

    #undef CPARACFG_ADD_NODE

    /*revise*/
    CPARACFG_NODE_DATA_U32(CPARACFG_NODE(cparacfg, 0)) = this_tcid;
    CPARACFG_NODE_DATA_U32(CPARACFG_NODE(cparacfg, 1)) = this_rank;

    /*log level*/
    log_level_tab_init(CPARACFG_LOG_LEVEL_TAB(cparacfg), SEC_NONE_END, LOG_DEFAULT_DBG_LEVEL);

    return (EC_TRUE);
}

CPARACFG_NODE *cparacfg_search(CPARACFG *cparacfg, const char *macro_name)
{
    UINT32      idx;

    for(idx = 0; idx < CPARACFG_NODE_MAX_NUM; idx ++)
    {
        CPARACFG_NODE       *cparacfg_node;

        cparacfg_node = CPARACFG_NODE(cparacfg, idx);
        if(NULL_PTR == cparacfg_node)
        {
            continue;
        }

        if(NULL_PTR != CPARACFG_NODE_MACRO_NAME(cparacfg_node)
        && NULL_PTR != macro_name
        && 0 == STRCMP(CPARACFG_NODE_MACRO_NAME(cparacfg_node), macro_name))
        {
            return (cparacfg_node);
        }
    }
    return (NULL_PTR);
}

EC_BOOL cparacfg_add_node(CPARACFG *cparacfg, const UINT32 idx, const char *macro_name, const char *type_name, void *data)
{
    CPARACFG_NODE       *cparacfg_node;

    if(NULL_PTR == macro_name)
    {
        dbg_log(SEC_0052_CPARACFG, 0)(LOGSTDOUT, "error:cparacfg_add_node: "
                                                 "macro is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == type_name)
    {
        dbg_log(SEC_0052_CPARACFG, 0)(LOGSTDOUT, "error:cparacfg_add_node: "
                                                 "type is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR != CPARACFG_NODE(cparacfg, idx))
    {
        dbg_log(SEC_0052_CPARACFG, 0)(LOGSTDOUT, "error:cparacfg_add_node: "
                                                 "node[%ld] is not null\n",
                                                 idx);
        return (EC_FALSE);
    }

    if(NULL_PTR != cparacfg_search(cparacfg, macro_name))
    {
        dbg_log(SEC_0052_CPARACFG, 0)(LOGSTDOUT, "error:cparacfg_add_node: "
                                                 "duplicate macro '%s'\n",
                                                 macro_name);
        return (EC_FALSE);
    }

    cparacfg_node = cparacfg_node_new();
    if(NULL_PTR == cparacfg_node)
    {
        dbg_log(SEC_0052_CPARACFG, 0)(LOGSTDOUT, "error:cparacfg_add_node: "
                                                 "new cparacfg_node failed\n");
        return (EC_FALSE);
    }

    CPARACFG_NODE_MACRO_NAME(cparacfg_node) = macro_name;
    CPARACFG_NODE_TYPE_NAME(cparacfg_node)  = type_name;
    if(EC_TRUE == cparacfg_node_is_type(cparacfg_node, "int"))
    {
        CPARACFG_NODE_DATA_INT(cparacfg_node) = (int)(uint64_t)data;

        CPARACFG_NODE(cparacfg, idx) = cparacfg_node;

        dbg_log(SEC_0052_CPARACFG, 9)(LOGSTDOUT, "cparacfg_add_node: "
                        "[%3d] macro %s, type %s, val %d\n",
                        idx,
                        CPARACFG_NODE_MACRO_NAME(cparacfg_node),
                        CPARACFG_NODE_TYPE_NAME(cparacfg_node),
                        CPARACFG_NODE_DATA_INT(cparacfg_node));
        return (EC_TRUE);
    }

    if(EC_TRUE == cparacfg_node_is_type(cparacfg_node, "uint8_t"))
    {
        CPARACFG_NODE_DATA_U8(cparacfg_node) = (uint8_t)(uint64_t)data;

        CPARACFG_NODE(cparacfg, idx) = cparacfg_node;

        dbg_log(SEC_0052_CPARACFG, 9)(LOGSTDOUT, "cparacfg_add_node: "
                     "[%3d] macro %s, type %s, val %u\n",
                     idx,
                     CPARACFG_NODE_MACRO_NAME(cparacfg_node),
                     CPARACFG_NODE_TYPE_NAME(cparacfg_node),
                     CPARACFG_NODE_DATA_U8(cparacfg_node));
        return (EC_TRUE);
    }

    if(EC_TRUE == cparacfg_node_is_type(cparacfg_node, "uint16_t"))
    {
        CPARACFG_NODE_DATA_U16(cparacfg_node) = (uint16_t)(uint64_t)data;

        CPARACFG_NODE(cparacfg, idx) = cparacfg_node;

        dbg_log(SEC_0052_CPARACFG, 9)(LOGSTDOUT, "cparacfg_add_node: "
                     "[%3d] macro %s, type %s, val %u\n",
                     idx,
                     CPARACFG_NODE_MACRO_NAME(cparacfg_node),
                     CPARACFG_NODE_TYPE_NAME(cparacfg_node),
                     CPARACFG_NODE_DATA_U16(cparacfg_node));
        return (EC_TRUE);
    }

    if(EC_TRUE == cparacfg_node_is_type(cparacfg_node, "uint32_t"))
    {
        CPARACFG_NODE_DATA_U32(cparacfg_node) = (uint32_t)(uint64_t)data;

        CPARACFG_NODE(cparacfg, idx) = cparacfg_node;

        dbg_log(SEC_0052_CPARACFG, 9)(LOGSTDOUT, "cparacfg_add_node: "
                     "[%3d] macro %s, type %s, val %u\n",
                     idx,
                     CPARACFG_NODE_MACRO_NAME(cparacfg_node),
                     CPARACFG_NODE_TYPE_NAME(cparacfg_node),
                     CPARACFG_NODE_DATA_U32(cparacfg_node));
        return (EC_TRUE);
    }

    if(EC_TRUE == cparacfg_node_is_type(cparacfg_node, "uint64_t"))
    {
        CPARACFG_NODE_DATA_U64(cparacfg_node) = (uint64_t)data;

        CPARACFG_NODE(cparacfg, idx) = cparacfg_node;

        dbg_log(SEC_0052_CPARACFG, 9)(LOGSTDOUT, "cparacfg_add_node: "
                     "[%3d] macro %s, type %s, val %lu\n",
                     idx,
                     CPARACFG_NODE_MACRO_NAME(cparacfg_node),
                     CPARACFG_NODE_TYPE_NAME(cparacfg_node),
                     CPARACFG_NODE_DATA_U64(cparacfg_node));
        return (EC_TRUE);
    }

    if(EC_TRUE == cparacfg_node_is_type(cparacfg_node, "UINT32"))
    {
        CPARACFG_NODE_DATA_WORD(cparacfg_node) = (UINT32)data;

        CPARACFG_NODE(cparacfg, idx) = cparacfg_node;

        dbg_log(SEC_0052_CPARACFG, 9)(LOGSTDOUT, "cparacfg_add_node: "
                     "[%3d] macro %s, type %s, val %ld\n",
                     idx,
                     CPARACFG_NODE_MACRO_NAME(cparacfg_node),
                     CPARACFG_NODE_TYPE_NAME(cparacfg_node),
                     CPARACFG_NODE_DATA_WORD(cparacfg_node));
        return (EC_TRUE);
    }

    if(EC_TRUE == cparacfg_node_is_type(cparacfg_node, "REAL"))
    {
        CPARACFG_NODE_DATA_REAL(cparacfg_node) = (REAL)(uint64_t)data;

        CPARACFG_NODE(cparacfg, idx) = cparacfg_node;

        dbg_log(SEC_0052_CPARACFG, 9)(LOGSTDOUT, "cparacfg_add_node: "
                     "[%3d] macro %s, type %s, val %.2f\n",
                     idx,
                     CPARACFG_NODE_MACRO_NAME(cparacfg_node),
                     CPARACFG_NODE_TYPE_NAME(cparacfg_node),
                     CPARACFG_NODE_DATA_REAL(cparacfg_node));
        return (EC_TRUE);
    }

    if(EC_TRUE == cparacfg_node_is_type(cparacfg_node, "CSTRING"))
    {
        CPARACFG_NODE_DATA_CSTR(cparacfg_node) = cstring_new((UINT8 *)data, LOC_CPARACFG_0005);
        if(NULL_PTR == CPARACFG_NODE_DATA_CSTR(cparacfg_node))
        {
            dbg_log(SEC_0052_CPARACFG, 0)(LOGSTDOUT, "error:cparacfg_add_node: "
                         "[%3d] macro %s, type %s, val %s failed\n",
                         idx,
                         CPARACFG_NODE_MACRO_NAME(cparacfg_node),
                         CPARACFG_NODE_TYPE_NAME(cparacfg_node),
                         (char *)cstring_get_str(CPARACFG_NODE_DATA_CSTR(cparacfg_node)));

            cparacfg_node_free(cparacfg_node);
            return (EC_FALSE);
        }

        CPARACFG_NODE(cparacfg, idx) = cparacfg_node;

        dbg_log(SEC_0052_CPARACFG, 9)(LOGSTDOUT, "cparacfg_add_node: "
                     "[%3d] macro %s, type %s, val %s\n",
                     idx,
                     CPARACFG_NODE_MACRO_NAME(cparacfg_node),
                     CPARACFG_NODE_TYPE_NAME(cparacfg_node),
                     (char *)cstring_get_str(CPARACFG_NODE_DATA_CSTR(cparacfg_node)));
        return (EC_TRUE);
    }

    if(EC_TRUE == cparacfg_node_is_type(cparacfg_node, "SWITCH"))
    {
        CPARACFG_NODE_DATA_SWITCH(cparacfg_node) = (UINT32)data;

        CPARACFG_NODE(cparacfg, idx) = cparacfg_node;

        dbg_log(SEC_0052_CPARACFG, 9)(LOGSTDOUT, "cparacfg_add_node: "
                     "[%3d] macro %s, type %s, val %s\n",
                     idx,
                     CPARACFG_NODE_MACRO_NAME(cparacfg_node),
                     CPARACFG_NODE_TYPE_NAME(cparacfg_node),
                     c_switch_to_str(CPARACFG_NODE_DATA_SWITCH(cparacfg_node)));
        return (EC_TRUE);
    }

    dbg_log(SEC_0052_CPARACFG, 0)(LOGSTDOUT, "error:cparacfg_add_node: "
                 "[%3d] macro %s, invalid type %s, val %lx\n",
                 idx,
                 CPARACFG_NODE_MACRO_NAME(cparacfg_node),
                 CPARACFG_NODE_TYPE_NAME(cparacfg_node),
                 CPARACFG_NODE_DATA_U64(cparacfg_node));

    cparacfg_node_free(cparacfg_node);

    return (EC_FALSE);
}

EC_BOOL cparacfg_clone(const CPARACFG *cparacfg_src, CPARACFG *cparacfg_des)
{
    UINT32      idx;

    for(idx = 0; idx < CPARACFG_NODE_MAX_NUM; idx ++)
    {
        CPARACFG_NODE       *cparacfg_node_src;
        CPARACFG_NODE       *cparacfg_node_des;

        cparacfg_node_src = CPARACFG_NODE(cparacfg_src, idx);
        if(NULL_PTR == cparacfg_node_src)
        {
            continue;
        }

        cparacfg_node_des = cparacfg_node_new();
        if(NULL_PTR == cparacfg_node_des)
        {
            dbg_log(SEC_0052_CPARACFG, 0)(LOGSTDOUT, "error:cparacfg_clone: "
                                                     "new node[%ld] failed\n",
                                                     idx);
            return (EC_FALSE);
        }

        if(EC_FALSE == cparacfg_node_clone(cparacfg_node_src, cparacfg_node_des))
        {
            dbg_log(SEC_0052_CPARACFG, 0)(LOGSTDOUT, "error:cparacfg_clone: "
                                                     "clone node[%ld] macro %s, type %s failed\n",
                                                     idx,
                                                     CPARACFG_NODE_MACRO_NAME(cparacfg_node_src),
                                                     CPARACFG_NODE_TYPE_NAME(cparacfg_node_src));
            cparacfg_node_free(cparacfg_node_des);
            return (EC_FALSE);
        }

        CPARACFG_NODE(cparacfg_des, idx) = cparacfg_node_des;
    }

    BCOPY(CPARACFG_LOG_LEVEL_TAB(cparacfg_src),
          CPARACFG_LOG_LEVEL_TAB(cparacfg_des),
          SEC_NONE_END * sizeof(UINT32));
    return (EC_TRUE);
}

EC_BOOL cparacfg_cmp(const CPARACFG *cparacfg_1st, const CPARACFG *cparacfg_2nd)
{
    if(CPARACFG_THIS_TCID(cparacfg_1st) != CPARACFG_THIS_TCID(cparacfg_2nd) )
    {
        return (EC_FALSE);
    }

    if(CPARACFG_THIS_RANK(cparacfg_1st) != CPARACFG_THIS_RANK(cparacfg_2nd) )
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

void cparacfg_print(LOG *log, const CPARACFG *cparacfg)
{
    UINT32      idx;

    if(NULL_PTR == cparacfg)
    {
        return;
    }

    sys_log(log, "cparacfg %p:\n", cparacfg);

    for(idx = 0; NULL_PTR != cparacfg && idx < CPARACFG_NODE_MAX_NUM; idx ++)
    {
        CPARACFG_NODE       *cparacfg_node;

        cparacfg_node = CPARACFG_NODE(cparacfg, idx);
        if(NULL_PTR == cparacfg_node)
        {
            continue;
        }

        if(EC_TRUE == cparacfg_node_is_type(cparacfg_node, "int"))
        {
            sys_log(log, "[%3d] %32s = %d\n", idx,
                         CPARACFG_NODE_MACRO_NAME(cparacfg_node),
                         CPARACFG_NODE_DATA_INT(cparacfg_node));
            continue;
        }

        if(EC_TRUE == cparacfg_node_is_type(cparacfg_node, "uint8_t"))
        {
            sys_log(log, "[%3d] %32s = %u\n", idx,
                         CPARACFG_NODE_MACRO_NAME(cparacfg_node),
                         CPARACFG_NODE_DATA_U32(cparacfg_node));
            continue;
        }

        if(EC_TRUE == cparacfg_node_is_type(cparacfg_node, "uint16_t"))
        {
            sys_log(log, "[%3d] %32s = %u\n", idx,
                         CPARACFG_NODE_MACRO_NAME(cparacfg_node),
                         CPARACFG_NODE_DATA_U32(cparacfg_node));
            continue;
        }

        if(EC_TRUE == cparacfg_node_is_type(cparacfg_node, "uint32_t"))
        {
            sys_log(log, "[%3d] %32s = %u\n", idx,
                         CPARACFG_NODE_MACRO_NAME(cparacfg_node),
                         CPARACFG_NODE_DATA_U32(cparacfg_node));
            continue;
        }

        if(EC_TRUE == cparacfg_node_is_type(cparacfg_node, "uint64_t"))
        {
            sys_log(log, "[%3d] %32s = %lu\n", idx,
                         CPARACFG_NODE_MACRO_NAME(cparacfg_node),
                         CPARACFG_NODE_DATA_U32(cparacfg_node));
            continue;
        }

        if(EC_TRUE == cparacfg_node_is_type(cparacfg_node, "UINT32"))
        {
            sys_log(log, "[%3d] %32s = %ld\n", idx,
                         CPARACFG_NODE_MACRO_NAME(cparacfg_node),
                         CPARACFG_NODE_DATA_U32(cparacfg_node));
            continue;
        }

        if(EC_TRUE == cparacfg_node_is_type(cparacfg_node, "REAL"))
        {
            sys_log(log, "[%3d] %32s = %.2f\n", idx,
                         CPARACFG_NODE_MACRO_NAME(cparacfg_node),
                         CPARACFG_NODE_DATA_U32(cparacfg_node));
            continue;
        }

        if(EC_TRUE == cparacfg_node_is_type(cparacfg_node, "CSTRING"))
        {
            sys_log(log, "[%3d] %32s = %s\n", idx,
                         CPARACFG_NODE_MACRO_NAME(cparacfg_node),
                         (char *)cstring_get_str(CPARACFG_NODE_DATA_CSTR(cparacfg_node)));
            continue;
        }

        if(EC_TRUE == cparacfg_node_is_type(cparacfg_node, "SWITCH"))
        {
            sys_log(log, "[%3d] %32s = %s\n", idx,
                         CPARACFG_NODE_MACRO_NAME(cparacfg_node),
                         c_switch_to_str(CPARACFG_NODE_DATA_SWITCH(cparacfg_node)));
            continue;
        }

        sys_log(log, "[%3d] (UNKNOWN)%32s = %lx\n", idx,
                     CPARACFG_NODE_MACRO_NAME(cparacfg_node),
                     CPARACFG_NODE_DATA_U64(cparacfg_node));
    }

    return;
}

void cparacfg_json(json_object *obj, const CPARACFG *cparacfg)
{
    UINT32      idx;

    for(idx = 0; idx < CPARACFG_NODE_MAX_NUM; idx ++)
    {
        CPARACFG_NODE       *cparacfg_node;

        cparacfg_node = CPARACFG_NODE(cparacfg, idx);
        if(NULL_PTR == cparacfg_node)
        {
            continue;
        }

        if(NULL_PTR != CPARACFG_NODE_TYPE_NAME(cparacfg_node)
        && 0 == STRCMP("int", CPARACFG_NODE_TYPE_NAME(cparacfg_node)))
        {
            json_object_add_k_int32(obj,
                    CPARACFG_NODE_MACRO_NAME(cparacfg_node),
                    CPARACFG_NODE_DATA_INT(cparacfg_node));
            continue;
        }

        if(NULL_PTR != CPARACFG_NODE_TYPE_NAME(cparacfg_node)
        && 0 == STRCMP("uint8_t", CPARACFG_NODE_TYPE_NAME(cparacfg_node)))
        {
            json_object_add_k_int32(obj,
                    CPARACFG_NODE_MACRO_NAME(cparacfg_node),
                    CPARACFG_NODE_DATA_U8(cparacfg_node));
            continue;
        }

        if(NULL_PTR != CPARACFG_NODE_TYPE_NAME(cparacfg_node)
        && 0 == STRCMP("uint16_t", CPARACFG_NODE_TYPE_NAME(cparacfg_node)))
        {
            json_object_add_k_int32(obj,
                    CPARACFG_NODE_MACRO_NAME(cparacfg_node),
                    CPARACFG_NODE_DATA_U16(cparacfg_node));
            continue;
        }

        if(NULL_PTR != CPARACFG_NODE_TYPE_NAME(cparacfg_node)
        && 0 == STRCMP("uint32_t", CPARACFG_NODE_TYPE_NAME(cparacfg_node)))
        {
            json_object_add_k_int32(obj,
                    CPARACFG_NODE_MACRO_NAME(cparacfg_node),
                    CPARACFG_NODE_DATA_U32(cparacfg_node));
            continue;
        }

        if(NULL_PTR != CPARACFG_NODE_TYPE_NAME(cparacfg_node)
        && 0 == STRCMP("uint64_t", CPARACFG_NODE_TYPE_NAME(cparacfg_node)))
        {
            json_object_add_k_int64(obj,
                    CPARACFG_NODE_MACRO_NAME(cparacfg_node),
                    CPARACFG_NODE_DATA_U64(cparacfg_node));
            continue;
        }

        if(NULL_PTR != CPARACFG_NODE_TYPE_NAME(cparacfg_node)
        && 0 == STRCMP("UINT32", CPARACFG_NODE_TYPE_NAME(cparacfg_node)))
        {
            json_object_add_k_int64(obj,
                    CPARACFG_NODE_MACRO_NAME(cparacfg_node),
                    CPARACFG_NODE_DATA_WORD(cparacfg_node));
            continue;
        }

        if(NULL_PTR != CPARACFG_NODE_TYPE_NAME(cparacfg_node)
        && 0 == STRCMP("REAL", CPARACFG_NODE_TYPE_NAME(cparacfg_node)))
        {
            json_object_add_k_double(obj,
                    CPARACFG_NODE_MACRO_NAME(cparacfg_node),
                    CPARACFG_NODE_DATA_REAL(cparacfg_node));
            continue;
        }

        if(NULL_PTR != CPARACFG_NODE_TYPE_NAME(cparacfg_node)
        && 0 == STRCMP("CSTRING", CPARACFG_NODE_TYPE_NAME(cparacfg_node)))
        {
            json_object_add_kv(obj,
                    CPARACFG_NODE_MACRO_NAME(cparacfg_node),
                    (char *)cstring_get_str(CPARACFG_NODE_DATA_CSTR(cparacfg_node)));
            continue;
        }

        if(NULL_PTR != CPARACFG_NODE_TYPE_NAME(cparacfg_node)
        && 0 == STRCMP("SWITCH", CPARACFG_NODE_TYPE_NAME(cparacfg_node)))
        {
            json_object_add_k_int64(obj,
                    CPARACFG_NODE_MACRO_NAME(cparacfg_node),
                    CPARACFG_NODE_DATA_SWITCH(cparacfg_node));
            continue;
        }
    }

    return;
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/
