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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <malloc.h>

#include "mm.h"
#include "debug.h"
#include "log.h"
#include "task.h"
#include "api_cmd.h"
#include "mod.inc"
#include "super.h"

#include "clist.h"
#include "cstack.h"
#include "cset.h"
#include "cqueue.h"
#include "cdequeue.h"
#include "cvector.h"
#include "cstring.h"
#include "crange.h"

#include "tcnode.h"
#include "cmutex.h"
#include "cthread.h"
#include "kbuff.h"
#include "csocket.h"
#include "ctimer.h"
#include "csys.h"
#include "taskcfg.inc"
#include "crouter.inc"
#include "chashnode.h"
#include "chashvec.h"
#include "chashdb.h"
#include "cbloom.h"
#include "cload.h"
#include "csrv.h"
#include "cproc.h"
#include "csession.h"
#include "cbytes.h"
#include "cbitmap.h"
#include "cbtimer.h"
#include "cxml.h"
#include "coroutine.h"
#include "cparacfg.inc"
#include "crb.h"
#include "crbbase.h"
#include "cpgb.h"
#include "cpgd.h"
#include "cpgv.h"
#include "crfs.h"
#include "crfsdn.h"
#include "crfsnp.h"
#include "crfsnpmgr.h"
#include "crfshttp.h"
#include "cxfspgb.h"
#include "cxfspgd.h"
#include "cxfspgv.h"
#include "cxfs.h"
#include "cxfsdn.h"
#include "cxfsnp.h"
#include "cxfsnpmgr.h"
#include "cxfshttp.h"
#include "cxfsop.h"
#include "cmon.h"
#include "cconhash.h"
#include "cmaglev.h"
#include "cepoll.h"
#include "csem.h"
#include "cstrkv.h"
#include "cbuffer.h"
#include "chttp.h"
#include "chttps.h"
#include "crfshttp.h"
#include "chunk.h"
#include "cmd5.h"

#include "chttp.inc"
#include "chttps.inc"
#include "cdns.inc"

#include "cexpat.h"
#include "ctdns.h"
#include "ctdnsnp.h"
#include "ctdnsnpmgr.h"
#include "ctdnssv.h"
#include "ctdnssvmgr.h"
#include "cdetectn.h"
#include "cp2p.h"
#include "ccallback.h"
#include "cagent.h"
#include "cping.h"

#include "cmcpgd.h"
#include "cmcpgv.h"
#include "cmcdn.h"
#include "cmcnp.h"

#include "cdcpgd.h"
#include "cdcpgv.h"
#include "cdcdn.h"
#include "cdcnp.h"
#include "cdc.h"

#include "caio.h"
#include "camd.h"
#include "cfc.h"
#include "cmmap.h"
#include "cmsync.h"

#include "csdisc.h"

#include "cdnscache.h"
#include "ceventfd.h"

#include "ctimeout.h"

#if (SWITCH_ON == NGX_BGN_SWITCH)
#include "cngx.h"
#include "cngx_mod.h"
#endif/*(SWITCH_ON == NGX_BGN_SWITCH)*/

/* memory manager will manage all node blocks and node block manage its nodes.*/
/* each memory manager manage only one type of node block */
/* and all nodes in a certain node block has the same type */
MM_MAN g_mem_manager[ MM_END ];
EC_BOOL g_mem_init_flag = EC_FALSE;

static MM_LOC g_mm_loc_tbl[] = {
#include "loc_tbl.inc"
};

//#if (SWITCH_ON == CROUTINE_SUPPORT_CTHREAD_SWITCH)
#define MAN_CMUTEX(pMan)                       ((CMUTEX *)&((pMan)->cmutex))
#define MAN_INIT_LOCK(pMan, __location__)      cmutex_init(MAN_CMUTEX(pMan), CMUTEX_PROCESS_PRIVATE, __location__)
#define MAN_CLEAN_LOCK(pMan, __location__)     cmutex_clean(MAN_CMUTEX(pMan), __location__)
#define MAN_LOCK(pMan, __location__)           cmutex_lock(MAN_CMUTEX(pMan), __location__)
#define MAN_UNLOCK(pMan, __location__)         cmutex_unlock(MAN_CMUTEX(pMan), __location__)
//#endif/*(SWITCH_ON == CROUTINE_SUPPORT_CTHREAD_SWITCH)*/

#if 0
#if (SWITCH_ON == CROUTINE_SUPPORT_COROUTINE_SWITCH)
#define MAN_INIT_LOCK(pMan, __location__)      do{}while(0)
#define MAN_CLEAN_LOCK(pMan, __location__)     do{}while(0)
#define MAN_LOCK(pMan, __location__)           do{}while(0)
#define MAN_UNLOCK(pMan, __location__)         do{}while(0)
#endif/*(SWITCH_ON == CROUTINE_SUPPORT_COROUTINE_SWITCH)*/
#endif


#define MM_ASSERT ASSERT
#define MM_DEBUG  SWITCH_OFF

/**
*
*   Initilize the memory managers including managed node type, node size and node number per node block.
*   This function does not allocate any dynamic memory. But before allocate any memory, the memory manager
*   has to be initialized at first.
*
**/
#define MM_MGR_INIT(mm_type, block_num, type_size, __location__) do{\
    pMan = &(g_mem_manager[ (mm_type) ]);\
    pMan->type = (mm_type);\
    pMan->name = (UINT8 *)"UNDEF";\
    pMan->nodenumsum = 0;\
    pMan->nodeblocknum = 0;\
    pMan->nodenumperblock = (block_num);\
    pMan->typesize = (type_size);\
    pMan->maxusedsum = 0;\
    pMan->curusedsum = 0;\
    MAN_LINKNODEBLOCK_HEAD_INIT(pMan);\
    MAN_FREENODEBLOCK_HEAD_INIT(pMan);\
    MAN_INIT_LOCK(pMan, (__location__));/*init lock*/\
}while(0)

#define MM_MGR_DEF(mm_type, mm_name, min_block_num, type_size, __location__) do{\
    pMan = &(g_mem_manager[ (mm_type) ]);\
    pMan->type = (mm_type);\
    pMan->name = (UINT8 *)strdup((char *)mm_name);\
    pMan->nodenumsum = 0;\
    pMan->nodeblocknum = 0;\
    pMan->nodenumperblock = DMAX(min_block_num, calc_block_num_min(type_size));\
    pMan->typesize = (type_size);\
    pMan->maxusedsum = 0;\
    pMan->curusedsum = 0;\
    MAN_LINKNODEBLOCK_HEAD_INIT(pMan);\
    MAN_FREENODEBLOCK_HEAD_INIT(pMan);\
    MAN_INIT_LOCK(pMan, (__location__));/*init lock*/\
}while(0)

STATIC_CAST static UINT32 init_mem_manager()
{
    MM_MAN *pMan;

    UINT32 idx;
    for(idx = 0; idx < MM_END; idx ++)
    {
        MM_MGR_INIT(idx, 0, 0, LOC_MM_0001);/*not init lock here*/
    }

    MM_MGR_DEF(MM_UINT32                       ,"MM_UINT32                       ", 256     , sizeof(UINT32)                     , LOC_MM_0002);
    MM_MGR_DEF(MM_UINT16                       ,"MM_UINT16                       ", 32      , sizeof(UINT16)                     , LOC_MM_0003);
    MM_MGR_DEF(MM_UINT8                        ,"MM_UINT8                        ", 32      , sizeof(UINT8)                      , LOC_MM_0004);

    MM_MGR_DEF(MM_REAL                         ,"MM_REAL                         ", 1024    , sizeof(REAL)                        , LOC_MM_0005);
    MM_MGR_DEF(MM_TASK_NODE                    ,"MM_TASK_NODE                    ", 1024    , sizeof(TASK_NODE)                   , LOC_MM_0006);
    MM_MGR_DEF(MM_TASK_MGR                     ,"MM_TASK_MGR                     ", 32      , sizeof(TASK_MGR)                    , LOC_MM_0007);
    MM_MGR_DEF(MM_TASK_CONTEXT                 ,"MM_TASK_CONTEXT                 ", 32      , sizeof(TASK_CONTEXT)                , LOC_MM_0008);

    MM_MGR_DEF(MM_MOD_NODE                     ,"MM_MOD_NODE                     ", 1024    , sizeof(MOD_NODE)                    , LOC_MM_0009);
    MM_MGR_DEF(MM_MOD_MGR                      ,"MM_MOD_MGR                      ", 32      , sizeof(MOD_MGR)                     , LOC_MM_0010);

    MM_MGR_DEF(MM_TASKC_MGR                    ,"MM_TASKC_MGR                    ", 32      , sizeof(TASKC_MGR)                   , LOC_MM_0011);

    MM_MGR_DEF(MM_CLIST_DATA                   ,"MM_CLIST_DATA                   ", 1024    , sizeof(CLIST_DATA)                  , LOC_MM_0012);
    MM_MGR_DEF(MM_CSTACK_DATA                  ,"MM_CSTACK_DATA                  ", 1024    , sizeof(CSTACK_DATA)                 , LOC_MM_0013);
    MM_MGR_DEF(MM_CSET_DATA                    ,"MM_CSET_DATA                    ", 1024    , sizeof(CSET_DATA)                   , LOC_MM_0014);
    MM_MGR_DEF(MM_CQUEUE_DATA                  ,"MM_CQUEUE_DATA                  ", 1024    , sizeof(CQUEUE_DATA)                 , LOC_MM_0015);
    MM_MGR_DEF(MM_CSTRING                      ,"MM_CSTRING                      ", 32      , sizeof(CSTRING)                     , LOC_MM_0016);

    MM_MGR_DEF(MM_FUNC_ADDR_MGR                ,"MM_FUNC_ADDR_MGR                ", 16      , sizeof(FUNC_ADDR_MGR)               , LOC_MM_0017);

    MM_MGR_DEF(MM_UINT8_064B                   ,"MM_UINT8_064B                   ", 64      , 64                                  , LOC_MM_0018);
    MM_MGR_DEF(MM_UINT8_128B                   ,"MM_UINT8_128B                   ", 32      , 128                                 , LOC_MM_0019);
    MM_MGR_DEF(MM_UINT8_256B                   ,"MM_UINT8_256B                   ", 16      , 256                                 , LOC_MM_0020);
    MM_MGR_DEF(MM_UINT8_512B                   ,"MM_UINT8_512B                   ", 8       , 512                                 , LOC_MM_0021);

    MM_MGR_DEF(MM_UINT8_001K                   ,"MM_UINT8_001K                   ", 64      , 1 * 1024                            , LOC_MM_0022);
    MM_MGR_DEF(MM_UINT8_002K                   ,"MM_UINT8_002K                   ", 256     , 2 * 1024                            , LOC_MM_0023);
    MM_MGR_DEF(MM_UINT8_004K                   ,"MM_UINT8_004K                   ", 128     , 4 * 1024                            , LOC_MM_0024);
    MM_MGR_DEF(MM_UINT8_008K                   ,"MM_UINT8_008K                   ", 8       , 5 * 1024                            , LOC_MM_0025);
    MM_MGR_DEF(MM_UINT8_016K                   ,"MM_UINT8_016K                   ", 4       , 16 * 1024                           , LOC_MM_0026);
    MM_MGR_DEF(MM_UINT8_032K                   ,"MM_UINT8_032K                   ", 2       , 32 * 1024                           , LOC_MM_0027);
    MM_MGR_DEF(MM_UINT8_064K                   ,"MM_UINT8_064K                   ", 8       , 64 * 1024                           , LOC_MM_0028);
    MM_MGR_DEF(MM_UINT8_128K                   ,"MM_UINT8_128K                   ", 4       , 128 * 1024                          , LOC_MM_0029);
    MM_MGR_DEF(MM_UINT8_256K                   ,"MM_UINT8_256K                   ", 2       , 256 * 1024                          , LOC_MM_0030);
    MM_MGR_DEF(MM_UINT8_512K                   ,"MM_UINT8_512K                   ", 1       , 512 * 1024                          , LOC_MM_0031);

    MM_MGR_DEF(MM_UINT8_001M                   ,"MM_UINT8_001M                   ", 64      , 1 * 1024 * 1024                     , LOC_MM_0032);
    MM_MGR_DEF(MM_UINT8_002M                   ,"MM_UINT8_002M                   ", 32      , 2 * 1024 * 1024                     , LOC_MM_0033);
    MM_MGR_DEF(MM_UINT8_004M                   ,"MM_UINT8_004M                   ", 16      , 4 * 1024 * 1024                     , LOC_MM_0034);
    MM_MGR_DEF(MM_UINT8_008M                   ,"MM_UINT8_008M                   ", 8       , 5 * 1024 * 1024                     , LOC_MM_0035);
    MM_MGR_DEF(MM_UINT8_016M                   ,"MM_UINT8_016M                   ", 4       , 16 * 1024 * 1024                    , LOC_MM_0036);
    MM_MGR_DEF(MM_UINT8_032M                   ,"MM_UINT8_032M                   ", 2       , 32 * 1024 * 1024                    , LOC_MM_0037);
    MM_MGR_DEF(MM_UINT8_064M                   ,"MM_UINT8_064M                   ", 2       , 64 * 1024 * 1024                    , LOC_MM_0038);
    MM_MGR_DEF(MM_UINT8_128M                   ,"MM_UINT8_128M                   ", 1       , 128 * 1024 * 1024                   , LOC_MM_0039);
    MM_MGR_DEF(MM_UINT8_256M                   ,"MM_UINT8_256M                   ", 1       , 256 * 1024 * 1024                   , LOC_MM_0040);
    MM_MGR_DEF(MM_UINT8_512M                   ,"MM_UINT8_512M                   ", 1       , 512 * 1024 * 1024                   , LOC_MM_0041);

    MM_MGR_DEF(MM_CLIST                        ,"MM_CLIST                        ", 32      , sizeof(CLIST)                       , LOC_MM_0042);
    MM_MGR_DEF(MM_CSTACK                       ,"MM_CSTACK                       ", 32      , sizeof(CSTACK)                      , LOC_MM_0043);
    MM_MGR_DEF(MM_CSET                         ,"MM_CSET                         ", 32      , sizeof(CSET)                        , LOC_MM_0044);
    MM_MGR_DEF(MM_CQUEUE                       ,"MM_CQUEUE                       ", 32      , sizeof(CQUEUE)                      , LOC_MM_0045);
    MM_MGR_DEF(MM_CDEQUEUE                     ,"MM_CDEQUEUE                     ", 32      , sizeof(CDEQUEUE)                    , LOC_MM_0046);
    MM_MGR_DEF(MM_CVECTOR                      ,"MM_CVECTOR                      ", 32      , sizeof(CVECTOR)                     , LOC_MM_0047);

    MM_MGR_DEF(MM_CTHREAD_TASK                 ,"MM_CTHREAD_TASK                 ", 32      , sizeof(CTHREAD_TASK)                , LOC_MM_0048);

    MM_MGR_DEF(MM_TASKS_CFG                    ,"MM_TASKS_CFG                    ", 32      , sizeof(TASKS_CFG)                   , LOC_MM_0049);
    MM_MGR_DEF(MM_TASKR_CFG                    ,"MM_TASKR_CFG                    ", 32      , sizeof(TASKR_CFG)                   , LOC_MM_0050);
    MM_MGR_DEF(MM_TASK_CFG                     ,"MM_TASK_CFG                     ", 1       , sizeof(TASK_CFG)                    , LOC_MM_0051);

    MM_MGR_DEF(MM_TASKS_NODE                   ,"MM_TASKS_NODE                   ", 32      , sizeof(TASKS_NODE)                  , LOC_MM_0052);
    MM_MGR_DEF(MM_TASKC_NODE                   ,"MM_TASKC_NODE                   ", 32      , sizeof(TASKC_NODE)                  , LOC_MM_0053);
    MM_MGR_DEF(MM_CROUTER_NODE                 ,"MM_CROUTER_NODE                 ", 128     , sizeof(CROUTER_NODE)                , LOC_MM_0054);
    MM_MGR_DEF(MM_CROUTER_NODE_VEC             ,"MM_CROUTER_NODE_VEC             ", 128     , sizeof(CROUTER_NODE_VEC)            , LOC_MM_0055);
    MM_MGR_DEF(MM_CROUTER_CFG                  ,"MM_CROUTER_CFG                  ", 128     , sizeof(CROUTER_CFG)                 , LOC_MM_0056);

    MM_MGR_DEF(MM_LOG                          ,"MM_LOG                          ", 4       , sizeof(LOG)                         , LOC_MM_0057);

    MM_MGR_DEF(MM_COMM_NODE                    ,"MM_COMM_NODE                    ", 128     , sizeof(MM_COMM)                     , LOC_MM_0058);
    MM_MGR_DEF(MM_KBUFF                        ,"MM_KBUFF                        ", 128     , sizeof(KBUFF)                       , LOC_MM_0059);

    MM_MGR_DEF(MM_CSOCKET_CNODE                ,"MM_CSOCKET_CNODE                ", 128     , sizeof(CSOCKET_CNODE)               , LOC_MM_0060);
    MM_MGR_DEF(MM_CTIMER_NODE                  ,"MM_CTIMER_NODE                  ", 128     , sizeof(CTIMER_NODE)                 , LOC_MM_0061);

    MM_MGR_DEF(MM_CSYS_CPU_STAT                ,"MM_CSYS_CPU_STAT                ", 128     , sizeof(CSYS_CPU_STAT)               , LOC_MM_0062);
    MM_MGR_DEF(MM_CSYS_CPU_AVG_STAT            ,"MM_CSYS_CPU_AVG_STAT            ", 128     , sizeof(CSYS_CPU_AVG_STAT)           , LOC_MM_0063);
    MM_MGR_DEF(MM_CSYS_MEM_STAT                ,"MM_CSYS_MEM_STAT                ", 4       , sizeof(CSYS_MEM_STAT)               , LOC_MM_0064);
    MM_MGR_DEF(MM_CPROC_MEM_STAT               ,"MM_CPROC_MEM_STAT               ", 4       , sizeof(CPROC_MEM_STAT)              , LOC_MM_0065);
    MM_MGR_DEF(MM_CPROC_CPU_STAT               ,"MM_CPROC_CPU_STAT               ", 4       , sizeof(CPROC_CPU_STAT)              , LOC_MM_0066);
    MM_MGR_DEF(MM_CPROC_THREAD_STAT            ,"MM_CPROC_THREAD_STAT            ", 4       , sizeof(CPROC_THREAD_STAT)           , LOC_MM_0067);
    MM_MGR_DEF(MM_CRANK_THREAD_STAT            ,"MM_CRANK_THREAD_STAT            ", 4       , sizeof(CRANK_THREAD_STAT)           , LOC_MM_0068);
    MM_MGR_DEF(MM_CPROC_MODULE_STAT            ,"MM_CPROC_MODULE_STAT            ", 4       , sizeof(CPROC_MODULE_STAT)           , LOC_MM_0069);
    MM_MGR_DEF(MM_CSYS_ETH_STAT                ,"MM_CSYS_ETH_STAT                ", 4       , sizeof(CSYS_ETH_STAT)               , LOC_MM_0070);
    MM_MGR_DEF(MM_CSYS_DSK_STAT                ,"MM_CSYS_DSK_STAT                ", 4       , sizeof(CSYS_DSK_STAT)               , LOC_MM_0071);
    MM_MGR_DEF(MM_MM_MAN_OCCUPY_NODE           ,"MM_MM_MAN_OCCUPY_NODE           ", 128     , sizeof(MM_MAN_OCCUPY_NODE)          , LOC_MM_0072);
    MM_MGR_DEF(MM_MM_MAN_LOAD_NODE             ,"MM_MM_MAN_LOAD_NODE             ", 128     , sizeof(MM_MAN_LOAD_NODE)            , LOC_MM_0073);
    MM_MGR_DEF(MM_CTHREAD_NODE                 ,"MM_CTHREAD_NODE                 ", 16      , sizeof(CTHREAD_NODE)                , LOC_MM_0074);
    MM_MGR_DEF(MM_CTHREAD_POOL                 ,"MM_CTHREAD_POOL                 ", 1       , sizeof(CTHREAD_POOL)                , LOC_MM_0075);
    MM_MGR_DEF(MM_TASK_RANK_NODE               ,"MM_TASK_RANK_NODE               ", 1       , sizeof(TASK_RANK_NODE)              , LOC_MM_0076);
    MM_MGR_DEF(MM_CMD_SEG                      ,"MM_CMD_SEG                      ", 128     , sizeof(CMD_SEG)                     , LOC_MM_0077);
    MM_MGR_DEF(MM_CMD_PARA                     ,"MM_CMD_PARA                     ", 8       , sizeof(CMD_PARA)                    , LOC_MM_0078);
    MM_MGR_DEF(MM_CMD_HELP                     ,"MM_CMD_HELP                     ", 32      , sizeof(CMD_HELP)                    , LOC_MM_0079);
    MM_MGR_DEF(MM_CMD_ELEM                     ,"MM_CMD_ELEM                     ", 32      , sizeof(CMD_ELEM)                    , LOC_MM_0080);
    MM_MGR_DEF(MM_TASK_REPORT_NODE             ,"MM_TASK_REPORT_NODE             ", 128     , sizeof(TASK_REPORT_NODE)            , LOC_MM_0081);

    MM_MGR_DEF(MM_CHASH_NODE                   ,"MM_CHASH_NODE                   ", 32      , sizeof(CHASH_NODE)                  , LOC_MM_0082);
    MM_MGR_DEF(MM_CHASH_VEC                    ,"MM_CHASH_VEC                    ", 4       , sizeof(CHASH_VEC)                   , LOC_MM_0083);

    MM_MGR_DEF(MM_CHASHDB_ITEM                 ,"MM_CHASHDB_ITEM                 ", 4       , sizeof(CHASHDB_ITEM)                , LOC_MM_0084);
    MM_MGR_DEF(MM_CHASHDB                      ,"MM_CHASHDB                      ", 4       , sizeof(CHASHDB)                     , LOC_MM_0085);
    MM_MGR_DEF(MM_CHASHDB_BUCKET               ,"MM_CHASHDB_BUCKET               ", 4       , sizeof(CHASHDB_BUCKET)              , LOC_MM_0086);

    MM_MGR_DEF(MM_CLOAD_STAT                   ,"MM_CLOAD_STAT                   ", 8       , sizeof(CLOAD_STAT)                  , LOC_MM_0087);
    MM_MGR_DEF(MM_CLOAD_NODE                   ,"MM_CLOAD_NODE                   ", 8       , sizeof(CLOAD_NODE)                  , LOC_MM_0088);

    MM_MGR_DEF(MM_TYPE_CONV_ITEM               ,"MM_TYPE_CONV_ITEM               ",64       , sizeof(TYPE_CONV_ITEM)              , LOC_MM_0089);
    MM_MGR_DEF(MM_CSRV                         ,"MM_CSRV                         ",64       , sizeof(CSRV)                        , LOC_MM_0090);

    MM_MGR_DEF(MM_CTIMEOUT_NODE                ,"MM_CTIMEOUT_NODE                ",64       , sizeof(CTIMEOUT_NODE)               , LOC_MM_0091);

    MM_MGR_DEF(MM_CBYTES                       ,"MM_CBYTES                       ",4        , sizeof(CBYTES)                      , LOC_MM_0092);
    MM_MGR_DEF(MM_CBITMAP                      ,"MM_CBITMAP                      ",1        , sizeof(CBITMAP)                     , LOC_MM_0093);

    MM_MGR_DEF(MM_CBTIMER_NODE                 ,"MM_CBTIMER_NODE                 ",4        , sizeof(CBTIMER_NODE)                , LOC_MM_0094);
    MM_MGR_DEF(MM_CLUSTER_NODE_CFG             ,"MM_CLUSTER_NODE_CFG             ",4        , sizeof(CLUSTER_NODE_CFG)            , LOC_MM_0095);
    MM_MGR_DEF(MM_CLUSTER_CFG                  ,"MM_CLUSTER_CFG                  ",4        , sizeof(CLUSTER_CFG)                 , LOC_MM_0096);
    MM_MGR_DEF(MM_CPARACFG                     ,"MM_CPARACFG                     ",1        , sizeof(CPARACFG)                    , LOC_MM_0097);
    MM_MGR_DEF(MM_MCAST_CFG                    ,"MM_MCAST_CFG                    ",1        , sizeof(MCAST_CFG)                   , LOC_MM_0098);
    MM_MGR_DEF(MM_SDISC_CFG                    ,"MM_SDISC_CFG                    ",1        , sizeof(SDISC_CFG)                   , LOC_MM_0099);
    MM_MGR_DEF(MM_BCAST_DHCP_CFG               ,"MM_BCAST_DHCP_CFG               ",1        , sizeof(BCAST_DHCP_CFG)              , LOC_MM_0100);
    MM_MGR_DEF(MM_MACIP_CFG                    ,"MM_MACIP_CFG                    ",4        , sizeof(MACIP_CFG)                   , LOC_MM_0101);
    MM_MGR_DEF(MM_SYS_CFG                      ,"MM_SYS_CFG                      ",1        , sizeof(SYS_CFG)                     , LOC_MM_0102);

    MM_MGR_DEF(MM_SUPER_FNODE                  ,"MM_SUPER_FNODE                  ",1        , sizeof(SUPER_FNODE)                 , LOC_MM_0103);

    MM_MGR_DEF(MM_CMAP_NODE                    ,"MM_CMAP_NODE                    ",4        , sizeof(CMAP_NODE)                   , LOC_MM_0104);
    MM_MGR_DEF(MM_CMAP                         ,"MM_CMAP                         ",4        , sizeof(CMAP)                        , LOC_MM_0105);
    MM_MGR_DEF(MM_CSESSION_NODE                ,"MM_CSESSION_NODE                ",4        , sizeof(CSESSION_NODE)               , LOC_MM_0106);
    MM_MGR_DEF(MM_CSESSION_ITEM                ,"MM_CSESSION_ITEM                ",4        , sizeof(CSESSION_ITEM)               , LOC_MM_0107);
    MM_MGR_DEF(MM_CTIMET                       ,"MM_CTIMET                       ",4        , sizeof(CTIMET)                      , LOC_MM_0108);

    MM_MGR_DEF(MM_COROUTINE_TASK               ,"MM_COROUTINE_TASK               ",4        , sizeof(COROUTINE_TASK)              , LOC_MM_0109);
    MM_MGR_DEF(MM_COROUTINE_NODE               ,"MM_COROUTINE_NODE               ",4        , sizeof(COROUTINE_NODE)              , LOC_MM_0110);
    MM_MGR_DEF(MM_COROUTINE_POOL               ,"MM_COROUTINE_POOL               ",4        , sizeof(COROUTINE_POOL)              , LOC_MM_0111);

    MM_MGR_DEF(MM_CRFSDN_NODE                  ,"MM_CRFSDN_NODE                  ",4        , sizeof(CRFSDN_NODE)                 , LOC_MM_0112);
    MM_MGR_DEF(MM_CRFSDN                       ,"MM_CRFSDN                       ",1        , sizeof(CRFSDN)                      , LOC_MM_0113);

    MM_MGR_DEF(MM_CPGB                         ,"MM_CPGB                         ",1        , CPGB_SIZE                           , LOC_MM_0114);
    MM_MGR_DEF(MM_CPGD                         ,"MM_CPGD                         ",256      , sizeof(CPGD)                        , LOC_MM_0115);
    MM_MGR_DEF(MM_CPGV                         ,"MM_CPGV                         ",64       , sizeof(CPGV)                        , LOC_MM_0116);

    MM_MGR_DEF(MM_CRB_NODE                     ,"MM_CRB_NODE                     ",64       , sizeof(CRB_NODE)                    , LOC_MM_0117);
    MM_MGR_DEF(MM_CRB_TREE                     ,"MM_CRB_TREE                     ",1        , sizeof(CRB_TREE)                    , LOC_MM_0118);

    MM_MGR_DEF(MM_CRBBASE_TREE                 ,"MM_CRBBASE_TREE                 ",1        , sizeof(CRBBASE_TREE)                , LOC_MM_0119);

    MM_MGR_DEF(MM_CRFSNP_FNODE                 ,"MM_CRFSNP_FNODE                 ",1        , sizeof(CRFSNP_FNODE)                , LOC_MM_0120);
    MM_MGR_DEF(MM_CRFSNP_DNODE                 ,"MM_CRFSNP_DNODE                 ",1        , sizeof(CRFSNP_DNODE)                , LOC_MM_0121);
    MM_MGR_DEF(MM_CRFSNP_ITEM                  ,"MM_CRFSNP_ITEM                  ",1        , sizeof(CRFSNP_ITEM)                 , LOC_MM_0122);
    MM_MGR_DEF(MM_CRFSNP                       ,"MM_CRFSNP                       ",1        , sizeof(CRFSNP)                      , LOC_MM_0123);
    MM_MGR_DEF(MM_CRFSNP_MGR                   ,"MM_CRFSNP_MGR                   ",1        , sizeof(CRFSNP_MGR)                  , LOC_MM_0124);
    MM_MGR_DEF(MM_CRFSNP_KEY                   ,"MM_CRFSNP_KEY                   ",1        , sizeof(CRFSNP_KEY)                  , LOC_MM_0125);
    MM_MGR_DEF(MM_CRFSDN_CACHE_NODE            ,"MM_CRFSDN_CACHE_NODE            ",1        , sizeof(CRFSDN_CACHE_NODE)           , LOC_MM_0126);

    MM_MGR_DEF(MM_UINT64                       ,"MM_UINT64                       ",32       , sizeof(uint64_t)                    , LOC_MM_0127);

    MM_MGR_DEF(MM_CEPOLL                       ,"MM_CEPOLL                       ",1        , sizeof(CEPOLL)                      , LOC_MM_0128);

    MM_MGR_DEF(MM_CSEM                         ,"MM_CSEM                         ",32        , sizeof(CSEM)                       , LOC_MM_0129);

    MM_MGR_DEF(MM_CSTRKV                       ,"MM_CSTRKV                       ",32        , sizeof(CSTRKV)                     , LOC_MM_0130);
    MM_MGR_DEF(MM_CSTRKV_MGR                   ,"MM_CSTRKV_MGR                   ",32        , sizeof(CSTRKV_MGR)                 , LOC_MM_0131);
    MM_MGR_DEF(MM_CBUFFER                      ,"MM_CBUFFER                      ",32        , sizeof(CBUFFER)                    , LOC_MM_0132);
    MM_MGR_DEF(MM_CHUNK                        ,"MM_CHUNK                        ",32        , sizeof(CHUNK)                      , LOC_MM_0133);
    MM_MGR_DEF(MM_CHUNK_MGR                    ,"MM_CHUNK_MGR                    ",32        , sizeof(CHUNK_MGR)                  , LOC_MM_0134);

    MM_MGR_DEF(MM_CMD5_DIGEST                  ,"MM_CMD5_DIGEST                  ",4         , sizeof(CMD5_DIGEST)                , LOC_MM_0135);

    MM_MGR_DEF(MM_CEXPAT_ATTR                  ,"MM_CEXPAT_ATTR                  ",256       , sizeof(CEXPAT_ATTR)                , LOC_MM_0136);
    MM_MGR_DEF(MM_CEXPAT_NODE                  ,"MM_CEXPAT_NODE                  ",256       , sizeof(CEXPAT_NODE)                , LOC_MM_0137);
    MM_MGR_DEF(MM_CRFS_LOCKED_FILE             ,"MM_CRFS_LOCKED_FILE             ",32        , sizeof(CRFS_LOCKED_FILE)           , LOC_MM_0138);
    MM_MGR_DEF(MM_CHTTP_NODE                   ,"MM_CHTTP_NODE                   ",256       , sizeof(CHTTP_NODE)                 , LOC_MM_0139);

    MM_MGR_DEF(MM_TASK_RUNNER_NODE             ,"MM_TASK_RUNNER_NODE             ",4         , sizeof(TASK_RUNNER_NODE)           , LOC_MM_0140);

    MM_MGR_DEF(MM_CHTTP_REQ                    ,"MM_CHTTP_REQ                    ",32        , sizeof(CHTTP_REQ)                  , LOC_MM_0141);
    MM_MGR_DEF(MM_CHTTP_RSP                    ,"MM_CHTTP_RSP                    ",32        , sizeof(CHTTP_RSP)                  , LOC_MM_0142);
    MM_MGR_DEF(MM_CHTTP_REST                   ,"MM_CHTTP_REST                   ",32        , sizeof(CHTTP_REST)                 , LOC_MM_0143);

    MM_MGR_DEF(MM_CDNS_NODE                    ,"MM_CDNS_NODE                    ",32        , sizeof(CDNS_NODE)                  , LOC_MM_0144);
    MM_MGR_DEF(MM_CDNS_REQ                     ,"MM_CDNS_REQ                     ",32        , sizeof(CDNS_REQ)                   , LOC_MM_0145);
    MM_MGR_DEF(MM_CDNS_RSP                     ,"MM_CDNS_RSP                     ",32        , sizeof(CDNS_RSP)                   , LOC_MM_0146);
    MM_MGR_DEF(MM_CDNS_RSP_NODE                ,"MM_CDNS_RSP_NODE                ",32        , sizeof(CDNS_RSP_NODE)              , LOC_MM_0147);

    MM_MGR_DEF(MM_CHTTP_STAT                   ,"MM_CHTTP_STAT                   ",256       , sizeof(CHTTP_STAT)                 , LOC_MM_0148);
    MM_MGR_DEF(MM_SUPER_CCOND                  ,"MM_SUPER_CCOND                  ",256       , sizeof(SUPER_CCOND)                , LOC_MM_0149);

    MM_MGR_DEF(MM_COROUTINE_CHECKER            ,"MM_COROUTINE_CHECKER            ",256       , sizeof(COROUTINE_CHECKER)          , LOC_MM_0150);
    MM_MGR_DEF(MM_COROUTINE_CLEANER            ,"MM_COROUTINE_CLEANER            ",256       , sizeof(COROUTINE_CLEANER)          , LOC_MM_0151);

    MM_MGR_DEF(MM_COROUTINE_COND               ,"MM_COROUTINE_COND               ",256       , sizeof(COROUTINE_COND)             , LOC_MM_0152);
    MM_MGR_DEF(MM_CHTTP_STORE                  ,"MM_CHTTP_STORE                  ",256       , sizeof(CHTTP_STORE)                , LOC_MM_0153);

    MM_MGR_DEF(MM_CRFS_WAIT_FILE               ,"MM_CRFS_WAIT_FILE               ",256       , sizeof(CRFS_WAIT_FILE)             , LOC_MM_0154);

    MM_MGR_DEF(MM_CCONNP                       ,"MM_CCONNP                       ",256       , sizeof(CCONNP)                     , LOC_MM_0155);
    MM_MGR_DEF(MM_CCONNP_MGR                   ,"MM_CCONNP_MGR                   ",256       , sizeof(CCONNP_MGR)                 , LOC_MM_0156);
    MM_MGR_DEF(MM_CSSL_NODE                    ,"MM_CSSL_NODE                    ",256       , sizeof(CSSL_NODE)                  , LOC_MM_0157);

    MM_MGR_DEF(MM_CRANGE_SEG                   ,"MM_CRANGE_SEG                   ",32        , sizeof(CRANGE_SEG)                 , LOC_MM_0158);
    MM_MGR_DEF(MM_CRANGE_NODE                  ,"MM_CRANGE_NODE                  ",32        , sizeof(CRANGE_NODE)                , LOC_MM_0159);
    MM_MGR_DEF(MM_CRANGE_MGR                   ,"MM_CRANGE_MGR                   ",32        , sizeof(CRANGE_MGR)                 , LOC_MM_0160);

#if (SWITCH_ON == NGX_BGN_SWITCH)
    MM_MGR_DEF(MM_CNGX_RANGE                   ,"MM_CNGX_RANGE                   ",32        , sizeof(CNGX_RANGE)                 , LOC_MM_0161);
    MM_MGR_DEF(MM_CNGX_BGN_MOD_MGR             ,"MM_CNGX_BGN_MOD_MGR             ",32        , sizeof(CNGX_BGN_MOD_MGR)           , LOC_MM_0162);
#endif/*(SWITCH_ON == NGX_BGN_SWITCH)*/

    MM_MGR_DEF(MM_CCALLBACK_NODE               ,"MM_CCALLBACK_NODE               ",256       , sizeof(CCALLBACK_NODE)             , LOC_MM_0163);

    MM_MGR_DEF(MM_CTDNSNP_ITEM                 ,"MM_CTDNSNP_ITEM                 ",256       , sizeof(CTDNSNP_ITEM)                 , LOC_MM_0164);
    MM_MGR_DEF(MM_CTDNSNP                      ,"MM_CTDNSNP                      ",256       , sizeof(CTDNSNP)                      , LOC_MM_0165);
    MM_MGR_DEF(MM_CTDNSNP_MGR                  ,"MM_CTDNSNP_MGR                  ",256       , sizeof(CTDNSNP_MGR)                  , LOC_MM_0166);
    MM_MGR_DEF(MM_CTDNSSV_ITEM                 ,"MM_CTDNSSV_ITEM                 ",256       , sizeof(CTDNSSV_ITEM)                 , LOC_MM_0167);
    MM_MGR_DEF(MM_CTDNSSV_NODE                 ,"MM_CTDNSSV_NODE                 ",256       , sizeof(CTDNSSV_NODE)                 , LOC_MM_0168);
    MM_MGR_DEF(MM_CTDNSSV_NODE_MGR             ,"MM_CTDNSSV_NODE_MGR             ",1         , sizeof(CTDNSSV_NODE_MGR)             , LOC_MM_0169);
    MM_MGR_DEF(MM_CTDNSSV_MGR                  ,"MM_CTDNSSV_MGR                  ",256       , sizeof(CTDNSSV_MGR)                  , LOC_MM_0170);
    MM_MGR_DEF(MM_CTDNSSV                      ,"MM_CTDNSSV                      ",256       , sizeof(CTDNSSV)                      , LOC_MM_0171);

    MM_MGR_DEF(MM_CDETECTN_ORIG_NODE           ,"MM_CDETECTN_ORIG_NODE           ",256      , sizeof(CDETECTN_ORIG_NODE)           , LOC_MM_0172);
    MM_MGR_DEF(MM_CDETECTN_IP_NODE             ,"MM_CDETECTN_IP_NODE             ",256      , sizeof(CDETECTN_IP_NODE)             , LOC_MM_0173);
    MM_MGR_DEF(MM_CDETECTN_STATUS_RANGE        ,"MM_CDETECTN_STATUS_RANGE        ",256      , sizeof(CDETECTN_STATUS_RANGE)        , LOC_MM_0174);
    MM_MGR_DEF(MM_CDETECTN_DOMAIN_NODE         ,"MM_CDETECTN_DOMAIN_NODE         ",256      , sizeof(CDETECTN_DOMAIN_NODE)         , LOC_MM_0175);

    MM_MGR_DEF(MM_CP2P_FILE                    ,"MM_CP2P_FILE                    ",256       , sizeof(CP2P_FILE)                    , LOC_MM_0176);
    MM_MGR_DEF(MM_CP2P_CMD                     ,"MM_CP2P_CMD                     ",256       , sizeof(CP2P_CMD)                     , LOC_MM_0177);

    MM_MGR_DEF(MM_CAGENT                       ,"MM_CAGENT                       ",1         , sizeof(CAGENT)                       , LOC_MM_0178);
    MM_MGR_DEF(MM_CPING_NODE                   ,"MM_CPING_NODE                   ",1         , sizeof(CPING_NODE)                   , LOC_MM_0179);

    MM_MGR_DEF(MM_CTDNS_SUSV_NODE              ,"MM_CTDNS_SUSV_NODE              ",1         , sizeof(CTDNS_SUSV_NODE)              , LOC_MM_0180);

    MM_MGR_DEF(MM_CMCDN                        ,"MM_CMCDN                        ",1         , sizeof(CMCDN)                        , LOC_MM_0181);
    MM_MGR_DEF(MM_CMCPGV                       ,"MM_CMCPGV                       ",1         , sizeof(CMCPGV)                       , LOC_MM_0182);
    MM_MGR_DEF(MM_CMCPGD                       ,"MM_CMCPGD                       ",256       , sizeof(CMCPGD)                       , LOC_MM_0183);

    MM_MGR_DEF(MM_CMCNP                        ,"MM_CMCNP                        ",1         , sizeof(CMCNP)                        , LOC_MM_0184);
    MM_MGR_DEF(MM_CMCNP_FNODE                  ,"MM_CMCNP_FNODE                  ",256       , sizeof(CMCNP_FNODE)                  , LOC_MM_0185);
    MM_MGR_DEF(MM_CMCNP_DNODE                  ,"MM_CMCNP_DNODE                  ",256       , sizeof(CMCNP_DNODE)                  , LOC_MM_0186);
    MM_MGR_DEF(MM_CMCNP_KEY                    ,"MM_CMCNP_KEY                    ",256       , sizeof(CMCNP_KEY)                    , LOC_MM_0187);
    MM_MGR_DEF(MM_CMCNP_ITEM                   ,"MM_CMCNP_ITEM                   ",256       , sizeof(CMCNP_ITEM)                   , LOC_MM_0188);
    MM_MGR_DEF(MM_CMCNP_BITMAP                 ,"MM_CMCNP_BITMAP                 ",256       , sizeof(CMCNP_BITMAP)                 , LOC_MM_0189);

    MM_MGR_DEF(MM_CAIO_NODE                    ,"MM_CAIO_NODE                    ",32        , sizeof(CAIO_NODE)                    , LOC_MM_0190);
    MM_MGR_DEF(MM_CAIO_REQ                     ,"MM_CAIO_REQ                     ",32        , sizeof(CAIO_REQ)                     , LOC_MM_0191);
    MM_MGR_DEF(MM_CAIO_PAGE                    ,"MM_CAIO_PAGE                    ",64        , sizeof(CAIO_PAGE)                    , LOC_MM_0192);
    MM_MGR_DEF(MM_CAIO_DISK                    ,"MM_CAIO_DISK                    ",64        , sizeof(CAIO_DISK)                    , LOC_MM_0193);

    MM_MGR_DEF(MM_CAMD_PAGE                    ,"MM_CAMD_PAGE                    ",256       , sizeof(CAMD_PAGE)                    , LOC_MM_0194);
    MM_MGR_DEF(MM_CAMD_REQ                     ,"MM_CAMD_REQ                     ",256       , sizeof(CAMD_REQ)                     , LOC_MM_0195);
    MM_MGR_DEF(MM_CAMD_NODE                    ,"MM_CAMD_NODE                    ",256       , sizeof(CAMD_NODE)                    , LOC_MM_0196);
    MM_MGR_DEF(MM_CAMD_SATA                    ,"MM_CAMD_SATA                    ",256       , sizeof(CAMD_SATA)                    , LOC_MM_0197);
    MM_MGR_DEF(MM_CAMD_SSD                     ,"MM_CAMD_SSD                     ",256       , sizeof(CAMD_SSD)                     , LOC_MM_0198);
    MM_MGR_DEF(MM_CAMD_COND                    ,"MM_CAMD_COND                    ",256       , sizeof(CAMD_COND)                    , LOC_MM_0199);
    MM_MGR_DEF(MM_CAMD_FILE_REQ                ,"MM_CAMD_FILE_REQ                ",256       , sizeof(CAMD_FILE_REQ)                , LOC_MM_0200);
    MM_MGR_DEF(MM_CDIO_FILE_REQ                ,"MM_CDIO_FILE_REQ                ",256       , sizeof(CDIO_FILE_REQ)                , LOC_MM_0201);
    MM_MGR_DEF(MM_CDCDN                        ,"MM_CDCDN                        ",1         , sizeof(CDCDN)                        , LOC_MM_0202);
    MM_MGR_DEF(MM_CDCPGV                       ,"MM_CDCPGV                       ",1         , sizeof(CDCPGV)                       , LOC_MM_0203);
    MM_MGR_DEF(MM_CDCPGD                       ,"MM_CDCPGD                       ",256       , sizeof(CDCPGD)                       , LOC_MM_0204);

    MM_MGR_DEF(MM_CDCNP                        ,"MM_CDCNP                        ",1         , sizeof(CDCNP)                        , LOC_MM_0205);
    MM_MGR_DEF(MM_CDCNP_FNODE                  ,"MM_CDCNP_FNODE                  ",256       , sizeof(CDCNP_FNODE)                  , LOC_MM_0206);
    MM_MGR_DEF(MM_CDCNP_DNODE                  ,"MM_CDCNP_DNODE                  ",256       , sizeof(CDCNP_DNODE)                  , LOC_MM_0207);
    MM_MGR_DEF(MM_CDCNP_KEY                    ,"MM_CDCNP_KEY                    ",256       , sizeof(CDCNP_KEY)                    , LOC_MM_0208);
    MM_MGR_DEF(MM_CDCNP_ITEM                   ,"MM_CDCNP_ITEM                   ",256       , sizeof(CDCNP_ITEM)                   , LOC_MM_0209);
    MM_MGR_DEF(MM_CDCNP_BITMAP                 ,"MM_CDCNP_BITMAP                 ",256       , sizeof(CDCNP_BITMAP)                 , LOC_MM_0210);

    MM_MGR_DEF(MM_CDC_PAGE                     ,"MM_CDC_PAGE                     ",256       , sizeof(CDC_PAGE)                     , LOC_MM_0211);
    MM_MGR_DEF(MM_CDC_REQ                      ,"MM_CDC_REQ                      ",256       , sizeof(CDC_REQ)                      , LOC_MM_0212);
    MM_MGR_DEF(MM_CDC_NODE                     ,"MM_CDC_NODE                     ",256       , sizeof(CDC_NODE)                     , LOC_MM_0213);
    MM_MGR_DEF(MM_CFC                          ,"MM_CFC                          ",4         , sizeof(CFC)                          , LOC_MM_0214);

    MM_MGR_DEF(MM_CMMAP_NODE                   ,"MM_CMMAP_NODE                   ",4         , sizeof(CMMAP_NODE)                   , LOC_MM_0215);
    MM_MGR_DEF(MM_CMSYNC_NODE                  ,"MM_CMSYNC_NODE                  ",4         , sizeof(CMSYNC_NODE)                  , LOC_MM_0216);

    MM_MGR_DEF(MM_CXFSPGB                      ,"MM_CXFSPGB                      ",1        , CXFSPGB_SIZE                        , LOC_MM_0217);
    MM_MGR_DEF(MM_CXFSPGD                      ,"MM_CXFSPGD                      ",256      , sizeof(CXFSPGD)                     , LOC_MM_0218);
    MM_MGR_DEF(MM_CXFSPGV                      ,"MM_CXFSPGV                      ",64       , sizeof(CXFSPGV)                     , LOC_MM_0219);

    MM_MGR_DEF(MM_CXFSDN                       ,"MM_CXFSDN                       ",1        , sizeof(CXFSDN)                      , LOC_MM_0220);

    MM_MGR_DEF(MM_CXFSNP_FNODE                 ,"MM_CXFSNP_FNODE                 ",1        , sizeof(CXFSNP_FNODE)                , LOC_MM_0221);
    MM_MGR_DEF(MM_CXFSNP_DNODE                 ,"MM_CXFSNP_DNODE                 ",1        , sizeof(CXFSNP_DNODE)                , LOC_MM_0222);
    MM_MGR_DEF(MM_CXFSNP_ITEM                  ,"MM_CXFSNP_ITEM                  ",1        , sizeof(CXFSNP_ITEM)                 , LOC_MM_0223);
    MM_MGR_DEF(MM_CXFSNP                       ,"MM_CXFSNP                       ",1        , sizeof(CXFSNP)                      , LOC_MM_0224);
    MM_MGR_DEF(MM_CXFSNP_MGR                   ,"MM_CXFSNP_MGR                   ",1        , sizeof(CXFSNP_MGR)                  , LOC_MM_0225);
    MM_MGR_DEF(MM_CXFSNP_KEY                   ,"MM_CXFSNP_KEY                   ",1        , sizeof(CXFSNP_KEY)                  , LOC_MM_0226);

    MM_MGR_DEF(MM_CXFS_LOCKED_FILE             ,"MM_CXFS_LOCKED_FILE             ",32        , sizeof(CXFS_LOCKED_FILE)           , LOC_MM_0227);
    MM_MGR_DEF(MM_CXFS_WAIT_FILE               ,"MM_CXFS_WAIT_FILE               ",256       , sizeof(CXFS_WAIT_FILE)             , LOC_MM_0228);

    MM_MGR_DEF(MM_CXFSOP_MGR                   ,"MM_CXFSOP_MGR                   ",4         , sizeof(CXFSOP_MGR)                 , LOC_MM_0229);

    MM_MGR_DEF(MM_CMON_NODE                    ,"MM_CMON_NODE                    ",256       , sizeof(CMON_NODE)                  , LOC_MM_0230);
    MM_MGR_DEF(MM_CMON_HOT_PATH                ,"MM_CMON_HOT_PATH                ",32        , sizeof(CMON_HOT_PATH)              , LOC_MM_0231);

    MM_MGR_DEF(MM_CCONHASH                     ,"MM_CCONHASH                     ",1         , sizeof(CCONHASH)                   , LOC_MM_0232);
    MM_MGR_DEF(MM_CCONHASH_RNODE               ,"MM_CCONHASH_RNODE               ",32        , sizeof(CCONHASH_RNODE)             , LOC_MM_0233);
    MM_MGR_DEF(MM_CCONHASH_VNODE               ,"MM_CCONHASH_VNODE               ",32        , sizeof(CCONHASH_VNODE)             , LOC_MM_0234);

    MM_MGR_DEF(MM_CSDISC_NODE                  ,"MM_CSDISC_NODE                  ",1         , sizeof(CSDISC_NODE)                , LOC_MM_0235);
    MM_MGR_DEF(MM_CSDISC_SENDER                ,"MM_CSDISC_SENDER                ",1         , sizeof(CSDISC_SENDER)              , LOC_MM_0236);
    MM_MGR_DEF(MM_CSDISC_RECVER                ,"MM_CSDISC_RECVER                ",1         , sizeof(CSDISC_RECVER)              , LOC_MM_0237);

    MM_MGR_DEF(MM_CDNSCACHE_NODE               ,"MM_CDNSCACHE_NODE               ",1         , sizeof(CDNSCACHE_NODE)             , LOC_MM_0238);
    MM_MGR_DEF(MM_CDNSCACHE                    ,"MM_CDNSCACHE                    ",1         , sizeof(CDNSCACHE)                  , LOC_MM_0239);

    MM_MGR_DEF(MM_CEVENTFD_NODE                ,"MM_CEVENTFD_NODE                ",4         , sizeof(CEVENTFD_NODE)              , LOC_MM_0240);

    MM_MGR_DEF(MM_CMAGLEV                      ,"MM_CMAGLEV                      ",1         , sizeof(CMAGLEV)                    , LOC_MM_0241);
    MM_MGR_DEF(MM_CMAGLEV_RNODE                ,"MM_CMAGLEV_RNODE                ",1         , sizeof(CMAGLEV_RNODE)              , LOC_MM_0242);
    MM_MGR_DEF(MM_CMAGLEV_QNODE                ,"MM_CMAGLEV_QNODE                ",2         , sizeof(CMAGLEV_QNODE)              , LOC_MM_0243);

    return ( 0 );
}
#undef MM_MGR_DEF

/**
*
*   calculate the min of block num ensure per block >=128KB
*
*   formula:
*       sizeof(MM_NODE_BLOCK)
*     + nodenum * sizeof ( MM_NODE )
*     + nodenum * (typesize + sizeof(MM_AUX))
*     >= 128KB
*
**/
UINT32 calc_block_num_min(const UINT32 typesize)
{
    UINT32 size;
    UINT32 nodenum;

    size = (sizeof ( MM_NODE ) + typesize + sizeof(MM_AUX));
    nodenum = (128 * 1024 - sizeof(MM_NODE_BLOCK) + (size - 1)) / (size);
    return (nodenum);
}

/**
*
*   initialize the static memory. this interface is for outer calling.
*   this interface will initialize the global memory managers and the
*   global memory manager initialized flag to EC_TRUE.
*
*
**/
UINT32 init_static_mem()
{
    if ( EC_TRUE == g_mem_init_flag)
    {
        return ( 0 );
    }

    g_mem_init_flag = EC_TRUE;

    init_mem_manager();

    dbg_log(SEC_0066_MM, 0)(LOGSTDOUT,"[DEBUG] init_static_mem: init done\n");

    return ( 0 );
}

UINT32 init_mm_man(const UINT32 mm_type)
{
    MM_MAN *pMan;

    if ( EC_TRUE == g_mem_init_flag)
    {
        dbg_log(SEC_0066_MM, 0)(LOGSTDOUT,"error:init_mm_man: mm was already initialized.\n");
        return ((UINT32)-1);
    }

    if ( MM_END <= mm_type )
    {
        dbg_log(SEC_0066_MM, 0)(LOGSTDOUT,"error:init_mm_man: type %ld is invalid\n", mm_type);
        return ((UINT32)-1);
    }

    pMan = &(g_mem_manager[ (mm_type) ]);

    if(0 != pMan->typesize)
    {
        dbg_log(SEC_0066_MM, 0)(LOGSTDOUT, "error:init_mm_man: type %ld was already registered\n", mm_type);
        return ((UINT32)-1);
    }

    pMan->type = (mm_type);
    pMan->name = (UINT8 *)"UNDEF";
    pMan->nodenumsum = 0;
    pMan->nodeblocknum = 0;
    pMan->nodenumperblock = 0;
    pMan->typesize = (0);
    pMan->maxusedsum = 0;
    pMan->curusedsum = 0;
    MAN_LINKNODEBLOCK_HEAD_INIT(pMan);
    MAN_FREENODEBLOCK_HEAD_INIT(pMan);

    return (0);
}

UINT32 reg_mm_man(const UINT32 mm_type, const char *mm_name, const UINT32 block_num, const UINT32 type_size, const UINT32 location)
{
    MM_MAN *pMan;

    if ( EC_FALSE == g_mem_init_flag)
    {
        dbg_log(SEC_0066_MM, 0)(LOGSTDOUT,"error:reg_mm_man: mm is not initialized yet.\n");
        return ((UINT32)-1);
    }

    if ( MM_END <= mm_type )
    {
        dbg_log(SEC_0066_MM, 0)(LOGSTDOUT,"error:reg_mm_man: type %ld is invalid where location %ld.\n", mm_type, location);
        return ((UINT32)-1);
    }

    pMan = &(g_mem_manager[ mm_type ]);
    if(0 != pMan->typesize)
    {
        dbg_log(SEC_0066_MM, 0)(LOGSTDOUT, "error:reg_mm_man: type %ld was already registered where location %ld\n", mm_type, location);
        return ((UINT32)-1);
    }

    pMan->type = (mm_type);
    pMan->name = (UINT8 *)(mm_name);
    pMan->nodenumsum = 0;
    pMan->nodeblocknum = 0;
    pMan->nodenumperblock = (block_num);
    pMan->typesize = (type_size);
    pMan->maxusedsum = 0;
    pMan->curusedsum = 0;
    MAN_LINKNODEBLOCK_HEAD_INIT(pMan);
    MAN_FREENODEBLOCK_HEAD_INIT(pMan);
    MAN_INIT_LOCK(pMan, location);/*init lock*/

    return ( 0 );
}

/**
*
*   get file name of location
*
**/
const char *get_file_name_of_location(const UINT32 location)
{
    if(LOC_NONE_BASE < location && location < LOC_NONE_END)
    {
        MM_LOC *mm_loc;

        mm_loc = &(g_mm_loc_tbl[ location ]);
        if(location != mm_loc->location)
        {
            dbg_log(SEC_0066_MM, 9)(LOGSTDOUT, "error:get_file_name_of_location: mistached location %ld and mm location %ld\n", location, mm_loc->location);
            return ("mistached");
        }
        return (mm_loc->filename);
    }

    dbg_log(SEC_0066_MM, 9)(LOGSTDOUT, "error:get_file_name_of_location: invalid location %ld\n", location);
    return ("overflow");
}

/**
*
*   get line no of location
*
**/
UINT32 get_line_no_of_location(const UINT32 location)
{
    if(LOC_NONE_BASE < location && location < LOC_NONE_END)
    {
        MM_LOC *mm_loc;

        mm_loc = &(g_mm_loc_tbl[ location ]);
        if(location != mm_loc->location)
        {
            dbg_log(SEC_0066_MM, 9)(LOGSTDOUT, "error:get_line_no_of_location: mistached location %ld and mm location %ld\n", location, mm_loc->location);
            return (~((UINT32)0));
        }
        return (mm_loc->lineno);
    }

    dbg_log(SEC_0066_MM, 9)(LOGSTDOUT, "error:get_line_no_of_location: invalid location %ld\n", location);
    return (~((UINT32)0));
}

/**
*
*   allocate a node block for static memory usage purpose.
*   it will allocate a dynamic memory block for nodes management purpose
*   and allocate another dynamic memory block for nodes themselves and link
*   the 2nd dynamic memory block to node block at pbaseaddr.
*
*   the 2nd dynamic memory block is splitted into several nodes and link them
*   one by one as free nodes. Note, they are all un-used at present.
*
*   set the free node index to point to the first free node in the node list.
*
**/

EC_BOOL man_debug(const UINT8 *info, MM_MAN *pMan)
{
    MM_NODE_BLOCK *pNodeBlock;

    MAN_LOCK(pMan, LOC_MM_0244);

    dbg_log(SEC_0066_MM, 5)(LOGSTDOUT, "[debug] ========================== man_debug beg ==========================\n\n");
    dbg_log(SEC_0066_MM, 5)(LOGSTDOUT, "%s\n", info);
    dbg_log(SEC_0066_MM, 5)(LOGSTDOUT, "[debug] man_debug: linknodeblockhead: (%p, %p, %p)\n", MAN_LINKNODEBLOCK_HEAD(pMan), MAN_LINKNODEBLOCK_HEAD(pMan)->prev, MAN_LINKNODEBLOCK_HEAD(pMan)->next);
    dbg_log(SEC_0066_MM, 5)(LOGSTDOUT, "[debug] man_debug: freenodeblockhead: (%p, %p, %p)\n", MAN_FREENODEBLOCK_HEAD(pMan), MAN_FREENODEBLOCK_HEAD(pMan)->prev, MAN_FREENODEBLOCK_HEAD(pMan)->next);
    MAN_LINKNODEBLOCK_LOOP_NEXT(pMan, pNodeBlock)
    {
        dbg_log(SEC_0066_MM, 5)(LOGSTDOUT, "[debug] man_debug: link nodeblock: %p\n", pNodeBlock);
    }
    MAN_FREENODEBLOCK_LOOP_NEXT(pMan, pNodeBlock)
    {
        dbg_log(SEC_0066_MM, 5)(LOGSTDOUT, "[debug] man_debug: free nodeblock: %p\n", pNodeBlock);
    }
    dbg_log(SEC_0066_MM, 5)(LOGSTDOUT, "[debug] ========================== man_debug end ==========================\n\n");

    MAN_UNLOCK(pMan, LOC_MM_0245);
    return (EC_TRUE);
}

EC_BOOL nodeblock_debug(const UINT8 *info, const MM_NODE_BLOCK *pNodeBlock)
{
    dbg_log(SEC_0066_MM, 5)(LOGSTDOUT, "%s\n", info);
    dbg_log(SEC_0066_MM, 5)(LOGSTDOUT, "[debug] nodeblock_debug: nodeblock %p\n", pNodeBlock);
    dbg_log(SEC_0066_MM, 5)(LOGSTDOUT, "[debug] nodeblock_debug: nodeblock %p, link = (%p, %p, %p)\n",
                    pNodeBlock,
                    NODEBLOCK_LINKNODE(pNodeBlock), NODEBLOCK_LINKNODE(pNodeBlock)->prev, NODEBLOCK_LINKNODE(pNodeBlock)->next);
    dbg_log(SEC_0066_MM, 5)(LOGSTDOUT, "[debug] nodeblock_debug: nodeblock %p, free = (%p, %p, %p)\n",
                    pNodeBlock,
                    NODEBLOCK_FREENODE(pNodeBlock), NODEBLOCK_FREENODE(pNodeBlock)->prev, NODEBLOCK_FREENODE(pNodeBlock)->next);

    return (EC_TRUE);
}
/*note:pMan is locked by alloc_nodeblock_static_mem caller, so do not lock inside*/
EC_BOOL alloc_nodeblock_static_mem(const UINT32 type)
{
    MM_MAN *pMan;
    MM_NODE *pNode;
    MM_NODE_BLOCK *pNodeBlock;
    UINT32 node_idx;

    void  *pvoid;
    UINT32 size;

    if ( MM_END <= type )
    {
        dbg_log(SEC_0066_MM, 0)(LOGSTDOUT,"error:alloc_nodeblock_static_mem: type is invalid.\n");
        exit ( 2 );
    }

    pMan = &(g_mem_manager[ type ]);

    /*alloc a node block and intilize it */
    size = sizeof(MM_NODE_BLOCK)
         + pMan->nodenumperblock * sizeof ( MM_NODE )
         + pMan->nodenumperblock * (pMan->typesize + sizeof(MM_AUX));

    pvoid = (MM_NODE_BLOCK *)malloc((size_t)size);
    if ( NULL_PTR == pvoid )
    {
        dbg_log(SEC_0066_MM, 0)(LOGSTDOUT,"error:alloc_nodeblock_static_mem: failed to alloc memory for node block with type %ld.\n", type);

        return( EC_FALSE );
    }

    pNodeBlock = (MM_NODE_BLOCK *)pvoid;

    NODEBLOCK_LINKNODE_INIT(pNodeBlock);
    NODEBLOCK_FREENODE_INIT(pNodeBlock);
    pNodeBlock->nodenum   = pMan->nodenumperblock;
    pNodeBlock->typesize  = pMan->typesize;
    pNodeBlock->nextfree  = NODE_LIST_TAIL;
    pNodeBlock->pnodes    = ((void *)pNodeBlock) + sizeof ( MM_NODE_BLOCK );
    pNodeBlock->pbaseaddr = ((void *)pNodeBlock->pnodes) + pNodeBlock->nodenum * sizeof ( MM_NODE );
    pNodeBlock->ptailaddr = pNodeBlock->pbaseaddr + (pNodeBlock->nodenum * (pNodeBlock->typesize + sizeof(MM_AUX)));

    for ( node_idx = 0; node_idx < pNodeBlock->nodenum; node_idx ++ )
    {
        MM_AUX *pAux;
        pNode = &(pNodeBlock->pnodes[ node_idx ]);

        /*link these free nodes one by one*/
        pNode->next = node_idx + 1;

        /*set the current node be un-used status*/
        pNode->usedflag = MM_NODE_NOT_USED;
        pNode->counter  = 0;

        /*link the memory piece which will be used by user's defined type but not memory manager*/
        pNode->pmem = pNodeBlock->pbaseaddr + ( node_idx * (pNodeBlock->typesize + sizeof(MM_AUX)) );

        pAux = (MM_AUX *)(pNode->pmem);
        pAux->type         = type;
        pAux->u.nodeblock = pNodeBlock; /*save memory block addr in each node*/
    }

    /*let the free node index point to the first free one in the node list*/
    pNodeBlock->nextfree = 0;

    /*update the node block's stat data*/
    pNodeBlock->maxusedsum = 0;
    pNodeBlock->curusedsum = 0;

    /*link the new node block to manager*/
    MAN_LINKNODEBLOCK_NODE_ADD_HEAD(pMan, pNodeBlock);

    MAN_FREENODEBLOCK_NODE_ADD_HEAD(pMan, pNodeBlock);

    /*update manager's stat data*/
    pMan->nodeblocknum ++;
    pMan->nodenumsum = pMan->nodenumsum + pNodeBlock->nodenum;

    return ( EC_TRUE );
}

/*note:pMan is locked by free_nodeblock_static_mem caller, so do not lock inside*/
EC_BOOL free_nodeblock_static_mem(MM_MAN *pMan, MM_NODE_BLOCK *pNodeBlock)
{
    /*remove node block from linknodeblock list of manager*/
    NODEBLOCK_LINKNODE_DEL(pNodeBlock);

    /*remove node block from freenodeblock list of manager*/
    if(EC_FALSE == NODEBLOCK_FREENODE_IS_EMPTY(pNodeBlock))
    {
        NODEBLOCK_FREENODE_DEL(pNodeBlock);
    }

    /*update the manager stat info before free node block*/
    pMan->nodenumsum = pMan->nodenumsum - pNodeBlock->nodenum;
    pMan->nodeblocknum --;

    /*free the dynamic memory used by nodes*/
    pNodeBlock->pbaseaddr = NULL_PTR;
    pNodeBlock->ptailaddr = NULL_PTR;

    /*free the dynamic memory used by node index */
    pNodeBlock->pnodes = NULL_PTR;
    pNodeBlock->nodenum = 0;

    /*update the node block's stat data*/
    pNodeBlock->maxusedsum = 0;
    pNodeBlock->curusedsum = 0;

    /*the node block has no any node entity now*/
    pNodeBlock->nextfree = NODE_LIST_TAIL;

    /*free the node block itself*/
    free(pNodeBlock);

    return (EC_TRUE);
}

/**
*
*   check the static memory type of node when allocate a node or free a node.
*   this function is for debug purpose only at present to find out mistakes in programming.
*
*   since all memory allocation and free is based on the node operation and limited number of
*   node type memory, we have a chance and ability to confirm the allocation and free operation
*   is used correctly.
*
*   note:
*       because MM_NAF is a memory block for NAF computation and we have not defined a data structer
*   for it, we cannot check its type normally. to make sure 100% it's being used correctly, we have
*   to check its calling points one by one.
*
**/
EC_BOOL check_static_mem_type(const UINT32 type, const UINT32 typesize)
{
    if ( MM_END <= type )
    {
        dbg_log(SEC_0066_MM, 0)(LOGSTDOUT,"error:check_static_mem_type: parameter type %ld is invalid.\n", type);
        exit ( 2 );
    }

    if(BUFF_MEM_DEF_BEG <= type && type <= BUFF_MEM_DEF_END)
    {
        return (EC_TRUE);
    }

    return EC_TRUE;
}

/**
*
*   fetch typesize of some kind of memory
*
**/
UINT32 fetch_static_mem_typesize(UINT32 type)
{
    MM_MAN *pMan;

    if ( MM_END <= type )
    {
        dbg_log(SEC_0066_MM, 0)(LOGSTDOUT,"error:fetch_static_mem_typesize: parameter type is invalid.\n");
        exit ( 2 );
    }

    pMan = &(g_mem_manager[ type ]);
    return (pMan->typesize);
}

/**
*
*   allocate a node with the appointed node type for the appointed module usage.
*   if allocation success, this funciton will change its status to be used and
*   update the statistic datas of its node block and its manager
*
*   if the manager has no more this type node, the manager will allocate a new
*   dynamic memory block as a new node block of this type and link it to its node
*   block list, and then allocate a node from its node block list.
*
*   if the node status of being occupied is being found conflict, for example,
*   the node in the free node list is being used, then this function will exit
*   because it indcates the memory management has fatal defect which is desired to
*   fix at first. under such condition, this function cannot return only an error
*   code because the calling point does not provide checking ret code mechanism.
*
*   from its implementation, this function provides a mechanism of memory expansion
*   which makes the BGN package more flexible.
*
**/
UINT32 alloc_static_mem_0(const UINT32 location, const UINT32 type, void **ppvoid)
{
    MM_MAN *pMan;
    MM_NODE *pNode;
    UINT32 freenodeidx;
    MM_NODE_BLOCK *pNodeBlock;
    EC_BOOL ret;

    if ( EC_FALSE == g_mem_init_flag)
    {
        dbg_log(SEC_0066_MM, 0)(LOGSTDOUT,"error:alloc_static_mem_0: mm is not initialized yet.\n");
        dbg_log(SEC_0066_MM, 0)(LOGSTDOUT,"error reported by: %s:%ld\n",MM_LOC_FILE_NAME(location),MM_LOC_LINE_NO(location));
        exit ( 2 );
    }

    if ( MM_END <= type )
    {
        dbg_log(SEC_0066_MM, 0)(LOGSTDOUT,"error:alloc_static_mem_0: parameter type is invalid.\n");
        dbg_log(SEC_0066_MM, 0)(LOGSTDOUT,"error reported by: %s:%ld\n",MM_LOC_FILE_NAME(location),MM_LOC_LINE_NO(location));
        exit ( 2 );
    }

    pMan = &(g_mem_manager[ type ]);
#if(SWITCH_ON == MM_DEBUG)
    if(1)
    {
        (*ppvoid) = safe_malloc(pMan->typesize, location);
        return (0);
    }
#endif/*(SWITCH_ON == MM_DEBUG)*/

    MAN_LOCK(pMan, LOC_MM_0246);

    /*if manager has no more free node, then alloc a new node block*/
    if ( pMan->curusedsum >= pMan->nodenumsum )
    {
        ret = alloc_nodeblock_static_mem(type);

        /*if failed to alloc a new node block, then exit*/
        if ( EC_FALSE == ret )
        {
            dbg_log(SEC_0066_MM, 0)(LOGSTDOUT,"error:alloc_static_mem_0: failed to alloc type = %ld node block.\n",type);
            dbg_log(SEC_0066_MM, 0)(LOGSTDOUT,"error reported by: %s:%ld\n",MM_LOC_FILE_NAME(location),MM_LOC_LINE_NO(location));

            (*ppvoid) = NULL_PTR;

            MAN_UNLOCK(pMan, LOC_MM_0247);
            /*return ((UINT32)( -1 ));*/
            exit( 0 );
        }
    }

    pNodeBlock = MAN_FREENODEBLOCK_FIRST_NODE(pMan);

    /* that pNodeBlock is null is impossible, since a new node block is alloced just now.*/
    if ( NULL_PTR == pNodeBlock )
    {
        dbg_log(SEC_0066_MM, 0)(LOGSTDOUT,"fatal error:alloc_static_mem_0: type = %ld has no free node.\n",type);
        dbg_log(SEC_0066_MM, 0)(LOGSTDOUT,"error reported by: %s:%ld\n",MM_LOC_FILE_NAME(location),MM_LOC_LINE_NO(location));

        (*ppvoid) = NULL_PTR;

        MAN_UNLOCK(pMan, LOC_MM_0248);
        print_static_mem_status(LOGSTDOUT);
        exit ( 2 );
    }

    freenodeidx = pNodeBlock->nextfree;
    pNode = &( pNodeBlock->pnodes[ freenodeidx ] );
    if ( MM_NODE_USED == pNode->usedflag)
    {
        dbg_log(SEC_0066_MM, 0)(LOGSTDOUT,"error:alloc_static_mem_0: status conflict: type = %ld, block address = 0x%lx, the free node %ld is used.\n",
                        type,
                        (UINT32)pNodeBlock,
                        freenodeidx);
        dbg_log(SEC_0066_MM, 0)(LOGSTDOUT,"error reported by: %s:%ld\n",MM_LOC_FILE_NAME(location),MM_LOC_LINE_NO(location));

        (*ppvoid) = NULL_PTR;

        MAN_UNLOCK(pMan, LOC_MM_0249);
        print_static_mem_status(LOGSTDOUT);
        exit ( 2 );
    }

    pNodeBlock->nextfree = pNode->next;
    pNode->usedflag      = MM_NODE_USED;
    pNode->counter       = 1;
    pNode->location      = location;

    *ppvoid = pNode->pmem + sizeof(MM_AUX);
    MM_ASSERT(((MM_AUX *)pNode->pmem)->type == type);

    /*update the node block's stat data*/
    pNodeBlock->curusedsum ++;
    if( pNodeBlock->maxusedsum < pNodeBlock->curusedsum )
    {
        pNodeBlock->maxusedsum = pNodeBlock->curusedsum;
    }

    /*update the manager's stat data*/
    pMan->curusedsum ++;
    if ( pMan->maxusedsum < pMan->curusedsum)
    {
        pMan->maxusedsum = pMan->curusedsum;
    }

    /*if all nodes in nodeblock are used, then remove the node block from free nodeblock list of manager*/
    if(pNodeBlock->curusedsum >= pNodeBlock->nodenum)
    {
        NODEBLOCK_FREENODE_DEL(pNodeBlock);
        NODEBLOCK_FREENODE_INIT(pNodeBlock);/*important: point its next and prev to itself*/
    }

    MAN_UNLOCK(pMan, LOC_MM_0250);
    return ( 0 );
}

/**
*
*   free a node with the appointed type and the refered module.
*   this function can only free the node that is allocated by alloc_static_mem_0,
*   and the caller has to remember the ndoe's type.
*
*   normally, this function will return this node to the manager. what the manager does
*   is to return this node to the free node list of the node block via change the node's
*   status to being un-used. so note: this function does not free the dynamic memory of
*   this node, it is only to recycle this node and let it for next being allocated.
*   Meanwhile, this function will update the stat data of the node's manager and node block.
*
*   before free a node, this function will check whether this node's memory falls into some
*   node block of the manager and check it's occupied status is right or not.
*   if not, it means this node is invalid, and there's some possible reasons:
*       1) this node's memory is destroyed somewhere
*       2) this node's type is not correct.
*       3) this node is not allocated by alloc_static_mem_0
*
**/
UINT32 free_static_mem_0(const UINT32 location, const UINT32 type, void *pvoid)
{
    MM_MAN *pMan;
    MM_NODE *pNode;
    MM_AUX * pAux;
    MM_NODE_BLOCK *pNodeBlock;
    UINT32 offset;
    UINT32 node_idx;
    UINT32 res;

    if ( EC_FALSE == g_mem_init_flag)
    {
        dbg_log(SEC_0066_MM, 0)(LOGSTDOUT,"error:free_static_mem_0: mm is not initialized yet.\n");
        dbg_log(SEC_0066_MM, 0)(LOGSTDOUT,"error reported by: %s:%ld\n",MM_LOC_FILE_NAME(location),MM_LOC_LINE_NO(location));
        exit ( 2 );
    }

    if ( MM_END <= type )
    {
        dbg_log(SEC_0066_MM, 0)(LOGSTDOUT,"error:free_static_mem_0: parameter type %ld is invalid.\n", type);
        dbg_log(SEC_0066_MM, 0)(LOGSTDOUT,"error reported by: %s:%ld\n",MM_LOC_FILE_NAME(location),MM_LOC_LINE_NO(location));
        exit ( 2 );
    }

    if ( NULL_PTR == pvoid )
    {
        dbg_log(SEC_0066_MM, 0)(LOGSTDOUT,"error:free_static_mem_0: parameter pvoid is null.\n");
        dbg_log(SEC_0066_MM, 0)(LOGSTDOUT,"error reported by: %s:%ld\n",MM_LOC_FILE_NAME(location),MM_LOC_LINE_NO(location));
        exit ( 2 );
    }

    pMan = &(g_mem_manager[ type ]);

#if(SWITCH_ON == MM_DEBUG)
    safe_free(pvoid, location);
    return (0);
#endif/*(SWITCH_ON == MM_DEBUG)*/

    MAN_LOCK(pMan, LOC_MM_0251);

    if ( 0 == pMan->curusedsum )
    {
        dbg_log(SEC_0066_MM, 0)(LOGSTDOUT,"error:free_static_mem_0: the manager %ld has no any node being used.\n", type);
        dbg_log(SEC_0066_MM, 0)(LOGSTDOUT,"error reported by: %s:%ld, pvoid %p\n",MM_LOC_FILE_NAME(location),MM_LOC_LINE_NO(location), pvoid);
        print_static_mem_status(LOGSTDOUT);

        MAN_UNLOCK(pMan, LOC_MM_0252);
        exit ( 2 );
    }

    /* search the node's position and update relative info */
    pAux = (MM_AUX *)((UINT32)pvoid - sizeof(MM_AUX));
    pNodeBlock = pAux->u.nodeblock;

    /* if the address pMem does not belong to this manager, then report error */
    if ( NULL_PTR == pNodeBlock )
    {
        dbg_log(SEC_0066_MM, 0)(LOGSTDOUT,"error:free_static_mem_0: pvoid = 0x%lx is out of this manager control.\n",
                        (UINT32)pvoid);
        dbg_log(SEC_0066_MM, 0)(LOGSTDOUT,"error reported by: %s:%ld\n",MM_LOC_FILE_NAME(location),MM_LOC_LINE_NO(location));

        MAN_UNLOCK(pMan, LOC_MM_0253);
        exit ( 2 );
    }

    /* now the address pMem belong to the node block pNodeBlock*/
    offset = (UINT32)(( (UINT8 *) pvoid ) - sizeof(MM_AUX) - ( pNodeBlock->pbaseaddr ));

    res = offset % (pNodeBlock->typesize + sizeof(MM_AUX));
    if ( 0 != res )
    {
        dbg_log(SEC_0066_MM, 0)(LOGSTDOUT,"error:free_static_mem_0: pvoid = 0x%lx is not an aligned address.\n",
                        (UINT32)pvoid);
        dbg_log(SEC_0066_MM, 0)(LOGSTDOUT,"error reported by: %s:%ld\n",MM_LOC_FILE_NAME(location),MM_LOC_LINE_NO(location));

        MAN_UNLOCK(pMan, LOC_MM_0254);
        exit ( 2 );
    }

    node_idx = offset / (pNodeBlock->typesize + sizeof(MM_AUX));
    if ( node_idx >= pNodeBlock->nodenum )
    {
        dbg_log(SEC_0066_MM, 0)(LOGSTDOUT,
                        "error:free_static_mem_0:status error:the node with index = %ld to free of Manager %ld is out of management.\n",
                        node_idx,
                        type);
        dbg_log(SEC_0066_MM, 0)(LOGSTDOUT,"error reported by: %s:%ld\n",MM_LOC_FILE_NAME(location),MM_LOC_LINE_NO(location));

        MAN_UNLOCK(pMan, LOC_MM_0255);
        exit ( 2 );
    }

    pNode = &( pNodeBlock->pnodes[ node_idx ] );
    if ( MM_NODE_NOT_USED == pNode->usedflag)
    {
        dbg_log(SEC_0066_MM, 0)(LOGSTDOUT,"error:free_static_mem_0: status error:the node %p to free of the Manager %ld is not used.\n",
                        pvoid, type);
        dbg_log(SEC_0066_MM, 0)(LOGSTDOUT,"error reported by: %s:%ld\n",MM_LOC_FILE_NAME(location),MM_LOC_LINE_NO(location));
        dbg_log(SEC_0066_MM, 0)(LOGSTDOUT,"error was free at: %s:%ld\n",MM_LOC_FILE_NAME(pNode->location),MM_LOC_LINE_NO(pNode->location));

        MAN_UNLOCK(pMan, LOC_MM_0256);

        c_backtrace_dump(LOGSTDOUT);

        exit ( 2 );
    }

    if ( 0 == pNode->counter)
    {
        dbg_log(SEC_0066_MM, 0)(LOGSTDOUT,"error:free_static_mem_0: status error:the node %p to free of the Manager %ld is not used (counter %u).\n",
                        pvoid, type, pNode->counter);
        dbg_log(SEC_0066_MM, 0)(LOGSTDOUT,"error reported by: %s:%ld\n",MM_LOC_FILE_NAME(location),MM_LOC_LINE_NO(location));
        dbg_log(SEC_0066_MM, 0)(LOGSTDOUT,"error was free at: %s:%ld\n",MM_LOC_FILE_NAME(pNode->location),MM_LOC_LINE_NO(pNode->location));

        MAN_UNLOCK(pMan, LOC_MM_0256);

        c_backtrace_dump(LOGSTDOUT);

        exit ( 2 );
    }

    pNode->counter --;

    if (0 < pNode->counter)
    {
        return 0;
    }

    pNode->usedflag = MM_NODE_NOT_USED;
    pNode->counter  = 0;
    pNode->location = location;

    pNode->next = pNodeBlock->nextfree;
    pNodeBlock->nextfree = node_idx;

    /*update the node block's stat data*/
    pNodeBlock->curusedsum --;

    /*update the manager's stat data*/
    pMan->curusedsum --;

    /*if nodeblock is NOT used and free nodeblock list of manager is not empty, then free the nodeblock*/
    /*otherwise, add the nodeblock to tail of free nodeblock list of manager if not in it*/
    if(EC_TRUE == NODEBLOCK_FREENODE_IS_EMPTY(pNodeBlock))
    {
        MAN_FREENODEBLOCK_NODE_ADD_TAIL(pMan, pNodeBlock);
    }

    if((0 == pNodeBlock->curusedsum) && (pNodeBlock != MAN_FREENODEBLOCK_FIRST_NODE(pMan)))
    {
        free_nodeblock_static_mem(pMan, pNodeBlock);
    }

    MAN_UNLOCK(pMan, LOC_MM_0257);
    return 0;
}

UINT32 reuse_static_mem_0(const UINT32 location, const UINT32 type, void *pvoid)
{
    MM_MAN *pMan;
    MM_NODE *pNode;
    MM_AUX * pAux;
    MM_NODE_BLOCK *pNodeBlock;
    UINT32 offset;
    UINT32 node_idx;
    UINT32 res;

    if ( EC_FALSE == g_mem_init_flag)
    {
        dbg_log(SEC_0066_MM, 0)(LOGSTDOUT,"error:reuse_static_mem_0: mm is not initialized yet.\n");
        dbg_log(SEC_0066_MM, 0)(LOGSTDOUT,"error reported by: %s:%ld\n",MM_LOC_FILE_NAME(location),MM_LOC_LINE_NO(location));
        exit ( 2 );
    }

    if ( MM_END <= type )
    {
        dbg_log(SEC_0066_MM, 0)(LOGSTDOUT,"error:reuse_static_mem_0: parameter type %ld is invalid.\n", type);
        dbg_log(SEC_0066_MM, 0)(LOGSTDOUT,"error reported by: %s:%ld\n",MM_LOC_FILE_NAME(location),MM_LOC_LINE_NO(location));
        exit ( 2 );
    }

    if ( NULL_PTR == pvoid )
    {
        dbg_log(SEC_0066_MM, 0)(LOGSTDOUT,"error:reuse_static_mem_0: parameter pvoid is null.\n");
        dbg_log(SEC_0066_MM, 0)(LOGSTDOUT,"error reported by: %s:%ld\n",MM_LOC_FILE_NAME(location),MM_LOC_LINE_NO(location));
        exit ( 2 );
    }

    pMan = &(g_mem_manager[ type ]);

#if(SWITCH_ON == MM_DEBUG)
    ASSERT(0);
#endif/*(SWITCH_ON == MM_DEBUG)*/

    MAN_LOCK(pMan, LOC_MM_0251);

    if ( 0 == pMan->curusedsum )
    {
        dbg_log(SEC_0066_MM, 0)(LOGSTDOUT,"error:reuse_static_mem_0: the manager %ld has no any node being used.\n", type);
        dbg_log(SEC_0066_MM, 0)(LOGSTDOUT,"error reported by: %s:%ld, pvoid %p\n",MM_LOC_FILE_NAME(location),MM_LOC_LINE_NO(location), pvoid);
        print_static_mem_status(LOGSTDOUT);

        MAN_UNLOCK(pMan, LOC_MM_0252);
        exit ( 2 );
    }

    /* search the node's position and update relative info */
    pAux = (MM_AUX *)((UINT32)pvoid - sizeof(MM_AUX));
    pNodeBlock = pAux->u.nodeblock;

    /* if the address pMem does not belong to this manager, then report error */
    if ( NULL_PTR == pNodeBlock )
    {
        dbg_log(SEC_0066_MM, 0)(LOGSTDOUT,"error:reuse_static_mem_0: pvoid = 0x%lx is out of this manager control.\n",
                        (UINT32)pvoid);
        dbg_log(SEC_0066_MM, 0)(LOGSTDOUT,"error reported by: %s:%ld\n",MM_LOC_FILE_NAME(location),MM_LOC_LINE_NO(location));

        MAN_UNLOCK(pMan, LOC_MM_0253);
        exit ( 2 );
    }

    /* now the address pMem belong to the node block pNodeBlock*/
    offset = (UINT32)(( (UINT8 *) pvoid ) - sizeof(MM_AUX) - ( pNodeBlock->pbaseaddr ));

    res = offset % (pNodeBlock->typesize + sizeof(MM_AUX));
    if ( 0 != res )
    {
        dbg_log(SEC_0066_MM, 0)(LOGSTDOUT,"error:reuse_static_mem_0: pvoid = 0x%lx is not an aligned address.\n",
                        (UINT32)pvoid);
        dbg_log(SEC_0066_MM, 0)(LOGSTDOUT,"error reported by: %s:%ld\n",MM_LOC_FILE_NAME(location),MM_LOC_LINE_NO(location));

        MAN_UNLOCK(pMan, LOC_MM_0254);
        exit ( 2 );
    }

    node_idx = offset / (pNodeBlock->typesize + sizeof(MM_AUX));
    if ( node_idx >= pNodeBlock->nodenum )
    {
        dbg_log(SEC_0066_MM, 0)(LOGSTDOUT,
                        "error:reuse_static_mem_0:status error:the node with index = %ld to free of Manager %ld is out of management.\n",
                        node_idx,
                        type);
        dbg_log(SEC_0066_MM, 0)(LOGSTDOUT,"error reported by: %s:%ld\n",MM_LOC_FILE_NAME(location),MM_LOC_LINE_NO(location));

        MAN_UNLOCK(pMan, LOC_MM_0255);
        exit ( 2 );
    }

    pNode = &( pNodeBlock->pnodes[ node_idx ] );
    if ( MM_NODE_NOT_USED == pNode->usedflag)
    {
        dbg_log(SEC_0066_MM, 0)(LOGSTDOUT,"error:reuse_static_mem_0: status error:the node %p to free of the Manager %ld is not used.\n",
                        pvoid, type);
        dbg_log(SEC_0066_MM, 0)(LOGSTDOUT,"error reported by: %s:%ld\n",MM_LOC_FILE_NAME(location),MM_LOC_LINE_NO(location));
        dbg_log(SEC_0066_MM, 0)(LOGSTDOUT,"error was free at: %s:%ld\n",MM_LOC_FILE_NAME(pNode->location),MM_LOC_LINE_NO(pNode->location));

        MAN_UNLOCK(pMan, LOC_MM_0256);

        c_backtrace_dump(LOGSTDOUT);

        exit ( 2 );
    }

    if ( 0 == pNode->counter)
    {
        dbg_log(SEC_0066_MM, 0)(LOGSTDOUT,"error:reuse_static_mem_0: status error:the node %p to free of the Manager %ld is not used (counter %u).\n",
                        pvoid, type, pNode->counter);
        dbg_log(SEC_0066_MM, 0)(LOGSTDOUT,"error reported by: %s:%ld\n",MM_LOC_FILE_NAME(location),MM_LOC_LINE_NO(location));
        dbg_log(SEC_0066_MM, 0)(LOGSTDOUT,"error was free at: %s:%ld\n",MM_LOC_FILE_NAME(pNode->location),MM_LOC_LINE_NO(pNode->location));

        MAN_UNLOCK(pMan, LOC_MM_0256);

        c_backtrace_dump(LOGSTDOUT);

        exit ( 2 );
    }

    pNode->counter ++;

    MAN_UNLOCK(pMan, LOC_MM_0257);
    return 0;
}

/**
*
*   memory breathing.
*   In fact, this function provides only memory shrinking,i.e., check all node blocks of all managers,
*   if any node block has no any node is being used, then free this node block, meanwhile, update the
*   nodes sum and node blocks sum of its manager. note: the stat data of the mananger is not necessary
*   to update.
*
*   memory expansion is provided by alloc_static_mem_0 function.
*
*   memory breathing function cannot be called frequently, otherwise it will lead to memory allocation flap
*   and decrease the performance of BGN package. So, its calling points are at the end of a module or free
*   module memory after entering X-ray.
*
*/
UINT32 breathing_static_mem()
{
    UINT32  type;

    MM_MAN *pMan;
    MM_NODE_BLOCK *pNodeBlock;

    /*memory breathing:*/
    /*clean up the node block if it has no node being used*/
    for ( type = 0; type < MM_END; type ++ )
    {
        /* do this manager */
        pMan = &(g_mem_manager[ type ]);

        MAN_LOCK(pMan, LOC_MM_0258);

        MAN_FREENODEBLOCK_LOOP_NEXT(pMan, pNodeBlock)
        {
            if ( 0 == pNodeBlock->curusedsum )
            {
                pNodeBlock = NODEBLOCK_FREENODE_PREV(pNodeBlock);
                free_nodeblock_static_mem(pMan, NODEBLOCK_FREENODE_NEXT(pNodeBlock));
            }
        }

        MAN_UNLOCK(pMan, LOC_MM_0259);
    }

    return 0;
}

/**
*
*   destory the whole static memory occupied by the BGN package.
*
*   attention:
*       Do not call this function unless one is ready to exit the BGN package.
*
**/
UINT32 destory_static_mem()
{
    UINT32  type;
    MM_MAN *pMan;
    MM_NODE_BLOCK *pNodeBlock;

    if ( EC_FALSE == g_mem_init_flag)
    {
        return ( 0 );
    }
    g_mem_init_flag = EC_FALSE;

    for ( type = 0; type < MM_END; type ++ )
    {
        pMan = &(g_mem_manager[ type ]);
        MAN_LOCK(pMan, LOC_MM_0260);

        MAN_LINKNODEBLOCK_LOOP_NEXT(pMan, pNodeBlock)
        {
            pNodeBlock = NODEBLOCK_LINKNODE_PREV(pNodeBlock);
            free_nodeblock_static_mem(pMan, NODEBLOCK_LINKNODE_NEXT(pNodeBlock));
        }

        /*validity checking*/
        if(0 < pMan->nodenumsum)
        {
            dbg_log(SEC_0066_MM, 0)(LOGSTDERR, "error:destory_static_mem: manager %p nodenumsum = %ld was not clean up to zero\n", pMan, pMan->nodenumsum);
        }

        if(0 < pMan->nodeblocknum)
        {
            dbg_log(SEC_0066_MM, 0)(LOGSTDERR, "error:destory_static_mem: manager %p nodeblocknum = %ld was not clean up to zero\n", pMan, pMan->nodeblocknum);
        }

        pMan->maxusedsum = 0;
        pMan->curusedsum = 0;

        MAN_LINKNODEBLOCK_HEAD_INIT(pMan);
        MAN_FREENODEBLOCK_HEAD_INIT(pMan);

        MAN_UNLOCK(pMan, LOC_MM_0261);
        MAN_CLEAN_LOCK(pMan, LOC_MM_0262);/*clean lock*/
    }

    return 0;
}

void *safe_malloc_0(const UINT32 size, const UINT32 location)
{
    void *pmem;
    void *pvoid;
    UINT32 len;
#if (32 == WORDSIZE)
    len = ((size + 3) & 0xFFFFFFFC);
#endif/*(32 == WORDSIZE)*/
#if (64 == WORDSIZE)
    len = ((size + 7) & 0xFFFFFFFFFFFFFF8);
#endif/*(64 == WORDSIZE)*/
    pmem = malloc(sizeof(UINT32) + len);
    if(NULL_PTR != pmem)
    {
        MM_COMM *mm_comm;
        alloc_static_mem(MM_COMM_NODE, &mm_comm, location);

        pvoid = (void *)((UINT32)pmem + sizeof(UINT32));

        *((UINT32 *)pmem) = (UINT32)mm_comm;
        mm_comm->pmem = pmem;

        return (pvoid);
    }
    return (NULL_PTR);
}

void safe_free_0(void *pvoid, const UINT32 location)
{
    void *pmem;
    MM_COMM *mm_comm;

    if(NULL_PTR == pvoid)
    {
        dbg_log(SEC_0066_MM, 0)(LOGSTDOUT, "error:safe_free: try to free null pointer at %s:%ld\n", MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
        return ;
    }

    pmem = (void *)((UINT32)pvoid - sizeof(UINT32));
    mm_comm = (MM_COMM *)(*((UINT32 *)pmem));

    if(mm_comm->pmem != pmem)
    {
        dbg_log(SEC_0066_MM, 1)(LOGSTDOUT, "warn:safe_free: found mismatched pmem pointer at %s:%ld\n", MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
    }

    free_static_mem(MM_COMM_NODE, mm_comm, location);
    free(pmem);
    return;
}

UINT32 get_static_mem_type(const UINT32 size)
{
    UINT32 mm_type;

    for(mm_type = BUFF_MEM_DEF_BEG; mm_type <= BUFF_MEM_DEF_END; mm_type ++)
    {
        MM_MAN *pMan;

        pMan = &(g_mem_manager[ (mm_type) ]);
        if(size <= pMan->typesize)
        {
            return mm_type;
        }
    }

    return (MM_END);
}

void *safe_calloc(const UINT32 size, const UINT32 location)
{
    UINT32 mm_type;
    void *pmem;

    mm_type = get_static_mem_type(size);
    if(MM_END != mm_type)
    {
        void    *pvoid;
        alloc_static_mem(mm_type, &pvoid, location);
        return (pvoid);
    }

    pmem = calloc(1, sizeof(MM_AUX) + size);
    if(NULL_PTR != pmem)
    {
        void    *pvoid;
        MM_COMM *mm_comm;
        MM_AUX  *pAux;

        /*to record the malloced memory, we have to alloc a comm node :-(*/
        /*if not need to record it, pmem is enough for free*/
        alloc_static_mem(MM_COMM_NODE, &mm_comm, location);

        pvoid = (void *)((UINT32)pmem + sizeof(MM_AUX));
        pAux  = (MM_AUX *)pmem;
        pAux->type      = MM_END;
        pAux->u.mm_comm = mm_comm;

        mm_comm->type = MM_END;
        mm_comm->pmem = pmem;
        return (pvoid);
    }
    return (NULL_PTR);
}

/*for debug only*/
EC_BOOL safe_assert(void *pvoid, const UINT32 location)
{
    MM_AUX  *pAux;
    void    *pmem;
    MM_COMM *mm_comm;

    pAux = (MM_AUX *)((UINT32)pvoid - sizeof(MM_AUX));
    pmem = (void *)pAux;

    mm_comm = pAux->u.mm_comm;
    if(mm_comm->pmem != pmem)
    {
        dbg_log(SEC_0066_MM, 0)(LOGSTDOUT, "error:safe_assert: found mismatched pmem pointer %p vs %p at %s:%ld\n", mm_comm->pmem, pmem, MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

/*for debug only*/
void *safe_fetch_pmem_of_mm_comm(void *pvoid)
{
    MM_AUX  *pAux;
    //void    *pmem;
    MM_COMM *mm_comm;

    pAux = (MM_AUX *)((UINT32)pvoid - sizeof(MM_AUX));
    //pmem = (void *)pAux;

    mm_comm = pAux->u.mm_comm;
    return (mm_comm->pmem);
}

/********************************************************************************************
*                ------------------
*       |------->|      MM_COMM   |
*       |        |----------------|            <== malloc memory from pool
*       |        |  type  |  pmem |
*       |        --------------|---
*       |                      |
*       |      ----------------|
*       |      |
*       |      |
*       |      V
*       |      ---------------------------
*       |      |    MM_AUX      |   <MEM> |
*       |      |--------------------------|     <=== malloc memory from heap
*       |      | type | mm_comm | pvoid   |
*       |      -----------|---------------
*       |                 |
*       |------------------
*
********************************************************************************************/

void *safe_malloc(const UINT32 size, const UINT32 location)
{
    void *pmem;

#if(SWITCH_ON == MM_DEBUG)
    if(1)
    {
        void *__pvoid = malloc((size_t)size);
        return __pvoid;
    }
#endif/*(SWITCH_ON == MM_DEBUG)*/

    if(1)
    {
        UINT32 mm_type;

        mm_type = get_static_mem_type(size);
        if(MM_END != mm_type)
        {
            void    *pvoid;
            alloc_static_mem(mm_type, &pvoid, location);
            MM_ASSERT(((MM_AUX *)((UINT32)pvoid - sizeof(MM_AUX)))->type == mm_type);
            return (pvoid);
        }
    }

    pmem = malloc(((size_t)size) + sizeof(MM_AUX));
    if(NULL_PTR != pmem)
    {
        void    *pvoid;
        MM_COMM *mm_comm;
        MM_AUX  *pAux;

        /*to record the malloced memory, we have to alloc a comm node :-(*/
        /*if not need to record it, pmem is enough for free*/
        alloc_static_mem(MM_COMM_NODE, &mm_comm, location);

        pvoid = (void *)((UINT32)pmem + sizeof(MM_AUX));
        pAux  = (MM_AUX *)pmem;
        pAux->type      = MM_END;
        pAux->u.mm_comm = mm_comm;

        mm_comm->type = MM_END;
        mm_comm->pmem = pmem;

        return (pvoid);
    }
    return (NULL_PTR);
}

void safe_free(void *pvoid, const UINT32 location)
{
    MM_AUX  *pAux;
    void    *pmem;
    MM_COMM *mm_comm;

    if(NULL_PTR == pvoid)
    {
        dbg_log(SEC_0066_MM, 0)(LOGSTDOUT, "error:safe_free: try to free null pointer at %s:%ld\n", MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
        return ;
    }

#if(SWITCH_ON == MM_DEBUG)
    if(1)
    {
        free(pvoid);
        return;
    }
#endif/*(SWITCH_ON == MM_DEBUG)*/

    pAux = (MM_AUX *)((UINT32)pvoid - sizeof(MM_AUX));

    if(0 == pAux->type)
    {
        dbg_log(SEC_0066_MM, 0)(LOGSTDOUT, "error:safe_free: found invalid type of %p, u %p at %s:%ld\n", pvoid, pAux->u.mm_comm, MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
        ASSERT(0 != pAux->type);
    }

    if(MM_END != pAux->type)
    {
        free_static_mem(pAux->type, pvoid, location);
        return;
    }

    pmem = (void *)pAux;

    mm_comm = pAux->u.mm_comm;
    if(mm_comm->pmem != pmem)
    {
        dbg_log(SEC_0066_MM, 1)(LOGSTDOUT, "warn:safe_free: found mismatched pmem pointer at %s:%ld\n", MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
        ASSERT(mm_comm->pmem == pmem);
    }

    if(MM_END != pAux->type)
    {
        dbg_log(SEC_0066_MM, 1)(LOGSTDOUT, "warn:safe_free: found mismatched pmem pointer at %s:%ld\n", MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
    }

    mm_comm->pmem = NULL_PTR;
    free_static_mem(MM_COMM_NODE, mm_comm, location);

    free(pmem);
    return;
}

void safe_copy(UINT8 *old_ptr, UINT8 *new_ptr, UINT32 len)
{
    BCOPY(old_ptr, new_ptr, len);
    return;
}

void *safe_realloc(void *old_pvoid, const UINT32 old_size, const UINT32 new_size, const UINT32 location)
{
    void *new_pvoid;

    new_pvoid = safe_malloc(new_size, location);

    BCOPY(old_pvoid, new_pvoid, DMIN(old_size, new_size));/*for both expand and shrink*/
    safe_free(old_pvoid, location);

    return (new_pvoid);
}

void print_static_mem_status(LOG *log)
{
    UINT32  type;

    if ( EC_TRUE == g_mem_init_flag )
    {
        sys_log(log,"g_mem_init_flag = EC_TRUE\n");
    }
    else
    {
        sys_log(log,"g_mem_init_flag = EC_FALSE\n");
        return;
    }

    for ( type = 0; type < MM_END; type ++ )
    {
        print_static_mem_status_of_type(log, type);
    }

    return ;
}

void print_static_mem_status_of_type(LOG *log, const UINT32  type)
{
    MM_MAN *pMan;

    if ( EC_FALSE == g_mem_init_flag )
    {
        return;
    }

    if(type >= MM_END)
    {
        sys_log(log, "error:print_static_mem_status_of_type: invalid type %ld\n", type);
        return ;
    }

    pMan = &(g_mem_manager[ type ]);
    //MAN_LOCK(pMan, LOC_MM_0263);

    if( 0 < pMan->nodeblocknum || 0 < pMan->nodenumsum || 0 < pMan->maxusedsum || 0 < pMan->curusedsum )
    {
        sys_log(log,
            "Manager %4ld [%s]: nodeblock num = %8ld, nodesum = %8ld, maxused = %8ld, curused = %8ld\n",
            type, pMan->name,
            pMan->nodeblocknum,
            pMan->nodenumsum,
            pMan->maxusedsum,
            pMan->curusedsum );
    }

    return ;
}

UINT32 print_static_mem_diag_info(LOG *log)
{
    UINT32  type;

    /* if no static memory is allocated before, then return success */
    if ( EC_FALSE == g_mem_init_flag )
    {
        return ( 0 );
    }

    for ( type = 0; type < MM_END; type ++ )
    {
        print_static_mem_diag_info_of_type(log, type);
    }

    return 0;
}

UINT32 print_static_mem_diag_info_of_type(LOG *log, const UINT32 type)
{
    MM_MAN *pMan;
    MM_NODE *pNode;
    MM_NODE_BLOCK *pNodeBlock;
    UINT32 node_num;
    UINT32 node_idx;

    /* if no static memory is allocated before, then return success */
    if ( EC_FALSE == g_mem_init_flag )
    {
        return ( 0 );
    }

    if(type >= MM_END)
    {
        sys_log(log, "error:print_static_mem_diag_info_of_type: invalid type %ld\n", type);
        return ((UINT32)-1);
    }

    /* do this manager */
    pMan = &(g_mem_manager[ type ]);

    MAN_LINKNODEBLOCK_LOOP_NEXT(pMan, pNodeBlock)
    {
        /* do this node block */
        node_num = pNodeBlock->nodenum;
        for ( node_idx = 0; node_idx < node_num; node_idx ++ )
        {
            /* do this node */
            pNode = &( pNodeBlock->pnodes[ node_idx ] );

            if ( MM_NODE_USED == pNode->usedflag)
            {
                sys_log(log,"Manager %4ld [%s]: file name = %s, line no = %ld, addr = %p, counter = %u\n",
                    type, pMan->name,
                    MM_LOC_FILE_NAME(pNode->location),
                    MM_LOC_LINE_NO(pNode->location),
                    pNode->pmem + sizeof(MM_AUX),
                    pNode->counter);
            }
        }
    }

    return 0;
}

UINT32 print_static_mem_diag_detail_of_type(LOG *log, const UINT32 type, void (*show)(LOG *, void *))
{
    MM_MAN *pMan;
    MM_NODE *pNode;
    MM_NODE_BLOCK *pNodeBlock;
    UINT32 node_num;
    UINT32 node_idx;

    /* if no static memory is allocated before, then return success */
    if ( EC_FALSE == g_mem_init_flag )
    {
        return ( 0 );
    }

    if(type >= MM_END)
    {
        sys_log(log, "error:print_static_mem_diag_detail_of_type: invalid type %ld\n", type);
        return ((UINT32)-1);
    }

    /* do this manager */
    pMan = &(g_mem_manager[ type ]);

    MAN_LINKNODEBLOCK_LOOP_NEXT(pMan, pNodeBlock)
    {
        /* do this node block */
        node_num = pNodeBlock->nodenum;
        for ( node_idx = 0; node_idx < node_num; node_idx ++ )
        {
            /* do this node */
            pNode = &( pNodeBlock->pnodes[ node_idx ] );

            if ( MM_NODE_USED == pNode->usedflag)
            {
                sys_log(log,"Manager %4ld [%s]: file name = %s, line no = %ld, addr = %p, counter = %u\n",
                    type, pMan->name,
                    MM_LOC_FILE_NAME(pNode->location),
                    MM_LOC_LINE_NO(pNode->location),
                    pNode->pmem + sizeof(MM_AUX),
                    pNode->counter);
                show(log, (void *)(pNode->pmem + sizeof(MM_AUX)));
            }
        }
    }

    return 0;
}

UINT32 print_static_mem_stat_info(LOG *log)
{
    UINT32  type;

    /* if no static memory is allocated before, then return success */
    if ( EC_FALSE == g_mem_init_flag )
    {
        return ( 0 );
    }

    for ( type = 0; type < MM_END; type ++ )
    {
        print_static_mem_stat_info_of_type(log, type);
    }

    return 0;
}

typedef struct
{
    UINT32 type;
    UINT32 location;
    UINT32 count;
}LOCATION_STAT;

STATIC_CAST static void location_stat_tbl_init(LOCATION_STAT *location_stat_tbl, const UINT32 size)
{
    UINT32 pos;

    for(pos = 0; pos < size; pos ++)
    {
        LOCATION_STAT *location_stat;

        location_stat = (location_stat_tbl + pos);
        location_stat->type    = MM_END;
        location_stat->location = (UINT32)-1;
        location_stat->count    = 0;
    }
    return;
}

STATIC_CAST static void location_stat_tbl_update(LOCATION_STAT *location_stat_tbl, const UINT32 size, const UINT32 type, const UINT32 location)
{
    UINT32 pos;

    for(pos = 0; pos < size; pos ++)
    {
        LOCATION_STAT *location_stat;

        location_stat = (location_stat_tbl + pos);
        if(location_stat->type == type && location_stat->location == location)
        {
            location_stat->count ++;
            return;
        }
    }

    for(pos = 0; pos < size; pos ++)
    {
        LOCATION_STAT *location_stat;

        location_stat = (location_stat_tbl + pos);
        if(0 == location_stat->count && (UINT32)-1 == location_stat->location)
        {
            location_stat->type     = type;
            location_stat->location = location;
            location_stat->count ++;
            return;
        }
    }

    dbg_log(SEC_0066_MM, 0)(LOGSTDOUT, "error:location_stat_tbl_update: location %ld overflow or invalid type %ld\n", location, type);
    return;
}

STATIC_CAST static void location_stat_tbl_print(LOG *log, const LOCATION_STAT *location_stat_tbl, const UINT32 size)
{
    UINT32 pos;

    for(pos = 0; pos < size; pos ++)
    {
        LOCATION_STAT *location_stat;

        location_stat = (LOCATION_STAT *)(location_stat_tbl + pos);
        if(0 == location_stat->count)
        {
            continue;
        }

        sys_log(log, "Manager %8ld: %8ld times at %s:%ld\n", location_stat->type, location_stat->count, MM_LOC_FILE_NAME(location_stat->location), MM_LOC_LINE_NO(location_stat->location));
    }
    return;
}

UINT32 print_static_mem_stat_info_of_type(LOG *log, const UINT32 type)
{
    MM_MAN *pMan;
    MM_NODE *pNode;
    MM_NODE_BLOCK *pNodeBlock;
    UINT32 node_num;
    UINT32 node_idx;

    LOCATION_STAT  location_stat_tbl[1024];
    UINT32         location_stat_tbl_size;

    /* if no static memory is allocated before, then return success */
    if ( EC_FALSE == g_mem_init_flag )
    {
        return ( 0 );
    }

    if(type >= MM_END)
    {
        sys_log(log, "error:print_static_mem_stat_info_of_type: invalid type %ld\n", type);
        return ((UINT32)-1);
    }

    location_stat_tbl_size = sizeof(location_stat_tbl)/sizeof(location_stat_tbl[0]);
    location_stat_tbl_init(location_stat_tbl, location_stat_tbl_size);

    /* do this manager */
    pMan = &(g_mem_manager[ type ]);

    MAN_LINKNODEBLOCK_LOOP_NEXT(pMan, pNodeBlock)
    {
        /* do this node block */
        node_num = pNodeBlock->nodenum;
        for ( node_idx = 0; node_idx < node_num; node_idx ++ )
        {
            /* do this node */
            pNode = &( pNodeBlock->pnodes[ node_idx ] );

            if ( MM_NODE_USED == pNode->usedflag )
            {
                location_stat_tbl_update(location_stat_tbl, location_stat_tbl_size, type, pNode->location);
            }
        }
    }

    location_stat_tbl_print(log, location_stat_tbl, location_stat_tbl_size);

    return 0;
}

UINT32 mm_man_occupy_node_clean(MM_MAN_OCCUPY_NODE *mm_man_occupy_node)
{
    MM_MAN_OCCUPY_NODE_TYPE(mm_man_occupy_node) = MM_END;
    MM_MAN_OCCUPY_NODE_SUM(mm_man_occupy_node)  = 0;
    MM_MAN_OCCUPY_NODE_MAX(mm_man_occupy_node)  = 0;
    MM_MAN_OCCUPY_NODE_CUR(mm_man_occupy_node)  = 0;

    return (0);
}

UINT32 mm_man_occupy_node_init(MM_MAN_OCCUPY_NODE *mm_man_occupy_node)
{
    MM_MAN_OCCUPY_NODE_TYPE(mm_man_occupy_node) = MM_END;
    MM_MAN_OCCUPY_NODE_SUM(mm_man_occupy_node)  = 0;
    MM_MAN_OCCUPY_NODE_MAX(mm_man_occupy_node)  = 0;
    MM_MAN_OCCUPY_NODE_CUR(mm_man_occupy_node)  = 0;

    return (0);
}

UINT32 mm_man_occupy_node_free(MM_MAN_OCCUPY_NODE *mm_man_occupy_node)
{
    free_static_mem(MM_MM_MAN_OCCUPY_NODE, mm_man_occupy_node, LOC_MM_0266);
    return (0);
}

UINT32 mm_man_occupy_node_clone(MM_MAN_OCCUPY_NODE *mm_man_occupy_node_src, MM_MAN_OCCUPY_NODE *mm_man_occupy_node_des)
{
    MM_MAN_OCCUPY_NODE_TYPE(mm_man_occupy_node_des) = MM_MAN_OCCUPY_NODE_TYPE(mm_man_occupy_node_src);
    MM_MAN_OCCUPY_NODE_SUM(mm_man_occupy_node_des)  = MM_MAN_OCCUPY_NODE_SUM(mm_man_occupy_node_src);
    MM_MAN_OCCUPY_NODE_MAX(mm_man_occupy_node_des)  = MM_MAN_OCCUPY_NODE_MAX(mm_man_occupy_node_src);
    MM_MAN_OCCUPY_NODE_CUR(mm_man_occupy_node_des)  = MM_MAN_OCCUPY_NODE_CUR(mm_man_occupy_node_src);

    return (0);
}

EC_BOOL mm_man_occupy_node_was_used(const UINT32 type)
{
    MM_MAN *pMan;

    if(type >= MM_END)
    {
        dbg_log(SEC_0066_MM, 0)(LOGSTDOUT, "error:mm_man_occupy_node_was_used: invalid type %ld\n", type);
        return (EC_FALSE);
    }

    pMan = &(g_mem_manager[ type ]);

    if( 0 < pMan->nodeblocknum || 0 < pMan->nodenumsum || 0 < pMan->maxusedsum || 0 < pMan->curusedsum )
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

UINT32 mm_man_occupy_node_fetch(const UINT32 type, MM_MAN_OCCUPY_NODE *mm_man_occupy_node)
{
    MM_MAN *pMan;

    if(type >= MM_END)
    {
        dbg_log(SEC_0066_MM, 0)(LOGSTDOUT, "error:mm_man_occupy_node_fetch: invalid type %ld\n", type);
        return ((UINT32)-1);
    }

    pMan = &(g_mem_manager[ type ]);

    MM_MAN_OCCUPY_NODE_TYPE(mm_man_occupy_node) = pMan->type;
    MM_MAN_OCCUPY_NODE_SUM(mm_man_occupy_node)  = pMan->nodenumsum;
    MM_MAN_OCCUPY_NODE_MAX(mm_man_occupy_node)  = pMan->maxusedsum;
    MM_MAN_OCCUPY_NODE_CUR(mm_man_occupy_node)  = pMan->curusedsum;

    return (0);
}

UINT32 mm_man_load_node_clean(MM_MAN_LOAD_NODE *mm_man_load_node)
{
    MM_MAN_LOAD_NODE_TYPE(mm_man_load_node) = MM_END;
    MM_MAN_LOAD_NODE_MAX(mm_man_load_node)  = 0.0;
    MM_MAN_LOAD_NODE_CUR(mm_man_load_node)  = 0.0;

    return (0);
}

UINT32 mm_man_load_node_init(MM_MAN_LOAD_NODE *mm_man_load_node)
{
    MM_MAN_LOAD_NODE_TYPE(mm_man_load_node) = MM_END;
    MM_MAN_LOAD_NODE_MAX(mm_man_load_node)  = 0.0;
    MM_MAN_LOAD_NODE_CUR(mm_man_load_node)  = 0.0;

    return (0);
}

UINT32 mm_man_load_node_free(MM_MAN_LOAD_NODE *mm_man_load_node)
{
    free_static_mem(MM_MM_MAN_LOAD_NODE, mm_man_load_node, LOC_MM_0267);
    return (0);
}

UINT32 mm_man_load_node_clone(MM_MAN_LOAD_NODE *mm_man_load_node_src, MM_MAN_LOAD_NODE *mm_man_load_node_des)
{
    MM_MAN_LOAD_NODE_TYPE(mm_man_load_node_des) = MM_MAN_LOAD_NODE_TYPE(mm_man_load_node_src);
    MM_MAN_LOAD_NODE_MAX(mm_man_load_node_des)  = MM_MAN_LOAD_NODE_MAX(mm_man_load_node_src);
    MM_MAN_LOAD_NODE_CUR(mm_man_load_node_des)  = MM_MAN_LOAD_NODE_CUR(mm_man_load_node_src);

    return (0);
}

EC_BOOL mm_man_load_node_was_used(const UINT32 type)
{
    MM_MAN *pMan;

    if(type >= MM_END)
    {
        dbg_log(SEC_0066_MM, 0)(LOGSTDOUT, "error:mm_man_load_node_was_used: invalid type %ld\n", type);
        return (EC_FALSE);
    }

    pMan = &(g_mem_manager[ type ]);

    if( 0 < pMan->nodeblocknum || 0 < pMan->nodenumsum || 0 < pMan->maxusedsum || 0 < pMan->curusedsum )
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

UINT32 mm_man_load_node_fetch(const UINT32 type, MM_MAN_LOAD_NODE *mm_man_load_node)
{
    MM_MAN *pMan;

    if(type >= MM_END)
    {
        dbg_log(SEC_0066_MM, 0)(LOGSTDOUT, "error:mm_man_load_node_fetch: invalid type %ld\n", type);
        return ((UINT32)-1);
    }

    pMan = &(g_mem_manager[ type ]);

    MM_MAN_LOAD_NODE_TYPE(mm_man_load_node) = pMan->type;
    MM_MAN_LOAD_NODE_MAX(mm_man_load_node)  = (100.0 * pMan->maxusedsum) / pMan->nodenumsum;
    MM_MAN_LOAD_NODE_CUR(mm_man_load_node)  = (100.0 * pMan->curusedsum) / pMan->nodenumsum;

    return (0);
}



#ifdef __cplusplus
}
#endif/*__cplusplus*/

