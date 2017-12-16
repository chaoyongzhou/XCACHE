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

#ifndef _CLOAD_H
#define _CLOAD_H

#include "type.h"
#include "clist.h"
#include "cvector.h"
#include "cmisc.h"

#define CLOAD_ERR_LOAD                 ((UINT32)  -1)

#define CLOAD_MAKE(old_load, new_load) (new_load)
#define CLOAD_INC(load)                (load + 1)
#define CLOAD_DEC(load)                (load - 1)

typedef struct
{
    UINT16 que_load;/*total in queues*/
    UINT16 obj_load;/*total module objects*/
    UINT8  cpu_load;/*[0..100]*/
    UINT8  mem_load;/*[0..100]*/
    UINT8  dsk_load;/*[0..100]*/
    UINT8  net_load;/*[0..100]*/
    CTIMET last_update;
}CLOAD_STAT;

#define CLOAD_STAT_QUE_LOAD(cload_stat)         ((cload_stat)->que_load)
#define CLOAD_STAT_OBJ_LOAD(cload_stat)         ((cload_stat)->obj_load)
#define CLOAD_STAT_CPU_LOAD(cload_stat)         ((cload_stat)->cpu_load)
#define CLOAD_STAT_MEM_LOAD(cload_stat)         ((cload_stat)->mem_load)
#define CLOAD_STAT_DSK_LOAD(cload_stat)         ((cload_stat)->dsk_load)
#define CLOAD_STAT_NET_LOAD(cload_stat)         ((cload_stat)->net_load)
#define CLOAD_STAT_LAST_UPDATE(cload_stat)      ((cload_stat)->last_update)


typedef struct
{
    UINT32      tcid;
    UINT32      comm;
    CVECTOR     rank_load_stat_vec;/*item type is CLOAD_STAT*/
}CLOAD_NODE;

#define CLOAD_NODE_TCID(cload_node)                  ((cload_node)->tcid)
#define CLOAD_NODE_COMM(cload_node)                  ((cload_node)->comm)
#define CLOAD_NODE_TCID_STR(cload_node)              (c_word_to_ipv4(CLOAD_NODE_TCID(cload_node)))
#define CLOAD_NODE_RANK_LOAD_STAT_VEC(cload_node)    (&((cload_node)->rank_load_stat_vec))
#define CLOAD_NODE_RANK_LOAD_STAT(cload_node, rank)  ((CLOAD_STAT *)cvector_get(CLOAD_NODE_RANK_LOAD_STAT_VEC(cload_node), (rank)))

typedef CLIST CLOAD_MGR;/*item is CLOAD_NODE*/

CLOAD_STAT *cload_stat_new();

EC_BOOL cload_stat_init(CLOAD_STAT *cload_stat);

EC_BOOL cload_stat_clean(CLOAD_STAT *cload_stat);

EC_BOOL cload_stat_free(CLOAD_STAT *cload_stat);

EC_BOOL cload_stat_clone(const CLOAD_STAT *cload_stat_src, CLOAD_STAT *cload_stat_des);

EC_BOOL cload_stat_update(const CLOAD_STAT *cload_stat_src, CLOAD_STAT *cload_stat_des);

EC_BOOL cload_stat_set_que(CLOAD_STAT *cload_stat, const UINT32 que_load);

EC_BOOL cload_stat_inc_que(CLOAD_STAT *cload_stat);

EC_BOOL cload_stat_dec_que(CLOAD_STAT *cload_stat);

CLOAD_NODE *cload_node_new(const UINT32 tcid, const UINT32 comm, const UINT32 size);

EC_BOOL cload_node_init(CLOAD_NODE *cload_node, const UINT32 tcid, const UINT32 comm, const UINT32 size);

EC_BOOL cload_node_clean(CLOAD_NODE *cload_node);

EC_BOOL cload_node_free(CLOAD_NODE *cload_node);

EC_BOOL cload_node_clone(const CLOAD_NODE *cload_node_src, CLOAD_NODE *cload_node_des);

EC_BOOL cload_node_update(const CLOAD_NODE *cload_node_src, CLOAD_NODE *cload_node_des);

void    cload_node_print(LOG *log, const CLOAD_NODE *cload_node);

EC_BOOL cload_node_init_0(CLOAD_NODE *cload_node);

CLOAD_STAT * cload_node_get(CLOAD_NODE *cload_node, const UINT32 rank);

EC_BOOL cload_node_set(CLOAD_NODE *cload_node, const UINT32 rank, const CLOAD_STAT *cload_stat_src);

EC_BOOL cload_node_set_que(CLOAD_NODE *cload_node, const UINT32 rank, const UINT32 que_load);

UINT32  cload_node_get_que(CLOAD_NODE *cload_node, const UINT32 rank);

EC_BOOL cload_node_inc_que(CLOAD_NODE *cload_node, const UINT32 rank);

EC_BOOL cload_node_dec_que(CLOAD_NODE *cload_node, const UINT32 rank);

EC_BOOL cload_node_fast_dec_que(CLOAD_NODE *cload_node, const UINT32 interval_nsec);

EC_BOOL cload_node_cmp_tcid(const CLOAD_NODE *cload_node_1st, const CLOAD_NODE *cload_node_2nd);

UINT32 cload_node_get_obj(CLOAD_NODE *cload_node, const UINT32 rank);

UINT32 cload_node_get_cpu(CLOAD_NODE *cload_node, const UINT32 rank);

UINT32 cload_node_get_mem(CLOAD_NODE *cload_node, const UINT32 rank);

UINT32 cload_node_get_dsk(CLOAD_NODE *cload_node, const UINT32 rank);

UINT32 cload_node_get_net(CLOAD_NODE *cload_node, const UINT32 rank);

CLIST *cload_mgr_new();

EC_BOOL cload_mgr_init(CLIST *cload_mgr);

EC_BOOL cload_mgr_clean(CLIST *cload_mgr);

EC_BOOL cload_mgr_free(CLIST *cload_mgr);

EC_BOOL cload_mgr_add(CLIST *cload_mgr, const CLOAD_NODE *cload_node);

EC_BOOL cload_mgr_rmv(CLIST *cload_mgr, const CLOAD_NODE *cload_node);

EC_BOOL cload_mgr_update(CLIST *cload_mgr, const CLOAD_NODE *cload_node);

CLOAD_NODE * cload_mgr_search(const CLIST *cload_mgr, const UINT32 tcid);

CLOAD_STAT * cload_mgr_get(const CLIST *cload_mgr, const UINT32 tcid, const UINT32 rank);

EC_BOOL cload_mgr_set(CLIST *cload_mgr, const UINT32 tcid, const UINT32 rank, const CLOAD_STAT *cload_stat);

EC_BOOL cload_mgr_set_que(CLIST *cload_mgr, const UINT32 tcid, const UINT32 rank, const UINT32 que_load);

UINT32  cload_mgr_get_que(const CLIST *cload_mgr, const UINT32 tcid, const UINT32 rank);

UINT32  cload_mgr_get_obj(const CLIST *cload_mgr, const UINT32 tcid, const UINT32 rank);

UINT32  cload_mgr_get_cpu(const CLIST *cload_mgr, const UINT32 tcid, const UINT32 rank);

UINT32  cload_mgr_get_mem(const CLIST *cload_mgr, const UINT32 tcid, const UINT32 rank);

UINT32  cload_mgr_get_dsk(const CLIST *cload_mgr, const UINT32 tcid, const UINT32 rank);

UINT32  cload_mgr_get_net(const CLIST *cload_mgr, const UINT32 tcid, const UINT32 rank);

EC_BOOL cload_mgr_del(CLIST *cload_mgr, const UINT32 tcid);

EC_BOOL cload_mgr_inc_que(CLIST *cload_mgr, const UINT32 tcid, const UINT32 rank);

EC_BOOL cload_mgr_dec_que(CLIST *cload_mgr, const UINT32 tcid, const UINT32 rank);

EC_BOOL cload_mgr_fast_decrease(CLIST *cload_mgr, const UINT32 interval_nsec);

void    cload_mgr_print(LOG *log, const CLIST *cload_mgr);


#endif /*_CLOAD_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/
