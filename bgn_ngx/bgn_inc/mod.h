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

#ifndef _MOD_H
#define _MOD_H

#include <stdio.h>
#include <stdlib.h>

#include "cmpic.inc"
#include "type.h"

#include "debug.h"

#include "cvector.h"
#include "cset.h"

#include "task.inc"
#include "tcnode.h"
#include "mod.inc"


/*--------------------------------------------- interface -----------------------------------------*/
EC_BOOL mod_node_alloc(MOD_NODE **mod_node);

MOD_NODE *mod_node_new();

EC_BOOL mod_node_free(MOD_NODE *mod_node);

EC_BOOL mod_node_clean(MOD_NODE *mod_node);

EC_BOOL mod_node_init(MOD_NODE *mod_node);

EC_BOOL mod_node_is_local(const MOD_NODE *mod_node);

EC_BOOL mod_node_update_local_stat(MOD_NODE *mod_node);

EC_BOOL mod_node_clone(const MOD_NODE *src_mod_node, MOD_NODE *des_mod_node);

EC_BOOL mod_node_cmp(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2);

EC_BOOL mod_node_vote_gt_hops(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2);

EC_BOOL mod_node_vote_ge_hops(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2);

EC_BOOL mod_node_vote_lt_hops(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2);

EC_BOOL mod_node_vote_le_hops(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2);

EC_BOOL mod_node_vote_gt_que(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2);

EC_BOOL mod_node_vote_ge_que(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2);

EC_BOOL mod_node_vote_lt_que(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2);

EC_BOOL mod_node_vote_le_que(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2);

EC_BOOL mod_node_vote_gt_obj(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2);

EC_BOOL mod_node_vote_ge_obj(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2);

EC_BOOL mod_node_vote_lt_obj(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2);

EC_BOOL mod_node_vote_le_obj(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2);

EC_BOOL mod_node_vote_gt_cpu(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2);

EC_BOOL mod_node_vote_ge_cpu(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2);

EC_BOOL mod_node_vote_lt_cpu(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2);

EC_BOOL mod_node_vote_le_cpu(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2);

EC_BOOL mod_node_vote_gt_mem(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2);

EC_BOOL mod_node_vote_ge_mem(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2);

EC_BOOL mod_node_vote_lt_mem(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2);

EC_BOOL mod_node_vote_le_mem(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2);

EC_BOOL mod_node_vote_gt_dsk(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2);

EC_BOOL mod_node_vote_ge_dsk(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2);

EC_BOOL mod_node_vote_lt_dsk(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2);

EC_BOOL mod_node_vote_le_dsk(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2);

EC_BOOL mod_node_vote_gt_net(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2);

EC_BOOL mod_node_vote_ge_net(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2);

EC_BOOL mod_node_vote_lt_net(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2);

EC_BOOL mod_node_vote_le_net(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2);


void mod_node_print(LOG *log, const MOD_NODE *mod_node);

/*as the algo described below, when src_mod_node_1 < src_mod_node_2, return EC_TRUE, otherwise return EC_FALSE*/
EC_BOOL mod_node_lt_que(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2);

/*as the algo described below, when src_mod_node_1 <= src_mod_node_2, return EC_TRUE, otherwise return EC_FALSE*/
EC_BOOL mod_node_le_que(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2);

/*as the algo described below, when src_mod_node_1 > src_mod_node_2, return EC_TRUE, otherwise return EC_FALSE*/
EC_BOOL mod_node_gt_que(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2);

/*as the algo described below, when src_mod_node_1 >= src_mod_node_2, return EC_TRUE, otherwise return EC_FALSE*/
EC_BOOL mod_node_ge_que(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2);

/*as the algo described below, when src_mod_node_1 < src_mod_node_2, return EC_TRUE, otherwise return EC_FALSE*/
EC_BOOL mod_node_lt_obj(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2);

/*as the algo described below, when src_mod_node_1 <= src_mod_node_2, return EC_TRUE, otherwise return EC_FALSE*/
EC_BOOL mod_node_le_obj(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2);

/*as the algo described below, when src_mod_node_1 > src_mod_node_2, return EC_TRUE, otherwise return EC_FALSE*/
EC_BOOL mod_node_gt_obj(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2);

/*as the algo described below, when src_mod_node_1 >= src_mod_node_2, return EC_TRUE, otherwise return EC_FALSE*/
EC_BOOL mod_node_ge_obj(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2);

/*as the algo described below, when src_mod_node_1 < src_mod_node_2, return EC_TRUE, otherwise return EC_FALSE*/
EC_BOOL mod_node_lt_cpu(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2);

/*as the algo described below, when src_mod_node_1 <= src_mod_node_2, return EC_TRUE, otherwise return EC_FALSE*/
EC_BOOL mod_node_le_cpu(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2);

/*as the algo described below, when src_mod_node_1 > src_mod_node_2, return EC_TRUE, otherwise return EC_FALSE*/
EC_BOOL mod_node_gt_cpu(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2);

/*as the algo described below, when src_mod_node_1 >= src_mod_node_2, return EC_TRUE, otherwise return EC_FALSE*/
EC_BOOL mod_node_ge_cpu(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2);

/*as the algo described below, when src_mod_node_1 < src_mod_node_2, return EC_TRUE, otherwise return EC_FALSE*/
EC_BOOL mod_node_lt_mem(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2);

/*as the algo described below, when src_mod_node_1 <= src_mod_node_2, return EC_TRUE, otherwise return EC_FALSE*/
EC_BOOL mod_node_le_mem(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2);

/*as the algo described below, when src_mod_node_1 > src_mod_node_2, return EC_TRUE, otherwise return EC_FALSE*/
EC_BOOL mod_node_gt_mem(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2);

/*as the algo described below, when src_mod_node_1 >= src_mod_node_2, return EC_TRUE, otherwise return EC_FALSE*/
EC_BOOL mod_node_ge_mem(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2);

/*as the algo described below, when src_mod_node_1 < src_mod_node_2, return EC_TRUE, otherwise return EC_FALSE*/
EC_BOOL mod_node_lt_dsk(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2);

/*as the algo described below, when src_mod_node_1 <= src_mod_node_2, return EC_TRUE, otherwise return EC_FALSE*/
EC_BOOL mod_node_le_dsk(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2);

/*as the algo described below, when src_mod_node_1 > src_mod_node_2, return EC_TRUE, otherwise return EC_FALSE*/
EC_BOOL mod_node_gt_dsk(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2);

/*as the algo described below, when src_mod_node_1 >= src_mod_node_2, return EC_TRUE, otherwise return EC_FALSE*/
EC_BOOL mod_node_ge_dsk(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2);

/*as the algo described below, when src_mod_node_1 < src_mod_node_2, return EC_TRUE, otherwise return EC_FALSE*/
EC_BOOL mod_node_lt_net(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2);

/*as the algo described below, when src_mod_node_1 <= src_mod_node_2, return EC_TRUE, otherwise return EC_FALSE*/
EC_BOOL mod_node_le_net(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2);

/*as the algo described below, when src_mod_node_1 > src_mod_node_2, return EC_TRUE, otherwise return EC_FALSE*/
EC_BOOL mod_node_gt_net(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2);

/*as the algo described below, when src_mod_node_1 >= src_mod_node_2, return EC_TRUE, otherwise return EC_FALSE*/
EC_BOOL mod_node_ge_net(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2);

EC_BOOL mod_node_tcid_filter(const MOD_NODE *mod_node, const UINT32 tcid);

EC_BOOL mod_node_rank_filter(const MOD_NODE *mod_node, const UINT32 rank);

EC_BOOL mod_node_modi_filter(const MOD_NODE *mod_node, const UINT32 modi);

EC_BOOL mod_node_tcid_excl_filter(const MOD_NODE *mod_node, const UINT32 tcid);

EC_BOOL mod_node_rank_excl_filter(const MOD_NODE *mod_node, const UINT32 rank);

EC_BOOL mod_node_modi_excl_filter(const MOD_NODE *mod_node, const UINT32 modi);

/*---------------------------------------- interface of MOD_MGR ----------------------------------------------*/
EC_BOOL mod_mgr_init(MOD_MGR * mod_mgr);

//EC_BOOL mod_mgr_alloc(MOD_MGR **mod_mgr);

MOD_MGR * mod_mgr_new(const UINT32 local_md_id, const UINT32 load_balancing_choice);

EC_BOOL mod_mgr_free(MOD_MGR *mod_mgr);

EC_BOOL mod_mgr_clean(MOD_MGR * mod_mgr);

EC_BOOL mod_mgr_set_local_mod(MOD_MGR * mod_mgr, const UINT32 local_md_id);

EC_BOOL mod_mgr_set_load_balancing(MOD_MGR * mod_mgr, const UINT32 load_balancing_choice);

/*clone limited part, but not the whole, of mod_mgr*/
EC_BOOL mod_mgr_limited_clone(const UINT32 mod_id, const MOD_MGR * src_mod_mgr, MOD_MGR *des_mod_mgr);

EC_BOOL mod_mgr_limited_clone_with_tcid_filter(const UINT32 mod_id, const MOD_MGR * src_mod_mgr, const CVECTOR *tcid_vec, MOD_MGR *des_mod_mgr);

EC_BOOL mod_mgr_limited_clone_with_rank_filter(const UINT32 mod_id, const MOD_MGR * src_mod_mgr, const CVECTOR *rank_vec, MOD_MGR *des_mod_mgr);

EC_BOOL mod_mgr_limited_clone_with_modi_filter(const UINT32 mod_id, const MOD_MGR * src_mod_mgr, const CVECTOR *modi_vec, MOD_MGR *des_mod_mgr);

EC_BOOL mod_mgr_limited_clone_with_tcid_excl_filter(const UINT32 mod_id, const MOD_MGR * src_mod_mgr, const CVECTOR *tcid_vec, MOD_MGR *des_mod_mgr);

EC_BOOL mod_mgr_limited_clone_with_rank_excl_filter(const UINT32 mod_id, const MOD_MGR * src_mod_mgr, const CVECTOR *rank_vec, MOD_MGR *des_mod_mgr);

EC_BOOL mod_mgr_limited_clone_with_modi_excl_filter(const UINT32 mod_id, const MOD_MGR * src_mod_mgr, const CVECTOR *modi_vec, MOD_MGR *des_mod_mgr);

/*generate mod_mgr from taskc_mgr*/
EC_BOOL mod_mgr_gen_by_taskc_mgr(const TASKC_MGR *taskc_mgr, const UINT32 tcid, const UINT32 rank, const UINT32 spec_modi, MOD_MGR *mod_mgr);

EC_BOOL mod_mgr_gen_from_cload_mgr(const CLOAD_MGR *cload_mgr, const UINT32 tcid, const UINT32 rank, const UINT32 spec_modi, MOD_MGR *mod_mgr);

/*initialize mod_mgr_def*/
EC_BOOL mod_mgr_default_init(MOD_MGR *mod_mgr_def, const UINT32 tcid, const UINT32 rank);

EC_BOOL mod_mgr_default_sync(const UINT32 max_hops, const UINT32 max_remotes, const UINT32 time_to_live, MOD_MGR *mod_mgr_def);

MOD_NODE * mod_mgr_loop_get(const MOD_MGR *mod_mgr, UINT32 *pos);

MOD_NODE * mod_mgr_loop_find(const MOD_MGR *mod_mgr, const UINT32 tcid, UINT32 *pos);


MOD_NODE *mod_mgr_find_min_load_with_tcid_filter(const MOD_MGR *mod_mgr, const UINT32 tcid);

MOD_NODE *mod_mgr_find_min_load_with_rank_filter(const MOD_MGR *mod_mgr, const UINT32 rank);

MOD_NODE *mod_mgr_find_min_load_with_modi_filter(const MOD_MGR *mod_mgr, const UINT32 modi);

MOD_NODE *mod_mgr_find_min_load_with_tcid_vec_filter(const MOD_MGR *mod_mgr, const CVECTOR *tcid_vec);

MOD_NODE *mod_mgr_find_min_load_with_rank_vec_filter(const MOD_MGR *mod_mgr, const CVECTOR *rank_vec);

MOD_NODE *mod_mgr_find_min_load_with_modi_vec_filter(const MOD_MGR *mod_mgr, const CVECTOR *modi_vec);

MOD_NODE *mod_mgr_find_min_load_with_tcid_excl_filter(const MOD_MGR *mod_mgr, const UINT32 tcid);

MOD_NODE *mod_mgr_find_min_load_with_rank_excl_filter(const MOD_MGR *mod_mgr, const UINT32 rank);

MOD_NODE *mod_mgr_find_min_load_with_modi_excl_filter(const MOD_MGR *mod_mgr, const UINT32 modi);

MOD_NODE *mod_mgr_find_min_load_with_tcid_vec_excl_filter(const MOD_MGR *mod_mgr, const CVECTOR *tcid_vec);

MOD_NODE *mod_mgr_find_min_load_with_rank_vec_excl_filter(const MOD_MGR *mod_mgr, const CVECTOR *rank_vec);

MOD_NODE *mod_mgr_find_min_load_with_modi_vec_excl_filter(const MOD_MGR *mod_mgr, const CVECTOR *modi_vec);

/*------------------ load balancing strategy of mod_mgr ------------------ */

/*get load balancing strategy*/
MOD_MGR_LDB * mod_mgr_ldb_strategy(const UINT32 load_balancing_strategy);

/*get remote mod node by loop load balancing strategy*/
MOD_NODE * mod_mgr_ldb_loop_get(MOD_MGR *mod_mgr);

/*get remote mod node by queue load balancing strategy*/
MOD_NODE * mod_mgr_ldb_mod_get(MOD_MGR *mod_mgr);

void mod_mgr_remote_mod_load_print(LOG *log, TASK_BRD *task_brd, MOD_NODE *mod_node);

void mod_mgr_remote_mod_list_load_print(LOG *log, TASK_BRD *task_brd, MOD_MGR *mod_mgr);

/*get remote mod node by rank load balancing strategy*/
MOD_NODE * mod_mgr_ldb_que_get(MOD_MGR *mod_mgr);

MOD_NODE * mod_mgr_ldb_obj_get(MOD_MGR *mod_mgr);

MOD_NODE * mod_mgr_ldb_cpu_get(MOD_MGR *mod_mgr);

MOD_NODE * mod_mgr_ldb_mem_get(MOD_MGR *mod_mgr);

MOD_NODE * mod_mgr_ldb_dsk_get(MOD_MGR *mod_mgr);

MOD_NODE * mod_mgr_ldb_net_get(MOD_MGR *mod_mgr);

EC_BOOL mod_mgr_print(LOG *log, const MOD_MGR * mod_mgr);

EC_BOOL mod_mgr_set(const UINT32 that_tcid, const UINT32 that_comm, const UINT32 that_modi, const CSET *rank_set, MOD_MGR *mod_mgr_def);

UINT32 mod_mgr_incl(const UINT32 tcid, const UINT32 comm, const UINT32 rank, const UINT32 modi, MOD_MGR *mod_mgr);

UINT32 mod_mgr_excl(const UINT32 tcid, const UINT32 comm, const UINT32 rank, const UINT32 modi, MOD_MGR *mod_mgr);

UINT32 mod_mgr_remote_mod_node_clone_with_tcid_filter(const MOD_MGR *src_mod_mgr, const CVECTOR *tcid_vec, MOD_MGR *des_mod_mgr);

UINT32 mod_mgr_remote_mod_node_clone_with_rank_filter(const MOD_MGR *src_mod_mgr, const CVECTOR *rank_vec, MOD_MGR *des_mod_mgr);

UINT32 mod_mgr_remote_mod_node_clone_with_modi_filter(const MOD_MGR *src_mod_mgr, const CVECTOR *modi_vec, MOD_MGR *des_mod_mgr);

UINT32 mod_mgr_remote_mod_node_clone_with_tcid_excl_filter(const MOD_MGR *src_mod_mgr, const CVECTOR *tcid_vec, MOD_MGR *des_mod_mgr);

UINT32 mod_mgr_remote_mod_node_clone_with_rank_excl_filter(const MOD_MGR *src_mod_mgr, const CVECTOR *rank_vec, MOD_MGR *des_mod_mgr);

UINT32 mod_mgr_remote_mod_node_clone_with_modi_excl_filter(const MOD_MGR *src_mod_mgr, const CVECTOR *modi_vec, MOD_MGR *des_mod_mgr);

UINT32 mod_mgr_remote_mod_node_num(const MOD_MGR *mod_mgr);


/*run through remote mod_ndoe list while skip local mod_node*/
EC_BOOL mod_mgr_first_remote_mod_node_pos(const MOD_MGR *mod_mgr, UINT32 *remote_mod_node_pos);
EC_BOOL mod_mgr_last_remote_mod_node_pos(const MOD_MGR *mod_mgr, UINT32 *remote_mod_node_pos);
EC_BOOL mod_mgr_next_remote_mod_node_pos(const MOD_MGR *mod_mgr, UINT32 *remote_mod_node_pos);
EC_BOOL mod_mgr_prev_remote_mod_node_pos(const MOD_MGR *mod_mgr, UINT32 *remote_mod_node_pos);

/*simple interface of run throung remote mod_node list while NOT consider local mod_node*/
UINT32 mod_mgr_remote_num(const MOD_MGR *mod_mgr, UINT32 *remote_mod_node_num);
EC_BOOL mod_mgr_first_remote(const MOD_MGR *mod_mgr, UINT32 *remote_mod_node_pos);
EC_BOOL mod_mgr_last_remote(const MOD_MGR *mod_mgr, UINT32 *remote_mod_node_pos);
EC_BOOL mod_mgr_next_remote(const MOD_MGR *mod_mgr, UINT32 *remote_mod_node_pos);
EC_BOOL mod_mgr_prev_remote(const MOD_MGR *mod_mgr, UINT32 *remote_mod_node_pos);

MOD_NODE *mod_mgr_search(const UINT32 tcid, const UINT32 comm, const UINT32 rank, const UINT32 modi, const MOD_MGR *mod_mgr);

EC_BOOL mod_mgr_has(const UINT32 tcid, const UINT32 comm, const UINT32 rank, const UINT32 modi, const MOD_MGR *mod_mgr);

/*local mod node load operation*/
EC_BOOL mod_mgr_local_mod_load_set(const UINT32 load, const MOD_NODE *check_local_mod_node, const MOD_NODE *except_mod_node, MOD_MGR *mod_mgr);

EC_BOOL mod_mgr_local_mod_load_inc(const UINT32 increasement, const MOD_NODE *check_local_mod_node, const MOD_NODE *except_mod_node, MOD_MGR *mod_mgr);

EC_BOOL mod_mgr_local_mod_load_dec(const UINT32 decreasement, const MOD_NODE *check_local_mod_node, const MOD_NODE *except_mod_node, MOD_MGR *mod_mgr);

/*remote mod node load operation*/
EC_BOOL mod_mgr_remote_mod_load_set(const UINT32 load, const MOD_NODE *mod_node, const MOD_NODE *except_mod_node, MOD_MGR *mod_mgr);

EC_BOOL mod_mgr_remote_mod_load_inc(const UINT32 increasement, const MOD_NODE *mod_node, const MOD_NODE *except_mod_node, MOD_MGR *mod_mgr);

EC_BOOL mod_mgr_remote_mod_load_dec(const UINT32 decreasement, const MOD_NODE *mod_node, const MOD_NODE *except_mod_node, MOD_MGR *mod_mgr);

#endif /*_MOD_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

