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

#ifndef _CROUTER_INC
#define _CROUTER_INC

#include "type.h"
#include "cvector.h"

#define CROUTE_MAX_HOPS             ((UINT32) 7)

typedef struct
{
    UINT32      des_tcid;            /*des remote tcid*/
    CVECTOR     next_hop_list;       /*next hop tasks node list*/
                                     /*note: here tasks node just save its reference, so do not alloc or free its memory*/
}CROUTER_NODE;

#define CROUTER_NODE_DES_TCID(crouter_node)           ((crouter_node)->des_tcid)
#define CROUTER_NODE_DES_TCID_STR(crouter_node)       (c_word_to_ipv4(CROUTER_NODE_DES_TCID(crouter_node)))
#define CROUTER_NODE_NEXT_HOPS(crouter_node)          (&((crouter_node)->next_hop_list))

typedef struct
{
    CVECTOR     crouter_node_vec;    /*route table*/
}CROUTER_NODE_VEC;

#define CROUTER_NODE_VEC_NODES(crouter_vec)           (&((crouter_vec)->crouter_node_vec))


typedef struct
{
    UINT32      src_tcid;
    UINT32      des_tcid;
    UINT32      next_hop;
    UINT32      max_hops;/*how many hops from src tcid to des tcid via next hop*/
}CROUTER_CFG;

#define CROUTER_CFG_SRC_TCID(crouter_cfg)           ((crouter_cfg)->src_tcid)
#define CROUTER_CFG_SRC_TCID_STR(crouter_cfg)       (c_word_to_ipv4(CROUTER_CFG_SRC_TCID(crouter_cfg)))
#define CROUTER_CFG_DES_TCID(crouter_cfg)           ((crouter_cfg)->des_tcid)
#define CROUTER_CFG_DES_TCID_STR(crouter_cfg)       (c_word_to_ipv4(CROUTER_CFG_DES_TCID(crouter_cfg)))
#define CROUTER_CFG_NEXT_HOP(crouter_cfg)           ((crouter_cfg)->next_hop)
#define CROUTER_CFG_NEXT_HOP_STR(crouter_cfg)       (c_word_to_ipv4(CROUTER_CFG_NEXT_HOP(crouter_cfg)))
#define CROUTER_CFG_MAX_HOPS(crouter_cfg)           ((crouter_cfg)->max_hops)


#endif /*_CROUTER_INC*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/
