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

#ifndef _MOD_INC
#define _MOD_INC

#include "type.h"

#include "debug.h"

#include "cvector.h"
#include "cload.h"


struct _MOD_NODE;/*claim the type here due to it be used in definition of MOD_MGR_LDB*/
struct _MOD_MGR;/*claim the type here due to it be used in definition of MOD_MGR_LDB*/


/*mod_mgr load balancing strategy*/
typedef struct
{
    UINT32  load_balancing_strategy;

    struct _MOD_NODE * (*get)(struct _MOD_MGR *);
}MOD_MGR_LDB;

typedef struct _MOD_NODE
{
    UINT32         tcid;              /* which taskComm*/
    UINT32         comm;              /* which communicator */
    UINT32         rank;              /* which rank process */
    UINT32         modi;              /* which module identity */

    UINT32         hops;              /* hops from src to des, used when sync taskcomm and it will be changed by remote caller*/
    UINT32         load;              /* the load on this mod_node*/
    UINT32         stat;
    CLOAD_STAT     cload_stat;        /* defined and used by application, default 0 is invalid*/
}MOD_NODE;

typedef struct _MOD_MGR
{
    MOD_MGR_LDB    ldb_choice;        /* load balancing strategy choice, default is LOAD_BALANCING_LOOP*/

    MOD_NODE       local_mod;         /* local task module */

    CVECTOR        remote_mod_list;   /* remote mod node list*/
    UINT32         local_mod_pos;     /* the position of local_mod in remote_mod_list*/
    UINT32         remote_mod_pos;    /* optional: used by LOOP balance strategy to save the current remote_mod pos*/
}MOD_MGR;

#endif /*_MOD_INC*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/
