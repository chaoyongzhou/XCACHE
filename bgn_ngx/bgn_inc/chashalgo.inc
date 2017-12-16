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

#ifndef _CHASHALGO_INC
#define _CHASHALGO_INC

const CHASH_ALGO_NODE g_chash_algo_nodes[] = {
    {CHASH_SIMPLE_ALGO_ID, simple_hash, },
    {CHASH_RS_ALGO_ID    , RS_hash,     },
    {CHASH_JS_ALGO_ID    , JS_hash,     },
    {CHASH_PJW_ALGO_ID   , PJW_hash,    },
    {CHASH_ELF_ALGO_ID   , ELF_hash,    },
    {CHASH_BKDR_ALGO_ID  , BKDR_hash,   },
    {CHASH_SDBM_ALGO_ID  , SDBM_hash,   },
    {CHASH_DJB_ALGO_ID   , DJB_hash,    },
    {CHASH_AP_ALGO_ID    , AP_hash,     },
    {CHASH_CRC_ALGO_ID   , CRC_hash,    },
    {CHASH_MD5_ALGO_ID   , MD5_hash,    },
};

const UINT32 g_chash_algo_nodes_num = sizeof(g_chash_algo_nodes)/sizeof(g_chash_algo_nodes[ 0 ]);

#endif /*_CHASHALGO_INC*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

