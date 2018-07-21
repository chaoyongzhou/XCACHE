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

#include "crfsnpkey.h"
#include "crfsnp.h"

#define CRFSNPKEY_ASSERT(condition)           ASSERT(condition)
//#define CRFSNPKEY_ASSERT(condition)           do{}while(0)


EC_BOOL crfsnpkey_pool_init(CRFSNPRB_POOL *pool, const uint32_t node_max_num, const uint32_t node_sizeof)
{
    uint32_t node_pos;
    uint32_t key_offset;

    if(CRFSNPRB_POOL_MAX_SIZE < node_max_num)
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDERR, "error:crfsnpkey_pool_init: node_max_num %u overflow!\n", node_max_num);
        return (EC_FALSE);
    }

    key_offset = node_sizeof * node_max_num;

    for(node_pos = 0; node_pos < node_max_num; node_pos ++)
    {
        CRFSNPRB_NODE  *crfsnprb_node;
        CRFSNP_ITEM    *crfsnp_item;
        CRFSNP_KEY     *crfsnp_key;

        crfsnprb_node  = CRFSNPRB_POOL_NODE(pool, node_pos);
        crfsnp_item    = (CRFSNP_ITEM *)crfsnprb_node;

        CRFSNPKEY_ASSERT((void *)crfsnp_item == (void *)crfsnprb_node); /*address must be aligned*/

        CRFSNP_ITEM_KEY_OFFSET(crfsnp_item) = key_offset;
        crfsnp_key     = CRFSNP_ITEM_KEY(crfsnp_item);
        crfsnp_key_init(crfsnp_key);

        /*move to next key offset*/
        key_offset = (key_offset + CRFSNP_KEY_MAX_SIZE + 1) - node_sizeof;

        if(0 == ((node_pos + 1) % 100000))
        {
            dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "info:crfsnpkey_pool_init: init node %u - %u of max %u done\n",
                               node_pos - 99999, node_pos, node_max_num);
        }
    }
    dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "info:crfsnpkey_pool_init: init %u nodes done\n", node_max_num);

    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/
