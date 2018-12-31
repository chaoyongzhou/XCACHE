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

#include "cxfsnpkey.h"
#include "cxfsnp.h"

#define CXFSNPKEY_ASSERT(condition)           ASSERT(condition)
//#define CXFSNPKEY_ASSERT(condition)           do{}while(0)


EC_BOOL cxfsnpkey_pool_init(CXFSNPRB_POOL *pool, const uint32_t node_max_num, const uint32_t node_sizeof)
{
    uint32_t node_pos;
    uint32_t key_offset;

    if(CXFSNPRB_POOL_MAX_SIZE < node_max_num)
    {
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDERR, "error:cxfsnpkey_pool_init: node_max_num %u overflow!\n", node_max_num);
        return (EC_FALSE);
    }

    key_offset = node_sizeof * node_max_num;

    for(node_pos = 0; node_pos < node_max_num; node_pos ++)
    {
        CXFSNPRB_NODE  *cxfsnprb_node;
        CXFSNP_ITEM    *cxfsnp_item;
        CXFSNP_KEY     *cxfsnp_key;

        cxfsnprb_node  = CXFSNPRB_POOL_NODE(pool, node_pos);
        cxfsnp_item    = (CXFSNP_ITEM *)cxfsnprb_node;

        CXFSNPKEY_ASSERT((void *)cxfsnp_item == (void *)cxfsnprb_node); /*address must be aligned*/

        CXFSNP_ITEM_KEY_OFFSET(cxfsnp_item) = key_offset;
        cxfsnp_key     = CXFSNP_ITEM_KEY(cxfsnp_item);
        cxfsnp_key_init(cxfsnp_key);

        /*move to next key offset*/
        key_offset = (key_offset + CXFSNP_KEY_MAX_SIZE + 1) - node_sizeof;

        if(0 == ((node_pos + 1) % 100000))
        {
            dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "info:cxfsnpkey_pool_init: init node %u - %u of max %u done\n",
                               node_pos - 99999, node_pos, node_max_num);
        }
    }
    dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "info:cxfsnpkey_pool_init: init %u nodes done\n", node_max_num);

    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/
