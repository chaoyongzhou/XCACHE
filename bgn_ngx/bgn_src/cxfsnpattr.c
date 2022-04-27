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

#include "cxfsnpattr.h"
#include "cxfsnp.h"

#define CXFSNPATTR_ASSERT(condition)           ASSERT(condition)
//#define CXFSNPATTR_ASSERT(condition)           do{}while(0)


EC_BOOL cxfsnpattr_pool_init(CXFSNPRB_POOL *pool, const uint32_t node_max_num, const uint32_t node_sizeof)
{
    uint32_t node_pos;
    uint32_t attr_soffset;

    if(CXFSNPRB_POOL_MAX_SIZE < node_max_num)
    {
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDERR, "error:cxfsnpattr_pool_init: "
                                               "node_max_num %u overflow!\n",
                                               node_max_num);
        return (EC_FALSE);
    }

    /*offset between attr[node_pos] and item[node_pos] is fixed which actually is node_max_num*/
    attr_soffset = (node_sizeof * node_max_num * 2 + 0) / (sizeof(CXFSNP_ITEM) + sizeof(CXFSNP_KEY));

    for(node_pos = 0; node_pos < node_max_num; node_pos ++)
    {
        CXFSNPRB_NODE  *cxfsnprb_node;
        CXFSNP_ITEM    *cxfsnp_item;
        CXFSNP_ATTR    *cxfsnp_attr;

        cxfsnprb_node  = CXFSNPRB_POOL_NODE(pool, node_pos);
        cxfsnp_item    = (CXFSNP_ITEM *)cxfsnprb_node;

        CXFSNPATTR_ASSERT((void *)cxfsnp_item == (void *)cxfsnprb_node); /*address must be aligned*/

        CXFSNP_ITEM_ATTR_SOFFSET(cxfsnp_item) = attr_soffset;
        cxfsnp_attr    = CXFSNP_ITEM_ATTR(cxfsnp_item);
        cxfsnp_attr_init(cxfsnp_attr);

        if(0 == ((node_pos + 1) % 100000))
        {
            dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "info:cxfsnpattr_pool_init: "
                                                   "init node %u - %u of max %u done\n",
                                                   node_pos - 99999, node_pos, node_max_num);
        }
    }
    dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "info:cxfsnpattr_pool_init: init %u nodes done\n", node_max_num);

    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/
