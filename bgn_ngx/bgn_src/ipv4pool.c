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

#include "type.h"
#include "mm.h"
#include "log.h"

#include "cmisc.h"
#include "cmutex.h"
#include "cbytes.h"

#include "task.h"

#include "cbitmap.h"
#include "ipv4pool.h"

#include "findex.inc"

/*e.g. ipv4_subnet from "192.168.231.0", ipv4_mask from "255.255.255.0"*/
IPV4_POOL *ipv4_pool_new(const uint32_t ipv4_subnet, const uint32_t ipv4_mask)
{
    IPV4_POOL *ipv4_pool;

    ipv4_pool = (IPV4_POOL *)SAFE_MALLOC(sizeof(IPV4_POOL), LOC_IPV4POOL_0001);
    if(NULL_PTR != ipv4_pool)
    {
        if(EC_FALSE == ipv4_pool_init(ipv4_pool, ipv4_subnet, ipv4_mask))
        {
            dbg_log(SEC_0027_IPV4POOL, 0)(LOGSTDOUT, "error:ipv4_pool_new: init ipv4 pool with subnet %s, mask %s failed\n",
                                c_word_to_ipv4(ipv4_subnet), c_word_to_ipv4(ipv4_mask));
            SAFE_FREE(ipv4_pool, LOC_IPV4POOL_0002);
            return (NULL_PTR);
        }
    }
    return (ipv4_pool);
}

EC_BOOL  ipv4_pool_init(IPV4_POOL *ipv4_pool, const uint32_t ipv4_subnet, const uint32_t ipv4_mask)
{
    UINT32 ipv4_addr_max_num;

    IPV4_POOL_SUBNET(ipv4_pool) = (ipv4_subnet & ipv4_mask);
    IPV4_POOL_MASK(ipv4_pool)   = ipv4_mask;

    IPV4_POOL_INIT_CRWLOCK(ipv4_pool, LOC_IPV4POOL_0003);

    ipv4_addr_max_num = (~ipv4_mask) + 1;
    dbg_log(SEC_0027_IPV4POOL, 9)(LOGSTDOUT, "[DEBUG] ipv4_pool_init: subnet %s, mask %s, ipv4 addr max num %ld\n",
                        c_word_to_ipv4(IPV4_POOL_SUBNET(ipv4_pool)),
                        c_word_to_ipv4(IPV4_POOL_MASK(ipv4_pool)),
                        ipv4_addr_max_num);
    if(EC_FALSE == cbitmap_init(IPV4_POOL_CBITMAP(ipv4_pool), ipv4_addr_max_num))
    {
        dbg_log(SEC_0027_IPV4POOL, 0)(LOGSTDOUT, "error:ipv4_pool_init: init cbitmap with ipv4 addr max num %ld failed\n", ipv4_addr_max_num);
        IPV4_POOL_CLEAN_CRWLOCK(ipv4_pool, LOC_IPV4POOL_0004);
        return (EC_FALSE);
    }
    CBITMAP_MAX_BITS(IPV4_POOL_CBITMAP(ipv4_pool)) = ipv4_addr_max_num; /*for safe purpose*/

#if 0
    /*ignore some ipaddr*/
#if  0
    ipv4_addr = 0;
    bit_pos   = (ipv4_addr & (~ IPV4_POOL_MASK(ipv4_pool)));
    if(EC_FALSE == cbitmap_set(IPV4_POOL_CBITMAP(ipv4_pool), bit_pos))
    {
        dbg_log(SEC_0027_IPV4POOL, 0)(LOGSTDOUT, "error:ipv4_pool_init: cbitmap set ipv4 %s failed\n", c_word_to_ipv4(ipv4_addr));
        IPV4_POOL_CLEAN_CRWLOCK(ipv4_pool, LOC_IPV4POOL_0005);
        cbitmap_clean(IPV4_POOL_CBITMAP(ipv4_pool));
        return (EC_FALSE);
    }
    dbg_log(SEC_0027_IPV4POOL, 9)(LOGSTDOUT, "[DEBUG] ipv4_pool_init: ignore ipv4 %s\n", c_word_to_ipv4(ipv4_addr));
#endif

#if  1
    ipv4_addr = (ipv4_subnet & 0xffffff00);
    bit_pos   = (ipv4_addr & (~ IPV4_POOL_MASK(ipv4_pool)));
    if(EC_FALSE == cbitmap_set(IPV4_POOL_CBITMAP(ipv4_pool), bit_pos))
    {
        dbg_log(SEC_0027_IPV4POOL, 0)(LOGSTDOUT, "error:ipv4_pool_init: cbitmap set ipv4 %s failed\n", c_word_to_ipv4(ipv4_addr));
        IPV4_POOL_CLEAN_CRWLOCK(ipv4_pool, LOC_IPV4POOL_0006);
        cbitmap_clean(IPV4_POOL_CBITMAP(ipv4_pool));
        return (EC_FALSE);
    }
    dbg_log(SEC_0027_IPV4POOL, 9)(LOGSTDOUT, "[DEBUG] ipv4_pool_init: ignore ipv4 %s\n", c_word_to_ipv4(ipv4_addr));
#endif

    ipv4_addr = (IPV4_POOL_SUBNET(ipv4_pool) | ((~ipv4_mask) & 0xffffffff));
    bit_pos   =  (ipv4_addr & (~ IPV4_POOL_MASK(ipv4_pool)));
    if(bit_pos < CBITMAP_MAX_BITS(IPV4_POOL_CBITMAP(ipv4_pool)) && EC_FALSE == cbitmap_set(IPV4_POOL_CBITMAP(ipv4_pool), bit_pos))
    {
        dbg_log(SEC_0027_IPV4POOL, 0)(LOGSTDOUT, "error:ipv4_pool_init: cbitmap set ipv4 %s failed\n", c_word_to_ipv4(ipv4_addr));
        IPV4_POOL_CLEAN_CRWLOCK(ipv4_pool, LOC_IPV4POOL_0007);
        cbitmap_clean(IPV4_POOL_CBITMAP(ipv4_pool));
        return (EC_FALSE);
    }
    dbg_log(SEC_0027_IPV4POOL, 9)(LOGSTDOUT, "[DEBUG] ipv4_pool_init: ignore ipv4 %s\n", c_word_to_ipv4(ipv4_addr));

    ipv4_addr = (IPV4_POOL_SUBNET(ipv4_pool) | ((~ipv4_mask) & 0xfffffffe));
    bit_pos   =  (ipv4_addr & (~ IPV4_POOL_MASK(ipv4_pool)));
    if(bit_pos < CBITMAP_MAX_BITS(IPV4_POOL_CBITMAP(ipv4_pool)) && EC_FALSE == cbitmap_set(IPV4_POOL_CBITMAP(ipv4_pool), bit_pos))
    {
        dbg_log(SEC_0027_IPV4POOL, 0)(LOGSTDOUT, "error:ipv4_pool_init: cbitmap set ipv4 %s failed\n", c_word_to_ipv4(ipv4_addr));
        IPV4_POOL_CLEAN_CRWLOCK(ipv4_pool, LOC_IPV4POOL_0008);
        cbitmap_clean(IPV4_POOL_CBITMAP(ipv4_pool));
        return (EC_FALSE);
    }
    dbg_log(SEC_0027_IPV4POOL, 9)(LOGSTDOUT, "[DEBUG] ipv4_pool_init: ignore ipv4 %s\n", c_word_to_ipv4(ipv4_addr));
#endif
    return (EC_TRUE);
}

EC_BOOL  ipv4_pool_clean(IPV4_POOL *ipv4_pool)
{
    if(NULL_PTR != ipv4_pool)
    {
        IPV4_POOL_SUBNET(ipv4_pool) = 0;
        IPV4_POOL_MASK(ipv4_pool)   = 0;

        IPV4_POOL_CLEAN_CRWLOCK(ipv4_pool, LOC_IPV4POOL_0009);

        cbitmap_clean(IPV4_POOL_CBITMAP(ipv4_pool));
    }
    return (EC_TRUE);
}

EC_BOOL  ipv4_pool_free(IPV4_POOL *ipv4_pool)
{
    if(NULL_PTR != ipv4_pool)
    {
        ipv4_pool_clean(ipv4_pool);
        SAFE_FREE(ipv4_pool, LOC_IPV4POOL_0010);
    }
    return (EC_TRUE);
}

void     ipv4_pool_print(LOG *log, const IPV4_POOL *ipv4_pool)
{
    sys_log(log, "ipv4 pool %lx: subnet %s, mask %s\n",
                ipv4_pool,
                c_word_to_ipv4(IPV4_POOL_SUBNET(ipv4_pool)),
                c_word_to_ipv4(IPV4_POOL_MASK(ipv4_pool))
                );
    cbitmap_print(log, IPV4_POOL_CBITMAP(ipv4_pool));
    return;
}

uint32_t ipv4_pool_get_subnet(const IPV4_POOL *ipv4_pool)
{
    return IPV4_POOL_SUBNET(ipv4_pool);
}

uint32_t ipv4_pool_get_mask(const IPV4_POOL *ipv4_pool)
{
    return IPV4_POOL_MASK(ipv4_pool);
}

EC_BOOL  ipv4_pool_reserve(IPV4_POOL *ipv4_pool, uint32_t *ipv4_addr)
{
    UINT32 bit_pos;
    uint32_t reserved_ipv4_addr;
    uint32_t reserved_ipv4_addr_tail;

    IPV4_POOL_CRWLOCK_WRLOCK(ipv4_pool, LOC_IPV4POOL_0011);
    do
    {
        if(EC_FALSE == cbitmap_reserve(IPV4_POOL_CBITMAP(ipv4_pool), &bit_pos))
        {
            dbg_log(SEC_0027_IPV4POOL, 0)(LOGSTDOUT, "error:ipv4_pool_reserve: reserve from cbitmap failed\n");
            IPV4_POOL_CRWLOCK_UNLOCK(ipv4_pool, LOC_IPV4POOL_0012);
            return (EC_FALSE);
        }

        if(bit_pos & (~((UINT32)0xffffffff)))/*confirm high bits is zero*/
        {
            dbg_log(SEC_0027_IPV4POOL, 0)(LOGSTDOUT, "error:ipv4_pool_reserve: reserved %ld from cbitmap is invalid\n", bit_pos);
            cbitmap_release(IPV4_POOL_CBITMAP(ipv4_pool), bit_pos);
            IPV4_POOL_CRWLOCK_UNLOCK(ipv4_pool, LOC_IPV4POOL_0013);
            return (EC_FALSE);
        }
        reserved_ipv4_addr = ((IPV4_POOL_SUBNET(ipv4_pool) & IPV4_POOL_MASK(ipv4_pool)) | bit_pos);
        reserved_ipv4_addr_tail = (reserved_ipv4_addr & 0x000000ff);/*discard special ipv4 addr*/
    }while(0 == reserved_ipv4_addr_tail || 0xff == reserved_ipv4_addr_tail || 0xfe == reserved_ipv4_addr_tail);

    (*ipv4_addr) = reserved_ipv4_addr;
    dbg_log(SEC_0027_IPV4POOL, 9)(LOGSTDOUT, "[DEBUG] ipv4_pool_reserve: subnet %s, mask %s, bit_pos %ld => %s\n",
                        c_word_to_ipv4(IPV4_POOL_SUBNET(ipv4_pool)),
                        c_word_to_ipv4(IPV4_POOL_MASK(ipv4_pool)),
                        bit_pos,
                        c_word_to_ipv4(*ipv4_addr)
                        );
    IPV4_POOL_CRWLOCK_UNLOCK(ipv4_pool, LOC_IPV4POOL_0014);
    return (EC_TRUE);

}

EC_BOOL  ipv4_pool_release(IPV4_POOL *ipv4_pool, const uint32_t ipv4_addr)
{
    UINT32 bit_pos;

    if((IPV4_POOL_SUBNET(ipv4_pool) & IPV4_POOL_MASK(ipv4_pool)) !=  (ipv4_addr & IPV4_POOL_MASK(ipv4_pool)))
    {
        dbg_log(SEC_0027_IPV4POOL, 0)(LOGSTDOUT, "error:ipv4_pool_release: ipv4 addr %s not belong to subnet %s, mask %s\n",
                            c_word_to_ipv4(ipv4_addr),
                            c_word_to_ipv4(IPV4_POOL_SUBNET(ipv4_pool)),
                            c_word_to_ipv4(IPV4_POOL_MASK(ipv4_pool))
                            );
        return (EC_FALSE);
    }

    bit_pos = ((ipv4_addr & (~ IPV4_POOL_MASK(ipv4_pool))) & 0xffffffff);
    if(0 == bit_pos || bit_pos == ((~ IPV4_POOL_MASK(ipv4_pool)) & 0xffffffff))
    {
        dbg_log(SEC_0027_IPV4POOL, 0)(LOGSTDOUT, "error:ipv4_pool_release: refuse to release ipv4 addr %s\n", c_word_to_ipv4(ipv4_addr));
        return (EC_FALSE);
    }

    IPV4_POOL_CRWLOCK_WRLOCK(ipv4_pool, LOC_IPV4POOL_0015);
    if(EC_FALSE == cbitmap_release(IPV4_POOL_CBITMAP(ipv4_pool), bit_pos))
    {
        dbg_log(SEC_0027_IPV4POOL, 0)(LOGSTDOUT, "error:ipv4_pool_release: release ipv4 addr %s failed\n", c_word_to_ipv4(ipv4_addr));
        IPV4_POOL_CRWLOCK_UNLOCK(ipv4_pool, LOC_IPV4POOL_0016);
        return (EC_FALSE);
    }
    IPV4_POOL_CRWLOCK_UNLOCK(ipv4_pool, LOC_IPV4POOL_0017);
    return (EC_TRUE);
}

EC_BOOL  ipv4_pool_set(IPV4_POOL *ipv4_pool, const uint32_t ipv4_addr)
{
    UINT32 bit_pos;

    if((IPV4_POOL_SUBNET(ipv4_pool) & IPV4_POOL_MASK(ipv4_pool)) !=  (ipv4_addr & IPV4_POOL_MASK(ipv4_pool)))
    {
        dbg_log(SEC_0027_IPV4POOL, 0)(LOGSTDOUT, "error:ipv4_pool_set: ipv4 addr %s not belong to subnet %s, mask %s\n",
                            c_word_to_ipv4(ipv4_addr),
                            c_word_to_ipv4(IPV4_POOL_SUBNET(ipv4_pool)),
                            c_word_to_ipv4(IPV4_POOL_MASK(ipv4_pool))
                            );
        return (EC_FALSE);
    }

    IPV4_POOL_CRWLOCK_WRLOCK(ipv4_pool, LOC_IPV4POOL_0018);
    bit_pos = ((ipv4_addr & (~ IPV4_POOL_MASK(ipv4_pool))) & 0xffffffff);
    if(EC_FALSE == cbitmap_set(IPV4_POOL_CBITMAP(ipv4_pool), bit_pos))
    {
        dbg_log(SEC_0027_IPV4POOL, 0)(LOGSTDOUT, "error:ipv4_pool_set: set ipv4 addr %s failed\n", c_word_to_ipv4(ipv4_addr));
        IPV4_POOL_CRWLOCK_UNLOCK(ipv4_pool, LOC_IPV4POOL_0019);
        return (EC_FALSE);
    }
    IPV4_POOL_CRWLOCK_UNLOCK(ipv4_pool, LOC_IPV4POOL_0020);
    return (EC_TRUE);
}

EC_BOOL  ipv4_pool_unset(IPV4_POOL *ipv4_pool, const uint32_t ipv4_addr)
{
    UINT32 bit_pos;

    if((IPV4_POOL_SUBNET(ipv4_pool) & IPV4_POOL_MASK(ipv4_pool)) !=  (ipv4_addr & IPV4_POOL_MASK(ipv4_pool)))
    {
        dbg_log(SEC_0027_IPV4POOL, 0)(LOGSTDOUT, "error:ipv4_pool_unset: ipv4 addr %s not belong to subnet %s, mask %s\n",
                            c_word_to_ipv4(ipv4_addr),
                            c_word_to_ipv4(IPV4_POOL_SUBNET(ipv4_pool)),
                            c_word_to_ipv4(IPV4_POOL_MASK(ipv4_pool))
                            );
        return (EC_FALSE);
    }

    IPV4_POOL_CRWLOCK_WRLOCK(ipv4_pool, LOC_IPV4POOL_0021);
    bit_pos = ((ipv4_addr & (~ IPV4_POOL_MASK(ipv4_pool))) & 0xffffffff);
    if(EC_FALSE == cbitmap_unset(IPV4_POOL_CBITMAP(ipv4_pool), bit_pos))
    {
        dbg_log(SEC_0027_IPV4POOL, 0)(LOGSTDOUT, "error:ipv4_pool_unset: unset ipv4 addr %s failed\n", c_word_to_ipv4(ipv4_addr));
        IPV4_POOL_CRWLOCK_UNLOCK(ipv4_pool, LOC_IPV4POOL_0022);
        return (EC_FALSE);
    }
    IPV4_POOL_CRWLOCK_UNLOCK(ipv4_pool, LOC_IPV4POOL_0023);
    return (EC_TRUE);
}

uint32_t  ipv4_pool_size(IPV4_POOL *ipv4_pool)
{
    UINT32 ipv4_addr_free_num;

    IPV4_POOL_CRWLOCK_RDLOCK(ipv4_pool, LOC_IPV4POOL_0024);
    ipv4_addr_free_num = cbitmap_room_size(IPV4_POOL_CBITMAP(ipv4_pool));
    IPV4_POOL_CRWLOCK_UNLOCK(ipv4_pool, LOC_IPV4POOL_0025);
    return (uint32_t)ipv4_addr_free_num;
}

EC_BOOL  ipv4_pool_is_empty(IPV4_POOL *ipv4_pool)
{
    EC_BOOL ret;

    IPV4_POOL_CRWLOCK_RDLOCK(ipv4_pool, LOC_IPV4POOL_0026);
    ret = cbitmap_is_full(IPV4_POOL_CBITMAP(ipv4_pool));
    IPV4_POOL_CRWLOCK_UNLOCK(ipv4_pool, LOC_IPV4POOL_0027);
    return ret;
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/
