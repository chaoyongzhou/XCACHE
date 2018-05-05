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

#ifndef _IPV4POOL_H
#define _IPV4POOL_H

#include <stdio.h>
#include <stdlib.h>

#include "type.h"
#include "mm.h"
#include "log.h"

#include "cmisc.h"
#include "cmutex.h"
#include "cbytes.h"

#include "cbitmap.h"

typedef struct
{
    uint32_t    ipv4_subnet;    /*in host byte order*/
    uint32_t    ipv4_mask;      /*in host byte order*/

    CRWLOCK     crwlock;
    CBITMAP     cbitmap;
}IPV4_POOL;

#define IPV4_POOL_SUBNET(ipv4_pool)         ((ipv4_pool)->ipv4_subnet)
#define IPV4_POOL_MASK(ipv4_pool)           ((ipv4_pool)->ipv4_mask)
#define IPV4_POOL_CRWLOCK(ipv4_pool)        (&((ipv4_pool)->crwlock))
#define IPV4_POOL_CBITMAP(ipv4_pool)        (&((ipv4_pool)->cbitmap))

#if 1
#define IPV4_POOL_INIT_CRWLOCK(ipv4_pool, location)            (crwlock_init(IPV4_POOL_CRWLOCK(ipv4_pool), CRWLOCK_PROCESS_PRIVATE, location))
#define IPV4_POOL_CLEAN_CRWLOCK(ipv4_pool, location)           (crwlock_clean(IPV4_POOL_CRWLOCK(ipv4_pool), location))
#define IPV4_POOL_CRWLOCK_RDLOCK(ipv4_pool, location)          (crwlock_rdlock(IPV4_POOL_CRWLOCK(ipv4_pool), location))
#define IPV4_POOL_CRWLOCK_WRLOCK(ipv4_pool, location)          (crwlock_wrlock(IPV4_POOL_CRWLOCK(ipv4_pool), location))
#define IPV4_POOL_CRWLOCK_UNLOCK(ipv4_pool, location)          (crwlock_unlock(IPV4_POOL_CRWLOCK(ipv4_pool), location))
#endif
#if 0
#define IPV4_POOL_INIT_CRWLOCK(ipv4_pool, location)            do{\
    crwlock_init(IPV4_POOL_CRWLOCK(ipv4_pool), CRWLOCK_PROCESS_PRIVATE, location);\
    sys_log(LOGSTDNULL, "[DEBUG] CRWLOCK %lx: init at %s:%d\n", IPV4_POOL_CRWLOCK(ipv4_pool), MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));\
}while(0)

#define IPV4_POOL_CLEAN_CRWLOCK(ipv4_pool, location)           do{\
    crwlock_clean(IPV4_POOL_CRWLOCK(ipv4_pool), location);\
    sys_log(LOGSTDNULL, "[DEBUG] CRWLOCK %lx: clean at %s:%d\n", IPV4_POOL_CRWLOCK(ipv4_pool), MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));\
}while(0)

#define IPV4_POOL_CRWLOCK_RDLOCK(ipv4_pool, location)          do{\
    crwlock_rdlock(IPV4_POOL_CRWLOCK(ipv4_pool), location);\
    sys_log(LOGSTDNULL, "[DEBUG] CRWLOCK %lx: RD lock at %s:%d\n", IPV4_POOL_CRWLOCK(ipv4_pool), MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));\
}while(0)

#define IPV4_POOL_CRWLOCK_WRLOCK(ipv4_pool, location)          do{\
    crwlock_wrlock(IPV4_POOL_CRWLOCK(ipv4_pool), location);\
    sys_log(LOGSTDNULL, "[DEBUG] CRWLOCK %lx: WR lock at %s:%d\n", IPV4_POOL_CRWLOCK(ipv4_pool), MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));\
}while(0)

#define IPV4_POOL_CRWLOCK_UNLOCK(ipv4_pool, location)          do{\
    crwlock_unlock(IPV4_POOL_CRWLOCK(ipv4_pool), location);\
    sys_log(LOGSTDNULL, "[DEBUG] CRWLOCK %lx: unlock at %s:%d\n", IPV4_POOL_CRWLOCK(ipv4_pool), MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));\
}while(0)
#endif

IPV4_POOL *ipv4_pool_new(const uint32_t ipv4_subnet, const uint32_t ipv4_mask);

EC_BOOL  ipv4_pool_init(IPV4_POOL *ipv4_pool, const uint32_t ipv4_subnet, const uint32_t ipv4_mask);

EC_BOOL  ipv4_pool_clean(IPV4_POOL *ipv4_pool);

EC_BOOL  ipv4_pool_free(IPV4_POOL *ipv4_pool);

void     ipv4_pool_print(LOG *log, const IPV4_POOL *ipv4_pool);

uint32_t ipv4_pool_get_subnet(const IPV4_POOL *ipv4_pool);

uint32_t ipv4_pool_get_mask(const IPV4_POOL *ipv4_pool);

EC_BOOL  ipv4_pool_reserve(IPV4_POOL *ipv4_pool, uint32_t *ipv4_addr);

EC_BOOL  ipv4_pool_release(IPV4_POOL *ipv4_pool, const uint32_t ipv4_addr);

EC_BOOL  ipv4_pool_set(IPV4_POOL *ipv4_pool, const uint32_t ipv4_addr);

EC_BOOL  ipv4_pool_unset(IPV4_POOL *ipv4_pool, const uint32_t ipv4_addr);

uint32_t ipv4_pool_size(IPV4_POOL *ipv4_pool);

EC_BOOL  ipv4_pool_is_empty(IPV4_POOL *ipv4_pool);


#endif/* _IPV4POOL_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/

