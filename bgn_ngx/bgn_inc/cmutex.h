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

#ifndef _CMUTEX_H
#define _CMUTEX_H

#include <pthread.h>

#include "type.h"

#define CMUTEX_OP_NEW          ((UINT32) 0)
#define CMUTEX_OP_INIT         ((UINT32) 1)
#define CMUTEX_OP_FREE         ((UINT32) 2)
#define CMUTEX_OP_CLEAN        ((UINT32) 3)
#define CMUTEX_OP_LOCK         ((UINT32) 4)
#define CMUTEX_OP_UNLOCK       ((UINT32) 5)
#define CMUTEX_OP_END          ((UINT32) 6)

#define CRWLOCK_OP_NEW          ((UINT32) 0)
#define CRWLOCK_OP_INIT         ((UINT32) 1)
#define CRWLOCK_OP_FREE         ((UINT32) 2)
#define CRWLOCK_OP_CLEAN        ((UINT32) 3)
#define CRWLOCK_OP_RDLOCK       ((UINT32) 4)
#define CRWLOCK_OP_WRLOCK       ((UINT32) 5)
#define CRWLOCK_OP_UNLOCK       ((UINT32) 6)
#define CRWLOCK_OP_END          ((UINT32) 7)

#define CMUTEX_FNAME_MAX_SIZE (64)
#define CCOND_FNAME_MAX_SIZE  (64)

#define CMUTEX_NODE_MAX_NUM     (4096)  /*the max cmutex num in one thread*/
#define CMUTEX_BUCKET_MAX_NUM   ( 256)  /*the max buckets in one process  */ 

#define CMUTEX_NODE_IS_NOT_USED ((UINT32) 0)
#define CMUTEX_NODE_IS_USED     ((UINT32) 1)

#define CMUTEX_PROCESS_PRIVATE  ((UINT32) 0x01)
#define CMUTEX_PROCESS_SHARED   ((UINT32) 0x02)
#define CMUTEX_TIMED_NP         ((UINT32) 0x04)
#define CMUTEX_RECURSIVE_NP     ((UINT32) 0x08)

#define CRWLOCK_PROCESS_PRIVATE  ((UINT32) 1)
#define CRWLOCK_PROCESS_SHARED   ((UINT32) 2)

#define LOCATION_INIT(location) do{ (location) = LOC_NONE_BASE; }while(0)

/*************************************************************************************************************************************
* cmutex record node in pool. the pool initialize before mem initialization, 
* the cmutex record node pool is used when cmutex init or clean. when some thread quit abnormally, we can reset all its cmutexs.
* we cannot used list structer to manage the pool, otherwise, when init or clean concurrently happen, we have no way to serialize them,
* especially, when happen on the adjacent record nodes. therefore, choose HASH BUCKET + TABLE + FLAG to manage
*************************************************************************************************************************************/
typedef struct
{
    void    *recorded_cmutex;   /*the recorded cmutex*/
    UINT32   used_flag;         /*the record node is used or unused flag*/
}CMUTEX_NODE;

#define CMUTEX_NODE_RECORDED_CMUTEX(cmutex_node)        ((cmutex_node)->recorded_cmutex)
#define CMUTEX_NODE_USED_FLAG(cmutex_node)              ((cmutex_node)->used_flag)

typedef struct
{
    pthread_spinlock_t spinlock; 
    CMUTEX_NODE cmutex_nodes[CMUTEX_NODE_MAX_NUM];   
}CMUTEX_BUCKET;

#define CMUTEX_BUCKET_SPINLOCK(cmutex_bucket)   (&((cmutex_bucket)->spinlock))

#define CMUTEX_BUCKET_NODE(cmutex_bucket, cmutex_node_idx)      \
    (&((cmutex_bucket)->cmutex_nodes[(cmutex_node_idx)]))

typedef struct
{
    CMUTEX_BUCKET cmutex_buckets[CMUTEX_BUCKET_MAX_NUM]; /*the bucket indexed by hash value of thread id*/
}CMUTEX_POOL;

#define CMUTEX_POOL_BUCKET_BY_IDX(cmutex_pool, cmutex_bucket_idx)      \
    (&((cmutex_pool)->cmutex_buckets[ cmutex_bucket_idx ]))

#define CMUTEX_POOL_BUCKET_BY_OWNER(cmutex_pool, pthread_owner)      \
    CMUTEX_POOL_BUCKET_BY_IDX(cmutex_pool, ((pthread_owner) % CMUTEX_BUCKET_MAX_NUM))

#if 1
typedef struct
{
    pthread_mutex_t mutex;
    CMUTEX_NODE *   record;/*cmutex record node info / mounted point in pool*/

    UINT32        location[CMUTEX_OP_END];
}CMUTEX;

#define CMUTEX_MUTEX(cmutex)          (&((cmutex)->mutex))
#define CMUTEX_RECORD_NODE(cmutex)    ((cmutex)->record)

#if 0
#define CMUTEX_RESERVED(cmutex)  ((cmutex)->mutex.__m_reserved)
#define CMUTEX_COUNT(cmutex)     ((cmutex)->mutex.__m_count)
#define CMUTEX_OWNER(cmutex)     ((cmutex)->mutex.__m_owner)
#define CMUTEX_KIND(cmutex)      ((cmutex)->mutex.__m_kind)
#endif
#if 1
#define CMUTEX_OBSCURE(cmutex)  ((cmutex)->mutex.__data.__lock)
#define CMUTEX_RESERVED(cmutex)  ((cmutex)->mutex.__data.__nusers)
#define CMUTEX_COUNT(cmutex)     ((cmutex)->mutex.__data.__count)
#define CMUTEX_OWNER(cmutex)     ((cmutex)->mutex.__data.__owner)
#define CMUTEX_KIND(cmutex)      ((cmutex)->mutex.__data.__kind)
#endif
#define CMUTEX_LOCATION(cmutex, __op__)  (((cmutex)->location)[__op__])

#define CMUTEX_GET_LOCATION(cmutex, __op__) \
    CMUTEX_LOCATION(cmutex, __op__)

#define CMUTEX_SET_LOCATION(cmutex, __op__, __location__) do{ \
    CMUTEX_LOCATION((cmutex) , (__op__)) = (__location__);\
}while(0)

#define CMUTEX_INIT_LOCATION(cmutex) do{\
    UINT32 __op__;\
    for(__op__ = 0; __op__ < CMUTEX_OP_END; __op__ ++)\
    {\
        LOCATION_INIT(CMUTEX_LOCATION((cmutex), __op__));\
    }\
}while(0)

#define CMUTEX_PRINT_LOCATION(fp, fname, cmutex) do{\
    UINT32 __op__;\
    for(__op__ = 0; __op__ < CMUTEX_OP_END; __op__ ++)\
    {\
        if(LOC_NONE_BASE != CMUTEX_LOCATION((cmutex), __op__))\
        {\
            sys_log(fp, "\t CMUTEX %lx: %s report: op = %ld happen at %s:%ld\n", cmutex, fname, __op__, MM_LOC_FILE_NAME(CMUTEX_LOCATION((cmutex), __op__)), MM_LOC_LINE_NO(CMUTEX_LOCATION((cmutex), __op__)));\
        }\
    }\
}while(0)

#define CMUTEX_PRINT_LOCK_INFO(fp, __op__, cmutex) do{\
    sys_log(fp, "cmutex %lx : op = %ld, __m_lock = %d, __m_reserved = %d, __m_count = %d, __m_owner = %d, __m_kind = %d\n", cmutex,__op__,\
        CMUTEX_OBSCURE(cmutex),\
        CMUTEX_RESERVED(cmutex),\
        CMUTEX_COUNT(cmutex),\
        CMUTEX_OWNER(cmutex),\
        CMUTEX_KIND(cmutex) \
        );\
}while(0)

#define CMUTEX_RESET(this_cmutex, flag)    do{\
    cmutex_init(this_cmutex, flag, CMUTEX_GET_LOCATION(this_cmutex, CMUTEX_OP_INIT));\
}while(0)

//#define CMUTEX_CHECK_LOCK_VALIDITY(__cmutex__, __op__, __location__) do{cmutex_check(__cmutex__, __op__, __location__);}while(0)

#define CMUTEX_CHECK_LOCK_VALIDITY(__cmutex__, __op__, __location__) do{}while(0)

#endif

#if 0

typedef pthread_mutex_t CMUTEX;
#define CMUTEX_MUTEX(cmutex) (cmutex)

#endif

#define CCOND_OP_NEW          ((UINT32) 0)
#define CCOND_OP_INIT         ((UINT32) 1)
#define CCOND_OP_FREE         ((UINT32) 2)
#define CCOND_OP_CLEAN        ((UINT32) 3)
#define CCOND_OP_WAIT         ((UINT32) 4)
#define CCOND_OP_RESERVE      ((UINT32) 5)
#define CCOND_OP_RELEASE      ((UINT32) 6)
#define CCOND_OP_END          ((UINT32) 7)

typedef struct
{
    pthread_mutex_t mutex;
    pthread_cond_t  var;

    UINT32          counter;/*down from nonzero to zero: reserve a nonzero, and then down one step when release*/

    UINT32          location[CCOND_OP_END];
}CCOND;

#define ERR_CCOND_TIMES         ((UINT32) -2)

#define CCOND_MUTEX(ccond)    (&((ccond)->mutex))
#define CCOND_VAR(ccond)      (&((ccond)->var))
#define CCOND_COUNTER(ccond)  ((ccond)->counter)

#define CCOND_LOCATION(ccond, __op__)  (((ccond)->location)[__op__])

#define CCOND_SET_LOCATION(ccond, __op__, __location__) do{ \
    CCOND_LOCATION((ccond) , (__op__)) = (__location__);\
}while(0)

#define CCOND_INIT_LOCATION(ccond) do{\
    UINT32 __op__;\
    for(__op__ = 0; __op__ < CCOND_OP_END; __op__ ++)\
    {\
        LOCATION_INIT(CCOND_LOCATION((ccond), __op__));\
    }\
}while(0)

typedef pthread_mutexattr_t CMUTEX_ATTR;

typedef pthread_rwlockattr_t CRWLOCK_ATTR;

typedef pthread_spinlock_t SPINLOCK;

#define SPINLOCK_INIT(spinlock)       do{pthread_spin_init(spinlock, PTHREAD_PROCESS_PRIVATE);}while(0)
#define SPINLOCK_CLEAN(spinlock)      do{pthread_spin_destroy(spinlock);}while(0)
#define SPINLOCK_LOCK(spinlock)       do{pthread_spin_lock(spinlock);}while(0)
#define SPINLOCK_UNLOCK(spinlock)     do{pthread_spin_unlock(spinlock);}while(0)

#if 0
typedef union
{
# if __WORDSIZE == 64
  struct
  {
    int __lock;
    unsigned int __nr_readers;
    unsigned int __readers_wakeup;
    unsigned int __writer_wakeup;
    unsigned int __nr_readers_queued;
    unsigned int __nr_writers_queued;
    int __writer;
    int __shared;
    unsigned long int __pad1;
    unsigned long int __pad2;
    /* FLAGS must stay at this position in the structure to maintain
       binary compatibility.  */
    unsigned int __flags;
  } __data;
# else
  struct
  {
    int __lock;
    unsigned int __nr_readers;
    unsigned int __readers_wakeup;
    unsigned int __writer_wakeup;
    unsigned int __nr_readers_queued;
    unsigned int __nr_writers_queued;
    /* FLAGS must stay at this position in the structure to maintain
       binary compatibility.  */
    unsigned char __flags;
    unsigned char __shared;
    unsigned char __pad1;
    unsigned char __pad2;
    int __writer;
  } __data;
# endif
  char __size[__SIZEOF_PTHREAD_RWLOCK_T];
  long int __align;
} pthread_rwlock_t;    
#endif

typedef struct
{
    pthread_rwlock_t    rwlock;

    UINT32        location[CRWLOCK_OP_END];    
}CRWLOCK;

#define CRWLOCK_RWLOCK(crwlock)          (&((crwlock)->rwlock))

#define CRWLOCK_LOCATION(crwlock, __op__)  (((crwlock)->location)[__op__])

#define CRWLOCK_GET_LOCATION(crwlock, __op__) \
    CRWLOCK_LOCATION(crwlock, __op__)

#define CRWLOCK_SET_LOCATION(crwlock, __op__, __location__) do{ \
    CRWLOCK_LOCATION((crwlock) , (__op__)) = (__location__);\
}while(0)

#define CRWLOCK_INIT_LOCATION(crwlock) do{\
    UINT32 __op__;\
    for(__op__ = 0; __op__ < CRWLOCK_OP_END; __op__ ++)\
    {\
        LOCATION_INIT(CRWLOCK_LOCATION((crwlock), __op__));\
    }\
}while(0)

#define CRWLOCK_PRINT_LOCATION(fp, fname, crwlock) do{\
    UINT32 __op__;\
    for(__op__ = 0; __op__ < CRWLOCK_OP_END; __op__ ++)\
    {\
        if(LOC_NONE_BASE != CRWLOCK_LOCATION((crwlock), __op__))\
        {\
            sys_log(fp, "\t CRWLOCK %lx: %s report: op = %ld happen at %s:%ld\n", crwlock, fname, __op__, MM_LOC_FILE_NAME(CRWLOCK_LOCATION((crwlock), __op__)), MM_LOC_LINE_NO(CRWLOCK_LOCATION((crwlock), __op__)));\
        }\
    }\
}while(0)

#define CRWLOCK_NR_READER(crwlock)            ((crwlock)->rwlock.__data.__nr_readers)
#define CRWLOCK_NR_READER_QUEUED(crwlock)     ((crwlock)->rwlock.__data.__nr_readers_queued)
#define CRWLOCK_NR_WRITER_QUEUED(crwlock)     ((crwlock)->rwlock.__data.__nr_writers_queued)

#define CRWLOCK_PRINT_LOCK_INFO(fp, __op__, crwlock) do{\
    sys_log(fp, "crwlock %lx : op = %ld, __nr_readers = %d, __nr_readers_queued = %d, __nr_writers_queued = %d\n", crwlock,__op__,\
        CRWLOCK_NR_READER(crwlock),\
        CRWLOCK_NR_READER_QUEUED(crwlock),\
        CRWLOCK_NR_WRITER_QUEUED(crwlock) \
        );\
}while(0)

#define CRWLOCK_RESET(this_crwlock, flag)    do{\
    crwlock_init(this_crwlock, flag, CRWLOCK_GET_LOCATION(this_crwlock, CRWLOCK_OP_INIT));\
}while(0)

//#define CRWLOCK_CHECK_LOCK_VALIDITY(__crwlock__, __op__, __location__) do{crwlock_check(__crwlock__, __op__, __location__);}while(0)

#define CRWLOCK_CHECK_LOCK_VALIDITY(__crwlock__, __op__, __location__) do{}while(0)

typedef struct
{
    void       *ptr;
    UINT32     location;
    UINT32     counter;
}PTR_DBG_NODE;


CMUTEX *cmutex_new(const UINT32 flag, const UINT32 location);

void    cmutex_free(CMUTEX *cmutex, const UINT32 location);

EC_BOOL cmutex_init(CMUTEX *cmutex, const UINT32 flag, const UINT32 location);

void    cmutex_clean(CMUTEX *cmutex, const UINT32 location);

EC_BOOL cmutex_lock(CMUTEX *cmutex, const UINT32 location);

EC_BOOL cmutex_unlock(CMUTEX *cmutex, const UINT32 location);


CCOND  *ccond_new(const UINT32 location);

EC_BOOL ccond_init(CCOND *ccond, const UINT32 location);

void    ccond_free(CCOND *ccond, const UINT32 location);

EC_BOOL ccond_clean(CCOND *ccond, const UINT32 location);

EC_BOOL ccond_wait(CCOND *ccond, const UINT32 location);

EC_BOOL ccond_reserve(CCOND *ccond, const UINT32 counter, const UINT32 location);

EC_BOOL ccond_release(CCOND *ccond, const UINT32 location);

EC_BOOL ccond_release_all(CCOND *ccond, const UINT32 location);

/*spy on the current times*/
UINT32  ccond_spy(CCOND *ccond, const UINT32 location);


EC_BOOL cmutex_node_init(CMUTEX_NODE *cmutex_node);

EC_BOOL cmutex_node_clean(CMUTEX_NODE *cmutex_node);

void    cmutex_node_print(LOG *log, CMUTEX_NODE *cmutex_node);

EC_BOOL cmutex_bucket_init(CMUTEX_BUCKET *cmutex_bucket);

EC_BOOL cmutex_bucket_clean(CMUTEX_BUCKET *cmutex_bucket);

EC_BOOL cmutex_bucket_add(CMUTEX_BUCKET *cmutex_bucket, CMUTEX *cmutex);

void    cmutex_bucket_print(LOG *log, CMUTEX_BUCKET *cmutex_bucket);

EC_BOOL cmutex_pool_init(CMUTEX_POOL *cmutex_pool);

EC_BOOL cmutex_pool_clean(CMUTEX_POOL *cmutex_pool);

EC_BOOL cmutex_pool_add(CMUTEX_POOL *cmutex_pool, CMUTEX *cmutex);

EC_BOOL cmutex_pool_rmv(CMUTEX_POOL *cmutex_pool, CMUTEX *cmutex);

EC_BOOL cmutex_pool_reset_one(CMUTEX_POOL *cmutex_pool, CMUTEX *cmutex);

EC_BOOL cmutex_pool_reset_all(CMUTEX_POOL *cmutex_pool, const UINT32 old_owner);

void    cmutex_pool_print(LOG *log, CMUTEX_POOL *cmutex_pool);

CMUTEX_POOL *cmutex_pool_default_get();

CRWLOCK *crwlock_new(const UINT32 flag, const UINT32 location);

EC_BOOL crwlock_init(CRWLOCK *crwlock, const UINT32 flag, const UINT32 location);

void    crwlock_free(CRWLOCK *crwlock, const UINT32 location);

void    crwlock_clean(CRWLOCK *crwlock, const UINT32 location);

EC_BOOL crwlock_rdlock(CRWLOCK *crwlock, const UINT32 location);

EC_BOOL crwlock_wrlock(CRWLOCK *crwlock, const UINT32 location);

EC_BOOL crwlock_unlock(CRWLOCK *crwlock, const UINT32 location);

#endif /*_CMUTEX_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

