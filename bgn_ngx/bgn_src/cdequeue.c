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

#include "cdequeue.h"


EC_BOOL cdequeue_init(CDEQUEUE *cdequeue, const uint32_t num)
{
    uint32_t idx;

    for(idx = 0; idx < num; idx ++)
    {
        CDEQUEUE_ITEM(cdequeue, idx) = NULL_PTR;
    }

    CDEQUEUE_SIZE(cdequeue)     = 0;
    CDEQUEUE_CAPACITY(cdequeue) = num;

    CDEQUEUE_FRONT(cdequeue)    = 0;
    CDEQUEUE_REAR(cdequeue)     = CDEQUEUE_CAPACITY(cdequeue) - 1;

    return (EC_TRUE);
}

CDEQUEUE *cdequeue_new(const uint32_t num)
{
    CDEQUEUE *cdequeue;

    /*num = 0 is not meaningful. do not consider such scenario even if interfaces are ok*/
    if(0 == num)
    {
        dbg_log(SEC_0207_CDEQUEUE, 0)(LOGSTDOUT, "error:cdequeue_new: invalid num = 0\n");
        return (NULL_PTR);
    }

    alloc_static_mem(MM_CDEQUEUE, &cdequeue, LOC_CDEQUEUE_0001);
    if(NULL_PTR == cdequeue)
    {
        dbg_log(SEC_0207_CDEQUEUE, 0)(LOGSTDOUT, "error:cdequeue_new: memory insufficient\n");
        return (NULL_PTR);
    }

    CDEQUEUE_ITEMS(cdequeue) = safe_malloc(num * sizeof(void*), LOC_CDEQUEUE_0002);
    if(NULL_PTR == CDEQUEUE_ITEMS(cdequeue))
    {
        free_static_mem(MM_CDEQUEUE, cdequeue, LOC_CDEQUEUE_0003);
        dbg_log(SEC_0207_CDEQUEUE, 0)(LOGSTDOUT, "error:cdequeue_new: malloc %u items failed\n", num);
        return (NULL_PTR);
    }

    cdequeue_init(cdequeue, num);

    return (cdequeue);
}

EC_BOOL cdequeue_clean(CDEQUEUE *cdequeue)
{
    if(NULL_PTR != cdequeue)
    {
        if(NULL_PTR != CDEQUEUE_ITEMS(cdequeue))
        {
            safe_free(CDEQUEUE_ITEMS(cdequeue), LOC_CDEQUEUE_0004);
            CDEQUEUE_ITEMS(cdequeue) = NULL_PTR;
        }

        CDEQUEUE_FRONT(cdequeue)    = 0;
        CDEQUEUE_REAR(cdequeue)     = 0;
        CDEQUEUE_SIZE(cdequeue)     = 0;
        CDEQUEUE_CAPACITY(cdequeue) = 0;
    }

    return (EC_TRUE);
}

EC_BOOL cdequeue_free(CDEQUEUE *cdequeue)
{
    if(NULL_PTR != cdequeue)
    {
        cdequeue_clean(cdequeue);
        free_static_mem(MM_CDEQUEUE, cdequeue, LOC_CDEQUEUE_0005);
    }

    return (EC_TRUE);
}

EC_BOOL cdequeue_is_empty(const CDEQUEUE *cdequeue)
{
    if(NULL_PTR == cdequeue)
    {
        return (EC_TRUE);
    }

    return CDEQUEUE_IS_EMPTY(cdequeue);
}

EC_BOOL cdequeue_is_full(const CDEQUEUE *cdequeue)
{
    if(NULL_PTR == cdequeue)
    {
        return (EC_FALSE);
    }

    return CDEQUEUE_IS_FULL(cdequeue);
}

uint32_t cdequeue_size(const CDEQUEUE *cdequeue)
{
    if(NULL_PTR == cdequeue)
    {
        return ((uint32_t)0);
    }

    return CDEQUEUE_SIZE(cdequeue);
}

void *cdequeue_push_front(CDEQUEUE *cdequeue, void *obj)
{
    if (NULL_PTR != cdequeue && EC_FALSE == CDEQUEUE_IS_FULL(cdequeue))
    {
        /*move backward*/
        CDEQUEUE_FRONT(cdequeue) = CDEQUEUE_BACKWARD(cdequeue, CDEQUEUE_FRONT(cdequeue));

        CDEQUEUE_ITEM(cdequeue, CDEQUEUE_FRONT(cdequeue)) = obj;
        CDEQUEUE_SIZE(cdequeue) ++;

        return (obj);
    }

    return (NULL_PTR);
}

void *cdequeue_pop_front(CDEQUEUE *cdequeue)
{
    if(NULL_PTR != cdequeue && EC_FALSE == CDEQUEUE_IS_EMPTY(cdequeue))
    {
        void *obj;

        obj = CDEQUEUE_ITEM(cdequeue, CDEQUEUE_FRONT(cdequeue));
        CDEQUEUE_ITEM(cdequeue, CDEQUEUE_FRONT(cdequeue)) = NULL_PTR; /*clean up*/

        /*move forward*/
        CDEQUEUE_FRONT(cdequeue) = CDEQUEUE_FORWARD(cdequeue, CDEQUEUE_FRONT(cdequeue));

        CDEQUEUE_SIZE(cdequeue) -- ;

        return (obj);
    }

    return (NULL_PTR);
}

void *cdequeue_push_back(CDEQUEUE *cdequeue, void *obj)
{
    if (NULL_PTR != cdequeue && EC_FALSE == CDEQUEUE_IS_FULL(cdequeue))
    {
        /*move forward*/
        CDEQUEUE_REAR(cdequeue) = CDEQUEUE_FORWARD(cdequeue, CDEQUEUE_REAR(cdequeue));

        CDEQUEUE_ITEM(cdequeue, CDEQUEUE_REAR(cdequeue)) = obj;

        CDEQUEUE_SIZE(cdequeue) ++;

        return (obj);
    }

    return (NULL_PTR);
}

void *cdequeue_pop_back(CDEQUEUE *cdequeue)
{
    if(NULL_PTR != cdequeue && EC_FALSE == CDEQUEUE_IS_EMPTY(cdequeue))
    {
        void *obj;

        obj = CDEQUEUE_ITEM(cdequeue, CDEQUEUE_REAR(cdequeue));
        CDEQUEUE_ITEM(cdequeue, CDEQUEUE_REAR(cdequeue)) = NULL_PTR;

        /*move backward*/
        CDEQUEUE_REAR(cdequeue) = CDEQUEUE_BACKWARD(cdequeue, CDEQUEUE_REAR(cdequeue));

        CDEQUEUE_SIZE(cdequeue)--;

        return (obj);
    }

    return (NULL_PTR);
}

void cdequeue_print(LOG *log, const CDEQUEUE *cdequeue)
{
    uint32_t size;
    uint32_t pos;

    sys_log(log, "cdequeue_print: cdequeue %p: front %u, rear %u, size %u, capacity %u\n",
                 cdequeue,
                 CDEQUEUE_FRONT(cdequeue),
                 CDEQUEUE_REAR(cdequeue),
                 CDEQUEUE_SIZE(cdequeue),
                 CDEQUEUE_CAPACITY(cdequeue));

    sys_log(log, "cdequeue_print: cdequeue %p: items from rear to front:\n", cdequeue);

    size = CDEQUEUE_SIZE(cdequeue);
    for(pos = CDEQUEUE_REAR(cdequeue); size > 0; pos = CDEQUEUE_BACKWARD(cdequeue, pos), size --)
    {
        sys_log(log, "[%u] %p\n", pos, CDEQUEUE_ITEM(cdequeue, pos));

    }

    return;
}


#ifdef __cplusplus
}
#endif/*__cplusplus*/
