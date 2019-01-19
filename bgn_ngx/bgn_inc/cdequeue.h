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

#ifndef _CDEQUEUE_H
#define _CDEQUEUE_H

#include "type.h"
#include "mm.h"
#include "log.h"

/*Double Ended Queue */
typedef struct
{
    uint32_t        capacity;
    uint32_t        size;

    uint32_t        front;
    uint32_t        rear;

    /*working items are from rear to front [--] or from front to rear [++]*/
    /*i.e., [rear, rear - 1, ..., front] or [front, front + 1, ..., rear] */
    void          **items;
}CDEQUEUE;

#define CDEQUEUE_FRONT(cdequeue)                ((cdequeue)->front)
#define CDEQUEUE_REAR(cdequeue)                 ((cdequeue)->rear)
#define CDEQUEUE_SIZE(cdequeue)                 ((cdequeue)->size)
#define CDEQUEUE_CAPACITY(cdequeue)             ((cdequeue)->capacity)
#define CDEQUEUE_ITEMS(cdequeue)                ((cdequeue)->items)
#define CDEQUEUE_ITEM(cdequeue, pos)            ((cdequeue)->items[ (pos) ])

#define CDEQUEUE_BACKWARD(cdequeue, pos)   \
    (((pos) + CDEQUEUE_CAPACITY(cdequeue) - 1) % CDEQUEUE_CAPACITY(cdequeue))

#define CDEQUEUE_FORWARD(cdequeue, pos)    \
    (((pos) + 1) % CDEQUEUE_CAPACITY(cdequeue))

#define CDEQUEUE_IS_FULL(cdequeue)         \
    ((CDEQUEUE_SIZE(cdequeue) == CDEQUEUE_CAPACITY(cdequeue))? EC_TRUE : EC_FALSE)

#define CDEQUEUE_IS_EMPTY(cdequeue)        \
    (0 == CDEQUEUE_SIZE(cdequeue)? EC_TRUE : EC_FALSE)

EC_BOOL cdequeue_init(CDEQUEUE *cdequeue, const uint32_t num);

CDEQUEUE *cdequeue_new(const uint32_t num);

EC_BOOL cdequeue_clean(CDEQUEUE *cdequeue);

EC_BOOL cdequeue_free(CDEQUEUE *cdequeue);

EC_BOOL cdequeue_is_empty(const CDEQUEUE *cdequeue);

EC_BOOL cdequeue_is_full(const CDEQUEUE *cdequeue);

uint32_t cdequeue_size(const CDEQUEUE *cdequeue);

void *cdequeue_push_front(CDEQUEUE *cdequeue, void *obj);

void *cdequeue_pop_front(CDEQUEUE *cdequeue);

void *cdequeue_push_back(CDEQUEUE *cdequeue, void *obj);

void *cdequeue_pop_back(CDEQUEUE *cdequeue);

void cdequeue_print(LOG *log, const CDEQUEUE *cdequeue);

#endif /*_CDEQUEUE_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

