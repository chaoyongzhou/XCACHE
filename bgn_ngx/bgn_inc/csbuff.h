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

#ifndef _CSBUFF_H
#define _CSBUFF_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <semaphore.h>

#include "type.h"
#include "cmutex.h"

/**
*
*   when read_pos == write_pos, cache is empty
*   when write_pos - read_pos = max_len, cache is full
*   in fact, always satisfy
*      write_pos >= read_pos,
*   and
*      max_len >= write_pos - read_pos
*   when write_pos >= read_pos >= max_len, reduce write_pos, read_pos by
*      write_pos = write_pos - max_len,
*      read_pos  = read_pos  - max_len
*
**/

typedef struct
{
    //CMUTEX    cmutex;
    sem_t     sem;
    UINT32    read_pos;
    UINT32    write_pos;
    UINT32    max_len;
    UINT8     cache[0];
}CSBUFF;

//#define CSBUFF_CMUTEX(csbuff)                  (&((csbuff)->cmutex))
#define CSBUFF_SEMAPHORE(csbuff)               (&((csbuff)->sem))
#define CSBUFF_READ_POS(csbuff)                ((csbuff)->read_pos)
#define CSBUFF_WRITE_POS(csbuff)               ((csbuff)->write_pos)
#define CSBUFF_MAX_LEN(csbuff)                 ((csbuff)->max_len)
#define CSBUFF_CACHE(csbuff)                   ((csbuff)->cache)
#define CSBUFF_CACHE_CHAR(csbuff, pos)         ((csbuff)->cache[ (pos) ])

/*if mutex in shared memory, when lock one area, process/thread info will record in current process, */
/* which means the info can be accessed only by current process but not others. shit*/
#if 0
#define CSBUFF_INIT_LOCK(csbuff, flag, location)      cmutex_init(CSBUFF_CMUTEX(csbuff), flag, location)
#define CSBUFF_CLEAN_LOCK(csbuff, location)           cmutex_clean(CSBUFF_CMUTEX(csbuff), location)
#define CSBUFF_LOCK(csbuff, location)                 cmutex_lock(CSBUFF_CMUTEX(csbuff), location)
#define CSBUFF_UNLOCK(csbuff, location)               cmutex_unlock(CSBUFF_CMUTEX(csbuff), location)
#endif

#if 1
#define CSBUFF_INIT_LOCK(csbuff, flag, location)      sem_init(CSBUFF_SEMAPHORE(csbuff), CMUTEX_PROCESS_SHARED == (flag)? 1:0, 1)
#define CSBUFF_CLEAN_LOCK(csbuff, location)           sem_destroy(CSBUFF_SEMAPHORE(csbuff))
#define CSBUFF_LOCK(csbuff, location)                 sem_wait(CSBUFF_SEMAPHORE(csbuff))
#define CSBUFF_UNLOCK(csbuff, location)               sem_post(CSBUFF_SEMAPHORE(csbuff))
#endif

EC_BOOL  csbuff_init(CSBUFF *csbuff, const UINT32 cmutex_flag);
CSBUFF * csbuff_new(const UINT32 size, const UINT32 cmutex_flag);
EC_BOOL  csbuff_clean(CSBUFF *csbuff);
EC_BOOL  csbuff_reset(CSBUFF *csbuff);
EC_BOOL  csbuff_free(CSBUFF *csbuff);
EC_BOOL  csbuff_set_max_len(CSBUFF *csbuff, const UINT32 size);
UINT32   csbuff_get_max_len(const CSBUFF *csbuff);
void     csbuff_print(LOG *log, CSBUFF *csbuff);

UINT32   csbuff_total_write_len(CSBUFF *csbuff);
UINT32   csbuff_total_read_len(CSBUFF *csbuff);

UINT32   csbuff_once_write_len(CSBUFF *csbuff);
UINT32   csbuff_once_read_len(CSBUFF *csbuff);

EC_BOOL  csbuff_pos_reduce(CSBUFF *csbuff);

EC_BOOL  csbuff_read(CSBUFF *csbuff, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *out_buff_pos);
EC_BOOL  csbuff_write(CSBUFF *csbuff, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *in_buff_pos);

EC_BOOL  csbuff_is_full(const CSBUFF *csbuff);

EC_BOOL csbuff_probe(CSBUFF *csbuff, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *out_buff_pos);

#endif/*_CSBUFF_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/
