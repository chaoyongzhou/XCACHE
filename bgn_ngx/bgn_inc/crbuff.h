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

#ifndef _CRBUFF_H
#define _CRBUFF_H

#include "type.h"
#include "log.h"
#include "mm.h"

typedef struct
{
  UINT32     capacity;
  void      *data;

  void      *begin;
  void      *end;
}CRBUFF;

#define CRBUFF_CAPACITY(crbuff)         ((crbuff)->capacity)
#define CRBUFF_DATA(crbuff)             ((crbuff)->data)
#define CRBUFF_BEG(crbuff)              ((crbuff)->begin)
#define CRBUFF_END(crbuff)              ((crbuff)->end)

CRBUFF *crbuff_new();

EC_BOOL crbuff_init(CRBUFF *crbuff);

EC_BOOL crbuff_clean(CRBUFF *crbuff);

EC_BOOL crbuff_free(CRBUFF *crbuff);

EC_BOOL crbuff_reset(CRBUFF *crbuff);

EC_BOOL crbuff_set_capacity(CRBUFF *crbuff, const UINT32 capacity);

/*used space size*/
UINT32 crbuff_data_size(const CRBUFF *crbuff);

/*left (not used) space size*/
UINT32 crbuff_room_size(const CRBUFF *crbuff);

EC_BOOL crbuff_push(CRBUFF *crbuff, void *data, const UINT32 data_size);

EC_BOOL crbuff_read(CRBUFF *crbuff, void *data, const UINT32 data_size);

EC_BOOL crbuff_pop(CRBUFF *crbuff, void *data, const UINT32 data_size);

void    crbuff_print(LOG *log, const CRBUFF *crbuff);


#endif/* _CRBUFF_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/
