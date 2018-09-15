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

#ifndef _CAIO_H
#define _CAIO_H

#include "type.h"
#include "mm.h"
#include "log.h"

#define CAIO_PAGE_SIZE      (512)

EC_BOOL caio_start(const UINT32 max_req_num);

void    caio_end();

EC_BOOL caio_file_load(int fd, UINT32 *offset, const UINT32 rsize, UINT8 *buff);

EC_BOOL caio_file_flush(int fd, UINT32 *offset, const UINT32 wsize, const UINT8 *buff);

#endif /*_CAIO_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/
