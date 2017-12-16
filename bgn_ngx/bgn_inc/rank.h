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

#ifndef _RANK_H
#define _RANK_H

#include <stdio.h>
#include <stdlib.h>

#include "type.h"

#include "debug.h"
#include "log.h"
#include "cset.h"

EC_BOOL rank_set_new(CSET **rank_set);

EC_BOOL rank_set_free(CSET *rank_set);

EC_BOOL rank_set_clean(CSET *rank_set);

UINT32 rank_set_incl(CSET *rank_set, const UINT32 rank);

UINT32 rank_set_excl(CSET *rank_set, const UINT32 rank);

UINT32 rank_set_print(LOG *log, const CSET *rank_set);

UINT32 rank_set_init(CSET *rank_set, const UINT32 comm_size);

UINT32 rank_set_default_init(CSET *rank_set);


#endif /*_RANK_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/
