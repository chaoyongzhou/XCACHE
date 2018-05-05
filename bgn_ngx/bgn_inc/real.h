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

#ifndef _REAL_H
#define _REAL_H

#include "type.h"

#define CONST_REAL_POS_DELTA_ZERO_VALUE ((REAL) 0.000001)
#define CONST_REAL_NEG_DELTA_ZERO_VALUE ((REAL)-0.000001)

#define CONST_REAL_POS_DELTA_ONE_VALUE  ((REAL)1.000001)
#define CONST_REAL_NEG_DELTA_ONE_VALUE  ((REAL)0.999999)


#define REAL_ISZERO(real_md_id, a) \
    ((( CONST_REAL_POS_DELTA_ZERO_VALUE >= (a) ) &&( (a) >= CONST_REAL_NEG_DELTA_ZERO_VALUE )) ? EC_TRUE : EC_FALSE)

#define REAL_ISONE(real_md_id, a)  \
    ((( CONST_REAL_POS_DELTA_ONE_VALUE  >= (a) ) &&( (a) >= CONST_REAL_NEG_DELTA_ONE_VALUE )) ? EC_TRUE : EC_FALSE)
#if 0
#define REAL_ISEQU(real_md_id, a, b) \
    ((( CONST_REAL_POS_DELTA_ZERO_VALUE  >= ((a) - (b)) ) &&( ((a) - (b)) >= CONST_REAL_NEG_DELTA_ZERO_VALUE )) ? EC_TRUE : EC_FALSE)

#define REAL_ISEQU(real_md_id, a, b) ((((a) > (b)) || ((a) < (b))) ? EC_FALSE : EC_TRUE)
#endif
#define REAL_ISEQU(real_md_id, a, b) ((((a) - (b) < CONST_REAL_POS_DELTA_ZERO_VALUE) && ((b) - (a) < CONST_REAL_POS_DELTA_ZERO_VALUE)) ? EC_TRUE : EC_FALSE)

#define REAL_SETZERO(real_md_id, a) ((a) = 0.0)
#define REAL_SETONE(real_md_id, a)  ((a) = 1.0)

/*real operation interface*/

#define REAL_CLONE(real_md_id, a, c)     ((c) = (a))

#define REAL_NEG(real_md_id, a, c)         ((c) = (-(a)))

#define REAL_ADD(real_md_id, a, b, c)     ((c) = (a) + (b))
#define REAL_ADC(real_md_id, a, c)         ((c) += (a))

#define REAL_SUB(real_md_id, a, b, c)     ((c) = (a) - (b))
#define REAL_SBB(real_md_id, a, c)         ((c) -= (a))

#define REAL_MUL(real_md_id, a, b, c)     ((c) = (a) * (b))
#define REAL_MUL_SELF(real_md_id, a, c)     ((c) *= (a))

#define REAL_DIV(real_md_id, a, b, c)     ((c) = (a) / (b))

#define REAL_INV(real_md_id, a, c)     ((c) = (1.0 / (a)))


#define real_start() (0)
#define real_end(real_md_id) do{}while(0)

UINT32 real_init(REAL *real);
UINT32 real_clean(REAL *real);
UINT32 real_free(REAL *real);
REAL * real_new(const UINT32 real_md_id);

void real_print(LOG *log, const REAL *real);

#endif/* _REAL_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/
