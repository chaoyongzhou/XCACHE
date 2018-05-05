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

#ifndef _TYPECONST_H
#define _TYPECONST_H

#define DOUBLE_IN_CHAR  32

#define NBITS_TO_NWORDS(nbits)         (((nbits) + WORDSIZE - 1) / WORDSIZE)
#define NBITS_TO_NBYTES(nbits)         (((nbits) + BYTESIZE - 1) / BYTESIZE)
#define NBYTES_TO_NWORDS(nbytes)       (((nbytes) + (WORDSIZE / BYTESIZE) - 1) / (WORDSIZE / BYTESIZE))
#define NWORDS_TO_NBYTES(nwords)       ((nwords) * (WORDSIZE / BYTESIZE))

#endif /*_TYPECONST_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

