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

#ifndef    _CDCNPDEG_INC
#define    _CDCNPDEG_INC

#include "type.h"
#include "cdcnprb.h"

#define CDCNPDEG_ROOT_POS          (0)/*point to the root rb node*/

#define CDCNPDEG_NODE_NOT_USED     ((uint32_t)0)
#define CDCNPDEG_NODE_USED         ((uint32_t)1)

typedef struct
{
    uint32_t prev_pos :31; /*value range: [0, 0x7FFFFFFF)*/
    uint32_t rsvd1    : 1;

    uint32_t next_pos :31; /*value range: [0, 0x7FFFFFFF)*/
    uint32_t rsvd2    : 1;
}CDCNPDEG_NODE; /*8B*/

#define CDCNPDEG_NODE_PREV_POS(node)          ((node)->prev_pos)
#define CDCNPDEG_NODE_NEXT_POS(node)          ((node)->next_pos)


#endif    /* _CDCNPDEG_INC */

#ifdef __cplusplus
}
#endif/*__cplusplus*/
