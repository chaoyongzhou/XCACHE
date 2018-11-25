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

#ifndef    _CDCNPDEL_INC
#define    _CDCNPDEL_INC

#include "type.h"
#include "cdcnprb.h"

#define CDCNPDEL_ROOT_POS          (0)/*point to the root rb node*/

#define CDCNPDEL_NODE_NOT_USED     ((uint32_t)0)
#define CDCNPDEL_NODE_USED         ((uint32_t)1)

typedef struct
{
    uint32_t prev_pos :31; /*value range: [0, 0x7FFFFFFF)*/
    uint32_t rsvd1    : 1;

    uint32_t next_pos :31; /*value range: [0, 0x7FFFFFFF)*/
    uint32_t rsvd2    : 1;
}CDCNPDEL_NODE; /*8B*/

#define CDCNPDEL_NODE_PREV_POS(node)          ((node)->prev_pos)
#define CDCNPDEL_NODE_NEXT_POS(node)          ((node)->next_pos)


#endif    /* _CDCNPDEL_INC */

#ifdef __cplusplus
}
#endif/*__cplusplus*/
