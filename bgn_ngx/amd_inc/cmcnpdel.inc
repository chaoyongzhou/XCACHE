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

#ifndef    _CMCNPDEL_INC
#define    _CMCNPDEL_INC

#include "type.h"
#include "cmcnprb.h"

#define CMCNPDEL_ROOT_POS          (0)/*point to the root rb node*/

#define CMCNPDEL_NODE_NOT_USED     ((uint32_t)0)
#define CMCNPDEL_NODE_USED         ((uint32_t)1)

typedef struct
{
    uint32_t prev_pos :31; /*value range: [0, 0x7FFFFFFF)*/
    uint32_t rsvd1    : 1;
    
    uint32_t next_pos :31; /*value range: [0, 0x7FFFFFFF)*/
    uint32_t rsvd2    : 1;
}CMCNPDEL_NODE; /*8B*/

#define CMCNPDEL_NODE_PREV_POS(node)          ((node)->prev_pos)
#define CMCNPDEL_NODE_NEXT_POS(node)          ((node)->next_pos)


#endif    /* _CMCNPDEL_INC */

#ifdef __cplusplus
}
#endif/*__cplusplus*/
