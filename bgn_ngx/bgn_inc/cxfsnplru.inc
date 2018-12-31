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

#ifndef    _CXFSNPLRU_INC
#define    _CXFSNPLRU_INC

#include "type.h"
#include "cxfsnprb.h"

#define CXFSNPLRU_ROOT_POS          (0)/*point to the root rb node*/

#define CXFSNPLRU_NODE_NOT_USED     ((uint32_t)0)
#define CXFSNPLRU_NODE_USED         ((uint32_t)1)

typedef struct
{
    uint32_t prev_pos :31; /*value range: [0, 0x7FFFFFFF)*/
    uint32_t rsvd1    : 1;
    
    uint32_t next_pos :31; /*value range: [0, 0x7FFFFFFF)*/
    uint32_t rsvd2    : 1;
}CXFSNPLRU_NODE; /*8B*/

#define CXFSNPLRU_NODE_PREV_POS(node)          ((node)->prev_pos)
#define CXFSNPLRU_NODE_NEXT_POS(node)          ((node)->next_pos)


#endif    /* _CXFSNPLRU_INC */

#ifdef __cplusplus
}
#endif/*__cplusplus*/
