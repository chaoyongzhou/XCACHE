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


#ifndef _CRANGE_H
#define _CRANGE_H

#include "type.h"
#include "mm.h"
#include "log.h"

#include "cstring.h"
#include "clist.h"


#define CRANGE_MAX_OFFSET          ((UINT32)~0)

/*up to 1GB. for safe reason. prevent range segs from overflow*/
#define CRANGE_MAX_LEN             (256 * 1024 * 4096) 

/*
* range is left-close-right-close: [seg_start_offset, seg_end_offset]
* where seg_start_offset <= seg_end_offset
*/
typedef struct
{
    UINT32      seg_size;          /*the given size per seg*/
    UINT32      seg_no;
    UINT32      seg_start_offset;
    UINT32      seg_end_offset;
}CRANGE_SEG;

#define CRANGE_SEG_SIZE(crange_seg)            ((crange_seg)->seg_size)
#define CRANGE_SEG_NO(crange_seg)              ((crange_seg)->seg_no)
#define CRANGE_SEG_S_OFFSET(crange_seg)        ((crange_seg)->seg_start_offset)
#define CRANGE_SEG_E_OFFSET(crange_seg)        ((crange_seg)->seg_end_offset)

/*parsed from cngx http req*/
typedef struct
{
    EC_BOOL      suffix_start;
    EC_BOOL      suffix_end;

    /*[range_start, range_end]*/
    UINT32       range_start;
    UINT32       range_end;

    /*split range into segs*/
    CLIST        crange_segs; /*item is CRANGE_SEG*/

    CSTRING      boundary;
}CRANGE_NODE;

#define CRANGE_NODE_SUFFIX_START(crange_node)  ((crange_node)->suffix_start)
#define CRANGE_NODE_SUFFIX_END(crange_node)    ((crange_node)->suffix_end)
#define CRANGE_NODE_RANGE_START(crange_node)   ((crange_node)->range_start)
#define CRANGE_NODE_RANGE_END(crange_node)     ((crange_node)->range_end)
#define CRANGE_NODE_RANGE_SEGS(crange_node)    (&((crange_node)->crange_segs))
#define CRANGE_NODE_BOUNDARY(crange_node)      (&((crange_node)->boundary))

typedef struct
{
    CLIST        crange_nodes; /*item is CRANGE_NODE*/

    /*for multi-ranges*/
    CSTRING      boundary;
    UINT32       body_size;
}CRANGE_MGR;

#define CRANGE_MGR_RANGE_NODES(crange_mgr)      (&((crange_mgr)->crange_nodes))
#define CRANGE_MGR_BOUNDARY(crange_mgr)         (&((crange_mgr)->boundary))
#define CRANGE_MGR_BODY_SIZE(crange_mgr)        ((crange_mgr)->body_size)


CRANGE_SEG *crange_seg_new();

EC_BOOL crange_seg_init(CRANGE_SEG *crange_seg);

EC_BOOL crange_seg_clean(CRANGE_SEG *crange_seg);

EC_BOOL crange_seg_free(CRANGE_SEG *crange_seg);

void    crange_seg_print(LOG *log, const CRANGE_SEG *crange_seg);

EC_BOOL crange_segs_split(const UINT32 range_start, const UINT32 range_end, const UINT32 range_seg_size, CLIST *range_segs);

EC_BOOL crange_segs_filter(CLIST *range_segs, const UINT32 content_length);

CRANGE_NODE *crange_node_new();

EC_BOOL crange_node_init(CRANGE_NODE *crange_node);

EC_BOOL crange_node_clean(CRANGE_NODE *crange_node);

EC_BOOL crange_node_free(CRANGE_NODE *crange_node);

EC_BOOL crange_node_has_boundary(const CRANGE_NODE *crange_node);

void    crange_node_print(LOG *log, const CRANGE_NODE *crange_node);

void    crange_node_print_no_seg(LOG *log, const CRANGE_NODE *crange_node);

CRANGE_SEG *crange_node_first_seg(CRANGE_NODE *crange_node);

CRANGE_SEG *crange_node_first_seg_pop(CRANGE_NODE *crange_node);

EC_BOOL crange_node_split(CRANGE_NODE *crange_node, const UINT32 range_seg_size);

EC_BOOL crange_node_adjust(CRANGE_NODE *crange_node, const UINT32 content_length);

EC_BOOL crange_node_filter(CRANGE_NODE *crange_node, const UINT32 content_length);

EC_BOOL crange_node_range(CRANGE_NODE *crange_node, UINT32 *range_start, UINT32 *range_end);

CRANGE_MGR *crange_mgr_new();

EC_BOOL crange_mgr_init(CRANGE_MGR *crange_mgr);

EC_BOOL crange_mgr_clean(CRANGE_MGR *crange_mgr);

EC_BOOL crange_mgr_free(CRANGE_MGR *crange_mgr);

void    crange_mgr_print(LOG *log, const CRANGE_MGR *crange_mgr);

void    crange_mgr_print_no_seg(LOG *log, const CRANGE_MGR *crange_mgr);

UINT32  crange_mgr_node_num(const CRANGE_MGR *crange_mgr);

UINT32 crange_mgr_total_length(const CRANGE_MGR *crange_mgr);

EC_BOOL crange_mgr_is_empty(const CRANGE_MGR *crange_mgr);

EC_BOOL crange_mgr_has_boundary(const CRANGE_MGR *crange_mgr);

CRANGE_NODE *crange_mgr_first_node(CRANGE_MGR *crange_mgr);

CRANGE_NODE *crange_mgr_first_node_pop(CRANGE_MGR *crange_mgr);

EC_BOOL crange_mgr_add_node(CRANGE_MGR *crange_mgr, CRANGE_NODE *crange_node);

EC_BOOL crange_mgr_get_naked_boundary(CRANGE_MGR *crange_mgr, char **boundary, uint32_t *boundary_len);

EC_BOOL crange_mgr_split(CRANGE_MGR *crange_mgr, const UINT32 range_seg_size);

EC_BOOL crange_mgr_adjust(CRANGE_MGR *crange_mgr, const UINT32 content_length);

EC_BOOL crange_mgr_filter(CRANGE_MGR *crange_nodes, const UINT32 content_length);

EC_BOOL crange_mgr_is_range(const CRANGE_MGR *crange_mgr, const UINT32 range_start, const UINT32 range_end);

EC_BOOL crange_parse_content_range_start(const char *content_range, UINT32 *pos, EC_BOOL *suffix, UINT32 *range_start);

/*range:0-*/
EC_BOOL crange_mgr_is_start_zero_endless(const CRANGE_MGR *crange_mgr);

EC_BOOL crange_parse_content_range_end(const char *content_range, UINT32 *pos, UINT32 *range_end);

EC_BOOL crange_parse_content_content_length(const char *content_range, UINT32 *pos, UINT32 *content_length);

/*Content-Range format: <START>-<END>/<LENGTH>*/
EC_BOOL crange_parse_content_range(const char *content_range, UINT32 *range_start, UINT32 *range_end, UINT32 *content_length);

EC_BOOL crange_parse_range_prepare(const char *range, UINT32 *pos);

EC_BOOL crange_parse_range_start(const char *range, UINT32 *pos, EC_BOOL *suffix, UINT32 *range_start);

EC_BOOL crange_parse_range_end(const char *range, UINT32 *pos, EC_BOOL *suffix, UINT32 *range_end);

EC_BOOL crange_parse_range(const char *range, CRANGE_MGR *crange_mgr);

#endif /*_CRANGE_H*/


#ifdef __cplusplus
}
#endif/*__cplusplus*/



