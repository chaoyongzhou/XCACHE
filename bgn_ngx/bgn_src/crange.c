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

#include "type.h"
#include "mm.h"
#include "log.h"

#include "cstring.h"
#include "clist.h"

#include "crange.h"

CRANGE_SEG *crange_seg_new()
{
    CRANGE_SEG *crange_seg;
    alloc_static_mem(MM_CRANGE_SEG, &crange_seg, LOC_CRANGE_0001);
    if(NULL_PTR != crange_seg)
    {
        crange_seg_init(crange_seg);
    }
    return (crange_seg);
}

EC_BOOL crange_seg_init(CRANGE_SEG *crange_seg)
{
    CRANGE_SEG_SIZE(crange_seg)     = 0;
    CRANGE_SEG_NO(crange_seg)       = 0;
    CRANGE_SEG_S_OFFSET(crange_seg) = 0;
    CRANGE_SEG_E_OFFSET(crange_seg) = 0;

    return (EC_TRUE);
}

EC_BOOL crange_seg_clean(CRANGE_SEG *crange_seg)
{
    CRANGE_SEG_SIZE(crange_seg)     = 0;
    CRANGE_SEG_NO(crange_seg)       = 0;
    CRANGE_SEG_S_OFFSET(crange_seg) = 0;
    CRANGE_SEG_E_OFFSET(crange_seg) = 0;

    return (EC_TRUE);
}

EC_BOOL crange_seg_free(CRANGE_SEG *crange_seg)
{
    if(NULL_PTR != crange_seg)
    {
        crange_seg_clean(crange_seg);
        free_static_mem(MM_CRANGE_SEG, crange_seg, LOC_CRANGE_0002);
    }
    return (EC_TRUE);
}

void crange_seg_print(LOG *log, const CRANGE_SEG *crange_seg)
{
    sys_print(log, "crange_seg_print: crange_seg %p: [%ld] [%ld, %ld] / %ld\n",
                   crange_seg,
                   CRANGE_SEG_NO(crange_seg),
                   CRANGE_SEG_S_OFFSET(crange_seg),
                   CRANGE_SEG_E_OFFSET(crange_seg),
                   CRANGE_SEG_SIZE(crange_seg));
    return;
}

EC_BOOL crange_segs_split(const UINT32 range_start, const UINT32 range_end, const UINT32 range_seg_size, CLIST *crange_segs)
{
    UINT32      seg_start;
    UINT32      seg_end;
    UINT32      seg_no;

    seg_start        = (range_start / range_seg_size);
    seg_end          = (range_end   / range_seg_size);

    dbg_log(SEC_0018_CRANGE, 9)(LOGSTDOUT, "[DEBUG] crange_segs_split: "
                                           "range [%ld, %ld] => seg_start %ld, seg_end %ld\n",
                                           range_start, range_end,
                                           seg_start, seg_end);

    for(seg_no = seg_start; seg_no <= seg_end; seg_no ++)
    {
        CRANGE_SEG      *crange_seg;
        UINT32           range_seg_no;
        UINT32           range_seg_s_offset;
        UINT32           range_seg_e_offset;

        range_seg_no = seg_no + 1;

        range_seg_s_offset = (seg_no == seg_start) ? (range_start % range_seg_size) : 0;
        range_seg_e_offset = (seg_no == seg_end  ) ? (range_end   % range_seg_size) : (range_seg_size - 1);

        crange_seg = crange_seg_new();
        if(NULL_PTR == crange_seg)
        {
            dbg_log(SEC_0018_CRANGE, 0)(LOGSTDOUT, "error:crange_segs_split: new [%ld] crange_seg failed\n",
                            range_seg_no);
            return (EC_FALSE);
        }

        CRANGE_SEG_SIZE(crange_seg)     = range_seg_size;
        CRANGE_SEG_NO(crange_seg)       = range_seg_no;
        CRANGE_SEG_S_OFFSET(crange_seg) = range_seg_s_offset;
        CRANGE_SEG_E_OFFSET(crange_seg) = range_seg_e_offset;

        if(NULL_PTR == clist_push_back(crange_segs, (void *)crange_seg))
        {
            dbg_log(SEC_0018_CRANGE, 0)(LOGSTDOUT, "error:crange_segs_split: push [%ld] crange_seg failed\n",
                            range_seg_no);
            crange_seg_free(crange_seg);
            return (EC_FALSE);
        }
        dbg_log(SEC_0018_CRANGE, 9)(LOGSTDOUT, "[DEBUG] crange_segs_split: push [%ld] crange_seg (%ld, %ld, %ld, %ld) done\n",
                            range_seg_no,
                            CRANGE_SEG_SIZE(crange_seg),
                            CRANGE_SEG_NO(crange_seg),
                            CRANGE_SEG_S_OFFSET(crange_seg),
                            CRANGE_SEG_E_OFFSET(crange_seg));
    }

    if(do_log(SEC_0018_CRANGE, 9))
    {
        dbg_log(SEC_0018_CRANGE, 9)(LOGSTDOUT, "[DEBUG] crange_segs_split: content-range: %ld-%ld, seg size %ld ==> \n",
                    range_start, range_end, range_seg_size);
        clist_print(LOGSTDOUT, crange_segs, (CLIST_DATA_DATA_PRINT)crange_seg_print);
    }

    return (EC_TRUE);
}

/*filter [content_start, content_end] / content_length*/
EC_BOOL crange_segs_filter(CLIST *crange_segs, const UINT32 content_start, const UINT32 content_end, const UINT32 content_length)
{
    CRANGE_SEG    *crange_seg;

    if(0 == content_length)
    {
        clist_clean(crange_segs, (CLIST_DATA_DATA_CLEANER)crange_seg_free);
        return (EC_TRUE);
    }

    /*filter content_length*/
    while(NULL_PTR != (crange_seg = clist_last_data(crange_segs)))
    {
        if(content_length <= CRANGE_SEG_E_OFFSET(crange_seg))
        {
            CRANGE_SEG_E_OFFSET(crange_seg) = content_length - 1;
        }

        if(CRANGE_SEG_S_OFFSET(crange_seg) <= CRANGE_SEG_E_OFFSET(crange_seg))
        {
            break;
        }

        dbg_log(SEC_0018_CRANGE, 9)(LOGSTDOUT, "[DEBUG] crange_segs_filter: "
                                               "dicard crange_seg %p: [%ld, %ld] / %ld (content_length)\n",
                                               crange_seg,
                                               CRANGE_SEG_S_OFFSET(crange_seg),
                                               CRANGE_SEG_E_OFFSET(crange_seg),
                                               content_length);
        clist_pop_back(crange_segs);
        crange_seg_free(crange_seg);
    }

    /*filter content_end*/
    while(content_end + 1 < content_length && NULL_PTR != (crange_seg = clist_last_data(crange_segs)))
    {
        if(content_end <= CRANGE_SEG_E_OFFSET(crange_seg))
        {
            CRANGE_SEG_E_OFFSET(crange_seg) = content_end;
        }

        if(CRANGE_SEG_S_OFFSET(crange_seg) <= CRANGE_SEG_E_OFFSET(crange_seg))
        {
            break;
        }

        dbg_log(SEC_0018_CRANGE, 9)(LOGSTDOUT, "[DEBUG] crange_segs_filter: "
                                               "dicard crange_seg %p: [%ld, %ld] / %ld (content_end)\n",
                                               crange_seg,
                                               CRANGE_SEG_S_OFFSET(crange_seg),
                                               CRANGE_SEG_E_OFFSET(crange_seg),
                                               content_end);
        clist_pop_back(crange_segs);
        crange_seg_free(crange_seg);
    }

    /*filter content_start*/
    while(0 < content_start && NULL_PTR != (crange_seg = clist_first_data(crange_segs)))
    {
        UINT32          s_offset;
        UINT32          e_offset;

        s_offset = (CRANGE_SEG_NO(crange_seg) - 1) * CRANGE_SEG_SIZE(crange_seg) + CRANGE_SEG_S_OFFSET(crange_seg);
        e_offset = (CRANGE_SEG_NO(crange_seg) - 1) * CRANGE_SEG_SIZE(crange_seg) + CRANGE_SEG_E_OFFSET(crange_seg);

        dbg_log(SEC_0018_CRANGE, 9)(LOGSTDOUT, "[DEBUG] crange_segs_filter: "
                                               "crange_seg %p: [%ld, %ld, %ld] => [%ld, %ld] (content_start %ld)\n",
                                               crange_seg,
                                               CRANGE_SEG_NO(crange_seg),
                                               CRANGE_SEG_S_OFFSET(crange_seg),
                                               CRANGE_SEG_E_OFFSET(crange_seg),
                                               s_offset,
                                               e_offset,
                                               content_start);

        if(s_offset >= content_start)
        {
            break;
        }

        if(s_offset <= content_start && content_start <= e_offset)
        {
            CRANGE_SEG_S_OFFSET(crange_seg) = (content_start % CRANGE_SEG_SIZE(crange_seg));
            break;
        }

        dbg_log(SEC_0018_CRANGE, 9)(LOGSTDOUT, "[DEBUG] crange_segs_filter: "
                                               "dicard crange_seg %p: [%ld, %ld, %ld] / %ld (content_start)\n",
                                               crange_seg,
                                               CRANGE_SEG_NO(crange_seg),
                                               CRANGE_SEG_S_OFFSET(crange_seg),
                                               CRANGE_SEG_E_OFFSET(crange_seg),
                                               content_start);
        clist_pop_front(crange_segs);
        crange_seg_free(crange_seg);
    }

    dbg_log(SEC_0018_CRANGE, 9)(LOGSTDOUT, "[DEBUG] crange_segs_filter: "
                                           "[%ld, %ld] / %ld, done\n",
                                           content_start, content_end, content_length);

    return (EC_TRUE);
}

CRANGE_NODE *crange_node_new()
{
    CRANGE_NODE *crange_node;
    alloc_static_mem(MM_CRANGE_NODE, &crange_node, LOC_CRANGE_0003);
    if(NULL_PTR != crange_node)
    {
        crange_node_init(crange_node);
    }
    return (crange_node);
}

EC_BOOL crange_node_init(CRANGE_NODE *crange_node)
{
    CRANGE_NODE_SUFFIX_START(crange_node)   = EC_FALSE;
    CRANGE_NODE_SUFFIX_END(crange_node)     = EC_FALSE;
    CRANGE_NODE_RANGE_START(crange_node)    = 0;
    CRANGE_NODE_RANGE_END(crange_node)      = 0;

    clist_init(CRANGE_NODE_RANGE_SEGS(crange_node), MM_CRANGE_SEG, LOC_CRANGE_0004);
    cstring_init(CRANGE_NODE_BOUNDARY(crange_node), NULL_PTR);
    return (EC_TRUE);
}

EC_BOOL crange_node_clean(CRANGE_NODE *crange_node)
{
    CRANGE_NODE_SUFFIX_START(crange_node)   = EC_FALSE;
    CRANGE_NODE_SUFFIX_END(crange_node)     = EC_FALSE;
    CRANGE_NODE_RANGE_START(crange_node)    = 0;
    CRANGE_NODE_RANGE_END(crange_node)      = 0;

    clist_clean(CRANGE_NODE_RANGE_SEGS(crange_node), (CLIST_DATA_DATA_CLEANER)crange_seg_free);
    cstring_clean(CRANGE_NODE_BOUNDARY(crange_node));
    return (EC_TRUE);
}

EC_BOOL crange_node_free(CRANGE_NODE *crange_node)
{
    if(NULL_PTR != crange_node)
    {
        crange_node_clean(crange_node);
        free_static_mem(MM_CRANGE_NODE, crange_node, LOC_CRANGE_0005);
    }
    return (EC_TRUE);
}

EC_BOOL crange_node_has_segs(const CRANGE_NODE *crange_node)
{
    if(EC_TRUE == clist_is_empty(CRANGE_NODE_RANGE_SEGS(crange_node)))
    {
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL crange_node_has_boundary(const CRANGE_NODE *crange_node)
{
    if(EC_TRUE == cstring_is_empty(CRANGE_NODE_BOUNDARY(crange_node)))
    {
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

void crange_node_print(LOG *log, const CRANGE_NODE *crange_node)
{
    CLIST_DATA      *clist_data;
    sys_print(log, "crange_node_print: crange_node %p: range (%ld:%s, %ld:%s), boudary [%s], segs:\n",
                   crange_node,
                   CRANGE_NODE_RANGE_START(crange_node), c_bool_str(CRANGE_NODE_SUFFIX_START(crange_node)),
                   CRANGE_NODE_RANGE_END(crange_node)  , c_bool_str(CRANGE_NODE_SUFFIX_END(crange_node)),
                   (EC_TRUE == crange_node_has_boundary(crange_node) ? "Y" : "N"));

    CLIST_LOOP_NEXT(CRANGE_NODE_RANGE_SEGS(crange_node), clist_data)
    {
        CRANGE_SEG      *crange_seg;

        crange_seg = (CRANGE_SEG *)CLIST_DATA_DATA(clist_data);
        sys_print(log, "range (%ld:%s, %ld:%s): seg [%ld] [%ld, %ld]\n",
                        CRANGE_NODE_RANGE_START(crange_node), c_bool_str(CRANGE_NODE_SUFFIX_START(crange_node)),
                        CRANGE_NODE_RANGE_END(crange_node)  , c_bool_str(CRANGE_NODE_SUFFIX_END(crange_node)),
                        CRANGE_SEG_NO(crange_seg),
                        CRANGE_SEG_S_OFFSET(crange_seg),
                        CRANGE_SEG_E_OFFSET(crange_seg));
    }
    return;
}

void crange_node_print_no_seg(LOG *log, const CRANGE_NODE *crange_node)
{
    sys_print(log, "crange_node_print_no_seg: crange_node %p: range (%ld:%s, %ld:%s), boudary [%s]\n",
                   crange_node,
                   CRANGE_NODE_RANGE_START(crange_node), c_bool_str(CRANGE_NODE_SUFFIX_START(crange_node)),
                   CRANGE_NODE_RANGE_END(crange_node)  , c_bool_str(CRANGE_NODE_SUFFIX_END(crange_node)),
                   (EC_TRUE == crange_node_has_boundary(crange_node) ? "Y" : "N"));

    return;
}

CRANGE_SEG *crange_node_first_seg(CRANGE_NODE *crange_node)
{
    return (CRANGE_SEG *)clist_first_data(CRANGE_NODE_RANGE_SEGS(crange_node));
}

CRANGE_SEG *crange_node_first_seg_pop(CRANGE_NODE *crange_node)
{
    return (CRANGE_SEG *)clist_pop_front(CRANGE_NODE_RANGE_SEGS(crange_node));
}

EC_BOOL crange_node_split(CRANGE_NODE *crange_node, const UINT32 range_seg_size)
{
    /*for safe reason*/
    if(EC_FALSE == clist_is_empty(CRANGE_NODE_RANGE_SEGS(crange_node)))
    {
        clist_clean(CRANGE_NODE_RANGE_SEGS(crange_node), (CLIST_DATA_DATA_CLEANER)crange_seg_free);
    }

    if(EC_FALSE == crange_segs_split(CRANGE_NODE_RANGE_START(crange_node),
                                     CRANGE_NODE_RANGE_END(crange_node),
                                     range_seg_size,
                                     CRANGE_NODE_RANGE_SEGS(crange_node)))
    {
        dbg_log(SEC_0018_CRANGE, 0)(LOGSTDOUT, "error:crange_node_split: "
                                                "split crange_node %p (%ld:%s, %ld:%s) into segs failed\n",
                                                crange_node,
                                                CRANGE_NODE_RANGE_START(crange_node), c_bool_str(CRANGE_NODE_SUFFIX_START(crange_node)),
                                                CRANGE_NODE_RANGE_END(crange_node), c_bool_str(CRANGE_NODE_SUFFIX_END(crange_node)));

        return (EC_FALSE);
    }

    if(do_log(SEC_0018_CRANGE, 9))
    {
        dbg_log(SEC_0018_CRANGE, 9)(LOGSTDOUT, "[DEBUG] crange_node_split: "
                                                "split crange_node %p (%ld:%s, %ld:%s) into segs done:\n",
                                                crange_node,
                                                CRANGE_NODE_RANGE_START(crange_node), c_bool_str(CRANGE_NODE_SUFFIX_START(crange_node)),
                                                CRANGE_NODE_RANGE_END(crange_node), c_bool_str(CRANGE_NODE_SUFFIX_END(crange_node)));

        crange_node_print(LOGSTDOUT, crange_node);
    }
    return (EC_TRUE);
}

EC_BOOL crange_node_adjust(CRANGE_NODE *crange_node, const UINT32 content_length)
{
    dbg_log(SEC_0018_CRANGE, 9)(LOGSTDOUT, "[DEBUG] crange_node_adjust: "
                                           "[%ld, %ld] / %ld =>  \n",
                                           CRANGE_NODE_RANGE_START(crange_node),
                                           CRANGE_NODE_RANGE_END(crange_node),
                                           content_length);

    if(EC_TRUE == CRANGE_NODE_SUFFIX_END(crange_node))
    {
        CRANGE_NODE_RANGE_END(crange_node) = content_length - 1;
    }
    else
    {
        if(EC_TRUE == CRANGE_NODE_SUFFIX_START(crange_node))
        {
            if(CRANGE_NODE_RANGE_END(crange_node) >= content_length )
            {
                CRANGE_NODE_RANGE_START(crange_node) = 0;
            }
            else
            {
                CRANGE_NODE_RANGE_START(crange_node) =
                                (content_length - CRANGE_NODE_RANGE_END(crange_node));
            }

            CRANGE_NODE_RANGE_END(crange_node)   = content_length - 1;
        }
    }

    if(CRANGE_NODE_RANGE_START(crange_node) >= content_length)
    {
        dbg_log(SEC_0018_CRANGE, 0)(LOGSTDOUT, "error:crange_node_adjust: "
                                               "[%ld, %ld] / %ld <=  range_start overflow\n",
                                               CRANGE_NODE_RANGE_START(crange_node),
                                               CRANGE_NODE_RANGE_END(crange_node),
                                               content_length);
        return (EC_FALSE);
    }

    if(CRANGE_NODE_RANGE_END(crange_node) >= content_length)
    {
        CRANGE_NODE_RANGE_END(crange_node) = content_length - 1;
    }

    if(CRANGE_NODE_RANGE_START(crange_node) > CRANGE_NODE_RANGE_END(crange_node))
    {
        dbg_log(SEC_0018_CRANGE, 0)(LOGSTDOUT, "error:crange_node_adjust: "
                                               "[%ld, %ld] / %ld <=  range_start > range_end\n",
                                               CRANGE_NODE_RANGE_START(crange_node),
                                               CRANGE_NODE_RANGE_END(crange_node),
                                               content_length);
        return (EC_FALSE);
    }

    CRANGE_NODE_SUFFIX_START(crange_node) = EC_FALSE;
    CRANGE_NODE_SUFFIX_END(crange_node)   = EC_FALSE;

    dbg_log(SEC_0018_CRANGE, 9)(LOGSTDOUT, "[DEBUG] crange_node_adjust: "
                                           "[%ld, %ld] / %ld <=  \n",
                                           CRANGE_NODE_RANGE_START(crange_node),
                                           CRANGE_NODE_RANGE_END(crange_node),
                                           content_length);
    return (EC_TRUE);
}

EC_BOOL crange_node_filter(CRANGE_NODE *crange_node, const UINT32 content_start, const UINT32 content_end, const UINT32 content_length)
{
    return crange_segs_filter(CRANGE_NODE_RANGE_SEGS(crange_node), content_start, content_end, content_length);
}

EC_BOOL crange_node_range(CRANGE_NODE *crange_node, UINT32 *range_start, UINT32 *range_end)
{
    CRANGE_SEG      *crange_seg_first;
    CRANGE_SEG      *crange_seg_last;

    if(EC_TRUE == clist_is_empty(CRANGE_NODE_RANGE_SEGS(crange_node)))
    {
        return (EC_FALSE);
    }

    crange_seg_first = clist_first_data(CRANGE_NODE_RANGE_SEGS(crange_node));
    crange_seg_last  = clist_last_data(CRANGE_NODE_RANGE_SEGS(crange_node));

    ASSERT(0 < CRANGE_SEG_NO(crange_seg_first));
    ASSERT(0 < CRANGE_SEG_NO(crange_seg_last));

    (*range_start) = (CRANGE_SEG_NO(crange_seg_first) - 1) * CRANGE_SEG_SIZE(crange_seg_first) + CRANGE_SEG_S_OFFSET(crange_seg_first);
    (*range_end  ) = (CRANGE_SEG_NO(crange_seg_last) - 1) * CRANGE_SEG_SIZE(crange_seg_last) + CRANGE_SEG_E_OFFSET(crange_seg_last);
    return (EC_TRUE);
}

CRANGE_MGR *crange_mgr_new()
{
    CRANGE_MGR *crange_mgr;
    alloc_static_mem(MM_CRANGE_MGR, &crange_mgr, LOC_CRANGE_0006);
    if(NULL_PTR != crange_mgr)
    {
        crange_mgr_init(crange_mgr);
    }
    return (crange_mgr);
}

EC_BOOL crange_mgr_init(CRANGE_MGR *crange_mgr)
{
    clist_init(CRANGE_MGR_RANGE_NODES(crange_mgr), MM_CRANGE_NODE, LOC_CRANGE_0007);

    cstring_init(CRANGE_MGR_BOUNDARY(crange_mgr), NULL_PTR);

    CRANGE_MGR_BODY_SIZE(crange_mgr) = 0;

    return (EC_TRUE);
}

EC_BOOL crange_mgr_clean(CRANGE_MGR *crange_mgr)
{
    clist_clean(CRANGE_MGR_RANGE_NODES(crange_mgr), (CLIST_DATA_DATA_CLEANER)crange_node_free);

    cstring_clean(CRANGE_MGR_BOUNDARY(crange_mgr));

    CRANGE_MGR_BODY_SIZE(crange_mgr) = 0;

    return (EC_TRUE);
}

EC_BOOL crange_mgr_free(CRANGE_MGR *crange_mgr)
{
    if(NULL_PTR != crange_mgr)
    {
        crange_mgr_clean(crange_mgr);
        free_static_mem(MM_CRANGE_MGR, crange_mgr, LOC_CRANGE_0008);
    }
    return (EC_TRUE);
}

void crange_mgr_print(LOG *log, const CRANGE_MGR *crange_mgr)
{
    sys_print(log, "crange_mgr_print: crange_mgr %p: body_size %d, boundary [%s], nodes:\n",
                   crange_mgr,
                   CRANGE_MGR_BODY_SIZE(crange_mgr),
                   (EC_TRUE == crange_mgr_has_boundary(crange_mgr) ? "Y" : "N"));

    clist_print(log, CRANGE_MGR_RANGE_NODES(crange_mgr), (CLIST_DATA_DATA_PRINT)crange_node_print);
    return;
}

void crange_mgr_print_no_seg(LOG *log, const CRANGE_MGR *crange_mgr)
{
    sys_print(log, "crange_mgr_print_no_seg: crange_mgr %p: body_size %d, boundary [%s], nodes:\n",
                   crange_mgr,
                   CRANGE_MGR_BODY_SIZE(crange_mgr),
                   (EC_TRUE == crange_mgr_has_boundary(crange_mgr) ? "Y" : "N"));

    clist_print(log, CRANGE_MGR_RANGE_NODES(crange_mgr), (CLIST_DATA_DATA_PRINT)crange_node_print_no_seg);
    return;
}

UINT32 crange_mgr_node_num(const CRANGE_MGR *crange_mgr)
{
    return clist_size(CRANGE_MGR_RANGE_NODES(crange_mgr));
}

UINT32 crange_mgr_total_length(const CRANGE_MGR *crange_mgr)
{
    CLIST_DATA      *clist_data;
    UINT32           total_length;

    total_length = 0;

    /*count total length*/
    total_length += CSTRING_LEN(CRANGE_MGR_BOUNDARY(crange_mgr));
    CLIST_LOOP_NEXT(CRANGE_MGR_RANGE_NODES(crange_mgr), clist_data)
    {
        CRANGE_NODE         *crange_node;

        crange_node = (CRANGE_NODE *)CLIST_DATA_DATA(clist_data);

        ASSERT(EC_FALSE == CRANGE_NODE_SUFFIX_START(crange_node));
        ASSERT(EC_FALSE == CRANGE_NODE_SUFFIX_END(crange_node));

        total_length += CSTRING_LEN(CRANGE_NODE_BOUNDARY(crange_node));
        total_length += CRANGE_NODE_RANGE_END(crange_node) + 1 - CRANGE_NODE_RANGE_START(crange_node);
    }

    return total_length;
}

EC_BOOL crange_mgr_is_empty(const CRANGE_MGR *crange_mgr)
{
    return clist_is_empty(CRANGE_MGR_RANGE_NODES(crange_mgr));
}

EC_BOOL crange_mgr_has_boundary(const CRANGE_MGR *crange_mgr)
{
    if(EC_TRUE == cstring_is_empty(CRANGE_MGR_BOUNDARY(crange_mgr)))
    {
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

CRANGE_NODE *crange_mgr_first_node(CRANGE_MGR *crange_mgr)
{
    return (CRANGE_NODE *)clist_first_data(CRANGE_MGR_RANGE_NODES(crange_mgr));
}

CRANGE_NODE *crange_mgr_first_node_pop(CRANGE_MGR *crange_mgr)
{
    return (CRANGE_NODE *)clist_pop_front(CRANGE_MGR_RANGE_NODES(crange_mgr));
}

EC_BOOL crange_mgr_add_node(CRANGE_MGR *crange_mgr, CRANGE_NODE *crange_node)
{
    if(NULL_PTR == clist_push_back(CRANGE_MGR_RANGE_NODES(crange_mgr), (void *)crange_node))
    {
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL crange_mgr_add_range(CRANGE_MGR *crange_mgr, const UINT32 range_start, const UINT32 range_end, const UINT32 seg_size)
{
    CRANGE_NODE  *crange_node;

    crange_node = crange_node_new();
    if(NULL_PTR == crange_node)
    {
        dbg_log(SEC_0018_CRANGE, 0)(LOGSTDOUT, "error:crange_mgr_add_range: "
                                               "new range_node failed\n");

        return (EC_FALSE);
    }

    CRANGE_NODE_SUFFIX_START(crange_node)  = EC_FALSE;
    CRANGE_NODE_SUFFIX_END(crange_node)    = EC_FALSE;
    CRANGE_NODE_RANGE_START(crange_node)   = range_start;
    CRANGE_NODE_RANGE_END(crange_node)     = range_end;

    if(EC_FALSE == crange_node_split(crange_node, seg_size))
    {
        dbg_log(SEC_0018_CRANGE, 0)(LOGSTDOUT, "error:crange_mgr_add_range: "
                                               "split [%ld, %ld] / %ld into segs failed\n",
                                               range_start, range_end, seg_size);

        crange_node_free(crange_node);
        return (EC_FALSE);
    }

    if(EC_FALSE == crange_mgr_add_node(crange_mgr, (void *)crange_node))
    {
        dbg_log(SEC_0018_CRANGE, 0)(LOGSTDOUT, "error:crange_mgr_add_range: "
                                               "add crange_node of [%ld, %ld] / %ld failed\n",
                                               range_start, range_end, seg_size);

        crange_node_free(crange_node);
        return (EC_FALSE);
    }

    dbg_log(SEC_0018_CRANGE, 9)(LOGSTDOUT, "[DEBUG] crange_mgr_add_range: "
                                           "split [%ld, %ld] / %ld into segs done\n",
                                           range_start, range_end, seg_size);
    return (EC_TRUE);
}

EC_BOOL crange_mgr_get_naked_boundary(CRANGE_MGR *crange_mgr, char **boundary, uint32_t *boundary_len)
{
    if(EC_TRUE == cstring_is_empty(CRANGE_MGR_BOUNDARY(crange_mgr)))
    {
        return (EC_FALSE);
    }

    /*ignore prefix '\n--' and postfix '--\n'*/
    (*boundary)     = (char   *)(cstring_get_str(CRANGE_MGR_BOUNDARY(crange_mgr)) + 3);
    (*boundary_len) = (uint32_t)(cstring_get_len(CRANGE_MGR_BOUNDARY(crange_mgr)) - 6);

    return (EC_TRUE);
}

EC_BOOL crange_mgr_split(CRANGE_MGR *crange_mgr, const UINT32 range_seg_size)
{
    CLIST_DATA      *clist_data;

    CLIST_LOOP_NEXT(CRANGE_MGR_RANGE_NODES(crange_mgr), clist_data)
    {
        CRANGE_NODE         *crange_node;

        crange_node = (CRANGE_NODE *)CLIST_DATA_DATA(clist_data);

        if(EC_FALSE == crange_node_split(crange_node, range_seg_size))
        {
            dbg_log(SEC_0018_CRANGE, 0)(LOGSTDOUT, "error:crange_mgr_split: "
                                                    "split crange_node %p (%ld:%s, %ld:%s) into segs failed\n",
                                                    crange_node,
                                                    CRANGE_NODE_RANGE_START(crange_node), c_bool_str(CRANGE_NODE_SUFFIX_START(crange_node)),
                                                    CRANGE_NODE_RANGE_END(crange_node), c_bool_str(CRANGE_NODE_SUFFIX_END(crange_node)));

            return (EC_FALSE);
        }

        dbg_log(SEC_0018_CRANGE, 9)(LOGSTDOUT, "[DEBUG] crange_mgr_split: "
                                                "split crange_node %p (%ld:%s, %ld:%s) into segs done\n",
                                                crange_node,
                                                CRANGE_NODE_RANGE_START(crange_node), c_bool_str(CRANGE_NODE_SUFFIX_START(crange_node)),
                                                CRANGE_NODE_RANGE_END(crange_node), c_bool_str(CRANGE_NODE_SUFFIX_END(crange_node)));
    }

    dbg_log(SEC_0018_CRANGE, 9)(LOGSTDOUT, "[DEBUG] crange_mgr_split: "
                                            "split crange_mgr %p into segs done\n",
                                            crange_mgr);
    return (EC_TRUE);
}

EC_BOOL crange_mgr_adjust(CRANGE_MGR *crange_mgr, const UINT32 content_length)
{
    CLIST_DATA      *clist_data;
#if 0
    CLIST            clist_tmp;
#endif

    /*adjust start & end*/
    CLIST_LOOP_NEXT(CRANGE_MGR_RANGE_NODES(crange_mgr), clist_data)
    {
        CRANGE_NODE         *crange_node;

        crange_node = (CRANGE_NODE *)CLIST_DATA_DATA(clist_data);

        if(EC_FALSE == crange_node_adjust(crange_node, content_length))
        {
            dbg_log(SEC_0018_CRANGE, 0)(LOGSTDOUT, "warn:crange_mgr_adjust: "
                                                    "adjust crange_node %p (%ld:%s, %ld:%s) failed => discard it\n",
                                                    crange_node,
                                                    CRANGE_NODE_RANGE_START(crange_node), c_bool_str(CRANGE_NODE_SUFFIX_START(crange_node)),
                                                    CRANGE_NODE_RANGE_END(crange_node), c_bool_str(CRANGE_NODE_SUFFIX_END(crange_node)));

            clist_erase(CRANGE_MGR_RANGE_NODES(crange_mgr), clist_data);
            crange_node_free(crange_node);

            dbg_log(SEC_0018_CRANGE, 9)(LOGSTDOUT, "[DEBUG] crange_mgr_adjust: "
                                                   "after discard, try recursively\n");

            return crange_mgr_adjust(crange_mgr, content_length);
        }

        /*if some range cover whole content, discard others*/
        if(0 == CRANGE_NODE_RANGE_START(crange_node)
        && content_length - 1 == CRANGE_NODE_RANGE_END(crange_node))
        {
            clist_erase(CRANGE_MGR_RANGE_NODES(crange_mgr), clist_data);
            clist_clean(CRANGE_MGR_RANGE_NODES(crange_mgr), (CLIST_DATA_DATA_CLEANER)crange_node_free);
            clist_push_back(CRANGE_MGR_RANGE_NODES(crange_mgr), (void *)crange_node);

            dbg_log(SEC_0018_CRANGE, 9)(LOGSTDOUT, "[DEBUG] crange_mgr_adjust: "
                                                   "found crange_node %p (%ld, %ld) covers whole content => discard others\n",
                                                   crange_node,
                                                   CRANGE_NODE_RANGE_START(crange_node),
                                                   CRANGE_NODE_RANGE_END(crange_node));
            return (EC_TRUE);
        }

        dbg_log(SEC_0018_CRANGE, 9)(LOGSTDOUT, "[DEBUG] crange_mgr_adjust: "
                                                "adjust crange_node %p (%ld:%s, %ld:%s) done\n",
                                                crange_node,
                                                CRANGE_NODE_RANGE_START(crange_node), c_bool_str(CRANGE_NODE_SUFFIX_START(crange_node)),
                                                CRANGE_NODE_RANGE_END(crange_node), c_bool_str(CRANGE_NODE_SUFFIX_END(crange_node)));
    }
#if 0
    /*merge continuous range*/
    clist_init(&clist_tmp, MM_CRANGE_NODE, LOC_CRANGE_0009);
    clist_handover(CRANGE_MGR_RANGE_NODES(crange_mgr), &clist_tmp);

    clist_push_back(CRANGE_MGR_RANGE_NODES(crange_mgr), clist_pop_front(&clist_tmp));

    while(EC_FALSE == clist_is_empty(&clist_tmp))
    {
        CRANGE_NODE         *crange_node_cur;
        CRANGE_NODE         *crange_node_top;

        crange_node_cur = (CRANGE_NODE *)clist_pop_front(&clist_tmp);
        crange_node_top = (CRANGE_NODE *)clist_last_data(CRANGE_MGR_RANGE_NODES(crange_mgr));

        /*found continuous range*/
        if(CRANGE_NODE_RANGE_END(crange_node_top) + 1 == CRANGE_NODE_RANGE_START(crange_node_cur))
        {
            dbg_log(SEC_0018_CRANGE, 9)(LOGSTDOUT, "[DEBUG] crange_mgr_adjust: "
                                                   "merge continous range: [%ld, %ld], [%ld, %ld] => [%ld, %ld]\n",
                                                   CRANGE_NODE_RANGE_START(crange_node_top),
                                                   CRANGE_NODE_RANGE_END(crange_node_top),

                                                   CRANGE_NODE_RANGE_START(crange_node_cur),
                                                   CRANGE_NODE_RANGE_END(crange_node_cur),

                                                   CRANGE_NODE_RANGE_START(crange_node_top),
                                                   CRANGE_NODE_RANGE_END(crange_node_cur));

            CRANGE_NODE_RANGE_END(crange_node_top) = CRANGE_NODE_RANGE_END(crange_node_cur);
            crange_node_free(crange_node_cur);
            continue;
        }
        /*not continous range*/
        clist_push_back(CRANGE_MGR_RANGE_NODES(crange_mgr), (void *)crange_node_cur);
    }
#endif

    dbg_log(SEC_0018_CRANGE, 9)(LOGSTDOUT, "[DEBUG] crange_mgr_adjust: "
                                           "adjust crange_mgr %p done\n",
                                           crange_mgr);
    return (EC_TRUE);
}

EC_BOOL crange_mgr_filter(CRANGE_MGR *crange_mgr, const UINT32 content_start, const UINT32 content_end, const UINT32 content_length)
{
    CLIST_DATA      *clist_data;

    CLIST_LOOP_NEXT(CRANGE_MGR_RANGE_NODES(crange_mgr), clist_data)
    {
        CRANGE_NODE         *crange_node;

        crange_node = (CRANGE_NODE *)CLIST_DATA_DATA(clist_data);

        if(EC_FALSE == crange_node_filter(crange_node, content_start, content_end, content_length))
        {
            dbg_log(SEC_0018_CRANGE, 0)(LOGSTDOUT, "error:crange_mgr_filter: "
                                                    "filter crange_node %p (%ld:%s, %ld:%s) failed\n",
                                                    crange_node,
                                                    CRANGE_NODE_RANGE_START(crange_node), c_bool_str(CRANGE_NODE_SUFFIX_START(crange_node)),
                                                    CRANGE_NODE_RANGE_END(crange_node), c_bool_str(CRANGE_NODE_SUFFIX_END(crange_node)));

            return (EC_FALSE);
        }

        dbg_log(SEC_0018_CRANGE, 9)(LOGSTDOUT, "[DEBUG] crange_mgr_filter: "
                                                "filter crange_node %p (%ld:%s, %ld:%s) done\n",
                                                crange_node,
                                                CRANGE_NODE_RANGE_START(crange_node), c_bool_str(CRANGE_NODE_SUFFIX_START(crange_node)),
                                                CRANGE_NODE_RANGE_END(crange_node), c_bool_str(CRANGE_NODE_SUFFIX_END(crange_node)));
    }

    dbg_log(SEC_0018_CRANGE, 9)(LOGSTDOUT, "[DEBUG] crange_mgr_filter: "
                                           "filter crange_mgr %p done\n",
                                           crange_mgr);
    return (EC_TRUE);
}

EC_BOOL crange_mgr_is_range(const CRANGE_MGR *crange_mgr, const UINT32 range_start, const UINT32 range_end)
{
    CLIST_DATA      *clist_data;

    UINT32           range_cur;

    range_cur = range_start;

    CLIST_LOOP_NEXT(CRANGE_MGR_RANGE_NODES(crange_mgr), clist_data)
    {
        CRANGE_NODE         *crange_node;

        UINT32               crange_node_start_t;
        UINT32               crange_node_end_t;

        crange_node = (CRANGE_NODE *)CLIST_DATA_DATA(clist_data);

        if(EC_FALSE == CRANGE_NODE_SUFFIX_START(crange_node)
        && EC_FALSE == CRANGE_NODE_SUFFIX_END(crange_node))
        {
            crange_node_start_t = CRANGE_NODE_RANGE_START(crange_node);
            crange_node_end_t   = CRANGE_NODE_RANGE_END(crange_node);
        }
        else
        {
            if(EC_FALSE == crange_node_range(crange_node, &crange_node_start_t, &crange_node_end_t))
            {
                dbg_log(SEC_0018_CRANGE, 0)(LOGSTDOUT, "error:crange_mgr_is_range: "
                                                        "get range from crange_node %p (%ld:%s, %ld:%s) failed\n",
                                                        crange_node,
                                                        CRANGE_NODE_RANGE_START(crange_node), c_bool_str(CRANGE_NODE_SUFFIX_START(crange_node)),
                                                        CRANGE_NODE_RANGE_END(crange_node), c_bool_str(CRANGE_NODE_SUFFIX_END(crange_node)));

                return (EC_FALSE);
            }
        }

        dbg_log(SEC_0018_CRANGE, 9)(LOGSTDOUT, "[DEBUG] crange_mgr_is_range: "
                                                "crange_node %p (%ld:%s, %ld:%s) => [%ld, %ld]\n",
                                                crange_node,
                                                CRANGE_NODE_RANGE_START(crange_node), c_bool_str(CRANGE_NODE_SUFFIX_START(crange_node)),
                                                CRANGE_NODE_RANGE_END(crange_node), c_bool_str(CRANGE_NODE_SUFFIX_END(crange_node)),
                                                crange_node_start_t, crange_node_end_t);

        if(range_cur != crange_node_start_t)
        {
            dbg_log(SEC_0018_CRANGE, 9)(LOGSTDOUT, "[DEBUG] crange_mgr_is_range: "
                                                    "crange_node %p (%ld:%s, %ld:%s) => [%ld, %ld] => mismtached cur %ld\n",
                                                    crange_node,
                                                    CRANGE_NODE_RANGE_START(crange_node), c_bool_str(CRANGE_NODE_SUFFIX_START(crange_node)),
                                                    CRANGE_NODE_RANGE_END(crange_node), c_bool_str(CRANGE_NODE_SUFFIX_END(crange_node)),
                                                    crange_node_start_t, crange_node_end_t,
                                                    range_cur);
            return (EC_FALSE);
        }

        range_cur = crange_node_end_t;
    }

    if(range_cur != range_end)
    {
        dbg_log(SEC_0018_CRANGE, 9)(LOGSTDOUT, "[DEBUG] crange_mgr_is_range: "
                                                "mismtached cur %ld and range_end %ld\n",
                                                range_cur, range_end);
        return (EC_FALSE);
    }

    dbg_log(SEC_0018_CRANGE, 9)(LOGSTDOUT, "[DEBUG] crange_mgr_is_range: "
                                           "crange_mgr %p matched range [%ld, %ld]\n",
                                           crange_mgr, range_start, range_end);
    return (EC_TRUE);
}

/*range:0-*/
EC_BOOL crange_mgr_is_start_zero_endless(const CRANGE_MGR *crange_mgr)
{
    CRANGE_NODE         *crange_node;

    if(1 != clist_size(CRANGE_MGR_RANGE_NODES(crange_mgr)))
    {
        return (EC_FALSE);
    }

    crange_node = clist_first_data(CRANGE_MGR_RANGE_NODES(crange_mgr));

    if(EC_FALSE == CRANGE_NODE_SUFFIX_START(crange_node)
    && EC_TRUE  == CRANGE_NODE_SUFFIX_END(crange_node)
    && 0 == CRANGE_NODE_RANGE_START(crange_node))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}
EC_BOOL crange_parse_content_range_start(const char *content_range, UINT32 *pos, EC_BOOL *suffix, UINT32 *range_start)
{
    const uint8_t                 *p;
    UINT32                         start;
    UINT32                         cutoff;

    p      = (const uint8_t *)(content_range + (*pos));

    cutoff = (UINT32)(CRANGE_MAX_OFFSET / 10);

    start  = 0;

    while (*p == ' ') { p++; }

    if(*p == 'b')
    {
        if(*p++ != 'b'
        || *p++ != 'y'
        || *p++ != 't'
        || *p++ != 'e'
        || *p++ != 's')
        {
            return (EC_FALSE);
        }

        while (*p == ' ') { p++; }
    }

    if(*p == '-')
    {
        (*suffix) = EC_TRUE;
        p++;

        (*range_start) = start;
        (*pos)         = (p - (const uint8_t *)content_range);

        return (EC_TRUE);
    }

    (*suffix) = EC_FALSE;

    /*parse prefix*/
    if (*p < '0' || *p > '9')
    {
        dbg_log(SEC_0018_CRANGE, 0)(LOGSTDOUT, "error:crange_parse_content_range_start: "
                                               "invalid char Content-Range '%s'\n",
                                               content_range);
        return (EC_FALSE);
    }

    while (*p >= '0' && *p <= '9')
    {
        if (start >= cutoff)
        {
            dbg_log(SEC_0018_CRANGE, 0)(LOGSTDOUT, "error:crange_parse_content_range_start: "
                                                   "overflow Content-Range '%s'\n",
                                                   content_range);
            return (EC_FALSE);
        }

        start = start * 10 + *p++ - '0';
    }

    while (*p == ' ') { p++; }

    if (*p++ != '-')
    {
        dbg_log(SEC_0018_CRANGE, 0)(LOGSTDOUT, "error:crange_parse_content_range_start: "
                                               "no postfix in Content-Range '%s'\n",
                                               content_range);
        return (EC_FALSE);
    }

    (*range_start) = start;
    (*pos)         = (p - (const uint8_t *)content_range);

    dbg_log(SEC_0018_CRANGE, 9)(LOGSTDOUT, "[DEBUG] crange_parse_content_range_start: "
                                           "range_start '%ld' in Content-Range '%s'\n",
                                           (*range_start), content_range);
    return (EC_TRUE);
}

EC_BOOL crange_parse_content_range_end(const char *content_range, UINT32 *pos, UINT32 *range_end)
{
    const uint8_t                 *p;
    UINT32                         end;
    UINT32                         cutoff;

    p      = (const uint8_t *)(content_range + (*pos));

    cutoff = (UINT32)(CRANGE_MAX_OFFSET / 10);

    end    = 0;

    while (*p == ' ') { p++; }

    /*parse postfix*/
    if (*p < '0' || *p > '9')
    {
        dbg_log(SEC_0018_CRANGE, 0)(LOGSTDOUT, "error:crange_parse_content_range_end: "
                                               "invalid Content-Range '%s'\n",
                                               content_range);
        return (EC_FALSE);
    }

    while (*p >= '0' && *p <= '9')
    {
        if (end >= cutoff)
        {
            dbg_log(SEC_0018_CRANGE, 0)(LOGSTDOUT, "error:crange_parse_content_range_end: "
                                                   "invalid char in Content-Range '%s'\n",
                                                   content_range);
            return (EC_FALSE);
        }

        end = end * 10 + *p++ - '0';
    }

    while (*p == ' ') { p++; }

    if (*p++ != '/')
    {
        dbg_log(SEC_0018_CRANGE, 0)(LOGSTDOUT, "error:crange_parse_content_range_end: "
                                               "no length in Content-Range '%s'\n",
                                               content_range);
        return (EC_FALSE);
    }

    (*range_end) = end;
    (*pos)       = (p - (const uint8_t *)content_range);

    dbg_log(SEC_0018_CRANGE, 9)(LOGSTDOUT, "[DEBUG] crange_parse_content_range_end: "
                                           "range_end '%ld' in Content-Range '%s'\n",
                                           (*range_end), content_range);
    return (EC_TRUE);
}

EC_BOOL crange_parse_content_content_length(const char *content_range, UINT32 *pos, UINT32 *content_length)
{
    const uint8_t                 *p;
    UINT32                         length;
    UINT32                         cutoff;

    p      = (const uint8_t *)(content_range + (*pos));

    cutoff = (UINT32)(CRANGE_MAX_OFFSET / 10);

    length = 0;

    while (*p == ' ') { p++; }

    /*parse postfix*/
    if (*p < '0' || *p > '9')
    {
        dbg_log(SEC_0018_CRANGE, 0)(LOGSTDOUT, "error:crange_parse_content_content_length: "
                                               "invalid Content-Range '%s'\n",
                                               content_range);
        return (EC_FALSE);
    }

    while (*p >= '0' && *p <= '9')
    {
        if (length >= cutoff)
        {
            dbg_log(SEC_0018_CRANGE, 0)(LOGSTDOUT, "error:crange_parse_content_content_length: "
                                                   "invalid char in Content-Range '%s'\n",
                                                   content_range);
            return (EC_FALSE);
        }

        length = length * 10 + *p++ - '0';
    }

    while (*p == ' ') { p++; }

    if (*p++ != '\0')
    {
        dbg_log(SEC_0018_CRANGE, 0)(LOGSTDOUT, "error:crange_parse_content_content_length: "
                                               "unexpected chars in Content-Range '%s'\n",
                                               content_range);
        return (EC_FALSE);
    }

    (*content_length) = length;
    (*pos)            = (p - (const uint8_t *)content_range);

    dbg_log(SEC_0018_CRANGE, 9)(LOGSTDOUT, "[DEBUG] crange_parse_content_content_length: "
                                           "content_length '%ld' in Content-Range '%s'\n",
                                           (*content_length), content_range);
    return (EC_TRUE);
}

/*Content-Range format: [bytes] <START>-<END>/<LENGTH>*/
EC_BOOL crange_parse_content_range(const char *content_range, UINT32 *range_start, UINT32 *range_end, UINT32 *content_length)
{
    EC_BOOL     suffix;
    UINT32      pos;

    pos = 0;

    if(EC_FALSE == crange_parse_content_range_start(content_range, &pos, &suffix, range_start))
    {
        dbg_log(SEC_0018_CRANGE, 0)(LOGSTDOUT, "error:crange_parse_content_range: "
                                               "parse range_start from Content-Range '%s' failed\n",
                                               content_range);
        return (EC_FALSE);
    }

    if(EC_FALSE == crange_parse_content_range_end(content_range, &pos, range_end))
    {
        dbg_log(SEC_0018_CRANGE, 0)(LOGSTDOUT, "error:crange_parse_content_range: "
                                               "parse range_end from Content-Range '%s' failed\n",
                                               content_range);
        return (EC_FALSE);
    }

    if(EC_FALSE == crange_parse_content_content_length(content_range, &pos, content_length))
    {
        dbg_log(SEC_0018_CRANGE, 0)(LOGSTDOUT, "error:crange_parse_content_range: "
                                               "parse content_length from Content-Range '%s' failed\n",
                                               content_range);
        return (EC_FALSE);
    }

    if (EC_TRUE == suffix)
    {
        (*range_start) = (*content_length) - (*range_end);
        (*range_end)   = (*content_length) - 1;
    }

    if ((*range_end) >= (*content_length))
    {
        (*range_end) = (*content_length);
    }

    dbg_log(SEC_0018_CRANGE, 9)(LOGSTDOUT, "[DEBUG] crange_parse_content_range: "
                                           "['%ld', '%ld']/'%ld' in Content-Range '%s'\n",
                                           (*range_start), (*range_end), (*content_length),
                                           content_range);
    return (EC_TRUE);
}

EC_BOOL crange_parse_range_prepare(const char *range, UINT32 *pos)
{
    const uint8_t                 *p;

    p      = (const uint8_t *)(range + (*pos));

    while (*p == ' ') { p++; }

    if(*p++ != 'b'
    || *p++ != 'y'
    || *p++ != 't'
    || *p++ != 'e'
    || *p++ != 's')
    {
        return (EC_FALSE);
    }

    while (*p == ' ') { p++; }

    if(*p++ != '=')
    {
        return (EC_FALSE);
    }

    while (*p == ' ') { p++; }

    (*pos)         = (p - (const uint8_t *)range);
    return (EC_TRUE);
}

EC_BOOL crange_parse_range_start(const char *range, UINT32 *pos, EC_BOOL *suffix, UINT32 *range_start)
{
    const uint8_t                 *p;
    UINT32                         start;
    UINT32                         cutoff;

    p      = (const uint8_t *)(range + (*pos));

    cutoff = (UINT32)(CRANGE_MAX_OFFSET / 10);

    start  = 0;

    while (*p == ' ') { p++; }

    if(*p == '-')
    {
        (*suffix) = EC_TRUE;
        p++;

        (*range_start) = start;
        (*pos)         = (p - (const uint8_t *)range);

        return (EC_TRUE);
    }

    (*suffix) = EC_FALSE;

    /*parse prefix*/
    if (*p < '0' || *p > '9')
    {
        dbg_log(SEC_0018_CRANGE, 0)(LOGSTDOUT, "error:crange_parse_range_start: invalid char Range '%s'\n",
                        range);
        return (EC_FALSE);
    }

    while (*p >= '0' && *p <= '9')
    {
        if (start >= cutoff )
        {
            dbg_log(SEC_0018_CRANGE, 0)(LOGSTDOUT, "error:crange_parse_range_start: overflow Range '%s'\n",
                        range);
            return (EC_FALSE);
        }

        start = start * 10 + *p++ - '0';
    }

    while (*p == ' ') { p++; }

    if (*p++ != '-')
    {
        dbg_log(SEC_0018_CRANGE, 0)(LOGSTDOUT, "error:crange_parse_range_start: no postfix in Range '%s'\n",
                        range);
        return (EC_FALSE);
    }

    (*range_start) = start;
    (*pos)         = (p - (const uint8_t *)range);

    dbg_log(SEC_0018_CRANGE, 9)(LOGSTDOUT, "[DEBUG] crange_parse_range_start: range_start '%ld' in Range '%s'\n",
                    (*range_start), range);
    return (EC_TRUE);
}

EC_BOOL crange_parse_range_end(const char *range, UINT32 *pos, EC_BOOL *suffix, UINT32 *range_end)
{
    const uint8_t                 *p;
    UINT32                         end;
    UINT32                         cutoff;

    p      = (const uint8_t *)(range + (*pos));

    cutoff = (UINT32)(CRANGE_MAX_OFFSET / 10);

    end    = 0;

    while (*p == ' ') { p++; }

    if(*p == ',')
    {
        p ++;
        (*suffix) = EC_TRUE;
        (*pos)       = (p - (const uint8_t *)range);
        return (EC_TRUE);
    }

    if(*p == '\0')
    {
        (*suffix) = EC_TRUE;
        (*pos)       = (p - (const uint8_t *)range);
        return (EC_TRUE);
    }

    /*parse postfix*/
    if (*p < '0' || *p > '9')
    {
        dbg_log(SEC_0018_CRANGE, 0)(LOGSTDOUT, "error:crange_parse_range_end: invalid Range '%s'\n",
                            range);
        return (EC_FALSE);
    }

    (*suffix) = EC_FALSE;

    while (*p >= '0' && *p <= '9')
    {
        if (end >= cutoff)
        {
            dbg_log(SEC_0018_CRANGE, 0)(LOGSTDOUT, "error:crange_parse_range_end: invalid char in Range '%s'\n",
                            range);
            return (EC_FALSE);
        }

        end = end * 10 + *p++ - '0';
    }

    while (*p == ' ') { p++; }

    if (*p != '\0' && *p != ',')
    {
        dbg_log(SEC_0018_CRANGE, 0)(LOGSTDOUT, "error:crange_parse_range_end: invalid terminate in Range '%s'\n",
                        range);
        return (EC_FALSE);
    }

    p ++;

    (*range_end) = end;
    (*pos)       = (p - (const uint8_t *)range);

    dbg_log(SEC_0018_CRANGE, 9)(LOGSTDOUT, "[DEBUG] crange_parse_range_end: range_end '%ld' in Range '%s'\n",
                    (*range_end), range);
    return (EC_TRUE);
}

EC_BOOL crange_parse_range_do(const char *range, UINT32 *pos, UINT32 *range_start, UINT32 *range_end, EC_BOOL *suffix_start, EC_BOOL *suffix_end)
{
    if(EC_FALSE == crange_parse_range_start(range, pos, suffix_start, range_start))
    {
        dbg_log(SEC_0018_CRANGE, 0)(LOGSTDOUT, "error:crange_parse_range_do: parse range_start from Range '%s' failed\n",
                        range);
        return (EC_FALSE);
    }

    if(EC_FALSE == crange_parse_range_end(range, pos, suffix_end, range_end))
    {
        dbg_log(SEC_0018_CRANGE, 0)(LOGSTDOUT, "error:crange_parse_range_do: parse range_end from Range '%s' failed\n",
                        range);
        return (EC_FALSE);
    }

    if(EC_FALSE == (*suffix_start)
    && EC_FALSE == (*suffix_end)
    && (*range_start) + CRANGE_MAX_LEN <= (*range_end))
    {
        dbg_log(SEC_0018_CRANGE, 0)(LOGSTDOUT, "error:crange_parse_range_do: "
                                                "parse Range '%s' => range ['%ld', '%ld'] and suffix_start '%s', "
                                                "range overflow!!!\n",
                                                range,
                                                (*range_start), (*range_end), c_bool_str(*suffix_start));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/*Range format: bytes=<START>-<END>[,<START>-<END>]*/
EC_BOOL crange_parse_range(const char *range, CRANGE_MGR *crange_mgr)
{
    UINT32      size;
    UINT32      pos;

    size = strlen(range);
    pos  = 0;

    if(EC_FALSE == crange_parse_range_prepare(range, &pos))
    {
        dbg_log(SEC_0018_CRANGE, 0)(LOGSTDOUT, "error:crange_parse_range: parse prepare from Range '%s' failed\n",
                        range);
        return (EC_FALSE);
    }

    while(pos < size)
    {
        UINT32              suffix_start;
        UINT32              suffix_end;
        UINT32              range_start;
        UINT32              range_end;
        CRANGE_NODE        *range_node;

        suffix_start = EC_FALSE;
        suffix_end   = EC_FALSE;
        range_start  = 0;
        range_end    = 0;

        if(EC_FALSE == crange_parse_range_do(range, &pos, &range_start, &range_end, &suffix_start, &suffix_end))
        {
            dbg_log(SEC_0018_CRANGE, 0)(LOGSTDOUT, "error:crange_parse_range: "
                                                   "parse range_start from Range '%s' failed\n",
                                                   range);
            return (EC_FALSE);
        }

        range_node = crange_node_new();
        if(NULL_PTR == range_node)
        {
            dbg_log(SEC_0018_CRANGE, 0)(LOGSTDOUT, "error:crange_parse_range: "
                                                   "new crange_node failed when parse Range '%s'\n",
                                                   range);
            return (EC_FALSE);
        }

        dbg_log(SEC_0018_CRANGE, 9)(LOGSTDOUT, "[DEBUG] crange_parse_range: "
                                               "parse Range '%s' => range ['%ld':'%s', '%ld':'%s']\n",
                                               range,
                                               range_start, c_bool_str(suffix_start),
                                               range_end, c_bool_str(suffix_end));

        CRANGE_NODE_SUFFIX_START(range_node)   = suffix_start;
        CRANGE_NODE_SUFFIX_END(range_node)     = suffix_end;
        CRANGE_NODE_RANGE_START(range_node)    = range_start;
        CRANGE_NODE_RANGE_END(range_node)      = range_end;

        if(EC_FALSE == crange_mgr_add_node(crange_mgr, (void *)range_node))
        {
            dbg_log(SEC_0018_CRANGE, 0)(LOGSTDOUT, "error:crange_parse_range: "
                                                   "push crange_node failed when parse Range '%s'\n",
                                                   range);

            crange_node_free(range_node);
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}


#ifdef __cplusplus
}
#endif/*__cplusplus*/

