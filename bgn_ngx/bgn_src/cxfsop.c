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

#include "cmisc.h"

#include "real.h"

#include "task.inc"
#include "task.h"

#include "cxfsnp.inc"
#include "cxfsnprb.h"

#include "cxfsop.h"
#include "camd.h"

#define CXFSOP_ASSERT(condition)           ASSERT(condition)
//#define CXFSOP_ASSERT(condition)           do{}while(0)

const char *cxfsop_mgr_op_str(const uint32_t op)
{
    if(CXFSOP_NP_F_ADD_OP == op)
    {
        return (const char *)"NP:F:ADD";
    }

    if(CXFSOP_NP_F_DEL_OP == op)
    {
        return (const char *)"NP:F:DEL";
    }

    if(CXFSOP_NP_F_UPD_OP == op)
    {
        return (const char *)"NP:F:UPD";
    }

    if(CXFSOP_NP_D_ADD_OP == op)
    {
        return (const char *)"NP:D:ADD";
    }

    if(CXFSOP_NP_D_DEL_OP == op)
    {
        return (const char *)"NP:D:DEL";
    }

    if(CXFSOP_NP_I_RET_OP == op)
    {
        return (const char *)"NP:I:RET";
    }

    if(CXFSOP_NP_I_REC_OP == op)
    {
        return (const char *)"NP:I:REC";
    }

    if(CXFSOP_DN_RSV_OP == op)
    {
        return (const char *)"DN:RSV";
    }

    if(CXFSOP_DN_REL_OP == op)
    {
        return (const char *)"DN:REL";
    }

    if(CXFSOP_DN_REC_OP == op)
    {
        return (const char *)"DN:REC";
    }

    return (const char *)"ERR";
}

CXFSOP_MGR *cxfsop_mgr_new()
{
    CXFSOP_MGR    *cxfsop_mgr;

    alloc_static_mem(MM_CXFSOP_MGR, &cxfsop_mgr, LOC_CXFSOP_0001);
    if(NULL_PTR == cxfsop_mgr)
    {
        dbg_log(SEC_0213_CXFSOP, 0)(LOGSTDOUT, "error:cxfsop_mgr_new: alloc memory failed\n");
        return (NULL_PTR);
    }

    cxfsop_mgr_init(cxfsop_mgr);
    return (cxfsop_mgr);
}

EC_BOOL cxfsop_mgr_init(CXFSOP_MGR *cxfsop_mgr)
{
    CXFSOP_MGR_SIZE(cxfsop_mgr)      = 0;
    CXFSOP_MGR_USED(cxfsop_mgr)      = 0;
    CXFSOP_MGR_DATA(cxfsop_mgr)      = NULL_PTR;
    CXFSOP_MGR_CAMD(cxfsop_mgr)      = NULL_PTR;

    return (EC_TRUE);
}

EC_BOOL cxfsop_mgr_clean(CXFSOP_MGR *cxfsop_mgr)
{
    if(NULL_PTR != cxfsop_mgr)
    {
        if(NULL_PTR != CXFSOP_MGR_DATA(cxfsop_mgr))
        {
            safe_free(CXFSOP_MGR_DATA(cxfsop_mgr), LOC_CXFSOP_0002);
            CXFSOP_MGR_DATA(cxfsop_mgr) = NULL_PTR;
        }
        CXFSOP_MGR_CAMD(cxfsop_mgr)      = NULL_PTR;
        CXFSOP_MGR_SIZE(cxfsop_mgr)      = 0;
        CXFSOP_MGR_USED(cxfsop_mgr)      = 0;
    }

    return (EC_TRUE);
}

EC_BOOL cxfsop_mgr_free(CXFSOP_MGR *cxfsop_mgr)
{
    if(NULL_PTR != cxfsop_mgr)
    {
        cxfsop_mgr_clean(cxfsop_mgr);
        free_static_mem(MM_CXFSOP_MGR, cxfsop_mgr, LOC_CXFSOP_0003);
    }

    return (EC_TRUE);
}

EC_BOOL cxfsop_mgr_make(CXFSOP_MGR *cxfsop_mgr, const uint64_t size)
{
    void    *data;

    data = safe_malloc(size, LOC_CXFSOP_0004);
    if(NULL_PTR == data)
    {
        dbg_log(SEC_0213_CXFSOP, 0)(LOGSTDOUT, "error:cxfsop_mgr_make: "
                                               "alloc %lu bytes failed\n",
                                               size);

        return (EC_FALSE);
    }

    BSET(data, 0, size);

    CXFSOP_MGR_SIZE(cxfsop_mgr)      = size;
    CXFSOP_MGR_USED(cxfsop_mgr)      = 0;
    CXFSOP_MGR_DATA(cxfsop_mgr)      = data;

    dbg_log(SEC_0213_CXFSOP, 9)(LOGSTDOUT, "[DEBUG] cxfsop_mgr_make: "
                                           "make size %lu done\n",
                                           size);

    return (EC_TRUE);
}

CXFSOP_MGR *cxfsop_mgr_create(const uint32_t size)
{
    CXFSOP_MGR    *cxfsop_mgr;

    cxfsop_mgr = cxfsop_mgr_new();
    if(NULL_PTR == cxfsop_mgr)
    {
        dbg_log(SEC_0213_CXFSOP, 0)(LOGSTDOUT, "error:cxfsop_mgr_create: "
                                               "new cxfsop_mgr failed\n");
        return (NULL_PTR);
    }

    if(EC_FALSE == cxfsop_mgr_make(cxfsop_mgr, size))
    {
        dbg_log(SEC_0213_CXFSOP, 0)(LOGSTDOUT, "error:cxfsop_mgr_create: "
                                               "make size %u failed\n",
                                               size);
        cxfsop_mgr_free(cxfsop_mgr);
        return (NULL_PTR);
    }

    dbg_log(SEC_0213_CXFSOP, 9)(LOGSTDOUT, "[DEBUG] cxfsop_mgr_create: "
                                           "create size %u done\n",
                                           size);

    return (cxfsop_mgr);
}

EC_BOOL cxfsop_mgr_mount_data(CXFSOP_MGR *cxfsop_mgr, const uint64_t size, void *data)
{
    if(NULL_PTR != cxfsop_mgr)
    {
        if(NULL_PTR != CXFSOP_MGR_DATA(cxfsop_mgr))
        {
            safe_free(CXFSOP_MGR_DATA(cxfsop_mgr), LOC_CXFSOP_0005);
            CXFSOP_MGR_DATA(cxfsop_mgr) = NULL_PTR;
        }

        CXFSOP_MGR_SIZE(cxfsop_mgr)      = size;
        CXFSOP_MGR_USED(cxfsop_mgr)      = size;
        CXFSOP_MGR_DATA(cxfsop_mgr)      = data;

        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL cxfsop_mgr_umount_data(CXFSOP_MGR *cxfsop_mgr, uint64_t *size, void **data)
{
    if(NULL_PTR != cxfsop_mgr)
    {
        if(NULL_PTR != CXFSOP_MGR_DATA(cxfsop_mgr))
        {
            if(NULL_PTR != data)
            {
                (*data) = CXFSOP_MGR_DATA(cxfsop_mgr);
            }

            if(NULL_PTR != size)
            {
                (*size) = CXFSOP_MGR_SIZE(cxfsop_mgr);
            }
        }

        CXFSOP_MGR_SIZE(cxfsop_mgr)      = 0;
        CXFSOP_MGR_USED(cxfsop_mgr)      = 0;
        CXFSOP_MGR_DATA(cxfsop_mgr)      = NULL_PTR;

        return (EC_TRUE);
    }

    return (EC_FALSE);
}

void cxfsop_mgr_print(LOG *log, const CXFSOP_MGR *cxfsop_mgr)
{
    sys_log(log, "[DEBUG] cxfsop_mgr_print: "
                 "cxfsop_mgr %p, size %lu, used %lu, data %p, camd %p\n",
                 cxfsop_mgr,
                 CXFSOP_MGR_SIZE(cxfsop_mgr),
                 CXFSOP_MGR_USED(cxfsop_mgr),
                 CXFSOP_MGR_DATA(cxfsop_mgr),
                 CXFSOP_MGR_CAMD(cxfsop_mgr));

    if(1)
    {
        uint8_t     *cur;
        uint8_t     *end;

        cur = CXFSOP_MGR_DATA(cxfsop_mgr);
        end = CXFSOP_MGR_DATA(cxfsop_mgr) + CXFSOP_MGR_USED(cxfsop_mgr);

        while(cur < end)
        {
            CXFSOP_COMM_HDR    *cxfsop_comm_hdr;

            cxfsop_comm_hdr = (CXFSOP_COMM_HDR *)cur;

            if(CXFSOP_MAGIC_VAL != CXFSOP_COMM_HDR_MAGIC(cxfsop_comm_hdr))
            {
                sys_log(log, "error:cxfsop_mgr_print: invalid magic num %lx\n",
                             CXFSOP_COMM_HDR_MAGIC(cxfsop_comm_hdr));
                break;/*terminate*/
            }

            cur += CXFSOP_COMM_HDR_SIZE(cxfsop_comm_hdr);

            if(CXFSOP_NP_F_ADD_OP == CXFSOP_COMM_HDR_OP(cxfsop_comm_hdr))
            {
                CXFSOP_NP_HDR       *cxfsop_np_hdr;
                CXFSOP_NP_FNODE     *cxfsop_np_fnode;

                cxfsop_np_hdr   = (CXFSOP_NP_HDR *)cxfsop_comm_hdr;
                cxfsop_np_fnode = (CXFSOP_NP_FNODE *)(cur - sizeof(CXFSOP_NP_FNODE));

                sys_log(log, "[DEBUG] cxfsop_mgr_print: [%s] time %lu, wildcard %u, klen %u, key %.*s, "
                             "(disk %u, block %u, page %u, size %u)\n",
                             cxfsop_mgr_op_str(CXFSOP_NP_HDR_OP(cxfsop_np_hdr)),
                             CXFSOP_NP_HDR_TIME(cxfsop_np_hdr),
                             CXFSOP_NP_HDR_WILDCARD(cxfsop_np_hdr),
                             CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr),
                             CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr), (char *)CXFSOP_NP_HDR_KEY(cxfsop_np_hdr),
                             CXFSOP_NP_FNODE_DISK_NO(cxfsop_np_fnode),
                             CXFSOP_NP_FNODE_BLOCK_NO(cxfsop_np_fnode),
                             CXFSOP_NP_FNODE_PAGE_NO(cxfsop_np_fnode),
                             CXFSOP_NP_FNODE_FILESZ(cxfsop_np_fnode));
                continue;
            }

            if(CXFSOP_NP_F_DEL_OP == CXFSOP_COMM_HDR_OP(cxfsop_comm_hdr))
            {
                CXFSOP_NP_HDR       *cxfsop_np_hdr;

                cxfsop_np_hdr   = (CXFSOP_NP_HDR *)cxfsop_comm_hdr;

                sys_log(log, "[DEBUG] cxfsop_mgr_print: [%s] time %lu, wildcard %u, klen %u, key %.*s\n",
                             cxfsop_mgr_op_str(CXFSOP_NP_HDR_OP(cxfsop_np_hdr)),
                             CXFSOP_NP_HDR_TIME(cxfsop_np_hdr),
                             CXFSOP_NP_HDR_WILDCARD(cxfsop_np_hdr),
                             CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr),
                             CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr), (char *)CXFSOP_NP_HDR_KEY(cxfsop_np_hdr));
                continue;
            }

            if(CXFSOP_NP_F_UPD_OP == CXFSOP_COMM_HDR_OP(cxfsop_comm_hdr))
            {
                CXFSOP_NP_HDR       *cxfsop_np_hdr;
                CXFSOP_NP_FNODE     *cxfsop_np_fnode;

                cxfsop_np_hdr   = (CXFSOP_NP_HDR *)cxfsop_comm_hdr;
                cxfsop_np_fnode = (CXFSOP_NP_FNODE *)(cur - sizeof(CXFSOP_NP_FNODE));

                sys_log(log, "[DEBUG] cxfsop_mgr_print: [%s] time %lu, wildcard %u, klen %u, key %.*s, "
                             "(disk %u, block %u, page %u, size %u)\n",
                             cxfsop_mgr_op_str(CXFSOP_NP_HDR_OP(cxfsop_np_hdr)),
                             CXFSOP_NP_HDR_TIME(cxfsop_np_hdr),
                             CXFSOP_NP_HDR_WILDCARD(cxfsop_np_hdr),
                             CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr),
                             CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr), (char *)CXFSOP_NP_HDR_KEY(cxfsop_np_hdr),
                             CXFSOP_NP_FNODE_DISK_NO(cxfsop_np_fnode),
                             CXFSOP_NP_FNODE_BLOCK_NO(cxfsop_np_fnode),
                             CXFSOP_NP_FNODE_PAGE_NO(cxfsop_np_fnode),
                             CXFSOP_NP_FNODE_FILESZ(cxfsop_np_fnode));
                continue;
            }

            if(CXFSOP_NP_D_ADD_OP == CXFSOP_COMM_HDR_OP(cxfsop_comm_hdr))
            {
                CXFSOP_NP_HDR   *cxfsop_np_hdr;

                cxfsop_np_hdr = (CXFSOP_NP_HDR *)cxfsop_comm_hdr;

                sys_log(log, "[DEBUG] cxfsop_mgr_print: [%s] time %lu, wildcard %u, klen %u, key %.*s\n",
                             cxfsop_mgr_op_str(CXFSOP_NP_HDR_OP(cxfsop_np_hdr)),
                             CXFSOP_NP_HDR_TIME(cxfsop_np_hdr),
                             CXFSOP_NP_HDR_WILDCARD(cxfsop_np_hdr),
                             CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr),
                             CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr), (char *)CXFSOP_NP_HDR_KEY(cxfsop_np_hdr));
                continue;
            }

            if(CXFSOP_NP_D_DEL_OP == CXFSOP_COMM_HDR_OP(cxfsop_comm_hdr))
            {
                CXFSOP_NP_HDR   *cxfsop_np_hdr;

                cxfsop_np_hdr = (CXFSOP_NP_HDR *)cxfsop_comm_hdr;

                sys_log(log, "[DEBUG] cxfsop_mgr_print: [%s] time %lu, wildcard %u, klen %u, key %.*s\n",
                             cxfsop_mgr_op_str(CXFSOP_NP_HDR_OP(cxfsop_np_hdr)),
                             CXFSOP_NP_HDR_TIME(cxfsop_np_hdr),
                             CXFSOP_NP_HDR_WILDCARD(cxfsop_np_hdr),
                             CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr),
                             CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr), (char *)CXFSOP_NP_HDR_KEY(cxfsop_np_hdr));
                continue;
            }

            if(CXFSOP_NP_I_RET_OP == CXFSOP_COMM_HDR_OP(cxfsop_comm_hdr))
            {
                CXFSOP_NP_ITEM   *cxfsop_np_item;

                cxfsop_np_item = (CXFSOP_NP_ITEM *)cxfsop_comm_hdr;

                sys_log(log, "[DEBUG] cxfsop_mgr_print: [%s] time %lu, np %u, node %u\n",
                             cxfsop_mgr_op_str(CXFSOP_NP_ITEM_OP(cxfsop_np_item)),
                             CXFSOP_NP_ITEM_TIME(cxfsop_np_item),
                             CXFSOP_NP_ITEM_NP_ID(cxfsop_np_item),
                             CXFSOP_NP_ITEM_NODE_POS(cxfsop_np_item));
                continue;
            }

            if(CXFSOP_NP_I_REC_OP == CXFSOP_COMM_HDR_OP(cxfsop_comm_hdr))
            {
                CXFSOP_NP_ITEM   *cxfsop_np_item;

                cxfsop_np_item = (CXFSOP_NP_ITEM *)cxfsop_comm_hdr;

                sys_log(log, "[DEBUG] cxfsop_mgr_print: [%s] time %lu, np %u, node %u\n",
                             cxfsop_mgr_op_str(CXFSOP_NP_ITEM_OP(cxfsop_np_item)),
                             CXFSOP_NP_ITEM_TIME(cxfsop_np_item),
                             CXFSOP_NP_ITEM_NP_ID(cxfsop_np_item),
                             CXFSOP_NP_ITEM_NODE_POS(cxfsop_np_item));
                continue;
            }

            if(CXFSOP_DN_RSV_OP == CXFSOP_COMM_HDR_OP(cxfsop_comm_hdr))
            {
                CXFSOP_DN_NODE      *cxfsop_dn_node;

                cxfsop_dn_node = (CXFSOP_DN_NODE *)cxfsop_comm_hdr;

                sys_log(log, "[DEBUG] cxfsop_mgr_dn_print: [%s] time %lu, (disk %u, block %u, page %u, size %u)\n",
                             cxfsop_mgr_op_str(CXFSOP_DN_NODE_OP(cxfsop_dn_node)),
                             CXFSOP_DN_NODE_TIME(cxfsop_dn_node),
                             CXFSOP_DN_NODE_DISK_NO(cxfsop_dn_node),
                             CXFSOP_DN_NODE_BLOCK_NO(cxfsop_dn_node),
                             CXFSOP_DN_NODE_PAGE_NO(cxfsop_dn_node),
                             CXFSOP_DN_NODE_DATA_LEN(cxfsop_dn_node));

                continue;
            }

            if(CXFSOP_DN_REL_OP == CXFSOP_COMM_HDR_OP(cxfsop_comm_hdr))
            {
                CXFSOP_DN_NODE      *cxfsop_dn_node;

                cxfsop_dn_node = (CXFSOP_DN_NODE *)cxfsop_comm_hdr;

                sys_log(log, "[DEBUG] cxfsop_mgr_dn_print: [%s] time %lu, (disk %u, block %u, page %u, size %u)\n",
                             cxfsop_mgr_op_str(CXFSOP_DN_NODE_OP(cxfsop_dn_node)),
                             CXFSOP_DN_NODE_TIME(cxfsop_dn_node),
                             CXFSOP_DN_NODE_DISK_NO(cxfsop_dn_node),
                             CXFSOP_DN_NODE_BLOCK_NO(cxfsop_dn_node),
                             CXFSOP_DN_NODE_PAGE_NO(cxfsop_dn_node),
                             CXFSOP_DN_NODE_DATA_LEN(cxfsop_dn_node));

                continue;
            }

            if(CXFSOP_DN_REC_OP == CXFSOP_COMM_HDR_OP(cxfsop_comm_hdr))
            {
                CXFSOP_DN_NODE      *cxfsop_dn_node;

                cxfsop_dn_node = (CXFSOP_DN_NODE *)cxfsop_comm_hdr;

                sys_log(log, "[DEBUG] cxfsop_mgr_dn_print: [%s] time %lu, (disk %u, block %u, page %u, size %u)\n",
                             cxfsop_mgr_op_str(CXFSOP_DN_NODE_OP(cxfsop_dn_node)),
                             CXFSOP_DN_NODE_TIME(cxfsop_dn_node),
                             CXFSOP_DN_NODE_DISK_NO(cxfsop_dn_node),
                             CXFSOP_DN_NODE_BLOCK_NO(cxfsop_dn_node),
                             CXFSOP_DN_NODE_PAGE_NO(cxfsop_dn_node),
                             CXFSOP_DN_NODE_DATA_LEN(cxfsop_dn_node));

                continue;
            }

            sys_log(log, "error:cxfsop_mgr_print: invalid op %u\n", CXFSOP_COMM_HDR_OP(cxfsop_comm_hdr));

            break; /*terminate*/
        }
    }

    return;
}

EC_BOOL cxfsop_mgr_is_full(const CXFSOP_MGR *cxfsop_mgr)
{
    if(CXFSOP_MGR_USED(cxfsop_mgr) >= CXFSOP_MGR_SIZE(cxfsop_mgr))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

uint64_t cxfsop_mgr_size(const CXFSOP_MGR *cxfsop_mgr)
{
    return CXFSOP_MGR_SIZE(cxfsop_mgr);
}

uint64_t cxfsop_mgr_used(const CXFSOP_MGR *cxfsop_mgr)
{
    return CXFSOP_MGR_USED(cxfsop_mgr);
}

REAL cxfsop_mgr_used_ratio(const CXFSOP_MGR *cxfsop_mgr)
{
    if(0 == CXFSOP_MGR_SIZE(cxfsop_mgr))
    {
        return (0.0);
    }
    return (CXFSOP_MGR_USED(cxfsop_mgr) + 0.0) / (CXFSOP_MGR_SIZE(cxfsop_mgr) + 0.0);
}

uint64_t cxfsop_mgr_room(const CXFSOP_MGR *cxfsop_mgr)
{
    return CXFSOP_MGR_SIZE(cxfsop_mgr) - CXFSOP_MGR_USED(cxfsop_mgr);
}

EC_BOOL cxfsop_mgr_mount_camd(CXFSOP_MGR *cxfsop_mgr, void *camd_md)
{
    if(NULL_PTR != CXFSOP_MGR_CAMD(cxfsop_mgr))
    {
        dbg_log(SEC_0213_CXFSOP, 0)(LOGSTDOUT, "error:cxfsop_mgr_mount_camd: "
                                               "camd is not null\n");
        return (EC_FALSE);
    }

    CXFSOP_MGR_CAMD(cxfsop_mgr) = camd_md;
    return (EC_TRUE);
}

EC_BOOL cxfsop_mgr_umount_camd(CXFSOP_MGR *cxfsop_mgr)
{
    if(NULL_PTR == CXFSOP_MGR_CAMD(cxfsop_mgr))
    {
        dbg_log(SEC_0213_CXFSOP, 0)(LOGSTDOUT, "error:cxfsop_mgr_mount_camd: "
                                               "camd is null\n");
        return (EC_FALSE);
    }

    CXFSOP_MGR_CAMD(cxfsop_mgr) = NULL_PTR;
    return (EC_TRUE);
}

void *cxfsop_mgr_search(CXFSOP_MGR *cxfsop_mgr, void *cur, const uint64_t max_scope_len)
{
    void       *end;
    void       *matched;
    uint64_t    c_time_msec;
    uint32_t    matched_num;

    if(cur + max_scope_len < CXFSOP_MGR_DATA(cxfsop_mgr) + CXFSOP_MGR_USED(cxfsop_mgr))
    {
        end = cur + max_scope_len;
    }
    else
    {
        end = CXFSOP_MGR_DATA(cxfsop_mgr) + CXFSOP_MGR_USED(cxfsop_mgr);
    }

    c_time_msec = c_get_cur_time_msec();
    matched_num = 0;
    matched     = NULL_PTR;

    while(cur < end)
    {
        CXFSOP_COMM_HDR    *cxfsop_comm_hdr;

        cxfsop_comm_hdr = (CXFSOP_COMM_HDR *)cur;

        if(CXFSOP_MAGIC_VAL != CXFSOP_COMM_HDR_MAGIC(cxfsop_comm_hdr)
        || 0 == CXFSOP_COMM_HDR_TIME(cxfsop_comm_hdr)
        || c_time_msec < CXFSOP_COMM_HDR_TIME(cxfsop_comm_hdr))
        {
            cur ++;

            matched_num = 0;        /*reset*/
            matched     = NULL_PTR; /*reset*/
            continue;
        }

        if(NULL_PTR == matched)
        {
            matched = cur;
        }

        matched_num ++;

        if(3 <= matched_num) /*matched 3 times*/
        {
            return (matched);
        }

        cur += CXFSOP_COMM_HDR_SIZE(cxfsop_comm_hdr);
    }

    return (NULL_PTR);
}

EC_BOOL cxfsop_mgr_scan(CXFSOP_MGR *cxfsop_mgr,
                             uint64_t           *s_op_offset,   /*OUT*/
                             uint64_t           *e_op_offset,   /*OUT*/
                             uint64_t           *s_op_time_msec,/*IN & OUT*/
                             uint64_t           *e_op_time_msec)/*IN & OUT*/
{
    uint64_t         c_time_msec;
    uint64_t         s_time_msec; /*min create time*/
    uint64_t         e_time_msec; /*max create time*/

    uint64_t         s_offset;
    uint64_t         e_offset;

    void            *cur;
    void            *end;

    c_time_msec  = c_get_cur_time_msec();
    s_time_msec  = ((uint64_t)~0);
    e_time_msec  = ((uint64_t) 0);

    s_offset = 0;
    e_offset = 0;

    cur = CXFSOP_MGR_DATA(cxfsop_mgr);
    end = CXFSOP_MGR_DATA(cxfsop_mgr) + CXFSOP_MGR_USED(cxfsop_mgr);

    while(NULL_PTR != cur && cur < end)
    {
        CXFSOP_COMM_HDR    *cxfsop_comm_hdr;

        cxfsop_comm_hdr = (CXFSOP_COMM_HDR *)cur;

        dbg_log(SEC_0213_CXFSOP, 6)(LOGSTDOUT, "[DEBUG] cxfsop_mgr_scan: "
                                               "offset %ld, time %lu (%s), magic %x, "
                                               "op %u, size %u\n",
                                               (UINT32)((void *)cxfsop_comm_hdr - CXFSOP_MGR_DATA(cxfsop_mgr)),
                                               CXFSOP_COMM_HDR_TIME(cxfsop_comm_hdr),
                                               c_get_time_msec_str(CXFSOP_COMM_HDR_TIME(cxfsop_comm_hdr)),
                                               CXFSOP_COMM_HDR_MAGIC(cxfsop_comm_hdr),
                                               CXFSOP_COMM_HDR_OP(cxfsop_comm_hdr),
                                               CXFSOP_COMM_HDR_SIZE(cxfsop_comm_hdr));

        if(0 == CXFSOP_COMM_HDR_MAGIC(cxfsop_comm_hdr)
        && 0 == CXFSOP_COMM_HDR_TIME(cxfsop_comm_hdr))
        {
            cur = cxfsop_mgr_search(cxfsop_mgr, cur, CXFSOP_SEARCH_MAX_LEN);

            continue;
        }

        /*invalid magic num*/
        if(CXFSOP_MAGIC_VAL != CXFSOP_COMM_HDR_MAGIC(cxfsop_comm_hdr))
        {
            dbg_log(SEC_0213_CXFSOP, 0)(LOGSTDOUT, "warn:cxfsop_mgr_scan: "
                                                   "invalid magic num %#x\n",
                                                   CXFSOP_COMM_HDR_MAGIC(cxfsop_comm_hdr));
            cur = cxfsop_mgr_search(cxfsop_mgr, cur, CXFSOP_SEARCH_MAX_LEN);
            continue;
        }

        /*no create time*/
        if(0 == CXFSOP_COMM_HDR_TIME(cxfsop_comm_hdr))
        {
            dbg_log(SEC_0213_CXFSOP, 0)(LOGSTDOUT, "warn:cxfsop_mgr_scan: "
                                                   "no create time\n");
            cur = cxfsop_mgr_search(cxfsop_mgr, cur, CXFSOP_SEARCH_MAX_LEN);
            continue;
        }

        /*invalid create time*/
        if(c_time_msec < CXFSOP_COMM_HDR_TIME(cxfsop_comm_hdr))
        {
            dbg_log(SEC_0213_CXFSOP, 0)(LOGSTDOUT, "warn:cxfsop_mgr_scan: "
                                                   "create time %lu >= cur time %lu\n",
                                                   CXFSOP_COMM_HDR_TIME(cxfsop_comm_hdr),
                                                   c_time_msec);
            cur = cxfsop_mgr_search(cxfsop_mgr, cur, CXFSOP_SEARCH_MAX_LEN);
            continue;
        }

        /*skip*/
        if((*s_op_time_msec) > CXFSOP_COMM_HDR_TIME(cxfsop_comm_hdr))
        {
            dbg_log(SEC_0213_CXFSOP, 5)(LOGSTDOUT, "[DEBUG] cxfsop_mgr_scan: "
                                                   "s_op_time_msec %lu (%s) > create time => skip\n",
                                                   (*s_op_time_msec),
                                                   c_get_time_msec_str((*s_op_time_msec)));

            cur += CXFSOP_COMM_HDR_SIZE(cxfsop_comm_hdr);
            continue;
        }

        /*end*/
        if((*e_op_time_msec) < CXFSOP_COMM_HDR_TIME(cxfsop_comm_hdr))
        {
            dbg_log(SEC_0213_CXFSOP, 0)(LOGSTDOUT, "[DEBUG] cxfsop_mgr_scan: "
                                                   "e_op_time_msec %lu (%s) < create time => end\n",
                                                   (*e_op_time_msec),
                                                   c_get_time_msec_str((*e_op_time_msec)));
            break;
        }

        if(s_time_msec > CXFSOP_COMM_HDR_TIME(cxfsop_comm_hdr))
        {
            dbg_log(SEC_0213_CXFSOP, 6)(LOGSTDOUT, "[DEBUG] cxfsop_mgr_scan: "
                                                   "s_time_msec: %lu => %lu\n",
                                                   s_time_msec,
                                                   CXFSOP_COMM_HDR_TIME(cxfsop_comm_hdr));

            s_time_msec = CXFSOP_COMM_HDR_TIME(cxfsop_comm_hdr);
            s_offset    = cur - CXFSOP_MGR_DATA(cxfsop_mgr);
        }

        if(e_time_msec < CXFSOP_COMM_HDR_TIME(cxfsop_comm_hdr))
        {
            dbg_log(SEC_0213_CXFSOP, 6)(LOGSTDOUT, "[DEBUG] cxfsop_mgr_scan: "
                                                   "e_time_msec: %lu => %lu\n",
                                                   e_time_msec,
                                                   CXFSOP_COMM_HDR_TIME(cxfsop_comm_hdr));

            e_time_msec = CXFSOP_COMM_HDR_TIME(cxfsop_comm_hdr);
            e_offset    = cur - CXFSOP_MGR_DATA(cxfsop_mgr) + CXFSOP_COMM_HDR_SIZE(cxfsop_comm_hdr);
        }

        cur += CXFSOP_COMM_HDR_SIZE(cxfsop_comm_hdr);

        if(CXFSOP_NP_F_ADD_OP == CXFSOP_COMM_HDR_OP(cxfsop_comm_hdr)
        || CXFSOP_NP_F_DEL_OP == CXFSOP_COMM_HDR_OP(cxfsop_comm_hdr)
        || CXFSOP_NP_F_UPD_OP == CXFSOP_COMM_HDR_OP(cxfsop_comm_hdr)
        || CXFSOP_NP_D_ADD_OP == CXFSOP_COMM_HDR_OP(cxfsop_comm_hdr)
        || CXFSOP_NP_D_DEL_OP == CXFSOP_COMM_HDR_OP(cxfsop_comm_hdr)
        || CXFSOP_NP_I_RET_OP == CXFSOP_COMM_HDR_OP(cxfsop_comm_hdr)
        || CXFSOP_NP_I_REC_OP == CXFSOP_COMM_HDR_OP(cxfsop_comm_hdr)
        || CXFSOP_DN_RSV_OP == CXFSOP_COMM_HDR_OP(cxfsop_comm_hdr)
        || CXFSOP_DN_REL_OP == CXFSOP_COMM_HDR_OP(cxfsop_comm_hdr)
        || CXFSOP_DN_REC_OP == CXFSOP_COMM_HDR_OP(cxfsop_comm_hdr))
        {
            dbg_log(SEC_0213_CXFSOP, 2)(LOGSTDOUT, "[DEBUG] cxfsop_mgr_scan: "
                                                   "offset %ld, time %lu (%s), magic %x, "
                                                   "op %u, size %u => OK\n",
                                                   (UINT32)((void *)cxfsop_comm_hdr - CXFSOP_MGR_DATA(cxfsop_mgr)),
                                                   CXFSOP_COMM_HDR_TIME(cxfsop_comm_hdr),
                                                   c_get_time_msec_str(CXFSOP_COMM_HDR_TIME(cxfsop_comm_hdr)),
                                                   CXFSOP_COMM_HDR_MAGIC(cxfsop_comm_hdr),
                                                   CXFSOP_COMM_HDR_OP(cxfsop_comm_hdr),
                                                   CXFSOP_COMM_HDR_SIZE(cxfsop_comm_hdr));
            continue;
        }

        dbg_log(SEC_0213_CXFSOP, 0)(LOGSTDOUT, "error:cxfsop_mgr_scan: invalid op %u\n",
                                               CXFSOP_COMM_HDR_OP(cxfsop_comm_hdr));
        return (EC_FALSE);
    }

    (*s_op_offset)    = s_offset;
    (*e_op_offset)    = e_offset;

    (*s_op_time_msec) = s_time_msec;
    (*e_op_time_msec) = e_time_msec;

    return (EC_TRUE);
}

EC_BOOL cxfsop_mgr_dump(CXFSOP_MGR *cxfsop_mgr, UINT32 *offset)
{
    uint64_t         used;
    void            *data;
    UINT32           offset_t;

    if(NULL_PTR == CXFSOP_MGR_CAMD(cxfsop_mgr))
    {
        dbg_log(SEC_0213_CXFSOP, 0)(LOGSTDOUT, "error:cxfsop_mgr_dump: "
                                               "camd is null\n");
        return (EC_FALSE);
    }

    used = CXFSOP_MGR_USED(cxfsop_mgr);
    data = CXFSOP_MGR_DATA(cxfsop_mgr);

    ASSERT(0 < used);
    ASSERT(NULL_PTR != data);

    offset_t = (*offset);

    if(EC_FALSE == camd_file_write_dio((CAMD_MD *)CXFSOP_MGR_CAMD(cxfsop_mgr),
                                        &offset_t, used, (UINT8 *)data))
    {
        dbg_log(SEC_0213_CXFSOP, 0)(LOGSTDOUT, "error:cxfsop_mgr_dump: "
                                               "op mgr %p, dump data %p, "
                                               "used %lu to offset %ld failed\n",
                                               cxfsop_mgr, data, used, (*offset));
        return (EC_FALSE);
    }

    dbg_log(SEC_0213_CXFSOP, 0)(LOGSTDOUT, "[DEBUG] cxfsop_mgr_dump: "
                                           "op mgr %p, dump data %p, "
                                           "used %lu to offset %ld (=> %ld) done\n",
                                           cxfsop_mgr, data, used, (*offset), offset_t);
    ASSERT((*offset) + used == offset_t);

    (*offset) = offset_t;
    return (EC_TRUE);
}

EC_BOOL cxfsop_mgr_pad(CXFSOP_MGR *cxfsop_mgr, UINT32 *offset, const UINT32 size)
{
    void            *data;
    UINT32           offset_t;

    if(NULL_PTR == CXFSOP_MGR_CAMD(cxfsop_mgr))
    {
        dbg_log(SEC_0213_CXFSOP, 0)(LOGSTDOUT, "error:cxfsop_mgr_pad: "
                                               "camd is null\n");
        return (EC_FALSE);
    }

    data = safe_malloc(size, LOC_CXFSOP_0006);
    if(NULL_PTR == data)
    {
        dbg_log(SEC_0213_CXFSOP, 0)(LOGSTDOUT, "error:cxfsop_mgr_pad: "
                                               "alloc %ld bytes failed\n",
                                               size);
        return (EC_FALSE);
    }

    BSET(data, 0x00, size); /*pad zeros*/

    offset_t = (*offset);

    if(EC_FALSE == camd_file_write_dio((CAMD_MD *)CXFSOP_MGR_CAMD(cxfsop_mgr),
                                        &offset_t, size, (UINT8 *)data))
    {
        safe_free(data, LOC_CXFSOP_0007);

        dbg_log(SEC_0213_CXFSOP, 0)(LOGSTDOUT, "error:cxfsop_mgr_pad: "
                                               "pad %lu zeros to offset %ld failed\n",
                                               size, (*offset));

        return (EC_FALSE);
    }

    safe_free(data, LOC_CXFSOP_0008);

    dbg_log(SEC_0213_CXFSOP, 0)(LOGSTDOUT, "[DEBUG] cxfsop_mgr_pad: "
                                           "pad %lu zeros to offset %ld done\n",
                                           size, (*offset));
    ASSERT((*offset) + size == offset_t);

    (*offset) = offset_t;
    return (EC_TRUE);
}

STATIC_CAST static uint16_t cxfsop_mgr_np_path_seg_len(const uint8_t  *full_path,
                                                               const uint16_t  full_path_len,
                                                               const uint8_t  *path_seg_beg)
{
    uint8_t *ptr;

    if(path_seg_beg < full_path || path_seg_beg >= full_path + full_path_len)
    {
        return (0);
    }

    for(ptr = (uint8_t *)path_seg_beg; ptr < full_path + full_path_len && '/' != (*ptr); ptr ++)
    {
        /*do nothing*/
    }

    return (uint16_t)(ptr - path_seg_beg);
}

STATIC_CAST static uint16_t __cxfsop_mgr_np_path_copy(const uint16_t  src_path_len,
                                                              const uint8_t   *src_path,
                                                              uint8_t         *des_path)
{
    uint16_t     src_path_seg_len;
    uint8_t     *src_path_seg_beg;
    uint8_t     *src_path_seg_end;

    uint8_t     *des_path_seg_cur;

    src_path_seg_beg = (uint8_t *)src_path;
    src_path_seg_len = 0;
    src_path_seg_end = (uint8_t *)(src_path_seg_beg + src_path_seg_len + 1);/*path always start with '/'*/

    des_path_seg_cur = des_path;
    BCOPY(src_path_seg_beg, des_path_seg_cur, src_path_seg_len);
    des_path_seg_cur += src_path_seg_len;

    while(src_path_len > (uint16_t)(src_path_seg_end - src_path))
    {
        *des_path_seg_cur ++ = '/';

        src_path_seg_beg = (uint8_t *)src_path_seg_end;
        src_path_seg_len = cxfsop_mgr_np_path_seg_len(src_path, src_path_len, src_path_seg_beg);
        src_path_seg_end = src_path_seg_beg + src_path_seg_len + 1;

        if(CXFSNP_KEY_MAX_SIZE < src_path_seg_len)/*overflow path seg*/
        {
            uint8_t     *md5_str;
            uint32_t     md5_len;

            md5_str = (uint8_t *)c_md5_sum_to_hex_str(src_path_seg_len, src_path_seg_beg);
            md5_len = (uint32_t )(2 * CMD5_DIGEST_LEN);

            BCOPY(md5_str, des_path_seg_cur, md5_len);

            des_path_seg_cur += md5_len;
        }
        else
        {
            BCOPY(src_path_seg_beg, des_path_seg_cur, src_path_seg_len);
            des_path_seg_cur += src_path_seg_len;
        }
    }

    return ((uint16_t)(des_path_seg_cur - des_path));
}

EC_BOOL cxfsop_mgr_np_push_dir_add_op(CXFSOP_MGR         *cxfsop_mgr,
                                                const uint16_t      klen,
                                                const uint8_t      *key)
{
    void             *data;
    CXFSOP_NP_HDR    *cxfsop_np_hdr;
    uint32_t          klen_aligned;

    klen_aligned = VAL_ALIGN(klen, 8);

    if(CXFSOP_MGR_USED(cxfsop_mgr)
       + sizeof(CXFSOP_NP_HDR)
       + klen_aligned
       > CXFSOP_MGR_SIZE(cxfsop_mgr))
    {
        dbg_log(SEC_0213_CXFSOP, 0)(LOGSTDOUT, "error:cxfsop_mgr_np_push_dir_add_op: "
                                               "used %lu, size %lu => op mgr %p is full\n",
                                               CXFSOP_MGR_USED(cxfsop_mgr),
                                               CXFSOP_MGR_SIZE(cxfsop_mgr),
                                               cxfsop_mgr);
        CXFSOP_ASSERT(0);
        return (EC_FALSE);
    }

    data = CXFSOP_MGR_DATA(cxfsop_mgr) + CXFSOP_MGR_USED(cxfsop_mgr);
    cxfsop_np_hdr = (CXFSOP_NP_HDR *)data;

    CXFSOP_NP_HDR_TIME(cxfsop_np_hdr)     = c_get_cur_time_msec();
    CXFSOP_NP_HDR_MAGIC(cxfsop_np_hdr)    = CXFSOP_MAGIC_VAL;
    CXFSOP_NP_HDR_OP(cxfsop_np_hdr)       = CXFSOP_NP_D_ADD_OP;
    CXFSOP_NP_HDR_WILDCARD(cxfsop_np_hdr) = BIT_FALSE;
    CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr)     = __cxfsop_mgr_np_path_copy(klen, key, CXFSOP_NP_HDR_KEY(cxfsop_np_hdr));
    if(CXFSOP_KEY_MAX_LEN <= CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr))
    {
        dbg_log(SEC_0213_CXFSOP, 0)(LOGSTDOUT, "error:cxfsop_mgr_np_push_dir_add_op: "
                                               "[NP][D] [ADD] %.*s => klen %u >= %u => overflow!\n",
                                               klen, key,
                                               CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr),
                                               CXFSOP_KEY_MAX_LEN);
        return (EC_FALSE);
    }

    klen_aligned                          = VAL_ALIGN(CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr), 8); /*align to 8B*/
    CXFSOP_NP_HDR_SIZE(cxfsop_np_hdr)     = sizeof(CXFSOP_NP_HDR) + klen_aligned;
    if(CXFSOP_HDR_MAX_LEN <= CXFSOP_NP_HDR_SIZE(cxfsop_np_hdr))
    {
        dbg_log(SEC_0213_CXFSOP, 0)(LOGSTDOUT, "error:cxfsop_mgr_np_push_dir_add_op: "
                                               "[NP][D] [ADD] %.*s => hdr size %u >= %u => overflow!\n",
                                               klen, key,
                                               CXFSOP_NP_HDR_SIZE(cxfsop_np_hdr),
                                               CXFSOP_HDR_MAX_LEN);
        return (EC_FALSE);
    }

    CXFSOP_MGR_USED(cxfsop_mgr)          += CXFSOP_NP_HDR_SIZE(cxfsop_np_hdr);

    if(CXFSOP_MGR_USED(cxfsop_mgr) > CXFSOP_MGR_SIZE(cxfsop_mgr))
    {
        CXFSOP_MGR_USED(cxfsop_mgr) = CXFSOP_MGR_SIZE(cxfsop_mgr);
    }

    dbg_log(SEC_0213_CXFSOP, 9)(LOGSTDOUT, "[DEBUG] cxfsop_mgr_np_push_dir_add_op: "
                                           "[NP][D] [ADD] %.*s => used %lu\n",
                                           klen, key, CXFSOP_MGR_USED(cxfsop_mgr));

    return (EC_TRUE);
}

EC_BOOL cxfsop_mgr_np_push_dir_delete_op(CXFSOP_MGR         *cxfsop_mgr,
                                                   const uint16_t      klen,
                                                   const uint8_t      *key)
{
    void             *data;
    CXFSOP_NP_HDR    *cxfsop_np_hdr;
    uint32_t          klen_aligned;

    klen_aligned = VAL_ALIGN(klen, 8);

    if(CXFSOP_MGR_USED(cxfsop_mgr)
       + sizeof(CXFSOP_NP_HDR)
       + klen_aligned
       > CXFSOP_MGR_SIZE(cxfsop_mgr))
    {
        dbg_log(SEC_0213_CXFSOP, 0)(LOGSTDOUT, "error:cxfsop_mgr_np_push_dir_delete_op: "
                                               "used %lu, size %lu => op mgr %p is full\n",
                                               CXFSOP_MGR_USED(cxfsop_mgr),
                                               CXFSOP_MGR_SIZE(cxfsop_mgr),
                                               cxfsop_mgr);
        CXFSOP_ASSERT(0);
        return (EC_FALSE);
    }

    data = CXFSOP_MGR_DATA(cxfsop_mgr) + CXFSOP_MGR_USED(cxfsop_mgr);
    cxfsop_np_hdr = (CXFSOP_NP_HDR *)data;

    CXFSOP_NP_HDR_TIME(cxfsop_np_hdr)     = c_get_cur_time_msec();
    CXFSOP_NP_HDR_MAGIC(cxfsop_np_hdr)    = CXFSOP_MAGIC_VAL;
    CXFSOP_NP_HDR_OP(cxfsop_np_hdr)       = CXFSOP_NP_D_DEL_OP;
    CXFSOP_NP_HDR_WILDCARD(cxfsop_np_hdr) = BIT_FALSE;
    CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr)     = __cxfsop_mgr_np_path_copy(klen, key, CXFSOP_NP_HDR_KEY(cxfsop_np_hdr));
    if(CXFSOP_KEY_MAX_LEN <= CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr))
    {
        dbg_log(SEC_0213_CXFSOP, 0)(LOGSTDOUT, "error:cxfsop_mgr_np_push_dir_delete_op: "
                                               "[NP][D] [DEL] %.*s => klen %u >= %u => overflow!\n",
                                               klen, key,
                                               CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr),
                                               CXFSOP_KEY_MAX_LEN);
        return (EC_FALSE);
    }

    klen_aligned                          = VAL_ALIGN(CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr), 8); /*align to 8B*/
    CXFSOP_NP_HDR_SIZE(cxfsop_np_hdr)     = sizeof(CXFSOP_NP_HDR) + klen_aligned;
    if(CXFSOP_HDR_MAX_LEN <= CXFSOP_NP_HDR_SIZE(cxfsop_np_hdr))
    {
        dbg_log(SEC_0213_CXFSOP, 0)(LOGSTDOUT, "error:cxfsop_mgr_np_push_dir_delete_op: "
                                               "[NP][D] [DEL] %.*s => hdr size %u >= %u => overflow!\n",
                                               klen, key,
                                               CXFSOP_NP_HDR_SIZE(cxfsop_np_hdr),
                                               CXFSOP_HDR_MAX_LEN);
        return (EC_FALSE);
    }

    CXFSOP_MGR_USED(cxfsop_mgr)          += CXFSOP_NP_HDR_SIZE(cxfsop_np_hdr);

    if(CXFSOP_MGR_USED(cxfsop_mgr) > CXFSOP_MGR_SIZE(cxfsop_mgr))
    {
        CXFSOP_MGR_USED(cxfsop_mgr) = CXFSOP_MGR_SIZE(cxfsop_mgr);
    }

    dbg_log(SEC_0213_CXFSOP, 9)(LOGSTDOUT, "[DEBUG] cxfsop_mgr_np_push_dir_delete_op: "
                                           "[NP][D] [DEL] %.*s => used %lu\n",
                                           klen, key, CXFSOP_MGR_USED(cxfsop_mgr));
    return (EC_TRUE);
}

EC_BOOL cxfsop_mgr_np_push_dir_wildcard_delete_op(CXFSOP_MGR      *cxfsop_mgr,
                                                              const uint16_t   klen,
                                                              const uint8_t   *key)
{
    void             *data;
    CXFSOP_NP_HDR    *cxfsop_np_hdr;
    uint32_t          klen_aligned;

    klen_aligned = VAL_ALIGN(klen, 8);

    if(CXFSOP_MGR_USED(cxfsop_mgr)
       + sizeof(CXFSOP_NP_HDR)
       + klen_aligned
       > CXFSOP_MGR_SIZE(cxfsop_mgr))
    {
        dbg_log(SEC_0213_CXFSOP, 0)(LOGSTDOUT, "error:cxfsop_mgr_np_push_dir_wildcard_delete_op: "
                                               "used %lu, size %lu => op mgr %p is full\n",
                                               CXFSOP_MGR_USED(cxfsop_mgr),
                                               CXFSOP_MGR_SIZE(cxfsop_mgr),
                                               cxfsop_mgr);
        CXFSOP_ASSERT(0);
        return (EC_FALSE);
    }

    data = CXFSOP_MGR_DATA(cxfsop_mgr) + CXFSOP_MGR_USED(cxfsop_mgr);
    cxfsop_np_hdr = (CXFSOP_NP_HDR *)data;

    CXFSOP_NP_HDR_TIME(cxfsop_np_hdr)     = c_get_cur_time_msec();
    CXFSOP_NP_HDR_MAGIC(cxfsop_np_hdr)    = CXFSOP_MAGIC_VAL;
    CXFSOP_NP_HDR_OP(cxfsop_np_hdr)       = CXFSOP_NP_D_DEL_OP;
    CXFSOP_NP_HDR_WILDCARD(cxfsop_np_hdr) = BIT_TRUE;
    CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr)     = __cxfsop_mgr_np_path_copy(klen, key, CXFSOP_NP_HDR_KEY(cxfsop_np_hdr));
    if(CXFSOP_KEY_MAX_LEN <= CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr))
    {
        dbg_log(SEC_0213_CXFSOP, 0)(LOGSTDOUT, "error:cxfsop_mgr_np_push_dir_wildcard_delete_op: "
                                               "[NP][D] [DEL] %.*s => klen %u >= %u => overflow!\n",
                                               klen, key,
                                               CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr),
                                               CXFSOP_KEY_MAX_LEN);
        return (EC_FALSE);
    }

    klen_aligned                          = VAL_ALIGN(CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr), 8); /*align to 8B*/
    CXFSOP_NP_HDR_SIZE(cxfsop_np_hdr)     = sizeof(CXFSOP_NP_HDR) + klen_aligned;
    if(CXFSOP_HDR_MAX_LEN <= CXFSOP_NP_HDR_SIZE(cxfsop_np_hdr))
    {
        dbg_log(SEC_0213_CXFSOP, 0)(LOGSTDOUT, "error:cxfsop_mgr_np_push_dir_wildcard_delete_op: "
                                               "[NP][D] [DEL] %.*s => hdr size %u >= %u => overflow!\n",
                                               klen, key,
                                               CXFSOP_NP_HDR_SIZE(cxfsop_np_hdr),
                                               CXFSOP_HDR_MAX_LEN);
        return (EC_FALSE);
    }

    CXFSOP_MGR_USED(cxfsop_mgr)          += CXFSOP_NP_HDR_SIZE(cxfsop_np_hdr);

    if(CXFSOP_MGR_USED(cxfsop_mgr) > CXFSOP_MGR_SIZE(cxfsop_mgr))
    {
        CXFSOP_MGR_USED(cxfsop_mgr) = CXFSOP_MGR_SIZE(cxfsop_mgr);
    }

    dbg_log(SEC_0213_CXFSOP, 9)(LOGSTDOUT, "[DEBUG] cxfsop_mgr_np_push_dir_wildcard_delete_op: "
                                           "[NP][D] [DEL] %.*s => used %lu\n",
                                           klen, key, CXFSOP_MGR_USED(cxfsop_mgr));
    return (EC_TRUE);
}

EC_BOOL cxfsop_mgr_np_push_file_add_op(CXFSOP_MGR      *cxfsop_mgr,
                                                 const uint16_t   klen,
                                                 const uint8_t   *key,
                                                 const uint32_t   file_size,
                                                 const uint16_t   disk_no,
                                                 const uint16_t   block_no,
                                                 const uint16_t   page_no)
{
    void             *data;
    CXFSOP_NP_HDR    *cxfsop_np_hdr;
    CXFSOP_NP_FNODE  *cxfsop_np_fnode;
    uint32_t          klen_aligned;

    klen_aligned = VAL_ALIGN(klen, 8);

    if(CXFSOP_MGR_USED(cxfsop_mgr)
       + sizeof(CXFSOP_NP_HDR)
       + klen_aligned
       + sizeof(CXFSOP_NP_FNODE)
       > CXFSOP_MGR_SIZE(cxfsop_mgr))
    {
        dbg_log(SEC_0213_CXFSOP, 0)(LOGSTDOUT, "error:cxfsop_mgr_np_push_file_add_op: "
                                               "used %lu, size %lu => op mgr %p is full\n",
                                               CXFSOP_MGR_USED(cxfsop_mgr),
                                               CXFSOP_MGR_SIZE(cxfsop_mgr),
                                               cxfsop_mgr);
        CXFSOP_ASSERT(0);
        return (EC_FALSE);
    }

    data = CXFSOP_MGR_DATA(cxfsop_mgr) + CXFSOP_MGR_USED(cxfsop_mgr);
    cxfsop_np_hdr = (CXFSOP_NP_HDR *)data;

    CXFSOP_NP_HDR_TIME(cxfsop_np_hdr)     = c_get_cur_time_msec();
    CXFSOP_NP_HDR_MAGIC(cxfsop_np_hdr)    = CXFSOP_MAGIC_VAL;
    CXFSOP_NP_HDR_OP(cxfsop_np_hdr)       = CXFSOP_NP_F_ADD_OP;
    CXFSOP_NP_HDR_WILDCARD(cxfsop_np_hdr) = BIT_FALSE;
    CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr)     = __cxfsop_mgr_np_path_copy(klen, key, CXFSOP_NP_HDR_KEY(cxfsop_np_hdr));
    if(CXFSOP_KEY_MAX_LEN <= CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr))
    {
        dbg_log(SEC_0213_CXFSOP, 0)(LOGSTDOUT, "error:cxfsop_mgr_np_push_file_add_op: "
                                               "[NP][F] [ADD] %.*s => klen %u >= %u => overflow!\n",
                                               klen, key,
                                               CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr),
                                               CXFSOP_KEY_MAX_LEN);
        return (EC_FALSE);
    }

    klen_aligned                          = VAL_ALIGN(CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr), 8); /*align to 8B*/
    CXFSOP_NP_HDR_SIZE(cxfsop_np_hdr)     = sizeof(CXFSOP_NP_HDR) + klen_aligned + sizeof(CXFSOP_NP_FNODE);
    if(CXFSOP_HDR_MAX_LEN <= CXFSOP_NP_HDR_SIZE(cxfsop_np_hdr))
    {
        dbg_log(SEC_0213_CXFSOP, 0)(LOGSTDOUT, "error:cxfsop_mgr_np_push_file_add_op: "
                                               "[NP][F] [ADD] %.*s => hdr size %u >= %u => overflow!\n",
                                               klen, key,
                                               CXFSOP_NP_HDR_SIZE(cxfsop_np_hdr),
                                               CXFSOP_HDR_MAX_LEN);
        return (EC_FALSE);
    }

    CXFSOP_MGR_USED(cxfsop_mgr)          += CXFSOP_NP_HDR_SIZE(cxfsop_np_hdr);

    data = CXFSOP_MGR_DATA(cxfsop_mgr) + CXFSOP_MGR_USED(cxfsop_mgr) - sizeof(CXFSOP_NP_FNODE);
    cxfsop_np_fnode = (CXFSOP_NP_FNODE *)data;

    CXFSOP_NP_FNODE_FILESZ(cxfsop_np_fnode)   = file_size;
    CXFSOP_NP_FNODE_DISK_NO(cxfsop_np_fnode)  = disk_no;
    CXFSOP_NP_FNODE_BLOCK_NO(cxfsop_np_fnode) = block_no;
    CXFSOP_NP_FNODE_PAGE_NO(cxfsop_np_fnode)  = page_no;

    if(CXFSOP_MGR_USED(cxfsop_mgr) > CXFSOP_MGR_SIZE(cxfsop_mgr))
    {
        CXFSOP_MGR_USED(cxfsop_mgr) = CXFSOP_MGR_SIZE(cxfsop_mgr);
    }

    dbg_log(SEC_0213_CXFSOP, 9)(LOGSTDOUT, "[DEBUG] cxfsop_mgr_np_push_file_add_op: "
                                           "[NP][F] [ADD] %.*s, (disk %u, block %u, page %u, size %u) => used %lu\n",
                                           klen, key,
                                           disk_no, block_no, page_no, file_size, CXFSOP_MGR_USED(cxfsop_mgr));
    return (EC_TRUE);
}

EC_BOOL cxfsop_mgr_np_push_file_delete_op(CXFSOP_MGR        *cxfsop_mgr,
                                                   const uint16_t     klen,
                                                   const uint8_t     *key)
{
    void             *data;
    CXFSOP_NP_HDR    *cxfsop_np_hdr;
    uint32_t          klen_aligned;

    klen_aligned = VAL_ALIGN(klen, 8);

    if(CXFSOP_MGR_USED(cxfsop_mgr)
       + sizeof(CXFSOP_NP_HDR)
       + klen_aligned
       > CXFSOP_MGR_SIZE(cxfsop_mgr))
    {
        dbg_log(SEC_0213_CXFSOP, 0)(LOGSTDOUT, "error:cxfsop_mgr_np_push_file_delete_op: "
                                               "used %lu, size %lu => op mgr %p is full\n",
                                               CXFSOP_MGR_USED(cxfsop_mgr),
                                               CXFSOP_MGR_SIZE(cxfsop_mgr),
                                               cxfsop_mgr);
        CXFSOP_ASSERT(0);
        return (EC_FALSE);
    }

    data = CXFSOP_MGR_DATA(cxfsop_mgr) + CXFSOP_MGR_USED(cxfsop_mgr);
    cxfsop_np_hdr = (CXFSOP_NP_HDR *)data;

    CXFSOP_NP_HDR_TIME(cxfsop_np_hdr)     = c_get_cur_time_msec();
    CXFSOP_NP_HDR_MAGIC(cxfsop_np_hdr)    = CXFSOP_MAGIC_VAL;
    CXFSOP_NP_HDR_OP(cxfsop_np_hdr)       = CXFSOP_NP_F_DEL_OP;
    CXFSOP_NP_HDR_WILDCARD(cxfsop_np_hdr) = BIT_FALSE;
    CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr)     = __cxfsop_mgr_np_path_copy(klen, key, CXFSOP_NP_HDR_KEY(cxfsop_np_hdr));
    if(CXFSOP_KEY_MAX_LEN <= CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr))
    {
        dbg_log(SEC_0213_CXFSOP, 0)(LOGSTDOUT, "error:cxfsop_mgr_np_push_file_delete_op: "
                                               "[NP][F] [DEL] %.*s => klen %u >= %u => overflow!\n",
                                               klen, key,
                                               CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr),
                                               CXFSOP_KEY_MAX_LEN);
        return (EC_FALSE);
    }

    klen_aligned                          = VAL_ALIGN(CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr), 8); /*align to 8B*/
    CXFSOP_NP_HDR_SIZE(cxfsop_np_hdr)     = sizeof(CXFSOP_NP_HDR) + klen_aligned;
    if(CXFSOP_HDR_MAX_LEN <= CXFSOP_NP_HDR_SIZE(cxfsop_np_hdr))
    {
        dbg_log(SEC_0213_CXFSOP, 0)(LOGSTDOUT, "error:cxfsop_mgr_np_push_file_delete_op: "
                                               "[NP][F] [DEL] %.*s => hdr size %u >= %u => overflow!\n",
                                               klen, key,
                                               CXFSOP_NP_HDR_SIZE(cxfsop_np_hdr),
                                               CXFSOP_HDR_MAX_LEN);
        return (EC_FALSE);
    }

    CXFSOP_MGR_USED(cxfsop_mgr)          += CXFSOP_NP_HDR_SIZE(cxfsop_np_hdr);

    if(CXFSOP_MGR_USED(cxfsop_mgr) > CXFSOP_MGR_SIZE(cxfsop_mgr))
    {
        CXFSOP_MGR_USED(cxfsop_mgr) = CXFSOP_MGR_SIZE(cxfsop_mgr);
    }

    dbg_log(SEC_0213_CXFSOP, 9)(LOGSTDOUT, "[DEBUG] cxfsop_mgr_np_push_file_delete_op: "
                                           "[NP][F] [DEL] %.*s => used %lu\n",
                                           klen, key, CXFSOP_MGR_USED(cxfsop_mgr));
    return (EC_TRUE);
}

EC_BOOL cxfsop_mgr_np_push_file_wildcard_delete_op(CXFSOP_MGR       *cxfsop_mgr,
                                                               const uint16_t   klen,
                                                               const uint8_t   *key)
{
    void             *data;
    CXFSOP_NP_HDR    *cxfsop_np_hdr;
    uint32_t          klen_aligned;

    klen_aligned = VAL_ALIGN(klen, 8);

    if(CXFSOP_MGR_USED(cxfsop_mgr)
       + sizeof(CXFSOP_NP_HDR)
       + klen_aligned
       > CXFSOP_MGR_SIZE(cxfsop_mgr))
    {
        dbg_log(SEC_0213_CXFSOP, 0)(LOGSTDOUT, "error:cxfsop_mgr_np_push_file_wildcard_delete_op: "
                                               "used %lu, size %lu => op mgr %p is full\n",
                                               CXFSOP_MGR_USED(cxfsop_mgr),
                                               CXFSOP_MGR_SIZE(cxfsop_mgr),
                                               cxfsop_mgr);
        CXFSOP_ASSERT(0);
        return (EC_FALSE);
    }

    data = CXFSOP_MGR_DATA(cxfsop_mgr) + CXFSOP_MGR_USED(cxfsop_mgr);
    cxfsop_np_hdr = (CXFSOP_NP_HDR *)data;

    CXFSOP_NP_HDR_TIME(cxfsop_np_hdr)     = c_get_cur_time_msec();
    CXFSOP_NP_HDR_MAGIC(cxfsop_np_hdr)    = CXFSOP_MAGIC_VAL;
    CXFSOP_NP_HDR_OP(cxfsop_np_hdr)       = CXFSOP_NP_F_DEL_OP;
    CXFSOP_NP_HDR_WILDCARD(cxfsop_np_hdr) = BIT_TRUE;
    CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr)     = __cxfsop_mgr_np_path_copy(klen, key, CXFSOP_NP_HDR_KEY(cxfsop_np_hdr));
    if(CXFSOP_KEY_MAX_LEN <= CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr))
    {
        dbg_log(SEC_0213_CXFSOP, 0)(LOGSTDOUT, "error:cxfsop_mgr_np_push_file_wildcard_delete_op: "
                                               "[NP][F] [DEL] %.*s => klen %u >= %u => overflow!\n",
                                               klen, key,
                                               CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr),
                                               CXFSOP_KEY_MAX_LEN);
        return (EC_FALSE);
    }

    klen_aligned                          = VAL_ALIGN(CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr), 8); /*align to 8B*/
    CXFSOP_NP_HDR_SIZE(cxfsop_np_hdr)     = sizeof(CXFSOP_NP_HDR) + klen_aligned;
    if(CXFSOP_HDR_MAX_LEN <= CXFSOP_NP_HDR_SIZE(cxfsop_np_hdr))
    {
        dbg_log(SEC_0213_CXFSOP, 0)(LOGSTDOUT, "error:cxfsop_mgr_np_push_file_wildcard_delete_op: "
                                               "[NP][F] [DEL] %.*s => hdr size %u >= %u => overflow!\n",
                                               klen, key,
                                               CXFSOP_NP_HDR_SIZE(cxfsop_np_hdr),
                                               CXFSOP_HDR_MAX_LEN);
        return (EC_FALSE);
    }

    CXFSOP_MGR_USED(cxfsop_mgr)          += CXFSOP_NP_HDR_SIZE(cxfsop_np_hdr);

    if(CXFSOP_MGR_USED(cxfsop_mgr) > CXFSOP_MGR_SIZE(cxfsop_mgr))
    {
        CXFSOP_MGR_USED(cxfsop_mgr) = CXFSOP_MGR_SIZE(cxfsop_mgr);
    }

    dbg_log(SEC_0213_CXFSOP, 9)(LOGSTDOUT, "[DEBUG] cxfsop_mgr_np_push_file_wildcard_delete_op: "
                                           "[NP][F] [DEL] %.*s => used %lu\n",
                                           klen, key, CXFSOP_MGR_USED(cxfsop_mgr));

    return (EC_TRUE);
}

EC_BOOL cxfsop_mgr_np_push_file_update_op(CXFSOP_MGR      *cxfsop_mgr,
                                                    const uint16_t   klen,
                                                    const uint8_t   *key,
                                                    const uint32_t   file_size,
                                                    const uint16_t   disk_no,
                                                    const uint16_t   block_no,
                                                    const uint16_t   page_no)
{
    void             *data;
    CXFSOP_NP_HDR    *cxfsop_np_hdr;
    CXFSOP_NP_FNODE  *cxfsop_np_fnode;
    uint32_t          klen_aligned;

    klen_aligned = VAL_ALIGN(klen, 8);

    if(CXFSOP_MGR_USED(cxfsop_mgr)
       + sizeof(CXFSOP_NP_HDR)
       + klen_aligned
       + sizeof(CXFSOP_NP_FNODE)
       > CXFSOP_MGR_SIZE(cxfsop_mgr))
    {
        dbg_log(SEC_0213_CXFSOP, 0)(LOGSTDOUT, "error:cxfsop_mgr_np_push_file_update_op: "
                                               "used %lu, size %lu => op mgr %p is full\n",
                                               CXFSOP_MGR_USED(cxfsop_mgr),
                                               CXFSOP_MGR_SIZE(cxfsop_mgr),
                                               cxfsop_mgr);
        CXFSOP_ASSERT(0);
        return (EC_FALSE);
    }

    data = CXFSOP_MGR_DATA(cxfsop_mgr) + CXFSOP_MGR_USED(cxfsop_mgr);
    cxfsop_np_hdr = (CXFSOP_NP_HDR *)data;

    CXFSOP_NP_HDR_TIME(cxfsop_np_hdr)     = c_get_cur_time_msec();
    CXFSOP_NP_HDR_MAGIC(cxfsop_np_hdr)    = CXFSOP_MAGIC_VAL;
    CXFSOP_NP_HDR_OP(cxfsop_np_hdr)       = CXFSOP_NP_F_UPD_OP;
    CXFSOP_NP_HDR_WILDCARD(cxfsop_np_hdr) = BIT_FALSE;
    CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr)     = __cxfsop_mgr_np_path_copy(klen, key, CXFSOP_NP_HDR_KEY(cxfsop_np_hdr));
    if(CXFSOP_KEY_MAX_LEN <= CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr))
    {
        dbg_log(SEC_0213_CXFSOP, 0)(LOGSTDOUT, "error:cxfsop_mgr_np_push_file_update_op: "
                                               "[NP][F][UPD] %.*s => klen %u >= %u => overflow!\n",
                                               klen, key,
                                               CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr),
                                               CXFSOP_KEY_MAX_LEN);
        return (EC_FALSE);
    }

    klen_aligned                          = VAL_ALIGN(CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr), 8); /*align to 8B*/
    CXFSOP_NP_HDR_SIZE(cxfsop_np_hdr)     = sizeof(CXFSOP_NP_HDR) + klen_aligned + sizeof(CXFSOP_NP_FNODE);
    if(CXFSOP_HDR_MAX_LEN <= CXFSOP_NP_HDR_SIZE(cxfsop_np_hdr))
    {
        dbg_log(SEC_0213_CXFSOP, 0)(LOGSTDOUT, "error:cxfsop_mgr_np_push_file_update_op: "
                                               "[NP][F][UPD] %.*s => hdr size %u >= %u => overflow!\n",
                                               klen, key,
                                               CXFSOP_NP_HDR_SIZE(cxfsop_np_hdr),
                                               CXFSOP_HDR_MAX_LEN);
        return (EC_FALSE);
    }

    CXFSOP_MGR_USED(cxfsop_mgr)          += CXFSOP_NP_HDR_SIZE(cxfsop_np_hdr);

    data = CXFSOP_MGR_DATA(cxfsop_mgr) + CXFSOP_MGR_USED(cxfsop_mgr) - sizeof(CXFSOP_NP_FNODE);
    cxfsop_np_fnode = (CXFSOP_NP_FNODE *)data;

    CXFSOP_NP_FNODE_FILESZ(cxfsop_np_fnode)   = file_size;
    CXFSOP_NP_FNODE_DISK_NO(cxfsop_np_fnode)  = disk_no;
    CXFSOP_NP_FNODE_BLOCK_NO(cxfsop_np_fnode) = block_no;
    CXFSOP_NP_FNODE_PAGE_NO(cxfsop_np_fnode)  = page_no;

    if(CXFSOP_MGR_USED(cxfsop_mgr) > CXFSOP_MGR_SIZE(cxfsop_mgr))
    {
        CXFSOP_MGR_USED(cxfsop_mgr) = CXFSOP_MGR_SIZE(cxfsop_mgr);
    }

    dbg_log(SEC_0213_CXFSOP, 9)(LOGSTDOUT, "[DEBUG] cxfsop_mgr_np_push_file_update_op: "
                                           "[NP][F][UPD] %.*s, (disk %u, block %u, page %u, size %u) => used %lu\n",
                                           klen, key,
                                           disk_no, block_no, page_no, file_size, CXFSOP_MGR_USED(cxfsop_mgr));
    return (EC_TRUE);
}

EC_BOOL cxfsop_mgr_np_push_item_retire(CXFSOP_MGR      *cxfsop_mgr,
                                                const uint32_t   np_id,
                                                const uint32_t   node_pos)
{
    void             *data;
    CXFSOP_NP_ITEM   *cxfsop_np_item;

    if(CXFSOP_MGR_USED(cxfsop_mgr)
       + sizeof(CXFSOP_NP_ITEM)
       > CXFSOP_MGR_SIZE(cxfsop_mgr))
    {
        dbg_log(SEC_0213_CXFSOP, 0)(LOGSTDOUT, "error:cxfsop_mgr_np_push_item_retire: "
                                               "used %lu, size %lu => op mgr %p is full\n",
                                               CXFSOP_MGR_USED(cxfsop_mgr),
                                               CXFSOP_MGR_SIZE(cxfsop_mgr),
                                               cxfsop_mgr);
        CXFSOP_ASSERT(0);
        return (EC_FALSE);
    }

    data = CXFSOP_MGR_DATA(cxfsop_mgr) + CXFSOP_MGR_USED(cxfsop_mgr);
    cxfsop_np_item = (CXFSOP_NP_ITEM *)data;

    CXFSOP_NP_ITEM_TIME(cxfsop_np_item)       = c_get_cur_time_msec();
    CXFSOP_NP_ITEM_MAGIC(cxfsop_np_item)      = CXFSOP_MAGIC_VAL;
    CXFSOP_NP_ITEM_OP(cxfsop_np_item)         = CXFSOP_NP_I_RET_OP;
    CXFSOP_NP_ITEM_SIZE(cxfsop_np_item)       = sizeof(CXFSOP_NP_ITEM);

    CXFSOP_NP_ITEM_NP_ID(cxfsop_np_item)      = np_id;
    CXFSOP_NP_ITEM_NODE_POS(cxfsop_np_item)   = node_pos;

    CXFSOP_MGR_USED(cxfsop_mgr)              += CXFSOP_NP_ITEM_SIZE(cxfsop_np_item);


   dbg_log(SEC_0213_CXFSOP, 9)(LOGSTDOUT, "[DEBUG] cxfsop_mgr_np_push_item_retire: "
                                           "[NP][I][RET] np %u, node %u => used %lu\n",
                                           np_id, node_pos,
                                           CXFSOP_MGR_USED(cxfsop_mgr));

    return (EC_TRUE);
}

EC_BOOL cxfsop_mgr_np_push_item_recycle(CXFSOP_MGR      *cxfsop_mgr,
                                                  const uint32_t   np_id,
                                                  const uint32_t   node_pos)
{
    void             *data;
    CXFSOP_NP_ITEM   *cxfsop_np_item;

    if(CXFSOP_MGR_USED(cxfsop_mgr)
       + sizeof(CXFSOP_NP_ITEM)
       > CXFSOP_MGR_SIZE(cxfsop_mgr))
    {
        dbg_log(SEC_0213_CXFSOP, 0)(LOGSTDOUT, "error:cxfsop_mgr_np_push_item_recycle: "
                                               "used %lu, size %lu => op mgr %p is full\n",
                                               CXFSOP_MGR_USED(cxfsop_mgr),
                                               CXFSOP_MGR_SIZE(cxfsop_mgr),
                                               cxfsop_mgr);
        CXFSOP_ASSERT(0);
        return (EC_FALSE);
    }

    data = CXFSOP_MGR_DATA(cxfsop_mgr) + CXFSOP_MGR_USED(cxfsop_mgr);
    cxfsop_np_item = (CXFSOP_NP_ITEM *)data;

    CXFSOP_NP_ITEM_TIME(cxfsop_np_item)       = c_get_cur_time_msec();
    CXFSOP_NP_ITEM_MAGIC(cxfsop_np_item)      = CXFSOP_MAGIC_VAL;
    CXFSOP_NP_ITEM_OP(cxfsop_np_item)         = CXFSOP_NP_I_REC_OP;
    CXFSOP_NP_ITEM_SIZE(cxfsop_np_item)       = sizeof(CXFSOP_NP_ITEM);

    CXFSOP_NP_ITEM_NP_ID(cxfsop_np_item)      = np_id;
    CXFSOP_NP_ITEM_NODE_POS(cxfsop_np_item)   = node_pos;

    CXFSOP_MGR_USED(cxfsop_mgr)              += CXFSOP_NP_ITEM_SIZE(cxfsop_np_item);


   dbg_log(SEC_0213_CXFSOP, 9)(LOGSTDOUT, "[DEBUG] cxfsop_mgr_np_push_item_recycle: "
                                           "[NP][I][REC] np %u, node %u => used %lu\n",
                                           np_id, node_pos,
                                           CXFSOP_MGR_USED(cxfsop_mgr));
    return (EC_TRUE);
}

EC_BOOL cxfsop_mgr_dn_push_reserve_op(CXFSOP_MGR      *cxfsop_mgr,
                                                const uint32_t   data_size,
                                                const uint16_t   disk_no,
                                                const uint16_t   block_no,
                                                const uint16_t   page_no)
{
    void             *data;
    CXFSOP_DN_NODE   *cxfsop_dn_node;

    if(CXFSOP_MGR_USED(cxfsop_mgr)
       + sizeof(CXFSOP_DN_NODE)
       > CXFSOP_MGR_SIZE(cxfsop_mgr))
    {
        dbg_log(SEC_0213_CXFSOP, 0)(LOGSTDOUT, "error:cxfsop_mgr_dn_push_reserve_op: "
                                               "used %lu, size %lu => op mgr %p is full\n",
                                               CXFSOP_MGR_USED(cxfsop_mgr),
                                               CXFSOP_MGR_SIZE(cxfsop_mgr),
                                               cxfsop_mgr);
        CXFSOP_ASSERT(0);
        return (EC_FALSE);
    }

    data = CXFSOP_MGR_DATA(cxfsop_mgr) + CXFSOP_MGR_USED(cxfsop_mgr);
    cxfsop_dn_node = (CXFSOP_DN_NODE *)data;

    CXFSOP_DN_NODE_TIME(cxfsop_dn_node)       = c_get_cur_time_msec();
    CXFSOP_DN_NODE_MAGIC(cxfsop_dn_node)      = CXFSOP_MAGIC_VAL;
    CXFSOP_DN_NODE_OP(cxfsop_dn_node)         = CXFSOP_DN_RSV_OP;
    CXFSOP_DN_NODE_SIZE(cxfsop_dn_node)       = sizeof(CXFSOP_DN_NODE);

    CXFSOP_DN_NODE_DISK_NO(cxfsop_dn_node)    = disk_no;
    CXFSOP_DN_NODE_BLOCK_NO(cxfsop_dn_node)   = block_no;
    CXFSOP_DN_NODE_PAGE_NO(cxfsop_dn_node)    = page_no;
    CXFSOP_DN_NODE_DATA_LEN(cxfsop_dn_node)   = data_size;

    CXFSOP_MGR_USED(cxfsop_mgr)              += CXFSOP_DN_NODE_SIZE(cxfsop_dn_node);

    dbg_log(SEC_0213_CXFSOP, 9)(LOGSTDOUT, "[DEBUG] cxfsop_mgr_dn_push_reserve_op: "
                                           "[DN][RSV] (disk %u, block %u, page %u, size %u) => used %lu\n",
                                           disk_no, block_no, page_no, data_size,
                                           CXFSOP_MGR_USED(cxfsop_mgr));

    return (EC_TRUE);
}

EC_BOOL cxfsop_mgr_dn_push_release_op(CXFSOP_MGR *cxfsop_mgr,
                                                const uint32_t   data_size,
                                                const uint16_t   disk_no,
                                                const uint16_t   block_no,
                                                const uint16_t   page_no)
{
    void             *data;
    CXFSOP_DN_NODE   *cxfsop_dn_node;

    if(CXFSOP_MGR_USED(cxfsop_mgr)
       + sizeof(CXFSOP_DN_NODE)
       > CXFSOP_MGR_SIZE(cxfsop_mgr))
    {
        dbg_log(SEC_0213_CXFSOP, 0)(LOGSTDOUT, "error:cxfsop_mgr_dn_push_release_op: "
                                               "used %lu, size %lu => op mgr %p is full\n",
                                               CXFSOP_MGR_USED(cxfsop_mgr),
                                               CXFSOP_MGR_SIZE(cxfsop_mgr),
                                               cxfsop_mgr);
        CXFSOP_ASSERT(0);
        return (EC_FALSE);
    }

    data = CXFSOP_MGR_DATA(cxfsop_mgr) + CXFSOP_MGR_USED(cxfsop_mgr);
    cxfsop_dn_node = (CXFSOP_DN_NODE *)data;

    CXFSOP_DN_NODE_TIME(cxfsop_dn_node)       = c_get_cur_time_msec();
    CXFSOP_DN_NODE_MAGIC(cxfsop_dn_node)      = CXFSOP_MAGIC_VAL;
    CXFSOP_DN_NODE_OP(cxfsop_dn_node)         = CXFSOP_DN_REL_OP;
    CXFSOP_DN_NODE_SIZE(cxfsop_dn_node)       = sizeof(CXFSOP_DN_NODE);

    CXFSOP_DN_NODE_DISK_NO(cxfsop_dn_node)    = disk_no;
    CXFSOP_DN_NODE_BLOCK_NO(cxfsop_dn_node)   = block_no;
    CXFSOP_DN_NODE_PAGE_NO(cxfsop_dn_node)    = page_no;
    CXFSOP_DN_NODE_DATA_LEN(cxfsop_dn_node)   = data_size;

    CXFSOP_MGR_USED(cxfsop_mgr)              += CXFSOP_DN_NODE_SIZE(cxfsop_dn_node);

    dbg_log(SEC_0213_CXFSOP, 9)(LOGSTDOUT, "[DEBUG] cxfsop_mgr_dn_push_release_op: "
                                           "[DN][REL] (disk %u, block %u, page %u, size %u) => used %lu\n",
                                           disk_no, block_no, page_no, data_size,
                                           CXFSOP_MGR_USED(cxfsop_mgr));

    return (EC_TRUE);
}

EC_BOOL cxfsop_mgr_dn_push_recycle_op(CXFSOP_MGR *cxfsop_mgr,
                                                const uint32_t   data_size,
                                                const uint16_t   disk_no,
                                                const uint16_t   block_no,
                                                const uint16_t   page_no)
{
    void             *data;
    CXFSOP_DN_NODE   *cxfsop_dn_node;

    if(CXFSOP_MGR_USED(cxfsop_mgr)
       + sizeof(CXFSOP_DN_NODE)
       > CXFSOP_MGR_SIZE(cxfsop_mgr))
    {
        dbg_log(SEC_0213_CXFSOP, 0)(LOGSTDOUT, "error:cxfsop_mgr_dn_push_recycle_op: "
                                               "used %lu, size %lu => op mgr %p is full\n",
                                               CXFSOP_MGR_USED(cxfsop_mgr),
                                               CXFSOP_MGR_SIZE(cxfsop_mgr),
                                               cxfsop_mgr);
        CXFSOP_ASSERT(0);
        return (EC_FALSE);
    }

    data = CXFSOP_MGR_DATA(cxfsop_mgr) + CXFSOP_MGR_USED(cxfsop_mgr);
    cxfsop_dn_node = (CXFSOP_DN_NODE *)data;

    CXFSOP_DN_NODE_TIME(cxfsop_dn_node)       = c_get_cur_time_msec();
    CXFSOP_DN_NODE_MAGIC(cxfsop_dn_node)      = CXFSOP_MAGIC_VAL;
    CXFSOP_DN_NODE_OP(cxfsop_dn_node)         = CXFSOP_DN_REC_OP;
    CXFSOP_DN_NODE_SIZE(cxfsop_dn_node)       = sizeof(CXFSOP_DN_NODE);

    CXFSOP_DN_NODE_DISK_NO(cxfsop_dn_node)    = disk_no;
    CXFSOP_DN_NODE_BLOCK_NO(cxfsop_dn_node)   = block_no;
    CXFSOP_DN_NODE_PAGE_NO(cxfsop_dn_node)    = page_no;
    CXFSOP_DN_NODE_DATA_LEN(cxfsop_dn_node)   = data_size;

    CXFSOP_MGR_USED(cxfsop_mgr)              += CXFSOP_DN_NODE_SIZE(cxfsop_dn_node);

    dbg_log(SEC_0213_CXFSOP, 9)(LOGSTDOUT, "[DEBUG] cxfsop_mgr_dn_push_release_op: "
                                           "[DN][REC] (disk %u, block %u, page %u, size %u) => used %lu\n",
                                           disk_no, block_no, page_no, data_size,
                                           CXFSOP_MGR_USED(cxfsop_mgr));
    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/


