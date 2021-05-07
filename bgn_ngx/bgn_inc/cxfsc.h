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

#ifndef _CXFSC_H
#define _CXFSC_H

#include <stdlib.h>
#include <stdio.h>

#include "type.h"
#include "cstring.h"
#include "clist.h"

#include "cxfs.h"

#define CXFSC_REPLICA_NUM       (3)

typedef struct
{
    UINT32                      cxfs_tcid;
    UINT32                      cxfs_modi;

    /*extension*/
    EC_BOOL                     result;

}CXFSC_RNODE;

#define CXFSC_RNODE_CXFS_TCID(cxfsc_rnode)            ((cxfsc_rnode)->cxfs_tcid)
#define CXFSC_RNODE_CXFS_TCID_STR(cxfsc_rnode)        (c_word_to_ipv4(CXFSC_RNODE_CXFS_TCID(cxfsc_rnode)))
#define CXFSC_RNODE_CXFS_MODI(cxfsc_rnode)            ((cxfsc_rnode)->cxfs_modi)
#define CXFSC_RNODE_EXT_RESULT(cxfsc_rnode)           ((cxfsc_rnode)->result)

typedef struct
{
    /* used counter >= 0 */
    UINT32                      usedcounter;

    uint32_t                    rnode_pos;
    uint32_t                    rnode_num;
    CXFSC_RNODE                 rnode[ CXFSC_REPLICA_NUM ];
}CXFSC_MD;

#define CXFSC_MD_RNODE_POS(cxfsc_md)                  ((cxfsc_md)->rnode_pos)
#define CXFSC_MD_RNODE_NUM(cxfsc_md)                  ((cxfsc_md)->rnode_num)
#define CXFSC_MD_RNODE(cxfsc_md, idx)                 (&((cxfsc_md)->rnode[ (idx) ]))

/**
*   for test only
*
*   to query the status of CXFSC Module
*
**/
void cxfsc_print_module_status(const UINT32 cxfsc_md_id, LOG *log);

/**
*
*   free all static memory occupied by the appointed CXFSC module
*
*
**/
UINT32 cxfsc_free_module_static_mem(const UINT32 cxfsc_md_id);

/**
*
* start CXFSC module
*
**/
UINT32 cxfsc_start();

/**
*
* end CXFSC module
*
**/
void cxfsc_end(const UINT32 cxfsc_md_id);

CXFSC_RNODE *cxfsc_rnode_new();

EC_BOOL cxfsc_rnode_init(CXFSC_RNODE *cxfsc_rnode);

EC_BOOL cxfsc_rnode_clean(CXFSC_RNODE *cxfsc_rnode);

EC_BOOL cxfsc_rnode_free(CXFSC_RNODE *cxfsc_rnode);

EC_BOOL cxfsc_rnode_clone(const CXFSC_RNODE *cxfsc_rnode_src, CXFSC_RNODE *cxfsc_rnode_des);

CXFSC_RNODE *cxfsc_rnode_dup(const CXFSC_RNODE *cxfsc_rnode);

void cxfsc_rnode_print(LOG *log, const CXFSC_RNODE *cxfsc_rnode);

EC_BOOL cxfsc_rnode_is_active(const CXFSC_RNODE *cxfsc_rnode);

EC_BOOL cxfsc_reg_xfs(const UINT32 cxfsc_md_id);

EC_BOOL cxfsc_has_rnode(const UINT32 cxfsc_md_id, const UINT32 tcid, const UINT32 modi);

EC_BOOL cxfsc_reg_rnode(const UINT32 cxfsc_md_id, const UINT32 tcid, const UINT32 modi);

EC_BOOL cxfsc_file_size(const UINT32 cxfsc_md_id, const CSTRING *path_cstr, uint64_t *file_size);

EC_BOOL cxfsc_is_file(const UINT32 cxfsc_md_id, const CSTRING *file_path);

EC_BOOL cxfsc_delete_file(const UINT32 cxfsc_md_id, const CSTRING *path);

EC_BOOL cxfsc_truncate_file(const UINT32 cxfsc_md_id, const CSTRING *file_path, const UINT32 file_size);

EC_BOOL cxfsc_read_e(const UINT32 cxfsc_md_id, const CSTRING *file_path, UINT32 *offset, const UINT32 max_len, CBYTES *cbytes);

EC_BOOL cxfsc_write_e(const UINT32 cxfsc_md_id, const CSTRING *file_path, UINT32 *offset, const UINT32 max_len, const CBYTES *cbytes);

#endif /*_CXFSC_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/
