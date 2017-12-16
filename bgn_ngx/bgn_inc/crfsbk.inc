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

#ifndef _CRFSBK_INC
#define _CRFSBK_INC

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>

#include "type.h"
#include "log.h"

#include "cvector.h"
#include "cmutex.h"
#include "cstring.h"

#include "chashalgo.h"
#include "crfsnp.inc"
#include "crfsdn.h"
#include "cpgd.h"

#define CRFSBK_NP_ID             ((uint32_t) 0x4000)
#define CRFSBK_DISK_NO           ((uint32_t) 0x0000)
#define CRFSBK_NP_MODEL          (CRFSNP_001G_MODEL)
#define CRFSBK_HASH_ALGO_ID      (CHASH_JS_ALGO_ID) 

#define CRFSBK_ROOM_SAFE_LEVEL   ((REAL) 0.80) /*80%*/

#define CRFSOP_ERR_OP            ((uint16_t) 0x0000)
#define CRFSOP_WR_REG_OP         ((uint16_t) 0x0001)
#define CRFSOP_WR_BIG_OP         ((uint16_t) 0x0002)
#define CRFSOP_RM_REG_OP         ((uint16_t) 0x0004)
#define CRFSOP_RM_BIG_OP         ((uint16_t) 0x0008)
#define CRFSOP_RM_DIR_OP         ((uint16_t) 0x0010)

#define CRFSOP_PATH_IS_ERR       ((uint16_t) 0x0000)
#define CRFSOP_PATH_IS_DIR       ((uint16_t) 0x0002)
#define CRFSOP_PATH_IS_REG       ((uint16_t) 0x0008)
#define CRFSOP_PATH_IS_BIG       (CRFSOP_PATH_IS_REG | CRFSOP_PATH_IS_DIR)

typedef struct
{
    uint16_t   crfs_op;   /*WRITE / DELETE*/
    uint16_t   path_type; /*regular file, big file,dir*/
    uint32_t   path_hash;
    CSTRING    path_name;   
}CRFSOP;

#define CRFSOP_OP_TYPE(crfsop)       ((crfsop)->crfs_op)
#define CRFSOP_PATH_TYPE(crfsop)     ((crfsop)->path_type)
#define CRFSOP_PATH_HASH(crfsop)     ((crfsop)->path_hash)
#define CRFSOP_PATH_NAME(crfsop)     (&((crfsop)->path_name))
#define CRFSOP_PATH_STR(crfsop)      (cstring_get_str(CRFSOP_PATH_NAME(crfsop)))
#define CRFSOP_PATH_LEN(crfsop)      (cstring_get_len(CRFSOP_PATH_NAME(crfsop)))

typedef struct
{
    CSTRING    crfs_op_file; /*file name*/
    CLIST      crfs_op_list; /*order in timestamp*/
    CRB_TREE   crfs_op_tree; /*item is CLIST_DATA pointer, order in (path_hash, path_len, path_str)*/
}CRFSOPREC;

#define CRFSOPREC_FILE(crfsoprec)   (&((crfsoprec)->crfs_op_file))
#define CRFSOPREC_LIST(crfsoprec)   (&((crfsoprec)->crfs_op_list))
#define CRFSOPREC_TREE(crfsoprec)   (&((crfsoprec)->crfs_op_tree))

typedef struct
{
    UINT32             crfs_md_id;
    CRFSNP            *crfsnp;      /*np in disk cache  */
    CRFSDN            *crfsdn;      /*dn in disk cache  */
    CRFSOPREC          op_recorder; /*operation recorder*/

    CROUTINE_RWLOCK    crwlock;
}CRFSBK;

#define CRFSBK_CRFS_MD_ID(crfsbk)  ((crfsbk)->crfs_md_id)
#define CRFSBK_NP(crfsbk)          ((crfsbk)->crfsnp)
#define CRFSBK_DN(crfsbk)          ((crfsbk)->crfsdn)
#define CRFSBK_OP_REC(crfsbk)      (&((crfsbk)->op_recorder))
#define CRFSBK_CRWLOCK(crfsbk)     (&((crfsbk)->crwlock))

#define CRFSBK_INIT_LOCK(crfsbk, location)  (croutine_rwlock_init(CRFSBK_CRWLOCK(crfsbk), CMUTEX_PROCESS_PRIVATE, location))
#define CRFSBK_CLEAN_LOCK(crfsbk, location) (croutine_rwlock_clean(CRFSBK_CRWLOCK(crfsbk), location))

#define CRFSBK_RDLOCK(crfsbk, location)     (croutine_rwlock_rdlock(CRFSBK_CRWLOCK(crfsbk), location))
#define CRFSBK_WRLOCK(crfsbk, location)     (croutine_rwlock_wrlock(CRFSBK_CRWLOCK(crfsbk), location))
#define CRFSBK_UNLOCK(crfsbk, location)     (croutine_rwlock_unlock(CRFSBK_CRWLOCK(crfsbk), location))

#endif/* _CRFSBK_INC */

#ifdef __cplusplus
}
#endif/*__cplusplus*/

