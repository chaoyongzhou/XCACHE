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

#ifndef _CRFSDT_INC
#define _CRFSDT_INC

#include <stdlib.h>
#include <stdio.h>

#include "type.h"
#include "log.h"
#include "cstring.h"
#include "clist.h"
#include "cvector.h"
#include "crfsconhash.inc"
#include "mod.inc"


/*RFS list info of a path*/
typedef struct
{
    CSTRING       path;
    CRFSCONHASH   crfsconhash;   /*path in which mod_mgr*/
}CRFSDT_PNODE;

#define CRFSDT_PNODE_PATH(crfsdt_pnode)      (&((crfsdt_pnode)->path))
#define CRFSDT_PNODE_CONHASH(crfsdt_pnode)   (&((crfsdt_pnode)->crfsconhash))


#define CRFSDT_PNODE_PATH_STR(crfsdt_pnode)  ((char *)cstring_get_str(CRFSDT_PNODE_PATH(crfsdt_pnode)))
#define CRFSDT_PNODE_PATH_LEN(crfsdt_pnode)  (cstring_get_len(CRFSDT_PNODE_PATH(crfsdt_pnode)))

//#define CRFSDT_PNODE_HASH_COMPUTE(len, str)  ((uint32_t)JS_hash(len, str))


/*path list info of a RFS*/
typedef struct
{
    UINT32       tcid;
    CRB_TREE     path_tree; /*item is path string*/
}CRFSDT_RNODE;

#define CRFSDT_RNODE_TCID(crfsdt_rnode)      ((crfsdt_rnode)->tcid)
#define CRFSDT_RNODE_PATH_TREE(crfsdt_rnode) (&((crfsdt_rnode)->path_tree))

typedef struct
{
    CROUTINE_RWLOCK  crwlock;
    CRB_TREE         pnode_tree; /*item is CRFSDT_PNODE. order in (path hash, path name)*/
    CRB_TREE         rnode_tree; /*item is CRFSDT_RNODE. order in (rfs tcid)*/
}CRFSDT;

#define CRFSDT_CRWLOCK(crfsdt)             (&((crfsdt)->crwlock))
#define CRFSDT_PNODE_TREE(crfsdt)          (&((crfsdt)->pnode_tree))
#define CRFSDT_RNODE_TREE(crfsdt)          (&((crfsdt)->rnode_tree))

#define CRFSDT_CRWLOCK_INIT(crfsdt, location)           (croutine_rwlock_init(CRFSDT_CRWLOCK(crfsdt), CMUTEX_PROCESS_PRIVATE, location))
#define CRFSDT_CRWLOCK_CLEAN(crfsdt, location)          (croutine_rwlock_clean(CRFSDT_CRWLOCK(crfsdt), location))
#define CRFSDT_CRWLOCK_RDLOCK(crfsdt, location)         (croutine_rwlock_rdlock(CRFSDT_CRWLOCK(crfsdt), location))
#define CRFSDT_CRWLOCK_WRLOCK(crfsdt, location)         (croutine_rwlock_wrlock(CRFSDT_CRWLOCK(crfsdt), location))
#define CRFSDT_CRWLOCK_UNLOCK(crfsdt, location)         (croutine_rwlock_unlock(CRFSDT_CRWLOCK(crfsdt), location))

#endif /*_CRFSDT_INC*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

