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

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <sys/mman.h>

#include <sys/stat.h>

#include <fuse.h>

#include "type.h"
#include "mm.h"
#include "log.h"

#include "cbc.h"
#include "ctimer.h"
#include "cbtimer.h"
#include "cmisc.h"

#include "real.h"

#include "task.h"
#include "coroutine.h"

#include "cmpie.h"

#include "crb.h"
#include "crange.h"
#include "cxfs.h"
#include "cxfsfuses.h"

#include "findex.inc"


#define CXFS_MD_CAPACITY()                  (cbc_md_capacity(MD_CXFS))

#define CXFS_MD_GET(cxfs_md_id)     ((CXFS_MD *)cbc_md_get(MD_CXFS, (cxfs_md_id)))

#define CXFS_MD_ID_CHECK_INVALID(cxfs_md_id)  \
    ((CMPI_ANY_MODI != (cxfs_md_id)) && ((NULL_PTR == CXFS_MD_GET(cxfs_md_id)) || (0 == (CXFS_MD_GET(cxfs_md_id)->usedcounter))))

#define CXFS_FUSES_DEBUG_ENTER(func_name) \
    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] " func_name ": enter\n")

#define CXFS_FUSES_DEBUG_LEAVE(func_name) \
    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] " func_name ": leave\n")


#define CXFS_FUSES_CHECK_ENV(cxfs_md_id, cxfs_md, func_name, res) do{       \
    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))                                    \
    {                                                                       \
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:" func_name ": "         \
                                             "npp was not open\n");         \
        (*res) = -EACCES;                                                   \
        return (EC_TRUE);                                                   \
    }                                                                       \
                                                                            \
    if(BIT_TRUE == CXFS_MD_OP_REPLAY_FLAG(cxfs_md))                         \
    {                                                                       \
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:" func_name ": "        \
                                             "xfs is in op-replay mode\n"); \
        (*res) = -EBUSY;                                                    \
        return (EC_TRUE);                                                   \
    }                                                                       \
                                                                            \
    if(EC_FALSE == cxfs_sync_wait(cxfs_md_id))                              \
    {                                                                       \
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:" func_name ": "        \
                                             "wait syncing timeout\n");     \
        (*res) = -EBUSY;                                                    \
        return (EC_TRUE);                                                   \
    }                                                                       \
}while(0)

STATIC_CAST EC_BOOL __cxfs_fuses_check_access(const UINT32 cxfs_md_id, const char *path, const uint64_t ino, const uint32_t mode, const uint32_t uid, const uint32_t gid)
{
    CXFS_MD         *cxfs_md;
    CXFSNP_ITEM     *cxfsnp_item;
    CXFSNP_ATTR     *cxfsnp_attr;

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    cxfsnp_item = cxfsnp_mgr_fetch_item(CXFS_MD_NPP(cxfs_md), ino);
    cxfsnp_attr = CXFSNP_ITEM_ATTR(cxfsnp_item);

    if(0 == uid || 0 == gid)
    {
        if(O_RDONLY == mode)
        {
            CXFSNP_ITEM     *cxfsnp_item_parent;
            CXFSNP_ATTR     *cxfsnp_attr_parent;

            if(0 == (CXFSNP_ATTR_MODE(cxfsnp_attr) & (S_IRUSR | S_IRGRP | S_IROTH)))
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fuses_check_access: "
                                 "dir '%s', "
                                 "(mode %#o, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) "
                                 "=> uid = 0 or gid = 0, "
                                 "mode & (S_IRUSR | S_IRGRP | S_IROTH) == 0\n",
                                 path, mode, uid, gid,
                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                 CXFSNP_ATTR_GID(cxfsnp_attr));

                return (EC_FALSE);
            }

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fuses_check_access: "
                             "dir '%s', "
                             "(mode %#o, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) "
                             "=> uid = 0 or gid = 0, "
                             "mode & (S_IRUSR | S_IRGRP | S_IROTH) != 0 => check parent\n",
                             path, mode, uid, gid,
                             CXFSNP_ATTR_MODE(cxfsnp_attr),
                             CXFSNP_ATTR_UID(cxfsnp_attr),
                             CXFSNP_ATTR_GID(cxfsnp_attr));

            cxfsnp_item_parent = cxfsnp_mgr_fetch_parent_item(CXFS_MD_NPP(cxfs_md), ino);
            cxfsnp_attr_parent = CXFSNP_ITEM_ATTR(cxfsnp_item_parent);

            if(0 == (S_IXUSR & CXFSNP_ATTR_MODE(cxfsnp_attr_parent)))
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fuses_check_access: "
                                 "dir '%s', "
                                 "(mode %#o, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) "
                                 "=> uid = 0 or gid = 0, "
                                 "parent mode %#o & S_IXUSR == 0\n",
                                 path, mode, uid, gid,
                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                 CXFSNP_ATTR_GID(cxfsnp_attr),
                                 CXFSNP_ATTR_MODE(cxfsnp_attr_parent));

                return (EC_FALSE);
            }

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fuses_check_access: "
                             "dir '%s', "
                             "(mode %#o, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) "
                             "=> uid = 0 or gid = 0, "
                             "parent mode %#o & S_IXUSR != 0\n",
                             path, mode, uid, gid,
                             CXFSNP_ATTR_MODE(cxfsnp_attr),
                             CXFSNP_ATTR_UID(cxfsnp_attr),
                             CXFSNP_ATTR_GID(cxfsnp_attr),
                             CXFSNP_ATTR_MODE(cxfsnp_attr_parent));

            return (EC_TRUE);
        }
        else
        {
            if(0 == (CXFSNP_ATTR_MODE(cxfsnp_attr) & (S_IWUSR | S_IWGRP | S_IWOTH)))
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fuses_check_access: "
                                                     "dir '%s', "
                                                     "(mode %#o, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) "
                                                     "its mode %#o & (S_IWUSR | S_IWGRP S_IWOTH) == 0\n",
                                                     path, mode, uid, gid,
                                                     CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                     CXFSNP_ATTR_UID(cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(cxfsnp_attr));

                return (EC_FALSE);
            }

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fuses_check_access: "
                                                 "dir '%s', "
                                                 "(mode %#o, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) "
                                                 "its mode %#o & (S_IWUSR | S_IWGRP S_IWOTH) == 0\n",
                                                 path, mode, uid, gid,
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr));

            return (EC_TRUE);
        }
    }

    if(uid == CXFSNP_ATTR_UID(cxfsnp_attr) && gid == CXFSNP_ATTR_GID(cxfsnp_attr))
    {
        if(O_RDONLY == mode)
        {
            CXFSNP_ITEM     *cxfsnp_item_parent;
            CXFSNP_ATTR     *cxfsnp_attr_parent;

            if(0 == (CXFSNP_ATTR_MODE(cxfsnp_attr) & (S_IRUSR)))
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fuses_check_access: "
                                 "dir '%s', "
                                 "(mode %#o, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) "
                                 "=> uid = 0 or gid = 0, "
                                 "mode & (S_IRUSR) == 0\n",
                                 path, mode, uid, gid,
                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                 CXFSNP_ATTR_GID(cxfsnp_attr));

                return (EC_FALSE);
            }

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fuses_check_access: "
                             "dir '%s', "
                             "(mode %#o, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) "
                             "=> uid = 0 or gid = 0, "
                             "mode & (S_IRUSR) != 0 => check parent\n",
                             path, mode, uid, gid,
                             CXFSNP_ATTR_MODE(cxfsnp_attr),
                             CXFSNP_ATTR_UID(cxfsnp_attr),
                             CXFSNP_ATTR_GID(cxfsnp_attr));

            cxfsnp_item_parent = cxfsnp_mgr_fetch_parent_item(CXFS_MD_NPP(cxfs_md), ino);
            cxfsnp_attr_parent = CXFSNP_ITEM_ATTR(cxfsnp_item_parent);

            if(0 == (S_IXUSR & CXFSNP_ATTR_MODE(cxfsnp_attr_parent)))
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fuses_check_access: "
                                 "dir '%s', "
                                 "(mode %#o, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) "
                                 "=> uid = 0 or gid = 0, "
                                 "parent mode %#o & S_IXUSR == 0\n",
                                 path, mode, uid, gid,
                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                 CXFSNP_ATTR_GID(cxfsnp_attr),
                                 CXFSNP_ATTR_MODE(cxfsnp_attr_parent));

                return (EC_FALSE);
            }

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fuses_check_access: "
                             "dir '%s', "
                             "(mode %#o, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) "
                             "=> uid = 0 or gid = 0, "
                             "parent mode %#o & S_IXUSR != 0\n",
                             path, mode, uid, gid,
                             CXFSNP_ATTR_MODE(cxfsnp_attr),
                             CXFSNP_ATTR_UID(cxfsnp_attr),
                             CXFSNP_ATTR_GID(cxfsnp_attr),
                             CXFSNP_ATTR_MODE(cxfsnp_attr_parent));

            return (EC_TRUE);
        }
        else
        {
            if(0 == (CXFSNP_ATTR_MODE(cxfsnp_attr) & (S_IWUSR)))
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fuses_check_access: "
                                 "dir '%s', "
                                 "(mode %#o, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) => uid & gid matched, "
                                 "mode & S_IWUSR == 0\n",
                                 path, mode, uid, gid,
                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                 CXFSNP_ATTR_GID(cxfsnp_attr));

                return (EC_FALSE);
            }

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fuses_check_access: "
                             "dir '%s', "
                             "(mode %#o, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) => uid & gid matched, "
                             "mode & S_IWUSR != 0\n",
                             path, mode, uid, gid,
                             CXFSNP_ATTR_MODE(cxfsnp_attr),
                             CXFSNP_ATTR_UID(cxfsnp_attr),
                             CXFSNP_ATTR_GID(cxfsnp_attr));

            return (EC_TRUE);
        }
    }

    if(gid == CXFSNP_ATTR_GID(cxfsnp_attr))
    {
        if(O_RDONLY == mode)
        {
            CXFSNP_ITEM     *cxfsnp_item_parent;
            CXFSNP_ATTR     *cxfsnp_attr_parent;

            if(0 == (CXFSNP_ATTR_MODE(cxfsnp_attr) & (S_IRGRP)))
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fuses_check_access: "
                                 "dir '%s', "
                                 "(mode %#o, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) "
                                 "=> uid = 0 or gid = 0, "
                                 "mode & (S_IRGRP) == 0\n",
                                 path, mode, uid, gid,
                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                 CXFSNP_ATTR_GID(cxfsnp_attr));

                return (EC_FALSE);
            }

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fuses_check_access: "
                             "dir '%s', "
                             "(mode %#o, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) "
                             "=> uid = 0 or gid = 0, "
                             "mode & (S_IRGRP) != 0 => check parent\n",
                             path, mode, uid, gid,
                             CXFSNP_ATTR_MODE(cxfsnp_attr),
                             CXFSNP_ATTR_UID(cxfsnp_attr),
                             CXFSNP_ATTR_GID(cxfsnp_attr));

            cxfsnp_item_parent = cxfsnp_mgr_fetch_parent_item(CXFS_MD_NPP(cxfs_md), ino);
            cxfsnp_attr_parent = CXFSNP_ITEM_ATTR(cxfsnp_item_parent);

            if(0 == (S_IXUSR & CXFSNP_ATTR_MODE(cxfsnp_attr_parent)))
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fuses_check_access: "
                                 "dir '%s', "
                                 "(mode %#o, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) "
                                 "=> uid = 0 or gid = 0, "
                                 "parent mode %#o & S_IXUSR == 0\n",
                                 path, mode, uid, gid,
                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                 CXFSNP_ATTR_GID(cxfsnp_attr),
                                 CXFSNP_ATTR_MODE(cxfsnp_attr_parent));

                return (EC_FALSE);
            }

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fuses_check_access: "
                             "dir '%s', "
                             "(mode %#o, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) "
                             "=> uid = 0 or gid = 0, "
                             "parent mode %#o & S_IXUSR != 0\n",
                             path, mode, uid, gid,
                             CXFSNP_ATTR_MODE(cxfsnp_attr),
                             CXFSNP_ATTR_UID(cxfsnp_attr),
                             CXFSNP_ATTR_GID(cxfsnp_attr),
                             CXFSNP_ATTR_MODE(cxfsnp_attr_parent));

            return (EC_TRUE);
        }
        else
        {
            if(0 == (CXFSNP_ATTR_MODE(cxfsnp_attr) & (S_IWGRP)))
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fuses_check_access: "
                                 "dir '%s', "
                                 "(mode %#o, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) => gid matched, "
                                 "mode & S_IWGRP == 0\n",
                                 path, mode, uid, gid,
                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                 CXFSNP_ATTR_GID(cxfsnp_attr));

                return (EC_FALSE);
            }

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fuses_check_access: "
                             "dir '%s', "
                             "(mode %#o, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) => gid matched, "
                             "mode & S_IWGRP != 0\n",
                             path, mode, uid, gid,
                             CXFSNP_ATTR_MODE(cxfsnp_attr),
                             CXFSNP_ATTR_UID(cxfsnp_attr),
                             CXFSNP_ATTR_GID(cxfsnp_attr));

            return (EC_TRUE);
        }
    }


    /*other*/
    if(O_RDONLY == mode)
    {
        CXFSNP_ITEM     *cxfsnp_item_parent;
        CXFSNP_ATTR     *cxfsnp_attr_parent;

        if(0 == (CXFSNP_ATTR_MODE(cxfsnp_attr) & (S_IROTH)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fuses_check_access: "
                             "dir '%s', "
                             "(mode %#o, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) "
                             "=> uid = 0 or gid = 0, "
                             "mode & (S_IROTH) == 0\n",
                             path, mode, uid, gid,
                             CXFSNP_ATTR_MODE(cxfsnp_attr),
                             CXFSNP_ATTR_UID(cxfsnp_attr),
                             CXFSNP_ATTR_GID(cxfsnp_attr));

            return (EC_FALSE);
        }

        dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fuses_check_access: "
                         "dir '%s', "
                         "(mode %#o, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) "
                         "=> uid = 0 or gid = 0, "
                         "mode & (S_IROTH) != 0 => check parent\n",
                         path, mode, uid, gid,
                         CXFSNP_ATTR_MODE(cxfsnp_attr),
                         CXFSNP_ATTR_UID(cxfsnp_attr),
                         CXFSNP_ATTR_GID(cxfsnp_attr));

        cxfsnp_item_parent = cxfsnp_mgr_fetch_parent_item(CXFS_MD_NPP(cxfs_md), ino);
        cxfsnp_attr_parent = CXFSNP_ITEM_ATTR(cxfsnp_item_parent);

        if(0 == (S_IXUSR & CXFSNP_ATTR_MODE(cxfsnp_attr_parent)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fuses_check_access: "
                             "dir '%s', "
                             "(mode %#o, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) "
                             "=> uid = 0 or gid = 0, "
                             "parent mode %#o & S_IXUSR == 0\n",
                             path, mode, uid, gid,
                             CXFSNP_ATTR_MODE(cxfsnp_attr),
                             CXFSNP_ATTR_UID(cxfsnp_attr),
                             CXFSNP_ATTR_GID(cxfsnp_attr),
                             CXFSNP_ATTR_MODE(cxfsnp_attr_parent));

            return (EC_FALSE);
        }

        dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fuses_check_access: "
                         "dir '%s', "
                         "(mode %#o, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) "
                         "=> uid = 0 or gid = 0, "
                         "parent mode %#o & S_IXUSR != 0\n",
                         path, mode, uid, gid,
                         CXFSNP_ATTR_MODE(cxfsnp_attr),
                         CXFSNP_ATTR_UID(cxfsnp_attr),
                         CXFSNP_ATTR_GID(cxfsnp_attr),
                         CXFSNP_ATTR_MODE(cxfsnp_attr_parent));

        return (EC_TRUE);
    }
    else
    {
        if(0 == (CXFSNP_ATTR_MODE(cxfsnp_attr) & (S_IWOTH)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fuses_check_access: "
                             "dir '%s', "
                             "(mode %#o, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) => not matched\n",
                             path, mode, uid, gid,
                             CXFSNP_ATTR_MODE(cxfsnp_attr),
                             CXFSNP_ATTR_UID(cxfsnp_attr),
                             CXFSNP_ATTR_GID(cxfsnp_attr));

            return (EC_FALSE);
        }

        dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fuses_check_access: "
                         "dir '%s', "
                         "(mode %#o, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) => other, "
                         "mode & S_IWOTH != 0\n",
                         path, mode, uid, gid,
                         CXFSNP_ATTR_MODE(cxfsnp_attr),
                         CXFSNP_ATTR_UID(cxfsnp_attr),
                         CXFSNP_ATTR_GID(cxfsnp_attr));

        return (EC_TRUE);
    }

    /*should never reach here*/
    return (EC_FALSE);
}

STATIC_CAST EC_BOOL __cxfs_fuses_dn_resize(const UINT32 cxfs_md_id, const uint32_t old_size, const uint32_t new_size)
{
    CXFS_MD         *cxfs_md;
    CXFSPGV         *cxfspgv;
    uint64_t         used_size;

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    cxfspgv = CXFSDN_CXFSPGV(CXFS_MD_DN(cxfs_md));
    ASSERT(NULL_PTR != cxfspgv);

    used_size = CXFSPGV_PAGE_ACTUAL_USED_SIZE(cxfspgv);

    CXFSPGV_PAGE_ACTUAL_USED_SIZE(cxfspgv) -= old_size;
    CXFSPGV_PAGE_ACTUAL_USED_SIZE(cxfspgv) += new_size;

    dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "[DEBUG] __cxfs_fuses_dn_resize: "
                                         "pgv_actual_used_size: %ld = %ld - %u + %u\n",
                                         CXFSPGV_PAGE_ACTUAL_USED_SIZE(cxfspgv),
                                         used_size, old_size, new_size);

    return (EC_TRUE);
}

STATIC_CAST EC_BOOL __cxfs_fuses_npp_resize(const UINT32 cxfs_md_id, const uint64_t ino, const uint32_t old_size, const uint32_t new_size)
{
    CXFS_MD         *cxfs_md;

    cxfs_md = CXFS_MD_GET(cxfs_md_id);
    cxfsnp_mgr_resize(CXFS_MD_NPP(cxfs_md), ino, old_size, new_size);

    dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "[DEBUG] __cxfs_fuses_npp_resize: "
                                         "file size %u => %u\n",
                                         old_size, new_size);

    return (EC_TRUE);
}

STATIC_CAST CXFSNP_ITEM *__cxfs_fuses_lookup(const UINT32 cxfs_md_id, const CSTRING *path, uint64_t *ino)
{
    CXFS_MD         *cxfs_md;
    CXFSNP_ITEM     *cxfsnp_item;
    uint64_t         ino_t;

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    CXFS_STAT_READ_COUNTER(CXFS_MD_STAT(cxfs_md)) ++;

    if(EC_FALSE == cxfsnp_mgr_ino(CXFS_MD_NPP(cxfs_md), path, CXFSNP_ITEM_FILE_IS_DIR, &ino_t))
    {
        return (NULL_PTR);
    }

    cxfsnp_item = cxfsnp_mgr_fetch_item(CXFS_MD_NPP(cxfs_md), ino_t);
    if(NULL_PTR != cxfsnp_item && NULL_PTR != ino)
    {
        (*ino) = ino_t;
    }

    return (cxfsnp_item);
}

STATIC_CAST CXFSNP_ITEM *__cxfs_fuses_lookup_seg(const UINT32 cxfs_md_id, const CSTRING *path, uint64_t *ino)
{
    CXFS_MD         *cxfs_md;
    CXFSNP_ITEM     *cxfsnp_item;
    uint64_t         ino_t;

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    CXFS_STAT_READ_COUNTER(CXFS_MD_STAT(cxfs_md)) ++;

    if(EC_FALSE == cxfsnp_mgr_ino(CXFS_MD_NPP(cxfs_md), path, CXFSNP_ITEM_FILE_IS_REG, &ino_t))
    {
        return (NULL_PTR);
    }

    cxfsnp_item = cxfsnp_mgr_fetch_item(CXFS_MD_NPP(cxfs_md), ino_t);
    if(NULL_PTR != cxfsnp_item && NULL_PTR != ino)
    {
        (*ino) = ino_t;
    }

    return (cxfsnp_item);
}


STATIC_CAST EC_BOOL __cxfs_fuses_make_empty_hidden_seg(const UINT32 cxfs_md_id, const CSTRING *path, int *res)
{
    CSTRING     *seg_path;
    UINT32       seg_no;
    UINT32       seg_size;

    seg_size = 0;
    seg_no   = 0; /*prevent it from xfs recycling empty dir*/

    seg_path = cstring_make("%s/%ld", cstring_get_str(path), seg_no);
    if(NULL_PTR == seg_path)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_fuses_make_empty_hidden_seg: "
                                             "make seg path %s/%ld failed\n",
                                             (char *)cstring_get_str(path),
                                             seg_no);
        (*res) = -ENOMEM;
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfs_reserve(cxfs_md_id, seg_path, seg_size))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_fuses_make_empty_hidden_seg: "
                                             "reserve empty seg file %s/%ld failed\n",
                                             (char *)cstring_get_str(path),
                                             seg_no);
        (*res) = -ENOENT;
        return (EC_FALSE);
    }

    cstring_free(seg_path);

    dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fuses_make_empty_hidden_seg: "
                                         "reserve empty seg file %s/%ld done\n",
                                         (char *)cstring_get_str(path),
                                         seg_no);

    return (EC_TRUE);
}

EC_BOOL cxfs_fuses_getattr(const UINT32 cxfs_md_id, const CSTRING *file_path, struct stat *stat, int *res)
{
    CXFS_MD      *cxfs_md;
    CXFSNP_ITEM  *cxfsnp_item;

    uint64_t      ino;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_fuses_getattr: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    CXFS_FUSES_DEBUG_ENTER("cxfs_fuses_getattr");

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    CXFS_FUSES_CHECK_ENV(cxfs_md_id, cxfs_md, "cxfs_fuses_getattr", res);

    cxfsnp_item = __cxfs_fuses_lookup(cxfs_md_id, file_path, &ino);
    if(NULL_PTR == cxfsnp_item)
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_fuses_getattr: "
                                             "%s not exist\n",
                                             (char *)cstring_get_str(file_path));

        (*res) = -ENOENT;
        return (EC_TRUE);
    }

    if(NULL_PTR != stat)
    {
        CXFSNP_ATTR  *cxfsnp_attr;
        CXFSNP_DNODE *cxfsnp_dnode;

        cxfsnp_attr  = CXFSNP_ITEM_ATTR(cxfsnp_item);
        cxfsnp_dnode = CXFSNP_ITEM_DNODE(cxfsnp_item);

        stat->st_ino        = ino;

        stat->st_mode       = CXFSNP_ATTR_MODE(cxfsnp_attr);
        stat->st_uid        = CXFSNP_ATTR_UID(cxfsnp_attr);
        stat->st_gid        = CXFSNP_ATTR_GID(cxfsnp_attr);
        stat->st_rdev       = CXFSNP_ATTR_RDEV(cxfsnp_attr);

        stat->st_atime      = CXFSNP_ATTR_ATIME_SEC(cxfsnp_attr);
        stat->st_mtime      = CXFSNP_ATTR_MTIME_SEC(cxfsnp_attr);
        stat->st_ctime      = CXFSNP_ATTR_CTIME_SEC(cxfsnp_attr);
        stat->st_nlink      = CXFSNP_ATTR_NLINK(cxfsnp_attr);

        stat->st_dev        = 0;/*xxx*/

        if(CXFSNP_ATTR_FUSES_IS_REG == CXFSNP_ATTR_FLAG(cxfsnp_attr))
        {
            stat->st_size       = CXFSNP_DNODE_FILE_SIZE(cxfsnp_dnode); /*xxx*/
            stat->st_blksize    = CXFS_FUSES_BLOCK_SIZE; /*xxx*/
            stat->st_blocks     = CXFS_FUSES_SECTOR_NUM(CXFSNP_DNODE_FILE_SIZE(cxfsnp_dnode));
        }

        else if(CXFSNP_ATTR_FUSES_IS_DIR == CXFSNP_ATTR_FLAG(cxfsnp_attr))
        {
            stat->st_size       = CXFSNP_DNODE_FILE_SIZE(cxfsnp_dnode); /*xxx*/
            stat->st_blksize    = CXFS_FUSES_BLOCK_SIZE; /*xxx*/
            stat->st_blocks     = CXFS_FUSES_SECTOR_NUM(CXFSNP_DNODE_FILE_SIZE(cxfsnp_dnode));
        }
        else
        {
            /*never reach here*/
        }
    }

    (*res) = 0;
    return (EC_TRUE);
}

EC_BOOL cxfs_fuses_readlink(const UINT32 cxfs_md_id, const CSTRING *path, CSTRING *buf, const UINT32 bufsize, int *res)
{
    CXFS_MD      *cxfs_md;

    CXFSNP_ITEM  *cxfsnp_item;
    uint64_t      ino;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_fuses_readlink: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    CXFS_FUSES_DEBUG_ENTER("cxfs_fuses_readlink");

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    CXFS_FUSES_CHECK_ENV(cxfs_md_id, cxfs_md, "cxfs_fuses_readlink", res);

    if(0 == bufsize)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_readlink: bufsize is zero\n");
        (*res) = -EINVAL;
        return (EC_TRUE);
    }

    cstring_clean(buf);

    cxfsnp_item = __cxfs_fuses_lookup(cxfs_md_id, path, &ino);
    if(NULL_PTR != cxfsnp_item)
    {
        CSTRING         link_path;

        CXFSNP_ATTR    *cxfsnp_attr;

        cstring_init(&link_path, NULL_PTR);

        cxfsnp_attr  = CXFSNP_ITEM_ATTR(cxfsnp_item);

        if(EC_FALSE == cxfsnp_mgr_relative_path(CXFS_MD_NPP(cxfs_md),
                                                CXFSNP_ATTR_INO_FETCH_NODE_POS(ino),
                                                CXFSNP_ATTR_NEXT_INO(cxfsnp_attr),
                                                &link_path))
        {
            (*res) = -ENOENT;
            cstring_clean(&link_path);
            return (EC_TRUE);
        }

        do
        {
            UINT8          *str;
            UINT32          len;
            UINT32          capacity;

            cstring_umount(&link_path, &str, &len, &capacity);
            if(len >= bufsize)
            {
                len = bufsize - 1;
            }

            while(0 < len && '/' == str[ len - 1])
            {
                len --;
            }
            str[ len ] = '\0';

            cstring_mount(buf, str, len, capacity);
        }while(0);

        cstring_clean(&link_path);

        dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_readlink: "
                                             "%s -> %s done\n",
                                             (char *)cstring_get_str(path),
                                             (char *)cstring_get_str(buf));

        (*res) = 0;
        return (EC_TRUE);
    }

    dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_readlink: "
                                         "src %s not exist => reallink failed\n",
                                         (char *)cstring_get_str(path));

    (*res) = -ENOENT;

    return (EC_TRUE);
}

EC_BOOL cxfs_fuses_mknod(const UINT32 cxfs_md_id, const CSTRING *path, const UINT32 mode, const UINT32 uid, const UINT32 gid, const UINT32 dev, int *res)
{
    CXFS_MD         *cxfs_md;
    CXFSNP_ITEM     *cxfsnp_item;
    CXFSNP_ATTR     *cxfsnp_attr;
    uint64_t         ino;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_fuses_mknod: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    CXFS_FUSES_DEBUG_ENTER("cxfs_fuses_mknod");

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    CXFS_FUSES_CHECK_ENV(cxfs_md_id, cxfs_md, "cxfs_fuses_mknod", res);

    if(EC_FALSE == cxfs_mkdir(cxfs_md_id, path))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_mknod: "
                                             "mkdir '%s'failed\n",
                                             (char *)cstring_get_str(path));
        (*res) = -EACCES;
        return (EC_FALSE);
    }

    if(EC_FALSE == __cxfs_fuses_make_empty_hidden_seg(cxfs_md_id, path, res))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_mknod: "
                                             "%s, make hidden seg file failed\n",
                                             (char *)cstring_get_str(path));
        return (EC_TRUE);
    }

    cxfsnp_item = __cxfs_fuses_lookup(cxfs_md_id, path, &ino);
    if(NULL_PTR == cxfsnp_item)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_mknod: "
                                             "path '%s' ino %lu fetch item failed\n",
                                             (char *)cstring_get_str(path),
                                             ino);
        (*res) = -ENOENT;
        return (EC_TRUE);
    }

    cxfsnp_attr = CXFSNP_ITEM_ATTR(cxfsnp_item);

    cxfsnp_attr_set_file(cxfsnp_attr);
    CXFSNP_ATTR_MODE(cxfsnp_attr)       = (uint16_t)(mode | S_IFREG);
    CXFSNP_ATTR_UID(cxfsnp_attr)        = (uint32_t)uid;
    CXFSNP_ATTR_GID(cxfsnp_attr)        = (uint32_t)gid;
    CXFSNP_ATTR_RDEV(cxfsnp_attr)       = (uint32_t)dev;

    dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_mknod: "
                                         "%s => ino %lu => mode %#o uid %u, gid %u => done\n",
                                         (char *)cstring_get_str(path), ino,
                                         CXFSNP_ATTR_MODE(cxfsnp_attr),
                                         CXFSNP_ATTR_UID(cxfsnp_attr),
                                         CXFSNP_ATTR_GID(cxfsnp_attr));

    (*res) = 0;

    return (EC_TRUE);
}

EC_BOOL cxfs_fuses_mkdir(const UINT32 cxfs_md_id, const CSTRING *path, const UINT32 mode, const UINT32 uid, const UINT32 gid, int *res)
{
    CXFS_MD         *cxfs_md;
    CXFSNP_ITEM     *cxfsnp_item;
    CXFSNP_ATTR     *cxfsnp_attr;
    uint64_t         ino;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_fuses_mkdir: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    CXFS_FUSES_DEBUG_ENTER("cxfs_fuses_mkdir");

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    CXFS_FUSES_CHECK_ENV(cxfs_md_id, cxfs_md, "cxfs_fuses_mkdir", res);

    if(EC_FALSE == cxfs_mkdir(cxfs_md_id, path))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_mkdir: "
                                             "mkdir '%s' failed\n",
                                             (char *)cstring_get_str(path));
        (*res) = -EACCES;
        return (EC_FALSE);
    }

    cxfsnp_item = __cxfs_fuses_lookup(cxfs_md_id, path, &ino);
    if(NULL_PTR == cxfsnp_item)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_mkdir: "
                                             "path '%s' ino %lu fetch item failed\n",
                                             (char *)cstring_get_str(path),
                                             ino);
        (*res) = -ENOENT;
        return (EC_TRUE);
    }

    cxfsnp_attr = CXFSNP_ITEM_ATTR(cxfsnp_item);
    cxfsnp_attr_set_dir(cxfsnp_attr);
    CXFSNP_ATTR_MODE(cxfsnp_attr)       = (uint16_t)(mode | S_IFDIR);
    CXFSNP_ATTR_UID(cxfsnp_attr)        = (uint32_t)uid;
    CXFSNP_ATTR_GID(cxfsnp_attr)        = (uint32_t)gid;

    dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_mkdir: "
                                         "mkdir %s => ino %lu => mode %#o uid %u, gid %u => done\n",
                                         (char *)cstring_get_str(path), ino,
                                         CXFSNP_ATTR_MODE(cxfsnp_attr),
                                         CXFSNP_ATTR_UID(cxfsnp_attr),
                                         CXFSNP_ATTR_GID(cxfsnp_attr));

    (*res) = 0;

    return (EC_TRUE);
}

EC_BOOL cxfs_fuses_unlink(const UINT32 cxfs_md_id, const CSTRING *path, int *res)
{
    CXFS_MD         *cxfs_md;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_fuses_unlink: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    CXFS_FUSES_DEBUG_ENTER("cxfs_fuses_unlink");

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    CXFS_FUSES_CHECK_ENV(cxfs_md_id, cxfs_md, "cxfs_fuses_unlink", res);

    if(EC_FALSE == cxfs_delete_dir(cxfs_md_id, path))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_unlink: "
                                             "delete dir '%s' failed\n",
                                             (char *)cstring_get_str(path));
        (*res) = -EACCES;
        return (EC_FALSE);
    }

    dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_unlink: "
                                         "delete dir %s => done\n",
                                         (char *)cstring_get_str(path));

    (*res) = 0;

    return (EC_TRUE);
}

EC_BOOL cxfs_fuses_rmdir(const UINT32 cxfs_md_id, const CSTRING *path, int *res)
{
    CXFS_MD         *cxfs_md;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_fuses_rmdir: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    CXFS_FUSES_DEBUG_ENTER("cxfs_fuses_rmdir");

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    CXFS_FUSES_CHECK_ENV(cxfs_md_id, cxfs_md, "cxfs_fuses_rmdir", res);

    if(EC_FALSE == cxfs_delete_dir(cxfs_md_id, path))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_rmdir: "
                                             "delete dir '%s' failed\n",
                                             (char *)cstring_get_str(path));
        (*res) = -EACCES;
        return (EC_FALSE);
    }

    dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_rmdir: "
                                         "delete dir %s => done\n",
                                         (char *)cstring_get_str(path));

    (*res) = 0;

    return (EC_TRUE);
}

EC_BOOL cxfs_fuses_symlink(const UINT32 cxfs_md_id, const CSTRING *from_path, const CSTRING *to_path, int *res)
{
    CXFS_MD         *cxfs_md;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_fuses_symlink: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    CXFS_FUSES_DEBUG_ENTER("cxfs_fuses_symlink");

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    CXFS_FUSES_CHECK_ENV(cxfs_md_id, cxfs_md, "cxfs_fuses_symlink", res);

    if(EC_FALSE == cxfs_link_dir(cxfs_md_id, from_path, to_path))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_symlink: "
                                             "link dir '%s' to '%s' failed\n",
                                             (char *)cstring_get_str(from_path),
                                             (char *)cstring_get_str(to_path));
        (*res) = -EACCES;
        return (EC_FALSE);
    }

    dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_symlink: "
                                         "link dir '%s' to '%s' done\n",
                                         (char *)cstring_get_str(from_path),
                                         (char *)cstring_get_str(to_path));

    (*res) = 0;

    return (EC_TRUE);
}

EC_BOOL cxfs_fuses_rename(const UINT32 cxfs_md_id, const CSTRING *from_path, const CSTRING *to_path, int *res)
{
    CXFS_MD         *cxfs_md;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_fuses_rename: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    CXFS_FUSES_DEBUG_ENTER("cxfs_fuses_rename");

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    CXFS_FUSES_CHECK_ENV(cxfs_md_id, cxfs_md, "cxfs_fuses_rename", res);

    if(EC_FALSE == cxfs_rename_dir(cxfs_md_id, from_path, to_path))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_rename: "
                                             "rename dir '%s' to '%s' failed\n",
                                             (char *)cstring_get_str(from_path),
                                             (char *)cstring_get_str(to_path));
        (*res) = -EACCES;
        return (EC_FALSE);
    }

    dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_rename: "
                                         "rename dir '%s' to '%s' done\n",
                                         (char *)cstring_get_str(from_path),
                                         (char *)cstring_get_str(to_path));

    (*res) = 0;

    return (EC_TRUE);
}

EC_BOOL cxfs_fuses_link(const UINT32 cxfs_md_id, const CSTRING *from_path, const CSTRING *to_path, int *res)
{
    CXFS_MD         *cxfs_md;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_fuses_link: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    CXFS_FUSES_DEBUG_ENTER("cxfs_fuses_link");

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    CXFS_FUSES_CHECK_ENV(cxfs_md_id, cxfs_md, "cxfs_fuses_link", res);

    if(EC_FALSE == cxfs_link_dir(cxfs_md_id, from_path, to_path))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_link: "
                                             "link dir '%s' to '%s' failed\n",
                                             (char *)cstring_get_str(from_path),
                                             (char *)cstring_get_str(to_path));
        (*res) = -EACCES;
        return (EC_FALSE);
    }

    dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_link: "
                                         "link dir '%s' to '%s' done\n",
                                         (char *)cstring_get_str(from_path),
                                         (char *)cstring_get_str(to_path));

    (*res) = 0;

    return (EC_TRUE);
}

EC_BOOL cxfs_fuses_chmod(const UINT32 cxfs_md_id, const CSTRING *path, const UINT32 mode, int *res)
{
    CXFS_MD         *cxfs_md;
    CXFSNP_ITEM     *cxfsnp_item;
    CXFSNP_ATTR     *cxfsnp_attr;
    uint64_t         ino;

    uint64_t         nsec;  /*seconds*/
    uint64_t         nanosec;/*nanosecond*/

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_fuses_chmod: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    CXFS_FUSES_DEBUG_ENTER("cxfs_fuses_chmod");

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    CXFS_FUSES_CHECK_ENV(cxfs_md_id, cxfs_md, "cxfs_fuses_chmod", res);

    c_get_cur_time_nsec_and_nanosec(&nsec, &nanosec);

    cxfsnp_item = __cxfs_fuses_lookup(cxfs_md_id, path, &ino);
    if(NULL_PTR == cxfsnp_item)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_chmod: "
                                             "path '%s' ino %lu fetch item failed\n",
                                             (char *)cstring_get_str(path),
                                             ino);
        (*res) = -ENOENT;
        return (EC_TRUE);
    }

    cxfsnp_attr = CXFSNP_ITEM_ATTR(cxfsnp_item);
    CXFSNP_ATTR_MODE(cxfsnp_attr)       = (uint16_t)mode;
    CXFSNP_ATTR_MTIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
    CXFSNP_ATTR_CTIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
    CXFSNP_ATTR_MTIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;
    CXFSNP_ATTR_CTIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;

    dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_chmod: "
                                         "chmod %s => ino %lu, mod %#o => done\n",
                                         (char *)cstring_get_str(path), ino, (uint16_t)mode);

    (*res) = 0;

    return (EC_TRUE);
}

EC_BOOL cxfs_fuses_chown(const UINT32 cxfs_md_id, const CSTRING *path, const UINT32 uid, const UINT32 gid, int *res)
{
    CXFS_MD         *cxfs_md;
    CXFSNP_ITEM     *cxfsnp_item;
    CXFSNP_ATTR     *cxfsnp_attr;
    uint64_t         ino;

    uint64_t         nsec;  /*seconds*/
    uint64_t         nanosec;/*nanosecond*/

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_fuses_chown: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    CXFS_FUSES_DEBUG_ENTER("cxfs_fuses_chown");

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    CXFS_FUSES_CHECK_ENV(cxfs_md_id, cxfs_md, "cxfs_fuses_chown", res);

    c_get_cur_time_nsec_and_nanosec(&nsec, &nanosec);

    cxfsnp_item = __cxfs_fuses_lookup(cxfs_md_id, path, &ino);
    if(NULL_PTR == cxfsnp_item)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_chown: "
                                             "path '%s' ino %lu fetch item failed\n",
                                             (char *)cstring_get_str(path),
                                             ino);
        (*res) = -ENOENT;
        return (EC_TRUE);
    }

    cxfsnp_attr = CXFSNP_ITEM_ATTR(cxfsnp_item);

    CXFSNP_ATTR_UID(cxfsnp_attr)        = (uint32_t)uid;
    CXFSNP_ATTR_GID(cxfsnp_attr)        = (uint32_t)gid;
    CXFSNP_ATTR_MTIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
    CXFSNP_ATTR_CTIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
    CXFSNP_ATTR_MTIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;
    CXFSNP_ATTR_CTIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;

    dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_chown: "
                                         "chown %s => ino %lu, uid %u, gid %u => done\n",
                                         (char *)cstring_get_str(path), ino,
                                         CXFSNP_ATTR_UID(cxfsnp_attr),
                                         CXFSNP_ATTR_GID(cxfsnp_attr));

    (*res) = 0;

    return (EC_TRUE);
}

STATIC_CAST EC_BOOL __cxfs_fuses_truncate_seg(const UINT32 cxfs_md_id, const CSTRING *seg_path, const CRANGE_SEG *crange_seg, int *res)
{
    CXFSNP_ITEM     *seg_item;
    uint64_t         seg_ino;

    ASSERT(0 == CRANGE_SEG_S_OFFSET(crange_seg));

    seg_item = __cxfs_fuses_lookup_seg(cxfs_md_id, seg_path, &seg_ino);
    if(NULL_PTR == seg_item) /*seg file not exist*/
    {
        UINT32      seg_file_size;

        seg_file_size = CRANGE_SEG_E_OFFSET(crange_seg) - CRANGE_SEG_S_OFFSET(crange_seg) + 1;
        if(EC_FALSE == cxfs_reserve(cxfs_md_id, seg_path, seg_file_size))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_fuses_truncate_seg: "
                                                 "reserve new seg '%s' size %ld failed\n",
                                                 (char *)cstring_get_str(seg_path),
                                                 seg_file_size);
            (*res) = -ENOENT;
            return (EC_FALSE);
        }

        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] __cxfs_fuses_truncate_seg: "
                                             "reserve new seg '%s' size %ld done\n",
                                             (char *)cstring_get_str(seg_path),
                                             seg_file_size);
        return (EC_TRUE);
    }
    else /*seg file exist*/
    {
        UINT32           seg_file_old_size;
        UINT32           seg_file_new_size;

        seg_file_old_size = CXFSNP_FNODE_FILESZ(CXFSNP_ITEM_FNODE(seg_item));
        seg_file_new_size = CRANGE_SEG_E_OFFSET(crange_seg) + 1;

        dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fuses_truncate_seg: "
                                             "lookup seg %s => ino %lu, size %ld, "
                                             "range [%ld, %ld)\n",
                                             (char *)cstring_get_str(seg_path),
                                             seg_ino, seg_file_old_size,
                                             CRANGE_SEG_S_OFFSET(crange_seg),
                                             CRANGE_SEG_E_OFFSET(crange_seg) + 1);

        if(seg_file_old_size != seg_file_new_size)
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fuses_truncate_seg: "
                                                 "seg %s resize %ld -> %ld\n",
                                                 (char *)cstring_get_str(seg_path),
                                                 seg_file_old_size,
                                                 seg_file_new_size);

            __cxfs_fuses_dn_resize(cxfs_md_id, seg_file_old_size, seg_file_new_size);
            __cxfs_fuses_npp_resize(cxfs_md_id, seg_ino, seg_file_old_size, seg_file_new_size);

            return (EC_TRUE);
        }

        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] __cxfs_fuses_truncate_seg: "
                                             "keep seg '%s' size %ld unchanged\n",
                                             (char *)cstring_get_str(seg_path),
                                             seg_file_old_size);
        return (EC_TRUE);
    }

    /*never reach here*/
    return (EC_TRUE);
}

EC_BOOL cxfs_fuses_truncate(const UINT32 cxfs_md_id, const CSTRING *path, const UINT32 length, int *res)
{
    CXFS_MD         *cxfs_md;
    CXFSNP_ITEM     *cxfsnp_item;
    CXFSNP_ATTR     *cxfsnp_attr;
    uint64_t         ino;

    UINT32           seg_no_src;
    UINT32           seg_no_des;

    uint64_t         nsec;  /*seconds*/
    uint64_t         nanosec;/*nanosecond*/

    uint64_t         dnode_file_size;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_fuses_truncate: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    CXFS_FUSES_DEBUG_ENTER("cxfs_fuses_truncate");

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    CXFS_FUSES_CHECK_ENV(cxfs_md_id, cxfs_md, "cxfs_fuses_truncate", res);

    if(EC_FALSE == cxfs_is_dir(cxfs_md_id, path))
    {
        if(EC_FALSE == cxfs_mkdir(cxfs_md_id, path))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_truncate: "
                                                 "mkdir path '%s' failed\n",
                                                 (char *)cstring_get_str(path));
            (*res) = -ENOENT;
            return (EC_TRUE);
        }

        dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_truncate: "
                                             "mkdir path '%s' done\n",
                                             (char *)cstring_get_str(path));

        if(EC_FALSE == __cxfs_fuses_make_empty_hidden_seg(cxfs_md_id, path, res))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_truncate: "
                                                 "%s, make hidden seg file failed\n",
                                                 (char *)cstring_get_str(path));
            return (EC_TRUE);
        }

        dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_truncate: "
                                             "%s, make hidden seg file done\n",
                                             (char *)cstring_get_str(path));

        cxfsnp_item = __cxfs_fuses_lookup(cxfs_md_id, path, &ino);
        if(NULL_PTR == cxfsnp_item)
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_truncate: "
                                                 "path '%s' ino %lu fetch item failed\n",
                                                 (char *)cstring_get_str(path),
                                                 ino);
            (*res) = -ENOENT;
            return (EC_TRUE);
        }

        cxfsnp_attr = CXFSNP_ITEM_ATTR(cxfsnp_item);

        c_get_cur_time_nsec_and_nanosec(&nsec, &nanosec);

        CXFSNP_ATTR_FLAG(cxfsnp_attr)       = CXFSNP_ATTR_FUSES_IS_REG;

        CXFSNP_ATTR_ATIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
        CXFSNP_ATTR_MTIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
        CXFSNP_ATTR_CTIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
        CXFSNP_ATTR_ATIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;
        CXFSNP_ATTR_MTIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;
        CXFSNP_ATTR_CTIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;
    }
    else
    {
        cxfsnp_item = __cxfs_fuses_lookup(cxfs_md_id, path, &ino);
        if(NULL_PTR == cxfsnp_item)
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_truncate: "
                                                 "path '%s' ino %lu fetch item failed\n",
                                                 (char *)cstring_get_str(path),
                                                 ino);
            (*res) = -ENOENT;
            return (EC_TRUE);
        }
    }
    dnode_file_size = CXFSNP_DNODE_FILE_SIZE(CXFSNP_ITEM_DNODE(cxfsnp_item));

    dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_truncate: "
                                         "path '%s' ino %lu size %lu\n",
                                         (char *)cstring_get_str(path),
                                         ino, dnode_file_size);

    if(0 < length)
    {
        CRANGE_NODE     *crange_node;
        CRANGE_SEG      *crange_seg;

        UINT32           complete_size;

        crange_node = crange_node_new();
        if(NULL_PTR == crange_node)
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_truncate: "
                                                 "'%s', new crange node failed\n",
                                                 (char *)cstring_get_str(path));
            (*res) = -ENOMEM;
            return (EC_TRUE);
        }

        CRANGE_NODE_SUFFIX_START(crange_node)  = EC_FALSE;
        CRANGE_NODE_SUFFIX_END(crange_node)    = EC_FALSE;
        CRANGE_NODE_RANGE_START(crange_node)   = 0;
        CRANGE_NODE_RANGE_END(crange_node)     = length - 1;

        if(EC_FALSE == crange_node_split(crange_node, (UINT32)CXFSPGB_PAGE_BYTE_SIZE))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_truncate: "
                                                 "'%s' split [%ld, %ld) failed\n",
                                                 (char *)cstring_get_str(path),
                                                 CRANGE_NODE_RANGE_START(crange_node),
                                                 CRANGE_NODE_RANGE_END(crange_node) + 1);

            crange_node_free(crange_node);

            (*res) = -ERANGE;
            return (EC_TRUE);
        }

        if(do_log(SEC_0192_CXFS, 2))
        {
            sys_log(LOGSTDOUT, "[DEBUG] cxfs_fuses_truncate: segs:\n");
            crange_node_print(LOGSTDOUT, crange_node);
        }

        complete_size = 0;
        while(NULL_PTR != (crange_seg = clist_pop_front(CRANGE_NODE_RANGE_SEGS(crange_node))))
        {
            CSTRING         *seg_path;

            ASSERT(0 == CRANGE_SEG_S_OFFSET(crange_seg));

            seg_path = cstring_make("%s/%ld", cstring_get_str(path), CRANGE_SEG_NO(crange_seg));
            if(NULL_PTR == seg_path)
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_truncate: "
                                                     "make seg path %s/%ld failed\n",
                                                     (char *)cstring_get_str(path),
                                                     CRANGE_SEG_NO(crange_seg));

                crange_seg_free(crange_seg);
                crange_node_free(crange_node);

                (*res) = -ENOMEM;
                return (EC_TRUE);
            }

            if(EC_FALSE == __cxfs_fuses_truncate_seg(cxfs_md_id, seg_path, crange_seg, res))
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_truncate: "
                                                     "truncate seg %s failed\n",
                                                     (char *)cstring_get_str(seg_path));

                cstring_free(seg_path);

                crange_seg_free(crange_seg);
                crange_node_free(crange_node);

                return (EC_TRUE);
            }

            complete_size  += (CRANGE_SEG_E_OFFSET(crange_seg) - CRANGE_SEG_S_OFFSET(crange_seg) + 1);

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_write: "
                                                 "truncate '%s' seg %ld => complete %ld / %ld\n",
                                                 (char *)cstring_get_str(path),
                                                 CRANGE_SEG_NO(crange_seg),
                                                 complete_size, length);

            cstring_free(seg_path);
            crange_seg_free(crange_seg);
        }

        crange_node_free(crange_node);
    }

    seg_no_src = (UINT32)((dnode_file_size + CXFSPGB_PAGE_BYTE_SIZE - 1) /  CXFSPGB_PAGE_BYTE_SIZE);
    seg_no_des = (UINT32)((length + CXFSPGB_PAGE_BYTE_SIZE - 1) /  CXFSPGB_PAGE_BYTE_SIZE);

    if(dnode_file_size <= length ||seg_no_src <= seg_no_des)
    {
        cxfsnp_attr = CXFSNP_ITEM_ATTR(cxfsnp_item);

        c_get_cur_time_nsec_and_nanosec(&nsec, &nanosec);

        CXFSNP_ATTR_ATIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
        CXFSNP_ATTR_MTIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
        CXFSNP_ATTR_CTIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
        CXFSNP_ATTR_ATIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;
        CXFSNP_ATTR_MTIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;
        CXFSNP_ATTR_CTIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;

        (*res) = 0;

        dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_truncate: "
                                             "[no retire] truncate %s: ino %lu, length %lu => %ld done\n",
                                             (char *)cstring_get_str(path), ino,
                                             dnode_file_size, length);

        return (EC_TRUE);
    }

    /*(dnode_file_size > length && seg_no_src > seg_no_des)*/

    if(0 < dnode_file_size)
    {
        CRANGE_NODE     *crange_node;
        CRANGE_SEG      *crange_seg;

        crange_node = crange_node_new();
        if(NULL_PTR == crange_node)
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_truncate: "
                                                 "'%s', new crange node failed\n",
                                                 (char *)cstring_get_str(path));
            (*res) = -ENOMEM;
            return (EC_TRUE);
        }

        CRANGE_NODE_SUFFIX_START(crange_node)  = EC_FALSE;
        CRANGE_NODE_SUFFIX_END(crange_node)    = EC_FALSE;
        CRANGE_NODE_RANGE_START(crange_node)   = (UINT32)(seg_no_des * CXFSPGB_PAGE_BYTE_SIZE);
        CRANGE_NODE_RANGE_END(crange_node)     = (UINT32)(dnode_file_size - 1);

        if(EC_FALSE == crange_node_split(crange_node, (UINT32)CXFSPGB_PAGE_BYTE_SIZE))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_truncate: "
                                                 "[retire] '%s' split [%ld, %ld) failed\n",
                                                 (char *)cstring_get_str(path),
                                                 CRANGE_NODE_RANGE_START(crange_node),
                                                 CRANGE_NODE_RANGE_END(crange_node) + 1);

            crange_node_free(crange_node);

            (*res) = -ERANGE;
            return (EC_TRUE);
        }

        if(do_log(SEC_0192_CXFS, 2))
        {
            sys_log(LOGSTDOUT, "[DEBUG] cxfs_fuses_truncate: retired segs:\n");
            crange_node_print(LOGSTDOUT, crange_node);
        }

        while(NULL_PTR != (crange_seg = clist_pop_front(CRANGE_NODE_RANGE_SEGS(crange_node))))
        {
            CSTRING         *seg_path;

            seg_path = cstring_make("%s/%ld", cstring_get_str(path), CRANGE_SEG_NO(crange_seg));
            if(NULL_PTR == seg_path)
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_truncate: "
                                                     "[retire] make seg path %s/%ld failed\n",
                                                     (char *)cstring_get_str(path),
                                                     CRANGE_SEG_NO(crange_seg));

                crange_seg_free(crange_seg);
                crange_node_free(crange_node);

                (*res) = -ENOMEM;
                return (EC_TRUE);
            }

            if(EC_FALSE == cxfs_delete_file(cxfs_md_id, seg_path))
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_truncate: "
                                                     "[retire] delete seg %s failed\n",
                                                     (char *)cstring_get_str(seg_path));

                cstring_free(seg_path);

                crange_seg_free(crange_seg);
                crange_node_free(crange_node);

                (*res) = -ENOENT;
                return (EC_TRUE);
            }

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_write: "
                                                 "[retire] delete '%s' done\n",
                                                 (char *)cstring_get_str(seg_path));

            cstring_free(seg_path);
            crange_seg_free(crange_seg);
        }

        crange_node_free(crange_node);
    }

    dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_truncate: "
                                         "[retire] truncate %s: ino %lu, length %lu => %ld done\n",
                                         (char *)cstring_get_str(path), ino,
                                         dnode_file_size, length);

    cxfsnp_attr = CXFSNP_ITEM_ATTR(cxfsnp_item);

    c_get_cur_time_nsec_and_nanosec(&nsec, &nanosec);

    CXFSNP_ATTR_ATIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
    CXFSNP_ATTR_MTIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
    CXFSNP_ATTR_CTIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
    CXFSNP_ATTR_ATIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;
    CXFSNP_ATTR_MTIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;
    CXFSNP_ATTR_CTIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;

    (*res) = 0;

    return (EC_TRUE);
}

EC_BOOL cxfs_fuses_utime(const UINT32 cxfs_md_id, const CSTRING *path, const struct utimbuf *times, int *res)
{
    CXFS_MD         *cxfs_md;
    CXFSNP_ITEM     *cxfsnp_item;
    CXFSNP_ATTR     *cxfsnp_attr;
    uint64_t         ino;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_fuses_utime: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    CXFS_FUSES_DEBUG_ENTER("cxfs_fuses_utime");

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    CXFS_FUSES_CHECK_ENV(cxfs_md_id, cxfs_md, "cxfs_fuses_utime", res);

    cxfsnp_item = __cxfs_fuses_lookup(cxfs_md_id, path, &ino);
    if(NULL_PTR == cxfsnp_item)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_utime: "
                                             "path '%s' ino %lu fetch item failed\n",
                                             (char *)cstring_get_str(path),
                                             ino);
        (*res) = -ENOENT;
        return (EC_TRUE);
    }

    CXFS_STAT_WRITE_COUNTER(CXFS_MD_STAT(cxfs_md)) ++;

    cxfsnp_attr = CXFSNP_ITEM_ATTR(cxfsnp_item);

    CXFSNP_ATTR_ATIME_SEC(cxfsnp_attr)  = (uint64_t)times->actime;
    CXFSNP_ATTR_MTIME_SEC(cxfsnp_attr)  = (uint64_t)times->modtime;

    dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_utime: "
                                         "utime %s => ino %lu, atime_sec %lu, mtime_sec %lu => done\n",
                                         (char *)cstring_get_str(path), ino,
                                         CXFSNP_ATTR_ATIME_SEC(cxfsnp_attr),
                                         CXFSNP_ATTR_MTIME_SEC(cxfsnp_attr));

    (*res) = 0;

    return (EC_TRUE);
}

/**
 * Open a file
 *
 * Open flags are available in fi->flags. The following rules
 * apply.
 *
 *  - Creation (O_CREAT, O_EXCL, O_NOCTTY) flags will be
 *    filtered out / handled by the kernel.
 *
 *  - Access modes (O_RDONLY, O_WRONLY, O_RDWR) should be used
 *    by the filesystem to check if the operation is
 *    permitted.  If the ``-o default_permissions`` mount
 *    option is given, this check is already done by the
 *    kernel before calling open() and may thus be omitted by
 *    the filesystem.
 *    ......
 **/
EC_BOOL cxfs_fuses_open(const UINT32 cxfs_md_id, const CSTRING *path, const UINT32 flags, const UINT32 uid, const UINT32 gid, int *res)
{
    CXFS_MD         *cxfs_md;

    uint64_t         ino;

    uint32_t         accmode;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_fuses_open: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    CXFS_FUSES_DEBUG_ENTER("cxfs_fuses_open");

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    CXFS_FUSES_CHECK_ENV(cxfs_md_id, cxfs_md, "cxfs_fuses_open", res);

    if(NULL_PTR == __cxfs_fuses_lookup(cxfs_md_id, path, &ino))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_open: "
                                             "no dir '%s'\n",
                                             (char *)cstring_get_str(path));
        (*res) = -ENOENT;
        return (EC_TRUE);
    }

    if(((uint32_t)flags) & O_TRUNC)
    {
        accmode = O_WRONLY;

        if(EC_FALSE == __cxfs_fuses_check_access(cxfs_md_id,
                                                (char *)cstring_get_str(path), ino,
                                                accmode, (uint32_t)uid, (uint32_t)gid))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_open: "
                                                 "find dir '%s', accmode %#o, uid %u, gid %u => not access "
                                                 "=> truncate refused\n",
                                                 (char *)cstring_get_str(path),
                                                 accmode, (uint32_t)uid, (uint32_t)gid);
                (*res) = -EACCES;
                return (EC_TRUE);
        }

        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "[DEBUG] cxfs_fuses_open: "
                                             "find dir '%s' => ino %lu => truncate to length 0\n",
                                             (char *)cstring_get_str(path), ino);

        return cxfs_fuses_truncate(cxfs_md_id, path, (UINT32)0, res);
    }

    accmode = (((uint32_t)flags) & O_ACCMODE);

    if(EC_FALSE == __cxfs_fuses_check_access(cxfs_md_id,
                                            (char *)cstring_get_str(path), ino,
                                            accmode, (uint32_t)uid, (uint32_t)gid))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_open: "
                                             "find dir '%s', accmode %#o, uid %u, gid %u => not access\n",
                                             (char *)cstring_get_str(path),
                                             accmode, (uint32_t)uid, (uint32_t)gid);
            (*res) = -EACCES;
            return (EC_TRUE);
    }

    dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "[DEBUG] cxfs_fuses_open: "
                                         "find dir '%s', accmode %#o, uid %u, gid %u => access\n",
                                         (char *)cstring_get_str(path),
                                         accmode, (uint32_t)uid, (uint32_t)gid);
    (*res) = 0;
    return (EC_TRUE);
}

EC_BOOL cxfs_fuses_create(const UINT32 cxfs_md_id, const CSTRING *path, const UINT32 mode, const UINT32 uid, const UINT32 gid, int *res)
{
    CXFS_MD         *cxfs_md;
    CXFSNP_ITEM     *cxfsnp_item;
    CXFSNP_ATTR     *cxfsnp_attr;
    uint64_t         ino;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_fuses_create: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    CXFS_FUSES_DEBUG_ENTER("cxfs_fuses_create");

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    CXFS_FUSES_CHECK_ENV(cxfs_md_id, cxfs_md, "cxfs_fuses_create", res);

    if(NULL_PTR != __cxfs_fuses_lookup(cxfs_md_id, path, &ino))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "[DEBUG] cxfs_fuses_create: "
                                             "find dir '%s' => ino %lu\n",
                                             (char *)cstring_get_str(path), ino);
        (*res) = 0;
        return (EC_TRUE);
    }

    if(1) /*check parent acccess*/
    {
        CSTRING  parent_path_cstr;
        char    *parent_path;
        uint64_t parent_ino;
        uint32_t parent_path_len;
        uint32_t accmode;

        parent_path = c_dirname((char *)cstring_get_str(path));
        if(NULL_PTR == parent_path)
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_create: "
                                                 "dirname '%s', failed\n",
                                                 (char *)cstring_get_str(path));
            (*res) = -ENOMEM;
            return (EC_TRUE);
        }

        parent_path_len = strlen(parent_path);

        cstring_mount(&parent_path_cstr, (UINT8 *)parent_path, parent_path_len, parent_path_len + 1);

        if(NULL_PTR == __cxfs_fuses_lookup(cxfs_md_id, &parent_path_cstr, &parent_ino))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_create: "
                                                 "find parent '%s' of '%s' failed\n",
                                                 parent_path,
                                                 (char *)cstring_get_str(path));
            c_str_free(parent_path);

            (*res) = -EIO;
            return (EC_TRUE);
        }

        accmode = O_WRONLY;

        if(EC_FALSE == __cxfs_fuses_check_access(cxfs_md_id, parent_path, parent_ino,
                                                accmode, (uint32_t)uid, (uint32_t)gid))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_create: "
                                                 "find parent '%s', accmode %#o, uid %u, gid %u => not access "
                                                 "=> create '%s' refused\n",
                                                 parent_path,
                                                 accmode, (uint32_t)uid, (uint32_t)gid,
                                                 (char *)cstring_get_str(path));
            c_str_free(parent_path);

            (*res) = -EACCES;
            return (EC_TRUE);
        }

        c_str_free(parent_path);
    }

    if(EC_FALSE == cxfs_mkdir(cxfs_md_id, path))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_create: "
                                             "mkdir '%s'failed\n",
                                             (char *)cstring_get_str(path));
        (*res) = -EACCES;
        return (EC_FALSE);
    }

    if(EC_FALSE == __cxfs_fuses_make_empty_hidden_seg(cxfs_md_id, path, res))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_create: "
                                             "%s, make hidden seg file failed\n",
                                             (char *)cstring_get_str(path));
        return (EC_TRUE);
    }

    cxfsnp_item = __cxfs_fuses_lookup(cxfs_md_id, path, &ino);
    if(NULL_PTR == cxfsnp_item)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_create: "
                                             "path '%s' ino %lu fetch item failed\n",
                                             (char *)cstring_get_str(path),
                                             ino);
        (*res) = -ENOENT;
        return (EC_TRUE);
    }

    cxfsnp_attr = CXFSNP_ITEM_ATTR(cxfsnp_item);

    cxfsnp_attr_set_file(cxfsnp_attr);
    CXFSNP_ATTR_MODE(cxfsnp_attr)       = (uint16_t)(mode | S_IFREG);
    CXFSNP_ATTR_UID(cxfsnp_attr)        = (uint32_t)uid;
    CXFSNP_ATTR_GID(cxfsnp_attr)        = (uint32_t)gid;

    dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_create: "
                                         "%s => ino %lu => mode %#o uid %u, gid %u => done\n",
                                         (char *)cstring_get_str(path), ino,
                                         CXFSNP_ATTR_MODE(cxfsnp_attr),
                                         CXFSNP_ATTR_UID(cxfsnp_attr),
                                         CXFSNP_ATTR_GID(cxfsnp_attr));

    (*res) = 0;

    return (EC_TRUE);
}

EC_BOOL cxfs_fuses_read(const UINT32 cxfs_md_id, const CSTRING *path, CBYTES *buf, const UINT32 size, const UINT32 offset, int *res)
{
    CXFS_MD         *cxfs_md;

    CXFSNP_ITEM     *cxfsnp_item;

    uint64_t         ino;
    uint64_t         file_size;
    CRANGE_NODE     *crange_node;
    CRANGE_SEG      *crange_seg;
    UINT8           *data;
    UINT32           rd_size;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_fuses_read: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    CXFS_FUSES_DEBUG_ENTER("cxfs_fuses_read");

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    CXFS_FUSES_CHECK_ENV(cxfs_md_id, cxfs_md, "cxfs_fuses_read", res);

    cxfsnp_item = __cxfs_fuses_lookup(cxfs_md_id, path, &ino);
    if(NULL_PTR == cxfsnp_item)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_read: "
                                             "no '%s'\n",
                                             (char *)cstring_get_str(path));
        (*res) = -ENOENT;
        return (EC_TRUE);
    }

    file_size = CXFSNP_DNODE_FILE_SIZE(CXFSNP_ITEM_DNODE(cxfsnp_item));
    if((UINT32)file_size <= offset)
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_fuses_read: "
                                             "file '%s' size %ld <= offset %ld\n",
                                             (char *)cstring_get_str(path), file_size, offset);
        cbytes_clean(buf);
        (*res) = 0;

        return (EC_TRUE);
    }

    crange_node = crange_node_new();
    if(NULL_PTR == crange_node)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_read: "
                                             "'%s', new crange node failed\n",
                                             (char *)cstring_get_str(path));
        (*res) = -ENOMEM;
        return (EC_TRUE);
    }

    if((UINT32)file_size >= offset + size)
    {
        CRANGE_NODE_SUFFIX_START(crange_node)  = EC_FALSE;
        CRANGE_NODE_SUFFIX_END(crange_node)    = EC_FALSE;
        CRANGE_NODE_RANGE_START(crange_node)   = offset;
        CRANGE_NODE_RANGE_END(crange_node)     = offset + size - 1;
    }
    else
    {
        CRANGE_NODE_SUFFIX_START(crange_node)  = EC_FALSE;
        CRANGE_NODE_SUFFIX_END(crange_node)    = EC_FALSE;
        CRANGE_NODE_RANGE_START(crange_node)   = offset;
        CRANGE_NODE_RANGE_END(crange_node)     = (UINT32)(file_size - 1);
    }

    if(EC_FALSE == crange_node_split(crange_node, (UINT32)CXFSPGB_PAGE_BYTE_SIZE))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_read: "
                                             "'%s' split [%ld, %ld) failed\n",
                                             (char *)cstring_get_str(path),
                                             CRANGE_NODE_RANGE_START(crange_node),
                                             CRANGE_NODE_RANGE_END(crange_node) + 1);

        crange_node_free(crange_node);

        (*res) = -ERANGE;
        return (EC_TRUE);
    }

    if(do_log(SEC_0192_CXFS, 2))
    {
        sys_log(LOGSTDOUT, "[DEBUG] cxfs_fuses_read: %s, segs:\n",
                           (char *)cstring_get_str(path));
        crange_node_print(LOGSTDOUT, crange_node);
    }

    data = safe_malloc(size, LOC_CXFSFUSES_0001);
    if(NULL_PTR == data)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_read: "
                                             "'%s', malloc %ld failed\n",
                                             (char *)cstring_get_str(path), size);

        crange_node_free(crange_node);

        (*res) = -ENOMEM;
        return (EC_TRUE);
    }

    rd_size = 0;
    while(NULL_PTR != (crange_seg = clist_pop_front(CRANGE_NODE_RANGE_SEGS(crange_node))))
    {
        CSTRING    *seg_path;
        CBYTES      content;
        UINT32      len;
        UINT32      offset_t;

        seg_path = cstring_make("%s/%ld", cstring_get_str(path), CRANGE_SEG_NO(crange_seg));
        if(NULL_PTR == seg_path)
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_read: "
                                                 "make seg path %s/%ld failed\n",
                                                 (char *)cstring_get_str(path),
                                                 CRANGE_SEG_NO(crange_seg));

            safe_free(data, LOC_CXFSFUSES_0002);
            crange_node_free(crange_node);

            (*res) = -ENOMEM;
            return (EC_TRUE);
        }

        offset_t = CRANGE_SEG_S_OFFSET(crange_seg);
        len      = CRANGE_SEG_E_OFFSET(crange_seg) - CRANGE_SEG_S_OFFSET(crange_seg) + 1;

        cbytes_mount(&content, len, data + rd_size, BIT_FALSE);

        if(EC_FALSE == cxfs_read_e(cxfs_md_id, seg_path, &offset_t, len, &content))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_read: "
                                                 "read seg '%s' [%ld, %ld) failed\n",
                                                 (char *)cstring_get_str(seg_path),
                                                 CRANGE_SEG_S_OFFSET(crange_seg),
                                                 CRANGE_SEG_E_OFFSET(crange_seg) + 1);

            cstring_free(seg_path);

            safe_free(data, LOC_CXFSFUSES_0003);
            crange_node_free(crange_node);

            (*res) = -ENOENT;
            return (EC_TRUE);
        }
        ASSERT(CBYTES_BUF(&content) == (data + rd_size));

        if(offset_t != CRANGE_SEG_E_OFFSET(crange_seg) + 1)
        {
            ASSERT(offset_t < CRANGE_SEG_E_OFFSET(crange_seg) + 1);
            rd_size += (offset_t - CRANGE_SEG_S_OFFSET(crange_seg));

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_read: "
                                                 "read seg '%s' [%ld, %ld) but stop at %ld => complete %ld\n",
                                                 (char *)cstring_get_str(seg_path),
                                                 CRANGE_SEG_S_OFFSET(crange_seg),
                                                 CRANGE_SEG_E_OFFSET(crange_seg) + 1,
                                                 offset_t,
                                                 rd_size);


            cstring_free(seg_path);

            break;
        }

        cbytes_umount(&content, NULL_PTR, NULL_PTR, NULL_PTR);

        rd_size += len;

        dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_read: "
                                             "read seg '%s' [%ld, %ld) => complete %ld\n",
                                             (char *)cstring_get_str(seg_path),
                                             CRANGE_SEG_S_OFFSET(crange_seg),
                                             CRANGE_SEG_E_OFFSET(crange_seg) + 1,
                                             rd_size);
        cstring_free(seg_path);
    }

    crange_node_free(crange_node);

    cbytes_clean(buf);
    cbytes_mount(buf, rd_size, data, BIT_FALSE);

    (*res) = (int)(rd_size);

    dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "[DEBUG] cxfs_fuses_read: "
                                         "read file '%s' offset %ld size %ld => ret %ld done\n",
                                         (char *)cstring_get_str(path), offset, size,
                                         rd_size);

    return (EC_TRUE);
}

STATIC_CAST EC_BOOL __cxfs_fuses_write_seg(const UINT32 cxfs_md_id, const CSTRING *seg_path, const CRANGE_SEG *crange_seg, const UINT8 *data, UINT32 *data_offset, int *res)
{
    CBYTES           content;
    UINT32           len;
    UINT32           seg_offset;

    CXFSNP_ITEM     *seg_item;
    uint64_t         seg_ino;

    seg_offset = CRANGE_SEG_S_OFFSET(crange_seg);
    len        = CRANGE_SEG_E_OFFSET(crange_seg) - CRANGE_SEG_S_OFFSET(crange_seg) + 1;

    cbytes_mount(&content, len, data + (*data_offset), BIT_FALSE);

    seg_item = __cxfs_fuses_lookup_seg(cxfs_md_id, seg_path, &seg_ino);
    if(NULL_PTR == seg_item) /*seg file not exist*/
    {
        UINT32           seg_file_size;

        seg_file_size = CRANGE_SEG_E_OFFSET(crange_seg) + 1;
        if(EC_FALSE == cxfs_reserve(cxfs_md_id, seg_path, seg_file_size))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_write_seg: "
                                                 "reserve seg '%s' size %ld failed\n",
                                                 (char *)cstring_get_str(seg_path),
                                                 seg_file_size);

            (*res) = -ENOENT;
            return (EC_FALSE);
        }

        dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_write_seg: "
                                             "reserve seg '%s' size %ld done\n",
                                             (char *)cstring_get_str(seg_path),
                                             seg_file_size);
    }
    else /*seg file exist*/
    {
        UINT32           seg_file_old_size;
        UINT32           seg_file_new_size;

        seg_file_old_size = CXFSNP_FNODE_FILESZ(CXFSNP_ITEM_FNODE(seg_item));
        seg_file_new_size = CRANGE_SEG_E_OFFSET(crange_seg) + 1;

        dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_write_seg: "
                                             "lookup seg %s => ino %lu, size %ld, "
                                             "range [%ld, %ld)\n",
                                             (char *)cstring_get_str(seg_path),
                                             seg_ino, seg_file_old_size,
                                             CRANGE_SEG_S_OFFSET(crange_seg),
                                             CRANGE_SEG_E_OFFSET(crange_seg) + 1);

        if(seg_file_old_size != seg_file_new_size)
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_write_seg: "
                                                 "seg %s resize %ld -> %ld\n",
                                                 (char *)cstring_get_str(seg_path),
                                                 seg_file_old_size,
                                                 seg_file_new_size);

            __cxfs_fuses_dn_resize(cxfs_md_id, seg_file_old_size, seg_file_new_size);
            __cxfs_fuses_npp_resize(cxfs_md_id, seg_ino, seg_file_old_size, seg_file_new_size);
        }
    }

    if(EC_FALSE == cxfs_write_e(cxfs_md_id, seg_path, &seg_offset, len, &content))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_write_seg: "
                                             "write seg '%s' [%ld, %ld) failed\n",
                                             (char *)cstring_get_str(seg_path),
                                             CRANGE_SEG_S_OFFSET(crange_seg),
                                             CRANGE_SEG_E_OFFSET(crange_seg) + 1);

        (*res) = -ENOENT;
        return (EC_FALSE);
    }

    (*data_offset) += (seg_offset - CRANGE_SEG_S_OFFSET(crange_seg));

    dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_write_seg: "
                                         "write seg '%s' [%ld, %ld) done\n",
                                         (char *)cstring_get_str(seg_path),
                                         CRANGE_SEG_S_OFFSET(crange_seg),
                                         seg_offset);

    return (EC_TRUE);
}

EC_BOOL cxfs_fuses_write(const UINT32 cxfs_md_id, const CSTRING *path, const CBYTES *buf, const UINT32 offset, int *res)
{
    CXFS_MD         *cxfs_md;
    UINT32           size;

    CXFSNP_ITEM     *cxfsnp_item;

    uint64_t         ino;
    uint64_t         file_old_size;
    CRANGE_NODE     *crange_node;
    CRANGE_SEG      *crange_seg;

    UINT32           seg_no_s; /*retire seg start*/
    UINT32           seg_no_e; /*retire seg end*/

    UINT8           *data;
    UINT32           complete_size;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_fuses_write: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    CXFS_FUSES_DEBUG_ENTER("cxfs_fuses_write");

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    CXFS_FUSES_CHECK_ENV(cxfs_md_id, cxfs_md, "cxfs_fuses_write", res);

    if(0 == CBYTES_LEN(buf))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "[DEBUG] cxfs_fuses_write: "
                                             "file '%s' offset %ld content size %ld "
                                             "=> write nothing\n",
                                             (char *)cstring_get_str(path), offset, CBYTES_LEN(buf));

        (*res) = 0;

        return (EC_TRUE);
    }

    data = CBYTES_BUF(buf);
    size = CBYTES_LEN(buf);

    cxfsnp_item = __cxfs_fuses_lookup(cxfs_md_id, path, &ino);
    if(NULL_PTR == cxfsnp_item)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_write: "
                                             "no '%s'\n",
                                             (char *)cstring_get_str(path));
        (*res) = -ENOENT;
        return (EC_TRUE);
    }

    file_old_size = CXFSNP_DNODE_FILE_SIZE(CXFSNP_ITEM_DNODE(cxfsnp_item));

    crange_node = crange_node_new();
    if(NULL_PTR == crange_node)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_write: "
                                             "'%s', new crange node failed\n",
                                             (char *)cstring_get_str(path));
        (*res) = -ENOMEM;
        return (EC_TRUE);
    }

    CRANGE_NODE_SUFFIX_START(crange_node)  = EC_FALSE;
    CRANGE_NODE_SUFFIX_END(crange_node)    = EC_FALSE;
    CRANGE_NODE_RANGE_START(crange_node)   = offset;
    CRANGE_NODE_RANGE_END(crange_node)     = offset + size - 1;

    if(EC_FALSE == crange_node_split(crange_node, (UINT32)CXFSPGB_PAGE_BYTE_SIZE))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_write: "
                                             "'%s' split [%ld, %ld) failed\n",
                                             (char *)cstring_get_str(path),
                                             CRANGE_NODE_RANGE_START(crange_node),
                                             CRANGE_NODE_RANGE_END(crange_node) + 1);

        crange_node_free(crange_node);

        (*res) = -ERANGE;
        return (EC_TRUE);
    }

    if(do_log(SEC_0192_CXFS, 2))
    {
        sys_log(LOGSTDOUT, "[DEBUG] cxfs_fuses_write: %s, segs:\n",
                           (char *)cstring_get_str(path));
        crange_node_print(LOGSTDOUT, crange_node);
    }

    complete_size = 0;
    while(NULL_PTR != (crange_seg = clist_pop_front(CRANGE_NODE_RANGE_SEGS(crange_node))))
    {
        CSTRING         *seg_path;

        UINT32           data_offset;
        UINT32           expect_len;
        UINT32           write_len;

        seg_path = cstring_make("%s/%ld", cstring_get_str(path), CRANGE_SEG_NO(crange_seg));
        if(NULL_PTR == seg_path)
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_write_seg: "
                                                 "make seg path %s/%ld failed\n",
                                                 (char *)cstring_get_str(path),
                                                 CRANGE_SEG_NO(crange_seg));

            crange_seg_free(crange_seg);
            crange_node_free(crange_node);

            (*res) = -ENOMEM;
            return (EC_TRUE);
        }

        data_offset = complete_size;
        expect_len  = (CRANGE_SEG_E_OFFSET(crange_seg) - CRANGE_SEG_S_OFFSET(crange_seg) + 1);

        if(EC_FALSE == __cxfs_fuses_write_seg(cxfs_md_id, seg_path, crange_seg, data, &data_offset, res))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_write: "
                                                 "write seg %s failed\n",
                                                 (char *)cstring_get_str(seg_path));

            cstring_free(seg_path);

            crange_seg_free(crange_seg);
            crange_node_free(crange_node);
            return (EC_TRUE);
        }

        write_len     = (data_offset - complete_size);
        complete_size = data_offset;

        if(write_len != expect_len)
        {
            dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_fuses_write: "
                                                 "'%s' seg %ld: write expect len %ld but %ld "
                                                 "=> complete %ld/%ld\n",
                                                 (char *)cstring_get_str(path),
                                                 CRANGE_SEG_NO(crange_seg),
                                                 expect_len, write_len,
                                                 complete_size, size);

            cstring_free(seg_path);
            crange_seg_free(crange_seg);

            break;
        }

        dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_write: "
                                             "write '%s' seg %ld "
                                             "=> complete %ld / %ld\n",
                                             (char *)cstring_get_str(path),
                                             CRANGE_SEG_NO(crange_seg),
                                             complete_size, size);

        cstring_free(seg_path);
        crange_seg_free(crange_seg);
    }

    if(EC_FALSE == clist_is_empty(CRANGE_NODE_RANGE_SEGS(crange_node)))
    {
        crange_node_free(crange_node);

        dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_write: "
                                             "write '%s' offset %ld, size %ld => complete %ld\n",
                                             (char *)cstring_get_str(path),
                                             offset, size, complete_size);
        (*res) = (int)(complete_size);

        return (EC_TRUE);
    }

    crange_node_free(crange_node);

    seg_no_s = ((offset + size + CXFSPGB_PAGE_BYTE_SIZE - 1) / CXFSPGB_PAGE_BYTE_SIZE);
    seg_no_e = ((file_old_size + CXFSPGB_PAGE_BYTE_SIZE - 1) / CXFSPGB_PAGE_BYTE_SIZE);

    if(seg_no_s < seg_no_e)
    {
        UINT32           seg_no;

        for(seg_no = seg_no_e; seg_no > seg_no_s; seg_no --)
        {
            CSTRING         *seg_path;

            seg_path = cstring_make("%s/%ld", cstring_get_str(path), seg_no);
            if(NULL_PTR == seg_path)
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_write_seg: "
                                                     "make retired seg path %s/%ld failed\n",
                                                     (char *)cstring_get_str(path),
                                                     seg_no);

                (*res) = -ENOMEM;
                return (EC_TRUE);
            }

            if(EC_FALSE == cxfs_delete_file(cxfs_md_id, seg_path))
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_write: "
                                                     "retire seg %s failed\n",
                                                     (char *)cstring_get_str(seg_path));

                cstring_free(seg_path);
                continue; /*xxx*/
            }

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_write: "
                                                 "retire seg '%s' done\n",
                                                 (char *)cstring_get_str(seg_path));

            cstring_free(seg_path);
        }

        dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_write: "
                                             "'%s' retire segs %ld .. %ld done\n",
                                             (char *)cstring_get_str(path),
                                             seg_no_s + 1,
                                             seg_no_e);
    }

    dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_write: "
                                         "write '%s' offset %ld, size %ld => complete %ld\n",
                                         (char *)cstring_get_str(path),
                                         offset, size, complete_size);
    (*res) = (int)(complete_size);

    return (EC_TRUE);
}

EC_BOOL cxfs_fuses_statfs(const UINT32 cxfs_md_id, const CSTRING *path, struct statvfs *statfs, int *res)
{
    CXFS_MD         *cxfs_md;
    CXFSNP_ITEM     *cxfsnp_item;
    CXFSNP_ATTR     *cxfsnp_attr;
    uint64_t         ino;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_fuses_statfs: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    CXFS_FUSES_DEBUG_ENTER("cxfs_fuses_statfs");

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    CXFS_FUSES_CHECK_ENV(cxfs_md_id, cxfs_md, "cxfs_fuses_statfs", res);

    cxfsnp_item = __cxfs_fuses_lookup(cxfs_md_id, path, &ino);
    if(NULL_PTR == cxfsnp_item)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_statfs: "
                                             "path '%s' ino %lu fetch item failed\n",
                                             (char *)cstring_get_str(path),
                                             ino);
        (*res) = -ENOENT;
        return (EC_TRUE);
    }

    cxfsnp_attr = CXFSNP_ITEM_ATTR(cxfsnp_item);

    if(CXFSNP_ATTR_FUSES_IS_REG == CXFSNP_ATTR_FLAG(cxfsnp_attr))
    {
        statfs->f_bsize     = 4096;                 /* Filesystem block size */
        statfs->f_frsize    = 4096;                 /* Fragment size */
        statfs->f_blocks    = 0x00FFFFFF;           /* Size of fs in f_frsize units */
        statfs->f_bfree     = 0x00FFFFFF;           /* Number of free blocks */
        statfs->f_bavail    = 0x00FFFFFF;           /* Number of free blocks for unprivileged users */
        statfs->f_files     = 0x00FFFFFF;           /* Number of inodes */
        statfs->f_ffree     = 0x0FFFFFFF;           /* Number of free inodes */
        statfs->f_favail    = 0x0FFFFFFF;           /* Number of free inodes for unprivileged users */
        statfs->f_fsid      = 0x0FEFEFEF;           /* Filesystem ID */
        statfs->f_flag      = 4096;                 /* Mount flags */
        statfs->f_namemax   = CXFSNP_KEY_MAX_SIZE;  /* Maximum filename length */

        dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_statfs: "
                                             "statfs %s => reg ino %lu => done\n",
                                             (char *)cstring_get_str(path), ino);
        (*res) = 0;

        return (EC_TRUE);
    }

    if(CXFSNP_ATTR_FUSES_IS_DIR == CXFSNP_ATTR_FLAG(cxfsnp_attr))
    {
        statfs->f_bsize     = 4096;                 /* Filesystem block size */
        statfs->f_frsize    = 4096;                 /* Fragment size */
        statfs->f_blocks    = 0x00FFFFFF;           /* Size of fs in f_frsize units */
        statfs->f_bfree     = 0x00FFFFFF;           /* Number of free blocks */
        statfs->f_bavail    = 0x00FFFFFF;           /* Number of free blocks for unprivileged users */
        statfs->f_files     = 0x00FFFFFF;           /* Number of inodes */
        statfs->f_ffree     = 0x0FFFFFFF;           /* Number of free inodes */
        statfs->f_favail    = 0x0FFFFFFF;           /* Number of free inodes for unprivileged users */
        statfs->f_fsid      = 0x0FEFEFEF;           /* Filesystem ID */
        statfs->f_flag      = 4096;                 /* Mount flags */
        statfs->f_namemax   = CXFSNP_KEY_MAX_SIZE;  /* Maximum filename length */

        dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_statfs: "
                                             "statfs %s => dir ino %lu => done\n",
                                             (char *)cstring_get_str(path), ino);

        (*res) = 0;

        return (EC_TRUE);
    }

    dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_statfs: "
                                         "statfs %s => ino %lu, flag %u=> unsupported\n",
                                         (char *)cstring_get_str(path), ino,
                                         CXFSNP_ATTR_FLAG(cxfsnp_attr));

    (*res) = -ENOENT;

    return (EC_TRUE);
}

EC_BOOL cxfs_fuses_flush(const UINT32 cxfs_md_id, const CSTRING *path, int *res)
{
    CXFS_MD         *cxfs_md;
    uint64_t         ino;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_fuses_flush: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    CXFS_FUSES_DEBUG_ENTER("cxfs_fuses_flush");

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    CXFS_FUSES_CHECK_ENV(cxfs_md_id, cxfs_md, "cxfs_fuses_flush", res);

    if(NULL_PTR == __cxfs_fuses_lookup(cxfs_md_id, path, &ino))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_flush: "
                                             "cxfsnp mgr ino %s failed\n",
                                             (char *)cstring_get_str(path));
        (*res) = -ENOENT;
        return (EC_TRUE);
    }

    dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "[DEBUG] cxfs_fuses_flush: "
                                         "flush %s => ino %lu => done\n",
                                         (char *)cstring_get_str(path), ino);

    (*res) = 0;

    return (EC_TRUE);
}

EC_BOOL cxfs_fuses_release(const UINT32 cxfs_md_id, const CSTRING *path, int *res)
{
    CXFS_MD         *cxfs_md;
    uint64_t         ino;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_fuses_release: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    CXFS_FUSES_DEBUG_ENTER("cxfs_fuses_release");

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    CXFS_FUSES_CHECK_ENV(cxfs_md_id, cxfs_md, "cxfs_fuses_release", res);

    if(NULL_PTR == __cxfs_fuses_lookup(cxfs_md_id, path, &ino))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_release: "
                                             "cxfsnp mgr ino %s failed\n",
                                             (char *)cstring_get_str(path));
        (*res) = -ENOENT;
        return (EC_TRUE);
    }

    dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "[DEBUG] cxfs_fuses_release: "
                                         "release %s => ino %lu => done\n",
                                         (char *)cstring_get_str(path), ino);

    (*res) = 0;

    return (EC_TRUE);
}

EC_BOOL cxfs_fuses_fsync(const UINT32 cxfs_md_id, const CSTRING *path, const UINT32 datasync, int *res)
{
    CXFS_MD         *cxfs_md;
    uint64_t         ino;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_fuses_fsync: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    CXFS_FUSES_DEBUG_ENTER("cxfs_fuses_fsync");

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    CXFS_FUSES_CHECK_ENV(cxfs_md_id, cxfs_md, "cxfs_fuses_fsync", res);

    if(NULL_PTR == __cxfs_fuses_lookup(cxfs_md_id, path, &ino))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_fsync: "
                                             "cxfsnp mgr ino %s failed\n",
                                             (char *)cstring_get_str(path));
        (*res) = -ENOENT;
        return (EC_TRUE);
    }

    dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "[DEBUG] cxfs_fuses_fsync: "
                                         "fsync %s => ino %lu => done\n",
                                         (char *)cstring_get_str(path), ino);

    (*res) = 0;

    return (EC_TRUE);
}

EC_BOOL cxfs_fuses_setxattr(const UINT32 cxfs_md_id, const CSTRING *path, const CSTRING *name, const CBYTES *value, const UINT32 flags, int *res)
{
    CXFS_MD        *cxfs_md;
    uint64_t        ino;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_fuses_setxattr: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    CXFS_FUSES_DEBUG_ENTER("cxfs_fuses_setxattr");

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    CXFS_FUSES_CHECK_ENV(cxfs_md_id, cxfs_md, "cxfs_fuses_setxattr", res);

    (void)name;
    (void)value;
    (void)flags;

    if(NULL_PTR == __cxfs_fuses_lookup(cxfs_md_id, path, &ino))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_fuses_setxattr: "
                                             "cxfsnp mgr ino %s failed\n",
                                             (char *)cstring_get_str(path));
        (*res) = -ENOENT;
        return (EC_TRUE);
    }

    dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "[DEBUG] cxfs_fuses_setxattr: "
                                         "setxattr %s => ino %lu => not support\n",
                                         (char *)cstring_get_str(path), ino);

    (*res) = -ENOTSUP;

    return (EC_TRUE);
}

EC_BOOL cxfs_fuses_getxattr(const UINT32 cxfs_md_id, const CSTRING *path, const CSTRING *name, CBYTES *value, const UINT32 size, int *res)
{
    CXFS_MD        *cxfs_md;
    uint64_t        ino;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_fuses_getxattr: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    CXFS_FUSES_DEBUG_ENTER("cxfs_fuses_getxattr");

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    CXFS_FUSES_CHECK_ENV(cxfs_md_id, cxfs_md, "cxfs_fuses_getxattr", res);

    (void)name;
    (void)value;
    (void)size;

    if(NULL_PTR == __cxfs_fuses_lookup(cxfs_md_id, path, &ino))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_fuses_getxattr: "
                                             "cxfsnp mgr ino %s failed\n",
                                             (char *)cstring_get_str(path));
        (*res) = -ENOENT;
        return (EC_TRUE);
    }

    dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "[DEBUG] cxfs_fuses_getxattr: "
                                         "getxattr %s => ino %lu => not support\n",
                                         (char *)cstring_get_str(path), ino);

    (*res) = -ENODATA;
    cbytes_clean(value);

    return (EC_TRUE);
}

EC_BOOL cxfs_fuses_listxattr(const UINT32 cxfs_md_id, const CSTRING *path, CBYTES *value_list, const UINT32 size, int *res)
{
    CXFS_MD        *cxfs_md;
    uint64_t        ino;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_fuses_listxattr: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    CXFS_FUSES_DEBUG_ENTER("cxfs_fuses_listxattr");

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    CXFS_FUSES_CHECK_ENV(cxfs_md_id, cxfs_md, "cxfs_fuses_listxattr", res);

    (void)value_list;
    (void)size;

    if(NULL_PTR == __cxfs_fuses_lookup(cxfs_md_id, path, &ino))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_fuses_listxattr: "
                                             "cxfsnp mgr ino %s failed\n",
                                             (char *)cstring_get_str(path));
        (*res) = -ENOENT;
        return (EC_TRUE);
    }

    dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "[DEBUG] cxfs_fuses_listxattr: "
                                         "listxattr %s => ino %lu => not support\n",
                                         (char *)cstring_get_str(path), ino);

    (*res) = -ENOTSUP;

    return (EC_TRUE);
}

EC_BOOL cxfs_fuses_removexattr(const UINT32 cxfs_md_id, const CSTRING *path, const CSTRING *name, int *res)
{
    CXFS_MD        *cxfs_md;
    uint64_t        ino;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_fuses_removexattr: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    CXFS_FUSES_DEBUG_ENTER("cxfs_fuses_removexattr");

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    CXFS_FUSES_CHECK_ENV(cxfs_md_id, cxfs_md, "cxfs_fuses_removexattr", res);

    (void)name;

    if(NULL_PTR == __cxfs_fuses_lookup(cxfs_md_id, path, &ino))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_fuses_removexattr: "
                                             "cxfsnp mgr ino %s failed\n",
                                             (char *)cstring_get_str(path));
        (*res) = -ENOENT;
        return (EC_TRUE);
    }

    dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "[DEBUG] cxfs_fuses_removexattr: "
                                         "removexattr %s => ino %lu => not support\n",
                                         (char *)cstring_get_str(path), ino);

    (*res) = -ENOTSUP;

    return (EC_TRUE);
}

EC_BOOL cxfs_fuses_access(const UINT32 cxfs_md_id, const CSTRING *path, const UINT32 mask, UINT32 *mode, int *res)
{
    CXFS_MD         *cxfs_md;
    CXFSNP_ITEM     *cxfsnp_item;
    CXFSNP_ATTR     *cxfsnp_attr;
    uint64_t         ino;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_fuses_access: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    CXFS_FUSES_DEBUG_ENTER("cxfs_fuses_access");

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    CXFS_FUSES_CHECK_ENV(cxfs_md_id, cxfs_md, "cxfs_fuses_access", res);

    if(0 != (((uint16_t)mask) & (~(R_OK|W_OK|X_OK|F_OK))))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_access: "
                                             "invalid mask %#x\n",
                                             (uint16_t)mask);
        (*res) = -EINVAL;
        return (EC_TRUE);
    }

    cxfsnp_item = __cxfs_fuses_lookup(cxfs_md_id, path, &ino);
    if(NULL_PTR == cxfsnp_item)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_access: "
                                             "path '%s' ino %lu fetch item failed\n",
                                             (char *)cstring_get_str(path),
                                             ino);
        (*res) = -ENOENT;
        return (EC_TRUE);
    }

    cxfsnp_attr = CXFSNP_ITEM_ATTR(cxfsnp_item);
    if(((uint16_t)mask) == (CXFSNP_ATTR_MODE(cxfsnp_attr) & ((uint16_t)mask)))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "[DEBUG] cxfs_fuses_access: "
                                             "access %s => ino %lu, mode %o & mask %o = mask\n",
                                             (char *)cstring_get_str(path), ino,
                                             CXFSNP_ATTR_MODE(cxfsnp_attr),
                                             ((uint16_t)mask));

        if(NULL_PTR != mode)
        {
            (*mode) = CXFSNP_ATTR_MODE(cxfsnp_attr);
        }
        (*res) = 0;

        return (EC_TRUE);
    }

    dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_fuses_access: "
                                         "access %s => ino %lu, mode %o & mask %o != mask\n",
                                         (char *)cstring_get_str(path), ino,
                                         CXFSNP_ATTR_MODE(cxfsnp_attr),
                                         ((uint16_t)mask));

    (*res) = -EACCES;

    return (EC_TRUE);
}

EC_BOOL cxfs_fuses_ftruncate(const UINT32 cxfs_md_id, const CSTRING *path, const UINT32 length, int *res)
{
    CXFS_MD         *cxfs_md;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_fuses_ftruncate: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    CXFS_FUSES_DEBUG_ENTER("cxfs_fuses_ftruncate");

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    CXFS_FUSES_CHECK_ENV(cxfs_md_id, cxfs_md, "cxfs_fuses_ftruncate", res);

    return cxfs_fuses_truncate(cxfs_md_id, path, length, res);
}

EC_BOOL cxfs_fuses_utimens(const UINT32 cxfs_md_id, const CSTRING *path, const struct timespec *tv0, const struct timespec *tv1, int *res)
{
    CXFS_MD         *cxfs_md;
    CXFSNP_ITEM     *cxfsnp_item;
    CXFSNP_ATTR     *cxfsnp_attr;
    uint64_t         ino;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_fuses_utimens: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    CXFS_FUSES_DEBUG_ENTER("cxfs_fuses_utimens");

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    CXFS_FUSES_CHECK_ENV(cxfs_md_id, cxfs_md, "cxfs_fuses_utimens", res);

    cxfsnp_item = __cxfs_fuses_lookup(cxfs_md_id, path, &ino);
    if(NULL_PTR == cxfsnp_item)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_utimens: "
                                             "path '%s' ino %lu fetch item failed\n",
                                             (char *)cstring_get_str(path),
                                             ino);
        (*res) = -ENOENT;
        return (EC_TRUE);
    }

    cxfsnp_attr = CXFSNP_ITEM_ATTR(cxfsnp_item);

    CXFSNP_ATTR_ATIME_SEC(cxfsnp_attr)   = (uint64_t)tv0->tv_sec;
    CXFSNP_ATTR_MTIME_SEC(cxfsnp_attr)   = (uint64_t)tv1->tv_sec;

    CXFSNP_ATTR_ATIME_NSEC(cxfsnp_attr)  = (uint64_t)tv0->tv_nsec;
    CXFSNP_ATTR_MTIME_NSEC(cxfsnp_attr)  = (uint64_t)tv1->tv_nsec;

    dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_utimens: "
                                         "utimens %s => ino %lu, atime %lu:%u, mtime %lu:%u => done\n",
                                         (char *)cstring_get_str(path), ino,
                                         CXFSNP_ATTR_ATIME_SEC(cxfsnp_attr),
                                         CXFSNP_ATTR_ATIME_NSEC(cxfsnp_attr),
                                         CXFSNP_ATTR_MTIME_SEC(cxfsnp_attr),
                                         CXFSNP_ATTR_MTIME_NSEC(cxfsnp_attr));

    (*res) = 0;

    return (EC_TRUE);
}

EC_BOOL cxfs_fuses_fallocate(const UINT32 cxfs_md_id, const CSTRING *path, const UINT32 mode, const UINT32 offset, const UINT32 length, int *res)
{
    CXFS_MD         *cxfs_md;
    CXFSNP_ITEM     *cxfsnp_item;
    CBYTES           content;
    uint64_t         ino;

    uint64_t         nsec;  /*seconds*/
    uint64_t         nanosec;/*nanosecond*/

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_fuses_fallocate: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    CXFS_FUSES_DEBUG_ENTER("cxfs_fuses_fallocate");

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    CXFS_FUSES_CHECK_ENV(cxfs_md_id, cxfs_md, "cxfs_fuses_fallocate", res);

    if(NULL_PTR == __cxfs_fuses_lookup(cxfs_md_id, path, &ino))
    {
        c_get_cur_time_nsec_and_nanosec(&nsec, &nanosec);

        if(EC_FALSE == cxfs_reserve(cxfs_md_id, path, length))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_fallocate: "
                                                 "file %s reserve %ld failed\n",
                                                 (char *)cstring_get_str(path),
                                                 length);
            (*res) = -ENOENT;
            return (EC_TRUE);
        }

        cxfsnp_item = __cxfs_fuses_lookup(cxfs_md_id, path, &ino);
        if(NULL_PTR == cxfsnp_item)
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_fallocate: "
                                                 "path '%s' ino %lu fetch item failed\n",
                                                 (char *)cstring_get_str(path),
                                                 ino);
            (*res) = -ENOENT;
            return (EC_TRUE);
        }

        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "[DEBUG] cxfs_fuses_fallocate: "
                                             "fallocate %s => ino %lu => done\n",
                                             (char *)cstring_get_str(path), ino);

        (*res) = 0;

        return (EC_TRUE);
    }

    (void)offset;
    cbytes_init(&content);

    if(EC_FALSE == cxfs_read(cxfs_md_id, path, &content))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_fallocate: "
                                             "read %s failed\n",
                                             (char *)cstring_get_str(path));

        cbytes_clean(&content);

        (*res) = -EIO;
        return (EC_TRUE);
    }

    if(CBYTES_LEN(&content) > length)
    {
        CBYTES_LEN(&content) = length;
    }
    else
    {
        if(EC_FALSE == cbytes_expand_to(&content, length))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_fallocate: "
                                                 "file %s expand to %ld failed\n",
                                                 (char *)cstring_get_str(path),
                                                 length);

            cbytes_clean(&content);

            (*res) = -ENOMEM;
            return (EC_TRUE);
        }
    }

    if(EC_FALSE == cxfs_delete_file(cxfs_md_id, path))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_fallocate: "
                                             "delete %s failed\n",
                                             (char *)cstring_get_str(path));

        cbytes_clean(&content);

        (*res) = -EIO;
        return (EC_TRUE);
    }

    c_get_cur_time_nsec_and_nanosec(&nsec, &nanosec);

    if(EC_FALSE == cxfs_write(cxfs_md_id, path, &content))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_fallocate: "
                                             "write %s length %ld failed\n",
                                             (char *)cstring_get_str(path),
                                             CBYTES_LEN(&content));

        cbytes_clean(&content);

        (*res) = -EIO;
        return (EC_TRUE);
    }

    cbytes_clean(&content);

    cxfsnp_item = __cxfs_fuses_lookup(cxfs_md_id, path, &ino);
    if(NULL_PTR == cxfsnp_item)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_fallocate: "
                                             "path '%s' ino %lu fetch item failed\n",
                                             (char *)cstring_get_str(path),
                                             ino);
        (*res) = -ENOENT;
        return (EC_TRUE);
    }

    dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "[DEBUG] cxfs_fuses_fallocate: "
                                         "fallocate %s => ino %lu => done\n",
                                         (char *)cstring_get_str(path), ino);

    (*res) = 0;

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cxfs_fuses_readdir_walker(CXFSNP_DIT_NODE *cxfsnp_dit_node, CXFSNP *cxfsnp, CXFSNP_ITEM *cxfsnp_item, const uint32_t node_pos)
{
    CXFSNP_KEY                 *cxfsnp_key;
    CXFSNP_ATTR                *cxfsnp_attr;
    struct dirnode             *dirnode;
    CLIST                      *dirnode_list;

    uint64_t                    ino;
    uint32_t                    cxfsnp_id;

    enum fuse_readdir_flags     flags_t;

    if(CXFSNP_ITEM_IS_NOT_USED == CXFSNP_ITEM_USED_FLAG(cxfsnp_item))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_fuses_readdir_walker: "
                                             "item was not used\n");
        return (EC_FALSE);
    }

    if(0 == node_pos)/*root item*/
    {
        dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fuses_readdir_walker: "
                                             "skip root item\n");
        return (EC_TRUE);
    }

    cxfsnp_attr = CXFSNP_ITEM_ATTR(cxfsnp_item);

    if(CXFSNP_ATTR_FUSES_IS_DIR == CXFSNP_ATTR_FLAG(cxfsnp_attr)
    && 1 == CXFSNP_DIT_NODE_MAX_DEPTH(cxfsnp_dit_node))
    {
        dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fuses_readdir_walker: "
                                             "skip entrance dir item\n");
        return (EC_TRUE);
    }

    cxfsnp_id    = CXFSNP_DIT_NODE_CUR_NP_ID(cxfsnp_dit_node);

    flags_t      = (enum fuse_readdir_flags)CXFSNP_DIT_NODE_ARG(cxfsnp_dit_node, 1);
    dirnode_list = (CLIST                 *)CXFSNP_DIT_NODE_ARG(cxfsnp_dit_node, 2);

    cxfsnp_key  = CXFSNP_ITEM_KEY(cxfsnp_item);

    ASSERT(0 != CXFSNP_KEY_LEN(cxfsnp_key));

    dirnode = c_dirnode_new();
    if(NULL_PTR == dirnode)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_fuses_readdir_walker: "
                                             "new dirnode failed\n");
        return (EC_FALSE);
    }

    dirnode->flags = 0; /*enum fuse_fill_dir_flags*/

    dirnode->name = c_str_n_dup((char *)CXFSNP_KEY_NAME(cxfsnp_key), (uint32_t)CXFSNP_KEY_LEN(cxfsnp_key));
    if(NULL_PTR == dirnode->name)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_fuses_readdir_walker: "
                                             "dup '%.*s' failed\n",
                                             (uint32_t)CXFSNP_KEY_LEN(cxfsnp_key),
                                             (char   *)CXFSNP_KEY_NAME(cxfsnp_key));
        c_dirnode_free(dirnode);
        return (EC_FALSE);
    }

    ino = CXFSNP_ATTR_INO_MAKE(cxfsnp_id, node_pos);

    if(flags_t & FUSE_READDIR_PLUS)
    {
        dirnode->flags |= FUSE_FILL_DIR_PLUS;

        dirnode->stat.st_ino        = ino;
        dirnode->stat.st_mode       = CXFSNP_ATTR_MODE(cxfsnp_attr);
        dirnode->stat.st_uid        = CXFSNP_ATTR_UID(cxfsnp_attr);
        dirnode->stat.st_gid        = CXFSNP_ATTR_GID(cxfsnp_attr);
        dirnode->stat.st_rdev       = CXFSNP_ATTR_RDEV(cxfsnp_attr);

        dirnode->stat.st_atime      = CXFSNP_ATTR_ATIME_SEC(cxfsnp_attr);
        dirnode->stat.st_mtime      = CXFSNP_ATTR_MTIME_SEC(cxfsnp_attr);
        dirnode->stat.st_ctime      = CXFSNP_ATTR_CTIME_SEC(cxfsnp_attr);
        dirnode->stat.st_nlink      = CXFSNP_ATTR_NLINK(cxfsnp_attr);

        dirnode->stat.st_dev        = 0;/*xxx*/

        if(CXFSNP_ITEM_FILE_IS_REG == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))
        {
            CXFSNP_FNODE       *cxfsnp_fnode;

            cxfsnp_fnode = CXFSNP_ITEM_FNODE(cxfsnp_item);

            dirnode->stat.st_size       = CXFSNP_FNODE_FILESZ(cxfsnp_fnode);
            dirnode->stat.st_blksize    = CXFS_FUSES_BLOCK_SIZE;
            dirnode->stat.st_blocks     = CXFS_FUSES_SECTOR_NUM(CXFSNP_FNODE_FILESZ(cxfsnp_fnode));
        }
        else
        {
            CXFSNP_DNODE       *cxfsnp_dnode;

            cxfsnp_dnode = CXFSNP_ITEM_DNODE(cxfsnp_item);

            dirnode->stat.st_size       = CXFSNP_DNODE_FILE_SIZE(cxfsnp_dnode); /*xxx*/
            dirnode->stat.st_blksize    = CXFS_FUSES_BLOCK_SIZE; /*xxx*/
            dirnode->stat.st_blocks     = CXFS_FUSES_SECTOR_NUM(CXFSNP_DNODE_FILE_SIZE(cxfsnp_dnode));
        }
    }

	if(!(dirnode->flags & FUSE_FILL_DIR_PLUS))
	{
		dirnode->stat.st_ino  = ino;
		dirnode->stat.st_mode = CXFSNP_ATTR_MODE(cxfsnp_attr);
	}

	clist_push_back(dirnode_list, (void *)dirnode);

    return (EC_FALSE);
}

EC_BOOL cxfs_fuses_readdir(const UINT32 cxfs_md_id, const CSTRING *path, const UINT32 offset, const UINT32 flags, CLIST *dirnode_list, int *res)
{
    CXFS_MD   *cxfs_md;

    CXFSNP_DIT_NODE cxfsnp_dit_node;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_fuses_readdir: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    CXFS_FUSES_DEBUG_ENTER("cxfs_fuses_readdir");

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    (void)offset;

    CXFS_FUSES_CHECK_ENV(cxfs_md_id, cxfs_md, "cxfs_fuses_readdir", res);

    clist_codec_set(dirnode_list, MM_DIRNODE);

    cxfsnp_dit_node_init(&cxfsnp_dit_node);

    CXFSNP_DIT_NODE_HANDLER(&cxfsnp_dit_node)   = __cxfs_fuses_readdir_walker;
    CXFSNP_DIT_NODE_CUR_NP_ID(&cxfsnp_dit_node) = CXFSNP_ERR_ID;
    CXFSNP_DIT_NODE_MAX_DEPTH(&cxfsnp_dit_node) = 1;
    CXFSNP_DIT_NODE_ARG(&cxfsnp_dit_node, 0)    = (void *)cxfs_md_id;
    CXFSNP_DIT_NODE_ARG(&cxfsnp_dit_node, 1)    = (void *)flags;
    CXFSNP_DIT_NODE_ARG(&cxfsnp_dit_node, 2)    = (void *)dirnode_list;

    if(EC_FALSE == cxfsnp_mgr_walk(CXFS_MD_NPP(cxfs_md), path, CXFSNP_ITEM_FILE_IS_DIR, &cxfsnp_dit_node))
    {
        cxfsnp_dit_node_clean(&cxfsnp_dit_node);

        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_readdir: "
                                             "readdir '%s' failed\n",
                                             (char *)cstring_get_str(path));
        (*res) = -EACCES;
        return (EC_FALSE);
    }

    cxfsnp_dit_node_clean(&cxfsnp_dit_node);

    dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_readdir: "
                                         "readdir '%s' done\n",
                                         (char *)cstring_get_str(path));

    (*res) = 0;
    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/
