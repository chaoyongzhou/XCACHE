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

#define CXFS_FUSES_GOTO_HARD_LINK_TOP(cxfs_md, ino, cxfsnp_item, cxfsnp_attr) do{\
    if(CXFSNP_ATTR_LINK_HARD_MID == CXFSNP_ATTR_LINK_FLAG(cxfsnp_attr))     \
    {                                                                       \
        while(CXFSNP_ATTR_ERR_INO != CXFSNP_ATTR_NEXT_INO(cxfsnp_attr))     \
        {                                                                   \
            ino         = CXFSNP_ATTR_NEXT_INO(cxfsnp_attr);                \
            cxfsnp_item = cxfsnp_mgr_fetch_item(CXFS_MD_NPP(cxfs_md), ino); \
            cxfsnp_attr = CXFSNP_ITEM_ATTR(cxfsnp_item);                    \
        }                                                                   \
    }                                                                       \
}while(0)

#define CXFS_FUSES_PERM_SWITCH      (SWITCH_ON)

/*mode: O_RDONLY, O_WRONLY, O_RDWR*/
STATIC_CAST EC_BOOL __cxfs_fuses_check_access(const UINT32 cxfs_md_id, const uint64_t ino,
                                const uint32_t accmode, const uint32_t uid, const uint32_t gid)
{
    CXFS_MD         *cxfs_md;
    CXFSNP_ITEM     *cxfsnp_item;
    CXFSNP_ATTR     *cxfsnp_attr;

    static const char *accmode_str[] = {
        /*O_RDONLY = 0*/    "O_RDONLY",
        /*O_WRONLY = 1*/    "O_WRONLY",
        /*O_RDWR   = 2*/    "O_RDWR",
    };

    ASSERT(O_ACCMODE > accmode);

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    cxfsnp_item = cxfsnp_mgr_fetch_item(CXFS_MD_NPP(cxfs_md), ino);
    cxfsnp_attr = CXFSNP_ITEM_ATTR(cxfsnp_item);

    if(0 == uid || 0 == gid)
    {
        if(O_RDONLY == accmode)
        {
            CXFSNP_ITEM     *cxfsnp_item_parent;
            CXFSNP_ATTR     *cxfsnp_attr_parent;

            if(0 == (CXFSNP_ATTR_MODE(cxfsnp_attr) & (S_IRUSR | S_IRGRP | S_IROTH)))
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fuses_check_access: "
                                 "ino %lu, "
                                 "(accmode %s, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) "
                                 "=> uid = 0 or gid = 0, "
                                 "mode & (S_IRUSR | S_IRGRP | S_IROTH) == 0\n",
                                 ino, accmode_str[accmode], uid, gid,
                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                 CXFSNP_ATTR_GID(cxfsnp_attr));

                return (EC_FALSE);
            }

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fuses_check_access: "
                             "ino %lu, "
                             "(accmode %s, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) "
                             "=> uid = 0 or gid = 0, "
                             "mode & (S_IRUSR | S_IRGRP | S_IROTH) != 0 => check parent\n",
                             ino, accmode_str[accmode], uid, gid,
                             CXFSNP_ATTR_MODE(cxfsnp_attr),
                             CXFSNP_ATTR_UID(cxfsnp_attr),
                             CXFSNP_ATTR_GID(cxfsnp_attr));

            cxfsnp_item_parent = cxfsnp_mgr_fetch_parent_item(CXFS_MD_NPP(cxfs_md), ino);
            cxfsnp_attr_parent = CXFSNP_ITEM_ATTR(cxfsnp_item_parent);

            if(0 == (S_IXUSR & CXFSNP_ATTR_MODE(cxfsnp_attr_parent)))
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fuses_check_access: "
                                 "ino %lu, "
                                 "(accmode %s, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) "
                                 "=> uid = 0 or gid = 0, "
                                 "parent mode %#o & S_IXUSR == 0\n",
                                 ino, accmode_str[accmode], uid, gid,
                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                 CXFSNP_ATTR_GID(cxfsnp_attr),
                                 CXFSNP_ATTR_MODE(cxfsnp_attr_parent));

                return (EC_FALSE);
            }

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fuses_check_access: "
                             "ino %lu, "
                             "(accmode %s, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) "
                             "=> uid = 0 or gid = 0, "
                             "parent mode %#o & S_IXUSR != 0\n",
                             ino, accmode_str[accmode], uid, gid,
                             CXFSNP_ATTR_MODE(cxfsnp_attr),
                             CXFSNP_ATTR_UID(cxfsnp_attr),
                             CXFSNP_ATTR_GID(cxfsnp_attr),
                             CXFSNP_ATTR_MODE(cxfsnp_attr_parent));

            return (EC_TRUE);
        }
        else if(O_WRONLY == accmode)
        {
            if(0 == (CXFSNP_ATTR_MODE(cxfsnp_attr) & (S_IWUSR | S_IWGRP | S_IWOTH)))
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fuses_check_access: "
                                                     "ino %lu, "
                                                     "(accmode %s, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) "
                                                     "its mode %#o & (S_IWUSR | S_IWGRP S_IWOTH) == 0\n",
                                                     ino, accmode_str[accmode], uid, gid,
                                                     CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                     CXFSNP_ATTR_UID(cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(cxfsnp_attr));

                return (EC_FALSE);
            }

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fuses_check_access: "
                                                 "ino %lu, "
                                                 "(accmode %s, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) "
                                                 "its mode %#o & (S_IWUSR | S_IWGRP S_IWOTH) == 0\n",
                                                 ino, accmode_str[accmode], uid, gid,
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr));

            return (EC_TRUE);
        }
        else/*O_RDWR*/
        {
            if(0 == (CXFSNP_ATTR_MODE(cxfsnp_attr) & (S_IWUSR | S_IRUSR))
            && 0 == (CXFSNP_ATTR_MODE(cxfsnp_attr) & (S_IWGRP | S_IRGRP))
            && 0 == (CXFSNP_ATTR_MODE(cxfsnp_attr) & (S_IWOTH | S_IROTH)) )
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fuses_check_access: "
                                                     "ino %lu, "
                                                     "(accmode %s, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) "
                                                     "its mode & (S_IWUSR | S_IRUSR) == 0 && "
                                                     "its mode & (S_IWGRP | S_IRGRP) == 0 && "
                                                     "its mode & (S_IWOTH | S_IROTH) == 0\n",
                                                     ino, accmode_str[accmode], uid, gid,
                                                     CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                     CXFSNP_ATTR_UID(cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(cxfsnp_attr));

                return (EC_FALSE);
            }

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fuses_check_access: "
                                                 "ino %lu, "
                                                 "(accmode %s, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) "
                                                 "its mode & (S_IWUSR | S_IRUSR) != 0 || "
                                                 "its mode & (S_IWGRP | S_IRGRP) != 0 || "
                                                 "its mode & (S_IWOTH | S_IROTH) != 0\n",
                                                 ino, accmode_str[accmode], uid, gid,
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr));

            return (EC_TRUE);
        }
    }

    if(uid == CXFSNP_ATTR_UID(cxfsnp_attr) && gid == CXFSNP_ATTR_GID(cxfsnp_attr))
    {
        if(O_RDONLY == accmode)
        {
            CXFSNP_ITEM     *cxfsnp_item_parent;
            CXFSNP_ATTR     *cxfsnp_attr_parent;

            if(0 == (CXFSNP_ATTR_MODE(cxfsnp_attr) & (S_IRUSR)))
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fuses_check_access: "
                                 "ino %lu, "
                                 "(accmode %s, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) "
                                 "=> uid = 0 or gid = 0, "
                                 "mode & (S_IRUSR) == 0\n",
                                 ino, accmode_str[accmode], uid, gid,
                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                 CXFSNP_ATTR_GID(cxfsnp_attr));

                return (EC_FALSE);
            }

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fuses_check_access: "
                             "ino %lu, "
                             "(accmode %s, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) "
                             "=> uid = 0 or gid = 0, "
                             "mode & (S_IRUSR) != 0 => check parent\n",
                             ino, accmode_str[accmode], uid, gid,
                             CXFSNP_ATTR_MODE(cxfsnp_attr),
                             CXFSNP_ATTR_UID(cxfsnp_attr),
                             CXFSNP_ATTR_GID(cxfsnp_attr));

            cxfsnp_item_parent = cxfsnp_mgr_fetch_parent_item(CXFS_MD_NPP(cxfs_md), ino);
            cxfsnp_attr_parent = CXFSNP_ITEM_ATTR(cxfsnp_item_parent);

            if(0 == (S_IXUSR & CXFSNP_ATTR_MODE(cxfsnp_attr_parent)))
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fuses_check_access: "
                                 "ino %lu, "
                                 "(accmode %s, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) "
                                 "=> uid = 0 or gid = 0, "
                                 "parent mode %#o & S_IXUSR == 0\n",
                                 ino, accmode_str[accmode], uid, gid,
                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                 CXFSNP_ATTR_GID(cxfsnp_attr),
                                 CXFSNP_ATTR_MODE(cxfsnp_attr_parent));

                return (EC_FALSE);
            }

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fuses_check_access: "
                             "ino %lu, "
                             "(accmode %s, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) "
                             "=> uid = 0 or gid = 0, "
                             "parent mode %#o & S_IXUSR != 0\n",
                             ino, accmode_str[accmode], uid, gid,
                             CXFSNP_ATTR_MODE(cxfsnp_attr),
                             CXFSNP_ATTR_UID(cxfsnp_attr),
                             CXFSNP_ATTR_GID(cxfsnp_attr),
                             CXFSNP_ATTR_MODE(cxfsnp_attr_parent));

            return (EC_TRUE);
        }
        else if(O_WRONLY == accmode)
        {
            if(0 == (CXFSNP_ATTR_MODE(cxfsnp_attr) & (S_IWUSR)))
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fuses_check_access: "
                                 "ino %lu, "
                                 "(accmode %s, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) => uid & gid matched, "
                                 "mode & S_IWUSR == 0\n",
                                 ino, accmode_str[accmode], uid, gid,
                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                 CXFSNP_ATTR_GID(cxfsnp_attr));

                return (EC_FALSE);
            }

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fuses_check_access: "
                             "ino %lu, "
                             "(accmode %s, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) => uid & gid matched, "
                             "mode & S_IWUSR != 0\n",
                             ino, accmode_str[accmode], uid, gid,
                             CXFSNP_ATTR_MODE(cxfsnp_attr),
                             CXFSNP_ATTR_UID(cxfsnp_attr),
                             CXFSNP_ATTR_GID(cxfsnp_attr));

            return (EC_TRUE);
        }
        else/*O_RDWR*/
        {
            if(0 == (CXFSNP_ATTR_MODE(cxfsnp_attr) & (S_IRUSR))
            || 0 == (CXFSNP_ATTR_MODE(cxfsnp_attr) & (S_IWUSR)))
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fuses_check_access: "
                                 "ino %lu, "
                                 "(accmode %s, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) => uid & gid matched, "
                                 "mode & S_IRUSR == 0 || mode & S_IWUSR == 0\n",
                                 ino, accmode_str[accmode], uid, gid,
                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                 CXFSNP_ATTR_GID(cxfsnp_attr));

                return (EC_FALSE);
            }

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fuses_check_access: "
                             "ino %lu, "
                             "(accmode %s, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) => uid & gid matched, "
                             "mode & S_IWUSR != 0 && mode & S_IWUSR != 0\n",
                             ino, accmode_str[accmode], uid, gid,
                             CXFSNP_ATTR_MODE(cxfsnp_attr),
                             CXFSNP_ATTR_UID(cxfsnp_attr),
                             CXFSNP_ATTR_GID(cxfsnp_attr));

            return (EC_TRUE);
        }
    }

    if(gid == CXFSNP_ATTR_GID(cxfsnp_attr))
    {
        if(O_RDONLY == accmode)
        {
            CXFSNP_ITEM     *cxfsnp_item_parent;
            CXFSNP_ATTR     *cxfsnp_attr_parent;

            if(0 == (CXFSNP_ATTR_MODE(cxfsnp_attr) & (S_IRGRP)))
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fuses_check_access: "
                                 "ino %lu, "
                                 "(accmode %s, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) "
                                 "=> uid = 0 or gid = 0, "
                                 "mode & (S_IRGRP) == 0\n",
                                 ino, accmode_str[accmode], uid, gid,
                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                 CXFSNP_ATTR_GID(cxfsnp_attr));

                return (EC_FALSE);
            }

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fuses_check_access: "
                             "ino %lu, "
                             "(accmode %s, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) "
                             "=> uid = 0 or gid = 0, "
                             "mode & (S_IRGRP) != 0 => check parent\n",
                             ino, accmode_str[accmode], uid, gid,
                             CXFSNP_ATTR_MODE(cxfsnp_attr),
                             CXFSNP_ATTR_UID(cxfsnp_attr),
                             CXFSNP_ATTR_GID(cxfsnp_attr));

            cxfsnp_item_parent = cxfsnp_mgr_fetch_parent_item(CXFS_MD_NPP(cxfs_md), ino);
            cxfsnp_attr_parent = CXFSNP_ITEM_ATTR(cxfsnp_item_parent);

            if(0 == (S_IXUSR & CXFSNP_ATTR_MODE(cxfsnp_attr_parent)))
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fuses_check_access: "
                                 "ino %lu, "
                                 "(accmode %s, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) "
                                 "=> uid = 0 or gid = 0, "
                                 "parent mode %#o & S_IXUSR == 0\n",
                                 ino, accmode_str[accmode], uid, gid,
                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                 CXFSNP_ATTR_GID(cxfsnp_attr),
                                 CXFSNP_ATTR_MODE(cxfsnp_attr_parent));

                return (EC_FALSE);
            }

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fuses_check_access: "
                             "ino %lu, "
                             "(accmode %s, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) "
                             "=> uid = 0 or gid = 0, "
                             "parent mode %#o & S_IXUSR != 0\n",
                             ino, accmode_str[accmode], uid, gid,
                             CXFSNP_ATTR_MODE(cxfsnp_attr),
                             CXFSNP_ATTR_UID(cxfsnp_attr),
                             CXFSNP_ATTR_GID(cxfsnp_attr),
                             CXFSNP_ATTR_MODE(cxfsnp_attr_parent));

            return (EC_TRUE);
        }
        else if(O_WRONLY == accmode)
        {
            if(0 == (CXFSNP_ATTR_MODE(cxfsnp_attr) & (S_IWGRP)))
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fuses_check_access: "
                                 "ino %lu, "
                                 "(accmode %s, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) => gid matched, "
                                 "mode & S_IWGRP == 0\n",
                                 ino, accmode_str[accmode], uid, gid,
                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                 CXFSNP_ATTR_GID(cxfsnp_attr));

                return (EC_FALSE);
            }

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fuses_check_access: "
                             "ino %lu, "
                             "(accmode %s, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) => gid matched, "
                             "mode & S_IWGRP != 0\n",
                             ino, accmode_str[accmode], uid, gid,
                             CXFSNP_ATTR_MODE(cxfsnp_attr),
                             CXFSNP_ATTR_UID(cxfsnp_attr),
                             CXFSNP_ATTR_GID(cxfsnp_attr));

            return (EC_TRUE);
        }
        else/*O_RDWR*/
        {
            if(0 == (CXFSNP_ATTR_MODE(cxfsnp_attr) & (S_IRGRP))
            || 0 == (CXFSNP_ATTR_MODE(cxfsnp_attr) & (S_IWGRP)))
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fuses_check_access: "
                                 "ino %lu, "
                                 "(accmode %s, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) => gid matched, "
                                 "mode & S_IRGRP == 0 || mode & S_IWGRP == 0\n",
                                 ino, accmode_str[accmode], uid, gid,
                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                 CXFSNP_ATTR_GID(cxfsnp_attr));

                return (EC_FALSE);
            }

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fuses_check_access: "
                             "ino %lu, "
                             "(accmode %s, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) => gid matched, "
                             "mode & S_IWGRP != 0 && mode & S_IWGRP != 0\n",
                             ino, accmode_str[accmode], uid, gid,
                             CXFSNP_ATTR_MODE(cxfsnp_attr),
                             CXFSNP_ATTR_UID(cxfsnp_attr),
                             CXFSNP_ATTR_GID(cxfsnp_attr));

            return (EC_TRUE);
        }
    }


    /*other*/
    if(O_RDONLY == accmode)
    {
        CXFSNP_ITEM     *cxfsnp_item_parent;
        CXFSNP_ATTR     *cxfsnp_attr_parent;

        if(0 == (CXFSNP_ATTR_MODE(cxfsnp_attr) & (S_IROTH)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fuses_check_access: "
                             "ino %lu, "
                             "(accmode %s, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) "
                             "=> uid = 0 or gid = 0, "
                             "mode & (S_IROTH) == 0\n",
                             ino, accmode_str[accmode], uid, gid,
                             CXFSNP_ATTR_MODE(cxfsnp_attr),
                             CXFSNP_ATTR_UID(cxfsnp_attr),
                             CXFSNP_ATTR_GID(cxfsnp_attr));

            return (EC_FALSE);
        }

        dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fuses_check_access: "
                         "ino %lu, "
                         "(accmode %s, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) "
                         "=> uid = 0 or gid = 0, "
                         "mode & (S_IROTH) != 0 => check parent\n",
                         ino, accmode_str[accmode], uid, gid,
                         CXFSNP_ATTR_MODE(cxfsnp_attr),
                         CXFSNP_ATTR_UID(cxfsnp_attr),
                         CXFSNP_ATTR_GID(cxfsnp_attr));

        cxfsnp_item_parent = cxfsnp_mgr_fetch_parent_item(CXFS_MD_NPP(cxfs_md), ino);
        cxfsnp_attr_parent = CXFSNP_ITEM_ATTR(cxfsnp_item_parent);

        if(0 == (S_IXUSR & CXFSNP_ATTR_MODE(cxfsnp_attr_parent)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fuses_check_access: "
                             "ino %lu, "
                             "(accmode %s, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) "
                             "=> uid = 0 or gid = 0, "
                             "parent mode %#o & S_IXUSR == 0\n",
                             ino, accmode_str[accmode], uid, gid,
                             CXFSNP_ATTR_MODE(cxfsnp_attr),
                             CXFSNP_ATTR_UID(cxfsnp_attr),
                             CXFSNP_ATTR_GID(cxfsnp_attr),
                             CXFSNP_ATTR_MODE(cxfsnp_attr_parent));

            return (EC_FALSE);
        }

        dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fuses_check_access: "
                         "ino %lu, "
                         "(accmode %s, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) "
                         "=> uid = 0 or gid = 0, "
                         "parent mode %#o & S_IXUSR != 0\n",
                         ino, accmode_str[accmode], uid, gid,
                         CXFSNP_ATTR_MODE(cxfsnp_attr),
                         CXFSNP_ATTR_UID(cxfsnp_attr),
                         CXFSNP_ATTR_GID(cxfsnp_attr),
                         CXFSNP_ATTR_MODE(cxfsnp_attr_parent));

        return (EC_TRUE);
    }
    else if(O_WRONLY == accmode)
    {
        if(0 == (CXFSNP_ATTR_MODE(cxfsnp_attr) & (S_IWOTH)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fuses_check_access: "
                             "ino %lu, "
                             "(accmode %s, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) => other, "
                             "mode & S_IWOTH == 0\n",
                             ino, accmode_str[accmode], uid, gid,
                             CXFSNP_ATTR_MODE(cxfsnp_attr),
                             CXFSNP_ATTR_UID(cxfsnp_attr),
                             CXFSNP_ATTR_GID(cxfsnp_attr));

            return (EC_FALSE);
        }

        dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fuses_check_access: "
                         "ino %lu, "
                         "(accmode %s, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) => other, "
                         "mode & S_IWOTH != 0\n",
                         ino, accmode_str[accmode], uid, gid,
                         CXFSNP_ATTR_MODE(cxfsnp_attr),
                         CXFSNP_ATTR_UID(cxfsnp_attr),
                         CXFSNP_ATTR_GID(cxfsnp_attr));

        return (EC_TRUE);
    }
    else /*O_RDWR*/
    {
        if(0 == (CXFSNP_ATTR_MODE(cxfsnp_attr) & (S_IROTH))
        || 0 == (CXFSNP_ATTR_MODE(cxfsnp_attr) & (S_IWOTH)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fuses_check_access: "
                             "ino %lu, "
                             "(accmode %s, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) => other, "
                             "mode & S_IROTH == 0 || mode & S_IWOTH == 0\n",
                             ino, accmode_str[accmode], uid, gid,
                             CXFSNP_ATTR_MODE(cxfsnp_attr),
                             CXFSNP_ATTR_UID(cxfsnp_attr),
                             CXFSNP_ATTR_GID(cxfsnp_attr));

            return (EC_FALSE);
        }

        dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fuses_check_access: "
                         "ino %lu, "
                         "(accmode %s, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) => other, "
                         "mode & S_IROTH != 0 && mode & S_IWOTH != 0\n",
                         ino, accmode_str[accmode], uid, gid,
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

STATIC_CAST CXFSNP_ITEM *__cxfs_fuses_lookup_parent(const UINT32 cxfs_md_id, const CSTRING *path, uint64_t *ino)
{
    CXFSNP_ITEM     *parent_item;
    CSTRING          parent_path_cstr;
    char            *parent_path;
    uint64_t         parent_ino;
    uint32_t         parent_path_len;

    parent_path = c_dirname((char *)cstring_get_str(path));
    if(NULL_PTR == parent_path)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_fuses_lookup_parent: "
                                             "dirname '%s', failed\n",
                                             (char *)cstring_get_str(path));
        return (NULL_PTR);
    }

    parent_path_len = strlen(parent_path);

    cstring_mount(&parent_path_cstr, (UINT8 *)parent_path, parent_path_len, parent_path_len + 1);

    parent_item = __cxfs_fuses_lookup(cxfs_md_id, &parent_path_cstr, &parent_ino);
    if(NULL_PTR == parent_item)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_fuses_lookup_parent: "
                                             "find parent '%s' of '%s' failed\n",
                                             parent_path,
                                             (char *)cstring_get_str(path));
        c_str_free(parent_path);

        return (NULL_PTR);
    }
    c_str_free(parent_path);

    if(NULL_PTR != ino)
    {
        (*ino) = parent_ino;
    }

    return (parent_item);
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
    CXFSNP_ATTR  *cxfsnp_attr;

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
    cxfsnp_attr  = CXFSNP_ITEM_ATTR(cxfsnp_item);

    if(CXFSNP_ATTR_IS_HIDE == CXFSNP_ATTR_HIDE_FLAG(cxfsnp_attr))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_fuses_getattr: "
                                             "%s is hide file or dir => nlink %u\n",
                                             (char *)cstring_get_str(file_path),
                                             CXFSNP_ATTR_NLINK(cxfsnp_attr));

        (*res) = -ENOENT;
        return (EC_TRUE);
    }

    if(do_log(SEC_0192_CXFS, 2))
    {
        cxfsnp_attr_print(LOGSTDOUT, cxfsnp_attr);
    }

    if(CXFSNP_ATTR_LINK_HARD_MASK & CXFSNP_ATTR_LINK_FLAG(cxfsnp_attr))
    {
        CXFS_FUSES_GOTO_HARD_LINK_TOP(cxfs_md, ino, cxfsnp_item, cxfsnp_attr);
    }

    if(NULL_PTR != stat)
    {
        CXFSNP_DNODE *cxfsnp_dnode;

        cxfsnp_dnode = CXFSNP_ITEM_DNODE(cxfsnp_item);

        stat->st_ino                = ino;

        stat->st_mode               = CXFSNP_ATTR_MODE(cxfsnp_attr);
        stat->st_uid                = CXFSNP_ATTR_UID(cxfsnp_attr);
        stat->st_gid                = CXFSNP_ATTR_GID(cxfsnp_attr);
        stat->st_rdev               = CXFS_FUSES_RDEV_DEFAULT;

        stat->st_atim.tv_sec        = CXFSNP_ATTR_ATIME_SEC(cxfsnp_attr);
        stat->st_mtim.tv_sec        = CXFSNP_ATTR_MTIME_SEC(cxfsnp_attr);
        stat->st_ctim.tv_sec        = CXFSNP_ATTR_CTIME_SEC(cxfsnp_attr);

        stat->st_atim.tv_nsec       = CXFSNP_ATTR_ATIME_NSEC(cxfsnp_attr);
        stat->st_mtim.tv_nsec       = CXFSNP_ATTR_MTIME_NSEC(cxfsnp_attr);
        stat->st_ctim.tv_nsec       = CXFSNP_ATTR_CTIME_NSEC(cxfsnp_attr);
        stat->st_nlink              = CXFSNP_ATTR_NLINK(cxfsnp_attr);
        stat->st_dev                = CXFSNP_ATTR_DEV(cxfsnp_attr);/*st_dev ignored by fuse*/

        stat->st_size               = CXFSNP_DNODE_FILE_SIZE(cxfsnp_dnode); /*xxx*/
        stat->st_blksize            = CXFS_FUSES_BLOCK_SIZE; /*st_blksize ignored by fuse*/
        stat->st_blocks             = CXFS_FUSES_SECTOR_NUM(CXFSNP_DNODE_FILE_SIZE(cxfsnp_dnode));

        if(do_log(SEC_0192_CXFS, 2))
        {
            sys_log(LOGSTDOUT, "[DEBUG] cxfs_fuses_getattr: path %s\n", (char *)cstring_get_str(file_path));
            sys_log(LOGSTDOUT, "[DEBUG] cxfs_fuses_getattr: st_dev     = %#x\n", stat->st_dev);
            sys_log(LOGSTDOUT, "[DEBUG] cxfs_fuses_getattr: st_ino     = %lu\n", stat->st_ino);
            sys_log(LOGSTDOUT, "[DEBUG] cxfs_fuses_getattr: st_mode    = %#o\n", stat->st_mode);
            sys_log(LOGSTDOUT, "[DEBUG] cxfs_fuses_getattr: st_nlink   = %d\n", stat->st_nlink);
            sys_log(LOGSTDOUT, "[DEBUG] cxfs_fuses_getattr: st_uid     = %u\n", stat->st_uid);
            sys_log(LOGSTDOUT, "[DEBUG] cxfs_fuses_getattr: st_gid     = %u\n", stat->st_gid);
            sys_log(LOGSTDOUT, "[DEBUG] cxfs_fuses_getattr: st_rdev    = %u\n", stat->st_rdev);
            sys_log(LOGSTDOUT, "[DEBUG] cxfs_fuses_getattr: st_size    = %ld\n", stat->st_size);
            sys_log(LOGSTDOUT, "[DEBUG] cxfs_fuses_getattr: st_blksize = %d\n", stat->st_blksize);
            sys_log(LOGSTDOUT, "[DEBUG] cxfs_fuses_getattr: st_blocks  = %ld\n", stat->st_blocks);
            sys_log(LOGSTDOUT, "[DEBUG] cxfs_fuses_getattr: st_atime   = %ld %ld\n", stat->st_atim.tv_sec, stat->st_atim.tv_nsec);
            sys_log(LOGSTDOUT, "[DEBUG] cxfs_fuses_getattr: st_mtime   = %ld %ld\n", stat->st_mtim.tv_sec, stat->st_mtim.tv_nsec);
            sys_log(LOGSTDOUT, "[DEBUG] cxfs_fuses_getattr: st_ctime   = %ld %ld\n", stat->st_ctim.tv_sec, stat->st_ctim.tv_nsec);
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

    ASSERT(uid == (uid & CXFS_FUSES_UID_MASK));
    ASSERT(gid == (gid & CXFS_FUSES_GID_MASK));

    if(CXFS_FUSES_PERM_SWITCH == SWITCH_ON
    && 0 != uid && 0 != gid) /*not root*/
    {
        CXFSNP_ITEM     *cxfsnp_item_parent;
        CXFSNP_ATTR     *cxfsnp_attr_parent;
        uint64_t         ino_parent;

        cxfsnp_item_parent = __cxfs_fuses_lookup_parent(cxfs_md_id, path, &ino_parent);
        if(NULL_PTR == cxfsnp_item_parent)
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_mknod: "
                                                 "lookup parent of '%s' failed\n",
                                                 (char *)cstring_get_str(path));
            (*res) = -ENOENT;
            return (EC_TRUE);
        }
        cxfsnp_attr_parent = CXFSNP_ITEM_ATTR(cxfsnp_item_parent);

        if(CXFS_FUSES_UID_ERR == (uint32_t)uid)
        {
            if(CXFSNP_ATTR_UID(cxfsnp_attr_parent) != (uint32_t)uid)
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_mknod: "
                                                     "'%s', uid %u, parent uid %u => not matched\n",
                                                     (char *)cstring_get_str(path),
                                                     (uint32_t)uid, CXFSNP_ATTR_UID(cxfsnp_attr_parent));
                (*res) = -EACCES;
                return (EC_TRUE);
            }
        }
        else
        {
            if(CXFSNP_ATTR_UID(cxfsnp_attr_parent) == (uint32_t)uid
            && 0 == (S_IWUSR & CXFSNP_ATTR_MODE(cxfsnp_attr_parent)))
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_mknod: "
                                                     "'%s', parent ino %lu, "
                                                     "uid %u same, parent mode %#o & (S_IWUSR) == 0 "
                                                     "=> deny (uid %u, gid %u) mode %#o\n",
                                                     (char *)cstring_get_str(path), ino_parent,
                                                     (uint32_t)uid,
                                                     CXFSNP_ATTR_MODE(cxfsnp_attr_parent),
                                                     (uint32_t)uid, (uint32_t)gid, (uint16_t)mode);
                (*res) = -EACCES;
                return (EC_TRUE);
            }

            if(CXFSNP_ATTR_UID(cxfsnp_attr_parent) != (uint32_t)uid
            && 0 == (S_IXOTH & CXFSNP_ATTR_MODE(cxfsnp_attr_parent)))
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_mknod: "
                                                     "path '%s', parent ino %lu, "
                                                     "parent mode %#o & (S_IXOTH) == 0 "
                                                     "=> deny (uid %u, gid %u) mode %#o\n",
                                                     (char *)cstring_get_str(path), ino_parent,
                                                     CXFSNP_ATTR_MODE(cxfsnp_attr_parent),
                                                     (uint32_t)uid, (uint32_t)gid, (uint16_t)mode);

                (*res) = -EACCES;
                return (EC_TRUE);
            }
        }

        if(CXFS_FUSES_GID_ERR == (uint32_t)gid)
        {
            if(CXFSNP_ATTR_GID(cxfsnp_attr_parent) != (uint32_t)gid)
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_mknod: "
                                                     "'%s', gid %#x overflow\n",
                                                     (char *)cstring_get_str(path),
                                                     (uint32_t)gid);
                (*res) = -EOVERFLOW;
                return (EC_TRUE);
            }
        }
        else
        {
            if(0 == (S_IXGRP & CXFSNP_ATTR_MODE(cxfsnp_attr_parent)))
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_mknod: "
                                                     "path '%s', parent ino %lu, "
                                                     "parent mode %#o & (S_IXGRP) == 0 "
                                                     "=> deny (uid %u, gid %u)\n",
                                                     (char *)cstring_get_str(path),
                                                     ino_parent,
                                                     CXFSNP_ATTR_MODE(cxfsnp_attr_parent),
                                                     (uint32_t)uid,
                                                     (uint32_t)gid);

                (*res) = -EACCES;
                return (EC_TRUE);
            }
        }
    }

    cxfsnp_item = __cxfs_fuses_lookup(cxfs_md_id, path, &ino);
    if(NULL_PTR != cxfsnp_item)
    {
        cxfsnp_attr = CXFSNP_ITEM_ATTR(cxfsnp_item);

        if(EC_FALSE == __cxfs_fuses_make_empty_hidden_seg(cxfs_md_id, path, res))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_mknod: "
                                                 "%s, make hidden seg file failed\n",
                                                 (char *)cstring_get_str(path));
            (*res) = -EACCES;
            return (EC_TRUE);
        }

        CXFSNP_ATTR_HIDE_FLAG(cxfsnp_attr)  = CXFSNP_ATTR_NOT_HIDE;

        cxfsnp_attr_set_file(cxfsnp_attr);
        CXFSNP_ATTR_MODE(cxfsnp_attr)       = (uint16_t)mode;
        CXFSNP_ATTR_UID(cxfsnp_attr)        = (uint32_t)uid;
        CXFSNP_ATTR_GID(cxfsnp_attr)        = (uint32_t)gid;
        CXFSNP_ATTR_DEV(cxfsnp_attr)        = (uint32_t)dev;

        dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_mknod: "
                                             "[obscure] %s, mode %#o => ino %lu => mode %#o uid %u, gid %u, dev %#x => done\n",
                                             (char *)cstring_get_str(path), (uint16_t)mode, ino,
                                             CXFSNP_ATTR_MODE(cxfsnp_attr),
                                             CXFSNP_ATTR_UID(cxfsnp_attr),
                                             CXFSNP_ATTR_GID(cxfsnp_attr),
                                             CXFSNP_ATTR_DEV(cxfsnp_attr));

        (*res) = 0;

        return (EC_TRUE);
    }

    if(EC_FALSE == cxfs_mkdir(cxfs_md_id, path))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_mknod: "
                                             "mkdir '%s' failed\n",
                                             (char *)cstring_get_str(path));
        (*res) = -EACCES;
        return (EC_TRUE);
    }

    if(EC_FALSE == __cxfs_fuses_make_empty_hidden_seg(cxfs_md_id, path, res))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_mknod: "
                                             "%s, make hidden seg file failed\n",
                                             (char *)cstring_get_str(path));
        (*res) = -EACCES;
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
    CXFSNP_ATTR_HIDE_FLAG(cxfsnp_attr)  = CXFSNP_ATTR_NOT_HIDE;

    CXFSNP_ATTR_MODE(cxfsnp_attr)       = (uint16_t)mode;
    CXFSNP_ATTR_UID(cxfsnp_attr)        = (uint32_t)uid;
    CXFSNP_ATTR_GID(cxfsnp_attr)        = (uint32_t)gid;
    CXFSNP_ATTR_DEV(cxfsnp_attr)        = (uint32_t)dev;

    dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_mknod: "
                                         "%s, mode %#o => ino %lu => mode %#o uid %u, gid %u, dev %#x => done\n",
                                         (char *)cstring_get_str(path), (uint16_t)mode, ino,
                                         CXFSNP_ATTR_MODE(cxfsnp_attr),
                                         CXFSNP_ATTR_UID(cxfsnp_attr),
                                         CXFSNP_ATTR_GID(cxfsnp_attr),
                                         CXFSNP_ATTR_DEV(cxfsnp_attr));

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

    ASSERT(uid == (uid & CXFS_FUSES_UID_MASK));
    ASSERT(gid == (gid & CXFS_FUSES_GID_MASK));

    if(CXFS_FUSES_PERM_SWITCH == SWITCH_ON
    && 0 != uid && 0 != gid) /*not root*/
    {
        CXFSNP_ITEM     *cxfsnp_item_parent;
        CXFSNP_ATTR     *cxfsnp_attr_parent;
        uint64_t         ino_parent;

        cxfsnp_item_parent = __cxfs_fuses_lookup_parent(cxfs_md_id, path, &ino_parent);
        if(NULL_PTR == cxfsnp_item_parent)
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_mkdir: "
                                                 "lookup parent of '%s' failed\n",
                                                 (char *)cstring_get_str(path));
            (*res) = -ENOENT;
            return (EC_TRUE);
        }
        cxfsnp_attr_parent = CXFSNP_ITEM_ATTR(cxfsnp_item_parent);

        if(CXFS_FUSES_UID_ERR == (uint32_t)uid)
        {
            if(CXFSNP_ATTR_UID(cxfsnp_attr_parent) != (uint32_t)uid)
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_mkdir: "
                                                     "'%s', uid %u, parent uid %u => not matched\n",
                                                     (char *)cstring_get_str(path),
                                                     (uint32_t)uid, CXFSNP_ATTR_UID(cxfsnp_attr_parent));
                (*res) = -EACCES;
                return (EC_TRUE);
            }
        }
        else
        {
            if(CXFSNP_ATTR_UID(cxfsnp_attr_parent) == (uint32_t)uid
            && 0 == (S_IWUSR & CXFSNP_ATTR_MODE(cxfsnp_attr_parent)))
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_mkdir: "
                                                     "'%s', parent ino %lu, "
                                                     "uid %u same, parent mode %#o & (S_IWUSR) == 0 "
                                                     "=> deny (uid %u, gid %u) mode %#o\n",
                                                     (char *)cstring_get_str(path), ino_parent,
                                                     (uint32_t)uid,
                                                     CXFSNP_ATTR_MODE(cxfsnp_attr_parent),
                                                     (uint32_t)uid, (uint32_t)gid, (uint16_t)mode);
                (*res) = -EACCES;
                return (EC_TRUE);
            }

            if(CXFSNP_ATTR_UID(cxfsnp_attr_parent) != (uint32_t)uid
            && 0 == (S_IXOTH & CXFSNP_ATTR_MODE(cxfsnp_attr_parent)))
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_mkdir: "
                                                     "path '%s', parent ino %lu, "
                                                     "parent mode %#o & (S_IXOTH) == 0 "
                                                     "=> deny (uid %u, gid %u) mode %#o\n",
                                                     (char *)cstring_get_str(path), ino_parent,
                                                     CXFSNP_ATTR_MODE(cxfsnp_attr_parent),
                                                     (uint32_t)uid, (uint32_t)gid, (uint16_t)mode);

                (*res) = -EACCES;
                return (EC_TRUE);
            }
        }

        if(CXFS_FUSES_GID_ERR == (uint32_t)gid)
        {
            if(CXFSNP_ATTR_GID(cxfsnp_attr_parent) != (uint32_t)gid)
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_mkdir: "
                                                     "'%s', gid %#x overflow\n",
                                                     (char *)cstring_get_str(path),
                                                     (uint32_t)gid);
                (*res) = -EOVERFLOW;
                return (EC_TRUE);
            }
        }
        else
        {
            if(0 == (S_IXGRP & CXFSNP_ATTR_MODE(cxfsnp_attr_parent)))
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_mkdir: "
                                                     "path '%s', parent ino %lu, "
                                                     "parent mode %#o & (S_IXGRP) == 0 "
                                                     "=> deny (uid %u, gid %u)\n",
                                                     (char *)cstring_get_str(path),
                                                     ino_parent,
                                                     CXFSNP_ATTR_MODE(cxfsnp_attr_parent),
                                                     (uint32_t)uid,
                                                     (uint32_t)gid);

                (*res) = -EACCES;
                return (EC_TRUE);
            }
        }
    }

    cxfsnp_item = __cxfs_fuses_lookup(cxfs_md_id, path, &ino);
    if(NULL_PTR != cxfsnp_item)
    {
        cxfsnp_attr = CXFSNP_ITEM_ATTR(cxfsnp_item);

        ASSERT(CXFSNP_ATTR_IS_HIDE == CXFSNP_ATTR_HIDE_FLAG(cxfsnp_attr));

        cxfsnp_attr_set_dir(cxfsnp_attr);
        CXFSNP_ATTR_HIDE_FLAG(cxfsnp_attr)  = CXFSNP_ATTR_NOT_HIDE;
        CXFSNP_ATTR_MODE(cxfsnp_attr)       = (uint16_t)(mode | S_IFDIR);
        CXFSNP_ATTR_UID(cxfsnp_attr)        = (uint32_t)uid;
        CXFSNP_ATTR_GID(cxfsnp_attr)        = (uint32_t)gid;

        dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_mkdir: "
                                             "[obscure] mkdir %s => ino %lu => mode %#o uid %u, gid %u => done\n",
                                             (char *)cstring_get_str(path), ino,
                                             CXFSNP_ATTR_MODE(cxfsnp_attr),
                                             CXFSNP_ATTR_UID(cxfsnp_attr),
                                             CXFSNP_ATTR_GID(cxfsnp_attr));

        (*res) = 0;

        return (EC_TRUE);
    }

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
    CXFSNP_ATTR_HIDE_FLAG(cxfsnp_attr)  = CXFSNP_ATTR_NOT_HIDE;
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

EC_BOOL cxfs_fuses_unlink(const UINT32 cxfs_md_id, const CSTRING *path, const UINT32 uid, const UINT32 gid, int *res)
{
    CXFS_MD         *cxfs_md;

    CXFSNP_ITEM     *cxfsnp_item;
    CXFSNP_ATTR     *cxfsnp_attr;

    uint64_t         ino;

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

    cxfsnp_item = __cxfs_fuses_lookup(cxfs_md_id, path, &ino);
    if(NULL_PTR == cxfsnp_item)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_unlink: "
                                             "path '%s' ino %lu fetch item failed\n",
                                             (char *)cstring_get_str(path),
                                             ino);
        (*res) = -ENOENT;
        return (EC_TRUE);
    }
    cxfsnp_attr = CXFSNP_ITEM_ATTR(cxfsnp_item);

    if(CXFS_FUSES_PERM_SWITCH == SWITCH_ON
    && 0 != uid && 0 != gid /*not root*/
    && (CXFSNP_ATTR_UID(cxfsnp_attr) == (uint32_t)uid
       && CXFSNP_ATTR_GID(cxfsnp_attr) == (uint32_t)gid))
    {
        CXFSNP_ITEM     *cxfsnp_item_parent;
        CXFSNP_ATTR     *cxfsnp_attr_parent;

        cxfsnp_item_parent = cxfsnp_mgr_fetch_parent_item(CXFS_MD_NPP(cxfs_md), ino);
        if(NULL_PTR == cxfsnp_item_parent)
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_unlink: "
                                                 "fetch parent of '%s' failed\n",
                                                 (char *)cstring_get_str(path));
            (*res) = -ENOENT;
            return (EC_TRUE);
        }
        cxfsnp_attr_parent = CXFSNP_ITEM_ATTR(cxfsnp_item_parent);

        if(CXFSNP_ATTR_UID(cxfsnp_attr_parent) != (uint32_t)uid
        && 0 == (S_IXOTH & CXFSNP_ATTR_MODE(cxfsnp_attr_parent)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_unlink: "
                                                 "path '%s', "
                                                 "same uid %u and gid %u, "
                                                 "parent (uid %u, gid %u) mode %#o & (S_IXOTH) == 0"
                                                 "=> deny (uid %u, gid %u)\n",
                                                 (char *)cstring_get_str(path),
                                                 (uint32_t)uid, (uint32_t)gid,
                                                 CXFSNP_ATTR_UID(cxfsnp_attr_parent),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr_parent),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr_parent),
                                                 (uint32_t)uid, (uint32_t)gid);

            (*res) = -EACCES;
            return (EC_TRUE);
        }

        if(CXFSNP_ATTR_UID(cxfsnp_attr_parent) == (uint32_t)uid
        && 0 == (S_IWUSR & CXFSNP_ATTR_MODE(cxfsnp_attr_parent)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_unlink: "
                                                 "path '%s', "
                                                 "same uid %u and gid %u, "
                                                 "parent (uid %u, gid %u) mode %#o & (S_IWUSR) == 0"
                                                 "=> deny (uid %u, gid %u)\n",
                                                 (char *)cstring_get_str(path),
                                                 (uint32_t)uid, (uint32_t)gid,
                                                 CXFSNP_ATTR_UID(cxfsnp_attr_parent),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr_parent),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr_parent),
                                                 (uint32_t)uid, (uint32_t)gid);

            (*res) = -EACCES;
            return (EC_TRUE);
        }

        if(CXFSNP_ATTR_UID(cxfsnp_attr_parent) == (uint32_t)uid
        && 0 == (S_IXUSR & CXFSNP_ATTR_MODE(cxfsnp_attr_parent)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_unlink: "
                                                 "path '%s', "
                                                 "same uid %u and gid %u, "
                                                 "parent (uid %u, gid %u) mode %#o & (S_IXUSR) == 0"
                                                 "=> deny (uid %u, gid %u)\n",
                                                 (char *)cstring_get_str(path),
                                                 (uint32_t)uid, (uint32_t)gid,
                                                 CXFSNP_ATTR_UID(cxfsnp_attr_parent),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr_parent),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr_parent),
                                                 (uint32_t)uid, (uint32_t)gid);

            (*res) = -EACCES;
            return (EC_TRUE);
        }
    }

    if(CXFS_FUSES_PERM_SWITCH == SWITCH_ON
    && 0 != uid && 0 != gid /*not root*/
    && (CXFSNP_ATTR_UID(cxfsnp_attr) != (uint32_t)uid
       || CXFSNP_ATTR_GID(cxfsnp_attr) != (uint32_t)gid))
    {
        CXFSNP_ITEM     *cxfsnp_item_parent;
        CXFSNP_ATTR     *cxfsnp_attr_parent;

        cxfsnp_item_parent = cxfsnp_mgr_fetch_parent_item(CXFS_MD_NPP(cxfs_md), ino);
        if(NULL_PTR == cxfsnp_item_parent)
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_unlink: "
                                                 "lookup parent of '%s' failed\n",
                                                 (char *)cstring_get_str(path));
            (*res) = -ENOENT;
            return (EC_TRUE);
        }
        cxfsnp_attr_parent = CXFSNP_ITEM_ATTR(cxfsnp_item_parent);

        if(CXFS_FUSES_UID_ERR == (uint32_t)uid)
        {
            if(CXFSNP_ATTR_UID(cxfsnp_attr_parent) != (uint32_t)uid)
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_unlink: "
                                                     "'%s', uid %u, parent uid %u => not matched\n",
                                                     (char *)cstring_get_str(path),
                                                     (uint32_t)uid, CXFSNP_ATTR_UID(cxfsnp_attr_parent));
                (*res) = -EACCES;
                return (EC_TRUE);
            }
        }
        else
        {
            if(CXFSNP_ATTR_UID(cxfsnp_attr_parent) != (uint32_t)uid)
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_unlink: "
                                                     "'%s', uid %u, parent uid %u => not matched\n",
                                                     (char *)cstring_get_str(path),
                                                     (uint32_t)uid, CXFSNP_ATTR_UID(cxfsnp_attr_parent));
                (*res) = -EACCES;
                return (EC_TRUE);
            }

            if(CXFSNP_ATTR_UID(cxfsnp_attr_parent) == (uint32_t)uid
            && 0 == (S_IWUSR & CXFSNP_ATTR_MODE(cxfsnp_attr_parent)))
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_unlink: "
                                                     "'%s', "
                                                     "uid %u same, parent mode %#o & (S_IWUSR) == 0 "
                                                     "=> deny (uid %u, gid %u)\n",
                                                     (char *)cstring_get_str(path),
                                                     (uint32_t)uid,
                                                     CXFSNP_ATTR_MODE(cxfsnp_attr_parent),
                                                     (uint32_t)uid, (uint32_t)gid);
                (*res) = -EACCES;
                return (EC_TRUE);
            }

            if(CXFSNP_ATTR_UID(cxfsnp_attr_parent) != (uint32_t)uid
            && 0 == (S_IXOTH & CXFSNP_ATTR_MODE(cxfsnp_attr_parent)))
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_unlink: "
                                                     "path '%s', "
                                                     "parent mode %#o & (S_IXOTH) == 0 "
                                                     "=> deny (uid %u, gid %u)\n",
                                                     (char *)cstring_get_str(path),
                                                     CXFSNP_ATTR_MODE(cxfsnp_attr_parent),
                                                     (uint32_t)uid, (uint32_t)gid);

                (*res) = -EACCES;
                return (EC_TRUE);
            }
        }

        if(CXFS_FUSES_GID_ERR == (uint32_t)gid)
        {
            if(CXFSNP_ATTR_GID(cxfsnp_attr_parent) != (uint32_t)gid)
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_unlink: "
                                                     "'%s', gid %#x overflow\n",
                                                     (char *)cstring_get_str(path),
                                                     (uint32_t)gid);
                (*res) = -EOVERFLOW;
                return (EC_TRUE);
            }
        }
        else
        {
            if(0 == (S_IXGRP & CXFSNP_ATTR_MODE(cxfsnp_attr_parent)))
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_unlink: "
                                                     "path '%s', "
                                                     "parent mode %#o & (S_IXGRP) == 0 "
                                                     "=> deny (uid %u, gid %u)\n",
                                                     (char *)cstring_get_str(path),
                                                     CXFSNP_ATTR_MODE(cxfsnp_attr_parent),
                                                     (uint32_t)uid, (uint32_t)gid);

                (*res) = -EACCES;
                return (EC_TRUE);
            }
        }
    }

    if(CXFSNP_ATTR_LINK_HARD_MID == CXFSNP_ATTR_LINK_FLAG(cxfsnp_attr))/*hard link middle*/
    {
        CXFSNP_ATTR     *cxfsnp_attr_save;
        uint64_t         ino_save;

        cxfsnp_attr_save = cxfsnp_attr; /*save*/
        ino_save         = ino; /*save*/

        CXFS_FUSES_GOTO_HARD_LINK_TOP(cxfs_md, ino, cxfsnp_item, cxfsnp_attr);

        /*now attr is hard link tail*/

        ASSERT(cxfsnp_attr != cxfsnp_attr_save);

        //CXFSNP_ATTR_NLINK(cxfsnp_attr_save) = 0;
        CXFSNP_ATTR_NEXT_INO(cxfsnp_attr_save) = CXFSNP_ATTR_ERR_INO; /*break hard link*/

        cxfsnp_attr_dec_link(cxfsnp_attr);

        dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_unlink: "
                                             "'%s' => hard link ino %lu => dec nlink to %u\n",
                                             (char *)cstring_get_str(path), ino,
                                             CXFSNP_ATTR_NLINK(cxfsnp_attr));

        if(0 == CXFSNP_ATTR_NLINK(cxfsnp_attr))
        {
            ASSERT(CXFSNP_ATTR_IS_HIDE == CXFSNP_ATTR_HIDE_FLAG(cxfsnp_attr));

            cxfsnp_mgr_delete_hidden_item(CXFS_MD_NPP(cxfs_md), ino);

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_unlink: "
                                                 "'%s' => delete hidden hard link ino %lu\n",
                                                 (char *)cstring_get_str(path), ino);
        }

        cxfsnp_attr = cxfsnp_attr_save;/*restore*/
        ino         = ino_save;/*restore*/

        /*fall through*/

        if(EC_FALSE == cxfs_delete_dir(cxfs_md_id, path))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_unlink: "
                                                 "[hard link middle] delete dir '%s' failed\n",
                                                 (char *)cstring_get_str(path));
            (*res) = -EACCES;
            return (EC_FALSE);
        }

        dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_unlink: "
                                             "[hard link middle] delete dir %s => done\n",
                                             (char *)cstring_get_str(path));

        (*res) = 0;

        return (EC_TRUE);
    }

    if(CXFSNP_ATTR_LINK_HARD_TAIL == CXFSNP_ATTR_LINK_FLAG(cxfsnp_attr)) /*hard link tail*/
    {
        ASSERT(CXFSNP_ATTR_NOT_HIDE == CXFSNP_ATTR_HIDE_FLAG(cxfsnp_attr));

        cxfsnp_attr_dec_link(cxfsnp_attr);

        if(0 < CXFSNP_ATTR_NLINK(cxfsnp_attr))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_unlink: "
                                                 "delete dir %s => tail nlink %u => set hide\n",
                                                 (char *)cstring_get_str(path),
                                                 CXFSNP_ATTR_NLINK(cxfsnp_attr));

            CXFSNP_ATTR_HIDE_FLAG(cxfsnp_attr) = CXFSNP_ATTR_IS_HIDE;

            cxfsnp_mgr_hide_item(CXFS_MD_NPP(cxfs_md), ino);

            (*res) = 0;
            return (EC_TRUE);
        }

        /*fall through to remove this item*/
        CXFSNP_ATTR_HIDE_FLAG(cxfsnp_attr) = CXFSNP_ATTR_NOT_HIDE; /*clear flag*/

        if(EC_FALSE == cxfs_delete_dir(cxfs_md_id, path))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_unlink: "
                                                 "[hard link tail] delete dir '%s' failed\n",
                                                 (char *)cstring_get_str(path));
            (*res) = -EACCES;
            return (EC_FALSE);
        }

        dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_unlink: "
                                             "[hard link tail] delete dir %s => done\n",
                                             (char *)cstring_get_str(path));

        (*res) = 0;

        return (EC_TRUE);
    }

    /*soft link middle*/
    if(CXFSNP_ATTR_LINK_SOFT == CXFSNP_ATTR_LINK_FLAG(cxfsnp_attr)
    && CXFSNP_ATTR_ERR_INO != CXFSNP_ATTR_NEXT_INO(cxfsnp_attr))
    {
        CXFSNP_ITEM     *cxfsnp_item_link;
        CXFSNP_ATTR     *cxfsnp_attr_link;
        uint64_t         ino_link;

        ino_link = CXFSNP_ATTR_NEXT_INO(cxfsnp_attr);
        cxfsnp_item_link = cxfsnp_mgr_fetch_item(CXFS_MD_NPP(cxfs_md), ino_link);
        ASSERT(NULL_PTR != cxfsnp_item_link);

        CXFSNP_ATTR_NEXT_INO(cxfsnp_attr) = CXFSNP_ATTR_ERR_INO; /*break soft link*/

        cxfsnp_attr_link = CXFSNP_ITEM_ATTR(cxfsnp_item_link);
        CXFSNP_ATTR_SLINK(cxfsnp_attr_link) --;

        if(0 == CXFSNP_ATTR_SLINK(cxfsnp_attr_link)
        && CXFSNP_ATTR_IS_HIDE == CXFSNP_ATTR_HIDE_FLAG(cxfsnp_attr_link))
        {
            cxfsnp_mgr_umount_item(CXFS_MD_NPP(cxfs_md), ino_link);

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_unlink: "
                                                 "'%s' => delete hidden soft link ino %lu\n",
                                                 (char *)cstring_get_str(path), ino_link);
        }

        /*fall through*/

        if(EC_FALSE == cxfs_delete_dir(cxfs_md_id, path))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_unlink: "
                                                 "[soft link middle] delete dir '%s' failed\n",
                                                 (char *)cstring_get_str(path));
            (*res) = -EACCES;
            return (EC_FALSE);
        }

        dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_unlink: "
                                             "[soft link middle] delete dir %s => done\n",
                                             (char *)cstring_get_str(path));

        (*res) = 0;

        return (EC_TRUE);
    }

    /*soft link tail*/
    if(CXFSNP_ATTR_LINK_SOFT == CXFSNP_ATTR_LINK_FLAG(cxfsnp_attr)
    && CXFSNP_ATTR_ERR_INO == CXFSNP_ATTR_NEXT_INO(cxfsnp_attr))
    {
        if(0 < CXFSNP_ATTR_SLINK(cxfsnp_attr))
        {
            CXFSNP_ATTR_HIDE_FLAG(cxfsnp_attr) = CXFSNP_ATTR_IS_HIDE;
            cxfsnp_mgr_hide_item(CXFS_MD_NPP(cxfs_md), ino);

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_unlink: "
                                                 "'%s' => hide soft link ino %lu\n",
                                                 (char *)cstring_get_str(path), ino);

            (*res) = 0;

            return (EC_TRUE);
        }

        if(EC_FALSE == cxfs_delete_dir(cxfs_md_id, path))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_unlink: "
                                                 "[soft link tail] delete dir '%s' failed\n",
                                                 (char *)cstring_get_str(path));
            (*res) = -EACCES;
            return (EC_FALSE);
        }

        dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_unlink: "
                                             "[soft link tail] delete dir %s => done\n",
                                             (char *)cstring_get_str(path));

        (*res) = 0;

        return (EC_TRUE);
    }

    /*else*/

    dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_unlink: "
                                         "'%s' =>  ino %lu, nlink %u\n",
                                         (char *)cstring_get_str(path), ino,
                                         CXFSNP_ATTR_NLINK(cxfsnp_attr));

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

EC_BOOL cxfs_fuses_rmdir(const UINT32 cxfs_md_id, const CSTRING *path, const UINT32 uid, const UINT32 gid, int *res)
{
    CXFS_MD         *cxfs_md;

    CXFSNP_ITEM     *cxfsnp_item;
    CXFSNP_ATTR     *cxfsnp_attr;
    uint64_t         ino;

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

    cxfsnp_item = __cxfs_fuses_lookup(cxfs_md_id, path, &ino);
    if(NULL_PTR == cxfsnp_item)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_rmdir: "
                                             "path '%s' ino %lu fetch item failed\n",
                                             (char *)cstring_get_str(path),
                                             ino);
        (*res) = -ENOENT;
        return (EC_TRUE);
    }
    cxfsnp_attr = CXFSNP_ITEM_ATTR(cxfsnp_item);

    if(CXFSNP_ATTR_FILE_IS_DIR != CXFSNP_ATTR_DIR_FLAG(cxfsnp_attr))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_rmdir: "
                                             "path '%s' => ino %lu, flag %#x => failed\n",
                                             (char *)cstring_get_str(path),
                                             ino, CXFSNP_ATTR_DIR_FLAG(cxfsnp_attr));
        (*res) = -ENOENT;
        return (EC_TRUE);
    }

#if 0
    if(0 < CXFSNP_DNODE_FILE_NUM(CXFSNP_ITEM_DNODE(cxfsnp_item)))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_rmdir: "
                                             "path '%s' => ino %lu, flag %#x, file num %lu => failed\n",
                                             (char *)cstring_get_str(path),
                                             ino, CXFSNP_ATTR_DIR_FLAG(cxfsnp_attr),
                                             CXFSNP_DNODE_FILE_NUM(CXFSNP_ITEM_DNODE(cxfsnp_item)));
        (*res) = -ENOTEMPTY;
        return (EC_TRUE);
    }
#endif

    if(CXFS_FUSES_PERM_SWITCH == SWITCH_ON
    && 0 != uid && 0 != gid /*not root*/
    && (CXFSNP_ATTR_UID(cxfsnp_attr) == (uint32_t)uid
       && CXFSNP_ATTR_GID(cxfsnp_attr) == (uint32_t)gid))
    {
        CXFSNP_ITEM     *cxfsnp_item_parent;
        CXFSNP_ATTR     *cxfsnp_attr_parent;

        cxfsnp_item_parent = cxfsnp_mgr_fetch_parent_item(CXFS_MD_NPP(cxfs_md), ino);
        if(NULL_PTR == cxfsnp_item_parent)
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_rmdir: "
                                                 "fetch parent of '%s' failed\n",
                                                 (char *)cstring_get_str(path));
            (*res) = -ENOENT;
            return (EC_TRUE);
        }
        cxfsnp_attr_parent = CXFSNP_ITEM_ATTR(cxfsnp_item_parent);

        if(CXFSNP_ATTR_UID(cxfsnp_attr_parent) != (uint32_t)uid
        && 0 == (S_IXOTH & CXFSNP_ATTR_MODE(cxfsnp_attr_parent)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_rmdir: "
                                                 "path '%s', "
                                                 "same uid %u and gid %u, "
                                                 "parent (uid %u, gid %u) mode %#o & (S_IXOTH) == 0"
                                                 "=> deny (uid %u, gid %u)\n",
                                                 (char *)cstring_get_str(path),
                                                 (uint32_t)uid, (uint32_t)gid,
                                                 CXFSNP_ATTR_UID(cxfsnp_attr_parent),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr_parent),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr_parent),
                                                 (uint32_t)uid, (uint32_t)gid);

            (*res) = -EACCES;
            return (EC_TRUE);
        }

        if(CXFSNP_ATTR_UID(cxfsnp_attr_parent) == (uint32_t)uid
        && 0 == (S_IWUSR & CXFSNP_ATTR_MODE(cxfsnp_attr_parent)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_rmdir: "
                                                 "path '%s', "
                                                 "same uid %u and gid %u, "
                                                 "parent (uid %u, gid %u) mode %#o & (S_IWUSR) == 0"
                                                 "=> deny (uid %u, gid %u)\n",
                                                 (char *)cstring_get_str(path),
                                                 (uint32_t)uid, (uint32_t)gid,
                                                 CXFSNP_ATTR_UID(cxfsnp_attr_parent),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr_parent),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr_parent),
                                                 (uint32_t)uid, (uint32_t)gid);

            (*res) = -EACCES;
            return (EC_TRUE);
        }

        if(CXFSNP_ATTR_UID(cxfsnp_attr_parent) == (uint32_t)uid
        && 0 == (S_IXUSR & CXFSNP_ATTR_MODE(cxfsnp_attr_parent)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_rmdir: "
                                                 "path '%s', "
                                                 "same uid %u and gid %u, "
                                                 "parent (uid %u, gid %u) mode %#o & (S_IXUSR) == 0"
                                                 "=> deny (uid %u, gid %u)\n",
                                                 (char *)cstring_get_str(path),
                                                 (uint32_t)uid, (uint32_t)gid,
                                                 CXFSNP_ATTR_UID(cxfsnp_attr_parent),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr_parent),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr_parent),
                                                 (uint32_t)uid, (uint32_t)gid);

            (*res) = -EACCES;
            return (EC_TRUE);
        }
    }

    if(CXFS_FUSES_PERM_SWITCH == SWITCH_ON
    && 0 != uid && 0 != gid /*not root*/
    && (CXFSNP_ATTR_UID(cxfsnp_attr) != (uint32_t)uid
       || CXFSNP_ATTR_GID(cxfsnp_attr) != (uint32_t)gid))
    {
        CXFSNP_ITEM     *cxfsnp_item_parent;
        CXFSNP_ATTR     *cxfsnp_attr_parent;

        cxfsnp_item_parent = cxfsnp_mgr_fetch_parent_item(CXFS_MD_NPP(cxfs_md), ino);
        if(NULL_PTR == cxfsnp_item_parent)
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_rmdir: "
                                                 "lookup parent of '%s' failed\n",
                                                 (char *)cstring_get_str(path));
            (*res) = -ENOENT;
            return (EC_TRUE);
        }
        cxfsnp_attr_parent = CXFSNP_ITEM_ATTR(cxfsnp_item_parent);

        if(CXFS_FUSES_UID_ERR == (uint32_t)uid)
        {
            if(CXFSNP_ATTR_UID(cxfsnp_attr_parent) != (uint32_t)uid)
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_rmdir: "
                                                     "'%s', uid %u, parent uid %u => not matched\n",
                                                     (char *)cstring_get_str(path),
                                                     (uint32_t)uid, CXFSNP_ATTR_UID(cxfsnp_attr_parent));
                (*res) = -EACCES;
                return (EC_TRUE);
            }
        }
        else
        {
            if(CXFSNP_ATTR_UID(cxfsnp_attr_parent) != (uint32_t)uid)
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_rmdir: "
                                                     "'%s', uid %u, parent uid %u => not matched\n",
                                                     (char *)cstring_get_str(path),
                                                     (uint32_t)uid, CXFSNP_ATTR_UID(cxfsnp_attr_parent));
                (*res) = -EACCES;
                return (EC_TRUE);
            }

            if(CXFSNP_ATTR_UID(cxfsnp_attr_parent) == (uint32_t)uid
            && 0 == (S_IWUSR & CXFSNP_ATTR_MODE(cxfsnp_attr_parent)))
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_rmdir: "
                                                     "'%s', "
                                                     "uid %u same, parent mode %#o & (S_IWUSR) == 0 "
                                                     "=> deny (uid %u, gid %u)\n",
                                                     (char *)cstring_get_str(path),
                                                     (uint32_t)uid,
                                                     CXFSNP_ATTR_MODE(cxfsnp_attr_parent),
                                                     (uint32_t)uid, (uint32_t)gid);
                (*res) = -EACCES;
                return (EC_TRUE);
            }

            if(CXFSNP_ATTR_UID(cxfsnp_attr_parent) != (uint32_t)uid
            && 0 == (S_IXOTH & CXFSNP_ATTR_MODE(cxfsnp_attr_parent)))
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_rmdir: "
                                                     "path '%s', "
                                                     "parent mode %#o & (S_IXOTH) == 0 "
                                                     "=> deny (uid %u, gid %u)\n",
                                                     (char *)cstring_get_str(path),
                                                     CXFSNP_ATTR_MODE(cxfsnp_attr_parent),
                                                     (uint32_t)uid, (uint32_t)gid);

                (*res) = -EACCES;
                return (EC_TRUE);
            }
        }

        if(CXFS_FUSES_GID_ERR == (uint32_t)gid)
        {
            if(CXFSNP_ATTR_GID(cxfsnp_attr_parent) != (uint32_t)gid)
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_rmdir: "
                                                     "'%s', gid %#x overflow\n",
                                                     (char *)cstring_get_str(path),
                                                     (uint32_t)gid);
                (*res) = -EOVERFLOW;
                return (EC_TRUE);
            }
        }
        else
        {
            if(0 == (S_IXGRP & CXFSNP_ATTR_MODE(cxfsnp_attr_parent)))
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_rmdir: "
                                                     "path '%s', "
                                                     "parent mode %#o & (S_IXGRP) == 0 "
                                                     "=> deny (uid %u, gid %u)\n",
                                                     (char *)cstring_get_str(path),
                                                     CXFSNP_ATTR_MODE(cxfsnp_attr_parent),
                                                     (uint32_t)uid, (uint32_t)gid);

                (*res) = -EACCES;
                return (EC_TRUE);
            }
        }
    }

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

EC_BOOL cxfs_fuses_symlink(const UINT32 cxfs_md_id, const CSTRING *src_path, const CSTRING *des_path, const UINT32 uid, const UINT32 gid, int *res)
{
    CXFS_MD         *cxfs_md;

    CXFSNP_ITEM     *cxfsnp_item_src;
    CXFSNP_ATTR     *cxfsnp_attr_src;
    uint64_t         ino_src;

    CXFSNP_ITEM     *cxfsnp_item_des;
    CXFSNP_ATTR     *cxfsnp_attr_des;
    uint64_t         ino_des;

    uint32_t         create_src_flag;

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

    create_src_flag = BIT_FALSE;

    cxfsnp_item_src = __cxfs_fuses_lookup(cxfs_md_id, src_path, &ino_src);
    if(NULL_PTR == cxfsnp_item_src)
    {
        if(EC_FALSE == cxfs_mkdir(cxfs_md_id, src_path))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_symlink: "
                                                 "make src '%s' failed\n",
                                                 (char *)cstring_get_str(src_path));
            (*res) = -ENOENT;
            return (EC_TRUE);
        }

        cxfsnp_item_src = __cxfs_fuses_lookup(cxfs_md_id, src_path, &ino_src);
        if(NULL_PTR == cxfsnp_item_src)
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_symlink: "
                                                 "[obscure] lookup src '%s' failed\n",
                                                 (char *)cstring_get_str(src_path));
            (*res) = -EACCES;
            return (EC_TRUE);
        }

        cxfsnp_attr_src = CXFSNP_ITEM_ATTR(cxfsnp_item_src);

        cxfsnp_attr_set_dir_symlink(cxfsnp_attr_src, CXFSNP_ATTR_ERR_INO); /*default is dir link */
        CXFSNP_ATTR_HIDE_FLAG(cxfsnp_attr_src) = CXFSNP_ATTR_IS_HIDE;
        CXFSNP_ATTR_LINK_FLAG(cxfsnp_attr_src) = CXFSNP_ATTR_LINK_SOFT; /*set soft link*/

        create_src_flag = BIT_TRUE; /*set src created flag*/

        dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_symlink: "
                                             "[obscure] make src '%s' done\n",
                                             (char *)cstring_get_str(src_path));
    }
    else
    {
        cxfsnp_attr_src = CXFSNP_ITEM_ATTR(cxfsnp_item_src);
    }

    cxfsnp_item_des = __cxfs_fuses_lookup(cxfs_md_id, des_path, &ino_des);
    if(NULL_PTR != cxfsnp_item_des)
    {
        if(ino_src == ino_des)
        {
            if(BIT_TRUE == create_src_flag)
            {
                cxfs_delete_dir(cxfs_md_id, src_path);
            }

            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_symlink: "
                                                 "src '%s' and des '%s' have same ino %lu => deny\n",
                                                 (char *)cstring_get_str(src_path),
                                                 (char *)cstring_get_str(des_path),
                                                 ino_src);
            (*res) = -ELOOP;
            return (EC_TRUE);
        }

        cxfsnp_attr_des = CXFSNP_ITEM_ATTR(cxfsnp_item_des);

        if(CXFSNP_ATTR_LINK_SOFT != CXFSNP_ATTR_LINK_FLAG(cxfsnp_attr_des))
        {
            if(BIT_TRUE == create_src_flag)
            {
                cxfs_delete_dir(cxfs_md_id, src_path);
            }

            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_symlink: "
                                                 "des '%s' exist already\n",
                                                 (char *)cstring_get_str(des_path));
            (*res) = -EACCES;
            return (EC_TRUE);
        }

        cxfsnp_attr_set_dir_symlink(cxfsnp_attr_des, ino_src);
        CXFSNP_ATTR_HIDE_FLAG(cxfsnp_attr_des) = CXFSNP_ATTR_NOT_HIDE;

        dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_symlink: "
                                             "link dir '%s' des [obscure] '%s' done\n",
                                             (char *)cstring_get_str(src_path),
                                             (char *)cstring_get_str(des_path));

        (*res) = 0;

        return (EC_TRUE);
    }

    /*check permission*/
    if(CXFS_FUSES_PERM_SWITCH == SWITCH_ON
    && NULL_PTR == cxfsnp_item_des
    && 0 != uid && 0 != gid)
    {
        CXFSNP_ITEM     *cxfsnp_item_des_parent;
        CXFSNP_ATTR     *cxfsnp_attr_des_parent;
        uint64_t         ino_des_parent;

        cxfsnp_item_des_parent = __cxfs_fuses_lookup_parent(cxfs_md_id, des_path, &ino_des_parent);
        if(NULL_PTR == cxfsnp_item_des_parent)
        {
            if(BIT_TRUE == create_src_flag)
            {
                cxfs_delete_dir(cxfs_md_id, src_path);
            }

            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_symlink: "
                                                 "lookup parent of '%s' failed\n",
                                                 (char *)cstring_get_str(des_path));
            (*res) = -ENOENT;
            return (EC_TRUE);
        }
        cxfsnp_attr_des_parent = CXFSNP_ITEM_ATTR(cxfsnp_item_des_parent);

        if(CXFSNP_ATTR_UID(cxfsnp_attr_des_parent) != (uint32_t)uid
        && 0 == (S_IXOTH & CXFSNP_ATTR_MODE(cxfsnp_attr_des_parent)))
        {
            if(BIT_TRUE == create_src_flag)
            {
                cxfs_delete_dir(cxfs_md_id, src_path);
            }

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_symlink: "
                                                 "path '%s', "
                                                 "same uid %u and gid %u, "
                                                 "parent (uid %u, gid %u) mode %#o & (S_IXOTH) == 0"
                                                 "=> deny (uid %u, gid %u)\n",
                                                 (char *)cstring_get_str(des_path),
                                                 (uint32_t)uid, (uint32_t)gid,
                                                 CXFSNP_ATTR_UID(cxfsnp_attr_des_parent),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr_des_parent),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr_des_parent),
                                                 (uint32_t)uid, (uint32_t)gid);

            (*res) = -EACCES;
            return (EC_TRUE);
        }

        if(CXFSNP_ATTR_UID(cxfsnp_attr_des_parent) == (uint32_t)uid
        && 0 == (S_IWUSR & CXFSNP_ATTR_MODE(cxfsnp_attr_des_parent)))
        {
            if(BIT_TRUE == create_src_flag)
            {
                cxfs_delete_dir(cxfs_md_id, src_path);
            }

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_symlink: "
                                                 "path '%s', "
                                                 "same uid %u and gid %u, "
                                                 "parent (uid %u, gid %u) mode %#o & (S_IWUSR) == 0"
                                                 "=> deny (uid %u, gid %u)\n",
                                                 (char *)cstring_get_str(des_path),
                                                 (uint32_t)uid, (uint32_t)gid,
                                                 CXFSNP_ATTR_UID(cxfsnp_attr_des_parent),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr_des_parent),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr_des_parent),
                                                 (uint32_t)uid, (uint32_t)gid);

            (*res) = -EACCES;
            return (EC_TRUE);
        }

        if(CXFSNP_ATTR_UID(cxfsnp_attr_des_parent) == (uint32_t)uid
        && 0 == (S_IXUSR & CXFSNP_ATTR_MODE(cxfsnp_attr_des_parent)))
        {
            if(BIT_TRUE == create_src_flag)
            {
                cxfs_delete_dir(cxfs_md_id, src_path);
            }

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_symlink: "
                                                 "path '%s', "
                                                 "same uid %u and gid %u, "
                                                 "parent (uid %u, gid %u) mode %#o & (S_IXUSR) == 0"
                                                 "=> deny (uid %u, gid %u)\n",
                                                 (char *)cstring_get_str(des_path),
                                                 (uint32_t)uid, (uint32_t)gid,
                                                 CXFSNP_ATTR_UID(cxfsnp_attr_des_parent),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr_des_parent),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr_des_parent),
                                                 (uint32_t)uid, (uint32_t)gid);

            (*res) = -EACCES;
            return (EC_TRUE);
        }
    }

    ASSERT(NULL_PTR != cxfsnp_item_src);
    ASSERT(NULL_PTR == cxfsnp_item_des);

    if(EC_FALSE == cxfs_mkdir(cxfs_md_id, des_path))
    {
        if(BIT_TRUE == create_src_flag)
        {
            cxfs_delete_dir(cxfs_md_id, src_path);
        }

        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_symlink: "
                                             "make des dir '%s' failed\n",
                                             (char *)cstring_get_str(des_path));
        (*res) = -EACCES;
        return (EC_FALSE);
    }

    cxfsnp_item_des = __cxfs_fuses_lookup(cxfs_md_id, des_path, &ino_des);
    if(NULL_PTR == cxfsnp_item_des)
    {
        if(BIT_TRUE == create_src_flag)
        {
            cxfs_delete_dir(cxfs_md_id, src_path);
        }

        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_symlink: "
                                             "lookup des '%s' failed\n",
                                             (char *)cstring_get_str(des_path));
        (*res) = -ENOENT;
        return (EC_FALSE);
    }
    cxfsnp_attr_des = CXFSNP_ITEM_ATTR(cxfsnp_item_des);

    if(CXFSNP_ATTR_FILE_IS_REG == CXFSNP_ATTR_DIR_FLAG(cxfsnp_attr_src))
    {
        cxfsnp_attr_set_file_symlink(cxfsnp_attr_des, ino_src);
        CXFSNP_ATTR_HIDE_FLAG(cxfsnp_attr_des) = CXFSNP_ATTR_NOT_HIDE;
        CXFSNP_ATTR_LINK_FLAG(cxfsnp_attr_des) = CXFSNP_ATTR_LINK_SOFT; /*set soft link*/

        dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_symlink: "
                                             "link file src '%s' des '%s' done\n",
                                             (char *)cstring_get_str(src_path),
                                             (char *)cstring_get_str(des_path));

        (*res) = 0;

        return (EC_TRUE);
    }

    if(CXFSNP_ATTR_FILE_IS_DIR == CXFSNP_ATTR_DIR_FLAG(cxfsnp_attr_src))
    {
        cxfsnp_attr_set_dir_symlink(cxfsnp_attr_des, ino_src);
        CXFSNP_ATTR_HIDE_FLAG(cxfsnp_attr_des) = CXFSNP_ATTR_NOT_HIDE;
        CXFSNP_ATTR_LINK_FLAG(cxfsnp_attr_des) = CXFSNP_ATTR_LINK_SOFT; /*set soft link*/

        dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_symlink: "
                                             "link dir src '%s' des '%s' done\n",
                                             (char *)cstring_get_str(src_path),
                                             (char *)cstring_get_str(des_path));

        (*res) = 0;

        return (EC_TRUE);
    }

    /*should never reach here*/
    if(BIT_TRUE == create_src_flag)
    {
        cxfs_delete_dir(cxfs_md_id, src_path);
    }
    cxfs_delete_dir(cxfs_md_id, des_path);

    dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_symlink: "
                                         "unknow src '%s' flag %#x\n",
                                         (char *)cstring_get_str(src_path),
                                         CXFSNP_ATTR_DIR_FLAG(cxfsnp_attr_src));

    (*res) = -EACCES;

    return (EC_TRUE);
}

EC_BOOL cxfs_fuses_rename(const UINT32 cxfs_md_id, const CSTRING *src_path, const CSTRING *des_path, const UINT32 uid, const UINT32 gid, int *res)
{
    CXFS_MD         *cxfs_md;

    CXFSNP_ITEM     *cxfsnp_item_src;
    uint64_t         ino_src;

    CXFSNP_ITEM     *cxfsnp_item_des; /*target parent item*/
    CXFSNP_DNODE    *cxfsnp_dnode_des;/*target parent dnode*/
    uint64_t         ino_des;
    uint64_t         ino_des_save; /*only if des path is hard link*/

    CXFSNP          *cxfsnp;

    uint32_t         node_pos_src;
    uint32_t         root_pos_des;

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

    cxfsnp_item_src = __cxfs_fuses_lookup(cxfs_md_id, src_path, &ino_src);
    if(NULL_PTR == cxfsnp_item_src)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_rename: "
                                             "no src '%s'\n",
                                             (char *)cstring_get_str(src_path));
        (*res) = -ENOENT;
        return (EC_TRUE);
    }

    cxfsnp = cxfsnp_mgr_fetch_np(CXFS_MD_NPP(cxfs_md), ino_src);
    if(NULL_PTR == cxfsnp)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_rename: "
                                             "fetch src '%s' np failed\n",
                                             (char *)cstring_get_str(src_path));

        (*res) = -EACCES;
        return (EC_TRUE);
    }

    ino_des_save = CXFSNP_ATTR_ERR_INO;
    cxfsnp_item_des = __cxfs_fuses_lookup(cxfs_md_id, des_path, &ino_des);
    if(NULL_PTR != cxfsnp_item_des)
    {
        CXFSNP_ATTR     *cxfsnp_attr_des;

        cxfsnp_attr_des        = CXFSNP_ITEM_ATTR(cxfsnp_item_des);

        if(0 == (CXFSNP_ATTR_LINK_HARD_MASK & CXFSNP_ATTR_LINK_FLAG(cxfsnp_attr_des))) /*not hard link*/
        {
            if(CXFS_FUSES_PERM_SWITCH == SWITCH_ON
            && 0 != uid && 0 != gid)
            {
                CXFSNP_ITEM     *cxfsnp_item_des_parent;
                CXFSNP_ATTR     *cxfsnp_attr_des_parent;

                cxfsnp_item_des_parent = cxfsnp_mgr_fetch_parent_item(CXFS_MD_NPP(cxfs_md), ino_des);
                cxfsnp_attr_des_parent = CXFSNP_ITEM_ATTR(cxfsnp_item_des_parent);

                if(/*CXFSNP_ATTR_UID(cxfsnp_attr_des_parent) == (uint32_t)uid
                && CXFSNP_ATTR_GID(cxfsnp_attr_des_parent) == (uint32_t)gid
                && */(S_ISVTX & CXFSNP_ATTR_MODE(cxfsnp_attr_des_parent)))
                {
                    (*res) = 0;

                    /*warning:  do not call cxfs_delete_dir*/
                    if(EC_FALSE == cxfs_fuses_unlink(cxfs_md_id, des_path, uid, gid, res)
                    || 0 != (*res))
                    {
                        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_rename: "
                                                             "[des sticky] delete des '%s' failed\n",
                                                             (char *)cstring_get_str(des_path));

                        return (EC_TRUE);
                    }

                    dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_rename: "
                                                         "[des sticky] delete des '%s' done\n",
                                                         (char *)cstring_get_str(des_path));

                    ino_des         = CXFSNP_ATTR_ERR_INO;
                    ino_des_save    = CXFSNP_ATTR_ERR_INO;
                    cxfsnp_item_des = NULL_PTR;
                }
                else
                {
                    ino_des_save = ino_des; /*save*/

                    dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_rename: "
                                                         "[not hard link] des '%s' exist => save ino %lu\n",
                                                         (char *)cstring_get_str(des_path), ino_des_save);
                }
            }
            else
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_rename: "
                                                     "des '%s' exist already\n",
                                                     (char *)cstring_get_str(des_path));
                (*res) = -EEXIST;
                return (EC_TRUE);
            }
        }
        else /*hard link*/
        {
            ino_des_save = ino_des; /*save*/

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_rename: "
                                                 "[hard link] des '%s' exist => save ino %lu\n",
                                                 (char *)cstring_get_str(des_path), ino_des_save);
        }
    }

    cxfsnp_item_des = __cxfs_fuses_lookup_parent(cxfs_md_id, des_path, &ino_des);
    if(NULL_PTR == cxfsnp_item_des)
    {
        /*give up creating the parent directory*/

        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_rename: "
                                             "lookup parent of created '%s' failed\n",
                                             (char *)cstring_get_str(des_path));
        (*res) = -ENOENT;
        return (EC_TRUE);
    }
    cxfsnp_dnode_des = CXFSNP_ITEM_DNODE(cxfsnp_item_des);

    /*check permission*/
    if(CXFS_FUSES_PERM_SWITCH == SWITCH_ON
    && 0 != uid && 0 == gid)
    {
        CXFSNP_ATTR     *cxfsnp_attr_src;

        cxfsnp_attr_src = CXFSNP_ITEM_ATTR(cxfsnp_item_src);

        if(CXFSNP_ATTR_UID(cxfsnp_attr_src) != (uint32_t)uid
        && CXFSNP_ATTR_GID(cxfsnp_attr_src) == (uint32_t)gid
        && 0 == (S_IXOTH & CXFSNP_ATTR_MODE(cxfsnp_attr_src)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_rename: "
                                                 "src '%s', "
                                                 "parent (uid %u, gid %u) mode %#o & (S_IXOTH) == 0"
                                                 "=> deny (uid %u, gid %u)\n",
                                                 (char *)cstring_get_str(src_path),
                                                 CXFSNP_ATTR_UID(cxfsnp_attr_src),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr_src),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr_src),
                                                 (uint32_t)uid, (uint32_t)gid);

            (*res) = -EACCES;
            return (EC_TRUE);
        }

        if(CXFSNP_ATTR_UID(cxfsnp_attr_src) != (uint32_t)uid
        && CXFSNP_ATTR_GID(cxfsnp_attr_src) == (uint32_t)gid
        && 0 == (S_IWOTH & CXFSNP_ATTR_MODE(cxfsnp_attr_src)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_rename: "
                                                 "src '%s', "
                                                 "parent (uid %u, gid %u) mode %#o & (S_IWOTH) == 0"
                                                 "=> deny (uid %u, gid %u)\n",
                                                 (char *)cstring_get_str(src_path),
                                                 CXFSNP_ATTR_UID(cxfsnp_attr_src),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr_src),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr_src),
                                                 (uint32_t)uid, (uint32_t)gid);

            (*res) = -EACCES;
            return (EC_TRUE);
        }

        if(CXFSNP_ATTR_UID(cxfsnp_attr_src) != (uint32_t)uid
        && CXFSNP_ATTR_GID(cxfsnp_attr_src) == (uint32_t)gid
        && S_IFSOCK == (S_IFSOCK & CXFSNP_ATTR_MODE(cxfsnp_attr_src)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_rename: "
                                                 "src '%s', "
                                                 "parent (uid %u, gid %u) mode %#o & (S_IFSOCK) == S_IFSOCK"
                                                 "=> deny (uid %u, gid %u)\n",
                                                 (char *)cstring_get_str(src_path),
                                                 CXFSNP_ATTR_UID(cxfsnp_attr_src),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr_src),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr_src),
                                                 (uint32_t)uid, (uint32_t)gid);

            (*res) = -EACCES;
            return (EC_TRUE);
        }
    }

    if(CXFS_FUSES_PERM_SWITCH == SWITCH_ON
    && 0 != uid && 0 != gid)
    {
        CXFSNP_ATTR     *cxfsnp_attr_des;

        cxfsnp_attr_des = CXFSNP_ITEM_ATTR(cxfsnp_item_des);

        if(CXFSNP_ATTR_UID(cxfsnp_attr_des) != (uint32_t)uid
        && 0 == (S_IWOTH & CXFSNP_ATTR_MODE(cxfsnp_attr_des)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_rename: "
                                                 "des '%s', "
                                                 "parent (uid %u, gid %u) mode %#o & (S_IWOTH) == 0"
                                                 "=> deny (uid %u, gid %u)\n",
                                                 (char *)cstring_get_str(des_path),
                                                 CXFSNP_ATTR_UID(cxfsnp_attr_des),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr_des),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr_des),
                                                 (uint32_t)uid, (uint32_t)gid);

            (*res) = -EACCES;
            return (EC_TRUE);
        }

        if(CXFSNP_ATTR_UID(cxfsnp_attr_des) == (uint32_t)uid
        && 0 == (S_IWUSR & CXFSNP_ATTR_MODE(cxfsnp_attr_des)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_rename: "
                                                 "des '%s', "
                                                 "parent (uid %u, gid %u) mode %#o & (S_IWUSR) == 0"
                                                 "=> deny (uid %u, gid %u)\n",
                                                 (char *)cstring_get_str(des_path),
                                                 CXFSNP_ATTR_UID(cxfsnp_attr_des),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr_des),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr_des),
                                                 (uint32_t)uid, (uint32_t)gid);

            (*res) = -EACCES;
            return (EC_TRUE);
        }

        if(CXFSNP_ATTR_UID(cxfsnp_attr_des) == (uint32_t)uid
        && CXFSNP_ATTR_GID(cxfsnp_attr_des) == (uint32_t)gid /*04.tt*/
        && 0 == (S_IXUSR & CXFSNP_ATTR_MODE(cxfsnp_attr_des)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_rename: "
                                                 "des '%s', "
                                                 "parent (uid %u, gid %u) mode %#o & (S_IXUSR) == 0"
                                                 "=> deny (uid %u, gid %u)\n",
                                                 (char *)cstring_get_str(des_path),
                                                 CXFSNP_ATTR_UID(cxfsnp_attr_des),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr_des),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr_des),
                                                 (uint32_t)uid, (uint32_t)gid);

            (*res) = -EACCES;
            return (EC_TRUE);
        }
    }

    if(CXFS_FUSES_PERM_SWITCH == SWITCH_ON
    && 0 != uid && 0 != gid)
    {
        CXFSNP_ATTR     *cxfsnp_attr_src;

        CXFSNP_ITEM     *cxfsnp_item_src_parent;
        CXFSNP_ATTR     *cxfsnp_attr_src_parent;
        uint64_t         ino_src_parent;

        cxfsnp_attr_src = CXFSNP_ITEM_ATTR(cxfsnp_item_src);

        cxfsnp_item_src_parent = __cxfs_fuses_lookup_parent(cxfs_md_id, src_path, &ino_src_parent);
        if(NULL_PTR == cxfsnp_item_src_parent)
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_rename: "
                                                 "lookup parent of src '%s' failed\n",
                                                 (char *)cstring_get_str(src_path));
            (*res) = -ENOENT;
            return (EC_TRUE);
        }
        cxfsnp_attr_src_parent = CXFSNP_ITEM_ATTR(cxfsnp_item_src_parent);

        if(CXFSNP_ATTR_UID(cxfsnp_attr_src_parent) != (uint32_t)uid
        && CXFSNP_ATTR_GID(cxfsnp_attr_src_parent) != (uint32_t)gid
        && 0 == (S_IWOTH & CXFSNP_ATTR_MODE(cxfsnp_attr_src_parent)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_rename: "
                                                 "src '%s', "
                                                 "parent (uid %u, gid %u) mode %#o & (S_IWOTH) == 0"
                                                 "=> deny (uid %u, gid %u)\n",
                                                 (char *)cstring_get_str(src_path),
                                                 CXFSNP_ATTR_UID(cxfsnp_attr_src_parent),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr_src_parent),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr_src_parent),
                                                 (uint32_t)uid, (uint32_t)gid);

            (*res) = -EACCES;
            return (EC_TRUE);
        }

        if(CXFSNP_ATTR_UID(cxfsnp_attr_src_parent) != (uint32_t)uid
        && CXFSNP_ATTR_GID(cxfsnp_attr_src_parent) == (uint32_t)gid
        && 0 == (S_IWGRP & CXFSNP_ATTR_MODE(cxfsnp_attr_src_parent)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_rename: "
                                                 "src '%s', "
                                                 "parent (uid %u, gid %u) mode %#o & (S_IWGRP) == 0"
                                                 "=> deny (uid %u, gid %u)\n",
                                                 (char *)cstring_get_str(src_path),
                                                 CXFSNP_ATTR_UID(cxfsnp_attr_src_parent),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr_src_parent),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr_src_parent),
                                                 (uint32_t)uid, (uint32_t)gid);

            (*res) = -EACCES;
            return (EC_TRUE);
        }

        if(CXFSNP_ATTR_UID(cxfsnp_attr_src_parent) == (uint32_t)uid
        && 0 == (S_IWUSR & CXFSNP_ATTR_MODE(cxfsnp_attr_src_parent)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_rename: "
                                                 "src '%s', "
                                                 "parent (uid %u, gid %u) mode %#o & (S_IWUSR) == 0"
                                                 "=> deny (uid %u, gid %u)\n",
                                                 (char *)cstring_get_str(src_path),
                                                 CXFSNP_ATTR_UID(cxfsnp_attr_src_parent),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr_src_parent),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr_src_parent),
                                                 (uint32_t)uid, (uint32_t)gid);

            (*res) = -EACCES;
            return (EC_TRUE);
        }

        if(CXFSNP_ATTR_UID(cxfsnp_attr_src_parent) == (uint32_t)uid
        && CXFSNP_ATTR_GID(cxfsnp_attr_src_parent) == (uint32_t)gid /*04.tt*/
        && 0 == (S_IXUSR & CXFSNP_ATTR_MODE(cxfsnp_attr_src_parent)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_rename: "
                                                 "src '%s', "
                                                 "parent (uid %u, gid %u) mode %#o & (S_IXUSR) == 0 "
                                                 "=> deny (uid %u, gid %u)\n",
                                                 (char *)cstring_get_str(src_path),
                                                 CXFSNP_ATTR_UID(cxfsnp_attr_src_parent),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr_src_parent),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr_src_parent),
                                                 (uint32_t)uid, (uint32_t)gid);

            (*res) = -EACCES;
            return (EC_TRUE);
        }

        /*09.tt*/
        if(CXFSNP_ATTR_UID(cxfsnp_attr_src_parent) == (uint32_t)uid
        && CXFSNP_ATTR_GID(cxfsnp_attr_src_parent) == (uint32_t)gid
        && 0 != (S_ISVTX & CXFSNP_ATTR_MODE(cxfsnp_attr_src_parent))
        && (CXFSNP_ATTR_UID(cxfsnp_attr_src) != (uint32_t)uid
        || CXFSNP_ATTR_GID(cxfsnp_attr_src) != (uint32_t)gid)
        && cxfsnp_item_src_parent != cxfsnp_item_des/*here is des parent*/
        )
        {
            if(CXFSNP_ATTR_ERR_INO != ino_des_save) /*des exist*/
            {
                CXFSNP_ITEM     *cxfsnp_item_des_t;
                CXFSNP_ATTR     *cxfsnp_attr_des_t;

                cxfsnp_item_des_t = cxfsnp_mgr_fetch_item(CXFS_MD_NPP(cxfs_md), ino_des_save);
                cxfsnp_attr_des_t = CXFSNP_ITEM_ATTR(cxfsnp_item_des_t);

                if(CXFSNP_ATTR_UID(cxfsnp_attr_des_t) != (uint32_t)uid
                || CXFSNP_ATTR_GID(cxfsnp_attr_des_t) != (uint32_t)gid)
                {
                    dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_rename: "
                                                         "src '%s' (uid %u, gid %u), "
                                                         "parent (uid %u, gid %u) mode %#o & (S_ISVTX) != 0, "
                                                         "des (uid %u, gid %u) exists "
                                                         "=> deny (uid %u, gid %u)\n",
                                                         (char *)cstring_get_str(src_path),
                                                         CXFSNP_ATTR_UID(cxfsnp_attr_src),
                                                         CXFSNP_ATTR_GID(cxfsnp_attr_src),
                                                         CXFSNP_ATTR_UID(cxfsnp_attr_src_parent),
                                                         CXFSNP_ATTR_GID(cxfsnp_attr_src_parent),
                                                         CXFSNP_ATTR_MODE(cxfsnp_attr_src_parent),
                                                         CXFSNP_ATTR_UID(cxfsnp_attr_des_t),
                                                         CXFSNP_ATTR_GID(cxfsnp_attr_des_t),
                                                         (uint32_t)uid, (uint32_t)gid);

                    (*res) = -EACCES;
                    return (EC_TRUE);
                }
            }
            else /*des not exist*/
            {
                CXFSNP_ATTR     *cxfsnp_attr_des; /*des parent*/

                cxfsnp_attr_des = CXFSNP_ITEM_ATTR(cxfsnp_item_des);

                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_rename: "
                                                     "src '%s' (uid %u, gid %u), "
                                                     "src parent (uid %u, gid %u) mode %#o,"
                                                     "no des, des parent (uid %u, gid %u) mode %#o, "
                                                     "=> (uid %u, gid %u) XXXXXXX\n",
                                                     (char *)cstring_get_str(src_path),
                                                     CXFSNP_ATTR_UID(cxfsnp_attr_src),
                                                     CXFSNP_ATTR_GID(cxfsnp_attr_src),
                                                     CXFSNP_ATTR_UID(cxfsnp_attr_src_parent),
                                                     CXFSNP_ATTR_GID(cxfsnp_attr_src_parent),
                                                     CXFSNP_ATTR_MODE(cxfsnp_attr_src_parent),
                                                     CXFSNP_ATTR_UID(cxfsnp_attr_des),
                                                     CXFSNP_ATTR_GID(cxfsnp_attr_des),
                                                     CXFSNP_ATTR_MODE(cxfsnp_attr_des),
                                                     (uint32_t)uid, (uint32_t)gid);

                if(CXFSNP_ATTR_UID(cxfsnp_attr_des) != (uint32_t)uid
                || CXFSNP_ATTR_GID(cxfsnp_attr_des) != (uint32_t)gid)
                {
                    dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_rename: "
                                                         "src '%s' (uid %u, gid %u), "
                                                         "src parent (uid %u, gid %u) mode %#o & (S_ISVTX) != 0, "
                                                         "no des, "
                                                         "=> deny (uid %u, gid %u)\n",
                                                         (char *)cstring_get_str(src_path),
                                                         CXFSNP_ATTR_UID(cxfsnp_attr_src),
                                                         CXFSNP_ATTR_GID(cxfsnp_attr_src),
                                                         CXFSNP_ATTR_UID(cxfsnp_attr_src_parent),
                                                         CXFSNP_ATTR_GID(cxfsnp_attr_src_parent),
                                                         CXFSNP_ATTR_MODE(cxfsnp_attr_src_parent),
                                                         (uint32_t)uid, (uint32_t)gid);

                    (*res) = -EACCES;
                    return (EC_TRUE);
                }

                if(0 /*faint, failed to satisfy all cases in 09.tt*/
                && (CXFSNP_ATTR_UID(cxfsnp_attr_des) == (uint32_t)uid
                && CXFSNP_ATTR_GID(cxfsnp_attr_des) == (uint32_t)gid)
                && (CXFSNP_ATTR_UID(cxfsnp_attr_des) != CXFSNP_ATTR_UID(cxfsnp_attr_src)
                && CXFSNP_ATTR_GID(cxfsnp_attr_des) != CXFSNP_ATTR_GID(cxfsnp_attr_src))
                && 0 == (S_IWOTH & CXFSNP_ATTR_MODE(cxfsnp_attr_des)))
                {
                    dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_rename: "
                                                         "src '%s' (uid %u, gid %u), "
                                                         "src parent (uid %u, gid %u) mode %#o & (S_ISVTX) != 0, "
                                                         "no des, des parent (uid %u, gid %u) mode %#o & (S_IWOTH) == 0 "
                                                         "=> deny (uid %u, gid %u)\n",
                                                         (char *)cstring_get_str(src_path),
                                                         CXFSNP_ATTR_UID(cxfsnp_attr_src),
                                                         CXFSNP_ATTR_GID(cxfsnp_attr_src),
                                                         CXFSNP_ATTR_UID(cxfsnp_attr_src_parent),
                                                         CXFSNP_ATTR_GID(cxfsnp_attr_src_parent),
                                                         CXFSNP_ATTR_MODE(cxfsnp_attr_src_parent),
                                                         CXFSNP_ATTR_UID(cxfsnp_attr_des),
                                                         CXFSNP_ATTR_GID(cxfsnp_attr_des),
                                                         CXFSNP_ATTR_MODE(cxfsnp_attr_des),
                                                         (uint32_t)uid, (uint32_t)gid);

                    (*res) = -EACCES;
                    return (EC_TRUE);
                }
            }
        }

        if((CXFSNP_ATTR_UID(cxfsnp_attr_src_parent) != (uint32_t)uid
            || CXFSNP_ATTR_GID(cxfsnp_attr_src_parent) != (uint32_t)gid)
        && 0 != (S_ISVTX & CXFSNP_ATTR_MODE(cxfsnp_attr_src_parent)))
        {
            if(CXFSNP_ATTR_UID(cxfsnp_attr_src) != (uint32_t)uid
            || CXFSNP_ATTR_GID(cxfsnp_attr_src) != (uint32_t)gid)
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_rename: "
                                                     "src '%s' (uid %u, gid %u), "
                                                     "parent (uid %u, gid %u) mode %#o & (S_ISVTX) != 0"
                                                     "=> deny (uid %u, gid %u)\n",
                                                     (char *)cstring_get_str(src_path),
                                                     CXFSNP_ATTR_UID(cxfsnp_attr_src),
                                                     CXFSNP_ATTR_GID(cxfsnp_attr_src),
                                                     CXFSNP_ATTR_UID(cxfsnp_attr_src_parent),
                                                     CXFSNP_ATTR_GID(cxfsnp_attr_src_parent),
                                                     CXFSNP_ATTR_MODE(cxfsnp_attr_src_parent),
                                                     (uint32_t)uid, (uint32_t)gid);

                (*res) = -EACCES;
                return (EC_TRUE);
            }
        }
    }

    node_pos_src = CXFSNP_ATTR_INO_FETCH_NODE_POS(ino_src);
    if(EC_FALSE == cxfsnp_tear_item(cxfsnp, node_pos_src))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_rename: "
                                             "tear src '%s', ino_src %lu failed\n",
                                             (char *)cstring_get_str(src_path), ino_src);

        (*res) = -EACCES;
        return (EC_TRUE);
    }

    dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_rename: "
                                         "tear src '%s', ino_src %lu done\n",
                                         (char *)cstring_get_str(src_path), ino_src);

    if(CXFSNP_ATTR_ERR_INO != ino_des_save)
    {
        CXFSNP_ATTR     *cxfsnp_attr_des;

        cxfsnp_item_des = cxfsnp_mgr_fetch_item(CXFS_MD_NPP(cxfs_md), ino_des_save);
        cxfsnp_attr_des = CXFSNP_ITEM_ATTR(cxfsnp_item_des);

        if(CXFSNP_ATTR_LINK_HARD_MID == CXFSNP_ATTR_LINK_FLAG(cxfsnp_attr_des))
        {
            CXFSNP_ITEM     *cxfsnp_item_tail;
            CXFSNP_ATTR     *cxfsnp_attr_tail;
            uint64_t         ino_tail;

            cxfsnp_item_tail = cxfsnp_item_des;
            cxfsnp_attr_tail = cxfsnp_attr_des;
            ino_tail         = ino_des_save;

            CXFS_FUSES_GOTO_HARD_LINK_TOP(cxfs_md, ino_tail, cxfsnp_item_tail, cxfsnp_attr_tail);

            /*now attr is hard link tail*/

            ASSERT(cxfsnp_attr_des != cxfsnp_attr_tail);

            CXFSNP_ATTR_NEXT_INO(cxfsnp_attr_des) = CXFSNP_ATTR_ERR_INO; /*break hard link*/

            cxfsnp_attr_dec_link(cxfsnp_attr_tail);

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_rename: "
                                                 "'%s' => hard link tail ino %lu "
                                                 "=> dec nlink to %u\n",
                                                 (char *)cstring_get_str(des_path), ino_tail,
                                                 CXFSNP_ATTR_NLINK(cxfsnp_attr_tail));

            if(0 == CXFSNP_ATTR_NLINK(cxfsnp_attr_tail))
            {
                ASSERT(CXFSNP_ATTR_IS_HIDE == CXFSNP_ATTR_HIDE_FLAG(cxfsnp_attr_tail));

                cxfsnp_mgr_delete_hidden_item(CXFS_MD_NPP(cxfs_md), ino_tail);

                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_rename: "
                                                     "'%s' => delete hidden hard link ino %lu\n",
                                                     (char *)cstring_get_str(des_path), ino_tail);
            }

            /*fall through*/

            if(EC_FALSE == cxfs_delete_dir(cxfs_md_id, des_path))
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_rename: "
                                                     "[hard link middle] delete dir '%s' failed\n",
                                                     (char *)cstring_get_str(des_path));
                (*res) = -EACCES;
                return (EC_FALSE);
            }

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_rename: "
                                                 "[hard link middle] delete dir %s => done\n",
                                                 (char *)cstring_get_str(des_path));
        }

        else if(CXFSNP_ATTR_LINK_HARD_TAIL == CXFSNP_ATTR_LINK_FLAG(cxfsnp_attr_des))
        {
            ASSERT(CXFSNP_ATTR_NOT_HIDE == CXFSNP_ATTR_HIDE_FLAG(cxfsnp_attr_des));

            cxfsnp_attr_dec_link(cxfsnp_attr_des);

            if(0 < CXFSNP_ATTR_NLINK(cxfsnp_attr_des))
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_rename: "
                                                     "[hard link tail] delete dir %s "
                                                     "=> tail nlink %u => set hide\n",
                                                     (char *)cstring_get_str(des_path),
                                                     CXFSNP_ATTR_NLINK(cxfsnp_attr_des));

                CXFSNP_ATTR_HIDE_FLAG(cxfsnp_attr_des) = CXFSNP_ATTR_IS_HIDE;

                cxfsnp_mgr_hide_item(CXFS_MD_NPP(cxfs_md), ino_des_save);
            }
            else
            {
                CXFSNP_ATTR_HIDE_FLAG(cxfsnp_attr_des) = CXFSNP_ATTR_NOT_HIDE; /*clear flag*/

                if(EC_FALSE == cxfs_delete_dir(cxfs_md_id, des_path))
                {
                    dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_rename: "
                                                         "[hard link tail] delete dir '%s' failed\n",
                                                         (char *)cstring_get_str(des_path));
                    (*res) = -EACCES;
                    return (EC_FALSE);
                }

                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_rename: "
                                                     "[hard link tail] delete dir %s => done\n",
                                                     (char *)cstring_get_str(des_path));
            }
        }

        else
        {
            (*res) = 0;

            /*warning:  do not call cxfs_delete_dir which cannont handle soft link etc.*/
            if(EC_FALSE == cxfs_fuses_unlink(cxfs_md_id, des_path, uid, gid, res)
            || 0 != (*res))
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_rename: "
                                                     "[not hard link] delete des '%s' failed\n",
                                                     (char *)cstring_get_str(des_path));

                return (EC_TRUE);
            }

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_rename: "
                                                 "[not hard link] delete des '%s' done\n",
                                                 (char *)cstring_get_str(des_path));

            ASSERT(NULL_PTR != __cxfs_fuses_lookup_parent(cxfs_md_id, des_path, NULL_PTR));

            /*ino_des and cxfsnp_item_des are parent of des => never change it*/
            ino_des_save    = CXFSNP_ATTR_ERR_INO;
        }
    }

    do
    {
        char            *path_seg;
        uint32_t         path_seg_len;
        uint32_t         path_seg_second_hash;

        path_seg     = c_basename((char *)cstring_get_str(des_path));
        if(NULL_PTR == path_seg)
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_rename: "
                                                 "basename des '%s' failed\n",
                                                 (char *)cstring_get_str(src_path));

            (*res) = -ENOMEM;
            return (EC_TRUE);
        }

        path_seg_len = strlen(path_seg);

        path_seg_second_hash = CXFSNP_2ND_CHASH_ALGO_COMPUTE(cxfsnp, path_seg_len, (uint8_t *)path_seg);

        if(CXFSNP_KEY_MAX_SIZE < path_seg_len)
        {
            uint8_t         *md5_str;
            uint32_t         md5_len;

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_rename: "
                                                 "des '%s' last seg '%s' => md5\n",
                                                 (char *)cstring_get_str(des_path),
                                                 (char *)path_seg);

            md5_str = (uint8_t *)c_md5_sum_to_hex_str(path_seg_len, (uint8_t *)path_seg);
            md5_len = (uint32_t )(2 * CMD5_DIGEST_LEN);

            cxfsnp_item_set_key(cxfsnp_item_src, md5_len, md5_str);
            CXFSNP_ITEM_SECOND_HASH(cxfsnp_item_src) = path_seg_second_hash;
            CXFSNP_ITEM_PARENT_POS(cxfsnp_item_src)  = CXFSNP_ATTR_INO_FETCH_NODE_POS(ino_des);
        }
        else
        {
            cxfsnp_item_set_key(cxfsnp_item_src, path_seg_len, (uint8_t *)path_seg);
            CXFSNP_ITEM_SECOND_HASH(cxfsnp_item_src) = path_seg_second_hash;
            CXFSNP_ITEM_PARENT_POS(cxfsnp_item_src)  = CXFSNP_ATTR_INO_FETCH_NODE_POS(ino_des);
        }

        c_str_free(path_seg);
    }while(0);

    root_pos_des = CXFSNP_DNODE_ROOT_POS(cxfsnp_dnode_des);

    if(EC_FALSE == cxfsnprb_tree_insert(CXFSNP_ITEMS_POOL(cxfsnp),
                                        &root_pos_des,
                                         CXFSNP_ITEM_SECOND_HASH(cxfsnp_item_src),
                                         CXFSNP_ITEM_KLEN(cxfsnp_item_src),
                                         CXFSNP_ITEM_KNAME(cxfsnp_item_src),
                                         CXFSNP_ITEM_DIR_FLAG(cxfsnp_item_src),
                                         node_pos_src))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_rename: "
                                             "move src '%s' to des '%s' failed\n",
                                             (char *)cstring_get_str(src_path),
                                             (char *)cstring_get_str(des_path));

        (*res) = -EACCES;
        return (EC_TRUE);
    }

    CXFSNP_DNODE_ROOT_POS(cxfsnp_dnode_des) = root_pos_des;

    /*move foward parent*/
    cxfsnp_item_src = cxfsnp_fetch(cxfsnp, CXFSNP_ITEM_PARENT_POS(cxfsnp_item_src));
    if(NULL_PTR != cxfsnp_item_src)
    {
        CXFSNP_ATTR     *cxfsnp_attr_src;

        cxfsnp_attr_src = CXFSNP_ITEM_ATTR(cxfsnp_item_src);
        CXFSNP_ATTR_NLINK(cxfsnp_attr_src) ++;
    }

    dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_rename: "
                                         "rename dir '%s' to '%s' done\n",
                                         (char *)cstring_get_str(src_path),
                                         (char *)cstring_get_str(des_path));

    (*res) = 0;

    return (EC_TRUE);
}

EC_BOOL cxfs_fuses_link(const UINT32 cxfs_md_id, const CSTRING *src_path, const CSTRING *des_path, const UINT32 uid, const UINT32 gid, int *res)
{
    CXFS_MD         *cxfs_md;

    CXFSNP_ITEM     *cxfsnp_item_src;
    CXFSNP_ATTR     *cxfsnp_attr_src;
    uint64_t         ino_src;

    CXFSNP_ITEM     *cxfsnp_item_des;
    CXFSNP_ATTR     *cxfsnp_attr_des;
    uint64_t         ino_des;

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
    /*des -> src*/

    CXFS_FUSES_CHECK_ENV(cxfs_md_id, cxfs_md, "cxfs_fuses_link", res);

    cxfsnp_item_des = __cxfs_fuses_lookup(cxfs_md_id, des_path, &ino_des);
    if(NULL_PTR != cxfsnp_item_des)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_link: "
                                             "des '%s' exist\n",
                                             (char *)cstring_get_str(src_path));
        (*res) = -EEXIST;
        return (EC_TRUE);
    }

    cxfsnp_item_src = __cxfs_fuses_lookup(cxfs_md_id, src_path, &ino_src);
    if(NULL_PTR == cxfsnp_item_src)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_link: "
                                             "src '%s' not exist\n",
                                             (char *)cstring_get_str(src_path));
        (*res) = -ENOENT;
        return (EC_TRUE);
    }
    cxfsnp_attr_src = CXFSNP_ITEM_ATTR(cxfsnp_item_src);

    /*find link tail of src: only one jump*/
    while(CXFSNP_ATTR_ERR_INO != CXFSNP_ATTR_NEXT_INO(cxfsnp_attr_src))
    {
        ino_src         = CXFSNP_ATTR_NEXT_INO(cxfsnp_attr_src);
        cxfsnp_item_src = cxfsnp_mgr_fetch_item(CXFS_MD_NPP(cxfs_md), ino_src);
        cxfsnp_attr_src = CXFSNP_ITEM_ATTR(cxfsnp_item_src);
    }

    /*check permission*/
    if(CXFS_FUSES_PERM_SWITCH == SWITCH_ON
    && NULL_PTR == cxfsnp_item_des
    && 0 != uid && 0 == gid)
    {
        if(CXFSNP_ATTR_UID(cxfsnp_attr_src) == (uint32_t)uid
        && CXFSNP_ATTR_GID(cxfsnp_attr_src) != (uint32_t)gid)
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_link: "
                                                 "src '%s', ino %lu, "
                                                 "(uid %u, gid %u, mode %#o), ",
                                                 "=> deny (uid %u, gid %u), des '%s'\n",
                                                 (char *)cstring_get_str(src_path), ino_src,
                                                 CXFSNP_ATTR_UID(cxfsnp_attr_src),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr_src),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr_src),
                                                 (uint32_t)uid, (uint32_t)gid,
                                                 (char *)cstring_get_str(des_path));

            (*res) = -EACCES;
            return (EC_TRUE);
        }
    }

    if(CXFS_FUSES_PERM_SWITCH == SWITCH_ON
    && NULL_PTR == cxfsnp_item_des
    && 0 != uid && 0 != gid)
    {
        CXFSNP_ITEM     *cxfsnp_item_des_parent;
        CXFSNP_ATTR     *cxfsnp_attr_des_parent;
        uint64_t         ino_des_parent;

        cxfsnp_item_des_parent = __cxfs_fuses_lookup_parent(cxfs_md_id, des_path, &ino_des_parent);
        if(NULL_PTR == cxfsnp_item_des_parent)
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_link: "
                                                 "lookup parent of des '%s' failed\n",
                                                 (char *)cstring_get_str(des_path));
            (*res) = -ENOENT;
            return (EC_TRUE);
        }
        cxfsnp_attr_des_parent = CXFSNP_ITEM_ATTR(cxfsnp_item_des_parent);

        if(CXFSNP_ATTR_UID(cxfsnp_attr_des_parent) != (uint32_t)uid
        && 0 == (S_IXOTH & CXFSNP_ATTR_MODE(cxfsnp_attr_des_parent)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_link: "
                                                 "des '%s', "
                                                 "parent (uid %u, gid %u) mode %#o & (S_IXOTH) == 0"
                                                 "=> deny (uid %u, gid %u)\n",
                                                 (char *)cstring_get_str(des_path),
                                                 CXFSNP_ATTR_UID(cxfsnp_attr_des_parent),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr_des_parent),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr_des_parent),
                                                 (uint32_t)uid, (uint32_t)gid);

            (*res) = -EACCES;
            return (EC_TRUE);
        }

        if(CXFSNP_ATTR_UID(cxfsnp_attr_des_parent) == (uint32_t)uid
        && 0 == (S_IWUSR & CXFSNP_ATTR_MODE(cxfsnp_attr_des_parent)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_link: "
                                                 "des '%s', "
                                                 "parent (uid %u, gid %u) mode %#o & (S_IWUSR) == 0"
                                                 "=> deny (uid %u, gid %u)\n",
                                                 (char *)cstring_get_str(des_path),
                                                 CXFSNP_ATTR_UID(cxfsnp_attr_des_parent),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr_des_parent),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr_des_parent),
                                                 (uint32_t)uid, (uint32_t)gid);

            (*res) = -EACCES;
            return (EC_TRUE);
        }

        if(CXFSNP_ATTR_UID(cxfsnp_attr_des_parent) == (uint32_t)uid
        && 0 == (S_IXUSR & CXFSNP_ATTR_MODE(cxfsnp_attr_des_parent)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_link: "
                                                 "des '%s', "
                                                 "parent (uid %u, gid %u) mode %#o & (S_IXUSR) == 0"
                                                 "=> deny (uid %u, gid %u)\n",
                                                 (char *)cstring_get_str(des_path),
                                                 CXFSNP_ATTR_UID(cxfsnp_attr_des_parent),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr_des_parent),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr_des_parent),
                                                 (uint32_t)uid, (uint32_t)gid);

            (*res) = -EACCES;
            return (EC_TRUE);
        }
    }

    if(CXFS_FUSES_PERM_SWITCH == SWITCH_ON
    /*&& NULL_PTR == cxfsnp_item_des*/
    && 0 != uid && 0 != gid)
    {
        CXFSNP_ITEM     *cxfsnp_item_src_parent;
        CXFSNP_ATTR     *cxfsnp_attr_src_parent;
        uint64_t         ino_src_parent;

        cxfsnp_item_src_parent = __cxfs_fuses_lookup_parent(cxfs_md_id, src_path, &ino_src_parent);
        if(NULL_PTR == cxfsnp_item_src_parent)
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_link: "
                                                 "lookup parent of src '%s' failed\n",
                                                 (char *)cstring_get_str(src_path));
            (*res) = -ENOENT;
            return (EC_TRUE);
        }
        cxfsnp_attr_src_parent = CXFSNP_ITEM_ATTR(cxfsnp_item_src_parent);

        if(CXFSNP_ATTR_UID(cxfsnp_attr_src_parent) != (uint32_t)uid
        && 0 == (S_IXOTH & CXFSNP_ATTR_MODE(cxfsnp_attr_src_parent)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_link: "
                                                 "src '%s', "
                                                 "parent (uid %u, gid %u) mode %#o & (S_IXOTH) == 0"
                                                 "=> deny (uid %u, gid %u)\n",
                                                 (char *)cstring_get_str(src_path),
                                                 CXFSNP_ATTR_UID(cxfsnp_attr_src_parent),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr_src_parent),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr_src_parent),
                                                 (uint32_t)uid, (uint32_t)gid);

            (*res) = -EACCES;
            return (EC_TRUE);
        }

        if(CXFSNP_ATTR_UID(cxfsnp_attr_src_parent) == (uint32_t)uid
        && 0 == (S_IWUSR & CXFSNP_ATTR_MODE(cxfsnp_attr_src_parent)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_link: "
                                                 "src '%s', "
                                                 "parent (uid %u, gid %u) mode %#o & (S_IWUSR) == 0"
                                                 "=> deny (uid %u, gid %u)\n",
                                                 (char *)cstring_get_str(src_path),
                                                 CXFSNP_ATTR_UID(cxfsnp_attr_src_parent),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr_src_parent),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr_src_parent),
                                                 (uint32_t)uid, (uint32_t)gid);

            (*res) = -EACCES;
            return (EC_TRUE);
        }

        if(CXFSNP_ATTR_UID(cxfsnp_attr_src_parent) == (uint32_t)uid
        && 0 == (S_IXUSR & CXFSNP_ATTR_MODE(cxfsnp_attr_src_parent)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_link: "
                                                 "src '%s', "
                                                 "parent (uid %u, gid %u) mode %#o & (S_IXUSR) == 0"
                                                 "=> deny (uid %u, gid %u)\n",
                                                 (char *)cstring_get_str(src_path),
                                                 CXFSNP_ATTR_UID(cxfsnp_attr_src_parent),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr_src_parent),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr_src_parent),
                                                 (uint32_t)uid, (uint32_t)gid);

            (*res) = -EACCES;
            return (EC_TRUE);
        }
    }

    ASSERT(NULL_PTR != cxfsnp_item_src);
    ASSERT(NULL_PTR == cxfsnp_item_des);

    if(EC_FALSE == cxfs_mkdir(cxfs_md_id, des_path))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_link: "
                                             "make des dir '%s' failed\n",
                                             (char *)cstring_get_str(des_path));
        (*res) = -EACCES;
        return (EC_FALSE);
    }

    cxfsnp_item_des = __cxfs_fuses_lookup(cxfs_md_id, des_path, &ino_des);
    if(NULL_PTR == cxfsnp_item_des)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_link: "
                                             "lookup des '%s' failed\n",
                                             (char *)cstring_get_str(des_path));
        (*res) = -ENOENT;
        return (EC_FALSE);
    }
    cxfsnp_attr_des = CXFSNP_ITEM_ATTR(cxfsnp_item_des);

    if(0 == (CXFSNP_ATTR_LINK_HARD_MASK & CXFSNP_ATTR_LINK_FLAG(cxfsnp_attr_src)))
    {
        CXFSNP_ATTR_LINK_FLAG(cxfsnp_attr_src) = CXFSNP_ATTR_LINK_HARD_TAIL; /*set hard link tail*/

        dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_link: "
                                             "set src '%s' hard link tail\n",
                                             (char *)cstring_get_str(src_path));
    }

    if(CXFSNP_ATTR_FILE_IS_REG == CXFSNP_ATTR_DIR_FLAG(cxfsnp_attr_src))
    {
        cxfsnp_attr_set_file_link(cxfsnp_attr_des, ino_src);
        CXFSNP_ATTR_HIDE_FLAG(cxfsnp_attr_des) = CXFSNP_ATTR_NOT_HIDE;
        CXFSNP_ATTR_LINK_FLAG(cxfsnp_attr_des) = CXFSNP_ATTR_LINK_HARD_MID;/*set hard link middle*/

        cxfsnp_attr_inc_link(cxfsnp_attr_src);


        dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_link: "
                                             "link file src '%s' des '%s' => nlink %u\n",
                                             (char *)cstring_get_str(src_path),
                                             (char *)cstring_get_str(des_path),
                                             CXFSNP_ATTR_NLINK(cxfsnp_attr_src));

        (*res) = 0;

        return (EC_TRUE);
    }

    if(CXFSNP_ATTR_FILE_IS_DIR == CXFSNP_ATTR_DIR_FLAG(cxfsnp_attr_src))
    {
        cxfsnp_attr_set_dir_link(cxfsnp_attr_des, ino_src);
        CXFSNP_ATTR_HIDE_FLAG(cxfsnp_attr_des) = CXFSNP_ATTR_NOT_HIDE;
        CXFSNP_ATTR_LINK_FLAG(cxfsnp_attr_des) = CXFSNP_ATTR_LINK_HARD_MID;/*set hard link middle*/

        cxfsnp_attr_inc_link(cxfsnp_attr_src);

        dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_link: "
                                             "link dir src '%s' des '%s' => nlink %u\n",
                                             (char *)cstring_get_str(src_path),
                                             (char *)cstring_get_str(des_path),
                                             CXFSNP_ATTR_NLINK(cxfsnp_attr_src));

        (*res) = 0;

        return (EC_TRUE);
    }

    /*should never reach here*/

    dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_link: "
                                         "unknow src '%s' flag %#x\n",
                                         (char *)cstring_get_str(src_path),
                                         CXFSNP_ATTR_DIR_FLAG(cxfsnp_attr_src));

    (*res) = -EACCES;

    return (EC_TRUE);
}

EC_BOOL cxfs_fuses_chmod(const UINT32 cxfs_md_id, const CSTRING *path, const UINT32 mode, const UINT32 op_uid, const UINT32 op_gid, int *res)
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

    if(CXFS_FUSES_PERM_SWITCH == SWITCH_ON
    && 0 == op_uid && 0 == op_gid) /*root*/
    {
        CXFS_FUSES_GOTO_HARD_LINK_TOP(cxfs_md, ino, cxfsnp_item, cxfsnp_attr);

        CXFSNP_ATTR_MODE(cxfsnp_attr)       = (uint16_t)mode;
        CXFSNP_ATTR_MTIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
        CXFSNP_ATTR_CTIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
        CXFSNP_ATTR_MTIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;
        CXFSNP_ATTR_CTIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;

        dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_chmod: "
                                             "[op:%u:%u] chmod %s => ino %lu, mod %#o => done\n",
                                             (uint32_t)op_uid, (uint32_t)op_gid,
                                             (char *)cstring_get_str(path), ino, (uint16_t)mode);

        (*res) = 0;

        return (EC_TRUE);
    }

    if(CXFS_FUSES_PERM_SWITCH == SWITCH_ON
    && 0 != op_uid && 0 != op_gid) /*not root*/
    {
        if(CXFSNP_ATTR_UID(cxfsnp_attr) == (uint32_t)op_uid)
        {
            CXFSNP_ITEM     *cxfsnp_item_parent;
            CXFSNP_ATTR     *cxfsnp_attr_parent;

            /*
            # POSIX: If the calling process does not have appropriate privileges, and if
            # the group ID of the file does not match the effective group ID or one of the
            # supplementary group IDs and if the file is a regular file, bit S_ISGID
            # (set-group-ID on execution) in the file's mode shall be cleared upon
            */
            if(CXFSNP_ATTR_GID(cxfsnp_attr) != (uint32_t)op_gid
            && CXFSNP_ATTR_FILE_IS_REG == CXFSNP_ATTR_DIR_FLAG(cxfsnp_attr))
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_chmod: "
                                                     "path '%s', ino %lu, "
                                                     "[op:%u:%u] (uid %u, gid %u) chmod %#o -> %#o => %#o, "
                                                     "regulare file, "
                                                     "=> accept but clear S_ISGID\n",
                                                     (char *)cstring_get_str(path), ino,
                                                     (uint32_t)op_uid, (uint32_t)op_gid,
                                                     CXFSNP_ATTR_UID(cxfsnp_attr), CXFSNP_ATTR_GID(cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                     (uint16_t)mode, (uint16_t)(mode & (~S_ISGID)));

                CXFS_FUSES_GOTO_HARD_LINK_TOP(cxfs_md, ino, cxfsnp_item, cxfsnp_attr);

                CXFSNP_ATTR_MODE(cxfsnp_attr)       = (uint16_t)(mode & (~S_ISGID));
                CXFSNP_ATTR_MTIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
                CXFSNP_ATTR_CTIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
                CXFSNP_ATTR_MTIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;
                CXFSNP_ATTR_CTIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;

                (*res) = 0;

                return (EC_TRUE);
            }

            if(CXFSNP_ATTR_GID(cxfsnp_attr) != (uint32_t)op_gid
            && 0 == (S_IXGRP & CXFSNP_ATTR_MODE(cxfsnp_attr)))
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_chmod: "
                                                     "path '%s', ino %lu, "
                                                     "[op:%u:%u] (uid %u, gid %u) chmod %#o -> %#o, "
                                                     "mode & (S_ S_IXGRP) == 0 "
                                                     "=> deny\n",
                                                     (char *)cstring_get_str(path), ino,
                                                     (uint32_t)op_uid, (uint32_t)op_gid,
                                                     CXFSNP_ATTR_UID(cxfsnp_attr), CXFSNP_ATTR_GID(cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(cxfsnp_attr), (uint16_t)mode);
                (*res) = -EPERM;
                return (EC_TRUE);
            }

            cxfsnp_item_parent = cxfsnp_mgr_fetch_parent_item(CXFS_MD_NPP(cxfs_md), ino);
            cxfsnp_attr_parent = CXFSNP_ITEM_ATTR(cxfsnp_item_parent);

            /*check parent*/
            if(0 == (S_IXOTH & CXFSNP_ATTR_MODE(cxfsnp_attr_parent)))
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_chmod: "
                                                     "path '%s', ino %lu, "
                                                     "[op:%u:%u] (uid %u, gid %u) chmod %#o -> %#o, "
                                                     "parent mode %#o & (S_IXOTH) == 0 "
                                                     "=> deny\n",
                                                     (char *)cstring_get_str(path), ino,
                                                     (uint32_t)op_uid, (uint32_t)op_gid,
                                                     CXFSNP_ATTR_UID(cxfsnp_attr), CXFSNP_ATTR_GID(cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(cxfsnp_attr), (uint16_t)mode,
                                                     CXFSNP_ATTR_MODE(cxfsnp_attr_parent));

                (*res) = -EACCES;
                return (EC_TRUE);
            }
        }
        else
        {
            if(0 == (S_IXOTH & CXFSNP_ATTR_MODE(cxfsnp_attr)))
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_chmod: "
                                                     "path '%s', ino %lu, "
                                                     "[op:%u:%u] (uid %u, gid %u) chmod %#o -> %#o, "
                                                     "mode & (S_ IXOTH) == 0 "
                                                     "=> deny\n",
                                                     (char *)cstring_get_str(path), ino,
                                                     (uint32_t)op_uid, (uint32_t)op_gid,
                                                     CXFSNP_ATTR_UID(cxfsnp_attr), CXFSNP_ATTR_GID(cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(cxfsnp_attr), (uint16_t)mode);
                (*res) = -EPERM;
                return (EC_TRUE);
            }
        }
    }

    /*op_uid == 0 || op_gid ==0*/
    if(CXFS_FUSES_PERM_SWITCH == SWITCH_ON
    && 0 == op_uid)
    {
        if(CXFSNP_ATTR_UID(cxfsnp_attr) != (uint32_t)op_uid)
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_chmod: "
                                                 "path '%s', ino %lu, "
                                                 "[op:%u:%u] (uid %u, gid %u) chmod %#o -> %#o, "
                                                 "uid mismatched, "
                                                 "=> deny\n",
                                                 (char *)cstring_get_str(path), ino,
                                                 (uint32_t)op_uid, (uint32_t)op_gid,
                                                 CXFSNP_ATTR_UID(cxfsnp_attr), CXFSNP_ATTR_GID(cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr), (uint16_t)mode);
            (*res) = -EPERM;
            return (EC_TRUE);
        }
        if(CXFSNP_ATTR_GID(cxfsnp_attr) != (uint32_t)op_gid
        && 0 == (S_IXGRP & CXFSNP_ATTR_MODE(cxfsnp_attr)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_chmod: "
                                                 "path '%s', ino %lu, "
                                                 "[op:%u:%u] (uid %u, gid %u) chmod %#o -> %#o, "
                                                 "mode & (S_ S_IXGRP) == 0 "
                                                 "=> deny\n",
                                                 (char *)cstring_get_str(path), ino,
                                                 (uint32_t)op_uid, (uint32_t)op_gid,
                                                 CXFSNP_ATTR_UID(cxfsnp_attr), CXFSNP_ATTR_GID(cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr), (uint16_t)mode);
            (*res) = -EPERM;
            return (EC_TRUE);
        }
    }

    if(CXFS_FUSES_PERM_SWITCH == SWITCH_ON
    && 0 == op_gid)
    {
        if(CXFSNP_ATTR_UID(cxfsnp_attr) != (uint32_t)op_uid)
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_chmod: "
                                                 "path '%s', ino %lu, "
                                                 "[op:%u:%u] (uid %u, gid %u) chmod %#o -> %#o, "
                                                 "uid mismatched, "
                                                 "=> deny\n",
                                                 (char *)cstring_get_str(path), ino,
                                                 (uint32_t)op_uid, (uint32_t)op_gid,
                                                 CXFSNP_ATTR_UID(cxfsnp_attr), CXFSNP_ATTR_GID(cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr), (uint16_t)mode);
            (*res) = -EPERM;
            return (EC_TRUE);
        }
    }

    CXFS_FUSES_GOTO_HARD_LINK_TOP(cxfs_md, ino, cxfsnp_item, cxfsnp_attr);

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

EC_BOOL cxfs_fuses_chown(const UINT32 cxfs_md_id, const CSTRING *path, const UINT32 uid, const UINT32 gid, const UINT32 op_uid, const UINT32 op_gid, int *res)
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

    ASSERT(uid == (uid & CXFS_FUSES_UID_MASK));
    ASSERT(gid == (gid & CXFS_FUSES_GID_MASK));

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

    if(CXFS_FUSES_PERM_SWITCH == SWITCH_ON
    && (0 != op_uid && 0 != op_gid) /*not root*/
    && CXFS_FUSES_UID_ERR == uid && CXFS_FUSES_GID_ERR == gid)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_chown: "
                                             "'%s', (uid %u, gid %#x) overflow => deny\n",
                                             (char *)cstring_get_str(path),
                                             (uint32_t)uid, (uint32_t)gid);
        (*res) = -EACCES;
        return (EC_TRUE);
    }

    if(CXFS_FUSES_PERM_SWITCH == SWITCH_OFF)
    {
        CXFS_FUSES_GOTO_HARD_LINK_TOP(cxfs_md, ino, cxfsnp_item, cxfsnp_attr);

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

    if(CXFS_FUSES_PERM_SWITCH == SWITCH_ON
    && 0 == op_uid && 0 == op_gid) /*root*/
    {
        CXFS_FUSES_GOTO_HARD_LINK_TOP(cxfs_md, ino, cxfsnp_item, cxfsnp_attr);

        CXFSNP_ATTR_UID(cxfsnp_attr)        = (uint32_t)uid;
        CXFSNP_ATTR_GID(cxfsnp_attr)        = (uint32_t)gid;

        /*According to POSIX: If both owner and group are -1, the times need not be updated.*/
        if(CXFS_FUSES_UID_ERR != uid || CXFS_FUSES_GID_ERR != gid)
        {
            /*update time only when change happen*/
            CXFSNP_ATTR_MTIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
            CXFSNP_ATTR_CTIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
            CXFSNP_ATTR_MTIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;
            CXFSNP_ATTR_CTIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;
        }

        dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_chown: "
                                             "[op:%u:%u] chown %s => ino %lu, uid %u, gid %u => done\n",
                                             (uint32_t)op_uid, (uint32_t)op_gid,
                                             (char *)cstring_get_str(path), ino,
                                             CXFSNP_ATTR_UID(cxfsnp_attr),
                                             CXFSNP_ATTR_GID(cxfsnp_attr));
        (*res) = 0;

        return (EC_TRUE);
    }

    if(CXFS_FUSES_PERM_SWITCH == SWITCH_ON
    && CXFSNP_ATTR_UID(cxfsnp_attr) == (uint32_t)uid
    && op_uid == uid)
    {
        CXFS_FUSES_GOTO_HARD_LINK_TOP(cxfs_md, ino, cxfsnp_item, cxfsnp_attr);

        CXFSNP_ATTR_GID(cxfsnp_attr)        = (uint32_t)gid;

        /*update time only when change happen*/
        CXFSNP_ATTR_MTIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
        CXFSNP_ATTR_CTIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
        CXFSNP_ATTR_MTIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;
        CXFSNP_ATTR_CTIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;

        dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_chown: "
                                             "path '%s', ino %lu, "
                                             "[op:%u:%u] (uid %u, gid %u) -> (uid %u, gid %u), "
                                             "uid == op uid == current uid "
                                             "=> done\n",
                                             (char *)cstring_get_str(path), ino,
                                             (uint32_t)op_uid, (uint32_t)op_gid,
                                             CXFSNP_ATTR_UID(cxfsnp_attr), CXFSNP_ATTR_GID(cxfsnp_attr),
                                             (uint32_t)uid, (uint32_t)gid,
                                             CXFSNP_ATTR_MODE(cxfsnp_attr));

        (*res) = 0;

        return (EC_TRUE);
    }

    if(CXFS_FUSES_PERM_SWITCH == SWITCH_ON
    && CXFSNP_ATTR_UID(cxfsnp_attr) != (uint32_t)uid
    && CXFS_FUSES_UID_ERR != uid)
    {
        CXFSNP_ITEM     *cxfsnp_item_parent;
        CXFSNP_ATTR     *cxfsnp_attr_parent;

        if(0 == CXFSNP_ATTR_UID(cxfsnp_attr))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_chown: "
                                                 "path '%s', ino %lu, "
                                                 "[op:%u:%u] chown (uid %u, gid %u) -> (uid %u, gid %u), "
                                                 "mode %#o, uid is root "
                                                 "=> deny\n",
                                                 (char *)cstring_get_str(path), ino,
                                                 (uint32_t)op_uid, (uint32_t)op_gid,
                                                 CXFSNP_ATTR_UID(cxfsnp_attr), CXFSNP_ATTR_GID(cxfsnp_attr),
                                                 (uint32_t)uid, (uint32_t)gid,
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr));

            (*res) = -EPERM;
            return (EC_TRUE);
        }

        if(0 != op_uid
        && 0 == (S_IXOTH & CXFSNP_ATTR_MODE(cxfsnp_attr)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_chown: "
                                                 "path '%s', ino %lu, "
                                                 "[op:%u:%u] chown (uid %u, gid %u) -> (uid %u, gid %u), "
                                                 "mode %#o & (S_ IXOTH) == 0 "
                                                 "=> deny\n",
                                                 (char *)cstring_get_str(path), ino,
                                                 (uint32_t)op_uid, (uint32_t)op_gid,
                                                 CXFSNP_ATTR_UID(cxfsnp_attr), CXFSNP_ATTR_GID(cxfsnp_attr),
                                                 (uint32_t)uid, (uint32_t)gid,
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr));

            (*res) = -EPERM;
            return (EC_TRUE);
        }

        cxfsnp_item_parent = cxfsnp_mgr_fetch_parent_item(CXFS_MD_NPP(cxfs_md), ino);
        cxfsnp_attr_parent = CXFSNP_ITEM_ATTR(cxfsnp_item_parent);

        if(CXFSNP_ATTR_UID(cxfsnp_attr) != (uint32_t)uid
        && 0 == (S_IXOTH & CXFSNP_ATTR_MODE(cxfsnp_attr_parent)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_chown: "
                                                 "path '%s', ino %lu, "
                                                 "(uid %u, gid %u) -> (uid %u, gid %u), "
                                                 "parent mode %#o & (S_IXOTH) == 0 "
                                                 "=> deny\n",
                                                 (char *)cstring_get_str(path), ino,
                                                 CXFSNP_ATTR_UID(cxfsnp_attr), CXFSNP_ATTR_GID(cxfsnp_attr),
                                                 (uint32_t)uid, (uint32_t)gid,
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr_parent));

            (*res) = -EACCES;
            return (EC_TRUE);
        }

        CXFS_FUSES_GOTO_HARD_LINK_TOP(cxfs_md, ino, cxfsnp_item, cxfsnp_attr);

        CXFSNP_ATTR_UID(cxfsnp_attr)        = (uint32_t)uid;

        /*update time only when change happen*/
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

    if(CXFS_FUSES_PERM_SWITCH == SWITCH_ON
    && CXFSNP_ATTR_GID(cxfsnp_attr) != (uint32_t)gid
    && CXFS_FUSES_GID_ERR != gid)
    {
        CXFSNP_ITEM     *cxfsnp_item_parent;
        CXFSNP_ATTR     *cxfsnp_attr_parent;

        if(0 == CXFSNP_ATTR_GID(cxfsnp_attr))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_chown: "
                                                 "path '%s', ino %lu, "
                                                 "[op:%u:%u] chown (uid %u, gid %u) -> (uid %u, gid %u), "
                                                 "mode %#o, gid is root "
                                                 "=> deny\n",
                                                 (char *)cstring_get_str(path), ino,
                                                 (uint32_t)op_uid, (uint32_t)op_gid,
                                                 CXFSNP_ATTR_UID(cxfsnp_attr), CXFSNP_ATTR_GID(cxfsnp_attr),
                                                 (uint32_t)uid, (uint32_t)gid,
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr));

            (*res) = -EPERM;
            return (EC_TRUE);
        }

        if(0 != op_gid
        && 0 == (S_IXGRP & CXFSNP_ATTR_MODE(cxfsnp_attr)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_chown: "
                                                 "path '%s', ino %lu, "
                                                 "[op:%u:%u] chown (uid %u, gid %u) -> (uid %u, gid %u), "
                                                 "mode %#o & (S_IXGRP) == 0 "
                                                 "=> deny\n",
                                                 (char *)cstring_get_str(path), ino,
                                                 (uint32_t)op_uid, (uint32_t)op_gid,
                                                 CXFSNP_ATTR_UID(cxfsnp_attr), CXFSNP_ATTR_GID(cxfsnp_attr),
                                                 (uint32_t)uid, (uint32_t)gid,
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr));

            (*res) = -EPERM;
            return (EC_TRUE);
        }

        cxfsnp_item_parent = cxfsnp_mgr_fetch_parent_item(CXFS_MD_NPP(cxfs_md), ino);
        cxfsnp_attr_parent = CXFSNP_ITEM_ATTR(cxfsnp_item_parent);

        if(CXFSNP_ATTR_GID(cxfsnp_attr) != (uint32_t)gid
        && 0 == (S_IXGRP & CXFSNP_ATTR_MODE(cxfsnp_attr_parent)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_chown: "
                                                 "path '%s', ino %lu, "
                                                 "(uid %u, gid %u) -> (uid %u, gid %u), "
                                                 "parent mode %#o & (S_IXGRP) == 0 "
                                                 "=> deny\n",
                                                 (char *)cstring_get_str(path), ino,
                                                 CXFSNP_ATTR_UID(cxfsnp_attr), CXFSNP_ATTR_GID(cxfsnp_attr),
                                                 (uint32_t)uid, (uint32_t)gid,
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr_parent));

            (*res) = -EACCES;
            return (EC_TRUE);
        }

        CXFS_FUSES_GOTO_HARD_LINK_TOP(cxfs_md, ino, cxfsnp_item, cxfsnp_attr);

        CXFSNP_ATTR_GID(cxfsnp_attr)        = (uint32_t)gid;

        /*update time only when change happen*/
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

    /*should never reach here*/
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

EC_BOOL cxfs_fuses_truncate(const UINT32 cxfs_md_id, const CSTRING *path, const UINT32 length, const UINT32 uid, const UINT32 gid, int *res)
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

    if(CXFS_FUSES_FILE_MAX_SIZE < ((uint64_t)length))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_truncate: "
                                             "path %s, expect length %lu overflow\n",
                                             (char *)cstring_get_str(path),
                                             (uint64_t)length);
        (*res) = -EFBIG;
        return (EC_TRUE);
    }

    ASSERT(uid == (uid & CXFS_FUSES_UID_MASK));
    ASSERT(gid == (gid & CXFS_FUSES_GID_MASK));

    cxfsnp_item = __cxfs_fuses_lookup(cxfs_md_id, path, &ino);

    if(CXFS_FUSES_PERM_SWITCH == SWITCH_ON
    && NULL_PTR != cxfsnp_item /*file exist*/
    && 0 != uid && 0 == gid) /*not root*/
    {
        cxfsnp_attr = CXFSNP_ITEM_ATTR(cxfsnp_item);

        dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_truncate: "
                                             "'%s', its (uid %u, gid %u, mod %#o), "
                                             "op (uid %u, gid %u)\n",
                                             (char *)cstring_get_str(path),
                                             CXFSNP_ATTR_UID(cxfsnp_attr),
                                             CXFSNP_ATTR_GID(cxfsnp_attr),
                                             CXFSNP_ATTR_MODE(cxfsnp_attr),
                                             (uint32_t)uid, (uint32_t)gid);

        if(CXFSNP_ATTR_UID(cxfsnp_attr) == (uint32_t)uid
        && CXFSNP_ATTR_GID(cxfsnp_attr) == (uint32_t)gid
        && 0 == (S_IWUSR & CXFSNP_ATTR_MODE(cxfsnp_attr)))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_truncate: "
                                                 "'%s', its (uid %u, gid %u, mod %#o), "
                                                 "op (uid %u, gid %u), "
                                                 "mod & (S_IWUSR) == 0\n",
                                                 (char *)cstring_get_str(path),
                                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                 (uint32_t)uid, (uint32_t)gid);
            (*res) = -EACCES;
            return (EC_TRUE);
        }

        if(CXFSNP_ATTR_UID(cxfsnp_attr) == (uint32_t)uid
        && CXFSNP_ATTR_GID(cxfsnp_attr) != (uint32_t)gid
        && 0 == (S_IWGRP & CXFSNP_ATTR_MODE(cxfsnp_attr)))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_truncate: "
                                                 "'%s', its (uid %u, gid %u, mod %#o), "
                                                 "op (uid %u, gid %u), "
                                                 "mod & (S_IWGRP) == 0\n",
                                                 (char *)cstring_get_str(path),
                                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                 (uint32_t)uid, (uint32_t)gid);
            (*res) = -EACCES;
            return (EC_TRUE);
        }

        if(CXFSNP_ATTR_UID(cxfsnp_attr) != (uint32_t)uid
        && CXFSNP_ATTR_GID(cxfsnp_attr) == (uint32_t)gid
        && 0 == (S_IXGRP & CXFSNP_ATTR_MODE(cxfsnp_attr)))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_truncate: "
                                                 "'%s', its (uid %u, gid %u, mod %#o), "
                                                 "op (uid %u, gid %u), "
                                                 "mod & (S_IXGRP) == 0\n",
                                                 (char *)cstring_get_str(path),
                                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                 (uint32_t)uid, (uint32_t)gid);
            (*res) = -EACCES;
            return (EC_TRUE);
        }

        if(CXFSNP_ATTR_UID(cxfsnp_attr) != (uint32_t)uid
        && CXFSNP_ATTR_GID(cxfsnp_attr) != (uint32_t)gid
        && 0 == (S_IWOTH & CXFSNP_ATTR_MODE(cxfsnp_attr)))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_truncate: "
                                                 "'%s', its (uid %u, gid %u, mod %#o), "
                                                 "op (uid %u, gid %u), "
                                                 "mod & (S_IWOTH) == 0\n",
                                                 (char *)cstring_get_str(path),
                                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                 (uint32_t)uid, (uint32_t)gid);
            (*res) = -EACCES;
            return (EC_TRUE);
        }
    }

    if(CXFS_FUSES_PERM_SWITCH == SWITCH_ON
    && NULL_PTR != cxfsnp_item /*file exist*/
    && 0 != uid && 0 != gid) /*not root*/
    {
        cxfsnp_attr = CXFSNP_ITEM_ATTR(cxfsnp_item);

        dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_truncate: "
                                             "'%s', its (uid %u, gid %u, mod %#o), "
                                             "op (uid %u, gid %u)\n",
                                             (char *)cstring_get_str(path),
                                             CXFSNP_ATTR_UID(cxfsnp_attr),
                                             CXFSNP_ATTR_GID(cxfsnp_attr),
                                             CXFSNP_ATTR_MODE(cxfsnp_attr),
                                             (uint32_t)uid, (uint32_t)gid);

        if(CXFSNP_ATTR_UID(cxfsnp_attr) == (uint32_t)uid
        && CXFSNP_ATTR_GID(cxfsnp_attr) == (uint32_t)gid
        && 0 == (S_IWUSR & CXFSNP_ATTR_MODE(cxfsnp_attr)))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_truncate: "
                                                 "'%s', its (uid %u, gid %u, mod %#o), "
                                                 "op (uid %u, gid %u), "
                                                 "mod & (S_IWUSR) == 0\n",
                                                 (char *)cstring_get_str(path),
                                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                 (uint32_t)uid, (uint32_t)gid);
            (*res) = -EACCES;
            return (EC_TRUE);
        }

        if(CXFSNP_ATTR_UID(cxfsnp_attr) == (uint32_t)uid
        && CXFSNP_ATTR_GID(cxfsnp_attr) != (uint32_t)gid
        && 0 == (S_IWGRP & CXFSNP_ATTR_MODE(cxfsnp_attr)))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_truncate: "
                                                 "'%s', its (uid %u, gid %u, mod %#o), "
                                                 "op (uid %u, gid %u), "
                                                 "mod & (S_IWGRP) == 0\n",
                                                 (char *)cstring_get_str(path),
                                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                 (uint32_t)uid, (uint32_t)gid);
            (*res) = -EACCES;
            return (EC_TRUE);
        }

        if(CXFSNP_ATTR_UID(cxfsnp_attr) != (uint32_t)uid
        && CXFSNP_ATTR_GID(cxfsnp_attr) == (uint32_t)gid
        && 0 == (S_IXGRP & CXFSNP_ATTR_MODE(cxfsnp_attr)))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_truncate: "
                                                 "'%s', its (uid %u, gid %u, mod %#o), "
                                                 "op (uid %u, gid %u), "
                                                 "mod & (S_IXGRP) == 0\n",
                                                 (char *)cstring_get_str(path),
                                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                 (uint32_t)uid, (uint32_t)gid);
            (*res) = -EACCES;
            return (EC_TRUE);
        }

        if(CXFSNP_ATTR_UID(cxfsnp_attr) != (uint32_t)uid
        && CXFSNP_ATTR_GID(cxfsnp_attr) != (uint32_t)gid
        && 0 == (S_IWOTH & CXFSNP_ATTR_MODE(cxfsnp_attr)))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_truncate: "
                                                 "'%s', its (uid %u, gid %u, mod %#o), "
                                                 "op (uid %u, gid %u), "
                                                 "mod & (S_IWOTH) == 0\n",
                                                 (char *)cstring_get_str(path),
                                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                 (uint32_t)uid, (uint32_t)gid);
            (*res) = -EACCES;
            return (EC_TRUE);
        }
    }

    if(CXFS_FUSES_PERM_SWITCH == SWITCH_ON
    && 0 != uid && 0 != gid) /*not root*/
    {
        CXFSNP_ITEM     *cxfsnp_item_parent;
        CXFSNP_ATTR     *cxfsnp_attr_parent;
        uint64_t         ino_parent;

        cxfsnp_item_parent = __cxfs_fuses_lookup_parent(cxfs_md_id, path, &ino_parent);
        if(NULL_PTR == cxfsnp_item_parent)
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_truncate: "
                                                 "lookup parent of '%s' failed\n",
                                                 (char *)cstring_get_str(path));
            (*res) = -ENOENT;
            return (EC_TRUE);
        }
        cxfsnp_attr_parent = CXFSNP_ITEM_ATTR(cxfsnp_item_parent);

        if(CXFS_FUSES_UID_ERR == (uint32_t)uid)
        {
            if(CXFSNP_ATTR_UID(cxfsnp_attr_parent) != (uint32_t)uid)
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_truncate: "
                                                     "'%s', uid %u, parent uid %u => not matched\n",
                                                     (char *)cstring_get_str(path),
                                                     (uint32_t)uid, CXFSNP_ATTR_UID(cxfsnp_attr_parent));
                (*res) = -EACCES;
                return (EC_TRUE);
            }
        }
        else
        {
            if(CXFSNP_ATTR_UID(cxfsnp_attr_parent) == (uint32_t)uid
            && 0 == (S_IWUSR & CXFSNP_ATTR_MODE(cxfsnp_attr_parent)))
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_truncate: "
                                                     "'%s', parent ino %lu, "
                                                     "uid %u same, parent mode %#o & (S_IWUSR) == 0 "
                                                     "=> deny (uid %u, gid %u)\n",
                                                     (char *)cstring_get_str(path), ino_parent,
                                                     (uint32_t)uid,
                                                     CXFSNP_ATTR_MODE(cxfsnp_attr_parent),
                                                     (uint32_t)uid, (uint32_t)gid);
                (*res) = -EACCES;
                return (EC_TRUE);
            }

            if(CXFSNP_ATTR_UID(cxfsnp_attr_parent) != (uint32_t)uid
            && 0 == (S_IXOTH & CXFSNP_ATTR_MODE(cxfsnp_attr_parent)))
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_truncate: "
                                                     "path '%s', parent ino %lu, "
                                                     "parent mode %#o & (S_IXOTH) == 0 "
                                                     "=> deny (uid %u, gid %u)\n",
                                                     (char *)cstring_get_str(path), ino_parent,
                                                     CXFSNP_ATTR_MODE(cxfsnp_attr_parent),
                                                     (uint32_t)uid, (uint32_t)gid);

                (*res) = -EACCES;
                return (EC_TRUE);
            }
        }

        if(CXFS_FUSES_GID_ERR == (uint32_t)gid)
        {
            if(CXFSNP_ATTR_GID(cxfsnp_attr_parent) != (uint32_t)gid)
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_truncate: "
                                                     "'%s', gid %#x overflow\n",
                                                     (char *)cstring_get_str(path),
                                                     (uint32_t)gid);
                (*res) = -EOVERFLOW;
                return (EC_TRUE);
            }
        }
        else
        {
            if(0 == (S_IXGRP & CXFSNP_ATTR_MODE(cxfsnp_attr_parent)))
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_truncate: "
                                                     "path '%s', parent ino %lu, "
                                                     "parent mode %#o & (S_IXGRP) == 0 "
                                                     "=> deny (uid %u, gid %u)\n",
                                                     (char *)cstring_get_str(path),
                                                     ino_parent,
                                                     CXFSNP_ATTR_MODE(cxfsnp_attr_parent),
                                                     (uint32_t)uid,
                                                     (uint32_t)gid);

                (*res) = -EACCES;
                return (EC_TRUE);
            }
        }
    }

    if(NULL_PTR == cxfsnp_item)
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
            (*res) = -EACCES;
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

        CXFSNP_ATTR_DIR_FLAG(cxfsnp_attr)   = CXFSNP_ATTR_FILE_IS_REG;

        CXFSNP_ATTR_ATIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
        CXFSNP_ATTR_MTIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
        CXFSNP_ATTR_CTIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
        CXFSNP_ATTR_ATIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;
        CXFSNP_ATTR_MTIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;
        CXFSNP_ATTR_CTIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;
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

    CXFSNP_ITEM     *cxfsnp_item;
    //CXFSNP_ATTR     *cxfsnp_attr;
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

    cxfsnp_item = __cxfs_fuses_lookup(cxfs_md_id, path, &ino);
    if(NULL_PTR == cxfsnp_item)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_open: "
                                             "no dir '%s'\n",
                                             (char *)cstring_get_str(path));
        (*res) = -ENOENT;
        return (EC_TRUE);
    }
    //cxfsnp_attr = CXFSNP_ITEM_ATTR(cxfsnp_item);

    if(((uint32_t)flags) & O_TRUNC)
    {
        accmode = O_WRONLY;

        if(CXFS_FUSES_PERM_SWITCH == SWITCH_ON
        && EC_FALSE == __cxfs_fuses_check_access(cxfs_md_id, ino, accmode, (uint32_t)uid, (uint32_t)gid))
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

        return cxfs_fuses_truncate(cxfs_md_id, path, (UINT32)0, uid, gid, res);
    }

    accmode = (((uint32_t)flags) & O_ACCMODE);
    if(O_ACCMODE <= accmode)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_open: "
                                             "dir '%s', "
                                             "flags %#x & O_ACCMODE %#x = %#x >= O_ACCMODE "
                                             "=> invalid flags\n",
                                             (char *)cstring_get_str(path),
                                             ((uint32_t)flags), accmode);


        (*res) = -EINVAL;
        return (EC_FALSE);
    }

    if(CXFS_FUSES_PERM_SWITCH == SWITCH_ON
    && EC_FALSE == __cxfs_fuses_check_access(cxfs_md_id, ino, accmode, (uint32_t)uid, (uint32_t)gid))
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

    ASSERT(uid == (uid & CXFS_FUSES_UID_MASK));
    ASSERT(gid == (gid & CXFS_FUSES_GID_MASK));

    cxfsnp_item = __cxfs_fuses_lookup(cxfs_md_id, path, &ino);
    if(NULL_PTR != cxfsnp_item) /*file exist*/
    {
        cxfsnp_attr = CXFSNP_ITEM_ATTR(cxfsnp_item);

        if(EC_FALSE == __cxfs_fuses_make_empty_hidden_seg(cxfs_md_id, path, res))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_mknod: "
                                                 "[obscure] %s, make hidden seg file failed\n",
                                                 (char *)cstring_get_str(path));

            (*res) = -EACCES;
            return (EC_TRUE);
        }

        cxfsnp_attr_set_file(cxfsnp_attr);
        CXFSNP_ATTR_HIDE_FLAG(cxfsnp_attr)  = CXFSNP_ATTR_NOT_HIDE;
        CXFSNP_ATTR_MODE(cxfsnp_attr)       = (uint16_t)mode;
        CXFSNP_ATTR_UID(cxfsnp_attr)        = (uint32_t)uid;
        CXFSNP_ATTR_GID(cxfsnp_attr)        = (uint32_t)gid;

        dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_mknod: "
                                             "[obscure] %s, mode %#o => ino %lu => mode %#o uid %u, gid %u => done\n",
                                             (char *)cstring_get_str(path), (uint16_t)mode, ino,
                                             CXFSNP_ATTR_MODE(cxfsnp_attr),
                                             CXFSNP_ATTR_UID(cxfsnp_attr),
                                             CXFSNP_ATTR_GID(cxfsnp_attr));

        (*res) = 0;

        return (EC_TRUE);
    }

    if(CXFS_FUSES_PERM_SWITCH == SWITCH_ON
    && 0 != uid && 0 != gid) /*not root*/
    {
        CXFSNP_ITEM     *cxfsnp_item_parent;
        CXFSNP_ATTR     *cxfsnp_attr_parent;
        uint64_t         ino_parent;
        cxfsnp_item_parent = __cxfs_fuses_lookup_parent(cxfs_md_id, path, &ino_parent);
        if(NULL_PTR == cxfsnp_item_parent)
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_create: "
                                                 "lookup parent of '%s' failed\n",
                                                 (char *)cstring_get_str(path));
            (*res) = -ENOENT;
            return (EC_TRUE);
        }
        cxfsnp_attr_parent = CXFSNP_ITEM_ATTR(cxfsnp_item_parent);

        if(CXFS_FUSES_UID_ERR == (uint32_t)uid)
        {
            if(CXFSNP_ATTR_UID(cxfsnp_attr_parent) == (uint32_t)uid
            && CXFSNP_ATTR_GID(cxfsnp_attr_parent) != (uint32_t)gid
            && 0 == (S_IWUSR & CXFSNP_ATTR_MODE(cxfsnp_attr_parent)))
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_create: "
                                                     "path '%s', parent ino %lu, "
                                                     "parent (uid %u, gid %u mode %#o), "
                                                     "parent mode & (S_IWUSR) == 0 "
                                                     "=> deny (uid %u, gid %u, mode %#o)\n",
                                                     (char *)cstring_get_str(path), ino_parent,
                                                     CXFSNP_ATTR_UID(cxfsnp_attr_parent),
                                                     CXFSNP_ATTR_GID(cxfsnp_attr_parent),
                                                     CXFSNP_ATTR_MODE(cxfsnp_attr_parent),
                                                     (uint32_t)uid, (uint32_t)gid, (uint16_t)mode);

                (*res) = -EACCES;
                return (EC_TRUE);
            }

            if(CXFSNP_ATTR_UID(cxfsnp_attr_parent) != (uint32_t)uid
            && CXFSNP_ATTR_GID(cxfsnp_attr_parent) != (uint32_t)gid
            && 0 == (S_IWOTH & CXFSNP_ATTR_MODE(cxfsnp_attr_parent)))
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_create: "
                                                     "path '%s', parent ino %lu, "
                                                     "parent (uid %u, gid %u mode %#o), "
                                                     "parent mode & (S_IWOTH) == 0 "
                                                     "=> deny (uid %u, gid %u, mode %#o)\n",
                                                     (char *)cstring_get_str(path), ino_parent,
                                                     CXFSNP_ATTR_UID(cxfsnp_attr_parent),
                                                     CXFSNP_ATTR_GID(cxfsnp_attr_parent),
                                                     CXFSNP_ATTR_MODE(cxfsnp_attr_parent),
                                                     (uint32_t)uid, (uint32_t)gid, (uint16_t)mode);
                (*res) = -EACCES;
                return (EC_TRUE);
            }
        }
        else
        {
            if(CXFSNP_ATTR_UID(cxfsnp_attr_parent) == (uint32_t)uid
            && 0 == (S_IWUSR & CXFSNP_ATTR_MODE(cxfsnp_attr_parent)))
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_create: "
                                                     "'%s', parent ino %lu, "
                                                     "uid %u same, parent mode %#o & (S_IWUSR) == 0 "
                                                     "=> deny (uid %u, gid %u) mode %#o\n",
                                                     (char *)cstring_get_str(path), ino_parent,
                                                     (uint32_t)uid,
                                                     CXFSNP_ATTR_MODE(cxfsnp_attr_parent),
                                                     (uint32_t)uid, (uint32_t)gid, (uint16_t)mode);
                (*res) = -EACCES;
                return (EC_TRUE);
            }

            if(CXFSNP_ATTR_UID(cxfsnp_attr_parent) != (uint32_t)uid
            && 0 == (S_IXOTH & CXFSNP_ATTR_MODE(cxfsnp_attr_parent)))
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_create: "
                                                     "path '%s', parent ino %lu, "
                                                     "parent mode %#o & (S_IXOTH) == 0 "
                                                     "=> deny (uid %u, gid %u) mode %#o\n",
                                                     (char *)cstring_get_str(path), ino_parent,
                                                     CXFSNP_ATTR_MODE(cxfsnp_attr_parent),
                                                     (uint32_t)uid, (uint32_t)gid, (uint16_t)mode);

                (*res) = -EACCES;
                return (EC_TRUE);
            }
        }

        if(CXFS_FUSES_GID_ERR == (uint32_t)gid)
        {
            if(CXFSNP_ATTR_GID(cxfsnp_attr_parent) != (uint32_t)gid)
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_create: "
                                                     "'%s', gid %#x overflow\n",
                                                     (char *)cstring_get_str(path),
                                                     (uint32_t)gid);
                (*res) = -EOVERFLOW;
                return (EC_TRUE);
            }
        }
        else
        {
            if(0 == (S_IXGRP & CXFSNP_ATTR_MODE(cxfsnp_attr_parent)))
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_create: "
                                                     "path '%s', parent ino %lu, "
                                                     "parent mode %#o & (S_IXGRP) == 0 "
                                                     "=> deny (uid %u, gid %u)\n",
                                                     (char *)cstring_get_str(path), ino_parent,
                                                     CXFSNP_ATTR_MODE(cxfsnp_attr_parent),
                                                     (uint32_t)uid,
                                                     (uint32_t)gid);

                (*res) = -EACCES;
                return (EC_TRUE);
            }
        }
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
        (*res) = -EACCES;
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
    CXFSNP_ATTR_HIDE_FLAG(cxfsnp_attr)  = CXFSNP_ATTR_NOT_HIDE;
    CXFSNP_ATTR_MODE(cxfsnp_attr)       = (uint16_t)mode;
    CXFSNP_ATTR_UID(cxfsnp_attr)        = (uint32_t)uid;
    CXFSNP_ATTR_GID(cxfsnp_attr)        = (uint32_t)gid;

    dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_create: "
                                         "%s mode %#o => ino %lu => mode %#o uid %u, gid %u => done\n",
                                         (char *)cstring_get_str(path), (uint16_t)mode, ino,
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

    /*fix*/
    if(EC_FALSE == clist_is_empty(CRANGE_NODE_RANGE_SEGS(crange_node)))
    {
        CSTRING         *seg_path;
        CRANGE_SEG      *crange_seg;
        UINT32           seg_no;

        crange_seg = clist_first_data(CRANGE_NODE_RANGE_SEGS(crange_node));

        for(seg_no = 1; seg_no < CRANGE_SEG_NO(crange_seg); seg_no ++)
        {
            seg_path = cstring_make("%s/%ld", cstring_get_str(path), seg_no);
            if(NULL_PTR == seg_path)
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_write_seg: "
                                                     "make seg path %s/%ld failed\n",
                                                     (char *)cstring_get_str(path),
                                                     seg_no);

                crange_node_free(crange_node);

                (*res) = -ENOMEM;
                return (EC_TRUE);
            }

            if(EC_TRUE == cxfs_find_file(cxfs_md_id, seg_path))
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_write: "
                                                     "check seg %s exist\n",
                                                     (char *)cstring_get_str(seg_path));

                cstring_free(seg_path);

                continue;
            }

            if(EC_FALSE == cxfs_reserve(cxfs_md_id, seg_path, (UINT32)CXFSPGB_PAGE_BYTE_SIZE))
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_write: "
                                                     "reserve seg %s failed\n",
                                                     (char *)cstring_get_str(seg_path));

                cstring_free(seg_path);

                crange_node_free(crange_node);
                return (EC_TRUE);
            }

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_write: "
                                                 "reserve seg %s done\n",
                                                 (char *)cstring_get_str(seg_path));

            cstring_free(seg_path);
        }
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

    if(CXFSNP_ATTR_FILE_IS_REG == CXFSNP_ATTR_DIR_FLAG(cxfsnp_attr))
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

#if 0
/* Definitions for the flag in `f_flag'.  These definitions should be
   kept in sync with the definitions in <sys/mount.h>.  */
enum
{
  ST_RDONLY = 1,        /* Mount read-only.  */
#define ST_RDONLY   ST_RDONLY
  ST_NOSUID = 2         /* Ignore suid and sgid bits.  */
#define ST_NOSUID   ST_NOSUID
#ifdef __USE_GNU
  ,
  ST_NODEV = 4,         /* Disallow access to device special files.  */
# define ST_NODEV   ST_NODEV
  ST_NOEXEC = 8,        /* Disallow program execution.  */
# define ST_NOEXEC  ST_NOEXEC
  ST_SYNCHRONOUS = 16,      /* Writes are synced at once.  */
# define ST_SYNCHRONOUS ST_SYNCHRONOUS
  ST_MANDLOCK = 64,     /* Allow mandatory locks on an FS.  */
# define ST_MANDLOCK    ST_MANDLOCK
  ST_WRITE = 128,       /* Write on file/directory/symlink.  */
# define ST_WRITE   ST_WRITE
  ST_APPEND = 256,      /* Append-only file.  */
# define ST_APPEND  ST_APPEND
  ST_IMMUTABLE = 512,       /* Immutable file.  */
# define ST_IMMUTABLE   ST_IMMUTABLE
  ST_NOATIME = 1024,        /* Do not update access times.  */
# define ST_NOATIME ST_NOATIME
  ST_NODIRATIME = 2048,     /* Do not update directory access times.  */
# define ST_NODIRATIME  ST_NODIRATIME
  ST_RELATIME = 4096        /* Update atime relative to mtime/ctime.  */
# define ST_RELATIME    ST_RELATIME
#endif  /* Use GNU.  */
};
#endif
    if(CXFSNP_ATTR_FILE_IS_DIR == CXFSNP_ATTR_DIR_FLAG(cxfsnp_attr))
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
                                         CXFSNP_ATTR_DIR_FLAG(cxfsnp_attr));

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

EC_BOOL cxfs_fuses_ftruncate(const UINT32 cxfs_md_id, const CSTRING *path, const UINT32 length, const UINT32 uid, const UINT32 gid, int *res)
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

    return cxfs_fuses_truncate(cxfs_md_id, path, length, uid, gid, res);
}

EC_BOOL cxfs_fuses_utimens(const UINT32 cxfs_md_id, const CSTRING *path, const struct timespec *tv0, const struct timespec *tv1, const UINT32 uid, const UINT32 gid, int *res)
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

    dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_utimens: "
                                         "path '%s', its (uid %u, gid %u, mode %#o), "
                                         "op (uid %u, gid %u)\n",
                                         (char *)cstring_get_str(path),
                                         CXFSNP_ATTR_UID(cxfsnp_attr),
                                         CXFSNP_ATTR_GID(cxfsnp_attr),
                                         CXFSNP_ATTR_MODE(cxfsnp_attr),
                                         (uint32_t)uid, (uint32_t)gid);


    if(CXFS_FUSES_UID_NOBODY == uid && CXFS_FUSES_GID_ROOT == gid
    && (CXFS_FUSES_GID_ROOT == CXFSNP_ATTR_UID(cxfsnp_attr)
       && CXFS_FUSES_GID_ROOT == CXFSNP_ATTR_GID(cxfsnp_attr)))
    {
        CXFSNP_ITEM     *cxfsnp_item_parent;
        CXFSNP_ATTR     *cxfsnp_attr_parent;

        cxfsnp_item_parent = cxfsnp_mgr_fetch_parent_item(CXFS_MD_NPP(cxfs_md), ino);
        if(NULL_PTR == cxfsnp_item_parent)
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_utimens: "
                                                 "fetch parent of '%s' failed\n",
                                                 (char *)cstring_get_str(path));
            (*res) = -ENOENT;
            return (EC_TRUE);
        }
        cxfsnp_attr_parent = CXFSNP_ITEM_ATTR(cxfsnp_item_parent);

        if(CXFSNP_ATTR_UID(cxfsnp_attr_parent) != (uint32_t)uid
        && CXFS_FUSES_GID_ROOT == CXFSNP_ATTR_UID(cxfsnp_attr_parent)
        && 0 == (S_IXGRP & CXFSNP_ATTR_MODE(cxfsnp_attr_parent)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_utimens: "
                                                 "path '%s', its uid %u, gid %u, "
                                                 "parent uid %u, gid %u, mode %#o, "
                                                 "mode & (S_IXGRP) == 0 "
                                                 "=> deny (uid %u, gid %u)\n",
                                                 (char *)cstring_get_str(path),
                                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr),
                                                 CXFSNP_ATTR_UID(cxfsnp_attr_parent),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr_parent),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr_parent),
                                                 (uint32_t)uid, (uint32_t)gid);

            (*res) = -EACCES;
            return (EC_TRUE);
        }
    }

    if(CXFS_FUSES_PERM_SWITCH == SWITCH_ON
    && 0 != uid && 0 == gid
    && (CXFSNP_ATTR_UID(cxfsnp_attr) != (uint32_t)uid
       || CXFSNP_ATTR_GID(cxfsnp_attr) != (uint32_t)gid))
    {
        if(0 == CXFSNP_ATTR_UID(cxfsnp_attr)
        && 0 == CXFSNP_ATTR_GID(cxfsnp_attr)
        && 0 == (S_IXGRP & CXFSNP_ATTR_MODE(cxfsnp_attr)))
        {
            if(0 == (S_IWGRP & CXFSNP_ATTR_MODE(cxfsnp_attr)))
            {
                if(UTIME_NOW == tv0->tv_nsec || UTIME_NOW == tv1->tv_nsec)
                {
                    dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_utimens: "
                                                         "path '%s', its uid %u, gid %u, mode %#o, "
                                                         "mode & (S_IXGRP) == 0 && mode & (S_IWGRP) == 0 && UTIME_NOW "
                                                         "=> deny (uid %u, gid %u)\n",
                                                         (char *)cstring_get_str(path),
                                                         CXFSNP_ATTR_UID(cxfsnp_attr),
                                                         CXFSNP_ATTR_GID(cxfsnp_attr),
                                                         CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                         (uint32_t)uid, (uint32_t)gid);

                    (*res) = -EACCES;
                    return (EC_TRUE);
                }
                else
                {
                    dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_utimens: "
                                                         "path '%s', its uid %u, gid %u, mode %#o, "
                                                         "mode & (S_IXGRP) == 0 && mode & (S_IWGRP) == 0 && NOT UTIME_NOW "
                                                         "=> deny (uid %u, gid %u)\n",
                                                         (char *)cstring_get_str(path),
                                                         CXFSNP_ATTR_UID(cxfsnp_attr),
                                                         CXFSNP_ATTR_GID(cxfsnp_attr),
                                                         CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                         (uint32_t)uid, (uint32_t)gid);

                    (*res) = -EPERM;
                    return (EC_TRUE);
                }
            }
            else
            {
                if(UTIME_NOW != tv0->tv_nsec && UTIME_NOW != tv1->tv_nsec)
                {
                    dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_utimens: "
                                                         "path '%s', its uid %u, gid %u, mode %#o, "
                                                         "mode & (S_IXGRP) == 0 && mode & (S_IWGRP) != 0 && NOT UTIME_NOW "
                                                         "=> deny (uid %u, gid %u)\n",
                                                         (char *)cstring_get_str(path),
                                                         CXFSNP_ATTR_UID(cxfsnp_attr),
                                                         CXFSNP_ATTR_GID(cxfsnp_attr),
                                                         CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                         (uint32_t)uid, (uint32_t)gid);

                    (*res) = -EPERM;
                    return (EC_TRUE);
                }
            }
        }

        if(CXFSNP_ATTR_UID(cxfsnp_attr) != (uint32_t)uid
        && 0 == (S_IWOTH & CXFSNP_ATTR_MODE(cxfsnp_attr)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_utimens: "
                                                 "path '%s', its uid %u, gid %u, "
                                                 "mode %#o & (S_IWOTH) == 0 "
                                                 "=> deny (uid %u, gid %u)\n",
                                                 (char *)cstring_get_str(path),
                                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                 (uint32_t)uid, (uint32_t)gid);

            (*res) = -EACCES;
            return (EC_TRUE);
        }
    }

    if(CXFS_FUSES_PERM_SWITCH == SWITCH_ON
    && 0 != uid && 0 != gid /*not root*/
    && (CXFSNP_ATTR_UID(cxfsnp_attr) == (uint32_t)uid
       && CXFSNP_ATTR_GID(cxfsnp_attr) == (uint32_t)gid))
    {
        CXFSNP_ITEM     *cxfsnp_item_parent;
        CXFSNP_ATTR     *cxfsnp_attr_parent;

        cxfsnp_item_parent = cxfsnp_mgr_fetch_parent_item(CXFS_MD_NPP(cxfs_md), ino);
        if(NULL_PTR == cxfsnp_item_parent)
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_utimens: "
                                                 "fetch parent of '%s' failed\n",
                                                 (char *)cstring_get_str(path));
            (*res) = -ENOENT;
            return (EC_TRUE);
        }
        cxfsnp_attr_parent = CXFSNP_ITEM_ATTR(cxfsnp_item_parent);

        if(CXFSNP_ATTR_UID(cxfsnp_attr_parent) != (uint32_t)uid
        && 0 == (S_IXOTH & CXFSNP_ATTR_MODE(cxfsnp_attr_parent)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_utimens: "
                                                 "path '%s', "
                                                 "same uid %u and gid %u, "
                                                 "parent (uid %u, gid %u) mode %#o & (S_IXOTH) == 0"
                                                 "=> deny (uid %u, gid %u)\n",
                                                 (char *)cstring_get_str(path),
                                                 (uint32_t)uid, (uint32_t)gid,
                                                 CXFSNP_ATTR_UID(cxfsnp_attr_parent),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr_parent),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr_parent),
                                                 (uint32_t)uid, (uint32_t)gid);

            (*res) = -EACCES;
            return (EC_TRUE);
        }

        if(CXFSNP_ATTR_UID(cxfsnp_attr_parent) == (uint32_t)uid
        && 0 == (S_IWUSR & CXFSNP_ATTR_MODE(cxfsnp_attr_parent)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_utimens: "
                                                 "path '%s', "
                                                 "same uid %u and gid %u, "
                                                 "parent (uid %u, gid %u) mode %#o & (S_IWUSR) == 0"
                                                 "=> deny (uid %u, gid %u)\n",
                                                 (char *)cstring_get_str(path),
                                                 (uint32_t)uid, (uint32_t)gid,
                                                 CXFSNP_ATTR_UID(cxfsnp_attr_parent),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr_parent),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr_parent),
                                                 (uint32_t)uid, (uint32_t)gid);

            (*res) = -EACCES;
            return (EC_TRUE);
        }

        if(CXFSNP_ATTR_UID(cxfsnp_attr_parent) == (uint32_t)uid
        && 0 == (S_IXUSR & CXFSNP_ATTR_MODE(cxfsnp_attr_parent)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_utimens: "
                                                 "path '%s', "
                                                 "same uid %u and gid %u, "
                                                 "parent (uid %u, gid %u) mode %#o & (S_IXUSR) == 0"
                                                 "=> deny (uid %u, gid %u)\n",
                                                 (char *)cstring_get_str(path),
                                                 (uint32_t)uid, (uint32_t)gid,
                                                 CXFSNP_ATTR_UID(cxfsnp_attr_parent),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr_parent),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr_parent),
                                                 (uint32_t)uid, (uint32_t)gid);

            (*res) = -EACCES;
            return (EC_TRUE);
        }
    }

    if(CXFS_FUSES_PERM_SWITCH == SWITCH_ON
    && 0 != uid && 0 != gid /*not root*/
    && (CXFSNP_ATTR_UID(cxfsnp_attr) != (uint32_t)uid
       || CXFSNP_ATTR_GID(cxfsnp_attr) != (uint32_t)gid))
    {
        if(CXFSNP_ATTR_UID(cxfsnp_attr) != (uint32_t)uid
        && CXFSNP_ATTR_GID(cxfsnp_attr) != (uint32_t)gid
        && 0 == (S_IXOTH & CXFSNP_ATTR_MODE(cxfsnp_attr)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_utimens: "
                                                 "path '%s', its uid %u, gid %u, "
                                                 "mode %#o & (S_IXOTH) == 0 "
                                                 "=> deny (uid %u, gid %u)\n",
                                                 (char *)cstring_get_str(path),
                                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                 (uint32_t)uid, (uint32_t)gid);

            (*res) = -EACCES;
            return (EC_TRUE);
        }

        if(CXFSNP_ATTR_UID(cxfsnp_attr) != (uint32_t)uid
        && CXFSNP_ATTR_GID(cxfsnp_attr) != (uint32_t)gid
        && 0 == (S_IWOTH & CXFSNP_ATTR_MODE(cxfsnp_attr)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_utimens: "
                                                 "path '%s', its uid %u, gid %u, "
                                                 "mode %#o & (S_IWOTH) == 0 "
                                                 "=> deny (uid %u, gid %u)\n",
                                                 (char *)cstring_get_str(path),
                                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                 (uint32_t)uid, (uint32_t)gid);

            (*res) = -EACCES;
            return (EC_TRUE);
        }

        if(CXFSNP_ATTR_UID(cxfsnp_attr) == (uint32_t)uid
        && CXFSNP_ATTR_GID(cxfsnp_attr) != (uint32_t)gid
        && 0 == (S_IXGRP & CXFSNP_ATTR_MODE(cxfsnp_attr)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_utimens: "
                                                 "path '%s', its uid %u, gid %u, "
                                                 "mode %#o & (S_IXGRP) == 0 "
                                                 "=> deny (uid %u, gid %u)\n",
                                                 (char *)cstring_get_str(path),
                                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                 (uint32_t)uid, (uint32_t)gid);

            (*res) = -EACCES;
            return (EC_TRUE);
        }

        if(CXFSNP_ATTR_UID(cxfsnp_attr) == (uint32_t)uid
        && CXFSNP_ATTR_GID(cxfsnp_attr) != (uint32_t)gid
        && 0 == (S_IWGRP & CXFSNP_ATTR_MODE(cxfsnp_attr)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_utimens: "
                                                 "path '%s', its uid %u, gid %u, "
                                                 "mode %#o & (S_IWGRP) == 0 "
                                                 "=> deny (uid %u, gid %u)\n",
                                                 (char *)cstring_get_str(path),
                                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                 (uint32_t)uid, (uint32_t)gid);

            (*res) = -EACCES;
            return (EC_TRUE);
        }
    }

    if(CXFS_FUSES_PERM_SWITCH == SWITCH_ON
    && 0 != uid && 0 != gid /*not root*/
    && (CXFSNP_ATTR_UID(cxfsnp_attr) != (uint32_t)uid
       || CXFSNP_ATTR_GID(cxfsnp_attr) != (uint32_t)gid))
    {
        CXFSNP_ITEM     *cxfsnp_item_parent;
        CXFSNP_ATTR     *cxfsnp_attr_parent;

        cxfsnp_item_parent = cxfsnp_mgr_fetch_parent_item(CXFS_MD_NPP(cxfs_md), ino);
        if(NULL_PTR == cxfsnp_item_parent)
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_utimens: "
                                                 "lookup parent of '%s' failed\n",
                                                 (char *)cstring_get_str(path));
            (*res) = -ENOENT;
            return (EC_TRUE);
        }
        cxfsnp_attr_parent = CXFSNP_ITEM_ATTR(cxfsnp_item_parent);

        if(CXFS_FUSES_UID_ERR == (uint32_t)uid)
        {
            if(CXFSNP_ATTR_UID(cxfsnp_attr_parent) != (uint32_t)uid)
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_utimens: "
                                                     "'%s', uid %u, parent uid %u => not matched\n",
                                                     (char *)cstring_get_str(path),
                                                     (uint32_t)uid, CXFSNP_ATTR_UID(cxfsnp_attr_parent));
                (*res) = -EACCES;
                return (EC_TRUE);
            }
        }
        else
        {
            if(CXFSNP_ATTR_UID(cxfsnp_attr_parent) != (uint32_t)uid)
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_utimens: "
                                                     "'%s', uid %u, parent uid %u => not matched\n",
                                                     (char *)cstring_get_str(path),
                                                     (uint32_t)uid, CXFSNP_ATTR_UID(cxfsnp_attr_parent));
                (*res) = -EACCES;
                return (EC_TRUE);
            }

            if(CXFSNP_ATTR_UID(cxfsnp_attr_parent) == (uint32_t)uid
            && 0 == (S_IWUSR & CXFSNP_ATTR_MODE(cxfsnp_attr_parent)))
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_utimens: "
                                                     "'%s', "
                                                     "uid %u same, parent mode %#o & (S_IWUSR) == 0 "
                                                     "=> deny (uid %u, gid %u)\n",
                                                     (char *)cstring_get_str(path),
                                                     (uint32_t)uid,
                                                     CXFSNP_ATTR_MODE(cxfsnp_attr_parent),
                                                     (uint32_t)uid, (uint32_t)gid);
                (*res) = -EACCES;
                return (EC_TRUE);
            }

            if(CXFSNP_ATTR_UID(cxfsnp_attr_parent) != (uint32_t)uid
            && 0 == (S_IXOTH & CXFSNP_ATTR_MODE(cxfsnp_attr_parent)))
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_utimens: "
                                                     "path '%s', "
                                                     "parent mode %#o & (S_IXOTH) == 0 "
                                                     "=> deny (uid %u, gid %u)\n",
                                                     (char *)cstring_get_str(path),
                                                     CXFSNP_ATTR_MODE(cxfsnp_attr_parent),
                                                     (uint32_t)uid, (uint32_t)gid);

                (*res) = -EACCES;
                return (EC_TRUE);
            }
        }

        if(CXFS_FUSES_GID_ERR == (uint32_t)gid)
        {
            if(CXFSNP_ATTR_GID(cxfsnp_attr_parent) != (uint32_t)gid)
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_utimens: "
                                                     "'%s', gid %#x overflow\n",
                                                     (char *)cstring_get_str(path),
                                                     (uint32_t)gid);
                (*res) = -EOVERFLOW;
                return (EC_TRUE);
            }
        }
        else
        {
            if(0 == (S_IXGRP & CXFSNP_ATTR_MODE(cxfsnp_attr_parent)))
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_utimens: "
                                                     "path '%s', "
                                                     "parent mode %#o & (S_IXGRP) == 0 "
                                                     "=> deny (uid %u, gid %u)\n",
                                                     (char *)cstring_get_str(path),
                                                     CXFSNP_ATTR_MODE(cxfsnp_attr_parent),
                                                     (uint32_t)uid, (uint32_t)gid);

                (*res) = -EACCES;
                return (EC_TRUE);
            }
        }
    }

    if(UTIME_NOW == tv0->tv_nsec)
    {
        uint64_t         nsec;  /*seconds*/
        uint64_t         nanosec;/*nanosecond*/

        c_get_cur_time_nsec_and_nanosec(&nsec, &nanosec);

        CXFSNP_ATTR_ATIME_SEC(cxfsnp_attr)   = nsec;
        CXFSNP_ATTR_ATIME_NSEC(cxfsnp_attr)  = nanosec;

        dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_utimens: "
                                             "utimens %s => ino %lu, atime %lu:%u "
                                             "=> set now done\n",
                                             (char *)cstring_get_str(path), ino,
                                             CXFSNP_ATTR_ATIME_SEC(cxfsnp_attr),
                                             CXFSNP_ATTR_ATIME_NSEC(cxfsnp_attr));
    }
    else if(UTIME_OMIT == tv0->tv_nsec)
    {
        dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_utimens: "
                                             "utimens %s => ino %lu, atime %lu:%u "
                                             "=> keep unchanged\n",
                                             (char *)cstring_get_str(path), ino,
                                             CXFSNP_ATTR_ATIME_SEC(cxfsnp_attr),
                                             CXFSNP_ATTR_ATIME_NSEC(cxfsnp_attr));
    }
    else
    {
        CXFSNP_ATTR_ATIME_SEC(cxfsnp_attr)   = (uint64_t)tv0->tv_sec;
        CXFSNP_ATTR_ATIME_NSEC(cxfsnp_attr)  = (uint64_t)tv0->tv_nsec;

        dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_utimens: "
                                             "utimens %s => ino %lu, atime %lu:%u "
                                             "=> done\n",
                                             (char *)cstring_get_str(path), ino,
                                             CXFSNP_ATTR_ATIME_SEC(cxfsnp_attr),
                                             CXFSNP_ATTR_ATIME_NSEC(cxfsnp_attr));
    }

    if(UTIME_NOW == tv1->tv_nsec)
    {
        uint64_t         nsec;  /*seconds*/
        uint64_t         nanosec;/*nanosecond*/

        c_get_cur_time_nsec_and_nanosec(&nsec, &nanosec);

        CXFSNP_ATTR_MTIME_SEC(cxfsnp_attr)   = nsec;
        CXFSNP_ATTR_MTIME_NSEC(cxfsnp_attr)  = nanosec;

        dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_utimens: "
                                             "utimens %s => ino %lu, mtime %lu:%u "
                                             "=> set now done\n",
                                             (char *)cstring_get_str(path), ino,
                                             CXFSNP_ATTR_MTIME_SEC(cxfsnp_attr),
                                             CXFSNP_ATTR_MTIME_NSEC(cxfsnp_attr));
    }
    else if(UTIME_OMIT == tv1->tv_nsec)
    {
        dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_utimens: "
                                             "utimens %s => ino %lu, mtime %lu:%u "
                                             "=> keep unchanged\n",
                                             (char *)cstring_get_str(path), ino,
                                             CXFSNP_ATTR_MTIME_SEC(cxfsnp_attr),
                                             CXFSNP_ATTR_MTIME_NSEC(cxfsnp_attr));
    }
    else
    {
        CXFSNP_ATTR_MTIME_SEC(cxfsnp_attr)   = (uint64_t)tv1->tv_sec;
        CXFSNP_ATTR_MTIME_NSEC(cxfsnp_attr)  = (uint64_t)tv1->tv_nsec;

        dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_utimens: "
                                             "utimens %s => ino %lu, mtime %lu:%u "
                                             "=> done\n",
                                             (char *)cstring_get_str(path), ino,
                                             CXFSNP_ATTR_MTIME_SEC(cxfsnp_attr),
                                             CXFSNP_ATTR_MTIME_NSEC(cxfsnp_attr));
    }

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

    if(CXFSNP_ATTR_FILE_IS_DIR == CXFSNP_ATTR_DIR_FLAG(cxfsnp_attr)
    && 1 == CXFSNP_DIT_NODE_MAX_DEPTH(cxfsnp_dit_node))
    {
        dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fuses_readdir_walker: "
                                             "skip entrance dir item\n");
        return (EC_TRUE);
    }

    if(CXFSNP_ATTR_IS_HIDE == CXFSNP_ATTR_HIDE_FLAG(cxfsnp_attr))
    {
        dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fuses_readdir_walker: "
                                             "skip hide item\n");
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
        dirnode->stat.st_rdev       = CXFS_FUSES_RDEV_DEFAULT;

        dirnode->stat.st_atime      = CXFSNP_ATTR_ATIME_SEC(cxfsnp_attr);
        dirnode->stat.st_mtime      = CXFSNP_ATTR_MTIME_SEC(cxfsnp_attr);
        dirnode->stat.st_ctime      = CXFSNP_ATTR_CTIME_SEC(cxfsnp_attr);
        dirnode->stat.st_nlink      = CXFSNP_ATTR_NLINK(cxfsnp_attr);

        dirnode->stat.st_dev        = CXFSNP_ATTR_DEV(cxfsnp_attr);

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
