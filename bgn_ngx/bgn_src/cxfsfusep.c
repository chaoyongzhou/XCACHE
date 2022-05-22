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

#include "type.h"
#include "mm.h"
#include "log.h"

#include "cmisc.h"

#include "crb.h"

#include "cxfs.h"
#include "cxfsfusep.h"


/*mode: O_RDONLY, O_WRONLY, O_RDWR*/
STATIC_CAST int __cxfs_fusep_check_access(CXFSNP_MGR *cxfsnp_mgr, const uint64_t ino,
                                const uint32_t accmode, const uint32_t op_uid, const uint32_t op_gid)
{
    CXFSNP_ITEM     *cxfsnp_item;
    CXFSNP_ATTR     *cxfsnp_attr;

    static const char *accmode_str[] = {
        /*O_RDONLY = 0*/    "O_RDONLY",
        /*O_WRONLY = 1*/    "O_WRONLY",
        /*O_RDWR   = 2*/    "O_RDWR",
    };

    ASSERT(O_ACCMODE > accmode);

    cxfsnp_item = cxfsnp_mgr_fetch_item(cxfsnp_mgr, ino);
    cxfsnp_attr = CXFSNP_ITEM_ATTR(cxfsnp_item);

    if(0 == op_uid || 0 == op_gid)
    {
        if(O_RDONLY == accmode)
        {
            CXFSNP_ITEM     *parent_cxfsnp_item;
            CXFSNP_ATTR     *parent_cxfsnp_attr;

            if(0 == (CXFSNP_ATTR_MODE(cxfsnp_attr) & (S_IRUSR | S_IRGRP | S_IROTH)))
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fusep_check_access: "
                                 "ino %lu, "
                                 "(accmode %s, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) "
                                 "=> op_uid = 0 or op_gid = 0, "
                                 "mode & (S_IRUSR | S_IRGRP | S_IROTH) == 0\n",
                                 ino, accmode_str[accmode], op_uid, op_gid,
                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                 CXFSNP_ATTR_GID(cxfsnp_attr));

                return (EC_FALSE);
            }

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fusep_check_access: "
                             "ino %lu, "
                             "(accmode %s, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) "
                             "=> op_uid = 0 or op_gid = 0, "
                             "mode & (S_IRUSR | S_IRGRP | S_IROTH) != 0 => check parent\n",
                             ino, accmode_str[accmode], op_uid, op_gid,
                             CXFSNP_ATTR_MODE(cxfsnp_attr),
                             CXFSNP_ATTR_UID(cxfsnp_attr),
                             CXFSNP_ATTR_GID(cxfsnp_attr));

            parent_cxfsnp_item = cxfsnp_mgr_fetch_parent_item(cxfsnp_mgr, ino);
            parent_cxfsnp_attr = CXFSNP_ITEM_ATTR(parent_cxfsnp_item);

            if(0 == (S_IXUSR & CXFSNP_ATTR_MODE(parent_cxfsnp_attr)))
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fusep_check_access: "
                                 "ino %lu, "
                                 "(accmode %s, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) "
                                 "=> op_uid = 0 or op_gid = 0, "
                                 "parent mode %#o & S_IXUSR == 0\n",
                                 ino, accmode_str[accmode], op_uid, op_gid,
                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                 CXFSNP_ATTR_GID(cxfsnp_attr),
                                 CXFSNP_ATTR_MODE(parent_cxfsnp_attr));

                return (EC_FALSE);
            }

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fusep_check_access: "
                             "ino %lu, "
                             "(accmode %s, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) "
                             "=> op_uid = 0 or op_gid = 0, "
                             "parent mode %#o & S_IXUSR != 0\n",
                             ino, accmode_str[accmode], op_uid, op_gid,
                             CXFSNP_ATTR_MODE(cxfsnp_attr),
                             CXFSNP_ATTR_UID(cxfsnp_attr),
                             CXFSNP_ATTR_GID(cxfsnp_attr),
                             CXFSNP_ATTR_MODE(parent_cxfsnp_attr));

            return (EC_TRUE);
        }
        else if(O_WRONLY == accmode)
        {
            if(0 == (CXFSNP_ATTR_MODE(cxfsnp_attr) & (S_IWUSR | S_IWGRP | S_IWOTH)))
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fusep_check_access: "
                                                     "ino %lu, "
                                                     "(accmode %s, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) "
                                                     "its mode %#o & (S_IWUSR | S_IWGRP S_IWOTH) == 0\n",
                                                     ino, accmode_str[accmode], op_uid, op_gid,
                                                     CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                     CXFSNP_ATTR_UID(cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(cxfsnp_attr));

                return (EC_FALSE);
            }

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fusep_check_access: "
                                                 "ino %lu, "
                                                 "(accmode %s, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) "
                                                 "its mode %#o & (S_IWUSR | S_IWGRP S_IWOTH) == 0\n",
                                                 ino, accmode_str[accmode], op_uid, op_gid,
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
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fusep_check_access: "
                                                     "ino %lu, "
                                                     "(accmode %s, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) "
                                                     "its mode & (S_IWUSR | S_IRUSR) == 0 && "
                                                     "its mode & (S_IWGRP | S_IRGRP) == 0 && "
                                                     "its mode & (S_IWOTH | S_IROTH) == 0\n",
                                                     ino, accmode_str[accmode], op_uid, op_gid,
                                                     CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                     CXFSNP_ATTR_UID(cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(cxfsnp_attr));

                return (EC_FALSE);
            }

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fusep_check_access: "
                                                 "ino %lu, "
                                                 "(accmode %s, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) "
                                                 "its mode & (S_IWUSR | S_IRUSR) != 0 || "
                                                 "its mode & (S_IWGRP | S_IRGRP) != 0 || "
                                                 "its mode & (S_IWOTH | S_IROTH) != 0\n",
                                                 ino, accmode_str[accmode], op_uid, op_gid,
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr));

            return (EC_TRUE);
        }
    }

    if(op_uid == CXFSNP_ATTR_UID(cxfsnp_attr) && op_gid == CXFSNP_ATTR_GID(cxfsnp_attr))
    {
        if(O_RDONLY == accmode)
        {
            CXFSNP_ITEM     *parent_cxfsnp_item;
            CXFSNP_ATTR     *parent_cxfsnp_attr;

            if(0 == (CXFSNP_ATTR_MODE(cxfsnp_attr) & (S_IRUSR)))
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fusep_check_access: "
                                 "ino %lu, "
                                 "(accmode %s, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) "
                                 "=> op_uid = 0 or op_gid = 0, "
                                 "mode & (S_IRUSR) == 0\n",
                                 ino, accmode_str[accmode], op_uid, op_gid,
                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                 CXFSNP_ATTR_GID(cxfsnp_attr));

                return (EC_FALSE);
            }

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fusep_check_access: "
                             "ino %lu, "
                             "(accmode %s, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) "
                             "=> op_uid = 0 or op_gid = 0, "
                             "mode & (S_IRUSR) != 0 => check parent\n",
                             ino, accmode_str[accmode], op_uid, op_gid,
                             CXFSNP_ATTR_MODE(cxfsnp_attr),
                             CXFSNP_ATTR_UID(cxfsnp_attr),
                             CXFSNP_ATTR_GID(cxfsnp_attr));

            parent_cxfsnp_item = cxfsnp_mgr_fetch_parent_item(cxfsnp_mgr, ino);
            parent_cxfsnp_attr = CXFSNP_ITEM_ATTR(parent_cxfsnp_item);

            if(0 == (S_IXUSR & CXFSNP_ATTR_MODE(parent_cxfsnp_attr)))
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fusep_check_access: "
                                 "ino %lu, "
                                 "(accmode %s, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) "
                                 "=> op_uid = 0 or op_gid = 0, "
                                 "parent mode %#o & S_IXUSR == 0\n",
                                 ino, accmode_str[accmode], op_uid, op_gid,
                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                 CXFSNP_ATTR_GID(cxfsnp_attr),
                                 CXFSNP_ATTR_MODE(parent_cxfsnp_attr));

                return (EC_FALSE);
            }

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fusep_check_access: "
                             "ino %lu, "
                             "(accmode %s, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) "
                             "=> op_uid = 0 or op_gid = 0, "
                             "parent mode %#o & S_IXUSR != 0\n",
                             ino, accmode_str[accmode], op_uid, op_gid,
                             CXFSNP_ATTR_MODE(cxfsnp_attr),
                             CXFSNP_ATTR_UID(cxfsnp_attr),
                             CXFSNP_ATTR_GID(cxfsnp_attr),
                             CXFSNP_ATTR_MODE(parent_cxfsnp_attr));

            return (EC_TRUE);
        }
        else if(O_WRONLY == accmode)
        {
            if(0 == (CXFSNP_ATTR_MODE(cxfsnp_attr) & (S_IWUSR)))
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fusep_check_access: "
                                 "ino %lu, "
                                 "(accmode %s, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) => op_uid & op_gid matched, "
                                 "mode & S_IWUSR == 0\n",
                                 ino, accmode_str[accmode], op_uid, op_gid,
                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                 CXFSNP_ATTR_GID(cxfsnp_attr));

                return (EC_FALSE);
            }

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fusep_check_access: "
                             "ino %lu, "
                             "(accmode %s, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) => op_uid & op_gid matched, "
                             "mode & S_IWUSR != 0\n",
                             ino, accmode_str[accmode], op_uid, op_gid,
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
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fusep_check_access: "
                                 "ino %lu, "
                                 "(accmode %s, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) => op_uid & op_gid matched, "
                                 "mode & S_IRUSR == 0 || mode & S_IWUSR == 0\n",
                                 ino, accmode_str[accmode], op_uid, op_gid,
                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                 CXFSNP_ATTR_GID(cxfsnp_attr));

                return (EC_FALSE);
            }

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fusep_check_access: "
                             "ino %lu, "
                             "(accmode %s, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) => op_uid & op_gid matched, "
                             "mode & S_IWUSR != 0 && mode & S_IWUSR != 0\n",
                             ino, accmode_str[accmode], op_uid, op_gid,
                             CXFSNP_ATTR_MODE(cxfsnp_attr),
                             CXFSNP_ATTR_UID(cxfsnp_attr),
                             CXFSNP_ATTR_GID(cxfsnp_attr));

            return (EC_TRUE);
        }
    }

    if(op_gid == CXFSNP_ATTR_GID(cxfsnp_attr))
    {
        if(O_RDONLY == accmode)
        {
            CXFSNP_ITEM     *parent_cxfsnp_item;
            CXFSNP_ATTR     *parent_cxfsnp_attr;

            if(0 == (CXFSNP_ATTR_MODE(cxfsnp_attr) & (S_IRGRP)))
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fusep_check_access: "
                                 "ino %lu, "
                                 "(accmode %s, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) "
                                 "=> op_uid = 0 or op_gid = 0, "
                                 "mode & (S_IRGRP) == 0\n",
                                 ino, accmode_str[accmode], op_uid, op_gid,
                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                 CXFSNP_ATTR_GID(cxfsnp_attr));

                return (EC_FALSE);
            }

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fusep_check_access: "
                             "ino %lu, "
                             "(accmode %s, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) "
                             "=> op_uid = 0 or op_gid = 0, "
                             "mode & (S_IRGRP) != 0 => check parent\n",
                             ino, accmode_str[accmode], op_uid, op_gid,
                             CXFSNP_ATTR_MODE(cxfsnp_attr),
                             CXFSNP_ATTR_UID(cxfsnp_attr),
                             CXFSNP_ATTR_GID(cxfsnp_attr));

            parent_cxfsnp_item = cxfsnp_mgr_fetch_parent_item(cxfsnp_mgr, ino);
            parent_cxfsnp_attr = CXFSNP_ITEM_ATTR(parent_cxfsnp_item);

            if(0 == (S_IXUSR & CXFSNP_ATTR_MODE(parent_cxfsnp_attr)))
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fusep_check_access: "
                                 "ino %lu, "
                                 "(accmode %s, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) "
                                 "=> op_uid = 0 or op_gid = 0, "
                                 "parent mode %#o & S_IXUSR == 0\n",
                                 ino, accmode_str[accmode], op_uid, op_gid,
                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                 CXFSNP_ATTR_GID(cxfsnp_attr),
                                 CXFSNP_ATTR_MODE(parent_cxfsnp_attr));

                return (EC_FALSE);
            }

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fusep_check_access: "
                             "ino %lu, "
                             "(accmode %s, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) "
                             "=> op_uid = 0 or op_gid = 0, "
                             "parent mode %#o & S_IXUSR != 0\n",
                             ino, accmode_str[accmode], op_uid, op_gid,
                             CXFSNP_ATTR_MODE(cxfsnp_attr),
                             CXFSNP_ATTR_UID(cxfsnp_attr),
                             CXFSNP_ATTR_GID(cxfsnp_attr),
                             CXFSNP_ATTR_MODE(parent_cxfsnp_attr));

            return (EC_TRUE);
        }
        else if(O_WRONLY == accmode)
        {
            if(0 == (CXFSNP_ATTR_MODE(cxfsnp_attr) & (S_IWGRP)))
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fusep_check_access: "
                                 "ino %lu, "
                                 "(accmode %s, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) => op_gid matched, "
                                 "mode & S_IWGRP == 0\n",
                                 ino, accmode_str[accmode], op_uid, op_gid,
                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                 CXFSNP_ATTR_GID(cxfsnp_attr));

                return (EC_FALSE);
            }

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fusep_check_access: "
                             "ino %lu, "
                             "(accmode %s, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) => op_gid matched, "
                             "mode & S_IWGRP != 0\n",
                             ino, accmode_str[accmode], op_uid, op_gid,
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
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fusep_check_access: "
                                 "ino %lu, "
                                 "(accmode %s, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) => op_gid matched, "
                                 "mode & S_IRGRP == 0 || mode & S_IWGRP == 0\n",
                                 ino, accmode_str[accmode], op_uid, op_gid,
                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                 CXFSNP_ATTR_GID(cxfsnp_attr));

                return (EC_FALSE);
            }

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fusep_check_access: "
                             "ino %lu, "
                             "(accmode %s, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) => op_gid matched, "
                             "mode & S_IWGRP != 0 && mode & S_IWGRP != 0\n",
                             ino, accmode_str[accmode], op_uid, op_gid,
                             CXFSNP_ATTR_MODE(cxfsnp_attr),
                             CXFSNP_ATTR_UID(cxfsnp_attr),
                             CXFSNP_ATTR_GID(cxfsnp_attr));

            return (EC_TRUE);
        }
    }

    /*other*/
    if(O_RDONLY == accmode)
    {
        CXFSNP_ITEM     *parent_cxfsnp_item;
        CXFSNP_ATTR     *parent_cxfsnp_attr;

        if(0 == (CXFSNP_ATTR_MODE(cxfsnp_attr) & (S_IROTH)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fusep_check_access: "
                             "ino %lu, "
                             "(accmode %s, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) "
                             "=> op_uid = 0 or op_gid = 0, "
                             "mode & (S_IROTH) == 0\n",
                             ino, accmode_str[accmode], op_uid, op_gid,
                             CXFSNP_ATTR_MODE(cxfsnp_attr),
                             CXFSNP_ATTR_UID(cxfsnp_attr),
                             CXFSNP_ATTR_GID(cxfsnp_attr));

            return (EC_FALSE);
        }

        dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fusep_check_access: "
                         "ino %lu, "
                         "(accmode %s, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) "
                         "=> op_uid = 0 or op_gid = 0, "
                         "mode & (S_IROTH) != 0 => check parent\n",
                         ino, accmode_str[accmode], op_uid, op_gid,
                         CXFSNP_ATTR_MODE(cxfsnp_attr),
                         CXFSNP_ATTR_UID(cxfsnp_attr),
                         CXFSNP_ATTR_GID(cxfsnp_attr));

        parent_cxfsnp_item = cxfsnp_mgr_fetch_parent_item(cxfsnp_mgr, ino);
        parent_cxfsnp_attr = CXFSNP_ITEM_ATTR(parent_cxfsnp_item);

        if(0 == (S_IXUSR & CXFSNP_ATTR_MODE(parent_cxfsnp_attr)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fusep_check_access: "
                             "ino %lu, "
                             "(accmode %s, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) "
                             "=> op_uid = 0 or op_gid = 0, "
                             "parent mode %#o & S_IXUSR == 0\n",
                             ino, accmode_str[accmode], op_uid, op_gid,
                             CXFSNP_ATTR_MODE(cxfsnp_attr),
                             CXFSNP_ATTR_UID(cxfsnp_attr),
                             CXFSNP_ATTR_GID(cxfsnp_attr),
                             CXFSNP_ATTR_MODE(parent_cxfsnp_attr));

            return (EC_FALSE);
        }

        dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fusep_check_access: "
                         "ino %lu, "
                         "(accmode %s, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) "
                         "=> op_uid = 0 or op_gid = 0, "
                         "parent mode %#o & S_IXUSR != 0\n",
                         ino, accmode_str[accmode], op_uid, op_gid,
                         CXFSNP_ATTR_MODE(cxfsnp_attr),
                         CXFSNP_ATTR_UID(cxfsnp_attr),
                         CXFSNP_ATTR_GID(cxfsnp_attr),
                         CXFSNP_ATTR_MODE(parent_cxfsnp_attr));

        return (EC_TRUE);
    }
    else if(O_WRONLY == accmode)
    {
        if(0 == (CXFSNP_ATTR_MODE(cxfsnp_attr) & (S_IWOTH)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fusep_check_access: "
                             "ino %lu, "
                             "(accmode %s, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) => other, "
                             "mode & S_IWOTH == 0\n",
                             ino, accmode_str[accmode], op_uid, op_gid,
                             CXFSNP_ATTR_MODE(cxfsnp_attr),
                             CXFSNP_ATTR_UID(cxfsnp_attr),
                             CXFSNP_ATTR_GID(cxfsnp_attr));

            return (EC_FALSE);
        }

        dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fusep_check_access: "
                         "ino %lu, "
                         "(accmode %s, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) => other, "
                         "mode & S_IWOTH != 0\n",
                         ino, accmode_str[accmode], op_uid, op_gid,
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
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fusep_check_access: "
                             "ino %lu, "
                             "(accmode %s, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) => other, "
                             "mode & S_IROTH == 0 || mode & S_IWOTH == 0\n",
                             ino, accmode_str[accmode], op_uid, op_gid,
                             CXFSNP_ATTR_MODE(cxfsnp_attr),
                             CXFSNP_ATTR_UID(cxfsnp_attr),
                             CXFSNP_ATTR_GID(cxfsnp_attr));

            return (EC_FALSE);
        }

        dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_fusep_check_access: "
                         "ino %lu, "
                         "(accmode %s, uid %u, gid %u) vs its (mode %#o, uid %u, gid %u) => other, "
                         "mode & S_IROTH != 0 && mode & S_IWOTH != 0\n",
                         ino, accmode_str[accmode], op_uid, op_gid,
                         CXFSNP_ATTR_MODE(cxfsnp_attr),
                         CXFSNP_ATTR_UID(cxfsnp_attr),
                         CXFSNP_ATTR_GID(cxfsnp_attr));

        return (EC_TRUE);
    }
    /*should never reach here*/
    return (EC_FALSE);
}

int cxfs_fusep_mknod(CXFSNP_MGR *cxfsnp_mgr, const uint64_t parent_ino, const uint16_t mode, const uint32_t op_uid, const uint32_t op_gid)
{
    if(0 != op_uid && 0 != op_gid) /*not root*/
    {
        CXFSNP_ITEM     *parent_cxfsnp_item;
        CXFSNP_ATTR     *parent_cxfsnp_attr;

        parent_cxfsnp_item = cxfsnp_mgr_fetch_item(cxfsnp_mgr, parent_ino);
        if(NULL_PTR == parent_cxfsnp_item)
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fusep_mknod: "
                                                 "lookup parent %lu failed\n",
                                                 parent_ino);
            return -ENOENT;
        }
        parent_cxfsnp_attr = CXFSNP_ITEM_ATTR(parent_cxfsnp_item);

        if(CXFS_FUSEP_UID_ERR == op_uid)
        {
            if(CXFSNP_ATTR_UID(parent_cxfsnp_attr) != op_uid)
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_mknod: "
                                                     "parent %lu (uid %u, gid %u, mode %#o), "
                                                     "uid not matched "
                                                     "=> deny (uid %u, gid %u, mode %#o)\n",
                                                     parent_ino,
                                                     CXFSNP_ATTR_UID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(parent_cxfsnp_attr),
                                                     op_uid, op_gid, mode);
                return -EACCES;
            }
        }
        else
        {
            if(CXFSNP_ATTR_UID(parent_cxfsnp_attr) == op_uid
            && 0 == (S_IWUSR & CXFSNP_ATTR_MODE(parent_cxfsnp_attr)))
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_mknod: "
                                                     "parent ino %lu (uid %u, gid %u, mode %#o), "
                                                     "parent mode & (S_IWUSR) == 0 "
                                                     "=> deny (uid %u, gid %u, mode %#o)\n",
                                                     parent_ino,
                                                     CXFSNP_ATTR_UID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(parent_cxfsnp_attr),
                                                     op_uid, op_gid, mode);
                return -EACCES;
            }

            if(CXFSNP_ATTR_UID(parent_cxfsnp_attr) != op_uid
            && 0 == (S_IXOTH & CXFSNP_ATTR_MODE(parent_cxfsnp_attr)))
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_mknod: "
                                                     "parent ino %lu (uid %u, gid %u, mode %#o), "
                                                     "parent mode & (S_IXOTH) == 0 "
                                                     "=> deny (uid %u, gid %u, mode %#o)\n",
                                                     parent_ino,
                                                     CXFSNP_ATTR_UID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(parent_cxfsnp_attr),
                                                     op_uid, op_gid, mode);

                return -EACCES;
            }
        }

        if(CXFS_FUSEP_GID_ERR == op_gid)
        {
            if(CXFSNP_ATTR_GID(parent_cxfsnp_attr) != op_gid)
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fusep_mknod: "
                                                     "parent ino %lu (uid %u, gid %u, mode %#o), "
                                                     "op gid overflow "
                                                     "=> deny (uid %u, gid %u, mode %#o)\n",
                                                     parent_ino,
                                                     CXFSNP_ATTR_UID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(parent_cxfsnp_attr),
                                                     op_uid, op_gid, mode);
                return -EOVERFLOW;
            }
        }
        else
        {
            if(0 == (S_IXGRP & CXFSNP_ATTR_MODE(parent_cxfsnp_attr)))
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_mknod: "
                                                     "parent ino %lu (uid %u, gid %u, mode %#o), "
                                                     "parent mode & (S_IXGRP) == 0 "
                                                     "=> deny (uid %u, gid %u, mode %#o)\n",
                                                     parent_ino,
                                                     CXFSNP_ATTR_UID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(parent_cxfsnp_attr),
                                                     op_uid, op_gid, mode);

                return -EACCES;
            }
        }
    }

    dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_mknod: "
                                         "parent ino %lu, "
                                         "=> accep (uid %u, gid %u, mode %#o)\n",
                                         parent_ino,
                                         op_uid, op_gid, mode);

    return 0;
}

int cxfs_fusep_mkdir(CXFSNP_MGR *cxfsnp_mgr, const uint64_t parent_ino, const uint16_t mode, const uint32_t op_uid, const uint32_t op_gid)
{
    if(0 != op_uid && 0 != op_gid) /*not root*/
    {
        CXFSNP_ITEM     *parent_cxfsnp_item;
        CXFSNP_ATTR     *parent_cxfsnp_attr;

        parent_cxfsnp_item = cxfsnp_mgr_fetch_item(cxfsnp_mgr, parent_ino);
        if(NULL_PTR == parent_cxfsnp_item)
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fusep_mkdir: "
                                                 "lookup parent %lu failed\n",
                                                 parent_ino);
            return -ENOENT;
        }
        parent_cxfsnp_attr = CXFSNP_ITEM_ATTR(parent_cxfsnp_item);

        if(CXFS_FUSEP_UID_ERR == op_uid)
        {
            if(CXFSNP_ATTR_UID(parent_cxfsnp_attr) != op_uid)
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_mkdir: "
                                                     "parent %lu (uid %u, gid %u, mode %#o), "
                                                     "uid not matched "
                                                     "=> deny (uid %u, gid %u)\n",
                                                     parent_ino,
                                                     CXFSNP_ATTR_UID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(parent_cxfsnp_attr),
                                                     op_uid, op_gid, mode);

                return -EACCES;
            }
        }
        else
        {
            if(CXFSNP_ATTR_UID(parent_cxfsnp_attr) == op_uid
            && 0 == (S_IWUSR & CXFSNP_ATTR_MODE(parent_cxfsnp_attr)))
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fusep_mkdir: "
                                                     "parent %lu (uid %u, gid %u, mode %#o), "
                                                     "parent mode & (S_IWUSR) == 0 "
                                                     "=> deny (uid %u, gid %u, mode %#o)\n",
                                                     parent_ino,
                                                     CXFSNP_ATTR_UID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(parent_cxfsnp_attr),
                                                     op_uid, op_gid, mode);
                return -EACCES;
            }

            if(CXFSNP_ATTR_UID(parent_cxfsnp_attr) != op_uid
            && 0 == (S_IXOTH & CXFSNP_ATTR_MODE(parent_cxfsnp_attr)))
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_mkdir: "
                                                     "parent %lu (uid %u, gid %u, mode %#o), "
                                                     "parent mode & (S_IXOTH) == 0 "
                                                     "=> deny (uid %u, gid %u, mode %#o)\n",
                                                     parent_ino,
                                                     CXFSNP_ATTR_UID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(parent_cxfsnp_attr),
                                                     op_uid, op_gid, mode);

                return -EACCES;
            }
        }

        if(CXFS_FUSEP_GID_ERR == op_gid)
        {
            if(CXFSNP_ATTR_GID(parent_cxfsnp_attr) != op_gid)
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fusep_mkdir: "
                                                     "parent %lu (uid %u, gid %u, mode %#o), "
                                                     "op gid overflow "
                                                     "=> deny (uid %u, gid %u, mode %#o)\n",
                                                     parent_ino,
                                                     CXFSNP_ATTR_UID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(parent_cxfsnp_attr),
                                                     op_uid, op_gid, mode);
                return -EOVERFLOW;
            }
        }
        else
        {
            if(0 == (S_IXGRP & CXFSNP_ATTR_MODE(parent_cxfsnp_attr)))
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_mkdir: "
                                                     "parent %lu (uid %u, gid %u, mode %#o), "
                                                     "parent mode & (S_IXGRP) == 0 "
                                                     "=> deny (uid %u, gid %u, mode %#o)\n",
                                                     parent_ino,
                                                     CXFSNP_ATTR_UID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(parent_cxfsnp_attr),
                                                     op_uid, op_gid, mode);

                return -EACCES;
            }
        }
    }

    dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_mkdir: "
                                         "parent ino %lu, "
                                         "=> accept (uid %u, gid %u, mode %#o)\n",
                                         parent_ino,
                                         op_uid, op_gid, mode);

    return 0;
}

int cxfs_fusep_unlink(CXFSNP_MGR *cxfsnp_mgr, const uint64_t ino, const uint32_t op_uid, const uint32_t op_gid)
{
    CXFSNP_ITEM     *cxfsnp_item;
    CXFSNP_ATTR     *cxfsnp_attr;

    cxfsnp_item = cxfsnp_mgr_fetch_item(cxfsnp_mgr, ino);
    if(NULL_PTR == cxfsnp_item)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fusep_unlink: "
                                             "ino %lu fetch item failed\n",
                                             ino);
        return -ENOENT;
    }
    cxfsnp_attr = CXFSNP_ITEM_ATTR(cxfsnp_item);

    if(0 == op_uid && 0 == op_gid)
    {
        return 0;
    }

    if(0 != op_uid && 0 == op_gid)
    {
        if(CXFSNP_ATTR_UID(cxfsnp_attr) != op_uid)
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_unlink: "
                                                 "its %lu (uid %u, gid %u, mode %#o), "
                                                 "uid not matched "
                                                 "=> deny (uid %u, gid %u)\n",
                                                 ino,
                                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                 op_uid, op_gid);
            return -EACCES;
        }
    }

    if(0 != op_uid && 0 != op_gid /*not root*/
    && (CXFSNP_ATTR_UID(cxfsnp_attr) == op_uid
       && CXFSNP_ATTR_GID(cxfsnp_attr) == op_gid))
    {
        uint64_t         parent_ino;
        CXFSNP_ITEM     *parent_cxfsnp_item;
        CXFSNP_ATTR     *parent_cxfsnp_attr;

        parent_ino = CXFSNP_ATTR_INO_MAKE(CXFSNP_ATTR_INO_FETCH_NP_ID(ino),
                                          CXFSNP_ITEM_PARENT_POS(cxfsnp_item));

        parent_cxfsnp_item = cxfsnp_mgr_fetch_item(cxfsnp_mgr, parent_ino);
        if(NULL_PTR == parent_cxfsnp_item)
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fusep_unlink: "
                                                 "fetch parent of %lu failed\n",
                                                 ino);
            return -ENOENT;
        }
        parent_cxfsnp_attr = CXFSNP_ITEM_ATTR(parent_cxfsnp_item);

        if(CXFSNP_ATTR_UID(parent_cxfsnp_attr) != op_uid
        && 0 == (S_IXOTH & CXFSNP_ATTR_MODE(parent_cxfsnp_attr)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_unlink: "
                                                 "its %lu (uid %u, gid %u, mode %#o), "
                                                 "parent %lu (uid %u, gid %u, mode %#o), "
                                                 "parent mode & (S_IXOTH) == 0"
                                                 "=> deny (uid %u, gid %u)\n",
                                                 ino,
                                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                 parent_ino,
                                                 CXFSNP_ATTR_UID(parent_cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(parent_cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(parent_cxfsnp_attr),
                                                 op_uid, op_gid);

            return -EACCES;
        }

        if(CXFSNP_ATTR_UID(parent_cxfsnp_attr) == op_uid
        && 0 == (S_IWUSR & CXFSNP_ATTR_MODE(parent_cxfsnp_attr)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_unlink: "
                                                 "its %lu (uid %u, gid %u, mode %#o), "
                                                 "parent %lu (uid %u, gid %u, mode %#o), "
                                                 "parent mode & (S_IWUSR) == 0"
                                                 "=> deny (uid %u, gid %u)\n",
                                                 ino,
                                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                 parent_ino,
                                                 CXFSNP_ATTR_UID(parent_cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(parent_cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(parent_cxfsnp_attr),
                                                 op_uid, op_gid);

            return -EACCES;
        }

        if(CXFSNP_ATTR_UID(parent_cxfsnp_attr) == op_uid
        && 0 == (S_IXUSR & CXFSNP_ATTR_MODE(parent_cxfsnp_attr)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_unlink: "
                                                 "its %lu (uid %u, gid %u, mode %#o), "
                                                 "parent %lu (uid %u, gid %u, mode %#o), "
                                                 "parent mode & (S_IXUSR) == 0"
                                                 "=> deny (uid %u, gid %u)\n",
                                                 ino,
                                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                 parent_ino,
                                                 CXFSNP_ATTR_UID(parent_cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(parent_cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(parent_cxfsnp_attr),
                                                 op_uid, op_gid);

            return -EACCES;
        }
    }

    if(0 != op_uid && 0 != op_gid /*not root*/
    && (CXFSNP_ATTR_UID(cxfsnp_attr) != op_uid
       || CXFSNP_ATTR_GID(cxfsnp_attr) != op_gid))
    {
        uint64_t         parent_ino;
        CXFSNP_ITEM     *parent_cxfsnp_item;
        CXFSNP_ATTR     *parent_cxfsnp_attr;

        parent_ino = CXFSNP_ATTR_INO_MAKE(CXFSNP_ATTR_INO_FETCH_NP_ID(ino),
                                          CXFSNP_ITEM_PARENT_POS(cxfsnp_item));

        parent_cxfsnp_item = cxfsnp_mgr_fetch_item(cxfsnp_mgr, parent_ino);
        if(NULL_PTR == parent_cxfsnp_item)
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fusep_unlink: "
                                                 "fetch parent of %lu failed\n",
                                                 ino);
            return -ENOENT;
        }
        parent_cxfsnp_attr = CXFSNP_ITEM_ATTR(parent_cxfsnp_item);

        if(CXFS_FUSEP_UID_ERR == op_uid)
        {
            if(CXFSNP_ATTR_UID(parent_cxfsnp_attr) != op_uid)
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_unlink: "
                                                     "its %lu (uid %u, gid %u, mode %#o), "
                                                     "parent %lu (uid %u, gid %u, mode %#o), "
                                                     "uid not matched "
                                                     "=> deny (uid %u, gid %u)\n",
                                                     ino,
                                                     CXFSNP_ATTR_UID(cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                     parent_ino,
                                                     CXFSNP_ATTR_UID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(parent_cxfsnp_attr),
                                                     op_uid, op_gid);
                return -EACCES;
            }
        }
        else
        {
            if(CXFSNP_ATTR_UID(parent_cxfsnp_attr) != op_uid)
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_unlink: "
                                                     "its %lu (uid %u, gid %u, mode %#o), "
                                                     "parent %lu (uid %u, gid %u, mode %#o), "
                                                     "uid not matched "
                                                     "=> deny (uid %u, gid %u)\n",
                                                     ino,
                                                     CXFSNP_ATTR_UID(cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                     parent_ino,
                                                     CXFSNP_ATTR_UID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(parent_cxfsnp_attr),
                                                     op_uid, op_gid);
                return -EACCES;
            }

            if(CXFSNP_ATTR_UID(parent_cxfsnp_attr) == op_uid
            && 0 == (S_IWUSR & CXFSNP_ATTR_MODE(parent_cxfsnp_attr)))
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_unlink: "
                                                     "its %lu (uid %u, gid %u, mode %#o), "
                                                     "parent %lu (uid %u, gid %u, mode %#o), "
                                                     "parent mode & (S_IWUSR) == 0 "
                                                     "=> deny (uid %u, gid %u)\n",
                                                     ino,
                                                     CXFSNP_ATTR_UID(cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                     parent_ino,
                                                     CXFSNP_ATTR_UID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(parent_cxfsnp_attr),
                                                     op_uid, op_gid);
                return -EACCES;
            }

            if(CXFSNP_ATTR_UID(parent_cxfsnp_attr) != op_uid
            && 0 == (S_IXOTH & CXFSNP_ATTR_MODE(parent_cxfsnp_attr)))
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_unlink: "
                                                     "its %lu (uid %u, gid %u, mode %#o), "
                                                     "parent %lu (uid %u, gid %u, mode %#o), "
                                                     "parent mode & (S_IXOTH) == 0 "
                                                     "=> deny (uid %u, gid %u)\n",
                                                     ino,
                                                     CXFSNP_ATTR_UID(cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                     parent_ino,
                                                     CXFSNP_ATTR_UID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(parent_cxfsnp_attr),
                                                     op_uid, op_gid);
                return -EACCES;
            }
        }

        if(CXFS_FUSEP_GID_ERR == op_gid)
        {
            if(CXFSNP_ATTR_GID(parent_cxfsnp_attr) != op_gid)
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_unlink: "
                                                     "its %lu (uid %u, gid %u, mode %#o), "
                                                     "parent %lu (uid %u, gid %u, mode %#o), "
                                                     "gid overflow "
                                                     "=> deny (uid %u, gid %u)\n",
                                                     ino,
                                                     CXFSNP_ATTR_UID(cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                     parent_ino,
                                                     CXFSNP_ATTR_UID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(parent_cxfsnp_attr),
                                                     op_uid, op_gid);
                return -EOVERFLOW;
            }
        }
        else
        {
            if(0 == (S_IXGRP & CXFSNP_ATTR_MODE(parent_cxfsnp_attr)))
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_unlink: "
                                                     "its %lu (uid %u, gid %u, mode %#o), "
                                                     "parent %lu (uid %u, gid %u, mode %#o), "
                                                     "parent mode & (S_IXGRP) == 0 "
                                                     "=> deny (uid %u, gid %u)\n",
                                                     ino,
                                                     CXFSNP_ATTR_UID(cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                     parent_ino,
                                                     CXFSNP_ATTR_UID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(parent_cxfsnp_attr),
                                                     op_uid, op_gid);

                return -EACCES;
            }
        }
    }

    dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_unlink: "
                                         "ino %lu, "
                                         "=> accept (uid %u, gid %u)\n",
                                         ino,
                                         op_uid, op_gid);

    return 0;
}

int cxfs_fusep_rmdir(CXFSNP_MGR *cxfsnp_mgr, const uint64_t ino, const uint32_t op_uid, const uint32_t op_gid)
{
    CXFSNP_ITEM     *cxfsnp_item;
    CXFSNP_ATTR     *cxfsnp_attr;

    cxfsnp_item = cxfsnp_mgr_fetch_item(cxfsnp_mgr, ino);
    if(NULL_PTR == cxfsnp_item)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fusep_rmdir: "
                                             "ino %lu fetch item failed\n",
                                             ino);
        return -ENOENT;
    }
    cxfsnp_attr = CXFSNP_ITEM_ATTR(cxfsnp_item);

    if(CXFSNP_ATTR_FILE_IS_DIR != CXFSNP_ATTR_DIR_FLAG(cxfsnp_attr))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fusep_rmdir: "
                                             "ino %lu, flag %#x, "
                                             "not fuse dir => failed\n",
                                             ino,
                                             CXFSNP_ATTR_DIR_FLAG(cxfsnp_attr));
        return -ENOENT;
    }


    if(0 != op_uid && 0 != op_gid /*not root*/
    && (CXFSNP_ATTR_UID(cxfsnp_attr) == op_uid
       && CXFSNP_ATTR_GID(cxfsnp_attr) == op_gid))
    {
        uint64_t         parent_ino;
        CXFSNP_ITEM     *parent_cxfsnp_item;
        CXFSNP_ATTR     *parent_cxfsnp_attr;

        parent_ino = CXFSNP_ATTR_INO_MAKE(CXFSNP_ATTR_INO_FETCH_NP_ID(ino),
                                          CXFSNP_ITEM_PARENT_POS(cxfsnp_item));

        parent_cxfsnp_item = cxfsnp_mgr_fetch_item(cxfsnp_mgr, parent_ino);
        if(NULL_PTR == parent_cxfsnp_item)
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fusep_rmdir: "
                                                 "fetch parent of %lu failed\n",
                                                 ino);
            return -ENOENT;
        }
        parent_cxfsnp_attr = CXFSNP_ITEM_ATTR(parent_cxfsnp_item);


        if(CXFSNP_ATTR_UID(parent_cxfsnp_attr) != op_uid
        && 0 == (S_IXOTH & CXFSNP_ATTR_MODE(parent_cxfsnp_attr)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_rmdir: "
                                                 "its %lu (uid %u, gid %u, mode %#o), "
                                                 "parent %lu (uid %u, gid %u, mode %#o), "
                                                 "parent mode & (S_IXOTH) == 0 "
                                                 "=> deny (uid %u, gid %u)\n",
                                                 ino,
                                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                 parent_ino,
                                                 CXFSNP_ATTR_UID(parent_cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(parent_cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(parent_cxfsnp_attr),
                                                 op_uid, op_gid);

            return -EACCES;
        }

        if(CXFSNP_ATTR_UID(parent_cxfsnp_attr) == op_uid
        && 0 == (S_IWUSR & CXFSNP_ATTR_MODE(parent_cxfsnp_attr)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_rmdir: "
                                                 "its %lu (uid %u, gid %u, mode %#o), "
                                                 "parent %lu (uid %u, gid %u, mode %#o), "
                                                 "parent mode & (S_IWUSR) == 0 "
                                                 "=> deny (uid %u, gid %u)\n",
                                                 ino,
                                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                 parent_ino,
                                                 CXFSNP_ATTR_UID(parent_cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(parent_cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(parent_cxfsnp_attr),
                                                 op_uid, op_gid);

            return -EACCES;
        }

        if(CXFSNP_ATTR_UID(parent_cxfsnp_attr) == op_uid
        && 0 == (S_IXUSR & CXFSNP_ATTR_MODE(parent_cxfsnp_attr)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_rmdir: "
                                                 "its %lu (uid %u, gid %u, mode %#o), "
                                                 "parent %lu (uid %u, gid %u, mode %#o), "
                                                 "parent mode & (S_IXUSR) == 0 "
                                                 "=> deny (uid %u, gid %u)\n",
                                                 ino,
                                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                 parent_ino,
                                                 CXFSNP_ATTR_UID(parent_cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(parent_cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(parent_cxfsnp_attr),
                                                 op_uid, op_gid);

            return -EACCES;
        }
    }

    if(0 != op_uid && 0 != op_gid /*not root*/
    && (CXFSNP_ATTR_UID(cxfsnp_attr) != op_uid
       || CXFSNP_ATTR_GID(cxfsnp_attr) != op_gid))
    {
        uint64_t         parent_ino;
        CXFSNP_ITEM     *parent_cxfsnp_item;
        CXFSNP_ATTR     *parent_cxfsnp_attr;

        parent_ino = CXFSNP_ATTR_INO_MAKE(CXFSNP_ATTR_INO_FETCH_NP_ID(ino),
                                          CXFSNP_ITEM_PARENT_POS(cxfsnp_item));

        parent_cxfsnp_item = cxfsnp_mgr_fetch_item(cxfsnp_mgr, parent_ino);
        if(NULL_PTR == parent_cxfsnp_item)
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fusep_rmdir: "
                                                 "fetch parent of %lu failed\n",
                                                 ino);
            return -ENOENT;
        }
        parent_cxfsnp_attr = CXFSNP_ITEM_ATTR(parent_cxfsnp_item);

        if(CXFS_FUSEP_UID_ERR == op_uid)
        {
            if(CXFSNP_ATTR_UID(parent_cxfsnp_attr) != op_uid)
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_rmdir: "
                                                     "its %lu (uid %u, gid %u, mode %#o), "
                                                     "parent %lu (uid %u, gid %u, mode %#o), "
                                                     "parent uid not matched "
                                                     "=> deny (uid %u, gid %u)\n",
                                                     ino,
                                                     CXFSNP_ATTR_UID(cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                     parent_ino,
                                                     CXFSNP_ATTR_UID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(parent_cxfsnp_attr),
                                                     op_uid, op_gid);
                return -EACCES;
            }
        }
        else
        {
            if(CXFSNP_ATTR_UID(parent_cxfsnp_attr) != op_uid)
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_rmdir: "
                                                     "its %lu (uid %u, gid %u, mode %#o), "
                                                     "parent %lu (uid %u, gid %u, mode %#o), "
                                                     "parent uid not matched "
                                                     "=> deny (uid %u, gid %u)\n",
                                                     ino,
                                                     CXFSNP_ATTR_UID(cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                     parent_ino,
                                                     CXFSNP_ATTR_UID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(parent_cxfsnp_attr),
                                                     op_uid, op_gid);
                return -EACCES;
            }

            if(CXFSNP_ATTR_UID(parent_cxfsnp_attr) == op_uid
            && 0 == (S_IWUSR & CXFSNP_ATTR_MODE(parent_cxfsnp_attr)))
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_rmdir: "
                                                     "its %lu (uid %u, gid %u, mode %#o), "
                                                     "parent %lu (uid %u, gid %u, mode %#o), "
                                                     "parent mode & (S_IWUSR) == 0 "
                                                     "=> deny (uid %u, gid %u)\n",
                                                     ino,
                                                     CXFSNP_ATTR_UID(cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                     parent_ino,
                                                     CXFSNP_ATTR_UID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(parent_cxfsnp_attr),
                                                     op_uid, op_gid);
                return -EACCES;
            }

            if(CXFSNP_ATTR_UID(parent_cxfsnp_attr) != op_uid
            && 0 == (S_IXOTH & CXFSNP_ATTR_MODE(parent_cxfsnp_attr)))
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_rmdir: "
                                                     "its %lu (uid %u, gid %u, mode %#o), "
                                                     "parent %lu (uid %u, gid %u, mode %#o), "
                                                     "parent mode & (S_IXOTH) == 0 "
                                                     "=> deny (uid %u, gid %u)\n",
                                                     ino,
                                                     CXFSNP_ATTR_UID(cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                     parent_ino,
                                                     CXFSNP_ATTR_UID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(parent_cxfsnp_attr),
                                                     op_uid, op_gid);

                return -EACCES;
            }
        }

        if(CXFS_FUSEP_GID_ERR == op_gid)
        {
            if(CXFSNP_ATTR_GID(parent_cxfsnp_attr) != op_gid)
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_rmdir: "
                                                     "its %lu (uid %u, gid %u, mode %#o), "
                                                     "parent %lu (uid %u, gid %u, mode %#o), "
                                                     "gid overflow "
                                                     "=> deny (uid %u, gid %u)\n",
                                                     ino,
                                                     CXFSNP_ATTR_UID(cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                     parent_ino,
                                                     CXFSNP_ATTR_UID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(parent_cxfsnp_attr),
                                                     op_uid, op_gid);
                return -EOVERFLOW;
            }
        }
        else
        {
            if(0 == (S_IXGRP & CXFSNP_ATTR_MODE(parent_cxfsnp_attr)))
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_rmdir: "
                                                     "its %lu (uid %u, gid %u, mode %#o), "
                                                     "parent %lu (uid %u, gid %u, mode %#o), "
                                                     "parent mode & (S_IXGRP) == 0 "
                                                     "=> deny (uid %u, gid %u)\n",
                                                     ino,
                                                     CXFSNP_ATTR_UID(cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                     parent_ino,
                                                     CXFSNP_ATTR_UID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(parent_cxfsnp_attr),
                                                     op_uid, op_gid);

                return -EACCES;
            }
        }
    }

    dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_rmdir: "
                                         "ino %lu, "
                                         "=> accept (uid %u, gid %u)\n",
                                         ino,
                                         op_uid, op_gid);

    return 0;
}


int cxfs_fusep_symlink(CXFSNP_MGR *cxfsnp_mgr, const uint64_t src_ino, const uint64_t des_parent_ino, const uint32_t op_uid, const uint32_t op_gid)
{
    CXFSNP_ITEM     *src_cxfsnp_item;
    CXFSNP_ATTR     *src_cxfsnp_attr;

    src_cxfsnp_item = cxfsnp_mgr_fetch_item(cxfsnp_mgr, src_ino);
    if(NULL_PTR == src_cxfsnp_item)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fusep_symlink: "
                                             "src %lu fetch item failed\n",
                                             src_ino);
        return -ENOENT;
    }
    src_cxfsnp_attr = CXFSNP_ITEM_ATTR(src_cxfsnp_item);

    /*check permission*/
    if(0 != op_uid && 0 != op_gid)
    {
        CXFSNP_ITEM     *des_parent_cxfsnp_item;
        CXFSNP_ATTR     *des_parent_cxfsnp_attr;

        des_parent_cxfsnp_item = cxfsnp_mgr_fetch_item(cxfsnp_mgr, des_parent_ino);
        if(NULL_PTR == des_parent_cxfsnp_item)
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fusep_symlink: "
                                                 "lookup des parent '%lu' failed\n",
                                                 des_parent_ino);
            return -ENOENT;
        }
        des_parent_cxfsnp_attr = CXFSNP_ITEM_ATTR(des_parent_cxfsnp_item);

        if(CXFSNP_ATTR_UID(des_parent_cxfsnp_attr) != op_uid
        && 0 == (S_IXOTH & CXFSNP_ATTR_MODE(des_parent_cxfsnp_attr)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_symlink: "
                                                 "src %lu (uid %u, gid %u, mode %#o), "
                                                 "no des, "
                                                 "des parent %lu (uid %u, gid %u, mode %#o), "
                                                 "des parent mode & (S_IXOTH) == 0"
                                                 "=> deny (uid %u, gid %u)\n",
                                                 src_ino,
                                                 CXFSNP_ATTR_UID(src_cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(src_cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(src_cxfsnp_attr),
                                                 des_parent_ino,
                                                 CXFSNP_ATTR_UID(des_parent_cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(des_parent_cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(des_parent_cxfsnp_attr),
                                                 op_uid, op_gid);

            return -EACCES;
        }

        if(CXFSNP_ATTR_UID(des_parent_cxfsnp_attr) == op_uid
        && 0 == (S_IWUSR & CXFSNP_ATTR_MODE(des_parent_cxfsnp_attr)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_symlink: "
                                                 "src %lu (uid %u, gid %u, mode %#o), "
                                                 "no des, "
                                                 "des parent %lu (uid %u, gid %u, mode %#o), "
                                                 "des parent mode & (S_IWUSR) == 0"
                                                 "=> deny (uid %u, gid %u)\n",
                                                 src_ino,
                                                 CXFSNP_ATTR_UID(src_cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(src_cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(src_cxfsnp_attr),
                                                 des_parent_ino,
                                                 CXFSNP_ATTR_UID(des_parent_cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(des_parent_cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(des_parent_cxfsnp_attr),
                                                 op_uid, op_gid);

            return -EACCES;
        }

        if(CXFSNP_ATTR_UID(des_parent_cxfsnp_attr) == op_uid
        && 0 == (S_IXUSR & CXFSNP_ATTR_MODE(des_parent_cxfsnp_attr)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_symlink: "
                                                 "src %lu (uid %u, gid %u, mode %#o), "
                                                 "no des, "
                                                 "des parent %lu (uid %u, gid %u, mode %#o), "
                                                 "des parent mode & (S_IXUSR) == 0"
                                                 "=> deny (uid %u, gid %u)\n",
                                                 src_ino,
                                                 CXFSNP_ATTR_UID(src_cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(src_cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(src_cxfsnp_attr),
                                                 des_parent_ino,
                                                 CXFSNP_ATTR_UID(des_parent_cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(des_parent_cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(des_parent_cxfsnp_attr),
                                                 op_uid, op_gid);

            return -EACCES;
        }
    }

    dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_symlink: "
                                         "src %lu (uid %u, gid %u, mode %#o), "
                                         "des parent %lu "
                                         "=> accept (uid %u, gid %u)\n",
                                         src_ino,
                                         CXFSNP_ATTR_UID(src_cxfsnp_attr),
                                         CXFSNP_ATTR_GID(src_cxfsnp_attr),
                                         CXFSNP_ATTR_MODE(src_cxfsnp_attr),
                                         des_parent_ino,
                                         op_uid, op_gid);

    return 0;
}

int cxfs_fusep_rename(CXFSNP_MGR *cxfsnp_mgr, const uint64_t src_ino, const uint64_t des_ino, const uint64_t des_parent_ino, const uint32_t op_uid, const uint32_t op_gid)
{
    CXFSNP_ITEM     *src_cxfsnp_item;
    CXFSNP_ATTR     *src_cxfsnp_attr;

    CXFSNP_ITEM     *des_parent_cxfsnp_item;
    CXFSNP_ATTR     *des_parent_cxfsnp_attr;

    CXFSNP_ITEM     *des_cxfsnp_item;
    CXFSNP_ATTR     *des_cxfsnp_attr;

    CXFSNP          *cxfsnp;

    src_cxfsnp_item = cxfsnp_mgr_fetch_item(cxfsnp_mgr, src_ino);
    if(NULL_PTR == src_cxfsnp_item)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fusep_rename: "
                                             "src %lu fetch item failed\n",
                                             src_ino);
        return -ENOENT;
    }
    src_cxfsnp_attr = CXFSNP_ITEM_ATTR(src_cxfsnp_item);

    des_parent_cxfsnp_item = cxfsnp_mgr_fetch_item(cxfsnp_mgr, des_parent_ino);
    if(NULL_PTR == des_parent_cxfsnp_item)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fusep_rename: "
                                             "des parent %lu fetch item failed\n",
                                             des_parent_ino);
        return -ENOENT;
    }
    des_parent_cxfsnp_attr = CXFSNP_ITEM_ATTR(des_parent_cxfsnp_item);

    cxfsnp = cxfsnp_mgr_fetch_np(cxfsnp_mgr, src_ino);
    if(NULL_PTR == cxfsnp)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fusep_rename: "
                                             "src %lu fetch np failed\n",
                                             src_ino);

        return -EACCES;
    }

    des_cxfsnp_item = cxfsnp_mgr_fetch_item(cxfsnp_mgr, des_ino);
    while(NULL_PTR != des_cxfsnp_item)
    {
        des_cxfsnp_attr = CXFSNP_ITEM_ATTR(des_cxfsnp_item);

        /*hard link*/
        if(CXFSNP_ATTR_LINK_HARD_MASK & CXFSNP_ATTR_LINK_FLAG(des_cxfsnp_attr)) /*hard link*/
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_rename: "
                                                 "src %lu (uid %u, gid %u, mode %#o)\n",
                                                 src_ino,
                                                 CXFSNP_ATTR_UID(src_cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(src_cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(src_cxfsnp_attr));

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_rename: "
                                                 "des %lu (uid %u, gid %u, mode %#o), "
                                                 "des parent %lu, "
                                                 "des hard link "
                                                 "=> continue (uid %u, gid %u)\n",
                                                 des_ino,
                                                 CXFSNP_ATTR_UID(des_cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(des_cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(des_cxfsnp_attr),
                                                 des_parent_ino,
                                                 op_uid, op_gid);
            break; /*fall through*/
        }

        /*not hard link*/
        if(0 == op_uid || 0 == op_gid)
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_rename: "
                                                 "src %lu (uid %u, gid %u, mode %#o)\n",
                                                 src_ino,
                                                 CXFSNP_ATTR_UID(src_cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(src_cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(src_cxfsnp_attr));

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_rename: "
                                                 "des %lu (uid %u, gid %u, mode %#o), "
                                                 "des parent %lu, "
                                                 "des exist but not hard link and op is root "
                                                 "=> deny (uid %u, gid %u)\n",
                                                 des_ino,
                                                 CXFSNP_ATTR_UID(des_cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(des_cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(des_cxfsnp_attr),
                                                 des_parent_ino,
                                                 op_uid, op_gid);
            return -EEXIST;
        }

        /*op is not root*/

        if(S_ISVTX & CXFSNP_ATTR_MODE(des_parent_cxfsnp_attr))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_rename: "
                                                 "src %lu (uid %u, gid %u, mode %#o)\n",
                                                 src_ino,
                                                 CXFSNP_ATTR_UID(src_cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(src_cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(src_cxfsnp_attr));

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_rename: "
                                                 "des %lu (uid %u, gid %u, mode %#o), "
                                                 "des parent %lu (uid %u, gid %u, mode %#o), "
                                                 "des not hard link but sticky => need to del des "
                                                 "=> deny (uid %u, gid %u)\n",
                                                 des_ino,
                                                 CXFSNP_ATTR_UID(des_cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(des_cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(des_cxfsnp_attr),
                                                 des_parent_ino,
                                                 CXFSNP_ATTR_UID(des_parent_cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(des_parent_cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(des_parent_cxfsnp_attr),
                                                 op_uid, op_gid);

            return CXFS_FUSEP_EEXIST;
        }

        dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_rename: "
                                             "src %lu (uid %u, gid %u, mode %#o)\n",
                                             src_ino,
                                             CXFSNP_ATTR_UID(src_cxfsnp_attr),
                                             CXFSNP_ATTR_GID(src_cxfsnp_attr),
                                             CXFSNP_ATTR_MODE(src_cxfsnp_attr));

        dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_rename: "
                                             "des %lu (uid %u, gid %u, mode %#o), "
                                             "des parent %lu (uid %u, gid %u, mode %#o), "
                                             "des not hard link or sticky "
                                             "=> continue (uid %u, gid %u)\n",
                                             des_ino,
                                             CXFSNP_ATTR_UID(des_cxfsnp_attr),
                                             CXFSNP_ATTR_GID(des_cxfsnp_attr),
                                             CXFSNP_ATTR_MODE(des_cxfsnp_attr),
                                             des_parent_ino,
                                             CXFSNP_ATTR_UID(des_parent_cxfsnp_attr),
                                             CXFSNP_ATTR_GID(des_parent_cxfsnp_attr),
                                             CXFSNP_ATTR_MODE(des_parent_cxfsnp_attr),
                                             op_uid, op_gid);
        break; /*fall through*/
    }

    /*check permission*/
    if(0 != op_uid && 0 == op_gid)
    {
        if(CXFSNP_ATTR_UID(src_cxfsnp_attr) != op_uid
        && CXFSNP_ATTR_GID(src_cxfsnp_attr) == op_gid
        && 0 == (S_IXOTH & CXFSNP_ATTR_MODE(src_cxfsnp_attr)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_rename: "
                                                 "src %lu (uid %u, gid %u, mode %#o)\n",
                                                 src_ino,
                                                 CXFSNP_ATTR_UID(src_cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(src_cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(src_cxfsnp_attr));

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_rename: "
                                                 "des %lu, "
                                                 "des parent %lu (uid %u, gid %u, mode %#o), "
                                                 "src mode & (S_IXOTH) == 0"
                                                 "=> deny (uid %u, gid %u)\n",
                                                 des_ino,
                                                 des_parent_ino,
                                                 CXFSNP_ATTR_UID(des_parent_cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(des_parent_cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(des_parent_cxfsnp_attr),
                                                 op_uid, op_gid);

            return -EACCES;
        }

        if(CXFSNP_ATTR_UID(src_cxfsnp_attr) != op_uid
        && CXFSNP_ATTR_GID(src_cxfsnp_attr) == op_gid
        && 0 == (S_IWOTH & CXFSNP_ATTR_MODE(src_cxfsnp_attr)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_rename: "
                                                 "src %lu (uid %u, gid %u, mode %#o)\n",
                                                 src_ino,
                                                 CXFSNP_ATTR_UID(src_cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(src_cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(src_cxfsnp_attr));

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_rename: "
                                                 "des %lu, "
                                                 "des parent %lu (uid %u, gid %u, mode %#o), "
                                                 "src mode & (S_IWOTH) == 0"
                                                 "=> deny (uid %u, gid %u)\n",
                                                 des_ino,
                                                 des_parent_ino,
                                                 CXFSNP_ATTR_UID(des_parent_cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(des_parent_cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(des_parent_cxfsnp_attr),
                                                 op_uid, op_gid);

            return -EACCES;
        }

        if(CXFSNP_ATTR_UID(src_cxfsnp_attr) != op_uid
        && CXFSNP_ATTR_GID(src_cxfsnp_attr) == op_gid
        && S_IFSOCK == (S_IFSOCK & CXFSNP_ATTR_MODE(src_cxfsnp_attr)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_rename: "
                                                 "src %lu (uid %u, gid %u, mode %#o)\n",
                                                 src_ino,
                                                 CXFSNP_ATTR_UID(src_cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(src_cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(src_cxfsnp_attr));

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_rename: "
                                                 "des %lu, "
                                                 "des parent %lu (uid %u, gid %u, mode %#o), "
                                                 "src mode & (S_IFSOCK) == S_IFSOCK"
                                                 "=> deny (uid %u, gid %u)\n",
                                                 des_ino,
                                                 des_parent_ino,
                                                 CXFSNP_ATTR_UID(des_parent_cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(des_parent_cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(des_parent_cxfsnp_attr),
                                                 op_uid, op_gid);

            return -EACCES;
        }
    }

    if(0 != op_uid && 0 != op_gid)
    {
        if(CXFSNP_ATTR_UID(des_parent_cxfsnp_attr) != op_uid
        && 0 == (S_IWOTH & CXFSNP_ATTR_MODE(des_parent_cxfsnp_attr)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_rename: "
                                                 "src %lu (uid %u, gid %u, mode %#o)\n",
                                                 src_ino,
                                                 CXFSNP_ATTR_UID(src_cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(src_cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(src_cxfsnp_attr));

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_rename: "
                                                 "des %lu, "
                                                 "des parent %lu (uid %u, gid %u, mode %#o), "
                                                 "des parent mode & (S_IWOTH) == 0"
                                                 "=> deny (uid %u, gid %u)\n",
                                                 des_ino,
                                                 des_parent_ino,
                                                 CXFSNP_ATTR_UID(des_parent_cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(des_parent_cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(des_parent_cxfsnp_attr),
                                                 op_uid, op_gid);

            return -EACCES;
        }

        if(CXFSNP_ATTR_UID(des_parent_cxfsnp_attr) == op_uid
        && 0 == (S_IWUSR & CXFSNP_ATTR_MODE(des_parent_cxfsnp_attr)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_rename: "
                                                 "src %lu (uid %u, gid %u, mode %#o)\n",
                                                 src_ino,
                                                 CXFSNP_ATTR_UID(src_cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(src_cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(src_cxfsnp_attr));

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_rename: "
                                                 "des %lu, "
                                                 "des parent %lu (uid %u, gid %u, mode %#o), "
                                                 "des parent mode & (S_IWUSR) == 0"
                                                 "=> deny (uid %u, gid %u)\n",
                                                 des_ino,
                                                 des_parent_ino,
                                                 CXFSNP_ATTR_UID(des_parent_cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(des_parent_cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(des_parent_cxfsnp_attr),
                                                 op_uid, op_gid);

            return -EACCES;
        }

        if(CXFSNP_ATTR_UID(des_parent_cxfsnp_attr) == op_uid
        && CXFSNP_ATTR_GID(des_parent_cxfsnp_attr) == op_gid /*04.t*/
        && 0 == (S_IXUSR & CXFSNP_ATTR_MODE(des_parent_cxfsnp_attr)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_rename: "
                                                 "src %lu (uid %u, gid %u, mode %#o)\n",
                                                 src_ino,
                                                 CXFSNP_ATTR_UID(src_cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(src_cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(src_cxfsnp_attr));

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_rename: "
                                                 "des %lu, "
                                                 "des parent %lu (uid %u, gid %u, mode %#o), "
                                                 "des parent mode & (S_IXUSR) == 0"
                                                 "=> deny (uid %u, gid %u)\n",
                                                 des_ino,
                                                 des_parent_ino,
                                                 CXFSNP_ATTR_UID(des_parent_cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(des_parent_cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(des_parent_cxfsnp_attr),
                                                 op_uid, op_gid);

            return -EACCES;
        }
    }

    if(0 != op_uid && 0 != op_gid)
    {
        CXFSNP_ITEM     *src_parent_cxfsnp_item;
        CXFSNP_ATTR     *src_parent_cxfsnp_attr;
        uint64_t         src_parent_ino;

        src_parent_ino = CXFSNP_ATTR_INO_MAKE(CXFSNP_ATTR_INO_FETCH_NP_ID(src_ino),
                                          CXFSNP_ITEM_PARENT_POS(src_cxfsnp_item));


        src_parent_cxfsnp_item = cxfsnp_mgr_fetch_item(cxfsnp_mgr, src_parent_ino);
        if(NULL_PTR == src_parent_cxfsnp_item)
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fusep_rename: "
                                                 "lookup parent of src %lu failed\n",
                                                 src_ino);
            return -ENOENT;
        }
        src_parent_cxfsnp_attr = CXFSNP_ITEM_ATTR(src_parent_cxfsnp_item);

        if(CXFSNP_ATTR_UID(src_parent_cxfsnp_attr) != op_uid
        && CXFSNP_ATTR_GID(src_parent_cxfsnp_attr) != op_gid
        && 0 == (S_IWOTH & CXFSNP_ATTR_MODE(src_parent_cxfsnp_attr)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_rename: "
                                                 "src %lu (uid %u, gid %u, mode %#o)\n",
                                                 src_ino,
                                                 CXFSNP_ATTR_UID(src_cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(src_cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(src_cxfsnp_attr));

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_rename: "
                                                 "des %lu, "
                                                 "src parent %lu (uid %u, gid %u, mode %#o), "
                                                 "src parent mode & (S_IWOTH) == 0"
                                                 "=> deny (uid %u, gid %u)\n",
                                                 des_ino,
                                                 src_parent_ino,
                                                 CXFSNP_ATTR_UID(src_parent_cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(src_parent_cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(src_parent_cxfsnp_attr),
                                                 op_uid, op_gid);

            return -EACCES;
        }

        if(CXFSNP_ATTR_UID(src_parent_cxfsnp_attr) != op_uid
        && CXFSNP_ATTR_GID(src_parent_cxfsnp_attr) == op_gid
        && 0 == (S_IWGRP & CXFSNP_ATTR_MODE(src_parent_cxfsnp_attr)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_rename: "
                                                 "src %lu (uid %u, gid %u, mode %#o)\n",
                                                 src_ino,
                                                 CXFSNP_ATTR_UID(src_cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(src_cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(src_cxfsnp_attr));

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_rename: "
                                                 "des %lu, "
                                                 "src parent %lu (uid %u, gid %u, mode %#o), "
                                                 "src parent mode & (S_IWGRP) == 0"
                                                 "=> deny (uid %u, gid %u)\n",
                                                 des_ino,
                                                 src_parent_ino,
                                                 CXFSNP_ATTR_UID(src_parent_cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(src_parent_cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(src_parent_cxfsnp_attr),
                                                 op_uid, op_gid);

            return -EACCES;
        }

        if(CXFSNP_ATTR_UID(src_parent_cxfsnp_attr) == op_uid
        && 0 == (S_IWUSR & CXFSNP_ATTR_MODE(src_parent_cxfsnp_attr)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_rename: "
                                                 "src %lu (uid %u, gid %u, mode %#o)\n",
                                                 src_ino,
                                                 CXFSNP_ATTR_UID(src_cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(src_cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(src_cxfsnp_attr));

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_rename: "
                                                 "des %lu, "
                                                 "src parent %lu (uid %u, gid %u, mode %#o), "
                                                 "src parent mode & (S_IWUSR) == 0"
                                                 "=> deny (uid %u, gid %u)\n",
                                                 des_ino,
                                                 src_parent_ino,
                                                 CXFSNP_ATTR_UID(src_parent_cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(src_parent_cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(src_parent_cxfsnp_attr),
                                                 op_uid, op_gid);

            return -EACCES;
        }

        if(CXFSNP_ATTR_UID(src_parent_cxfsnp_attr) == op_uid
        && CXFSNP_ATTR_GID(src_parent_cxfsnp_attr) == op_gid /*04.t*/
        && 0 == (S_IXUSR & CXFSNP_ATTR_MODE(src_parent_cxfsnp_attr)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_rename: "
                                                 "src %lu (uid %u, gid %u, mode %#o)\n",
                                                 src_ino,
                                                 CXFSNP_ATTR_UID(src_cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(src_cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(src_cxfsnp_attr));

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_rename: "
                                                 "des %lu, "
                                                 "src parent %lu (uid %u, gid %u, mode %#o), "
                                                 "src parent mode & (S_IXUSR) == 0"
                                                 "=> deny (uid %u, gid %u)\n",
                                                 des_ino,
                                                 src_parent_ino,
                                                 CXFSNP_ATTR_UID(src_parent_cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(src_parent_cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(src_parent_cxfsnp_attr),
                                                 op_uid, op_gid);

            return -EACCES;
        }

        /*09.t*/
        if(CXFSNP_ATTR_UID(src_parent_cxfsnp_attr) == op_uid
        && CXFSNP_ATTR_GID(src_parent_cxfsnp_attr) == op_gid
        && 0 != (S_ISVTX & CXFSNP_ATTR_MODE(src_parent_cxfsnp_attr))
        && (CXFSNP_ATTR_UID(src_cxfsnp_attr) != op_uid
        || CXFSNP_ATTR_GID(src_cxfsnp_attr) != op_gid)
        && src_parent_cxfsnp_item != des_parent_cxfsnp_item
        )
        {
            if(NULL_PTR != des_cxfsnp_item) /*des exist*/
            {
                if(CXFSNP_ATTR_UID(des_parent_cxfsnp_attr) != op_uid
                || CXFSNP_ATTR_GID(des_parent_cxfsnp_attr) != op_gid)
                {
                    dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_rename: "
                                                         "src %lu (uid %u, gid %u, mode %#o)\n",
                                                         src_ino,
                                                         CXFSNP_ATTR_UID(src_cxfsnp_attr),
                                                         CXFSNP_ATTR_GID(src_cxfsnp_attr),
                                                         CXFSNP_ATTR_MODE(src_cxfsnp_attr));

                    dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_rename: "
                                                         "des %lu exist, "
                                                         "des parent %lu (uid %u, gid %u, mode %#o), "
                                                         "des parent mode & (S_ISVTX) != 0"
                                                         "=> deny (uid %u, gid %u)\n",
                                                         des_ino,
                                                         des_parent_ino,
                                                         CXFSNP_ATTR_UID(des_parent_cxfsnp_attr),
                                                         CXFSNP_ATTR_GID(des_parent_cxfsnp_attr),
                                                         CXFSNP_ATTR_MODE(des_parent_cxfsnp_attr),
                                                         op_uid, op_gid);

                    return -EACCES;
                }
            }
            else /*des not exist*/
            {
                if(CXFSNP_ATTR_UID(des_parent_cxfsnp_attr) != op_uid
                || CXFSNP_ATTR_GID(des_parent_cxfsnp_attr) != op_gid)
                {
                    dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_rename: "
                                                         "src %lu (uid %u, gid %u, mode %#o)\n",
                                                         src_ino,
                                                         CXFSNP_ATTR_UID(src_cxfsnp_attr),
                                                         CXFSNP_ATTR_GID(src_cxfsnp_attr),
                                                         CXFSNP_ATTR_MODE(src_cxfsnp_attr));

                    dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_rename: "
                                                         "des %lu not exist, "
                                                         "des parent %lu (uid %u, gid %u, mode %#o), "
                                                         "des parent mode & (S_ISVTX) != 0"
                                                         "=> deny (uid %u, gid %u)\n",
                                                         des_ino,
                                                         des_parent_ino,
                                                         CXFSNP_ATTR_UID(des_parent_cxfsnp_attr),
                                                         CXFSNP_ATTR_GID(des_parent_cxfsnp_attr),
                                                         CXFSNP_ATTR_MODE(des_parent_cxfsnp_attr),
                                                         op_uid, op_gid);

                    return -EACCES;
                }

               if(0 /*faint, failed to satisfy all cases in 09.tt*/
                && (CXFSNP_ATTR_UID(des_parent_cxfsnp_attr) == (uint32_t)op_uid
                && CXFSNP_ATTR_GID(des_parent_cxfsnp_attr) == (uint32_t)op_gid)
                && (CXFSNP_ATTR_UID(des_parent_cxfsnp_attr) != CXFSNP_ATTR_UID(src_cxfsnp_attr)
                && CXFSNP_ATTR_GID(des_parent_cxfsnp_attr) != CXFSNP_ATTR_GID(src_cxfsnp_attr))
                && 0 == (S_IWOTH & CXFSNP_ATTR_MODE(des_parent_cxfsnp_attr)))
                {
                    dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_rename: "
                                                         "src %lu (uid %u, gid %u), "
                                                         "src parent (uid %u, gid %u, mode %#o), "
                                                         "src parent mode & (S_ISVTX) != 0\n",
                                                         src_ino,
                                                         CXFSNP_ATTR_UID(src_cxfsnp_attr),
                                                         CXFSNP_ATTR_GID(src_cxfsnp_attr),
                                                         CXFSNP_ATTR_UID(src_parent_cxfsnp_attr),
                                                         CXFSNP_ATTR_GID(src_parent_cxfsnp_attr),
                                                         CXFSNP_ATTR_MODE(src_parent_cxfsnp_attr));

                    dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_rename: "
                                                         "no des, des parent (uid %u, gid %u, mode %#o ) "
                                                         "des parent mode & (S_IWOTH) == 0 "
                                                         "=> deny (uid %u, gid %u)\n",
                                                         CXFSNP_ATTR_UID(des_parent_cxfsnp_attr),
                                                         CXFSNP_ATTR_GID(des_parent_cxfsnp_attr),
                                                         CXFSNP_ATTR_MODE(des_parent_cxfsnp_attr),
                                                         (uint32_t)op_uid, (uint32_t)op_gid);

                    return -EACCES;
                }
            }
        }

        if((CXFSNP_ATTR_UID(src_parent_cxfsnp_attr) != op_uid
            || CXFSNP_ATTR_GID(src_parent_cxfsnp_attr) != op_gid)
        && 0 != (S_ISVTX & CXFSNP_ATTR_MODE(src_parent_cxfsnp_attr)))
        {
            if(CXFSNP_ATTR_UID(src_cxfsnp_attr) != op_uid
            || CXFSNP_ATTR_GID(src_cxfsnp_attr) != op_gid)
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_rename: "
                                                     "src %lu (uid %u, gid %u, mode %#o)\n",
                                                     src_ino,
                                                     CXFSNP_ATTR_UID(src_cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(src_cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(src_cxfsnp_attr));

                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_rename: "
                                                     "des %lu, "
                                                     "src parent %lu (uid %u, gid %u, mode %#o), "
                                                     "=> deny (uid %u, gid %u)\n",
                                                     des_ino,
                                                     src_parent_ino,
                                                     CXFSNP_ATTR_UID(src_parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(src_parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(src_parent_cxfsnp_attr),
                                                     op_uid, op_gid);

                return -EACCES;
            }
        }
    }

    dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_rename: "
                                         "src %lu (uid %u, gid %u, mode %#o), "
                                         "des parent %lu "
                                         "=> accept (uid %u, gid %u)\n",
                                         src_ino,
                                         CXFSNP_ATTR_UID(src_cxfsnp_attr),
                                         CXFSNP_ATTR_GID(src_cxfsnp_attr),
                                         CXFSNP_ATTR_MODE(src_cxfsnp_attr),
                                         des_parent_ino,
                                         op_uid, op_gid);

    return 0;
}

int cxfs_fusep_link(CXFSNP_MGR *cxfsnp_mgr, const uint64_t src_ino, const uint64_t des_parent_ino, const uint32_t op_uid, const uint32_t op_gid)
{
    CXFSNP_ITEM     *src_cxfsnp_item;
    CXFSNP_ATTR     *src_cxfsnp_attr;

    CXFSNP_ITEM     *src_tail_cxfsnp_item;
    CXFSNP_ATTR     *src_tail_cxfsnp_attr;
    uint64_t         src_tail_ino;

    /*des -> src*/

    src_cxfsnp_item = cxfsnp_mgr_fetch_item(cxfsnp_mgr, src_ino);
    if(NULL_PTR == src_cxfsnp_item)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fusep_link: "
                                             "src %lu not exist\n",
                                             src_ino);
        return -ENOENT;
    }
    src_cxfsnp_attr = CXFSNP_ITEM_ATTR(src_cxfsnp_item);

    /*find link tail of src*/
    src_tail_ino         = src_ino;
    src_tail_cxfsnp_item = src_cxfsnp_item;
    src_tail_cxfsnp_attr = src_cxfsnp_attr;
    while(CXFSNP_ATTR_ERR_INO != CXFSNP_ATTR_NEXT_INO(src_tail_cxfsnp_attr))
    {
        src_tail_ino         = CXFSNP_ATTR_NEXT_INO(src_tail_cxfsnp_attr);
        src_tail_cxfsnp_item = cxfsnp_mgr_fetch_item(cxfsnp_mgr, src_tail_ino);
        src_tail_cxfsnp_attr = CXFSNP_ITEM_ATTR(src_tail_cxfsnp_item);
    }

    /*check permission*/
    if(0 != op_uid && 0 == op_gid)
    {
        if(CXFSNP_ATTR_UID(src_tail_cxfsnp_attr) == op_uid
        && CXFSNP_ATTR_GID(src_tail_cxfsnp_attr) != op_gid)
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_link: "
                                                 "src %lu, "
                                                 "src tail %lu (uid %u, gid %u, mode %#o), "
                                                 "=> deny (uid %u, gid %u)\n",
                                                 src_ino,
                                                 src_tail_ino,
                                                 CXFSNP_ATTR_UID(src_tail_cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(src_tail_cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(src_tail_cxfsnp_attr),
                                                 op_uid, op_gid);

            return -EACCES;
        }
    }

    if(0 != op_uid && 0 != op_gid)
    {
        CXFSNP_ITEM     *des_parent_cxfsnp_item;
        CXFSNP_ATTR     *des_parent_cxfsnp_attr;

        des_parent_cxfsnp_item = cxfsnp_mgr_fetch_item(cxfsnp_mgr, des_parent_ino);
        if(NULL_PTR == des_parent_cxfsnp_item)
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fusep_link: "
                                                 "lookup des parent %lu failed\n",
                                                 des_parent_ino);
            return -ENOENT;
        }
        des_parent_cxfsnp_attr = CXFSNP_ITEM_ATTR(des_parent_cxfsnp_item);

        if(CXFSNP_ATTR_UID(des_parent_cxfsnp_attr) != op_uid
        && 0 == (S_IXOTH & CXFSNP_ATTR_MODE(des_parent_cxfsnp_attr)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_link: "
                                                 "src %lu, "
                                                 "des parent %lu (uid %u, gid %u, mode %#o), "
                                                 "des parent mode & (S_IXOTH) == 0"
                                                 "=> deny (uid %u, gid %u)\n",
                                                 src_ino,
                                                 des_parent_ino,
                                                 CXFSNP_ATTR_UID(des_parent_cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(des_parent_cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(des_parent_cxfsnp_attr),
                                                 op_uid, op_gid);


            return -EACCES;
        }

        if(CXFSNP_ATTR_UID(des_parent_cxfsnp_attr) == op_uid
        && 0 == (S_IWUSR & CXFSNP_ATTR_MODE(des_parent_cxfsnp_attr)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_link: "
                                                 "src %lu, "
                                                 "des parent %lu (uid %u, gid %u, mode %#o), "
                                                 "des parent mode & (S_IWUSR) == 0"
                                                 "=> deny (uid %u, gid %u)\n",
                                                 src_ino,
                                                 des_parent_ino,
                                                 CXFSNP_ATTR_UID(des_parent_cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(des_parent_cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(des_parent_cxfsnp_attr),
                                                 op_uid, op_gid);

            return -EACCES;
        }

        if(CXFSNP_ATTR_UID(des_parent_cxfsnp_attr) == op_uid
        && 0 == (S_IXUSR & CXFSNP_ATTR_MODE(des_parent_cxfsnp_attr)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_link: "
                                                 "src %lu, "
                                                 "des parent %lu (uid %u, gid %u, mode %#o), "
                                                 "des parent mode & (S_IXUSR) == 0"
                                                 "=> deny (uid %u, gid %u)\n",
                                                 src_ino,
                                                 des_parent_ino,
                                                 CXFSNP_ATTR_UID(des_parent_cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(des_parent_cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(des_parent_cxfsnp_attr),
                                                 op_uid, op_gid);

            return -EACCES;
        }
    }


    if(0 != op_uid && 0 != op_gid)
    {
        CXFSNP_ITEM     *src_parent_cxfsnp_item;
        CXFSNP_ATTR     *src_parent_cxfsnp_attr;
        uint64_t         src_parent_ino;

        src_parent_ino = CXFSNP_ATTR_INO_MAKE(CXFSNP_ATTR_INO_FETCH_NP_ID(src_ino),
                                             CXFSNP_ITEM_PARENT_POS(src_cxfsnp_item));


        src_parent_cxfsnp_item = cxfsnp_mgr_fetch_item(cxfsnp_mgr, src_parent_ino);
        if(NULL_PTR == src_parent_cxfsnp_item)
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fusep_link: "
                                                 "lookup parent of src %lu failed\n",
                                                 src_ino);
            return -ENOENT;
        }
        src_parent_cxfsnp_attr = CXFSNP_ITEM_ATTR(src_parent_cxfsnp_item);

        if(CXFSNP_ATTR_UID(src_parent_cxfsnp_attr) != op_uid
        && 0 == (S_IXOTH & CXFSNP_ATTR_MODE(src_parent_cxfsnp_attr)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_link: src %lu, "
                                                 "src parent %lu (uid %u, gid %u, mode %#o), "
                                                 "src parent mode & (S_IXOTH) == 0 "
                                                 "=> deny (uid %u, gid %u)\n",
                                                 src_ino,
                                                 src_parent_ino,
                                                 CXFSNP_ATTR_UID(src_parent_cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(src_parent_cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(src_parent_cxfsnp_attr),
                                                 op_uid, op_gid);

            return -EACCES;
        }

        if(CXFSNP_ATTR_UID(src_parent_cxfsnp_attr) == op_uid
        && 0 == (S_IWUSR & CXFSNP_ATTR_MODE(src_parent_cxfsnp_attr)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_link: src %lu, "
                                                 "src parent %lu (uid %u, gid %u, mode %#o), "
                                                 "src parent mode & (S_IWUSR) == 0"
                                                 "=> deny (uid %u, gid %u)\n",
                                                 src_ino,
                                                 src_parent_ino,
                                                 CXFSNP_ATTR_UID(src_parent_cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(src_parent_cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(src_parent_cxfsnp_attr),
                                                 op_uid, op_gid);
            return -EACCES;
        }

        if(CXFSNP_ATTR_UID(src_parent_cxfsnp_attr) == op_uid
        && 0 == (S_IXUSR & CXFSNP_ATTR_MODE(src_parent_cxfsnp_attr)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_link: src %lu, "
                                                 "src parent %lu (uid %u, gid %u, mode %#o), "
                                                 "src parent mode & (S_IXUSR) == 0 "
                                                 "=> deny (uid %u, gid %u)\n",
                                                 src_ino,
                                                 src_parent_ino,
                                                 CXFSNP_ATTR_UID(src_parent_cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(src_parent_cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(src_parent_cxfsnp_attr),
                                                 op_uid, op_gid);

            return -EACCES;
        }
    }

    dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_link: "
                                         "src %lu (uid %u, gid %u, mode %#o), "
                                         "des parent %lu "
                                         "=> accept (uid %u, gid %u)\n",
                                         src_ino,
                                         CXFSNP_ATTR_UID(src_cxfsnp_attr),
                                         CXFSNP_ATTR_GID(src_cxfsnp_attr),
                                         CXFSNP_ATTR_MODE(src_cxfsnp_attr),
                                         des_parent_ino,
                                         op_uid, op_gid);

    return 0;
}

int cxfs_fusep_chmod(CXFSNP_MGR *cxfsnp_mgr, const uint64_t ino, const uint16_t mode, const uint32_t op_uid, const uint32_t op_gid)
{
    CXFSNP_ITEM     *cxfsnp_item;
    CXFSNP_ATTR     *cxfsnp_attr;

    if(0 == op_uid && 0 == op_gid) /*root*/
    {
        return 0;
    }

    cxfsnp_item = cxfsnp_mgr_fetch_item(cxfsnp_mgr, ino);
    if(NULL_PTR == cxfsnp_item)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fusep_chmod: "
                                             "ino %lu fetch item failed\n",
                                             ino);
        return -ENOENT;
    }

    cxfsnp_attr = CXFSNP_ITEM_ATTR(cxfsnp_item);

    if(0 != op_uid && 0 != op_gid) /*not root*/
    {
        if(CXFSNP_ATTR_UID(cxfsnp_attr) == op_uid)
        {
            CXFSNP_ITEM     *parent_cxfsnp_item;
            CXFSNP_ATTR     *parent_cxfsnp_attr;
            uint64_t         parent_ino;

            /*
            # POSIX: If the calling process does not have appropriate privileges, and if
            # the group ID of the file does not match the effective group ID or one of the
            # supplementary group IDs and if the file is a regular file, bit S_ISGID
            # (set-group-ID on execution) in the file's mode shall be cleared upon
            */
            if(CXFSNP_ATTR_GID(cxfsnp_attr) != op_gid
            && CXFSNP_ATTR_FILE_IS_REG == CXFSNP_ATTR_DIR_FLAG(cxfsnp_attr))
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_chmod: "
                                                     "its %lu (uid %u, gid %u, mode %#o), "
                                                     "regulare file, "
                                                     "=> accept (uid %u, gid %u) but need to clear S_ISGID\n",
                                                     ino,
                                                     CXFSNP_ATTR_UID(cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                     op_uid, op_gid);
                return CXFS_FUSEP_ECGID;
            }

            if(CXFSNP_ATTR_GID(cxfsnp_attr) != op_gid
            && 0 == (S_IXGRP & CXFSNP_ATTR_MODE(cxfsnp_attr)))
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_chmod: "
                                                     "its %lu (uid %u, gid %u, mode %#o), "
                                                     "mode & (S_ S_IXGRP) == 0 "
                                                     "=> deny (uid %u, gid %u)\n",
                                                     ino,
                                                     CXFSNP_ATTR_UID(cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                     op_uid, op_gid);
                return -EPERM;
            }

            parent_ino = CXFSNP_ATTR_INO_MAKE(CXFSNP_ATTR_INO_FETCH_NP_ID(ino),
                                              CXFSNP_ITEM_PARENT_POS(cxfsnp_item));

            parent_cxfsnp_item = cxfsnp_mgr_fetch_item(cxfsnp_mgr, parent_ino);
            parent_cxfsnp_attr = CXFSNP_ITEM_ATTR(parent_cxfsnp_item);

            /*check parent*/
            if(0 == (S_IXOTH & CXFSNP_ATTR_MODE(parent_cxfsnp_attr)))
            {
                /*warning: split into 2 logs to avoid si parser complain complex :-(*/
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_chmod: "
                                                     "its %lu (uid %u, gid %u, mode %#o)\n",
                                                     ino,
                                                     CXFSNP_ATTR_UID(cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(cxfsnp_attr));

                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_chmod: "
                                                     "parent %lu (uid %u, gid %u, mode %#o), "
                                                     "parent mode & (S_IXOTH) == 0 "
                                                     "=> deny (uid %u, gid %u)\n",
                                                     parent_ino,
                                                     CXFSNP_ATTR_UID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(parent_cxfsnp_attr),
                                                     op_uid, op_gid);

                return -EACCES;
            }

        }
        else
        {
            if(0 == (S_IXOTH & CXFSNP_ATTR_MODE(cxfsnp_attr)))
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_chmod: "
                                                     "its %lu (uid %u, gid %u, mode %#o), "
                                                     "mode & (S_IXOTH) == 0 "
                                                     "=> deny (uid %u, gid %u)\n",
                                                     ino,
                                                     CXFSNP_ATTR_UID(cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                     op_uid, op_gid);
                return -EPERM;
            }
        }
    }

    /*op_uid == 0 || op_gid ==0*/
    if(0 == op_uid)
    {
        if(CXFSNP_ATTR_UID(cxfsnp_attr) != op_uid)
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_chmod: "
                                                 "its %lu (uid %u, gid %u, mode %#o), "
                                                 "uid not matched "
                                                 "=> deny (uid %u, gid %u)\n",
                                                 ino,
                                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                 op_uid, op_gid);
            return -EPERM;
        }
        if(CXFSNP_ATTR_GID(cxfsnp_attr) != op_gid
        && 0 == (S_IXGRP & CXFSNP_ATTR_MODE(cxfsnp_attr)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_chmod: "
                                                 "its %lu (uid %u, gid %u, mode %#o), "
                                                 "mode & (S_IXGRP) == 0 "
                                                 "=> deny (uid %u, gid %u)\n",
                                                 ino,
                                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                 op_uid, op_gid);
            return -EPERM;
        }
    }

    if(0 == op_gid)
    {
        if(CXFSNP_ATTR_UID(cxfsnp_attr) != op_uid)
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_chmod: "
                                                 "its %lu (uid %u, gid %u, mode %#o), "
                                                 "uid not matched "
                                                 "=> deny (uid %u, gid %u)\n",
                                                 ino,
                                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                 op_uid, op_gid);
            return -EPERM;
        }
    }

    dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_link: "
                                         "its %lu (uid %u, gid %u, mode %#o), "
                                         "=> accept (uid %u, gid %u)\n",
                                         ino,
                                         CXFSNP_ATTR_UID(cxfsnp_attr),
                                         CXFSNP_ATTR_GID(cxfsnp_attr),
                                         CXFSNP_ATTR_MODE(cxfsnp_attr),
                                         op_uid, op_gid);
    return 0;
}

int cxfs_fusep_chown(CXFSNP_MGR *cxfsnp_mgr, const uint64_t ino, const UINT32 des_uid, const uint32_t des_gid, const uint32_t op_uid, const uint32_t op_gid)
{
    CXFSNP_ITEM     *cxfsnp_item;
    CXFSNP_ATTR     *cxfsnp_attr;

    cxfsnp_item = cxfsnp_mgr_fetch_item(cxfsnp_mgr, ino);
    if(NULL_PTR == cxfsnp_item)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fusep_chown: "
                                             "ino %lu fetch item failed\n",
                                             ino);
        return -ENOENT;
    }
    cxfsnp_attr = CXFSNP_ITEM_ATTR(cxfsnp_item);

    if((0 != op_uid && 0 != op_gid) /*not root*/
    && CXFS_FUSEP_UID_ERR == des_uid && CXFS_FUSEP_GID_ERR == des_gid)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fusep_chown: "
                                             "ino %lu, "
                                             "des (uid %u, gid %#x) overflow => deny\n",
                                             ino,
                                             des_uid, des_gid);
        return -EACCES;
    }

    if(0 == op_uid && 0 == op_gid) /*root*/
    {
        /*According to POSIX: If both owner and group are -1, the times need not be updated.*/
        if(CXFS_FUSEP_UID_ERR != des_uid || CXFS_FUSEP_GID_ERR != des_gid)
        {
            return 0;
        }

        return CXFS_FUSEP_ENOTIME;
    }

    if(0 != op_uid && 0 != op_gid)
    {
        /*chown:07.t*/
        if(CXFSNP_ATTR_UID(cxfsnp_attr) != op_uid
        /*|| CXFSNP_ATTR_GID(cxfsnp_attr) != op_gid*/)
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_chown: "
                                                 "ino %lu (uid %u, gid %u, mode %#o), "
                                                 "op (uid %u, gid %u), "
                                                 "op is not owner "
                                                 "=> deny des (uid %u, gid %u)\n",
                                                 ino,
                                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                 op_uid, op_gid,
                                                 des_uid, des_gid);

            return -EPERM;
        }

        /*chown:07.t*/
        if(CXFSNP_ATTR_UID(cxfsnp_attr) != des_uid
        /*|| CXFSNP_ATTR_GID(cxfsnp_attr) != des_gid*/)
        {
            /*chown:00.t*/
            if(CXFS_FUSEP_UID_ERR == des_uid && CXFS_FUSEP_GID_ERR != des_gid)
            {
                /*chown:07.t but block chown:00.t*/
                if(0 && 0 == (S_IXUSR & CXFSNP_ATTR_MODE(cxfsnp_attr)))
                {
                    dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_chown: "
                                                         "its %lu (uid %u, gid %u, mode %#o), "
                                                         "op (uid %u, gid %u), "
                                                         "its mode & (S_IXUSR) == 0 "
                                                         "=> deny des (uid %u, gid %u)\n",
                                                         ino,
                                                         CXFSNP_ATTR_UID(cxfsnp_attr),
                                                         CXFSNP_ATTR_GID(cxfsnp_attr),
                                                         CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                         op_uid, op_gid,
                                                         des_uid, des_gid);

                    return -EPERM;
                }
            }

            if(CXFS_FUSEP_UID_ERR == des_uid && CXFS_FUSEP_GID_ERR != des_gid)
            {
                CXFSNP_ITEM     *parent_cxfsnp_item;
                CXFSNP_ATTR     *parent_cxfsnp_attr;
                uint64_t         parent_ino;

                parent_ino = CXFSNP_ATTR_INO_MAKE(CXFSNP_ATTR_INO_FETCH_NP_ID(ino),
                                                  CXFSNP_ITEM_PARENT_POS(cxfsnp_item));
                parent_cxfsnp_item = cxfsnp_mgr_fetch_item(cxfsnp_mgr, parent_ino);
                parent_cxfsnp_attr = CXFSNP_ITEM_ATTR(parent_cxfsnp_item);

                /*chown:05.t*/
                if(0 == (S_IXUSR & CXFSNP_ATTR_MODE(parent_cxfsnp_attr)))
                {
                    /*warning: split into 2 logs to avoid si parser complain complex :-(*/

                    dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_chown: "
                                                         "its %lu (uid %u, gid %u, mode %#o)\n",
                                                         ino,
                                                         CXFSNP_ATTR_UID(cxfsnp_attr),
                                                         CXFSNP_ATTR_GID(cxfsnp_attr),
                                                         CXFSNP_ATTR_MODE(cxfsnp_attr));

                    dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_chown: "
                                                         "parent %lu (uid %u, gid %u, mode %#o), "
                                                         "op (uid %u, gid %u), "
                                                         "parent mode & (S_IXUSR) == 0 "
                                                         "=> deny des (uid %u, gid %u)\n",
                                                         parent_ino,
                                                         CXFSNP_ATTR_UID(parent_cxfsnp_attr),
                                                         CXFSNP_ATTR_GID(parent_cxfsnp_attr),
                                                         CXFSNP_ATTR_MODE(parent_cxfsnp_attr),
                                                         op_uid, op_gid,
                                                         des_uid, des_gid);

                    return -EACCES;
                }

                /*chown:07.t but block chown:00.t*/
                if(0 && 0 == (S_IWGRP & CXFSNP_ATTR_MODE(parent_cxfsnp_attr)))
                {
                    /*warning: split into 2 logs to avoid si parser complain complex :-(*/

                    dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_chown: "
                                                         "its %lu (uid %u, gid %u, mode %#o)\n",
                                                         ino,
                                                         CXFSNP_ATTR_UID(cxfsnp_attr),
                                                         CXFSNP_ATTR_GID(cxfsnp_attr),
                                                         CXFSNP_ATTR_MODE(cxfsnp_attr));

                    dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_chown: "
                                                         "parent %lu (uid %u, gid %u, mode %#o), "
                                                         "op (uid %u, gid %u), "
                                                         "parent mode & (S_IWGRP) == 0 "
                                                         "=> deny des (uid %u, gid %u)\n",
                                                         parent_ino,
                                                         CXFSNP_ATTR_UID(parent_cxfsnp_attr),
                                                         CXFSNP_ATTR_GID(parent_cxfsnp_attr),
                                                         CXFSNP_ATTR_MODE(parent_cxfsnp_attr),
                                                         op_uid, op_gid,
                                                         des_uid, des_gid);

                    return -EPERM;
                }

                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_chown: "
                                                     "ino %lu (uid %u, gid %u, mode %#o), "
                                                     "op (uid %u, gid %u), "
                                                     "=> accept des (uid %u, gid %u) but gid only\n",
                                                     ino,
                                                     CXFSNP_ATTR_UID(cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                     op_uid, op_gid,
                                                     des_uid, des_gid);
                return CXFS_FUSEP_EUGID;
            }

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_chown: "
                                                 "ino %lu (uid %u, gid %u, mode %#o), "
                                                 "op (uid %u, gid %u), "
                                                 "des is not owner "
                                                 "=> deny des (uid %u, gid %u)\n",
                                                 ino,
                                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                 op_uid, op_gid,
                                                 des_uid, des_gid);

            return -EPERM;
        }
    }

    if((0 != op_uid || 0 != op_gid)
    && CXFSNP_ATTR_UID(cxfsnp_attr) == des_uid
    && CXFSNP_ATTR_UID(cxfsnp_attr) == op_uid)
    {
        dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_chown: "
                                             "ino %lu (uid %u, gid %u, mode %#o), "
                                             "op (uid %u, gid %u), "
                                             "des_uid == op uid == uid "
                                             "=> accept des (uid %u, gid %u)\n",
                                             ino,
                                             CXFSNP_ATTR_UID(cxfsnp_attr),
                                             CXFSNP_ATTR_GID(cxfsnp_attr),
                                             CXFSNP_ATTR_MODE(cxfsnp_attr),
                                             op_uid, op_gid,
                                             des_uid, des_gid);

        return 0;
    }

    if((0 != op_uid || 0 != op_gid)
    && CXFSNP_ATTR_UID(cxfsnp_attr) != des_uid
    && CXFS_FUSEP_UID_ERR != des_uid)
    {
        CXFSNP_ITEM     *parent_cxfsnp_item;
        CXFSNP_ATTR     *parent_cxfsnp_attr;
        uint64_t         parent_ino;

        if(0 == CXFSNP_ATTR_UID(cxfsnp_attr))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_chown: "
                                                 "ino %lu (uid %u, gid %u, mode %#o), "
                                                 "op (uid %u, gid %u), "
                                                 "uid is root "
                                                 "=> deny des (uid %u, gid %u)\n",
                                                 ino,
                                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                 op_uid, op_gid,
                                                 des_uid, des_gid);

            return -EPERM;
        }

        if(0 != op_uid
        && 0 == (S_IXOTH & CXFSNP_ATTR_MODE(cxfsnp_attr)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_chown: "
                                                 "ino %lu (uid %u, gid %u, mode %#o), "
                                                 "op (uid %u, gid %u), "
                                                 "mode & (S_IXOTH) == 0 "
                                                 "=> deny des (uid %u, gid %u)\n",
                                                 ino,
                                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                 op_uid, op_gid,
                                                 des_uid, des_gid);

            return -EPERM;
        }

        parent_ino = CXFSNP_ATTR_INO_MAKE(CXFSNP_ATTR_INO_FETCH_NP_ID(ino),
                                          CXFSNP_ITEM_PARENT_POS(cxfsnp_item));
        parent_cxfsnp_item = cxfsnp_mgr_fetch_item(cxfsnp_mgr, parent_ino);
        parent_cxfsnp_attr = CXFSNP_ITEM_ATTR(parent_cxfsnp_item);

        if(CXFSNP_ATTR_UID(cxfsnp_attr) != des_uid
        && 0 == (S_IXOTH & CXFSNP_ATTR_MODE(parent_cxfsnp_attr)))
        {
            /*warning: split into 2 logs to avoid si parser complain complex :-(*/

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_chown: "
                                                 "its %lu (uid %u, gid %u, mode %#o)\n",
                                                 ino,
                                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr));

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_chown: "
                                                 "parent %lu (uid %u, gid %u, mode %#o), "
                                                 "op (uid %u, gid %u), "
                                                 "parent mode & (S_IXOTH) == 0 "
                                                 "=> deny des (uid %u, gid %u)\n",
                                                 parent_ino,
                                                 CXFSNP_ATTR_UID(parent_cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(parent_cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(parent_cxfsnp_attr),
                                                 op_uid, op_gid,
                                                 des_uid, des_gid);

            return -EACCES;
        }

        return 0;
    }

    if((0 != op_uid || 0 != op_gid)
    && CXFSNP_ATTR_GID(cxfsnp_attr) != des_gid
    && CXFS_FUSEP_GID_ERR != des_gid)
    {
        CXFSNP_ITEM     *parent_cxfsnp_item;
        CXFSNP_ATTR     *parent_cxfsnp_attr;
        uint64_t         parent_ino;

        if(0 == CXFSNP_ATTR_GID(cxfsnp_attr))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_chown: "
                                                 "its %lu (uid %u, gid %u, mode %#o), "
                                                 "op (uid %u, gid %u), "
                                                 "gid is root "
                                                 "=> deny des (uid %u, gid %u)\n",
                                                 ino,
                                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                 op_uid, op_gid,
                                                 des_uid, des_gid);

            return -EPERM;
        }

        if(0 != op_gid
        && 0 == (S_IXGRP & CXFSNP_ATTR_MODE(cxfsnp_attr)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_chown: "
                                                 "its %lu (uid %u, gid %u, mode %#o), "
                                                 "op (uid %u, gid %u), "
                                                 "mode & (S_IXGRP) == 0 "
                                                 "=> deny des (uid %u, gid %u)\n",
                                                 ino,
                                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                 op_uid, op_gid,
                                                 des_uid, des_gid);

            return -EPERM;
        }

        parent_ino = CXFSNP_ATTR_INO_MAKE(CXFSNP_ATTR_INO_FETCH_NP_ID(ino),
                                          CXFSNP_ITEM_PARENT_POS(cxfsnp_item));

        parent_cxfsnp_item = cxfsnp_mgr_fetch_item(cxfsnp_mgr, parent_ino);
        parent_cxfsnp_attr = CXFSNP_ITEM_ATTR(parent_cxfsnp_item);

        if(CXFSNP_ATTR_GID(cxfsnp_attr) != des_gid
        && 0 == (S_IXGRP & CXFSNP_ATTR_MODE(parent_cxfsnp_attr)))
        {
            /*warning: split into 2 logs to avoid si parser complain complex :-(*/

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_chown: "
                                                 "its %lu (uid %u, gid %u, mode %#o)\n",
                                                 ino,
                                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr));

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_chown: "
                                                 "parent %lu (uid %u, gid %u, mode %#o), "
                                                 "op (uid %u, gid %u), "
                                                 "parent mode & (S_IXGRP) == 0 "
                                                 "=> deny des (uid %u, gid %u)\n",
                                                 parent_ino,
                                                 CXFSNP_ATTR_UID(parent_cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(parent_cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(parent_cxfsnp_attr),
                                                 op_uid, op_gid,
                                                 des_uid, des_gid);
            return -EACCES;
        }

        return 0;
    }

    dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_chown: "
                                         "its %lu (uid %u, gid %u, mode %#o), "
                                         "op (uid %u, gid %u), "
                                         "=> accept des (uid %u, gid %u)\n",
                                         ino,
                                         CXFSNP_ATTR_UID(cxfsnp_attr),
                                         CXFSNP_ATTR_GID(cxfsnp_attr),
                                         CXFSNP_ATTR_MODE(cxfsnp_attr),
                                         op_uid, op_gid,
                                         des_uid, des_gid);
    return 0;
}

int cxfs_fusep_truncate(CXFSNP_MGR *cxfsnp_mgr, const uint64_t ino, const uint32_t op_uid, const uint32_t op_gid)
{
    CXFSNP_ITEM     *cxfsnp_item;
    CXFSNP_ATTR     *cxfsnp_attr;

    cxfsnp_item = cxfsnp_mgr_fetch_item(cxfsnp_mgr, ino);

    if(NULL_PTR != cxfsnp_item /*file exist*/
    && 0 != op_uid && 0 == op_gid) /*not root*/
    {
        cxfsnp_attr = CXFSNP_ITEM_ATTR(cxfsnp_item);

        dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_truncate: "
                                             "its ino %lu (uid %u, gid %u, mod %#o), "
                                             "op (uid %u, gid %u)\n",
                                             ino,
                                             CXFSNP_ATTR_UID(cxfsnp_attr),
                                             CXFSNP_ATTR_GID(cxfsnp_attr),
                                             CXFSNP_ATTR_MODE(cxfsnp_attr),
                                             op_uid, op_gid);

        if(CXFSNP_ATTR_UID(cxfsnp_attr) == op_uid
        && CXFSNP_ATTR_GID(cxfsnp_attr) == op_gid
        && 0 == (S_IWUSR & CXFSNP_ATTR_MODE(cxfsnp_attr)))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fusep_truncate: "
                                                 "its ino %lu (uid %u, gid %u, mod %#o), "
                                                 "mod & (S_IWUSR) == 0 "
                                                 "=> deny (uid %u, gid %u)\n",
                                                 ino,
                                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                 op_uid, op_gid);
            return -EACCES;
        }

        if(CXFSNP_ATTR_UID(cxfsnp_attr) == op_uid
        && CXFSNP_ATTR_GID(cxfsnp_attr) != op_gid
        && 0 == (S_IWGRP & CXFSNP_ATTR_MODE(cxfsnp_attr)))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fusep_truncate: "
                                                 "its ino %lu (uid %u, gid %u, mod %#o), "
                                                 "mod & (S_IWGRP) == 0 "
                                                 "=> deny (uid %u, gid %u)\n",
                                                 ino,
                                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                 op_uid, op_gid);
            return -EACCES;
        }

        if(CXFSNP_ATTR_UID(cxfsnp_attr) != op_uid
        && CXFSNP_ATTR_GID(cxfsnp_attr) == op_gid
        && 0 == (S_IXGRP & CXFSNP_ATTR_MODE(cxfsnp_attr)))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fusep_truncate: "
                                                 "its ino %lu (uid %u, gid %u, mod %#o), "
                                                 "mod & (S_IXGRP) == 0 "
                                                 "=> deny (uid %u, gid %u)\n",
                                                 ino,
                                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                 op_uid, op_gid);
            return -EACCES;
        }

        if(CXFSNP_ATTR_UID(cxfsnp_attr) != op_uid
        && CXFSNP_ATTR_GID(cxfsnp_attr) != op_gid
        && 0 == (S_IWOTH & CXFSNP_ATTR_MODE(cxfsnp_attr)))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fusep_truncate: "
                                                 "its ino %lu (uid %u, gid %u, mod %#o), "
                                                 "mod & (S_IWOTH) == 0 "
                                                 "=> deny (uid %u, gid %u)\n",
                                                 ino,
                                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                 op_uid, op_gid);
            return -EACCES;
        }
    }

    if(NULL_PTR != cxfsnp_item /*file exist*/
    && 0 != op_uid && 0 != op_gid) /*not root*/
    {
        cxfsnp_attr = CXFSNP_ITEM_ATTR(cxfsnp_item);

        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fusep_truncate: "
                                             "its ino %lu (uid %u, gid %u, mod %#o), "
                                             "op (uid %u, gid %u)\n",
                                             ino,
                                             CXFSNP_ATTR_UID(cxfsnp_attr),
                                             CXFSNP_ATTR_GID(cxfsnp_attr),
                                             CXFSNP_ATTR_MODE(cxfsnp_attr),
                                             op_uid, op_gid);

        if(CXFSNP_ATTR_UID(cxfsnp_attr) == op_uid
        && CXFSNP_ATTR_GID(cxfsnp_attr) == op_gid
        && 0 == (S_IWUSR & CXFSNP_ATTR_MODE(cxfsnp_attr)))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fusep_truncate: "
                                                 "its ino %lu (uid %u, gid %u, mod %#o), "
                                                 "mod & (S_IWUSR) == 0 "
                                                 "=> deny (uid %u, gid %u)\n",
                                                 ino,
                                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                 op_uid, op_gid);
            return -EACCES;
        }

        if(CXFSNP_ATTR_UID(cxfsnp_attr) == op_uid
        && CXFSNP_ATTR_GID(cxfsnp_attr) != op_gid
        && 0 == (S_IWGRP & CXFSNP_ATTR_MODE(cxfsnp_attr)))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fusep_truncate: "
                                                 "its ino %lu (uid %u, gid %u, mod %#o), "
                                                 "mod & (S_IWGRP) == 0 "
                                                 "=> deny (uid %u, gid %u)\n",
                                                 ino,
                                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                 op_uid, op_gid);
            return -EACCES;
        }

        if(CXFSNP_ATTR_UID(cxfsnp_attr) != op_uid
        && CXFSNP_ATTR_GID(cxfsnp_attr) == op_gid
        && 0 == (S_IXGRP & CXFSNP_ATTR_MODE(cxfsnp_attr)))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fusep_truncate: "
                                                 "its ino %lu (uid %u, gid %u, mod %#o), "
                                                 "mod & (S_IXGRP) == 0 "
                                                 "=> deny (uid %u, gid %u)\n",
                                                 ino,
                                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                 op_uid, op_gid);
            return -EACCES;
        }

        if(CXFSNP_ATTR_UID(cxfsnp_attr) != op_uid
        && CXFSNP_ATTR_GID(cxfsnp_attr) != op_gid
        && 0 == (S_IWOTH & CXFSNP_ATTR_MODE(cxfsnp_attr)))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fusep_truncate: "
                                                 "its ino %lu (uid %u, gid %u, mod %#o), "
                                                 "mod & (S_IWOTH) == 0 "
                                                 "=> deny (uid %u, gid %u)\n",
                                                 ino,
                                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                 op_uid, op_gid);
            return -EACCES;
        }
    }

    if(0 != op_uid && 0 != op_gid) /*not root*/
    {
        CXFSNP_ITEM     *parent_cxfsnp_item;
        CXFSNP_ATTR     *parent_cxfsnp_attr;
        uint64_t         parent_ino;

        parent_ino = CXFSNP_ATTR_INO_MAKE(CXFSNP_ATTR_INO_FETCH_NP_ID(ino),
                                          CXFSNP_ITEM_PARENT_POS(cxfsnp_item));

        parent_cxfsnp_item = cxfsnp_mgr_fetch_item(cxfsnp_mgr, parent_ino);
        if(NULL_PTR == parent_cxfsnp_item)
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fusep_truncate: "
                                                 "lookup parent of %lu failed\n",
                                                 ino);
            return -ENOENT;
        }
        parent_cxfsnp_attr = CXFSNP_ITEM_ATTR(parent_cxfsnp_item);

        if(CXFS_FUSEP_UID_ERR == op_uid)
        {
            if(CXFSNP_ATTR_UID(parent_cxfsnp_attr) != op_uid)
            {
                /*warning: split into 2 logs to avoid si parser complain complex :-(*/

                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fusep_truncate: "
                                                     "its ino %lu (uid %u, gid %u, mod %#o)\n",
                                                     ino,
                                                     CXFSNP_ATTR_UID(cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(cxfsnp_attr));

                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fusep_truncate: "
                                                     "parent ino %lu (uid %u, gid %u, mod %#o), "
                                                     "uid not matched "
                                                     "=> deny (uid %u, gid %u)\n",
                                                     parent_ino,
                                                     CXFSNP_ATTR_UID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(parent_cxfsnp_attr),
                                                     op_uid, op_gid);
                return -EACCES;
            }
        }
        else
        {
            if(CXFSNP_ATTR_UID(parent_cxfsnp_attr) == op_uid
            && 0 == (S_IWUSR & CXFSNP_ATTR_MODE(parent_cxfsnp_attr)))
            {
                /*warning: split into 2 logs to avoid si parser complain complex :-(*/

                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fusep_truncate: "
                                                     "its ino %lu (uid %u, gid %u, mod %#o)\n",
                                                     ino,
                                                     CXFSNP_ATTR_UID(cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(cxfsnp_attr));

                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fusep_truncate: "
                                                     "parent ino %lu (uid %u, gid %u, mod %#o), "
                                                     "parent mode & (S_IWUSR) == 0 "
                                                     "=> deny (uid %u, gid %u)\n",
                                                     parent_ino,
                                                     CXFSNP_ATTR_UID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(parent_cxfsnp_attr),
                                                     op_uid, op_gid);
                return -EACCES;
            }

            if(CXFSNP_ATTR_UID(parent_cxfsnp_attr) != op_uid
            && 0 == (S_IXOTH & CXFSNP_ATTR_MODE(parent_cxfsnp_attr)))
            {
                /*warning: split into 2 logs to avoid si parser complain complex :-(*/

                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fusep_truncate: "
                                                     "its ino %lu (uid %u, gid %u, mod %#o)\n",
                                                     ino,
                                                     CXFSNP_ATTR_UID(cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(cxfsnp_attr));

                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fusep_truncate: "
                                                     "parent ino %lu (uid %u, gid %u, mod %#o), "
                                                     "parent mode & (S_IXOTH) == 0 "
                                                     "=> deny (uid %u, gid %u)\n",
                                                     parent_ino,
                                                     CXFSNP_ATTR_UID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(parent_cxfsnp_attr),
                                                     op_uid, op_gid);

                return -EACCES;
            }
        }

        if(CXFS_FUSEP_GID_ERR == op_gid)
        {
            if(CXFSNP_ATTR_GID(parent_cxfsnp_attr) != op_gid)
            {
                /*warning: split into 2 logs to avoid si parser complain complex :-(*/

                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fusep_truncate: "
                                                     "its ino %lu (uid %u, gid %u, mod %#o)\n",
                                                     ino,
                                                     CXFSNP_ATTR_UID(cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(cxfsnp_attr));

                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fusep_truncate: "
                                                     "parent ino %lu (uid %u, gid %u, mod %#o), "
                                                     "gid not matched "
                                                     "=> deny (uid %u, gid %u)\n",
                                                     parent_ino,
                                                     CXFSNP_ATTR_UID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(parent_cxfsnp_attr),
                                                     op_uid, op_gid);
                return -EOVERFLOW;
            }
        }
        else
        {
            if(0 == (S_IXGRP & CXFSNP_ATTR_MODE(parent_cxfsnp_attr)))
            {
                /*warning: split into 2 logs to avoid si parser complain complex :-(*/

                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fusep_truncate: "
                                                     "its ino %lu (uid %u, gid %u, mod %#o)\n",
                                                     ino,
                                                     CXFSNP_ATTR_UID(cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(cxfsnp_attr));

                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fusep_truncate: "
                                                     "parent ino %lu (uid %u, gid %u, mod %#o), "
                                                     "parent mode & (S_IXGRP) == 0 "
                                                     "=> deny (uid %u, gid %u)\n",
                                                     parent_ino,
                                                     CXFSNP_ATTR_UID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(parent_cxfsnp_attr),
                                                     op_uid, op_gid);

                return -EACCES;
            }
        }
    }

    return 0;
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
int cxfs_fusep_open(CXFSNP_MGR *cxfsnp_mgr, const uint64_t ino, const uint32_t flags, const uint32_t op_uid, const uint32_t op_gid)
{
    CXFSNP_ITEM     *cxfsnp_item;
    CXFSNP_ATTR     *cxfsnp_attr;

    uint32_t         accmode;

    cxfsnp_item = cxfsnp_mgr_fetch_item(cxfsnp_mgr, ino);
    if(NULL_PTR == cxfsnp_item)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fusep_open: "
                                             "ino %lu not exist\n",
                                             ino);
        return -ENOENT;
    }
    cxfsnp_attr = CXFSNP_ITEM_ATTR(cxfsnp_item);

    if(((uint32_t)flags) & O_TRUNC)
    {
        accmode = O_WRONLY;

        if(EC_FALSE == __cxfs_fusep_check_access(cxfsnp_mgr, ino, accmode, op_uid, op_gid))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fusep_open: "
                                                 "ino %lu (uid %u, gid %u, mod %#o), "
                                                 "accmode %#o, "
                                                 "=> deny (uid %u, gid %u)\n",
                                                 ino,
                                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                 accmode, op_uid, op_gid);
            return -EACCES;
        }

        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "[DEBUG] cxfs_fusep_open: "
                                             "ino %lu (uid %u, gid %u, mod %#o) "
                                             "=> truncate to length 0\n",
                                             ino,
                                             CXFSNP_ATTR_UID(cxfsnp_attr),
                                             CXFSNP_ATTR_GID(cxfsnp_attr),
                                             CXFSNP_ATTR_MODE(cxfsnp_attr));

        return cxfs_fusep_truncate(cxfsnp_mgr, ino, op_uid, op_gid);
    }

    accmode = (((uint32_t)flags) & O_ACCMODE);
    if(O_ACCMODE <= accmode)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fusep_open: "
                                             "ino %lu (uid %u, gid %u, mod %#o), "
                                             "flags %#x & O_ACCMODE = %#x >= O_ACCMODE "
                                             "=> invalid flags\n",
                                             ino,
                                             CXFSNP_ATTR_UID(cxfsnp_attr),
                                             CXFSNP_ATTR_GID(cxfsnp_attr),
                                             CXFSNP_ATTR_MODE(cxfsnp_attr),
                                             (uint32_t)flags,
                                             accmode);


        return -EINVAL;
    }

    if(EC_FALSE == __cxfs_fusep_check_access(cxfsnp_mgr, ino, accmode, op_uid, op_gid))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fusep_open: "
                                             "ino %lu (uid %u, gid %u, mod %#o), "
                                             "accmode %#o "
                                             "=> deny (uid %u, gid %u)\n",
                                             ino,
                                             CXFSNP_ATTR_UID(cxfsnp_attr),
                                             CXFSNP_ATTR_GID(cxfsnp_attr),
                                             CXFSNP_ATTR_MODE(cxfsnp_attr),
                                             accmode,
                                             op_uid, op_gid);
        return -EACCES;
    }

    dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "[DEBUG] cxfs_fusep_open: "
                                         "ino %u (uid %u, gid %u, mod %#o), "
                                         "accmode %#o "
                                         "=> accept (uid %u, gid %u)\n",
                                         ino,
                                         CXFSNP_ATTR_UID(cxfsnp_attr),
                                         CXFSNP_ATTR_GID(cxfsnp_attr),
                                         CXFSNP_ATTR_MODE(cxfsnp_attr),
                                         accmode,
                                         op_uid, op_gid);
    return 0;
}


int cxfs_fusep_create(CXFSNP_MGR *cxfsnp_mgr, const uint64_t parent_ino, const uint16_t mode, const uint32_t op_uid, const uint32_t op_gid)
{
    if(0 != op_uid && 0 != op_gid) /*not root*/
    {
        CXFSNP_ITEM     *parent_cxfsnp_item;
        CXFSNP_ATTR     *parent_cxfsnp_attr;

        parent_cxfsnp_item = cxfsnp_mgr_fetch_item(cxfsnp_mgr, parent_ino);
        if(NULL_PTR == parent_cxfsnp_item)
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fusep_create: "
                                                 "lookup parent %lu failed\n",
                                                 parent_ino);
            return -ENOENT;
        }
        parent_cxfsnp_attr = CXFSNP_ITEM_ATTR(parent_cxfsnp_item);

        if(CXFS_FUSEP_UID_ERR == op_uid)
        {
            if(CXFSNP_ATTR_UID(parent_cxfsnp_attr) == op_uid
            && CXFSNP_ATTR_GID(parent_cxfsnp_attr) != op_gid
            && 0 == (S_IWUSR & CXFSNP_ATTR_MODE(parent_cxfsnp_attr)))
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_create: "
                                                     "parent ino %lu (gid %u, gid %u, mode %#o), "
                                                     "parent mode & (S_IWUSR) == 0 "
                                                     "=> deny (gid %u, gid %u, mode %#o)\n",
                                                     parent_ino,
                                                     CXFSNP_ATTR_UID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(parent_cxfsnp_attr),
                                                     op_uid, op_gid, mode);

                return -EACCES;
            }

            if(CXFSNP_ATTR_UID(parent_cxfsnp_attr) != op_uid
            && CXFSNP_ATTR_GID(parent_cxfsnp_attr) != op_gid
            && 0 == (S_IWOTH & CXFSNP_ATTR_MODE(parent_cxfsnp_attr)))
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_create: "
                                                     "parent ino %lu (gid %u, gid %u, mode %#o), "
                                                     "parent mode & (S_IWOTH) == 0 "
                                                     "=> deny (gid %u, gid %u, mode %#o)\n",
                                                     parent_ino,
                                                     CXFSNP_ATTR_UID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(parent_cxfsnp_attr),
                                                     op_uid, op_gid, mode);
                return -EACCES;
            }
        }
        else
        {
            if(CXFSNP_ATTR_UID(parent_cxfsnp_attr) == op_uid
            && 0 == (S_IWUSR & CXFSNP_ATTR_MODE(parent_cxfsnp_attr)))
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_create: "
                                                     "parent ino %lu (gid %u, gid %u, mode %#o), "
                                                     "parent mode & (S_IWUSR) == 0 "
                                                     "=> deny (gid %u, gid %u, mode %#o)\n",
                                                     parent_ino,
                                                     CXFSNP_ATTR_UID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(parent_cxfsnp_attr),
                                                     op_uid, op_gid, mode);
                return -EACCES;
            }

            if(CXFSNP_ATTR_UID(parent_cxfsnp_attr) != op_uid
            && 0 == (S_IXOTH & CXFSNP_ATTR_MODE(parent_cxfsnp_attr)))
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_create: "
                                                     "parent ino %lu (gid %u, gid %u, mode %#o), "
                                                     "parent mode & (S_IXOTH) == 0 "
                                                     "=> deny (gid %u, gid %u, mode %#o)\n",
                                                     parent_ino,
                                                     CXFSNP_ATTR_UID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(parent_cxfsnp_attr),
                                                     op_uid, op_gid, mode);

                return -EACCES;
            }

            if(CXFSNP_ATTR_UID(parent_cxfsnp_attr) != op_uid
            && 0 == (S_IWOTH & CXFSNP_ATTR_MODE(parent_cxfsnp_attr)))
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_create: "
                                                     "parent ino %lu (gid %u, gid %u, mode %#o), "
                                                     "parent mode & (S_IWOTH) == 0 "
                                                     "=> deny (gid %u, gid %u, mode %#o)\n",
                                                     parent_ino,
                                                     CXFSNP_ATTR_UID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(parent_cxfsnp_attr),
                                                     op_uid, op_gid, mode);

                return -EACCES;
            }
        }

        if(CXFS_FUSEP_GID_ERR == op_gid)
        {
            if(CXFSNP_ATTR_GID(parent_cxfsnp_attr) != op_gid)
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_create: "
                                                     "parent ino %lu (gid %u, gid %u, mode %#o), "
                                                     "op gid overflow "
                                                     "=> deny (gid %u, gid %u, mode %#o)\n",
                                                     parent_ino,
                                                     CXFSNP_ATTR_UID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(parent_cxfsnp_attr),
                                                     op_uid, op_gid, mode);
                return -EOVERFLOW;
            }
        }
        else
        {
            if(0 == (S_IXGRP & CXFSNP_ATTR_MODE(parent_cxfsnp_attr)))
            {
                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_create: "
                                                     "parent ino %lu (gid %u, gid %u, mode %#o), "
                                                     "parent mode & (S_IXGRP) == 0 "
                                                     "=> deny (gid %u, gid %u, mode %#o)\n",
                                                     parent_ino,
                                                     CXFSNP_ATTR_UID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(parent_cxfsnp_attr),
                                                     op_uid, op_gid, mode);

                return -EACCES;
            }
        }
    }

    dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_create: "
                                         "parent ino %lu , "
                                         "=> accept (gid %u, gid %u, mode %#o)\n",
                                         parent_ino,
                                         op_uid, op_gid, mode);

    return 0;
}


int cxfs_fusep_access(CXFSNP_MGR *cxfsnp_mgr, const uint64_t ino, const uint16_t mask)
{
    CXFSNP_ITEM     *cxfsnp_item;
    CXFSNP_ATTR     *cxfsnp_attr;

    if(0 != (mask & (~(R_OK|W_OK|X_OK|F_OK))))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fusep_access: "
                                             "invalid mask %#x\n",
                                             mask);
        return -EINVAL;
    }

    cxfsnp_item = cxfsnp_mgr_fetch_item(cxfsnp_mgr, ino);
    if(NULL_PTR == cxfsnp_item)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fusep_access: "
                                             "ino %lu fetch item failed\n",
                                             ino);
        return -ENOENT;
    }
    cxfsnp_attr = CXFSNP_ITEM_ATTR(cxfsnp_item);

    if(mask == (CXFSNP_ATTR_MODE(cxfsnp_attr) & mask))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "[DEBUG] cxfs_fusep_access: "
                                             "ino %lu (uid %u, gid %u, mode %#o), "
                                             "mask %#o"
                                             "mode & mask == mask\n",
                                             ino,
                                             CXFSNP_ATTR_UID(cxfsnp_attr),
                                             CXFSNP_ATTR_GID(cxfsnp_attr),
                                             CXFSNP_ATTR_MODE(cxfsnp_attr),
                                             mask);
        return 0;
    }

    dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "[DEBUG] cxfs_fusep_access: "
                                         "ino %lu (uid %u, gid %u, mode %#o), "
                                         "mask %#o"
                                         "mode & mask != mask "
                                         "=> deny\n",
                                         ino,
                                         CXFSNP_ATTR_UID(cxfsnp_attr),
                                         CXFSNP_ATTR_GID(cxfsnp_attr),
                                         CXFSNP_ATTR_MODE(cxfsnp_attr),
                                         mask);

    return -EACCES;
}


int cxfs_fusep_ftruncate(CXFSNP_MGR *cxfsnp_mgr, const uint64_t ino, const uint32_t op_uid, const uint32_t op_gid)
{
    return cxfs_fusep_truncate(cxfsnp_mgr, ino, op_uid, op_gid);
}

int cxfs_fusep_utimens(CXFSNP_MGR *cxfsnp_mgr, const uint64_t ino, const struct timespec *tv0, const struct timespec *tv1, const uint32_t op_uid, const uint32_t op_gid)
{
    CXFSNP_ITEM     *cxfsnp_item;
    CXFSNP_ATTR     *cxfsnp_attr;

    cxfsnp_item = cxfsnp_mgr_fetch_item(cxfsnp_mgr, ino);
    if(NULL_PTR == cxfsnp_item)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fusep_utimens: "
                                             "ino %lu fetch item failed\n",
                                             ino);
        return -ENOENT;
    }
    cxfsnp_attr = CXFSNP_ITEM_ATTR(cxfsnp_item);

    dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_utimens: "
                                         "its ino %lu (uid %u, gid %u, mode %#o), "
                                         "op (uid %u, gid %u)\n",
                                         ino,
                                         CXFSNP_ATTR_UID(cxfsnp_attr),
                                         CXFSNP_ATTR_GID(cxfsnp_attr),
                                         CXFSNP_ATTR_MODE(cxfsnp_attr),
                                         op_uid, op_gid);


    if(CXFS_FUSEP_UID_NOBODY == op_uid && 0 == op_gid
    && (0 == CXFSNP_ATTR_UID(cxfsnp_attr)
       && 0 == CXFSNP_ATTR_GID(cxfsnp_attr)))
    {
        CXFSNP_ITEM     *parent_cxfsnp_item;
        CXFSNP_ATTR     *parent_cxfsnp_attr;
        uint64_t         parent_ino;

        parent_ino = CXFSNP_ATTR_INO_MAKE(CXFSNP_ATTR_INO_FETCH_NP_ID(ino),
                                          CXFSNP_ITEM_PARENT_POS(cxfsnp_item));

        parent_cxfsnp_item = cxfsnp_mgr_fetch_item(cxfsnp_mgr, parent_ino);
        if(NULL_PTR == parent_cxfsnp_item)
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fusep_utimens: "
                                                 "fetch parent of %lu failed\n",
                                                 ino);
            return -ENOENT;
        }
        parent_cxfsnp_attr = CXFSNP_ITEM_ATTR(parent_cxfsnp_item);

        if(CXFSNP_ATTR_UID(parent_cxfsnp_attr) != op_uid
        && 0 == CXFSNP_ATTR_UID(parent_cxfsnp_attr)
        && 0 == (S_IXGRP & CXFSNP_ATTR_MODE(parent_cxfsnp_attr)))
        {
            /*warning: split into 2 logs to avoid si parser complain complex :-(*/

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_utimens: "
                                                 "its ino %lu (uid %u, gid %u, mode %#o)\n",
                                                 ino,
                                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr));

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_utimens: "
                                                 "parent ino %lu (uid %u, gid %u, mode %#o), "
                                                 "parent mode & (S_IXGRP) == 0 "
                                                 "=> deny (uid %u, gid %u)\n",
                                                 parent_ino,
                                                 CXFSNP_ATTR_UID(parent_cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(parent_cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(parent_cxfsnp_attr),
                                                 op_uid, op_gid);

            return -EACCES;
        }
    }

    if(0 != op_uid && 0 == op_gid
    && (CXFSNP_ATTR_UID(cxfsnp_attr) != op_uid
       || CXFSNP_ATTR_GID(cxfsnp_attr) != op_gid))
    {
        if(0 == CXFSNP_ATTR_UID(cxfsnp_attr)
        && 0 == CXFSNP_ATTR_GID(cxfsnp_attr)
        && 0 == (S_IXGRP & CXFSNP_ATTR_MODE(cxfsnp_attr)))
        {
            if(0 == (S_IWGRP & CXFSNP_ATTR_MODE(cxfsnp_attr)))
            {
                if(UTIME_NOW == tv0->tv_nsec || UTIME_NOW == tv1->tv_nsec)
                {
                    dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_utimens: "
                                                         "its ino %lu (uid %u, gid %u, mode %#o), "
                                                         "mode & (S_IXGRP) == 0 && mode & (S_IWGRP) == 0 && UTIME_NOW "
                                                         "=> deny (uid %u, gid %u)\n",
                                                         ino,
                                                         CXFSNP_ATTR_UID(cxfsnp_attr),
                                                         CXFSNP_ATTR_GID(cxfsnp_attr),
                                                         CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                         op_uid, op_gid);

                    return -EACCES;
                }
                else
                {
                    dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_utimens: "
                                                         "its ino %lu (uid %u, gid %u, mode %#o), "
                                                         "mode & (S_IXGRP) == 0 && mode & (S_IWGRP) == 0 && NOT UTIME_NOW "
                                                         "=> deny (uid %u, gid %u)\n",
                                                         ino,
                                                         CXFSNP_ATTR_UID(cxfsnp_attr),
                                                         CXFSNP_ATTR_GID(cxfsnp_attr),
                                                         CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                         op_uid, op_gid);
                    return -EPERM;
                }
            }
            else
            {
                if(UTIME_NOW != tv0->tv_nsec && UTIME_NOW != tv1->tv_nsec)
                {
                    dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_utimens: "
                                                         "its ino %lu (uid %u, gid %u, mode %#o), "
                                                         "mode & (S_IXGRP) == 0 && mode & (S_IWGRP) != 0 && NOT UTIME_NOW "
                                                         "=> deny (uid %u, gid %u)\n",
                                                         ino,
                                                         CXFSNP_ATTR_UID(cxfsnp_attr),
                                                         CXFSNP_ATTR_GID(cxfsnp_attr),
                                                         CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                         op_uid, op_gid);

                    return -EPERM;
                }
            }
        }

        if(CXFSNP_ATTR_UID(cxfsnp_attr) != op_uid
        && 0 == (S_IWOTH & CXFSNP_ATTR_MODE(cxfsnp_attr)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_utimens: "
                                                 "its ino %lu (uid %u, gid %u, mode %#o), "
                                                 "mode & (S_IWOTH) == 0 "
                                                 "=> deny (uid %u, gid %u)\n",
                                                 ino,
                                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                 op_uid, op_gid);

            return -EACCES;
        }
    }

    if(0 != op_uid && 0 != op_gid /*not root*/
    && (CXFSNP_ATTR_UID(cxfsnp_attr) == op_uid
       && CXFSNP_ATTR_GID(cxfsnp_attr) == op_gid))
    {
        CXFSNP_ITEM     *parent_cxfsnp_item;
        CXFSNP_ATTR     *parent_cxfsnp_attr;
        uint64_t         parent_ino;

        parent_ino = CXFSNP_ATTR_INO_MAKE(CXFSNP_ATTR_INO_FETCH_NP_ID(ino),
                                          CXFSNP_ITEM_PARENT_POS(cxfsnp_item));

        parent_cxfsnp_item = cxfsnp_mgr_fetch_item(cxfsnp_mgr, parent_ino);
        if(NULL_PTR == parent_cxfsnp_item)
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fusep_utimens: "
                                                 "fetch parent of '%s' failed\n",
                                                 ino);
            return -ENOENT;
        }
        parent_cxfsnp_attr = CXFSNP_ITEM_ATTR(parent_cxfsnp_item);

        if(CXFSNP_ATTR_UID(parent_cxfsnp_attr) != op_uid
        && 0 == (S_IXOTH & CXFSNP_ATTR_MODE(parent_cxfsnp_attr)))
        {
            /*warning: split into 2 logs to avoid si parser complain complex :-(*/

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_utimens: "
                                                 "its ino %lu (uid %u, gid %u, mode %#o)\n",
                                                 ino,
                                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr));

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_utimens: "
                                                 "parent ino %lu (uid %u, gid %u, mode %#o), "
                                                 "parent mode & (S_IXOTH) == 0"
                                                 "=> deny (uid %u, gid %u)\n",
                                                 parent_ino,
                                                 CXFSNP_ATTR_UID(parent_cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(parent_cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(parent_cxfsnp_attr),
                                                 op_uid, op_gid);

            return -EACCES;
        }

        if(CXFSNP_ATTR_UID(parent_cxfsnp_attr) == op_uid
        && 0 == (S_IWUSR & CXFSNP_ATTR_MODE(parent_cxfsnp_attr)))
        {
            /*warning: split into 2 logs to avoid si parser complain complex :-(*/

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_utimens: "
                                                 "its ino %lu (uid %u, gid %u, mode %#o)\n",
                                                 ino,
                                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr));

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_utimens: "
                                                 "parent ino %lu (uid %u, gid %u, mode %#o), "
                                                 "parent mode & (S_IWUSR) == 0"
                                                 "=> deny (uid %u, gid %u)\n",
                                                 parent_ino,
                                                 CXFSNP_ATTR_UID(parent_cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(parent_cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(parent_cxfsnp_attr),
                                                 op_uid, op_gid);

            return -EACCES;
        }

        if(CXFSNP_ATTR_UID(parent_cxfsnp_attr) == op_uid
        && 0 == (S_IXUSR & CXFSNP_ATTR_MODE(parent_cxfsnp_attr)))
        {
            /*warning: split into 2 logs to avoid si parser complain complex :-(*/

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_utimens: "
                                                 "its ino %lu (uid %u, gid %u, mode %#o)\n",
                                                 ino,
                                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr));

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_utimens: "
                                                 "parent ino %lu (uid %u, gid %u, mode %#o), "
                                                 "parent mode & (S_IXUSR) == 0"
                                                 "=> deny (uid %u, gid %u)\n",
                                                 parent_ino,
                                                 CXFSNP_ATTR_UID(parent_cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(parent_cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(parent_cxfsnp_attr),
                                                 op_uid, op_gid);

            return -EACCES;
        }
    }

    if(0 != op_uid && 0 != op_gid /*not root*/
    && (CXFSNP_ATTR_UID(cxfsnp_attr) != op_uid
       || CXFSNP_ATTR_GID(cxfsnp_attr) != op_gid))
    {
        if(CXFSNP_ATTR_UID(cxfsnp_attr) != op_uid
        && CXFSNP_ATTR_GID(cxfsnp_attr) != op_gid
        && 0 == (S_IXOTH & CXFSNP_ATTR_MODE(cxfsnp_attr)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_utimens: "
                                                 "its ino %lu (uid %u, gid %u, mode %#o), "
                                                 "mode & (S_IXOTH) == 0"
                                                 "=> deny (uid %u, gid %u)\n",
                                                 ino,
                                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                 op_uid, op_gid);

            return -EACCES;
        }

        if(CXFSNP_ATTR_UID(cxfsnp_attr) != op_uid
        && CXFSNP_ATTR_GID(cxfsnp_attr) != op_gid
        && 0 == (S_IWOTH & CXFSNP_ATTR_MODE(cxfsnp_attr)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_utimens: "
                                                 "its ino %lu (uid %u, gid %u, mode %#o), "
                                                 "mode & (S_IWOTH) == 0"
                                                 "=> deny (uid %u, gid %u)\n",
                                                 ino,
                                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                 op_uid, op_gid);

            return -EACCES;
        }

        if(CXFSNP_ATTR_UID(cxfsnp_attr) == op_uid
        && CXFSNP_ATTR_GID(cxfsnp_attr) != op_gid
        && 0 == (S_IXGRP & CXFSNP_ATTR_MODE(cxfsnp_attr)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_utimens: "
                                                 "its ino %lu (uid %u, gid %u, mode %#o), "
                                                 "mode & (S_IXGRP) == 0"
                                                 "=> deny (uid %u, gid %u)\n",
                                                 ino,
                                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                 op_uid, op_gid);

            return -EACCES;
        }

        if(CXFSNP_ATTR_UID(cxfsnp_attr) == op_uid
        && CXFSNP_ATTR_GID(cxfsnp_attr) != op_gid
        && 0 == (S_IWGRP & CXFSNP_ATTR_MODE(cxfsnp_attr)))
        {
            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_utimens: "
                                                 "its ino %lu (uid %u, gid %u, mode %#o), "
                                                 "mode & (S_IWGRP) == 0"
                                                 "=> deny (uid %u, gid %u)\n",
                                                 ino,
                                                 CXFSNP_ATTR_UID(cxfsnp_attr),
                                                 CXFSNP_ATTR_GID(cxfsnp_attr),
                                                 CXFSNP_ATTR_MODE(cxfsnp_attr),
                                                 op_uid, op_gid);

            return -EACCES;
        }
    }

    if(0 != op_uid && 0 != op_gid /*not root*/
    && (CXFSNP_ATTR_UID(cxfsnp_attr) != op_uid
       || CXFSNP_ATTR_GID(cxfsnp_attr) != op_gid))
    {
        CXFSNP_ITEM     *parent_cxfsnp_item;
        CXFSNP_ATTR     *parent_cxfsnp_attr;
        uint64_t         parent_ino;

        parent_ino = CXFSNP_ATTR_INO_MAKE(CXFSNP_ATTR_INO_FETCH_NP_ID(ino),
                                          CXFSNP_ITEM_PARENT_POS(cxfsnp_item));

        parent_cxfsnp_item = cxfsnp_mgr_fetch_item(cxfsnp_mgr, parent_ino);
        if(NULL_PTR == parent_cxfsnp_item)
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fusep_utimens: "
                                                 "lookup parent of %lu failed\n",
                                                 ino);
            return -ENOENT;
        }
        parent_cxfsnp_attr = CXFSNP_ITEM_ATTR(parent_cxfsnp_item);

        if(CXFS_FUSEP_UID_ERR == op_uid)
        {
            if(CXFSNP_ATTR_UID(parent_cxfsnp_attr) != op_uid)
            {
                /*warning: split into 2 logs to avoid si parser complain complex :-(*/

                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_utimens: "
                                                     "its ino %lu (uid %u, gid %u, mode %#o)\n",
                                                     ino,
                                                     CXFSNP_ATTR_UID(cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(cxfsnp_attr));

                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_utimens: "
                                                     "parent ino %lu (uid %u, gid %u, mode %#o), "
                                                     "uid not matched "
                                                     "=> deny (uid %u, gid %u)\n",
                                                     parent_ino,
                                                     CXFSNP_ATTR_UID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(parent_cxfsnp_attr),
                                                     op_uid, op_gid);
                return -EACCES;
            }
        }
        else
        {
            if(CXFSNP_ATTR_UID(parent_cxfsnp_attr) != op_uid)
            {
                /*warning: split into 2 logs to avoid si parser complain complex :-(*/

                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_utimens: "
                                                     "its ino %lu (uid %u, gid %u, mode %#o)\n",
                                                     ino,
                                                     CXFSNP_ATTR_UID(cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(cxfsnp_attr));

                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_utimens: "
                                                     "parent ino %lu (uid %u, gid %u, mode %#o), "
                                                     "uid not matched "
                                                     "=> deny (uid %u, gid %u)\n",
                                                     parent_ino,
                                                     CXFSNP_ATTR_UID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(parent_cxfsnp_attr),
                                                     op_uid, op_gid);
                return -EACCES;
            }

            if(CXFSNP_ATTR_UID(parent_cxfsnp_attr) == op_uid
            && 0 == (S_IWUSR & CXFSNP_ATTR_MODE(parent_cxfsnp_attr)))
            {
                /*warning: split into 2 logs to avoid si parser complain complex :-(*/

                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_utimens: "
                                                     "its ino %lu (uid %u, gid %u, mode %#o)\n",
                                                     ino,
                                                     CXFSNP_ATTR_UID(cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(cxfsnp_attr));

                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_utimens: "
                                                     "parent ino %lu (uid %u, gid %u, mode %#o), "
                                                     "parent mode & (S_IWUSR) == 0 "
                                                     "=> deny (uid %u, gid %u)\n",
                                                     parent_ino,
                                                     CXFSNP_ATTR_UID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(parent_cxfsnp_attr),
                                                     op_uid, op_gid);

                return -EACCES;
            }

            if(CXFSNP_ATTR_UID(parent_cxfsnp_attr) != op_uid
            && 0 == (S_IXOTH & CXFSNP_ATTR_MODE(parent_cxfsnp_attr)))
            {
                /*warning: split into 2 logs to avoid si parser complain complex :-(*/

                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_utimens: "
                                                     "its ino %lu (uid %u, gid %u, mode %#o)\n",
                                                     ino,
                                                     CXFSNP_ATTR_UID(cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(cxfsnp_attr));

                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_utimens: "
                                                     "parent ino %lu (uid %u, gid %u, mode %#o), "
                                                     "parent mode & (S_IXOTH) == 0 "
                                                     "=> deny (uid %u, gid %u)\n",
                                                     parent_ino,
                                                     CXFSNP_ATTR_UID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(parent_cxfsnp_attr),
                                                     op_uid, op_gid);

                return -EACCES;
            }
        }

        if(CXFS_FUSEP_GID_ERR == op_gid)
        {
            if(CXFSNP_ATTR_GID(parent_cxfsnp_attr) != op_gid)
            {
                /*warning: split into 2 logs to avoid si parser complain complex :-(*/

                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_utimens: "
                                                     "its ino %lu (uid %u, gid %u, mode %#o)\n",
                                                     ino,
                                                     CXFSNP_ATTR_UID(cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(cxfsnp_attr));

                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_utimens: "
                                                     "parent ino %lu (uid %u, gid %u, mode %#o), "
                                                     "gid overflow "
                                                     "=> deny (uid %u, gid %u)\n",
                                                     parent_ino,
                                                     CXFSNP_ATTR_UID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(parent_cxfsnp_attr),
                                                     op_uid, op_gid);
                return -EOVERFLOW;
            }
        }
        else
        {
            if(0 == (S_IXGRP & CXFSNP_ATTR_MODE(parent_cxfsnp_attr)))
            {
                /*warning: split into 2 logs to avoid si parser complain complex :-(*/

                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_utimens: "
                                                     "its ino %lu (uid %u, gid %u, mode %#o)\n",
                                                     ino,
                                                     CXFSNP_ATTR_UID(cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(cxfsnp_attr));

                dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fusep_utimens: "
                                                     "parent ino %lu (uid %u, gid %u, mode %#o), "
                                                     "parent mode & (S_IXGRP) == 0 "
                                                     "=> deny (uid %u, gid %u)\n",
                                                     parent_ino,
                                                     CXFSNP_ATTR_UID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_GID(parent_cxfsnp_attr),
                                                     CXFSNP_ATTR_MODE(parent_cxfsnp_attr),
                                                     op_uid, op_gid);

                return -EACCES;
            }
        }
    }

    return 0;
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/
