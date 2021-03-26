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

#if (SWITCH_ON == NGX_BGN_SWITCH)

#include "type.h"
#include "mm.h"
#include "log.h"
#include "cstring.h"
#include "cmisc.h"

#include "carray.h"
#include "cvector.h"

#include "crb.h"

#include "cngx_mod.h"


static CRB_TREE  g_cngx_bgn_mod_mgr_tree;
static EC_BOOL   g_cngx_bgn_mod_mgr_tree_init_flag = EC_FALSE;


/*------------------------------ NGX BGN MODULE MANAGEMENT ------------------------------*/
EC_BOOL cngx_bgn_mod_node_init(CNGX_BGN_MOD_NODE *cngx_bgn_mod_node)
{
    CNGX_BGN_MOD_NODE_DL_LIB(cngx_bgn_mod_node)  = NULL_PTR;

    CNGX_BGN_MOD_NODE_VER(cngx_bgn_mod_node)     = CNGX_BGN_MOD_NODE_VER_ERR;

    CNGX_BGN_MOD_NODE_INDEX(cngx_bgn_mod_node)   = CNGX_BGN_MOD_NODE_INDEX_ERR;
    CNGX_BGN_MOD_NODE_COUNTER(cngx_bgn_mod_node) = 0;

    CNGX_BGN_MOD_NODE_PARENT(cngx_bgn_mod_node)  = NULL_PTR;

    CNGX_BGN_MOD_NODE_REG(cngx_bgn_mod_node)     = NULL_PTR;
    CNGX_BGN_MOD_NODE_UNREG(cngx_bgn_mod_node)   = NULL_PTR;
    CNGX_BGN_MOD_NODE_START(cngx_bgn_mod_node)   = NULL_PTR;
    CNGX_BGN_MOD_NODE_END(cngx_bgn_mod_node)     = NULL_PTR;
    CNGX_BGN_MOD_NODE_GETRC(cngx_bgn_mod_node)   = NULL_PTR;
    CNGX_BGN_MOD_NODE_HANDLE(cngx_bgn_mod_node)  = NULL_PTR;

    return (EC_TRUE);
}

EC_BOOL cngx_bgn_mod_node_clean(CNGX_BGN_MOD_NODE *cngx_bgn_mod_node)
{
    if(NULL_PTR != CNGX_BGN_MOD_NODE_DL_LIB(cngx_bgn_mod_node))
    {
        dlclose(CNGX_BGN_MOD_NODE_DL_LIB(cngx_bgn_mod_node));
        CNGX_BGN_MOD_NODE_DL_LIB(cngx_bgn_mod_node) = NULL_PTR;
    }

    CNGX_BGN_MOD_NODE_VER(cngx_bgn_mod_node)     = CNGX_BGN_MOD_NODE_VER_ERR;

    CNGX_BGN_MOD_NODE_INDEX(cngx_bgn_mod_node)   = CNGX_BGN_MOD_NODE_INDEX_ERR;
    CNGX_BGN_MOD_NODE_COUNTER(cngx_bgn_mod_node) = 0;

    CNGX_BGN_MOD_NODE_PARENT(cngx_bgn_mod_node)  = NULL_PTR;

    CNGX_BGN_MOD_NODE_REG(cngx_bgn_mod_node)     = NULL_PTR;
    CNGX_BGN_MOD_NODE_UNREG(cngx_bgn_mod_node)   = NULL_PTR;
    CNGX_BGN_MOD_NODE_START(cngx_bgn_mod_node)   = NULL_PTR;
    CNGX_BGN_MOD_NODE_END(cngx_bgn_mod_node)     = NULL_PTR;
    CNGX_BGN_MOD_NODE_GETRC(cngx_bgn_mod_node)   = NULL_PTR;
    CNGX_BGN_MOD_NODE_HANDLE(cngx_bgn_mod_node)  = NULL_PTR;

    return (EC_TRUE);
}

void cngx_bgn_mod_node_print(LOG *log, const CNGX_BGN_MOD_NODE *cngx_bgn_mod_node)
{
    if(NULL_PTR != cngx_bgn_mod_node)
    {
        sys_log(log, "cngx_bgn_mod_node_print: "
                     "%p, index %u, counter %u, lib %p, parent %p\n",
                     cngx_bgn_mod_node,
                     CNGX_BGN_MOD_NODE_INDEX(cngx_bgn_mod_node),
                     CNGX_BGN_MOD_NODE_COUNTER(cngx_bgn_mod_node),
                     CNGX_BGN_MOD_NODE_DL_LIB(cngx_bgn_mod_node),
                     CNGX_BGN_MOD_NODE_PARENT(cngx_bgn_mod_node));
    }
    return;
}

STATIC_CAST static char *__cngx_bgn_mod_node_dl_path_latest(const char *dl_path, const uint32_t dl_path_len, uint32_t *version)
{
    DIR             *dp;
    struct dirent   *entry;

    char            *so_name;
    char            *so_path;
    char            *dl_path_latest;

    uint32_t         so_name_len;
    uint32_t         so_path_len;
    uint32_t         ver_val;

    /*check dl_path*/
    if('/' == dl_path[ dl_path_len - 1 ])
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:__cngx_bgn_mod_node_dl_path_latest: "
                                             "invalid dl_path '%.*s' which must not terminate with '/'\n",
                                             dl_path_len, dl_path);
        return (NULL_PTR);
    }

    /*finger out so_name and so_path_len*/
    so_name = strrchr(dl_path, '/');
    if(NULL_PTR == so_name)
    {
        so_name     = (char *)dl_path;
        so_name_len = dl_path_len;

        so_path_len = dl_path_len;
    }
    else
    {
        so_name ++;
        so_name_len = dl_path_len - ((uint32_t)(so_name - dl_path));

        so_path_len = ((uint32_t)(so_name - dl_path - 1));
    }

    dbg_log(SEC_0176_CNGX, 1)(LOGSTDOUT, "[DEBUG] __cngx_bgn_mod_node_dl_path_latest: "
                                         "dl_path '%.*s' => so_name '%.*s' done\n",
                                         dl_path_len, dl_path,
                                         so_name_len, so_name);

    /*check so_path_len*/
    while(0 < so_path_len
    && '/' == dl_path[ so_path_len - 1 ])
    {
        so_path_len --;
    }
    if(0 == so_path_len)
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:__cngx_bgn_mod_node_dl_path_latest: "
                                             "dl_path '%.*s' => so_path_len is zero\n",
                                             dl_path_len, dl_path);
        return (NULL_PTR);
    }

    /*dup so_path*/
    so_path = c_str_n_dup(dl_path, so_path_len);
    if(NULL_PTR == so_path)
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:__cngx_bgn_mod_node_dl_path_latest: "
                                             "dup so_path '%.*s' failed\n",
                                             so_path_len, dl_path);
        return (NULL_PTR);
    }

    dbg_log(SEC_0176_CNGX, 1)(LOGSTDOUT, "[DEBUG] __cngx_bgn_mod_node_dl_path_latest: "
                                         "dl_path '%.*s' => so_path '%.*s'\n",
                                         dl_path_len, dl_path,
                                         so_path_len, so_path);

    dp = opendir(so_path);
    if(NULL_PTR == dp)
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:__cngx_bgn_mod_node_dl_path_latest: "
                                             "open so_path '%.*s' failed\n",
                                             so_path_len, so_path);
        c_str_free(so_path);
        return (NULL_PTR);
    }

    /*init min ver_val*/
    ver_val = 0;

    chdir(so_path);
    while(NULL_PTR != (entry = readdir(dp)))
    {
        struct stat      statbuf;

        lstat(entry->d_name, &statbuf);

        if(S_IFREG & statbuf.st_mode)
        {
            char    *so_name_t;
            char    *ver_str_t;

            uint32_t so_name_t_len;
            uint32_t ver_val_t;

            ver_str_t = strrchr(entry->d_name, '.'); /*cut off ver_val part*/
            if(NULL_PTR == ver_str_t)
            {
                continue;
            }
            ver_str_t ++;

            so_name_t     = entry->d_name;
            so_name_t_len = ver_str_t - entry->d_name - 1;

            if(so_name_len != so_name_t_len
            || 0 != STRNCMP(so_name, so_name_t, so_name_t_len))
            {
                continue;
            }

            if(EC_FALSE == c_str_is_digit(ver_str_t))
            {
                continue;
            }

            ver_val_t = c_str_to_uint32_t(ver_str_t);
            if(ver_val_t > ver_val)
            {
                ver_val = ver_val_t;
            }

            dbg_log(SEC_0176_CNGX, 1)(LOGSTDOUT, "[DEBUG] __cngx_bgn_mod_node_dl_path_latest: "
                               "[matched] %s, so_name %.*s, ver str %s (%u) => ver_val: %u\n",
                               entry->d_name,
                               so_name_t_len, so_name_t,
                               ver_str_t, ver_val_t,
                               ver_val);
            continue;
        }
    }

    closedir(dp);

    c_str_free(so_path);

    if(NULL_PTR != version)
    {
        (*version) = ver_val;
    }

    if(0 == ver_val) /*keep unchanged*/
    {
        dl_path_latest = c_str_n_dup(dl_path, dl_path_len);
        if(NULL_PTR == dl_path_latest)
        {
            dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:__cngx_bgn_mod_node_dl_path_latest: "
                                                 "dup dl_path_latest '%.*s' failed\n",
                                                 dl_path_len, dl_path);
            return (NULL_PTR);
        }

        return (dl_path_latest);
    }
    else /*cat version*/
    {
        char             ver_str[32];

        snprintf(ver_str, sizeof(ver_str) - 1, ".%u", ver_val);
        dl_path_latest = c_str_cat(dl_path, (char *)ver_str);

        if(NULL_PTR == dl_path_latest)
        {
            dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:__cngx_bgn_mod_node_dl_path_latest: "
                                                 "cat '%.*s''.%u' failed\n",
                                                 dl_path_len, dl_path,
                                                 ver_val);
            return (NULL_PTR);
        }
    }

    return (dl_path_latest);
}

EC_BOOL cngx_bgn_mod_node_dl_load(CNGX_BGN_MOD_NODE *cngx_bgn_mod_node,
                                                  const char *dl_path, const uint32_t dl_path_len,
                                                  const char *mod_name, const uint32_t mod_name_len,
                                                  const char *posix_name, const uint32_t posix_name_len)
{
    char     func_name[ CNGX_BGN_MOD_MGR_FUNC_NAME_MAX_SIZE ];

    /*WARNING: dlmopen ask so library is completely self contained!*/
    /*CNGX_BGN_MOD_NODE_DL_LIB(cngx_bgn_mod_node) = dlmopen(LM_ID_NEWLM, dl_path, RTLD_LAZY);*/
    CNGX_BGN_MOD_NODE_DL_LIB(cngx_bgn_mod_node) = dlopen(dl_path, RTLD_LAZY);
    if(NULL_PTR == CNGX_BGN_MOD_NODE_DL_LIB(cngx_bgn_mod_node))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_bgn_mod_node_dl_load: "
                                             "load '%.*s' failed, err = '%s'\n",
                                             dl_path_len, dl_path,
                                             dlerror());

        return (EC_FALSE);
    }

    /*load reg interface*/
    snprintf(func_name, sizeof(func_name), "%.*s""_reg", mod_name_len, mod_name);
    CNGX_BGN_MOD_NODE_REG(cngx_bgn_mod_node) = (CNGX_BGN_MOD_NODE_REG_FUNC)dlsym(
                                                    CNGX_BGN_MOD_NODE_DL_LIB(cngx_bgn_mod_node),
                                                    (const char *)func_name);

    if(NULL_PTR == CNGX_BGN_MOD_NODE_REG(cngx_bgn_mod_node))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_bgn_mod_node_dl_load: "
                                             "not found '%s' in '%.*s', err = '%s'\n",
                                             (char *)func_name,
                                             dl_path_len, dl_path,
                                             dlerror());

        cngx_bgn_mod_node_clean(cngx_bgn_mod_node);
        return (EC_FALSE);
    }

    /*load unreg interface*/
    snprintf(func_name, sizeof(func_name), "%.*s""_unreg", mod_name_len, mod_name);
    CNGX_BGN_MOD_NODE_UNREG(cngx_bgn_mod_node) = (CNGX_BGN_MOD_NODE_REG_FUNC)dlsym(
                                                      CNGX_BGN_MOD_NODE_DL_LIB(cngx_bgn_mod_node),
                                                      (const char *)func_name);

    if(NULL_PTR == CNGX_BGN_MOD_NODE_UNREG(cngx_bgn_mod_node))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_bgn_mod_node_dl_load: "
                                             "not found '%s' in '%.*s', err = '%s'\n",
                                             (char *)func_name,
                                             dl_path_len, dl_path,
                                             dlerror());

        cngx_bgn_mod_node_clean(cngx_bgn_mod_node);
        return (EC_FALSE);
    }

    /*load start interface*/
    snprintf(func_name, sizeof(func_name), "%.*s""_start", mod_name_len, mod_name);
    CNGX_BGN_MOD_NODE_START(cngx_bgn_mod_node) = (CNGX_BGN_MOD_NODE_START_FUNC)dlsym(
                                                        CNGX_BGN_MOD_NODE_DL_LIB(cngx_bgn_mod_node),
                                                        (const char *)func_name);

    if(NULL_PTR == CNGX_BGN_MOD_NODE_START(cngx_bgn_mod_node))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_bgn_mod_node_dl_load: "
                                             "not found '%s' in '%.*s', err = '%s'\n",
                                             (char *)func_name,
                                             dl_path_len, dl_path,
                                             dlerror());

        cngx_bgn_mod_node_clean(cngx_bgn_mod_node);
        return (EC_FALSE);
    }

    /*load end interface*/
    snprintf(func_name, sizeof(func_name), "%.*s""_end", mod_name_len, mod_name);
    CNGX_BGN_MOD_NODE_END(cngx_bgn_mod_node) = (CNGX_BGN_MOD_NODE_END_FUNC)dlsym(
                                                        CNGX_BGN_MOD_NODE_DL_LIB(cngx_bgn_mod_node),
                                                        (const char *)func_name);

    if(NULL_PTR == CNGX_BGN_MOD_NODE_END(cngx_bgn_mod_node))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_bgn_mod_node_dl_load: "
                                             "not found '%s' in '%.*s', err = '%s'\n",
                                             (char *)func_name,
                                             dl_path_len, dl_path,
                                             dlerror());

        cngx_bgn_mod_node_clean(cngx_bgn_mod_node);
        return (EC_FALSE);
    }

    /*load get_ngx_rc interface*/
    snprintf(func_name, sizeof(func_name), "%.*s""_get_ngx_rc", mod_name_len, mod_name);
    CNGX_BGN_MOD_NODE_GETRC(cngx_bgn_mod_node) = (CNGX_BGN_MOD_NODE_GETRC_FUNC)dlsym(
                                                        CNGX_BGN_MOD_NODE_DL_LIB(cngx_bgn_mod_node),
                                                        (const char *)func_name);

    if(NULL_PTR == CNGX_BGN_MOD_NODE_GETRC(cngx_bgn_mod_node))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_bgn_mod_node_dl_load: "
                                             "not found '%s' in '%.*s', err = '%s'\n",
                                             (char *)func_name,
                                             dl_path_len, dl_path,
                                             dlerror());

        cngx_bgn_mod_node_clean(cngx_bgn_mod_node);
        return (EC_FALSE);
    }

    /*load content_handler interface*/
    snprintf(func_name, sizeof(func_name), "%.*s""_""%.*s", mod_name_len, mod_name, posix_name_len, posix_name);
    CNGX_BGN_MOD_NODE_HANDLE(cngx_bgn_mod_node) = (CNGX_BGN_MOD_NODE_HANDLE_FUNC)dlsym(
                                                        CNGX_BGN_MOD_NODE_DL_LIB(cngx_bgn_mod_node),
                                                        (const char *)func_name);

    if(NULL_PTR == CNGX_BGN_MOD_NODE_HANDLE(cngx_bgn_mod_node))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_bgn_mod_node_dl_load: "
                                             "not found '%s' in '%.*s', err = '%s'\n",
                                             (char *)func_name,
                                             dl_path_len, dl_path,
                                             dlerror());

        cngx_bgn_mod_node_clean(cngx_bgn_mod_node);
        return (EC_FALSE);
    }

    /*register module*/
    if(EC_FALSE == CNGX_BGN_MOD_NODE_REG(cngx_bgn_mod_node)())
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_bgn_mod_node_dl_load: "
                                             "call reg in '%.*s' failed\n",
                                             dl_path_len, dl_path);

        cngx_bgn_mod_node_clean(cngx_bgn_mod_node);
        return (EC_FALSE);
    }

    CNGX_BGN_MOD_NODE_COUNTER(cngx_bgn_mod_node) = 0;

    dbg_log(SEC_0176_CNGX, 1)(LOGSTDOUT, "[DEBUG] cngx_bgn_mod_node_dl_load: "
                                         "load '%.*s' done\n",
                                         dl_path_len, dl_path);

    return (EC_TRUE);
}

EC_BOOL cngx_bgn_mod_node_dl_unload(CNGX_BGN_MOD_NODE *cngx_bgn_mod_node)
{
    if(0 < CNGX_BGN_MOD_NODE_COUNTER(cngx_bgn_mod_node))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_bgn_mod_node_dl_unload: "
                                             "invalid counter %u > 0\n",
                                             CNGX_BGN_MOD_NODE_COUNTER(cngx_bgn_mod_node));
        return (EC_FALSE);
    }

    /*unregister module*/
    if(NULL_PTR != CNGX_BGN_MOD_NODE_UNREG(cngx_bgn_mod_node)
    && EC_FALSE == CNGX_BGN_MOD_NODE_UNREG(cngx_bgn_mod_node)())
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_bgn_mod_node_dl_unload: "
                                             "unreg failed\n");

        return (EC_FALSE);
    }

    cngx_bgn_mod_node_clean(cngx_bgn_mod_node);

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_bgn_mod_node_dl_unload: "
                                         "unload done\n");

    return (EC_TRUE);
}

EC_BOOL cngx_bgn_mod_node_dl_reload(CNGX_BGN_MOD_NODE *cngx_bgn_mod_node,
                                              const char *dl_path, const uint32_t dl_path_len,
                                              const char *mod_name, const uint32_t mod_name_len,
                                              const char *posix_name, const uint32_t posix_name_len)
{
    if(EC_FALSE == cngx_bgn_mod_node_dl_unload(cngx_bgn_mod_node))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_bgn_mod_node_dl_reload: "
                                             "unload failed\n");

        return (EC_FALSE);
    }

    if(EC_FALSE == cngx_bgn_mod_node_dl_load(cngx_bgn_mod_node,
                                              dl_path, dl_path_len,
                                              mod_name, mod_name_len,
                                              posix_name, posix_name_len))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_bgn_mod_node_dl_reload: "
                                             "load failed\n");

        return (EC_FALSE);
    }

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_bgn_mod_node_dl_reload: "
                                         "reload done\n");

    return (EC_TRUE);
}

CNGX_BGN_MOD_MGR *cngx_bgn_mod_mgr_new()
{
    CNGX_BGN_MOD_MGR *cngx_bgn_mod_mgr;
    alloc_static_mem(MM_CNGX_BGN_MOD_MGR, &cngx_bgn_mod_mgr, LOC_CNGX_0082);
    if(NULL_PTR != cngx_bgn_mod_mgr)
    {
        cngx_bgn_mod_mgr_init(cngx_bgn_mod_mgr);
    }
    return (cngx_bgn_mod_mgr);
}

EC_BOOL cngx_bgn_mod_mgr_init(CNGX_BGN_MOD_MGR *cngx_bgn_mod_mgr)
{
    CNGX_BGN_MOD_NODE  *cngx_bgn_mod_node;

    cstring_init(CNGX_BGN_MOD_MGR_DL_PATH(cngx_bgn_mod_mgr), NULL_PTR);

    cstring_init(CNGX_BGN_MOD_MGR_NAME(cngx_bgn_mod_mgr), NULL_PTR);
    CNGX_BGN_MOD_MGR_TYPE(cngx_bgn_mod_mgr)   = MD_END;

    CNGX_BGN_MOD_MGR_HASH(cngx_bgn_mod_mgr)   = 0;

    CNGX_BGN_MOD_MGR_CHOICE(cngx_bgn_mod_mgr) = 0; /*set 0# is active node*/
    CNGX_BGN_MOD_MGR_STATE(cngx_bgn_mod_mgr)  = CNGX_BGN_MOD_MGR_STATE_ERR;

    cngx_bgn_mod_node = CNGX_BGN_MOD_MGR_NODE(cngx_bgn_mod_mgr, 0);
    cngx_bgn_mod_node_init(cngx_bgn_mod_node);
    CNGX_BGN_MOD_NODE_INDEX(cngx_bgn_mod_node)  = 0;
    CNGX_BGN_MOD_NODE_PARENT(cngx_bgn_mod_node) = (void *)cngx_bgn_mod_mgr;

    cngx_bgn_mod_node = CNGX_BGN_MOD_MGR_NODE(cngx_bgn_mod_mgr, 1);
    cngx_bgn_mod_node_init(cngx_bgn_mod_node);
    CNGX_BGN_MOD_NODE_INDEX(cngx_bgn_mod_node)  = 1;
    CNGX_BGN_MOD_NODE_PARENT(cngx_bgn_mod_node) = (void *)cngx_bgn_mod_mgr;

    return (EC_TRUE);
}

EC_BOOL cngx_bgn_mod_mgr_clean(CNGX_BGN_MOD_MGR *cngx_bgn_mod_mgr)
{
    CNGX_BGN_MOD_NODE  *cngx_bgn_mod_node;

    cstring_clean(CNGX_BGN_MOD_MGR_DL_PATH(cngx_bgn_mod_mgr));

    cstring_clean(CNGX_BGN_MOD_MGR_NAME(cngx_bgn_mod_mgr));
    CNGX_BGN_MOD_MGR_TYPE(cngx_bgn_mod_mgr)   = MD_END;

    CNGX_BGN_MOD_MGR_HASH(cngx_bgn_mod_mgr)   = 0;

    CNGX_BGN_MOD_MGR_CHOICE(cngx_bgn_mod_mgr) = 0;
    CNGX_BGN_MOD_MGR_STATE(cngx_bgn_mod_mgr)  = CNGX_BGN_MOD_MGR_STATE_ERR;

    cngx_bgn_mod_node = CNGX_BGN_MOD_MGR_NODE(cngx_bgn_mod_mgr, 0);
    cngx_bgn_mod_node_clean(cngx_bgn_mod_node);

    cngx_bgn_mod_node = CNGX_BGN_MOD_MGR_NODE(cngx_bgn_mod_mgr, 1);
    cngx_bgn_mod_node_clean(cngx_bgn_mod_node);

    return (EC_TRUE);
}

EC_BOOL cngx_bgn_mod_mgr_free(CNGX_BGN_MOD_MGR *cngx_bgn_mod_mgr)
{
    if(NULL_PTR != cngx_bgn_mod_mgr)
    {
        cngx_bgn_mod_mgr_clean(cngx_bgn_mod_mgr);
        free_static_mem(MM_CNGX_BGN_MOD_MGR, cngx_bgn_mod_mgr, LOC_CNGX_0083);
    }
    return (EC_TRUE);
}

int cngx_bgn_mod_mgr_cmp(const CNGX_BGN_MOD_MGR *cngx_bgn_mod_mgr_1st, const CNGX_BGN_MOD_MGR *cngx_bgn_mod_mgr_2nd)
{
#if 0
    if(CNGX_BGN_MOD_MGR_TYPE(cngx_bgn_mod_mgr_1st) > CNGX_BGN_MOD_MGR_TYPE(cngx_bgn_mod_mgr_2nd))
    {
        return (1);
    }

    if(CNGX_BGN_MOD_MGR_TYPE(cngx_bgn_mod_mgr_1st) < CNGX_BGN_MOD_MGR_TYPE(cngx_bgn_mod_mgr_2nd))
    {
        return (-1);
    }
#endif
    if(CNGX_BGN_MOD_MGR_HASH(cngx_bgn_mod_mgr_1st) > CNGX_BGN_MOD_MGR_HASH(cngx_bgn_mod_mgr_2nd))
    {
        return (1);
    }

    if(CNGX_BGN_MOD_MGR_HASH(cngx_bgn_mod_mgr_1st) < CNGX_BGN_MOD_MGR_HASH(cngx_bgn_mod_mgr_2nd))
    {
        return (-1);
    }

    return cstring_cmp(CNGX_BGN_MOD_MGR_NAME(cngx_bgn_mod_mgr_1st), CNGX_BGN_MOD_MGR_NAME(cngx_bgn_mod_mgr_1st));
}

EC_BOOL cngx_bgn_mod_mgr_hash(CNGX_BGN_MOD_MGR *cngx_bgn_mod_mgr)
{
    if(0 == CNGX_BGN_MOD_MGR_HASH(cngx_bgn_mod_mgr))
    {
        CSTRING     *name;
        UINT32       hash;

        name = CNGX_BGN_MOD_MGR_NAME(cngx_bgn_mod_mgr);
        hash = CNGX_BGN_MOD_MGR_NAME_HASH(CSTRING_STR(name), CSTRING_LEN(name));

        CNGX_BGN_MOD_MGR_HASH(cngx_bgn_mod_mgr) = hash;
    }
    return (EC_TRUE);
}

EC_BOOL cngx_bgn_mod_mgr_set_name(CNGX_BGN_MOD_MGR *cngx_bgn_mod_mgr, const char *name, const uint32_t len)
{
    if(EC_FALSE == cstring_set_chars(CNGX_BGN_MOD_MGR_NAME(cngx_bgn_mod_mgr), (const UINT8 *)name, (UINT32)len))
    {
        dbg_log(SEC_0176_CNGX, 1)(LOGSTDOUT, "warn:cngx_bgn_mod_mgr_set_name: "
                                             "set '%.*s'failed\n",
                                             len, name);
        return (EC_FALSE);
    }

    cngx_bgn_mod_mgr_hash(cngx_bgn_mod_mgr);

    return (EC_TRUE);
}

void cngx_bgn_mod_mgr_print(LOG *log, const CNGX_BGN_MOD_MGR *cngx_bgn_mod_mgr)
{
    if(NULL_PTR != cngx_bgn_mod_mgr)
    {
        sys_log(log, "cngx_bgn_mod_mgr_print: "
                     "%p, path '%s', type %ld, name '%s', hash %ld, choice %u, state %u\n",
                     cngx_bgn_mod_mgr,
                     (char *)cstring_get_str(CNGX_BGN_MOD_MGR_DL_PATH(cngx_bgn_mod_mgr)),
                     CNGX_BGN_MOD_MGR_TYPE(cngx_bgn_mod_mgr),
                     (char *)cstring_get_str(CNGX_BGN_MOD_MGR_NAME(cngx_bgn_mod_mgr)),
                     CNGX_BGN_MOD_MGR_HASH(cngx_bgn_mod_mgr),
                     CNGX_BGN_MOD_MGR_CHOICE(cngx_bgn_mod_mgr),
                     CNGX_BGN_MOD_MGR_STATE(cngx_bgn_mod_mgr));

        cngx_bgn_mod_node_print(log, CNGX_BGN_MOD_MGR_NODE(cngx_bgn_mod_mgr, 0));
        cngx_bgn_mod_node_print(log, CNGX_BGN_MOD_MGR_NODE(cngx_bgn_mod_mgr, 1));
    }
    return;
}

/*switch active and standby*/
EC_BOOL cngx_bgn_mod_mgr_switch(CNGX_BGN_MOD_MGR *cngx_bgn_mod_mgr)
{
    CNGX_BGN_MOD_NODE      *cngx_bgn_mod_node;
    uint32_t                choice;

    if(CNGX_BGN_MOD_MGR_STATE_ERR == CNGX_BGN_MOD_MGR_STATE(cngx_bgn_mod_mgr))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_bgn_mod_mgr_switch: "
                                             "module not loaded yet\n");
        return (EC_FALSE);
    }

    if(CNGX_BGN_MOD_MGR_STATE_RELOADING == CNGX_BGN_MOD_MGR_STATE(cngx_bgn_mod_mgr))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_bgn_mod_mgr_switch: "
                                             "module is reloading\n");
        return (EC_FALSE);
    }

    /*check standby validity*/
    cngx_bgn_mod_node = CNGX_BGN_MOD_MGR_STANDBY_NODE(cngx_bgn_mod_mgr);

    if(NULL_PTR == CNGX_BGN_MOD_NODE_DL_LIB(cngx_bgn_mod_node))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_bgn_mod_mgr_switch: "
                                             "lib is nulll\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == CNGX_BGN_MOD_NODE_PARENT(cngx_bgn_mod_node))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_bgn_mod_mgr_switch: "
                                             "parent is nulll\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == CNGX_BGN_MOD_NODE_REG(cngx_bgn_mod_node))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_bgn_mod_mgr_switch: "
                                             "func reg is nulll\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == CNGX_BGN_MOD_NODE_UNREG(cngx_bgn_mod_node))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_bgn_mod_mgr_switch: "
                                             "func unreg is nulll\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == CNGX_BGN_MOD_NODE_START(cngx_bgn_mod_node))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_bgn_mod_mgr_switch: "
                                             "func start is nulll\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == CNGX_BGN_MOD_NODE_END(cngx_bgn_mod_node))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_bgn_mod_mgr_switch: "
                                             "func end is nulll\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == CNGX_BGN_MOD_NODE_GETRC(cngx_bgn_mod_node))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_bgn_mod_mgr_switch: "
                                             "func getrc is nulll\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == CNGX_BGN_MOD_NODE_HANDLE(cngx_bgn_mod_node))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_bgn_mod_mgr_switch: "
                                             "func handle is nulll\n");
        return (EC_FALSE);
    }

    choice = CNGX_BGN_MOD_MGR_CHOICE(cngx_bgn_mod_mgr);

    /*switch active and standby*/
    CNGX_BGN_MOD_MGR_SWITCH_NODE(cngx_bgn_mod_mgr);

    dbg_log(SEC_0176_CNGX, 1)(LOGSTDOUT, "[DEBUG] cngx_bgn_mod_mgr_switch: "
                                         "switch %u -> %u\n",
                                         choice,
                                         CNGX_BGN_MOD_MGR_CHOICE(cngx_bgn_mod_mgr));
    return (EC_TRUE);
}

STATIC_CAST EC_BOOL __cngx_bgn_mod_mgr_dl_switch_0(const void *cngx_bgn_mod_mgr, void *UNUSED(none))
{
    return cngx_bgn_mod_mgr_switch((CNGX_BGN_MOD_MGR *)cngx_bgn_mod_mgr);
}

EC_BOOL cngx_bgn_mod_mgr_is_reloading(const CNGX_BGN_MOD_MGR *cngx_bgn_mod_mgr)
{
    if(CNGX_BGN_MOD_MGR_STATE_RELOADING == CNGX_BGN_MOD_MGR_STATE(cngx_bgn_mod_mgr))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

CNGX_BGN_MOD_MGR *cngx_bgn_mod_mgr_dl_load(const char *so_path, const uint32_t so_path_len,
                                                      const char *mod_name, const uint32_t mod_name_len,
                                                      const char *posix_name, const uint32_t posix_name_len)
{
    CNGX_BGN_MOD_MGR        *cngx_bgn_mod_mgr;
    CNGX_BGN_MOD_NODE       *cngx_bgn_mod_node;

    CSTRING                 *dl_path;

    cngx_bgn_mod_mgr = cngx_bgn_mod_mgr_table_search(mod_name, mod_name_len);
    if(NULL_PTR != cngx_bgn_mod_mgr)
    {
        dbg_log(SEC_0176_CNGX, 5)(LOGSTDOUT, "info:cngx_bgn_mod_mgr_dl_load: "
                                             "module '%.*s' exist already\n",
                                             mod_name_len, mod_name);
        return (cngx_bgn_mod_mgr);
    }

    cngx_bgn_mod_mgr = cngx_bgn_mod_mgr_new();
    if(NULL_PTR == cngx_bgn_mod_mgr)
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_bgn_mod_mgr_dl_load: "
                                             "new cngx_bgn_mod_mgr failed\n");
        return (NULL_PTR);
    }

    if(EC_FALSE == cngx_bgn_mod_mgr_set_name(cngx_bgn_mod_mgr, mod_name, mod_name_len))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_bgn_mod_mgr_dl_load: "
                                             "set '%.*s' to cngx_bgn_mod_mgr failed\n",
                                             mod_name_len, mod_name);
        return (NULL_PTR);
    }

    /* load */
    if(NULL_PTR == so_path || 0 == so_path_len)
    {
        dl_path = CNGX_BGN_MOD_MGR_DL_PATH(cngx_bgn_mod_mgr);
        cstring_clean(dl_path);

        if(EC_FALSE == cstring_format(dl_path, (const char *)"%s/lib%.*s.so",
                                      (char *)CNGX_BGN_MOD_SO_PATH_DEFAULT,
                                      mod_name_len, mod_name))
        {
            dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_bgn_mod_mgr_dl_load: "
                                                 "format string '%s/%.*s.so' failed\n",
                                                 (char *)CNGX_BGN_MOD_SO_PATH_DEFAULT,
                                                 mod_name_len, mod_name);
            cngx_bgn_mod_mgr_free(cngx_bgn_mod_mgr);
            return (NULL_PTR);
        }
    }
    else
    {
        dl_path = CNGX_BGN_MOD_MGR_DL_PATH(cngx_bgn_mod_mgr);
        cstring_clean(dl_path);

        if(EC_FALSE == cstring_format(dl_path, (const char *)"%.*s/lib%.*s.so",
                                      so_path_len, so_path,
                                      mod_name_len, mod_name))
        {
            dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_bgn_mod_mgr_dl_load: "
                                                 "format string '%.*s/%.*s.so' failed\n",
                                                 so_path_len, so_path,
                                                 mod_name_len, mod_name);
            cngx_bgn_mod_mgr_free(cngx_bgn_mod_mgr);
            return (NULL_PTR);
        }
    }

    do /*load*/
    {
        char        *dl_path_latest;
        uint32_t     dl_path_latest_len;
        uint32_t     dl_version_latest;

        dl_path_latest = __cngx_bgn_mod_node_dl_path_latest((char   *)cstring_get_str(dl_path),
                                                            (uint32_t)cstring_get_len(dl_path),
                                                            &dl_version_latest);
        if(NULL_PTR == dl_path_latest)
        {
            dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_bgn_mod_mgr_dl_load: "
                                                 "finger latest dl of '%.*s' failed\n",
                                                 (uint32_t)cstring_get_len(dl_path),
                                                 (char   *)cstring_get_str(dl_path));

            return (NULL_PTR);
        }
        dl_path_latest_len = strlen(dl_path_latest);

        dbg_log(SEC_0176_CNGX, 1)(LOGSTDOUT, "[DEBUG] cngx_bgn_mod_mgr_dl_load: "
                                             "finger latest dl '%.*s', version %u done\n",
                                             dl_path_latest_len, dl_path_latest, dl_version_latest);

        cngx_bgn_mod_node = CNGX_BGN_MOD_MGR_ACTIVE_NODE(cngx_bgn_mod_mgr);
        if(EC_FALSE == cngx_bgn_mod_node_dl_load(cngx_bgn_mod_node,
                                                  dl_path_latest,
                                                  dl_path_latest_len,
                                                  mod_name,
                                                  mod_name_len,
                                                  posix_name,
                                                  posix_name_len))
        {
            dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_bgn_mod_mgr_dl_load: "
                                                 "load bgn module '%.*s' failed\n",
                                                 mod_name_len, mod_name);

            c_str_free(dl_path_latest);
            cngx_bgn_mod_mgr_free(cngx_bgn_mod_mgr);
            return (NULL_PTR);
        }

        c_str_free(dl_path_latest);

        CNGX_BGN_MOD_NODE_INDEX(cngx_bgn_mod_node)  = (CNGX_BGN_MOD_MGR_CHOICE(cngx_bgn_mod_mgr) & 1);
        CNGX_BGN_MOD_NODE_PARENT(cngx_bgn_mod_node) = cngx_bgn_mod_mgr;
        CNGX_BGN_MOD_NODE_VER(cngx_bgn_mod_node)    = dl_version_latest;
        CNGX_BGN_MOD_MGR_STATE(cngx_bgn_mod_mgr)    = CNGX_BGN_MOD_MGR_STATE_RUNNING;
    }while(0);

    if(EC_FALSE == cngx_bgn_mod_mgr_table_add(cngx_bgn_mod_mgr))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_bgn_mod_mgr_dl_load: "
                                             "add bgn module '%.*s' to table failed\n",
                                             mod_name_len, mod_name);

        cngx_bgn_mod_mgr_free(cngx_bgn_mod_mgr);
        return (NULL_PTR);
    }

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_bgn_mod_mgr_dl_load: "
                                         "load bgn module '%.*s' done\n",
                                         mod_name_len, mod_name);
    return (cngx_bgn_mod_mgr);
}

EC_BOOL cngx_bgn_mod_mgr_dl_unload(const char *mod_name, const uint32_t mod_name_len)
{
    CNGX_BGN_MOD_MGR       *cngx_bgn_mod_mgr;
    CNGX_BGN_MOD_NODE      *cngx_bgn_mod_node;

    cngx_bgn_mod_mgr = cngx_bgn_mod_mgr_table_search(mod_name, mod_name_len);
    if(NULL_PTR == cngx_bgn_mod_mgr)
    {
        dbg_log(SEC_0176_CNGX, 1)(LOGSTDOUT, "warn:cngx_bgn_mod_mgr_dl_unload: "
                                             "module '%.*s' not exist\n",
                                             mod_name_len, mod_name);
        return (EC_TRUE);
    }

    /*unload standby node*/
    cngx_bgn_mod_node = CNGX_BGN_MOD_MGR_STANDBY_NODE(cngx_bgn_mod_mgr);
    if(EC_FALSE == cngx_bgn_mod_node_dl_unload(cngx_bgn_mod_node))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_bgn_mod_mgr_dl_unload: "
                                             "unload standby of '%.*s' failed\n",
                                             mod_name_len, mod_name);

        return (EC_FALSE);
    }
    dbg_log(SEC_0176_CNGX, 1)(LOGSTDOUT, "[DEBUG] cngx_bgn_mod_mgr_dl_unload: "
                                         "unload standby of '%.*s' done\n",
                                         mod_name_len, mod_name);

    /*unload active node*/
    cngx_bgn_mod_node = CNGX_BGN_MOD_MGR_ACTIVE_NODE(cngx_bgn_mod_mgr);
    if(EC_FALSE == cngx_bgn_mod_node_dl_unload(cngx_bgn_mod_node))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_bgn_mod_mgr_dl_unload: "
                                             "unload active of '%.*s' failed\n",
                                            mod_name_len, mod_name);

        return (EC_FALSE);
    }
    dbg_log(SEC_0176_CNGX, 1)(LOGSTDOUT, "[DEBUG] cngx_bgn_mod_mgr_dl_unload: "
                                         "unload active of '%.*s' done\n",
                                         mod_name_len, mod_name);

    if(EC_FALSE == cngx_bgn_mod_mgr_table_del(mod_name, mod_name_len))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_bgn_mod_mgr_dl_unload: "
                                             "unload mod '%.*s' failed\n",
                                             mod_name_len, mod_name);
        return (EC_FALSE);
    }

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_bgn_mod_mgr_dl_unload: "
                                         "unload mod '%.*s' done\n",
                                         mod_name_len, mod_name);
    return (EC_TRUE);
}

EC_BOOL cngx_bgn_mod_mgr_dl_reload(const char *so_path, const uint32_t so_path_len,
                                             const char *mod_name, const uint32_t mod_name_len,
                                             const char *posix_name, const uint32_t posix_name_len)
{
    CNGX_BGN_MOD_MGR        *cngx_bgn_mod_mgr;
    CNGX_BGN_MOD_NODE       *cngx_bgn_mod_node;
    CSTRING                 *dl_path;

    cngx_bgn_mod_mgr = cngx_bgn_mod_mgr_table_search(mod_name, mod_name_len);
    if(NULL_PTR == cngx_bgn_mod_mgr)
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "warn:cngx_bgn_mod_mgr_dl_reload: "
                                             "module '%.*s' not exist\n",
                                             mod_name_len, mod_name);
        return (EC_TRUE);
    }

    ASSERT(CNGX_BGN_MOD_MGR_STATE_RELOADING == CNGX_BGN_MOD_MGR_STATE(cngx_bgn_mod_mgr));

    if(NULL_PTR == so_path || 0 == so_path_len)
    {
        dl_path = CNGX_BGN_MOD_MGR_DL_PATH(cngx_bgn_mod_mgr);
        cstring_clean(dl_path);

        if(EC_FALSE == cstring_format(dl_path, (const char *)"%s/lib%.*s.so",
                                      (char *)CNGX_BGN_MOD_SO_PATH_DEFAULT,
                                      mod_name_len, mod_name))
        {
            dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_bgn_mod_mgr_dl_reload: "
                                                 "format string '%s/%.*s.so' failed\n",
                                                 (char *)CNGX_BGN_MOD_SO_PATH_DEFAULT,
                                                 mod_name_len, mod_name);
            /*keep reloading state and wait for next reloading*/
            return (EC_FALSE);
        }
    }
    else
    {
        dl_path = CNGX_BGN_MOD_MGR_DL_PATH(cngx_bgn_mod_mgr);
        cstring_clean(dl_path);

        if(EC_FALSE == cstring_format(dl_path, (const char *)"%.*s/lib%.*s.so",
                                      so_path_len, so_path,
                                      mod_name_len, mod_name))
        {
            dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_bgn_mod_mgr_dl_reload: "
                                                 "format string '%.*s/%.*s.so' failed\n",
                                                 so_path_len, so_path,
                                                 mod_name_len, mod_name);

            /*keep reloading state and wait for next reloading*/
            return (EC_FALSE);
        }
    }

    do /*reload*/
    {
        char        *dl_path_latest;
        uint32_t     dl_path_latest_len;
        uint32_t     dl_version_latest;
        uint32_t     dl_version_active;
        uint32_t     dl_version_standby;

        dl_path_latest = __cngx_bgn_mod_node_dl_path_latest((char   *)cstring_get_str(dl_path),
                                                            (uint32_t)cstring_get_len(dl_path),
                                                            &dl_version_latest);
        if(NULL_PTR == dl_path_latest)
        {
            dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_bgn_mod_mgr_dl_reload: "
                                                 "finger latest dl of '%.*s' failed\n",
                                                 (uint32_t)cstring_get_len(dl_path),
                                                 (char   *)cstring_get_str(dl_path));

            /*prevent from loop-less scan dir*/
            CNGX_BGN_MOD_MGR_STATE(cngx_bgn_mod_mgr) = CNGX_BGN_MOD_MGR_STATE_RUNNING;

            return (EC_FALSE);
        }
        dl_path_latest_len = strlen(dl_path_latest);

        dbg_log(SEC_0176_CNGX, 1)(LOGSTDOUT, "[DEBUG] cngx_bgn_mod_mgr_dl_reload: "
                                             "finger latest dl '%.*s', version %u done\n",
                                             dl_path_latest_len, dl_path_latest, dl_version_latest);

        /*obtain active version*/
        cngx_bgn_mod_node  = CNGX_BGN_MOD_MGR_ACTIVE_NODE(cngx_bgn_mod_mgr);
        dl_version_active  = CNGX_BGN_MOD_NODE_VER(cngx_bgn_mod_node);

        /*obtain standby version*/
        cngx_bgn_mod_node  = CNGX_BGN_MOD_MGR_STANDBY_NODE(cngx_bgn_mod_mgr);
        dl_version_standby = CNGX_BGN_MOD_NODE_VER(cngx_bgn_mod_node);

        /*check version validity*/
        if(CNGX_BGN_MOD_NODE_VER_ERR == dl_version_standby)
        {
            /*if active is latest, give up reloading due to dlopen cannot open same so lib*/
            if(dl_version_latest == dl_version_active)
            {
                dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "warn:cngx_bgn_mod_mgr_dl_reload: "
                                                     "module '%.*s' active version %u is latest\n",
                                                     mod_name_len, mod_name,
                                                     dl_version_active);
                c_str_free(dl_path_latest);

                CNGX_BGN_MOD_MGR_STATE(cngx_bgn_mod_mgr) = CNGX_BGN_MOD_MGR_STATE_RUNNING;

                /*not reload && not switch*/
                return (EC_TRUE);
            }
            else
            {
                /*reload && switch*/
                /*fall through*/
            }
        }
        else
        {
            /*if active is latest, give up reloading due to dlopen cannot open same so lib*/
            if(dl_version_latest == dl_version_active)
            {
                dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "warn:cngx_bgn_mod_mgr_dl_reload: "
                                                     "module '%.*s' active version %u is latest\n",
                                                     mod_name_len, mod_name,
                                                     dl_version_active);
                c_str_free(dl_path_latest);

                CNGX_BGN_MOD_MGR_STATE(cngx_bgn_mod_mgr) = CNGX_BGN_MOD_MGR_STATE_RUNNING;

                /*not reload && not switch*/
                return (EC_TRUE);
            }

            /*if standby is latest, give up reloading due to dlopen cannot open same so lib*/
            else if(dl_version_latest == dl_version_standby)
            {
                dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "warn:cngx_bgn_mod_mgr_dl_reload: "
                                                     "module '%.*s' standby version %u is latest\n",
                                                     mod_name_len, mod_name,
                                                     dl_version_standby);
                c_str_free(dl_path_latest);

                CNGX_BGN_MOD_MGR_STATE(cngx_bgn_mod_mgr) = CNGX_BGN_MOD_MGR_STATE_RUNNING;

                /*switch only*/
                break;
            }

            else
            {
                /*not reload && not switch*/
                /*fall through*/
            }
        }

        /*reload standby*/
        cngx_bgn_mod_node  = CNGX_BGN_MOD_MGR_STANDBY_NODE(cngx_bgn_mod_mgr);
        if(EC_FALSE == cngx_bgn_mod_node_dl_reload(cngx_bgn_mod_node,
                                                    dl_path_latest,
                                                    dl_path_latest_len,
                                                    mod_name, mod_name_len,
                                                    posix_name, posix_name_len))
        {
            dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_bgn_mod_mgr_dl_reload: "
                                                 "module '%.*s' reload failed\n",
                                                 mod_name_len, mod_name);
            c_str_free(dl_path_latest);

            /*prevent from loop-less reloading*/
            CNGX_BGN_MOD_MGR_STATE(cngx_bgn_mod_mgr)    = CNGX_BGN_MOD_MGR_STATE_RUNNING;

            return (EC_FALSE);
        }
        c_str_free(dl_path_latest);

        CNGX_BGN_MOD_NODE_INDEX(cngx_bgn_mod_node)  = (CNGX_BGN_MOD_MGR_CHOICE(cngx_bgn_mod_mgr) ^ 1);
        CNGX_BGN_MOD_NODE_PARENT(cngx_bgn_mod_node) = cngx_bgn_mod_mgr;
        CNGX_BGN_MOD_NODE_VER(cngx_bgn_mod_node)    = dl_version_latest;

        CNGX_BGN_MOD_MGR_STATE(cngx_bgn_mod_mgr)    = CNGX_BGN_MOD_MGR_STATE_RUNNING;
    }while(0);

    /*switch active and standby*/
    if(EC_FALSE == cngx_bgn_mod_mgr_switch(cngx_bgn_mod_mgr))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_bgn_mod_mgr_dl_reload: "
                                             "module '%.*s' switch failed\n",
                                             mod_name_len, mod_name);
        return (EC_FALSE);
    }

    dbg_log(SEC_0176_CNGX, 1)(LOGSTDOUT, "[DEBUG] cngx_bgn_mod_mgr_dl_reload: "
                                         "module '%.*s' reload done\n",
                                         mod_name_len, mod_name);

    return (EC_TRUE);
}

EC_BOOL cngx_bgn_mod_mgr_dl_set_reload(const char *mod_name, const uint32_t mod_name_len)
{
    CNGX_BGN_MOD_MGR       *cngx_bgn_mod_mgr;

    cngx_bgn_mod_mgr = cngx_bgn_mod_mgr_table_search(mod_name, mod_name_len);
    if(NULL_PTR == cngx_bgn_mod_mgr)
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "warn:cngx_bgn_mod_mgr_dl_set_reload: "
                                             "module '%.*s' not exist\n",
                                             mod_name_len, mod_name);
        return (EC_TRUE);
    }

    if(CNGX_BGN_MOD_MGR_STATE_ERR == CNGX_BGN_MOD_MGR_STATE(cngx_bgn_mod_mgr))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_bgn_mod_mgr_dl_set_reload: "
                                             "module '%.*s' not loaded yet\n",
                                             mod_name_len, mod_name);
        return (EC_FALSE);
    }

    if(CNGX_BGN_MOD_MGR_STATE_RELOADING == CNGX_BGN_MOD_MGR_STATE(cngx_bgn_mod_mgr))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_bgn_mod_mgr_dl_set_reload: "
                                             "module '%.*s' is reloading\n",
                                             mod_name_len, mod_name);
        return (EC_FALSE);
    }

    CNGX_BGN_MOD_MGR_STATE(cngx_bgn_mod_mgr) = CNGX_BGN_MOD_MGR_STATE_RELOADING;

    dbg_log(SEC_0176_CNGX, 1)(LOGSTDOUT, "[DEBUG] cngx_bgn_mod_mgr_dl_set_reload: "
                                         "module '%.*s' set reloading\n",
                                         mod_name_len, mod_name);
    return (EC_TRUE);
}

EC_BOOL cngx_bgn_mod_mgr_dl_set_reload_0(CNGX_BGN_MOD_MGR *cngx_bgn_mod_mgr)
{
    char    *name;
    uint32_t len;

    name = (char   *)cstring_get_str(CNGX_BGN_MOD_MGR_NAME(cngx_bgn_mod_mgr));
    len  = (uint32_t)cstring_get_len(CNGX_BGN_MOD_MGR_NAME(cngx_bgn_mod_mgr));

    return cngx_bgn_mod_mgr_dl_set_reload(name, len);
}

STATIC_CAST EC_BOOL __cngx_bgn_mod_mgr_dl_set_reload_0(const void *cngx_bgn_mod_mgr, void *UNUSED(none))
{
    return cngx_bgn_mod_mgr_dl_set_reload_0((CNGX_BGN_MOD_MGR *)cngx_bgn_mod_mgr);
}


EC_BOOL cngx_bgn_mod_mgr_table_init()
{
    if(EC_FALSE == g_cngx_bgn_mod_mgr_tree_init_flag)
    {
        crb_tree_init(&g_cngx_bgn_mod_mgr_tree,
                      (CRB_DATA_CMP  )cngx_bgn_mod_mgr_cmp,
                      (CRB_DATA_FREE )cngx_bgn_mod_mgr_free,
                      (CRB_DATA_PRINT)cngx_bgn_mod_mgr_print);

        g_cngx_bgn_mod_mgr_tree_init_flag = EC_TRUE;
    }
    return (EC_TRUE);
}

EC_BOOL cngx_bgn_mod_mgr_table_add(CNGX_BGN_MOD_MGR *cngx_bgn_mod_mgr)
{
    CRB_NODE    *crb_node;

    cngx_bgn_mod_mgr_table_init();/*trick*/

    ASSERT(0 < CNGX_BGN_MOD_MGR_HASH(cngx_bgn_mod_mgr));

    crb_node = crb_tree_insert_data(&g_cngx_bgn_mod_mgr_tree, (void *)cngx_bgn_mod_mgr);
    if(NULL_PTR == crb_node)
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_bgn_mod_mgr_table_add: "
                        "add mod '%s' failed\n",
                        (char *)cstring_get_str(CNGX_BGN_MOD_MGR_NAME(cngx_bgn_mod_mgr)));
        return (EC_FALSE);
    }

    if(CRB_NODE_DATA(crb_node) != cngx_bgn_mod_mgr)/*found duplicate*/
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_bgn_mod_mgr_table_add: "
                        "duplicate mod '%s'\n",
                        (char *)cstring_get_str(CNGX_BGN_MOD_MGR_NAME(cngx_bgn_mod_mgr)));
        return (EC_FALSE);/*xxx*/
    }

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_bgn_mod_mgr_table_add: "
                        "add mod '%s' done\n",
                        (char *)cstring_get_str(CNGX_BGN_MOD_MGR_NAME(cngx_bgn_mod_mgr)));
    return (EC_TRUE);
}

CNGX_BGN_MOD_MGR *cngx_bgn_mod_mgr_table_search(const char *mod_name, const uint32_t mod_name_len)
{
    CRB_NODE          *crb_node;

    CNGX_BGN_MOD_MGR *cngx_bgn_mod_mgr;
    CNGX_BGN_MOD_MGR *cngx_bgn_mod_mgr_searched;

    cngx_bgn_mod_mgr_table_init();/*trick*/

    cngx_bgn_mod_mgr = cngx_bgn_mod_mgr_new();
    if(NULL_PTR == cngx_bgn_mod_mgr)
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_bgn_mod_mgr_table_search: "
                                             "new cngx_bgn_mod_mgr failed\n");
        return (NULL_PTR);
    }

    if(EC_FALSE == cngx_bgn_mod_mgr_set_name(cngx_bgn_mod_mgr, mod_name, mod_name_len))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_bgn_mod_mgr_table_search: "
                                             "set mod '%.*s' failed\n",
                                             mod_name_len, mod_name);
        cngx_bgn_mod_mgr_free(cngx_bgn_mod_mgr);
        return (NULL_PTR);
    }

    /*searched by mod_name*/
    crb_node = crb_tree_search_data(&g_cngx_bgn_mod_mgr_tree, (void *)cngx_bgn_mod_mgr);
    if(NULL_PTR == crb_node)
    {
        cngx_bgn_mod_mgr_free(cngx_bgn_mod_mgr);
        return (NULL_PTR);
    }

    cngx_bgn_mod_mgr_free(cngx_bgn_mod_mgr);

    cngx_bgn_mod_mgr_searched = CRB_NODE_DATA(crb_node);
    return (cngx_bgn_mod_mgr_searched);
}

CNGX_BGN_MOD_MGR *cngx_bgn_mod_mgr_table_get(const char *mod_name, const uint32_t mod_name_len)
{
    CNGX_BGN_MOD_MGR *cngx_bgn_mod_mgr;

    cngx_bgn_mod_mgr = cngx_bgn_mod_mgr_table_search(mod_name, mod_name_len);
    if(NULL_PTR == cngx_bgn_mod_mgr)
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_bgn_mod_mgr_table_get: "
                                             "not found mod '%.*s'\n",
                                             mod_name_len, mod_name);
        return (NULL_PTR);
    }

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_bgn_mod_mgr_table_get: "
                                         "get mod '%.*s' done\n",
                                         mod_name_len, mod_name);
    return (cngx_bgn_mod_mgr);
}

EC_BOOL cngx_bgn_mod_mgr_table_del(const char *mod_name, const uint32_t mod_name_len)
{
    CNGX_BGN_MOD_MGR *cngx_bgn_mod_mgr;

    cngx_bgn_mod_mgr_table_init();/*trick*/

    cngx_bgn_mod_mgr = cngx_bgn_mod_mgr_new();
    if(NULL_PTR == cngx_bgn_mod_mgr)
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_bgn_mod_mgr_table_del: "
                                             "new cngx_bgn_mod_mgr failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cngx_bgn_mod_mgr_set_name(cngx_bgn_mod_mgr, mod_name, mod_name_len))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_bgn_mod_mgr_table_del: "
                                             "set mod '%.*s' failed\n",
                                             mod_name_len, mod_name);
        cngx_bgn_mod_mgr_free(cngx_bgn_mod_mgr);
        return (EC_FALSE);
    }

    /*search and delete by mod_name*/
    if(EC_FALSE == crb_tree_delete_data(&g_cngx_bgn_mod_mgr_tree, (void *)cngx_bgn_mod_mgr))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_bgn_mod_mgr_table_del: "
                                             "del mod '%.*s' failed\n",
                                             mod_name_len, mod_name);
        cngx_bgn_mod_mgr_free(cngx_bgn_mod_mgr);
        return (EC_FALSE);
    }

    cngx_bgn_mod_mgr_free(cngx_bgn_mod_mgr);

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_bgn_mod_mgr_table_del: "
                                         "del mod '%.*s' done\n",
                                         mod_name_len, mod_name);
    return (EC_TRUE);
}

void cngx_bgn_mod_mgr_table_print(LOG *log)
{
    sys_log(log, "cngx_bgn_mod_mgr_table_print: g_cngx_bgn_mod_mgr_tree:\n");
    crb_tree_print(log, &g_cngx_bgn_mod_mgr_tree);

    return;
}

EC_BOOL cngx_bgn_mod_mgr_table_set_reload()
{
    if(EC_FALSE == crb_inorder_walk(&g_cngx_bgn_mod_mgr_tree,
                                    __cngx_bgn_mod_mgr_dl_set_reload_0,
                                    NULL_PTR))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_bgn_mod_mgr_table_set_reload: "
                                             "reload failed\n");

        return (EC_FALSE);
    }

    dbg_log(SEC_0176_CNGX, 1)(LOGSTDOUT, "[DEBUG] cngx_bgn_mod_mgr_table_set_reload: "
                                         "reload done\n");
    return (EC_TRUE);
}

EC_BOOL cngx_bgn_mod_mgr_table_switch()
{
    if(EC_FALSE == crb_inorder_walk(&g_cngx_bgn_mod_mgr_tree,
                                    __cngx_bgn_mod_mgr_dl_switch_0,
                                    NULL_PTR))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_bgn_mod_mgr_table_switch: "
                                             "switch failed\n");

        return (EC_FALSE);
    }

    dbg_log(SEC_0176_CNGX, 1)(LOGSTDOUT, "[DEBUG] cngx_bgn_mod_mgr_table_switch: "
                                         "switch done\n");
    return (EC_TRUE);
}

#endif/*(SWITCH_ON == NGX_BGN_SWITCH)*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/
