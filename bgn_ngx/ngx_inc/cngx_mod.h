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

#ifndef _CNGX_MOD_H
#define _CNGX_MOD_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <unistd.h>
#include <dlfcn.h>

#include <ngx_config.h>

#include "type.h"
#include "cstring.h"
#include "clist.h"
#include "cvector.h"
#include "chashalgo.h"
#include "chttp.h"

#define  CNGX_BGN_MOD_SO_PATH_DEFAULT             ("/usr/local/xcache/lib")

typedef EC_BOOL    (*CNGX_BGN_MOD_NODE_REG_FUNC   )();
typedef EC_BOOL    (*CNGX_BGN_MOD_NODE_UNREG_FUNC )();
typedef UINT32     (*CNGX_BGN_MOD_NODE_START_FUNC )(void *r);
typedef void       (*CNGX_BGN_MOD_NODE_END_FUNC   )(const UINT32 modi);
typedef EC_BOOL    (*CNGX_BGN_MOD_NODE_GETRC_FUNC )(const UINT32 modi, ngx_int_t *, UINT32 *);
typedef EC_BOOL    (*CNGX_BGN_MOD_NODE_HANDLE_FUNC)(const UINT32 modi);

#define CNGX_BGN_MOD_NODE_INDEX_ERR                   ((uint32_t)~0)
#define CNGX_BGN_MOD_NODE_VER_ERR                     ((uint32_t)~0)

typedef struct {
    void                                  *dl_lib;

    uint32_t                               version;
    uint32_t                               rsvd01;

    uint32_t                               index;  /*who am i*/
    uint32_t                               counter;/*reference counter*/

    void                                  *parent; /*point to parent CNGX_BGN_MOD_MGR*/

    CNGX_BGN_MOD_NODE_REG_FUNC        reg;
    CNGX_BGN_MOD_NODE_UNREG_FUNC      unreg;
    CNGX_BGN_MOD_NODE_START_FUNC      start;
    CNGX_BGN_MOD_NODE_END_FUNC        end;
    CNGX_BGN_MOD_NODE_GETRC_FUNC      getrc;
    CNGX_BGN_MOD_NODE_HANDLE_FUNC     handle;
}CNGX_BGN_MOD_NODE;

#define CNGX_BGN_MOD_NODE_DL_LIB(cngx_bgn_mod_node)         ((cngx_bgn_mod_node)->dl_lib)

#define CNGX_BGN_MOD_NODE_VER(cngx_bgn_mod_node)            ((cngx_bgn_mod_node)->version)

#define CNGX_BGN_MOD_NODE_INDEX(cngx_bgn_mod_node)          ((cngx_bgn_mod_node)->index)
#define CNGX_BGN_MOD_NODE_COUNTER(cngx_bgn_mod_node)        ((cngx_bgn_mod_node)->counter)

#define CNGX_BGN_MOD_NODE_PARENT(cngx_bgn_mod_node)         ((cngx_bgn_mod_node)->parent)

#define CNGX_BGN_MOD_NODE_REG(cngx_bgn_mod_node)            ((cngx_bgn_mod_node)->reg)
#define CNGX_BGN_MOD_NODE_UNREG(cngx_bgn_mod_node)          ((cngx_bgn_mod_node)->unreg)
#define CNGX_BGN_MOD_NODE_START(cngx_bgn_mod_node)          ((cngx_bgn_mod_node)->start)
#define CNGX_BGN_MOD_NODE_END(cngx_bgn_mod_node)            ((cngx_bgn_mod_node)->end)
#define CNGX_BGN_MOD_NODE_GETRC(cngx_bgn_mod_node)          ((cngx_bgn_mod_node)->getrc)
#define CNGX_BGN_MOD_NODE_HANDLE(cngx_bgn_mod_node)         ((cngx_bgn_mod_node)->handle)


#define CNGX_BGN_MOD_MGR_NAME_HASH(name, len)        (JS_hash(len, name))
#define CNGX_BGN_MOD_MGR_FUNC_NAME_MAX_SIZE          (256)

#define CNGX_BGN_MOD_MGR_STATE_ERR             ((uint32_t) 0)
#define CNGX_BGN_MOD_MGR_STATE_RUNNING         ((uint32_t) 1)
#define CNGX_BGN_MOD_MGR_STATE_RELOADING       ((uint32_t) 2)

typedef struct {
    CSTRING                           dl_path;

    CSTRING                           name;   /*module name*/
    UINT32                            type;   /*module type, like as MD_XXX*/

    UINT32                            hash;   /*hash of module name*/

    uint32_t                          choice; /*which is active*/
    uint32_t                          state;  /*state machine*/

    CNGX_BGN_MOD_NODE            node[2];
}CNGX_BGN_MOD_MGR;

#define CNGX_BGN_MOD_MGR_DL_PATH(cngx_bgn_mod_mgr)            (&((cngx_bgn_mod_mgr)->dl_path))

#define CNGX_BGN_MOD_MGR_NAME(cngx_bgn_mod_mgr)               (&((cngx_bgn_mod_mgr)->name))
#define CNGX_BGN_MOD_MGR_TYPE(cngx_bgn_mod_mgr)               ((cngx_bgn_mod_mgr)->type)

#define CNGX_BGN_MOD_MGR_HASH(cngx_bgn_mod_mgr)               ((cngx_bgn_mod_mgr)->hash)

#define CNGX_BGN_MOD_MGR_CHOICE(cngx_bgn_mod_mgr)             ((cngx_bgn_mod_mgr)->choice)
#define CNGX_BGN_MOD_MGR_STATE(cngx_bgn_mod_mgr)              ((cngx_bgn_mod_mgr)->state)

#define CNGX_BGN_MOD_MGR_NODE(cngx_bgn_mod_mgr, idx)          (&((cngx_bgn_mod_mgr)->node[ (idx) ]))
#define CNGX_BGN_MOD_MGR_ACTIVE_NODE(cngx_bgn_mod_mgr)        \
        (&((cngx_bgn_mod_mgr)->node[ CNGX_BGN_MOD_MGR_CHOICE(cngx_bgn_mod_mgr) & 1 ]))
#define CNGX_BGN_MOD_MGR_STANDBY_NODE(cngx_bgn_mod_mgr)       \
        (&((cngx_bgn_mod_mgr)->node[ CNGX_BGN_MOD_MGR_CHOICE(cngx_bgn_mod_mgr) ^ 1 ]))
#define CNGX_BGN_MOD_MGR_SWITCH_NODE(cngx_bgn_mod_mgr)        \
        do{ CNGX_BGN_MOD_MGR_CHOICE(cngx_bgn_mod_mgr) ^= 1; }while(0)

/*------------------------------ NGX BGN MODULE MANAGEMENT ------------------------------*/
EC_BOOL cngx_bgn_mod_node_init(CNGX_BGN_MOD_NODE *cngx_bgn_mod_node);

EC_BOOL cngx_bgn_mod_node_clean(CNGX_BGN_MOD_NODE *cngx_bgn_mod_node);

void    cngx_bgn_mod_node_print(LOG *log, const CNGX_BGN_MOD_NODE *cngx_bgn_mod_node);

EC_BOOL cngx_bgn_mod_node_dl_load(CNGX_BGN_MOD_NODE *cngx_bgn_mod_node,
                                            const char *dl_path, const uint32_t dl_path_len,
                                            const char *mod_name, const uint32_t mod_name_len,
                                            const char *posix_name, const uint32_t posix_name_len);

EC_BOOL cngx_bgn_mod_node_dl_unload(CNGX_BGN_MOD_NODE *cngx_bgn_mod_node);

EC_BOOL cngx_bgn_mod_node_dl_reload(CNGX_BGN_MOD_NODE *cngx_bgn_mod_node,
                                              const char *dl_path, const uint32_t dl_path_len,
                                              const char *mod_name, const uint32_t mod_name_len,
                                              const char *posix_name, const uint32_t posix_name_len);


CNGX_BGN_MOD_MGR *cngx_bgn_mod_mgr_new();

EC_BOOL cngx_bgn_mod_mgr_init(CNGX_BGN_MOD_MGR *cngx_bgn_mod_mgr);

EC_BOOL cngx_bgn_mod_mgr_clean(CNGX_BGN_MOD_MGR *cngx_bgn_mod_mgr);

EC_BOOL cngx_bgn_mod_mgr_free(CNGX_BGN_MOD_MGR *cngx_bgn_mod_mgr);

int     cngx_bgn_mod_mgr_cmp(const CNGX_BGN_MOD_MGR *cngx_bgn_mod_mgr_1st, const CNGX_BGN_MOD_MGR *cngx_bgn_mod_mgr_2nd);

EC_BOOL cngx_bgn_mod_mgr_hash(CNGX_BGN_MOD_MGR *cngx_bgn_mod_mgr);

EC_BOOL cngx_bgn_mod_mgr_set_name(CNGX_BGN_MOD_MGR *cngx_bgn_mod_mgr, const char *name, const uint32_t len);

void    cngx_bgn_mod_mgr_print(LOG *log, const CNGX_BGN_MOD_MGR *cngx_bgn_mod_mgr);

/*switch active and standby*/
EC_BOOL cngx_bgn_mod_mgr_switch(CNGX_BGN_MOD_MGR *cngx_bgn_mod_mgr);

EC_BOOL cngx_bgn_mod_mgr_is_reloading(const CNGX_BGN_MOD_MGR *cngx_bgn_mod_mgr);

CNGX_BGN_MOD_MGR *cngx_bgn_mod_mgr_dl_load(const char *so_path, const uint32_t so_path_len,
                                                      const char *mod_name, const uint32_t mod_name_len,
                                                      const char *posix_name, const uint32_t posix_name_len);

EC_BOOL cngx_bgn_mod_mgr_dl_unload(const char *mod_name, const uint32_t mod_name_len);

EC_BOOL cngx_bgn_mod_mgr_dl_reload(const char *so_path, const uint32_t so_path_len,
                                             const char *mod_name, const uint32_t mod_name_len,
                                             const char *posix_name, const uint32_t posix_name_len);

EC_BOOL cngx_bgn_mod_mgr_dl_set_reload(const char *mod_name, const uint32_t mod_name_len);

EC_BOOL cngx_bgn_mod_mgr_dl_set_reload_0(CNGX_BGN_MOD_MGR *cngx_bgn_mod_mgr);


EC_BOOL cngx_bgn_mod_mgr_table_init();

EC_BOOL cngx_bgn_mod_mgr_table_add(CNGX_BGN_MOD_MGR *cngx_bgn_mod_mgr);

CNGX_BGN_MOD_MGR *cngx_bgn_mod_mgr_table_search(const char *mod_name, const uint32_t mod_name_len);

CNGX_BGN_MOD_MGR *cngx_bgn_mod_mgr_table_get(const char *mod_name, const uint32_t mod_name_len);

EC_BOOL cngx_bgn_mod_mgr_table_del(const char *mod_name, const uint32_t mod_name_len);

void    cngx_bgn_mod_mgr_table_print(LOG *log);

EC_BOOL cngx_bgn_mod_mgr_table_set_reload();

EC_BOOL cngx_bgn_mod_mgr_table_switch();

#endif /*_CNGX_MOD_H*/

#endif/*(SWITCH_ON == NGX_BGN_SWITCH)*/
#ifdef __cplusplus
}
#endif/*__cplusplus*/

