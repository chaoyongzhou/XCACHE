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

#ifndef _CDETECT_H
#define _CDETECT_H

#include "type.h"
#include "cstring.h"
#include "clist.h"
#include "cvector.h"
#include "crb.h"
#include "chashalgo.h"
#include "csocket.h"
#include "cbtimer.h"
#include "mod.inc"

#define  CDETECT_RELOAD_STATUS_OK            ((UINT32) 0)
#define  CDETECT_RELOAD_STATUS_ONGOING       ((UINT32) 1)
#define  CDETECT_RELOAD_STATUS_COMPLETED     ((UINT32) 2)

typedef struct
{
    /* used counter >= 0 */
    UINT32               usedcounter;
    EC_BOOL              terminate_flag;

    CSTRING              cdetect_conf_file;

    UINT32               cdetect_reload_status;

    UINT32               cdetectn_modi_choice; /*0 or 1*/

    UINT32               cdetectn_modi[2];
}CDETECT_MD;

#define CDETECT_MD_TERMINATE_FLAG(cdetect_md)           ((cdetect_md)->terminate_flag)

#define CDETECT_MD_CONF_FILE(cdetect_md)                (&((cdetect_md)->cdetect_conf_file))

#define CDETECT_MD_REALOD_STATUS(cdetect_md)            ((cdetect_md)->cdetect_reload_status)

#define CDETECT_MD_CDETECTN_MODI_CHOICE(cdetect_md)     ((cdetect_md)->cdetectn_modi_choice)

/*current active cdetectn*/
#define CDETECT_MD_CDETECTN_MODI_ACTIVE(cdetect_md)      \
        ((cdetect_md)->cdetectn_modi[ CDETECT_MD_CDETECTN_MODI_CHOICE(cdetect_md) & 1 ])

/*current standby cdetectn*/
#define CDETECT_MD_CDETECTN_MODI_STANDBY(cdetect_md)      \
        ((cdetect_md)->cdetectn_modi[ CDETECT_MD_CDETECTN_MODI_CHOICE(cdetect_md) ^ 1 ])

/**
*   for test only
*
*   to query the status of CDETECT Module
*
**/
void cdetect_print_module_status(const UINT32 cdetect_md_id, LOG *log);

/**
*
*   free all static memory occupied by the appointed CDETECT module
*
*
**/
UINT32 cdetect_free_module_static_mem(const UINT32 cdetect_md_id);

/**
*
* start CDETECT module
*
**/
UINT32 cdetect_start(const CSTRING *cdetect_conf_file);

/**
*
* end CDETECT module
*
**/
void cdetect_end(const UINT32 cdetect_md_id);

/**
*
*  show orig nodes
*
*
**/
EC_BOOL cdetect_show_orig_nodes(const UINT32 cdetect_md_id, LOG *log);

/**
*
*  print single orig node
*
*
**/
EC_BOOL cdetect_show_orig_node(const UINT32 cdetect_md_id, const CSTRING *domain, LOG *log);

/**
*
*  dns resolve
*   - return the first one in ip nodes
*
**/
EC_BOOL cdetect_dns_resolve(const UINT32 cdetect_md_id, const CSTRING *domain, UINT32 *ipaddr);

/**
*
*  switch active and standby cdetectn
*
**/
EC_BOOL cdetect_switch(const UINT32 cdetect_md_id);

/**
*
*  reload detect conf and switch detect
*
**/
EC_BOOL cdetect_reload(const UINT32 cdetect_md_id);

/**
*
*  reload status string
*
**/
const char *cdetect_reload_status_str(const UINT32 cdetect_md_id);

/**
*
*  cdetectn choice
*
**/
EC_BOOL cdetect_choice(const UINT32 cdetect_md_id, UINT32 *choice);

/**
*
*  start to detect domain
*
**/
EC_BOOL cdetect_start_domain(const UINT32 cdetect_md_id, const CSTRING *domain);

/**
*
*  stop to detect domain
*
**/
EC_BOOL cdetect_stop_domain(const UINT32 cdetect_md_id, const CSTRING *domain);

/**
*
*  process entry
*
**/
EC_BOOL cdetect_process(const UINT32 cdetect_md_id, const UINT32 detect_task_max_num);

/**
*
*  process loop
*
**/
EC_BOOL cdetect_process_loop(const UINT32 cdetect_md_id, const UINT32 detect_task_max_num);

#endif /*_CDETECT_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/


