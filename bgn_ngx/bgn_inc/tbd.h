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

#ifndef _TBD_H
#define _TBD_H

#include "type.h"
#include "mm.h"
#include "real.h"
#include "task.h"

typedef struct
{
    /* used counter >= 0 */
    UINT32 usedcounter ;

    MOD_MGR  *mod_mgr;

}TBD_MD;

/**
*   for test only
*
*   to query the status of TBD Module
*
**/
void tbd_print_module_status(const UINT32 tbd_md_id, LOG *log);

/**
*
*   free all static memory occupied by the appointed TBD module
*
*
**/
UINT32 tbd_free_module_static_mem(const UINT32 tbd_md_id);

/**
*
* start TBD module
*
**/
UINT32 tbd_start( );

/**
*
* end TBD module
*
**/
void tbd_end(const UINT32 tbd_md_id);


/**
*
* initialize mod mgr of TBD module
*
**/
UINT32 tbd_set_mod_mgr(const UINT32 tbd_md_id, const MOD_MGR * src_mod_mgr);

/**
*
* get mod mgr of TBD module
*
**/
MOD_MGR * tbd_get_mod_mgr(const UINT32 tbd_md_id);

/**
*
* run body
* load user interface and execute it
*
**/
UINT32 tbd_run(const UINT32 tbd_md_id, const void * ui_retval_addr, const UINT32 ui_id, ...);

#endif /*_TBD_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

