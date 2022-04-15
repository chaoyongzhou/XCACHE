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

#ifndef _CREG_H
#define _CREG_H

#include "type.h"
#include "mm.h"
#include "log.h"

#include "debug.h"

#define CREG_TYPE_CONV_ITEM_DEFAULT_NUM     ((UINT32)256)
#define CREG_FUNC_ADDR_MGR_DEFAULT_NUM      ((UINT32)256)

TYPE_CONV_ITEM *creg_type_conv_item_new();

EC_BOOL creg_type_conv_item_init(TYPE_CONV_ITEM *type_conv_item);

EC_BOOL creg_type_conv_item_clean(TYPE_CONV_ITEM *type_conv_item);

EC_BOOL creg_type_conv_item_free(TYPE_CONV_ITEM *type_conv_item);

CVECTOR *creg_type_conv_vec_fetch();

EC_BOOL creg_type_conv_vec_init(CVECTOR *type_conv_vec);

EC_BOOL creg_type_conv_vec_clean(CVECTOR *type_conv_vec);

TYPE_CONV_ITEM *creg_type_conv_vec_get(CVECTOR *type_conv_vec, const UINT32 var_dbg_type);

EC_BOOL creg_type_conv_vec_add(CVECTOR *type_conv_vec,
                                         const UINT32 var_dbg_type, const UINT32 var_sizeof, const UINT32 var_pointer_flag, const UINT32 var_mm_type,
                                         const UINT32 var_new_func, const UINT32 var_init_func, const UINT32 var_clean_func, const UINT32 var_free_func,
                                         const UINT32 var_encode_func, const UINT32 var_decode_func, const UINT32 var_encode_size
                                         );

EC_BOOL creg_type_conv_vec_add_default(CVECTOR *type_conv_vec);

FUNC_ADDR_MGR *creg_func_addr_mgr_new();

EC_BOOL creg_func_addr_mgr_init(FUNC_ADDR_MGR *func_addr_mgr);

EC_BOOL creg_func_addr_mgr_clean(FUNC_ADDR_MGR *func_addr_mgr);

EC_BOOL creg_func_addr_mgr_free(FUNC_ADDR_MGR *func_addr_mgr);

CVECTOR *creg_func_addr_vec_fetch();

EC_BOOL creg_func_addr_vec_init(CVECTOR *func_addr_vec);

EC_BOOL creg_func_addr_vec_clean(CVECTOR *func_addr_vec);

FUNC_ADDR_MGR *creg_func_addr_vec_get(const CVECTOR *func_addr_vec, const UINT32 md_type);

EC_BOOL creg_func_addr_vec_add(CVECTOR *func_addr_vec,
                                        const UINT32 md_type, const UINT32 *func_num_ptr, const FUNC_ADDR_NODE *func_addr_node,
                                        const UINT32 md_start_func_id, const UINT32 md_end_func_id,
                                        const UINT32 md_set_mod_mgr_func_id, void * (*md_fget_mod_mgr)(const UINT32)
                                        );

EC_BOOL creg_func_addr_vec_add_default(CVECTOR *func_addr_vec);


EC_BOOL creg_static_mem_tbl_add(const UINT32 mm_type, const char *mm_name, const UINT32 block_num, const UINT32 type_size, const UINT32 location);

#endif /*_CREG_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

