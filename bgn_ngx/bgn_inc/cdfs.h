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

#ifndef _CDFS_H
#define _CDFS_H

#include <stdlib.h>
#include <stdio.h>

#include "type.h"
#include "cstring.h"
#include "clist.h"
#include "cvector.h"

#include "csocket.h"

#include "mod.inc"

#include "cdfsnp.h"
#include "cdfsdn.h"
#include "cdfsnpmgr.h"

#define CDFS_LOST_FNODE_LINE_MAX_SIZE       (512)
#define CDFS_LOST_REPLICA_LINE_MAX_SIZE     (512)

#define CDFS_MOD_NODE_WRITE_DISABLE         ((UINT32) ((MD_CDFS << (WORDSIZE/2)) + 0x1000))

#define CDFS_OP_WRITE                       ((UINT8)  1)
#define CDFS_OP_READ                        ((UINT8)  2)
#define CDFS_OP_GET_WORDSIZE                ((UINT8)  3)
#define CDFS_OP_QLIST_PATH                  ((UINT8)  4)
#define CDFS_OP_MKDIR                       ((UINT8)  5)
#define CDFS_OP_EXISTS                      ((UINT8)  6)
#define CDFS_OP_IS_FILE                     ((UINT8)  7)
#define CDFS_OP_IS_DIR                      ((UINT8)  8)
#define CDFS_OP_IS_QFILE                    ((UINT8)  9)
#define CDFS_OP_IS_QDIR                     ((UINT8) 10)

#define CDFS_TYPE_IS_NP                     ((UINT32) 1)
#define CDFS_TYPE_IS_DN                     ((UINT32) 2)
#define CDFS_TYPE_IS_CLIENT                 ((UINT32) 3)
#define CDFS_TYPE_IS_ERR                    ((UINT32)-1)


typedef struct
{
    /* used counter >= 0 */
    UINT32      usedcounter;

    MOD_MGR    *cdfsdn_mod_mgr;
    MOD_MGR    *cdfsnpp_mod_mgr;

    CDFSNP_MGR *cdfsnpp;/*namespace pool*/
    CDFSDN     *cdfsdn;

    UINT32      cdfsnp_min_num;/*min num setting of cdfsnp in npp mgr*/

}CDFS_MD;

#define CDFS_MD_DN_MOD_MGR(cdfs_md)  ((cdfs_md)->cdfsdn_mod_mgr)
#define CDFS_MD_NPP_MOD_MGR(cdfs_md) ((cdfs_md)->cdfsnpp_mod_mgr)
#define CDFS_MD_DN(cdfs_md)          ((cdfs_md)->cdfsdn)
#define CDFS_MD_NPP(cdfs_md)         ((cdfs_md)->cdfsnpp)
#define CDFS_MD_NP_MIN_NUM(cdfs_md)  ((cdfs_md)->cdfsnp_min_num)

/**
*   for test only
*
*   to query the status of CDFS Module
*
**/
void cdfs_print_module_status(const UINT32 cdfs_md_id, LOG *log);

/**
*
*   free all static memory occupied by the appointed CDFS module
*
*
**/
UINT32 cdfs_free_module_static_mem(const UINT32 cdfs_md_id);

/**
*
* start CDFS module
*
**/
UINT32 cdfs_start(const UINT32 cdfsnp_min_num);

/**
*
* end CDFS module
*
**/
void cdfs_end(const UINT32 cdfs_md_id);

/**
*
* initialize mod mgr of CDFS module
*
**/
UINT32 cdfs_set_npp_mod_mgr(const UINT32 cdfs_md_id, const MOD_MGR * src_mod_mgr);

UINT32 cdfs_set_dn_mod_mgr(const UINT32 cdfs_md_id, const MOD_MGR * src_mod_mgr);

/**
*
* get mod mgr of CDFS module
*
**/
MOD_MGR * cdfs_get_npp_mod_mgr(const UINT32 cdfs_md_id);

MOD_MGR * cdfs_get_dn_mod_mgr(const UINT32 cdfs_md_id);

/**
*
*  open name node pool
*
**/
EC_BOOL cdfs_open_npp(const UINT32 cdfs_md_id, const CSTRING *cdfsnp_db_root_dir, const UINT32 cdfsnp_cached_max_num);

/**
*
*  close name node pool
*
**/
EC_BOOL cdfs_close_npp(const UINT32 cdfs_md_id);

/**
*
*  flush and close name node pool
*
**/
EC_BOOL cdfs_close_with_flush_npp(const UINT32 cdfs_md_id);

/*collect all dn tcid vec*/
EC_BOOL cdfs_collect_dn_tcid_vec(const UINT32 cdfs_md_id, CVECTOR *cdfsdn_tcid_vec);

/*collect all npp tcid vec*/
EC_BOOL cdfs_collect_npp_tcid_vec(const UINT32 cdfs_md_id, CVECTOR *cdfsnpp_tcid_vec);

/*collect all dn & npp tcid vec*/
EC_BOOL cdfs_collect_cluster_tcid_vec(const UINT32 cdfs_md_id, CVECTOR *cdfs_cluster_tcid_vec);

/*collect all dn & npp & client tcid vec*/
EC_BOOL cdfs_collect_all_tcid_vec(const UINT32 cdfs_md_id, CVECTOR *cdfs_all_tcid_vec);

/**
*
*  create name node pool
*
**/
EC_BOOL cdfs_create_npp(const UINT32 cdfs_md_id, const UINT32 cdfsnp_mode, const UINT32 cdfsnp_disk_max_num, const UINT32 cdfsnp_support_max_num, const UINT32 cdfsnp_first_chash_algo_id, const UINT32 cdfsnp_second_chash_algo_id, const CSTRING *cdfsnp_db_root_dir);

EC_BOOL cdfs_add_npp(const UINT32 cdfs_md_id, const UINT32 cdfsnpp_tcid);

EC_BOOL cdfs_add_dn(const UINT32 cdfs_md_id, const UINT32 cdfsdn_tcid);

EC_BOOL cdfs_add_dn_vec(const UINT32 cdfs_md_id);

EC_BOOL cdfs_add_npp_vec(const UINT32 cdfs_md_id);

EC_BOOL cdfs_reg_npp(const UINT32 cdfs_md_id, const UINT32 cdfsnpp_tcid);

EC_BOOL cdfs_reg_dn(const UINT32 cdfs_md_id, const UINT32 cdfsdn_tcid);

EC_BOOL cdfs_reg_dn_vec(const UINT32 cdfs_md_id);

EC_BOOL cdfs_reg_npp_vec(const UINT32 cdfs_md_id);

/**
*
*  check existing of a dir
*
**/
EC_BOOL cdfs_find_dir(const UINT32 cdfs_md_id, const CSTRING *dir_path);

/**
*
*  check existing of a file
*
**/
EC_BOOL cdfs_find_file(const UINT32 cdfs_md_id, const CSTRING *file_path);

/**
*
*  check existing of a file or a dir
*
**/
EC_BOOL cdfs_find(const UINT32 cdfs_md_id, const CSTRING *path);

/**
*
*  check existing of a file or a dir
*
**/
EC_BOOL cdfs_exists(const UINT32 cdfs_md_id, const CSTRING *path);
EC_BOOL cdfs_exists_npp(const UINT32 cdfs_md_id, const CSTRING *path);

/**
*
*  check existing of a file
*
**/
EC_BOOL cdfs_is_file(const UINT32 cdfs_md_id, const CSTRING *file_path);

/**
*
*  check existing of a dir
*
**/
EC_BOOL cdfs_is_dir(const UINT32 cdfs_md_id, const CSTRING *dir_path);

/**
*
*  truncate a file
*
**/
EC_BOOL cdfs_truncate(const UINT32 cdfs_md_id, const CSTRING *file_path, const UINT32 fsize, const UINT32 replica_num);

/**
*
*  write a file
*
**/
EC_BOOL cdfs_write(const UINT32 cdfs_md_id, const CSTRING *file_path, const CBYTES *cbytes, const UINT32 replica_num);

/**
*
*  read a file
*
**/
EC_BOOL cdfs_read(const UINT32 cdfs_md_id, const CSTRING *file_path, CBYTES *cbytes);

/**
*
*  update a file
*
**/
EC_BOOL cdfs_update(const UINT32 cdfs_md_id, const CSTRING *file_path, const CBYTES *cbytes);

/**
*
*  log lost fnode info
*
**/
void cdfs_lost_fnode_log(const UINT32 cdfs_md_id, const CSTRING *file_path, const CDFSNP_FNODE *cdfsnp_fnode);

/**
*
*  log incomplete replica info
*
**/
void cdfs_lost_replica_log(const UINT32 cdfs_md_id, const CSTRING *file_path, const UINT32 replica_num, const CDFSNP_FNODE *cdfsnp_fnode);

/**
*
*  create data node
*
**/
EC_BOOL cdfs_create_dn(const UINT32 cdfs_md_id, const CSTRING *root_dir, const UINT32 disk_num, const UINT32 max_gb_num_of_disk_space);

/**
*
*  open data node
*
**/
EC_BOOL cdfs_open_dn(const UINT32 cdfs_md_id, const CSTRING *root_dir);

/**
*
*  close data node
*
**/
EC_BOOL cdfs_close_dn(const UINT32 cdfs_md_id);

/**
*
*  close and flush data node
*
**/
EC_BOOL cdfs_close_with_flush_dn(const UINT32 cdfs_md_id);

/**
*
*  truncate data node in pipe line
*
**/
EC_BOOL cdfs_truncate_dn_ppl(const UINT32 cdfs_md_id, const UINT32 fsize, const UINT32 cdfsnp_inode_pos, CDFSNP_FNODE *cdfsnp_fnode, CDFSDN_STAT *cdfsdn_stat);

/**
*
*  truncate data node
*
**/
EC_BOOL cdfs_truncate_dn_p(const UINT32 cdfs_md_id, const UINT32 fsize, const UINT32 replica_num, CDFSNP_FNODE *cdfsnp_fnode);

/**
*
*  update data node
*
**/
EC_BOOL cdfs_update_dn_p(const UINT32 cdfs_md_id, const CBYTES *cbytes, const CDFSNP_FNODE *cdfsnp_fnode);

/**
*
*  update data node in pipe line
*
**/
EC_BOOL cdfs_update_dn_ppl(const UINT32 cdfs_md_id, const CBYTES *cbytes, const UINT32 cdfsnp_inode_pos, const CDFSNP_FNODE *cdfsnp_fnode);

/**
*
*  write data node in pipe line
*
**/
EC_BOOL cdfs_write_dn_ppl(const UINT32 cdfs_md_id, const CBYTES *cbytes, const UINT32 cdfsnp_inode_pos, CDFSNP_FNODE *cdfsnp_fnode, CDFSDN_STAT *cdfsdn_stat);

/**
*
*  read data node in pipe line
*
**/
EC_BOOL cdfs_read_dn_ppl(const UINT32 cdfs_md_id, const UINT32 cdfsnp_inode_pos, const CDFSNP_FNODE *cdfsnp_fnode, CBYTES *cbytes);

/**
*
*  write data node
*
**/
EC_BOOL cdfs_write_dn_p(const UINT32 cdfs_md_id, const CBYTES *cbytes, const UINT32 replica_num, CDFSNP_FNODE *cdfsnp_fnode);

/**
*
*  read data node
*
**/
EC_BOOL cdfs_read_dn(const UINT32 cdfs_md_id, const CDFSNP_FNODE *cdfsnp_fnode, CBYTES *cbytes);

/**
*
*  read data node
*
**/
EC_BOOL cdfs_read_dn_p_with_tcid_filter(const UINT32 cdfs_md_id, const CVECTOR *cdfsdn_tcid_vec, const CDFSNP_FNODE *cdfsnp_fnode, CBYTES *cbytes);

/**
*
*  read data node
*
**/
EC_BOOL cdfs_read_dn_p(const UINT32 cdfs_md_id, const CDFSNP_FNODE *cdfsnp_fnode, CBYTES *cbytes);

/**
*
*  write a fnode to name node
*
**/
EC_BOOL cdfs_write_npp_p(const UINT32 cdfs_md_id, const CSTRING *file_path, const UINT32 replica_num, const CDFSNP_FNODE *cdfsnp_fnode);

/**
*
*  read a fnode from name node
*
**/
EC_BOOL cdfs_read_npp_p(const UINT32 cdfs_md_id, const CSTRING *file_path, CDFSNP_FNODE *cdfsnp_fnode);

/**
*
*  update a fnode to name node
*
**/
EC_BOOL cdfs_update_npp_p(const UINT32 cdfs_md_id, const CSTRING *file_path, const CDFSNP_FNODE *cdfsnp_fnode);

/**
*
*  delete a file or dir from all npp
*
**/
EC_BOOL cdfs_delete_npp_p(const UINT32 cdfs_md_id, const CSTRING *path, const UINT32 dflag, CVECTOR *cdfsnp_fnode_vec);

/**
*
*  write a fnode to name node
*
**/
EC_BOOL cdfs_write_npp(const UINT32 cdfs_md_id, const CSTRING *file_path, const CDFSNP_FNODE *cdfsnp_fnode);

/**
*
*  read a fnode from name node
*
**/
EC_BOOL cdfs_read_npp(const UINT32 cdfs_md_id, const CSTRING *file_path, CDFSNP_FNODE *cdfsnp_fnode);

/**
*
*  delete a file or dir from current npp
*
**/
EC_BOOL cdfs_delete_npp(const UINT32 cdfs_md_id, const CSTRING *path, const UINT32 dflag, CVECTOR *cdfsnp_fnode_vec);


EC_BOOL cdfs_delete(const UINT32 cdfs_md_id, const CSTRING *path, const UINT32 dflag);

/**
*
*  mkdir in current name node pool
*
**/
EC_BOOL cdfs_mkdir(const UINT32 cdfs_md_id, const CSTRING *path_cstr);

/**
*
*  mkdir to all name node pool
*
**/
EC_BOOL cdfs_mkdir_npp(const UINT32 cdfs_md_id, const CSTRING *path_cstr);

/**
*
*  mkdir to all name node pool
*
**/
EC_BOOL cdfs_mkdir_p(const UINT32 cdfs_md_id, const CSTRING *path_cstr);

/**
*
*  update a fnode to name node
*
**/
EC_BOOL cdfs_update_npp(const UINT32 cdfs_md_id, const CSTRING *file_path, const CDFSNP_FNODE *cdfsnp_fnode);

/**
*
*  delete file data from current dn
*
**/
EC_BOOL cdfs_delete_dn(const UINT32 cdfs_md_id, const UINT32 path_layout, const UINT32 offset);

/**
*
*  delete file data from all dn
*
**/
EC_BOOL cdfs_delete_dn_p(const UINT32 cdfs_md_id, const CVECTOR *cdfsnp_fnode_vec);

/**
*
*  query a file
*
**/
EC_BOOL cdfs_qfile(const UINT32 cdfs_md_id, const CSTRING *file_path, CDFSNP_ITEM  *cdfsnp_item);

/**
*
*  query a dir
*
**/
EC_BOOL cdfs_qdir(const UINT32 cdfs_md_id, const CSTRING *dir_path, CVECTOR  *cdfsnp_item_vec);

/**
*
*  query and list full path of a file or dir
*
**/
EC_BOOL cdfs_qlist_path(const UINT32 cdfs_md_id, const CSTRING *file_path, CVECTOR  *path_cstr_vec);
EC_BOOL cdfs_qlist_path_npp(const UINT32 cdfs_md_id, const CSTRING *file_path, CVECTOR  *path_cstr_vec);

/**
*
*  query and list short name of a file or dir
*
**/
EC_BOOL cdfs_qlist_seg(const UINT32 cdfs_md_id, const CSTRING *file_path, CVECTOR  *seg_cstr_vec);
EC_BOOL cdfs_qlist_seg_npp(const UINT32 cdfs_md_id, const CSTRING *file_seg, CVECTOR  *seg_cstr_vec);

/**
*
*  flush name node pool
*
**/
EC_BOOL cdfs_flush_npp(const UINT32 cdfs_md_id, const UINT32 cdfsnpp_tcid);

/**
*
*  flush data node
*
*
**/
EC_BOOL cdfs_flush_dn(const UINT32 cdfs_md_id, const UINT32 cdfsdn_tcid);

/**
*
*  flush specific name node
*
*
**/
void    cdfs_flush_np(const UINT32 cdfs_md_id, const UINT32 cdfsnp_path_layout);

/**
*
*  check this CDFS is name node pool or not
*
*
**/
EC_BOOL cdfs_is_npp(const UINT32 cdfs_md_id);

/**
*
*  check this CDFS is data node or not
*
*
**/
EC_BOOL cdfs_is_dn(const UINT32 cdfs_md_id);

/**
*
*  list all added or registed name node pool to this CDFS
*
*
**/
EC_BOOL cdfs_list_npp(const UINT32 cdfs_md_id, LOG *log);

/**
*
*  list all added or registed data nodes to this CDFS
*
*
**/
EC_BOOL cdfs_list_dn(const UINT32 cdfs_md_id, LOG *log);

/**
*
*  count file num under specific path
*  if path is regular file, return file_num 1
*  if path is directory, return file num under it
*
**/
EC_BOOL cdfs_file_num(const UINT32 cdfs_md_id, const CSTRING *path_cstr, UINT32 *file_num);

/**
*
*  get file size of specific file given full path name
*
**/
EC_BOOL cdfs_file_size(const UINT32 cdfs_md_id, const CSTRING *path_cstr, UINT32 *file_size);

/**
*
*  check replica num and tcid set and path layout validity
*
**/
EC_BOOL cdfs_check_replicas(const UINT32 cdfs_md_id, const CSTRING *file_path, const UINT32 replica_num, const CVECTOR *tcid_vec);

/**
*
*  check file content on data node
*
**/
EC_BOOL cdfs_check_file_content(const UINT32 cdfs_md_id, const UINT32 path_layout, const UINT32 offset, const UINT32 file_size, const CSTRING *file_content_cstr);

/**
*
*  check content with sepcific len of all replica files
*
**/
EC_BOOL cdfs_check_replica_files_content(const UINT32 cdfs_md_id, const CSTRING *file_path, const UINT32 file_size, const CSTRING *file_content_cstr);

/**
*
*  check inode info belong to specific cdfsdn block on some tcid
*
**/
EC_BOOL cdfs_figure_out_block(const UINT32 cdfs_md_id, const UINT32 tcid, const UINT32 path_layout, LOG *log);

/**
*
*  show name node pool info if it is npp
*
*
**/
EC_BOOL cdfs_show_npp(const UINT32 cdfs_md_id, LOG *log);

/**
*
*  show cdfsdn info if it is dn
*
*
**/
EC_BOOL cdfs_show_dn(const UINT32 cdfs_md_id, LOG *log);

/*debug*/
EC_BOOL cdfs_show_cached_np(const UINT32 cdfs_md_id, LOG *log);

EC_BOOL cdfs_show_specific_np(const UINT32 cdfs_md_id, const UINT32 cdfsnp_path_layout, LOG *log);

/**
*
*  import lost fnode records from current np to remote np
*
*
**/
EC_BOOL cdfs_import_lost_fnode_from_file(const UINT32 cdfs_md_id, const CSTRING *file_name, const UINT32 des_tcid);

/**
*
*  import/complete lost replica from current dn
*
*
**/
EC_BOOL cdfs_import_lost_replica_from_file(const UINT32 cdfs_md_id, const CSTRING *file_name, const UINT32 des_tcid);

/**
*
*   disable write access to a mod node in dn mod_mgr
*
**/
EC_BOOL cdfs_disable_write_access_dn(const UINT32 cdfs_md_id, const UINT32 cdfsdn_tcid);

/**
*
*   get attr of a file or path
*
**/

EC_BOOL cdfs_transfer_out(const UINT32 cdfs_md_id, const UINT32 des_datanode_tcid, UINT32 *src_block_path_layout, UINT32 *des_block_path_layout);

EC_BOOL cdfs_transfer_in(const UINT32 cdfs_md_id, const CDFSDN_RECORD *cdfsdn_record, const CDFSDN_BLOCK *cdfsdn_block, UINT32 *des_block_path_layout);

EC_BOOL cdfs_transfer(const UINT32 cdfs_md_id, const UINT32 src_datanode_tcid, const UINT32 des_datanode_tcid, const UINT32 transfer_max_gb);

EC_BOOL cdfs_transfer_update(const UINT32 cdfs_md_id, const UINT32 src_datanode_tcid, const UINT32 src_block_path_layout, const UINT32 des_datanode_tcid, const UINT32 des_block_path_layout);

EC_BOOL cdfs_snapshot_dn(const UINT32 cdfs_md_id);

EC_BOOL cdfs_snapshot_npp(const UINT32 cdfs_md_id);

EC_BOOL cdfs_snapshot(const UINT32 cdfs_md_id);


#endif /*_CDFS_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

