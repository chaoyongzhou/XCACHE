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

#ifndef _CDC_H
#define _CDC_H

#include <stdlib.h>
#include <stdio.h>

#include "type.h"

#include "cdcnp.h"
#include "cdcdn.h"

#include "caio.h"

#define CDC_RECYCLE_MAX_NUM                ((UINT32)~0)

#define CDC_TRY_RETIRE_MAX_NUM             (8)
#define CDC_TRY_RECYCLE_MAX_NUM            (128)

#define CDC_OFFSET_ERR                     ((UINT32)~0)

#define CDC_LOADING_DN_TIMEOUT_NSEC        (60) /*second*/
#define CDC_FLUSHING_DN_TIMEOUT_NSEC       (60) /*second*/

#define CDC_LOADING_NP_TIMEOUT_NSEC        (60) /*second*/
#define CDC_FLUSHING_NP_TIMEOUT_NSEC       (60) /*second*/

#define CDC_FILE_AIO_TIMEOUT_NSEC          (30) /*second*/

typedef struct
{
    int                 fd;
    int                 rsvd01;

    UINT32              s_offset;
    UINT32              e_offset;
    UINT32              c_offset; /*temporary*/

    CDCDN              *cdcdn;
    CDCNP              *cdcnp;

    CAIO_MD            *caio_md;

    uint32_t            cdcdn_flushing_flag:1;
    uint32_t            cdcdn_loading_flag :1;
    uint32_t            cdcnp_flushing_flag:1;
    uint32_t            cdcnp_loading_flag :1;
    uint32_t            flushing_flag      :1;
    uint32_t            loading_flag       :1;
    uint32_t            rsvd02             :26;
    uint32_t            rsvd03;
}CDC_MD;

#define CDC_MD_FD(cdc_md)                       ((cdc_md)->fd)
#define CDC_MD_S_OFFSET(cdc_md)                 ((cdc_md)->s_offset)
#define CDC_MD_E_OFFSET(cdc_md)                 ((cdc_md)->e_offset)
#define CDC_MD_C_OFFSET(cdc_md)                 ((cdc_md)->c_offset)
#define CDC_MD_DN(cdc_md)                       ((cdc_md)->cdcdn)
#define CDC_MD_NP(cdc_md)                       ((cdc_md)->cdcnp)
#define CDC_MD_CAIO_MD(cdc_md)                  ((cdc_md)->caio_md)

#define CDC_MD_FLUSHING_FLAG(cdc_md)            ((cdc_md)->flushing_flag)
#define CDC_MD_LOADING_FLAG(cdc_md)             ((cdc_md)->loading_flag)

#define CDC_MD_DN_FLUSHING_FLAG(cdc_md)         ((cdc_md)->cdcdn_flushing_flag)
#define CDC_MD_DN_LOADING_FLAG(cdc_md)          ((cdc_md)->cdcdn_loading_flag)
#define CDC_MD_NP_FLUSHING_FLAG(cdc_md)         ((cdc_md)->cdcnp_flushing_flag)
#define CDC_MD_NP_LOADING_FLAG(cdc_md)          ((cdc_md)->cdcnp_loading_flag)

typedef struct
{
    CDC_MD             *cdc_md;

    UINT32             *i_data_len;
    UINT32             *f_i_offset;
    UINT32              f_s_offset;
    UINT32              f_e_offset;
    UINT32              f_c_offset;
    uint32_t            f_size;
    uint32_t            f_old_size;
    UINT8              *m_buff;
    UINT32              m_len;

    CBYTES              cbytes;

    CDCNP_KEY           cdcnp_key;
    CDCNP_FNODE         cdcnp_fnode;
    CDCNP_FNODE        *t_cdcnp_fnode;

    CAIO_CB             caio_cb;
}CDC_FILE_AIO;

#define CDC_FILE_AIO_CDC_MD(cdc_file_aio)            ((cdc_file_aio)->cdc_md)
#define CDC_FILE_AIO_I_DATA_LEN(cdc_file_aio)        ((cdc_file_aio)->i_data_len)
#define CDC_FILE_AIO_F_I_OFFSET(cdc_file_aio)        ((cdc_file_aio)->f_i_offset)
#define CDC_FILE_AIO_F_S_OFFSET(cdc_file_aio)        ((cdc_file_aio)->f_s_offset)
#define CDC_FILE_AIO_F_E_OFFSET(cdc_file_aio)        ((cdc_file_aio)->f_e_offset)
#define CDC_FILE_AIO_F_C_OFFSET(cdc_file_aio)        ((cdc_file_aio)->f_c_offset)
#define CDC_FILE_AIO_F_SIZE(cdc_file_aio)            ((cdc_file_aio)->f_size)
#define CDC_FILE_AIO_F_OLD_SIZE(cdc_file_aio)        ((cdc_file_aio)->f_old_size)
#define CDC_FILE_AIO_M_BUFF(cdc_file_aio)            ((cdc_file_aio)->m_buff)
#define CDC_FILE_AIO_M_LEN(cdc_file_aio)             ((cdc_file_aio)->m_len)
#define CDC_FILE_AIO_CBYTES(cdc_file_aio)            (&((cdc_file_aio)->cbytes))
#define CDC_FILE_AIO_CDCNP_KEY(cdc_file_aio)         (&((cdc_file_aio)->cdcnp_key))
#define CDC_FILE_AIO_CDCNP_FNODE(cdc_file_aio)       (&((cdc_file_aio)->cdcnp_fnode))
#define CDC_FILE_AIO_T_CDCNP_FNODE(cdc_file_aio)     ((cdc_file_aio)->t_cdcnp_fnode)
#define CDC_FILE_AIO_CAIO_CB(cdc_file_aio)           (&((cdc_file_aio)->caio_cb))

/**
*
* start CDC module
*
**/
CDC_MD *cdc_start(const int fd, const UINT32 offset, const UINT32 rdisk_size/*in GB*/);

/**
*
* end CDC module
*
**/
void cdc_end(CDC_MD *cdc_md);

/**
*
* create CDC
*
**/
EC_BOOL cdc_create(CDC_MD *cdc_md);

/**
*
* load CDC
*
**/
EC_BOOL cdc_load(CDC_MD *cdc_md);

EC_BOOL cdc_load_aio(CDC_MD *cdc_md, CAIO_CB *caio_cb);

/**
*
* flush CDC
*
**/
EC_BOOL cdc_flush(CDC_MD *cdc_md);

EC_BOOL cdc_flush_aio(CDC_MD *cdc_md, CAIO_CB *caio_cb);

/**
*
* print CDC module
*
**/
void cdc_print(LOG *log, const CDC_MD *cdc_md);

/**
*
* aio eventfd of CDC module
*
**/
int cdc_get_eventfd(CDC_MD *cdc_md);

/**
*
* aio event handler of CDC module
*
**/
EC_BOOL cdc_event_handler(CDC_MD *cdc_md);

/**
*
* process CDC
*
**/
void cdc_process(CDC_MD *cdc_md);

/*for debug*/
EC_BOOL cdc_poll(CDC_MD *cdc_md);

/**
*
*  create name node
*
**/
EC_BOOL cdc_create_np(CDC_MD *cdc_md, UINT32 *s_offset, const UINT32 e_offset);

/**
*
*  close name node
*
**/
EC_BOOL cdc_close_np(CDC_MD *cdc_md);

/**
*
*  load name node from disk
*
**/
EC_BOOL cdc_load_np(CDC_MD *cdc_md, UINT32 *s_offset, const UINT32 e_offset);

EC_BOOL cdc_load_np_aio(CDC_MD *cdc_md, CAIO_CB *caio_cb);

/**
*
*  flush name node to disk
*
**/
EC_BOOL cdc_flush_np(CDC_MD *cdc_md);

EC_BOOL cdc_flush_np_aio(CDC_MD *cdc_md, CAIO_CB *caio_cb);

/**
*
*  create data node
*
**/
EC_BOOL cdc_create_dn(CDC_MD *cdc_md, UINT32 *s_offset, const UINT32 e_offset);

/**
*
*  load data node from disk
*
**/
EC_BOOL cdc_load_dn(CDC_MD *cdc_md, UINT32 *s_offset, const UINT32 e_offset);

EC_BOOL cdc_load_dn_aio(CDC_MD *cdc_md, CAIO_CB *caio_cb);

/**
*
*  flush data node to disk
*
**/
EC_BOOL cdc_flush_dn(CDC_MD *cdc_md);

EC_BOOL cdc_flush_dn_aio(CDC_MD *cdc_md, CAIO_CB *caio_cb);

/**
*
*  close data node
*
**/
EC_BOOL cdc_close_dn(CDC_MD *cdc_md);


/**
*
*  find intersected range
*
**/
EC_BOOL cdc_find_intersected(CDC_MD *cdc_md, const CDCNP_KEY *cdcnp_key);

/**
*
*  find closest range
*
**/
EC_BOOL cdc_find_closest(CDC_MD *cdc_md, const CDCNP_KEY *cdcnp_key, CDCNP_KEY *cdcnp_key_closest);


/**
*
*  reserve space from dn
*
**/
EC_BOOL cdc_reserve_dn(CDC_MD *cdc_md, const UINT32 data_len, CDCNP_FNODE *cdcnp_fnode);

/**
*
*  release space to dn
*
**/
EC_BOOL cdc_release_dn(CDC_MD *cdc_md, const CDCNP_FNODE *cdcnp_fnode);

CDC_FILE_AIO *cdc_file_aio_new();

EC_BOOL cdc_file_aio_init(CDC_FILE_AIO *cdc_file_aio);

EC_BOOL cdc_file_aio_clean(CDC_FILE_AIO *cdc_file_aio);

EC_BOOL cdc_file_aio_free(CDC_FILE_AIO *cdc_file_aio);

void cdc_file_aio_print(LOG *log, const CDC_FILE_AIO *cdc_file_aio);


/**
*
*  read a file (POSIX style interface)
*
**/
EC_BOOL cdc_file_read(CDC_MD *cdc_md, UINT32 *offset, const UINT32 rsize, UINT8 *buff);

EC_BOOL cdc_file_read_aio(CDC_MD *cdc_md, UINT32 *offset, const UINT32 rsize, UINT8 *buff, CAIO_CB *caio_cb);

/**
*
*  write a file (POSIX style interface)
*
**/
EC_BOOL cdc_file_write(CDC_MD *cdc_md, UINT32 *offset, const UINT32 wsize, UINT8 *buff);

EC_BOOL cdc_file_write_aio(CDC_MD *cdc_md, UINT32 *offset, const UINT32 wsize, UINT8 *buff, CAIO_CB *caio_cb);

/**
*
*  delete a file (POSIX style interface)
*
**/
EC_BOOL cdc_file_delete(CDC_MD *cdc_md, UINT32 *offset, const UINT32 dsize);

/**
*
*  write a page
*
**/
EC_BOOL cdc_page_write(CDC_MD *cdc_md, const CDCNP_KEY *cdcnp_key, const CBYTES *cbytes);

EC_BOOL cdc_page_write_aio(CDC_MD *cdc_md, const CDCNP_KEY *cdcnp_key, const CBYTES *cbytes, CAIO_CB *caio_cb);

/**
*
*  read a page
*
**/
EC_BOOL cdc_page_read(CDC_MD *cdc_md, const CDCNP_KEY *cdcnp_key, CBYTES *cbytes);

EC_BOOL cdc_page_read_aio(CDC_MD *cdc_md, const CDCNP_KEY *cdcnp_key, CBYTES *cbytes, CAIO_CB *caio_cb);

/**
*
*  write a page at offset
*
**/
EC_BOOL cdc_page_write_e(CDC_MD *cdc_md, const CDCNP_KEY *cdcnp_key, UINT32 *offset, const UINT32 max_len, const CBYTES *cbytes);

EC_BOOL cdc_page_write_e_aio(CDC_MD *cdc_md, const CDCNP_KEY *cdcnp_key, UINT32 *offset, const UINT32 max_len, const CBYTES *cbytes, CAIO_CB *caio_cb);

/**
*
*  read a page from offset
*
**/
EC_BOOL cdc_page_read_e(CDC_MD *cdc_md, const CDCNP_KEY *cdcnp_key, UINT32 *offset, const UINT32 max_len, CBYTES *cbytes);

EC_BOOL cdc_page_read_e_aio(CDC_MD *cdc_md, const CDCNP_KEY *cdcnp_key, UINT32 *offset, const UINT32 max_len, CBYTES *cbytes, CAIO_CB *caio_cb);

/**
*
*  export data into data node
*
**/
EC_BOOL cdc_export_dn(CDC_MD *cdc_md, const CBYTES *cbytes, const CDCNP_FNODE *cdcnp_fnode);

EC_BOOL cdc_export_dn_aio(CDC_MD *cdc_md, const CBYTES *cbytes, const CDCNP_FNODE *cdcnp_fnode, CAIO_CB *caio_cb);

/**
*
*  write data node
*
**/
EC_BOOL cdc_write_dn(CDC_MD *cdc_md, const CBYTES *cbytes, CDCNP_FNODE *cdcnp_fnode);

EC_BOOL cdc_write_dn_aio(CDC_MD *cdc_md, const CBYTES *cbytes, CDCNP_FNODE *cdcnp_fnode, CAIO_CB *caio_cb);

/**
*
*  read data node
*
**/
EC_BOOL cdc_read_dn(CDC_MD *cdc_md, const CDCNP_FNODE *cdcnp_fnode, CBYTES *cbytes);

EC_BOOL cdc_read_dn_aio(CDC_MD *cdc_md, const CDCNP_FNODE *cdcnp_fnode, CBYTES *cbytes, CAIO_CB *caio_cb);

/**
*
*  write data node at offset in the specific file
*
**/
EC_BOOL cdc_write_e_dn(CDC_MD *cdc_md, CDCNP_FNODE *cdcnp_fnode, UINT32 *offset, const UINT32 max_len, const CBYTES *cbytes);

EC_BOOL cdc_write_e_dn_aio(CDC_MD *cdc_md, CDCNP_FNODE *cdcnp_fnode, UINT32 *offset, const UINT32 max_len, const CBYTES *cbytes, CAIO_CB *caio_cb);

/**
*
*  read data node from offset in the specific file
*
**/
EC_BOOL cdc_read_e_dn(CDC_MD *cdc_md, const CDCNP_FNODE *cdcnp_fnode, UINT32 *offset, const UINT32 max_len, CBYTES *cbytes);

EC_BOOL cdc_read_e_dn_aio(CDC_MD *cdc_md, const CDCNP_FNODE *cdcnp_fnode, UINT32 *offset, const UINT32 max_len, CBYTES *cbytes, CAIO_CB *caio_cb);

/**
*
*  delete all intersected file
*
**/
EC_BOOL cdc_delete_intersected(CDC_MD *cdc_md, const CDCNP_KEY *cdcnp_key);

/**
*
*  delete a page
*
**/
EC_BOOL cdc_page_delete(CDC_MD *cdc_md, const CDCNP_KEY *cdcnp_key);

/**
*
*  update a page
*
**/
EC_BOOL cdc_page_update(CDC_MD *cdc_md, const CDCNP_KEY *cdcnp_key, const CBYTES *cbytes);

/**
*
*  count file num under specific path
*  if path is regular file, return file_num 1
*  if path is directory, return file num under it
*
**/
EC_BOOL cdc_file_num(CDC_MD *cdc_md, UINT32 *file_num);

/**
*
*  get file size of specific file given full path name
*
**/
EC_BOOL cdc_file_size(CDC_MD *cdc_md, const CDCNP_KEY *cdcnp_key, uint64_t *file_size);

/**
*
*  search in current name node
*
**/
EC_BOOL cdc_search(CDC_MD *cdc_md, const CDCNP_KEY *cdcnp_key);

/**
*
*  empty recycle
*
**/
EC_BOOL cdc_recycle(CDC_MD *cdc_md, const UINT32 max_num, UINT32 *complete_num);

/**
*
*  retire files
*
**/
EC_BOOL cdc_retire(CDC_MD *cdc_md, const UINT32 max_num, UINT32 *complete_num);

/**
*
*  show name node
*
*
**/
EC_BOOL cdc_show_np(const CDC_MD *cdc_md, LOG *log);

/**
*
*  show name node LRU
*
*
**/
EC_BOOL cdc_show_np_lru_list(const CDC_MD *cdc_md, LOG *log);

/**
*
*  show name node DEL
*
*
**/
EC_BOOL cdc_show_np_del_list(const CDC_MD *cdc_md, LOG *log);

/**
*
*  show name node BITMAP
*
*
**/
EC_BOOL cdc_show_np_bitmap(const CDC_MD *cdc_md, LOG *log);

/**
*
*  show cdcdn info if it is dn
*
*
**/
EC_BOOL cdc_show_dn(const CDC_MD *cdc_md, LOG *log);

/**
*
*  show all files
*
**/

EC_BOOL cdc_show_files(const CDC_MD *cdc_md, LOG *log);

#endif /*_CDC_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

