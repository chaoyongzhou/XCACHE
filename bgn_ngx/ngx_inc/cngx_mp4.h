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

#ifndef _CNGX_MP4_H
#define _CNGX_MP4_H

/*copied and modified from ngx_http_mp4_module*/

/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define CNGX_MP4_TRAK_ATOM     0
#define CNGX_MP4_TKHD_ATOM     1
#define CNGX_MP4_MDIA_ATOM     2
#define CNGX_MP4_MDHD_ATOM     3
#define CNGX_MP4_HDLR_ATOM     4
#define CNGX_MP4_MINF_ATOM     5
#define CNGX_MP4_VMHD_ATOM     6
#define CNGX_MP4_SMHD_ATOM     7
#define CNGX_MP4_DINF_ATOM     8
#define CNGX_MP4_STBL_ATOM     9
#define CNGX_MP4_STSD_ATOM    10
#define CNGX_MP4_STTS_ATOM    11
#define CNGX_MP4_STTS_DATA    12
#define CNGX_MP4_STSS_ATOM    13
#define CNGX_MP4_STSS_DATA    14
#define CNGX_MP4_CTTS_ATOM    15
#define CNGX_MP4_CTTS_DATA    16
#define CNGX_MP4_STSC_ATOM    17
#define CNGX_MP4_STSC_START   18
#define CNGX_MP4_STSC_DATA    19
#define CNGX_MP4_STSC_END     20
#define CNGX_MP4_STSZ_ATOM    21
#define CNGX_MP4_STSZ_DATA    22
#define CNGX_MP4_STCO_ATOM    23
#define CNGX_MP4_STCO_DATA    24
#define CNGX_MP4_CO64_ATOM    25
#define CNGX_MP4_CO64_DATA    26

#define CNGX_MP4_LAST_ATOM    CNGX_MP4_CO64_DATA


typedef struct {
    size_t                buffer_size;
    size_t                max_buffer_size;
} cngx_mp4_conf_t;


typedef struct {
    u_char                chunk[4];
    u_char                samples[4];
    u_char                id[4];
} cngx_mp4_stsc_entry_t;

typedef struct {
    uint32_t              timescale;
    uint32_t              time_to_sample_entries;
    uint32_t              sample_to_chunk_entries;
    uint32_t              sync_samples_entries;
    uint32_t              composition_offset_entries;
    uint32_t              sample_sizes_entries;
    uint32_t              chunks;

    ngx_uint_t            start_sample;
    ngx_uint_t            end_sample;
    ngx_uint_t            start_chunk;
    ngx_uint_t            end_chunk;
    ngx_uint_t            start_chunk_samples;
    ngx_uint_t            end_chunk_samples;
    uint64_t              start_chunk_samples_size;
    uint64_t              end_chunk_samples_size;
    off_t                 start_offset;
    off_t                 end_offset;

    size_t                tkhd_size;
    size_t                mdhd_size;
    size_t                hdlr_size;
    size_t                vmhd_size;
    size_t                smhd_size;
    size_t                dinf_size;
    size_t                size;

    ngx_chain_t           out[CNGX_MP4_LAST_ATOM + 1];

    ngx_buf_t             trak_atom_buf;
    ngx_buf_t             tkhd_atom_buf;
    ngx_buf_t             mdia_atom_buf;
    ngx_buf_t             mdhd_atom_buf;
    ngx_buf_t             hdlr_atom_buf;
    ngx_buf_t             minf_atom_buf;
    ngx_buf_t             vmhd_atom_buf;
    ngx_buf_t             smhd_atom_buf;
    ngx_buf_t             dinf_atom_buf;
    ngx_buf_t             stbl_atom_buf;
    ngx_buf_t             stsd_atom_buf;
    ngx_buf_t             stts_atom_buf;
    ngx_buf_t             stts_data_buf;
    ngx_buf_t             stss_atom_buf;
    ngx_buf_t             stss_data_buf;
    ngx_buf_t             ctts_atom_buf;
    ngx_buf_t             ctts_data_buf;
    ngx_buf_t             stsc_atom_buf;
    ngx_buf_t             stsc_start_chunk_buf;
    ngx_buf_t             stsc_end_chunk_buf;
    ngx_buf_t             stsc_data_buf;
    ngx_buf_t             stsz_atom_buf;
    ngx_buf_t             stsz_data_buf;
    ngx_buf_t             stco_atom_buf;
    ngx_buf_t             stco_data_buf;
    ngx_buf_t             co64_atom_buf;
    ngx_buf_t             co64_data_buf;

    cngx_mp4_stsc_entry_t  stsc_start_chunk_entry;
    cngx_mp4_stsc_entry_t  stsc_end_chunk_entry;
} cngx_mp4_trak_t;


typedef struct {
    ngx_file_t            file;

    ngx_uint_t            modi; 

    /*file read handler*/
    ngx_int_t  (*handler)(ngx_uint_t modi, size_t size, off_t offset, uint8_t *buf, ssize_t *rsize);

    u_char               *buffer;
    u_char               *buffer_start;
    u_char               *buffer_pos;
    u_char               *buffer_end;
    size_t                buffer_size;
    size_t                max_buffer_size;

    off_t                 offset;
    off_t                 end;
    off_t                 content_length;
    ngx_uint_t            start;
    ngx_uint_t            length;
    uint32_t              timescale;
    ngx_http_request_t   *request;
    ngx_array_t           trak;
    cngx_mp4_trak_t       traks[2];

    size_t                ftyp_size;
    size_t                moov_size;

    ngx_chain_t          *out;
    ngx_chain_t           ftyp_atom;
    ngx_chain_t           moov_atom;
    ngx_chain_t           mvhd_atom;
    ngx_chain_t           mdat_atom;
    ngx_chain_t           mdat_data;

    ngx_buf_t             ftyp_atom_buf;
    ngx_buf_t             moov_atom_buf;
    ngx_buf_t             mvhd_atom_buf;
    ngx_buf_t             mdat_atom_buf;
    ngx_buf_t             mdat_data_buf;

    u_char                moov_atom_header[8];
    u_char                mdat_atom_header[16];
} cngx_mp4_file_t;

typedef ngx_int_t  (*cngx_mp4_file_read_handler)(ngx_uint_t modi, size_t size, off_t offset, uint8_t *buf, ssize_t *rsize);

typedef struct {
    char                 *name;
    ngx_int_t           (*handler)(cngx_mp4_file_t *mp4,
                                   uint64_t atom_data_size);
} cngx_mp4_atom_handler_t;


#define cngx_mp4_atom_header(mp4)   (mp4->buffer_pos - 8)
#define cngx_mp4_atom_data(mp4)     mp4->buffer_pos
#define cngx_mp4_atom_data_size(t)  (uint64_t) (sizeof(t) - 8)


#define cngx_mp4_atom_next(mp4, n)                                             \
    mp4->buffer_pos += (size_t) n;                                            \
    mp4->offset += n


#define cngx_mp4_set_atom_name(p, n1, n2, n3, n4)                              \
    ((u_char *) (p))[4] = n1;                                                 \
    ((u_char *) (p))[5] = n2;                                                 \
    ((u_char *) (p))[6] = n3;                                                 \
    ((u_char *) (p))[7] = n4

#define cngx_mp4_get_32value(p)                                                \
    ( ((uint32_t) ((u_char *) (p))[0] << 24)                                  \
    + (           ((u_char *) (p))[1] << 16)                                  \
    + (           ((u_char *) (p))[2] << 8)                                   \
    + (           ((u_char *) (p))[3]) )

#define cngx_mp4_set_32value(p, n)                                             \
    ((u_char *) (p))[0] = (u_char) ((n) >> 24);                               \
    ((u_char *) (p))[1] = (u_char) ((n) >> 16);                               \
    ((u_char *) (p))[2] = (u_char) ((n) >> 8);                                \
    ((u_char *) (p))[3] = (u_char)  (n)

#define cngx_mp4_get_64value(p)                                                \
    ( ((uint64_t) ((u_char *) (p))[0] << 56)                                  \
    + ((uint64_t) ((u_char *) (p))[1] << 48)                                  \
    + ((uint64_t) ((u_char *) (p))[2] << 40)                                  \
    + ((uint64_t) ((u_char *) (p))[3] << 32)                                  \
    + ((uint64_t) ((u_char *) (p))[4] << 24)                                  \
    + (           ((u_char *) (p))[5] << 16)                                  \
    + (           ((u_char *) (p))[6] << 8)                                   \
    + (           ((u_char *) (p))[7]) )

#define cngx_mp4_set_64value(p, n)                                             \
    ((u_char *) (p))[0] = (u_char) ((uint64_t) (n) >> 56);                    \
    ((u_char *) (p))[1] = (u_char) ((uint64_t) (n) >> 48);                    \
    ((u_char *) (p))[2] = (u_char) ((uint64_t) (n) >> 40);                    \
    ((u_char *) (p))[3] = (u_char) ((uint64_t) (n) >> 32);                    \
    ((u_char *) (p))[4] = (u_char) (           (n) >> 24);                    \
    ((u_char *) (p))[5] = (u_char) (           (n) >> 16);                    \
    ((u_char *) (p))[6] = (u_char) (           (n) >> 8);                     \
    ((u_char *) (p))[7] = (u_char)             (n)

#define cngx_mp4_last_trak(mp4)                                                \
    &((cngx_mp4_trak_t *) mp4->trak.elts)[mp4->trak.nelts - 1]

typedef struct {
    u_char    size[4];
    u_char    name[4];
} cngx_mp4_atom_header_t;

typedef struct {
    u_char    size[4];
    u_char    name[4];
    u_char    size64[8];
} cngx_mp4_atom_header64_t;

/*
 * Small excess buffer to process atoms after moov atom, mp4->buffer_start
 * will be set to this buffer part after moov atom processing.
 */
#define CNGX_MP4_MOOV_BUFFER_EXCESS  (4 * 1024)

typedef struct {
    u_char    size[4];
    u_char    name[4];
    u_char    version[1];
    u_char    flags[3];
    u_char    creation_time[4];
    u_char    modification_time[4];
    u_char    timescale[4];
    u_char    duration[4];
    u_char    rate[4];
    u_char    volume[2];
    u_char    reserved[10];
    u_char    matrix[36];
    u_char    preview_time[4];
    u_char    preview_duration[4];
    u_char    poster_time[4];
    u_char    selection_time[4];
    u_char    selection_duration[4];
    u_char    current_time[4];
    u_char    next_track_id[4];
} cngx_mp4_mvhd_atom_t;

typedef struct {
    u_char    size[4];
    u_char    name[4];
    u_char    version[1];
    u_char    flags[3];
    u_char    creation_time[8];
    u_char    modification_time[8];
    u_char    timescale[4];
    u_char    duration[8];
    u_char    rate[4];
    u_char    volume[2];
    u_char    reserved[10];
    u_char    matrix[36];
    u_char    preview_time[4];
    u_char    preview_duration[4];
    u_char    poster_time[4];
    u_char    selection_time[4];
    u_char    selection_duration[4];
    u_char    current_time[4];
    u_char    next_track_id[4];
} cngx_mp4_mvhd64_atom_t;

typedef struct {
    u_char    size[4];
    u_char    name[4];
    u_char    version[1];
    u_char    flags[3];
    u_char    creation_time[4];
    u_char    modification_time[4];
    u_char    track_id[4];
    u_char    reserved1[4];
    u_char    duration[4];
    u_char    reserved2[8];
    u_char    layer[2];
    u_char    group[2];
    u_char    volume[2];
    u_char    reserved3[2];
    u_char    matrix[36];
    u_char    width[4];
    u_char    height[4];
} cngx_mp4_tkhd_atom_t;

typedef struct {
    u_char    size[4];
    u_char    name[4];
    u_char    version[1];
    u_char    flags[3];
    u_char    creation_time[8];
    u_char    modification_time[8];
    u_char    track_id[4];
    u_char    reserved1[4];
    u_char    duration[8];
    u_char    reserved2[8];
    u_char    layer[2];
    u_char    group[2];
    u_char    volume[2];
    u_char    reserved3[2];
    u_char    matrix[36];
    u_char    width[4];
    u_char    height[4];
} cngx_mp4_tkhd64_atom_t;

typedef struct {
    u_char    size[4];
    u_char    name[4];
    u_char    version[1];
    u_char    flags[3];
    u_char    creation_time[4];
    u_char    modification_time[4];
    u_char    timescale[4];
    u_char    duration[4];
    u_char    language[2];
    u_char    quality[2];
} cngx_mp4_mdhd_atom_t;

typedef struct {
    u_char    size[4];
    u_char    name[4];
    u_char    version[1];
    u_char    flags[3];
    u_char    creation_time[8];
    u_char    modification_time[8];
    u_char    timescale[4];
    u_char    duration[8];
    u_char    language[2];
    u_char    quality[2];
} cngx_mp4_mdhd64_atom_t;


typedef struct {
    u_char    size[4];
    u_char    name[4];
    u_char    version[1];
    u_char    flags[3];
    u_char    entries[4];

    u_char    media_size[4];
    u_char    media_name[4];
} cngx_mp4_stsd_atom_t;

typedef struct {
    u_char    size[4];
    u_char    name[4];
    u_char    version[1];
    u_char    flags[3];
    u_char    entries[4];
} cngx_mp4_stts_atom_t;

typedef struct {
    u_char    count[4];
    u_char    duration[4];
} cngx_mp4_stts_entry_t;

typedef struct {
    u_char    size[4];
    u_char    name[4];
    u_char    version[1];
    u_char    flags[3];
    u_char    entries[4];
} cngx_mp4_stss_atom_t;

typedef struct {
    u_char    size[4];
    u_char    name[4];
    u_char    version[1];
    u_char    flags[3];
    u_char    entries[4];
} cngx_mp4_ctts_atom_t;

typedef struct {
    u_char    count[4];
    u_char    offset[4];
} cngx_mp4_ctts_entry_t;

typedef struct {
    u_char    size[4];
    u_char    name[4];
    u_char    version[1];
    u_char    flags[3];
    u_char    entries[4];
} cngx_mp4_stsc_atom_t;

typedef struct {
    u_char    size[4];
    u_char    name[4];
    u_char    version[1];
    u_char    flags[3];
    u_char    uniform_size[4];
    u_char    entries[4];
} cngx_mp4_stsz_atom_t;

typedef struct {
    u_char    size[4];
    u_char    name[4];
    u_char    version[1];
    u_char    flags[3];
    u_char    entries[4];
} cngx_mp4_stco_atom_t;

typedef struct {
    u_char    size[4];
    u_char    name[4];
    u_char    version[1];
    u_char    flags[3];
    u_char    entries[4];
} cngx_mp4_co64_atom_t;


ngx_int_t cngx_mp4_process(cngx_mp4_file_t *mp4);

#endif /*_CNGX_MP4_H*/

#endif/*(SWITCH_ON == NGX_BGN_SWITCH)*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/



