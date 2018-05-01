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
#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_request.h>

#include "type.h"
#include "mm.h"
#include "log.h"
#include "cstring.h"

#include "carray.h"

#include "chttp.h"
#include "cngx.h"
#include "cngx_mp4.h"

#include "crfsmon.h"
#include "ccache.h"

/*copied and modified from ngx_http_mp4_module*/

/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */

static ngx_int_t cngx_mp4_read_atom(cngx_mp4_file_t *mp4,
    cngx_mp4_atom_handler_t *atom, uint64_t atom_data_size);
static ngx_int_t cngx_mp4_read(cngx_mp4_file_t *mp4, size_t size);
static ngx_int_t cngx_mp4_read_ftyp_atom(cngx_mp4_file_t *mp4,
    uint64_t atom_data_size);
static ngx_int_t cngx_mp4_read_moov_atom(cngx_mp4_file_t *mp4,
    uint64_t atom_data_size);
static ngx_int_t cngx_mp4_read_mdat_atom(cngx_mp4_file_t *mp4,
    uint64_t atom_data_size);
static size_t cngx_mp4_update_mdat_atom(cngx_mp4_file_t *mp4,
    off_t start_offset, off_t end_offset);
static ngx_int_t cngx_mp4_read_mvhd_atom(cngx_mp4_file_t *mp4,
    uint64_t atom_data_size);
static ngx_int_t cngx_mp4_read_trak_atom(cngx_mp4_file_t *mp4,
    uint64_t atom_data_size);
static void cngx_mp4_update_trak_atom(cngx_mp4_file_t *mp4,
    cngx_mp4_trak_t *trak);
static ngx_int_t cngx_mp4_read_cmov_atom(cngx_mp4_file_t *mp4,
    uint64_t atom_data_size);
static ngx_int_t cngx_mp4_read_tkhd_atom(cngx_mp4_file_t *mp4,
    uint64_t atom_data_size);
static ngx_int_t cngx_mp4_read_mdia_atom(cngx_mp4_file_t *mp4,
    uint64_t atom_data_size);
static void cngx_mp4_update_mdia_atom(cngx_mp4_file_t *mp4,
    cngx_mp4_trak_t *trak);
static ngx_int_t cngx_mp4_read_mdhd_atom(cngx_mp4_file_t *mp4,
    uint64_t atom_data_size);
static ngx_int_t cngx_mp4_read_hdlr_atom(cngx_mp4_file_t *mp4,
    uint64_t atom_data_size);
static ngx_int_t cngx_mp4_read_minf_atom(cngx_mp4_file_t *mp4,
    uint64_t atom_data_size);
static void cngx_mp4_update_minf_atom(cngx_mp4_file_t *mp4,
    cngx_mp4_trak_t *trak);
static ngx_int_t cngx_mp4_read_dinf_atom(cngx_mp4_file_t *mp4,
    uint64_t atom_data_size);
static ngx_int_t cngx_mp4_read_vmhd_atom(cngx_mp4_file_t *mp4,
    uint64_t atom_data_size);
static ngx_int_t cngx_mp4_read_smhd_atom(cngx_mp4_file_t *mp4,
    uint64_t atom_data_size);
static ngx_int_t cngx_mp4_read_stbl_atom(cngx_mp4_file_t *mp4,
    uint64_t atom_data_size);
static void cngx_mp4_update_stbl_atom(cngx_mp4_file_t *mp4,
    cngx_mp4_trak_t *trak);
static ngx_int_t cngx_mp4_read_stsd_atom(cngx_mp4_file_t *mp4,
    uint64_t atom_data_size);
static ngx_int_t cngx_mp4_read_stts_atom(cngx_mp4_file_t *mp4,
    uint64_t atom_data_size);
static ngx_int_t cngx_mp4_update_stts_atom(cngx_mp4_file_t *mp4,
    cngx_mp4_trak_t *trak);
static ngx_int_t cngx_mp4_crop_stts_data(cngx_mp4_file_t *mp4,
    cngx_mp4_trak_t *trak, ngx_uint_t start);
static ngx_int_t cngx_mp4_read_stss_atom(cngx_mp4_file_t *mp4,
    uint64_t atom_data_size);
static ngx_int_t cngx_mp4_update_stss_atom(cngx_mp4_file_t *mp4,
    cngx_mp4_trak_t *trak);
static void cngx_mp4_crop_stss_data(cngx_mp4_file_t *mp4,
    cngx_mp4_trak_t *trak, ngx_uint_t start);
static ngx_int_t cngx_mp4_read_ctts_atom(cngx_mp4_file_t *mp4,
    uint64_t atom_data_size);
static void cngx_mp4_update_ctts_atom(cngx_mp4_file_t *mp4,
    cngx_mp4_trak_t *trak);
static void cngx_mp4_crop_ctts_data(cngx_mp4_file_t *mp4,
    cngx_mp4_trak_t *trak, ngx_uint_t start);
static ngx_int_t cngx_mp4_read_stsc_atom(cngx_mp4_file_t *mp4,
    uint64_t atom_data_size);
static ngx_int_t cngx_mp4_update_stsc_atom(cngx_mp4_file_t *mp4,
    cngx_mp4_trak_t *trak);
static ngx_int_t cngx_mp4_crop_stsc_data(cngx_mp4_file_t *mp4,
    cngx_mp4_trak_t *trak, ngx_uint_t start);
static ngx_int_t cngx_mp4_read_stsz_atom(cngx_mp4_file_t *mp4,
    uint64_t atom_data_size);
static ngx_int_t cngx_mp4_update_stsz_atom(cngx_mp4_file_t *mp4,
    cngx_mp4_trak_t *trak);
static ngx_int_t cngx_mp4_read_stco_atom(cngx_mp4_file_t *mp4,
    uint64_t atom_data_size);
static ngx_int_t cngx_mp4_update_stco_atom(cngx_mp4_file_t *mp4,
    cngx_mp4_trak_t *trak);
static void cngx_mp4_adjust_stco_atom(cngx_mp4_file_t *mp4,
    cngx_mp4_trak_t *trak, int32_t adjustment);
static ngx_int_t cngx_mp4_read_co64_atom(cngx_mp4_file_t *mp4,
    uint64_t atom_data_size);
static ngx_int_t cngx_mp4_update_co64_atom(cngx_mp4_file_t *mp4,
    cngx_mp4_trak_t *trak);
static void cngx_mp4_adjust_co64_atom(cngx_mp4_file_t *mp4,
    cngx_mp4_trak_t *trak, off_t adjustment);


static cngx_mp4_atom_handler_t  cngx_mp4_atoms[] = {
    { "ftyp", cngx_mp4_read_ftyp_atom },
    { "moov", cngx_mp4_read_moov_atom },
    { "mdat", cngx_mp4_read_mdat_atom },
    { NULL, NULL }
};

static cngx_mp4_atom_handler_t  cngx_mp4_moov_atoms[] = {
    { "mvhd", cngx_mp4_read_mvhd_atom },
    { "trak", cngx_mp4_read_trak_atom },
    { "cmov", cngx_mp4_read_cmov_atom },
    { NULL, NULL }
};

static cngx_mp4_atom_handler_t  cngx_mp4_trak_atoms[] = {
    { "tkhd", cngx_mp4_read_tkhd_atom },
    { "mdia", cngx_mp4_read_mdia_atom },
    { NULL, NULL }
};

static cngx_mp4_atom_handler_t  cngx_mp4_mdia_atoms[] = {
    { "mdhd", cngx_mp4_read_mdhd_atom },
    { "hdlr", cngx_mp4_read_hdlr_atom },
    { "minf", cngx_mp4_read_minf_atom },
    { NULL, NULL }
};

static cngx_mp4_atom_handler_t  cngx_mp4_minf_atoms[] = {
    { "vmhd", cngx_mp4_read_vmhd_atom },
    { "smhd", cngx_mp4_read_smhd_atom },
    { "dinf", cngx_mp4_read_dinf_atom },
    { "stbl", cngx_mp4_read_stbl_atom },
    { NULL, NULL }
};

static cngx_mp4_atom_handler_t  cngx_mp4_stbl_atoms[] = {
    { "stsd", cngx_mp4_read_stsd_atom },
    { "stts", cngx_mp4_read_stts_atom },
    { "stss", cngx_mp4_read_stss_atom },
    { "ctts", cngx_mp4_read_ctts_atom },
    { "stsc", cngx_mp4_read_stsc_atom },
    { "stsz", cngx_mp4_read_stsz_atom },
    { "stco", cngx_mp4_read_stco_atom },
    { "co64", cngx_mp4_read_co64_atom },
    { NULL, NULL }
};


ngx_int_t
cngx_mp4_process(cngx_mp4_file_t *mp4)
{
    off_t                  start_offset, end_offset, adjustment;
    ngx_int_t              rc;
    ngx_uint_t             i, j;
    ngx_chain_t          **prev;
    cngx_mp4_trak_t       *trak;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
                   "mp4 start:%ui, length:%ui", mp4->start, mp4->length);

    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cngx_mp4_process: "
                                         "mp4 start:%ld, length:%ld\n",
                                         mp4->start, mp4->length);

    rc = cngx_mp4_read_atom(mp4, cngx_mp4_atoms, mp4->end);
    if (rc != NGX_OK) {
        return rc;
    }

    if (mp4->trak.nelts == 0) {
        ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
                      "no mp4 trak atoms were found in \"%s\"",
                      mp4->file.name.data);

        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT,"error:cngx_mp4_process: "
                      "no mp4 trak atoms were found in \"%s\"\n",
                      mp4->file.name.data);                      
        return NGX_ERROR;
    }

    if (mp4->mdat_atom.buf == NULL) {
        ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
                      "no mp4 mdat atom was found in \"%s\"",
                      mp4->file.name.data);
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT,"error:cngx_mp4_process: "
                      "no mp4 mdat atom was found in \"%s\"\n",
                      mp4->file.name.data);                      
        return NGX_ERROR;
    }

    prev = &mp4->out;

    if (mp4->ftyp_atom.buf) {
        *prev = &mp4->ftyp_atom;
        prev = &mp4->ftyp_atom.next;
    }

    *prev = &mp4->moov_atom;
    prev = &mp4->moov_atom.next;

    if (mp4->mvhd_atom.buf) {
        mp4->moov_size += mp4->mvhd_atom_buf.last - mp4->mvhd_atom_buf.pos;
        *prev = &mp4->mvhd_atom;
        prev = &mp4->mvhd_atom.next;
    }

    start_offset = mp4->end;
    end_offset = 0;
    trak = mp4->trak.elts;

    for (i = 0; i < mp4->trak.nelts; i++) {

        if (cngx_mp4_update_stts_atom(mp4, &trak[i]) != NGX_OK) {
            return NGX_ERROR;
        }

        if (cngx_mp4_update_stss_atom(mp4, &trak[i]) != NGX_OK) {
            return NGX_ERROR;
        }

        cngx_mp4_update_ctts_atom(mp4, &trak[i]);

        if (cngx_mp4_update_stsc_atom(mp4, &trak[i]) != NGX_OK) {
            return NGX_ERROR;
        }

        if (cngx_mp4_update_stsz_atom(mp4, &trak[i]) != NGX_OK) {
            return NGX_ERROR;
        }

        if (trak[i].out[CNGX_MP4_CO64_DATA].buf) {
            if (cngx_mp4_update_co64_atom(mp4, &trak[i]) != NGX_OK) {
                return NGX_ERROR;
            }

        } else {
            if (cngx_mp4_update_stco_atom(mp4, &trak[i]) != NGX_OK) {
                return NGX_ERROR;
            }
        }

        cngx_mp4_update_stbl_atom(mp4, &trak[i]);
        cngx_mp4_update_minf_atom(mp4, &trak[i]);
        trak[i].size += trak[i].mdhd_size;
        trak[i].size += trak[i].hdlr_size;
        cngx_mp4_update_mdia_atom(mp4, &trak[i]);
        trak[i].size += trak[i].tkhd_size;
        cngx_mp4_update_trak_atom(mp4, &trak[i]);

        mp4->moov_size += trak[i].size;

        if (start_offset > trak[i].start_offset) {
            start_offset = trak[i].start_offset;
        }

        if (end_offset < trak[i].end_offset) {
            end_offset = trak[i].end_offset;
        }

        *prev = &trak[i].out[CNGX_MP4_TRAK_ATOM];
        prev = &trak[i].out[CNGX_MP4_TRAK_ATOM].next;

        for (j = 0; j < CNGX_MP4_LAST_ATOM + 1; j++) {
            if (trak[i].out[j].buf) {
                *prev = &trak[i].out[j];
                prev = &trak[i].out[j].next;
            }
        }
    }

    if (end_offset < start_offset) {
        end_offset = start_offset;
    }

    mp4->moov_size += 8;

    cngx_mp4_set_32value(mp4->moov_atom_header, mp4->moov_size);
    cngx_mp4_set_atom_name(mp4->moov_atom_header, 'm', 'o', 'o', 'v');
    mp4->content_length += mp4->moov_size;

    *prev = &mp4->mdat_atom;

    if (start_offset > mp4->mdat_data.buf->file_last) {
        ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
                      "start time is out mp4 mdat atom in \"%s\"",
                      mp4->file.name.data);
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT,"error:cngx_mp4_process: "
                      "start time is out mp4 mdat atom in \"%s\"\n",
                      mp4->file.name.data);                      
        return NGX_ERROR;
    }

    adjustment = mp4->ftyp_size + mp4->moov_size
                 + cngx_mp4_update_mdat_atom(mp4, start_offset, end_offset)
                 - start_offset;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
                   "mp4 adjustment:%O", adjustment);
    
    for (i = 0; i < mp4->trak.nelts; i++) {
        if (trak[i].out[CNGX_MP4_CO64_DATA].buf) {
            cngx_mp4_adjust_co64_atom(mp4, &trak[i], adjustment);
        } else {
            cngx_mp4_adjust_stco_atom(mp4, &trak[i], (int32_t) adjustment);
        }
    }

    return NGX_OK;
}


static ngx_int_t
cngx_mp4_read_atom(cngx_mp4_file_t *mp4,
    cngx_mp4_atom_handler_t *atom, uint64_t atom_data_size)
{
    off_t        end;
    size_t       atom_header_size;
    u_char      *atom_header, *atom_name;
    uint64_t     atom_size;
    ngx_int_t    rc;
    ngx_uint_t   n;

    end = mp4->offset + atom_data_size;

    while (mp4->offset < end) {

        if (cngx_mp4_read(mp4, sizeof(uint32_t)) != NGX_OK) {
            return NGX_ERROR;
        }

        atom_header = mp4->buffer_pos;
        atom_size = cngx_mp4_get_32value(atom_header);
        atom_header_size = sizeof(cngx_mp4_atom_header_t);

        if (atom_size == 0) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
                           "mp4 atom end");
            return NGX_OK;
        }

        if (atom_size < sizeof(cngx_mp4_atom_header_t)) {

            if (atom_size == 1) {

                if (cngx_mp4_read(mp4, sizeof(cngx_mp4_atom_header64_t))
                    != NGX_OK)
                {
                    return NGX_ERROR;
                }

                /* 64-bit atom size */
                atom_header = mp4->buffer_pos;
                atom_size = cngx_mp4_get_64value(atom_header + 8);
                atom_header_size = sizeof(cngx_mp4_atom_header64_t);

            } else {
                ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
                              "\"%s\" mp4 atom is too small:%uL",
                              mp4->file.name.data, atom_size);
                dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT,"error:cngx_mp4_read_atom: "
                              "\"%s\" mp4 atom is too small:%ld\n",
                              mp4->file.name.data, (UINT32)atom_size);                              
                return NGX_ERROR;
            }
        }

        if (cngx_mp4_read(mp4, sizeof(cngx_mp4_atom_header_t)) != NGX_OK) {
            return NGX_ERROR;
        }

        atom_header = mp4->buffer_pos;
        atom_name = atom_header + sizeof(uint32_t);

        ngx_log_debug4(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
                       "mp4 atom: %*s @%O:%uL",
                       (size_t) 4, atom_name, mp4->offset, atom_size);

        if (atom_size > (uint64_t) (NGX_MAX_OFF_T_VALUE - mp4->offset)
            || mp4->offset + (off_t) atom_size > end)
        {
            ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
                          "\"%s\" mp4 atom too large:%uL",
                          mp4->file.name.data, atom_size);
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT,"error:cngx_mp4_read_atom: "
                          "\"%s\" mp4 atom too large:%ld\n",
                          mp4->file.name.data, (UINT32)atom_size);                          
            return NGX_ERROR;
        }

        for (n = 0; atom[n].name; n++) {

            if (ngx_strncmp(atom_name, atom[n].name, 4) == 0) {

                cngx_mp4_atom_next(mp4, atom_header_size);

                rc = atom[n].handler(mp4, atom_size - atom_header_size);
                if (rc != NGX_OK) {
                    return rc;
                }

                goto next;
            }
        }

        cngx_mp4_atom_next(mp4, atom_size);

    next:
        continue;
    }

    return NGX_OK;
}

static ngx_int_t
cngx_mp4_read(cngx_mp4_file_t *mp4, size_t size)
{
    ssize_t  n;

    if (mp4->buffer_pos + size <= mp4->buffer_end) {
        return NGX_OK;
    }

    if (mp4->offset + (off_t) mp4->buffer_size > mp4->end) {
        mp4->buffer_size = (size_t) (mp4->end - mp4->offset);
    }

    if (mp4->buffer_size < size) {
        ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
                      "\"%s\" mp4 file truncated", mp4->file.name.data);
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT,"error:cngx_mp4_read: "
                      "\"%s\" mp4 file truncated\n", mp4->file.name.data);                      
        return NGX_ERROR;
    }

    if (mp4->buffer == NULL) {
        mp4->buffer = ngx_palloc(mp4->request->pool, mp4->buffer_size);
        if (mp4->buffer == NULL) {
            return NGX_ERROR;
        }

        mp4->buffer_start = mp4->buffer;
    }

    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT,"[DEBUG] cngx_mp4_read: "
                  "mp4 %p: buffer_size = %ld, offset = %ld, buffer_start = %p\n",
                  mp4, 
                  mp4->buffer_size, mp4->offset, mp4->buffer_start);     

    n = 0;
    
    if(NGX_OK != mp4->handler(mp4->modi, 
                            mp4->buffer_size, mp4->offset, 
                            mp4->buffer_start, 
                            &n))
    {
        return NGX_ERROR;
    }

    if ((size_t) n != mp4->buffer_size) {
        ngx_log_error(NGX_LOG_CRIT, mp4->file.log, 0,
                      ngx_read_file_n " read only %z of %z from \"%s\"",
                      n, mp4->buffer_size, mp4->file.name.data);
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT,"error:cngx_mp4_read: "
                      ngx_read_file_n " read only %ld of %ld from \"%s\"\n",
                      n, mp4->buffer_size, mp4->file.name.data);                      
        return NGX_ERROR;
    }

    mp4->buffer_pos = mp4->buffer_start;
    mp4->buffer_end = mp4->buffer_start + mp4->buffer_size;

    return NGX_OK;
}


static ngx_int_t
cngx_mp4_read_ftyp_atom(cngx_mp4_file_t *mp4, uint64_t atom_data_size)
{
    u_char     *ftyp_atom;
    size_t      atom_size;
    ngx_buf_t  *atom;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0, "mp4 ftyp atom");

    if (atom_data_size > 1024
        || cngx_mp4_atom_data(mp4) + (size_t) atom_data_size > mp4->buffer_end)
    {
        ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
                      "\"%s\" mp4 ftyp atom is too large:%uL",
                      mp4->file.name.data, atom_data_size);
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT,"error:cngx_mp4_read_ftyp_atom: "
                      "\"%s\" mp4 ftyp atom is too large:%ld\n",
                      mp4->file.name.data, (UINT32)atom_data_size);                      
        return NGX_ERROR;
    }

    atom_size = sizeof(cngx_mp4_atom_header_t) + (size_t) atom_data_size;

    ftyp_atom = ngx_palloc(mp4->request->pool, atom_size);
    if (ftyp_atom == NULL) {
        return NGX_ERROR;
    }

    cngx_mp4_set_32value(ftyp_atom, atom_size);
    cngx_mp4_set_atom_name(ftyp_atom, 'f', 't', 'y', 'p');

    /*
     * only moov atom content is guaranteed to be in mp4->buffer
     * during sending response, so ftyp atom content should be copied
     */
    ngx_memcpy(ftyp_atom + sizeof(cngx_mp4_atom_header_t),
               cngx_mp4_atom_data(mp4), (size_t) atom_data_size);

    atom = &mp4->ftyp_atom_buf;
    atom->temporary = 1;
    atom->pos = ftyp_atom;
    atom->last = ftyp_atom + atom_size;

    mp4->ftyp_atom.buf = atom;
    mp4->ftyp_size = atom_size;
    mp4->content_length = atom_size;

    cngx_mp4_atom_next(mp4, atom_data_size);

    return NGX_OK;
}


static ngx_int_t
cngx_mp4_read_moov_atom(cngx_mp4_file_t *mp4, uint64_t atom_data_size)
{
    ngx_int_t             rc;
    ngx_uint_t            no_mdat;
    ngx_buf_t            *atom;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0, "mp4 moov atom");

    no_mdat = (mp4->mdat_atom.buf == NULL);

    if (no_mdat && mp4->start == 0 && mp4->length == 0) {
        /*
         * send original file if moov atom resides before
         * mdat atom and client requests integral file
         */
        return NGX_DECLINED;
    }

    if (atom_data_size > mp4->buffer_size) {

        if (atom_data_size > mp4->max_buffer_size) {
            ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
                          "\"%s\" mp4 moov atom is too large:%uL, "
                          "you may want to increase mp4_max_buffer_size",
                          mp4->file.name.data, atom_data_size);
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT,"error:cngx_mp4_read_moov_atom: "
                          "\"%s\" mp4 moov atom is too large:%ld, "
                          "you may want to increase mp4_max_buffer_size\n",
                          mp4->file.name.data, (UINT32)atom_data_size);                          
            return NGX_ERROR;
        }

        ngx_pfree(mp4->request->pool, mp4->buffer);
        mp4->buffer = NULL;
        mp4->buffer_pos = NULL;
        mp4->buffer_end = NULL;

        mp4->buffer_size = (size_t) atom_data_size
                         + CNGX_MP4_MOOV_BUFFER_EXCESS * no_mdat;
    }

    if (cngx_mp4_read(mp4, (size_t) atom_data_size) != NGX_OK) {
        return NGX_ERROR;
    }

    mp4->trak.elts = &mp4->traks;
    mp4->trak.size = sizeof(cngx_mp4_trak_t);
    mp4->trak.nalloc = 2;
    mp4->trak.pool = mp4->request->pool;

    atom = &mp4->moov_atom_buf;
    atom->temporary = 1;
    atom->pos = mp4->moov_atom_header;
    atom->last = mp4->moov_atom_header + 8;

    mp4->moov_atom.buf = &mp4->moov_atom_buf;

    rc = cngx_mp4_read_atom(mp4, cngx_mp4_moov_atoms, atom_data_size);

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0, "mp4 moov atom done");

    if (no_mdat) {
        mp4->buffer_start = mp4->buffer_pos;
        mp4->buffer_size = CNGX_MP4_MOOV_BUFFER_EXCESS;

        if (mp4->buffer_start + mp4->buffer_size > mp4->buffer_end) {
            mp4->buffer = NULL;
            mp4->buffer_pos = NULL;
            mp4->buffer_end = NULL;
        }

    } else {
        /* skip atoms after moov atom */
        mp4->offset = mp4->end;
    }

    return rc;
}


static ngx_int_t
cngx_mp4_read_mdat_atom(cngx_mp4_file_t *mp4, uint64_t atom_data_size)
{
    ngx_buf_t  *data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0, "mp4 mdat atom");

    data = &mp4->mdat_data_buf;
    data->file = &mp4->file;
    data->in_file = 1;
    data->last_buf = 1;
    data->last_in_chain = 1;
    data->file_last = mp4->offset + atom_data_size;

    mp4->mdat_atom.buf = &mp4->mdat_atom_buf;
    mp4->mdat_atom.next = &mp4->mdat_data;
    mp4->mdat_data.buf = data;

    if (mp4->trak.nelts) {
        /* skip atoms after mdat atom */
        mp4->offset = mp4->end;

    } else {
        cngx_mp4_atom_next(mp4, atom_data_size);
    }

    return NGX_OK;
}


static size_t
cngx_mp4_update_mdat_atom(cngx_mp4_file_t *mp4, off_t start_offset,
    off_t end_offset)
{
    off_t       atom_data_size;
    u_char     *atom_header;
    uint32_t    atom_header_size;
    uint64_t    atom_size;
    ngx_buf_t  *atom;

    atom_data_size = end_offset - start_offset;
    mp4->mdat_data.buf->file_pos = start_offset;
    mp4->mdat_data.buf->file_last = end_offset;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
                   "mdat new offset @%O:%O", start_offset, atom_data_size);

    atom_header = mp4->mdat_atom_header;

    if ((uint64_t) atom_data_size > (uint64_t) 0xffffffff) {
        atom_size = 1;
        atom_header_size = sizeof(cngx_mp4_atom_header64_t);
        cngx_mp4_set_64value(atom_header + sizeof(cngx_mp4_atom_header_t),
                            sizeof(cngx_mp4_atom_header64_t) + atom_data_size);
    } else {
        atom_size = sizeof(cngx_mp4_atom_header_t) + atom_data_size;
        atom_header_size = sizeof(cngx_mp4_atom_header_t);
    }

    mp4->content_length += atom_header_size + atom_data_size;

    cngx_mp4_set_32value(atom_header, atom_size);
    cngx_mp4_set_atom_name(atom_header, 'm', 'd', 'a', 't');

    atom = &mp4->mdat_atom_buf;
    atom->temporary = 1;
    atom->pos = atom_header;
    atom->last = atom_header + atom_header_size;

    return atom_header_size;
}


static ngx_int_t
cngx_mp4_read_mvhd_atom(cngx_mp4_file_t *mp4, uint64_t atom_data_size)
{
    u_char                 *atom_header;
    size_t                  atom_size;
    uint32_t                timescale;
    uint64_t                duration, start_time, length_time;
    ngx_buf_t              *atom;
    cngx_mp4_mvhd_atom_t    *mvhd_atom;
    cngx_mp4_mvhd64_atom_t  *mvhd64_atom;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0, "mp4 mvhd atom");

    atom_header = cngx_mp4_atom_header(mp4);
    mvhd_atom = (cngx_mp4_mvhd_atom_t *) atom_header;
    mvhd64_atom = (cngx_mp4_mvhd64_atom_t *) atom_header;
    cngx_mp4_set_atom_name(atom_header, 'm', 'v', 'h', 'd');

    if (cngx_mp4_atom_data_size(cngx_mp4_mvhd_atom_t) > atom_data_size) {
        ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
                      "\"%s\" mp4 mvhd atom too small", mp4->file.name.data);
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT,"error:cngx_mp4_read_mvhd_atom: "
                      "\"%s\" mp4 mvhd atom too small\n", mp4->file.name.data);                      
        return NGX_ERROR;
    }

    if (mvhd_atom->version[0] == 0) {
        /* version 0: 32-bit duration */
        timescale = cngx_mp4_get_32value(mvhd_atom->timescale);
        duration = cngx_mp4_get_32value(mvhd_atom->duration);

    } else {
        /* version 1: 64-bit duration */

        if (cngx_mp4_atom_data_size(cngx_mp4_mvhd64_atom_t) > atom_data_size) {
            ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
                          "\"%s\" mp4 mvhd atom too small",
                          mp4->file.name.data);
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT,"error:cngx_mp4_read_mvhd_atom: "
                          "\"%s\" mp4 mvhd atom too small\n",
                          mp4->file.name.data);                          
            return NGX_ERROR;
        }

        timescale = cngx_mp4_get_32value(mvhd64_atom->timescale);
        duration = cngx_mp4_get_64value(mvhd64_atom->duration);
    }

    mp4->timescale = timescale;

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
                   "mvhd timescale:%uD, duration:%uL, time:%.3fs",
                   timescale, duration, (double) duration / timescale);

    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT,"[DEBUG] cngx_mp4_read_mvhd_atom: "
                   "mvhd timescale:%u, duration:%ld, time:%.3fs",
                   timescale, (UINT32)duration, (double) duration / timescale);
                   
    start_time = (uint64_t) mp4->start * timescale / 1000;

    if (duration < start_time) {
        ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
                      "\"%s\" mp4 start time exceeds file duration",
                      mp4->file.name.data);
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT,"error:cngx_mp4_read_mvhd_atom: "
                      "\"%s\" mp4 start time exceeds file duration: duration %ld, start_time %ld\n",
                      mp4->file.name.data, (UINT32)duration, (UINT32)start_time);                      
        return NGX_ERROR;
    }
    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT,"[DEBUG] cngx_mp4_read_mvhd_atom: "
                  "\"%s\" parsed: duration %ld, start_time %ld, timescale %u\n",
                  mp4->file.name.data, (UINT32)duration, (UINT32)start_time, timescale);      

    duration -= start_time;

    if (mp4->length) {
        length_time = (uint64_t) mp4->length * timescale / 1000;

        if (duration > length_time) {
            duration = length_time;
        }
    }

    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT,"[DEBUG] cngx_mp4_read_mvhd_atom: "
                  "\"%s\" mvhd new duration: duration %ld, time:%.3fs\n",
                  mp4->file.name.data, (UINT32)duration, (double) duration / timescale); 
                  
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
                   "mvhd new duration:%uL, time:%.3fs",
                   duration, (double) duration / timescale);

    atom_size = sizeof(cngx_mp4_atom_header_t) + (size_t) atom_data_size;
    cngx_mp4_set_32value(mvhd_atom->size, atom_size);

    if (mvhd_atom->version[0] == 0) {
        cngx_mp4_set_32value(mvhd_atom->duration, duration);

    } else {
        cngx_mp4_set_64value(mvhd64_atom->duration, duration);
    }

    atom = &mp4->mvhd_atom_buf;
    atom->temporary = 1;
    atom->pos = atom_header;
    atom->last = atom_header + atom_size;

    mp4->mvhd_atom.buf = atom;

    cngx_mp4_atom_next(mp4, atom_data_size);

    return NGX_OK;
}


static ngx_int_t
cngx_mp4_read_trak_atom(cngx_mp4_file_t *mp4, uint64_t atom_data_size)
{
    u_char               *atom_header, *atom_end;
    off_t                 atom_file_end;
    ngx_int_t             rc;
    ngx_buf_t            *atom;
    cngx_mp4_trak_t  *trak;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0, "mp4 trak atom");

    trak = ngx_array_push(&mp4->trak);
    if (trak == NULL) {
        return NGX_ERROR;
    }

    ngx_memzero(trak, sizeof(cngx_mp4_trak_t));

    atom_header = cngx_mp4_atom_header(mp4);
    cngx_mp4_set_atom_name(atom_header, 't', 'r', 'a', 'k');

    atom = &trak->trak_atom_buf;
    atom->temporary = 1;
    atom->pos = atom_header;
    atom->last = atom_header + sizeof(cngx_mp4_atom_header_t);

    trak->out[CNGX_MP4_TRAK_ATOM].buf = atom;

    atom_end = mp4->buffer_pos + (size_t) atom_data_size;
    atom_file_end = mp4->offset + atom_data_size;

    rc = cngx_mp4_read_atom(mp4, cngx_mp4_trak_atoms, atom_data_size);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
                   "mp4 trak atom: %i", rc);

    if (rc == NGX_DECLINED) {
        /* skip this trak */
        ngx_memzero(trak, sizeof(cngx_mp4_trak_t));
        mp4->trak.nelts--;
        mp4->buffer_pos = atom_end;
        mp4->offset = atom_file_end;
        return NGX_OK;
    }

    return rc;
}


static void
cngx_mp4_update_trak_atom(cngx_mp4_file_t *mp4,
    cngx_mp4_trak_t *trak)
{
    ngx_buf_t  *atom;

    trak->size += sizeof(cngx_mp4_atom_header_t);
    atom = &trak->trak_atom_buf;
    cngx_mp4_set_32value(atom->pos, trak->size);
}


static ngx_int_t
cngx_mp4_read_cmov_atom(cngx_mp4_file_t *mp4, uint64_t atom_data_size)
{
    ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
                  "\"%s\" mp4 compressed moov atom (cmov) is not supported",
                  mp4->file.name.data);

    dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT,"error:cngx_mp4_read_cmov_atom: "
                  "\"%s\" mp4 compressed moov atom (cmov) is not supported\n",
                  mp4->file.name.data);
    return NGX_ERROR;
}


static ngx_int_t
cngx_mp4_read_tkhd_atom(cngx_mp4_file_t *mp4, uint64_t atom_data_size)
{
    u_char                 *atom_header;
    size_t                  atom_size;
    uint64_t                duration, start_time, length_time;
    ngx_buf_t              *atom;
    cngx_mp4_trak_t    *trak;
    cngx_mp4_tkhd_atom_t    *tkhd_atom;
    cngx_mp4_tkhd64_atom_t  *tkhd64_atom;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0, "mp4 tkhd atom");

    atom_header = cngx_mp4_atom_header(mp4);
    tkhd_atom = (cngx_mp4_tkhd_atom_t *) atom_header;
    tkhd64_atom = (cngx_mp4_tkhd64_atom_t *) atom_header;
    cngx_mp4_set_atom_name(tkhd_atom, 't', 'k', 'h', 'd');

    if (cngx_mp4_atom_data_size(cngx_mp4_tkhd_atom_t) > atom_data_size) {
        ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
                      "\"%s\" mp4 tkhd atom too small", mp4->file.name.data);
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT,"error:cngx_mp4_read_tkhd_atom: "
                      "\"%s\" mp4 tkhd atom too small\n", mp4->file.name.data);                      
        return NGX_ERROR;
    }

    if (tkhd_atom->version[0] == 0) {
        /* version 0: 32-bit duration */
        duration = cngx_mp4_get_32value(tkhd_atom->duration);

    } else {
        /* version 1: 64-bit duration */

        if (cngx_mp4_atom_data_size(cngx_mp4_tkhd64_atom_t) > atom_data_size) {
            ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
                          "\"%s\" mp4 tkhd atom too small",
                          mp4->file.name.data);
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT,"error:cngx_mp4_read_tkhd_atom: "
                          "\"%s\" mp4 tkhd atom too small\n",
                          mp4->file.name.data);                          
            return NGX_ERROR;
        }

        duration = cngx_mp4_get_64value(tkhd64_atom->duration);
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
                   "tkhd duration:%uL, time:%.3fs",
                   duration, (double) duration / mp4->timescale);

    start_time = (uint64_t) mp4->start * mp4->timescale / 1000;

    if (duration <= start_time) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
                       "tkhd duration is less than start time");
        return NGX_DECLINED;
    }

    duration -= start_time;

    if (mp4->length) {
        length_time = (uint64_t) mp4->length * mp4->timescale / 1000;

        if (duration > length_time) {
            duration = length_time;
        }
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
                   "tkhd new duration:%uL, time:%.3fs",
                   duration, (double) duration / mp4->timescale);

    atom_size = sizeof(cngx_mp4_atom_header_t) + (size_t) atom_data_size;

    trak = cngx_mp4_last_trak(mp4);
    trak->tkhd_size = atom_size;

    cngx_mp4_set_32value(tkhd_atom->size, atom_size);

    if (tkhd_atom->version[0] == 0) {
        cngx_mp4_set_32value(tkhd_atom->duration, duration);

    } else {
        cngx_mp4_set_64value(tkhd64_atom->duration, duration);
    }

    atom = &trak->tkhd_atom_buf;
    atom->temporary = 1;
    atom->pos = atom_header;
    atom->last = atom_header + atom_size;

    trak->out[CNGX_MP4_TKHD_ATOM].buf = atom;

    cngx_mp4_atom_next(mp4, atom_data_size);

    return NGX_OK;
}


static ngx_int_t
cngx_mp4_read_mdia_atom(cngx_mp4_file_t *mp4, uint64_t atom_data_size)
{
    u_char               *atom_header;
    ngx_buf_t            *atom;
    cngx_mp4_trak_t  *trak;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0, "process mdia atom");

    atom_header = cngx_mp4_atom_header(mp4);
    cngx_mp4_set_atom_name(atom_header, 'm', 'd', 'i', 'a');

    trak = cngx_mp4_last_trak(mp4);

    atom = &trak->mdia_atom_buf;
    atom->temporary = 1;
    atom->pos = atom_header;
    atom->last = atom_header + sizeof(cngx_mp4_atom_header_t);

    trak->out[CNGX_MP4_MDIA_ATOM].buf = atom;

    return cngx_mp4_read_atom(mp4, cngx_mp4_mdia_atoms, atom_data_size);
}


static void
cngx_mp4_update_mdia_atom(cngx_mp4_file_t *mp4,
    cngx_mp4_trak_t *trak)
{
    ngx_buf_t  *atom;

    trak->size += sizeof(cngx_mp4_atom_header_t);
    atom = &trak->mdia_atom_buf;
    cngx_mp4_set_32value(atom->pos, trak->size);
}


static ngx_int_t
cngx_mp4_read_mdhd_atom(cngx_mp4_file_t *mp4, uint64_t atom_data_size)
{
    u_char                 *atom_header;
    size_t                  atom_size;
    uint32_t                timescale;
    uint64_t                duration, start_time, length_time;
    ngx_buf_t              *atom;
    cngx_mp4_trak_t    *trak;
    cngx_mp4_mdhd_atom_t    *mdhd_atom;
    cngx_mp4_mdhd64_atom_t  *mdhd64_atom;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0, "mp4 mdhd atom");

    atom_header = cngx_mp4_atom_header(mp4);
    mdhd_atom = (cngx_mp4_mdhd_atom_t *) atom_header;
    mdhd64_atom = (cngx_mp4_mdhd64_atom_t *) atom_header;
    cngx_mp4_set_atom_name(mdhd_atom, 'm', 'd', 'h', 'd');

    if (cngx_mp4_atom_data_size(cngx_mp4_mdhd_atom_t) > atom_data_size) {
        ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
                      "\"%s\" mp4 mdhd atom too small", mp4->file.name.data);
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT,"error:cngx_mp4_read_mdhd_atom: "
                      "\"%s\" mp4 mdhd atom too small\n", mp4->file.name.data);                      
        return NGX_ERROR;
    }

    if (mdhd_atom->version[0] == 0) {
        /* version 0: everything is 32-bit */
        timescale = cngx_mp4_get_32value(mdhd_atom->timescale);
        duration = cngx_mp4_get_32value(mdhd_atom->duration);

    } else {
        /* version 1: 64-bit duration and 32-bit timescale */

        if (cngx_mp4_atom_data_size(cngx_mp4_mdhd64_atom_t) > atom_data_size) {
            ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
                          "\"%s\" mp4 mdhd atom too small",
                          mp4->file.name.data);
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT,"error:cngx_mp4_read_mdhd_atom: "
                          "\"%s\" mp4 mdhd atom too small\n",
                          mp4->file.name.data);                          
            return NGX_ERROR;
        }

        timescale = cngx_mp4_get_32value(mdhd64_atom->timescale);
        duration = cngx_mp4_get_64value(mdhd64_atom->duration);
    }

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
                   "mdhd timescale:%uD, duration:%uL, time:%.3fs",
                   timescale, duration, (double) duration / timescale);

    start_time = (uint64_t) mp4->start * timescale / 1000;

    if (duration <= start_time) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
                       "mdhd duration is less than start time");
        return NGX_DECLINED;
    }

    duration -= start_time;

    if (mp4->length) {
        length_time = (uint64_t) mp4->length * timescale / 1000;

        if (duration > length_time) {
            duration = length_time;
        }
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
                   "mdhd new duration:%uL, time:%.3fs",
                   duration, (double) duration / timescale);

    atom_size = sizeof(cngx_mp4_atom_header_t) + (size_t) atom_data_size;

    trak = cngx_mp4_last_trak(mp4);
    trak->mdhd_size = atom_size;
    trak->timescale = timescale;

    cngx_mp4_set_32value(mdhd_atom->size, atom_size);

    if (mdhd_atom->version[0] == 0) {
        cngx_mp4_set_32value(mdhd_atom->duration, duration);

    } else {
        cngx_mp4_set_64value(mdhd64_atom->duration, duration);
    }

    atom = &trak->mdhd_atom_buf;
    atom->temporary = 1;
    atom->pos = atom_header;
    atom->last = atom_header + atom_size;

    trak->out[CNGX_MP4_MDHD_ATOM].buf = atom;

    cngx_mp4_atom_next(mp4, atom_data_size);

    return NGX_OK;
}


static ngx_int_t
cngx_mp4_read_hdlr_atom(cngx_mp4_file_t *mp4, uint64_t atom_data_size)
{
    u_char              *atom_header;
    size_t               atom_size;
    ngx_buf_t            *atom;
    cngx_mp4_trak_t  *trak;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0, "mp4 hdlr atom");

    atom_header = cngx_mp4_atom_header(mp4);
    atom_size = sizeof(cngx_mp4_atom_header_t) + (size_t) atom_data_size;
    cngx_mp4_set_32value(atom_header, atom_size);
    cngx_mp4_set_atom_name(atom_header, 'h', 'd', 'l', 'r');

    trak = cngx_mp4_last_trak(mp4);

    atom = &trak->hdlr_atom_buf;
    atom->temporary = 1;
    atom->pos = atom_header;
    atom->last = atom_header + atom_size;

    trak->hdlr_size = atom_size;
    trak->out[CNGX_MP4_HDLR_ATOM].buf = atom;

    cngx_mp4_atom_next(mp4, atom_data_size);

    return NGX_OK;
}


static ngx_int_t
cngx_mp4_read_minf_atom(cngx_mp4_file_t *mp4, uint64_t atom_data_size)
{
    u_char               *atom_header;
    ngx_buf_t            *atom;
    cngx_mp4_trak_t  *trak;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0, "process minf atom");

    atom_header = cngx_mp4_atom_header(mp4);
    cngx_mp4_set_atom_name(atom_header, 'm', 'i', 'n', 'f');

    trak = cngx_mp4_last_trak(mp4);

    atom = &trak->minf_atom_buf;
    atom->temporary = 1;
    atom->pos = atom_header;
    atom->last = atom_header + sizeof(cngx_mp4_atom_header_t);

    trak->out[CNGX_MP4_MINF_ATOM].buf = atom;

    return cngx_mp4_read_atom(mp4, cngx_mp4_minf_atoms, atom_data_size);
}


static void
cngx_mp4_update_minf_atom(cngx_mp4_file_t *mp4,
    cngx_mp4_trak_t *trak)
{
    ngx_buf_t  *atom;

    trak->size += sizeof(cngx_mp4_atom_header_t)
               + trak->vmhd_size
               + trak->smhd_size
               + trak->dinf_size;
    atom = &trak->minf_atom_buf;
    cngx_mp4_set_32value(atom->pos, trak->size);
}


static ngx_int_t
cngx_mp4_read_vmhd_atom(cngx_mp4_file_t *mp4, uint64_t atom_data_size)
{
    u_char              *atom_header;
    size_t               atom_size;
    ngx_buf_t            *atom;
    cngx_mp4_trak_t  *trak;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0, "mp4 vmhd atom");

    atom_header = cngx_mp4_atom_header(mp4);
    atom_size = sizeof(cngx_mp4_atom_header_t) + (size_t) atom_data_size;
    cngx_mp4_set_32value(atom_header, atom_size);
    cngx_mp4_set_atom_name(atom_header, 'v', 'm', 'h', 'd');

    trak = cngx_mp4_last_trak(mp4);

    atom = &trak->vmhd_atom_buf;
    atom->temporary = 1;
    atom->pos = atom_header;
    atom->last = atom_header + atom_size;

    trak->vmhd_size += atom_size;
    trak->out[CNGX_MP4_VMHD_ATOM].buf = atom;

    cngx_mp4_atom_next(mp4, atom_data_size);

    return NGX_OK;
}


static ngx_int_t
cngx_mp4_read_smhd_atom(cngx_mp4_file_t *mp4, uint64_t atom_data_size)
{
    u_char              *atom_header;
    size_t               atom_size;
    ngx_buf_t            *atom;
    cngx_mp4_trak_t  *trak;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0, "mp4 smhd atom");

    atom_header = cngx_mp4_atom_header(mp4);
    atom_size = sizeof(cngx_mp4_atom_header_t) + (size_t) atom_data_size;
    cngx_mp4_set_32value(atom_header, atom_size);
    cngx_mp4_set_atom_name(atom_header, 's', 'm', 'h', 'd');

    trak = cngx_mp4_last_trak(mp4);

    atom = &trak->smhd_atom_buf;
    atom->temporary = 1;
    atom->pos = atom_header;
    atom->last = atom_header + atom_size;

    trak->smhd_size += atom_size;
    trak->out[CNGX_MP4_SMHD_ATOM].buf = atom;

    cngx_mp4_atom_next(mp4, atom_data_size);

    return NGX_OK;
}


static ngx_int_t
cngx_mp4_read_dinf_atom(cngx_mp4_file_t *mp4, uint64_t atom_data_size)
{
    u_char              *atom_header;
    size_t               atom_size;
    ngx_buf_t            *atom;
    cngx_mp4_trak_t  *trak;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0, "mp4 dinf atom");

    atom_header = cngx_mp4_atom_header(mp4);
    atom_size = sizeof(cngx_mp4_atom_header_t) + (size_t) atom_data_size;
    cngx_mp4_set_32value(atom_header, atom_size);
    cngx_mp4_set_atom_name(atom_header, 'd', 'i', 'n', 'f');

    trak = cngx_mp4_last_trak(mp4);

    atom = &trak->dinf_atom_buf;
    atom->temporary = 1;
    atom->pos = atom_header;
    atom->last = atom_header + atom_size;

    trak->dinf_size += atom_size;
    trak->out[CNGX_MP4_DINF_ATOM].buf = atom;

    cngx_mp4_atom_next(mp4, atom_data_size);

    return NGX_OK;
}


static ngx_int_t
cngx_mp4_read_stbl_atom(cngx_mp4_file_t *mp4, uint64_t atom_data_size)
{
    u_char               *atom_header;
    ngx_buf_t            *atom;
    cngx_mp4_trak_t  *trak;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0, "process stbl atom");

    atom_header = cngx_mp4_atom_header(mp4);
    cngx_mp4_set_atom_name(atom_header, 's', 't', 'b', 'l');

    trak = cngx_mp4_last_trak(mp4);

    atom = &trak->stbl_atom_buf;
    atom->temporary = 1;
    atom->pos = atom_header;
    atom->last = atom_header + sizeof(cngx_mp4_atom_header_t);

    trak->out[CNGX_MP4_STBL_ATOM].buf = atom;

    return cngx_mp4_read_atom(mp4, cngx_mp4_stbl_atoms, atom_data_size);
}


static void
cngx_mp4_update_stbl_atom(cngx_mp4_file_t *mp4,
    cngx_mp4_trak_t *trak)
{
    ngx_buf_t  *atom;

    trak->size += sizeof(cngx_mp4_atom_header_t);
    atom = &trak->stbl_atom_buf;
    cngx_mp4_set_32value(atom->pos, trak->size);
}


static ngx_int_t
cngx_mp4_read_stsd_atom(cngx_mp4_file_t *mp4, uint64_t atom_data_size)
{
    u_char               *atom_header, *atom_table;
    size_t                atom_size;
    ngx_buf_t            *atom;
    cngx_mp4_stsd_atom_t  *stsd_atom;
    cngx_mp4_trak_t  *trak;

    /* sample description atom */

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0, "mp4 stsd atom");

    atom_header = cngx_mp4_atom_header(mp4);
    stsd_atom = (cngx_mp4_stsd_atom_t *) atom_header;
    atom_size = sizeof(cngx_mp4_atom_header_t) + (size_t) atom_data_size;
    atom_table = atom_header + atom_size;
    cngx_mp4_set_32value(stsd_atom->size, atom_size);
    cngx_mp4_set_atom_name(stsd_atom, 's', 't', 's', 'd');

    if (cngx_mp4_atom_data_size(cngx_mp4_stsd_atom_t) > atom_data_size) {
        ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
                      "\"%s\" mp4 stsd atom too small", mp4->file.name.data);
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT,"error:cngx_mp4_read_stsd_atom: "
                      "\"%s\" mp4 stsd atom too small\n", mp4->file.name.data);                      
        return NGX_ERROR;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
                   "stsd entries:%uD, media:%*s",
                   cngx_mp4_get_32value(stsd_atom->entries),
                   (size_t) 4, stsd_atom->media_name);

    trak = cngx_mp4_last_trak(mp4);

    atom = &trak->stsd_atom_buf;
    atom->temporary = 1;
    atom->pos = atom_header;
    atom->last = atom_table;

    trak->out[CNGX_MP4_STSD_ATOM].buf = atom;
    trak->size += atom_size;

    cngx_mp4_atom_next(mp4, atom_data_size);

    return NGX_OK;
}


static ngx_int_t
cngx_mp4_read_stts_atom(cngx_mp4_file_t *mp4, uint64_t atom_data_size)
{
    u_char               *atom_header, *atom_table, *atom_end;
    uint32_t              entries;
    ngx_buf_t            *atom, *data;
    cngx_mp4_stts_atom_t  *stts_atom;
    cngx_mp4_trak_t  *trak;

    /* time-to-sample atom */

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0, "mp4 stts atom");

    atom_header = cngx_mp4_atom_header(mp4);
    stts_atom = (cngx_mp4_stts_atom_t *) atom_header;
    cngx_mp4_set_atom_name(stts_atom, 's', 't', 't', 's');

    if (cngx_mp4_atom_data_size(cngx_mp4_stts_atom_t) > atom_data_size) {
        ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
                      "\"%s\" mp4 stts atom too small", mp4->file.name.data);
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT,"error:cngx_mp4_read_stts_atom: "
                      "\"%s\" mp4 stts atom too small\n", mp4->file.name.data);                      
        return NGX_ERROR;
    }

    entries = cngx_mp4_get_32value(stts_atom->entries);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
                   "mp4 time-to-sample entries:%uD", entries);

    if (cngx_mp4_atom_data_size(cngx_mp4_stts_atom_t)
        + entries * sizeof(cngx_mp4_stts_entry_t) > atom_data_size)
    {
        ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
                      "\"%s\" mp4 stts atom too small", mp4->file.name.data);
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT,"error:cngx_mp4_read_stts_atom: "
                      "\"%s\" mp4 stts atom too small\n", mp4->file.name.data);                      
        return NGX_ERROR;
    }

    atom_table = atom_header + sizeof(cngx_mp4_stts_atom_t);
    atom_end = atom_table + entries * sizeof(cngx_mp4_stts_entry_t);

    trak = cngx_mp4_last_trak(mp4);
    trak->time_to_sample_entries = entries;

    atom = &trak->stts_atom_buf;
    atom->temporary = 1;
    atom->pos = atom_header;
    atom->last = atom_table;

    data = &trak->stts_data_buf;
    data->temporary = 1;
    data->pos = atom_table;
    data->last = atom_end;

    trak->out[CNGX_MP4_STTS_ATOM].buf = atom;
    trak->out[CNGX_MP4_STTS_DATA].buf = data;

    cngx_mp4_atom_next(mp4, atom_data_size);

    return NGX_OK;
}


static ngx_int_t
cngx_mp4_update_stts_atom(cngx_mp4_file_t *mp4,
    cngx_mp4_trak_t *trak)
{
    size_t                atom_size;
    ngx_buf_t            *atom, *data;
    cngx_mp4_stts_atom_t  *stts_atom;

    /*
     * mdia.minf.stbl.stts updating requires trak->timescale
     * from mdia.mdhd atom which may reside after mdia.minf
     */

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
                   "mp4 stts atom update");

    data = trak->out[CNGX_MP4_STTS_DATA].buf;

    if (data == NULL) {
        ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
                      "no mp4 stts atoms were found in \"%s\"",
                      mp4->file.name.data);
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT,"error:cngx_mp4_update_stts_atom: "
                      "no mp4 stts atoms were found in \"%s\"\n",
                      mp4->file.name.data);                      
        return NGX_ERROR;
    }

    if (cngx_mp4_crop_stts_data(mp4, trak, 1) != NGX_OK) {
        return NGX_ERROR;
    }

    if (cngx_mp4_crop_stts_data(mp4, trak, 0) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
                   "time-to-sample entries:%uD", trak->time_to_sample_entries);

    atom_size = sizeof(cngx_mp4_stts_atom_t) + (data->last - data->pos);
    trak->size += atom_size;

    atom = trak->out[CNGX_MP4_STTS_ATOM].buf;
    stts_atom = (cngx_mp4_stts_atom_t *) atom->pos;
    cngx_mp4_set_32value(stts_atom->size, atom_size);
    cngx_mp4_set_32value(stts_atom->entries, trak->time_to_sample_entries);

    return NGX_OK;
}


static ngx_int_t
cngx_mp4_crop_stts_data(cngx_mp4_file_t *mp4,
    cngx_mp4_trak_t *trak, ngx_uint_t start)
{
    uint32_t               count, duration, rest;
    uint64_t               start_time;
    ngx_buf_t             *data;
    ngx_uint_t             start_sample, entries, start_sec;
    cngx_mp4_stts_entry_t  *entry, *end;

    if (start) {
        start_sec = mp4->start;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
                       "mp4 stts crop start_time:%ui", start_sec);

    } else if (mp4->length) {
        start_sec = mp4->length;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
                       "mp4 stts crop end_time:%ui", start_sec);

    } else {
        return NGX_OK;
    }

    data = trak->out[CNGX_MP4_STTS_DATA].buf;

    start_time = (uint64_t) start_sec * trak->timescale / 1000;

    entries = trak->time_to_sample_entries;
    start_sample = 0;
    entry = (cngx_mp4_stts_entry_t *) data->pos;
    end = (cngx_mp4_stts_entry_t *) data->last;

    while (entry < end) {
        count = cngx_mp4_get_32value(entry->count);
        duration = cngx_mp4_get_32value(entry->duration);

        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
                       "time:%uL, count:%uD, duration:%uD",
                       start_time, count, duration);

        if (start_time < (uint64_t) count * duration) {
            start_sample += (ngx_uint_t) (start_time / duration);
            rest = (uint32_t) (start_time / duration);
            goto found;
        }

        start_sample += count;
        start_time -= count * duration;
        entries--;
        entry++;
    }

    if (start) {
        ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
                      "start time is out mp4 stts samples in \"%s\"",
                      mp4->file.name.data);
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT,"error:cngx_mp4_crop_stts_data: "
                      "start time is out mp4 stts samples in \"%s\"\n",
                      mp4->file.name.data);
        return NGX_ERROR;

    } else {
        trak->end_sample = trak->start_sample + start_sample;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
                       "end_sample:%ui", trak->end_sample);

        return NGX_OK;
    }

found:

    if (start) {
        cngx_mp4_set_32value(entry->count, count - rest);
        data->pos = (u_char *) entry;
        trak->time_to_sample_entries = entries;
        trak->start_sample = start_sample;

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
                       "start_sample:%ui, new count:%uD",
                       trak->start_sample, count - rest);

    } else {
        cngx_mp4_set_32value(entry->count, rest);
        data->last = (u_char *) (entry + 1);
        trak->time_to_sample_entries -= entries - 1;
        trak->end_sample = trak->start_sample + start_sample;

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
                       "end_sample:%ui, new count:%uD",
                       trak->end_sample, rest);
    }

    return NGX_OK;
}


static ngx_int_t
cngx_mp4_read_stss_atom(cngx_mp4_file_t *mp4, uint64_t atom_data_size)
{
    u_char                    *atom_header, *atom_table, *atom_end;
    uint32_t                   entries;
    ngx_buf_t                 *atom, *data;
    cngx_mp4_trak_t           *trak;
    cngx_mp4_stss_atom_t      *stss_atom;

    /* sync samples atom */

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0, "mp4 stss atom");

    atom_header = cngx_mp4_atom_header(mp4);
    stss_atom = (cngx_mp4_stss_atom_t *) atom_header;
    cngx_mp4_set_atom_name(stss_atom, 's', 't', 's', 's');

    if (cngx_mp4_atom_data_size(cngx_mp4_stss_atom_t) > atom_data_size) {
        ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
                      "\"%s\" mp4 stss atom too small", mp4->file.name.data);
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT,"error:cngx_mp4_read_stss_atom: "
                      "\"%s\" mp4 stss atom too small\n", mp4->file.name.data);                      
        return NGX_ERROR;
    }

    entries = cngx_mp4_get_32value(stss_atom->entries);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
                   "sync sample entries:%uD", entries);

    trak = cngx_mp4_last_trak(mp4);
    trak->sync_samples_entries = entries;

    atom_table = atom_header + sizeof(cngx_mp4_stss_atom_t);

    atom = &trak->stss_atom_buf;
    atom->temporary = 1;
    atom->pos = atom_header;
    atom->last = atom_table;

    if (cngx_mp4_atom_data_size(cngx_mp4_stss_atom_t)
        + entries * sizeof(uint32_t) > atom_data_size)
    {
        ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
                      "\"%s\" mp4 stss atom too small", mp4->file.name.data);
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT,"error:cngx_mp4_read_stss_atom: "
                      "\"%s\" mp4 stss atom too small\n", mp4->file.name.data);                      
        return NGX_ERROR;
    }

    atom_end = atom_table + entries * sizeof(uint32_t);

    data = &trak->stss_data_buf;
    data->temporary = 1;
    data->pos = atom_table;
    data->last = atom_end;

    trak->out[CNGX_MP4_STSS_ATOM].buf = atom;
    trak->out[CNGX_MP4_STSS_DATA].buf = data;

    cngx_mp4_atom_next(mp4, atom_data_size);

    return NGX_OK;
}


static ngx_int_t
cngx_mp4_update_stss_atom(cngx_mp4_file_t *mp4,
    cngx_mp4_trak_t *trak)
{
    size_t                     atom_size;
    uint32_t                   sample, start_sample, *entry, *end;
    ngx_buf_t                 *atom, *data;
    cngx_mp4_stss_atom_t      *stss_atom;

    /*
     * mdia.minf.stbl.stss updating requires trak->start_sample
     * from mdia.minf.stbl.stts which depends on value from mdia.mdhd
     * atom which may reside after mdia.minf
     */

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
                   "mp4 stss atom update");

    data = trak->out[CNGX_MP4_STSS_DATA].buf;

    if (data == NULL) {
        return NGX_OK;
    }

    cngx_mp4_crop_stss_data(mp4, trak, 1);
    cngx_mp4_crop_stss_data(mp4, trak, 0);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
                   "sync sample entries:%uD", trak->sync_samples_entries);

    if (trak->sync_samples_entries) {
        entry = (uint32_t *) data->pos;
        end = (uint32_t *) data->last;

        start_sample = trak->start_sample;

        while (entry < end) {
            sample = cngx_mp4_get_32value(entry);
            sample -= start_sample;
            cngx_mp4_set_32value(entry, sample);
            entry++;
        }

    } else {
        trak->out[CNGX_MP4_STSS_DATA].buf = NULL;
    }

    atom_size = sizeof(cngx_mp4_stss_atom_t) + (data->last - data->pos);
    trak->size += atom_size;

    atom = trak->out[CNGX_MP4_STSS_ATOM].buf;
    stss_atom = (cngx_mp4_stss_atom_t *) atom->pos;

    cngx_mp4_set_32value(stss_atom->size, atom_size);
    cngx_mp4_set_32value(stss_atom->entries, trak->sync_samples_entries);

    return NGX_OK;
}


static void
cngx_mp4_crop_stss_data(cngx_mp4_file_t *mp4,
    cngx_mp4_trak_t *trak, ngx_uint_t start)
{
    uint32_t     sample, start_sample, *entry, *end;
    ngx_buf_t   *data;
    ngx_uint_t   entries;

    /* sync samples starts from 1 */

    if (start) {
        start_sample = trak->start_sample + 1;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
                       "mp4 stss crop start_sample:%uD", start_sample);

    } else if (mp4->length) {
        start_sample = trak->end_sample + 1;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
                       "mp4 stss crop end_sample:%uD", start_sample);

    } else {
        return;
    }

    data = trak->out[CNGX_MP4_STSS_DATA].buf;

    entries = trak->sync_samples_entries;
    entry = (uint32_t *) data->pos;
    end = (uint32_t *) data->last;

    while (entry < end) {
        sample = cngx_mp4_get_32value(entry);

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
                       "sync:%uD", sample);

        if (sample >= start_sample) {
            goto found;
        }

        entries--;
        entry++;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
                   "sample is out of mp4 stss atom");

found:

    if (start) {
        data->pos = (u_char *) entry;
        trak->sync_samples_entries = entries;

    } else {
        data->last = (u_char *) entry;
        trak->sync_samples_entries -= entries;
    }
}


static ngx_int_t
cngx_mp4_read_ctts_atom(cngx_mp4_file_t *mp4, uint64_t atom_data_size)
{
    u_char               *atom_header, *atom_table, *atom_end;
    uint32_t              entries;
    ngx_buf_t            *atom, *data;
    cngx_mp4_ctts_atom_t  *ctts_atom;
    cngx_mp4_trak_t      *trak;

    /* composition offsets atom */

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0, "mp4 ctts atom");

    atom_header = cngx_mp4_atom_header(mp4);
    ctts_atom = (cngx_mp4_ctts_atom_t *) atom_header;
    cngx_mp4_set_atom_name(ctts_atom, 'c', 't', 't', 's');

    if (cngx_mp4_atom_data_size(cngx_mp4_ctts_atom_t) > atom_data_size) {
        ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
                      "\"%s\" mp4 ctts atom too small", mp4->file.name.data);
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT,"error:cngx_mp4_read_ctts_atom: "
                      "\"%s\" mp4 ctts atom too small\n", mp4->file.name.data);                      
        return NGX_ERROR;
    }

    entries = cngx_mp4_get_32value(ctts_atom->entries);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
                   "composition offset entries:%uD", entries);

    trak = cngx_mp4_last_trak(mp4);
    trak->composition_offset_entries = entries;

    atom_table = atom_header + sizeof(cngx_mp4_ctts_atom_t);

    atom = &trak->ctts_atom_buf;
    atom->temporary = 1;
    atom->pos = atom_header;
    atom->last = atom_table;

    if (cngx_mp4_atom_data_size(cngx_mp4_ctts_atom_t)
        + entries * sizeof(cngx_mp4_ctts_entry_t) > atom_data_size)
    {
        ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
                      "\"%s\" mp4 ctts atom too small", mp4->file.name.data);
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT,"error:cngx_mp4_read_ctts_atom: "
                      "\"%s\" mp4 ctts atom too small\n", mp4->file.name.data);                      
        return NGX_ERROR;
    }

    atom_end = atom_table + entries * sizeof(cngx_mp4_ctts_entry_t);

    data = &trak->ctts_data_buf;
    data->temporary = 1;
    data->pos = atom_table;
    data->last = atom_end;

    trak->out[CNGX_MP4_CTTS_ATOM].buf = atom;
    trak->out[CNGX_MP4_CTTS_DATA].buf = data;

    cngx_mp4_atom_next(mp4, atom_data_size);

    return NGX_OK;
}


static void
cngx_mp4_update_ctts_atom(cngx_mp4_file_t *mp4,
    cngx_mp4_trak_t *trak)
{
    size_t                atom_size;
    ngx_buf_t            *atom, *data;
    cngx_mp4_ctts_atom_t  *ctts_atom;

    /*
     * mdia.minf.stbl.ctts updating requires trak->start_sample
     * from mdia.minf.stbl.stts which depends on value from mdia.mdhd
     * atom which may reside after mdia.minf
     */

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
                   "mp4 ctts atom update");

    data = trak->out[CNGX_MP4_CTTS_DATA].buf;

    if (data == NULL) {
        return;
    }

    cngx_mp4_crop_ctts_data(mp4, trak, 1);
    cngx_mp4_crop_ctts_data(mp4, trak, 0);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
                   "composition offset entries:%uD",
                   trak->composition_offset_entries);

    if (trak->composition_offset_entries == 0) {
        trak->out[CNGX_MP4_CTTS_ATOM].buf = NULL;
        trak->out[CNGX_MP4_CTTS_DATA].buf = NULL;
        return;
    }

    atom_size = sizeof(cngx_mp4_ctts_atom_t) + (data->last - data->pos);
    trak->size += atom_size;

    atom = trak->out[CNGX_MP4_CTTS_ATOM].buf;
    ctts_atom = (cngx_mp4_ctts_atom_t *) atom->pos;

    cngx_mp4_set_32value(ctts_atom->size, atom_size);
    cngx_mp4_set_32value(ctts_atom->entries, trak->composition_offset_entries);

    return;
}


static void
cngx_mp4_crop_ctts_data(cngx_mp4_file_t *mp4,
    cngx_mp4_trak_t *trak, ngx_uint_t start)
{
    uint32_t               count, start_sample, rest;
    ngx_buf_t             *data;
    ngx_uint_t             entries;
    cngx_mp4_ctts_entry_t  *entry, *end;

    /* sync samples starts from 1 */

    if (start) {
        start_sample = trak->start_sample + 1;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
                       "mp4 ctts crop start_sample:%uD", start_sample);

    } else if (mp4->length) {
        start_sample = trak->end_sample - trak->start_sample + 1;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
                       "mp4 ctts crop end_sample:%uD", start_sample);

    } else {
        return;
    }

    data = trak->out[CNGX_MP4_CTTS_DATA].buf;

    entries = trak->composition_offset_entries;
    entry = (cngx_mp4_ctts_entry_t *) data->pos;
    end = (cngx_mp4_ctts_entry_t *) data->last;

    while (entry < end) {
        count = cngx_mp4_get_32value(entry->count);

        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
                       "sample:%uD, count:%uD, offset:%uD",
                       start_sample, count, cngx_mp4_get_32value(entry->offset));

        if (start_sample <= count) {
            rest = start_sample - 1;
            goto found;
        }

        start_sample -= count;
        entries--;
        entry++;
    }

    if (start) {
        data->pos = (u_char *) end;
        trak->composition_offset_entries = 0;
    }

    return;

found:

    if (start) {
        cngx_mp4_set_32value(entry->count, count - rest);
        data->pos = (u_char *) entry;
        trak->composition_offset_entries = entries;

    } else {
        cngx_mp4_set_32value(entry->count, rest);
        data->last = (u_char *) (entry + 1);
        trak->composition_offset_entries -= entries - 1;
    }
}


static ngx_int_t
cngx_mp4_read_stsc_atom(cngx_mp4_file_t *mp4, uint64_t atom_data_size)
{
    u_char               *atom_header, *atom_table, *atom_end;
    uint32_t              entries;
    ngx_buf_t            *atom, *data;
    cngx_mp4_stsc_atom_t  *stsc_atom;
    cngx_mp4_trak_t  *trak;

    /* sample-to-chunk atom */

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0, "mp4 stsc atom");

    atom_header = cngx_mp4_atom_header(mp4);
    stsc_atom = (cngx_mp4_stsc_atom_t *) atom_header;
    cngx_mp4_set_atom_name(stsc_atom, 's', 't', 's', 'c');

    if (cngx_mp4_atom_data_size(cngx_mp4_stsc_atom_t) > atom_data_size) {
        ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
                      "\"%s\" mp4 stsc atom too small", mp4->file.name.data);
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT,"error:cngx_mp4_read_stsc_atom: "
                      "\"%s\" mp4 stsc atom too small\n", mp4->file.name.data);                      
        return NGX_ERROR;
    }

    entries = cngx_mp4_get_32value(stsc_atom->entries);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
                   "sample-to-chunk entries:%uD", entries);

    if (cngx_mp4_atom_data_size(cngx_mp4_stsc_atom_t)
        + entries * sizeof(cngx_mp4_stsc_entry_t) > atom_data_size)
    {
        ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
                      "\"%s\" mp4 stsc atom too small", mp4->file.name.data);
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT,"error:cngx_mp4_read_stsc_atom: "
                      "\"%s\" mp4 stsc atom too small\n", mp4->file.name.data);                      
        return NGX_ERROR;
    }

    atom_table = atom_header + sizeof(cngx_mp4_stsc_atom_t);
    atom_end = atom_table + entries * sizeof(cngx_mp4_stsc_entry_t);

    trak = cngx_mp4_last_trak(mp4);
    trak->sample_to_chunk_entries = entries;

    atom = &trak->stsc_atom_buf;
    atom->temporary = 1;
    atom->pos = atom_header;
    atom->last = atom_table;

    data = &trak->stsc_data_buf;
    data->temporary = 1;
    data->pos = atom_table;
    data->last = atom_end;

    trak->out[CNGX_MP4_STSC_ATOM].buf = atom;
    trak->out[CNGX_MP4_STSC_DATA].buf = data;

    cngx_mp4_atom_next(mp4, atom_data_size);

    return NGX_OK;
}


static ngx_int_t
cngx_mp4_update_stsc_atom(cngx_mp4_file_t *mp4,
    cngx_mp4_trak_t *trak)
{
    size_t                 atom_size;
    uint32_t               chunk;
    ngx_buf_t             *atom, *data;
    cngx_mp4_stsc_atom_t   *stsc_atom;
    cngx_mp4_stsc_entry_t  *entry, *end;

    /*
     * mdia.minf.stbl.stsc updating requires trak->start_sample
     * from mdia.minf.stbl.stts which depends on value from mdia.mdhd
     * atom which may reside after mdia.minf
     */

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
                   "mp4 stsc atom update");

    data = trak->out[CNGX_MP4_STSC_DATA].buf;

    if (data == NULL) {
        ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
                      "no mp4 stsc atoms were found in \"%s\"",
                      mp4->file.name.data);
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT,"error:cngx_mp4_update_stsc_atom: "
                      "no mp4 stsc atoms were found in \"%s\"\n",
                      mp4->file.name.data);                      
        return NGX_ERROR;
    }

    if (trak->sample_to_chunk_entries == 0) {
        ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
                      "zero number of entries in stsc atom in \"%s\"",
                      mp4->file.name.data);
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT,"error:cngx_mp4_update_stsc_atom: "
                      "zero number of entries in stsc atom in \"%s\"\n",
                      mp4->file.name.data);                      
        return NGX_ERROR;
    }

    if (cngx_mp4_crop_stsc_data(mp4, trak, 1) != NGX_OK) {
        return NGX_ERROR;
    }

    if (cngx_mp4_crop_stsc_data(mp4, trak, 0) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
                   "sample-to-chunk entries:%uD",
                   trak->sample_to_chunk_entries);

    entry = (cngx_mp4_stsc_entry_t *) data->pos;
    end = (cngx_mp4_stsc_entry_t *) data->last;

    while (entry < end) {
        chunk = cngx_mp4_get_32value(entry->chunk);
        chunk -= trak->start_chunk;
        cngx_mp4_set_32value(entry->chunk, chunk);
        entry++;
    }

    atom_size = sizeof(cngx_mp4_stsc_atom_t)
                + trak->sample_to_chunk_entries * sizeof(cngx_mp4_stsc_entry_t);

    trak->size += atom_size;

    atom = trak->out[CNGX_MP4_STSC_ATOM].buf;
    stsc_atom = (cngx_mp4_stsc_atom_t *) atom->pos;

    cngx_mp4_set_32value(stsc_atom->size, atom_size);
    cngx_mp4_set_32value(stsc_atom->entries, trak->sample_to_chunk_entries);

    return NGX_OK;
}


static ngx_int_t
cngx_mp4_crop_stsc_data(cngx_mp4_file_t *mp4,
    cngx_mp4_trak_t *trak, ngx_uint_t start)
{
    uint32_t               start_sample, chunk, samples, id, next_chunk, n,
                           prev_samples;
    ngx_buf_t             *data, *buf;
    ngx_uint_t             entries, target_chunk, chunk_samples;
    cngx_mp4_stsc_entry_t  *entry, *end, *first;

    entries = trak->sample_to_chunk_entries - 1;

    if (start) {
        start_sample = (uint32_t) trak->start_sample;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
                       "mp4 stsc crop start_sample:%uD", start_sample);

    } else if (mp4->length) {
        start_sample = (uint32_t) (trak->end_sample - trak->start_sample);
        samples = 0;

        data = trak->out[CNGX_MP4_STSC_START].buf;

        if (data) {
            entry = (cngx_mp4_stsc_entry_t *) data->pos;
            samples = cngx_mp4_get_32value(entry->samples);
            entries--;

            if (samples > start_sample) {
                samples = start_sample;
                cngx_mp4_set_32value(entry->samples, samples);
            }

            start_sample -= samples;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
                       "mp4 stsc crop end_sample:%uD, ext_samples:%uD",
                       start_sample, samples);

    } else {
        return NGX_OK;
    }

    data = trak->out[CNGX_MP4_STSC_DATA].buf;

    entry = (cngx_mp4_stsc_entry_t *) data->pos;
    end = (cngx_mp4_stsc_entry_t *) data->last;

    chunk = cngx_mp4_get_32value(entry->chunk);
    samples = cngx_mp4_get_32value(entry->samples);
    id = cngx_mp4_get_32value(entry->id);
    prev_samples = 0;
    entry++;

    while (entry < end) {

        next_chunk = cngx_mp4_get_32value(entry->chunk);

        ngx_log_debug5(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
                       "sample:%uD, chunk:%uD, chunks:%uD, "
                       "samples:%uD, id:%uD",
                       start_sample, chunk, next_chunk - chunk, samples, id);

        n = (next_chunk - chunk) * samples;

        if (start_sample < n) {
            goto found;
        }

        start_sample -= n;

        prev_samples = samples;
        chunk = next_chunk;
        samples = cngx_mp4_get_32value(entry->samples);
        id = cngx_mp4_get_32value(entry->id);
        entries--;
        entry++;
    }

    next_chunk = trak->chunks + 1;

    ngx_log_debug4(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
                   "sample:%uD, chunk:%uD, chunks:%uD, samples:%uD",
                   start_sample, chunk, next_chunk - chunk, samples);

    n = (next_chunk - chunk) * samples;

    if (start_sample > n) {
        ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
                      "%s time is out mp4 stsc chunks in \"%s\"",
                      start ? "start" : "end", mp4->file.name.data);
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT,"error:cngx_mp4_crop_stsc_data: "
                      "%s time is out mp4 stsc chunks in \"%s\"\n",
                      start ? "start" : "end", mp4->file.name.data);                      
        return NGX_ERROR;
    }

found:

    entries++;
    entry--;

    if (samples == 0) {
        ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
                      "zero number of samples in \"%s\"",
                      mp4->file.name.data);
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT,"error:cngx_mp4_crop_stsc_data: "
                      "zero number of samples in \"%s\"\n",
                      mp4->file.name.data);                      
        return NGX_ERROR;
    }

    target_chunk = chunk - 1;
    target_chunk += start_sample / samples;
    chunk_samples = start_sample % samples;

    if (start) {
        data->pos = (u_char *) entry;

        trak->sample_to_chunk_entries = entries;
        trak->start_chunk = target_chunk;
        trak->start_chunk_samples = chunk_samples;

        cngx_mp4_set_32value(entry->chunk, trak->start_chunk + 1);

        samples -= chunk_samples;

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
                       "start_chunk:%ui, start_chunk_samples:%ui",
                       trak->start_chunk, trak->start_chunk_samples);

    } else {
        if (start_sample) {
            data->last = (u_char *) (entry + 1);
            trak->sample_to_chunk_entries -= entries - 1;
            trak->end_chunk_samples = samples;

        } else {
            data->last = (u_char *) entry;
            trak->sample_to_chunk_entries -= entries;
            trak->end_chunk_samples = prev_samples;
        }

        if (chunk_samples) {
            trak->end_chunk = target_chunk + 1;
            trak->end_chunk_samples = chunk_samples;

        } else {
            trak->end_chunk = target_chunk;
        }

        samples = chunk_samples;
        next_chunk = chunk + 1;

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
                       "end_chunk:%ui, end_chunk_samples:%ui",
                       trak->end_chunk, trak->end_chunk_samples);
    }

    if (chunk_samples && next_chunk - target_chunk == 2) {

        cngx_mp4_set_32value(entry->samples, samples);

    } else if (chunk_samples && start) {

        first = &trak->stsc_start_chunk_entry;
        cngx_mp4_set_32value(first->chunk, 1);
        cngx_mp4_set_32value(first->samples, samples);
        cngx_mp4_set_32value(first->id, id);

        buf = &trak->stsc_start_chunk_buf;
        buf->temporary = 1;
        buf->pos = (u_char *) first;
        buf->last = (u_char *) first + sizeof(cngx_mp4_stsc_entry_t);

        trak->out[CNGX_MP4_STSC_START].buf = buf;

        cngx_mp4_set_32value(entry->chunk, trak->start_chunk + 2);

        trak->sample_to_chunk_entries++;

    } else if (chunk_samples) {

        first = &trak->stsc_end_chunk_entry;
        cngx_mp4_set_32value(first->chunk, trak->end_chunk - trak->start_chunk);
        cngx_mp4_set_32value(first->samples, samples);
        cngx_mp4_set_32value(first->id, id);

        buf = &trak->stsc_end_chunk_buf;
        buf->temporary = 1;
        buf->pos = (u_char *) first;
        buf->last = (u_char *) first + sizeof(cngx_mp4_stsc_entry_t);

        trak->out[CNGX_MP4_STSC_END].buf = buf;

        trak->sample_to_chunk_entries++;
    }

    return NGX_OK;
}


static ngx_int_t
cngx_mp4_read_stsz_atom(cngx_mp4_file_t *mp4, uint64_t atom_data_size)
{
    u_char               *atom_header, *atom_table, *atom_end;
    size_t                atom_size;
    uint32_t              entries, size;
    ngx_buf_t            *atom, *data;
    cngx_mp4_stsz_atom_t  *stsz_atom;
    cngx_mp4_trak_t  *trak;

    /* sample sizes atom */

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0, "mp4 stsz atom");

    atom_header = cngx_mp4_atom_header(mp4);
    stsz_atom = (cngx_mp4_stsz_atom_t *) atom_header;
    cngx_mp4_set_atom_name(stsz_atom, 's', 't', 's', 'z');

    if (cngx_mp4_atom_data_size(cngx_mp4_stsz_atom_t) > atom_data_size) {
        ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
                      "\"%s\" mp4 stsz atom too small", mp4->file.name.data);
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT,"error:cngx_mp4_read_stsz_atom: "
                      "\"%s\" mp4 stsz atom too small\n", mp4->file.name.data);                      
        return NGX_ERROR;
    }

    size = cngx_mp4_get_32value(stsz_atom->uniform_size);
    entries = cngx_mp4_get_32value(stsz_atom->entries);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
                   "sample uniform size:%uD, entries:%uD", size, entries);

    trak = cngx_mp4_last_trak(mp4);
    trak->sample_sizes_entries = entries;

    atom_table = atom_header + sizeof(cngx_mp4_stsz_atom_t);

    atom = &trak->stsz_atom_buf;
    atom->temporary = 1;
    atom->pos = atom_header;
    atom->last = atom_table;

    trak->out[CNGX_MP4_STSZ_ATOM].buf = atom;

    if (size == 0) {
        if (cngx_mp4_atom_data_size(cngx_mp4_stsz_atom_t)
            + entries * sizeof(uint32_t) > atom_data_size)
        {
            ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
                          "\"%s\" mp4 stsz atom too small",
                          mp4->file.name.data);
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT,"error:cngx_mp4_read_stsz_atom: "
                          "\"%s\" mp4 stsz atom too small\n",
                          mp4->file.name.data);                          
            return NGX_ERROR;
        }

        atom_end = atom_table + entries * sizeof(uint32_t);

        data = &trak->stsz_data_buf;
        data->temporary = 1;
        data->pos = atom_table;
        data->last = atom_end;

        trak->out[CNGX_MP4_STSZ_DATA].buf = data;

    } else {
        /* if size != 0 then all samples are the same size */
        /* TODO : chunk samples */
        atom_size = sizeof(cngx_mp4_atom_header_t) + (size_t) atom_data_size;
        cngx_mp4_set_32value(atom_header, atom_size);
        trak->size += atom_size;
    }

    cngx_mp4_atom_next(mp4, atom_data_size);

    return NGX_OK;
}


static ngx_int_t
cngx_mp4_update_stsz_atom(cngx_mp4_file_t *mp4,
    cngx_mp4_trak_t *trak)
{
    size_t                atom_size;
    uint32_t             *pos, *end, entries;
    ngx_buf_t            *atom, *data;
    cngx_mp4_stsz_atom_t  *stsz_atom;

    /*
     * mdia.minf.stbl.stsz updating requires trak->start_sample
     * from mdia.minf.stbl.stts which depends on value from mdia.mdhd
     * atom which may reside after mdia.minf
     */

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
                   "mp4 stsz atom update");

    data = trak->out[CNGX_MP4_STSZ_DATA].buf;

    if (data) {
        entries = trak->sample_sizes_entries;

        if (trak->start_sample > entries) {
            ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
                          "start time is out mp4 stsz samples in \"%s\"",
                          mp4->file.name.data);
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT,"error:cngx_mp4_update_stsz_atom: "
                          "start time is out mp4 stsz samples in \"%s\"\n",
                          mp4->file.name.data);                          
            return NGX_ERROR;
        }

        entries -= trak->start_sample;
        data->pos += trak->start_sample * sizeof(uint32_t);
        end = (uint32_t *) data->pos;

        for (pos = end - trak->start_chunk_samples; pos < end; pos++) {
            trak->start_chunk_samples_size += cngx_mp4_get_32value(pos);
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
                       "chunk samples sizes:%uL",
                       trak->start_chunk_samples_size);

        if (mp4->length) {
            if (trak->end_sample - trak->start_sample > entries) {
                ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
                              "end time is out mp4 stsz samples in \"%s\"",
                              mp4->file.name.data);
                dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT,"error:cngx_mp4_update_stsz_atom: "
                              "end time is out mp4 stsz samples in \"%s\"\n",
                              mp4->file.name.data);                              
                return NGX_ERROR;
            }

            entries = trak->end_sample - trak->start_sample;
            data->last = data->pos + entries * sizeof(uint32_t);
            end = (uint32_t *) data->last;

            for (pos = end - trak->end_chunk_samples; pos < end; pos++) {
                trak->end_chunk_samples_size += cngx_mp4_get_32value(pos);
            }

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
                           "mp4 stsz end_chunk_samples_size:%uL",
                           trak->end_chunk_samples_size);
        }

        atom_size = sizeof(cngx_mp4_stsz_atom_t) + (data->last - data->pos);
        trak->size += atom_size;

        atom = trak->out[CNGX_MP4_STSZ_ATOM].buf;
        stsz_atom = (cngx_mp4_stsz_atom_t *) atom->pos;

        cngx_mp4_set_32value(stsz_atom->size, atom_size);
        cngx_mp4_set_32value(stsz_atom->entries, entries);
    }

    return NGX_OK;
}


static ngx_int_t
cngx_mp4_read_stco_atom(cngx_mp4_file_t *mp4, uint64_t atom_data_size)
{
    u_char               *atom_header, *atom_table, *atom_end;
    uint32_t              entries;
    ngx_buf_t            *atom, *data;
    cngx_mp4_stco_atom_t  *stco_atom;
    cngx_mp4_trak_t  *trak;

    /* chunk offsets atom */

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0, "mp4 stco atom");

    atom_header = cngx_mp4_atom_header(mp4);
    stco_atom = (cngx_mp4_stco_atom_t *) atom_header;
    cngx_mp4_set_atom_name(stco_atom, 's', 't', 'c', 'o');

    if (cngx_mp4_atom_data_size(cngx_mp4_stco_atom_t) > atom_data_size) {
        ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
                      "\"%s\" mp4 stco atom too small", mp4->file.name.data);
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT,"error:cngx_mp4_read_stco_atom: "
                      "\"%s\" mp4 stco atom too small\n", mp4->file.name.data);                      
        return NGX_ERROR;
    }

    entries = cngx_mp4_get_32value(stco_atom->entries);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0, "chunks:%uD", entries);

    if (cngx_mp4_atom_data_size(cngx_mp4_stco_atom_t)
        + entries * sizeof(uint32_t) > atom_data_size)
    {
        ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
                      "\"%s\" mp4 stco atom too small", mp4->file.name.data);
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT,"error:cngx_mp4_read_stco_atom: "
                      "\"%s\" mp4 stco atom too small\n", mp4->file.name.data);                      
        return NGX_ERROR;
    }

    atom_table = atom_header + sizeof(cngx_mp4_stco_atom_t);
    atom_end = atom_table + entries * sizeof(uint32_t);

    trak = cngx_mp4_last_trak(mp4);
    trak->chunks = entries;

    atom = &trak->stco_atom_buf;
    atom->temporary = 1;
    atom->pos = atom_header;
    atom->last = atom_table;

    data = &trak->stco_data_buf;
    data->temporary = 1;
    data->pos = atom_table;
    data->last = atom_end;

    trak->out[CNGX_MP4_STCO_ATOM].buf = atom;
    trak->out[CNGX_MP4_STCO_DATA].buf = data;

    cngx_mp4_atom_next(mp4, atom_data_size);

    return NGX_OK;
}


static ngx_int_t
cngx_mp4_update_stco_atom(cngx_mp4_file_t *mp4,
    cngx_mp4_trak_t *trak)
{
    size_t                atom_size;
    uint32_t              entries;
    ngx_buf_t            *atom, *data;
    cngx_mp4_stco_atom_t  *stco_atom;

    /*
     * mdia.minf.stbl.stco updating requires trak->start_chunk
     * from mdia.minf.stbl.stsc which depends on value from mdia.mdhd
     * atom which may reside after mdia.minf
     */

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
                   "mp4 stco atom update");

    data = trak->out[CNGX_MP4_STCO_DATA].buf;

    if (data == NULL) {
        ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
                      "no mp4 stco atoms were found in \"%s\"",
                      mp4->file.name.data);
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT,"error:cngx_mp4_update_stco_atom: "
                      "no mp4 stco atoms were found in \"%s\"\n",
                      mp4->file.name.data);                      
        return NGX_ERROR;
    }

    if (trak->start_chunk > trak->chunks) {
        ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
                      "start time is out mp4 stco chunks in \"%s\"",
                      mp4->file.name.data);
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT,"error:cngx_mp4_update_stco_atom: "
                      "start time is out mp4 stco chunks in \"%s\"\n",
                      mp4->file.name.data);                      
        return NGX_ERROR;
    }

    data->pos += trak->start_chunk * sizeof(uint32_t);

    trak->start_offset = cngx_mp4_get_32value(data->pos);
    trak->start_offset += trak->start_chunk_samples_size;
    cngx_mp4_set_32value(data->pos, trak->start_offset);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
                   "start chunk offset:%O", trak->start_offset);

    if (mp4->length) {

        if (trak->end_chunk > trak->chunks) {
            ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
                          "end time is out mp4 stco chunks in \"%s\"",
                          mp4->file.name.data);
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT,"error:cngx_mp4_update_stco_atom: "
                          "end time is out mp4 stco chunks in \"%s\"\n",
                          mp4->file.name.data);                          
            return NGX_ERROR;
        }

        entries = trak->end_chunk - trak->start_chunk;
        data->last = data->pos + entries * sizeof(uint32_t);

        if (entries) {
            trak->end_offset =
                            cngx_mp4_get_32value(data->last - sizeof(uint32_t));
            trak->end_offset += trak->end_chunk_samples_size;

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
                           "end chunk offset:%O", trak->end_offset);
        }

    } else {
        entries = trak->chunks - trak->start_chunk;
        trak->end_offset = mp4->mdat_data.buf->file_last;
    }

    if (entries == 0) {
        trak->start_offset = mp4->end;
        trak->end_offset = 0;
    }

    atom_size = sizeof(cngx_mp4_stco_atom_t) + (data->last - data->pos);
    trak->size += atom_size;

    atom = trak->out[CNGX_MP4_STCO_ATOM].buf;
    stco_atom = (cngx_mp4_stco_atom_t *) atom->pos;

    cngx_mp4_set_32value(stco_atom->size, atom_size);
    cngx_mp4_set_32value(stco_atom->entries, entries);

    return NGX_OK;
}


static void
cngx_mp4_adjust_stco_atom(cngx_mp4_file_t *mp4,
    cngx_mp4_trak_t *trak, int32_t adjustment)
{
    uint32_t    offset, *entry, *end;
    ngx_buf_t  *data;

    /*
     * moov.trak.mdia.minf.stbl.stco adjustment requires
     * minimal start offset of all traks and new moov atom size
     */

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
                   "mp4 stco atom adjustment");

    data = trak->out[CNGX_MP4_STCO_DATA].buf;
    entry = (uint32_t *) data->pos;
    end = (uint32_t *) data->last;

    while (entry < end) {
        offset = cngx_mp4_get_32value(entry);
        offset += adjustment;
        cngx_mp4_set_32value(entry, offset);
        entry++;
    }
}


static ngx_int_t
cngx_mp4_read_co64_atom(cngx_mp4_file_t *mp4, uint64_t atom_data_size)
{
    u_char               *atom_header, *atom_table, *atom_end;
    uint32_t              entries;
    ngx_buf_t            *atom, *data;
    cngx_mp4_co64_atom_t  *co64_atom;
    cngx_mp4_trak_t  *trak;

    /* chunk offsets atom */

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0, "mp4 co64 atom");

    atom_header = cngx_mp4_atom_header(mp4);
    co64_atom = (cngx_mp4_co64_atom_t *) atom_header;
    cngx_mp4_set_atom_name(co64_atom, 'c', 'o', '6', '4');

    if (cngx_mp4_atom_data_size(cngx_mp4_co64_atom_t) > atom_data_size) {
        ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
                      "\"%s\" mp4 co64 atom too small", mp4->file.name.data);
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT,"error:cngx_mp4_read_co64_atom: "
                      "\"%s\" mp4 co64 atom too small\n", mp4->file.name.data);                      
        return NGX_ERROR;
    }

    entries = cngx_mp4_get_32value(co64_atom->entries);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0, "chunks:%uD", entries);

    if (cngx_mp4_atom_data_size(cngx_mp4_co64_atom_t)
        + entries * sizeof(uint64_t) > atom_data_size)
    {
        ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
                      "\"%s\" mp4 co64 atom too small", mp4->file.name.data);
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT,"error:cngx_mp4_read_co64_atom: "
                      "\"%s\" mp4 co64 atom too small\n", mp4->file.name.data);                      
        return NGX_ERROR;
    }

    atom_table = atom_header + sizeof(cngx_mp4_co64_atom_t);
    atom_end = atom_table + entries * sizeof(uint64_t);

    trak = cngx_mp4_last_trak(mp4);
    trak->chunks = entries;

    atom = &trak->co64_atom_buf;
    atom->temporary = 1;
    atom->pos = atom_header;
    atom->last = atom_table;

    data = &trak->co64_data_buf;
    data->temporary = 1;
    data->pos = atom_table;
    data->last = atom_end;

    trak->out[CNGX_MP4_CO64_ATOM].buf = atom;
    trak->out[CNGX_MP4_CO64_DATA].buf = data;

    cngx_mp4_atom_next(mp4, atom_data_size);

    return NGX_OK;
}


static ngx_int_t
cngx_mp4_update_co64_atom(cngx_mp4_file_t *mp4,
    cngx_mp4_trak_t *trak)
{
    size_t                atom_size;
    uint64_t              entries;
    ngx_buf_t            *atom, *data;
    cngx_mp4_co64_atom_t  *co64_atom;

    /*
     * mdia.minf.stbl.co64 updating requires trak->start_chunk
     * from mdia.minf.stbl.stsc which depends on value from mdia.mdhd
     * atom which may reside after mdia.minf
     */

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
                   "mp4 co64 atom update");

    data = trak->out[CNGX_MP4_CO64_DATA].buf;

    if (data == NULL) {
        ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
                      "no mp4 co64 atoms were found in \"%s\"",
                      mp4->file.name.data);
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT,"error:cngx_mp4_update_co64_atom: "
                      "no mp4 co64 atoms were found in \"%s\"\n",
                      mp4->file.name.data);                      
        return NGX_ERROR;
    }

    if (trak->start_chunk > trak->chunks) {
        ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
                      "start time is out mp4 co64 chunks in \"%s\"",
                      mp4->file.name.data);
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT,"error:cngx_mp4_update_co64_atom: "
                      "start time is out mp4 co64 chunks in \"%s\"\n",
                      mp4->file.name.data);                      
        return NGX_ERROR;
    }

    data->pos += trak->start_chunk * sizeof(uint64_t);

    trak->start_offset = cngx_mp4_get_64value(data->pos);
    trak->start_offset += trak->start_chunk_samples_size;
    cngx_mp4_set_64value(data->pos, trak->start_offset);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
                   "start chunk offset:%O", trak->start_offset);

    if (mp4->length) {

        if (trak->end_chunk > trak->chunks) {
            ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
                          "end time is out mp4 co64 chunks in \"%s\"",
                          mp4->file.name.data);
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT,"error:cngx_mp4_update_co64_atom: "
                          "end time is out mp4 co64 chunks in \"%s\"\n",
                          mp4->file.name.data);                          
            return NGX_ERROR;
        }

        entries = trak->end_chunk - trak->start_chunk;
        data->last = data->pos + entries * sizeof(uint64_t);

        if (entries) {
            trak->end_offset =
                            cngx_mp4_get_64value(data->last - sizeof(uint64_t));
            trak->end_offset += trak->end_chunk_samples_size;

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
                           "end chunk offset:%O", trak->end_offset);
        }

    } else {
        entries = trak->chunks - trak->start_chunk;
        trak->end_offset = mp4->mdat_data.buf->file_last;
    }

    if (entries == 0) {
        trak->start_offset = mp4->end;
        trak->end_offset = 0;
    }

    atom_size = sizeof(cngx_mp4_co64_atom_t) + (data->last - data->pos);
    trak->size += atom_size;

    atom = trak->out[CNGX_MP4_CO64_ATOM].buf;
    co64_atom = (cngx_mp4_co64_atom_t *) atom->pos;

    cngx_mp4_set_32value(co64_atom->size, atom_size);
    cngx_mp4_set_32value(co64_atom->entries, entries);

    return NGX_OK;
}


static void
cngx_mp4_adjust_co64_atom(cngx_mp4_file_t *mp4,
    cngx_mp4_trak_t *trak, off_t adjustment)
{
    uint64_t    offset, *entry, *end;
    ngx_buf_t  *data;

    /*
     * moov.trak.mdia.minf.stbl.co64 adjustment requires
     * minimal start offset of all traks and new moov atom size
     */

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
                   "mp4 co64 atom adjustment");

    data = trak->out[CNGX_MP4_CO64_DATA].buf;
    entry = (uint64_t *) data->pos;
    end = (uint64_t *) data->last;

    while (entry < end) {
        offset = cngx_mp4_get_64value(entry);
        offset += adjustment;
        cngx_mp4_set_64value(entry, offset);
        entry++;
    }
}


#endif/*(SWITCH_ON == NGX_BGN_SWITCH)*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/
