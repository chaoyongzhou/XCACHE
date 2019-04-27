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

#include "type.h"
#include "mm.h"
#include "log.h"
#include "cmisc.h"

#include "camd.h"
#include "cmmap.h"

CMMAP_NODE *cmmap_node_new()
{
    CMMAP_NODE *cmmap_node;

    alloc_static_mem(MM_CMMAP_NODE, &cmmap_node, LOC_CMMAP_0001);
    if(NULL_PTR == cmmap_node)
    {
        dbg_log(SEC_0209_CMMAP, 0)(LOGSTDOUT, "error:cmmap_node_new: "
                                              "alloc memory failed\n");
        return (NULL_PTR);
    }

    cmmap_node_init(cmmap_node);
    return (cmmap_node);
}

EC_BOOL cmmap_node_init(CMMAP_NODE *cmmap_node)
{
    CMMAP_NODE_S_ADDR(cmmap_node)         = NULL_PTR;
    CMMAP_NODE_E_ADDR(cmmap_node)         = NULL_PTR;
    CMMAP_NODE_C_ADDR(cmmap_node)         = NULL_PTR;

    return (EC_TRUE);
}

EC_BOOL cmmap_node_clean(CMMAP_NODE *cmmap_node)
{
    if(NULL_PTR != cmmap_node)
    {
        if(NULL_PTR != CMMAP_NODE_S_ADDR(cmmap_node)
        && CMMAP_NODE_S_ADDR(cmmap_node) < CMMAP_NODE_E_ADDR(cmmap_node))
        {
            UINT32  size;

            size = CMMAP_NODE_E_ADDR(cmmap_node) - CMMAP_NODE_S_ADDR(cmmap_node);

            c_munlock(CMMAP_NODE_S_ADDR(cmmap_node), size);

            c_mdiscard(CMMAP_NODE_S_ADDR(cmmap_node), size);

            c_munmap_aligned(CMMAP_NODE_S_ADDR(cmmap_node), size);
        }

        CMMAP_NODE_S_ADDR(cmmap_node)         = NULL_PTR;
        CMMAP_NODE_E_ADDR(cmmap_node)         = NULL_PTR;
        CMMAP_NODE_C_ADDR(cmmap_node)         = NULL_PTR;
    }

    return (EC_TRUE);
}

EC_BOOL cmmap_node_free(CMMAP_NODE *cmmap_node)
{
    if(NULL_PTR != cmmap_node)
    {
        cmmap_node_clean(cmmap_node);
        free_static_mem(MM_CMMAP_NODE, cmmap_node, LOC_CMMAP_0002);
    }
    return (EC_TRUE);
}

void cmmap_node_print(LOG *log, const CMMAP_NODE *cmmap_node)
{
    if(NULL_PTR != cmmap_node)
    {
        sys_log(log, "[DEBUG] cmmap_node_print: "
                     "cmmap_node %p: range [%p, %p), cur %p\n",
                     cmmap_node,
                     CMMAP_NODE_S_ADDR(cmmap_node),
                     CMMAP_NODE_E_ADDR(cmmap_node),
                     CMMAP_NODE_C_ADDR(cmmap_node));
    }
    return;
}

CMMAP_NODE *cmmap_node_create(const UINT32 size, const UINT32 align)
{
    CMMAP_NODE *cmmap_node;

    cmmap_node = cmmap_node_new();
    if(NULL_PTR == cmmap_node)
    {
        dbg_log(SEC_0209_CMMAP, 0)(LOGSTDOUT, "error:cmmap_node_create: "
                                              "new cmmap_node failed\n");
        return (NULL_PTR);
    }

    CMMAP_NODE_S_ADDR(cmmap_node) = c_mmap_aligned(size, align, CMMAP_PROTO, CMMAP_FLAGS);
    if(NULL_PTR == CMMAP_NODE_S_ADDR(cmmap_node))
    {
        dbg_log(SEC_0209_CMMAP, 0)(LOGSTDOUT, "error:cmmap_node_create: "
                                              "mmap size %ld, align %ld failed\n",
                                              size, align);
        cmmap_node_free(cmmap_node);
        return (NULL_PTR);
    }

    CMMAP_NODE_E_ADDR(cmmap_node) = CMMAP_NODE_S_ADDR(cmmap_node) + size;
    CMMAP_NODE_C_ADDR(cmmap_node) = CMMAP_NODE_S_ADDR(cmmap_node);

    return (cmmap_node);
}

EC_BOOL cmmap_node_shrink(CMMAP_NODE *cmmap_node)
{
    void    *c_mmap_addr;
    ASSERT(CMMAP_NODE_S_ADDR(cmmap_node) < CMMAP_NODE_C_ADDR(cmmap_node));

    c_mmap_addr = (void *)VAL_ALIGN((UINT32)CMMAP_NODE_C_ADDR(cmmap_node), CMMAP_MEM_ALIGNMENT);

    if(c_mmap_addr < CMMAP_NODE_E_ADDR(cmmap_node))
    {
        UINT32      size;

        size = CMMAP_NODE_E_ADDR(cmmap_node) - c_mmap_addr;

        if(EC_FALSE == c_munmap_aligned(c_mmap_addr, size))
        {
            dbg_log(SEC_0209_CMMAP, 0)(LOGSTDOUT, "error:cmmap_node_shrink: "
                                                  "mmap [%p, %p), cur %p (aligned %p), shrink %ld bytes failed\n",
                                                  CMMAP_NODE_S_ADDR(cmmap_node),
                                                  CMMAP_NODE_E_ADDR(cmmap_node),
                                                  CMMAP_NODE_C_ADDR(cmmap_node),
                                                  c_mmap_addr,
                                                  size);
            return (EC_FALSE);
        }

        dbg_log(SEC_0209_CMMAP, 0)(LOGSTDOUT, "[DEBUG] cmmap_node_shrink: "
                                              "mmap [%p, %p), cur %p, size %ld "
                                              "=> [%p, %p), cur %p, size %ld\n",
                                              CMMAP_NODE_S_ADDR(cmmap_node),
                                              CMMAP_NODE_E_ADDR(cmmap_node),
                                              CMMAP_NODE_C_ADDR(cmmap_node),
                                              CMMAP_NODE_E_ADDR(cmmap_node) - CMMAP_NODE_S_ADDR(cmmap_node),
                                              CMMAP_NODE_S_ADDR(cmmap_node),
                                              c_mmap_addr,
                                              CMMAP_NODE_C_ADDR(cmmap_node),
                                              CMMAP_NODE_C_ADDR(cmmap_node) - CMMAP_NODE_S_ADDR(cmmap_node));


        CMMAP_NODE_E_ADDR(cmmap_node) = c_mmap_addr;

        return (EC_TRUE);
    }

    return (EC_TRUE);
}

void *cmmap_node_alloc(CMMAP_NODE *cmmap_node, const UINT32 size, const UINT32 align, const char *tip)
{
    void    *c_mmap_addr;

    c_mmap_addr = CMMAP_NODE_C_ADDR(cmmap_node);
    if(0 < align)
    {
        c_mmap_addr = (void *)VAL_ALIGN((UINT32)c_mmap_addr, align);
    }

    if(c_mmap_addr + size > CMMAP_NODE_E_ADDR(cmmap_node))
    {
        dbg_log(SEC_0209_CMMAP, 0)(LOGSTDOUT, "error:cmmap_node_alloc: [%s] "
                                              "cmmap node [%p, %p), cur %p cannot alloc %ld, align %ld\n",
                                              tip,
                                              CMMAP_NODE_S_ADDR(cmmap_node),
                                              CMMAP_NODE_E_ADDR(cmmap_node),
                                              CMMAP_NODE_C_ADDR(cmmap_node),
                                              size, align);
        return (NULL_PTR);
    }

    dbg_log(SEC_0209_CMMAP, 1)(LOGSTDOUT, "[DEBUG] cmmap_node_alloc: [%s] "
                                          "mmap [%p, %p), cur %p (aligned %p) => %p, "
                                          "capacity %ld, offset %ld, size %ld, align %ld\n",
                                          tip,
                                          CMMAP_NODE_S_ADDR(cmmap_node),
                                          CMMAP_NODE_E_ADDR(cmmap_node),
                                          CMMAP_NODE_C_ADDR(cmmap_node),
                                          c_mmap_addr,
                                          c_mmap_addr + size,
                                          CMMAP_NODE_E_ADDR(cmmap_node) - CMMAP_NODE_S_ADDR(cmmap_node),
                                          CMMAP_NODE_C_ADDR(cmmap_node) - CMMAP_NODE_S_ADDR(cmmap_node),
                                          size, align);

    CMMAP_NODE_C_ADDR(cmmap_node) = c_mmap_addr + size; /*point to start address of free space*/

    return (c_mmap_addr);
}

EC_BOOL cmmap_node_peek(CMMAP_NODE *cmmap_node, const UINT32 size, void *data)
{
    void    *c_mmap_addr;

    c_mmap_addr = CMMAP_NODE_C_ADDR(cmmap_node);

    if(c_mmap_addr + size > CMMAP_NODE_E_ADDR(cmmap_node))
    {
        dbg_log(SEC_0209_CMMAP, 0)(LOGSTDOUT, "error:cmmap_node_peek: "
                                              "cmmap node [%p, %p), cur %p, peek %ld bytes failed\n",
                                              CMMAP_NODE_S_ADDR(cmmap_node),
                                              CMMAP_NODE_E_ADDR(cmmap_node),
                                              CMMAP_NODE_C_ADDR(cmmap_node),
                                              size);
        return (EC_FALSE);
    }

    BCOPY(c_mmap_addr, data, size);

    dbg_log(SEC_0209_CMMAP, 1)(LOGSTDOUT, "[DEBUG] cmmap_node_peek: "
                                          "mmap [%p, %p), cur %p, "
                                          "capacity %ld, offset %ld, size %ld\n",
                                          CMMAP_NODE_S_ADDR(cmmap_node),
                                          CMMAP_NODE_E_ADDR(cmmap_node),
                                          CMMAP_NODE_C_ADDR(cmmap_node),
                                          CMMAP_NODE_E_ADDR(cmmap_node) - CMMAP_NODE_S_ADDR(cmmap_node),
                                          CMMAP_NODE_C_ADDR(cmmap_node) - CMMAP_NODE_S_ADDR(cmmap_node),
                                          size);

    return (EC_TRUE);
}

UINT32 cmmap_node_space(const CMMAP_NODE *cmmap_node)
{
    UINT32      space;

    space = CMMAP_NODE_E_ADDR(cmmap_node) - CMMAP_NODE_S_ADDR(cmmap_node);
    return (space);
}

UINT32 cmmap_node_room(const CMMAP_NODE *cmmap_node)
{
    UINT32      room;

    room = CMMAP_NODE_E_ADDR(cmmap_node) - CMMAP_NODE_C_ADDR(cmmap_node);
    return (room);
}

UINT32 cmmap_node_used(const CMMAP_NODE *cmmap_node)
{
    UINT32      used;

    used = CMMAP_NODE_C_ADDR(cmmap_node) - CMMAP_NODE_S_ADDR(cmmap_node);
    return (used);
}

EC_BOOL cmmap_node_dump_shm(CMMAP_NODE *cmmap_node, const char *shm_root_dir, const UINT32 shm_file_size)
{
    uint32_t         shm_file_idx;

    for(shm_file_idx = 0;
        CMMAP_NODE_S_ADDR(cmmap_node) < CMMAP_NODE_E_ADDR(cmmap_node);
        shm_file_idx ++)
    {
        void            *c_mmap_addr;
        char            *shm_file_name;
        UINT32           shm_file_offset;
        UINT32           shm_size;
        int              shm_fd;

        c_mmap_addr = CMMAP_NODE_S_ADDR(cmmap_node);
        shm_size    = DMIN(shm_file_size, CMMAP_NODE_E_ADDR(cmmap_node) - CMMAP_NODE_S_ADDR(cmmap_node));

        shm_file_name = safe_malloc(CMMAP_SHM_FNAME_MAX_LEN, LOC_CMMAP_0003);
        if(NULL_PTR == shm_file_name)
        {
            dbg_log(SEC_0209_CMMAP, 0)(LOGSTDOUT, "error:cmmap_node_dump_shm: "
                                                  "malloc file name failed\n");
            return (EC_FALSE);
        }

        snprintf(shm_file_name, CMMAP_SHM_FNAME_MAX_LEN, "%s/%u", shm_root_dir, shm_file_idx);

        if(EC_TRUE == c_shm_file_exist(shm_file_name))
        {
            if(EC_FALSE == c_shm_file_remove(shm_file_name))
            {
                dbg_log(SEC_0209_CMMAP, 0)(LOGSTDOUT, "error:cmmap_node_dump_shm: "
                                                      "remove existing shm file '%s' failed\n",
                                                      shm_file_name);
                safe_free(shm_file_name, LOC_CMMAP_0004);
                return (EC_FALSE);
            }
            dbg_log(SEC_0209_CMMAP, 9)(LOGSTDOUT, "[DEBUG] cmmap_node_dump_shm: "
                                                  "remove existing shm file '%s' done\n",
                                                  shm_file_name);
        }

        shm_fd = c_shm_file_create(shm_file_name, shm_size,
                                   O_RDWR | O_CREAT | O_EXCL,
                                   S_IRUSR | S_IWUSR);
        if(ERR_FD == shm_fd)
        {
            dbg_log(SEC_0209_CMMAP, 0)(LOGSTDOUT, "error:cmmap_node_dump_shm: "
                                                  "create shm file '%s' failed\n",
                                                  shm_file_name);
            safe_free(shm_file_name, LOC_CMMAP_0005);
            return (EC_FALSE);
        }

        shm_file_offset = 0;

        if(EC_FALSE == c_shm_file_pwrite(shm_fd, &shm_file_offset, shm_size, c_mmap_addr))
        {
            dbg_log(SEC_0209_CMMAP, 0)(LOGSTDOUT, "error:cmmap_node_dump_shm: "
                                                  "flush to '%s' failed\n",
                                                  shm_file_name);
            c_shm_file_close(shm_fd);
            c_shm_file_remove(shm_file_name);

            safe_free(shm_file_name, LOC_CMMAP_0006);
            return (EC_FALSE);
        }
        dbg_log(SEC_0209_CMMAP, 9)(LOGSTDOUT, "[DEBUG] cmmap_node_dump_shm: "
                                              "flush to '%s' done\n",
                                              shm_file_name);

        c_shm_file_close(shm_fd);
        safe_free(shm_file_name, LOC_CMMAP_0007);

        if(EC_FALSE == c_munlock(c_mmap_addr, shm_size))
        {
            dbg_log(SEC_0209_CMMAP, 0)(LOGSTDOUT, "error:cmmap_node_dump_shm: "
                                                  "munlock %p, size %ld failed\n",
                                                  c_mmap_addr, shm_size);
            return (EC_FALSE);
        }

        if(EC_FALSE == c_mdiscard(c_mmap_addr, shm_size))
        {
            dbg_log(SEC_0209_CMMAP, 0)(LOGSTDOUT, "error:cmmap_node_dump_shm: "
                                                  "discard %p, size %ld failed\n",
                                                  c_mmap_addr, shm_size);
            return (EC_FALSE);
        }

        if(EC_FALSE == c_munmap_aligned(c_mmap_addr, shm_size))
        {
            dbg_log(SEC_0209_CMMAP, 0)(LOGSTDOUT, "error:cmmap_node_dump_shm: "
                                                  "munmap %p, size %ld failed\n",
                                                  c_mmap_addr, shm_size);
            return (EC_FALSE);
        }

        CMMAP_NODE_S_ADDR(cmmap_node) += shm_size;
        if(CMMAP_NODE_C_ADDR(cmmap_node) < CMMAP_NODE_S_ADDR(cmmap_node))
        {
            CMMAP_NODE_C_ADDR(cmmap_node) = CMMAP_NODE_S_ADDR(cmmap_node);
        }
    }

    if(CMMAP_NODE_S_ADDR(cmmap_node) == CMMAP_NODE_E_ADDR(cmmap_node))
    {
        cmmap_node_clean(cmmap_node); /*reset*/
    }
    return (EC_TRUE);
}

EC_BOOL cmmap_node_restore_shm(CMMAP_NODE *cmmap_node, const char *shm_root_dir, const UINT32 align)
{
    UINT32           c_mmap_offset;
    uint32_t         shm_file_idx;

    c_mmap_offset = 0;

    for(shm_file_idx = 0;/*nothing*/;shm_file_idx ++)
    {
        void            *c_mmap_addr;
        char            *shm_file_name;
        UINT32           shm_file_size;
        UINT32           shm_file_offset;
        int              shm_fd;

        shm_file_name = safe_malloc(CMMAP_SHM_FNAME_MAX_LEN, LOC_CMMAP_0008);
        if(NULL_PTR == shm_file_name)
        {
            dbg_log(SEC_0209_CMMAP, 0)(LOGSTDOUT, "error:cmmap_node_restore_shm: "
                                                  "malloc file name failed\n");
            return (EC_FALSE);
        }

        snprintf(shm_file_name, CMMAP_SHM_FNAME_MAX_LEN, "%s/%u", shm_root_dir, shm_file_idx);

        if(EC_FALSE == c_shm_file_exist(shm_file_name))
        {
            safe_free(shm_file_name, LOC_CMMAP_0009);
            break;
        }

        shm_fd = c_shm_file_open(shm_file_name, O_RDWR | O_EXCL, S_IRUSR | S_IWUSR);
        if(ERR_FD == shm_fd)
        {
            dbg_log(SEC_0209_CMMAP, 0)(LOGSTDOUT, "error:cmmap_node_restore_shm: "
                                                  "open shm file '%s' failed\n",
                                                  shm_file_name);
            safe_free(shm_file_name, LOC_CMMAP_0010);
            return (EC_FALSE);
        }

        if(EC_FALSE == c_shm_file_size(shm_fd, &shm_file_size))
        {
            dbg_log(SEC_0209_CMMAP, 0)(LOGSTDOUT, "error:cmmap_node_restore_shm: "
                                                  "size of shm file '%s' failed\n",
                                                  shm_file_name);
            safe_free(shm_file_name, LOC_CMMAP_0011);
            c_shm_file_close(shm_fd);
            return (EC_FALSE);
        }

        if(NULL_PTR == CMMAP_NODE_S_ADDR(cmmap_node))
        {
            void       *addr;
            UINT32      size;

            size = shm_file_size;

            addr = c_mmap_aligned(size, align, CMMAP_PROTO, CMMAP_FLAGS);
            if(NULL_PTR == addr)
            {
                dbg_log(SEC_0209_CMMAP, 0)(LOGSTDOUT, "error:cmmap_node_restore_shm: "
                                                      "mmap size %ld, align %ld for shm file '%s' failed\n",
                                                      size, align, shm_file_name);
                safe_free(shm_file_name, LOC_CMMAP_0012);
                c_shm_file_close(shm_fd);
                return (EC_FALSE);
            }

            dbg_log(SEC_0209_CMMAP, 9)(LOGSTDOUT, "[DEBUG] cmmap_node_restore_shm: "
                                                  "mmap for shm file '%s' done, [%p, %p), %ld\n",
                                                  shm_file_name,
                                                  addr, addr + size, size);

            CMMAP_NODE_S_ADDR(cmmap_node) = addr;
            CMMAP_NODE_E_ADDR(cmmap_node) = addr + size;
            CMMAP_NODE_C_ADDR(cmmap_node) = addr;
        }

        else if(CMMAP_NODE_S_ADDR(cmmap_node)
              + c_mmap_offset
              + shm_file_size
              > CMMAP_NODE_E_ADDR(cmmap_node))
        {
            void       *old_addr;
            UINT32      old_size;
            void       *new_addr;
            UINT32      new_size;

            old_addr = CMMAP_NODE_S_ADDR(cmmap_node);
            old_size = CMMAP_NODE_E_ADDR(cmmap_node) - CMMAP_NODE_S_ADDR(cmmap_node);
            new_size = old_size + shm_file_size;

            new_addr = c_mremap_aligned(old_addr, old_size, new_size, align);
            if(NULL_PTR == new_addr)
            {
                dbg_log(SEC_0209_CMMAP, 0)(LOGSTDOUT, "error:cmmap_node_restore_shm: "
                                                      "mremap for shm file '%s' failed\n",
                                                      shm_file_name);
                safe_free(shm_file_name, LOC_CMMAP_0013);
                c_shm_file_close(shm_fd);
                return (EC_FALSE);
            }

            dbg_log(SEC_0209_CMMAP, 9)(LOGSTDOUT, "[DEBUG] cmmap_node_restore_shm: "
                                                  "mremap for shm file '%s' done, "
                                                  "[%p, %p), %ld => [%p, %p), %ld\n",
                                                  shm_file_name,
                                                  CMMAP_NODE_S_ADDR(cmmap_node),
                                                  CMMAP_NODE_E_ADDR(cmmap_node),
                                                  old_size,
                                                  new_addr,
                                                  new_addr + new_size,
                                                  new_size);

            CMMAP_NODE_S_ADDR(cmmap_node) = new_addr;
            CMMAP_NODE_E_ADDR(cmmap_node) = new_addr + new_size;
            CMMAP_NODE_C_ADDR(cmmap_node) = new_addr;
        }

        shm_file_offset = 0;
        c_mmap_addr     = CMMAP_NODE_S_ADDR(cmmap_node) + c_mmap_offset;

        if(EC_FALSE == c_shm_file_pread(shm_fd, &shm_file_offset, shm_file_size, c_mmap_addr))
        {
            dbg_log(SEC_0209_CMMAP, 0)(LOGSTDOUT, "error:cmmap_node_restore_shm: "
                                                  "load from '%s' failed\n",
                                                  shm_file_name);
            c_shm_file_close(shm_fd);
            safe_free(shm_file_name, LOC_CMMAP_0014);
            return (EC_FALSE);
        }

        dbg_log(SEC_0209_CMMAP, 9)(LOGSTDOUT, "[DEBUG] cmmap_node_restore_shm: "
                                              "load from '%s' done\n",
                                              shm_file_name);

        c_shm_file_close(shm_fd);

        if(EC_FALSE == c_shm_file_remove(shm_file_name))
        {
            dbg_log(SEC_0209_CMMAP, 0)(LOGSTDOUT, "error:cmmap_node_restore_shm: "
                                                  "remove '%s' failed\n",
                                                  shm_file_name);
            safe_free(shm_file_name, LOC_CMMAP_0015);
            return (EC_FALSE);
        }
        dbg_log(SEC_0209_CMMAP, 9)(LOGSTDOUT, "[DEBUG] cmmap_node_restore_shm: "
                                              "remove '%s' done\n",
                                              shm_file_name);
        safe_free(shm_file_name, LOC_CMMAP_0016);

        c_mmap_offset += shm_file_size;
    }

    if(EC_FALSE == c_shm_dir_remove(shm_root_dir))
    {
        dbg_log(SEC_0209_CMMAP, 0)(LOGSTDOUT, "error:cmmap_node_restore_shm: "
                                              "remove root dir '%s' failed\n",
                                              shm_root_dir);
        return (EC_FALSE);
    }
    dbg_log(SEC_0209_CMMAP, 9)(LOGSTDOUT, "[DEBUG] cmmap_node_restore_shm: "
                                          "remove root dir '%s' done\n",
                                          shm_root_dir);

    return (EC_TRUE);
}

EC_BOOL cmmap_node_import(CMMAP_NODE *cmmap_node, const void *data, const UINT32 size)
{
    if(CMMAP_NODE_S_ADDR(cmmap_node) + size != CMMAP_NODE_E_ADDR(cmmap_node))
    {
        dbg_log(SEC_0209_CMMAP, 0)(LOGSTDOUT, "error:cmmap_node_import: "
                                              "space %ld != size %ld\n",
                                              CMMAP_NODE_E_ADDR(cmmap_node) - CMMAP_NODE_S_ADDR(cmmap_node),
                                              size);
        return (EC_FALSE);
    }

    BCOPY(data, CMMAP_NODE_S_ADDR(cmmap_node), size);

    dbg_log(SEC_0209_CMMAP, 0)(LOGSTDOUT, "[DEBUG] cmmap_node_import: "
                                          "copy %ld bytes done\n",
                                          size);
    return (EC_TRUE);
}

EC_BOOL cmmap_node_sync(CMMAP_NODE *cmmap_node, void *camd_md, const UINT32 offset)
{
    UINT32           c_offset;

    c_offset = offset;

    while(CMMAP_NODE_S_ADDR(cmmap_node) < CMMAP_NODE_E_ADDR(cmmap_node))
    {
        UINT32           space;
        UINT32           wsize;
        UINT32           c_offset_saved;
        void            *s_mmap_addr;

        space           = CMMAP_NODE_E_ADDR(cmmap_node) - CMMAP_NODE_S_ADDR(cmmap_node);
        wsize           = DMIN(space, CMMAP_SYNC_SIZE_NBYTES);
        c_offset_saved  = c_offset;
        s_mmap_addr     = CMMAP_NODE_S_ADDR(cmmap_node);

        if(EC_FALSE == camd_file_write_dio((CAMD_MD *)camd_md, &c_offset, wsize, s_mmap_addr))
        {
            dbg_log(SEC_0209_CMMAP, 0)(LOGSTDOUT, "error:cmmap_node_sync: "
                                                  "sync %p, space %ld, wsize %ld to offset %ld failed\n",
                                                  s_mmap_addr, space, wsize, c_offset_saved);
            return (EC_FALSE);
        }

        if(EC_FALSE == c_munlock(s_mmap_addr, wsize))
        {
            dbg_log(SEC_0209_CMMAP, 0)(LOGSTDOUT, "error:cmmap_node_sync: "
                                                  "munlock %p, space %ld, wsize %ld failed\n",
                                                  s_mmap_addr, space, wsize);
            return (EC_FALSE);
        }

        if(EC_FALSE == c_mdiscard(s_mmap_addr, wsize))
        {
            dbg_log(SEC_0209_CMMAP, 0)(LOGSTDOUT, "error:cmmap_node_sync: "
                                                  "discard %p, space %ld, wsize %ld failed\n",
                                                  s_mmap_addr, space, wsize);
            return (EC_FALSE);
        }

        if(EC_FALSE == c_munmap_aligned(s_mmap_addr, wsize))
        {
            dbg_log(SEC_0209_CMMAP, 0)(LOGSTDOUT, "error:cmmap_node_sync: "
                                                  "munmap %p, space %ld, size %ld failed\n",
                                                  s_mmap_addr, space, wsize);
            return (EC_FALSE);
        }

        dbg_log(SEC_0209_CMMAP, 0)(LOGSTDOUT, "[DEBUG] cmmap_node_sync: "
                                              "sync %p, space %ld, wsize %ld to offset %ld done\n",
                                              s_mmap_addr, space, wsize, c_offset_saved);

        CMMAP_NODE_S_ADDR(cmmap_node) += wsize;

        if(CMMAP_NODE_C_ADDR(cmmap_node) < CMMAP_NODE_S_ADDR(cmmap_node))
        {
            CMMAP_NODE_C_ADDR(cmmap_node) = CMMAP_NODE_S_ADDR(cmmap_node);
        }
    }

    dbg_log(SEC_0209_CMMAP, 0)(LOGSTDOUT, "[DEBUG] cmmap_node_sync: "
                                          "sync done\n");
    return (EC_TRUE);
}


#ifdef __cplusplus
}
#endif/*__cplusplus*/
