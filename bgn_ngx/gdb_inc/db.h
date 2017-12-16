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


#ifndef _GNUPDATEDB_DB_H_
#define _GNUPDATEDB_DB_H_

typedef struct _GDatabase GDatabase;   /**< GNUpdate database. */

/**
 * Database types.
 */
#define  GDB_INDEX_FILE  ((uint8_t) 0x01)
#define  GDB_DATA_FILE   ((uint8_t) 0x02)

/**
 * Status types.
 */
typedef enum
{
    GDB_SUCCESS,    /**< Success.         */
    GDB_DUPLICATE,  /**< Duplicate entry. */
    GDB_ERROR       /**< Error.           */

} GdbStatus;

#include "pcre.h"

#include "db_types.h"
#include "db_blocks.h"
#include "btree.h"

#include "raw_data.h"
#include "keyvalue.h"
#include "cmutex.h"
#include "cmap.h"

/**
 * GNUpdate database.
 */

#define GDB_CRWLOCK_SWITCH (SWITCH_ON)

struct _GDatabase
{
    PmAccessMode mode;      /**< Access mode.                    */

    uint8_t *filename;      /**< Filename of the database.       */
    RawFile *idxRawFile;             /**< Active file pointer.            */

    RawFile *datRawFile;       /*< store raw data                   */

    uint8_t type;           /**< Database type.                  */

    word_t table_id;
    word_t cdfs_md_id;

    uint32_t freeBlockCount;/**< Number of free blocks.          */

    BTree *mainTree;        /**< Main B+Tree.                    */
    //void *mainTree;

    uint32_t openBlockCount;     /**< Number of open blocks.          */
    uint32_t openBlockSize;      /**< Size of the open blocks array.  */
    GdbBlock **openBlocks;       /**< Open blocks array.              */

#if (SWITCH_ON == GDB_CRWLOCK_SWITCH)
    CRWLOCK crwlock;
#endif/*(SWITCH_ON == GDB_CRWLOCK_SWITCH)*/

#if (SWITCH_OFF == GDB_CRWLOCK_SWITCH)
    CMUTEX   cmutex;
#endif/*(SWITCH_OFF == GDB_CRWLOCK_SWITCH)*/
};

#if (SWITCH_ON == GDB_CRWLOCK_SWITCH)
#define GDB_CRWLOCK(gdb)                    (&((gdb)->crwlock))
#define GDB_CRWLOCK_INIT(gdb, location)     (crwlock_init(GDB_CRWLOCK(gdb), CMUTEX_PROCESS_PRIVATE, location))
#define GDB_CRWLOCK_CLEAN(gdb, location)    (crwlock_clean(GDB_CRWLOCK(gdb), location))
#define GDB_CRWLOCK_RDLOCK(gdb, location)   (crwlock_rdlock(GDB_CRWLOCK(gdb), location))
#define GDB_CRWLOCK_WRLOCK(gdb, location)   (crwlock_wrlock(GDB_CRWLOCK(gdb), location))
#define GDB_CRWLOCK_UNLOCK(gdb, location)   (crwlock_unlock(GDB_CRWLOCK(gdb), location))
#endif/*(SWITCH_ON == GDB_CRWLOCK_SWITCH)*/

#if (SWITCH_OFF == GDB_CRWLOCK_SWITCH)
#define GDB_CRWLOCK(gdb)                    (&((gdb)->cmutex))
#define GDB_CRWLOCK_INIT(gdb, location)     (cmutex_init(GDB_CRWLOCK(gdb), CMUTEX_PROCESS_PRIVATE, location))
#define GDB_CRWLOCK_CLEAN(gdb, location)    (cmutex_clean(GDB_CRWLOCK(gdb), location))
#define GDB_CRWLOCK_RDLOCK(gdb, location)   (cmutex_lock(GDB_CRWLOCK(gdb), location))
#define GDB_CRWLOCK_WRLOCK(gdb, location)   (cmutex_lock(GDB_CRWLOCK(gdb), location))
#define GDB_CRWLOCK_UNLOCK(gdb, location)   (cmutex_unlock(GDB_CRWLOCK(gdb), location))
#endif/*(SWITCH_OFF == GDB_CRWLOCK_SWITCH)*/

int gdbIdxfd(const GDatabase *db);
int gdbDatfd(const GDatabase *db);
word_t gdbTableId(const GDatabase *db);

/**
 * Opens a database from a file.
 *
 * If the file does not exist, it will be created through a call to
 * gdbCreate().
 *
 * If a type is specified that does not match the type of database, this
 * will return NULL.
 *
 * @param filename The name of the database file.
 * @param type     The type of database to open.
 * @param mode     The access mode.
 *
 * @return A GDatabase structure.
 */
GDatabase *gdbOpen(const uint8_t *root_path, const word_t table_id, const word_t cdfs_md_id, const int flags);

GDatabase *gdbMake(const uint8_t *root_path, const word_t table_id, const word_t cdfs_md_id, const int idx_fd, const int dat_fd);

/**
 * Closes a database.
 *
 * @param db The database to close.
 */
void gdbClean(GDatabase *db);
void gdbReset(GDatabase *db);
void gdbClose(GDatabase *db);

void gdbUnMake(GDatabase *db);

/**
 * Creates a database.
 *
 * gdbOpen() automatically calls this if the specified file does not
 * exist. Calling this instead of gdbOpen() will overwrite an existing
 * file.
 *
 * @param filename The name of the file to store the database in.
 * @param type     The type of database to create.
 *
 * @return A GDatabase structure.
 */
GDatabase *gdbCreate(const uint8_t *root_path, const word_t table_id, const word_t cdfs_md_id);

/**
 * Destroys a GDatabase structure in memory.
 *
 * Calling gdbClose() will automatically call this to free up the
 * memory for the database.
 *
 * @param db The database structure to destroy.
 *
 * @return NULL
 */
GDatabase *gdbDestroy(GDatabase *db);

GdbStatus  gdbFlush(GDatabase *db);

GdbStatus gdbUnlink(const uint8_t *root_path, const word_t table_id);

GdbStatus  gdbSplit(const GDatabase *db, GDatabase *db_left, GDatabase *db_right);

uint8_t gdbIsEmpty(const GDatabase *db);


/**
 * Adds an internal B+Tree with the specified key.
 *
 * @param db      The active database.
 * @param tree    The tree to add to.
 * @param key     The key to associate with.
 * @param newTree The resulting tree.
 *
 * @return The status of the operation.
 */
GdbStatus gdbAddTree(GDatabase *db, BTree *tree, const uint8_t *key,
                     BTree **newTree);

GdbStatus gdbInsertKeyValue(GDatabase *db, const KeyValue *keyValue, const uint8_t replaceDup);

GdbStatus gdbInsertKV(GDatabase *db, const uint8_t *kv, const uint8_t replaceDup);

GdbStatus gdbDeleteKey(GDatabase *db, const uint8_t *key, int(* keyCompare)(const uint8_t *, const uint8_t *), offset_t *offset);

GdbStatus gdbDeleteVal(GDatabase *db, offset_t offset);

GdbStatus gdbScanKey(const GDatabase *db, const uint8_t *key, int(* keyCompare)(const uint8_t *, const uint8_t *), offset_t *offset);

GdbStatus gdbSearchKey(const GDatabase *db, const uint8_t *key, int(* keyCompare)(const uint8_t *, const uint8_t *), offset_t *offset);

GdbStatus gdbFetchKey(const GDatabase *db, const offset_t offset, uint8_t **key, uint16_t *klen);

GdbStatus gdbFetchValue(const GDatabase *db, const offset_t offset, uint8_t **value, uint32_t *vlen);

GdbStatus gdbFetchKV(const GDatabase *db, const offset_t offset, uint8_t **kv, uint32_t *kv_len);

GdbStatus gdbUpdateValue(GDatabase *db, const offset_t offset, const uint8_t *value, const uint32_t vlen);

GdbStatus gdbCompact(const GDatabase *db_src, GDatabase *db_des);

GdbStatus gdbRunthrough(LOG *log, const GDatabase *db, void (*runthrough)(LOG *log, const offset_t , GDatabase *));

GdbStatus gdbTraversal(LOG *log, const GDatabase *db, void (*keyPrinter)(LOG *, const uint8_t *));

GdbStatus gdbFetchFirstKey(const GDatabase *db, uint8_t  **key, uint16_t *klen);

GdbStatus gdbFetchFirstKV(const GDatabase *db, uint8_t  **kv, uint32_t *kv_len);

GdbStatus gdbFetchLastKey(const GDatabase *db, uint8_t  **key, uint16_t *klen);

GdbStatus gdbFetchLastKV(const GDatabase *db, uint8_t  **kv, uint32_t *kv_len);

GdbStatus gdbCollectAllOffset(const GDatabase *db, offset_t **offset_list, uint32_t *offset_num);

GdbStatus gdbKeyRegexScanKV(const GDatabase *db, int (*key_regex)(const uint8_t *, pcre *, pcre *, pcre *), pcre *row_re, pcre *colf_re, pcre *colq_re, CVECTOR *kv_vec);

GdbStatus gdbKeyRegexScanKVOffset(const GDatabase *db, int (*key_regex)(const uint8_t *, pcre *, pcre *, pcre *), pcre *row_re, pcre *colf_re, pcre *colq_re, CMAP *kvoffset_map);

GdbStatus gdbKVRegexScanKV(const GDatabase *db, int (*kv_regex)(const uint8_t *, pcre *, pcre *, pcre *, pcre *), pcre *row_re, pcre *colf_re, pcre *colq_re, pcre *val_re, CVECTOR *kv_vec);

GdbStatus gdbKVRegexScanKVOffset(const GDatabase *db, int (*kv_regex)(const uint8_t *, pcre *, pcre *, pcre *, pcre *), pcre *row_re, pcre *colf_re, pcre *colq_re, pcre *val_re, CMAP *kvoffset_map);

#endif /* _GNUPDATEDB_DB_H_ */

#ifdef __cplusplus
}
#endif/*__cplusplus*/
