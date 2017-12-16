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


#ifndef _GNUPDATEDB_HEADER_H_
#define _GNUPDATEDB_HEADER_H_

#define DB_HEADER_DATA_SIZE   11 /**< Header data size.       */
#define DB_HEADER_BLOCK_SIZE  16 /**< Header block size.      */

#define DB_MAGIC     "\1GDBDBF\2" /**< Database magic string.  */
#define DB_MAJOR_VER            0 /**< Database major version. */
#define DB_MINOR_VER            2 /**< Database minor version. */

/** @name Database header offsets */
/*@{*/
#define DB_OFFSET_MAGIC             0 /**< Offset of the magic string.      */
#define DB_OFFSET_VERSION           8 /**< Offset of the version.           */
#define DB_OFFSET_TYPE             10 /**< Offset of the database type.     */
/*@}*/

/**
 * Offset of the main tree.
 *
 * The main tree resides right after the main header block.
 */
#define DB_MAIN_TREE_OFFSET (DB_HEADER_BLOCK_SIZE + DB_FREE_BLOCK_LIST_SIZE)

/**
 * Utility macro that determines if the specified offset is valid.
 *
 * @param offset The offset to validate.
 */
#define GDB_VALID_OFFSET(offset) ((offset) >= DB_FREE_BLOCK_LIST_OFFSET)

/**
 * Reads in the database header from the file.
 *
 * @param db The database to read the header of.
 *
 * @return 1 if successful; 0 otherwise.
 */
uint8_t gdbReadHeader(GDatabase *db);

/**
 * Writes the database header to the file.
 *
 * @param db The database to write the header of.
 */
void gdbWriteHeader(GDatabase *db);

#endif /* _GNUPDATEDB_HEADER_H_ */

#ifdef __cplusplus
}
#endif/*__cplusplus*/
