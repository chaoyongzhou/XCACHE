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


#ifndef _DB_LOCK_H_
#define _DB_LOCK_H_

/**
 * Types of locks.
 */
typedef enum
{
    /** Node is unlocked. Used for IsLocked() functions. */
    DB_UNLOCKED = 0x00,

    /** Lock for writing. Nobody else can read or write. */
    DB_WRITE_LOCK = 0x01,

    /** Lock for reading. Nobody else can write. */
    DB_READ_LOCK = 0x02

} GdbLockType;

#include "db.h"


uint8_t gdbInitlockFreeBlockList(GDatabase *db, const word_t location);

/**
 * Locks the free block list.
 *
 * If the free block list is already locked, this will wait until it is
 * unlocked before locking and returning.
 *
 * @param db   The active database.
 * @param type The type of lock.
 *
 * @return 1 on success, 0 on failure.
 */
uint8_t gdbLockFreeBlockList(GDatabase *db, GdbLockType type, const word_t location);

/**
 * Unlocks the free block list.
 *
 * @param db The active database.
 *
 * @return 1 on success, 0 on failure.
 */
uint8_t gdbUnlockFreeBlockList(GDatabase *db, const word_t location);

/**
 * Returns the current lock on the free block list.
 *
 * @param db The active database.
 *
 * @return The current lock on the free blocks list (or DB_UNLOCKED if none.)
 */
GdbLockType gdbGetFreeBlockListLock(GDatabase *db, const word_t location);

#endif /* _DB_LOCK_H_ */

#ifdef __cplusplus
}
#endif/*__cplusplus*/
