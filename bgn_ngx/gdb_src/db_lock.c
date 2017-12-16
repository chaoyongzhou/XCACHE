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

#include "db_internal.h"

uint8_t
gdbInitlockFreeBlockList(GDatabase *db, const word_t location)
{
    GDB_CRWLOCK_INIT(db, location);
    return 1;
}

uint8_t
gdbLockFreeBlockList(GDatabase *db, GdbLockType type, const word_t location)
{
    if (db == NULL)
    {
        return 0;
    }
    if (type == DB_UNLOCKED)
    {
        return gdbUnlockFreeBlockList(db, location);
    }

    if(type == DB_WRITE_LOCK)
    {
        GDB_CRWLOCK_WRLOCK(db, location);
        return 1;
    }

    if(type == DB_READ_LOCK)
    {
        GDB_CRWLOCK_RDLOCK(db, location);
        return 1;
    }
    return 0;
}

uint8_t
gdbUnlockFreeBlockList(GDatabase *db, const word_t location)
{
    GDB_CRWLOCK_UNLOCK(db, location);
    return 1;
}

GdbLockType
gdbGetFreeBlockListLock(GDatabase *db, const word_t location)
{
    return DB_UNLOCKED;
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

