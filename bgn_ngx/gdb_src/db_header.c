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

STATIC_CAST static int __safe_strncmp(const uint8_t *str_1st, const uint8_t *str_2nd, size_t n, const word_t location)
{
    return memcmp(str_1st, str_2nd, n);
}

uint8_t
gdbReadHeader(GDatabase *db)
{
    uint8_t  version[2];
    uint8_t  buffer[DB_HEADER_DATA_SIZE];
    uint32_t counter;

    if (db == NULL || db->idxRawFile == NULL)
    {
        return 0;
    }

    rawFileSeek(db->idxRawFile, 0, SEEK_SET);
    if (rawFileRead(db->idxRawFile, 0, buffer, DB_HEADER_DATA_SIZE, 1, LOC_DB_0074) != 1)
    {
        dbg_log(SEC_0131_DB, 0)(LOGSTDOUT, "error:gdbReadHeader: Truncated database.\n");
        return 0;
    }

    if(0)/*debug*/
    {
        int idx;
        dbg_log(SEC_0131_DB, 9)(LOGSTDOUT, "[DEBUG]gdbReadHeader: header: ");
        for(idx = 0; idx < DB_HEADER_DATA_SIZE; idx ++)
        {
            dbg_log(SEC_0131_DB, 5)(LOGSTDOUT, "%02x ", *(buffer + idx));
        }
        dbg_log(SEC_0131_DB, 5)(LOGSTDOUT, "\n");
    }

    /* Check the magic string. */
    if (0 != __safe_strncmp(buffer + DB_OFFSET_MAGIC, (const uint8_t *)DB_MAGIC, 8, LOC_DB_0075))
    {
        dbg_log(SEC_0131_DB, 0)(LOGSTDOUT, "error:gdbReadHeader: Invalid database signature.\n");
        return 0;
    }

    counter = 8;

    version[0] = gdbGet8(buffer, &counter);
    version[1] = gdbGet8(buffer, &counter);

    if (version[0] != DB_MAJOR_VER || version[1] != DB_MINOR_VER)
    {
        dbg_log(SEC_0131_DB, 0)(LOGSTDOUT, "error:gdbReadHeader: Unsupported database version %d.%d\n",
                            version[0], version[1]);

        return 0;
    }

    db->type = gdbGet8(buffer, &counter);

    if (GDB_INDEX_FILE != db->type && GDB_DATA_FILE != db->type)
    {
        dbg_log(SEC_0131_DB, 0)(LOGSTDOUT, "error:gdbReadHeader: Unsupported database type.\n");

        return 0;
    }

    return 1;
}

void
gdbWriteHeader(GDatabase *db)
{
    uint8_t version[2];
    uint8_t type;
    offset_t offset;

    if (db == NULL || db->idxRawFile == NULL)
    {
        return;
    }

    version[0] = DB_MAJOR_VER;
    version[1] = DB_MINOR_VER;

    type = db->type;

    rawFileSeek(db->idxRawFile, 0, SEEK_SET);
    offset = 0;

    /* Write the magic string. */

    rawFilePuts(db->idxRawFile, offset, DB_MAGIC);
    offset += strlen(DB_MAGIC);

    rawFileWrite(db->idxRawFile, offset, version, sizeof(uint8_t), 2, LOC_DB_0076);
    offset += (sizeof(uint8_t) * 2);

    rawFileWrite(db->idxRawFile, offset, &type,   sizeof(uint8_t), 1, LOC_DB_0077);
    offset += sizeof(uint8_t);

    if (DB_HEADER_BLOCK_SIZE > DB_HEADER_DATA_SIZE)
    {
        gdbPad(db->idxRawFile, offset, DB_HEADER_BLOCK_SIZE - DB_HEADER_DATA_SIZE);
    }
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

