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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>

#include <sys/time.h>
#include <signal.h>

#include "type.h"
#include "log.h"

#include "ccoredumper.h"

/* Writes the core file to disk. This is a convenience method wrapping
 * GetCoreDump(). If a core file could not be generated for any reason,
 * -1 is returned and errno is set appropriately. On success, zero is
 * returned.
 */
EC_BOOL ccoredumper_write(const char *file_name)
{
    if(0 != WriteCoreDump(file_name))
    {
        dbg_log(SEC_0107_CCOREDUMPER, 0)(LOGSTDOUT, "error:ccoredumper_write:failed to dump core to file %s\n", file_name);
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

/* Writes a core dump to the given file with the given parameters.           */
EC_BOOL ccoredumper_write_with(const struct CoreDumpParameters *params,const char *file_name)
{
    if(0 != WriteCoreDumpWith(params, file_name))
    {
        dbg_log(SEC_0107_CCOREDUMPER, 0)(LOGSTDOUT, "error:ccoredumper_write_with:failed to dump core to file %s\n", file_name);
        return (EC_FALSE);
    }
    return (EC_TRUE);
}


/* Callers might need to restrict the maximum size of the core file. This
 * convenience method provides the necessary support to emulate "ulimit -c".
 */
EC_BOOL ccoredumper_write_limited(const char *file_name, size_t max_length)
{
    if(0 != WriteCoreDumpLimited(file_name, max_length))
    {
        dbg_log(SEC_0107_CCOREDUMPER, 0)(LOGSTDOUT, "error:ccoredumper_write_limited:failed to dump core to file %s with max length %ld\n", file_name, max_length);
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

/* Writes a limited size core file, however instead of truncating the file at
 * the limit, the core dumper will prioritize smaller memory segments. This
 * means that a large heap will most likely either be only partially included
 * or not included at all. If the max_length is set too small, this could cause
 * performance issues.
 */
EC_BOOL ccoredumper_write_limited_by_priority(const char *file_name, size_t max_length)
{
    if(0 != WriteCoreDumpLimitedByPriority(file_name, max_length))
    {
        dbg_log(SEC_0107_CCOREDUMPER, 0)(LOGSTDOUT, "error:ccoredumper_write_limited_by_priority:failed to dump core to file %s with max length %ld\n", file_name, max_length);
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

/* Attempts to compress the core file on the fly, if a suitable compressor
 * could be located. Sets "selected_compressor" to the compressor that
 * was picked. The filename automatically has a suitable suffix appended
 * to it. Normally this would be ".bz2" for bzip2 compression ".gz" for
 * gzip compression, or ".Z" for compress compression. This behavior can
 * be changed by defining custom CoredumperCompressor descriptions.
 */
EC_BOOL ccoredumper_write_compressed(const char *file_name, size_t max_length, const struct CoredumperCompressor *compressors, struct CoredumperCompressor **selected_compressor)
{
    if(0 != WriteCompressedCoreDump(file_name, max_length, compressors, selected_compressor))
    {
        dbg_log(SEC_0107_CCOREDUMPER, 0)(LOGSTDOUT, "error:ccoredumper_write_compressed:failed to dump core to file %s with max length %ld\n", file_name, max_length);
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/
