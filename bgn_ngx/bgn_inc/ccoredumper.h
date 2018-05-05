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

#ifndef _CCOREDUMPER_H
#define _CCOREDUMPER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>

#include <sys/time.h>
#include <signal.h>

#include "type.h"
#include "log.h"

#define WriteCoreDump(file_name)                                                         (-1)
#define WriteCoreDumpWith(params, file_name)                                             (-1)
#define WriteCoreDumpLimited(file_name, max_length)                                      (-1)
#define WriteCoreDumpLimitedByPriority(file_name, max_length)                            (-1)
#define WriteCompressedCoreDump(file_name, max_length, compressors, selected_compressor) (-1)

struct CoreDumpParameters
{
    void  *ptr;
};

struct CoredumperCompressor
{
    void *ptr;
};


/* Writes the core file to disk. This is a convenience method wrapping
 * GetCoreDump(). If a core file could not be generated for any reason,
 * EC_FALSE is returned and errno is set appropriately. On success, EC_TRUE is
 * returned.
 */
EC_BOOL ccoredumper_write(const char *file_name);

/* Writes a core dump to the given file with the given parameters.           */
EC_BOOL ccoredumper_write_with(const struct CoreDumpParameters *params,const char *file_name);


/* Callers might need to restrict the maximum size of the core file. This
 * convenience method provides the necessary support to emulate "ulimit -c".
 */
EC_BOOL ccoredumper_write_limited(const char *file_name, size_t max_length);

/* Writes a limited size core file, however instead of truncating the file at
 * the limit, the core dumper will prioritize smaller memory segments. This
 * means that a large heap will most likely either be only partially included
 * or not included at all. If the max_length is set too small, this could cause
 * performance issues.
 */
EC_BOOL ccoredumper_write_limited_by_priority(const char *file_name, size_t max_length);

/* Attempts to compress the core file on the fly, if a suitable compressor
 * could be located. Sets "selected_compressor" to the compressor that
 * was picked. The filename automatically has a suitable suffix appended
 * to it. Normally this would be ".bz2" for bzip2 compression ".gz" for
 * gzip compression, or ".Z" for compress compression. This behavior can
 * be changed by defining custom CoredumperCompressor descriptions.
 */
EC_BOOL ccoredumper_write_compressed(const char *file_name, size_t max_length, const struct CoredumperCompressor *compressors, struct CoredumperCompressor **selected_compressor);


#endif/* _CCOREDUMPER_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/
