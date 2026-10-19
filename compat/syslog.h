#ifndef VSCP_COMPAT_SYSLOG_H
#define VSCP_COMPAT_SYSLOG_H

#include <stdarg.h>
#include <stdio.h>

#define LOG_ERR 3
#define LOG_DEBUG 7

static inline void
syslog(int priority, const char* format, ...)
{
    (void)priority;

    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    fputc('\n', stderr);
    va_end(args);
}

#endif
