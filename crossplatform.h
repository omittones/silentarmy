#pragma once

#ifdef WIN32

#undef _UNICODE // @mrb quick patch to make win getopt work

#include <Winsock2.h>
#include <io.h>
#include <BaseTsd.h>
#include "gettimeofday.h"
#include "getopt.h"

#define _GNU_SOURCE	1/* memrchr */
#include "memrchr.h"

typedef SSIZE_T ssize_t;

#define open _open
#define read _read
#define write _write
#define close _close

#else

#include <sys/time.h>
#include <unistd.h>
#include <getopt.h>
#include "_kernel.h"

#endif