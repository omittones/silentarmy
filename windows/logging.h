#pragma once

#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include "CL/opencl.h"
#include "../sha256.h"
#include "../param.h"

#define min(a,b) ((a)<(b)?(a):(b))

void exit(int);

extern uint16_t verbose;

typedef struct  debug_s
{
	uint32_t    dropped_coll;
	uint32_t    dropped_stor;
}               debug_t;

inline void debug(const char *fmt, ...)
{
	va_list     ap;
	if (!verbose)
		return;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}


inline void warn(const char *fmt, ...)
{
	va_list     ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

inline void fatal(const char *fmt, ...)
{
	va_list     ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	exit(1);
}

inline void hexdump(uint8_t *a, uint32_t a_len)
{
	for (uint32_t i = 0; i < a_len; i++)
		fprintf(stderr, "%02x", a[i]);
}

inline char *s_hexdump(const void *_a, uint32_t a_len)
{
	const uint8_t	*a = reinterpret_cast<const uint8_t*>(_a);
	static char		buf[4096];
	uint32_t		i;
	for (i = 0; i < a_len && i + 2 < sizeof(buf); i++)
		sprintf(buf + i * 2, "%02x", a[i]);
	buf[i * 2] = 0;
	return buf;
}

void examine_ht(unsigned round, cl_command_queue queue, cl_mem buf_ht);

void examine_dbg(cl_command_queue queue, cl_mem buf_dbg, size_t dbg_size);

void store_encoded_sol(uint8_t *out, uint32_t *inputs, uint32_t n);

void print_encoded_sol(uint32_t *inputs, uint32_t n);

void print_sol(uint32_t *values, uint64_t *nonce);

int32_t cmp_target_256(void *_a, void *_b);

int sol_cmp(const void *_a, const void *_b);

uint32_t print_solver_line(uint32_t *values, uint8_t *header, size_t fixed_nonce_bytes, uint8_t *target, char *job_id);

uint32_t print_sols(sols_t *all_sols, uint64_t *nonce, uint32_t nr_valid_sols, uint8_t *header, size_t fixed_nonce_bytes, 
	uint8_t *target, char *job_id);