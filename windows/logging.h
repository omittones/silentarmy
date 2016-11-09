#pragma once

#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include "CL/opencl.h"
#include "../sha256.h"
#include "../param.h"

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

#ifdef ENABLE_DEBUG
uint32_t has_i(uint32_t round, uint8_t *ht, uint32_t row, uint32_t i,
	uint32_t mask, uint32_t *res)
{
	uint32_t	slot;
	uint8_t	*p = (uint8_t *)(ht + row * NR_SLOTS * SLOT_LEN);
	uint32_t	cnt = *(uint32_t *)p;
	cnt = MIN(cnt, NR_SLOTS);
	for (slot = 0; slot < cnt; slot++, p += SLOT_LEN)
	{
		if ((*(uint32_t *)(p + xi_offset_for_round(round) - 4) & mask) ==
			(i & mask))
		{
			if (res)
				*res = slot;
			return 1;
		}
	}
	return 0;
}

uint32_t has_xi(uint32_t round, uint8_t *ht, uint32_t row, uint32_t xi,
	uint32_t *res)
{
	uint32_t	slot;
	uint8_t	*p = (uint8_t *)(ht + row * NR_SLOTS * SLOT_LEN);
	uint32_t	cnt = *(uint32_t *)p;
	cnt = MIN(cnt, NR_SLOTS);
	for (slot = 0; slot < cnt; slot++, p += SLOT_LEN)
	{
		if ((*(uint32_t *)(p + xi_offset_for_round(round))) == (xi))
		{
			if (res)
				*res = slot;
			return 1;
		}
	}
	return 0;
}

void examine_ht(unsigned round, cl_command_queue queue, cl_mem buf_ht)
{
	uint8_t     *ht;
	uint8_t	*p;
	if (verbose < 3)
		return;
	ht = (uint8_t *)malloc(HT_SIZE);
	if (!ht)
		fatal("malloc: %s\n", strerror(errno));
	check_clEnqueueReadBuffer(queue, buf_ht,
		CL_TRUE,	// cl_bool	blocking_read
		0,		// size_t	offset
		HT_SIZE,    // size_t	size
		ht,	        // void		*ptr
		0,		// cl_uint	num_events_in_wait_list
		NULL,	// cl_event	*event_wait_list
		NULL);	// cl_event	*event
	for (unsigned row = 0; row < NR_ROWS; row++)
	{
		char show = 0;
		uint32_t star = 0;
		if (round == 0)
		{
			// i = 0x35c and 0x12d31f collide on first 20 bits
			show |= has_i(round, ht, row, 0x35c, 0xffffffffUL, &star);
			show |= has_i(round, ht, row, 0x12d31f, 0xffffffffUL, &star);
		}
		if (round == 1)
		{
			show |= has_xi(round, ht, row, 0xf0937683, &star);
			show |= (row < 256);
		}
		if (round == 2)
		{
			show |= has_xi(round, ht, row, 0x3519d2e0, &star);
			show |= (row < 256);
		}
		if (round == 3)
		{
			show |= has_xi(round, ht, row, 0xd6950b66, &star);
			show |= (row < 256);
		}
		if (round == 4)
		{
			show |= has_xi(round, ht, row, 0xa92db6ab, &star);
			show |= (row < 256);
		}
		if (round == 5)
		{
			show |= has_xi(round, ht, row, 0x2daaa343, &star);
			show |= (row < 256);
		}
		if (round == 6)
		{
			show |= has_xi(round, ht, row, 0x53b9dd5d, &star);
			show |= (row < 256);
		}
		if (round == 7)
		{
			show |= has_xi(round, ht, row, 0xb9d374fe, &star);
			show |= (row < 256);
		}
		if (round == 8)
		{
			show |= has_xi(round, ht, row, 0x005ae381, &star);
			show |= (row < 256);
		}
		if (show)
		{
			debug("row %#x:\n", row);
			uint32_t cnt = *(uint32_t *)(ht + row * NR_SLOTS * SLOT_LEN);
			cnt = MIN(cnt, NR_SLOTS);
			for (unsigned slot = 0; slot < cnt; slot++)
				if (slot < NR_SLOTS)
				{
					p = ht + row * NR_SLOTS * SLOT_LEN + slot * SLOT_LEN;
					debug("%c%02x ", (star == slot) ? '*' : ' ', slot);
					for (unsigned i = 0; i < 4; i++, p++)
						!slot ? debug("%02x", *p) : debug("__");
					uint64_t val[3] = { 0, };
					for (unsigned i = 0; i < 28; i++, p++)
					{
						if (i == round / 2 * 4 + 4)
						{
							val[0] = *(uint64_t *)(p + 0);
							val[1] = *(uint64_t *)(p + 8);
							val[2] = *(uint64_t *)(p + 16);
							debug(" | ");
						}
						else if (!(i % 4))
							debug(" ");
						debug("%02x", *p);
					}
					val[0] = (val[0] >> 4) | (val[1] << (64 - 4));
					val[1] = (val[1] >> 4) | (val[2] << (64 - 4));
					val[2] = (val[2] >> 4);
					debug("\n");
				}
		}
	}
	free(ht);
}
#else
inline void examine_ht(unsigned round, cl_command_queue queue, cl_mem buf_ht)
{
	(void)round;
	(void)queue;
	(void)buf_ht;
}
#endif

void examine_dbg(cl_command_queue queue, cl_mem buf_dbg, size_t dbg_size);

void store_encoded_sol(uint8_t *out, uint32_t *inputs, uint32_t n);

void print_encoded_sol(uint32_t *inputs, uint32_t n);

void print_sol(uint32_t *values, uint64_t *nonce);

int32_t cmp_target_256(void *_a, void *_b);

int sol_cmp(const void *_a, const void *_b);

uint32_t print_solver_line(uint32_t *values, uint8_t *header, size_t fixed_nonce_bytes, uint8_t *target, char *job_id);

uint32_t print_sols(sols_t *all_sols, uint64_t *nonce, uint32_t nr_valid_sols, uint8_t *header, size_t fixed_nonce_bytes, 
	uint8_t *target, char *job_id);