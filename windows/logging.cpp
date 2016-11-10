#include "../param.h"
#include "logging.h"
#include "../clErrors.h"
#include <assert.h>
#include <string.h>
#include <inttypes.h>

uint16_t verbose = 0;

/*
** Write ZCASH_SOL_LEN bytes representing the encoded solution as per the
** Zcash protocol specs (512 x 21-bit inputs).
**
** out		ZCASH_SOL_LEN-byte buffer where the solution will be stored
** inputs	array of 32-bit inputs
** n		number of elements in array
*/
void store_encoded_sol(uint8_t *out, uint32_t *inputs, uint32_t n)
{
	uint32_t byte_pos = 0;
	int32_t bits_left = PREFIX + 1;
	uint8_t x = 0;
	uint8_t x_bits_used = 0;
	while (byte_pos < n)
	{
		if (bits_left >= 8 - x_bits_used)
		{
			x |= inputs[byte_pos] >> (bits_left - 8 + x_bits_used);
			bits_left -= 8 - x_bits_used;
			x_bits_used = 8;
		}
		else if (bits_left > 0)
		{
			uint32_t mask = ~(-1 << (8 - x_bits_used));
			mask = ((~mask) >> bits_left) & mask;
			x |= (inputs[byte_pos] << (8 - x_bits_used - bits_left)) & mask;
			x_bits_used += bits_left;
			bits_left = 0;
		}
		else if (bits_left <= 0)
		{
			assert(!bits_left);
			byte_pos++;
			bits_left = PREFIX + 1;
		}
		if (x_bits_used == 8)
		{
			*out++ = x;
			x = x_bits_used = 0;
		}
	}
}

/*
** Print on stdout a hex representation of the encoded solution as per the
** zcash protocol specs (512 x 21-bit inputs).
**
** inputs	array of 32-bit inputs
** n		number of elements in array
*/
void print_encoded_sol(uint32_t *inputs, uint32_t n)
{
	uint8_t	sol[ZCASH_SOL_LEN];
	uint32_t	i;
	store_encoded_sol(sol, inputs, n);
	for (i = 0; i < sizeof(sol); i++)
		printf("%02x", sol[i]);
	printf("\n");
	fflush(stdout);
}

void print_sol(uint32_t *values, uint64_t *nonce)
{
	uint32_t	show_n_sols;
	show_n_sols = (1 << PARAM_K);
	if (verbose < 2)
		show_n_sols = min(10, show_n_sols);
	fprintf(stderr, "Soln:");
	// for brievity, only print "small" nonces
	if (*nonce < (1ULL << 32))
		fprintf(stderr, " 0x%" PRIx64 ":", *nonce);
	for (unsigned i = 0; i < show_n_sols; i++)
		fprintf(stderr, " %x", values[i]);
	fprintf(stderr, "%s\n", (show_n_sols != (1 << PARAM_K) ? "..." : ""));
}

/*
** Compare two 256-bit values interpreted as little-endian 256-bit integers.
*/
int32_t cmp_target_256(void *_a, void *_b)
{
	uint8_t	*a = reinterpret_cast<uint8_t*>(_a);
	uint8_t	*b = reinterpret_cast<uint8_t*>(_b);
	int32_t	i;
	for (i = SHA256_TARGET_LEN - 1; i >= 0; i--)
		if (a[i] != b[i])
			return (int32_t)a[i] - b[i];
	return 0;
}

int sol_cmp(const void *_a, const void *_b)
{
	const uint32_t	*a = reinterpret_cast<const uint32_t*>(_a);
	const uint32_t	*b = reinterpret_cast<const uint32_t*>(_b);

	for (uint32_t i = 0; i < (1 << PARAM_K); i++)
	{
		if (*a != *b)
			return *a - *b;
		a++;
		b++;
	}
	return 0;
}

/*
** Verify if the solution's block hash is under the target, and if yes print
** it formatted as:
** "sol: <job_id> <ntime> <nonce_rightpart> <solSize+sol>"
**
** Return 1 iff the block hash is under the target.
*/
uint32_t print_solver_line(uint32_t *values, uint8_t *header,
	size_t fixed_nonce_bytes, uint8_t *target, char *job_id)
{
	uint8_t	buffer[ZCASH_BLOCK_HEADER_LEN + ZCASH_SOLSIZE_LEN +
		ZCASH_SOL_LEN];
	uint8_t	hash0[SHA256_DIGEST_SIZE];
	uint8_t	hash1[SHA256_DIGEST_SIZE];
	uint8_t	*p;
	p = buffer;
	memcpy(p, header, ZCASH_BLOCK_HEADER_LEN);
	p += ZCASH_BLOCK_HEADER_LEN;
	memcpy(p, "\xfd\x40\x05", ZCASH_SOLSIZE_LEN);
	p += ZCASH_SOLSIZE_LEN;
	store_encoded_sol(p, values, 1 << PARAM_K);
	Sha256_Onestep(buffer, sizeof(buffer), hash0);
	Sha256_Onestep(hash0, sizeof(hash0), hash1);
	// compare the double SHA256 hash with the target
	if (cmp_target_256(target, hash1) < 0)
	{
		debug("Hash is above target\n");
		return 0;
	}
	debug("Hash is under target\n");
	printf("sol: %s ", job_id);
	p = header + ZCASH_BLOCK_OFFSET_NTIME;
	printf("%02x%02x%02x%02x ", p[0], p[1], p[2], p[3]);
	printf("%s ", s_hexdump(header + ZCASH_BLOCK_HEADER_LEN - ZCASH_NONCE_LEN +
		fixed_nonce_bytes, ZCASH_NONCE_LEN - fixed_nonce_bytes));
	printf("%s%s\n", ZCASH_SOLSIZE_HEX,
		s_hexdump(buffer + ZCASH_BLOCK_HEADER_LEN + ZCASH_SOLSIZE_LEN,
			ZCASH_SOL_LEN));
	fflush(stdout);
	return 1;
}

/*
** Print all solutions.
**
** In mining mode, return the number of shares, that is the number of solutions
** that were under the target.
*/
uint32_t print_sols(sols_t *all_sols, uint64_t *nonce, uint32_t nr_valid_sols,
	uint8_t *header, size_t fixed_nonce_bytes, uint8_t *target,
	char *job_id)
{
	uint8_t		*valid_sols;
	uint32_t		counted;
	uint32_t		shares = 0;
	valid_sols = (uint8_t*)malloc(nr_valid_sols * SOL_SIZE);
	if (!valid_sols)
		fatal("malloc: %s\n", strerror(errno));
	counted = 0;
	for (uint32_t i = 0; i < all_sols->nr; i++)
		if (all_sols->valid[i])
		{
			if (counted >= nr_valid_sols)
				fatal("Bug: more than %d solutions\n", nr_valid_sols);
			memcpy(valid_sols + counted * SOL_SIZE, all_sols->values[i],
				SOL_SIZE);
			counted++;
		}
	assert(counted == nr_valid_sols);
	// sort the solutions amongst each other, to make the solver's output
	// deterministic and testable
	qsort(valid_sols, nr_valid_sols, SOL_SIZE, sol_cmp);
	for (uint32_t i = 0; i < nr_valid_sols; i++)
	{
		uint32_t	*inputs = (uint32_t *)(valid_sols + i * SOL_SIZE);

		//print_encoded_sol(inputs, 1 << PARAM_K);
		if (verbose)
			print_sol(inputs, nonce);
		/*
		if (mining)
			shares += print_solver_line(inputs, header, fixed_nonce_bytes, target, job_id);
		*/
	}
	free(valid_sols);
	return shares;
}

#ifdef _DEBUG

uint32_t has_i(uint32_t round, uint8_t *ht, uint32_t row, uint32_t i,
	uint32_t mask, uint32_t *res)
{
	uint32_t	slot;
	uint8_t	*p = (uint8_t *)(ht + row * NR_SLOTS * SLOT_LEN);
	uint32_t	cnt = *(uint32_t *)p;
	cnt = min(cnt, NR_SLOTS);
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
	cnt = min(cnt, NR_SLOTS);
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

void examine_dbg(cl_command_queue queue, cl_mem buf_dbg, size_t dbg_size)
{
	debug_t     *dbg;
	size_t      dropped_coll_total, dropped_stor_total;
	if (verbose < 2)
		return;
	dbg = (debug_t *)malloc(dbg_size);
	if (!dbg)
		fatal("malloc: %s\n", strerror(errno));
	auto status = clEnqueueReadBuffer(queue, buf_dbg,
		CL_TRUE,	// cl_bool	blocking_read
		0,		// size_t	offset
		dbg_size,   // size_t	size
		dbg,	// void		*ptr
		0,		// cl_uint	num_events_in_wait_list
		NULL,	// cl_event	*event_wait_list
		NULL);	// cl_event	*event
	if (status != CL_SUCCESS) {
		fatal("examine_dbg failed! (%d)", status);
	}

	dropped_coll_total = dropped_stor_total = 0;
	for (unsigned tid = 0; tid < dbg_size / sizeof(*dbg); tid++)
	{
		dropped_coll_total += dbg[tid].dropped_coll;
		dropped_stor_total += dbg[tid].dropped_stor;
		if (0 && (dbg[tid].dropped_coll || dbg[tid].dropped_stor))
			debug("thread %6d: dropped_coll %zd dropped_stor %zd\n", tid,
				dbg[tid].dropped_coll, dbg[tid].dropped_stor);
	}
	debug("Dropped: %zd (coll) %zd (stor)\n",
		dropped_coll_total, dropped_stor_total);
	free(dbg);
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
	auto status = clEnqueueReadBuffer(queue, buf_ht,
		CL_TRUE,	// cl_bool	blocking_read
		0,		// size_t	offset
		HT_SIZE,    // size_t	size
		ht,	        // void		*ptr
		0,		// cl_uint	num_events_in_wait_list
		NULL,	// cl_event	*event_wait_list
		NULL);	// cl_event	*event
	if (status != CL_SUCCESS)
		fatal("Failed to examine ht (%s)", clGetErrorString(status));

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
			cnt = min(cnt, NR_SLOTS);
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
#endif