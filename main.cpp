#include "windows\crossplatform.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <assert.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "windows\logging.h"

#include <errno.h>
#include <CL/cl.h>

#define _CC
#include "blake.hpp"
#undef _CC

#include "sha256.h"
#include "solver.h"

typedef uint8_t		uchar;
typedef uint32_t	uint;
#include "param.h"

#define MIN(A, B)	(((A) < (B)) ? (A) : (B))
#define MAX(A, B)	(((A) > (B)) ? (A) : (B))

bool             verbose = 0;
uint32_t	show_encoded = 0;
uint64_t	nr_nonces = 1;
uint32_t	do_list_devices = 0;
uint32_t	gpu_to_use = 0;
uint32_t	mining = 0;

uint64_t parse_num(char *str)
{
	char	*endptr;
	uint64_t	n;
	n = strtoul(str, &endptr, 0);
	if (endptr == str || *endptr)
		fatal("'%s' is not a valid number\n", str);
	return n;
}

uint64_t now(void)
{
	struct timeval	tv;
	gettimeofday(&tv, NULL);
	return (uint64_t)tv.tv_sec * 1000 * 1000 + tv.tv_usec;
}

void show_time(uint64_t t0)
{
	uint64_t            t1;
	t1 = now();
	fprintf(stderr, "Elapsed time: %.1f msec\n", (t1 - t0) / 1e3);
}

#ifndef WIN32
void set_blocking_mode(int fd, int block)
{

	int	f;
	if (-1 == (f = fcntl(fd, F_GETFL)))
		fatal("fcntl F_GETFL: %s\n", strerror(errno));
	if (-1 == fcntl(fd, F_SETFL, block ? (f & ~O_NONBLOCK) : (f | O_NONBLOCK)))
		fatal("fcntl F_SETFL: %s\n", strerror(errno));
}
#endif

void randomize(void *p, ssize_t l)
{
#ifndef WIN32
	const char	*fname = "/dev/urandom";
	int		fd;
	ssize_t	ret;
	if (-1 == (fd = open(fname, O_RDONLY)))
		fatal("open %s: %s\n", fname, strerror(errno));
	if (-1 == (ret = read(fd, p, l)))
		fatal("read %s: %s\n", fname, strerror(errno));
	if (ret != l)
		fatal("%s: short read %d bytes out of %d\n", fname, ret, l);
	if (-1 == close(fd))
		fatal("close %s: %s\n", fname, strerror(errno));
#else
	for (int i = 0; i < l; i++)
		((uint8_t *)p)[i] = rand() & 0xff;
#endif
}

uint8_t hex2val(const char *base, size_t off)
{
	const char          c = base[off];
	if (c >= '0' && c <= '9')           return c - '0';
	else if (c >= 'a' && c <= 'f')      return 10 + c - 'a';
	else if (c >= 'A' && c <= 'F')      return 10 + c - 'A';
	fatal("Invalid hex char at offset %d: ...%d...\n", off, c);
	return 0;
}

void dump(const char *fname, void *data, size_t len)
{
	int			fd;
	ssize_t		ret;
	if (-1 == (fd = open(fname, O_WRONLY | O_CREAT | O_TRUNC, 0666)))
		fatal("%s: %s\n", fname, strerror(errno));
	ret = write(fd, data, len);
	if (ret == -1)
		fatal("write: %s: %s\n", fname, strerror(errno));
	if ((size_t)ret != len)
		fatal("%s: partial write\n", fname);
	if (-1 == close(fd))
		fatal("close: %s: %s\n", fname, strerror(errno));
}

void get_program_bins(cl_program program)
{
	cl_int		status;
	size_t		sizes;
	unsigned char	*p;
	size_t		ret = 0;
	status = clGetProgramInfo(program, CL_PROGRAM_BINARY_SIZES,
		sizeof(sizes),	// size_t param_value_size
		&sizes,		// void *param_value
		&ret);		// size_t *param_value_size_ret
	if (status != CL_SUCCESS)
		fatal("clGetProgramInfo(sizes) (%d)\n", status);
	if (ret != sizeof(sizes))
		fatal("clGetProgramInfo(sizes) did not fill sizes (%d)\n", status);
	debug("Program binary size is %zd bytes\n", sizes);
	p = (unsigned char *)malloc(sizes);
	status = clGetProgramInfo(program, CL_PROGRAM_BINARIES,
		sizeof(p),	// size_t param_value_size
		&p,		// void *param_value
		&ret);	// size_t *param_value_size_ret
	if (status != CL_SUCCESS)
		fatal("clGetProgramInfo (%d)\n", status);
	dump("dump.co", p, sizes);
	debug("program: %02x%02x%02x%02x...\n", p[0], p[1], p[2], p[3]);
}

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
		show_n_sols = MIN(10, show_n_sols);
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
** Read a complete line from stdin. If 2 or more lines are available, store
** only the last one in the buffer.
**
** buf		buffer to store the line
** len		length of the buffer
** block	blocking mode: do not return until a line was read
**
** Return 1 iff a line was read.
*/
int read_last_line(char *buf, size_t len, int block)
{
	char	*start;
	size_t	pos = 0;
	ssize_t	n;
#ifndef WIN32
	set_blocking_mode(0, block);
#endif
	while (42)
	{
#ifndef WIN32
		n = read(0, buf + pos, len - pos);
		if (n == -1 && errno == EINTR)
			continue;
		else if (n == -1 && (errno == EAGAIN || errno == EWOULDBLOCK))
		{
			if (!pos)
				return 0;
			warn("strange: a partial line was read\n");
			// a partial line was read, continue reading it in blocking mode
			// to be sure to read it completely
			set_blocking_mode(0, 1);
			continue;
		}
		else if (n == -1)
			fatal("read stdin: %s\n", strerror(errno));
		else if (!n)
			fatal("EOF on stdin\n");
		pos += n;

		if (buf[pos - 1] == '\n')
			// 1 (or more) complete lines were read
			break;
#else
		DWORD bytesAvailable = 0;
		HANDLE stdinHandle = GetStdHandle(STD_INPUT_HANDLE);
		PeekNamedPipe(stdinHandle, NULL, 0, NULL, &bytesAvailable, NULL);
		if (bytesAvailable > 0) {

			if (!ReadFile(stdinHandle, buf, bytesAvailable, &bytesAvailable, NULL)) {
				fatal("ReadFile: %d", GetLastError());
			}
			pos += bytesAvailable;
		}
		else {
			return 0;
		}
		if (buf[pos - 1] == '\n')
			// 1 (or more) complete lines were read
			break;
#endif
	}
	start = (char*)memrchr(buf, '\n', pos - 1);
	if (start)
	{
		warn("strange: more than 1 line was read\n");
		// more than 1 line; copy the last line to the beginning of the buffer
		pos -= (start + 1 - buf);
		memmove(buf, start + 1, pos);
	}
	// overwrite '\n' with NUL

	buf[pos - 1] = 0;
	return 1;
}

/*
** Parse a string:
**   "<target> <job_id> <header> <nonce_leftpart>"
** (all the parts are in hex, except job_id which is a non-whitespace string),
** decode the hex values and store them in the relevant buffers.
**
** The remaining part of <header> that is not set by
** <header><nonce_leftpart> will be randomized so that the miner
** solves a unique Equihash PoW.
**
** str		string to parse
** target	buffer where the <target> will be stored
** target_len	size of target buffer
** job_id	buffer where the <job_id> will be stored
** job_id_len	size of job_id buffer
** header	buffer where the <header><nonce_leftpart> will be
** 		concatenated and stored
** header_len	size of the header_buffer
** fixed_nonce_bytes
** 		nr of bytes represented by <nonce_leftpart> will be stored here;
** 		this is the number of nonce bytes fixed by the stratum server
*/
void mining_parse_job(char *str, uint8_t *target, size_t target_len,
	char *job_id, size_t job_id_len, uint8_t *header, size_t header_len,
	size_t *fixed_nonce_bytes)
{
	uint32_t		str_i, i;
	// parse target
	str_i = 0;
	for (i = 0; i < target_len; i++, str_i += 2)
		target[i] = hex2val(str, str_i) * 16 + hex2val(str, str_i + 1);
	assert(str[str_i] == ' ');
	str_i++;
	// parse job_id
	for (i = 0; i < job_id_len && str[str_i] != ' '; i++, str_i++)
		job_id[i] = str[str_i];
	assert(str[str_i] == ' ');
	assert(i < job_id_len);
	job_id[i] = 0;
	str_i++;
	// parse header and nonce_leftpart
	for (i = 0; i < header_len && str[str_i] != ' '; i++, str_i += 2)
		header[i] = hex2val(str, str_i) * 16 + hex2val(str, str_i + 1);
	assert(str[str_i] == ' ');
	str_i++;
	*fixed_nonce_bytes = 0;
	while (i < header_len && str[str_i] && str[str_i] != '\n')
	{
		header[i] = hex2val(str, str_i) * 16 + hex2val(str, str_i + 1);
		i++;
		str_i += 2;
		(*fixed_nonce_bytes)++;
	}
	assert(!str[str_i]);
	// Randomize rest of the bytes except N_ZERO_BYTES bytes which must be zero
	debug("Randomizing %d bytes in nonce\n", header_len - N_ZERO_BYTES - i);
	randomize(header + i, header_len - N_ZERO_BYTES - i);
	memset(header + header_len - N_ZERO_BYTES, 0, N_ZERO_BYTES);
}

/*
** Run in mining mode.
*/
void mining_mode(solver_context_t self, uint8_t *header)
{
	char		line[4096];
	uint8_t		target[SHA256_DIGEST_SIZE];
	char		job_id[256];
	size_t		fixed_nonce_bytes = 0;
	uint64_t		i;
	uint64_t		total = 0;
	uint32_t		shares;
	uint64_t		total_shares = 0;
	uint64_t		t0, t1;
	uint64_t		status_period = 500e3; // time (usec) between statuses
	puts("SILENTARMY mining mode ready");
	fflush(stdout);

#ifdef WIN32
	TIMEVAL t;
	gettimeofday((timeval*)&t1, NULL);
	srand(t.tv_usec * t.tv_sec);
	SetConsoleOutputCP(65001);
#endif

	for (i = 0; ; i++)
	{
		// iteration #0 always reads a job or else there is nothing to do

		if (read_last_line(line, sizeof(line), !i))
			mining_parse_job(line,
				target, sizeof(target),
				job_id, sizeof(job_id),
				header, ZCASH_BLOCK_HEADER_LEN,
				&fixed_nonce_bytes);
		total += solve_equihash(true, self, header, ZCASH_BLOCK_HEADER_LEN, i,
			fixed_nonce_bytes, target, job_id, &shares);
		total_shares += shares;
		if ((t1 = now()) > t0 + status_period)
		{
			t0 = t1;
			printf("status: %" PRId64 " %" PRId64 "\n", total, total_shares);
			fflush(stdout);
		}
	}
}


void run_opencl(solver_context_t solver, uint8_t *header, size_t header_len)
{
	uint64_t		nonce;
	uint64_t		total;
		
	if (mining) {

		mining_mode(solver, header);

	}
	else {

		fprintf(stderr, "Running...\n");
		total = 0;
		uint64_t t0 = now();
		while (total < 100) {

			//randomize header
			for (size_t i = 0; i < header_len; i += sizeof(int))
				*((int*)(header + i)) = rand();

			// Solve Equihash while solution is not found
			for (nonce = 0; nonce < 1024; nonce++) {
				int sols = solve_equihash(false, solver, header, header_len, nonce, 0, NULL, NULL, NULL);
				total += sols;
				if (sols > 0)
					break;
			}
		}

		uint64_t t1 = now();

		fprintf(stderr, "Total %" PRId64 " solutions in %.1f ms (%.1f Sol/s)\n",
			total, (t1 - t0) / 1e3, total / ((t1 - t0) / 1e6));
	}	
}

void init_and_run_opencl(uint8_t *header, size_t header_len)
{
	solver_context_t solver = setup_context(gpu_to_use, mining);

	// Run
	run_opencl(solver, header, header_len);

	destroy_context(solver);
}

uint32_t parse_header(uint8_t *h, size_t h_len, const char *hex)
{
	size_t      hex_len;
	size_t      bin_len;
	size_t	opt0 = ZCASH_BLOCK_HEADER_LEN;
	size_t	opt1 = ZCASH_BLOCK_HEADER_LEN - ZCASH_NONCE_LEN;
	size_t      i;
	if (!hex)
	{
		if (!do_list_devices && !mining)
			fprintf(stderr, "Solving default all-zero %d-byte header\n", opt0);
		return opt1;
	}
	hex_len = strlen(hex);
	bin_len = hex_len / 2;
	if (hex_len % 2)
		fatal("Error: input header must be an even number of hex digits\n");
	if (bin_len != opt0 && bin_len != opt1)
		fatal("Error: input header must be either a %zd-byte full header, "
			"or a %zd-byte nonceless header\n", opt0, opt1);
	assert(bin_len <= h_len);
	for (i = 0; i < bin_len; i++)
		h[i] = hex2val(hex, i * 2) * 16 + hex2val(hex, i * 2 + 1);
	if (bin_len == opt0)
		while (--i >= bin_len - N_ZERO_BYTES)
			if (h[i])
				fatal("Error: last %d bytes of full header (ie. last %d "
					"bytes of 32-byte nonce) must be zero due to an "
					"optimization in my BLAKE2b implementation\n",
					N_ZERO_BYTES, N_ZERO_BYTES);
	return bin_len;
}

enum
{
	OPT_HELP,
	OPT_VERBOSE,
	OPT_INPUTHEADER,
	OPT_NONCES,
	OPT_THREADS,
	OPT_N,
	OPT_K,
	OPT_LIST,
	OPT_USE,
	OPT_MINING,
};

static struct option    optlong[] =
{
	  {"help",		no_argument,		0,	OPT_HELP},
	  {"h",		no_argument,		0,	OPT_HELP},
	  {"verbose",	no_argument,		0,	OPT_VERBOSE},
	  {"v",		no_argument,		0,	OPT_VERBOSE},
	  {"i",		required_argument,	0,	OPT_INPUTHEADER},
	  {"nonces",	required_argument,	0,	OPT_NONCES},
	  {"t",		required_argument,	0,	OPT_THREADS},
	  {"n",		required_argument,	0,	OPT_N},
	  {"k",		required_argument,	0,	OPT_K},
	  {"list",		no_argument,		0,	OPT_LIST},
	  {"use",		required_argument,	0,	OPT_USE},
	  {"mining",	no_argument,		0,	OPT_MINING},
	  {0,		0,			0,	0},
};

void usage(const char *progname)
{
	printf("Usage: %s [options]\n"
		"A standalone GPU Zcash Equihash solver.\n"
		"\n"
		"Options are:\n"
		"  -h, --help     display this help and exit\n"
		"  -v, --verbose  print verbose messages\n"
		"  -i <input>     hex block header to solve; either a 140-byte "
		"full header,\n"
		"                 or a 108-byte nonceless header with implicit "
		"zero nonce\n"
		"                 (default: all-zero header)\n"
		"  --nonces <nr>  number of nonces to try (default: 1)\n"
		"  -n <n>         equihash n param (only supported value is 200)\n"
		"  -k <k>         equihash k param (only supported value is 9)\n"
		"  --list         list available OpenCL devices by ID (GPUs...)\n"
		"  --use <id>     use GPU <id> (default: 0)\n"
		"  --mining       enable mining mode (solver controlled via "
		"stdin/stdout)\n"
		, progname);
}

void tests(void)
{
	// if NR_ROWS_LOG is smaller, there is not enough space to store all bits
	// of Xi in a 32-byte slot
	assert(NR_ROWS_LOG >= 12);
}

int main(int argc, char **argv)
{
	uint8_t             header[ZCASH_BLOCK_HEADER_LEN] = { 0, };
	uint32_t            header_len;
	char		*hex_header = NULL;
	int32_t             i;
	while (-1 != (i = getopt_long_only(argc, argv, "", optlong, 0)))
		switch (i)
		{
		case OPT_HELP:
			usage(argv[0]), exit(0);
			break;
		case OPT_VERBOSE:
			verbose += 1;
			break;
		case OPT_INPUTHEADER:
			hex_header = optarg;
			show_encoded = 1;
			break;
		case OPT_NONCES:
			nr_nonces = parse_num(optarg);
			break;
		case OPT_THREADS:
			// ignored, this is just to conform to the contest CLI API
			break;
		case OPT_N:
			if (PARAM_N != parse_num(optarg))
				fatal("Unsupported n (must be %d)\n", PARAM_N);
			break;
		case OPT_K:
			if (PARAM_K != parse_num(optarg))
				fatal("Unsupported k (must be %d)\n", PARAM_K);
			break;
		case OPT_LIST:
			do_list_devices = 1;
			break;
		case OPT_USE:
			gpu_to_use = parse_num(optarg);
			break;
		case OPT_MINING:
			mining = 1;
			break;
		default:
			fatal("Try '%s --help'\n", argv[0]);
			break;
		}
	tests();
	if (mining)
		puts("SILENTARMY mining mode ready"), fflush(stdout);
	header_len = parse_header(header, sizeof(header), hex_header);
	init_and_run_opencl(header, header_len);
	return 0;
}
