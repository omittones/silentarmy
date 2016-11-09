#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <assert.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "solver.h"
#include "windows\logging.h"
#include "windows\crossplatform.h"

#define _CC
#include "blake.hpp"
#undef _CC

void print_platform_info(cl_platform_id plat)
{
	char	name[1024];
	size_t	len = 0;
	int		status;
	status = clGetPlatformInfo(plat, CL_PLATFORM_NAME, sizeof(name), &name,
		&len);
	if (status != CL_SUCCESS)
		fatal("clGetPlatformInfo (%d)\n", status);
	printf("Devices on platform \"%s\":\n", name);
	fflush(stdout);
}

void print_device_info(unsigned i, cl_device_id d)
{
	char	name[1024];
	size_t	len = 0;
	int		status;
	status = clGetDeviceInfo(d, CL_DEVICE_NAME, sizeof(name), &name, &len);
	if (status != CL_SUCCESS)
		fatal("clGetDeviceInfo (%d)\n", status);
	printf("  ID %d: %s\n", i, name);
	fflush(stdout);
}

/*
** Scan the devices available on this platform. Try to find the device
** selected by the "--use <id>" option and, if found, store the platform and
** device in plat_id and dev_id.
**
** plat			platform being scanned
** nr_devs_total	total number of devices detected so far, will be
** 			incremented by the number of devices available on this
** 			platform
** plat_id		where to store the platform id
** dev_id		where to store the device id
**
** Return 1 iff the selected device was found.
*/
unsigned scan_platform(
	int selectGpu,
	cl_platform_id plat,
	cl_uint *nr_devs_total,
	cl_platform_id *plat_id,
	cl_device_id *dev_id)
{
	cl_device_type	typ = CL_DEVICE_TYPE_ALL;
	cl_uint		nr_devs = 0;
	cl_device_id	*devices;
	cl_int		status;
	unsigned		found = 0;
	unsigned		i;

	status = clGetDeviceIDs(plat, typ, 0, NULL, &nr_devs);
	if (status != CL_SUCCESS)
		fatal("clGetDeviceIDs (%d)\n", status);
	if (nr_devs == 0)
		return 0;
	devices = (cl_device_id *)malloc(nr_devs * sizeof(*devices));
	status = clGetDeviceIDs(plat, typ, nr_devs, devices, NULL);
	if (status != CL_SUCCESS)
		fatal("clGetDeviceIDs (%d)\n", status);
	i = 0;
	while (i < nr_devs)
	{
		if (selectGpu < 0) {
			print_device_info(*nr_devs_total, devices[i]);
		}
		else if (*nr_devs_total == selectGpu)
		{
			found = 1;
			*plat_id = plat;
			*dev_id = devices[i];
			break;
		}
		(*nr_devs_total)++;
		i++;
	}
	free(devices);
	return found;
}

/*
** Stores the platform id and device id that was selected by the "--use <id>"
** option.
**
** plat_id		where to store the platform id
** dev_id		where to store the device id
*/
void scan_platforms(
	int gpuToUse,
	cl_platform_id *plat_id, 
	cl_device_id *dev_id)
{
	cl_uint		nr_platforms;
	cl_platform_id	*platforms;
	cl_uint		i, nr_devs_total;
	cl_int		status;
	status = clGetPlatformIDs(0, NULL, &nr_platforms);
	if (status != CL_SUCCESS)
		fatal("Cannot get OpenCL platforms (%d)\n", status);
	if (!nr_platforms || verbose)
		fprintf(stderr, "Found %d OpenCL platform(s)\n", nr_platforms);
	if (!nr_platforms)
		exit(1);
	platforms = (cl_platform_id *)malloc(nr_platforms * sizeof(*platforms));
	if (!platforms)
		fatal("malloc: %s\n", strerror(errno));
	status = clGetPlatformIDs(nr_platforms, platforms, NULL);
	if (status != CL_SUCCESS)
		fatal("clGetPlatformIDs (%d)\n", status);
	i = nr_devs_total = 0;
	while (i < nr_platforms)
	{
		if (scan_platform(gpuToUse, platforms[i], &nr_devs_total, plat_id, dev_id))
			break;
		i++;
	}
	debug("Using GPU device ID %d\n", gpuToUse);
	free(platforms);
}

/*
** Sort a pair of binary blobs (a, b) which are consecutive in memory and
** occupy a total of 2*len 32-bit words.
**
** a            points to the pair
** len          number of 32-bit words in each pair
*/
void sort_pair(uint32_t *a, uint32_t len)
{
	uint32_t    *b = a + len;
	uint32_t     tmp, need_sorting = 0;
	for (uint32_t i = 0; i < len; i++)
		if (need_sorting || a[i] > b[i])
		{
			need_sorting = 1;
			tmp = a[i];
			a[i] = b[i];
			b[i] = tmp;
		}
		else if (a[i] < b[i])
			return;
}

/*
** If solution is invalid return 0. If solution is valid, sort the inputs
** and return 1.
*/

#define SEEN_LEN (1 << (PREFIX + 1)) / 8

uint32_t verify_sol(sols_t *sols, unsigned sol_i)
{
	uint32_t	*inputs = sols->values[sol_i];
	//uint32_t	seen_len = (1 << (PREFIX + 1)) / 8;
	//uint8_t	seen[seen_len]; // @mrb MSVC didn't like this.
	uint8_t	seen[SEEN_LEN];
	uint32_t	i;
	uint8_t	tmp;
	// look for duplicate inputs
	memset(seen, 0, SEEN_LEN);
	for (i = 0; i < (1 << PARAM_K); i++)
	{
		tmp = seen[inputs[i] / 8];
		seen[inputs[i] / 8] |= 1 << (inputs[i] & 7);
		if (tmp == seen[inputs[i] / 8])
		{
			// at least one input value is a duplicate
			sols->valid[sol_i] = 0;
			return 0;
		}
	}
	// the valid flag is already set by the GPU, but set it again because
	// I plan to change the GPU code to not set it
	sols->valid[sol_i] = 1;
	// sort the pairs in place
	for (uint32_t level = 0; level < PARAM_K; level++)
		for (i = 0; i < (1 << PARAM_K); i += (2 << level))
			sort_pair(&inputs[i], 1 << level);
	return 1;
}

/*
** Return the number of valid solutions.
*/
uint32_t verify_sols(
	bool mining,
	cl_command_queue queue, cl_mem buf_sols, uint64_t *nonce,
	uint8_t *header, size_t fixed_nonce_bytes, uint8_t *target,
	char *job_id, uint32_t *shares)
{
	sols_t	*sols;
	uint32_t	nr_valid_sols;
	sols = (sols_t *)malloc(sizeof(*sols));
	if (!sols)
		fatal("malloc: %s\n", strerror(errno));
	check_clEnqueueReadBuffer(queue, buf_sols,
		CL_TRUE,	// cl_bool	blocking_read
		0,		// size_t	offset
		sizeof(*sols),	// size_t	size
		sols,	// void		*ptr
		0,		// cl_uint	num_events_in_wait_list
		NULL,	// cl_event	*event_wait_list
		NULL);	// cl_event	*event
	if (sols->nr > MAX_SOLS)
	{
		fprintf(stderr, "%d (probably invalid) solutions were dropped!\n",
			sols->nr - MAX_SOLS);
		sols->nr = MAX_SOLS;
	}
	nr_valid_sols = 0;
	for (unsigned sol_i = 0; sol_i < sols->nr; sol_i++)
		nr_valid_sols += verify_sol(sols, sol_i);
	uint32_t sh = print_sols(sols, nonce, nr_valid_sols, header,
		fixed_nonce_bytes, target, job_id);
	if (shares)
		*shares = sh;
	if (!mining || verbose)
		fprintf(stderr, "Nonce %s: %d sol%s\n",
			s_hexdump(nonce, ZCASH_NONCE_LEN), nr_valid_sols,
			nr_valid_sols == 1 ? "" : "s");
	debug("Stats: %d likely invalids\n", sols->likely_invalids);
	free(sols);
	return nr_valid_sols;
}

cl_mem check_clCreateBuffer(cl_context ctx, cl_mem_flags flags, size_t size,
	void *host_ptr)
{
	cl_int	status;
	cl_mem	ret;
	ret = clCreateBuffer(ctx, flags, size, host_ptr, &status);
	if (status != CL_SUCCESS || !ret)
		fatal("clCreateBuffer (%d)\n", status);
	return ret;
}

void check_clSetKernelArg(cl_kernel k, cl_uint a_pos, cl_mem *a)
{
	cl_int	status;
	status = clSetKernelArg(k, a_pos, sizeof(*a), a);
	if (status != CL_SUCCESS)
		fatal("clSetKernelArg (%d)\n", status);
}

void check_clEnqueueNDRangeKernel(cl_command_queue queue, cl_kernel k, cl_uint
	work_dim, const size_t *global_work_offset, const size_t
	*global_work_size, const size_t *local_work_size, cl_uint
	num_events_in_wait_list, const cl_event *event_wait_list, cl_event
	*event)
{
	cl_uint	status;
	status = clEnqueueNDRangeKernel(queue, k, work_dim, global_work_offset,
		global_work_size, local_work_size, num_events_in_wait_list,
		event_wait_list, event);
	if (status != CL_SUCCESS)
		fatal("clEnqueueNDRangeKernel (%d)\n", status);
}

void check_clEnqueueReadBuffer(cl_command_queue queue, cl_mem buffer, cl_bool
	blocking_read, size_t offset, size_t size, void *ptr, cl_uint
	num_events_in_wait_list, const cl_event *event_wait_list, cl_event
	*event)
{
	cl_int	status;
	status = clEnqueueReadBuffer(queue, buffer, blocking_read, offset,
		size, ptr, num_events_in_wait_list, event_wait_list, event);
	if (status != CL_SUCCESS)
		fatal("clEnqueueReadBuffer (%d)\n", status);
}

unsigned nr_compute_units(const char *gpu)
{
	if (!strcmp(gpu, "rx480")) return 36;
	fprintf(stderr, "Unknown GPU: %s\n", gpu);
	return 0;
}

size_t select_work_size_blake(void)
{
	size_t              work_size =
		64 * /* thread per wavefront */
		BLAKE_WPS * /* wavefront per simd */
		4 * /* simd per compute unit */
		nr_compute_units("rx480");
	// Make the work group size a multiple of the nr of wavefronts, while
	// dividing the number of inputs. This results in the worksize being a
	// power of 2.
	while (NR_INPUTS % work_size)
		work_size += 64;
	//debug("Blake: work size %zd\n", work_size);
	return work_size;
}

void init_ht(cl_command_queue queue, cl_kernel k_init_ht, cl_mem buf_ht)
{
	size_t      global_ws = NR_ROWS;
	size_t      local_ws = 64;
	cl_int      status;
#if 0
	uint32_t    pat = -1;
	status = clEnqueueFillBuffer(queue, buf_ht, &pat, sizeof(pat), 0,
		NR_ROWS * NR_SLOTS * SLOT_LEN,
		0,		// cl_uint	num_events_in_wait_list
		NULL,	// cl_event	*event_wait_list
		NULL);	// cl_event	*event
	if (status != CL_SUCCESS)
		fatal("clEnqueueFillBuffer (%d)\n", status);
#endif
	status = clSetKernelArg(k_init_ht, 0, sizeof(buf_ht), &buf_ht);
	if (status != CL_SUCCESS)
		fatal("clSetKernelArg (%d)\n", status);
	check_clEnqueueNDRangeKernel(queue, k_init_ht,
		1,		// cl_uint	work_dim
		NULL,	// size_t	*global_work_offset
		&global_ws,	// size_t	*global_work_size
		&local_ws,	// size_t	*local_work_size
		0,		// cl_uint	num_events_in_wait_list
		NULL,	// cl_event	*event_wait_list
		NULL);	// cl_event	*event
}


void load_file(const char *fname, char **dat, size_t *dat_len)
{
	struct stat	st;
	int		fd;
	ssize_t	ret;
	if (-1 == (fd = open(fname, O_RDONLY)))
		fatal("%s: %s\n", fname, strerror(errno));
	if (fstat(fd, &st))
		fatal("fstat: %s: %s\n", fname, strerror(errno));
	*dat_len = st.st_size;
	if (!(*dat = (char *)malloc(*dat_len + 1)))
		fatal("malloc: %s\n", strerror(errno));

	size_t offset = 0;
	while (1) {
		int maxchars = max(0, *dat_len - offset);
		if (maxchars == 0)
			fatal("not enough memory");
		ret = read(fd, *dat + offset, maxchars);
		if (ret < 0)
			fatal("read: %s: %s\n", fname, strerror(errno));
		offset += ret;
		if (ret == 0)
			break;
	}

	*dat_len = offset;

	if (close(fd))
		fatal("close: %s: %s\n", fname, strerror(errno));

	(*dat)[*dat_len] = 0;
}

void get_program_build_log(cl_program program, cl_device_id device)
{
	cl_int		status;
	char	        val[2 * 1024 * 1024];
	size_t		ret = 0;
	status = clGetProgramBuildInfo(program, device,
		CL_PROGRAM_BUILD_LOG,
		sizeof(val),	// size_t param_value_size
		&val,		// void *param_value
		&ret);		// size_t *param_value_size_ret
	if (status != CL_SUCCESS)
		fatal("clGetProgramBuildInfo (%d)\n", status);
	fprintf(stderr, "%s\n", val);
}

/*
** Attempt to find Equihash solutions for the given Zcash block header and
** nonce. The 'header' passed in argument is either:
**
** - a 140-byte full header specifying the nonce, or
** - a 108-byte nonceless header, implying a nonce of 32 zero bytes
**
** In both cases the function constructs the full block header to solve by
** adding the value of 'nonce' to the nonce in 'header'. This allows
** repeatedly calling this fuction while changing only the value of 'nonce'
** to attempt different Equihash problems.
**
** header	must be a buffer allocated with ZCASH_BLOCK_HEADER_LEN bytes
** header_len	number of bytes initialized in header (either 140 or 108)
** shares	if not NULL, in mining mode the number of shares (ie. number
**		of solutions that were under the target) are stored here
**
** Return the number of solutions found.
*/
uint32_t solve_equihash(
	bool mining,
	solver_context_t self,
	uint8_t *header, size_t header_len, uint64_t nonce,
	size_t fixed_nonce_bytes, uint8_t *target, char *job_id,
	uint32_t *shares)
{
	blake2b_state_t     blake;
	cl_mem              buf_blake_st;
	size_t		global_ws;
	size_t              local_work_size = 64;
	uint32_t		sol_found = 0;
	uint64_t		*nonce_ptr;

	if (mining)
	{
		// mining mode must specify full header
		assert(header_len == ZCASH_BLOCK_HEADER_LEN);
		assert(target && job_id);
	}
	else
		assert(header_len == ZCASH_BLOCK_HEADER_LEN ||
			header_len == ZCASH_BLOCK_HEADER_LEN - ZCASH_NONCE_LEN);
	
	nonce_ptr = (uint64_t *)(header + ZCASH_BLOCK_HEADER_LEN - ZCASH_NONCE_LEN);
	// add the nonce. if (header_len == ZCASH_BLOCK_HEADER_LEN) the full
	// header is preserved between calls to solve_equihash(), so we can just
	// increment by 1, else 'nonce' is used to construct the 32-byte nonce.

	if (mining)
	{
		// increment bytes 17-19
		(*(uint32_t *)((uint8_t *)nonce_ptr + 17))++;
		// byte 20 and above must be zero
		*(uint32_t *)((uint8_t *)nonce_ptr + 20) = 0;
	}
	else
	{
		if (header_len == ZCASH_BLOCK_HEADER_LEN - ZCASH_NONCE_LEN)
		{
			memset(nonce_ptr, 0, ZCASH_NONCE_LEN);
			// add the nonce
			*nonce_ptr += nonce;
		}
		else
			(*nonce_ptr)++;
	}
	
	debug("\nSolving nonce %s\n", s_hexdump(nonce_ptr, ZCASH_NONCE_LEN));

	// Process first BLAKE2b-400 block
	zcash_blake2b_init(&blake, ZCASH_HASH_LEN, PARAM_N, PARAM_K);
	zcash_blake2b_update(&blake, header, 128, 0);
	buf_blake_st = check_clCreateBuffer(self.ctx, CL_MEM_READ_ONLY |
		CL_MEM_COPY_HOST_PTR, sizeof(blake.h), &blake.h);
	for (unsigned round = 0; round < PARAM_K; round++)
	{
		if (verbose > 1)
			debug("Round %d\n", round);

		if (round < 2) {
			init_ht(self.queue, self.k_init_ht, self.buf_ht[round % 2]);
		}
			
		if (!round)
		{
			check_clSetKernelArg(self.k_rounds[round], 0, &buf_blake_st);
			check_clSetKernelArg(self.k_rounds[round], 1, &self.buf_ht[round % 2]);
			global_ws = select_work_size_blake();
		}
		else
		{
			check_clSetKernelArg(self.k_rounds[round], 0, &self.buf_ht[(round - 1) % 2]);
			check_clSetKernelArg(self.k_rounds[round], 1, &self.buf_ht[round % 2]);
			global_ws = NR_ROWS;
		}
		check_clSetKernelArg(self.k_rounds[round], 2, &self.buf_dbg);
		if (round == PARAM_K - 1)
			check_clSetKernelArg(self.k_rounds[round], 3, &self.buf_sols);
		check_clEnqueueNDRangeKernel(self.queue, self.k_rounds[round], 1, NULL,
			&global_ws, &local_work_size, 0, NULL, NULL);
		examine_ht(round, self.queue, self.buf_ht[round % 2]);
		examine_dbg(self.queue, self.buf_dbg, self.dbg_size);
	}
	check_clSetKernelArg(self.k_sols, 0, &self.buf_ht[0]);
	check_clSetKernelArg(self.k_sols, 1, &self.buf_ht[1]);
	check_clSetKernelArg(self.k_sols, 2, &self.buf_sols);
	global_ws = NR_ROWS;
	check_clEnqueueNDRangeKernel(self.queue, self.k_sols, 1, NULL,
		&global_ws, &local_work_size, 0, NULL, NULL);
	sol_found = verify_sols(mining, self.queue, self.buf_sols, nonce_ptr, header,
		fixed_nonce_bytes, target, job_id, shares);
	clReleaseMemObject(buf_blake_st);
	return sol_found;
}

solver_context_t setup_context(int gpu_to_use, bool mining) {

	solver_context_t self;
	self.buf_dbg_helper = NULL;

	cl_platform_id	plat_id = 0;
	cl_device_id	dev_id = 0;
	cl_int		status;
	scan_platforms(gpu_to_use, &plat_id, &dev_id);
	if (!plat_id || !dev_id)
		fatal("Selected device (ID %d) not found; see --list\n", gpu_to_use);
	/* Create context.*/
	self.ctx = clCreateContext(NULL, 1, &dev_id, NULL, NULL, &status);
	if (status != CL_SUCCESS || !self.ctx)
		fatal("clCreateContext (%d)\n", status);
	/* Creating command queue associate with the context.*/
	self.queue = clCreateCommandQueue(self.ctx, dev_id, 0, &status);
	if (status != CL_SUCCESS || !self.queue)
		fatal("clCreateCommandQueue (%d)\n", status);
	/* Create program object */

	char *source;
	size_t source_len;
#ifdef WIN32
	load_file("input.cl", &source, &source_len);
#else
	source = ocl_code;
#endif
	source_len = strlen(source);
	self.program = clCreateProgramWithSource(self.ctx, 1, (const char **)&source, &source_len, &status);
	if (status != CL_SUCCESS || !self.program)
		fatal("clCreateProgramWithSource (%d)\n", status);
	/* Build program. */
	if (!mining || verbose)
		fprintf(stderr, "Building program\n");
	status = clBuildProgram(self.program, 1, &dev_id, "-I .. -I .", // compile options
		NULL, NULL);
	if (status != CL_SUCCESS)
	{
		warn("OpenCL build failed (%d). Build log follows:\n", status);
		get_program_build_log(self.program, dev_id);
		exit(1);
	}
	//get_program_bins(program);
	// Create kernel objects
	self.k_init_ht = clCreateKernel(self.program, "kernel_init_ht", &status);
	if (status != CL_SUCCESS || !self.k_init_ht)
		fatal("clCreateKernel (%d)\n", status);
	for (unsigned round = 0; round < PARAM_K; round++)
	{
		char	name[128];
		snprintf(name, sizeof(name), "kernel_round%d", round);
		self.k_rounds[round] = clCreateKernel(self.program, name, &status);
		if (status != CL_SUCCESS || !self.k_rounds[round])
			fatal("clCreateKernel (%d)\n", status);
	}
	self.k_sols = clCreateKernel(self.program, "kernel_sols", &status);
	if (status != CL_SUCCESS || !self.k_sols)
		fatal("clCreateKernel (%d)\n", status);

#ifdef ENABLE_DEBUG
	self.dbg_size = NR_ROWS * sizeof(debug_t);
#else
	self.dbg_size = 1 * sizeof(debug_t);
#endif

	if (!mining || verbose)
		fprintf(stderr, "Hash tables will use %.1f MB\n", 2.0 * HT_SIZE / 1e6);
	// Set up buffers for the host and memory objects for the kernel
	if (!(self.buf_dbg_helper = calloc(self.dbg_size, 1)))
		fatal("malloc: %s\n", strerror(errno));
	self.buf_dbg = check_clCreateBuffer(self.ctx, CL_MEM_READ_WRITE |
		CL_MEM_COPY_HOST_PTR, self.dbg_size, self.buf_dbg_helper);
	self.buf_ht[0] = check_clCreateBuffer(self.ctx, CL_MEM_READ_WRITE, HT_SIZE, NULL);
	self.buf_ht[1] = check_clCreateBuffer(self.ctx, CL_MEM_READ_WRITE, HT_SIZE, NULL);
	self.buf_sols = check_clCreateBuffer(self.ctx, CL_MEM_READ_WRITE, sizeof(sols_t),
		NULL);

	return self;
}

void destroy_context(solver_context_t self) {

	// Clean up
	if (self.buf_dbg_helper)
		free(self.buf_dbg_helper);

	clReleaseMemObject(self.buf_dbg);
	clReleaseMemObject(self.buf_sols);
	clReleaseMemObject(self.buf_ht[0]);
	clReleaseMemObject(self.buf_ht[1]);

	// Release resources
	assert(CL_SUCCESS == 0);
	auto status = CL_SUCCESS;
	status |= clReleaseKernel(self.k_init_ht);
	for (unsigned round = 0; round < PARAM_K; round++)
		status |= clReleaseKernel(self.k_rounds[round]);
	status |= clReleaseKernel(self.k_sols);
	status |= clReleaseProgram(self.program);
	status |= clReleaseCommandQueue(self.queue);
	status |= clReleaseContext(self.ctx);
	if (status)
		fprintf(stderr, "Cleaning resources failed\n");

}