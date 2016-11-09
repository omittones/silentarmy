#pragma once

#include <stdbool.h>
#include "param.h"
#include "CL\opencl.h"

typedef struct solver_context_s {
	cl_context ctx;
	cl_program program;
	cl_command_queue queue;
	cl_kernel k_init_ht;
	cl_kernel k_rounds[PARAM_K];
	cl_kernel k_sols;
	cl_mem buf_ht[2];
	cl_mem buf_sols;
	cl_mem buf_dbg;
	size_t dbg_size;
	void* buf_dbg_helper;
} solver_context_t;

solver_context_t setup_context(int gpu_to_use, bool mining);

void destroy_context(solver_context_t self);

uint32_t solve_equihash(
	bool mining,
	solver_context_t self,
	uint8_t *header, size_t header_len, uint64_t nonce,
	size_t fixed_nonce_bytes, uint8_t *target, char *job_id,
	uint32_t *shares);

cl_mem check_clCreateBuffer(cl_context ctx, cl_mem_flags flags, size_t size, void *host_ptr);

void check_clSetKernelArg(cl_kernel k, cl_uint a_pos, cl_mem *a);

void check_clEnqueueNDRangeKernel(cl_command_queue queue, cl_kernel k, cl_uint
	work_dim, const size_t *global_work_offset, const size_t
	*global_work_size, const size_t *local_work_size, cl_uint
	num_events_in_wait_list, const cl_event *event_wait_list, cl_event
	*event);

void check_clEnqueueReadBuffer(cl_command_queue queue, cl_mem buffer, cl_bool
	blocking_read, size_t offset, size_t size, void *ptr, cl_uint
	num_events_in_wait_list, const cl_event *event_wait_list, cl_event
	*event);