#pragma once

#include <stdbool.h>
#include <vector>
#include <string>
#include "param.h"
#include "CL\opencl.h"

struct platform_t {
	cl_platform_id platfId;
	cl_device_id devId;
	std::string name;

	inline platform_t() {
	}

	inline platform_t(const platform_t& cc) {
		devId = cc.devId;
		platfId = cc.platfId;
		name = cc.name;
	}

	inline platform_t(platform_t&& cc) {
		devId = cc.devId;
		platfId = cc.platfId;
		name = cc.name;
	}

	inline ~platform_t() {
	}
};

struct solver_context_t {
	cl_context ctx;
	cl_program program;
	cl_command_queue queue;
	cl_kernel k_init_ht;
	cl_kernel k_rounds[PARAM_K];
	cl_kernel k_sols;
	cl_mem buf_ht[2];
	cl_mem rowCounters[2];
	cl_mem buf_sols;
	cl_mem buf_dbg;
	size_t dbg_size;
	void* buf_dbg_helper;
};

std::vector<platform_t> scan_platforms();

void setup_context(solver_context_t& self, cl_device_id devId);

void destroy_context(solver_context_t& self);

sols_t* solve_equihash(solver_context_t self, size_t noThreadsPerBlock,	uint8_t *header, size_t header_len);

bool verify_sol(sols_t *sols, unsigned sol_i);

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