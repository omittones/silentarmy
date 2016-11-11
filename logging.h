#pragma once

#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <chrono>
#include <iostream>
#include "CL/opencl.h"
#include "../sha256.h"
#include "../param.h"

#define min(a,b) ((a)<(b)?(a):(b))

extern uint16_t verbose;

typedef struct  debug_s
{
	uint32_t    dropped_coll;
	uint32_t    dropped_stor;
}               debug_t;

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

template<typename TimeT = std::chrono::milliseconds>
struct measure
{
private:
	std::chrono::high_resolution_clock::time_point start;
	const char* name;

public:
	inline measure(const char* name) {
		this->start = std::chrono::high_resolution_clock::now();
		this->name = name;
	}

	inline TimeT stop(bool output = true) {
		auto duration = std::chrono::duration_cast<TimeT>(std::chrono::high_resolution_clock::now() - start);
		auto count = duration.count();
		if (output)
			std::cout << name << ": " << count << std::endl;
		return duration;
	}

	template<typename F, typename ...Args>
	static typename TimeT::rep execution(const char* name, F func, Args&&... args)
	{
		measure m(name);

		// Now call the function with all the parameters you need.
		func(std::forward<Args>(args)...);

		return m.stop(false);
	}
};