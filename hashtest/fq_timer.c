
#include <rte_cycles.h>
#include "fq_timer.h"


double cycle_to_ns()
{
	double hz=rte_get_tsc_hz();	
	return (hz/(double)NS_PER_S);
}

uint64_t get_time_ns()
{
	uint64_t cur_tsc = rte_rdtsc();
	
    return (uint64_t)(cur_tsc/cycle_to_ns());
}

uint64_t get_time_us()
{
	return (get_time_ns()/1000);
}

uint64_t get_time_ms()
{
	return (get_time_ns()/1000000);
}


uint64_t get_time_sec()
{
	uint64_t cur_tsc = rte_rdtsc();

	return (cur_tsc/rte_get_tsc_hz());
}


