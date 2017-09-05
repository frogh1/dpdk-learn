

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/queue.h>

#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_cycles.h>
#include <rte_random.h>
#include <rte_memory.h>
#include <rte_memzone.h>

#include <rte_eal.h>
#include <rte_hash.h>
#include <rte_jhash.h>

#include "fq_timer.h"

static struct rte_hash_parameters uthash_params = {
	.name = "uint_hash_params",
	.entries = 8,
	.key_len = sizeof(uint32_t),	
	.hash_func = rte_jhash,
	.hash_func_init_val = 0,
};

#define HASH_NUM (1024*1024)
static struct rte_hash_parameters uthash_params1 = {
	.name = "uint_hash_params_test",
	.entries = HASH_NUM,
	.key_len = sizeof(uint32_t),	
	.hash_func = rte_jhash,
	.hash_func_init_val = 0,
};


int main(int argc,char **argv)
{
			int ret;
			/* init EAL */
			ret = rte_eal_init(argc, argv);
			if (ret < 0)
				rte_exit(EXIT_FAILURE, "Invalid EAL parameters\n");
			argc -= ret;
			argv += ret;

		struct rte_hash *handle;
		handle = rte_hash_create(&uthash_params); 
		if(handle == NULL)
		{
				rte_exit(EXIT_FAILURE, "Invalid hash handle parameters\n");
		}
		
		int i = 0;
		for(i = 0;i< 10;i++)
		{
				uint32_t key = i;
				ret = rte_hash_add_key(handle,&key);
				printf("add iret %d\n",ret);
		}
                
   uint32_t iter =0 ;
		uint32_t *k,*v;
    while(rte_hash_iterate(handle,(void **)&k,(void **)&v,&iter)>= 0)
		{
			printf("k=%u,iter=%u\n",*k,iter);
		}
printf("*********************************\n");		
    
    for(i = 0;i<10;i++)
		{
			if(i & 1)
			{
				uint32_t key = i;
				rte_hash_del_key(handle,&key);
			}
		}                
               
    iter = 0;
		while(rte_hash_iterate(handle,(void **)&k,(void **)&v,&iter)>= 0)
    {
         printf("k=%u,iter=%u\n",*k,iter);
    }
printf("*********************************\n");
		for(i = 10;i< 20;i++)
    {
        uint32_t key = i;
        ret = rte_hash_add_key(handle,&key);
        printf("add iret %d\n",ret);
    }
	        iter = 0;
		while(rte_hash_iterate(handle,(void **)&k,(void **)&v,&iter)>= 0)
    {
            printf("k=%u,iter=%u\n",*k,iter);
    }
printf("*********************************\n");


		struct rte_hash *handle1;
		handle1 = rte_hash_create(&uthash_params1); 
		if(handle1 == NULL)
		{
				rte_exit(EXIT_FAILURE, "Invalid hash handle parameters\n");
		}

		uint64_t cur,fin;
		cur = get_time_ms();
		for(i=0;i<HASH_NUM-1;i++)
		{
			uint32_t key = i;
			rte_hash_add_key(handle1,&key);
		}
		fin = get_time_ms();
		printf("finished %lu \n",fin-cur);
	
		cur = get_time_ms();
		iter = 0;
		while(rte_hash_iterate(handle1,(void **)&k,(void **)&v,&iter)>= 0)
   {
                      // printf("k=%u,iter=%u\n",*k,iter);
			if(*k & 1)
			{
				*k++;
			}
   }	
		fin = get_time_ms();
		printf("finished %lu \n",fin-cur);
	 return 0;			
}
