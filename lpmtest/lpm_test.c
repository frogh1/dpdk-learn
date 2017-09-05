
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <string.h>
#include <sys/queue.h>
#include <stdarg.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>

#include <rte_common.h>
#include <rte_vect.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>

#include <rte_ip.h>
#include <rte_lpm.h>


#define MAX_DEPTH 32
#define MAX_RULES 0x200
#define NUMBER_TBL8S 256
#define PASS 0

int main(int argc,char **argv)
{
	int ret;
	/* init EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL parameters\n");
	argc -= ret;
	argv += ret;
     
		
	struct rte_lpm *lpm = NULL;
	struct rte_lpm_config config;
	
	config.max_rules = MAX_RULES;
	config.number_tbl8s = NUMBER_TBL8S;
	config.flags = 0;
	
	lpm = rte_lpm_create("lpm_test", SOCKET_ID_ANY, &config);
	
	if(lpm == NULL)
	{
			printf("create lpm hash error\n");
			return -1;
	}
	int i;
	uint32_t next_hop;
#if 0
	ret = rte_lpm_add(lpm, IPv4(192,168,1,3), 32, 1);
	ret = rte_lpm_is_rule_present(lpm,IPv4(192,168,1,25),24,&next_hop);
	printf("1 ret %d\n",ret);
	ret = rte_lpm_is_rule_present(lpm,IPv4(192,168,1,3),32,&next_hop);
	printf("2 ret %d\n",ret); 
#endif
	ret= rte_lpm_add(lpm, IPv4(192,168,1,0), 24, 1);
        ret = rte_lpm_is_rule_present(lpm,IPv4(192,168,1,3),24,&next_hop);
        printf("3 ret %d\n",ret);
        ret = rte_lpm_is_rule_present(lpm,IPv4(192,168,1,3),32,&next_hop);
        printf("4 ret %d\n",ret);

	ret = rte_lpm_is_rule_present(lpm,IPv4(192,168,1,12),24,&next_hop);
        printf("5 ret %d\n",ret);
	ret = rte_lpm_is_rule_present(lpm,IPv4(192,168,1,23),32,&next_hop);
        printf("6 ret %d\n",ret);

	ret=rte_lpm_lookup(lpm, IPv4(192,168,1,3), &next_hop);
	printf("7 ret %d\n",ret);
	ret=rte_lpm_delete(lpm,IPv4(192,168,1,3),32);
	printf("8 ret %d\n",ret);
	ret=rte_lpm_lookup(lpm, IPv4(192,168,1,3), &next_hop);
        printf("9 ret %d\n",ret);

	ret=rte_lpm_delete(lpm,IPv4(192,168,1,3),24);
        printf("10 ret %d\n",ret);
        ret=rte_lpm_lookup(lpm, IPv4(192,168,1,3), &next_hop);
        printf("11 ret %d\n",ret);

	ret= rte_lpm_add(lpm, IPv4(192,168,1,5), 32, 6);
	printf("12 ret %d\n",ret);
	ret=rte_lpm_lookup(lpm, IPv4(192,168,1,5), &next_hop);
	printf("13 ret %d next_hop %u\n",ret,next_hop);

        ret = rte_lpm_add(lpm, IPv4(192,168,1,7), 32, 10);
	ret=rte_lpm_lookup(lpm, IPv4(192,168,1,7), &next_hop);
        printf("14 ret %d next_hop %u\n",ret,next_hop);	

	ret=rte_lpm_lookup(lpm, IPv4(192,168,1,8), &next_hop);
        printf("15 ret %d next_hop %u\n",ret,next_hop);	
#if 1
	for(i = 0;i<300;i++)
	{    
		ret = rte_lpm_is_rule_present(lpm,IPv4(192,168,1,i),24,&next_hop);
		if(1 == ret)
		{
			printf("exist \n");
			continue;
		}
		ret = rte_lpm_add(lpm, IPv4(192,168,1,i), 32, 1);
	
		if(ret != 0)
		{
				printf("add error ret %d \n",ret);
				break;
		}
	}
#endif	

	ret = rte_lpm_add(lpm, IPv4(192,168,1,21), 24, 1);
	for(i = 0; i< 20; i++)
	{
	//	ret = rte_lpm_add(lpm, IPv4(192,168,1,i), 32, 1);
		ret=rte_lpm_lookup(lpm, IPv4(192,168,1,i), &next_hop);

                if(ret != 0)
                {
                                printf("find error ret %d \n",ret);
                                break;
                }
	}

	printf("lpm maxrules %u\n",lpm->max_rules);	

	for(i = 0;i < RTE_LPM_MAX_DEPTH; i++)
	{
		printf("depth %d used rules %d\n",i,lpm->rule_info[i].used_rules);
	}

	return 0;
}
