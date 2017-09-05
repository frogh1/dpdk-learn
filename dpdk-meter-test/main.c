/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2015 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdint.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_arp.h>
#include <rte_ip.h>
#include <rte_tcp.h>

#include <rte_meter.h>

#define RX_RING_SIZE 128
#define TX_RING_SIZE 512

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

enum policer_action {
        GREEN = e_RTE_METER_GREEN,
        YELLOW = e_RTE_METER_YELLOW,
        RED = e_RTE_METER_RED,
        DROP = 3,
};

/*
*1000M->8192
*100M->819200
*10->819200
*/

struct rte_meter_srtcm_params app_srtcm_params[] = {
	{.cir = 1000000*1000,  .cbs = 819200, .ebs = 819200},
	{.cir = 1000000*10,  .cbs = 819200, .ebs = 819200}
};

#define APP_FLOWS_MAX  256

struct rte_meter_srtcm app_flows[APP_FLOWS_MAX];


static int
app_configure_flow_table(void)
{
	uint32_t i, j;
	int ret;
	ret = rte_meter_srtcm_config(&app_flows[0], &app_srtcm_params[0]);
	ret = rte_meter_srtcm_config(&app_flows[1], &app_srtcm_params[1]);
#if 0
	for (i = 0, j = 0; i < APP_FLOWS_MAX;
			i ++, j = (j + 1) % RTE_DIM(app_srtcm_params)) {
		ret = rte_meter_srtcm_config(&app_flows[i], &app_srtcm_params[j]);
		if (ret)
			return ret;
	}
#endif
	return 0;
}

static inline int
app_pkt_handle(struct rte_mbuf *pkt, uint64_t time)
{
	uint8_t input_color, output_color;
	uint8_t *pkt_data = rte_pktmbuf_mtod(pkt, uint8_t *);
	
	//uint32_t pkt_len = rte_pktmbuf_pkt_len(pkt) - sizeof(struct ether_hdr);
	uint32_t pkt_len = rte_pktmbuf_pkt_len(pkt);
	uint8_t flow_id = 1;//可根据实际情况赋值
	input_color = 0;

	/* color input is not used for blind modes */
	output_color = (uint8_t) rte_meter_srtcm_color_blind_check(&app_flows[flow_id], time, pkt_len);
	return output_color;
}

#define PERIOD rte_get_timer_hz()
#define PREFETCH_OFFSET 3

static const struct rte_eth_conf port_conf_default = {
	.rxmode = { .max_rx_pkt_len = ETHER_MAX_LEN }
};

const struct ether_addr client_mac = {.addr_bytes = {0xd4,0x3d,0x7e,0x71,0x83,0x13}};
const struct ether_addr server_mac = {.addr_bytes = {0xd4,0x3d,0x7e,0x0e,0x5e,0x1e}};

const uint32_t client_ip = IPv4(192,168,1,11);
const uint32_t server_ip = IPv4(192,168,1,21);
const uint32_t my_ip = IPv4(192,168,1,3);

enum tcp_state {
  CLOSED      ,
//  LISTEN      ,
  SYN_SENT    ,
  SYN_RCVD    ,
  ESTABLISHED ,
  FIN_WAIT_1  ,
//  FIN_WAIT_2  ,
  CLOSE_WAIT  ,
//  CLOSING     ,
  LAST_ACK    ,
  TIME_WAIT   
};

const char *s_state[] = {  
	"CLOSED"      ,
//  "LISTEN"      ,
	"SYN_SENT"    ,
	"SYN_RCVD"    ,
	"ESTABLISHED" ,
	"FIN_WAIT_1"  ,
//	"FIN_WAIT_2"  ,
	"CLOSE_WAIT"  ,
//  "CLOSING"     ,
	"LAST_ACK"    ,
	"TIME_WAIT"
};

#define TCP_FIN 0x01U
#define TCP_SYN 0x02U
#define TCP_RST 0x04U
#define TCP_PSH 0x08U
#define TCP_ACK 0x10U
#define TCP_URG 0x20U
#define TCP_ECE 0x40U
#define TCP_CWR 0x80U

#define TCP_FLAGS 0x3fU

struct session
{
	enum tcp_state state;
	uint64_t expire;
}S;

/* basicfwd.c: Basic DPDK skeleton forwarding example. */

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */
static inline int
port_init(uint8_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf = port_conf_default;
	const uint16_t rx_rings = 1, tx_rings = 1;
	int retval;
	uint16_t q;

	if (port >= rte_eth_dev_count())
		return -1;

	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	/* Allocate and set up 1 RX queue per Ethernet port. */
	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, RX_RING_SIZE,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	/* Allocate and set up 1 TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, TX_RING_SIZE,
				rte_eth_dev_socket_id(port), NULL);
		if (retval < 0)
			return retval;
	}

	/* Start the Ethernet port. */
	retval = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;

	/* Display the port MAC address. */
	struct ether_addr addr;
	rte_eth_macaddr_get(port, &addr);
	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			(unsigned)port,
			addr.addr_bytes[0], addr.addr_bytes[1],
			addr.addr_bytes[2], addr.addr_bytes[3],
			addr.addr_bytes[4], addr.addr_bytes[5]);

	/* Enable RX in promiscuous mode for the Ethernet device. */
	rte_eth_promiscuous_enable(port);

	return 0;
}

// flag: if ==0, for in->out flow; else ==1, for out->in flow.
// only in-closing is considered
static inline int process_tcp(struct tcp_hdr *tcphdr, int flag)
{
	uint8_t state = tcphdr->tcp_flags & TCP_FLAGS;
	if(state == TCP_RST)
	{
		S.state = CLOSED;
		return 1;
	}
	if(state == TCP_SYN && (S.state != SYN_SENT && S.state != SYN_RCVD))
	{
		S.state = CLOSED;
		return 1;
	}
	switch(S.state)
	{
		case CLOSED:
			if(state & TCP_SYN && ! flag){S.state = SYN_SENT;}
			break;
			
		case SYN_SENT:
			if(state & TCP_SYN && state & TCP_ACK && flag){S.state = SYN_RCVD;}
			break;
			
		case SYN_RCVD:
			if(state & TCP_ACK && ! flag){S.state = ESTABLISHED;}
			break;
			
		case ESTABLISHED:
			if(state & TCP_FIN && ! flag){S.state = FIN_WAIT_1;}
			break;
			
		case FIN_WAIT_1:
			if(state & TCP_ACK && state & TCP_FIN && flag){S.state = LAST_ACK;}
			else if(state & TCP_ACK && flag){S.state = CLOSE_WAIT;}
			break;
			
		case CLOSE_WAIT:
			if(state & TCP_FIN && flag){S.state = LAST_ACK;}
			break;
			
		case LAST_ACK:
			if(state & TCP_ACK && ! flag)
			{
				S.state = TIME_WAIT;
				S.expire = rte_rdtsc()/PERIOD + 10;
				printf("now is %lu\n",rte_rdtsc()/PERIOD);
				printf("timer set %lu\n",S.expire);
			}
			break;
			
		case TIME_WAIT:
			return 0;
	}
	return 1;
}

static inline int process_packets(struct rte_mbuf *pkt, uint8_t portid, struct rte_mbuf **trans)
{
	struct ether_hdr *eth;
	struct ipv4_hdr *iphdr;
	struct ether_addr loc_addr;
	eth = rte_pktmbuf_mtod(pkt, struct ether_hdr *);	
	rte_eth_macaddr_get(portid,&loc_addr);
	
	*trans = NULL;
	
	if(unlikely(ETHER_TYPE_ARP == rte_be_to_cpu_16(eth->ether_type)))
	{
		struct arp_hdr *arphdr = rte_pktmbuf_mtod_offset(pkt, struct arp_hdr *,sizeof(struct ether_hdr));
		if(rte_cpu_to_be_16(arphdr->arp_op) == ARP_OP_REQUEST && arphdr->arp_data.arp_tip == rte_cpu_to_be_32(my_ip))
		{
			ether_addr_copy(&eth->s_addr,&eth->d_addr);
			ether_addr_copy(&loc_addr,&eth->s_addr);
			
			arphdr->arp_op =rte_cpu_to_be_16(ARP_OP_REPLY);
			
			struct arp_ipv4 *arpdata;
			arpdata = &arphdr->arp_data;	
			ether_addr_copy(&arpdata->arp_sha,&arpdata->arp_tha);
			arpdata->arp_tip = arpdata->arp_sip;
			ether_addr_copy(&loc_addr,&arpdata->arp_sha);
			arpdata->arp_sip = rte_cpu_to_be_32(my_ip);
			
			printf("arp reply\n");
			*trans = pkt;
			return 1;
		}
		goto cleanup;
	}
 
	iphdr = rte_pktmbuf_mtod_offset(pkt, struct ipv4_hdr *,sizeof(struct ether_hdr));
	if(iphdr->next_proto_id == IPPROTO_TCP)
	{
		struct tcp_hdr *tcphdr = (struct tcp_hdr *)((uint8_t *)iphdr + sizeof(struct ipv4_hdr));
		
		if(is_same_ether_addr(&eth->s_addr, &client_mac))
		{
			if(0 == process_tcp(tcphdr, 0))
			{
				goto cleanup;
			}
			ether_addr_copy(&loc_addr, &eth->s_addr);
			ether_addr_copy(&server_mac, &eth->d_addr);

			iphdr->src_addr = iphdr->dst_addr;
			iphdr->dst_addr = rte_cpu_to_be_32(server_ip);
		}
		else if(is_same_ether_addr(&eth->s_addr, &server_mac))
		{
			if(0 == process_tcp(tcphdr, 1))
			{
				goto cleanup;
			}
			ether_addr_copy(&loc_addr, &eth->s_addr);
			ether_addr_copy(&client_mac, &eth->d_addr);

			iphdr->src_addr = iphdr->dst_addr;
			iphdr->dst_addr = rte_cpu_to_be_32(client_ip);
		}
		iphdr->hdr_checksum = 0;
		iphdr->hdr_checksum = rte_ipv4_cksum(iphdr);

		tcphdr->cksum = 0;
		tcphdr->cksum = rte_ipv4_udptcp_cksum(iphdr, (void *)tcphdr);
		*trans = pkt;
		return 1;
	}
cleanup:
	rte_pktmbuf_free(pkt);
	return 0;
}




/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */
static __attribute__((noreturn)) void
lcore_main(void)
{
	const uint8_t nb_ports = rte_eth_dev_count();
	uint8_t port;
	struct rte_mbuf *m = NULL;
	uint64_t begin, now;
	begin = rte_rdtsc();
	int old = S.state;

	/*
	 * Check that the port is on the same NUMA node as the polling thread
	 * for best performance.
	 */
	for (port = 0; port < nb_ports; port++)
		if (rte_eth_dev_socket_id(port) > 0 &&
				rte_eth_dev_socket_id(port) !=
						(int)rte_socket_id())
			printf("WARNING, port %u is on remote NUMA node to "
					"polling thread.\n\tPerformance will "
					"not be optimal.\n", port);

	printf("\nCore %u forwarding packets. [Ctrl+C to quit]\n",
			rte_lcore_id());

	/* Run until the application is quit or killed. */
	for (;;) {
		if(old!=(int)S.state)
		{
			printf("state------%s\n", s_state[(int)S.state]);
			old = S.state;
		}
		
		now = rte_rdtsc();
		if(now - begin >= PERIOD)
		{
			begin = now;
			if(S.expire <= now/PERIOD && S.state == TIME_WAIT)
			{
				S.state = CLOSED;
			}
		}
		
		/*
		 * Receive packets on a port and forward them on the paired
		 * port. The mapping is 0 -> 1, 1 -> 0, 2 -> 3, 3 -> 2, etc.
		 */
		for (port = 0; port < nb_ports; port++) {

			/* Get burst of RX packets, from first port of pair. */
			struct rte_mbuf *bufs[BURST_SIZE];
			struct rte_mbuf *trans[BURST_SIZE];
			const uint16_t nb_rx = rte_eth_rx_burst(port, 0,
					bufs, BURST_SIZE);
					
			//if(nb_rx != 0){printf("recv------%d\n",nb_rx);}

			if (unlikely(nb_rx == 0))
				continue;

			int j, count=0;
			for (j = 0; j < PREFETCH_OFFSET && j < nb_rx; j++)
				rte_prefetch0(rte_pktmbuf_mtod(bufs[j], void *));

			for (j = 0; j < (nb_rx - PREFETCH_OFFSET); j++) {
				rte_prefetch0(rte_pktmbuf_mtod(bufs[j + PREFETCH_OFFSET], void *));
				m = bufs[j];
				rte_prefetch0(rte_pktmbuf_mtod(m, void *));
#if 1
				if(app_pkt_handle(m,now) == 2)
				{
					rte_pktmbuf_free(m);
					continue;
				}
#endif
				count += process_packets(m, port, &trans[count]);
			}
			
			for (; j < nb_rx; j++)
			 {
				m = bufs[j];
				 if(app_pkt_handle(m,now) == 2)
                                {
                                        rte_pktmbuf_free(m);
                                        continue;
                                }
				count += process_packets(bufs[j], port, &trans[count]);
			}

			
			/* Send burst of TX packets, to second port of pair. */
            if(count!=nb_rx){
                printf("-----lose-----%d\n",nb_rx-count);
            }
			const uint16_t nb_tx = rte_eth_tx_burst(port, 0,
					trans, count);
					
			//if(nb_tx != 0){printf("trans------%d\n",nb_tx);}

			/* Free any unsent packets. */
			if (unlikely(nb_tx < count)) {
				uint16_t buf;
				for (buf = nb_tx; buf < count; buf++)
					rte_pktmbuf_free(trans[buf]);
			}
		}
	}
}

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int
main(int argc, char *argv[])
{
	struct rte_mempool *mbuf_pool;
	unsigned nb_ports;
	uint8_t portid;

	/* Initialize the Environment Abstraction Layer (EAL). */
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	argc -= ret;
	argv += ret;

	/* Check that there is an even number of ports to send/receive on. */
	nb_ports = rte_eth_dev_count();

	/* Creates a new mempool in memory to hold the mbufs. */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	/* Initialize all ports. */
	for (portid = 0; portid < nb_ports; portid++)
		if (port_init(portid, mbuf_pool) != 0)
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu8 "\n",
					portid);

	if (rte_lcore_count() > 1)
		printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");
	
	app_configure_flow_table();

	/* Call lcore_main on the master core only. */
	S.state = CLOSED;
	S.expire = 0;
	lcore_main();

	return 0;
}
