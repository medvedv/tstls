/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018 Vladimir Medvedkin <medvedkinv@gmail.com>
 */

#include <getopt.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/stat.h>
#include <rte_common.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_acl.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_byteorder.h>
#include <rte_cycles.h>

#include "acl.h"
#include "cmdline.h"
#include "main.h"

#define MAX_LCORES 8
#define MIN_LCORES 2
#define NB_MBUF	65535
#define MBUF_SIZE (2048 + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM)
#define NB_RXD	512
#define NB_TXD	512

uint64_t tsc_hz;
static uint64_t poll_tsc;
struct rte_mempool *pktmbuf_pool;
int8_t dst_ports[MAX_PORTS];
struct lcore_conf lcore_conf[RTE_MAX_LCORE] __rte_cache_aligned;
struct  ether_addr dst_mac[MAX_PORTS] __rte_cache_aligned;
struct  ether_addr src_mac[MAX_PORTS] __rte_cache_aligned;

struct ports_pair {
	uint16_t sport;
	uint16_t dport;
};

#define OFF_ETHHEAD     (sizeof(struct ether_hdr))
#define OFF_IPV42PROTO (offsetof(struct ipv4_hdr, next_proto_id))

#define MBUF_IPV4_2PROTO(m)						\
	(rte_pktmbuf_mtod((m), uint8_t *) + OFF_ETHHEAD + OFF_IPV42PROTO)


/*
 * RX and TX Prefetch, Host, and Write-back threshold values should be
 * carefully set for optimal performance. Consult the network
 * controller's datasheet and supporting DPDK documentation for guidance
 * on how these parameters should be set.
 */
#define RX_PTHRESH 8 /**< Default values of RX prefetch threshold reg. */
#define RX_HTHRESH 8 /**< Default values of RX host threshold reg. */
#define RX_WTHRESH 4 /**< Default values of RX write-back threshold reg. */

/*
 * These default values are optimized for use with the Intel(R) 82599 10 GbE
 * Controller and the DPDK ixgbe PMD. Consider using other values for other
 * network controllers and/or network drivers.
 */
#define TX_PTHRESH 36 /**< Default values of TX prefetch threshold reg. */
#define TX_HTHRESH 0  /**< Default values of TX host threshold reg. */
#define TX_WTHRESH 0  /**< Default values of TX write-back threshold reg. */

#define BURST_TX_DRAIN_US	100 /* TX drain every ~100us */
#define RX_POLL_US		2  /*  Poll every ~30 pkts @15 Mpps*/
#define PREFETCH_OFFSET		16

static const struct rte_eth_conf port_conf = {
	.rxmode = {
		.mq_mode = ETH_MQ_RX_RSS,
		.split_hdr_size = 0,
		.header_split   = 0, /**< Header Split disabled */
		.hw_ip_checksum = 1, /**< IP checksum offload disabled */
		.hw_vlan_filter = 0, /**< VLAN filtering disabled */
		.jumbo_frame    = 0, /**< Jumbo Frame Support disabled */
		.hw_strip_crc   = 1, /**< CRC stripped by hardware */
	},
        .rx_adv_conf = {
                .rss_conf = {
                        .rss_key = NULL,
                        .rss_hf = ETH_RSS_IP | ETH_RSS_UDP |
                                ETH_RSS_TCP | ETH_RSS_SCTP,
                },
        },
        .txmode = {
                .mq_mode = ETH_MQ_TX_NONE,
	},
};

static const struct rte_eth_rxconf rx_conf = {
	.rx_thresh = {
		.pthresh = RX_PTHRESH,
		.hthresh = RX_HTHRESH,
		.wthresh = RX_WTHRESH,
	},
};

static const struct rte_eth_txconf tx_conf = {
	.tx_thresh = {
		.pthresh = TX_PTHRESH,
		.hthresh = TX_HTHRESH,
		.wthresh = TX_WTHRESH,
	},
	.tx_free_thresh = 0, /* Use PMD default values */
	.tx_rs_thresh = 0, /* Use PMD default values */
};

static void
send_burst(struct lcore_conf *conf, unsigned n, uint8_t port)
{
	struct rte_mbuf **m_table;
	unsigned ret;
	unsigned queue_id = conf->queue_id;

	m_table = (struct rte_mbuf **)conf->tx_mbufs[port].m_table;
	ret = rte_eth_tx_burst(port, (uint16_t) queue_id,
			m_table, (uint16_t) n);
	conf->stats.tx_pkts += ret;
	if (unlikely(ret < n)) {
		do {
			rte_pktmbuf_free(m_table[ret]);
		} while (++ret < n);
	}
}

void
send_packet(struct rte_mbuf *m, struct lcore_conf *conf, uint8_t port)
{
	unsigned len;

	m->l2_len = sizeof(struct ether_hdr);
	m->l3_len = sizeof(struct ipv4_hdr);
	len = conf->len[port];
	conf->tx_mbufs[port].m_table[len] = m;
	len++;
	if (unlikely(len == MAX_PKT_BURST)) {
		send_burst(conf, MAX_PKT_BURST, port);
		len = 0;
	}
	conf->len[port] = len;
}

static inline int
is_valid_ipv4_pkt(struct ipv4_hdr *pkt, uint32_t link_len)
{
	if (unlikely(link_len < sizeof(struct ipv4_hdr)))
		return -1;

	if (unlikely(((pkt->version_ihl) >> 4) != 4))
		return -3;
	/* drop pkts with options */
	if (unlikely((pkt->version_ihl & 0xf) != 5))
		return -4;

	if (unlikely(rte_be_to_cpu_16(pkt->total_length) < sizeof(struct ipv4_hdr)))
		return -5;

	return 0;
}

static inline int
parse_transport(struct ipv4_hdr *ip, uint16_t pkt_len, struct mbuf_ext *ext)
{
	struct ports_pair *ppair;

	switch (ip->next_proto_id) {
	case IPPROTO_TCP:
		if (unlikely((pkt_len - sizeof(struct ipv4_hdr)) < sizeof(struct tcp_hdr)))
			return -1;
		break;
	case IPPROTO_UDP:
		if (unlikely((pkt_len - sizeof(struct ipv4_hdr)) < sizeof(struct udp_hdr)))
			return -1;
		break;
	default:
		return -1;
	}
	ppair = (struct ports_pair *)(ip + 1);
	ext->sport = ppair->sport;
	ext->dport = ppair->dport;

	return 0;
}

static inline int
parse_pkts(struct rte_mbuf **mbuf_arr, int nb_rx)
{
	int i, j;
	struct rte_mbuf *m;
	struct ether_hdr *eth;
	struct ipv4_hdr *ipv4_hdr;
	uint16_t pkt_len;
	struct mbuf_ext *ext;

	for(i = 0, j = 0; i < nb_rx; i++) {
		m = mbuf_arr[i];
		pkt_len = rte_pktmbuf_data_len(m);
		if (unlikely(pkt_len < (sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr)))) {
			rte_pktmbuf_free(m);
			continue;
		}
		eth = rte_pktmbuf_mtod(m, struct ether_hdr *);
		if (unlikely(eth->ether_type != rte_cpu_to_be_16(ETHER_TYPE_IPv4))) {
			rte_pktmbuf_free(m);
			continue;
		}
		ipv4_hdr = (struct ipv4_hdr *)(eth + 1);
		pkt_len -=sizeof(struct ether_hdr);
		if (unlikely(is_valid_ipv4_pkt(ipv4_hdr, pkt_len))) {
			rte_pktmbuf_free(m);
			continue;
		}
		if (unlikely((rte_be_to_cpu_16(ipv4_hdr->fragment_offset) & (IPV4_HDR_OFFSET_MASK|IPV4_HDR_MF_FLAG)) != 0)) {
			rte_pktmbuf_free(m);
			continue;
		}
		if (unlikely(pkt_len != rte_be_to_cpu_16(ipv4_hdr->total_length))) {
			rte_pktmbuf_free(m);
			continue;
		}

		ext = (struct mbuf_ext *)(m + 1);
		ext->proto = ipv4_hdr->next_proto_id;
		ext->sip = ipv4_hdr->src_addr;
		ext->dip = ipv4_hdr->dst_addr;
		ext->pkt_len = ipv4_hdr->total_length;
		ext->ttl = ipv4_hdr->time_to_live;
		if (unlikely(parse_transport(ipv4_hdr, pkt_len, ext) != 0)) {
			rte_pktmbuf_free(m);
			continue;
		}

		mbuf_arr[j++] = m;
	}
	return j;
}

static int
main_loop(__attribute__((unused)) void *dummy)
{
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	const uint8_t *acl_p[MAX_PKT_BURST];
	uint32_t result[MAX_PKT_BURST];
	uint64_t diff_tsc, cur_tsc, prev_tsc;
	uint64_t prev_poll_tsc, diff_poll_tsc;
	int cb, j, lcore_id, port_id, nb_rx;
	struct lcore_conf *conf;
	const uint64_t drain_tsc = (tsc_hz + US_PER_S - 1) / US_PER_S * BURST_TX_DRAIN_US;

	lcore_id = rte_lcore_id();
	conf = &lcore_conf[lcore_id];
	prev_poll_tsc = prev_tsc = 0;

	while (1) {
		cur_tsc = rte_rdtsc();
		conf->tsc = cur_tsc;

		diff_tsc = cur_tsc - prev_tsc;
		if (unlikely(diff_tsc > drain_tsc)) {
			for (port_id = 0; port_id < MAX_PORTS; port_id++) {
				if (conf->len[port_id] == 0)
					continue;
				send_burst(conf, conf->len[port_id], (uint8_t) port_id);
				conf->len[port_id] = 0;
			}
			prev_tsc = cur_tsc;
		}
		diff_poll_tsc = cur_tsc - prev_poll_tsc;
		if (unlikely(diff_poll_tsc < poll_tsc)) {
			continue;
		}
		for (port_id = 0; port_id < MAX_PORTS; port_id++) {
			nb_rx = rte_eth_rx_burst((uint8_t) port_id, conf->queue_id,
						pkts_burst, MAX_PKT_BURST);
			conf->stats.rx_pkts += nb_rx;
			nb_rx = parse_pkts(pkts_burst, nb_rx);
                        for (j = 0; j < nb_rx; j++) {
				acl_p[j] = (uint8_t *)(pkts_burst[j] + 1);
                        }

			rte_acl_classify(acl_ctx, acl_p, result, nb_rx, 1);
			for (j = 0; j < nb_rx; j++) {
				cb = result[j] & ACL_ACTION_MASK;
				if (unlikely(cb >= MAX_ACTIONS)) {
					rte_pktmbuf_free(pkts_burst[j]);
					continue;
				}
				(*acl_callbacks[cb])(pkts_burst[j], result[j], conf, cur_tsc);
			}
		}
		prev_poll_tsc = cur_tsc;
	}
	return 0;
}

static void
init_nic(int nb_fwd_cores) {
	int i, ret, nb_ports, portid;
	struct rte_eth_link link;

	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports != MAX_PORTS)
		rte_exit(EXIT_FAILURE, "Invalid ethernet ports count - bye\n");

	for (portid = 0; portid < nb_ports; portid++) {
		ret = rte_eth_dev_configure(portid, nb_fwd_cores, nb_fwd_cores, &port_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%d\n", ret, portid);

		rte_eth_macaddr_get(portid, &src_mac[portid]);

		for (i = 0; i < nb_fwd_cores; i++) {
			ret = rte_eth_rx_queue_setup(portid, i, NB_RXD, SOCKET0, &rx_conf, pktmbuf_pool);
				if (ret < 0)
					rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup: err=%d\n", ret);
			ret = rte_eth_tx_queue_setup(portid, i, NB_TXD, SOCKET0, &tx_conf);
				if (ret < 0)
					rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup: err=%d\n", ret);
		}

		ret = rte_eth_dev_start(portid);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_dev_start: err=%d\n", ret);

		rte_eth_promiscuous_enable(portid);
		rte_eth_link_get(portid, &link);
		if (link.link_status) {
			printf(" Link Up - speed %u Mbps - %s\n",
				(unsigned) link.link_speed,
				(link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
				("full-duplex") : ("half-duplex\n"));
		} else {
			printf(" Link Down\n");
		}
	}
}

int
main(int argc, char **argv)
{
	int pid, sid;
	int ret, nb_lcores;
	unsigned lcore_id;
	FILE *log_file;

	pid = fork();
	if (pid == -1)
		rte_exit(EXIT_FAILURE, "fork() failed with error %d\n", errno);

	if (pid > 0)
		return 0;

	umask(0);
	sid = setsid();
	if (sid < 0)
		rte_exit(EXIT_FAILURE, "setsid() failed with error %d\n", errno);

	ret = chdir("/");
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "chdir() failed with error %d\n", errno);

	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);

	ret = rte_eal_init(argc, argv);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
	}
	argc -= ret;
	argv += ret;

	log_file = fopen("/var/log/tstls.log", "a+");
	if (log_file == NULL)
		rte_exit(EXIT_FAILURE, "Can not open log file\n");
	rte_openlog_stream(log_file);

	nb_lcores = rte_lcore_count();

	if ((nb_lcores > MAX_LCORES) || (nb_lcores < MIN_LCORES)) {
		rte_exit(EXIT_FAILURE, "Invalid lcores count\n");
	}

	/*init in lcore_conf core roles*/
	memset(lcore_conf, 0, sizeof(struct lcore_conf)*RTE_MAX_LCORE);
	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		if (lcore_id == rte_get_master_lcore())
			continue;
		lcore_conf[lcore_id].queue_id = lcore_id - 1;
	}

	/* Init memory */
	pktmbuf_pool = rte_mempool_create("mbuf_pool", NB_MBUF, MBUF_SIZE,
					MEMPOOL_CACHE_SIZE,
					sizeof(struct rte_pktmbuf_pool_private),
					rte_pktmbuf_pool_init, NULL,
					rte_pktmbuf_init, NULL,
					SOCKET0, 0);
	if (pktmbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");

	init_nic(nb_lcores - 1);
	dst_ports[0] = 1;
	dst_ports[1] = 0;
	tsc_hz = rte_get_tsc_hz();
	poll_tsc = (tsc_hz + US_PER_S - 1) / (US_PER_S * (rte_lcore_count() - 1)) * RX_POLL_US;

	init_acl_config();
	/*init fake acl context*/
	build_empty_acl(&acl_ctx);

	/* launch per-lcore init on every lcore */
	if (rte_eal_mp_remote_launch(main_loop, NULL, SKIP_MASTER) != 0)
		return;

	mgmt();

	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		if (rte_eal_wait_lcore(lcore_id) < 0)
			return -1;
	}
	return 0;
}
