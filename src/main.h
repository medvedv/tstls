/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018 Vladimir Medvedkin <medvedkinv@gmail.com>
 */

#ifndef _MAIN_H_
#define _MAIN_H_

int main(int argc, char **argv);

#define ARRAY_SIZE(x)	(sizeof(x)/sizeof(x[0]))
#define MAX_PKT_BURST	32
#define MAX_PORTS		2
#define MEMPOOL_CACHE_SIZE	256
#define SOCKET0		0

#ifndef NIPQUAD
#define NIPQUAD_FMT "%u.%u.%u.%u"
#define NIPQUAD(addr)				\
	(unsigned)((unsigned char *)&addr)[0],	\
	(unsigned)((unsigned char *)&addr)[1],	\
	(unsigned)((unsigned char *)&addr)[2],	\
	(unsigned)((unsigned char *)&addr)[3]
#endif

struct lcore_stats {
	uint64_t rx_pkts;
	uint64_t tx_pkts;
	uint64_t bad_csum;
	uint64_t frags;
	uint64_t acl_stat[ACL_MAX_RULES];
} __rte_cache_aligned;

struct mbuf_table {
	struct rte_mbuf *m_table[MAX_PKT_BURST];
};

struct lcore_conf {
	uint8_t		queue_id;
	uint32_t	len[MAX_PORTS];
	uint64_t	tsc;
	struct mbuf_table	tx_mbufs[MAX_PORTS] __rte_cache_aligned;
	struct lcore_stats	stats __rte_cache_aligned;
} __rte_cache_aligned;

extern struct lcore_conf lcore_conf[RTE_MAX_LCORE] __rte_cache_aligned;
extern int8_t dst_ports[MAX_PORTS];

void send_packet(struct rte_mbuf *m, struct lcore_conf *conf, uint8_t port);

#endif /* _MAIN_H_ */
