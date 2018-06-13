/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018 Vladimir Medvedkin <medvedkinv@gmail.com>
 */

#include <stdarg.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <termios.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <sys/queue.h>
#include <rte_mbuf.h>
#include <rte_memcpy.h>
#include <rte_atomic.h>
#include <rte_byteorder.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_acl.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <cmdline_rdline.h>
#include <cmdline_parse.h>
#include <cmdline_parse_num.h>
#include <cmdline_parse_string.h>
#include <cmdline_parse_ipaddr.h>
#include <cmdline.h>

#include "cmdline.h"
#include "acl.h"
#include "main.h"

#define TELNET_PORT		9999

struct cmdline_head {
	cmdline_fixed_string_t action;
	cmdline_fixed_string_t target;
};

cmdline_parse_token_string_t cmd_show =
	TOKEN_STRING_INITIALIZER(struct cmdline_head,
				action, "show");
cmdline_parse_token_string_t cmd_show_del =
	TOKEN_STRING_INITIALIZER(struct cmdline_head,
				action, "show#del");
cmdline_parse_token_string_t cmd_del =
	TOKEN_STRING_INITIALIZER(struct cmdline_head,
				action, "del");
cmdline_parse_token_string_t cmd_create =
	TOKEN_STRING_INITIALIZER(struct cmdline_head,
				action, "create");
cmdline_parse_token_string_t cmd_set =
	TOKEN_STRING_INITIALIZER(struct cmdline_head,
				action, "set");

cmdline_parse_token_string_t cmd_policy =
	TOKEN_STRING_INITIALIZER(struct cmdline_head,
				target, "policy");
cmdline_parse_token_string_t cmd_acl =
	TOKEN_STRING_INITIALIZER(struct cmdline_head,
				target, "acl");


#define COLLECT_STAT(counter, field)	do {			\
	counter = 0;						\
	RTE_LCORE_FOREACH_SLAVE(i) {				\
		counter += lcore_conf[i].stats.field;		\
	}							\
} while (0)

#define ACL_CNT_BITMAP_BITS_IN_WORD		3

struct str2int {
	const char	*str;
	int	val;
};

static const struct str2int proto_map[] = {
	{"any", 	0},
	{"tcp", 	6},
	{"udp", 	17},
	{NULL, 		-1},
};

static const char *
int2str(const struct str2int *map, int val)
{
	int i;

	for (i = 0; map[i].str != NULL; i++)
		if (map[i].val == val)
			return map[i].str;
	return NULL;
}

static int
str2int(const struct str2int *map, char *str)
{
	int i;

	for (i = 0; map[i].str != NULL; i++)
		if (strcmp(map[i].str, str) == 0)
			return map[i].val;
	return -1;
}

struct acl_entry {
	LIST_ENTRY(acl_entry)	next;
	uint32_t		idx;
	int32_t			cnt_idx;
	uint32_t		src_ip;
	uint32_t		dst_ip;
	uint16_t		sport_low;
	uint16_t		sport_hi;
	uint16_t		dport_low;
	uint16_t		dport_hi;
	uint16_t		pktlen_low;
	uint16_t		pktlen_hi;
	uint8_t			ttl_low;
	uint8_t			ttl_hi;
	uint8_t			sprefixlen;
	uint8_t			dprefixlen;
	uint8_t			proto;
	uint8_t			action;
};

/* define struct acl_list */
LIST_HEAD(acl_list, acl_entry);

int default_policy = ACCEPT;

struct acl_list global_acl_list;
uint8_t acl_cnt_bitmap[(1 << (ACL_MAX_RULES_BITS - ACL_CNT_BITMAP_BITS_IN_WORD))] = {0};

static inline void
free_acl_cnt_idx(int idx)
{
	idx--;
	acl_cnt_bitmap[(idx >> ACL_CNT_BITMAP_BITS_IN_WORD)] &=
		~(1 << (idx & ((1 << ACL_CNT_BITMAP_BITS_IN_WORD) - 1)));

}

static inline int
get_acl_cnt_idx(void)
{
	uint32_t i, j;

	for (i = 0; i < sizeof(acl_cnt_bitmap); i++) {
		for (j = 0; j < 8; j++) {
			if (!(acl_cnt_bitmap[i] & (1 << j))) {
				acl_cnt_bitmap[i] |= (1 << j);
				return (i << ACL_CNT_BITMAP_BITS_IN_WORD | j) + 1;
			}
		}
	}
	return -ENOENT;
}

static void
cmdline_build_acl(void)
{
	uint64_t tmp;
	int ret, i = 0;
	struct acl4_rule *rules;
	struct acl_entry *ent;
	struct rte_acl_ctx *new_ctx, *tmp_ctx;

	LIST_FOREACH(ent, &global_acl_list, next) {
		i++;
	}
	if (i == 0) {
		build_empty_acl(&new_ctx);
		goto init_acl;
	}

	rules = rte_calloc(NULL, i, sizeof(struct acl4_rule), 0);
	i = 0;
	LIST_FOREACH(ent, &global_acl_list, next) {
		rules[i].data.category_mask			= 1;
		rules[i].data.priority				= RTE_ACL_MAX_PRIORITY - ent->idx;
		rules[i].data.userdata = ent->action | (ent->cnt_idx << ACL_RESULT_RULE_SHIFT);
		rules[i].field[PROTO_FIELD_IPV4].value.u8	= ent->proto;
		if (ent->proto == 0)
			rules[i].field[PROTO_FIELD_IPV4].mask_range.u8  = 0;
		else
			rules[i].field[PROTO_FIELD_IPV4].mask_range.u8	= 0xff;
		rules[i].field[SRC_FIELD_IPV4].value.u32	= rte_be_to_cpu_32(ent->src_ip);
		rules[i].field[SRC_FIELD_IPV4].mask_range.u32	= ent->sprefixlen;
		rules[i].field[DST_FIELD_IPV4].value.u32	= rte_be_to_cpu_32(ent->dst_ip);
		rules[i].field[DST_FIELD_IPV4].mask_range.u32	= ent->dprefixlen;
		rules[i].field[SRCP_FIELD_IPV4].value.u16	= ent->sport_low;
		rules[i].field[SRCP_FIELD_IPV4].mask_range.u16	= ent->sport_hi;
		rules[i].field[DSTP_FIELD_IPV4].value.u16	= ent->dport_low;
		rules[i].field[DSTP_FIELD_IPV4].mask_range.u16	= ent->dport_hi;
		rules[i].field[PKT_LEN].value.u16	= ent->pktlen_low;
		rules[i].field[PKT_LEN].mask_range.u16	= ent->pktlen_hi;
		rules[i].field[TTL_IPV4].value.u16	= ent->ttl_low << 8;
		rules[i].field[TTL_IPV4].mask_range.u16	= ent->ttl_hi << 8;
printf("sp %d - %d dp %d - %d pl %d - %d ttl %d - %d\n", rules[i].field[SRCP_FIELD_IPV4].value.u16, rules[i].field[SRCP_FIELD_IPV4].mask_range.u16,
							rules[i].field[DSTP_FIELD_IPV4].value.u16, rules[i].field[DSTP_FIELD_IPV4].mask_range.u16,
							rules[i].field[PKT_LEN].value.u16, rules[i].field[PKT_LEN].mask_range.u16,
							rules[i].field[TTL_IPV4].value.u16, rules[i].field[TTL_IPV4].mask_range.u16);
		i++;
	}
	ret = acl_create((struct rte_acl_rule *)rules, i, &new_ctx);
	if (ret != 0)
		rte_exit(EXIT_FAILURE, "Failed to create ACL context\n");
	rte_free(rules);

init_acl:
	tmp_ctx = acl_ctx;
	acl_ctx = new_ctx;
	rte_mb();

	RTE_LCORE_FOREACH_SLAVE(i) {
		tmp = lcore_conf[i].tsc;
		while(tmp == *(volatile uint64_t *)&lcore_conf[i].tsc);
	}
	rte_acl_dump(acl_ctx);
	rte_acl_free(tmp_ctx);
}

/* *** SHOW ALL *** */
static void cmd_show_all_parsed(__attribute__((unused)) void *parsed_result,
				struct cmdline *cl,
				__attribute__((unused)) void *data)
{
	struct cmdline_head *res = parsed_result;
	struct acl_entry *acl;
	uint64_t counter = 0;
	int i;

	struct rte_eth_stats stats;

	if (strcmp(res->target, "statistics") == 0) {
		cmdline_printf(cl,	"\r\n Statistic: \r\n");
		COLLECT_STAT(counter, rx_pkts);
		cmdline_printf(cl,	"\t Rx pkts %"PRIu64"\r\n", counter);
		COLLECT_STAT(counter, tx_pkts);
		cmdline_printf(cl,	"\t Tx pkts %"PRIu64"\r\n", counter);
		COLLECT_STAT(counter, bad_csum);
		cmdline_printf(cl,	"\t bad_csum %"PRIu64"\r\n", counter);
		COLLECT_STAT(counter, frags);
		cmdline_printf(cl,	"\t frags %"PRIu64"\r\n", counter);
	} else if (strcmp(res->target, "acl") == 0) {
		cmdline_printf(cl, "\tCounter\tRule Index\tAccess list\r\n");
		LIST_FOREACH(acl, &global_acl_list, next) {
			COLLECT_STAT(counter, acl_stat[acl->cnt_idx]);
			cmdline_printf(cl, "\t%"PRIu64"", counter);
			cmdline_printf(cl, "\t%d %s src "NIPQUAD_FMT"/%d", acl->idx, int2str(proto_map, acl->proto), NIPQUAD(acl->src_ip), acl->sprefixlen);
			cmdline_printf(cl, " dst "NIPQUAD_FMT"/%d", NIPQUAD(acl->dst_ip), acl->dprefixlen);
			cmdline_printf(cl, " sport_range %d %d", acl->sport_low, acl->sport_hi);
			cmdline_printf(cl, " dport_range %d %d", acl->dport_low, acl->dport_hi);
			cmdline_printf(cl, " pktlen_range %d %d", acl->pktlen_low, acl->pktlen_hi);
			cmdline_printf(cl, " ttl_range %d %d", acl->ttl_low, acl->ttl_hi);
			if (acl->action == DROP) {
				cmdline_printf(cl, " drop\r\n");
			} else if (acl->action == ACCEPT) {
				 cmdline_printf(cl, " accept\r\n");
			}
		}
	} else if (strcmp(res->target, "policy") == 0) {
		COLLECT_STAT(counter, acl_stat[0]);
		switch (default_policy) {
		case DROP:
			cmdline_printf(cl, "\t %"PRIu64"\t DROP policy\r\n", counter);
			break;
		case ACCEPT:
			cmdline_printf(cl, "\t %"PRIu64"\t ACCEPT policy\r\n", counter);
			break;
		default:
			cmdline_printf(cl, "\t Unknown policy\r\n");
			break;
		}
	} else if (strcmp(res->target, "interface_stats") == 0) {
		for (i = 0; i < MAX_PORTS; i++) {
			rte_eth_stats_get(i, &stats);
			cmdline_printf(cl,      "Port %d :\r\n", i);
			cmdline_printf(cl,      "\tRX pkts %"PRIu64" :\r\n", stats.ipackets);
			cmdline_printf(cl,      "\tTX pkts %"PRIu64" :\r\n", stats.opackets);
			cmdline_printf(cl,      "\tRX bytes %"PRIu64" :\r\n", stats.ibytes);
			cmdline_printf(cl,      "\tTX bytes %"PRIu64" :\r\n", stats.obytes);
			cmdline_printf(cl,      "\tRX missed %"PRIu64" :\r\n", stats.imissed);
			cmdline_printf(cl,      "\tRX errors %"PRIu64" :\r\n", stats.ierrors);
			cmdline_printf(cl,      "\tTX errors %"PRIu64" :\r\n", stats.oerrors);
			cmdline_printf(cl,      "\tRX no mbuf %"PRIu64" :\r\n", stats.rx_nombuf);
		}
	}
}

cmdline_parse_token_string_t cmd_all_target =
	TOKEN_STRING_INITIALIZER(struct cmdline_head, target,
		"statistics#acl#policy#interface_stats");

cmdline_parse_inst_t cmd_show_all = {
	.f = cmd_show_all_parsed,
	.data = NULL,
	.help_str = "Show system information",
	.tokens = {
		(void *)&cmd_show,
		(void *)&cmd_all_target,
		NULL,
	},
};

/* *** END OF SHOW ALL *** */

/* *** SET DEFAULT ACL POLICY *** */
struct cmd_set_acl_policy {
	struct cmdline_head	head;
	cmdline_fixed_string_t	policy;
};

static void cmd_set_acl_policy_parsed(void *parsed_result,
				struct cmdline *cl,
				__attribute__((unused)) void *data)
{
	struct cmd_set_acl_policy *res = parsed_result;

	if (strcmp(res->policy, "accept") == 0) {
		default_policy = ACCEPT;
		acl_callbacks[0] = acl_accept;
		cmdline_printf(cl, "\tDefault ACL policy ACCEPT\r\n");
		return;
	} else if (strcmp(res->policy, "drop") == 0) {
		default_policy = DROP;
		acl_callbacks[0] = acl_drop;
		cmdline_printf(cl, "\tDefault ACL policy DROP\r\n");
		return;
	}
}

cmdline_parse_token_string_t cmd_set_policy =
	TOKEN_STRING_INITIALIZER(struct cmd_set_acl_policy,
				policy, "accept#drop");

cmdline_parse_inst_t cmd_set_acl_policy = {
	.f = cmd_set_acl_policy_parsed,
	.data = NULL,
	.help_str = "Set default ACL policy",
	.tokens = {
		(void *)&cmd_set,
		(void *)&cmd_policy,
		(void *)&cmd_set_policy,
		NULL,
	},
};

/* *** END OF DEFAULT ACL POLICY *** */

/* *** SET ACL *** */
struct cmd_set_acl_params {
	struct cmdline_head	head;
	uint16_t		idx;
	cmdline_fixed_string_t	src_ip;
	cmdline_fixed_string_t	dst_ip;
	cmdline_fixed_string_t	sport_range;
	cmdline_fixed_string_t	dport_range;
	cmdline_fixed_string_t	action;
	cmdline_fixed_string_t	proto;
	cmdline_ipaddr_t	sprefix;
	cmdline_ipaddr_t	dprefix;
	uint16_t                sport_low;
	uint16_t                sport_hi;
	uint16_t                dport_low;
	uint16_t                dport_hi;
	uint16_t                pktlen_low;
	uint16_t                pktlen_hi;
	uint8_t		ttl_low;
	uint8_t		ttl_hi;
};

static void cmd_set_acl_parsed(void *parsed_result,
				struct cmdline *cl,
				__attribute__((unused)) void *data)
{
	struct cmd_set_acl_params *res = parsed_result;
	struct acl_entry *ent, *prev, *new_ent = NULL;

	if ((res->sport_low > res->sport_hi) || (res->dport_low > res->dport_hi)) {
		cmdline_printf(cl, "Bad arguments\r\n");
		return;
	}
	new_ent = rte_zmalloc(NULL, sizeof(*new_ent), RTE_CACHE_LINE_SIZE);
	if (new_ent == NULL) {
		cmdline_printf(cl, "\tNot enough memory\r\n");
		return;
	}
	if ((new_ent->cnt_idx = get_acl_cnt_idx()) < 0) {
		cmdline_printf(cl, "\tNo counter space\r\n");
		rte_free(new_ent);
		return;
	}
	if LIST_EMPTY(&global_acl_list) {
		LIST_INSERT_HEAD(&global_acl_list, new_ent, next);
	} else {
		LIST_FOREACH(ent, &global_acl_list, next) {
			prev = ent;
			if (ent->idx == res->idx) {
				cmdline_printf(cl, "\tACL index %d is occupied\r\n", res->idx);
				free_acl_cnt_idx(new_ent->cnt_idx);
				rte_free(new_ent);
				return;
			}
			if (ent->idx > res->idx) {
				LIST_INSERT_BEFORE(ent, new_ent, next);
				goto init_new_ent;
			}
		}
		LIST_INSERT_AFTER(prev, new_ent, next);
	}

init_new_ent:
	new_ent->idx		= res->idx;
	new_ent->src_ip		= (res->sprefix.addr.ipv4.s_addr) & ~(rte_cpu_to_be_32((uint32_t)(((1ULL << (32 - res->sprefix.prefixlen)) - 1))));
	new_ent->dst_ip		= (res->dprefix.addr.ipv4.s_addr) & ~(rte_cpu_to_be_32((uint32_t)(((1ULL << (32 - res->dprefix.prefixlen)) - 1))));
	new_ent->sport_low	= res->sport_low;
	new_ent->sport_hi	= res->sport_hi;
	new_ent->dport_low	= res->dport_low;
	new_ent->dport_hi	= res->dport_hi;
	new_ent->pktlen_low	= res->pktlen_low;
	new_ent->pktlen_hi	= res->pktlen_hi;
	new_ent->ttl_low	= res->ttl_low;
	new_ent->ttl_hi		= res->ttl_hi;
	new_ent->sprefixlen	= res->sprefix.prefixlen;
	new_ent->dprefixlen	= res->dprefix.prefixlen;
	if (strcmp(res->action, "drop") == 0) {
		new_ent->action		= DROP;
	} else if (strcmp(res->action, "accept") == 0) {
		new_ent->action		= ACCEPT;
	}
	new_ent->proto = str2int(proto_map, res->proto);
	cmdline_build_acl();
}

cmdline_parse_token_num_t cmd_set_acl_idx =
	TOKEN_NUM_INITIALIZER(struct cmd_set_acl_params, idx, UINT16);

cmdline_parse_token_string_t cmd_set_acl_src_ip =
	TOKEN_STRING_INITIALIZER(struct cmd_set_acl_params,
				src_ip, "src");

cmdline_parse_token_string_t cmd_set_acl_dst_ip =
	TOKEN_STRING_INITIALIZER(struct cmd_set_acl_params,
				dst_ip, "dst");

cmdline_parse_token_string_t cmd_set_acl_sport_range =
	TOKEN_STRING_INITIALIZER(struct cmd_set_acl_params,
				sport_range, "sport_range");

cmdline_parse_token_string_t cmd_set_acl_dport_range =
	TOKEN_STRING_INITIALIZER(struct cmd_set_acl_params,
				dport_range, "dport_range");

cmdline_parse_token_string_t cmd_set_acl_pktlen_range =
	TOKEN_STRING_INITIALIZER(struct cmd_set_acl_params,
				dport_range, "pktlen_range");

cmdline_parse_token_string_t cmd_set_acl_ttl_range =
	TOKEN_STRING_INITIALIZER(struct cmd_set_acl_params,
				dport_range, "ttl_range");

cmdline_parse_token_string_t cmd_set_acl_action =
	TOKEN_STRING_INITIALIZER(struct cmd_set_acl_params,
				action, "accept#drop");

cmdline_parse_token_string_t cmd_set_acl_proto =
	TOKEN_STRING_INITIALIZER(struct cmd_set_acl_params,
				proto, "any#tcp#udp");

cmdline_parse_token_ipaddr_t cmd_set_acl_sprefix =
	TOKEN_IPV4NET_INITIALIZER(struct cmd_set_acl_params, sprefix);

cmdline_parse_token_ipaddr_t cmd_set_acl_dprefix =
	TOKEN_IPV4NET_INITIALIZER(struct cmd_set_acl_params, dprefix);

cmdline_parse_token_num_t cmd_set_acl_sport_low =
	TOKEN_NUM_INITIALIZER(struct cmd_set_acl_params, sport_low, UINT16);

cmdline_parse_token_num_t cmd_set_acl_sport_hi =
	TOKEN_NUM_INITIALIZER(struct cmd_set_acl_params, sport_hi, UINT16);

cmdline_parse_token_num_t cmd_set_acl_dport_low =
	TOKEN_NUM_INITIALIZER(struct cmd_set_acl_params, dport_low, UINT16);

cmdline_parse_token_num_t cmd_set_acl_dport_hi =
	TOKEN_NUM_INITIALIZER(struct cmd_set_acl_params, dport_hi, UINT16);

cmdline_parse_token_num_t cmd_set_acl_pktlen_low =
	TOKEN_NUM_INITIALIZER(struct cmd_set_acl_params, pktlen_low, UINT16);

cmdline_parse_token_num_t cmd_set_acl_pktlen_hi =
	TOKEN_NUM_INITIALIZER(struct cmd_set_acl_params, pktlen_hi, UINT16);

cmdline_parse_token_num_t cmd_set_acl_ttl_low =
	TOKEN_NUM_INITIALIZER(struct cmd_set_acl_params, ttl_low, UINT8);

cmdline_parse_token_num_t cmd_set_acl_ttl_hi =
	TOKEN_NUM_INITIALIZER(struct cmd_set_acl_params, ttl_hi, UINT8);

cmdline_parse_inst_t cmd_set_acl = {
	.f = cmd_set_acl_parsed,
	.data = NULL,
	.help_str = "Set ACL entry",
	.tokens = {
		(void *)&cmd_set,
		(void *)&cmd_acl,
		(void *)&cmd_set_acl_idx,
		(void *)&cmd_set_acl_proto,
		(void *)&cmd_set_acl_src_ip,
		(void *)&cmd_set_acl_sprefix,
		(void *)&cmd_set_acl_dst_ip,
		(void *)&cmd_set_acl_dprefix,
		(void *)&cmd_set_acl_sport_range,
		(void *)&cmd_set_acl_sport_low,
		(void *)&cmd_set_acl_sport_hi,
		(void *)&cmd_set_acl_dport_range,
		(void *)&cmd_set_acl_dport_low,
		(void *)&cmd_set_acl_dport_hi,
		(void *)&cmd_set_acl_pktlen_range,
		(void *)&cmd_set_acl_pktlen_low,
		(void *)&cmd_set_acl_pktlen_hi,
		(void *)&cmd_set_acl_ttl_range,
		(void *)&cmd_set_acl_ttl_low,
		(void *)&cmd_set_acl_ttl_hi,
		(void *)&cmd_set_acl_action,
		NULL,
	},
};

/* *** END OF SET ACL *** */

/* *** DEL ACL *** */
struct cmd_del_acl_params {
	struct cmdline_head	head;
	uint16_t		idx;
};

static void cmd_del_acl_parsed(void *parsed_result,
				struct cmdline *cl,
				__attribute__((unused)) void *data)
{
	struct cmd_del_acl_params *res = parsed_result;
	struct acl_entry *ent;
	int i;

	if LIST_EMPTY(&global_acl_list) {
		cmdline_printf(cl, "\tACL index %d not exist\r\n", res->idx);
		return;
	}
	LIST_FOREACH(ent, &global_acl_list, next) {
		if (ent->idx == res->idx) {
			LIST_REMOVE(ent, next);
			RTE_LCORE_FOREACH_SLAVE(i) {
				lcore_conf[i].stats.acl_stat[ent->cnt_idx] = 0;
			}
			free_acl_cnt_idx(ent->cnt_idx);
			rte_free(ent);
			cmdline_build_acl();
			cmdline_printf(cl, "\tACL index %d deleted\r\n", res->idx);
			return;
		}
	}
	cmdline_printf(cl, "\tACL index %d not found\r\n", res->idx);
}

cmdline_parse_token_num_t cmd_del_acl_idx =
	TOKEN_NUM_INITIALIZER(struct cmd_del_acl_params, idx, UINT16);

cmdline_parse_inst_t cmd_del_acl = {
	.f = cmd_del_acl_parsed,
	.data = NULL,
	.help_str = "Delete ACL entry",
	.tokens = {
		(void *)&cmd_del,
		(void *)&cmd_acl,
		(void *)&cmd_del_acl_idx,
		NULL,
	},
};

/* *** END OF DEL ACL *** */

/* *** QUIT *** */

struct cmd_quit_result {
	cmdline_fixed_string_t quit;
};

static void cmd_quit_parsed(__attribute__((unused)) void *parsed_result,
				struct cmdline *cl,
				__attribute__((unused)) void *data)
{
	cmdline_quit(cl);
}

cmdline_parse_token_string_t cmd_quit_token =
	TOKEN_STRING_INITIALIZER(struct cmd_quit_result, quit, "quit");

cmdline_parse_inst_t cmd_quit = {
	.f = cmd_quit_parsed,
	.data = NULL,
	.help_str = "Quit",
	.tokens = {
		(void *)&cmd_quit_token,
		NULL,
	},
};

/* *** END OF QUIT *** */

/* *** MAIN CONTEXT *** */

static cmdline_parse_ctx_t main_ctx[] = {
	(cmdline_parse_inst_t *)&cmd_show_all,
	(cmdline_parse_inst_t *)&cmd_set_acl_policy,
	(cmdline_parse_inst_t *)&cmd_set_acl,
	(cmdline_parse_inst_t *)&cmd_del_acl,
	(cmdline_parse_inst_t *)&cmd_quit,
	NULL,
};

void * cmdline_thread(void *);

void *
cmdline_thread(void *arg)
{
	struct cmdline *cl;
	int ret;
	uint8_t telnet_opt[] = {0xff, 0xfb, 0x03, 0xff, 0xfb, 0x01};
	char thread_name[RTE_MAX_THREAD_NAME_LEN];

	cl = (struct cmdline *)arg;

	snprintf(thread_name, RTE_MAX_THREAD_NAME_LEN, "Purifier CLI");
	rte_thread_setname(pthread_self(), thread_name);
	ret = send(cl->s_out, telnet_opt, sizeof(telnet_opt), 0);
		if (ret != sizeof(telnet_opt))
			rte_exit(EXIT_FAILURE, "Can not init telnet session\n");

	cmdline_interact(cl);
	cmdline_free(cl);
	return NULL;
}

void
mgmt(void)
{
	int sockfd, newsockfd, ret;
	struct sockaddr_in serv_addr, cl_addr;
	socklen_t socklen;
	pthread_t tid;
	struct cmdline *cl;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0)
		rte_exit(EXIT_FAILURE, "can not create socket, eeror %d\n", errno);

	ret = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int));
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "setsockopt failed with error %d\n", errno);

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(TELNET_PORT);

	if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
		rte_exit(EXIT_FAILURE, "ERROR on binding with error %d\n", errno);

	if (listen(sockfd,5) < 0)
		rte_exit(EXIT_FAILURE, "ERROR on listen with error %d\n", errno);

	socklen = sizeof(cl_addr);

	while(1) {
		newsockfd = accept(sockfd, (struct sockaddr *) &cl_addr, &socklen);
		if (newsockfd == -1) {
			RTE_LOG(ERR, USER1, "accept failed with error %d\n", errno);
			continue;
		}

		cl = cmdline_new(main_ctx, "ololo> ", newsockfd, newsockfd);
		if (cl == NULL)
			rte_exit(EXIT_FAILURE, "Can not allocate memory for command line\n");

		ret = pthread_create(&tid, NULL, cmdline_thread, cl);
		if (ret)
			rte_exit(EXIT_FAILURE, "Thread create failed\n");

		ret = pthread_detach(tid);
		if (ret)
			rte_exit(EXIT_FAILURE, "Thread detach failed\n");

	}
}
