/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018 Vladimir Medvedkin <medvedkinv@gmail.com>
 */

#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_acl.h>

#include "acl.h"
#include "main.h"

static const struct rte_acl_field_def ipv4_defs[NUM_FIELDS_IPV4] = {
	{
		.type = RTE_ACL_FIELD_TYPE_BITMASK,
		.size = sizeof(uint8_t),
		.field_index = PROTO_FIELD_IPV4,
		.input_index = 0,
		.offset = 0,
	},
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof(uint32_t),
		.field_index = SRC_FIELD_IPV4,
		.input_index = 1,
		.offset = offsetof(struct mbuf_ext, sip),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof(uint32_t),
		.field_index = DST_FIELD_IPV4,
		.input_index = 2,
		.offset = offsetof(struct mbuf_ext, dip),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_RANGE,
		.size = sizeof(uint16_t),
		.field_index = SRCP_FIELD_IPV4,
		.input_index = 3,
		.offset = offsetof(struct mbuf_ext, sport),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_RANGE,
		.size = sizeof(uint16_t),
		.field_index = DSTP_FIELD_IPV4,
		.input_index = 3,
		.offset = offsetof(struct mbuf_ext, dport),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_RANGE,
		.size = sizeof(uint16_t),
		.field_index = PKT_LEN,
		.input_index = 4,
		.offset = offsetof(struct mbuf_ext, pkt_len),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_RANGE,
		.size = sizeof(uint16_t),
		.field_index = TTL_IPV4,
		.input_index = 4,
		.offset = offsetof(struct mbuf_ext, ttl),
	},
};

acl_callback_fn_t acl_callbacks[] = { acl_accept, acl_drop, acl_accept};

struct rte_acl_ctx *acl_ctx;
int acl_version = 0;
struct rte_acl_param acl_param;
struct rte_acl_config acl_build_param;

void
acl_drop(struct rte_mbuf *m, uint32_t result, struct lcore_conf *conf, __attribute__((unused)) uint64_t time)
{
	++conf->stats.acl_stat[(result >> ACL_RESULT_RULE_SHIFT) & ACL_RESULT_RULE_MASK];
	rte_pktmbuf_free(m);
}

void
acl_accept(struct rte_mbuf *m, uint32_t result, struct lcore_conf *conf, __attribute__((unused)) uint64_t time)
{
	++conf->stats.acl_stat[(result >> ACL_RESULT_RULE_SHIFT) & ACL_RESULT_RULE_MASK];
	send_packet(m, conf, dst_ports[m->port]);
}

void
init_acl_config(void)
{
	acl_param.socket_id		= SOCKET0;
	acl_param.rule_size		= RTE_ACL_RULE_SZ(RTE_DIM(ipv4_defs));
	acl_param.max_rule_num		= ACL_MAX_RULES;
	acl_build_param.num_categories	= DEFAULT_MAX_CATEGORIES;
	acl_build_param.num_fields	= RTE_DIM(ipv4_defs);
	memcpy(&acl_build_param.defs, ipv4_defs, sizeof(ipv4_defs));
}

int
acl_create(struct rte_acl_rule *acl_rules, int acl_num, struct rte_acl_ctx **ctx)
{
	int ret = 0;
	char name[ACL_NAME];

	acl_version++;
	snprintf(name, sizeof(name), "acl_%d", acl_version);

	acl_param.name = name;
	*ctx = rte_acl_create(&acl_param);
	if (*ctx == NULL)
		return -ENOENT;

	if (acl_num > 0) {
		ret = rte_acl_add_rules(*ctx, acl_rules, acl_num);
		if (ret < 0) {
			rte_acl_free(*ctx);
			return ret;
		}
	}

	ret = rte_acl_build(*ctx, &acl_build_param);
	if (ret != 0)
		rte_acl_free(*ctx);

	return ret;
}

void
build_empty_acl(struct rte_acl_ctx **ctx)
{
	int ret;
	struct acl4_rule *rules = rte_calloc(NULL, 1, sizeof(struct acl4_rule), 0);

	rules->data.category_mask = 1;
	rules->data.priority = RTE_ACL_MAX_PRIORITY - 1;
	rules->data.userdata = 1 << (ACL_RESULT_RULE_SHIFT + ACL_MAX_RULES_BITS);
	rules->field[PROTO_FIELD_IPV4].value.u8       = 0;
	rules->field[PROTO_FIELD_IPV4].mask_range.u8  = 0;
	rules->field[SRC_FIELD_IPV4].value.u32        = IPv4(0, 0, 0, 0);
	rules->field[SRC_FIELD_IPV4].mask_range.u32   = 0;
	rules->field[DST_FIELD_IPV4].value.u32        = IPv4(0, 0, 0, 0);
	rules->field[DST_FIELD_IPV4].mask_range.u32   = 0;
	rules->field[SRCP_FIELD_IPV4].value.u16       = 0;
	rules->field[SRCP_FIELD_IPV4].mask_range.u16  = 65535;
	rules->field[DSTP_FIELD_IPV4].value.u16       = 0;
	rules->field[DSTP_FIELD_IPV4].mask_range.u16  = 65535;
	rules->field[PKT_LEN].value.u16       = 0;
	rules->field[PKT_LEN].mask_range.u16  = 65535;
	rules->field[TTL_IPV4].value.u16       = 0;
	rules->field[TTL_IPV4].mask_range.u16  = 65535;

	ret = acl_create((struct rte_acl_rule *)rules, 1, ctx);
	if (ret != 0)
		rte_exit(EXIT_FAILURE, "Failed to create ACL context\n");
	rte_free(rules);
}
