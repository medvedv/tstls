/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018 Vladimir Medvedkin <medvedkinv@gmail.com>
 */

#ifndef _ACL_H_
#define _ACL_H_

struct lcore_conf;

#define ACL_NAME			32

#define ACL_MAX_ACTIONS_BITS		3
#define ACL_MAX_ACTIONS			(1 << ACL_MAX_ACTIONS_BITS)
#define ACL_ACTION_MASK			(ACL_MAX_ACTIONS - 1)

#define ACL_MAX_RULES_BITS		10
#define ACL_MAX_RULES			(1 << ACL_MAX_RULES_BITS)
#define ACL_RESULT_RULE_MASK		(ACL_MAX_RULES - 1)
#define ACL_RESULT_RULE_SHIFT		(ACL_MAX_ACTIONS_BITS)

#define DEFAULT_MAX_CATEGORIES		1

enum {
	DEFAULT_POLICY = 0,
	DROP,
	ACCEPT,
	MAX_ACTIONS
};

struct mbuf_ext {
	uint8_t proto;
	uint32_t sip;
	uint32_t dip;
	uint16_t sport;
	uint16_t dport;
	uint16_t pkt_len;
	uint8_t ttl;
};

extern struct rte_acl_ctx *acl_ctx;
extern int acl_version;
extern struct rte_acl_param acl_param;
extern struct rte_acl_config acl_build_param;

typedef void (*acl_callback_fn_t)(struct rte_mbuf *m, uint32_t result, struct lcore_conf *conf, uint64_t time);

void acl_drop(struct rte_mbuf *m, uint32_t result, struct lcore_conf *conf, uint64_t time);

void acl_accept(struct rte_mbuf *m, uint32_t result, struct lcore_conf *conf, uint64_t time);

void init_acl_config(void);

int acl_create(struct rte_acl_rule *acl_rules, int acl_num, struct rte_acl_ctx **ctx);

void build_empty_acl(struct rte_acl_ctx **ctx);

extern acl_callback_fn_t acl_callbacks[];

enum {
	PROTO_FIELD_IPV4,
	SRC_FIELD_IPV4,
	DST_FIELD_IPV4,
	SRCP_FIELD_IPV4,
	DSTP_FIELD_IPV4,
	PKT_LEN,
	TTL_IPV4,
	NUM_FIELDS_IPV4
};

RTE_ACL_RULE_DEF(acl4_rule, NUM_FIELDS_IPV4);

#endif /* _ACL_H_ */
