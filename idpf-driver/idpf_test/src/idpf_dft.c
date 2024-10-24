/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2019-2024 Intel Corporation */

// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2022 Intel Corporation */

#include "idpf.h"

#define NO_DFT_IDX -1		/* invalid index */

struct idpf_dft_rule idpf_dft_rules[IDPF_MAX_DFT_RULES] = {{0}};
u64 idpf_last_tstamp[IDPF_MAX_DFT_RULES] = {0};
unsigned int idpf_dft_tstamp_type;

#define DFLT_FG_SLOT_NS 2048
unsigned long idpf_dft_hw_gran = DFLT_FG_SLOT_NS >> IDPF_DFLT_HW_DIV_S;

/* Dump all the rules to dmesg */
void idpf_dft_dump_rules(struct device *dev)
{
	unsigned int i;

	dev_info(dev, "HW Granularity: %lu ns\n", idpf_dft_hw_gran);
	dev_info(dev, "Fine-Grained Slot Size: %lu us\n",
		 (idpf_dft_hw_gran << IDPF_DFLT_HW_DIV_S) / 1024);
	dev_info(dev, "Timestamp type = %d\n", idpf_dft_tstamp_type);

	for (i = 0; i < IDPF_MAX_DFT_RULES; i++) {
		dev_info(dev, "%u: Port %u Pacing %u\n",
			 i, idpf_dft_rules[i].port,
			 idpf_dft_rules[i].pacing);
	}
}

/* Returns -1 if no rule found, otherwise return rule index */
static int idpf_dft_rule_idx(u16 port)
{
	unsigned int i;

	for (i = 0; i < IDPF_MAX_DFT_RULES; i++) {
		u16 dft_port = idpf_dft_rules[i].port;

		if (!dft_port)
			break;
		if (port == dft_port)
			return i;
	}
	return NO_DFT_IDX;
}

/* Returns -1 if no rule found, otherwise return rule index.
 * Must be called with an skb for a TCP packet.
 */
static int idpf_dft_rule_idx_tcp(struct sk_buff *skb)
{
	struct tcphdr *tcp = tcp_hdr(skb);

	return idpf_dft_rule_idx(ntohs(tcp->dest));
}

/* Returns -1 if no rule found, otherwise return rule index.
 * Must be called with an skb for a UDP packet.
 */
static int idpf_dft_rule_idx_udp(struct sk_buff *skb)
{
	struct udphdr *udp = udp_hdr(skb);

	return idpf_dft_rule_idx(ntohs(udp->dest));
}

/* Return time in nanoseconds */
static unsigned long idpf_get_timestamp(void)
{
	return ktime_get_real_ns();
}

/* Convert nanoseconds to expected hardware granularity */
static inline unsigned long idpf_ns_to_hw_gran(unsigned long ns)
{
	return ns / idpf_dft_hw_gran;
}

/* Based on the now time, estimate start time of 1st packet in reverse order */
static inline u64 idpf_reverse_start_time(u64 now, u32 pacing)
{
	return now + (20 * pacing);
}

/* Grab timestamp or add pacing if existing */
static void idpf_set_hw_tstamp(struct idpf_vport *vport, struct sk_buff *skb,
			       int idx, struct idpf_tx_splitq_params *parms)
{
	struct idpf_adapter *adapter = vport->adapter;
	u32 pacing = idpf_dft_rules[idx].pacing;
	u64 now = 0;

	if (adapter->dev_ops.reg_ops.read_master_time)
		now = adapter->dev_ops.reg_ops.read_master_time(&adapter->hw);
	else
		now = idpf_get_timestamp();

	if (idpf_dft_tstamp_type == IDPF_DFT_BEFORE_HORIZON)
		idpf_last_tstamp[idx] = now - vport->tw_horizon;
	else if (idpf_dft_tstamp_type == IDPF_DFT_BEYOND_HORIZON)
		idpf_last_tstamp[idx] = now + 2 * vport->tw_horizon;
	else if (idpf_dft_tstamp_type == IDPF_DFT_WITHIN_REVERSE)
		/* The "Reverse" scheme attempts to place the first packet in
		 * the future time (currently, now + 20 * pacing time),
		 * then each subsequent packet is paced at an earlier time
		 * until the previous packet was before the now time, and then
		 * the cycle begins again. If 1st packet's future time is chosen
		 * too far from curent time, it may cause iperf connection issue
		 */
		if (idpf_last_tstamp[idx] < now)
			idpf_last_tstamp[idx] = idpf_reverse_start_time(now,
									pacing);
		else
			idpf_last_tstamp[idx] -= idpf_dft_rules[idx].pacing;
	else if (!idpf_last_tstamp[idx])
		idpf_last_tstamp[idx] = now;
	else
		idpf_last_tstamp[idx] = max(now, idpf_dft_rules[idx].pacing +
					    idpf_last_tstamp[idx]);

#ifdef HAVE_ETF_SUPPORT
	/* SKB timestamp changed around the time ETF support was added */
	skb->skb_mstamp_ns = idpf_last_tstamp[idx];

	pr_info("Hit rule: %d now: %llu time: %llu timestamp: %llu\n", idx, now,
		idpf_last_tstamp[idx], skb->skb_mstamp_ns);
#else
	skb->tstamp = (ktime_t)idpf_last_tstamp[idx];

	pr_info("Hit rule: %d now: %llu time: %llu timestamp: %llu\n", idx, now,
		idpf_last_tstamp[idx], skb->tstamp);
#endif /* HAVE_ETF_SUPPORT */
}

bool idpf_dft_check(struct idpf_vport *vport, struct sk_buff *skb,
		    struct idpf_tx_splitq_params *parms)
{
	struct skb_shared_hwtstamps hwtstamps;
	struct iphdr *iphdr;
	int idx;

	/* Currently only works with IPv4, but IPv6 support can be added if
	 * required.
	 */
	if (skb->protocol != htons(ETH_P_IP))
		return false;
	iphdr = ip_hdr(skb);
	if (iphdr->protocol == IPPROTO_TCP)
		idx = idpf_dft_rule_idx_tcp(skb);
	else if (iphdr->protocol == IPPROTO_UDP)
		idx = idpf_dft_rule_idx_udp(skb);
	else
		return false;

	if (idx == NO_DFT_IDX)
		return false;
	idpf_set_hw_tstamp(vport, skb, idx, parms);
	hwtstamps.hwtstamp = ns_to_ktime(idpf_last_tstamp[idx]);
	skb_tstamp_tx(skb, &hwtstamps);
	return true;
}
