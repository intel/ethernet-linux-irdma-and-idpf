/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2019-2024 Intel Corporation */

/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2022 Intel Corporation */

#ifndef _IDPF_DFT_H_
#define _IDPF_DFT_H_

#define IDPF_DFLT_HW_DIV_S 2	/* default is 4 (shift right 2) */
#define IDPF_MAX_DFT_RULES 10	/* number of rules available */

struct idpf_dft_rule {
	unsigned int pacing;
	u16 port;
};

extern struct idpf_dft_rule idpf_dft_rules[IDPF_MAX_DFT_RULES];
extern u64 idpf_last_tstamp[IDPF_MAX_DFT_RULES];
extern unsigned long idpf_dft_hw_gran;

#define IDPF_DFT_WITHIN_HORIZON 0
#define IDPF_DFT_BEFORE_HORIZON 1
#define IDPF_DFT_BEYOND_HORIZON 2
#define IDPF_DFT_WITHIN_REVERSE 3
extern unsigned int idpf_dft_tstamp_type;
bool idpf_dft_check(struct idpf_vport *vport, struct sk_buff *skb,
		    struct idpf_tx_splitq_params *parms);
void idpf_dft_dump_rules(struct device *dev);
#endif /* _IDPF_DFT_H_ */
