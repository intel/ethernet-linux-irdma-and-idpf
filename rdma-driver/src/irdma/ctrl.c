// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2015 - 2025 Intel Corporation */
#include "osdep.h"
#include "hmc.h"
#include "defs.h"
#include "type.h"
#include "ws.h"
#include "protos.h"
#include "virtchnl.h"

extern bool irdma_rca_ena;
extern bool irdma_rca_rq_post;
extern bool irdma_rca_rq_polarity;

static bool irdma_rca_rq_posted;

/**
 * hmc_obj_name - return name from hmc resource type
 * @type: resource type whose name to return
 */
static char *hmc_obj_name(enum irdma_hmc_rsrc_type type)
{
	switch (type) {
	case IRDMA_HMC_IW_QP:
		return "QP:";
	case IRDMA_HMC_IW_CQ:
		return "CQ:";
	case IRDMA_HMC_IW_SRQ:
		return "SRQ:";
	case IRDMA_HMC_IW_HTE:
		return "HTE:";
	case IRDMA_HMC_IW_ARP:
		return "ARP:";
	case IRDMA_HMC_IW_APBVT_ENTRY:
		return "APBVT:";
	case IRDMA_HMC_IW_MR:
		return "MR:";
	case IRDMA_HMC_IW_XF:
		return "XF:";
	case IRDMA_HMC_IW_XFFL:
		return "XFFL:";
	case IRDMA_HMC_IW_Q1:
		return "Q1:";
	case IRDMA_HMC_IW_Q1FL:
		return "Q1FL:";
	case IRDMA_HMC_IW_TIMER:
		return "TIMER:";
	case IRDMA_HMC_IW_FSIMC:
		return "FSIMC:";
	case IRDMA_HMC_IW_FSIAV:
		return "FSIAV:";
	case IRDMA_HMC_IW_PBLE:
		return "PBLE:";
	case IRDMA_HMC_IW_RRF:
		return "RRF:";
	case IRDMA_HMC_IW_RRFFL:
		return "RRFFL:";
	case IRDMA_HMC_IW_HDR:
		return "HDR:";
	default:
		return "UNKNOWN";
	}
}

/**
 * irdma_get_qp_from_list - get next qp from a list
 * @head: Listhead of qp's
 * @qp: current qp
 */
struct irdma_sc_qp *irdma_get_qp_from_list(struct list_head *head,
					   struct irdma_sc_qp *qp)
{
	struct list_head *lastentry;
	struct list_head *entry = NULL;

	if (list_empty(head))
		return NULL;

	if (!qp) {
		entry = head->next;
	} else {
		lastentry = &qp->list;
		entry = lastentry->next;
		if (entry == head)
			return NULL;
	}

	return container_of(entry, struct irdma_sc_qp, list);
}

/**
 * irdma_set_qs_idx - set qset index based on round robbin
 * @qp: qp for qset
 */
static void irdma_set_qs_idx(struct irdma_sc_qp *qp)
{
	struct irdma_qos *qos;

	qos = &qp->vsi->qos[qp->user_pri];

	qp->qs_idx = qos->qs_nxt_idx;
	qos->qs_nxt_idx++;
	qos->qs_nxt_idx %= qos->qs_cnt;
}

/**
 * irdma_get_qp_qs - return qs_handle for the qp
 * @qp: qp for qset
 *
 * Returns the queue set that should be used for a given qp.  The qos
 * mutex should be acquired before calling.
 */
static u16 irdma_get_qp_qs(struct irdma_sc_qp *qp)
{

	struct irdma_sc_vsi *vsi = qp->vsi;
	u16 qs_handle;

	if (qp->dev->hw_attrs.uk_attrs.hw_rev >= IRDMA_GEN_3)
		irdma_set_qs_idx(qp);
	qs_handle =
		vsi->qos[qp->user_pri].qs_handle[qp->qs_idx];

	return qs_handle;
}

/**
 * irdma_sc_suspend_resume_qps - suspend/resume all qp's on VSI
 * @vsi: the VSI struct pointer
 * @op: Set to IRDMA_OP_RESUME or IRDMA_OP_SUSPEND
 */
void irdma_sc_suspend_resume_qps(struct irdma_sc_vsi *vsi, u8 op)
{
	struct irdma_sc_qp *qp = NULL;
	u8 i;

	for (i = 0; i < IRDMA_MAX_USER_PRIORITY; i++) {
		mutex_lock(&vsi->qos[i].qos_mutex);
		qp = irdma_get_qp_from_list(&vsi->qos[i].qplist, qp);
		while (qp) {
			if (op == IRDMA_OP_RESUME) {
				if (!qp->suspended) {
					qp = irdma_get_qp_from_list(&vsi->qos[i].qplist,
								    qp);
					continue;
				}
				if (!qp->dev->ws_add(vsi, i)) {
					qp->qs_handle = irdma_get_qp_qs(qp);
					if (!irdma_cqp_qp_suspend_resume(qp, op))
						qp->suspended = false;
				} else {
					if (!irdma_cqp_qp_suspend_resume(qp, op))
						qp->suspended = false;
					irdma_modify_qp_to_err(qp);
				}
			} else if (op == IRDMA_OP_SUSPEND) {
				/* issue cqp suspend command */
				if ((qp->qp_state == IRDMA_QP_STATE_RTS ||
				     qp->qp_state == IRDMA_QP_STATE_RTR) &&
				    !irdma_cqp_qp_suspend_resume(qp, op)) {
					atomic_inc(&vsi->qp_suspend_reqs);
					qp->suspended = true;
				}
			}
			qp = irdma_get_qp_from_list(&vsi->qos[i].qplist, qp);
		}
		mutex_unlock(&vsi->qos[i].qos_mutex);
	}
}

static void irdma_set_qos_info_gen_3(struct irdma_sc_vsi  *vsi)
{
	u8 i;

	for (i = 0; i < IRDMA_MAX_USER_PRIORITY; i++) {
		vsi->qos[i].valid = true;
		vsi->qos[i].qs_cnt = vsi->dev->qos[i].qs_cnt;
		vsi->qos[i].qs_nxt_idx = 0;
		memcpy(vsi->qos[i].qs_handle,
			     vsi->dev->qos[i].qs_handle,
			     vsi->qos[i].qs_cnt * sizeof(u16));
	}
}

static void irdma_set_qos_info(struct irdma_sc_vsi  *vsi, struct irdma_l2params *l2p)
{
	u8 i;

	if (vsi->dev->hw_attrs.uk_attrs.hw_rev >= IRDMA_GEN_3)
		return irdma_set_qos_info_gen_3(vsi);

	vsi->qos_rel_bw = l2p->vsi_rel_bw;
	vsi->qos_prio_type = l2p->vsi_prio_type;
	vsi->dscp_mode = l2p->dscp_mode;
	if (l2p->dscp_mode) {
		memcpy(vsi->dscp_map, l2p->dscp_map, sizeof(vsi->dscp_map));
		for (i = 0; i < IRDMA_MAX_USER_PRIORITY; i++)
			l2p->up2tc[i] = i;
	}
	for (i = 0; i < IEEE_8021QAZ_MAX_TCS; i++)
		vsi->tc_print_warning[i] = true;
	for (i = 0; i < IRDMA_MAX_USER_PRIORITY; i++) {
		if (vsi->dev->hw_attrs.uk_attrs.hw_rev == IRDMA_GEN_1)
			vsi->qos[i].qs_handle[0] =
				l2p->qs_handle_list[i];
		if (vsi->dev->hw_attrs.uk_attrs.hw_rev == IRDMA_GEN_2)
			irdma_init_config_check(&vsi->cfg_check[i],
						l2p->up2tc[i], i,
						l2p->qs_handle_list[i]);
		vsi->qos[i].traffic_class = l2p->up2tc[i];
		vsi->qos[i].rel_bw =
			l2p->tc_info[vsi->qos[i].traffic_class].rel_bw;
		vsi->qos[i].prio_type =
			l2p->tc_info[vsi->qos[i].traffic_class].prio_type;
		vsi->qos[i].valid = false;
	}
}

/**
 * irdma_change_l2params - given the new l2 parameters, change all qp
 * @vsi: RDMA VSI pointer
 * @l2params: New parameters from l2
 */
void irdma_change_l2params(struct irdma_sc_vsi *vsi,
			   struct irdma_l2params *l2params)
{
	if (l2params->tc_changed) {
		vsi->tc_change_pending = false;
		irdma_set_qos_info(vsi, l2params);
		irdma_sc_suspend_resume_qps(vsi, IRDMA_OP_RESUME);
	}
	if (l2params->mtu_changed) {
		vsi->mtu = l2params->mtu;
		if (vsi->ieq)
			irdma_reinitialize_ieq(vsi);
	}
}

/**
 * irdma_qp_rem_qos - remove qp from qos lists during destroy qp
 * @qp: qp to be removed from qos
 */
void irdma_qp_rem_qos(struct irdma_sc_qp *qp)
{
	struct irdma_sc_vsi *vsi = qp->vsi;

	ibdev_dbg(to_ibdev(qp->dev),
		  "DCB: DCB: Remove qp[%d] UP[%d] qset[%d] on_qoslist[%d]\n",
		  qp->qp_uk.qp_id, qp->user_pri, qp->qs_handle,
		  qp->on_qoslist);
	mutex_lock(&vsi->qos[qp->user_pri].qos_mutex);
	if (qp->on_qoslist) {
		qp->on_qoslist = false;
		list_del(&qp->list);
	}
	mutex_unlock(&vsi->qos[qp->user_pri].qos_mutex);
}

/**
 * irdma_qp_add_qos - called during setctx for qp to be added to qos
 * @qp: qp to be added to qos
 */
void irdma_qp_add_qos(struct irdma_sc_qp *qp)
{
	struct irdma_sc_vsi *vsi = qp->vsi;

	mutex_lock(&vsi->qos[qp->user_pri].qos_mutex);
	if (!qp->on_qoslist) {
		list_add(&qp->list, &vsi->qos[qp->user_pri].qplist);
		qp->on_qoslist = true;
		qp->qs_handle = irdma_get_qp_qs(qp);
		ibdev_dbg(to_ibdev(qp->dev),
			  "DCB: DCB: Add qp[%d] UP[%d] qset[%d] on_qoslist[%d]\n",
			  qp->qp_uk.qp_id, qp->user_pri, qp->qs_handle,
			  qp->on_qoslist);

	}
	mutex_unlock(&vsi->qos[qp->user_pri].qos_mutex);
}

/**
 * irdma_sc_pd_init - initialize sc pd struct
 * @dev: sc device struct
 * @pd: sc pd ptr
 * @pd_id: pd_id for allocated pd
 * @abi_ver: User/Kernel ABI version
 */
void irdma_sc_pd_init(struct irdma_sc_dev *dev, struct irdma_sc_pd *pd, u32 pd_id,
		      int abi_ver)
{
	pd->pd_id = pd_id;
	pd->abi_ver = abi_ver;
	pd->dev = dev;
}

/**
 * irdma_sc_add_arp_cache_entry - cqp wqe add arp cache entry
 * @cqp: struct for cqp hw
 * @info: arp entry information
 * @scratch: u64 saved to be used during cqp completion
 * @post_sq: flag for cqp db to ring
 */
static int
irdma_sc_add_arp_cache_entry(struct irdma_sc_cqp *cqp,
			     struct irdma_add_arp_cache_entry_info *info,
			     u64 scratch, bool post_sq)
{
	__le64 *wqe;
	u64 hdr;

	wqe = irdma_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;
	set_64bit_val(wqe, 8, info->reach_max);

	set_64bit_val(wqe, 16, ether_addr_to_u64(info->mac_addr));

	hdr = info->arp_index |
	      FIELD_PREP(IRDMA_CQPSQ_OPCODE, IRDMA_CQP_OP_MANAGE_ARP) |
	      FIELD_PREP(IRDMA_CQPSQ_MAT_PERMANENT, info->permanent) |
	      FIELD_PREP(IRDMA_CQPSQ_MAT_ENTRYVALID, true) |
	      FIELD_PREP(IRDMA_CQPSQ_WQEVALID, cqp->polarity);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: ARP_CACHE_ENTRY WQE", DUMP_PREFIX_OFFSET,
			     16, 8, wqe, IRDMA_CQP_WQE_SIZE * 8, false);
	if (post_sq)
		irdma_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * irdma_sc_del_arp_cache_entry - dele arp cache entry
 * @cqp: struct for cqp hw
 * @scratch: u64 saved to be used during cqp completion
 * @arp_index: arp index to delete arp entry
 * @post_sq: flag for cqp db to ring
 */
static int irdma_sc_del_arp_cache_entry(struct irdma_sc_cqp *cqp, u64 scratch,
					u16 arp_index, bool post_sq)
{
	__le64 *wqe;
	u64 hdr;

	wqe = irdma_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;

	hdr = arp_index |
	      FIELD_PREP(IRDMA_CQPSQ_OPCODE, IRDMA_CQP_OP_MANAGE_ARP) |
	      FIELD_PREP(IRDMA_CQPSQ_WQEVALID, cqp->polarity);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: ARP_CACHE_DEL_ENTRY WQE",
			     DUMP_PREFIX_OFFSET, 16, 8, wqe,
			     IRDMA_CQP_WQE_SIZE * 8, false);
	if (post_sq)
		irdma_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * irdma_sc_manage_apbvt_entry - for adding and deleting apbvt entries
 * @cqp: struct for cqp hw
 * @info: info for apbvt entry to add or delete
 * @scratch: u64 saved to be used during cqp completion
 * @post_sq: flag for cqp db to ring
 */
static int irdma_sc_manage_apbvt_entry(struct irdma_sc_cqp *cqp,
				       struct irdma_apbvt_info *info,
				       u64 scratch, bool post_sq)
{
	__le64 *wqe;
	u64 hdr;

	wqe = irdma_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;

	set_64bit_val(wqe, 16, info->port);

	hdr = FIELD_PREP(IRDMA_CQPSQ_OPCODE, IRDMA_CQP_OP_MANAGE_APBVT) |
	      FIELD_PREP(IRDMA_CQPSQ_MAPT_ADDPORT, info->add) |
	      FIELD_PREP(IRDMA_CQPSQ_WQEVALID, cqp->polarity);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: MANAGE_APBVT WQE", DUMP_PREFIX_OFFSET, 16,
			     8, wqe, IRDMA_CQP_WQE_SIZE * 8, false);
	if (post_sq)
		irdma_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * irdma_sc_manage_qhash_table_entry - manage quad hash entries
 * @cqp: struct for cqp hw
 * @info: info for quad hash to manage
 * @scratch: u64 saved to be used during cqp completion
 * @post_sq: flag for cqp db to ring
 *
 * This is called before connection establishment is started.
 * For passive connections, when listener is created, it will
 * call with entry type of  IRDMA_QHASH_TYPE_TCP_SYN with local
 * ip address and tcp port. When SYN is received (passive
 * connections) or sent (active connections), this routine is
 * called with entry type of IRDMA_QHASH_TYPE_TCP_ESTABLISHED
 * and quad is passed in info.
 *
 * When iwarp connection is done and its state moves to RTS, the
 * quad hash entry in the hardware will point to iwarp's qp
 * number and requires no calls from the driver.
 */
static int
irdma_sc_manage_qhash_table_entry(struct irdma_sc_cqp *cqp,
				  struct irdma_qhash_table_info *info,
				  u64 scratch, bool post_sq)
{
	__le64 *wqe;
	u64 qw1 = 0;
	u64 qw2 = 0;
	u64 temp;
	u16 qs_handle;
	struct irdma_sc_vsi *vsi = info->vsi;

	wqe = irdma_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;
	set_64bit_val(wqe, 0, ether_addr_to_u64(info->mac_addr));

	qw1 = FIELD_PREP(IRDMA_CQPSQ_QHASH_QPN, info->qp_num) |
	      FIELD_PREP(IRDMA_CQPSQ_QHASH_DEST_PORT, info->dest_port);
	if (info->ipv4_valid) {
		set_64bit_val(wqe, 48,
			      FIELD_PREP(IRDMA_CQPSQ_QHASH_ADDR3, info->dest_ip[0]));
	} else {
		set_64bit_val(wqe, 56,
			      FIELD_PREP(IRDMA_CQPSQ_QHASH_ADDR0, info->dest_ip[0]) |
			      FIELD_PREP(IRDMA_CQPSQ_QHASH_ADDR1, info->dest_ip[1]));

		set_64bit_val(wqe, 48,
			      FIELD_PREP(IRDMA_CQPSQ_QHASH_ADDR2, info->dest_ip[2]) |
			      FIELD_PREP(IRDMA_CQPSQ_QHASH_ADDR3, info->dest_ip[3]));
	}

	qs_handle = vsi->qos[info->user_pri].qs_handle[0];

	qw2 = FIELD_PREP(IRDMA_CQPSQ_QHASH_QS_HANDLE, qs_handle);
	if (info->vlan_valid)
		qw2 |= FIELD_PREP(IRDMA_CQPSQ_QHASH_VLANID, info->vlan_id);
	set_64bit_val(wqe, 16, qw2);
	if (info->entry_type == IRDMA_QHASH_TYPE_TCP_ESTABLISHED) {
		qw1 |= FIELD_PREP(IRDMA_CQPSQ_QHASH_SRC_PORT, info->src_port);
		if (!info->ipv4_valid) {
			set_64bit_val(wqe, 40,
				      FIELD_PREP(IRDMA_CQPSQ_QHASH_ADDR0, info->src_ip[0]) |
				      FIELD_PREP(IRDMA_CQPSQ_QHASH_ADDR1, info->src_ip[1]));
			set_64bit_val(wqe, 32,
				      FIELD_PREP(IRDMA_CQPSQ_QHASH_ADDR2, info->src_ip[2]) |
				      FIELD_PREP(IRDMA_CQPSQ_QHASH_ADDR3, info->src_ip[3]));
		} else {
			set_64bit_val(wqe, 32,
				      FIELD_PREP(IRDMA_CQPSQ_QHASH_ADDR3, info->src_ip[0]));
		}
	}

	set_64bit_val(wqe, 8, qw1);
	temp = FIELD_PREP(IRDMA_CQPSQ_QHASH_WQEVALID, cqp->polarity) |
	       FIELD_PREP(IRDMA_CQPSQ_QHASH_OPCODE,
			  IRDMA_CQP_OP_MANAGE_QUAD_HASH_TABLE_ENTRY) |
	       FIELD_PREP(IRDMA_CQPSQ_QHASH_MANAGE, info->manage) |
	       FIELD_PREP(IRDMA_CQPSQ_QHASH_IPV4VALID, info->ipv4_valid) |
	       FIELD_PREP(IRDMA_CQPSQ_QHASH_VLANVALID, info->vlan_valid) |
	       FIELD_PREP(IRDMA_CQPSQ_QHASH_ENTRYTYPE, info->entry_type);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, temp);

	print_hex_dump_debug("WQE: MANAGE_QHASH WQE", DUMP_PREFIX_OFFSET, 16,
			     8, wqe, IRDMA_CQP_WQE_SIZE * 8, false);
	if (post_sq)
		irdma_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * irdma_sc_cqp_nop - send a nop wqe
 * @cqp: struct for cqp hw
 * @scratch: u64 saved to be used during cqp completion
 * @post_sq: flag for cqp db to ring
 */
int irdma_sc_cqp_nop(struct irdma_sc_cqp *cqp, u64 scratch, bool post_sq)
{
	__le64 *wqe;
	u64 hdr;

	wqe = irdma_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;
	hdr = FIELD_PREP(IRDMA_CQPSQ_OPCODE, IRDMA_CQP_OP_NOP) |
	      FIELD_PREP(IRDMA_CQPSQ_WQEVALID, cqp->polarity);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: NOP WQE", DUMP_PREFIX_OFFSET, 16, 8, wqe,
			     IRDMA_CQP_WQE_SIZE * 8, false);
	if (post_sq)
		irdma_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * irdma_sc_qp_init - initialize qp
 * @qp: sc qp
 * @info: initialization qp info
 */
int irdma_sc_qp_init(struct irdma_sc_qp *qp, struct irdma_qp_init_info *info)
{
	int ret_code;
	u32 pble_obj_cnt;
	u16 wqe_size;

	if (info->qp_uk_init_info.max_sq_frag_cnt >
	    info->pd->dev->hw_attrs.uk_attrs.max_hw_wq_frags ||
	    info->qp_uk_init_info.max_rq_frag_cnt >
	    info->pd->dev->hw_attrs.uk_attrs.max_hw_wq_frags)
		return -EINVAL;

	qp->dev = info->pd->dev;
	qp->vsi = info->vsi;
	qp->ieq_qp = info->vsi->exception_lan_q;
	qp->sq_pa = info->sq_pa;
	qp->rq_pa = info->rq_pa;
	qp->hw_host_ctx_pa = info->host_ctx_pa;
	qp->q2_pa = info->q2_pa;
	qp->shadow_area_pa = info->shadow_area_pa;
	qp->q2_buf = info->q2;
	qp->pd = info->pd;
	qp->hw_host_ctx = info->host_ctx;
	info->qp_uk_init_info.wqe_alloc_db = qp->pd->dev->wqe_alloc_db;
	ret_code = irdma_uk_qp_init(&qp->qp_uk, &info->qp_uk_init_info);
	if (ret_code)
		return ret_code;

	qp->virtual_map = info->virtual_map;
	pble_obj_cnt = info->pd->dev->hmc_info->hmc_obj[IRDMA_HMC_IW_PBLE].cnt;

	if ((info->virtual_map && info->sq_pa >= pble_obj_cnt) ||
	    (!info->qp_uk_init_info.srq_uk && info->virtual_map && info->rq_pa >= pble_obj_cnt))
		return -EINVAL;

	qp->llp_stream_handle = (void *)(-1);
	qp->hw_sq_size = irdma_get_encoded_wqe_size(qp->qp_uk.sq_ring.size,
						    IRDMA_QUEUE_TYPE_SQ_RQ);
	ibdev_dbg(to_ibdev(qp->dev),
		  "WQE: hw_sq_size[%04d] sq_ring.size[%04d]\n",
		  qp->hw_sq_size, qp->qp_uk.sq_ring.size);
	if (qp->qp_uk.uk_attrs->hw_rev == IRDMA_GEN_1 && qp->pd->abi_ver > 4)
		wqe_size = IRDMA_WQE_SIZE_128;
	else
		ret_code = irdma_fragcnt_to_wqesize_rq(qp->qp_uk.max_rq_frag_cnt,
						       &wqe_size);
	if (ret_code)
		return ret_code;

	qp->hw_rq_size =
		irdma_get_encoded_wqe_size(qp->qp_uk.rq_size *
					   (wqe_size / IRDMA_QP_WQE_MIN_SIZE),
					   IRDMA_QUEUE_TYPE_SQ_RQ);
	ibdev_dbg(to_ibdev(qp->dev),
		  "WQE: hw_rq_size[%04d] qp_uk.rq_size[%04d] wqe_size[%04d]\n",
		  qp->hw_rq_size, qp->qp_uk.rq_size, wqe_size);

	qp->sq_tph_val = info->sq_tph_val;
	qp->rq_tph_val = info->rq_tph_val;
	qp->sq_tph_en = info->sq_tph_en;
	qp->rq_tph_en = info->rq_tph_en;
	qp->rcv_tph_en = info->rcv_tph_en;
	qp->xmit_tph_en = info->xmit_tph_en;
	qp->qp_uk.first_sq_wq = info->qp_uk_init_info.first_sq_wq;

	return 0;
}

/**
 * irdma_sc_srq_init - init sc_srq structure
 * @srq: srq sc struct
 * @info: parameters for srq init
 */
int irdma_sc_srq_init(struct irdma_sc_srq *srq,
		      struct irdma_srq_init_info *info)
{
	u32 srq_size_quanta;
	int ret_code;

	ret_code = irdma_uk_srq_init(&srq->srq_uk, &info->srq_uk_init_info);
	if (ret_code)
		return ret_code;

	srq->dev = info->pd->dev;
	srq->pd = info->pd;
	srq->vsi = info->vsi;
	srq->srq_pa = info->srq_pa;
	srq->first_pm_pbl_idx = info->first_pm_pbl_idx;
	srq->pasid = info->pasid;
	srq->pasid_valid = info->pasid_valid;
	srq->srq_limit = info->srq_limit;
	srq->leaf_pbl_size = info->leaf_pbl_size;
	srq->virtual_map = info->virtual_map;
	srq->tph_en = info->tph_en;
	srq->arm_limit_event = info->arm_limit_event;
	srq->tph_val = info->tph_value;
	srq->shadow_area_pa = info->shadow_area_pa;

	/* Smallest SRQ size is 256B i.e. 8 quanta */
	srq_size_quanta = max((u32)IRDMA_SRQ_MIN_QUANTA,
			      srq->srq_uk.srq_size * srq->srq_uk.wqe_size_multiplier);
	srq->hw_srq_size = irdma_get_encoded_wqe_size(srq_size_quanta, IRDMA_QUEUE_TYPE_SRQ);

	return 0;
}

/**
 * irdma_sc_srq_create - send srq create CQP WQE
 * @srq: srq sc struct
 * @scratch: u64 saved to be used during cqp completion
 * @post_sq: flag for cqp db to ring
 */
static int irdma_sc_srq_create(struct irdma_sc_srq *srq, u64 scratch,
			       bool post_sq)
{
	struct irdma_sc_cqp *cqp;
	__le64 *wqe;
	u64 hdr;

	cqp = srq->pd->dev->cqp;
	if (srq->srq_uk.srq_id < cqp->dev->hw_attrs.min_hw_srq_id ||
	    srq->srq_uk.srq_id > (cqp->dev->hmc_info->hmc_obj[IRDMA_HMC_IW_SRQ].max_cnt - 1))
		return -EINVAL;

	wqe = irdma_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;

	set_64bit_val(wqe, 0,
		      FIELD_PREP(IRDMA_CQPSQ_SRQ_SRQ_LIMIT, srq->srq_limit) |
		      FIELD_PREP(IRDMA_CQPSQ_SRQ_RQSIZE, srq->hw_srq_size) |
		      FIELD_PREP(IRDMA_CQPSQ_SRQ_RQ_WQE_SIZE, srq->srq_uk.wqe_size));
	set_64bit_val(wqe, 8,
		      FIELD_PREP(IRDMA_AEQE_CMPL_CTXT, srq->srq_uk.srq_id));
	set_64bit_val(wqe, 16,
		      FIELD_PREP(IRDMA_CQPSQ_SRQ_PD_ID, srq->pd->pd_id));
	set_64bit_val(wqe, 32,
		      FIELD_PREP(IRDMA_CQPSQ_SRQ_PHYSICAL_BUFFER_ADDR,
				 srq->srq_pa >> IRDMA_CQPSQ_SRQ_PHYSICAL_BUFFER_ADDR_S));
	set_64bit_val(wqe, 40,
		      FIELD_PREP(IRDMA_CQPSQ_SRQ_DB_SHADOW_ADDR,
				 srq->shadow_area_pa >> IRDMA_CQPSQ_SRQ_DB_SHADOW_ADDR_S));
	set_64bit_val(wqe, 48,
		      FIELD_PREP(IRDMA_CQPSQ_SRQ_FIRST_PM_PBL_IDX, srq->first_pm_pbl_idx));

	hdr = srq->srq_uk.srq_id |
	      FIELD_PREP(IRDMA_CQPSQ_OPCODE, IRDMA_CQP_OP_CREATE_SRQ) |
	      FIELD_PREP(IRDMA_CQPSQ_SRQ_LEAF_PBL_SIZE, srq->leaf_pbl_size) |
	      FIELD_PREP(IRDMA_CQPSQ_SRQ_VIRTMAP, srq->virtual_map) |
	      FIELD_PREP(IRDMA_CQPSQ_SRQ_ARM_LIMIT_EVENT,
			 srq->arm_limit_event) |
	      FIELD_PREP(IRDMA_CQPSQ_WQEVALID, cqp->polarity);

	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: SRQ_CREATE WQE", DUMP_PREFIX_OFFSET, 16, 8,
			     wqe, IRDMA_CQP_WQE_SIZE * 8, false);
	if (post_sq)
		irdma_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * irdma_sc_srq_modify - send modify_srq CQP WQE
 * @srq: srq sc struct
 * @info: parameters for srq modification
 * @scratch: u64 saved to be used during cqp completion
 * @post_sq: flag for cqp db to ring
 */
static int irdma_sc_srq_modify(struct irdma_sc_srq *srq,
			       struct irdma_modify_srq_info *info, u64 scratch,
			       bool post_sq)
{
	struct irdma_sc_cqp *cqp;
	__le64 *wqe;
	u64 hdr;

	cqp = srq->dev->cqp;
	if (srq->srq_uk.srq_id < cqp->dev->hw_attrs.min_hw_srq_id ||
	    srq->srq_uk.srq_id > (cqp->dev->hmc_info->hmc_obj[IRDMA_HMC_IW_SRQ].max_cnt - 1))
		return -EINVAL;

	wqe = irdma_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;

	set_64bit_val(wqe, 0,
		      FIELD_PREP(IRDMA_CQPSQ_SRQ_SRQ_LIMIT, info->srq_limit) |
		      FIELD_PREP(IRDMA_CQPSQ_SRQ_RQSIZE, srq->hw_srq_size) |
		      FIELD_PREP(IRDMA_CQPSQ_SRQ_RQ_WQE_SIZE, srq->srq_uk.wqe_size));
	set_64bit_val(wqe, 8,
		      FIELD_PREP(IRDMA_AEQE_CMPL_CTXT, srq->srq_uk.srq_id));
	set_64bit_val(wqe, 16,
		      FIELD_PREP(IRDMA_CQPSQ_SRQ_PD_ID, srq->pd->pd_id));
	set_64bit_val(wqe, 32,
		      FIELD_PREP(IRDMA_CQPSQ_SRQ_PHYSICAL_BUFFER_ADDR,
				 srq->srq_pa >> IRDMA_CQPSQ_SRQ_PHYSICAL_BUFFER_ADDR_S));
	set_64bit_val(wqe, 40,
		      FIELD_PREP(IRDMA_CQPSQ_SRQ_DB_SHADOW_ADDR,
				 srq->shadow_area_pa >> IRDMA_CQPSQ_SRQ_DB_SHADOW_ADDR_S));
	set_64bit_val(wqe, 48,
		      FIELD_PREP(IRDMA_CQPSQ_SRQ_FIRST_PM_PBL_IDX, srq->first_pm_pbl_idx));

	hdr = srq->srq_uk.srq_id |
	      FIELD_PREP(IRDMA_CQPSQ_OPCODE, IRDMA_CQP_OP_MODIFY_SRQ) |
	      FIELD_PREP(IRDMA_CQPSQ_SRQ_LEAF_PBL_SIZE, srq->leaf_pbl_size) |
	      FIELD_PREP(IRDMA_CQPSQ_SRQ_VIRTMAP, srq->virtual_map) |
	      FIELD_PREP(IRDMA_CQPSQ_SRQ_ARM_LIMIT_EVENT,
			 info->arm_limit_event) |
	      FIELD_PREP(IRDMA_CQPSQ_WQEVALID, cqp->polarity);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: SRQ_MODIFY WQE", DUMP_PREFIX_OFFSET, 16, 8,
			     wqe, IRDMA_CQP_WQE_SIZE * 8, false);
	if (post_sq)
		irdma_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * irdma_sc_srq_destroy - send srq_destroy CQP WQE
 * @srq: srq sc struct
 * @scratch: u64 saved to be used during cqp completion
 * @post_sq: flag for cqp db to ring
 */
static int irdma_sc_srq_destroy(struct irdma_sc_srq *srq, u64 scratch,
				bool post_sq)
{
	struct irdma_sc_cqp *cqp;
	__le64 *wqe;
	u64 hdr;

	cqp = srq->dev->cqp;

	wqe = irdma_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;

	set_64bit_val(wqe, 8, (u64)srq);

	hdr = srq->srq_uk.srq_id |
	      FIELD_PREP(IRDMA_CQPSQ_OPCODE, IRDMA_CQP_OP_DESTROY_SRQ) |
	      FIELD_PREP(IRDMA_CQPSQ_WQEVALID, cqp->polarity);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: SRQ_DESTROY WQE", DUMP_PREFIX_OFFSET, 16,
			     8, wqe, IRDMA_CQP_WQE_SIZE * 8, false);
	if (post_sq)
		irdma_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * irdma_sc_qp_create - create qp
 * @qp: sc qp
 * @info: qp create info
 * @scratch: u64 saved to be used during cqp completion
 * @post_sq: flag for cqp db to ring
 */
int irdma_sc_qp_create(struct irdma_sc_qp *qp, struct irdma_create_qp_info *info,
		       u64 scratch, bool post_sq)
{
	struct irdma_sc_cqp *cqp;
	__le64 *wqe;
	u64 hdr;

	cqp = qp->dev->cqp;
	if (qp->qp_uk.qp_id < cqp->dev->hw_attrs.min_hw_qp_id ||
	    qp->qp_uk.qp_id > (cqp->dev->hmc_info->hmc_obj[IRDMA_HMC_IW_QP].max_cnt - 1))
		return -EINVAL;

	wqe = irdma_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;

	set_64bit_val(wqe, 16, qp->hw_host_ctx_pa);
	set_64bit_val(wqe, 40, qp->shadow_area_pa);

	if (qp->dev->hw_wa & NO_LPB)
		info->force_lpb = 0;
	if (qp->dev->hw_wa & FORCE_LPB)
		info->force_lpb = 1;
	hdr = qp->qp_uk.qp_id |
	      FIELD_PREP(IRDMA_CQPSQ_OPCODE, IRDMA_CQP_OP_CREATE_QP) |
	      FIELD_PREP(IRDMA_CQPSQ_QP_ORDVALID, info->ord_valid) |
	      FIELD_PREP(IRDMA_CQPSQ_QP_TOECTXVALID, info->tcp_ctx_valid) |
	      FIELD_PREP(IRDMA_CQPSQ_QP_MACVALID, info->mac_valid) |
	      FIELD_PREP(IRDMA_CQPSQ_QP_QPTYPE, qp->qp_uk.qp_type) |
	      FIELD_PREP(IRDMA_CQPSQ_QP_VQ, qp->virtual_map) |
	      FIELD_PREP(IRDMA_CQPSQ_QP_FORCELOOPBACK, info->force_lpb) |
	      FIELD_PREP(IRDMA_CQPSQ_QP_CQNUMVALID, info->cq_num_valid) |
	      FIELD_PREP(IRDMA_CQPSQ_QP_ARPTABIDXVALID,
			 info->arp_cache_idx_valid) |
	      FIELD_PREP(IRDMA_CQPSQ_QP_NEXTIWSTATE, info->next_iwarp_state) |
	      FIELD_PREP(IRDMA_CQPSQ_WQEVALID, cqp->polarity);

	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: QP_CREATE WQE", DUMP_PREFIX_OFFSET, 16, 8,
			     wqe, IRDMA_CQP_WQE_SIZE * 8, false);
	if (post_sq)
		irdma_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * irdma_sc_qp_modify - modify qp cqp wqe
 * @qp: sc qp
 * @info: modify qp info
 * @scratch: u64 saved to be used during cqp completion
 * @post_sq: flag for cqp db to ring
 */
int irdma_sc_qp_modify(struct irdma_sc_qp *qp, struct irdma_modify_qp_info *info,
		       u64 scratch, bool post_sq)
{
	__le64 *wqe;
	struct irdma_sc_cqp *cqp;
	u64 hdr;
	u8 term_actions = 0;
	u8 term_len = 0;

	cqp = qp->dev->cqp;
	wqe = irdma_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;

	if (info->next_iwarp_state == IRDMA_QP_STATE_TERMINATE) {
		if (info->dont_send_fin)
			term_actions += IRDMAQP_TERM_SEND_TERM_ONLY;
		if (info->dont_send_term)
			term_actions += IRDMAQP_TERM_SEND_FIN_ONLY;
		if (term_actions == IRDMAQP_TERM_SEND_TERM_AND_FIN ||
		    term_actions == IRDMAQP_TERM_SEND_TERM_ONLY)
			term_len = info->termlen;
	}

	set_64bit_val(wqe, 8,
		      FIELD_PREP(IRDMA_CQPSQ_QP_NEWMSS, info->new_mss) |
		      FIELD_PREP(IRDMA_CQPSQ_QP_TERMLEN, term_len));
	set_64bit_val(wqe, 16, qp->hw_host_ctx_pa);
	set_64bit_val(wqe, 40, qp->shadow_area_pa);

	if (qp->dev->hw_wa & NO_LPB)
		info->force_lpb = 0;
	if (qp->dev->hw_wa & FORCE_LPB)
		info->force_lpb = 1;
	hdr = qp->qp_uk.qp_id |
	      FIELD_PREP(IRDMA_CQPSQ_OPCODE, IRDMA_CQP_OP_MODIFY_QP) |
	      FIELD_PREP(IRDMA_CQPSQ_QP_ORDVALID, info->ord_valid) |
	      FIELD_PREP(IRDMA_CQPSQ_QP_TOECTXVALID, info->tcp_ctx_valid) |
	      FIELD_PREP(IRDMA_CQPSQ_QP_CACHEDVARVALID,
			 info->cached_var_valid) |
	      FIELD_PREP(IRDMA_CQPSQ_QP_VQ, qp->virtual_map) |
	      FIELD_PREP(IRDMA_CQPSQ_QP_FORCELOOPBACK, info->force_lpb) |
	      FIELD_PREP(IRDMA_CQPSQ_QP_CQNUMVALID, info->cq_num_valid) |
	      FIELD_PREP(IRDMA_CQPSQ_QP_MACVALID, info->mac_valid) |
	      FIELD_PREP(IRDMA_CQPSQ_QP_QPTYPE, qp->qp_uk.qp_type) |
	      FIELD_PREP(IRDMA_CQPSQ_QP_MSSCHANGE, info->mss_change) |
	      FIELD_PREP(IRDMA_CQPSQ_QP_REMOVEHASHENTRY,
			 info->remove_hash_idx) |
	      FIELD_PREP(IRDMA_CQPSQ_QP_TERMACT, term_actions) |
	      FIELD_PREP(IRDMA_CQPSQ_QP_RESETCON, info->reset_tcp_conn) |
	      FIELD_PREP(IRDMA_CQPSQ_QP_ARPTABIDXVALID,
			 info->arp_cache_idx_valid) |
	      FIELD_PREP(IRDMA_CQPSQ_QP_NEXTIWSTATE, info->next_iwarp_state) |
	      FIELD_PREP(IRDMA_CQPSQ_WQEVALID, cqp->polarity);

	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: QP_MODIFY WQE", DUMP_PREFIX_OFFSET, 16, 8,
			     wqe, IRDMA_CQP_WQE_SIZE * 8, false);
	if (post_sq)
		irdma_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * irdma_sc_qp_destroy - cqp destroy qp
 * @qp: sc qp
 * @scratch: u64 saved to be used during cqp completion
 * @remove_hash_idx: flag if to remove hash idx
 * @ignore_mw_bnd: memory window bind flag
 * @post_sq: flag for cqp db to ring
 */
int irdma_sc_qp_destroy(struct irdma_sc_qp *qp, u64 scratch,
			bool remove_hash_idx, bool ignore_mw_bnd, bool post_sq)
{
	__le64 *wqe;
	struct irdma_sc_cqp *cqp;
	u64 hdr;

	cqp = qp->dev->cqp;
	wqe = irdma_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;

	set_64bit_val(wqe, 16, qp->hw_host_ctx_pa);
	set_64bit_val(wqe, 40, qp->shadow_area_pa);

	hdr = qp->qp_uk.qp_id |
	      FIELD_PREP(IRDMA_CQPSQ_OPCODE, IRDMA_CQP_OP_DESTROY_QP) |
	      FIELD_PREP(IRDMA_CQPSQ_QP_QPTYPE, qp->qp_uk.qp_type) |
	      FIELD_PREP(IRDMA_CQPSQ_QP_IGNOREMWBOUND, ignore_mw_bnd) |
	      FIELD_PREP(IRDMA_CQPSQ_QP_REMOVEHASHENTRY, remove_hash_idx) |
	      FIELD_PREP(IRDMA_CQPSQ_WQEVALID, cqp->polarity);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: QP_DESTROY WQE", DUMP_PREFIX_OFFSET, 16, 8,
			     wqe, IRDMA_CQP_WQE_SIZE * 8, false);
	if (post_sq)
		irdma_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * irdma_sc_get_encoded_ird_size -
 * @ird_size: IRD size
 * The ird from the connection is rounded to a supported HW setting and then encoded
 * for ird_size field of qp_ctx. Consumers are expected to provide valid ird size based
 * on hardware attributes. IRD size defaults to a value of 4 in case of invalid input
 */
static u8 irdma_sc_get_encoded_ird_size(u16 ird_size)
{
	switch (ird_size ?
		roundup_pow_of_two(2 * ird_size) : 4) {
	case 256:
		return IRDMA_IRD_HW_SIZE_256;
	case 128:
		return IRDMA_IRD_HW_SIZE_128;
	case 64:
	case 32:
		return IRDMA_IRD_HW_SIZE_64;
	case 16:
	case 8:
		return IRDMA_IRD_HW_SIZE_16;
	case 4:
	default:
		break;
	}

	return IRDMA_IRD_HW_SIZE_4;
}

/**
 * irdma_sc_qp_setctx_roce_gen_2 - set qp's context
 * @qp: sc qp
 * @qp_ctx: context ptr
 * @info: ctx info
 */
static void irdma_sc_qp_setctx_roce_gen_2(struct irdma_sc_qp *qp, __le64 *qp_ctx,
					  struct irdma_qp_host_ctx_info *info)
{
	struct irdma_roce_offload_info *roce_info;
	struct irdma_udp_offload_info *udp;
	u8 push_mode_en;
	u32 push_idx;

	roce_info = info->roce_info;
	udp = info->udp_info;

	qp->user_pri = info->user_pri;
	if (qp->push_idx == IRDMA_INVALID_PUSH_PAGE_INDEX) {
		push_mode_en = 0;
		push_idx = 0;
	} else {
		push_mode_en = 1;
		push_idx = qp->push_idx;
	}
	set_64bit_val(qp_ctx, 0,
		      FIELD_PREP(IRDMAQPC_RQWQESIZE, qp->qp_uk.rq_wqe_size) |
		      FIELD_PREP(IRDMAQPC_RCVTPHEN, qp->rcv_tph_en) |
		      FIELD_PREP(IRDMAQPC_XMITTPHEN, qp->xmit_tph_en) |
		      FIELD_PREP(IRDMAQPC_RQTPHEN, qp->rq_tph_en) |
		      FIELD_PREP(IRDMAQPC_SQTPHEN, qp->sq_tph_en) |
		      FIELD_PREP(IRDMAQPC_PPIDX, push_idx) |
		      FIELD_PREP(IRDMAQPC_PMENA, push_mode_en) |
		      FIELD_PREP(IRDMAQPC_PDIDXHI, roce_info->pd_id >> 16) |
		      FIELD_PREP(IRDMAQPC_DC_TCP_EN, roce_info->dctcp_en) |
		      FIELD_PREP(IRDMAQPC_ERR_RQ_IDX_VALID, roce_info->err_rq_idx_valid) |
		      FIELD_PREP(IRDMAQPC_ISQP1, roce_info->is_qp1) |
		      FIELD_PREP(IRDMAQPC_ROCE_TVER, roce_info->roce_tver) |
		      FIELD_PREP(IRDMAQPC_IPV4, udp->ipv4) |
		      FIELD_PREP(IRDMAQPC_INSERTVLANTAG, udp->insert_vlan_tag));
	set_64bit_val(qp_ctx, 8, qp->sq_pa);
	set_64bit_val(qp_ctx, 16, qp->rq_pa);
	if (roce_info->dcqcn_en || roce_info->dctcp_en) {
		udp->tos &= ~ECN_CODE_PT_MASK;
		udp->tos |= ECN_CODE_PT_VAL;
	}

	set_64bit_val(qp_ctx, 24,
		      FIELD_PREP(IRDMAQPC_RQSIZE, qp->hw_rq_size) |
		      FIELD_PREP(IRDMAQPC_SQSIZE, qp->hw_sq_size) |
		      FIELD_PREP(IRDMAQPC_TTL, udp->ttl) | FIELD_PREP(IRDMAQPC_TOS, udp->tos) |
		      FIELD_PREP(IRDMAQPC_SRCPORTNUM, udp->src_port) |
		      FIELD_PREP(IRDMAQPC_DESTPORTNUM, udp->dst_port));
	set_64bit_val(qp_ctx, 32,
		      FIELD_PREP(IRDMAQPC_DESTIPADDR2, udp->dest_ip_addr[2]) |
		      FIELD_PREP(IRDMAQPC_DESTIPADDR3, udp->dest_ip_addr[3]));
	set_64bit_val(qp_ctx, 40,
		      FIELD_PREP(IRDMAQPC_DESTIPADDR0, udp->dest_ip_addr[0]) |
		      FIELD_PREP(IRDMAQPC_DESTIPADDR1, udp->dest_ip_addr[1]));
	set_64bit_val(qp_ctx, 48,
		      FIELD_PREP(IRDMAQPC_SNDMSS, udp->snd_mss) |
		      FIELD_PREP(IRDMAQPC_VLANTAG, udp->vlan_tag) |
		      FIELD_PREP(IRDMAQPC_ARPIDX, udp->arp_idx));
	set_64bit_val(qp_ctx, 56,
		      FIELD_PREP(IRDMAQPC_PKEY, roce_info->p_key) |
		      FIELD_PREP(IRDMAQPC_PDIDX, roce_info->pd_id) |
		      FIELD_PREP(IRDMAQPC_ACKCREDITS, roce_info->ack_credits) |
		      FIELD_PREP(IRDMAQPC_FLOWLABEL, udp->flow_label));
	set_64bit_val(qp_ctx, 64,
		      FIELD_PREP(IRDMAQPC_QKEY, roce_info->qkey) |
		      FIELD_PREP(IRDMAQPC_DESTQP, roce_info->dest_qp));
	set_64bit_val(qp_ctx, 80,
		      FIELD_PREP(IRDMAQPC_PSNNXT, udp->psn_nxt) |
		      FIELD_PREP(IRDMAQPC_LSN, udp->lsn));
	set_64bit_val(qp_ctx, 88,
		      FIELD_PREP(IRDMAQPC_EPSN, udp->epsn));
	set_64bit_val(qp_ctx, 96,
		      FIELD_PREP(IRDMAQPC_PSNMAX, udp->psn_max) |
		      FIELD_PREP(IRDMAQPC_PSNUNA, udp->psn_una));
	set_64bit_val(qp_ctx, 112,
		      FIELD_PREP(IRDMAQPC_CWNDROCE, udp->cwnd));
	set_64bit_val(qp_ctx, 128,
		      FIELD_PREP(IRDMAQPC_ERR_RQ_IDX, roce_info->err_rq_idx) |
		      FIELD_PREP(IRDMAQPC_RNRNAK_THRESH, udp->rnr_nak_thresh) |
		      FIELD_PREP(IRDMAQPC_REXMIT_THRESH, udp->rexmit_thresh) |
		      FIELD_PREP(IRDMAQPC_RTOMIN, roce_info->rtomin));
	set_64bit_val(qp_ctx, 136,
		      FIELD_PREP(IRDMAQPC_TXCQNUM, info->send_cq_num) |
		      FIELD_PREP(IRDMAQPC_RXCQNUM, info->rcv_cq_num));
	set_64bit_val(qp_ctx, 144,
		      FIELD_PREP(IRDMAQPC_STAT_INDEX, info->stats_idx));
	set_64bit_val(qp_ctx, 152,
		      FIELD_PREP(IRDMAQPC_MACADDRESS,
				 ether_addr_to_u64(roce_info->mac_addr)));
	set_64bit_val(qp_ctx, 160,
		      FIELD_PREP(IRDMAQPC_ORDSIZE, roce_info->ord_size) |
		      FIELD_PREP(IRDMAQPC_IRDSIZE, irdma_sc_get_encoded_ird_size(roce_info->ird_size)) |
		      FIELD_PREP(IRDMAQPC_WRRDRSPOK, roce_info->wr_rdresp_en) |
		      FIELD_PREP(IRDMAQPC_RDOK, roce_info->rd_en) |
		      FIELD_PREP(IRDMAQPC_USESTATSINSTANCE, info->stats_idx_valid) |
		      FIELD_PREP(IRDMAQPC_FASTREGEN, roce_info->fast_reg_en) |
		      FIELD_PREP(IRDMAQPC_DCQCNENABLE, roce_info->dcqcn_en) |
		      FIELD_PREP(IRDMAQPC_RCVNOICRC, roce_info->rcv_no_icrc) |
		      FIELD_PREP(IRDMAQPC_FW_CC_ENABLE, roce_info->fw_cc_enable) |
		      FIELD_PREP(IRDMAQPC_UDPRIVCQENABLE, roce_info->udprivcq_en) |
		      FIELD_PREP(IRDMAQPC_PRIVEN, roce_info->priv_mode_en) |
		      FIELD_PREP(IRDMAQPC_TIMELYENABLE, roce_info->timely_en));
	set_64bit_val(qp_ctx, 168,
		      FIELD_PREP(IRDMAQPC_QPCOMPCTX, info->qp_compl_ctx));
	set_64bit_val(qp_ctx, 176,
		      FIELD_PREP(IRDMAQPC_SQTPHVAL, qp->sq_tph_val) |
		      FIELD_PREP(IRDMAQPC_RQTPHVAL, qp->rq_tph_val) |
		      FIELD_PREP(IRDMAQPC_QSHANDLE, qp->qs_handle));
	set_64bit_val(qp_ctx, 184,
		      FIELD_PREP(IRDMAQPC_LOCAL_IPADDR3, udp->local_ipaddr[3]) |
		      FIELD_PREP(IRDMAQPC_LOCAL_IPADDR2, udp->local_ipaddr[2]));
	set_64bit_val(qp_ctx, 192,
		      FIELD_PREP(IRDMAQPC_LOCAL_IPADDR1, udp->local_ipaddr[1]) |
		      FIELD_PREP(IRDMAQPC_LOCAL_IPADDR0, udp->local_ipaddr[0]));
	set_64bit_val(qp_ctx, 200,
		      FIELD_PREP(IRDMAQPC_THIGH, roce_info->t_high) |
		      FIELD_PREP(IRDMAQPC_TLOW, roce_info->t_low));
	set_64bit_val(qp_ctx, 208,
		      FIELD_PREP(IRDMAQPC_REMENDPOINTIDX, info->rem_endpoint_idx));

	print_hex_dump_debug("WQE: QP_HOST CTX WQE", DUMP_PREFIX_OFFSET, 16,
			     8, qp_ctx, IRDMA_QP_CTX_SIZE, false);
}

/**
 * irdma_sc_get_encoded_ird_size_gen_3 - get encoded IRD size for GEN 3
 * @ird_size: IRD size
 * The ird from the connection is rounded to a supported HW setting and then encoded
 * for ird_size field of qp_ctx. Consumers are expected to provide valid ird size based
 * on hardware attributes. IRD size defaults to a value of 4 in case of invalid input.
 */
static u8 irdma_sc_get_encoded_ird_size_gen_3(u16 ird_size)
{

	switch (ird_size ?
		roundup_pow_of_two(2 * ird_size) : 4) {
	case 4096:
		return IRDMA_IRD_HW_SIZE_4096_GEN3;
	case 2048:
		return IRDMA_IRD_HW_SIZE_2048_GEN3;
	case 1024:
		return IRDMA_IRD_HW_SIZE_1024_GEN3;
	case 512:
		return IRDMA_IRD_HW_SIZE_512_GEN3;
	case 256:
		return IRDMA_IRD_HW_SIZE_256_GEN3;
	case 128:
		return IRDMA_IRD_HW_SIZE_128_GEN3;
	case 64:
		return IRDMA_IRD_HW_SIZE_64_GEN3;
	case 32:
		return IRDMA_IRD_HW_SIZE_32_GEN3;
	case 16:
		return IRDMA_IRD_HW_SIZE_16_GEN3;
	case 8:
		return IRDMA_IRD_HW_SIZE_8_GEN3;
	case 4:
	default:
		break;
	}

	return IRDMA_IRD_HW_SIZE_4_GEN3;
}

/**
 * irdma_sc_qp_setctx_roce_gen_3 - set qp's context
 * @qp: sc qp
 * @qp_ctx: context ptr
 * @info: ctx info
 */
static void irdma_sc_qp_setctx_roce_gen_3(struct irdma_sc_qp *qp, __le64 *qp_ctx,
					  struct irdma_qp_host_ctx_info *info)
{
	struct irdma_roce_offload_info *roce_info = info->roce_info;
	struct irdma_udp_offload_info *udp = info->udp_info;
	u64 qw0, qw3, qw7 = 0, qw8 = 0;
	u8 push_mode_en;
	u8 rq_prefetch_en = 0;
	u32 push_idx;

	qp->user_pri = info->user_pri;
	if (qp->push_idx == IRDMA_INVALID_PUSH_PAGE_INDEX) {
		push_mode_en = 0;
		push_idx = 0;
	} else {
		push_mode_en = 1;
		push_idx = qp->push_idx;
	}
	if (qp->dev->hw_wa & RQ_PREFETCH_EN)
		rq_prefetch_en = 1;

	qw0 = FIELD_PREP(IRDMAQPC_RQWQESIZE, qp->qp_uk.rq_wqe_size) |
	      FIELD_PREP(IRDMAQPC_RCVTPHEN, qp->rcv_tph_en) |
	      FIELD_PREP(IRDMAQPC_XMITTPHEN, qp->xmit_tph_en) |
	      FIELD_PREP(IRDMAQPC_RQTPHEN, qp->rq_tph_en) |
	      FIELD_PREP(IRDMAQPC_SQTPHEN, qp->sq_tph_en) |
	      FIELD_PREP(IRDMAQPC_PPIDX, push_idx) |
	      FIELD_PREP(IRDMAQPC_PMENA, push_mode_en) |
	      FIELD_PREP(IRDMAQPSQ_FLUSH_MR, roce_info->flush_mr) |
	      FIELD_PREP(IRDMAQPC_RQ_PREFETCH_EN, rq_prefetch_en) |
	      FIELD_PREP(IRDMAQPC_DC_TCP_EN, roce_info->dctcp_en) |
	      FIELD_PREP(IRDMAQPC_ISQP1, roce_info->is_qp1) |
	      FIELD_PREP(IRDMAQPC_ROCE_TVER, roce_info->roce_tver) |
	      FIELD_PREP(IRDMAQPC_IPV4, udp->ipv4) |
	      FIELD_PREP(IRDMAQPC_USE_SRQ, !qp->qp_uk.srq_uk ? 0 : 1) |
	      FIELD_PREP(IRDMAQPC_INSERTVLANTAG, udp->insert_vlan_tag);
	set_64bit_val(qp_ctx, 0, qw0);
	set_64bit_val(qp_ctx, 8, qp->sq_pa);
	set_64bit_val(qp_ctx, 16, qp->rq_pa);
	qw3 = FIELD_PREP(IRDMAQPC_RQSIZE, qp->hw_rq_size) |
	      FIELD_PREP(IRDMAQPC_SQSIZE, qp->hw_sq_size) |
	      FIELD_PREP(IRDMAQPC_TTL, udp->ttl) |
	      FIELD_PREP(IRDMAQPC_TOS, udp->tos) |
	      FIELD_PREP(IRDMAQPC_SRCPORTNUM, udp->src_port) |
	      FIELD_PREP(IRDMAQPC_DESTPORTNUM, udp->dst_port);
	set_64bit_val(qp_ctx, 24, qw3);
	set_64bit_val(qp_ctx, 32,
		      FIELD_PREP(IRDMAQPC_DESTIPADDR2, udp->dest_ip_addr[2]) |
		      FIELD_PREP(IRDMAQPC_DESTIPADDR3, udp->dest_ip_addr[3]));
	set_64bit_val(qp_ctx, 40,
		      FIELD_PREP(IRDMAQPC_DESTIPADDR0, udp->dest_ip_addr[0]) |
		      FIELD_PREP(IRDMAQPC_DESTIPADDR1, udp->dest_ip_addr[1]));
	set_64bit_val(qp_ctx, 48,
		      FIELD_PREP(IRDMAQPC_SNDMSS, udp->snd_mss) |
		      FIELD_PREP(IRDMAQPC_VLANTAG, udp->vlan_tag) |
		      FIELD_PREP(IRDMAQPC_ARPIDX, udp->arp_idx));
	qw7 =  FIELD_PREP(IRDMAQPC_PKEY, roce_info->p_key) |
	       FIELD_PREP(IRDMAQPC_ACKCREDITS, roce_info->ack_credits) |
	       FIELD_PREP(IRDMAQPC_FLOWLABEL, udp->flow_label);
	set_64bit_val(qp_ctx, 56, qw7);
	qw8 = FIELD_PREP(IRDMAQPC_QKEY, roce_info->qkey) |
	      FIELD_PREP(IRDMAQPC_DESTQP, roce_info->dest_qp);
	set_64bit_val(qp_ctx, 64, qw8);
	set_64bit_val(qp_ctx, 72, roce_info->rca_key[0]);
	set_64bit_val(qp_ctx, 80,
		      FIELD_PREP(IRDMAQPC_PSNNXT, udp->psn_nxt) |
		      FIELD_PREP(IRDMAQPC_LSN, udp->lsn));
	set_64bit_val(qp_ctx, 88,
		      FIELD_PREP(IRDMAQPC_EPSN, udp->epsn));
	set_64bit_val(qp_ctx, 96,
		      FIELD_PREP(IRDMAQPC_PSNMAX, udp->psn_max) |
		      FIELD_PREP(IRDMAQPC_PSNUNA, udp->psn_una));
	set_64bit_val(qp_ctx, 104, roce_info->rca_key[1]);
	set_64bit_val(qp_ctx, 112,
		      FIELD_PREP(IRDMAQPC_CWNDROCE, udp->cwnd));
	set_64bit_val(qp_ctx, 128,
		      FIELD_PREP(IRDMAQPC_MINRNR_TIMER, udp->min_rnr_timer) |
		      FIELD_PREP(IRDMAQPC_RNRNAK_THRESH, udp->rnr_nak_thresh) |
		      FIELD_PREP(IRDMAQPC_REXMIT_THRESH, udp->rexmit_thresh) |
		      FIELD_PREP(IRDMAQPC_RNRNAK_TMR, udp->rnr_nak_tmr) |
		      FIELD_PREP(IRDMAQPC_RTOMIN, roce_info->rtomin));
	set_64bit_val(qp_ctx, 136,
		      FIELD_PREP(IRDMAQPC_TXCQNUM, info->send_cq_num) |
		      FIELD_PREP(IRDMAQPC_RXCQNUM, info->rcv_cq_num));
	set_64bit_val(qp_ctx, 152,
		      FIELD_PREP(IRDMAQPC_MACADDRESS,
				 ether_addr_to_u64(roce_info->mac_addr)) |
		      FIELD_PREP(IRDMAQPC_LOCALACKTIMEOUT,
				 roce_info->local_ack_timeout));
	set_64bit_val(qp_ctx, 160,
		      FIELD_PREP(IRDMAQPC_ORDSIZE_GEN3, roce_info->ord_size) |
		      FIELD_PREP(IRDMAQPC_IRDSIZE_GEN3,
				 irdma_sc_get_encoded_ird_size_gen_3(roce_info->ird_size)) |
		      FIELD_PREP(IRDMAQPC_WRRDRSPOK, roce_info->wr_rdresp_en) |
		      FIELD_PREP(IRDMAQPC_RDOK, roce_info->rd_en) |
		      FIELD_PREP(IRDMAQPC_USESTATSINSTANCE,
				 info->stats_idx_valid) |
		      FIELD_PREP(IRDMAQPC_BINDEN, roce_info->bind_en) |
		      FIELD_PREP(IRDMAQPC_FASTREGEN, roce_info->fast_reg_en) |
		      FIELD_PREP(IRDMAQPC_DCQCNENABLE, roce_info->dcqcn_en) |
		      FIELD_PREP(IRDMAQPC_RCVNOICRC, roce_info->rcv_no_icrc) |
		      FIELD_PREP(IRDMAQPC_FW_CC_ENABLE,
				 roce_info->fw_cc_enable) |
		      FIELD_PREP(IRDMAQPC_UDPRIVCQENABLE,
				 roce_info->udprivcq_en) |
		      FIELD_PREP(IRDMAQPC_PRIVEN, roce_info->priv_mode_en) |
		      FIELD_PREP(IRDMAQPC_REMOTE_ATOMIC_EN,
				 info->remote_atomics_en) |
		      FIELD_PREP(IRDMAQPC_TIMELYENABLE, roce_info->timely_en));
	set_64bit_val(qp_ctx, 168,
		      FIELD_PREP(IRDMAQPC_QPCOMPCTX, info->qp_compl_ctx));
	set_64bit_val(qp_ctx, 176,
		      FIELD_PREP(IRDMAQPC_SQTPHVAL, qp->sq_tph_val) |
		      FIELD_PREP(IRDMAQPC_RQTPHVAL, qp->rq_tph_val) |
		      FIELD_PREP(IRDMAQPC_QSHANDLE, qp->qs_handle));
	set_64bit_val(qp_ctx, 184,
		      FIELD_PREP(IRDMAQPC_LOCAL_IPADDR3, udp->local_ipaddr[3]) |
		      FIELD_PREP(IRDMAQPC_LOCAL_IPADDR2, udp->local_ipaddr[2]));
	set_64bit_val(qp_ctx, 192,
		      FIELD_PREP(IRDMAQPC_LOCAL_IPADDR1, udp->local_ipaddr[1]) |
		      FIELD_PREP(IRDMAQPC_LOCAL_IPADDR0, udp->local_ipaddr[0]));
	set_64bit_val(qp_ctx, 200,
		      FIELD_PREP(IRDMAQPC_THIGH, roce_info->t_high) |
		      FIELD_PREP(IRDMAQPC_SRQ_ID,
				 !qp->qp_uk.srq_uk ? 0 : qp->qp_uk.srq_uk->srq_id) |
		      FIELD_PREP(IRDMAQPC_TLOW, roce_info->t_low));
	set_64bit_val(qp_ctx, 208, roce_info->pd_id |
		      FIELD_PREP(IRDMAQPC_STAT_INDEX_GEN3, info->stats_idx) |
		      FIELD_PREP(IRDMAQPC_PKT_LIMIT, qp->pkt_limit));

	print_hex_dump_debug("WQE: QP_HOST ROCE CTX WQE", DUMP_PREFIX_OFFSET,
			     16, 8, qp_ctx, IRDMA_QP_CTX_SIZE, false);
}

void irdma_sc_qp_setctx_roce(struct irdma_sc_qp *qp, __le64 *qp_ctx,
			     struct irdma_qp_host_ctx_info *info)
{
	if (qp->dev->hw_attrs.uk_attrs.hw_rev == IRDMA_GEN_2)
		irdma_sc_qp_setctx_roce_gen_2(qp, qp_ctx, info);
	else
		irdma_sc_qp_setctx_roce_gen_3(qp, qp_ctx, info);
}

/* irdma_sc_alloc_local_mac_entry - allocate a mac entry
 * @cqp: struct for cqp hw
 * @scratch: u64 saved to be used during cqp completion
 * @post_sq: flag for cqp db to ring
 */
static int irdma_sc_alloc_local_mac_entry(struct irdma_sc_cqp *cqp, u64 scratch,
					  bool post_sq)
{
	__le64 *wqe;
	u64 hdr;

	wqe = irdma_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;

	hdr = FIELD_PREP(IRDMA_CQPSQ_OPCODE,
			 IRDMA_CQP_OP_ALLOCATE_LOC_MAC_TABLE_ENTRY) |
	      FIELD_PREP(IRDMA_CQPSQ_WQEVALID, cqp->polarity);

	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: ALLOCATE_LOCAL_MAC WQE",
			     DUMP_PREFIX_OFFSET, 16, 8, wqe,
			     IRDMA_CQP_WQE_SIZE * 8, false);

	if (post_sq)
		irdma_sc_cqp_post_sq(cqp);
	return 0;
}

/**
 * irdma_sc_add_local_mac_entry - add mac enry
 * @cqp: struct for cqp hw
 * @info:mac addr info
 * @scratch: u64 saved to be used during cqp completion
 * @post_sq: flag for cqp db to ring
 */
static int irdma_sc_add_local_mac_entry(struct irdma_sc_cqp *cqp,
					struct irdma_local_mac_entry_info *info,
					u64 scratch, bool post_sq)
{
	__le64 *wqe;
	u64 header;

	wqe = irdma_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;

	set_64bit_val(wqe, 32, ether_addr_to_u64(info->mac_addr));

	header = FIELD_PREP(IRDMA_CQPSQ_MLM_TABLEIDX, info->entry_idx) |
		 FIELD_PREP(IRDMA_CQPSQ_OPCODE,
			    IRDMA_CQP_OP_MANAGE_LOC_MAC_TABLE) |
		 FIELD_PREP(IRDMA_CQPSQ_WQEVALID, cqp->polarity);

	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, header);

	print_hex_dump_debug("WQE: ADD_LOCAL_MAC WQE", DUMP_PREFIX_OFFSET, 16,
			     8, wqe, IRDMA_CQP_WQE_SIZE * 8, false);

	if (post_sq)
		irdma_sc_cqp_post_sq(cqp);
	return 0;
}

/**
 * irdma_sc_del_local_mac_entry - cqp wqe to dele local mac
 * @cqp: struct for cqp hw
 * @scratch: u64 saved to be used during cqp completion
 * @entry_idx: index of mac entry
 * @ignore_ref_count: to force mac adde delete
 * @post_sq: flag for cqp db to ring
 */
static int irdma_sc_del_local_mac_entry(struct irdma_sc_cqp *cqp, u64 scratch,
					u16 entry_idx, u8 ignore_ref_count,
					bool post_sq)
{
	__le64 *wqe;
	u64 header;

	wqe = irdma_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;
	header = FIELD_PREP(IRDMA_CQPSQ_MLM_TABLEIDX, entry_idx) |
		 FIELD_PREP(IRDMA_CQPSQ_OPCODE,
			    IRDMA_CQP_OP_MANAGE_LOC_MAC_TABLE) |
		 FIELD_PREP(IRDMA_CQPSQ_MLM_FREEENTRY, 1) |
		 FIELD_PREP(IRDMA_CQPSQ_WQEVALID, cqp->polarity) |
		 FIELD_PREP(IRDMA_CQPSQ_MLM_IGNORE_REF_CNT, ignore_ref_count);

	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, header);

	print_hex_dump_debug("WQE: DEL_LOCAL_MAC_IPADDR WQE",
			     DUMP_PREFIX_OFFSET, 16, 8, wqe,
			     IRDMA_CQP_WQE_SIZE * 8, false);

	if (post_sq)
		irdma_sc_cqp_post_sq(cqp);
	return 0;
}

/**
 * irdma_sc_qp_setctx - set qp's context
 * @qp: sc qp
 * @qp_ctx: context ptr
 * @info: ctx info
 */
void irdma_sc_qp_setctx(struct irdma_sc_qp *qp, __le64 *qp_ctx,
			struct irdma_qp_host_ctx_info *info)
{
	struct irdma_iwarp_offload_info *iw;
	struct irdma_tcp_offload_info *tcp;
	struct irdma_sc_dev *dev;
	u8 push_mode_en;
	u32 push_idx;
	u64 qw0, qw3, qw7 = 0, qw16 = 0;
	u64 mac = 0;

	iw = info->iwarp_info;
	tcp = info->tcp_info;
	dev = qp->dev;
	if (iw->rcv_mark_en) {
		qp->pfpdu.marker_len = 4;
		qp->pfpdu.rcv_start_seq = tcp->rcv_nxt;
	}
	qp->user_pri = info->user_pri;
	if (qp->push_idx == IRDMA_INVALID_PUSH_PAGE_INDEX) {
		push_mode_en = 0;
		push_idx = 0;
	} else {
		push_mode_en = 1;
		push_idx = qp->push_idx;
	}
	qw0 = FIELD_PREP(IRDMAQPC_RQWQESIZE, qp->qp_uk.rq_wqe_size) |
	      FIELD_PREP(IRDMAQPC_RCVTPHEN, qp->rcv_tph_en) |
	      FIELD_PREP(IRDMAQPC_XMITTPHEN, qp->xmit_tph_en) |
	      FIELD_PREP(IRDMAQPC_RQTPHEN, qp->rq_tph_en) |
	      FIELD_PREP(IRDMAQPC_SQTPHEN, qp->sq_tph_en) |
	      FIELD_PREP(IRDMAQPC_PPIDX, push_idx) |
	      FIELD_PREP(IRDMAQPC_PMENA, push_mode_en);

	set_64bit_val(qp_ctx, 8, qp->sq_pa);
	set_64bit_val(qp_ctx, 16, qp->rq_pa);

	qw3 = FIELD_PREP(IRDMAQPC_RQSIZE, qp->hw_rq_size) |
	      FIELD_PREP(IRDMAQPC_SQSIZE, qp->hw_sq_size);
	if (dev->hw_attrs.uk_attrs.hw_rev == IRDMA_GEN_1)
		qw3 |= FIELD_PREP(IRDMAQPC_GEN1_SRCMACADDRIDX,
				  qp->src_mac_addr_idx);
	set_64bit_val(qp_ctx, 136,
		      FIELD_PREP(IRDMAQPC_TXCQNUM, info->send_cq_num) |
		      FIELD_PREP(IRDMAQPC_RXCQNUM, info->rcv_cq_num));
	set_64bit_val(qp_ctx, 168,
		      FIELD_PREP(IRDMAQPC_QPCOMPCTX, info->qp_compl_ctx));
	set_64bit_val(qp_ctx, 176,
		      FIELD_PREP(IRDMAQPC_SQTPHVAL, qp->sq_tph_val) |
		      FIELD_PREP(IRDMAQPC_RQTPHVAL, qp->rq_tph_val) |
		      FIELD_PREP(IRDMAQPC_QSHANDLE, qp->qs_handle) |
		      FIELD_PREP(IRDMAQPC_EXCEPTION_LAN_QUEUE, qp->ieq_qp));
	if (info->iwarp_info_valid) {
		qw0 |= FIELD_PREP(IRDMAQPC_DDP_VER, iw->ddp_ver) |
		       FIELD_PREP(IRDMAQPC_RDMAP_VER, iw->rdmap_ver) |
		       FIELD_PREP(IRDMAQPC_DC_TCP_EN, iw->dctcp_en) |
		       FIELD_PREP(IRDMAQPC_ECN_EN, iw->ecn_en) |
		       FIELD_PREP(IRDMAQPC_IBRDENABLE, iw->ib_rd_en) |
		       FIELD_PREP(IRDMAQPC_PDIDXHI, iw->pd_id >> 16) |
		       FIELD_PREP(IRDMAQPC_ERR_RQ_IDX_VALID,
				  iw->err_rq_idx_valid);
		qw7 |= FIELD_PREP(IRDMAQPC_PDIDX, iw->pd_id);
		qw16 |= FIELD_PREP(IRDMAQPC_ERR_RQ_IDX, iw->err_rq_idx) |
			FIELD_PREP(IRDMAQPC_RTOMIN, iw->rtomin);
		set_64bit_val(qp_ctx, 144,
			      FIELD_PREP(IRDMAQPC_Q2ADDR, qp->q2_pa >> 8) |
			      FIELD_PREP(IRDMAQPC_STAT_INDEX, info->stats_idx));

		if (dev->hw_attrs.uk_attrs.hw_rev >= IRDMA_GEN_2)
			mac = FIELD_PREP(IRDMAQPC_MACADDRESS,
					 ether_addr_to_u64(iw->mac_addr));

		set_64bit_val(qp_ctx, 152,
			      mac | FIELD_PREP(IRDMAQPC_LASTBYTESENT, iw->last_byte_sent));
		set_64bit_val(qp_ctx, 160,
			      FIELD_PREP(IRDMAQPC_ORDSIZE, iw->ord_size) |
			      FIELD_PREP(IRDMAQPC_IRDSIZE, irdma_sc_get_encoded_ird_size(iw->ird_size)) |
			      FIELD_PREP(IRDMAQPC_WRRDRSPOK, iw->wr_rdresp_en) |
			      FIELD_PREP(IRDMAQPC_RDOK, iw->rd_en) |
			      FIELD_PREP(IRDMAQPC_SNDMARKERS, iw->snd_mark_en) |
			      FIELD_PREP(IRDMAQPC_FASTREGEN, iw->fast_reg_en) |
			      FIELD_PREP(IRDMAQPC_PRIVEN, iw->priv_mode_en) |
			      FIELD_PREP(IRDMAQPC_USESTATSINSTANCE, info->stats_idx_valid) |
			      FIELD_PREP(IRDMAQPC_IWARPMODE, 1) |
			      FIELD_PREP(IRDMAQPC_RCVMARKERS, iw->rcv_mark_en) |
			      FIELD_PREP(IRDMAQPC_ALIGNHDRS, iw->align_hdrs) |
			      FIELD_PREP(IRDMAQPC_RCVNOMPACRC, iw->rcv_no_mpa_crc) |
			      FIELD_PREP(IRDMAQPC_RCVMARKOFFSET, iw->rcv_mark_offset || !tcp ? iw->rcv_mark_offset : tcp->rcv_nxt) |
			      FIELD_PREP(IRDMAQPC_SNDMARKOFFSET, iw->snd_mark_offset || !tcp ? iw->snd_mark_offset : tcp->snd_nxt) |
			      FIELD_PREP(IRDMAQPC_TIMELYENABLE, iw->timely_en));
	}
	if (info->tcp_info_valid) {
		qw0 |= FIELD_PREP(IRDMAQPC_IPV4, tcp->ipv4) |
		       FIELD_PREP(IRDMAQPC_NONAGLE, tcp->no_nagle) |
		       FIELD_PREP(IRDMAQPC_INSERTVLANTAG,
				  tcp->insert_vlan_tag) |
		       FIELD_PREP(IRDMAQPC_TIMESTAMP, tcp->time_stamp) |
		       FIELD_PREP(IRDMAQPC_LIMIT, tcp->cwnd_inc_limit) |
		       FIELD_PREP(IRDMAQPC_DROPOOOSEG, tcp->drop_ooo_seg) |
		       FIELD_PREP(IRDMAQPC_DUPACK_THRESH, tcp->dup_ack_thresh);
		if (iw->ecn_en || iw->dctcp_en) {
			tcp->tos &= ~ECN_CODE_PT_MASK;
			tcp->tos |= ECN_CODE_PT_VAL;
		}

		qw3 |= FIELD_PREP(IRDMAQPC_TTL, tcp->ttl) |
		       FIELD_PREP(IRDMAQPC_AVOIDSTRETCHACK, tcp->avoid_stretch_ack) |
		       FIELD_PREP(IRDMAQPC_TOS, tcp->tos) |
		       FIELD_PREP(IRDMAQPC_SRCPORTNUM, tcp->src_port) |
		       FIELD_PREP(IRDMAQPC_DESTPORTNUM, tcp->dst_port);
		if (dev->hw_attrs.uk_attrs.hw_rev == IRDMA_GEN_1) {
			qw3 |= FIELD_PREP(IRDMAQPC_GEN1_SRCMACADDRIDX, tcp->src_mac_addr_idx);

			qp->src_mac_addr_idx = tcp->src_mac_addr_idx;
		}
		set_64bit_val(qp_ctx, 32,
			      FIELD_PREP(IRDMAQPC_DESTIPADDR2, tcp->dest_ip_addr[2]) |
			      FIELD_PREP(IRDMAQPC_DESTIPADDR3, tcp->dest_ip_addr[3]));
		set_64bit_val(qp_ctx, 40,
			      FIELD_PREP(IRDMAQPC_DESTIPADDR0, tcp->dest_ip_addr[0]) |
			      FIELD_PREP(IRDMAQPC_DESTIPADDR1, tcp->dest_ip_addr[1]));
		set_64bit_val(qp_ctx, 48,
			      FIELD_PREP(IRDMAQPC_SNDMSS, tcp->snd_mss) |
			      FIELD_PREP(IRDMAQPC_SYN_RST_HANDLING, tcp->syn_rst_handling) |
			      FIELD_PREP(IRDMAQPC_VLANTAG, tcp->vlan_tag) |
			      FIELD_PREP(IRDMAQPC_ARPIDX, tcp->arp_idx));
		qw7 |= FIELD_PREP(IRDMAQPC_FLOWLABEL, tcp->flow_label) |
		       FIELD_PREP(IRDMAQPC_WSCALE, tcp->wscale) |
		       FIELD_PREP(IRDMAQPC_IGNORE_TCP_OPT,
				  tcp->ignore_tcp_opt) |
		       FIELD_PREP(IRDMAQPC_IGNORE_TCP_UNS_OPT,
				  tcp->ignore_tcp_uns_opt) |
		       FIELD_PREP(IRDMAQPC_TCPSTATE, tcp->tcp_state) |
		       FIELD_PREP(IRDMAQPC_RCVSCALE, tcp->rcv_wscale) |
		       FIELD_PREP(IRDMAQPC_SNDSCALE, tcp->snd_wscale);
		set_64bit_val(qp_ctx, 72,
			      FIELD_PREP(IRDMAQPC_TIMESTAMP_RECENT, tcp->time_stamp_recent) |
			      FIELD_PREP(IRDMAQPC_TIMESTAMP_AGE, tcp->time_stamp_age));
		set_64bit_val(qp_ctx, 80,
			      FIELD_PREP(IRDMAQPC_SNDNXT, tcp->snd_nxt) |
			      FIELD_PREP(IRDMAQPC_SNDWND, tcp->snd_wnd));
		set_64bit_val(qp_ctx, 88,
			      FIELD_PREP(IRDMAQPC_RCVNXT, tcp->rcv_nxt) |
			      FIELD_PREP(IRDMAQPC_RCVWND, tcp->rcv_wnd));
		set_64bit_val(qp_ctx, 96,
			      FIELD_PREP(IRDMAQPC_SNDMAX, tcp->snd_max) |
			      FIELD_PREP(IRDMAQPC_SNDUNA, tcp->snd_una));
		set_64bit_val(qp_ctx, 104,
			      FIELD_PREP(IRDMAQPC_SRTT, tcp->srtt) |
			      FIELD_PREP(IRDMAQPC_RTTVAR, tcp->rtt_var));
		set_64bit_val(qp_ctx, 112,
			      FIELD_PREP(IRDMAQPC_SSTHRESH, tcp->ss_thresh) |
			      FIELD_PREP(IRDMAQPC_CWND, tcp->cwnd));
		set_64bit_val(qp_ctx, 120,
			      FIELD_PREP(IRDMAQPC_SNDWL1, tcp->snd_wl1) |
			      FIELD_PREP(IRDMAQPC_SNDWL2, tcp->snd_wl2));
		qw16 |= FIELD_PREP(IRDMAQPC_MAXSNDWND, tcp->max_snd_window) |
			FIELD_PREP(IRDMAQPC_REXMIT_THRESH, tcp->rexmit_thresh);
		set_64bit_val(qp_ctx, 184,
			      FIELD_PREP(IRDMAQPC_LOCAL_IPADDR3, tcp->local_ipaddr[3]) |
			      FIELD_PREP(IRDMAQPC_LOCAL_IPADDR2, tcp->local_ipaddr[2]));
		set_64bit_val(qp_ctx, 192,
			      FIELD_PREP(IRDMAQPC_LOCAL_IPADDR1, tcp->local_ipaddr[1]) |
			      FIELD_PREP(IRDMAQPC_LOCAL_IPADDR0, tcp->local_ipaddr[0]));
		set_64bit_val(qp_ctx, 200,
			      FIELD_PREP(IRDMAQPC_THIGH, iw->t_high) |
			      FIELD_PREP(IRDMAQPC_TLOW, iw->t_low));
		set_64bit_val(qp_ctx, 208,
			      FIELD_PREP(IRDMAQPC_REMENDPOINTIDX, info->rem_endpoint_idx));
	}

	set_64bit_val(qp_ctx, 0, qw0);
	set_64bit_val(qp_ctx, 24, qw3);
	set_64bit_val(qp_ctx, 56, qw7);
	set_64bit_val(qp_ctx, 128, qw16);

	print_hex_dump_debug("WQE: QP_HOST CTX", DUMP_PREFIX_OFFSET, 16, 8,
			     qp_ctx, IRDMA_QP_CTX_SIZE, false);
}

/**
 * irdma_sc_alloc_stag - mr stag alloc
 * @dev: sc device struct
 * @info: stag info
 * @scratch: u64 saved to be used during cqp completion
 * @post_sq: flag for cqp db to ring
 */
static int irdma_sc_alloc_stag(struct irdma_sc_dev *dev,
			       struct irdma_allocate_stag_info *info,
			       u64 scratch, bool post_sq)
{
	__le64 *wqe;
	struct irdma_sc_cqp *cqp;
	u64 hdr;
	enum irdma_page_size page_size;

	if (!info->total_len && !info->all_memory)
		return -EINVAL;

	if (info->page_size == 0x40000000)
		page_size = IRDMA_PAGE_SIZE_1G;
	else if (info->page_size == 0x200000)
		page_size = IRDMA_PAGE_SIZE_2M;
	else
		page_size = IRDMA_PAGE_SIZE_4K;

	cqp = dev->cqp;
	wqe = irdma_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;

	set_64bit_val(wqe, 8,
		      FLD_LS_64(dev, info->pd_id, IRDMA_CQPSQ_STAG_PDID) |
		      FIELD_PREP(IRDMA_CQPSQ_STAG_STAGLEN, info->total_len));
	set_64bit_val(wqe, 16,
		      FIELD_PREP(IRDMA_CQPSQ_STAG_IDX, info->stag_idx) |
		      FIELD_PREP(IRDMA_CQPSQ_STAG_PDID_HI, info->pd_id >> 18));
	if (dev->hw_attrs.uk_attrs.hw_rev < IRDMA_GEN_3) {
		set_64bit_val(wqe, 40,
			      FIELD_PREP(IRDMA_CQPSQ_STAG_HMCFNIDX, info->hmc_fcn_index));
	} else {
		hdr = 0;
		hdr |= FIELD_PREP(IRDMA_CQPSQ_STAG_HMCFNIDX, info->hmc_fcn_index);
		if (dev->hw_attrs.uk_attrs.hw_rev >= IRDMA_GEN_4)
			hdr |= FIELD_PREP(IRDMA_CQPSQ_STAG_NON_CACHED, info->non_cached);
		set_64bit_val(wqe, 40, hdr);
	}

	if (info->chunk_size)
		set_64bit_val(wqe, 48,
			      FIELD_PREP(IRDMA_CQPSQ_STAG_FIRSTPMPBLIDX, info->first_pm_pbl_idx));

	hdr = FIELD_PREP(IRDMA_CQPSQ_OPCODE, IRDMA_CQP_OP_ALLOC_STAG) |
	      FIELD_PREP(IRDMA_CQPSQ_STAG_MR, 1) |
	      FIELD_PREP(IRDMA_CQPSQ_STAG_ARIGHTS, info->access_rights) |
	      FIELD_PREP(IRDMA_CQPSQ_STAG_LPBLSIZE, info->chunk_size) |
	      FIELD_PREP(IRDMA_CQPSQ_STAG_HPAGESIZE, page_size) |
	      FIELD_PREP(IRDMA_CQPSQ_STAG_REMACCENABLED, info->remote_access) |
	      FIELD_PREP(IRDMA_CQPSQ_STAG_PLACEMENTTYPE, info->placement_type) |
	      FIELD_PREP(IRDMA_CQPSQ_WQEVALID, cqp->polarity);
	if (dev->hw_attrs.uk_attrs.hw_rev >= IRDMA_GEN_3) {
		hdr |= FIELD_PREP(IRDMA_CQPSQ_STAG_REMOTE_ATOMIC_EN, info->remote_atomics_en);
		hdr |= FIELD_PREP(IRDMA_CQPSQ_STAG_USEHMCFNIDX, info->use_hmc_fcn_index);
	} else {
		/* for FNIC, a PF can send this WQE for a VF */
		hdr |= FIELD_PREP(IRDMA_CQPSQ_STAG_USEHMCFNIDX, info->use_hmc_fcn_index);
	}
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: ALLOC_STAG WQE", DUMP_PREFIX_OFFSET, 16, 8,
			     wqe, IRDMA_CQP_WQE_SIZE * 8, false);
	if (post_sq)
		irdma_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * irdma_sc_mr_reg_non_shared - non-shared mr registration
 * @dev: sc device struct
 * @info: mr info
 * @scratch: u64 saved to be used during cqp completion
 * @post_sq: flag for cqp db to ring
 */
static int irdma_sc_mr_reg_non_shared(struct irdma_sc_dev *dev,
				      struct irdma_reg_ns_stag_info *info,
				      u64 scratch, bool post_sq)
{
	__le64 *wqe;
	u64 fbo;
	struct irdma_sc_cqp *cqp;
	u64 hdr;
	u32 pble_obj_cnt;
	bool remote_access;
	u8 addr_type;
	enum irdma_page_size page_size;

	if (!info->total_len && !info->all_memory)
		return -EINVAL;

	if (info->page_size == 0x40000000)
		page_size = IRDMA_PAGE_SIZE_1G;
	else if (info->page_size == 0x200000)
		page_size = IRDMA_PAGE_SIZE_2M;
	else if (info->page_size == 0x1000)
		page_size = IRDMA_PAGE_SIZE_4K;
	else
		return -EINVAL;

	if (info->access_rights & (IRDMA_ACCESS_FLAGS_REMOTEREAD_ONLY |
				   IRDMA_ACCESS_FLAGS_REMOTEWRITE_ONLY))
		remote_access = true;
	else
		remote_access = false;

	pble_obj_cnt = dev->hmc_info->hmc_obj[IRDMA_HMC_IW_PBLE].cnt;
	if (info->chunk_size && info->first_pm_pbl_index >= pble_obj_cnt)
		return -EINVAL;

	cqp = dev->cqp;
	wqe = irdma_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;
	fbo = info->va & (info->page_size - 1);

	set_64bit_val(wqe, 0,
		      (info->addr_type == IRDMA_ADDR_TYPE_VA_BASED ?
		      info->va : fbo));
	set_64bit_val(wqe, 8,
		      FIELD_PREP(IRDMA_CQPSQ_STAG_STAGLEN, info->total_len) |
		      FLD_LS_64(dev, info->pd_id, IRDMA_CQPSQ_STAG_PDID));
	set_64bit_val(wqe, 16,
		      FIELD_PREP(IRDMA_CQPSQ_STAG_KEY, info->stag_key) |
		      FIELD_PREP(IRDMA_CQPSQ_STAG_PDID_HI, info->pd_id >> 18) |
		      FIELD_PREP(IRDMA_CQPSQ_STAG_IDX, info->stag_idx));
	if (!info->chunk_size)
		set_64bit_val(wqe, 32, info->reg_addr_pa);
	else
		set_64bit_val(wqe, 48,
			      FIELD_PREP(IRDMA_CQPSQ_STAG_FIRSTPMPBLIDX, info->first_pm_pbl_index));
	set_64bit_val(wqe, 40, FIELD_PREP(IRDMA_CQPSQ_STAG_NON_CACHED, info->non_cached) |
		      info->hmc_fcn_index);
	set_64bit_val(wqe, 56,
		      FIELD_PREP(IRDMA_CQPSQ_PASID, info->pasid));

	addr_type = (info->addr_type == IRDMA_ADDR_TYPE_VA_BASED) ? 1 : 0;
	hdr = FIELD_PREP(IRDMA_CQPSQ_OPCODE, IRDMA_CQP_OP_REG_MR) |
	      FIELD_PREP(IRDMA_CQPSQ_STAG_MR, 1) |
	      FIELD_PREP(IRDMA_CQPSQ_STAG_LPBLSIZE, info->chunk_size) |
	      FIELD_PREP(IRDMA_CQPSQ_STAG_HPAGESIZE, page_size) |
	      FIELD_PREP(IRDMA_CQPSQ_STAG_ARIGHTS, info->access_rights) |
	      FIELD_PREP(IRDMA_CQPSQ_STAG_REMACCENABLED, remote_access) |
	      FIELD_PREP(IRDMA_CQPSQ_STAG_VABASEDTO, addr_type) |
	      FIELD_PREP(IRDMA_CQPSQ_STAG_USEHMCFNIDX, info->use_hmc_fcn_index) |
	      FIELD_PREP(IRDMA_CQPSQ_STAG_PLACEMENTTYPE, info->placement_type) |
	      FIELD_PREP(IRDMA_CQPSQ_PASID_VALID, info->pasid_valid) |
	      FIELD_PREP(IRDMA_CQPSQ_STAG_REMOTE_ATOMIC_EN,
			 info->remote_atomics_en) |
	      FIELD_PREP(IRDMA_CQPSQ_WQEVALID, cqp->polarity);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: MR_REG_NS WQE", DUMP_PREFIX_OFFSET, 16, 8,
			     wqe, IRDMA_CQP_WQE_SIZE * 8, false);
	if (post_sq)
		irdma_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * irdma_sc_dealloc_stag - deallocate stag
 * @dev: sc device struct
 * @info: dealloc stag info
 * @scratch: u64 saved to be used during cqp completion
 * @post_sq: flag for cqp db to ring
 */
static int irdma_sc_dealloc_stag(struct irdma_sc_dev *dev,
				 struct irdma_dealloc_stag_info *info,
				 u64 scratch, bool post_sq)
{
	u64 hdr;
	__le64 *wqe;
	struct irdma_sc_cqp *cqp;

	cqp = dev->cqp;
	wqe = irdma_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;

	set_64bit_val(wqe, 8,
		      FLD_LS_64(dev, info->pd_id, IRDMA_CQPSQ_STAG_PDID));
	set_64bit_val(wqe, 16,
		      FIELD_PREP(IRDMA_CQPSQ_STAG_IDX, info->stag_idx) |
		      FIELD_PREP(IRDMA_CQPSQ_STAG_PDID_HI, info->pd_id >> 18));

	hdr = FIELD_PREP(IRDMA_CQPSQ_OPCODE, IRDMA_CQP_OP_DEALLOC_STAG) |
	      FIELD_PREP(IRDMA_CQPSQ_STAG_MR, info->mr) |
	      FIELD_PREP(IRDMA_CQPSQ_WQEVALID, cqp->polarity);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: DEALLOC_STAG WQE", DUMP_PREFIX_OFFSET, 16,
			     8, wqe, IRDMA_CQP_WQE_SIZE * 8, false);
	if (post_sq)
		irdma_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * irdma_sc_mw_alloc - mw allocate
 * @dev: sc device struct
 * @info: memory window allocation information
 * @scratch: u64 saved to be used during cqp completion
 * @post_sq: flag for cqp db to ring
 */
static int irdma_sc_mw_alloc(struct irdma_sc_dev *dev,
			     struct irdma_mw_alloc_info *info, u64 scratch,
			     bool post_sq)
{
	u64 hdr;
	struct irdma_sc_cqp *cqp;
	__le64 *wqe;

	cqp = dev->cqp;
	wqe = irdma_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;

	set_64bit_val(wqe, 8,
		      FLD_LS_64(dev, info->pd_id, IRDMA_CQPSQ_STAG_PDID));
	set_64bit_val(wqe, 16,
		      FIELD_PREP(IRDMA_CQPSQ_STAG_IDX, info->mw_stag_index) |
		      FIELD_PREP(IRDMA_CQPSQ_STAG_PDID_HI, info->pd_id >> 18));

	hdr = FIELD_PREP(IRDMA_CQPSQ_OPCODE, IRDMA_CQP_OP_ALLOC_STAG) |
	      FIELD_PREP(IRDMA_CQPSQ_STAG_MWTYPE, info->mw_wide) |
	      FIELD_PREP(IRDMA_CQPSQ_STAG_MW1_BIND_DONT_VLDT_KEY,
			 info->mw1_bind_dont_vldt_key) |
	      FIELD_PREP(IRDMA_CQPSQ_WQEVALID, cqp->polarity);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: MW_ALLOC WQE", DUMP_PREFIX_OFFSET, 16, 8,
			     wqe, IRDMA_CQP_WQE_SIZE * 8, false);
	if (post_sq)
		irdma_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * irdma_sc_mr_fast_register - Posts RDMA fast register mr WR to iwarp qp
 * @qp: sc qp struct
 * @info: fast mr info
 * @post_sq: flag for cqp db to ring
 */
int irdma_sc_mr_fast_register(struct irdma_sc_qp *qp,
			      struct irdma_fast_reg_stag_info *info,
			      bool post_sq)
{
	u64 temp, hdr;
	__le64 *wqe;
	u32 wqe_idx;
	u16 quanta = IRDMA_QP_WQE_MIN_QUANTA;
	enum irdma_page_size page_size;
	struct irdma_post_sq_info sq_info = {};

	if (info->page_size == 0x40000000)
		page_size = IRDMA_PAGE_SIZE_1G;
	else if (info->page_size == 0x200000)
		page_size = IRDMA_PAGE_SIZE_2M;
	else
		page_size = IRDMA_PAGE_SIZE_4K;

	sq_info.wr_id = info->wr_id;
	sq_info.signaled = info->signaled;
	sq_info.push_wqe = info->push_wqe;

	wqe = irdma_qp_get_next_send_wqe(&qp->qp_uk, &wqe_idx, &quanta, 0, &sq_info);
	if (!wqe)
		return -ENOMEM;

	ibdev_dbg(to_ibdev(qp->dev),
		  "MR: wr_id[%llxh] wqe_idx[%04d] location[%p]\n",
		  info->wr_id, wqe_idx,
		  &qp->qp_uk.sq_wrtrk_array[wqe_idx].wrid);

	temp = (info->addr_type == IRDMA_ADDR_TYPE_VA_BASED) ?
		(uintptr_t)info->va : info->fbo;
	set_64bit_val(wqe, 0, temp);

	temp = FIELD_GET(IRDMAQPSQ_FIRSTPMPBLIDXHI,
			 info->first_pm_pbl_index >> 16);
	set_64bit_val(wqe, 8,
		      FIELD_PREP(IRDMAQPSQ_FIRSTPMPBLIDXHI, temp) |
		      FIELD_PREP(IRDMAQPSQ_PBLADDR, info->reg_addr_pa >> IRDMA_HW_PAGE_SHIFT));
	set_64bit_val(wqe, 16,
		      info->total_len |
		      FIELD_PREP(IRDMAQPSQ_FIRSTPMPBLIDXLO, info->first_pm_pbl_index));
	hdr = FIELD_PREP(IRDMAQPSQ_STAGKEY, info->stag_key) |
	      FIELD_PREP(IRDMAQPSQ_STAGINDEX, info->stag_idx) |
	      FIELD_PREP(IRDMAQPSQ_OPCODE, IRDMAQP_OP_FAST_REGISTER) |
	      FIELD_PREP(IRDMAQPSQ_LPBLSIZE, info->chunk_size) |
	      FIELD_PREP(IRDMAQPSQ_HPAGESIZE, page_size) |
	      FIELD_PREP(IRDMAQPSQ_STAGRIGHTS, info->access_rights) |
	      FIELD_PREP(IRDMAQPSQ_VABASEDTO, info->addr_type) |
	      FIELD_PREP(IRDMAQPSQ_PUSHWQE, (sq_info.push_wqe ? 1 : 0)) |
	      FIELD_PREP(IRDMAQPSQ_READFENCE, info->read_fence) |
	      FIELD_PREP(IRDMAQPSQ_LOCALFENCE, info->local_fence) |
	      FIELD_PREP(IRDMAQPSQ_SIGCOMPL, info->signaled) |
	      FIELD_PREP(IRDMAQPSQ_REMOTE_ATOMICS_EN, info->remote_atomics_en) |
	      FIELD_PREP(IRDMAQPSQ_VALID, qp->qp_uk.swqe_polarity);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: FAST_REG WQE", DUMP_PREFIX_OFFSET, 16, 8,
			     wqe, quanta * IRDMA_QP_WQE_MIN_SIZE, false);
	if (sq_info.push_wqe)
		irdma_qp_push_wqe(&qp->qp_uk, wqe, quanta, wqe_idx, post_sq);
	else if (post_sq)
		irdma_uk_qp_post_wr(&qp->qp_uk);

	return 0;
}

/**
 * irdma_sc_gen_rts_ae - request AE generated after RTS
 * @qp: sc qp struct
 */
static void irdma_sc_gen_rts_ae(struct irdma_sc_qp *qp)
{
	__le64 *wqe;
	u64 hdr;
	struct irdma_qp_uk *qp_uk;

	qp_uk = &qp->qp_uk;

	wqe = qp_uk->sq_base[1].elem;

	hdr = FIELD_PREP(IRDMAQPSQ_OPCODE, IRDMAQP_OP_NOP) |
	      FIELD_PREP(IRDMAQPSQ_LOCALFENCE, 1) |
	      FIELD_PREP(IRDMAQPSQ_VALID, qp->qp_uk.swqe_polarity);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);
	print_hex_dump_debug("QP: NOP W/LOCAL FENCE WQE", DUMP_PREFIX_OFFSET,
			     16, 8, wqe, IRDMA_QP_WQE_MIN_SIZE, false);

	wqe = qp_uk->sq_base[2].elem;
	hdr = FIELD_PREP(IRDMAQPSQ_OPCODE, IRDMAQP_OP_GEN_RTS_AE) |
	      FIELD_PREP(IRDMAQPSQ_VALID, qp->qp_uk.swqe_polarity);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);
	print_hex_dump_debug("QP: CONN EST WQE", DUMP_PREFIX_OFFSET, 16, 8,
			     wqe, IRDMA_QP_WQE_MIN_SIZE, false);
	if (qp->qp_uk.start_wqe_idx) {
		wqe = qp_uk->sq_base[3].elem;
		hdr = FIELD_PREP(IRDMAQPSQ_OPCODE, IRDMAQP_OP_NOP) |
		      FIELD_PREP(IRDMAQPSQ_LOCALFENCE, 1) |
		      FIELD_PREP(IRDMAQPSQ_VALID, qp->qp_uk.swqe_polarity);
		dma_wmb(); /* make sure WQE is written before valid bit is set */

		set_64bit_val(wqe, 24, hdr);
	}
}

/**
 * irdma_sc_send_lsmm - send last streaming mode message
 * @qp: sc qp struct
 * @lsmm_buf: buffer with lsmm message
 * @size: size of lsmm buffer
 * @stag: stag of lsmm buffer
 */
void irdma_sc_send_lsmm(struct irdma_sc_qp *qp, void *lsmm_buf, u32 size,
			irdma_stag stag)
{
	__le64 *wqe;
	u64 hdr;
	struct irdma_qp_uk *qp_uk;

	qp_uk = &qp->qp_uk;
	wqe = qp_uk->sq_base->elem;

	set_64bit_val(wqe, 0, (uintptr_t)lsmm_buf);
	if (qp->qp_uk.uk_attrs->hw_rev == IRDMA_GEN_1) {
		set_64bit_val(wqe, 8,
			      FIELD_PREP(IRDMAQPSQ_GEN1_FRAG_LEN, size) |
			      FIELD_PREP(IRDMAQPSQ_GEN1_FRAG_STAG, stag));
	} else {
		set_64bit_val(wqe, 8,
			      FIELD_PREP(IRDMAQPSQ_FRAG_LEN, size) |
			      FIELD_PREP(IRDMAQPSQ_FRAG_STAG, stag) |
			      FIELD_PREP(IRDMAQPSQ_VALID, qp->qp_uk.swqe_polarity));
	}
	set_64bit_val(wqe, 16, 0);

	hdr = FIELD_PREP(IRDMAQPSQ_OPCODE, IRDMAQP_OP_RDMA_SEND) |
	      FIELD_PREP(IRDMAQPSQ_STREAMMODE, 1) |
	      FIELD_PREP(IRDMAQPSQ_WAITFORRCVPDU, 1) |
	      FIELD_PREP(IRDMAQPSQ_VALID, qp->qp_uk.swqe_polarity);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: SEND_LSMM WQE", DUMP_PREFIX_OFFSET, 16, 8,
		             wqe, IRDMA_QP_WQE_MIN_SIZE, false);

	if (qp->dev->hw_attrs.uk_attrs.feature_flags & IRDMA_FEATURE_RTS_AE)
		irdma_sc_gen_rts_ae(qp);
}

/**
 * irdma_sc_send_rtt - send last read0 or write0
 * @qp: sc qp struct
 * @read: Do read0 or write0
 */
void irdma_sc_send_rtt(struct irdma_sc_qp *qp, bool read)
{
	__le64 *wqe;
	u64 hdr;
	struct irdma_qp_uk *qp_uk;

	qp_uk = &qp->qp_uk;
	wqe = qp_uk->sq_base->elem;

	set_64bit_val(wqe, 0, 0);
	set_64bit_val(wqe, 16, 0);
	if (read) {
		if (qp->qp_uk.uk_attrs->hw_rev == IRDMA_GEN_1) {
			set_64bit_val(wqe, 8,
				      FIELD_PREP(IRDMAQPSQ_GEN1_FRAG_STAG, 0xabcd));
		} else {
			set_64bit_val(wqe, 8,
				      (u64)0xabcd | FIELD_PREP(IRDMAQPSQ_VALID,
							       qp->qp_uk.swqe_polarity));
		}
		hdr = FIELD_PREP(IRDMAQPSQ_REMSTAG, 0x1234) |
		      FIELD_PREP(IRDMAQPSQ_OPCODE, IRDMAQP_OP_RDMA_READ) |
		      FIELD_PREP(IRDMAQPSQ_VALID, qp->qp_uk.swqe_polarity);

	} else {
		if (qp->qp_uk.uk_attrs->hw_rev == IRDMA_GEN_1) {
			set_64bit_val(wqe, 8, 0);
		} else {
			set_64bit_val(wqe, 8,
				      FIELD_PREP(IRDMAQPSQ_VALID, qp->qp_uk.swqe_polarity));
		}
		hdr = FIELD_PREP(IRDMAQPSQ_OPCODE, IRDMAQP_OP_RDMA_WRITE) |
		      FIELD_PREP(IRDMAQPSQ_VALID, qp->qp_uk.swqe_polarity);
	}

	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: RTR WQE", DUMP_PREFIX_OFFSET, 16, 8, wqe,
		             IRDMA_QP_WQE_MIN_SIZE, false);

	if (qp->dev->hw_attrs.uk_attrs.feature_flags & IRDMA_FEATURE_RTS_AE)
		irdma_sc_gen_rts_ae(qp);
}

/**
 * irdma_iwarp_opcode - determine if incoming is rdma layer
 * @info: aeq info for the packet
 * @pkt: packet for error
 */
static u32 irdma_iwarp_opcode(struct irdma_aeqe_info *info, u8 *pkt)
{
	__be16 *mpa;
	u32 opcode = 0xffffffff;

	if (info->q2_data_written) {
		mpa = (__be16 *)pkt;
		opcode = ntohs(mpa[1]) & 0xf;
	}

	return opcode;
}

/**
 * irdma_locate_mpa - return pointer to mpa in the pkt
 * @pkt: packet with data
 */
static u8 *irdma_locate_mpa(u8 *pkt)
{
	/* skip over ethernet header */
	pkt += IRDMA_MAC_HLEN;

	/* Skip over IP and TCP headers */
	pkt += 4 * (pkt[0] & 0x0f);
	pkt += 4 * ((pkt[12] >> 4) & 0x0f);

	return pkt;
}

/**
 * irdma_bld_termhdr_ctrl - setup terminate hdr control fields
 * @qp: sc qp ptr for pkt
 * @hdr: term hdr
 * @opcode: flush opcode for termhdr
 * @layer_etype: error layer + error type
 * @err: error cod ein the header
 */
static void irdma_bld_termhdr_ctrl(struct irdma_sc_qp *qp,
				   struct irdma_terminate_hdr *hdr,
				   enum irdma_flush_opcode opcode,
				   u8 layer_etype, u8 err)
{
	qp->flush_code = opcode;
	hdr->layer_etype = layer_etype;
	hdr->error_code = err;
}

/**
 * irdma_bld_termhdr_ddp_rdma - setup ddp and rdma hdrs in terminate hdr
 * @pkt: ptr to mpa in offending pkt
 * @hdr: term hdr
 * @copy_len: offending pkt length to be copied to term hdr
 * @is_tagged: DDP tagged or untagged
 */
static void irdma_bld_termhdr_ddp_rdma(u8 *pkt, struct irdma_terminate_hdr *hdr,
				       int *copy_len, u8 *is_tagged)
{
	u16 ddp_seg_len;

	ddp_seg_len = ntohs(*(__be16 *)pkt);
	if (ddp_seg_len) {
		*copy_len = 2;
		hdr->hdrct = DDP_LEN_FLAG;
		if (pkt[2] & 0x80) {
			*is_tagged = 1;
			if (ddp_seg_len >= TERM_DDP_LEN_TAGGED) {
				*copy_len += TERM_DDP_LEN_TAGGED;
				hdr->hdrct |= DDP_HDR_FLAG;
			}
		} else {
			if (ddp_seg_len >= TERM_DDP_LEN_UNTAGGED) {
				*copy_len += TERM_DDP_LEN_UNTAGGED;
				hdr->hdrct |= DDP_HDR_FLAG;
			}
			if (ddp_seg_len >= (TERM_DDP_LEN_UNTAGGED + TERM_RDMA_LEN) &&
			    ((pkt[3] & RDMA_OPCODE_M) == RDMA_READ_REQ_OPCODE)) {
				*copy_len += TERM_RDMA_LEN;
				hdr->hdrct |= RDMA_HDR_FLAG;
			}
		}
	}
}

/**
 * irdma_bld_terminate_hdr - build terminate message header
 * @qp: qp associated with received terminate AE
 * @info: the struct contiaing AE information
 */
static int irdma_bld_terminate_hdr(struct irdma_sc_qp *qp,
				   struct irdma_aeqe_info *info)
{
	u8 *pkt = qp->q2_buf + Q2_BAD_FRAME_OFFSET;
	int copy_len = 0;
	u8 is_tagged = 0;
	u32 opcode;
	struct irdma_terminate_hdr *termhdr;

	termhdr = (struct irdma_terminate_hdr *)qp->q2_buf;
	memset(termhdr, 0, Q2_BAD_FRAME_OFFSET);

	if (info->q2_data_written) {
		pkt = irdma_locate_mpa(pkt);
		irdma_bld_termhdr_ddp_rdma(pkt, termhdr, &copy_len, &is_tagged);
	}

	opcode = irdma_iwarp_opcode(info, pkt);
	qp->event_type = IRDMA_QP_EVENT_CATASTROPHIC;
	qp->sq_flush_code = info->sq;
	qp->rq_flush_code = info->rq;

	switch (info->ae_id) {
	case IRDMA_AE_AMP_UNALLOCATED_STAG:
		qp->event_type = IRDMA_QP_EVENT_ACCESS_ERR;
		if (opcode == IRDMA_OP_TYPE_RDMA_WRITE)
			irdma_bld_termhdr_ctrl(qp, termhdr, FLUSH_PROT_ERR,
					       (LAYER_DDP << 4) | DDP_TAGGED_BUF,
					       DDP_TAGGED_INV_STAG);
		else
			irdma_bld_termhdr_ctrl(qp, termhdr, FLUSH_REM_ACCESS_ERR,
					       (LAYER_RDMA << 4) | RDMAP_REMOTE_PROT,
					       RDMAP_INV_STAG);
		break;
	case IRDMA_AE_AMP_BOUNDS_VIOLATION:
		qp->event_type = IRDMA_QP_EVENT_ACCESS_ERR;
		if (info->q2_data_written)
			irdma_bld_termhdr_ctrl(qp, termhdr, FLUSH_PROT_ERR,
					       (LAYER_DDP << 4) | DDP_TAGGED_BUF,
					       DDP_TAGGED_BOUNDS);
		else
			irdma_bld_termhdr_ctrl(qp, termhdr, FLUSH_REM_ACCESS_ERR,
					       (LAYER_RDMA << 4) | RDMAP_REMOTE_PROT,
					       RDMAP_INV_BOUNDS);
		break;
	case IRDMA_AE_AMP_BAD_PD:
		switch (opcode) {
		case IRDMA_OP_TYPE_RDMA_WRITE:
			irdma_bld_termhdr_ctrl(qp, termhdr, FLUSH_PROT_ERR,
					       (LAYER_DDP << 4) | DDP_TAGGED_BUF,
					       DDP_TAGGED_UNASSOC_STAG);
			break;
		case IRDMA_OP_TYPE_SEND_INV:
		case IRDMA_OP_TYPE_SEND_SOL_INV:
			irdma_bld_termhdr_ctrl(qp, termhdr, FLUSH_REM_ACCESS_ERR,
					       (LAYER_RDMA << 4) | RDMAP_REMOTE_PROT,
					       RDMAP_CANT_INV_STAG);
			break;
		default:
			irdma_bld_termhdr_ctrl(qp, termhdr, FLUSH_REM_ACCESS_ERR,
					       (LAYER_RDMA << 4) | RDMAP_REMOTE_PROT,
					       RDMAP_UNASSOC_STAG);
		}
		break;
	case IRDMA_AE_AMP_INVALID_STAG:
		qp->event_type = IRDMA_QP_EVENT_ACCESS_ERR;
		irdma_bld_termhdr_ctrl(qp, termhdr, FLUSH_REM_ACCESS_ERR,
				       (LAYER_RDMA << 4) | RDMAP_REMOTE_PROT,
				       RDMAP_INV_STAG);
		break;
	case IRDMA_AE_AMP_BAD_QP:
		irdma_bld_termhdr_ctrl(qp, termhdr, FLUSH_LOC_QP_OP_ERR,
				       (LAYER_DDP << 4) | DDP_UNTAGGED_BUF,
				       DDP_UNTAGGED_INV_QN);
		break;
	case IRDMA_AE_AMP_BAD_STAG_KEY:
	case IRDMA_AE_AMP_BAD_STAG_INDEX:
		qp->event_type = IRDMA_QP_EVENT_ACCESS_ERR;
		switch (opcode) {
		case IRDMA_OP_TYPE_SEND_INV:
		case IRDMA_OP_TYPE_SEND_SOL_INV:
			irdma_bld_termhdr_ctrl(qp, termhdr, FLUSH_REM_OP_ERR,
					       (LAYER_RDMA << 4) | RDMAP_REMOTE_OP,
					       RDMAP_CANT_INV_STAG);
			break;
		default:
			irdma_bld_termhdr_ctrl(qp, termhdr, FLUSH_REM_ACCESS_ERR,
					       (LAYER_RDMA << 4) | RDMAP_REMOTE_OP,
					       RDMAP_INV_STAG);
		}
		break;
	case IRDMA_AE_AMP_RIGHTS_VIOLATION:
	case IRDMA_AE_AMP_INVALIDATE_NO_REMOTE_ACCESS_RIGHTS:
	case IRDMA_AE_PRIV_OPERATION_DENIED:
		qp->event_type = IRDMA_QP_EVENT_ACCESS_ERR;
		irdma_bld_termhdr_ctrl(qp, termhdr, FLUSH_REM_ACCESS_ERR,
				       (LAYER_RDMA << 4) | RDMAP_REMOTE_PROT,
				       RDMAP_ACCESS);
		break;
	case IRDMA_AE_AMP_TO_WRAP:
		qp->event_type = IRDMA_QP_EVENT_ACCESS_ERR;
		irdma_bld_termhdr_ctrl(qp, termhdr, FLUSH_REM_ACCESS_ERR,
				       (LAYER_RDMA << 4) | RDMAP_REMOTE_PROT,
				       RDMAP_TO_WRAP);
		break;
	case IRDMA_AE_LLP_RECEIVED_MPA_CRC_ERROR:
		irdma_bld_termhdr_ctrl(qp, termhdr, FLUSH_GENERAL_ERR,
				       (LAYER_MPA << 4) | DDP_LLP, MPA_CRC);
		break;
	case IRDMA_AE_LLP_SEGMENT_TOO_SMALL:
		irdma_bld_termhdr_ctrl(qp, termhdr, FLUSH_LOC_LEN_ERR,
				       (LAYER_DDP << 4) | DDP_CATASTROPHIC,
				       DDP_CATASTROPHIC_LOCAL);
		break;
	case IRDMA_AE_LCE_QP_CATASTROPHIC:
	case IRDMA_AE_DDP_NO_L_BIT:
		irdma_bld_termhdr_ctrl(qp, termhdr, FLUSH_FATAL_ERR,
				       (LAYER_DDP << 4) | DDP_CATASTROPHIC,
				       DDP_CATASTROPHIC_LOCAL);
		break;
	case IRDMA_AE_DDP_INVALID_MSN_GAP_IN_MSN:
		irdma_bld_termhdr_ctrl(qp, termhdr, FLUSH_GENERAL_ERR,
				       (LAYER_DDP << 4) | DDP_UNTAGGED_BUF,
				       DDP_UNTAGGED_INV_MSN_RANGE);
		break;
	case IRDMA_AE_DDP_UBE_DDP_MESSAGE_TOO_LONG_FOR_AVAILABLE_BUFFER:
		qp->event_type = IRDMA_QP_EVENT_ACCESS_ERR;
		irdma_bld_termhdr_ctrl(qp, termhdr, FLUSH_LOC_LEN_ERR,
				       (LAYER_DDP << 4) | DDP_UNTAGGED_BUF,
				       DDP_UNTAGGED_INV_TOO_LONG);
		break;
	case IRDMA_AE_DDP_UBE_INVALID_DDP_VERSION:
		if (is_tagged)
			irdma_bld_termhdr_ctrl(qp, termhdr, FLUSH_GENERAL_ERR,
					       (LAYER_DDP << 4) | DDP_TAGGED_BUF,
					       DDP_TAGGED_INV_DDP_VER);
		else
			irdma_bld_termhdr_ctrl(qp, termhdr, FLUSH_GENERAL_ERR,
					       (LAYER_DDP << 4) | DDP_UNTAGGED_BUF,
					       DDP_UNTAGGED_INV_DDP_VER);
		break;
	case IRDMA_AE_DDP_UBE_INVALID_MO:
		irdma_bld_termhdr_ctrl(qp, termhdr, FLUSH_GENERAL_ERR,
				       (LAYER_DDP << 4) | DDP_UNTAGGED_BUF,
				       DDP_UNTAGGED_INV_MO);
		break;
	case IRDMA_AE_DDP_UBE_INVALID_MSN_NO_BUFFER_AVAILABLE:
		irdma_bld_termhdr_ctrl(qp, termhdr, FLUSH_REM_OP_ERR,
				       (LAYER_DDP << 4) | DDP_UNTAGGED_BUF,
				       DDP_UNTAGGED_INV_MSN_NO_BUF);
		break;
	case IRDMA_AE_DDP_UBE_INVALID_QN:
		irdma_bld_termhdr_ctrl(qp, termhdr, FLUSH_GENERAL_ERR,
				       (LAYER_DDP << 4) | DDP_UNTAGGED_BUF,
				       DDP_UNTAGGED_INV_QN);
		break;
	case IRDMA_AE_RDMAP_ROE_INVALID_RDMAP_VERSION:
		irdma_bld_termhdr_ctrl(qp, termhdr, FLUSH_GENERAL_ERR,
				       (LAYER_RDMA << 4) | RDMAP_REMOTE_OP,
				       RDMAP_INV_RDMAP_VER);
		break;
	default:
		irdma_bld_termhdr_ctrl(qp, termhdr, FLUSH_FATAL_ERR,
				       (LAYER_RDMA << 4) | RDMAP_REMOTE_OP,
				       RDMAP_UNSPECIFIED);
		break;
	}

	if (copy_len)
		memcpy(termhdr + 1, pkt, copy_len);

	return sizeof(*termhdr) + copy_len;
}

/**
 * irdma_terminate_send_fin() - Send fin for terminate message
 * @qp: qp associated with received terminate AE
 */
void irdma_terminate_send_fin(struct irdma_sc_qp *qp)
{
	irdma_term_modify_qp(qp, IRDMA_QP_STATE_TERMINATE,
			     IRDMAQP_TERM_SEND_FIN_ONLY, 0);
}

/**
 * irdma_terminate_connection() - Bad AE and send terminate to remote QP
 * @qp: qp associated with received terminate AE
 * @info: the struct contiaing AE information
 */
void irdma_terminate_connection(struct irdma_sc_qp *qp,
				struct irdma_aeqe_info *info)
{
	u8 termlen = 0;

	if (qp->term_flags & IRDMA_TERM_SENT)
		return;

	termlen = irdma_bld_terminate_hdr(qp, info);
	irdma_terminate_start_timer(qp);
	qp->term_flags |= IRDMA_TERM_SENT;
	irdma_term_modify_qp(qp, IRDMA_QP_STATE_TERMINATE,
			     IRDMAQP_TERM_SEND_TERM_ONLY, termlen);
}

/**
 * irdma_terminate_received - handle terminate received AE
 * @qp: qp associated with received terminate AE
 * @info: the struct contiaing AE information
 */
void irdma_terminate_received(struct irdma_sc_qp *qp,
			      struct irdma_aeqe_info *info)
{
	u8 *pkt = qp->q2_buf + Q2_BAD_FRAME_OFFSET;
	__be32 *mpa;
	u8 ddp_ctl;
	u8 rdma_ctl;
	u16 aeq_id = 0;
	struct irdma_terminate_hdr *termhdr;

	mpa = (__be32 *)irdma_locate_mpa(pkt);
	if (info->q2_data_written) {
		/* did not validate the frame - do it now */
		ddp_ctl = (ntohl(mpa[0]) >> 8) & 0xff;
		rdma_ctl = ntohl(mpa[0]) & 0xff;
		if ((ddp_ctl & 0xc0) != 0x40)
			aeq_id = IRDMA_AE_LCE_QP_CATASTROPHIC;
		else if ((ddp_ctl & 0x03) != 1)
			aeq_id = IRDMA_AE_DDP_UBE_INVALID_DDP_VERSION;
		else if (ntohl(mpa[2]) != 2)
			aeq_id = IRDMA_AE_DDP_UBE_INVALID_QN;
		else if (ntohl(mpa[3]) != 1)
			aeq_id = IRDMA_AE_DDP_INVALID_MSN_GAP_IN_MSN;
		else if (ntohl(mpa[4]) != 0)
			aeq_id = IRDMA_AE_DDP_UBE_INVALID_MO;
		else if ((rdma_ctl & 0xc0) != 0x40)
			aeq_id = IRDMA_AE_RDMAP_ROE_INVALID_RDMAP_VERSION;

		info->ae_id = aeq_id;
		if (info->ae_id) {
			/* Bad terminate recvd - send back a terminate */
			irdma_terminate_connection(qp, info);
			return;
		}
	}

	qp->term_flags |= IRDMA_TERM_RCVD;
	qp->event_type = IRDMA_QP_EVENT_CATASTROPHIC;
	termhdr = (struct irdma_terminate_hdr *)&mpa[5];
	if (termhdr->layer_etype == RDMAP_REMOTE_PROT ||
	    termhdr->layer_etype == RDMAP_REMOTE_OP) {
		irdma_terminate_done(qp, 0);
	} else {
		irdma_terminate_start_timer(qp);
		irdma_terminate_send_fin(qp);
	}
}

/**
 * irdma_sc_gather_rdma_sys_stats - send gather RDMA system
 * stats CQP WQE
 * @cqp: cqp sc struct
 * @info: parameters for rdma system stats
 * @scratch: u64 saved to be used during cqp completion
 * @post_sq: flag for cqp db to ring
 */
static int irdma_sc_gather_rdma_sys_stats(struct irdma_sc_cqp *cqp,
					  struct irdma_sc_rdma_sys_stats_info *info,
					  u64 scratch, bool post_sq)
{
	__le64 *wqe;
	u64 hdr;

	wqe = irdma_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;

	set_64bit_val(wqe, 32, info->stats_buf.pa);
	set_64bit_val(wqe, 40, info->hmc_fcn_ids[0] | ((u64)info->hmc_fcn_ids[1] << 16) |
		      ((u64)info->hmc_fcn_ids[2] << 32) | ((u64)info->hmc_fcn_ids[3] << 48));
	set_64bit_val(wqe, 0, info->hmc_fcn_ids[4] | ((u64)info->hmc_fcn_ids[5] << 16) |
		      ((u64)info->hmc_fcn_ids[6] << 32) | ((u64)info->hmc_fcn_ids[7] << 48));
	set_64bit_val(wqe, 8, info->hmc_fcn_ids[8] | ((u64)info->hmc_fcn_ids[9] << 16) |
		      ((u64)info->hmc_fcn_ids[10] << 32) | ((u64)info->hmc_fcn_ids[11] << 48));
	set_64bit_val(wqe, 16, info->hmc_fcn_ids[12] | ((u64)info->hmc_fcn_ids[13] << 16) |
		      ((u64)info->hmc_fcn_ids[14] << 32) | ((u64)info->hmc_fcn_ids[15] << 48));

	hdr = FIELD_PREP(IRDMA_CQPSQ_OPCODE, IRDMA_CQP_OP_GATHER_RDMA_SYS_STATS) |
	      FIELD_PREP(IRDMA_CQPSQ_MHMC_LOCALFENCE, info->local_fence) |
	      FIELD_PREP(IRDMA_CQPSQ_GATHER_RDMA_SYSTEM_STATS_STATS_TYPE, info->stats_type) |
	      FIELD_PREP(IRDMA_CQPSQ_GATHER_RDMA_SYSTEM_STATS_STATS_SUBTYPE, info->sub_type) |
	      FIELD_PREP(IRDMA_CQPSQ_GATHER_RDMA_SYSTEM_STATS_VF_COUNT, info->vf_cnt) |
	      FIELD_PREP(IRDMA_CQPSQ_WQEVALID, cqp->polarity);

	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: GATHER_RDMA_SYS_STATS WQE",
			     DUMP_PREFIX_OFFSET, 16, 8, wqe,
			     IRDMA_CQP_WQE_SIZE * 8, false);
	if (post_sq)
		irdma_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * irdma_sc_copy_data - copy data to HMC function
 * @cqp: cqp sc struct
 * @info: copy data CQP op info
 * @scratch: u64 saved to be used during cqp completion
 * @post_sq: flag for cqp db to ring
 */
static int irdma_sc_copy_data(struct irdma_sc_cqp *cqp,
			      struct irdma_copy_data_info *info,
			      u64 scratch, bool post_sq)
{
	__le64 *wqe;
	u64 hdr;

	wqe = irdma_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;

	set_64bit_val(wqe, 16, info->src_addr);
	set_64bit_val(wqe, 32, info->dst_addr);
	set_64bit_val(wqe, 40,
		      FIELD_PREP(IRDMA_CQPSQ_COPY_DATA_HMC_FCN_ID,
				 info->hmc_fcn_id));

	hdr = FIELD_PREP(IRDMA_CQPSQ_OPCODE, IRDMA_CQP_OP_COPY_DATA) |
	      FIELD_PREP(IRDMA_CQPSQ_COPY_DATA_LENGTH, info->length) |
	      FIELD_PREP(IRDMA_CQPSQ_WQEVALID, cqp->polarity);

	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: COPY DATA WQE", DUMP_PREFIX_OFFSET, 16, 8,
			     wqe, IRDMA_CQP_WQE_SIZE * 8, false);
	if (post_sq)
		irdma_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * irdma_sc_ret_cqp_cmpl - send return CQP completion CQP WQE
 * @cqp: cqp sc struct
 * @info: parameters for forward CQP ops
 * @scratch: u64 saved to be used during cqp completion
 * @post_sq: flag for cqp db to ring
 */
static int irdma_sc_ret_cqp_cmpl(struct irdma_sc_cqp *cqp,
				 struct irdma_ret_cqp_cmpl_info *info,
				 u64 scratch, bool post_sq)
{
	__le64 *wqe;
	u64 hdr;

	wqe = irdma_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;

	set_64bit_val(wqe, 16,
		      FIELD_PREP(IRDMA_CQPSQ_RET_CQP_CMPL_HMC_FCN_ID,
				 info->hmc_fcn_id));
	set_64bit_val(wqe, 32, info->cqe_values[0]);
	set_64bit_val(wqe, 40, info->cqe_values[1]);
	set_64bit_val(wqe, 48, info->cqe_values[2]);
	set_64bit_val(wqe, 56, info->cqe_values[3]);

	hdr = FIELD_PREP(IRDMA_CQPSQ_OPCODE, IRDMA_CQP_OP_RET_CQP_CMPL) |
	      FIELD_PREP(IRDMA_CQPSQ_RET_CQP_CMPL_PEND_CMPL, info->pending) |
	      FIELD_PREP(IRDMA_CQPSQ_WQEVALID, cqp->polarity);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: RETURN CQP CMPL WQE", DUMP_PREFIX_OFFSET,
			     16, 8, wqe, IRDMA_CQP_WQE_SIZE * 8, false);
	if (post_sq)
		irdma_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * irdma_sc_rca_exec_fwd_op - execute forwarded CQP op
 * @cqp: cqp sc struct
 * @info: forwarded CQP op info
 * @scratch: u64 saved to be used during cqp completion
 * @post_sq: flag for cqp db to ring
 */
static int irdma_sc_rca_exec_fwd_op(struct irdma_sc_cqp *cqp,
				    struct irdma_rca_exec_fwd_op_info *info,
				    u64 scratch, bool post_sq)
{
	__le64 *wqe;
	u64 hdr;
	u64 wqe0, wqe2, wqe5;

	wqe = irdma_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;

	/*
	 * To execute forwarded CQP op on behalf of originating function
	 * simply copy the entire WQE data, set 'use_hmc_fcn_id' flag
	 * and set 'HMC_FCN_ID' to the originating function ID.
	 * For 'QP Create/Modify' and for 'Upload Context' ops, we also need
	 * to substitute the address of input/output buffer (QP context)
	 * with the address of RCA-owned buffer.
	 */
	wqe0 = info->wqe[0];
	wqe2 = info->wqe[2];
	wqe5 = info->wqe[5];
	hdr = info->wqe[3];

	switch (info->op_code) {
	case IRDMA_CQP_OP_REG_MR:
		wqe5 &= ~(FIELD_PREP(IRDMA_CQPSQ_STAG_HMCFNIDX,
				     IRDMA_CQPSQ_STAG_HMCFNIDX));
		wqe5 |= FIELD_PREP(IRDMA_CQPSQ_STAG_HMCFNIDX,
				   info->orig_hmc_fcn_id);
		hdr |= FIELD_PREP(IRDMA_CQPSQ_STAG_USEHMCFNIDX, 1);
		break;
	case IRDMA_CQP_OP_UPLOAD_CONTEXT:
		wqe2 = info->buf_addr;
		wqe5 &= ~(FIELD_PREP(IRDMA_CQPSQ_UCTX_HMC_FCN_ID,
				     IRDMA_CQPSQ_UCTX_HMC_FCN_ID));
		wqe5 |= FIELD_PREP(IRDMA_CQPSQ_UCTX_HMC_FCN_ID,
				   info->orig_hmc_fcn_id);
		hdr |= FIELD_PREP(IRDMA_CQPSQ_UCTX_USE_HMC_FCN_ID, 1);
		break;
	case IRDMA_CQP_OP_CREATE_ADDR_HANDLE:
	case IRDMA_CQP_OP_MODIFY_ADDR_HANDLE:
	case IRDMA_CQP_OP_DESTROY_ADDR_HANDLE:
		wqe0 &= ~(FIELD_PREP(IRDMA_CQPSQ_AH_HMCFNIDX,
				     IRDMA_CQPSQ_AH_HMCFNIDX));
		wqe0 |= FIELD_PREP(IRDMA_CQPSQ_AH_HMCFNIDX,
				   info->orig_hmc_fcn_id);
		hdr |= FIELD_PREP(IRDMA_CQPSQ_AH_USEHMCFNIDX, 1);
		break;
	case IRDMA_CQP_OP_CREATE_QP:
	case IRDMA_CQP_OP_MODIFY_QP:
	case IRDMA_CQP_OP_DESTROY_QP:
		wqe2 = info->buf_addr;
		wqe0 &= ~(FIELD_PREP(IRDMA_CQPSQ_QP_HMCFNIDX,
				     IRDMA_CQPSQ_QP_HMCFNIDX));
		wqe0 |= FIELD_PREP(IRDMA_CQPSQ_QP_HMCFNIDX,
				   info->orig_hmc_fcn_id);
		hdr |= FIELD_PREP(IRDMA_CQPSQ_QP_USEHMCFNIDX, 1);
		break;
	default:
		return -EOPNOTSUPP;
	}

	set_64bit_val(wqe, 0, wqe0);
	set_64bit_val(wqe, 8, info->wqe[1]);
	set_64bit_val(wqe, 16, wqe2);
	set_64bit_val(wqe, 32, info->wqe[4]);
	set_64bit_val(wqe, 40, wqe5);
	set_64bit_val(wqe, 48, info->wqe[6]);
	set_64bit_val(wqe, 56, info->wqe[7]);

	hdr &= ~(FIELD_PREP(IRDMA_CQPSQ_WQEVALID, 1));
	hdr |= FIELD_PREP(IRDMA_CQPSQ_WQEVALID, cqp->polarity);

	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: FORWARDED WQE", DUMP_PREFIX_OFFSET, 16, 8,
			     wqe, IRDMA_CQP_WQE_SIZE * 8, false);
	if (post_sq)
		irdma_sc_cqp_post_sq(cqp);

	return 0;
}

static int irdma_null_ws_add(struct irdma_sc_vsi *vsi, u8 user_pri)
{
	return 0;
}

static void irdma_null_ws_remove(struct irdma_sc_vsi *vsi, u8 user_pri)
{
	/* do nothing */
}

static void irdma_null_ws_reset(struct irdma_sc_vsi *vsi)
{
	/* do nothing */
}

/**
 * irdma_sc_vsi_init - Init the vsi structure
 * @vsi: pointer to vsi structure to initialize
 * @info: the info used to initialize the vsi struct
 */
void irdma_sc_vsi_init(struct irdma_sc_vsi  *vsi,
		       struct irdma_vsi_init_info *info)
{
	u8 i;

	vsi->dev = info->dev;
	vsi->back_vsi = info->back_vsi;
	vsi->register_qset = info->register_qset;
	vsi->unregister_qset = info->unregister_qset;
	vsi->mtu = info->params->mtu;
	vsi->exception_lan_q = info->exception_lan_q;
	vsi->vsi_idx = info->pf_data_vsi_num;
	vsi->vm_vf_type = info->vm_vf_type;

	irdma_set_qos_info(vsi, info->params);
	for (i = 0; i < IRDMA_MAX_USER_PRIORITY; i++) {
		mutex_init(&vsi->qos[i].qos_mutex);
		INIT_LIST_HEAD(&vsi->qos[i].qplist);
	}
	if (vsi->dev->hw_attrs.uk_attrs.hw_rev == IRDMA_GEN_2) {
		vsi->dev->ws_add = irdma_ws_add;
		vsi->dev->ws_remove = irdma_ws_remove;
		vsi->dev->ws_reset = irdma_ws_reset;
	} else {
		vsi->dev->ws_add = irdma_null_ws_add;
		vsi->dev->ws_remove = irdma_null_ws_remove;
		vsi->dev->ws_reset = irdma_null_ws_reset;
	}
}

/**
 * irdma_get_stats_idx - Return stats index
 * @vsi: pointer to the vsi
 */
static u16 irdma_get_stats_idx(struct irdma_sc_vsi *vsi)
{
	struct irdma_stats_inst_info stats_info = {};
	struct irdma_sc_dev *dev = vsi->dev;
	u8 i;

	if (dev->hw_attrs.uk_attrs.hw_rev >= IRDMA_GEN_2) {
		if (!irdma_cqp_stats_inst_cmd(vsi, IRDMA_OP_STATS_ALLOCATE,
					      &stats_info))
			return stats_info.stats_idx;
	}

	for (i = 0; i < IRDMA_MAX_STATS_COUNT_GEN1; i++) {
		if (!dev->stats_idx_array[i]) {
			dev->stats_idx_array[i] = true;
			return i;
		}
	}

	return IRDMA_INVALID_STATS_IDX;
}

/**
 * irdma_hw_stats_init_gen1 - Initialize stat reg table used for gen1
 * @vsi: vsi structure where hw_regs are set
 *
 * Populate the HW stats table
 */
static void irdma_hw_stats_init_gen1(struct irdma_sc_vsi *vsi)
{
	struct irdma_sc_dev *dev = vsi->dev;
	const struct irdma_hw_stat_map *map;
	u64 *stat_reg = vsi->hw_stats_regs;
	u64 *regs = dev->hw_stats_regs;
	u16 i, stats_reg_set = vsi->stats_idx;

	map = dev->hw_stats_map;

	/* First 4 stat instances are reserved for port level statistics. */
	stats_reg_set += vsi->stats_inst_alloc ? IRDMA_FIRST_NON_PF_STAT : 0;

	for (i = 0; i < dev->hw_attrs.max_stat_idx; i++) {
		if (map[i].bitmask <= IRDMA_MAX_STATS_32) {
			stat_reg[i] = regs[i] +
				      stats_reg_set * sizeof(u32);
		} else {
			stat_reg[i] = regs[i] +
				      stats_reg_set * sizeof(u64);
		}
	}
}

/**
 * irdma_vsi_stats_init - Initialize the vsi statistics
 * @vsi: pointer to the vsi structure
 * @info: The info structure used for initialization
 */
int irdma_vsi_stats_init(struct irdma_sc_vsi *vsi,
			 struct irdma_vsi_stats_info *info)
{
	struct irdma_dma_mem *stats_buff_mem;

	vsi->pestat = info->pestat;
	vsi->pestat->hw = vsi->dev->hw;
	vsi->pestat->vsi = vsi;

	stats_buff_mem = &vsi->pestat->gather_info.stats_buff_mem;
	stats_buff_mem->size = ALIGN(IRDMA_GATHER_STATS_BUF_SIZE * 2, 1);
	stats_buff_mem->va = dma_alloc_coherent(vsi->pestat->hw->device,
						stats_buff_mem->size,
						&stats_buff_mem->pa,
						GFP_KERNEL);
	if (!stats_buff_mem->va)
		return -ENOMEM;

	vsi->pestat->gather_info.gather_stats_va = stats_buff_mem->va;
	vsi->pestat->gather_info.last_gather_stats_va =
		(void *)((uintptr_t)stats_buff_mem->va +
			 IRDMA_GATHER_STATS_BUF_SIZE);

	if (vsi->dev->hw_attrs.uk_attrs.hw_rev < IRDMA_GEN_3)
		irdma_hw_stats_start_timer(vsi);

	/* when stat allocation is not required default to fcn_id. */
	vsi->stats_idx = info->fcn_id;
	if (info->alloc_stats_inst) {
		u16 stats_idx = irdma_get_stats_idx(vsi);

		if (stats_idx != IRDMA_INVALID_STATS_IDX) {
			vsi->stats_inst_alloc = true;
			vsi->stats_idx = stats_idx;
			vsi->pestat->gather_info.use_stats_inst = true;
			vsi->pestat->gather_info.stats_inst_index = stats_idx;
		}
	}

	if (vsi->dev->hw_attrs.uk_attrs.hw_rev == IRDMA_GEN_1)
		irdma_hw_stats_init_gen1(vsi);

	return 0;
}

/**
 * irdma_vsi_stats_free - Free the vsi stats
 * @vsi: pointer to the vsi structure
 */
void irdma_vsi_stats_free(struct irdma_sc_vsi *vsi)
{
	struct irdma_stats_inst_info stats_info = {};
	struct irdma_sc_dev *dev = vsi->dev;
	u16 stats_idx = vsi->stats_idx;

	if (dev->hw_attrs.uk_attrs.hw_rev >= IRDMA_GEN_2) {
		if (vsi->stats_inst_alloc) {
			stats_info.stats_idx = vsi->stats_idx;
			irdma_cqp_stats_inst_cmd(vsi, IRDMA_OP_STATS_FREE,
						 &stats_info);
		}
	} else {
		if (vsi->stats_inst_alloc &&
		    stats_idx < vsi->dev->hw_attrs.max_stat_inst)
			vsi->dev->stats_idx_array[stats_idx] = false;
	}

	if (!vsi->pestat)
		return;

	if (dev->hw_attrs.uk_attrs.hw_rev < IRDMA_GEN_3)
		irdma_hw_stats_stop_timer(vsi);
	dma_free_coherent(vsi->pestat->hw->device,
			  vsi->pestat->gather_info.stats_buff_mem.size,
			  vsi->pestat->gather_info.stats_buff_mem.va,
			  vsi->pestat->gather_info.stats_buff_mem.pa);
	vsi->pestat->gather_info.stats_buff_mem.va = NULL;
}

/**
 * irdma_get_encoded_wqe_size - given wq size, returns hardware encoded size
 * @wqsize: size of the wq (sq, rq) to encoded_size
 * @queue_type: queue type selected for the calculation algorithm
 */
u8 irdma_get_encoded_wqe_size(u32 wqsize, enum irdma_queue_type queue_type)
{
	u8 encoded_size = 0;

	if (queue_type == IRDMA_QUEUE_TYPE_SRQ) {
		/* Smallest SRQ size is 256B (8 quanta) that gets encoded to 0 */
		encoded_size = ilog2(wqsize) - 3;

		return encoded_size;
	}
	/* cqp sq's hw coded value starts from 1 for size of 4
	 * while it starts from 0 for qp' wq's.
	 */
	if (queue_type == IRDMA_QUEUE_TYPE_CQP)
		encoded_size = 1;
	wqsize >>= 2;
	while (wqsize >>= 1)
		encoded_size++;

	return encoded_size;
}

/**
 * irdma_sc_gather_stats - collect the statistics
 * @cqp: struct for cqp hw
 * @info: gather stats info structure
 * @scratch: u64 saved to be used during cqp completion
 */
static int irdma_sc_gather_stats(struct irdma_sc_cqp *cqp,
				 struct irdma_stats_gather_info *info,
				 u64 scratch)
{
	__le64 *wqe;
	u64 temp;

	if (info->stats_buff_mem.size < IRDMA_GATHER_STATS_BUF_SIZE)
		return -ENOMEM;

	wqe = irdma_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;

	set_64bit_val(wqe, 40,
		      FIELD_PREP(IRDMA_CQPSQ_STATS_HMC_FCN_INDEX, info->hmc_fcn_index));
	set_64bit_val(wqe, 32, info->stats_buff_mem.pa);

	temp = FIELD_PREP(IRDMA_CQPSQ_STATS_WQEVALID, cqp->polarity) |
	       FIELD_PREP(IRDMA_CQPSQ_STATS_USE_INST, info->use_stats_inst) |
	       FIELD_PREP(IRDMA_CQPSQ_STATS_INST_INDEX,
			  info->stats_inst_index) |
	       FIELD_PREP(IRDMA_CQPSQ_STATS_USE_HMC_FCN_INDEX,
			  info->use_hmc_fcn_index) |
	       FIELD_PREP(IRDMA_CQPSQ_STATS_OP, IRDMA_CQP_OP_GATHER_STATS);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, temp);

	print_hex_dump_debug("STATS: GATHER_STATS WQE", DUMP_PREFIX_OFFSET,
			     16, 8, wqe, IRDMA_CQP_WQE_SIZE * 8, false);

	irdma_sc_cqp_post_sq(cqp);
	return 0;
}

/**
 * irdma_sc_manage_stats_inst - allocate or free stats instance
 * @cqp: struct for cqp hw
 * @info: stats info structure
 * @alloc: alloc vs. delete flag
 * @scratch: u64 saved to be used during cqp completion
 */
static int irdma_sc_manage_stats_inst(struct irdma_sc_cqp *cqp,
				      struct irdma_stats_inst_info *info,
				      bool alloc, u64 scratch)
{
	__le64 *wqe;
	u64 temp;

	wqe = irdma_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;

	set_64bit_val(wqe, 40,
		      FIELD_PREP(IRDMA_CQPSQ_STATS_HMC_FCN_INDEX, info->hmc_fn_id));
	temp = FIELD_PREP(IRDMA_CQPSQ_STATS_WQEVALID, cqp->polarity) |
	       FIELD_PREP(IRDMA_CQPSQ_STATS_ALLOC_INST, alloc) |
	       FIELD_PREP(IRDMA_CQPSQ_STATS_USE_HMC_FCN_INDEX,
			  info->use_hmc_fcn_index) |
	       FIELD_PREP(IRDMA_CQPSQ_STATS_INST_INDEX, info->stats_idx) |
	       FIELD_PREP(IRDMA_CQPSQ_STATS_OP, IRDMA_CQP_OP_MANAGE_STATS);

	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, temp);

	print_hex_dump_debug("WQE: MANAGE_STATS WQE", DUMP_PREFIX_OFFSET, 16,
			     8, wqe, IRDMA_CQP_WQE_SIZE * 8, false);

	irdma_sc_cqp_post_sq(cqp);
	return 0;
}

/**
 * irdma_sc_set_up_map - set the up map table
 * @cqp: struct for cqp hw
 * @info: User priority map info
 * @scratch: u64 saved to be used during cqp completion
 */
static int irdma_sc_set_up_map(struct irdma_sc_cqp *cqp,
			       struct irdma_up_info *info, u64 scratch)
{
	__le64 *wqe;
	u64 temp = 0;
	int i;

	wqe = irdma_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;

	for (i = 0; i < IRDMA_MAX_USER_PRIORITY; i++)
		temp |= (u64)info->map[i] << (i * 8);

	set_64bit_val(wqe, 0, temp);
	set_64bit_val(wqe, 40,
		      FIELD_PREP(IRDMA_CQPSQ_UP_CNPOVERRIDE, info->cnp_up_override) |
		      FIELD_PREP(IRDMA_CQPSQ_UP_HMCFCNIDX, info->hmc_fcn_idx));

	temp = FIELD_PREP(IRDMA_CQPSQ_UP_WQEVALID, cqp->polarity) |
	       FIELD_PREP(IRDMA_CQPSQ_UP_USEVLAN, info->use_vlan) |
	       FIELD_PREP(IRDMA_CQPSQ_UP_USEOVERRIDE,
			  info->use_cnp_up_override) |
	       FIELD_PREP(IRDMA_CQPSQ_UP_OP, IRDMA_CQP_OP_UP_MAP);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, temp);

	print_hex_dump_debug("WQE: UPMAP WQE", DUMP_PREFIX_OFFSET, 16, 8, wqe,
			     IRDMA_CQP_WQE_SIZE * 8, false);
	irdma_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * irdma_sc_manage_ws_node - create/modify/destroy WS node
 * @cqp: struct for cqp hw
 * @info: node info structure
 * @node_op: 0 for add 1 for modify, 2 for delete
 * @scratch: u64 saved to be used during cqp completion
 */
static int irdma_sc_manage_ws_node(struct irdma_sc_cqp *cqp,
				   struct irdma_ws_node_info *info,
				   enum irdma_ws_node_op node_op, u64 scratch)
{
	__le64 *wqe;
	u64 temp = 0;

	wqe = irdma_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;

	set_64bit_val(wqe, 32,
		      FIELD_PREP(IRDMA_CQPSQ_WS_VSI, info->vsi) |
		      FIELD_PREP(IRDMA_CQPSQ_WS_WEIGHT, info->weight));

	temp = FIELD_PREP(IRDMA_CQPSQ_WS_WQEVALID, cqp->polarity) |
	       FIELD_PREP(IRDMA_CQPSQ_WS_NODEOP, node_op) |
	       FIELD_PREP(IRDMA_CQPSQ_WS_ENABLENODE, info->enable) |
	       FIELD_PREP(IRDMA_CQPSQ_WS_NODETYPE, info->type_leaf) |
	       FIELD_PREP(IRDMA_CQPSQ_WS_PRIOTYPE, info->prio_type) |
	       FIELD_PREP(IRDMA_CQPSQ_WS_TC, info->tc) |
	       FIELD_PREP(IRDMA_CQPSQ_WS_OP, IRDMA_CQP_OP_WORK_SCHED_NODE) |
	       FIELD_PREP(IRDMA_CQPSQ_WS_PARENTID, info->parent_id) |
	       FIELD_PREP(IRDMA_CQPSQ_WS_NODEID, info->id);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, temp);

	print_hex_dump_debug("WQE: MANAGE_WS WQE", DUMP_PREFIX_OFFSET, 16, 8,
			     wqe, IRDMA_CQP_WQE_SIZE * 8, false);
	irdma_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * irdma_sc_qp_flush_wqes - flush qp's wqe
 * @qp: sc qp
 * @info: dlush information
 * @scratch: u64 saved to be used during cqp completion
 * @post_sq: flag for cqp db to ring
 */
int irdma_sc_qp_flush_wqes(struct irdma_sc_qp *qp,
			   struct irdma_qp_flush_info *info, u64 scratch,
			   bool post_sq)
{
	u64 temp = 0;
	__le64 *wqe;
	struct irdma_sc_cqp *cqp;
	u64 hdr;
	bool flush_sq = false, flush_rq = false;

	if (info->rq && !qp->flush_rq)
		flush_rq = true;
	if (info->sq && !qp->flush_sq)
		flush_sq = true;
	qp->flush_sq |= flush_sq;
	qp->flush_rq |= flush_rq;

	if (!flush_sq && !flush_rq) {
		ibdev_dbg(to_ibdev(qp->dev),
			  "CQP: Additional flush request ignored for qp %x\n",
			  qp->qp_uk.qp_id);
		return -EALREADY;
	}

	cqp = qp->pd->dev->cqp;
	wqe = irdma_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;

	if (info->userflushcode) {
		if (flush_rq)
			temp |= FIELD_PREP(IRDMA_CQPSQ_FWQE_RQMNERR,
					   info->rq_minor_code) |
				FIELD_PREP(IRDMA_CQPSQ_FWQE_RQMJERR,
					   info->rq_major_code);
		if (flush_sq)
			temp |= FIELD_PREP(IRDMA_CQPSQ_FWQE_SQMNERR,
					   info->sq_minor_code) |
				FIELD_PREP(IRDMA_CQPSQ_FWQE_SQMJERR,
					   info->sq_major_code);
	}
	set_64bit_val(wqe, 16, temp);

	temp = (info->generate_ae) ?
		info->ae_code | FIELD_PREP(IRDMA_CQPSQ_FWQE_AESOURCE,
					   info->ae_src) : 0;
	set_64bit_val(wqe, 8, temp);
	if (cqp->dev->hw_attrs.uk_attrs.hw_rev >= IRDMA_GEN_3) {
		set_64bit_val(wqe, 40,
			      FIELD_PREP(IRDMA_CQPSQ_FWQE_ERR_SQ_IDX, info->err_sq_idx));
		set_64bit_val(wqe, 48,
			      FIELD_PREP(IRDMA_CQPSQ_FWQE_ERR_RQ_IDX, info->err_rq_idx));
	}

	hdr = qp->qp_uk.qp_id |
	      FIELD_PREP(IRDMA_CQPSQ_OPCODE, IRDMA_CQP_OP_FLUSH_WQES) |
	      FIELD_PREP(IRDMA_CQPSQ_FWQE_GENERATE_AE, info->generate_ae) |
	      FIELD_PREP(IRDMA_CQPSQ_FWQE_USERFLCODE, info->userflushcode) |
	      FIELD_PREP(IRDMA_CQPSQ_FWQE_FLUSHSQ, flush_sq) |
	      FIELD_PREP(IRDMA_CQPSQ_FWQE_FLUSHRQ, flush_rq) |
	      FIELD_PREP(IRDMA_CQPSQ_WQEVALID, cqp->polarity);
	if (cqp->dev->hw_attrs.uk_attrs.hw_rev >= IRDMA_GEN_3)
		hdr |= FIELD_PREP(IRDMA_CQPSQ_FWQE_ERR_SQ_IDX_VALID, info->err_sq_idx_valid) |
		       FIELD_PREP(IRDMA_CQPSQ_FWQE_ERR_RQ_IDX_VALID, info->err_rq_idx_valid);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: QP_FLUSH WQE", DUMP_PREFIX_OFFSET, 16, 8,
			     wqe, IRDMA_CQP_WQE_SIZE * 8, false);
	if (post_sq)
		irdma_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * irdma_sc_gen_ae - generate AE, uses flush WQE CQP OP
 * @qp: sc qp
 * @info: gen ae information
 * @scratch: u64 saved to be used during cqp completion
 * @post_sq: flag for cqp db to ring
 */
static int irdma_sc_gen_ae(struct irdma_sc_qp *qp,
			   struct irdma_gen_ae_info *info, u64 scratch,
			   bool post_sq)
{
	u64 temp;
	__le64 *wqe;
	struct irdma_sc_cqp *cqp;
	u64 hdr;

	cqp = qp->pd->dev->cqp;
	wqe = irdma_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;

	temp = info->ae_code | FIELD_PREP(IRDMA_CQPSQ_FWQE_AESOURCE,
					  info->ae_src);
	set_64bit_val(wqe, 8, temp);

	hdr = qp->qp_uk.qp_id | FIELD_PREP(IRDMA_CQPSQ_OPCODE,
					   IRDMA_CQP_OP_GEN_AE) |
	      FIELD_PREP(IRDMA_CQPSQ_FWQE_GENERATE_AE, 1) |
	      FIELD_PREP(IRDMA_CQPSQ_WQEVALID, cqp->polarity);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: GEN_AE WQE", DUMP_PREFIX_OFFSET, 16, 8,
			     wqe, IRDMA_CQP_WQE_SIZE * 8, false);
	if (post_sq)
		irdma_sc_cqp_post_sq(cqp);

	return 0;
}

/*** irdma_sc_qp_upload_context - upload qp's context
 * @dev: sc device struct
 * @info: upload context info ptr for return
 * @scratch: u64 saved to be used during cqp completion
 * @post_sq: flag for cqp db to ring
 */
static int irdma_sc_qp_upload_context(struct irdma_sc_dev *dev,
				      struct irdma_upload_context_info *info,
				      u64 scratch, bool post_sq)
{
	__le64 *wqe;
	struct irdma_sc_cqp *cqp;
	u64 hdr;

	cqp = dev->cqp;
	wqe = irdma_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;

	set_64bit_val(wqe, 16, info->buf_pa);

	hdr = FIELD_PREP(IRDMA_CQPSQ_UCTX_QPID, info->qp_id) |
	      FIELD_PREP(IRDMA_CQPSQ_OPCODE, IRDMA_CQP_OP_UPLOAD_CONTEXT) |
	      FIELD_PREP(IRDMA_CQPSQ_UCTX_QPTYPE, info->qp_type) |
	      FIELD_PREP(IRDMA_CQPSQ_UCTX_RAWFORMAT, info->raw_format) |
	      FIELD_PREP(IRDMA_CQPSQ_UCTX_FREEZEQP, info->freeze_qp) |
	      FIELD_PREP(IRDMA_CQPSQ_WQEVALID, cqp->polarity);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: QP_UPLOAD_CTX WQE", DUMP_PREFIX_OFFSET, 16,
			     8, wqe, IRDMA_CQP_WQE_SIZE * 8, false);
	if (post_sq)
		irdma_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * irdma_sc_manage_push_page - Handle push page
 * @cqp: struct for cqp hw
 * @info: push page info
 * @scratch: u64 saved to be used during cqp completion
 * @post_sq: flag for cqp db to ring
 */
static int
irdma_sc_manage_push_page(struct irdma_sc_cqp *cqp,
			  struct irdma_cqp_manage_push_page_info *info,
			  u64 scratch, bool post_sq)
{
	__le64 *wqe;
	u64 hdr;

	if (info->free_page &&
	    info->push_idx >= cqp->dev->hw_attrs.max_hw_device_pages)
		return -EINVAL;
	wqe = irdma_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;

	set_64bit_val(wqe, 16, info->qs_handle);
	hdr = FIELD_PREP(IRDMA_CQPSQ_MPP_PPIDX, info->push_idx) |
	      FIELD_PREP(IRDMA_CQPSQ_MPP_PPTYPE, info->push_page_type) |
	      FIELD_PREP(IRDMA_CQPSQ_OPCODE, IRDMA_CQP_OP_MANAGE_PUSH_PAGES) |
	      FIELD_PREP(IRDMA_CQPSQ_WQEVALID, cqp->polarity) |
	      FIELD_PREP(IRDMA_CQPSQ_MPP_FREE_PAGE, info->free_page);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: MANAGE_PUSH_PAGES WQE", DUMP_PREFIX_OFFSET,
			     16, 8, wqe, IRDMA_CQP_WQE_SIZE * 8, false);
	if (post_sq)
		irdma_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * irdma_sc_suspend_qp - suspend qp for param change
 * @cqp: struct for cqp hw
 * @qp: sc qp struct
 * @scratch: u64 saved to be used during cqp completion
 */
static int irdma_sc_suspend_qp(struct irdma_sc_cqp *cqp, struct irdma_sc_qp *qp,
			       u64 scratch)
{
	u64 hdr;
	__le64 *wqe;

	wqe = irdma_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;

	hdr = FIELD_PREP(IRDMA_CQPSQ_SUSPENDQP_QPID, qp->qp_uk.qp_id) |
	      FIELD_PREP(IRDMA_CQPSQ_OPCODE, IRDMA_CQP_OP_SUSPEND_QP) |
	      FIELD_PREP(IRDMA_CQPSQ_WQEVALID, cqp->polarity);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: SUSPEND_QP WQE", DUMP_PREFIX_OFFSET, 16, 8,
			     wqe, IRDMA_CQP_WQE_SIZE * 8, false);
	irdma_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * irdma_sc_resume_qp - resume qp after suspend
 * @cqp: struct for cqp hw
 * @qp: sc qp struct
 * @scratch: u64 saved to be used during cqp completion
 */
static int irdma_sc_resume_qp(struct irdma_sc_cqp *cqp, struct irdma_sc_qp *qp,
			      u64 scratch)
{
	u64 hdr;
	__le64 *wqe;

	wqe = irdma_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;

	set_64bit_val(wqe, 16,
		      FIELD_PREP(IRDMA_CQPSQ_RESUMEQP_QSHANDLE, qp->qs_handle));

	hdr = FIELD_PREP(IRDMA_CQPSQ_RESUMEQP_QPID, qp->qp_uk.qp_id) |
	      FIELD_PREP(IRDMA_CQPSQ_OPCODE, IRDMA_CQP_OP_RESUME_QP) |
	      FIELD_PREP(IRDMA_CQPSQ_WQEVALID, cqp->polarity);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: RESUME_QP WQE", DUMP_PREFIX_OFFSET, 16, 8,
			     wqe, IRDMA_CQP_WQE_SIZE * 8, false);
	irdma_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * irdma_sc_manage_pble_bp - manage pble
 * @cqp: cqp for cqp' sq wqe
 * @info: pble info
 * @scratch: pointer for completion
 * @post_sq: to post and ring
 */
static int irdma_sc_manage_pble_bp(struct irdma_sc_cqp *cqp,
				   struct irdma_manage_pble_info *info,
				   u64 scratch, bool post_sq)
{
	u64 temp, hdr, pd_pl_pba;
	__le64 *wqe;

	wqe = irdma_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;

	temp = FIELD_PREP(IRDMA_CQPSQ_MVPBP_PD_ENTRY_CNT, info->pd_entry_cnt) |
	       FIELD_PREP(IRDMA_CQPSQ_MVPBP_FIRST_PD_INX,
			  info->first_pd_index) |
	       FIELD_PREP(IRDMA_CQPSQ_MVPBP_SD_INX, info->sd_index);
	set_64bit_val(wqe, 16, temp);

	pd_pl_pba =
		FIELD_PREP(IRDMA_CQPSQ_MVPBP_PD_PLPBA, info->pd_pl_pba >> 3);
	set_64bit_val(wqe, 32, pd_pl_pba);

	hdr = FIELD_PREP(IRDMA_CQPSQ_MVPBP_INV_PD_ENT, info->inv_pd_ent ? 1 : 0) |
	      FIELD_PREP(IRDMA_CQPSQ_OPCODE, IRDMA_CQP_OP_MANAGE_PBLE_BP) |
	      FIELD_PREP(IRDMA_CQPSQ_WQEVALID, cqp->polarity);

	dma_wmb(); /* make sure WQE is populated before valid bit is set */
	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: MANAGE PBLE_BP WQE", DUMP_PREFIX_OFFSET,
			     16, 8, wqe, IRDMA_CQP_WQE_SIZE * 8, false);

	if (post_sq)
		irdma_sc_cqp_post_sq(cqp);
	return 0;
}

/**
 * irdma_sc_cq_ack - acknowledge completion q
 * @cq: cq struct
 */
static inline void irdma_sc_cq_ack(struct irdma_sc_cq *cq)
{
	if (cq->dev->hw_wa & NO_CQACK)
		return;
	writel(cq->cq_uk.cq_id, cq->cq_uk.cq_ack_db);
}

/**
 * irdma_sc_cq_init - initialize completion q
 * @cq: cq struct
 * @info: cq initialization info
 */
int irdma_sc_cq_init(struct irdma_sc_cq *cq, struct irdma_cq_init_info *info)
{
	int ret_code;
	u32 pble_obj_cnt;

	pble_obj_cnt = info->dev->hmc_info->hmc_obj[IRDMA_HMC_IW_PBLE].cnt;
	if (info->virtual_map && info->first_pm_pbl_idx >= pble_obj_cnt)
		return -EINVAL;

	cq->cq_pa = info->cq_base_pa;
	cq->dev = info->dev;
	cq->ceq_id = info->ceq_id;
	info->cq_uk_init_info.cqe_alloc_db = cq->dev->cq_arm_db;
	info->cq_uk_init_info.cq_ack_db = cq->dev->cq_ack_db;
	ret_code = irdma_uk_cq_init(&cq->cq_uk, &info->cq_uk_init_info);
	if (ret_code)
		return ret_code;

	cq->virtual_map = info->virtual_map;
	cq->pbl_chunk_size = info->pbl_chunk_size;
	cq->ceqe_mask = info->ceqe_mask;
	cq->cq_type = (info->type) ? info->type : IRDMA_CQ_TYPE_IWARP;
	cq->shadow_area_pa = info->shadow_area_pa;
	cq->shadow_read_threshold = info->shadow_read_threshold;
	cq->ceq_id_valid = info->ceq_id_valid;
	cq->tph_en = info->tph_en;
	cq->tph_val = info->tph_val;
	cq->first_pm_pbl_idx = info->first_pm_pbl_idx;
	cq->vsi = info->vsi;
	cq->pasid = info->pasid;
	cq->pasid_valid = info->pasid_valid;

	return 0;
}

/**
 * irdma_sc_cq_create - create completion q
 * @cq: cq struct
 * @scratch: u64 saved to be used during cqp completion
 * @check_overflow: flag for overflow check
 * @post_sq: flag for cqp db to ring
 */
static int irdma_sc_cq_create(struct irdma_sc_cq *cq, u64 scratch,
			      bool check_overflow, bool post_sq)
{
	__le64 *wqe;
	struct irdma_sc_cqp *cqp;
	u64 hdr;
	struct irdma_sc_ceq *ceq;
	int ret_code = 0;

	cqp = cq->dev->cqp;
	if (cq->cq_uk.cq_id > (cqp->dev->hmc_info->hmc_obj[IRDMA_HMC_IW_CQ].max_cnt - 1))
		return -EINVAL;

	if (cq->ceq_id > (cq->dev->hmc_fpm_misc.max_ceqs - 1))
		return -EINVAL;

	ceq = cq->dev->ceq[cq->ceq_id];
	if (ceq && ceq->reg_cq) {
		ret_code = irdma_sc_add_cq_ctx(ceq, cq);
		if (ret_code)
			return ret_code;
	}

	wqe = irdma_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe) {
		if (ceq && ceq->reg_cq)
			irdma_sc_remove_cq_ctx(ceq, cq);
		return -ENOMEM;
	}

	set_64bit_val(wqe, 0, cq->cq_uk.cq_size);
	set_64bit_val(wqe, 8, RS_64_1(cq, 1));
	set_64bit_val(wqe, 16,
		      FIELD_PREP(IRDMA_CQPSQ_CQ_SHADOW_READ_THRESHOLD,
				 cq->shadow_read_threshold));
	set_64bit_val(wqe, 32, cq->virtual_map ? 0 : cq->cq_pa);
	set_64bit_val(wqe, 40, cq->shadow_area_pa);
	set_64bit_val(wqe, 48,
		      FIELD_PREP(IRDMA_CQPSQ_CQ_FIRSTPMPBLIDX,
				 cq->virtual_map ? cq->first_pm_pbl_idx : 0));
	set_64bit_val(wqe, 56,
		      FIELD_PREP(IRDMA_CQPSQ_TPHVAL, cq->tph_val) |
		      FIELD_PREP(IRDMA_CQPSQ_PASID, cq->pasid) |
		      FIELD_PREP(IRDMA_CQPSQ_VSIIDX, cq->vsi->vsi_idx));
	if (cq->dev->hw_wa & NO_CEQMASK)
		cq->ceqe_mask = 0;
	hdr = FLD_LS_64(cq->dev, cq->cq_uk.cq_id, IRDMA_CQPSQ_CQ_CQID) |
	      FLD_LS_64(cq->dev, cq->ceq_id_valid ? cq->ceq_id : 0,
			IRDMA_CQPSQ_CQ_CEQID) |
	      FIELD_PREP(IRDMA_CQPSQ_OPCODE, IRDMA_CQP_OP_CREATE_CQ) |
	      FIELD_PREP(IRDMA_CQPSQ_CQ_LPBLSIZE, cq->pbl_chunk_size) |
	      FIELD_PREP(IRDMA_CQPSQ_CQ_CHKOVERFLOW, check_overflow) |
	      FIELD_PREP(IRDMA_CQPSQ_CQ_VIRTMAP, cq->virtual_map) |
	      FIELD_PREP(IRDMA_CQPSQ_CQ_CQID_HIGH, cq->cq_uk.cq_id >> 22) |
	      FIELD_PREP(IRDMA_CQPSQ_CQ_CEQID_HIGH,
			 (cq->ceq_id_valid ? cq->ceq_id : 0) >> 10) |
	      FIELD_PREP(IRDMA_CQPSQ_PASID_VALID, cq->pasid_valid) |
	      FIELD_PREP(IRDMA_CQPSQ_CQ_ENCEQEMASK, cq->ceqe_mask) |
	      FIELD_PREP(IRDMA_CQPSQ_CQ_CEQIDVALID, cq->ceq_id_valid) |
	      FIELD_PREP(IRDMA_CQPSQ_TPHEN, cq->tph_en) |
	      FIELD_PREP(IRDMA_CQPSQ_CQ_AVOIDMEMCNFLCT,
			 cq->cq_uk.avoid_mem_cflct) |
	      FIELD_PREP(IRDMA_CQPSQ_WQEVALID, cqp->polarity);

	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: CQ_CREATE WQE", DUMP_PREFIX_OFFSET, 16, 8,
			     wqe, IRDMA_CQP_WQE_SIZE * 8, false);
	if (post_sq)
		irdma_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * irdma_sc_cq_destroy - destroy completion q
 * @cq: cq struct
 * @scratch: u64 saved to be used during cqp completion
 * @post_sq: flag for cqp db to ring
 */
int irdma_sc_cq_destroy(struct irdma_sc_cq *cq, u64 scratch, bool post_sq)
{
	struct irdma_sc_cqp *cqp;
	__le64 *wqe;
	u64 hdr;
	struct irdma_sc_ceq *ceq;

	cqp = cq->dev->cqp;
	wqe = irdma_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;

	ceq = cq->dev->ceq[cq->ceq_id];
	if (ceq && ceq->reg_cq)
		irdma_sc_remove_cq_ctx(ceq, cq);

	set_64bit_val(wqe, 0, cq->cq_uk.cq_size);
	set_64bit_val(wqe, 8, RS_64_1(cq, 1));
	set_64bit_val(wqe, 40, cq->shadow_area_pa);
	set_64bit_val(wqe, 48,
		      (cq->virtual_map ? cq->first_pm_pbl_idx : 0));
	set_64bit_val(wqe, 56,
		      FIELD_PREP(IRDMA_CQPSQ_PASID, cq->pasid));

	if (cq->dev->hw_wa & NO_CEQMASK)
		cq->ceqe_mask = 0;
	hdr = cq->cq_uk.cq_id |
	      FLD_LS_64(cq->dev, (cq->ceq_id_valid ? cq->ceq_id : 0),
			IRDMA_CQPSQ_CQ_CEQID) |
	      FIELD_PREP(IRDMA_CQPSQ_OPCODE, IRDMA_CQP_OP_DESTROY_CQ) |
	      FIELD_PREP(IRDMA_CQPSQ_CQ_LPBLSIZE, cq->pbl_chunk_size) |
	      FIELD_PREP(IRDMA_CQPSQ_CQ_VIRTMAP, cq->virtual_map) |
	      FIELD_PREP(IRDMA_CQPSQ_CQ_ENCEQEMASK, cq->ceqe_mask) |
	      FIELD_PREP(IRDMA_CQPSQ_CQ_CEQIDVALID, cq->ceq_id_valid) |
	      FIELD_PREP(IRDMA_CQPSQ_TPHEN, cq->tph_en) |
	      FIELD_PREP(IRDMA_CQPSQ_CQ_AVOIDMEMCNFLCT, cq->cq_uk.avoid_mem_cflct) |
	      FIELD_PREP(IRDMA_CQPSQ_PASID_VALID, cq->pasid_valid) |
	      FIELD_PREP(IRDMA_CQPSQ_WQEVALID, cqp->polarity);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: CQ_DESTROY WQE", DUMP_PREFIX_OFFSET, 16, 8,
			     wqe, IRDMA_CQP_WQE_SIZE * 8, false);
	if (post_sq)
		irdma_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * irdma_sc_cq_resize - set resized cq buffer info
 * @cq: resized cq
 * @info: resized cq buffer info
 */
void irdma_sc_cq_resize(struct irdma_sc_cq *cq, struct irdma_modify_cq_info *info)
{
	cq->virtual_map = info->virtual_map;
	cq->cq_pa = info->cq_pa;
	cq->first_pm_pbl_idx = info->first_pm_pbl_idx;
	cq->pbl_chunk_size = info->pbl_chunk_size;
	irdma_uk_cq_resize(&cq->cq_uk, info->cq_base, info->cq_size);
}

/**
 * irdma_sc_cq_modify - modify a Completion Queue
 * @cq: cq struct
 * @info: modification info struct
 * @scratch: u64 saved to be used during cqp completion
 * @post_sq: flag to post to sq
 */
static int irdma_sc_cq_modify(struct irdma_sc_cq *cq,
			      struct irdma_modify_cq_info *info, u64 scratch,
			      bool post_sq)
{
	struct irdma_sc_cqp *cqp;
	__le64 *wqe;
	u64 hdr;
	u32 pble_obj_cnt;

	pble_obj_cnt = cq->dev->hmc_info->hmc_obj[IRDMA_HMC_IW_PBLE].cnt;
	if (info->cq_resize && info->virtual_map &&
	    info->first_pm_pbl_idx >= pble_obj_cnt)
		return -EINVAL;

	cqp = cq->dev->cqp;
	wqe = irdma_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;

	set_64bit_val(wqe, 0, info->cq_size);
	set_64bit_val(wqe, 8, RS_64_1(cq, 1));
	set_64bit_val(wqe, 16,
		      FIELD_PREP(IRDMA_CQPSQ_CQ_SHADOW_READ_THRESHOLD, info->shadow_read_threshold));
	set_64bit_val(wqe, 32, info->cq_pa);
	set_64bit_val(wqe, 40, cq->shadow_area_pa);
	set_64bit_val(wqe, 48, info->first_pm_pbl_idx);
	set_64bit_val(wqe, 56,
		      FIELD_PREP(IRDMA_CQPSQ_TPHVAL, cq->tph_val) |
		      FIELD_PREP(IRDMA_CQPSQ_PASID, cq->pasid) |
		      FIELD_PREP(IRDMA_CQPSQ_VSIIDX, cq->vsi->vsi_idx));

	if (cq->dev->hw_wa & NO_CEQMASK)
		cq->ceqe_mask = 0;
	hdr = cq->cq_uk.cq_id |
	      FIELD_PREP(IRDMA_CQPSQ_OPCODE, IRDMA_CQP_OP_MODIFY_CQ) |
	      FIELD_PREP(IRDMA_CQPSQ_CQ_CQRESIZE, info->cq_resize) |
	      FIELD_PREP(IRDMA_CQPSQ_CQ_LPBLSIZE, info->pbl_chunk_size) |
	      FIELD_PREP(IRDMA_CQPSQ_CQ_CHKOVERFLOW, info->check_overflow) |
	      FIELD_PREP(IRDMA_CQPSQ_CQ_VIRTMAP, info->virtual_map) |
	      FIELD_PREP(IRDMA_CQPSQ_CQ_ENCEQEMASK, cq->ceqe_mask) |
	      FIELD_PREP(IRDMA_CQPSQ_TPHEN, cq->tph_en) |
	      FIELD_PREP(IRDMA_CQPSQ_CQ_AVOIDMEMCNFLCT,
			 cq->cq_uk.avoid_mem_cflct) |
	      FIELD_PREP(IRDMA_CQPSQ_PASID_VALID, cq->pasid_valid) |
	      FIELD_PREP(IRDMA_CQPSQ_WQEVALID, cqp->polarity);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: CQ_MODIFY WQE", DUMP_PREFIX_OFFSET, 16, 8,
			     wqe, IRDMA_CQP_WQE_SIZE * 8, false);
	if (post_sq)
		irdma_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * irdma_check_cqp_progress - check cqp processing progress
 * @timeout: timeout info struct
 * @dev: sc device struct
 */
void irdma_check_cqp_progress(struct irdma_cqp_timeout *timeout,
			      struct irdma_sc_dev *dev)
{
	u64 completed_ops = atomic64_read(&dev->cqp->completed_ops);

	if (timeout->compl_cqp_cmds != completed_ops) {
		timeout->compl_cqp_cmds = completed_ops;
		timeout->count = 0;
	} else if (timeout->compl_cqp_cmds != dev->cqp->requested_ops) {
		timeout->count++;
	}
}

/**
 * irdma_get_cqp_reg_info - get head and tail for cqp using registers
 * @cqp: struct for cqp hw
 * @val: cqp tail register value
 * @tail: wqtail register value
 * @error: cqp processing err
 */
static inline void irdma_get_cqp_reg_info(struct irdma_sc_cqp *cqp, u32 *val,
					  u32 *tail, u32 *error)
{
	*val = readl(cqp->dev->hw_regs[IRDMA_CQPTAIL]);
	*tail = FIELD_GET(IRDMA_CQPTAIL_WQTAIL, *val);
	*error = FIELD_GET(IRDMA_CQPTAIL_CQP_OP_ERR, *val);
}

/**
 * irdma_sc_get_decoded_ird_size_gen_3 - get decoded IRD size for GEN 3
 * @ird_enc: IRD encoding
 * IRD size defaults to a value of 4 in case of invalid input.
 */
static u16 irdma_sc_get_decoded_ird_size_gen_3(u8 ird_enc)
{
	switch (ird_enc) {
	case IRDMA_IRD_HW_SIZE_4096_GEN3:
		return 4096;
	case IRDMA_IRD_HW_SIZE_2048_GEN3:
		return 2048;
	case IRDMA_IRD_HW_SIZE_1024_GEN3:
		return 1024;
	case IRDMA_IRD_HW_SIZE_512_GEN3:
		return 512;
	case IRDMA_IRD_HW_SIZE_256_GEN3:
		return 256;
	case IRDMA_IRD_HW_SIZE_128_GEN3:
		return 128;
	case IRDMA_IRD_HW_SIZE_64_GEN3:
		return 64;
	case IRDMA_IRD_HW_SIZE_32_GEN3:
		return 32;
	case IRDMA_IRD_HW_SIZE_16_GEN3:
		return 16;
	case IRDMA_IRD_HW_SIZE_8_GEN3:
		return 8;
	case IRDMA_IRD_HW_SIZE_4_GEN3:
		return 4;
	default:
		return 4;
	}
}

/**
 * irdma_sc_cqp_def_cmpl_ae_handler - remove completed requests from pending list
 * @dev: sc device struct
 * @info: AE entry info
 * @first: true if this is the first call to this handler for given AEQE
 * @scratch: (out) scratch entry pointer
 * @sw_def_info: (in/out) SW ticket value for this AE
 *
 * In case of AE_DEF_CMPL event, this function should be called in a loop
 * until it returns NULL-ptr via scratch.
 * For each call, it looks for a matching CQP request on pending list,
 * removes it from the list and returns the pointer to the associated scratch
 * entry.
 * If this is the first call to this function for given AEQE, sw_def_info
 * value is not used to find matching requests.  Instead, it is populated
 * with the value from the first matching cqp_request on the list.
 * For subsequent calls, ooo_op->sw_def_info need to match the value passed
 * by a caller.
 *
 * Return: scratch entry pointer for cqp_request to be released or NULL
 * if no matching request is found.
 */
void irdma_sc_cqp_def_cmpl_ae_handler(struct irdma_sc_dev *dev,
				      struct irdma_aeqe_info *info,
				      bool first, u64 *scratch,
				      u32 *sw_def_info)
{
	struct irdma_ooo_cqp_op *ooo_op;
	unsigned long flags;

	ibdev_dbg(to_ibdev(dev),
		  "CQP: DEBUG_FW_OOO AE DEFERRED def_info 0x%x first %d\n",
		  info->def_info, first);

	*scratch = 0;

	spin_lock_irqsave(&dev->cqp->ooo_list_lock, flags);
	list_for_each_entry(ooo_op, &dev->cqp->ooo_pnd, list_entry) {
		if (ooo_op->deferred &&
		    ((first && ooo_op->def_info == info->def_info) ||
		     (!first && ooo_op->sw_def_info == *sw_def_info))) {
			*sw_def_info = ooo_op->sw_def_info;
			*scratch = ooo_op->scratch;

			ibdev_dbg(to_ibdev(dev),
				  "CQP: DEBUG_FW_OOO AE DEFERRED def_info 0x%x sw_def_info 0x%x wqe_idx 0x%x\n",
				  ooo_op->def_info, *sw_def_info,
				  ooo_op->wqe_idx);

			list_move(&ooo_op->list_entry, &dev->cqp->ooo_avail);
			atomic64_inc(&dev->cqp->completed_ops);

			break;
		}
	}
	spin_unlock_irqrestore(&dev->cqp->ooo_list_lock, flags);
	if (first && !*scratch)
		ibdev_dbg(to_ibdev(dev),
		          "AEQ: deferred completion with unknown ticket: def_info 0x%x\n",
		          info->def_info);
}

/**
 * irdma_sc_cqp_cleanup_handler - remove requests from pending list
 * @dev: sc device struct
 *
 * This function should be called in a loop from irdma_cleanup_pending_cqp_op.
 * For each call, it returns first CQP request on pending list, removes it
 * from the list and returns the pointer to the associated scratch entry.
 *
 * Return: scratch entry pointer for cqp_request to be released or NULL
 * if pending list is empty.
 */
u64 irdma_sc_cqp_cleanup_handler(struct irdma_sc_dev *dev)
{
	struct irdma_ooo_cqp_op *ooo_op;
	u64 scratch = 0;

	list_for_each_entry(ooo_op, &dev->cqp->ooo_pnd, list_entry) {
		scratch = ooo_op->scratch;

		list_del(&ooo_op->list_entry);
		list_add(&ooo_op->list_entry, &dev->cqp->ooo_avail);
		atomic64_inc(&dev->cqp->completed_ops);

		break;
	}

	return scratch;
}

/**
 * irdma_cqp_poll_registers - poll cqp registers
 * @cqp: struct for cqp hw
 * @tail: wqtail register value
 * @count: how many times to try for completion
 */
static int irdma_cqp_poll_registers(struct irdma_sc_cqp *cqp, u32 tail,
				    u32 count)
{
	u32 i = 0;
	u32 newtail, error, val;

	while (i++ < count) {
		irdma_get_cqp_reg_info(cqp, &val, &newtail, &error);
		if (error) {
			error = readl(cqp->dev->hw_regs[IRDMA_CQPERRCODES]);
			ibdev_dbg(to_ibdev(cqp->dev),
				  "CQP: CQPERRCODES error_code[x%08X]\n",
				  error);
			return -EIO;
		}
		if (newtail != tail) {
			/* SUCCESS */
			IRDMA_RING_MOVE_TAIL(cqp->sq_ring);
			atomic64_inc(&cqp->completed_ops);
			return 0;
		}
		udelay(cqp->dev->hw_attrs.max_sleep_count);
	}

	return -ETIMEDOUT;
}

/**
 * irdma_sc_decode_fpm_commit - decode a 64 bit value into count and base
 * @dev: sc device struct
 * @buf: pointer to commit buffer
 * @buf_idx: buffer index
 * @obj_info: object info pointer
 * @rsrc_idx: indexs of memory resource
 */
static u64 irdma_sc_decode_fpm_commit(struct irdma_sc_dev *dev, __le64 *buf,
				      u32 buf_idx, struct irdma_hmc_obj_info *obj_info,
				      u32 rsrc_idx)
{
	u64 temp;

	get_64bit_val(buf, buf_idx, &temp);

	switch (rsrc_idx) {
	case IRDMA_HMC_IW_QP:
		obj_info[rsrc_idx].cnt = (u32)FIELD_GET(IRDMA_COMMIT_FPM_QPCNT, temp);
		break;
	case IRDMA_HMC_IW_CQ:
		obj_info[rsrc_idx].cnt = (u32)FLD_RS_64(dev, temp, IRDMA_COMMIT_FPM_CQCNT);
		break;
	case IRDMA_HMC_IW_APBVT_ENTRY:
		if (dev->hw_attrs.uk_attrs.hw_rev <= IRDMA_GEN_2)
			obj_info[rsrc_idx].cnt = 1;
		else
			obj_info[rsrc_idx].cnt = 0;
		break;
	default:
		obj_info[rsrc_idx].cnt = (u32)temp;
		break;
	}

	obj_info[rsrc_idx].base = (u64)RS_64_1(temp, IRDMA_COMMIT_FPM_BASE_S) * 512;

	return temp;
}

/**
 * irdma_sc_parse_fpm_commit_buf - parse fpm commit buffer
 * @dev: pointer to dev struct
 * @buf: ptr to fpm commit buffer
 * @info: ptr to irdma_hmc_obj_info struct
 * @sd: number of SDs for HMC objects
 *
 * parses fpm commit info and copy base value
 * of hmc objects in hmc_info
 */
static void irdma_sc_parse_fpm_commit_buf(struct irdma_sc_dev *dev, __le64 *buf,
					  struct irdma_hmc_obj_info *info,
					  u32 *sd)
{
	u64 size;
	u32 i;
	u64 max_base = 0;
	u32 last_hmc_obj = 0;

	irdma_sc_decode_fpm_commit(dev, buf, 0, info,
				   IRDMA_HMC_IW_QP);
	irdma_sc_decode_fpm_commit(dev, buf, 8, info,
				   IRDMA_HMC_IW_CQ);
	irdma_sc_decode_fpm_commit(dev, buf, 16, info,
				   IRDMA_HMC_IW_SRQ);
	irdma_sc_decode_fpm_commit(dev, buf, 24, info,
				   IRDMA_HMC_IW_HTE);
	irdma_sc_decode_fpm_commit(dev, buf, 32, info,
				   IRDMA_HMC_IW_ARP);
	irdma_sc_decode_fpm_commit(dev, buf, 40, info,
				   IRDMA_HMC_IW_APBVT_ENTRY);
	irdma_sc_decode_fpm_commit(dev, buf, 48, info,
				   IRDMA_HMC_IW_MR);
	irdma_sc_decode_fpm_commit(dev, buf, 56, info,
				   IRDMA_HMC_IW_XF);
	irdma_sc_decode_fpm_commit(dev, buf, 64, info,
				   IRDMA_HMC_IW_XFFL);
	irdma_sc_decode_fpm_commit(dev, buf, 72, info,
				   IRDMA_HMC_IW_Q1);
	irdma_sc_decode_fpm_commit(dev, buf, 80, info,
				   IRDMA_HMC_IW_Q1FL);
	irdma_sc_decode_fpm_commit(dev, buf, 88, info,
				   IRDMA_HMC_IW_TIMER);
	irdma_sc_decode_fpm_commit(dev, buf, 112, info,
				   IRDMA_HMC_IW_PBLE);
	/* skipping RSVD. */
	if (dev->hw_attrs.uk_attrs.hw_rev != IRDMA_GEN_1) {
		irdma_sc_decode_fpm_commit(dev, buf, 96, info,
					   IRDMA_HMC_IW_FSIMC);
		irdma_sc_decode_fpm_commit(dev, buf, 104, info,
					   IRDMA_HMC_IW_FSIAV);
		irdma_sc_decode_fpm_commit(dev, buf, 128, info,
					   IRDMA_HMC_IW_RRF);
		irdma_sc_decode_fpm_commit(dev, buf, 136, info,
					   IRDMA_HMC_IW_RRFFL);
		irdma_sc_decode_fpm_commit(dev, buf, 144, info,
					   IRDMA_HMC_IW_HDR);
		irdma_sc_decode_fpm_commit(dev, buf, 152, info,
					   IRDMA_HMC_IW_MD);
		if (dev->hw_attrs.uk_attrs.hw_rev <= IRDMA_GEN_2) {
			irdma_sc_decode_fpm_commit(dev, buf, 160, info,
						   IRDMA_HMC_IW_OOISC);
			irdma_sc_decode_fpm_commit(dev, buf, 168, info,
						   IRDMA_HMC_IW_OOISCFFL);
		}
	}

	/* searching for the last object in HMC to find the size of the HMC area. */
	for (i = IRDMA_HMC_IW_QP; i < IRDMA_HMC_IW_MAX; i++) {
		if (info[i].base > max_base && info[i].cnt) {
			max_base = info[i].base;
			last_hmc_obj = i;
		}
	}

	size = info[last_hmc_obj].cnt * info[last_hmc_obj].size +
	       info[last_hmc_obj].base;

	if (size & 0x1FFFFF)
		*sd = (u32)((size >> 21) + 1); /* add 1 for remainder */
	else
		*sd = (u32)(size >> 21);

}

/**
 * irdma_sc_decode_fpm_query() - Decode a 64 bit value into max count and size
 * @buf: ptr to fpm query buffer
 * @buf_idx: index into buf
 * @obj_info: ptr to irdma_hmc_obj_info struct
 * @rsrc_idx: resource index into info
 *
 * Decode a 64 bit value from fpm query buffer into max count and size
 */
static u64 irdma_sc_decode_fpm_query(__le64 *buf, u32 buf_idx,
				     struct irdma_hmc_obj_info *obj_info,
				     u32 rsrc_idx)
{
	u64 temp;
	u32 size;

	get_64bit_val(buf, buf_idx, &temp);
	obj_info[rsrc_idx].max_cnt = (u32)temp;
	size = (u32)RS_64_1(temp, 32);
	obj_info[rsrc_idx].size = LS_64_1(1, size);

	return temp;
}

/**
 * irdma_sc_parse_fpm_query_buf() - parses fpm query buffer
 * @dev: ptr to shared code device
 * @buf: ptr to fpm query buffer
 * @hmc_info: ptr to irdma_hmc_obj_info struct
 * @hmc_fpm_misc: ptr to fpm data
 *
 * parses fpm query buffer and copy max_cnt and
 * size value of hmc objects in hmc_info
 */
static int irdma_sc_parse_fpm_query_buf(struct irdma_sc_dev *dev, __le64 *buf,
					struct irdma_hmc_info *hmc_info,
					struct irdma_hmc_fpm_misc *hmc_fpm_misc)
{
	struct irdma_hmc_obj_info *obj_info;
	u8 ird_encoding;
	u16 max_pe_sds;
	u64 temp;
	u32 size;


	obj_info = hmc_info->hmc_obj;

	get_64bit_val(buf, 0, &temp);
	hmc_info->first_sd_index = (u16)FIELD_GET(IRDMA_QUERY_FPM_FIRST_PE_SD_INDEX, temp);
	if (dev->hw_attrs.uk_attrs.hw_rev >= IRDMA_GEN_3)
		max_pe_sds = (u16)FIELD_GET(IRDMA_QUERY_FPM_MAX_PE_SDS_GEN3, temp);
	else
		max_pe_sds = (u16)FIELD_GET(IRDMA_QUERY_FPM_MAX_PE_SDS, temp);

	/* Reduce SD count for unprivleged functions by 1 to account for PBLE
	 * backing page rounding
	 */
	if (dev->hw_attrs.uk_attrs.hw_rev <= IRDMA_GEN_2 &&
	    (hmc_info->hmc_fn_id >= dev->hw_attrs.first_hw_vf_fpm_id ||
	     !dev->privileged))
		max_pe_sds--;
	hmc_fpm_misc->max_sds = max_pe_sds;
	hmc_info->sd_table.sd_cnt = max_pe_sds + hmc_info->first_sd_index;
	get_64bit_val(buf, 8, &temp);
	obj_info[IRDMA_HMC_IW_QP].max_cnt = (u32)FIELD_GET(IRDMA_QUERY_FPM_MAX_QPS, temp);
	size = (u32)RS_64_1(temp, 32);
	obj_info[IRDMA_HMC_IW_QP].size = LS_64_1(1, size);

	get_64bit_val(buf, 16, &temp);
	obj_info[IRDMA_HMC_IW_CQ].max_cnt = (u32)FIELD_GET(IRDMA_QUERY_FPM_MAX_CQS, temp);
	size = (u32)RS_64_1(temp, 32);
	obj_info[IRDMA_HMC_IW_CQ].size = LS_64_1(1, size);

	if (dev->hw_attrs.uk_attrs.hw_rev > IRDMA_GEN_3) {
		get_64bit_val(buf, 176, &temp);
		hmc_fpm_misc->loc_mem_pages = (u32)FIELD_GET(IRDMA_QUERY_FPM_LOC_MEM_PAGES, temp);
		pr_err("DEBUG_LOC_MEM_PAGES from query = %d\n",
		       hmc_fpm_misc->loc_mem_pages);
		if (!hmc_fpm_misc->loc_mem_pages && dev->wa_mem_pages)
			hmc_fpm_misc->loc_mem_pages = dev->wa_mem_pages;
	}

	irdma_sc_decode_fpm_query(buf, 24, obj_info, IRDMA_HMC_IW_SRQ);
	irdma_sc_decode_fpm_query(buf, 32, obj_info, IRDMA_HMC_IW_HTE);
	irdma_sc_decode_fpm_query(buf, 40, obj_info, IRDMA_HMC_IW_ARP);

	if (dev->hw_attrs.uk_attrs.hw_rev >= IRDMA_GEN_3) {
		obj_info[IRDMA_HMC_IW_APBVT_ENTRY].size = 0;
		obj_info[IRDMA_HMC_IW_APBVT_ENTRY].max_cnt = 0;
	} else {
		obj_info[IRDMA_HMC_IW_APBVT_ENTRY].size = 8192;
		obj_info[IRDMA_HMC_IW_APBVT_ENTRY].max_cnt = 1;
	}

	irdma_sc_decode_fpm_query(buf, 48, obj_info, IRDMA_HMC_IW_MR);
	irdma_sc_decode_fpm_query(buf, 56, obj_info, IRDMA_HMC_IW_XF);

	get_64bit_val(buf, 64, &temp);
	obj_info[IRDMA_HMC_IW_XFFL].max_cnt = (u32)temp;
	obj_info[IRDMA_HMC_IW_XFFL].size = 4;
	hmc_fpm_misc->xf_block_size = FIELD_GET(IRDMA_QUERY_FPM_XFBLOCKSIZE, temp);
	if (obj_info[IRDMA_HMC_IW_XF].max_cnt && !hmc_fpm_misc->xf_block_size)
		return -EINVAL;

	irdma_sc_decode_fpm_query(buf, 72, obj_info, IRDMA_HMC_IW_Q1);
	get_64bit_val(buf, 80, &temp);
	obj_info[IRDMA_HMC_IW_Q1FL].max_cnt = (u32)temp;
	obj_info[IRDMA_HMC_IW_Q1FL].size = 4;

	hmc_fpm_misc->q1_block_size = FIELD_GET(IRDMA_QUERY_FPM_Q1BLOCKSIZE, temp);
	if (!hmc_fpm_misc->q1_block_size)
		return -EINVAL;

	irdma_sc_decode_fpm_query(buf, 88, obj_info, IRDMA_HMC_IW_TIMER);

	get_64bit_val(buf, 112, &temp);
	obj_info[IRDMA_HMC_IW_PBLE].max_cnt = (u32)temp;
	obj_info[IRDMA_HMC_IW_PBLE].size = 8;

	get_64bit_val(buf, 120, &temp);
	hmc_fpm_misc->max_ceqs = FIELD_GET(IRDMA_QUERY_FPM_MAX_CEQS, temp);
	hmc_fpm_misc->ht_multiplier = FIELD_GET(IRDMA_QUERY_FPM_HTMULTIPLIER, temp);
	hmc_fpm_misc->timer_bucket = FIELD_GET(IRDMA_QUERY_FPM_TIMERBUCKET, temp);
	if (FIELD_GET(IRDMA_MANAGE_RSRC_VER2,
		      dev->feature_info[IRDMA_FTN_FLAGS])) {
		ird_encoding = (u8)FIELD_GET(IRDMA_QUERY_FPM_MAX_IRD, temp);
		hmc_fpm_misc->ird =
			irdma_sc_get_decoded_ird_size_gen_3(ird_encoding) / 2;
		dev->hw_attrs.max_hw_ird = hmc_fpm_misc->ird;
		dev->hw_attrs.max_hw_ord = hmc_fpm_misc->ird;
	}
	if (dev->hw_attrs.uk_attrs.hw_rev == IRDMA_GEN_1)
		return 0;
	irdma_sc_decode_fpm_query(buf, 96, obj_info, IRDMA_HMC_IW_FSIMC);
	irdma_sc_decode_fpm_query(buf, 104, obj_info, IRDMA_HMC_IW_FSIAV);
	irdma_sc_decode_fpm_query(buf, 128, obj_info, IRDMA_HMC_IW_RRF);

	get_64bit_val(buf, 136, &temp);
	obj_info[IRDMA_HMC_IW_RRFFL].max_cnt = (u32)temp;
	obj_info[IRDMA_HMC_IW_RRFFL].size = 4;
	hmc_fpm_misc->rrf_block_size = FIELD_GET(IRDMA_QUERY_FPM_RRFBLOCKSIZE, temp);
	if (!hmc_fpm_misc->rrf_block_size &&
	    obj_info[IRDMA_HMC_IW_RRFFL].max_cnt)
		return -EINVAL;

	if (!obj_info[IRDMA_HMC_IW_XF].max_cnt)
		obj_info[IRDMA_HMC_IW_RRF].max_cnt = IRDMA_HMC_MIN_RRF;

	irdma_sc_decode_fpm_query(buf, 144, obj_info, IRDMA_HMC_IW_HDR);
	irdma_sc_decode_fpm_query(buf, 152, obj_info, IRDMA_HMC_IW_MD);

	if (dev->hw_attrs.uk_attrs.hw_rev <= IRDMA_GEN_2) {
		irdma_sc_decode_fpm_query(buf, 160, obj_info, IRDMA_HMC_IW_OOISC);

		get_64bit_val(buf, 168, &temp);
		obj_info[IRDMA_HMC_IW_OOISCFFL].max_cnt = (u32)temp;
		obj_info[IRDMA_HMC_IW_OOISCFFL].size = 4;
		hmc_fpm_misc->ooiscf_block_size = FIELD_GET(IRDMA_QUERY_FPM_OOISCFBLOCKSIZE, temp);
		if (!hmc_fpm_misc->ooiscf_block_size &&
		    obj_info[IRDMA_HMC_IW_OOISCFFL].max_cnt)
			return -EINVAL;
	}

	if (dev->hw_attrs.uk_attrs.hw_rev >= IRDMA_GEN_3) {
		get_64bit_val(buf, 176, &temp);
		hmc_fpm_misc->loc_mem_pages = (u32)FIELD_GET(IRDMA_QUERY_FPM_LOC_MEM_PAGES, temp);
		pr_err("DEBUG_LOC_MEM_PAGES from query = %d\n",
		       hmc_fpm_misc->loc_mem_pages);
		for (size = 0; size <= IRDMA_HMC_IW_MAX; size++)
			if (obj_info[size].max_cnt)
				pr_err("QUERY %s\t\tmaxcnt = %u\n",
				       hmc_obj_name(size),
				       obj_info[size].max_cnt);
		if (!hmc_fpm_misc->loc_mem_pages && dev->wa_mem_pages)
			hmc_fpm_misc->loc_mem_pages = dev->wa_mem_pages;
	}

	return 0;
}

/**
 * irdma_sc_find_reg_cq - find cq ctx index
 * @ceq: ceq sc structure
 * @cq: cq sc structure
 */
static u32 irdma_sc_find_reg_cq(struct irdma_sc_ceq *ceq,
				struct irdma_sc_cq *cq)
{
	u32 i;

	for (i = 0; i < ceq->reg_cq_size; i++) {
		if (cq == ceq->reg_cq[i])
			return i;
	}

	return IRDMA_INVALID_CQ_IDX;
}

/**
 * irdma_sc_add_cq_ctx - add cq ctx tracking for ceq
 * @ceq: ceq sc structure
 * @cq: cq sc structure
 */
int irdma_sc_add_cq_ctx(struct irdma_sc_ceq *ceq, struct irdma_sc_cq *cq)
{
	unsigned long flags;

	spin_lock_irqsave(&ceq->req_cq_lock, flags);

	if (ceq->reg_cq_size == ceq->elem_cnt) {
		spin_unlock_irqrestore(&ceq->req_cq_lock, flags);
		return -ENOMEM;
	}

	ceq->reg_cq[ceq->reg_cq_size++] = cq;

	spin_unlock_irqrestore(&ceq->req_cq_lock, flags);

	return 0;
}

/**
 * irdma_sc_remove_cq_ctx - remove cq ctx tracking for ceq
 * @ceq: ceq sc structure
 * @cq: cq sc structure
 */
void irdma_sc_remove_cq_ctx(struct irdma_sc_ceq *ceq, struct irdma_sc_cq *cq)
{
	unsigned long flags;
	u32 cq_ctx_idx;

	spin_lock_irqsave(&ceq->req_cq_lock, flags);
	cq_ctx_idx = irdma_sc_find_reg_cq(ceq, cq);
	if (cq_ctx_idx == IRDMA_INVALID_CQ_IDX)
		goto exit;

	ceq->reg_cq_size--;
	if (cq_ctx_idx != ceq->reg_cq_size)
		ceq->reg_cq[cq_ctx_idx] = ceq->reg_cq[ceq->reg_cq_size];
	ceq->reg_cq[ceq->reg_cq_size] = NULL;

exit:
	spin_unlock_irqrestore(&ceq->req_cq_lock, flags);
}

/**
 * irdma_sc_cqp_get_next_recv_wqe_idx - get next wqe on cqp rq
 * and pass back index
 * @cqp: CQP HW structure
 * @scratch: private data for CQP WQE
 * @wqe_idx: WQE index of CQP RQ
 */
static __le64 *irdma_sc_cqp_get_next_recv_wqe_idx(struct irdma_sc_cqp *cqp,
						  u64 scratch, u32 *wqe_idx)
{
	__le64 *wqe = NULL;
	int ret_code;

	if (IRDMA_RING_FULL_ERR(cqp->rq_ring)) {
		ibdev_dbg(to_ibdev(cqp->dev),
			  "WQE: CQP RQ is full, head 0x%x tail 0x%x size 0x%x\n",
			  cqp->rq_ring.head, cqp->rq_ring.tail,
			  cqp->rq_ring.size);
		return NULL;
	}
	IRDMA_ATOMIC_RING_MOVE_HEAD(cqp->rq_ring, *wqe_idx, ret_code);
	if (ret_code)
		return NULL;

	if (!*wqe_idx)
		cqp->rq_polarity = !cqp->rq_polarity;
	wqe = cqp->rq_base[*wqe_idx].elem;
	cqp->rq_scratch_array[*wqe_idx] = scratch;

	return wqe;
}

static inline __le64 *irdma_sc_cqp_get_next_recv_wqe(struct irdma_sc_cqp *cqp,
						     u64 scratch)
{
	u32 wqe_idx;

	return irdma_sc_cqp_get_next_recv_wqe_idx(cqp, scratch, &wqe_idx);
}

/**
 * irdma_sc_cqp_post_rq - Post RQ entry to RCA RQ and advance RQ head
 * This is only for initial posting to CQP RQ.
 * @cqp: IWARP control queue pair pointer
 * @scratch: pointer to RQE buffers
 */
int irdma_sc_cqp_post_rq(struct irdma_sc_cqp *cqp, u64 scratch)
{
	struct irdma_cqp_rqe_bufs *rqe = (struct irdma_cqp_rqe_bufs *)scratch;
	u8 frag_valid;

	__le64 *wqe = irdma_sc_cqp_get_next_recv_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;

	/* irdma_sc_cqp_get_next_recv_wqe may alter polarity */
	frag_valid = irdma_rca_rq_polarity ? cqp->rq_polarity : 1;

	set_64bit_val(wqe, 0, 0);
	set_64bit_val(wqe, 8, 0);
	set_64bit_val(wqe, 16, 0);
	set_64bit_val(wqe, 32,
		      FIELD_PREP(IRDMAQPSQ_FRAG_TO, rqe->small_buf.pa));
	set_64bit_val(wqe, 40,
		      FIELD_PREP(IRDMAQPSQ_FRAG_LEN,
				 IRDMA_CQP_RQ_SMALL_BUF_SZ) |
		      FIELD_PREP(IRDMAQPSQ_FRAG_VALID, frag_valid));
	set_64bit_val(wqe, 48,
		      FIELD_PREP(IRDMAQPSQ_FRAG_TO, rqe->large_buf.pa));
	set_64bit_val(wqe, 56,
		      FIELD_PREP(IRDMAQPSQ_FRAG_LEN,
				 IRDMA_CQP_RQ_LARGE_BUF_SZ) |
		      FIELD_PREP(IRDMAQPSQ_FRAG_VALID, frag_valid));
	dma_wmb();
	set_64bit_val(wqe, 24,
		      FIELD_PREP(IRDMAQPSQ_VALID, cqp->rq_polarity));

	print_hex_dump_debug("CQP: CQP RQ WQE", DUMP_PREFIX_OFFSET, 16, 8,
			     wqe, IRDMA_CQP_WQE_SIZE * 8, false);

	ibdev_dbg(to_ibdev(cqp->dev),
		  "WQE: CQP RQ head 0x%x tail 0x%x size 0x%x\n",
		  cqp->rq_ring.head, cqp->rq_ring.tail, cqp->rq_ring.size);

	return 0;
}

/**
 * irdma_sc_cqp_post_rqes - Post all RQ entries to RCA CQP RQ
 * @cqp: IWARP control queue pair pointer
 */
void irdma_sc_cqp_post_rqes(struct irdma_sc_cqp *cqp)
{
	u32 rqe_idx;

	if (irdma_rca_rq_posted)
		return;

	for (rqe_idx = 0; rqe_idx < cqp->rq_size - 1; rqe_idx++)
		irdma_sc_cqp_post_rq(cqp, (u64)&cqp->rqe_array[rqe_idx]);

	irdma_rca_rq_posted = true;
}

/**
 * irdma_sc_cqp_init - Initialize buffers for a control Queue Pair
 * @cqp: IWARP control queue pair pointer
 * @info: IWARP control queue pair init info pointer
 *
 * Initializes the object and context buffers for a control Queue Pair.
 */
int irdma_sc_cqp_init(struct irdma_sc_cqp *cqp,
		      struct irdma_cqp_init_info *info)
{
	struct irdma_ooo_cqp_op *ooo_op;
	u32 num_ooo_ops;
	u8 hw_rq_size;
	u8 hw_sq_size;

	if (info->sq_size > IRDMA_CQP_SW_SQSIZE_2048 ||
	    info->sq_size < IRDMA_CQP_SW_SQSIZE_4 ||
	    ((info->sq_size & (info->sq_size - 1))))
		return -EINVAL;

	hw_sq_size = irdma_get_encoded_wqe_size(info->sq_size,
						IRDMA_QUEUE_TYPE_CQP);
	cqp->size = sizeof(*cqp);
	cqp->sq_size = info->sq_size;
	cqp->hw_sq_size = hw_sq_size;
	cqp->sq_base = info->sq;
	cqp->host_ctx = info->host_ctx;
	cqp->sq_pa = info->sq_pa;
	cqp->host_ctx_pa = info->host_ctx_pa;
	cqp->dev = info->dev;
	cqp->struct_ver = info->struct_ver;
	cqp->hw_maj_ver = info->hw_maj_ver;
	cqp->hw_min_ver = info->hw_min_ver;
	cqp->scratch_array = info->scratch_array;
	cqp->rq_scratch_array = info->rq_scratch_array;
	cqp->polarity = 0;
	cqp->en_datacenter_tcp = info->en_datacenter_tcp;
	cqp->ena_vf_count = info->ena_vf_count;
	cqp->hmc_profile = info->hmc_profile;
	cqp->ceqs_per_vf = info->ceqs_per_vf;
	cqp->disable_packed = info->disable_packed;
	cqp->rocev2_rto_policy = info->rocev2_rto_policy;
	cqp->protocol_used = info->protocol_used;
	memcpy(&cqp->dcqcn_params, &info->dcqcn_params, sizeof(cqp->dcqcn_params));
	cqp->en_rem_endpoint_trk = info->en_rem_endpoint_trk;
	cqp->timer_slots = info->timer_slots;
	if (cqp->dev->hw_attrs.uk_attrs.hw_rev >= IRDMA_GEN_3) {
		cqp->ooisc_blksize = info->ooisc_blksize;
		cqp->rrsp_blksize = info->rrsp_blksize;
		cqp->q1_blksize = info->q1_blksize;
		cqp->xmit_blksize = info->xmit_blksize;
		cqp->blksizes_valid = info->blksizes_valid;
		cqp->ts_shift = info->ts_shift;
		cqp->ts_override = info->ts_override;
		cqp->en_fine_grained_timers = info->en_fine_grained_timers;
		cqp->pe_en_vf_cnt = info->pe_en_vf_cnt;
		cqp->ooo_op_array = info->ooo_op_array;
		cqp->cqp_type = info->cqp_type;
		hw_rq_size = info->rq_size
			? irdma_get_encoded_wqe_size(info->rq_size,
						     IRDMA_QUEUE_TYPE_CQP)
			: 0;
		cqp->hw_rq_size = hw_rq_size;
		cqp->rq_base = info->rq;
		cqp->rq_pa = info->rq_pa;
		cqp->rqe_array = info->rqe_array;
		cqp->rq_size = info->rq_size;
		cqp->rq_polarity = 0;
		IRDMA_RING_INIT(cqp->rq_ring, cqp->rq_size);
		if (cqp->rq_size) {
			u32 rqe_idx;
			u8 *small_buf_va = info->rq_small_bufs.va;
			dma_addr_t small_buf_pa = info->rq_small_bufs.pa;
			u8 *large_buf_va = info->rq_large_bufs.va;
			dma_addr_t large_buf_pa = info->rq_large_bufs.pa;
			/* Initialize the RQ list and entries */
			for (rqe_idx = 0; rqe_idx < cqp->rq_size; rqe_idx++) {
				/* Build rqe tracking structure with
				 * buffer info.
				 */
				cqp->rqe_array[rqe_idx].small_buf.va =
					small_buf_va;
				cqp->rqe_array[rqe_idx].small_buf.pa =
					small_buf_pa;
				cqp->rqe_array[rqe_idx].large_buf.va =
					large_buf_va;
				cqp->rqe_array[rqe_idx].large_buf.pa =
					large_buf_pa;

				small_buf_va += IRDMA_CQP_RQ_SMALL_BUF_SZ;
				small_buf_pa += IRDMA_CQP_RQ_SMALL_BUF_SZ;
				large_buf_va += IRDMA_CQP_RQ_LARGE_BUF_SZ;
				large_buf_pa += IRDMA_CQP_RQ_LARGE_BUF_SZ;
			}

			/* Post to the RQ */
			if (irdma_rca_rq_post)
				irdma_sc_cqp_post_rqes(cqp);
		}

		/* initialize the OOO lists */
		INIT_LIST_HEAD(&cqp->ooo_avail);
		INIT_LIST_HEAD(&cqp->ooo_pnd);
		if (cqp->ooo_op_array) {
			/* Populate avail list entries */
			for (num_ooo_ops = 0, ooo_op = info->ooo_op_array;
			     num_ooo_ops < cqp->sq_size;
			     num_ooo_ops++, ooo_op++)
				list_add(&ooo_op->list_entry, &cqp->ooo_avail);
		}
	}
	info->dev->cqp = cqp;

	IRDMA_RING_INIT(cqp->sq_ring, cqp->sq_size);
	cqp->last_def_cmpl_ticket = 0;
	cqp->sw_def_cmpl_ticket = 0;
	cqp->requested_ops = 0;
	atomic64_set(&cqp->completed_ops, 0);
	/* for the cqp commands backlog. */
	INIT_LIST_HEAD(&cqp->dev->cqp_cmd_head);

	writel(0, cqp->dev->hw_regs[IRDMA_CQPTAIL]);
	if (cqp->dev->hw_attrs.uk_attrs.hw_rev <= IRDMA_GEN_2) {
		writel(0, cqp->dev->hw_regs[IRDMA_CQPDB]);
		writel(0, cqp->dev->hw_regs[IRDMA_CCQPSTATUS]);
	}

	ibdev_dbg(to_ibdev(cqp->dev),
		  "WQE: sq_size[%04d] hw_sq_size[%04d] sq_base[%p] sq_pa[%pK] cqp[%p] polarity[x%04x]\n",
		  cqp->sq_size, cqp->hw_sq_size, cqp->sq_base,
		  (u64 *)(uintptr_t)cqp->sq_pa, cqp, cqp->polarity);
	return 0;
}

/**
 * irdma_sc_cqp_create - create cqp during bringup
 * @cqp: struct for cqp hw
 * @maj_err: If error, major err number
 * @min_err: If error, minor err number
 */
int irdma_sc_cqp_create(struct irdma_sc_cqp *cqp, u16 *maj_err, u16 *min_err)
{
	u64 temp;
	u8 hw_rev;
	u32 cnt = 0, p1, p2, val = 0, err_code;
	int ret_code;

	hw_rev = cqp->dev->hw_attrs.uk_attrs.hw_rev;
	cqp->sdbuf.size = ALIGN(IRDMA_UPDATE_SD_BUFF_SIZE * cqp->sq_size,
				IRDMA_SD_BUF_ALIGNMENT);
	cqp->sdbuf.va = dma_alloc_coherent(cqp->dev->hw->device,
					   cqp->sdbuf.size, &cqp->sdbuf.pa,
					   GFP_KERNEL);
	if (!cqp->sdbuf.va)
		return -ENOMEM;

	spin_lock_init(&cqp->dev->cqp_lock);
	spin_lock_init(&cqp->ooo_list_lock);

	temp = FIELD_PREP(IRDMA_CQPHC_SQSIZE, cqp->hw_sq_size) |
	       FIELD_PREP(IRDMA_CQPHC_SVER, cqp->struct_ver) |
	       FIELD_PREP(IRDMA_CQPHC_DISABLE_PFPDUS, cqp->disable_packed) |
	       FIELD_PREP(IRDMA_CQPHC_CEQPERVF, cqp->ceqs_per_vf);
	if (hw_rev >= IRDMA_GEN_2) {
		temp |= FIELD_PREP(IRDMA_CQPHC_ROCEV2_RTO_POLICY,
				   cqp->rocev2_rto_policy) |
			FIELD_PREP(IRDMA_CQPHC_PROTOCOL_USED,
				   cqp->protocol_used);
	}
	if (hw_rev >= IRDMA_GEN_3)
		temp |= FIELD_PREP(IRDMA_CQPHC_RQSIZE, cqp->hw_rq_size) |
			FIELD_PREP(IRDMA_CQPHC_CQP_TYPE, cqp->cqp_type) |
			FIELD_PREP(IRDMA_CQPHC_EN_FINE_GRAINED_TIMERS,
				   cqp->en_fine_grained_timers);

	set_64bit_val(cqp->host_ctx, 0, temp);
	set_64bit_val(cqp->host_ctx, 8, cqp->sq_pa);

	temp = FIELD_PREP(IRDMA_CQPHC_ENABLED_VFS, cqp->ena_vf_count) |
	       FIELD_PREP(IRDMA_CQPHC_HMC_PROFILE, cqp->hmc_profile);

	if (hw_rev == IRDMA_GEN_2)
		temp |= FIELD_PREP(IRDMA_CQPHC_TMR_SLOT, cqp->timer_slots);
	if (hw_rev >= IRDMA_GEN_2)
		temp |= FIELD_PREP(IRDMA_CQPHC_EN_REM_ENDPOINT_TRK,
				   cqp->en_rem_endpoint_trk);
	if (hw_rev >= IRDMA_GEN_3)
		temp |= FIELD_PREP(IRDMA_CQPHC_OOISC_BLKSIZE, cqp->ooisc_blksize) |
			FIELD_PREP(IRDMA_CQPHC_RRSP_BLKSIZE, cqp->rrsp_blksize) |
			FIELD_PREP(IRDMA_CQPHC_Q1_BLKSIZE, cqp->q1_blksize) |
			FIELD_PREP(IRDMA_CQPHC_XMIT_BLKSIZE, cqp->xmit_blksize) |
			FIELD_PREP(IRDMA_CQPHC_BLKSIZES_VALID, cqp->blksizes_valid) |
			FIELD_PREP(IRDMA_CQPHC_TIMESTAMP_OVERRIDE, cqp->ts_override) |
			FIELD_PREP(IRDMA_CQPHC_TS_SHIFT, cqp->ts_shift);
	set_64bit_val(cqp->host_ctx, 16, temp);
	set_64bit_val(cqp->host_ctx, 24, (uintptr_t)cqp);
	temp = FIELD_PREP(IRDMA_CQPHC_HW_MAJVER, cqp->hw_maj_ver) |
	       FIELD_PREP(IRDMA_CQPHC_HW_MINVER, cqp->hw_min_ver);
	if (hw_rev >= IRDMA_GEN_2) {
		temp |= FIELD_PREP(IRDMA_CQPHC_MIN_RATE, cqp->dcqcn_params.min_rate) |
			FIELD_PREP(IRDMA_CQPHC_MIN_DEC_FACTOR, cqp->dcqcn_params.min_dec_factor);
	}
	set_64bit_val(cqp->host_ctx, 32, temp);
	set_64bit_val(cqp->host_ctx, 40, cqp->rq_pa);
	temp = 0;
	if (hw_rev >= IRDMA_GEN_2) {
		temp |= FIELD_PREP(IRDMA_CQPHC_DCQCN_T, cqp->dcqcn_params.dcqcn_t) |
			FIELD_PREP(IRDMA_CQPHC_RAI_FACTOR, cqp->dcqcn_params.rai_factor) |
			FIELD_PREP(IRDMA_CQPHC_HAI_FACTOR, cqp->dcqcn_params.hai_factor);
	}
	set_64bit_val(cqp->host_ctx, 48, temp);
	temp = 0;
	if (hw_rev >= IRDMA_GEN_2) {
		temp |= FIELD_PREP(IRDMA_CQPHC_DCQCN_B, cqp->dcqcn_params.dcqcn_b) |
			FIELD_PREP(IRDMA_CQPHC_DCQCN_F, cqp->dcqcn_params.dcqcn_f) |
			FIELD_PREP(IRDMA_CQPHC_CC_CFG_VALID, cqp->dcqcn_params.cc_cfg_valid) |
			FIELD_PREP(IRDMA_CQPHC_RREDUCE_MPERIOD, cqp->dcqcn_params.rreduce_mperiod);
	}
	set_64bit_val(cqp->host_ctx, 56, temp);
	print_hex_dump_debug("WQE: CQP_HOST_CTX WQE", DUMP_PREFIX_OFFSET, 16,
			     8, cqp->host_ctx, IRDMA_CQP_CTX_SIZE * 8, false);
	p1 = RS_32_1(cqp->host_ctx_pa, 32);
	p2 = (u32)cqp->host_ctx_pa;

	writel(p1, cqp->dev->hw_regs[IRDMA_CCQPHIGH]);
	writel(p2, cqp->dev->hw_regs[IRDMA_CCQPLOW]);

	do {
		if (cnt++ > cqp->dev->hw_attrs.max_done_count) {
			ret_code = -ETIMEDOUT;
			goto err;
		}
		udelay(cqp->dev->hw_attrs.max_sleep_count);
		val = readl(cqp->dev->hw_regs[IRDMA_CCQPSTATUS]);
	} while (!val);

	if (FLD_RS_32(cqp->dev, val, IRDMA_CCQPSTATUS_CCQP_ERR)) {
		ret_code = -EOPNOTSUPP;
		goto err;
	}

	cqp->process_cqp_sds = irdma_update_sds_noccq;
	return 0;

err:
	dma_free_coherent(cqp->dev->hw->device, cqp->sdbuf.size,
			  cqp->sdbuf.va, cqp->sdbuf.pa);
	cqp->sdbuf.va = NULL;
	err_code = readl(cqp->dev->hw_regs[IRDMA_CQPERRCODES]);
	*min_err = FIELD_GET(IRDMA_CQPERRCODES_CQP_MINOR_CODE, err_code);
	*maj_err = FIELD_GET(IRDMA_CQPERRCODES_CQP_MAJOR_CODE, err_code);
	return ret_code;
}

/**
 * irdma_sc_cqp_post_sq - post of cqp's sq
 * @cqp: struct for cqp hw
 */
void irdma_sc_cqp_post_sq(struct irdma_sc_cqp *cqp)
{
	writel(IRDMA_RING_CURRENT_HEAD(cqp->sq_ring), cqp->dev->cqp_db);

	ibdev_dbg(to_ibdev(cqp->dev),
		  "WQE: CQP SQ head 0x%x tail 0x%x size 0x%x\n",
		  cqp->sq_ring.head, cqp->sq_ring.tail, cqp->sq_ring.size);
}

/**
 * irdma_sc_cqp_get_next_send_wqe_idx - get next wqe on cqp sq
 * and pass back index
 * @cqp: CQP HW structure
 * @scratch: private data for CQP WQE
 * @wqe_idx: WQE index of CQP SQ
 */
__le64 *irdma_sc_cqp_get_next_send_wqe_idx(struct irdma_sc_cqp *cqp, u64 scratch,
					   u32 *wqe_idx)
{
	__le64 *wqe = NULL;
	int ret_code;

	if (IRDMA_RING_FULL_ERR(cqp->sq_ring)) {
		ibdev_dbg(to_ibdev(cqp->dev),
			  "WQE: CQP SQ is full, head 0x%x tail 0x%x size 0x%x\n",
			  cqp->sq_ring.head, cqp->sq_ring.tail,
			  cqp->sq_ring.size);
		return NULL;
	}
	IRDMA_ATOMIC_RING_MOVE_HEAD(cqp->sq_ring, *wqe_idx, ret_code);
	if (ret_code)
		return NULL;

	cqp->requested_ops++;
	if (!*wqe_idx)
		cqp->polarity = !cqp->polarity;
	wqe = cqp->sq_base[*wqe_idx].elem;
	cqp->scratch_array[*wqe_idx] = scratch;

	memset(&wqe[0], 0, 24);
	memset(&wqe[4], 0, 32);

	return wqe;
}

/**
 * irdma_sc_cqp_destroy - destroy cqp during close
 * @cqp: struct for cqp hw
 * @free_hwcqp: true for regular cqp destroy; false for reset path
 */
int irdma_sc_cqp_destroy(struct irdma_sc_cqp *cqp, bool free_hwcqp)
{
	u32 cnt = 0, val;
	int ret_code = 0;

	if (free_hwcqp) {
		writel(0, cqp->dev->hw_regs[IRDMA_CCQPHIGH]);
		writel(0, cqp->dev->hw_regs[IRDMA_CCQPLOW]);
		do {
			if (cnt++ > cqp->dev->hw_attrs.max_done_count) {
				ret_code = -ETIMEDOUT;
				break;
			}
			udelay(cqp->dev->hw_attrs.max_sleep_count);
			val = readl(cqp->dev->hw_regs[IRDMA_CCQPSTATUS]);
		} while (FLD_RS_32(cqp->dev, val, IRDMA_CCQPSTATUS_CCQP_DONE));
	}
	dma_free_coherent(cqp->dev->hw->device, cqp->sdbuf.size,
			  cqp->sdbuf.va, cqp->sdbuf.pa);
	cqp->sdbuf.va = NULL;
	irdma_rca_rq_posted = false;
	if (irdma_rca_ena && cqp->dev->is_pf)
		irdma_iounmap_db(cqp->dev);
	return ret_code;
}

/**
 * irdma_sc_ccq_arm - enable intr for control cq
 * @ccq: ccq sc struct
 */
void irdma_sc_ccq_arm(struct irdma_sc_cq *ccq)
{
	unsigned long flags;
	u64 temp_val;
	u16 sw_cq_sel;
	u8 arm_next_se;
	u8 arm_seq_num;

	spin_lock_irqsave(&ccq->dev->cqp_lock, flags);
	get_64bit_val(ccq->cq_uk.shadow_area, 32, &temp_val);
	sw_cq_sel = (u16)FIELD_GET(IRDMA_CQ_DBSA_SW_CQ_SELECT, temp_val);
	arm_next_se = (u8)FIELD_GET(IRDMA_CQ_DBSA_ARM_NEXT_SE, temp_val);
	arm_seq_num = (u8)FIELD_GET(IRDMA_CQ_DBSA_ARM_SEQ_NUM, temp_val);
	arm_seq_num++;
	temp_val = FIELD_PREP(IRDMA_CQ_DBSA_ARM_SEQ_NUM, arm_seq_num) |
		   FIELD_PREP(IRDMA_CQ_DBSA_SW_CQ_SELECT, sw_cq_sel) |
		   FIELD_PREP(IRDMA_CQ_DBSA_ARM_NEXT_SE, arm_next_se) |
		   FIELD_PREP(IRDMA_CQ_DBSA_ARM_NEXT, 1);
	set_64bit_val(ccq->cq_uk.shadow_area, 32, temp_val);
	spin_unlock_irqrestore(&ccq->dev->cqp_lock, flags);

	dma_wmb(); /* make sure shadow area is updated before arming */

	writel(ccq->cq_uk.cq_id, ccq->dev->cq_arm_db);
}

/**
 * irdma_sc_process_def_cmpl - process deferred or pending completion
 * @cqp: CQP sc struct
 * @info: CQP CQE info
 * @wqe_idx: CQP WQE descriptor index
 * @def_info: deferred op ticket value or out-of-order completion id
 * @def_cmpl: true for deferred completion, false for pending (RCA)
 */
static void irdma_sc_process_def_cmpl(struct irdma_sc_cqp *cqp,
				      struct irdma_ccq_cqe_info *info,
				      u32 wqe_idx, u32 def_info, bool def_cmpl)
{
	struct irdma_ooo_cqp_op *ooo_op;
	unsigned long flags;

	/* Deferred and out-of-order completions share the same list of pending
	 * completions.  Since the list can be also accessed from AE handler,
	 * it must be protected by a lock.
	 */
	spin_lock_irqsave(&cqp->ooo_list_lock, flags);

	/* For deferred completions bump up SW completion ticket value. */
	if (def_cmpl) {
		cqp->last_def_cmpl_ticket = def_info;
		cqp->sw_def_cmpl_ticket++;
	}
	ibdev_dbg(to_ibdev(cqp->dev),
		  "CQP: DEBUG_FW_OOO process %s completion def_info 0x%x sw_def_info 0x%x\n",
		  def_cmpl ? "deferred" : "pending", def_info,
		  cqp->sw_def_cmpl_ticket);

	if (!list_empty(&cqp->ooo_avail)) {
		ooo_op = (struct irdma_ooo_cqp_op *)
			 list_entry(cqp->ooo_avail.next,
				    struct irdma_ooo_cqp_op, list_entry);

		list_del(&ooo_op->list_entry);
		ooo_op->scratch = info->scratch;
		ooo_op->def_info = def_info;
		ooo_op->sw_def_info = cqp->sw_def_cmpl_ticket;
		ooo_op->deferred = def_cmpl;
		ooo_op->wqe_idx = wqe_idx;
		/* Pending completions must be chronologically ordered,
		 * so adding at the end of list.
		 */
		list_add_tail(&ooo_op->list_entry, &cqp->ooo_pnd);
	} else {
		/* something went wrong - avail list is empty */
		ibdev_dbg(to_ibdev(cqp->dev),
			  "CQP: DEBUG_FW_OOO ERROR: no space on pending list\n");
	}
	spin_unlock_irqrestore(&cqp->ooo_list_lock, flags);

	info->pending = true;
}

/**
 * irdma_sc_process_ooo_cmpl - process out-of-order (final) completion
 * @cqp: CQP sc struct
 * @info: CQP CQE info
 * @def_info: out-of-order completion id
 */
static void irdma_sc_process_ooo_cmpl(struct irdma_sc_cqp *cqp,
				      struct irdma_ccq_cqe_info *info,
				      u32 def_info)
{
	struct irdma_ooo_cqp_op *ooo_op_tmp;
	struct irdma_ooo_cqp_op *ooo_op;
	unsigned long flags;

	info->scratch = 0;

	spin_lock_irqsave(&cqp->ooo_list_lock, flags);
	list_for_each_entry_safe(ooo_op, ooo_op_tmp, &cqp->ooo_pnd,
				 list_entry) {
		if (!ooo_op->deferred && ooo_op->def_info == def_info) {
			list_del(&ooo_op->list_entry);
			info->scratch = ooo_op->scratch;
			list_add(&ooo_op->list_entry, &cqp->ooo_avail);
			break;
		}
	}
	spin_unlock_irqrestore(&cqp->ooo_list_lock, flags);

	if (!info->scratch)
		/* something went wrong - OOO completion with unknown def_info */
		ibdev_dbg(to_ibdev(cqp->dev),
		          "CQP: DEBUG_FW_OOO out-of-order completion with unknown def_info = 0x%x\n",
		          def_info);
}

/**
 * irdma_sc_ccq_get_cqe_info - get ccq's cq entry
 * @ccq: ccq sc struct
 * @info: completion q entry to return
 */
int irdma_sc_ccq_get_cqe_info(struct irdma_sc_cq *ccq,
			      struct irdma_ccq_cqe_info *info)
{
	u32 def_info;
	bool def_cmpl = false;
	bool pend_cmpl = false;
	bool ooo_final_cmpl = false;
	u64 debug_ooo_def;
	u64 qp_ctx, temp, temp1;
	__le64 *cqe;
	struct irdma_sc_cqp *cqp;
	u32 wqe_idx;
	u32 error;
	u8 polarity;
	int ret_code = 0;
	unsigned long flags;

	if (ccq->cq_uk.avoid_mem_cflct)
		cqe = IRDMA_GET_CURRENT_EXTENDED_CQ_ELEM(&ccq->cq_uk);
	else
		cqe = IRDMA_GET_CURRENT_CQ_ELEM(&ccq->cq_uk);

	get_64bit_val(cqe, 24, &temp);
	debug_ooo_def = temp;
	polarity = (u8)FIELD_GET(IRDMA_CQ_VALID, temp);
	if (polarity != ccq->cq_uk.polarity)
		return -ENOENT;

	/* Ensure CEQE contents are read after valid bit is checked */
	dma_rmb();

	get_64bit_val(cqe, 8, &qp_ctx);
	cqp = (struct irdma_sc_cqp *)(unsigned long)qp_ctx;
	info->error = (bool)FIELD_GET(IRDMA_CQ_ERROR, temp);
	info->maj_err_code = IRDMA_CQPSQ_MAJ_NO_ERROR;
	info->min_err_code = (u16)FIELD_GET(IRDMA_CQ_MINERR, temp);
	if (cqp->dev->hw_attrs.uk_attrs.hw_rev >= IRDMA_GEN_3) {
		info->sq = (bool)FIELD_GET(IRDMA_CQ_SQ, temp);

		get_64bit_val(cqe, 0, &temp1);
		info->orig_hmc_fcn_id = (u16)FIELD_GET(IRDMA_CQ_HMC_FCN_ID,
						       temp1);
		info->orig_wq_desc_idx = (u16)FIELD_GET(IRDMA_CQ_WQEIDX,
							temp1);
	}
	if (info->error) {
		info->maj_err_code = (u16)FIELD_GET(IRDMA_CQ_MAJERR, temp);
		error = readl(cqp->dev->hw_regs[IRDMA_CQPERRCODES]);
		ibdev_dbg(to_ibdev(cqp->dev),
			  "CQP: CQPERRCODES error_code[x%08X]\n", error);
	}

	wqe_idx = (u32)FIELD_GET(IRDMA_CQ_WQEIDX, temp);
	info->scratch = cqp->scratch_array[wqe_idx];

	ibdev_dbg(to_ibdev(cqp->dev),
		  "CQP: DEBUG_FW_OOO completion wqe_idx 0x%x byte_offset24 0x%llx\n",
		  wqe_idx, debug_ooo_def);

	get_64bit_val(cqe, 16, &temp1);
	info->op_ret_val = (u32)FIELD_GET(IRDMA_CCQ_OPRETVAL, temp1);
	if (cqp->dev->hw_attrs.uk_attrs.hw_rev >= IRDMA_GEN_3) {
		def_cmpl = info->maj_err_code == IRDMA_CQPSQ_MAJ_NO_ERROR &&
			   info->min_err_code == IRDMA_CQPSQ_MIN_DEF_CMPL;
		def_info = (u32)FIELD_GET(IRDMA_CCQ_DEFINFO, temp1);
		if (def_cmpl)
			ibdev_dbg(to_ibdev(cqp->dev),
				  "CQP: DEBUG_FW_OOO Deferred completion def_info 0x%x byte_offset24 0x%llx\n",
				  def_info, debug_ooo_def);

		pend_cmpl = info->maj_err_code == IRDMA_CQPSQ_MAJ_NO_ERROR &&
			    info->min_err_code == IRDMA_CQPSQ_MIN_OOO_CMPL;
		if (pend_cmpl)
			ibdev_dbg(to_ibdev(cqp->dev),
				  "CQP: DEBUG_FW_OOO Pending completion def_info 0x%x byte_offset24 0x%llx\n",
				  def_info, debug_ooo_def);

		ooo_final_cmpl = (bool)FIELD_GET(IRDMA_OOO_CMPL, temp);
		if (cqp->dev->hw_wa & IGNORE_OOO)
			ooo_final_cmpl = false;

		if (def_cmpl || pend_cmpl || ooo_final_cmpl) {

			if (ooo_final_cmpl)
				/* this is final completion for an earlier pending one */
				irdma_sc_process_ooo_cmpl(cqp, info, def_info);
			else
				irdma_sc_process_def_cmpl(cqp, info, wqe_idx,
							  def_info, def_cmpl);
		}

		if (!info->sq) {
			info->rqe_idx = wqe_idx;
			info->scratch = cqp->rq_scratch_array[wqe_idx];
		}
	}

	/* TBD: if sq=0, opcode should be extracted from info->scratch (WQE) */
	get_64bit_val(cqp->sq_base[wqe_idx].elem, 24, &temp1);
	info->op_code = (u8)FIELD_GET(IRDMA_CQPSQ_OPCODE, temp1);
	info->cqp = cqp;

	/* move the head for cq */
	IRDMA_RING_MOVE_HEAD(ccq->cq_uk.cq_ring, ret_code);
	if (!IRDMA_RING_CURRENT_HEAD(ccq->cq_uk.cq_ring))
		ccq->cq_uk.polarity ^= 1;

	/* update cq tail in cq shadow memory also */
	IRDMA_RING_MOVE_TAIL(ccq->cq_uk.cq_ring);
	set_64bit_val(ccq->cq_uk.shadow_area, 0,
		      IRDMA_RING_CURRENT_HEAD(ccq->cq_uk.cq_ring));

	dma_wmb(); /* make sure shadow area is updated before moving tail */

	spin_lock_irqsave(&cqp->dev->cqp_lock, flags);
	if (info->sq) {
		if (!ooo_final_cmpl)
			IRDMA_RING_MOVE_TAIL(cqp->sq_ring);
	} else if (!(info->error && info->maj_err_code == 0xf002 &&
		     info->min_err_code == 0x0001)) {
		/* do not move RQ tail in case of unsolicited completion */
		IRDMA_RING_MOVE_TAIL(cqp->rq_ring);
	}
	spin_unlock_irqrestore(&cqp->dev->cqp_lock, flags);

	/* Do not increment completed_ops counter on pending or deferred
	 * completions.
	 */
	if (pend_cmpl || def_cmpl)
		return ret_code;
	atomic64_inc(&cqp->completed_ops);

	return ret_code;
}

/**
 * irdma_sc_poll_for_cqp_op_done - Waits for last write to complete in CQP SQ
 * @cqp: struct for cqp hw
 * @op_code: cqp opcode for completion
 * @compl_info: completion q entry to return
 */
int irdma_sc_poll_for_cqp_op_done(struct irdma_sc_cqp *cqp, u8 op_code,
				  struct irdma_ccq_cqe_info *compl_info)
{
	struct irdma_ccq_cqe_info info = {};
	struct irdma_sc_cq *ccq;
	int ret_code = 0;
	u32 cnt = 0;

	ccq = cqp->dev->ccq;
	while (1) {
		if (cnt++ > 100 * cqp->dev->hw_attrs.max_done_count)
			return -ETIMEDOUT;

		if (irdma_sc_ccq_get_cqe_info(ccq, &info)) {
			udelay(cqp->dev->hw_attrs.max_sleep_count);
			continue;
		}
		if (info.error && info.op_code != IRDMA_CQP_OP_QUERY_STAG) {
			ret_code = -EIO;
			break;
		}
		/* make sure op code matches*/
		if (op_code == info.op_code)
			break;
		ibdev_dbg(to_ibdev(cqp->dev),
			  "WQE: opcode mismatch for my op code 0x%x, returned opcode %x\n",
			  op_code, info.op_code);
	}

	if (compl_info)
		memcpy(compl_info, &info, sizeof(*compl_info));

	return ret_code;
}

/**
 * irdma_sc_manage_hmc_pm_func_table - manage of function table
 * @cqp: struct for cqp hw
 * @scratch: u64 saved to be used during cqp completion
 * @info: info for the manage function table operation
 * @post_sq: flag for cqp db to ring
 */
static int irdma_sc_manage_hmc_pm_func_table(struct irdma_sc_cqp *cqp,
					     struct irdma_hmc_fcn_info *info,
					     u64 scratch, bool post_sq)
{
	__le64 *wqe;
	u64 hdr;

	wqe = irdma_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;

	hdr = FIELD_PREP(IRDMA_CQPSQ_MHMC_VFIDX, info->vf_id) |
	      FIELD_PREP(IRDMA_CQPSQ_OPCODE,
			 IRDMA_CQP_OP_MANAGE_HMC_PM_FUNC_TABLE) |
	      FIELD_PREP(IRDMA_CQPSQ_MHMC_FREEPMFN, info->free_fcn) |
	      FIELD_PREP(IRDMA_CQPSQ_WQEVALID, cqp->polarity);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: MANAGE_HMC_PM_FUNC_TABLE WQE",
			     DUMP_PREFIX_OFFSET, 16, 8, wqe,
			     IRDMA_CQP_WQE_SIZE * 8, false);
	if (post_sq)
		irdma_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * irdma_sc_commit_fpm_val_done - wait for cqp eqe completion
 * for fpm commit
 * @cqp: struct for cqp hw
 */
static int irdma_sc_commit_fpm_val_done(struct irdma_sc_cqp *cqp)
{
	return irdma_sc_poll_for_cqp_op_done(cqp, IRDMA_CQP_OP_COMMIT_FPM_VAL,
					     NULL);
}

/**
 * irdma_sc_commit_fpm_val - cqp wqe for commit fpm values
 * @cqp: struct for cqp hw
 * @scratch: u64 saved to be used during cqp completion
 * @hmc_fn_id: hmc function id
 * @commit_fpm_mem: Memory for fpm values
 * @post_sq: flag for cqp db to ring
 * @wait_type: poll ccq or cqp registers for cqp completion
 */
static int irdma_sc_commit_fpm_val(struct irdma_sc_cqp *cqp, u64 scratch,
				   u16 hmc_fn_id,
				   struct irdma_dma_mem *commit_fpm_mem,
				   bool post_sq, u8 wait_type)
{
	__le64 *wqe;
	u64 hdr;
	u32 tail, val, error;
	int ret_code = 0;

	wqe = irdma_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;

	set_64bit_val(wqe, 16, hmc_fn_id);
	set_64bit_val(wqe, 32, commit_fpm_mem->pa);

	hdr = FIELD_PREP(IRDMA_CQPSQ_BUFSIZE, IRDMA_COMMIT_FPM_BUF_SIZE) |
	      FIELD_PREP(IRDMA_CQPSQ_OPCODE, IRDMA_CQP_OP_COMMIT_FPM_VAL) |
	      FIELD_PREP(IRDMA_CQPSQ_WQEVALID, cqp->polarity);

	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: COMMIT_FPM_VAL WQE", DUMP_PREFIX_OFFSET,
			     16, 8, wqe, IRDMA_CQP_WQE_SIZE * 8, false);
	irdma_get_cqp_reg_info(cqp, &val, &tail, &error);

	if (post_sq) {
		irdma_sc_cqp_post_sq(cqp);
		if (wait_type == IRDMA_CQP_WAIT_POLL_REGS)
			ret_code = irdma_cqp_poll_registers(cqp, tail,
							    cqp->dev->hw_attrs.max_done_count);
		else if (wait_type == IRDMA_CQP_WAIT_POLL_CQ)
			ret_code = irdma_sc_commit_fpm_val_done(cqp);
	}

	return ret_code;
}

/**
 * irdma_sc_query_fpm_val_done - poll for cqp wqe completion for
 * query fpm
 * @cqp: struct for cqp hw
 */
static int irdma_sc_query_fpm_val_done(struct irdma_sc_cqp *cqp)
{
	return irdma_sc_poll_for_cqp_op_done(cqp, IRDMA_CQP_OP_QUERY_FPM_VAL,
					     NULL);
}

/**
 * irdma_sc_query_fpm_val - cqp wqe query fpm values
 * @cqp: struct for cqp hw
 * @scratch: u64 saved to be used during cqp completion
 * @hmc_fn_id: hmc function id
 * @query_fpm_mem: memory for return fpm values
 * @post_sq: flag for cqp db to ring
 * @wait_type: poll ccq or cqp registers for cqp completion
 */
static int irdma_sc_query_fpm_val(struct irdma_sc_cqp *cqp, u64 scratch,
				  u16 hmc_fn_id,
				  struct irdma_dma_mem *query_fpm_mem,
				  bool post_sq, u8 wait_type)
{
	__le64 *wqe;
	u64 hdr;
	u32 tail, val, error;
	int ret_code = 0;

	wqe = irdma_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;

	set_64bit_val(wqe, 16, hmc_fn_id);
	set_64bit_val(wqe, 32, query_fpm_mem->pa);

	hdr = FIELD_PREP(IRDMA_CQPSQ_OPCODE, IRDMA_CQP_OP_QUERY_FPM_VAL) |
	      FIELD_PREP(IRDMA_CQPSQ_WQEVALID, cqp->polarity);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: QUERY_FPM WQE", DUMP_PREFIX_OFFSET, 16, 8,
			     wqe, IRDMA_CQP_WQE_SIZE * 8, false);
	irdma_get_cqp_reg_info(cqp, &val, &tail, &error);

	if (post_sq) {
		irdma_sc_cqp_post_sq(cqp);
		if (wait_type == IRDMA_CQP_WAIT_POLL_REGS)
			ret_code = irdma_cqp_poll_registers(cqp, tail,
							    cqp->dev->hw_attrs.max_done_count);
		else if (wait_type == IRDMA_CQP_WAIT_POLL_CQ)
			ret_code = irdma_sc_query_fpm_val_done(cqp);
	}

	return ret_code;
}

/**
 * irdma_sc_ceq_init - initialize ceq
 * @ceq: ceq sc structure
 * @info: ceq initialization info
 */
int irdma_sc_ceq_init(struct irdma_sc_ceq *ceq,
		      struct irdma_ceq_init_info *info)
{
	u32 pble_obj_cnt;

	if (info->elem_cnt < info->dev->hw_attrs.min_hw_ceq_size ||
	    info->elem_cnt > info->dev->hw_attrs.max_hw_ceq_size)
		return -EINVAL;

	if (info->ceq_id > (info->dev->hmc_fpm_misc.max_ceqs - 1))
		return -EINVAL;
	pble_obj_cnt = info->dev->hmc_info->hmc_obj[IRDMA_HMC_IW_PBLE].cnt;

	if (info->virtual_map && info->first_pm_pbl_idx >= pble_obj_cnt)
		return -EINVAL;

	ceq->size = sizeof(*ceq);
	ceq->ceqe_base = (struct irdma_ceqe *)info->ceqe_base;
	ceq->ceq_id = info->ceq_id;
	ceq->dev = info->dev;
	ceq->elem_cnt = info->elem_cnt;
	ceq->ceq_elem_pa = info->ceqe_pa;
	ceq->virtual_map = info->virtual_map;
	ceq->itr_no_expire = info->itr_no_expire;
	ceq->reg_cq = info->reg_cq;
	ceq->reg_cq_size = 0;
	spin_lock_init(&ceq->req_cq_lock);
	ceq->pbl_chunk_size = (ceq->virtual_map ? info->pbl_chunk_size : 0);
	ceq->first_pm_pbl_idx = (ceq->virtual_map ? info->first_pm_pbl_idx : 0);
	ceq->pbl_list = (ceq->virtual_map ? info->pbl_list : NULL);
	ceq->tph_en = info->tph_en;
	ceq->tph_val = info->tph_val;
	ceq->vsi = info->vsi;
	ceq->polarity = 1;
	IRDMA_RING_INIT(ceq->ceq_ring, ceq->elem_cnt);
	ceq->dev->ceq[info->ceq_id] = ceq;

	return 0;
}

/**
 * irdma_sc_ceq_create - create ceq wqe
 * @ceq: ceq sc structure
 * @scratch: u64 saved to be used during cqp completion
 * @post_sq: flag for cqp db to ring
 */
static int irdma_sc_ceq_create(struct irdma_sc_ceq *ceq, u64 scratch,
			       bool post_sq)
{
	struct irdma_sc_cqp *cqp;
	__le64 *wqe;
	u64 hdr;

	cqp = ceq->dev->cqp;
	wqe = irdma_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;
	set_64bit_val(wqe, 16, ceq->elem_cnt);
	set_64bit_val(wqe, 32,
		      (ceq->virtual_map ? 0 : ceq->ceq_elem_pa));
	set_64bit_val(wqe, 48,
		      (ceq->virtual_map ? ceq->first_pm_pbl_idx : 0));
	set_64bit_val(wqe, 56,
		      FIELD_PREP(IRDMA_CQPSQ_TPHVAL, ceq->tph_val) |
		      FIELD_PREP(IRDMA_CQPSQ_PASID, ceq->pasid) |
		      FIELD_PREP(IRDMA_CQPSQ_VSIIDX, ceq->vsi->vsi_idx));
	hdr = FIELD_PREP(IRDMA_CQPSQ_CEQ_CEQID, ceq->ceq_id) |
	      FIELD_PREP(IRDMA_CQPSQ_CEQ_CEQID_HIGH, ceq->ceq_id >> 10) |
	      FIELD_PREP(IRDMA_CQPSQ_OPCODE, IRDMA_CQP_OP_CREATE_CEQ) |
	      FIELD_PREP(IRDMA_CQPSQ_CEQ_LPBLSIZE, ceq->pbl_chunk_size) |
	      FIELD_PREP(IRDMA_CQPSQ_CEQ_VMAP, ceq->virtual_map) |
	      FIELD_PREP(IRDMA_CQPSQ_CEQ_ITRNOEXPIRE, ceq->itr_no_expire) |
	      FIELD_PREP(IRDMA_CQPSQ_TPHEN, ceq->tph_en) |
	      FIELD_PREP(IRDMA_CQPSQ_PASID_VALID, ceq->pasid_valid) |
	      FIELD_PREP(IRDMA_CQPSQ_WQEVALID, cqp->polarity);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: CEQ_CREATE WQE", DUMP_PREFIX_OFFSET, 16, 8,
			     wqe, IRDMA_CQP_WQE_SIZE * 8, false);
	if (post_sq)
		irdma_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * irdma_sc_cceq_create_done - poll for control ceq wqe to complete
 * @ceq: ceq sc structure
 */
static int irdma_sc_cceq_create_done(struct irdma_sc_ceq *ceq)
{
	struct irdma_sc_cqp *cqp;

	cqp = ceq->dev->cqp;
	return irdma_sc_poll_for_cqp_op_done(cqp, IRDMA_CQP_OP_CREATE_CEQ,
					     NULL);
}

/**
 * irdma_sc_cceq_destroy_done - poll for destroy cceq to complete
 * @ceq: ceq sc structure
 */
int irdma_sc_cceq_destroy_done(struct irdma_sc_ceq *ceq)
{
	struct irdma_sc_cqp *cqp;

	if (ceq->reg_cq)
		irdma_sc_remove_cq_ctx(ceq, ceq->dev->ccq);
	cqp = ceq->dev->cqp;
	cqp->process_cqp_sds = irdma_update_sds_noccq;

	return irdma_sc_poll_for_cqp_op_done(cqp, IRDMA_CQP_OP_DESTROY_CEQ,
					     NULL);
}

/**
 * irdma_sc_cceq_create - create cceq
 * @ceq: ceq sc structure
 */
int irdma_sc_cceq_create(struct irdma_sc_ceq *ceq)
{
	int ret_code;
	struct irdma_sc_dev *dev = ceq->dev;

	dev->ccq->vsi = ceq->vsi;
	if (ceq->reg_cq) {
		ret_code = irdma_sc_add_cq_ctx(ceq, ceq->dev->ccq);
		if (ret_code)
			return ret_code;
	}
	ret_code = irdma_sc_ceq_create(ceq, 0, true);
	if (!ret_code)
		return irdma_sc_cceq_create_done(ceq);

	return ret_code;
}

/**
 * irdma_sc_ceq_destroy - destroy ceq
 * @ceq: ceq sc structure
 * @scratch: u64 saved to be used during cqp completion
 * @post_sq: flag for cqp db to ring
 */
int irdma_sc_ceq_destroy(struct irdma_sc_ceq *ceq, u64 scratch, bool post_sq)
{
	struct irdma_sc_cqp *cqp;
	__le64 *wqe;
	u64 hdr;

	cqp = ceq->dev->cqp;
	wqe = irdma_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;

	set_64bit_val(wqe, 16, ceq->elem_cnt);
	set_64bit_val(wqe, 48, ceq->first_pm_pbl_idx);
	set_64bit_val(wqe, 56,
		      FIELD_PREP(IRDMA_CQPSQ_PASID, ceq->pasid));
	hdr = ceq->ceq_id |
	      FIELD_PREP(IRDMA_CQPSQ_OPCODE, IRDMA_CQP_OP_DESTROY_CEQ) |
	      FIELD_PREP(IRDMA_CQPSQ_CEQ_LPBLSIZE, ceq->pbl_chunk_size) |
	      FIELD_PREP(IRDMA_CQPSQ_CEQ_VMAP, ceq->virtual_map) |
	      FIELD_PREP(IRDMA_CQPSQ_TPHEN, ceq->tph_en) |
	      FIELD_PREP(IRDMA_CQPSQ_PASID_VALID, ceq->pasid_valid) |
	      FIELD_PREP(IRDMA_CQPSQ_WQEVALID, cqp->polarity);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: CEQ_DESTROY WQE", DUMP_PREFIX_OFFSET, 16,
			     8, wqe, IRDMA_CQP_WQE_SIZE * 8, false);
	if (post_sq)
		irdma_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * irdma_sc_process_ceq - process ceq
 * @dev: sc device struct
 * @ceq: ceq sc structure
 *
 * It is expected caller serializes this function with cleanup_ceqes()
 * because these functions manipulate the same ceq
 */
void *irdma_sc_process_ceq(struct irdma_sc_dev *dev, struct irdma_sc_ceq *ceq)
{
	u64 temp;
	__le64 *ceqe;
	struct irdma_sc_cq *cq = NULL;
	struct irdma_sc_cq *temp_cq;
	u8 polarity;
	u32 cq_idx;
	unsigned long flags;

	do {
		cq_idx = 0;
		ceqe = IRDMA_GET_CURRENT_CEQ_ELEM(ceq);
		get_64bit_val(ceqe, 0, &temp);
		polarity = (u8)FIELD_GET(IRDMA_CEQE_VALID, temp);
		if (polarity != ceq->polarity)
			return NULL;

		temp_cq = (struct irdma_sc_cq *)(unsigned long)LS_64_1(temp, 1);
		if (!temp_cq) {
			cq_idx = IRDMA_INVALID_CQ_IDX;
			IRDMA_RING_MOVE_TAIL(ceq->ceq_ring);

			if (!IRDMA_RING_CURRENT_TAIL(ceq->ceq_ring))
				ceq->polarity ^= 1;
			continue;
		}

		cq = temp_cq;
		if (ceq->reg_cq) {
			spin_lock_irqsave(&ceq->req_cq_lock, flags);
			cq_idx = irdma_sc_find_reg_cq(ceq, cq);
			spin_unlock_irqrestore(&ceq->req_cq_lock, flags);
		}
		IRDMA_RING_MOVE_TAIL(ceq->ceq_ring);
		if (!IRDMA_RING_CURRENT_TAIL(ceq->ceq_ring))
			ceq->polarity ^= 1;
	} while (cq_idx == IRDMA_INVALID_CQ_IDX);

	if (cq)
		irdma_sc_cq_ack(cq);
	return cq;
}

/**
 * irdma_sc_cleanup_ceqes - clear the valid ceqes ctx matching the cq
 * @cq: cq for which the ceqes need to be cleaned up
 * @ceq: ceq ptr
 *
 * The function is called after the cq is destroyed to cleanup
 * its pending ceqe entries. It is expected caller serializes this
 * function with process_ceq() in interrupt context.
 */
void irdma_sc_cleanup_ceqes(struct irdma_sc_cq *cq, struct irdma_sc_ceq *ceq)
{
	struct irdma_sc_cq *next_cq;
	u8 ceq_polarity = ceq->polarity;
	__le64 *ceqe;
	u8 polarity;
	u64 temp;
	int next;
	u32 i;

	next = IRDMA_RING_GET_NEXT_TAIL(ceq->ceq_ring, 0);

	for (i = 1; i <= IRDMA_RING_SIZE(*ceq); i++) {
		ceqe = IRDMA_GET_CEQ_ELEM_AT_POS(ceq, next);

		get_64bit_val(ceqe, 0, &temp);
		polarity = (u8)FIELD_GET(IRDMA_CEQE_VALID, temp);
		if (polarity != ceq_polarity)
			return;

		next_cq = (struct irdma_sc_cq *)(unsigned long)LS_64_1(temp, 1);
		if (cq == next_cq)
			set_64bit_val(ceqe, 0, temp & IRDMA_CEQE_VALID);

		next = IRDMA_RING_GET_NEXT_TAIL(ceq->ceq_ring, i);
		if (!next)
			ceq_polarity ^= 1;
	}
}

/**
 * irdma_sc_aeq_init - initialize aeq
 * @aeq: aeq structure ptr
 * @info: aeq initialization info
 */
int irdma_sc_aeq_init(struct irdma_sc_aeq *aeq,
		      struct irdma_aeq_init_info *info)
{
	u32 pble_obj_cnt;

	if (info->elem_cnt < info->dev->hw_attrs.min_hw_aeq_size ||
	    info->elem_cnt > info->dev->hw_attrs.max_hw_aeq_size)
		return -EINVAL;

	pble_obj_cnt = info->dev->hmc_info->hmc_obj[IRDMA_HMC_IW_PBLE].cnt;

	if (info->virtual_map && info->first_pm_pbl_idx >= pble_obj_cnt)
		return -EINVAL;

	aeq->size = sizeof(*aeq);
	aeq->polarity = 1;
	aeq->aeqe_base = (struct irdma_sc_aeqe *)info->aeqe_base;
	aeq->dev = info->dev;
	aeq->elem_cnt = info->elem_cnt;
	aeq->aeq_elem_pa = info->aeq_elem_pa;
	IRDMA_RING_INIT(aeq->aeq_ring, aeq->elem_cnt);
	aeq->virtual_map = info->virtual_map;
	aeq->pbl_list = (aeq->virtual_map ? info->pbl_list : NULL);
	aeq->pbl_chunk_size = (aeq->virtual_map ? info->pbl_chunk_size : 0);
	aeq->first_pm_pbl_idx = (aeq->virtual_map ? info->first_pm_pbl_idx : 0);
	aeq->msix_idx = info->msix_idx;
	info->dev->aeq = aeq;

	return 0;
}

/**
 * irdma_sc_aeq_create - create aeq
 * @aeq: aeq structure ptr
 * @scratch: u64 saved to be used during cqp completion
 * @post_sq: flag for cqp db to ring
 */
static int irdma_sc_aeq_create(struct irdma_sc_aeq *aeq, u64 scratch,
			       bool post_sq)
{
	__le64 *wqe;
	struct irdma_sc_cqp *cqp;
	u64 hdr;

	cqp = aeq->dev->cqp;
	wqe = irdma_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;
	set_64bit_val(wqe, 16, aeq->elem_cnt);
	set_64bit_val(wqe, 32,
		      (aeq->virtual_map ? 0 : aeq->aeq_elem_pa));
	set_64bit_val(wqe, 48,
		      (aeq->virtual_map ? aeq->first_pm_pbl_idx : 0));
	set_64bit_val(wqe, 56,
		      FIELD_PREP(IRDMA_CQPSQ_PASID, aeq->pasid));

	hdr = FIELD_PREP(IRDMA_CQPSQ_OPCODE, IRDMA_CQP_OP_CREATE_AEQ) |
	      FIELD_PREP(IRDMA_CQPSQ_AEQ_LPBLSIZE, aeq->pbl_chunk_size) |
	      FIELD_PREP(IRDMA_CQPSQ_AEQ_VMAP, aeq->virtual_map) |
	      FIELD_PREP(IRDMA_CQPSQ_PASID_VALID, aeq->pasid_valid) |
	      FIELD_PREP(IRDMA_CQPSQ_WQEVALID, cqp->polarity);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: AEQ_CREATE WQE", DUMP_PREFIX_OFFSET, 16, 8,
			     wqe, IRDMA_CQP_WQE_SIZE * 8, false);
	if (post_sq)
		irdma_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * irdma_sc_aeq_destroy - destroy aeq during close
 * @aeq: aeq structure ptr
 * @scratch: u64 saved to be used during cqp completion
 * @post_sq: flag for cqp db to ring
 */
int irdma_sc_aeq_destroy(struct irdma_sc_aeq *aeq, u64 scratch, bool post_sq)
{
	__le64 *wqe;
	struct irdma_sc_cqp *cqp;
	struct irdma_sc_dev *dev;
	u64 hdr;

	dev = aeq->dev;
	if (dev->privileged)
		writel(0, dev->hw_regs[IRDMA_PFINT_AEQCTL]);

	cqp = dev->cqp;
	wqe = irdma_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;
	set_64bit_val(wqe, 16, aeq->elem_cnt);
	set_64bit_val(wqe, 48, aeq->first_pm_pbl_idx);
	set_64bit_val(wqe, 56,
		      FIELD_PREP(IRDMA_CQPSQ_PASID, aeq->pasid));
	hdr = FIELD_PREP(IRDMA_CQPSQ_OPCODE, IRDMA_CQP_OP_DESTROY_AEQ) |
	      FIELD_PREP(IRDMA_CQPSQ_AEQ_LPBLSIZE, aeq->pbl_chunk_size) |
	      FIELD_PREP(IRDMA_CQPSQ_AEQ_VMAP, aeq->virtual_map) |
	      FIELD_PREP(IRDMA_CQPSQ_PASID_VALID, aeq->pasid_valid) |
	      FIELD_PREP(IRDMA_CQPSQ_WQEVALID, cqp->polarity);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: AEQ_DESTROY WQE", DUMP_PREFIX_OFFSET, 16,
			     8, wqe, IRDMA_CQP_WQE_SIZE * 8, false);
	if (post_sq)
		irdma_sc_cqp_post_sq(cqp);
	return 0;
}

/**
 * irdma_sc_get_next_aeqe - get next aeq entry
 * @aeq: aeq structure ptr
 * @info: aeqe info to be returned
 */
int irdma_sc_get_next_aeqe(struct irdma_sc_aeq *aeq,
			   struct irdma_aeqe_info *info)
{
	u64 temp, compl_ctx;
	__le64 *aeqe;
	u8 ae_src;
	u8 polarity;

	aeqe = IRDMA_GET_CURRENT_AEQ_ELEM(aeq);
	get_64bit_val(aeqe, 8, &temp);
	polarity = (u8)FIELD_GET(IRDMA_AEQE_VALID, temp);

	if (aeq->polarity != polarity)
		return -ENOENT;

	/* Ensure AEQE contents are read after valid bit is checked */
	dma_rmb();

	get_64bit_val(aeqe, 0, &compl_ctx);

	print_hex_dump_debug("WQE: AEQ_ENTRY WQE", DUMP_PREFIX_OFFSET, 16, 8,
			     aeqe, 16, false);

	if (aeq->dev->hw_attrs.uk_attrs.hw_rev >= IRDMA_GEN_3) {
		ae_src = (u8)FIELD_GET(IRDMA_AEQE_AESRC_GEN_3, temp);
		info->wqe_idx = (u16)FIELD_GET(IRDMA_AEQE_WQDESCIDX_GEN_3, temp);
		info->qp_cq_id = (u32)FIELD_GET(IRDMA_AEQE_QPCQID_GEN_3, temp);
		info->ae_id = (u16)FIELD_GET(IRDMA_AEQE_AECODE_GEN_3, temp);
		info->tcp_state = (u8)FIELD_GET(IRDMA_AEQE_TCPSTATE_GEN_3, compl_ctx);
		info->iwarp_state = (u8)FIELD_GET(IRDMA_AEQE_IWSTATE_GEN_3, temp);
		info->q2_data_written = (u8)FIELD_GET(IRDMA_AEQE_Q2DATA_GEN_3, compl_ctx);
		info->aeqe_overflow = (bool)FIELD_GET(IRDMA_AEQE_OVERFLOW_GEN_3, temp);
		info->compl_ctx = FIELD_GET(IRDMA_AEQE_CMPL_CTXT, compl_ctx);
		compl_ctx = FIELD_GET(IRDMA_AEQE_CMPL_CTXT, compl_ctx) << IRDMA_AEQE_CMPL_CTXT_S;
	} else {
		ae_src = (u8)FIELD_GET(IRDMA_AEQE_AESRC, temp);
		info->wqe_idx = (u16)FIELD_GET(IRDMA_AEQE_WQDESCIDX, temp);
		info->qp_cq_id = (u32)FIELD_GET(IRDMA_AEQE_QPCQID_LOW, temp) |
			 ((u32)FIELD_GET(IRDMA_AEQE_QPCQID_HI, temp) << 18);
		info->ae_id = (u16)FIELD_GET(IRDMA_AEQE_AECODE, temp);
		info->tcp_state = (u8)FIELD_GET(IRDMA_AEQE_TCPSTATE, temp);
		info->iwarp_state = (u8)FIELD_GET(IRDMA_AEQE_IWSTATE, temp);
		info->q2_data_written = (u8)FIELD_GET(IRDMA_AEQE_Q2DATA, temp);
		info->aeqe_overflow = (bool)FIELD_GET(IRDMA_AEQE_OVERFLOW,
						      temp);
	}

	info->ae_src = ae_src;
	switch (info->ae_id) {
	case IRDMA_AE_SRQ_LIMIT:
		info->srq = true;
		/* Bits [63:6] of CMPL_CTX are treated as SRQ_ID. */
		info->compl_ctx = compl_ctx >> IRDMA_AEQE_CMPL_CTXT_S;
		ae_src = IRDMA_AE_SOURCE_RSVD;
		break;
	case IRDMA_AE_PRIV_OPERATION_DENIED:
	case IRDMA_AE_AMP_INVALIDATE_TYPE1_MW:
	case IRDMA_AE_AMP_MWBIND_ZERO_BASED_TYPE1_MW:
	case IRDMA_AE_AMP_FASTREG_INVALID_PBL_HPS_CFG:
	case IRDMA_AE_AMP_FASTREG_PBLE_MISMATCH:
	case IRDMA_AE_UDA_XMIT_DGRAM_TOO_LONG:
	case IRDMA_AE_UDA_XMIT_BAD_PD:
	case IRDMA_AE_UDA_XMIT_DGRAM_TOO_SHORT:
	case IRDMA_AE_BAD_CLOSE:
	case IRDMA_AE_RDMA_READ_WHILE_ORD_ZERO:
	case IRDMA_AE_STAG_ZERO_INVALID:
	case IRDMA_AE_IB_RREQ_AND_Q1_FULL:
	case IRDMA_AE_IB_INVALID_REQUEST:
	case IRDMA_AE_WQE_UNEXPECTED_OPCODE:
	case IRDMA_AE_IB_REMOTE_ACCESS_ERROR:
	case IRDMA_AE_IB_REMOTE_OP_ERROR:
	case IRDMA_AE_DDP_UBE_INVALID_DDP_VERSION:
	case IRDMA_AE_DDP_UBE_INVALID_MO:
	case IRDMA_AE_DDP_UBE_INVALID_QN:
	case IRDMA_AE_DDP_NO_L_BIT:
	case IRDMA_AE_RDMAP_ROE_INVALID_RDMAP_VERSION:
	case IRDMA_AE_RDMAP_ROE_UNEXPECTED_OPCODE:
	case IRDMA_AE_ROE_INVALID_RDMA_READ_REQUEST:
	case IRDMA_AE_ROE_INVALID_RDMA_WRITE_OR_READ_RESP:
	case IRDMA_AE_ROCE_RSP_LENGTH_ERROR:
	case IRDMA_AE_ROCE_REQ_LENGTH_ERROR:
	case IRDMA_AE_INVALID_ARP_ENTRY:
	case IRDMA_AE_INVALID_TCP_OPTION_RCVD:
	case IRDMA_AE_STALE_ARP_ENTRY:
	case IRDMA_AE_INVALID_AH_ENTRY:
	case IRDMA_AE_LLP_RECEIVED_MPA_CRC_ERROR:
	case IRDMA_AE_LLP_SEGMENT_TOO_SMALL:
	case IRDMA_AE_LLP_TOO_MANY_RETRIES:
	case IRDMA_AE_LCE_QP_CATASTROPHIC:
	case IRDMA_AE_INVALID_RSN_GAP_IN_RSN:
	case IRDMA_AE_REMOTE_QP_CATASTROPHIC:
	case IRDMA_AE_LOCAL_QP_CATASTROPHIC:
	case IRDMA_AE_RCE_QP_CATASTROPHIC:
	case IRDMA_AE_LLP_DOUBT_REACHABILITY:
	case IRDMA_AE_LLP_CONNECTION_ESTABLISHED:
	case IRDMA_AE_LLP_TOO_MANY_RNRS:
	case IRDMA_AE_RESET_SENT:
	case IRDMA_AE_TERMINATE_SENT:
	case IRDMA_AE_RESET_NOT_SENT:
	case IRDMA_AE_QP_SUSPEND_COMPLETE:
	case IRDMA_AE_UDA_L4LEN_INVALID:
		info->qp = true;
		info->compl_ctx = compl_ctx;
		break;
	case IRDMA_AE_LCE_CQ_CATASTROPHIC:
		info->cq = true;
		info->compl_ctx = LS_64_1(compl_ctx, 1);
		ae_src = IRDMA_AE_SOURCE_RSVD;
		break;
	case IRDMA_AE_CQP_DEFERRED_COMPLETE:
		info->def_info = info->wqe_idx;
		ae_src = IRDMA_AE_SOURCE_RSVD;
		break;
	case IRDMA_AE_ROCE_EMPTY_MCG:
	case IRDMA_AE_ROCE_BAD_MC_IP_ADDR:
	case IRDMA_AE_ROCE_BAD_MC_QPID:
	case IRDMA_AE_MCG_QP_PROTOCOL_MISMATCH:
		fallthrough;
	case IRDMA_AE_LLP_CONNECTION_RESET:
	case IRDMA_AE_LLP_SYN_RECEIVED:
	case IRDMA_AE_LLP_FIN_RECEIVED:
	case IRDMA_AE_LLP_CLOSE_COMPLETE:
	case IRDMA_AE_LLP_TERMINATE_RECEIVED:
	case IRDMA_AE_RDMAP_ROE_BAD_LLP_CLOSE:
		ae_src = IRDMA_AE_SOURCE_RSVD;
		info->qp = true;
		info->compl_ctx = compl_ctx;
		break;
	case IRDMA_AE_RESOURCE_EXHAUSTION:
		/* ae_src contains the exhausted resource with a unique decoding.
		 * Set RSVD here to prevent matching with a CQ or QP.
		 */
		ae_src = IRDMA_AE_SOURCE_RSVD;
		break;
	default:
		break;
	}

	switch (ae_src) {
	case IRDMA_AE_SOURCE_RQ:
	case IRDMA_AE_SOURCE_RQ_0011:
		info->qp = true;
		info->rq = true;
		info->compl_ctx = compl_ctx;
		info->err_rq_idx_valid = true;
		break;
	case IRDMA_AE_SOURCE_CQ:
	case IRDMA_AE_SOURCE_CQ_0110:
	case IRDMA_AE_SOURCE_CQ_1010:
	case IRDMA_AE_SOURCE_CQ_1110:
		info->cq = true;
		info->compl_ctx = LS_64_1(compl_ctx, 1);
		break;
	case IRDMA_AE_SOURCE_SQ:
	case IRDMA_AE_SOURCE_SQ_0111:
		info->qp = true;
		info->sq = true;
		info->compl_ctx = compl_ctx;
		break;
	case IRDMA_AE_SOURCE_IN_WR:
		info->qp = true;
		if (aeq->dev->hw_attrs.uk_attrs.hw_rev >= IRDMA_GEN_3)
			info->err_rq_idx_valid = true;
		info->compl_ctx = compl_ctx;
		info->in_rdrsp_wr = true;
		break;
	case IRDMA_AE_SOURCE_IN_RR:
		info->qp = true;
		if (aeq->dev->hw_attrs.uk_attrs.hw_rev >= IRDMA_GEN_3) {
			info->sq = true;
			info->err_rq_idx_valid = true;
		}
		info->compl_ctx = compl_ctx;
		info->in_rdrsp_wr = true;
		break;
	case IRDMA_AE_SOURCE_OUT_RR:
	case IRDMA_AE_SOURCE_OUT_RR_1111:
		info->qp = true;
		info->compl_ctx = compl_ctx;
		info->out_rdrsp = true;
		break;
	case IRDMA_AE_SOURCE_RSVD:
	default:
		break;
	}

	IRDMA_RING_MOVE_TAIL(aeq->aeq_ring);
	if (!IRDMA_RING_CURRENT_TAIL(aeq->aeq_ring))
		aeq->polarity ^= 1;

	return 0;
}

/**
 * irdma_sc_repost_aeq_entries - repost completed aeq entries
 * @dev: sc device struct
 * @count: allocate count
 */
void irdma_sc_repost_aeq_entries(struct irdma_sc_dev *dev, u32 count)
{
	writel(count, dev->aeq_alloc_db);

}

/**
 * irdma_sc_ccq_init - initialize control cq
 * @cq: sc's cq ctruct
 * @info: info for control cq initialization
 */
int irdma_sc_ccq_init(struct irdma_sc_cq *cq, struct irdma_ccq_init_info *info)
{
	u32 pble_obj_cnt;

	if (info->num_elem < info->dev->hw_attrs.uk_attrs.min_hw_cq_size ||
	    info->num_elem > info->dev->hw_attrs.uk_attrs.max_hw_cq_size)
		return -EINVAL;

	if (info->ceq_id > (info->dev->hmc_fpm_misc.max_ceqs - 1))
		return -EINVAL;

	pble_obj_cnt = info->dev->hmc_info->hmc_obj[IRDMA_HMC_IW_PBLE].cnt;

	if (info->virtual_map && info->first_pm_pbl_idx >= pble_obj_cnt)
		return -EINVAL;

	cq->cq_pa = info->cq_pa;
	cq->cq_uk.cq_base = info->cq_base;
	cq->shadow_area_pa = info->shadow_area_pa;
	cq->cq_uk.shadow_area = info->shadow_area;
	cq->shadow_read_threshold = info->shadow_read_threshold;
	cq->dev = info->dev;
	cq->ceq_id = info->ceq_id;
	cq->cq_uk.cq_size = info->num_elem;
	cq->cq_type = IRDMA_CQ_TYPE_CQP;
	cq->ceqe_mask = info->ceqe_mask;
	IRDMA_RING_INIT(cq->cq_uk.cq_ring, info->num_elem);
	cq->cq_uk.cq_id = 0; /* control cq is id 0 always */
	cq->ceq_id_valid = info->ceq_id_valid;
	cq->tph_en = info->tph_en;
	cq->tph_val = info->tph_val;
	cq->cq_uk.avoid_mem_cflct = info->avoid_mem_cflct;
	cq->pbl_list = info->pbl_list;
	cq->virtual_map = info->virtual_map;
	cq->pbl_chunk_size = info->pbl_chunk_size;
	cq->first_pm_pbl_idx = info->first_pm_pbl_idx;
	cq->cq_uk.polarity = true;
	cq->vsi = info->vsi;
	cq->cq_uk.cq_ack_db = cq->dev->cq_ack_db;

	/* Only applicable to CQs other than CCQ so initialize to zero */
	cq->cq_uk.cqe_alloc_db = NULL;

	info->dev->ccq = cq;
	return 0;
}

/**
 * irdma_sc_ccq_create_done - poll cqp for ccq create
 * @ccq: ccq sc struct
 */
static inline int irdma_sc_ccq_create_done(struct irdma_sc_cq *ccq)
{
	struct irdma_sc_cqp *cqp;

	cqp = ccq->dev->cqp;

	return irdma_sc_poll_for_cqp_op_done(cqp, IRDMA_CQP_OP_CREATE_CQ, NULL);
}

/**
 * irdma_sc_ccq_create - create control cq
 * @ccq: ccq sc struct
 * @scratch: u64 saved to be used during cqp completion
 * @check_overflow: overlow flag for ccq
 * @post_sq: flag for cqp db to ring
 */
int irdma_sc_ccq_create(struct irdma_sc_cq *ccq, u64 scratch,
			bool check_overflow, bool post_sq)
{
	int ret_code;

	ret_code = irdma_sc_cq_create(ccq, scratch, check_overflow, post_sq);
	if (ret_code)
		return ret_code;

	if (post_sq) {
		ret_code = irdma_sc_ccq_create_done(ccq);
		if (ret_code)
			return ret_code;
	}
	ccq->dev->cqp->process_cqp_sds = irdma_cqp_sds_cmd;

	return 0;
}

/**
 * irdma_sc_ccq_destroy - destroy ccq during close
 * @ccq: ccq sc struct
 * @scratch: u64 saved to be used during cqp completion
 * @post_sq: flag for cqp db to ring
 */
int irdma_sc_ccq_destroy(struct irdma_sc_cq *ccq, u64 scratch, bool post_sq)
{
	struct irdma_sc_cqp *cqp;
	__le64 *wqe;
	u64 hdr;
	int ret_code = 0;
	u32 tail, val, error;
	struct irdma_sc_dev *dev;

	cqp = ccq->dev->cqp;
	dev = ccq->dev;
	wqe = irdma_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;

	set_64bit_val(wqe, 0, ccq->cq_uk.cq_size);
	set_64bit_val(wqe, 8, RS_64_1(ccq, 1));
	set_64bit_val(wqe, 40, ccq->shadow_area_pa);

	if (dev->hw_wa & NO_CEQMASK)
		ccq->ceqe_mask = 0;
	hdr = ccq->cq_uk.cq_id |
	      FLD_LS_64(ccq->dev, (ccq->ceq_id_valid ? ccq->ceq_id : 0),
			IRDMA_CQPSQ_CQ_CEQID) |
	      FIELD_PREP(IRDMA_CQPSQ_OPCODE, IRDMA_CQP_OP_DESTROY_CQ) |
	      FIELD_PREP(IRDMA_CQPSQ_CQ_ENCEQEMASK, ccq->ceqe_mask) |
	      FIELD_PREP(IRDMA_CQPSQ_CQ_CEQIDVALID, ccq->ceq_id_valid) |
	      FIELD_PREP(IRDMA_CQPSQ_TPHEN, ccq->tph_en) |
	      FIELD_PREP(IRDMA_CQPSQ_CQ_AVOIDMEMCNFLCT, ccq->cq_uk.avoid_mem_cflct) |
	      FIELD_PREP(IRDMA_CQPSQ_WQEVALID, cqp->polarity);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: CCQ_DESTROY WQE", DUMP_PREFIX_OFFSET, 16,
			     8, wqe, IRDMA_CQP_WQE_SIZE * 8, false);
	irdma_get_cqp_reg_info(cqp, &val, &tail, &error);

	if (post_sq) {
		irdma_sc_cqp_post_sq(cqp);
		ret_code = irdma_cqp_poll_registers(cqp, tail,
						    dev->hw_attrs.max_done_count);
	}

	cqp->process_cqp_sds = irdma_update_sds_noccq;
	dev->ccq = NULL;

	return ret_code;
}

/**
 * irdma_sc_init_iw_hmc() - queries fpm values using cqp and populates hmc_info
 * @dev : ptr to irdma_dev struct
 * @hmc_fn_id: hmc function id
 */
int irdma_sc_init_iw_hmc(struct irdma_sc_dev *dev, u16 hmc_fn_id)
{
	struct irdma_hmc_info *hmc_info;
	struct irdma_hmc_fpm_misc *hmc_fpm_misc;
	struct irdma_dma_mem query_fpm_mem;
	struct irdma_virt_mem virt_mem;
	struct irdma_vchnl_dev *vc_dev = NULL;
	bool poll_registers = true;
	u16 iw_vf_idx;
	u32 mem_size;
	int ret_code = 0;
	u8 wait_type;

	if ((dev->privileged && hmc_fn_id > dev->hw_attrs.max_hw_vf_fpm_id) ||
	    (dev->hmc_fn_id != hmc_fn_id &&
	     hmc_fn_id < dev->hw_attrs.first_hw_vf_fpm_id))
		return -EINVAL;

	ibdev_dbg(to_ibdev(dev), "HMC: hmc_fn_id %u, dev->hmc_fn_id %u\n",
		  hmc_fn_id, dev->hmc_fn_id);
	if (hmc_fn_id == dev->hmc_fn_id) {
		hmc_info = dev->hmc_info;
		hmc_fpm_misc = &dev->hmc_fpm_misc;
		query_fpm_mem.pa = dev->fpm_query_buf_pa;
		query_fpm_mem.va = dev->fpm_query_buf;
	} else {
		vc_dev = irdma_vchnl_dev_from_fpm(dev, hmc_fn_id);
		if (!vc_dev)
			return -EINVAL;

		hmc_info = &vc_dev->hmc_info;
		hmc_fpm_misc = &vc_dev->hmc_fpm_misc;
		iw_vf_idx = vc_dev->iw_vf_idx;
		ibdev_dbg(to_ibdev(dev),
			  "HMC: vc_dev %p, hmc_info %p, hmc_obj %p\n", vc_dev,
			  hmc_info, hmc_info->hmc_obj);
		if (!vc_dev->fpm_query_buf) {
			if (!dev->vf_fpm_query_buf[iw_vf_idx].va) {
				ret_code = irdma_alloc_query_fpm_buf(
					dev, &dev->vf_fpm_query_buf[iw_vf_idx]);
				if (ret_code)
					return ret_code;
			}
			vc_dev->fpm_query_buf =
				dev->vf_fpm_query_buf[iw_vf_idx].va;
			vc_dev->fpm_query_buf_pa =
				dev->vf_fpm_query_buf[iw_vf_idx].pa;
		}
		query_fpm_mem.pa = vc_dev->fpm_query_buf_pa;
		query_fpm_mem.va = vc_dev->fpm_query_buf;
		poll_registers = false;
	}
	hmc_info->hmc_fn_id = hmc_fn_id;

	if (hmc_fn_id != dev->hmc_fn_id) {
		ret_code = irdma_cqp_query_fpm_val_cmd(dev, &query_fpm_mem,
						       hmc_fn_id);
	} else {
		wait_type = poll_registers ? (u8)IRDMA_CQP_WAIT_POLL_REGS :
					     (u8)IRDMA_CQP_WAIT_POLL_CQ;

		ret_code = irdma_sc_query_fpm_val(dev->cqp, 0,
						  hmc_info->hmc_fn_id,
						  &query_fpm_mem, true,
						  wait_type);
	}
	if (ret_code)
		return ret_code;

	/* parse the fpm_query_buf and fill hmc obj info */
	ret_code = irdma_sc_parse_fpm_query_buf(dev, query_fpm_mem.va, hmc_info,
						hmc_fpm_misc);

	print_hex_dump_debug("HMC: QUERY FPM BUFFER", DUMP_PREFIX_OFFSET, 16,
			     8, query_fpm_mem.va, IRDMA_QUERY_FPM_BUF_SIZE,
			     false);

	if (ret_code)
		return ret_code;

	if (hmc_fn_id != dev->hmc_fn_id) {
		irdma_cqp_commit_fpm_val_cmd(dev, &query_fpm_mem, hmc_fn_id);
		/* parse the fpm_commit_buf and fill hmc obj info */
		irdma_sc_parse_fpm_commit_buf(dev, query_fpm_mem.va,
					      hmc_info->hmc_obj,
					      &hmc_info->sd_table.sd_cnt);

		print_hex_dump_debug("HMC: COMMIT FPM BUFFER",
				     DUMP_PREFIX_OFFSET, 16, 8,
				     query_fpm_mem.va,
				     IRDMA_COMMIT_FPM_BUF_SIZE, false);
		mem_size =
			sizeof(struct irdma_hmc_sd_entry) *
			(hmc_info->sd_table.sd_cnt + hmc_info->first_sd_index);
		virt_mem.size = mem_size;
		virt_mem.va = kzalloc(virt_mem.size, GFP_KERNEL);
		if (!virt_mem.va)
			return -ENOMEM;

		hmc_info->sd_table.sd_entry = virt_mem.va;
	}
	return ret_code;
}

/**
 * irdma_set_loc_mem() - set a local memory bit field
 * @buf: ptr to a buffer where local memory gets enabled
 */
static void irdma_set_loc_mem(__le64 *buf)
{
	u64 loc_mem_en = BIT_ULL(ENABLE_LOC_MEM);
	u32 offset;
	u64 temp;

	for (offset = 0; offset < IRDMA_COMMIT_FPM_BUF_SIZE;
	     offset += sizeof(__le64)) {
		if (offset == IRDMA_PBLE_COMMIT_OFFSET)
			continue;
		get_64bit_val(buf, offset, &temp);
		/*
		 * On MMG EMU due to a fw bug, we need to set local memory
		 * for QP in config FPM (although it is with 0 count)
		 * TODO - Remove this WA once FW is fixed
		 */
		set_64bit_val(buf, offset, temp | loc_mem_en);
	}
}

/**
 * irdma_sc_cfg_iw_fpm() - commits hmc obj cnt values using cqp
 * command and populates fpm base address in hmc_info
 * @dev : ptr to irdma_dev struct
 * @hmc_fn_id: hmc function id
 */
static int irdma_sc_cfg_iw_fpm(struct irdma_sc_dev *dev, u16 hmc_fn_id)
{
	struct irdma_hmc_obj_info *obj_info;
	__le64 *buf;
	struct irdma_hmc_info *hmc_info;
	struct irdma_dma_mem commit_fpm_mem;
	bool poll_registers = true;
	int ret_code = 0;
	u8 wait_type;

	if ((dev->privileged && hmc_fn_id > dev->hw_attrs.max_hw_vf_fpm_id) ||
	    (dev->hmc_fn_id != hmc_fn_id &&
	     hmc_fn_id < dev->hw_attrs.first_hw_vf_fpm_id))
		return -EINVAL;

	if (hmc_fn_id == dev->hmc_fn_id) {
		hmc_info = dev->hmc_info;
	} else {
		hmc_info = irdma_vf_hmcinfo_from_fpm(dev, hmc_fn_id);
		poll_registers = false;
	}
	if (!hmc_info)
		return -EFAULT;
	obj_info = hmc_info->hmc_obj;
	buf = dev->fpm_commit_buf;

	set_64bit_val(buf, 0, (u64)obj_info[IRDMA_HMC_IW_QP].cnt);
	set_64bit_val(buf, 8, (u64)obj_info[IRDMA_HMC_IW_CQ].cnt);
	set_64bit_val(buf, 16, (u64)obj_info[IRDMA_HMC_IW_SRQ].cnt);
	set_64bit_val(buf, 24, (u64)obj_info[IRDMA_HMC_IW_HTE].cnt);
	set_64bit_val(buf, 32, (u64)obj_info[IRDMA_HMC_IW_ARP].cnt);
	set_64bit_val(buf, 40, (u64)0); /* RSVD */
	set_64bit_val(buf, 48, (u64)obj_info[IRDMA_HMC_IW_MR].cnt);
	set_64bit_val(buf, 56, (u64)obj_info[IRDMA_HMC_IW_XF].cnt);
	set_64bit_val(buf, 64, (u64)obj_info[IRDMA_HMC_IW_XFFL].cnt);
	set_64bit_val(buf, 72, (u64)obj_info[IRDMA_HMC_IW_Q1].cnt);
	set_64bit_val(buf, 80, (u64)obj_info[IRDMA_HMC_IW_Q1FL].cnt);
	set_64bit_val(buf, 88,
		      (u64)obj_info[IRDMA_HMC_IW_TIMER].cnt);
	set_64bit_val(buf, 96,
		      (u64)obj_info[IRDMA_HMC_IW_FSIMC].cnt);
	set_64bit_val(buf, 104,
		      (u64)obj_info[IRDMA_HMC_IW_FSIAV].cnt);
	set_64bit_val(buf, 112,
		      (u64)obj_info[IRDMA_HMC_IW_PBLE].cnt);
	set_64bit_val(buf, 120, (u64)0); /* RSVD */
	set_64bit_val(buf, 128, (u64)obj_info[IRDMA_HMC_IW_RRF].cnt);
	set_64bit_val(buf, 136,
		      (u64)obj_info[IRDMA_HMC_IW_RRFFL].cnt);
	set_64bit_val(buf, 144, (u64)obj_info[IRDMA_HMC_IW_HDR].cnt);
	set_64bit_val(buf, 152, (u64)obj_info[IRDMA_HMC_IW_MD].cnt);
	set_64bit_val(buf, 160,
		      (u64)obj_info[IRDMA_HMC_IW_OOISC].cnt);
	set_64bit_val(buf, 168,
		      (u64)obj_info[IRDMA_HMC_IW_OOISCFFL].cnt);
	if (dev->hw_attrs.uk_attrs.hw_rev >= IRDMA_GEN_3 &&
	    dev->hmc_fpm_misc.loc_mem_pages)
		irdma_set_loc_mem(buf);
	commit_fpm_mem.pa = dev->fpm_commit_buf_pa;
	commit_fpm_mem.va = dev->fpm_commit_buf;

	wait_type = poll_registers ? (u8)IRDMA_CQP_WAIT_POLL_REGS :
				     (u8)IRDMA_CQP_WAIT_POLL_CQ;
	print_hex_dump_debug("HMC: COMMIT FPM BUFFER", DUMP_PREFIX_OFFSET, 16,
			     8, commit_fpm_mem.va, IRDMA_COMMIT_FPM_BUF_SIZE,
			     false);
	ret_code = irdma_sc_commit_fpm_val(dev->cqp, 0, hmc_info->hmc_fn_id,
					   &commit_fpm_mem, true, wait_type);
	if (!ret_code)
		irdma_sc_parse_fpm_commit_buf(dev, dev->fpm_commit_buf,
					      hmc_info->hmc_obj,
					      &hmc_info->sd_table.sd_cnt);
	print_hex_dump_debug("HMC: COMMIT FPM BUFFER", DUMP_PREFIX_OFFSET, 16,
			     8, commit_fpm_mem.va, IRDMA_COMMIT_FPM_BUF_SIZE,
			     false);
	{
		int i;

		for (i = 0; i < 20; i++)
			if (hmc_info->hmc_obj[i].cnt)
				pr_err("BEGIN %s\t\tcnt = %u\n",
				       hmc_obj_name(i),
				       hmc_info->hmc_obj[i].cnt);
	}

	return ret_code;
}

/**
 * cqp_sds_wqe_fill - fill cqp wqe doe sd
 * @cqp: struct for cqp hw
 * @info: sd info for wqe
 * @scratch: u64 saved to be used during cqp completion
 */
static int cqp_sds_wqe_fill(struct irdma_sc_cqp *cqp,
			    struct irdma_update_sds_info *info, u64 scratch)
{
	u64 data;
	u64 hdr;
	__le64 *wqe;
	int mem_entries, wqe_entries;
	struct irdma_dma_mem *sdbuf = &cqp->sdbuf;
	u64 offset = 0;
	u32 wqe_idx;

	wqe = irdma_sc_cqp_get_next_send_wqe_idx(cqp, scratch, &wqe_idx);
	if (!wqe)
		return -ENOMEM;

	wqe_entries = (info->cnt > 3) ? 3 : info->cnt;
	mem_entries = info->cnt - wqe_entries;

	if (mem_entries) {
		offset = wqe_idx * IRDMA_UPDATE_SD_BUFF_SIZE;
		memcpy(((char *)sdbuf->va + offset), &info->entry[3], mem_entries << 4);

		data = (u64)sdbuf->pa + offset;
	} else {
		data = 0;
	}
	data |= FLD_LS_64(cqp->dev, info->hmc_fn_id, IRDMA_CQPSQ_UPESD_HMCFNID);
	set_64bit_val(wqe, 16, data);

	switch (wqe_entries) {
	case 3:
		set_64bit_val(wqe, 48,
			      (FIELD_PREP(IRDMA_CQPSQ_UPESD_SDCMD, info->entry[2].cmd) |
			       FIELD_PREP(IRDMA_CQPSQ_UPESD_ENTRY_VALID, 1)));

		set_64bit_val(wqe, 56, info->entry[2].data);
		fallthrough;
	case 2:
		set_64bit_val(wqe, 32,
			      (FIELD_PREP(IRDMA_CQPSQ_UPESD_SDCMD, info->entry[1].cmd) |
			       FIELD_PREP(IRDMA_CQPSQ_UPESD_ENTRY_VALID, 1)));

		set_64bit_val(wqe, 40, info->entry[1].data);
		fallthrough;
	case 1:
		set_64bit_val(wqe, 0,
			      FIELD_PREP(IRDMA_CQPSQ_UPESD_SDCMD, info->entry[0].cmd));

		set_64bit_val(wqe, 8, info->entry[0].data);
		break;
	default:
		break;
	}

	hdr = FIELD_PREP(IRDMA_CQPSQ_OPCODE, IRDMA_CQP_OP_UPDATE_PE_SDS) |
	      FIELD_PREP(IRDMA_CQPSQ_WQEVALID, cqp->polarity) |
	      FIELD_PREP(IRDMA_CQPSQ_UPESD_ENTRY_COUNT, mem_entries);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	if (mem_entries)
		print_hex_dump_debug("WQE: UPDATE_PE_SDS WQE Buffer",
				     DUMP_PREFIX_OFFSET, 16, 8,
				     (char *)sdbuf->va + offset,
				     mem_entries << 4, false);

	print_hex_dump_debug("WQE: UPDATE_PE_SDS WQE", DUMP_PREFIX_OFFSET, 16,
			     8, wqe, IRDMA_CQP_WQE_SIZE * 8, false);

	return 0;
}

/**
 * irdma_update_pe_sds - cqp wqe for sd
 * @dev: ptr to irdma_dev struct
 * @info: sd info for sd's
 * @scratch: u64 saved to be used during cqp completion
 */
static int irdma_update_pe_sds(struct irdma_sc_dev *dev,
			       struct irdma_update_sds_info *info, u64 scratch)
{
	struct irdma_sc_cqp *cqp = dev->cqp;
	int ret_code;

	ret_code = cqp_sds_wqe_fill(cqp, info, scratch);
	if (!ret_code)
		irdma_sc_cqp_post_sq(cqp);

	return ret_code;
}

/**
 * irdma_update_sds_noccq - update sd before ccq created
 * @dev: sc device struct
 * @info: sd info for sd's
 */
int irdma_update_sds_noccq(struct irdma_sc_dev *dev,
			   struct irdma_update_sds_info *info)
{
	u32 error, val, tail;
	struct irdma_sc_cqp *cqp = dev->cqp;
	int ret_code;

	ret_code = cqp_sds_wqe_fill(cqp, info, 0);
	if (ret_code)
		return ret_code;

	irdma_get_cqp_reg_info(cqp, &val, &tail, &error);

	irdma_sc_cqp_post_sq(cqp);
	return irdma_cqp_poll_registers(cqp, tail,
					cqp->dev->hw_attrs.max_done_count);
}

/**
 * irdma_sc_static_hmc_pages_allocated - cqp wqe to allocate hmc pages
 * @cqp: struct for cqp hw
 * @scratch: u64 saved to be used during cqp completion
 * @hmc_fn_id: hmc function id
 * @post_sq: flag for cqp db to ring
 * @poll_registers: flag to poll register for cqp completion
 */
int irdma_sc_static_hmc_pages_allocated(struct irdma_sc_cqp *cqp, u64 scratch,
					u16 hmc_fn_id, bool post_sq,
					bool poll_registers)
{
	u64 hdr;
	__le64 *wqe;
	u32 tail, val, error;

	wqe = irdma_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;

	set_64bit_val(wqe, 16,
		      FIELD_PREP(IRDMA_SHMC_PAGE_ALLOCATED_HMC_FN_ID, hmc_fn_id));

	hdr = FIELD_PREP(IRDMA_CQPSQ_OPCODE,
			 IRDMA_CQP_OP_SHMC_PAGES_ALLOCATED) |
	      FIELD_PREP(IRDMA_CQPSQ_WQEVALID, cqp->polarity);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: SHMC_PAGES_ALLOCATED WQE",
			     DUMP_PREFIX_OFFSET, 16, 8, wqe,
			     IRDMA_CQP_WQE_SIZE * 8, false);
	irdma_get_cqp_reg_info(cqp, &val, &tail, &error);

	if (post_sq) {
		irdma_sc_cqp_post_sq(cqp);
		if (poll_registers)
			/* check for cqp sq tail update */
			return irdma_cqp_poll_registers(cqp, tail,
							cqp->dev->hw_attrs.max_done_count);
		else
			return irdma_sc_poll_for_cqp_op_done(cqp,
							     IRDMA_CQP_OP_SHMC_PAGES_ALLOCATED,
							     NULL);
	}

	return 0;
}

/**
 * irdma_cqp_ring_full - check if cqp ring is full
 * @cqp: struct for cqp hw
 */
static bool irdma_cqp_ring_full(struct irdma_sc_cqp *cqp)
{
	return IRDMA_RING_FULL_ERR(cqp->sq_ring);
}

/**
 * irdma_est_sd - returns approximate number of SDs for HMC
 * @dev: sc device struct
 * @hmc_info: hmc structure, size and count for HMC objects
 */
static u32 irdma_est_sd(struct irdma_sc_dev *dev,
			struct irdma_hmc_info *hmc_info)
{
	struct irdma_hmc_obj_info *pble_info;
	u64 size = 0;
	u64 sd;
	int i;

	for (i = IRDMA_HMC_IW_QP; i < IRDMA_HMC_IW_MAX; i++) {
		if (i != IRDMA_HMC_IW_PBLE)
			size += round_up(hmc_info->hmc_obj[i].cnt *
					 hmc_info->hmc_obj[i].size, 512);
	}

	pble_info = &hmc_info->hmc_obj[IRDMA_HMC_IW_PBLE];
	if (dev->privileged)
		size += round_up(pble_info->cnt * pble_info->size, 512);
	if (size & 0x1FFFFF)
		sd = (size >> 21) + 1; /* add 1 for remainder */
	else
		sd = size >> 21;
	if (!dev->privileged && !dev->hmc_fpm_misc.loc_mem_pages) {
		/* 2MB alignment for VF PBLE HMC */
		size = pble_info->cnt * pble_info->size;
		if (size & 0x1FFFFF)
			sd += (size >> 21) + 1; /* add 1 for remainder */
		else
			sd += size >> 21;
	}
	if (sd > 0xFFFFFFFF) {
		ibdev_dbg(to_ibdev(dev), "HMC: sd overflow[%lld]\n", sd);
		sd = 0xFFFFFFFE;
	}

	return (u32)sd;
}

/**
 * irdma_sc_query_rdma_features - query RDMA features and FW ver
 * @cqp: struct for cqp hw
 * @buf: buffer to hold query info
 * @scratch: u64 saved to be used during cqp completion
 */
static int irdma_sc_query_rdma_features(struct irdma_sc_cqp *cqp,
					struct irdma_dma_mem *buf, u64 scratch)
{
	__le64 *wqe;
	u64 temp;
	u32 tail, val, error;
	int status;

	wqe = irdma_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;

	temp = buf->pa;
	set_64bit_val(wqe, 32, temp);

	temp = FIELD_PREP(IRDMA_CQPSQ_QUERY_RDMA_FEATURES_WQEVALID,
			  cqp->polarity) |
	       FIELD_PREP(IRDMA_CQPSQ_QUERY_RDMA_FEATURES_BUF_LEN, buf->size) |
	       FIELD_PREP(IRDMA_CQPSQ_UP_OP, IRDMA_CQP_OP_QUERY_RDMA_FEATURES);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, temp);

	print_hex_dump_debug("WQE: QUERY RDMA FEATURES", DUMP_PREFIX_OFFSET,
			     16, 8, wqe, IRDMA_CQP_WQE_SIZE * 8, false);
	irdma_get_cqp_reg_info(cqp, &val, &tail, &error);

	irdma_sc_cqp_post_sq(cqp);
	status = irdma_cqp_poll_registers(cqp, tail,
					  cqp->dev->hw_attrs.max_done_count);
	if (error || status)
		status = -EIO;

	return status;
}

/**
 * irdma_get_rdma_features - get RDMA features
 * @dev: sc device struct
 */
int irdma_get_rdma_features(struct irdma_sc_dev *dev)
{
	struct irdma_dma_mem feat_buf;
	u16 feat_cnt;
	u16 feat_idx;
	u8 feat_type;
	int ret_code;
	u64 temp;

	feat_buf.size = ALIGN(IRDMA_FEATURE_BUF_SIZE,
			      IRDMA_FEATURE_BUF_ALIGNMENT);
	feat_buf.va = dma_alloc_coherent(dev->hw->device, feat_buf.size,
					 &feat_buf.pa, GFP_KERNEL);
	if (!feat_buf.va)
		return -ENOMEM;

	ret_code = irdma_sc_query_rdma_features(dev->cqp, &feat_buf, 0);
	if (ret_code)
		goto exit;

	get_64bit_val(feat_buf.va, 0, &temp);
	feat_cnt = (u16)FIELD_GET(IRDMA_FEATURE_CNT, temp);
	if (feat_cnt < IRDMA_MIN_FEATURES) {
		ret_code = -EINVAL;
		goto exit;
	} else if (feat_cnt > IRDMA_MAX_FEATURES) {
		ibdev_dbg(to_ibdev(dev),
			  "DEV: feature buf size insufficient, retrying with larger buffer\n");
		dma_free_coherent(dev->hw->device, feat_buf.size, feat_buf.va,
				  feat_buf.pa);
		feat_buf.va = NULL;
		feat_buf.size = ALIGN(8 * feat_cnt,
				      IRDMA_FEATURE_BUF_ALIGNMENT);
		feat_buf.va = dma_alloc_coherent(dev->hw->device,
						 feat_buf.size, &feat_buf.pa,
						 GFP_KERNEL);
		if (!feat_buf.va)
			return -ENOMEM;

		ret_code = irdma_sc_query_rdma_features(dev->cqp, &feat_buf, 0);
		if (ret_code)
			goto exit;

		get_64bit_val(feat_buf.va, 0, &temp);
		feat_cnt = (u16)FIELD_GET(IRDMA_FEATURE_CNT, temp);
		if (feat_cnt < IRDMA_MIN_FEATURES) {
			ret_code = -EINVAL;
			goto exit;
		}
	}

	print_hex_dump_debug("WQE: QUERY RDMA FEATURES", DUMP_PREFIX_OFFSET,
			     16, 8, feat_buf.va, feat_cnt * 8, false);

	for (feat_idx = 0; feat_idx < feat_cnt; feat_idx++) {
		get_64bit_val(feat_buf.va, feat_idx * 8, &temp);
		feat_type = FIELD_GET(IRDMA_FEATURE_TYPE, temp);

		if (feat_type >= IRDMA_MAX_FEATURES) {
			ibdev_dbg(to_ibdev(dev),
				  "DEV: unknown feature type %u\n", feat_type);
			continue;
		}
		dev->feature_info[feat_type] = temp;
	}
	if (dev->feature_info[IRDMA_FTN_FLAGS] & IRDMA_ATOMICS_ALLOWED_BIT)
		dev->hw_attrs.uk_attrs.feature_flags |= IRDMA_FEATURE_ATOMIC_OPS;
exit:
	dma_free_coherent(dev->hw->device, feat_buf.size, feat_buf.va,
			  feat_buf.pa);
	feat_buf.va = NULL;
	return ret_code;
}

/**
 * irdma_get_rsrc_mem_config - configure resources if local memory or host
 * @dev: sc device struct
 * @is_mrte_loc_mem: if true, MR's to be in local memory because sd=loc pages
 *
 * Only mr can be configured host or local memory if qp's are in local memory.
 * If qp is in local memory, then all resource object will be in local memory except
 * mr which can be either host or local memory. The only exception is pble's which are always
 * in host memory.
 */
static void irdma_get_rsrc_mem_config(struct irdma_sc_dev *dev, bool is_mrte_loc_mem)
{
	struct irdma_hmc_fpm_misc *hmc_fpm_misc = &dev->hmc_fpm_misc;
	struct irdma_hmc_info *hmc_info = dev->hmc_info;
	enum irdma_hmc_obj_mem mem_loc;
	int i;

	mem_loc = hmc_fpm_misc->loc_mem_pages ? IRDMA_LOC_MEM : IRDMA_HOST_MEM;

	for (i = IRDMA_HMC_IW_QP; i < IRDMA_HMC_IW_MAX; i++)
		hmc_info->hmc_obj[i].mem_loc = mem_loc;

	if (dev->feature_info[IRDMA_OBJ_1] && !is_mrte_loc_mem) {
		u8 mem_type;

		mem_type = (u8)FIELD_GET(IRDMA_MR_MEM_LOC, dev->feature_info[IRDMA_OBJ_1]);

		/* Force mr's to be in host mem if module parameter set it */
		hmc_info->hmc_obj[IRDMA_HMC_IW_MR].mem_loc =
			(dev->host_mem_mrte && mem_type & IRDMA_OBJ_HOST_MEM_BIT) ?
			IRDMA_HOST_MEM : IRDMA_LOC_MEM;
	} else {
		hmc_info->hmc_obj[IRDMA_HMC_IW_MR].mem_loc = IRDMA_LOC_MEM;
	}

	hmc_info->hmc_obj[IRDMA_HMC_IW_PBLE].mem_loc = IRDMA_HOST_MEM;

	ibdev_dbg(to_ibdev(dev), "HMC: INFO: mrte_mem_loc = %d pble = %d\n",
		  hmc_info->hmc_obj[IRDMA_HMC_IW_MR].mem_loc,
		  hmc_info->hmc_obj[IRDMA_HMC_IW_PBLE].mem_loc);
}

static u32 irdma_q1_cnt(struct irdma_sc_dev *dev,
			struct irdma_hmc_info *hmc_info, u32 qpwanted)
{
	u32 q1_cnt;

	if (dev->hw_attrs.uk_attrs.hw_rev == IRDMA_GEN_1) {
		q1_cnt = roundup_pow_of_two(dev->hw_attrs.max_hw_ird * 2 * qpwanted);
	} else {
		if (dev->cqp->protocol_used != IRDMA_IWARP_PROTOCOL_ONLY)
			q1_cnt = roundup_pow_of_two(dev->hw_attrs.max_hw_ird * 2 * qpwanted + 512);
		else
			q1_cnt = dev->hw_attrs.max_hw_ird * 2 * qpwanted;
	}

	return q1_cnt;
}

static void cfg_fpm_value_gen_1(struct irdma_sc_dev *dev,
				struct irdma_hmc_info *hmc_info, u32 qpwanted)
{
	hmc_info->hmc_obj[IRDMA_HMC_IW_XF].cnt = roundup_pow_of_two(qpwanted * dev->hw_attrs.max_hw_wqes);
}

static void cfg_fpm_value_gen_2(struct irdma_sc_dev *dev,
				struct irdma_hmc_info *hmc_info, u32 qpwanted)
{
	struct irdma_hmc_fpm_misc *hmc_fpm_misc = &dev->hmc_fpm_misc;

	hmc_info->hmc_obj[IRDMA_HMC_IW_XF].cnt =
		4 * hmc_fpm_misc->xf_block_size * qpwanted;

	hmc_info->hmc_obj[IRDMA_HMC_IW_HDR].cnt = qpwanted;

	if (hmc_info->hmc_obj[IRDMA_HMC_IW_RRF].max_cnt)
		hmc_info->hmc_obj[IRDMA_HMC_IW_RRF].cnt = 32 * qpwanted;
	if (hmc_info->hmc_obj[IRDMA_HMC_IW_RRFFL].max_cnt)
		hmc_info->hmc_obj[IRDMA_HMC_IW_RRFFL].cnt =
			hmc_info->hmc_obj[IRDMA_HMC_IW_RRF].cnt /
			hmc_fpm_misc->rrf_block_size;
	if (dev->cqp->protocol_used == IRDMA_IWARP_PROTOCOL_ONLY) {
		if (hmc_info->hmc_obj[IRDMA_HMC_IW_OOISC].max_cnt)
			hmc_info->hmc_obj[IRDMA_HMC_IW_OOISC].cnt = 32 * qpwanted;
		if (hmc_info->hmc_obj[IRDMA_HMC_IW_OOISCFFL].max_cnt)
			hmc_info->hmc_obj[IRDMA_HMC_IW_OOISCFFL].cnt =
				hmc_info->hmc_obj[IRDMA_HMC_IW_OOISC].cnt /
				hmc_fpm_misc->ooiscf_block_size;
	}
}

/**
 * irdma_cfg_sd_mem - allocate sd memory
 * @dev: sc device struct
 * @hmc_info: ptr to irdma_hmc_obj_info struct
 */
static int irdma_cfg_sd_mem(struct irdma_sc_dev *dev,
			    struct irdma_hmc_info *hmc_info)
{
	struct irdma_virt_mem virt_mem;
	u32 mem_size;

	mem_size = sizeof(struct irdma_hmc_sd_entry) * hmc_info->sd_table.sd_cnt;
	virt_mem.size = mem_size;
	virt_mem.va = kzalloc(virt_mem.size, GFP_KERNEL);
	if (!virt_mem.va)
		return -ENOMEM;
	hmc_info->sd_table.sd_entry = virt_mem.va;

	return 0;
}

/**
 * irdma_get_objs_pages - get number of 2M pages needed
 * @dev: sc device struct
 * @hmc_info: pointer to the HMC configuration information struct
 * @mem_loc: pages for local or host memory
 */
static u32 irdma_get_objs_pages(struct irdma_sc_dev *dev,
				struct irdma_hmc_info *hmc_info,
				enum irdma_hmc_obj_mem mem_loc)
{
	u64 size = 0;
	int i;

	for (i = IRDMA_HMC_IW_QP; i < IRDMA_HMC_IW_MAX; i++) {
		if (hmc_info->hmc_obj[i].mem_loc == mem_loc) {
			size += round_up(hmc_info->hmc_obj[i].cnt *
					 hmc_info->hmc_obj[i].size, 512);
		}
	}

	return (u32)DIV_ROUND_UP(size, IRDMA_HMC_PAGE_SIZE);
}

/**
 * irdma_set_host_hmc_rsrc_gen_3 - calculate host hmc resources for gen 3
 * @dev: sc device struct
 */
static void irdma_set_host_hmc_rsrc_gen_3(struct irdma_sc_dev *dev)
{
	struct irdma_hmc_fpm_misc *hmc_fpm_misc;
	struct irdma_hmc_info *hmc_info;
	enum irdma_hmc_obj_mem mrte_loc;
	u32 mrwanted, pblewanted;
	u32  avail_sds, mr_sds;

	hmc_info = dev->hmc_info;
	hmc_fpm_misc = &dev->hmc_fpm_misc;
	avail_sds = hmc_fpm_misc->max_sds;
	mrte_loc = hmc_info->hmc_obj[IRDMA_HMC_IW_MR].mem_loc;
	mrwanted = hmc_info->hmc_obj[IRDMA_HMC_IW_MR].cnt;
	pblewanted = hmc_info->hmc_obj[IRDMA_HMC_IW_PBLE].max_cnt;

	if (mrte_loc == IRDMA_HOST_MEM && avail_sds > IRDMA_MIN_PBLE_PAGES) {
		mr_sds = avail_sds - IRDMA_MIN_PBLE_PAGES;
		mrwanted = min(mrwanted, mr_sds * MAX_MR_PER_SD);
		hmc_info->hmc_obj[IRDMA_HMC_IW_MR].cnt = mrwanted;
		avail_sds -= DIV_ROUND_UP(mrwanted, MAX_MR_PER_SD);
	}

	if (FIELD_GET(IRDMA_MANAGE_RSRC_VER2, dev->feature_info[IRDMA_FTN_FLAGS]) &&
	    pblewanted > avail_sds * MAX_PBLE_PER_SD)
		ibdev_dbg(to_ibdev(dev),
			  "HMC: Warn: Resource version 2: pble wanted = 0x%x available = 0x%x\n",
			  pblewanted, avail_sds * MAX_PBLE_PER_SD);

	pblewanted = min(pblewanted, avail_sds * MAX_PBLE_PER_SD);
	hmc_info->hmc_obj[IRDMA_HMC_IW_PBLE].cnt = pblewanted;
}

/**
 * irdma_verify_commit_fpm_gen_3 - verify query fpm values
 * @dev: sc device struct
 * @max_pages: max local memory available
 * @qpwanted: number of qp's wanted
 */
static int irdma_verify_commit_fpm_gen_3(struct irdma_sc_dev *dev,
					 u32 max_pages,
					 u32 qpwanted)
{
	struct irdma_hmc_fpm_misc *hmc_fpm_misc;
	u32 rrf_cnt, xf_cnt, timer_cnt, pages_needed;
	struct irdma_hmc_info *hmc_info;
	u32 rrffl_cnt = 0;
	u32 xffl_cnt = 0;
	u32 q1fl_cnt;
	int i;

	hmc_info = dev->hmc_info;
	hmc_fpm_misc = &dev->hmc_fpm_misc;

	rrf_cnt = roundup_pow_of_two(IRDMA_RRF_MULTIPLIER * qpwanted);

	if (hmc_info->hmc_obj[IRDMA_HMC_IW_RRFFL].max_cnt)
		rrffl_cnt =
			hmc_info->hmc_obj[IRDMA_HMC_IW_RRF].cnt /
			hmc_fpm_misc->rrf_block_size;

	xf_cnt = roundup_pow_of_two(IRDMA_XF_MULTIPLIER * qpwanted);

	if (xf_cnt)
		xffl_cnt = xf_cnt / hmc_fpm_misc->xf_block_size;

	timer_cnt = (round_up(qpwanted, 512) / 512 + 1) *
		hmc_fpm_misc->timer_bucket;

	for (i = IRDMA_HMC_IW_QP; i < IRDMA_HMC_IW_MAX; i++)
		ibdev_dbg(to_ibdev(dev),
			  "HMC: obj = %d cnt = %u size = %llu total = %llu\n",
			  i, hmc_info->hmc_obj[i].cnt,
			  hmc_info->hmc_obj[i].size,
			  hmc_info->hmc_obj[i].cnt * hmc_info->hmc_obj[i].size);
	q1fl_cnt = hmc_info->hmc_obj[IRDMA_HMC_IW_Q1].cnt / hmc_fpm_misc->q1_block_size;

	pages_needed = irdma_get_objs_pages(dev, hmc_info, IRDMA_LOC_MEM);
	ibdev_dbg(to_ibdev(dev),
		  "HMC: IRD=%u Q1 CNT = %u pages_needed = %u max_pages = %u\n",
		  dev->hw_attrs.max_hw_ird,
		  hmc_info->hmc_obj[IRDMA_HMC_IW_Q1].cnt, pages_needed,
		  max_pages);
	if (pages_needed > max_pages) {
		ibdev_dbg(to_ibdev(dev),
			  "HMC: FAIL: SW counts rrf_cnt = %u rrffl_cnt = %u timer_cnt = %u",
			  rrf_cnt, rrffl_cnt, timer_cnt);
		ibdev_dbg(to_ibdev(dev),
			  "HMC: FAIL: SW counts xf_cnt = %u xffl_cnt = %u q1fl_cnt = %u",
			  xf_cnt, xffl_cnt, q1fl_cnt);

		return -EINVAL;
	}

	hmc_fpm_misc->max_sds -= pages_needed;
	hmc_fpm_misc->loc_mem_pages -= pages_needed;

	return 0;
}

/**
 * irdma_set_loc_hmc_rsrc_gen_3 - calculate hmc resources for gen 3
 * @dev: sc device struct
 * @max_pages: max local memory available
 * @qpwanted: number of qp's wanted
 */
static int irdma_set_loc_hmc_rsrc_gen_3(struct irdma_sc_dev *dev,
					u32 max_pages,
					u32 qpwanted)
{
	struct irdma_hmc_fpm_misc *hmc_fpm_misc;
	u32 rrf_cnt, xf_cnt, timer_cnt, pages_needed;
	struct irdma_hmc_info *hmc_info;
	u32 ird, ord;
	u32 i;

	if (FIELD_GET(IRDMA_MANAGE_RSRC_VER2, dev->feature_info[IRDMA_FTN_FLAGS]))
		return irdma_verify_commit_fpm_gen_3(dev, max_pages, qpwanted);

	hmc_info = dev->hmc_info;
	hmc_fpm_misc = &dev->hmc_fpm_misc;
	ird = dev->hw_attrs.max_hw_ird;
	ord = dev->hw_attrs.max_hw_ord;

//	irdma_debug(dev, IRDMA_DEBUG_HMC,
//		    " qpwanted = %u\n max_pages = %u\n",
//		    qpwanted, max_pages);
	hmc_info->hmc_obj[IRDMA_HMC_IW_HDR].cnt = qpwanted;
	hmc_info->hmc_obj[IRDMA_HMC_IW_QP].cnt = qpwanted;

	hmc_info->hmc_obj[IRDMA_HMC_IW_CQ].cnt =
		min(hmc_info->hmc_obj[IRDMA_HMC_IW_CQ].cnt, qpwanted * 2);

	hmc_info->hmc_obj[IRDMA_HMC_IW_FSIAV].cnt = min(qpwanted * 8,
							hmc_info->hmc_obj[IRDMA_HMC_IW_FSIAV].max_cnt);

	rrf_cnt = roundup_pow_of_two(dev->rrf_multiplier * qpwanted);
	hmc_info->hmc_obj[IRDMA_HMC_IW_RRF].cnt =
		min(hmc_info->hmc_obj[IRDMA_HMC_IW_RRF].max_cnt, rrf_cnt);
	if (hmc_info->hmc_obj[IRDMA_HMC_IW_RRFFL].max_cnt)
		hmc_info->hmc_obj[IRDMA_HMC_IW_RRFFL].cnt =
			hmc_info->hmc_obj[IRDMA_HMC_IW_RRF].cnt /
			hmc_fpm_misc->rrf_block_size;

	xf_cnt = roundup_pow_of_two(dev->xf_multiplier * qpwanted);
	xf_cnt = min(hmc_info->hmc_obj[IRDMA_HMC_IW_XF].max_cnt, xf_cnt);
	hmc_info->hmc_obj[IRDMA_HMC_IW_XF].cnt = xf_cnt;

	if (xf_cnt)
		hmc_info->hmc_obj[IRDMA_HMC_IW_XFFL].cnt =
			xf_cnt / hmc_fpm_misc->xf_block_size;

	timer_cnt = (round_up(qpwanted, 512) / 512 + 1) *
		hmc_fpm_misc->timer_bucket;
	hmc_info->hmc_obj[IRDMA_HMC_IW_TIMER].cnt =
		min(timer_cnt, hmc_info->hmc_obj[IRDMA_HMC_IW_TIMER].cnt);

	for (i = IRDMA_HMC_IW_QP; i < IRDMA_HMC_IW_MAX; i++)
		if (hmc_info->hmc_obj[i].cnt)
			ibdev_dbg(to_ibdev(dev),
				  "HMC: HMC: %s cnt = %u size = %llu total = %llu pages = %llu\n",
				  hmc_obj_name(i), hmc_info->hmc_obj[i].cnt,
				  hmc_info->hmc_obj[i].size,
				  hmc_info->hmc_obj[i].cnt * hmc_info->hmc_obj[i].size,
				  (hmc_info->hmc_obj[i].cnt * hmc_info->hmc_obj[i].size) / IRDMA_HMC_PAGE_SIZE);
	do {
		hmc_info->hmc_obj[IRDMA_HMC_IW_Q1].cnt = roundup_pow_of_two(ird * 2 * qpwanted);
		hmc_info->hmc_obj[IRDMA_HMC_IW_Q1FL].cnt =
			hmc_info->hmc_obj[IRDMA_HMC_IW_Q1].cnt / hmc_fpm_misc->q1_block_size;

		pages_needed = irdma_get_objs_pages(dev, hmc_info, IRDMA_LOC_MEM);
		ibdev_dbg(to_ibdev(dev),
			  "HMC: IRD=%u Q1 CNT = %u pages_needed = %u max_pages = %u\n",
			  ird, hmc_info->hmc_obj[IRDMA_HMC_IW_Q1].cnt,
			  pages_needed, max_pages);
		if (pages_needed <= max_pages)
			break;

		ird /= 2;
		ord /= 2;
	} while (ird >= dev->min_ird);

	if (ird < dev->min_ird) {
		ibdev_dbg(to_ibdev(dev), "HMC: FAIL: IRD=%u Q1 CNT = %u\n",
			  ird, hmc_info->hmc_obj[IRDMA_HMC_IW_Q1].cnt);
		return -EINVAL;
	}

	dev->hw_attrs.max_hw_ird = ird;
	dev->hw_attrs.max_hw_ord = ord;
	hmc_fpm_misc->max_sds -= pages_needed;
	ibdev_dbg(to_ibdev(dev), "HMC: SUCCESS: IRD=%u Q1 CNT = %u\n", ird,
		  hmc_info->hmc_obj[IRDMA_HMC_IW_Q1].cnt);
	for (i = IRDMA_HMC_IW_QP; i < IRDMA_HMC_IW_MAX; i++)
		if (hmc_info->hmc_obj[i].cnt)
			ibdev_dbg(to_ibdev(dev),
				  "HMC:  AFTER SUCCESS HMC: %s\t\tcnt = %u size = %llu total = %llu pages = %llu\n",
				  hmc_obj_name(i), hmc_info->hmc_obj[i].cnt,
				  hmc_info->hmc_obj[i].size,
				  hmc_info->hmc_obj[i].cnt * hmc_info->hmc_obj[i].size,
				  (hmc_info->hmc_obj[i].cnt * hmc_info->hmc_obj[i].size) / IRDMA_HMC_PAGE_SIZE);

	return 0;
}

/**
 * cfg_fpm_value_gen_3 - configure fpm for gen 3
 * @dev: sc device struct
 * @hmc_info: ptr to irdma_hmc_obj_info struct
 * @hmc_fpm_misc: ptr to fpm data
 */
static int cfg_fpm_value_gen_3(struct irdma_sc_dev *dev,
			       struct irdma_hmc_info *hmc_info,
			       struct irdma_hmc_fpm_misc *hmc_fpm_misc)
{
	enum irdma_hmc_obj_mem mrte_loc;
	u32 mrwanted,  qpwanted;
	int i, ret_code = 0;
	u32 loc_mem_pages;
	bool is_mrte_loc_mem;

	loc_mem_pages = hmc_fpm_misc->loc_mem_pages;
	is_mrte_loc_mem = hmc_fpm_misc->loc_mem_pages == hmc_fpm_misc->max_sds ?
			true : false;

	irdma_get_rsrc_mem_config(dev, is_mrte_loc_mem);
	mrte_loc = hmc_info->hmc_obj[IRDMA_HMC_IW_MR].mem_loc;

	if (is_mrte_loc_mem)
		loc_mem_pages -= IRDMA_MIN_PBLE_PAGES;
	ibdev_dbg(to_ibdev(dev),
		  "HMC: mrte_loc %d loc_mem %u fpm max sds %u host_obj %d\n",
		  hmc_info->hmc_obj[IRDMA_HMC_IW_MR].mem_loc,
		  hmc_fpm_misc->loc_mem_pages, hmc_fpm_misc->max_sds,
		  is_mrte_loc_mem);

	if (dev->hw_wa & MAX_QP_2K) {
	/* Reduce the resources for this release */
		hmc_info->hmc_obj[IRDMA_HMC_IW_QP].max_cnt = 2048;
		hmc_info->hmc_obj[IRDMA_HMC_IW_MR].max_cnt = 8192;
		hmc_info->hmc_obj[IRDMA_HMC_IW_PBLE].max_cnt = 2097152;
		hmc_info->hmc_obj[IRDMA_HMC_IW_SRQ].max_cnt = 64;
		hmc_info->hmc_obj[IRDMA_HMC_IW_FSIAV].max_cnt = 2048;
	}
	mrwanted = hmc_info->hmc_obj[IRDMA_HMC_IW_MR].max_cnt;
	qpwanted = hmc_info->hmc_obj[IRDMA_HMC_IW_QP].max_cnt;
	hmc_info->hmc_obj[IRDMA_HMC_IW_HDR].cnt = qpwanted;

	hmc_info->hmc_obj[IRDMA_HMC_IW_OOISC].max_cnt = 0;
	hmc_info->hmc_obj[IRDMA_HMC_IW_OOISCFFL].max_cnt = 0;
	hmc_info->hmc_obj[IRDMA_HMC_IW_HTE].max_cnt = 0;
	hmc_info->hmc_obj[IRDMA_HMC_IW_FSIMC].max_cnt = 0;
	if (!FIELD_GET(IRDMA_MANAGE_RSRC_VER2, dev->feature_info[IRDMA_FTN_FLAGS]))
		hmc_info->hmc_obj[IRDMA_HMC_IW_FSIAV].max_cnt =
			min(hmc_info->hmc_obj[IRDMA_HMC_IW_FSIAV].max_cnt,
			    (u32)IRDMA_FSIAV_CNT_MAX);

	for (i = IRDMA_HMC_IW_QP; i < IRDMA_HMC_IW_MAX; i++)
		hmc_info->hmc_obj[i].cnt = hmc_info->hmc_obj[i].max_cnt;

	while (qpwanted >= IRDMA_MIN_QP_CNT) {
		if (!irdma_set_loc_hmc_rsrc_gen_3(dev, loc_mem_pages, qpwanted))
			break;

		if (FIELD_GET(IRDMA_MANAGE_RSRC_VER2, dev->feature_info[IRDMA_FTN_FLAGS]))
			return -EINVAL;

		qpwanted /= 2;
		if (mrte_loc == IRDMA_LOC_MEM) {
			mrwanted = qpwanted * IRDMA_MIN_MR_PER_QP;
			hmc_info->hmc_obj[IRDMA_HMC_IW_MR].cnt =
				min(hmc_info->hmc_obj[IRDMA_HMC_IW_MR].max_cnt, mrwanted);
		}
	}

	if (qpwanted < IRDMA_MIN_QP_CNT) {
		ibdev_dbg(to_ibdev(dev),
			  "HMC: Could not allocate fpm resources.\n");

		return -EINVAL;
	}

	irdma_set_host_hmc_rsrc_gen_3(dev);
	ret_code = irdma_sc_cfg_iw_fpm(dev, dev->hmc_fn_id);
	if (ret_code) {
		ibdev_dbg(to_ibdev(dev),
			  "HMC: cfg_iw_fpm returned error_code[x%08X]\n",
			  readl(dev->hw_regs[IRDMA_CQPERRCODES]));

		return ret_code;
	}

	return irdma_cfg_sd_mem(dev, hmc_info);
}

/**
 * irdma_cfg_fpm_val - configure HMC objects
 * @dev: sc device struct
 * @qp_count: desired qp count
 */
int irdma_cfg_fpm_val(struct irdma_sc_dev *dev, u32 qp_count)
{
	u32 qpwanted, mrwanted, pblewanted;
	u32 powerof2, hte, i;
	u32 sd_needed;
	u32 sd_diff;
	u32 loop_count = 0;
	struct irdma_hmc_info *hmc_info;
	struct irdma_hmc_fpm_misc *hmc_fpm_misc;
	int ret_code = 0;
	u32 max_sds;

	hmc_info = dev->hmc_info;
	hmc_fpm_misc = &dev->hmc_fpm_misc;
	ret_code = irdma_sc_init_iw_hmc(dev, dev->hmc_fn_id);
	if (ret_code) {
		ibdev_dbg(to_ibdev(dev),
			  "HMC: irdma_sc_init_iw_hmc returned error_code = %d\n",
			  ret_code);
		return ret_code;
	}

	max_sds = hmc_fpm_misc->max_sds;

	if (dev->hw_attrs.uk_attrs.hw_rev >= IRDMA_GEN_3)
		return cfg_fpm_value_gen_3(dev, hmc_info, hmc_fpm_misc);

	for (i = IRDMA_HMC_IW_QP; i < IRDMA_HMC_IW_MAX; i++)
		hmc_info->hmc_obj[i].cnt = hmc_info->hmc_obj[i].max_cnt;

	sd_needed = irdma_est_sd(dev, hmc_info);
	ibdev_dbg(to_ibdev(dev), "HMC: sd count %u where max sd is %u\n",
		  hmc_info->sd_table.sd_cnt, max_sds);

	qpwanted = min(qp_count, hmc_info->hmc_obj[IRDMA_HMC_IW_QP].max_cnt);

	powerof2 = 1;
	while (powerof2 <= qpwanted)
		powerof2 *= 2;
	powerof2 /= 2;
	qpwanted = powerof2;

	mrwanted = hmc_info->hmc_obj[IRDMA_HMC_IW_MR].max_cnt;
	pblewanted = hmc_info->hmc_obj[IRDMA_HMC_IW_PBLE].max_cnt;

	ibdev_dbg(to_ibdev(dev),
		  "HMC: req_qp=%d max_sd=%u, max_qp = %u, max_cq=%u, max_mr=%u, max_pble=%u, mc=%d, av=%u\n",
		  qp_count, max_sds,
		  hmc_info->hmc_obj[IRDMA_HMC_IW_QP].max_cnt,
		  hmc_info->hmc_obj[IRDMA_HMC_IW_CQ].max_cnt,
		  hmc_info->hmc_obj[IRDMA_HMC_IW_MR].max_cnt,
		  hmc_info->hmc_obj[IRDMA_HMC_IW_PBLE].max_cnt,
		  hmc_info->hmc_obj[IRDMA_HMC_IW_FSIMC].max_cnt,
		  hmc_info->hmc_obj[IRDMA_HMC_IW_FSIAV].max_cnt);
	hmc_info->hmc_obj[IRDMA_HMC_IW_FSIMC].cnt =
		hmc_info->hmc_obj[IRDMA_HMC_IW_FSIMC].max_cnt;
	hmc_info->hmc_obj[IRDMA_HMC_IW_FSIAV].cnt =
		hmc_info->hmc_obj[IRDMA_HMC_IW_FSIAV].max_cnt;
	hmc_info->hmc_obj[IRDMA_HMC_IW_ARP].cnt =
		hmc_info->hmc_obj[IRDMA_HMC_IW_ARP].max_cnt;
	hmc_info->hmc_obj[IRDMA_HMC_IW_APBVT_ENTRY].cnt = 1;

	while (irdma_q1_cnt(dev, hmc_info, qpwanted) > hmc_info->hmc_obj[IRDMA_HMC_IW_Q1].max_cnt)
		qpwanted /= 2;

	if (dev->hw_attrs.uk_attrs.hw_rev == IRDMA_GEN_1) {
		cfg_fpm_value_gen_1(dev, hmc_info, qpwanted);
		while (hmc_info->hmc_obj[IRDMA_HMC_IW_XF].cnt > hmc_info->hmc_obj[IRDMA_HMC_IW_XF].max_cnt) {
			qpwanted /= 2;
			cfg_fpm_value_gen_1(dev, hmc_info, qpwanted);
		}
	}

	do {
		++loop_count;
		hmc_info->hmc_obj[IRDMA_HMC_IW_QP].cnt = qpwanted;
		hmc_info->hmc_obj[IRDMA_HMC_IW_CQ].cnt =
			min(2 * qpwanted, hmc_info->hmc_obj[IRDMA_HMC_IW_CQ].cnt);
		hmc_info->hmc_obj[IRDMA_HMC_IW_SRQ].cnt = 0; /* Reserved */
		hmc_info->hmc_obj[IRDMA_HMC_IW_MR].cnt = mrwanted;

		hte = round_up(qpwanted + hmc_info->hmc_obj[IRDMA_HMC_IW_FSIMC].cnt, 512);
		powerof2 = 1;
		while (powerof2 < hte)
			powerof2 *= 2;
		hmc_info->hmc_obj[IRDMA_HMC_IW_HTE].cnt =
			powerof2 * hmc_fpm_misc->ht_multiplier;
		if (dev->hw_attrs.uk_attrs.hw_rev == IRDMA_GEN_1)
			cfg_fpm_value_gen_1(dev, hmc_info, qpwanted);
		else
			cfg_fpm_value_gen_2(dev, hmc_info, qpwanted);

		hmc_info->hmc_obj[IRDMA_HMC_IW_Q1].cnt = irdma_q1_cnt(dev, hmc_info, qpwanted);
		hmc_info->hmc_obj[IRDMA_HMC_IW_XFFL].cnt =
			hmc_info->hmc_obj[IRDMA_HMC_IW_XF].cnt / hmc_fpm_misc->xf_block_size;
		hmc_info->hmc_obj[IRDMA_HMC_IW_Q1FL].cnt =
			hmc_info->hmc_obj[IRDMA_HMC_IW_Q1].cnt / hmc_fpm_misc->q1_block_size;
		hmc_info->hmc_obj[IRDMA_HMC_IW_TIMER].cnt =
			(round_up(qpwanted, 512) / 512 + 1) * hmc_fpm_misc->timer_bucket;

		hmc_info->hmc_obj[IRDMA_HMC_IW_PBLE].cnt = pblewanted;
		sd_needed = irdma_est_sd(dev, hmc_info);
		ibdev_dbg(to_ibdev(dev),
			  "HMC: sd_needed = %d, max_sds=%d, mrwanted=%d, pblewanted=%d qpwanted=%d\n",
			  sd_needed, max_sds, mrwanted, pblewanted, qpwanted);

		/* Do not reduce resources further. All objects fit with max SDs */
		if (sd_needed <= max_sds)
			break;

		sd_diff = sd_needed - max_sds;
		if (sd_diff > 128) {
			if (!(loop_count % 2) && qpwanted > 128) {
				qpwanted /= 2;
			} else {
				pblewanted /= 2;
				mrwanted /= 2;
			}
			continue;
		}

		if (dev->cqp->hmc_profile != IRDMA_HMC_PROFILE_FAVOR_VF &&
		    pblewanted > (512 * FPM_MULTIPLIER * sd_diff)) {
			pblewanted -= 256 * FPM_MULTIPLIER * sd_diff;
			continue;
		} else if (pblewanted > 100 * FPM_MULTIPLIER) {
			pblewanted -= 10 * FPM_MULTIPLIER;
		} else if (pblewanted > 16 * FPM_MULTIPLIER) {
			pblewanted -= FPM_MULTIPLIER;
		} else if (qpwanted <= 128) {
			if (hmc_info->hmc_obj[IRDMA_HMC_IW_FSIMC].cnt > 256)
				hmc_info->hmc_obj[IRDMA_HMC_IW_FSIMC].cnt /= 2;
			if (hmc_info->hmc_obj[IRDMA_HMC_IW_FSIAV].cnt > 256)
				hmc_info->hmc_obj[IRDMA_HMC_IW_FSIAV].cnt /= 2;
		}
		if (mrwanted > FPM_MULTIPLIER)
			mrwanted -= FPM_MULTIPLIER;
		if (!(loop_count % 10) && qpwanted > 128) {
			qpwanted /= 2;
			if (hmc_info->hmc_obj[IRDMA_HMC_IW_FSIAV].cnt > 256)
				hmc_info->hmc_obj[IRDMA_HMC_IW_FSIAV].cnt /= 2;
		}
	} while (loop_count < 2000);

	if (sd_needed > max_sds) {
		ibdev_dbg(to_ibdev(dev),
			  "HMC: cfg_fpm failed loop_cnt=%u, sd_needed=%u, max sd count %u\n",
			  loop_count, sd_needed, hmc_info->sd_table.sd_cnt);
		return -EINVAL;
	}

	if (loop_count > 1 && sd_needed < max_sds) {
		pblewanted += (max_sds - sd_needed) * 256 * FPM_MULTIPLIER;
		hmc_info->hmc_obj[IRDMA_HMC_IW_PBLE].cnt = pblewanted;
		sd_needed = irdma_est_sd(dev, hmc_info);
	}

	ibdev_dbg(to_ibdev(dev),
		  "HMC: loop_cnt=%d, sd_needed=%d, qpcnt = %d, cqcnt=%d, mrcnt=%d, pblecnt=%d, mc=%d, ah=%d, max sd count %d, first sd index %d\n",
		  loop_count, sd_needed,
		  hmc_info->hmc_obj[IRDMA_HMC_IW_QP].cnt,
		  hmc_info->hmc_obj[IRDMA_HMC_IW_CQ].cnt,
		  hmc_info->hmc_obj[IRDMA_HMC_IW_MR].cnt,
		  hmc_info->hmc_obj[IRDMA_HMC_IW_PBLE].cnt,
		  hmc_info->hmc_obj[IRDMA_HMC_IW_FSIMC].cnt,
		  hmc_info->hmc_obj[IRDMA_HMC_IW_FSIAV].cnt,
		  hmc_info->sd_table.sd_cnt, hmc_info->first_sd_index);

	ret_code = irdma_sc_cfg_iw_fpm(dev, dev->hmc_fn_id);
	if (ret_code) {
		ibdev_dbg(to_ibdev(dev),
			  "HMC: cfg_iw_fpm returned error_code[x%08X]\n",
			  readl(dev->hw_regs[IRDMA_CQPERRCODES]));
		return ret_code;
	}

	return irdma_cfg_sd_mem(dev, hmc_info);
}

/**
 * irdma_exec_cqp_cmd - execute cqp cmd when wqe are available
 * @dev: rdma device
 * @pcmdinfo: cqp command info
 */
static int irdma_exec_cqp_cmd(struct irdma_sc_dev *dev,
			      struct cqp_cmds_info *pcmdinfo)
{
	int status;
	struct irdma_dma_mem val_mem;
	bool alloc = false;

	dev->cqp_cmd_stats[pcmdinfo->cqp_cmd]++;
	switch (pcmdinfo->cqp_cmd) {
	case IRDMA_OP_CEQ_DESTROY:
		status = irdma_sc_ceq_destroy(pcmdinfo->in.u.ceq_destroy.ceq,
					      pcmdinfo->in.u.ceq_destroy.scratch,
					      pcmdinfo->post_sq);
		break;
	case IRDMA_OP_AEQ_DESTROY:
		status = irdma_sc_aeq_destroy(pcmdinfo->in.u.aeq_destroy.aeq,
					      pcmdinfo->in.u.aeq_destroy.scratch,
					      pcmdinfo->post_sq);
		break;
	case IRDMA_OP_CEQ_CREATE:
		status = irdma_sc_ceq_create(pcmdinfo->in.u.ceq_create.ceq,
					     pcmdinfo->in.u.ceq_create.scratch,
					     pcmdinfo->post_sq);
		break;
	case IRDMA_OP_AEQ_CREATE:
		status = irdma_sc_aeq_create(pcmdinfo->in.u.aeq_create.aeq,
					     pcmdinfo->in.u.aeq_create.scratch,
					     pcmdinfo->post_sq);
		break;
	case IRDMA_OP_QP_UPLOAD_CONTEXT:
		status = irdma_sc_qp_upload_context(pcmdinfo->in.u.qp_upload_context.dev,
						    &pcmdinfo->in.u.qp_upload_context.info,
						    pcmdinfo->in.u.qp_upload_context.scratch,
						    pcmdinfo->post_sq);
		break;
	case IRDMA_OP_CQ_CREATE:
		status = irdma_sc_cq_create(pcmdinfo->in.u.cq_create.cq,
					    pcmdinfo->in.u.cq_create.scratch,
					    pcmdinfo->in.u.cq_create.check_overflow,
					    pcmdinfo->post_sq);
		break;
	case IRDMA_OP_CQ_MODIFY:
		status = irdma_sc_cq_modify(pcmdinfo->in.u.cq_modify.cq,
					    &pcmdinfo->in.u.cq_modify.info,
					    pcmdinfo->in.u.cq_modify.scratch,
					    pcmdinfo->post_sq);
		break;
	case IRDMA_OP_CQ_DESTROY:
		status = irdma_sc_cq_destroy(pcmdinfo->in.u.cq_destroy.cq,
					     pcmdinfo->in.u.cq_destroy.scratch,
					     pcmdinfo->post_sq);
		break;
	case IRDMA_OP_QP_FLUSH_WQES:
		status = irdma_sc_qp_flush_wqes(pcmdinfo->in.u.qp_flush_wqes.qp,
						&pcmdinfo->in.u.qp_flush_wqes.info,
						pcmdinfo->in.u.qp_flush_wqes.scratch,
						pcmdinfo->post_sq);
		break;
	case IRDMA_OP_GEN_AE:
		status = irdma_sc_gen_ae(pcmdinfo->in.u.gen_ae.qp,
					 &pcmdinfo->in.u.gen_ae.info,
					 pcmdinfo->in.u.gen_ae.scratch,
					 pcmdinfo->post_sq);
		break;
	case IRDMA_OP_MANAGE_PUSH_PAGE:
		status = irdma_sc_manage_push_page(pcmdinfo->in.u.manage_push_page.cqp,
						   &pcmdinfo->in.u.manage_push_page.info,
						   pcmdinfo->in.u.manage_push_page.scratch,
						   pcmdinfo->post_sq);
		break;
	case IRDMA_OP_UPDATE_PE_SDS:
		status = irdma_update_pe_sds(pcmdinfo->in.u.update_pe_sds.dev,
					     &pcmdinfo->in.u.update_pe_sds.info,
					     pcmdinfo->in.u.update_pe_sds.scratch);
		break;
	case IRDMA_OP_MANAGE_HMC_PM_FUNC_TABLE:
		/* switch to calling through the call table */
		status =
			irdma_sc_manage_hmc_pm_func_table(pcmdinfo->in.u.manage_hmc_pm.dev->cqp,
							  &pcmdinfo->in.u.manage_hmc_pm.info,
							  pcmdinfo->in.u.manage_hmc_pm.scratch,
							  true);
		break;
	case IRDMA_OP_SUSPEND:
		status = irdma_sc_suspend_qp(pcmdinfo->in.u.suspend_resume.cqp,
					     pcmdinfo->in.u.suspend_resume.qp,
					     pcmdinfo->in.u.suspend_resume.scratch);
		break;
	case IRDMA_OP_RESUME:
		status = irdma_sc_resume_qp(pcmdinfo->in.u.suspend_resume.cqp,
					    pcmdinfo->in.u.suspend_resume.qp,
					    pcmdinfo->in.u.suspend_resume.scratch);
		break;
	case IRDMA_OP_MANAGE_PBLE_BP:
		status = irdma_sc_manage_pble_bp(pcmdinfo->in.u.manage_pble_bp.cqp,
						 &pcmdinfo->in.u.manage_pble_bp.info,
						 pcmdinfo->in.u.manage_pble_bp.scratch,
						 true);
		break;
	case IRDMA_OP_QUERY_FPM_VAL:
		val_mem.pa = pcmdinfo->in.u.query_fpm_val.fpm_val_pa;
		val_mem.va = pcmdinfo->in.u.query_fpm_val.fpm_val_va;
		status = irdma_sc_query_fpm_val(pcmdinfo->in.u.query_fpm_val.cqp,
						pcmdinfo->in.u.query_fpm_val.scratch,
						pcmdinfo->in.u.query_fpm_val.hmc_fn_id,
						&val_mem, true, IRDMA_CQP_WAIT_EVENT);
		break;
	case IRDMA_OP_COMMIT_FPM_VAL:
		val_mem.pa = pcmdinfo->in.u.commit_fpm_val.fpm_val_pa;
		val_mem.va = pcmdinfo->in.u.commit_fpm_val.fpm_val_va;
		status = irdma_sc_commit_fpm_val(pcmdinfo->in.u.commit_fpm_val.cqp,
						 pcmdinfo->in.u.commit_fpm_val.scratch,
						 pcmdinfo->in.u.commit_fpm_val.hmc_fn_id,
						 &val_mem,
						 true,
						 IRDMA_CQP_WAIT_EVENT);
		break;
	case IRDMA_OP_STATS_ALLOCATE:
		alloc = true;
		fallthrough;
	case IRDMA_OP_STATS_FREE:
		status = irdma_sc_manage_stats_inst(pcmdinfo->in.u.stats_manage.cqp,
						    &pcmdinfo->in.u.stats_manage.info,
						    alloc,
						    pcmdinfo->in.u.stats_manage.scratch);
		break;
	case IRDMA_OP_STATS_GATHER:
		status = irdma_sc_gather_stats(pcmdinfo->in.u.stats_gather.cqp,
					       &pcmdinfo->in.u.stats_gather.info,
					       pcmdinfo->in.u.stats_gather.scratch);
		break;
	case IRDMA_OP_WS_MODIFY_NODE:
		status = irdma_sc_manage_ws_node(pcmdinfo->in.u.ws_node.cqp,
						 &pcmdinfo->in.u.ws_node.info,
						 IRDMA_MODIFY_NODE,
						 pcmdinfo->in.u.ws_node.scratch);
		break;
	case IRDMA_OP_WS_DELETE_NODE:
		status = irdma_sc_manage_ws_node(pcmdinfo->in.u.ws_node.cqp,
						 &pcmdinfo->in.u.ws_node.info,
						 IRDMA_DEL_NODE,
						 pcmdinfo->in.u.ws_node.scratch);
		break;
	case IRDMA_OP_WS_ADD_NODE:
		status = irdma_sc_manage_ws_node(pcmdinfo->in.u.ws_node.cqp,
						 &pcmdinfo->in.u.ws_node.info,
						 IRDMA_ADD_NODE,
						 pcmdinfo->in.u.ws_node.scratch);
		break;
	case IRDMA_OP_SET_UP_MAP:
		status = irdma_sc_set_up_map(pcmdinfo->in.u.up_map.cqp,
					     &pcmdinfo->in.u.up_map.info,
					     pcmdinfo->in.u.up_map.scratch);
		break;
	case IRDMA_OP_QUERY_RDMA_FEATURES:
		status = irdma_sc_query_rdma_features(pcmdinfo->in.u.query_rdma.cqp,
						      &pcmdinfo->in.u.query_rdma.query_buff_mem,
						      pcmdinfo->in.u.query_rdma.scratch);
		break;
	case IRDMA_OP_DELETE_ARP_CACHE_ENTRY:
		status = irdma_sc_del_arp_cache_entry(pcmdinfo->in.u.del_arp_cache_entry.cqp,
						      pcmdinfo->in.u.del_arp_cache_entry.scratch,
						      pcmdinfo->in.u.del_arp_cache_entry.arp_index,
						      pcmdinfo->post_sq);
		break;
	case IRDMA_OP_MANAGE_APBVT_ENTRY:
		status = irdma_sc_manage_apbvt_entry(pcmdinfo->in.u.manage_apbvt_entry.cqp,
						     &pcmdinfo->in.u.manage_apbvt_entry.info,
						     pcmdinfo->in.u.manage_apbvt_entry.scratch,
						     pcmdinfo->post_sq);
		break;
	case IRDMA_OP_MANAGE_QHASH_TABLE_ENTRY:
		status = irdma_sc_manage_qhash_table_entry(pcmdinfo->in.u.manage_qhash_table_entry.cqp,
							   &pcmdinfo->in.u.manage_qhash_table_entry.info,
							   pcmdinfo->in.u.manage_qhash_table_entry.scratch,
							   pcmdinfo->post_sq);
		break;
	case IRDMA_OP_QP_MODIFY:
		status = irdma_sc_qp_modify(pcmdinfo->in.u.qp_modify.qp,
					    &pcmdinfo->in.u.qp_modify.info,
					    pcmdinfo->in.u.qp_modify.scratch,
					    pcmdinfo->post_sq);
		break;
	case IRDMA_OP_QP_CREATE:
		status = irdma_sc_qp_create(pcmdinfo->in.u.qp_create.qp,
					    &pcmdinfo->in.u.qp_create.info,
					    pcmdinfo->in.u.qp_create.scratch,
					    pcmdinfo->post_sq);
		break;
	case IRDMA_OP_QP_DESTROY:
		status = irdma_sc_qp_destroy(pcmdinfo->in.u.qp_destroy.qp,
					     pcmdinfo->in.u.qp_destroy.scratch,
					     pcmdinfo->in.u.qp_destroy.remove_hash_idx,
					     pcmdinfo->in.u.qp_destroy.ignore_mw_bnd,
					     pcmdinfo->post_sq);
		break;
	case IRDMA_OP_ALLOC_STAG:
		status = irdma_sc_alloc_stag(pcmdinfo->in.u.alloc_stag.dev,
					     &pcmdinfo->in.u.alloc_stag.info,
					     pcmdinfo->in.u.alloc_stag.scratch,
					     pcmdinfo->post_sq);
		break;
	case IRDMA_OP_MR_REG_NON_SHARED:
		status = irdma_sc_mr_reg_non_shared(pcmdinfo->in.u.mr_reg_non_shared.dev,
						    &pcmdinfo->in.u.mr_reg_non_shared.info,
						    pcmdinfo->in.u.mr_reg_non_shared.scratch,
						    pcmdinfo->post_sq);
		break;
	case IRDMA_OP_DEALLOC_STAG:
		status = irdma_sc_dealloc_stag(pcmdinfo->in.u.dealloc_stag.dev,
					       &pcmdinfo->in.u.dealloc_stag.info,
					       pcmdinfo->in.u.dealloc_stag.scratch,
					       pcmdinfo->post_sq);
		break;
	case IRDMA_OP_MW_ALLOC:
		status = irdma_sc_mw_alloc(pcmdinfo->in.u.mw_alloc.dev,
					   &pcmdinfo->in.u.mw_alloc.info,
					   pcmdinfo->in.u.mw_alloc.scratch,
					   pcmdinfo->post_sq);
		break;
	case IRDMA_OP_ADD_ARP_CACHE_ENTRY:
		status = irdma_sc_add_arp_cache_entry(pcmdinfo->in.u.add_arp_cache_entry.cqp,
						      &pcmdinfo->in.u.add_arp_cache_entry.info,
						      pcmdinfo->in.u.add_arp_cache_entry.scratch,
						      pcmdinfo->post_sq);
		break;
	case IRDMA_OP_ALLOC_LOCAL_MAC_ENTRY:
		status = irdma_sc_alloc_local_mac_entry(pcmdinfo->in.u.alloc_local_mac_entry.cqp,
							pcmdinfo->in.u.alloc_local_mac_entry.scratch,
							pcmdinfo->post_sq);
		break;
	case IRDMA_OP_ADD_LOCAL_MAC_ENTRY:
		status = irdma_sc_add_local_mac_entry(pcmdinfo->in.u.add_local_mac_entry.cqp,
						      &pcmdinfo->in.u.add_local_mac_entry.info,
						      pcmdinfo->in.u.add_local_mac_entry.scratch,
						      pcmdinfo->post_sq);
		break;
	case IRDMA_OP_DELETE_LOCAL_MAC_ENTRY:
		status = irdma_sc_del_local_mac_entry(pcmdinfo->in.u.del_local_mac_entry.cqp,
						      pcmdinfo->in.u.del_local_mac_entry.scratch,
						      pcmdinfo->in.u.del_local_mac_entry.entry_idx,
						      pcmdinfo->in.u.del_local_mac_entry.ignore_ref_count,
						      pcmdinfo->post_sq);
		break;
	case IRDMA_OP_AH_CREATE:
		status = irdma_sc_create_ah(pcmdinfo->in.u.ah_create.cqp,
					    &pcmdinfo->in.u.ah_create.info,
					    pcmdinfo->in.u.ah_create.scratch);
		break;
	case IRDMA_OP_AH_DESTROY:
		status = irdma_sc_destroy_ah(pcmdinfo->in.u.ah_destroy.cqp,
					     &pcmdinfo->in.u.ah_destroy.info,
					     pcmdinfo->in.u.ah_destroy.scratch);
		break;
	case IRDMA_OP_AH_MODIFY:
		status = irdma_sc_modify_ah(pcmdinfo->in.u.ah_modify.cqp,
					    &pcmdinfo->in.u.ah_modify.info,
					    pcmdinfo->in.u.ah_modify.scratch);
		break;
	case IRDMA_OP_MC_CREATE:
		status = irdma_sc_create_mcast_grp(pcmdinfo->in.u.mc_create.cqp,
						   &pcmdinfo->in.u.mc_create.info,
						   pcmdinfo->in.u.mc_create.scratch);
		break;
	case IRDMA_OP_MC_DESTROY:
		status = irdma_sc_destroy_mcast_grp(pcmdinfo->in.u.mc_destroy.cqp,
						    &pcmdinfo->in.u.mc_destroy.info,
						    pcmdinfo->in.u.mc_destroy.scratch);
		break;
	case IRDMA_OP_MC_MODIFY:
		status = irdma_sc_modify_mcast_grp(pcmdinfo->in.u.mc_modify.cqp,
						   &pcmdinfo->in.u.mc_modify.info,
						   pcmdinfo->in.u.mc_modify.scratch);
		break;
	case IRDMA_OP_SRQ_CREATE:
		status = irdma_sc_srq_create(pcmdinfo->in.u.srq_create.srq,
					     pcmdinfo->in.u.srq_create.scratch,
					     pcmdinfo->post_sq);
		break;
	case IRDMA_OP_SRQ_MODIFY:
		status = irdma_sc_srq_modify(pcmdinfo->in.u.srq_modify.srq,
					     &pcmdinfo->in.u.srq_modify.info,
					     pcmdinfo->in.u.srq_modify.scratch,
					     pcmdinfo->post_sq);
		break;
	case IRDMA_OP_SRQ_DESTROY:
		status = irdma_sc_srq_destroy(pcmdinfo->in.u.srq_destroy.srq,
					      pcmdinfo->in.u.srq_destroy.scratch,
					      pcmdinfo->post_sq);
		break;
	case IRDMA_OP_GATHER_RDMA_SYSTEM_STATS:
		status = irdma_sc_gather_rdma_sys_stats(pcmdinfo->in.u.gather_rdma_system_stats.cqp,
							&pcmdinfo->in.u.gather_rdma_system_stats.info,
							pcmdinfo->in.u.gather_rdma_system_stats.scratch,
							pcmdinfo->post_sq);
		break;
	case IRDMA_OP_RCA_EXEC_FWD_OP:
		status = irdma_sc_rca_exec_fwd_op(pcmdinfo->in.u.rca_exec_fwd_op.cqp,
						  &pcmdinfo->in.u.rca_exec_fwd_op.info,
						  pcmdinfo->in.u.rca_exec_fwd_op.scratch,
						  pcmdinfo->post_sq);
		break;
	case IRDMA_OP_RET_CQP_CMPL:
		status = irdma_sc_ret_cqp_cmpl(pcmdinfo->in.u.ret_cqp_cmpl.cqp,
					       &pcmdinfo->in.u.ret_cqp_cmpl.info,
					       pcmdinfo->in.u.ret_cqp_cmpl.scratch,
					       pcmdinfo->post_sq);
		break;
	case IRDMA_OP_COPY_DATA:
		status = irdma_sc_copy_data(pcmdinfo->in.u.copy_data.cqp,
					    &pcmdinfo->in.u.copy_data.info,
					    pcmdinfo->in.u.copy_data.scratch,
					    pcmdinfo->post_sq);
		break;
	case IRDMA_OP_NOP:
		status = irdma_sc_cqp_nop(pcmdinfo->in.u.nop.cqp,
					  pcmdinfo->in.u.nop.scratch,
					  pcmdinfo->post_sq);
		break;
	default:
		status = -EOPNOTSUPP;
		break;
	}

	return status;
}

/**
 * irdma_process_cqp_cmd - process all cqp commands
 * @dev: sc device struct
 * @pcmdinfo: cqp command info
 */
int irdma_process_cqp_cmd(struct irdma_sc_dev *dev,
			  struct cqp_cmds_info *pcmdinfo)
{
	int status = 0;
	unsigned long flags;

	spin_lock_irqsave(&dev->cqp_lock, flags);
	if (list_empty(&dev->cqp_cmd_head) && !irdma_cqp_ring_full(dev->cqp))
		status = irdma_exec_cqp_cmd(dev, pcmdinfo);
	else
		list_add_tail(&pcmdinfo->cqp_cmd_entry, &dev->cqp_cmd_head);
	pcmdinfo->cqp_cmd_exec_status = status;
	spin_unlock_irqrestore(&dev->cqp_lock, flags);
	return status;
}

/**
 * irdma_process_bh - called from tasklet for cqp list
 * @dev: sc device struct
 */
void irdma_process_bh(struct irdma_sc_dev *dev)
{
	int status = 0;
	struct cqp_cmds_info *pcmdinfo;
	unsigned long flags;

	spin_lock_irqsave(&dev->cqp_lock, flags);
	while (!list_empty(&dev->cqp_cmd_head) &&
	       !irdma_cqp_ring_full(dev->cqp)) {
		pcmdinfo = (struct cqp_cmds_info *)irdma_remove_cqp_head(dev);
		status = irdma_exec_cqp_cmd(dev, pcmdinfo);
		if (status)
			pcmdinfo->cqp_cmd_exec_status = status;
	}
	spin_unlock_irqrestore(&dev->cqp_lock, flags);
}

#if IS_ENABLED(CONFIG_CONFIGFS_FS)
/**
 * irdma_set_irq_rate_limit- Configure interrupt rate limit
 * @dev: pointer to the device structure
 * @idx: vector index
 * @interval: Time interval in 4 usec units. Zero for no limit.
 */
void irdma_set_irq_rate_limit(struct irdma_sc_dev *dev, u32 idx, u32 interval)
{
	u32 reg_val = 0;

	if (interval) {
#define IRDMA_MAX_SUPPORTED_INT_RATE_INTERVAL 59 /* 59 * 4 = 236 us */
		if (interval > IRDMA_MAX_SUPPORTED_INT_RATE_INTERVAL)
			interval = IRDMA_MAX_SUPPORTED_INT_RATE_INTERVAL;
		reg_val = interval & IRDMA_GLINT_RATE_INTERVAL;
		reg_val |= FIELD_PREP(IRDMA_GLINT_RATE_INTRL_ENA, 1);
	}
	writel(reg_val, dev->hw_regs[IRDMA_GLINT_RATE] + idx);
}

#endif
/**
 * irdma_cfg_aeq- Configure AEQ interrupt
 * @dev: pointer to the device structure
 * @idx: vector index
 * @enable: True to enable, False disables
 */
void irdma_cfg_aeq(struct irdma_sc_dev *dev, u32 idx, bool enable)
{
	u32 reg_val;

	reg_val = FIELD_PREP(IRDMA_PFINT_AEQCTL_CAUSE_ENA, enable) |
		  FIELD_PREP(IRDMA_PFINT_AEQCTL_MSIX_INDX, idx) |
		  FIELD_PREP(IRDMA_PFINT_AEQCTL_ITR_INDX, IRDMA_IDX_NOITR);

	writel(reg_val, dev->hw_regs[IRDMA_PFINT_AEQCTL]);
}

/**
 * sc_vsi_update_stats - Update statistics
 * @vsi: sc_vsi instance to update
 */
void sc_vsi_update_stats(struct irdma_sc_vsi *vsi)
{
	struct irdma_dev_hw_stats *hw_stats = &vsi->pestat->hw_stats;
	struct irdma_gather_stats *gather_stats =
		vsi->pestat->gather_info.gather_stats_va;
	struct irdma_gather_stats *last_gather_stats =
		vsi->pestat->gather_info.last_gather_stats_va;
	const struct irdma_hw_stat_map *map = vsi->dev->hw_stats_map;
	u16 max_stat_idx = vsi->dev->hw_attrs.max_stat_idx;
	u16 i;

	if (vsi->dev->hw_attrs.uk_attrs.hw_rev >= IRDMA_GEN_3) {
		for (i = 0; i < max_stat_idx; i++) {
			u16 idx = map[i].byteoff / sizeof(u64);

			hw_stats->stats_val[i] = gather_stats->val[idx];
		}
		return;
	}

	irdma_update_stats(hw_stats, gather_stats, last_gather_stats,
			   map, max_stat_idx);
}

/**
 * irdma_wait_pe_ready - Check if firmware is ready
 * @dev: provides access to registers
 */
static int irdma_wait_pe_ready(struct irdma_sc_dev *dev)
{
	u32 statuscpu0;
	u32 statuscpu1;
	u32 statuscpu2;
	u32 retrycount = 0;

	do {
		statuscpu0 = readl(dev->hw_regs[IRDMA_GLPE_CPUSTATUS0]);
		statuscpu1 = readl(dev->hw_regs[IRDMA_GLPE_CPUSTATUS1]);
		statuscpu2 = readl(dev->hw_regs[IRDMA_GLPE_CPUSTATUS2]);
		if (statuscpu0 == 0x80 && statuscpu1 == 0x80 &&
		    statuscpu2 == 0x80)
			return 0;
		mdelay(100);
	} while (retrycount++ < dev->hw_attrs.max_pe_ready_count);
	return -1;
}

/**
 * irdma_set_attr_from_fragcnt
 * @dev: Device pointer
 * @max_fragcnt: maximum fragment count
 *
 * configure device attributes given a fragment count limit
 */
int irdma_set_attr_from_fragcnt(struct irdma_sc_dev *dev, u8 max_fragcnt)
{
	int ret;
	u32 max_inline;
	u16 max_wqesz, max_quanta_per_wr;

	if (dev->hw_attrs.uk_attrs.hw_rev == IRDMA_GEN_1)
		return -EOPNOTSUPP;

	/* Compute the max wqe block size applicable to both queues */
	ret = irdma_fragcnt_to_wqesize_rq(max_fragcnt + 1, &max_wqesz);
	if (ret)
		return ret;

	/* auto-correct max inline we support to fit in the computed max wqe block */
	max_inline = dev->hw_attrs.uk_attrs.max_hw_inline;
	switch (max_wqesz) {
	case 32:
		if (max_inline > 8)
			max_inline = 8;
		break;
	case 64:
		if (max_inline > 39)
			max_inline = 39;
		break;
	case 128:
		if (max_inline > 101)
			max_inline = 101;
		break;
	case 256:
	default:
		break;
	}

	max_quanta_per_wr = max_wqesz / IRDMA_QP_WQE_MIN_SIZE;
	dev->hw_attrs.uk_attrs.max_hw_wq_frags = max_fragcnt;
	dev->hw_attrs.uk_attrs.max_hw_read_sges = max_fragcnt;
	dev->hw_attrs.uk_attrs.max_hw_inline = max_inline;
	dev->hw_attrs.max_qp_wr = IRDMA_MAX_QP_WRS(max_quanta_per_wr);

	return 0;
}

static inline void irdma_sc_init_hw(struct irdma_sc_dev *dev)
{
	switch (dev->hw_attrs.uk_attrs.hw_rev) {
	case IRDMA_GEN_1:
		i40iw_init_hw(dev);
		break;
	case IRDMA_GEN_2:
		icrdma_init_hw(dev);
		break;
	case IRDMA_GEN_3:
	case IRDMA_GEN_4:
		ig3rdma_init_hw(dev);
		break;
	}
}

/**
 * irdma_sc_dev_init - Initialize control part of device
 * @dev: Device pointer
 * @info: Device init info
 */
int irdma_sc_dev_init(struct irdma_sc_dev *dev, struct irdma_device_init_info *info)
{
	u32 val;
	int ret_code = 0;
	u8 db_size;

	INIT_LIST_HEAD(&dev->cqp_cmd_head); /* for CQP command backlog */
	mutex_init(&dev->ws_mutex);
	dev->hmc_fn_id = info->hmc_fn_id;
	dev->num_vfs = info->max_vfs;
	dev->fpm_query_buf_pa = info->fpm_query_buf_pa;
	dev->fpm_query_buf = info->fpm_query_buf;
	dev->fpm_commit_buf_pa = info->fpm_commit_buf_pa;
	dev->fpm_commit_buf = info->fpm_commit_buf;
	dev->hw = info->hw;
	dev->hw->hw_addr = info->bar0;
	dev->protocol_used = info->protocol_used;
	/* Setup the hardware limits, hmc may limit further */
	dev->hw_attrs.min_hw_qp_id = IRDMA_MIN_IW_QP_ID;
	dev->hw_attrs.min_hw_srq_id = IRDMA_MIN_IW_SRQ_ID;
	dev->hw_attrs.min_hw_aeq_size = IRDMA_MIN_AEQ_ENTRIES;

		if (dev->hw_attrs.uk_attrs.hw_rev >= IRDMA_GEN_3)
			dev->hw_attrs.max_hw_aeq_size = IRDMA_MAX_AEQ_ENTRIES_GEN_3;
		else
			dev->hw_attrs.max_hw_aeq_size = IRDMA_MAX_AEQ_ENTRIES;
	dev->hw_attrs.min_hw_ceq_size = IRDMA_MIN_CEQ_ENTRIES;
	dev->hw_attrs.max_hw_ceq_size = IRDMA_MAX_CEQ_ENTRIES;
	dev->hw_attrs.uk_attrs.min_hw_cq_size = IRDMA_MIN_CQ_SIZE;
	dev->hw_attrs.uk_attrs.max_hw_cq_size = IRDMA_MAX_CQ_SIZE;
	dev->hw_attrs.max_hw_outbound_msg_size = IRDMA_MAX_OUTBOUND_MSG_SIZE;
	dev->hw_attrs.max_mr_size = IRDMA_MAX_MR_SIZE;
	dev->hw_attrs.max_hw_inbound_msg_size = IRDMA_MAX_INBOUND_MSG_SIZE;
	dev->hw_attrs.uk_attrs.max_hw_inline = IRDMA_MAX_INLINE_DATA_SIZE;
	dev->hw_attrs.max_hw_wqes = IRDMA_MAX_WQ_ENTRIES;
	dev->hw_attrs.max_qp_wr = IRDMA_MAX_QP_WRS(IRDMA_MAX_QUANTA_PER_WR);

	dev->hw_attrs.uk_attrs.max_hw_rq_quanta = IRDMA_QP_SW_MAX_RQ_QUANTA;
	dev->hw_attrs.uk_attrs.max_hw_wq_quanta = IRDMA_QP_SW_MAX_WQ_QUANTA;
	dev->hw_attrs.max_hw_pds = IRDMA_MAX_PDS;
	dev->hw_attrs.max_hw_ena_vf_count = IRDMA_MAX_PE_ENA_VF_COUNT;

	dev->hw_attrs.max_pe_ready_count = 14;
	dev->hw_attrs.max_done_count = IRDMA_DONE_COUNT;
	dev->hw_attrs.max_sleep_count = IRDMA_SLEEP_COUNT;
	dev->hw_attrs.max_cqp_compl_wait_time_ms = CQP_COMPL_WAIT_TIME_MS;

	if (!dev->privileged) {
		ret_code = irdma_vchnl_req_get_hmc_fcn(dev);
		if (ret_code) {
			ibdev_dbg(to_ibdev(dev),
				  "DEV: Get HMC function ret = %d\n",
				  ret_code);

			return ret_code;
		}
		if (FIELD_GET(IRDMA_MULTI_QS_BIT, dev->vc_caps.feature_cap)) {
			ret_code = irdma_vchnl_req_get_multi_qs(dev);
			if (ret_code)
				ibdev_dbg(to_ibdev(dev),
					  "DEV: ERR: Get MULTI QS ret = %d\n",
					  ret_code);
		}
	}

	spin_lock_init(&dev->vc_dev_lock);
	irdma_sc_init_hw(dev);

	if (dev->privileged) {
		if (irdma_wait_pe_ready(dev))
			return -ETIMEDOUT;

		val = readl(dev->hw_regs[IRDMA_GLPCI_LBARCTRL]);
		if (dev->hw_attrs.uk_attrs.hw_rev <= IRDMA_GEN_2) {
			db_size = (u8)FIELD_GET(IRDMA_GLPCI_LBARCTRL_PE_DB_SIZE, val);
			if (db_size != IRDMA_PE_DB_SIZE_4M &&
			    db_size != IRDMA_PE_DB_SIZE_8M) {
				ibdev_dbg(to_ibdev(dev),
					  "DEV: RDMA PE doorbell is not enabled in CSR val 0x%x db_size=%d\n",
					  val, db_size);
				return -ENODEV;
			}
		}
	} else if (dev->hw_attrs.uk_attrs.hw_rev >= IRDMA_GEN_3) {
		ret_code = irdma_vchnl_req_get_reg_layout(dev);
		if (ret_code)
			ibdev_dbg(to_ibdev(dev),
				  "DEV: Get Register layout failed ret = %d\n",
				  ret_code);
	}

	return ret_code;
}

/**
 * irdma_stat_val - Extract HW counter value from statistics buffer
 * @stats_val: pointer to statistics buffer
 * @byteoff: byte offset of counter value in the buffer (8B-aligned)
 * @bitoff: bit offset of counter value within 8B entry
 * @bitmask: maximum counter value (e.g. 0xffffff for 24-bit counter)
 */
static inline u64 irdma_stat_val(const u64 *stats_val, u16 byteoff,
				 u8 bitoff, u64 bitmask)
{
	u16 idx = byteoff / sizeof(*stats_val);

	return (stats_val[idx] >> bitoff) & bitmask;
}

/**
 * irdma_stat_delta - Calculate counter delta
 * @new_val: updated counter value
 * @old_val: last counter value
 * @max_val: maximum counter value (e.g. 0xffffff for 24-bit counter)
 */
static inline u64 irdma_stat_delta(u64 new_val, u64 old_val, u64 max_val)
{
	if (new_val >= old_val)
		return new_val - old_val;

	/* roll-over case */
	return max_val - old_val + new_val + 1;
}

/**
 * irdma_update_stats - Update statistics
 * @hw_stats: hw_stats instance to update
 * @gather_stats: updated stat counters
 * @last_gather_stats: last stat counters
 * @map: HW stat map (hw_stats => gather_stats)
 * @max_stat_idx: number of HW stats
 */
void irdma_update_stats(struct irdma_dev_hw_stats *hw_stats,
			struct irdma_gather_stats *gather_stats,
			struct irdma_gather_stats *last_gather_stats,
			const struct irdma_hw_stat_map *map,
			u16 max_stat_idx)
{
	u64 *stats_val = hw_stats->stats_val;
	u16 i;

	for (i = 0; i < max_stat_idx; i++) {
		u64 new_val = irdma_stat_val(gather_stats->val,
					     map[i].byteoff, map[i].bitoff,
					     map[i].bitmask);
		u64 last_val = irdma_stat_val(last_gather_stats->val,
					      map[i].byteoff, map[i].bitoff,
					      map[i].bitmask);

		stats_val[i] += irdma_stat_delta(new_val, last_val,
						 map[i].bitmask);
	}

	memcpy(last_gather_stats, gather_stats,
		     sizeof(*last_gather_stats));
}

void mev_enable_hw_wa(struct irdma_sc_dev *dev, u64 hw_wa,
		      u32 wa_mem_pages, u32 wa_bitmask,
		      bool host_mem_mrte)
{
	if (hw_wa == 0xFFFF) {
		dev->hw_wa = (u64)wa_bitmask;
		goto exit;
	}

	switch (hw_wa) {
	case NRB_A0_04:
	case MEV_B0_34:
		dev->hw_wa |= CCQ_CQ3_POLL |
			      NO_CQACK |
			      NO_CEQMASK |
			      NO_LPB |
			      IGNORE_OOO |
			      REDUCE_ORD_IRD |
			      MAX_QP_2K |
			      CQ_NO_CHECKFLOW;
		break;
	case MEV_C0_45:
		if (dev->hw_attrs.uk_attrs.hw_rev == IRDMA_GEN_4)
			dev->hw_wa |= REDUCE_ORD_IRD;
		break;
	case MMG_DEV_00:
		dev->hw_wa |= REDUCE_ORD_IRD |
			      MMG_WA;
		break;
	case MEV_B0_37:
	case MEV_B0_39:
		dev->hw_wa |= AEQ_POLL |
			      NO_CQACK |
			      NO_CEQMASK |
			      NO_LPB |
			      IGNORE_OOO |
			      LOC_MEM_WA |
			      REDUCE_ORD_IRD |
			      NO_STAG0 |
			      CQ_NO_CHECKFLOW;
		break;
	case SIMICS_42:
		dev->hw_wa |= LOC_MEM_WA |
			      REDUCE_ORD_IRD_SIMICS |
			      STAG_ACC_RIGHTS |
			      CQP_COMPL_WAIT |
			      MSIX_SHARED;
		break;
	default:
		ibdev_dbg(to_ibdev(dev), "INIT: only atomics are enabled\n");
		break;
	}

exit:
	dev->hw_wa |= CQP_COMPL_WAIT;
	ibdev_dbg(to_ibdev(dev), "INIT: HW Workarounds set 0x%llx\n",
		  dev->hw_wa);

	if (wa_mem_pages || dev->hw_wa & LOC_MEM_WA)
		dev->wa_mem_pages = wa_mem_pages ? wa_mem_pages : 256;

	dev->host_mem_mrte = host_mem_mrte;
}

