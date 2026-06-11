// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2015 - 2024 Intel Corporation */

#include "main.h"
#include "iidc.h"
/* TODO: Adding this here is not ideal. Can we remove this warning now? */
#include "icrdma_hw.h"

/* Used for testing in CNV */
extern bool mod_rdpu_bw;

static void icrdma_prep_tc_change(struct irdma_device *iwdev)
{
	iwdev->vsi.tc_change_pending = true;
	irdma_sc_suspend_resume_qps(&iwdev->vsi, IRDMA_OP_SUSPEND);

	/* Wait for all qp's to suspend */
	wait_event_timeout(iwdev->suspend_wq,
			   !atomic_read(&iwdev->vsi.qp_suspend_reqs),
			   msecs_to_jiffies(IRDMA_EVENT_TIMEOUT_MS));
	irdma_ws_reset(&iwdev->vsi);
}

static void icrdma_fill_qos_info(struct irdma_l2params *l2params,
				 struct iidc_qos_params *qos_info)
{
	int i;

	l2params->num_tc = qos_info->num_tc;
	l2params->vsi_prio_type = qos_info->vport_priority_type;
	l2params->vsi_rel_bw = qos_info->vport_relative_bw;
	for (i = 0; i < l2params->num_tc; i++) {
		l2params->tc_info[i].egress_virt_up =
			qos_info->tc_info[i].egress_virt_up;
		l2params->tc_info[i].ingress_virt_up =
			qos_info->tc_info[i].ingress_virt_up;
		l2params->tc_info[i].prio_type = qos_info->tc_info[i].prio_type;
		l2params->tc_info[i].rel_bw = qos_info->tc_info[i].rel_bw;
		l2params->tc_info[i].tc_ctx = qos_info->tc_info[i].tc_ctx;
	}
	for (i = 0; i < IIDC_MAX_USER_PRIORITY; i++)
		l2params->up2tc[i] = qos_info->up2tc[i];
	if (qos_info->pfc_mode == IIDC_DSCP_PFC_MODE) {
		l2params->dscp_mode = true;
		memcpy(l2params->dscp_map, qos_info->dscp_map,
		       sizeof(l2params->dscp_map));
	}
}


/*
 * icrdma_lan_register_qset - Register qsets with LAN driver
 * @vsi: vsi structure
 * @tc_node1: List of Traffic class node ponters
 * @tc_node2: List of Traffic class node ponters
 */
static int icrdma_lan_register_qset(struct irdma_sc_vsi *vsi,
				    struct irdma_ws_node *tc_node1,
				    struct irdma_ws_node *tc_node2)
{
	struct irdma_device *iwdev = vsi->back_vsi;
	struct iidc_core_dev_info *cdev_info = iwdev->rf->cdev;
	int ret;

	if (tc_node2) {
		struct iidc_rdma_multi_qset_params mqset = { };

		mqset.qs_handle[0] = tc_node1->qs_handle;
		mqset.qs_handle[1] = tc_node2->qs_handle;
		mqset.tc = tc_node2->traffic_class;
		mqset.vport_id = vsi->vsi_idx;
		mqset.num = 2;
		ret = cdev_info->ops->alloc_multi_res(cdev_info, &mqset);
		if (ret) {
			irdma_rblog_ibdev_warn(&iwdev->ibdev,
					       "WS: LAN alloc_multi_res for rdma qset failed.\n");
			/* return ret; Ignore return code since RDMA still works when it fails, until ICE is debugged */
		}
		tc_node1->l2_sched_node_id = mqset.teid[0];
		tc_node2->l2_sched_node_id = mqset.teid[1];
		vsi->qos[tc_node1->user_pri].l2_sched_node_id[0] = mqset.teid[0];
		vsi->qos[tc_node1->user_pri].l2_sched_node_id[1] = mqset.teid[1];
	} else {
		struct iidc_rdma_qset_params qset = { };

		qset.qs_handle = tc_node1->qs_handle;
		qset.tc = tc_node1->traffic_class;
		qset.vport_id = vsi->vsi_idx;
		ret = cdev_info->ops->alloc_res(cdev_info, &qset);
		if (ret) {
			irdma_rblog_ibdev_warn(&iwdev->ibdev,
					       "WS: LAN alloc_res for rdma qset failed.\n");
			//return ret;
		}

		tc_node1->l2_sched_node_id = qset.teid;
		vsi->qos[tc_node1->user_pri].l2_sched_node_id[0] = qset.teid;
	}
	return 0;
}

/**
 * icrdma_lan_unregister_qset - Unregister qsets with LAN driver
 * @vsi: vsi structure
 * @tc_node1: Traffic class node
 * @tc_node2: Traffic class node
 */
static void icrdma_lan_unregister_qset(struct irdma_sc_vsi *vsi,
				       struct irdma_ws_node *tc_node1,
				       struct irdma_ws_node *tc_node2)
{
	struct irdma_device *iwdev = vsi->back_vsi;
	struct iidc_core_dev_info *cdev_info = iwdev->rf->cdev;

	if (vsi->lag_aa) {
		struct iidc_rdma_multi_qset_params mqset = { };

		mqset.qs_handle[0] = tc_node1->qs_handle;
		mqset.qs_handle[1] = tc_node2->qs_handle;
		mqset.tc = tc_node1->traffic_class; /* TC is the same for both nodes */
		mqset.vport_id = vsi->vsi_idx;
		mqset.num = 2;
		mqset.teid[0] = tc_node1->l2_sched_node_id;
		mqset.teid[1] = tc_node2->l2_sched_node_id;
		if (cdev_info->ops->free_multi_res(cdev_info, &mqset))
			irdma_rblog_ibdev_warn(&iwdev->ibdev,
					       "WS: LAN free_res for rdma qset failed.\n");
	} else {
		struct iidc_rdma_qset_params qset = { };
		struct irdma_ws_node *tc_node = tc_node1 ? tc_node1 : tc_node2;

		qset.qs_handle = tc_node->qs_handle;
		qset.tc = tc_node->traffic_class;
		qset.vport_id = vsi->vsi_idx;
		qset.teid = tc_node->l2_sched_node_id;

		if (cdev_info->ops->free_res(cdev_info, &qset))
			irdma_rblog_ibdev_warn(&iwdev->ibdev,
					       "WS: LAN free_res for rdma qset failed.\n");
	}
}

/**
 * icrdma_request_reset - Request a reset
 * @rf: RDMA PCI function
 */
static void icrdma_request_reset(struct irdma_pci_f *rf)
{
	struct iidc_core_dev_info *cdev_info = rf->cdev;

	irdma_rblog_ibdev_warn(&rf->iwdev->ibdev, "Requesting a reset\n");
	rf->sc_dev.vchnl_up = false;
	cdev_info->ops->request_reset(rf->cdev, IIDC_CORER);
}

static struct irdma_vchnl_if irdma_vchnl_if_pf = {
	.vchnl_recv = irdma_vchnl_recv_pf,
};

static struct irdma_vchnl_if irdma_vchnl_if_req = {
	.vchnl_recv = irdma_vchnl_req_recv,
};

static int icrdma_vchnl_init(struct irdma_pci_f *rf,
			     struct iidc_core_dev_info *cdev_info, u8 *rdma_ver)
{
	struct irdma_vchnl_init_info virt_info = {};
	u8 gen = *rdma_ver;
	int ret;

	rf->vchnl_wq = alloc_ordered_workqueue("irdma-virtchnl-wq", 0);
	if (!rf->vchnl_wq)
		return -ENOMEM;

	mutex_init(&rf->sc_dev.vchnl_mutex);

	virt_info.hw_rev = gen;
	virt_info.is_pf = !cdev_info->ftype;

	if (cdev_info->ftype)
		virt_info.privileged = false;
	else
		virt_info.privileged = true;
	virt_info.vchnl_if = virt_info.privileged ? &irdma_vchnl_if_pf :
						    &irdma_vchnl_if_req;
	virt_info.vchnl_wq = rf->vchnl_wq;
	ret = irdma_sc_vchnl_init(&rf->sc_dev, &virt_info);
	if (ret) {
		destroy_workqueue(rf->vchnl_wq);
		return ret;
	}

	*rdma_ver = rf->sc_dev.hw_attrs.uk_attrs.hw_rev;
	return 0;
}

static void irdma_modify_rdpu_bw(struct irdma_pci_f *rf)
{
	u32 val;
#define GL_RDPU_CNTRL   0x00052054

	val = rd32(&rf->hw, GL_RDPU_CNTRL);
	irdma_rblog_dev_warn(rf->hw.device, "Read GL_RDPU_CNTRL[%x] = 0x%08X",
			     GL_RDPU_CNTRL, val);

	/* Clear the load balancing bit */
	val &= ~(0x1 << 2);
	wr32(&rf->hw, GL_RDPU_CNTRL, val);
	val = rd32(&rf->hw, GL_RDPU_CNTRL);
	irdma_rblog_dev_warn(rf->hw.device, "Set GL_RDPU_CNTRL[%x] = 0x%08X",
			     GL_RDPU_CNTRL, val);
}

static int icrdma_fill_device_info(struct irdma_device *iwdev,
				   struct iidc_core_dev_info *cdev_info)
{
	struct irdma_pci_f *rf = iwdev->rf;
	int err;

	rf->sc_dev.hw = &rf->hw;
	rf->iwdev = iwdev;
	rf->cdev = cdev_info;
	rf->hw.hw_addr = cdev_info->hw_addr;
	rf->pcidev = cdev_info->pdev;
	rf->hw.device = &rf->pcidev->dev;
	rf->rdma_ver = IRDMA_GEN_2;
	rf->ftype = cdev_info->ftype;
	rf->msix_count = cdev_info->msix_count;
	rf->msix_entries = cdev_info->msix_entries;

	err = icrdma_vchnl_init(rf, cdev_info, &rf->rdma_ver);
	if (err)
		return err;

	if (!cdev_info->ftype && cdev_info->ver.major == 10 &&
	    cdev_info->ver.minor == 0) {
		u32 val;
#define PF_FUNC_RID 0x0009E880
#define PF_FUNC_RID_FUNCTION_NUMBER GENMASK(2, 0)
		rf->hw.hw_addr = cdev_info->hw_addr;
		val = rd32(&rf->hw, PF_FUNC_RID);
		rf->pf_id = (u8)FIELD_GET(PF_FUNC_RID_FUNCTION_NUMBER, val);
	} else {
		rf->pf_id = cdev_info->pf_id;
	}

	if (!cdev_info->ftype) {
		rf->gen_ops.register_qset = icrdma_lan_register_qset;
		rf->gen_ops.unregister_qset = icrdma_lan_unregister_qset;
	}

	rf->default_vsi.vsi_idx = cdev_info->vport_id;
	rf->protocol_used = cdev_info->rdma_protocol == IIDC_RDMA_PROTOCOL_ROCEV2 ?
			    IRDMA_ROCE_PROTOCOL_ONLY : IRDMA_IWARP_PROTOCOL_ONLY;
	rf->rsrc_profile = IRDMA_HMC_PROFILE_DEFAULT;
	rf->check_fc = irdma_check_fc_for_qp;
	rf->gen_ops.request_reset = icrdma_request_reset;
	/* Can override limits_sel, protocol_used */
	irdma_set_rf_user_cfg_params(rf);
	mutex_init(&iwdev->ah_tbl_lock);
	spin_lock_init(&iwdev->ah_nosleep_tbl_lock);

	rcu_read_lock();
	iwdev->netdev =  netdev_master_upper_dev_get_rcu(cdev_info->netdev);
	rcu_read_unlock();
	if (!iwdev->netdev || cdev_info->rdma_active_port ==
	    IIDC_RDMA_INVALID_PORT) {
		iwdev->netdev = cdev_info->netdev;
	} else {
		if (rf->protocol_used != IRDMA_ROCE_PROTOCOL_ONLY) {
			irdma_rblog_dev_err(rf->hw.device,
					    "LAG is only supported in RoCEv2 mode.\n");
			return -EINVAL;
		}

		if (cdev_info->ver.major >= 10 && cdev_info->ver.minor >= 3)
			iwdev->lag_mode = cdev_info->bond_aa ?
					IRDMA_LAG_ACTIVE_ACTIVE :
					IRDMA_LAG_ACTIVE_PASSIVE;
		else
			iwdev->lag_mode = IRDMA_LAG_ACTIVE_PASSIVE;
	}
	iwdev->vsi_num = cdev_info->vport_id;
	iwdev->init_state = INITIAL_STATE;
	iwdev->roce_cwnd = IRDMA_ROCE_CWND_DEFAULT;
	iwdev->roce_ackcreds = IRDMA_ROCE_ACKCREDS_DEFAULT;
	iwdev->rcv_wnd = IRDMA_CM_DEFAULT_RCV_WND_SCALED;
	iwdev->rcv_wscale = IRDMA_CM_DEFAULT_RCV_WND_SCALE;
#if IS_ENABLED(CONFIG_CONFIGFS_FS)
	iwdev->iwarp_ecn_en = iwdev->rf->rdma_ver == IRDMA_GEN_2 ? true : false;
	iwdev->iwarp_rtomin = 5;
	iwdev->up_up_map = IRDMA_DEFAULT_UP_UP_MAP;
#endif
	if (iwdev->rf->protocol_used != IRDMA_IWARP_PROTOCOL_ONLY) {
		iwdev->roce_rtomin = 5;
		iwdev->roce_dcqcn_en = iwdev->rf->dcqcn_ena;
		iwdev->roce_mode = true;
	}

	iwdev->rf->sc_dev.periodic_flush = false;

	irdma_rblog_dev_info(rf->hw.device, "%s: iwdev->lag_mode = %d\n",
			     __func__, iwdev->lag_mode);
	return 0;
}

/**
 * icrdma_failover_start - Handle failover start
 * @iwdev: rdma device
 * @failing_port: Port number failing
 **/
static void icrdma_failover_start(struct irdma_device *iwdev, u8 failing_port)
{
	iwdev->vsi.failover_pending = true;
	irdma_ws_failover_cmd(&iwdev->vsi, IRDMA_OP_WS_FAILOVER_START, failing_port, 0);
}

/**
 * icrdma_failover_complete - Handle fail over complete
 * @iwdev: rdma device structure
 * @failing_port: Port number failing
 * @active_port: fail_over_port number
 **/
static void icrdma_failover_complete(struct irdma_device *iwdev, u8 failing_port, u8 active_port)
{
	if (iwdev->vsi.lag_aa)
		irdma_ws_move_cmd(&iwdev->vsi);
	else
		irdma_ws_failover_cmd(&iwdev->vsi,
				      IRDMA_OP_WS_FAILOVER_COMPLETE,
				      failing_port, active_port);
	iwdev->vsi.failover_pending = false;
}

static void irdma_free_one_vf(struct irdma_vchnl_dev *vc_dev)
{
	struct irdma_sc_dev *dev = vc_dev->pf_dev;

	if (vc_dev->vf_vsi)
		irdma_ws_reset(vc_dev->vf_vsi);
	irdma_del_hmc_objects(dev, &vc_dev->hmc_info, true, false,
			      dev->hw_attrs.uk_attrs.hw_rev);
	irdma_pf_put_vf_hmc_fcn(dev, vc_dev);
}

static void irdma_free_all_vf_rsrc(struct irdma_sc_dev *dev)
{
	u16 vf_idx;

	for (vf_idx = 0; vf_idx < dev->num_vfs; vf_idx++) {
		if (dev->vc_dev[vf_idx])
			irdma_free_one_vf(dev->vc_dev[vf_idx]);
	}
}

static void icrdma_iidc_event_handler(struct iidc_core_dev_info *cdev_info,
				      struct iidc_event *event)
{
	struct irdma_device *iwdev = dev_get_drvdata(&cdev_info->adev->dev);

	struct irdma_l2params l2params = {};

	if (!iwdev || iwdev->rf->reset)
		return;

	if (*event->type & BIT(IIDC_EVENT_AFTER_MTU_CHANGE)) {
		irdma_rblog_ibdev_dbg(&iwdev->ibdev, "CLNT: new MTU = %d\n",
				      iwdev->netdev->mtu);
		if (iwdev->vsi.mtu != iwdev->netdev->mtu) {
			l2params.mtu = iwdev->netdev->mtu;
			l2params.mtu_changed = true;
			irdma_log_invalid_mtu(l2params.mtu, &iwdev->rf->sc_dev);
			if (iwdev->vsi.tc_change_pending) {
				iwdev->vsi.mtu_change_pending = true;
				iwdev->vsi.mtu = iwdev->netdev->mtu;
				return;
			}
			irdma_change_l2params(&iwdev->vsi, &l2params);
		}
	} else if (*event->type & BIT(IIDC_EVENT_VF_RESET)) {
		struct irdma_sc_dev *dev = &iwdev->rf->sc_dev;
		struct irdma_vchnl_dev *vc_dev =
			irdma_find_vc_dev(dev, event->info.vf_id);

		if (vc_dev) {
			vc_dev->reset_en = true;
			irdma_free_one_vf(vc_dev);
			irdma_put_vfdev(dev, vc_dev);
		}
	} else if (*event->type & BIT(IIDC_EVENT_BEFORE_TC_CHANGE)) {
		if (iwdev->vsi.tc_change_pending)
			return;

		icrdma_prep_tc_change(iwdev);
	} else if (*event->type & BIT(IIDC_EVENT_AFTER_TC_CHANGE)) {

		if (!iwdev->vsi.tc_change_pending)
			return;

		if (iwdev->vsi.mtu_change_pending) {
			iwdev->vsi.mtu_change_pending = false;
			l2params.mtu = iwdev->vsi.mtu;
			l2params.mtu_changed = true;
		}

		l2params.tc_changed = true;
		irdma_rblog_ibdev_dbg(&iwdev->ibdev, "CLNT: TC Change\n");

		icrdma_fill_qos_info(&l2params, &cdev_info->qos_info);
		if (iwdev->rf->protocol_used != IRDMA_IWARP_PROTOCOL_ONLY)
			iwdev->dcb_vlan_mode =
				l2params.num_tc > 1 && !l2params.dscp_mode;
		if (iwdev->rf->sc_dev.privileged)
			irdma_check_fc_for_tc_update(&iwdev->vsi, &l2params);
		irdma_change_l2params(&iwdev->vsi, &l2params);
	} else if (*event->type & BIT(IIDC_EVENT_FAILOVER_START) && iwdev->lag_mode) {
		irdma_rblog_ibdev_dbg(&iwdev->ibdev,
				      "CLNT: IIDC_EVENT_FAILOVER_START: rdma_port = [%d, %d], bitmap = 0x%x, failing_port=%d\n",
				      cdev_info->rdma_ports[0],
				      cdev_info->rdma_ports[1],
				      cdev_info->rdma_port_bitmap,
				      cdev_info->rdma_active_port);
		icrdma_failover_start(iwdev, cdev_info->rdma_active_port);
	} else if (*event->type & BIT(IIDC_EVENT_FAILOVER_FINISH)) {
		if (iwdev->lag_mode == IRDMA_LAG_ACTIVE_ACTIVE) {
			irdma_rblog_ibdev_dbg(&iwdev->ibdev,
					      "CLNT: IIDC_EVENT_FAILOVER_FINISH ports[1][2] = %d %d, bitmap = 0x%x\n",
					      cdev_info->rdma_ports[0],
					      cdev_info->rdma_ports[1],
					      cdev_info->rdma_port_bitmap);
			iwdev->vsi.lag_ports[0] = cdev_info->rdma_ports[0];
			iwdev->vsi.lag_ports[1] = cdev_info->rdma_ports[1];
			iwdev->vsi.lag_port_bitmap = cdev_info->rdma_port_bitmap;
		}
		icrdma_failover_complete(iwdev, 0, cdev_info->rdma_active_port);
	} else if (*event->type & BIT(IIDC_EVENT_CRIT_ERR)) {
		irdma_rblog_ibdev_warn(&iwdev->ibdev,
				       "ICE OICR event notification: oicr = 0x%08x\n",
				       event->info.reg);
		if (event->info.reg & IRDMAPFINT_OICR_PE_CRITERR_M) {
			u32 pe_criterr;

			pe_criterr = readl(iwdev->rf->sc_dev.hw_regs[IRDMA_GLPE_CRITERR]);
#define IRDMA_Q1_RESOURCE_ERR 0x0001024d
			if (pe_criterr != IRDMA_Q1_RESOURCE_ERR) {
				irdma_rblog_ibdev_err(&iwdev->ibdev,
						      "critical PE Error, GLPE_CRITERR=0x%08x\n",
						      pe_criterr);
				iwdev->rf->reset = true;
			} else {
				irdma_rblog_ibdev_warn(&iwdev->ibdev,
						       "Q1 Resource Check\n");
			}
		}
		if (event->info.reg & IRDMAPFINT_OICR_HMC_ERR_M) {
			irdma_rblog_ibdev_err(&iwdev->ibdev, "HMC Error\n");
			iwdev->rf->reset = true;
		}
		if (event->info.reg & IRDMAPFINT_OICR_PE_PUSH_M) {
			irdma_rblog_ibdev_err(&iwdev->ibdev,
					      "PE Push Error\n");
			iwdev->rf->reset = true;
		}
		if (iwdev->rf->reset)
			iwdev->rf->gen_ops.request_reset(iwdev->rf);
	} else if (*event->type & BIT(IIDC_EVENT_WARN_RESET)) {
		if (iwdev->rf->rdma_ver == IRDMA_GEN_2 && iwdev->rf->sc_dev.privileged)
			iwdev->rf->sc_dev.vchnl_up = false;
		irdma_rblog_ibdev_warn(&iwdev->ibdev, "Event warn reset");
		iwdev->rf->reset = true;
	}
}


static int icrdma_probe(struct auxiliary_device *aux_dev, const struct auxiliary_device_id *id)
{
	struct iidc_auxiliary_dev *iidc_adev = container_of(aux_dev,
							    struct iidc_auxiliary_dev,
							    adev);
	struct iidc_core_dev_info *cdev_info = iidc_adev->cdev_info;
	struct irdma_l2params l2params = {};
	struct irdma_device *iwdev;
	struct irdma_pci_f *rf;
	int err;
	struct irdma_handler *hdl;

#define MIN_COMPATIBLE_IIDC_MAJOR_VER (11)
	if (cdev_info->ver.major < MIN_COMPATIBLE_IIDC_MAJOR_VER) {
		irdma_rblog_pr_info("irdma: RDMA/LAN interface version mismatch (Expected %0d.%0d Received %0d.%0d). Unable to initialize RDMA.\n",
				    IIDC_MAJOR_VER, IIDC_MINOR_VER,
				    cdev_info->ver.major,
				    cdev_info->ver.minor);
		irdma_rblog_pr_info("irdma: Please update both LAN and RDMA drivers from same release for interface compatibility\n");
		return -EINVAL;
	}
	if (cdev_info->ver.minor != IIDC_MINOR_VER)
		irdma_rblog_pr_info("probe: minor version mismatch: expected %0d.%0d caller specified %0d.%0d\n",
				    IIDC_MAJOR_VER, IIDC_MINOR_VER,
				    cdev_info->ver.major,
				    cdev_info->ver.minor);
	irdma_rblog_pr_info("probe: cdev_info=%p, cdev_info->dev.aux_dev.bus->number=%d, cdev_info->rdma_active_port=0x%x netdev=%s\n",
			    cdev_info, cdev_info->pdev->bus->number,
			    cdev_info->rdma_active_port,
			    netdev_name(cdev_info->netdev));
	iwdev = ib_alloc_device(irdma_device, ibdev);
	if (!iwdev)
		return -ENOMEM;

	spin_lock_init(&iwdev->ae_info.info_lock);

	iwdev->rf = kzalloc(sizeof(*rf), GFP_KERNEL);
	if (!iwdev->rf) {
		ib_dealloc_device(&iwdev->ibdev);
		return -ENOMEM;
	}

	err = icrdma_fill_device_info(iwdev, cdev_info);
	if (err)
		goto err_fill_devinfo;
	rf = iwdev->rf;
	iwdev->aux_dev = aux_dev;

	hdl = kzalloc(sizeof(*hdl), GFP_KERNEL);
	if (!hdl)
		goto err_hdl;

	hdl->iwdev = iwdev;
	iwdev->hdl = hdl;
	err = irdma_ctrl_init_hw(rf);
	if (err)
		goto err_ctrl_init;

	if (irdma_fw_major_ver(&rf->sc_dev) == 2 && mod_rdpu_bw)
		irdma_modify_rdpu_bw(rf);

	if (irdma_set_attr_from_fragcnt(&rf->sc_dev, rf->fragcnt_limit))
		irdma_rblog_dev_warn(rf->hw.device,
				     "device limit update failed for fragment count %d\n",
				     rf->fragcnt_limit);
	l2params.mtu = iwdev->netdev->mtu;
	icrdma_fill_qos_info(&l2params, &cdev_info->qos_info);
	if (rf->protocol_used != IRDMA_IWARP_PROTOCOL_ONLY)
		iwdev->dcb_vlan_mode = l2params.num_tc > 1 && !l2params.dscp_mode;
	err = irdma_rt_init_hw(iwdev, &l2params);
	if (err)
		goto err_rt_init;

	if (iwdev->lag_mode == IRDMA_LAG_ACTIVE_ACTIVE) {
		irdma_rblog_dev_info(rf->hw.device,
				     "%s: cdev_info->rdma_ports[] = %d %d, rdma_port_bitmap = 0x%x\n",
				     __func__, cdev_info->rdma_ports[0],
				     cdev_info->rdma_ports[1],
				     cdev_info->rdma_port_bitmap);
		iwdev->vsi.lag_ports[0] = cdev_info->rdma_ports[0];
		iwdev->vsi.lag_ports[1] = cdev_info->rdma_ports[1];
		iwdev->vsi.lag_port_bitmap = cdev_info->rdma_port_bitmap;
	}
	err = irdma_register_notifiers(iwdev);
	if (err)
		goto err_notifier_reg;
	irdma_add_handler(hdl);
#ifdef CONFIG_DEBUG_FS
	irdma_dbg_pf_init(hdl);
#endif

	err = irdma_ib_register_device(iwdev);
	if (err)
		goto err_ibreg;

	if (rf->sc_dev.privileged)
		cdev_info->ops->update_vport_filter(
			cdev_info, iwdev->vsi_num, true);

	irdma_rblog_ibdev_dbg(&iwdev->ibdev,
			      "INIT: Gen[%d] PF[%d] device probe success\n",
			      rf->rdma_ver, PCI_FUNC(rf->pcidev->devfn));

	if (!rf->ftype &&
	    rdma_protocol_roce(&iwdev->ibdev, 1)) {
		INIT_DELAYED_WORK(&rf->dwork_cqp_poll, cqp_poll_worker);
		rf->chk_stag = irdma_create_stag(rf->iwdev);
		rf->used_mrs++;
		mod_delayed_work(iwdev->cleanup_wq, &rf->dwork_cqp_poll,
				 msecs_to_jiffies(5000));
	}

	auxiliary_set_drvdata(aux_dev, iwdev);

	return 0;

err_ibreg:
#ifdef CONFIG_DEBUG_FS
	irdma_dbg_pf_exit(iwdev->hdl);
#endif
	irdma_del_handler(iwdev->hdl);
	irdma_unregister_notifiers(iwdev);
err_notifier_reg:
	irdma_rt_deinit_hw(iwdev);
err_rt_init:
	irdma_ctrl_deinit_hw(rf);
err_ctrl_init:
	kfree(hdl);
err_hdl:
	destroy_workqueue(rf->vchnl_wq);
err_fill_devinfo:
	kfree(iwdev->rf);
	ib_dealloc_device(&iwdev->ibdev);

	return err;
}

#ifdef HAVE_AUXILIARY_DRIVER_INT_REMOVE
static int icrdma_remove(struct auxiliary_device *aux_dev)
#else /* HAVE_AUXILIARY_DRIVER_INT_REMOVE */
static void icrdma_remove(struct auxiliary_device *aux_dev)
#endif /* HAVE_AUXILIARY_DRIVER_INT_REMOVE */
{
	struct iidc_auxiliary_dev *iidc_adev = container_of(aux_dev,
							    struct iidc_auxiliary_dev,
							    adev);
	struct iidc_core_dev_info *cdev_info = iidc_adev->cdev_info;
	struct irdma_device *iwdev = auxiliary_get_drvdata(aux_dev);

	u8 rdma_ver = iwdev->rf->rdma_ver;

	if (!iwdev->rf->ftype &&
	    rdma_protocol_roce(&iwdev->ibdev, 1)) {
		cancel_delayed_work_sync(&iwdev->rf->dwork_cqp_poll);
		irdma_free_stag(iwdev->rf->iwdev, iwdev->rf->chk_stag);
	}

	if (!iwdev->rf->irdma_initiated_reset)
		iwdev->rf->reset = false;

	if (!iwdev->rf->reset) {
		if (iwdev->rf->sc_dev.privileged)
			irdma_free_all_vf_rsrc(&iwdev->rf->sc_dev);
#if IS_ENABLED(CONFIG_CONFIGFS_FS)
		if (iwdev->up_map_en) {
			struct irdma_up_info up_map_info = {};

			*((u64 *)up_map_info.map) = IRDMA_DEFAULT_UP_UP_MAP;
			up_map_info.use_cnp_up_override = false;
			up_map_info.cnp_up_override = 0;
			up_map_info.hmc_fcn_idx = iwdev->rf->sc_dev.hmc_fn_id;
			irdma_cqp_up_map_cmd(&iwdev->rf->sc_dev,
					     IRDMA_OP_SET_UP_MAP,
					     &up_map_info);
		}
#endif /* CONFIG_CONFIGFS_FS */
		if (iwdev->vsi.tc_change_pending) {
			iwdev->vsi.tc_change_pending = false;
			irdma_sc_suspend_resume_qps(&iwdev->vsi,
						    IRDMA_OP_RESUME);
		}

	}

	if (iwdev->rf->sc_dev.privileged)
		cdev_info->ops->update_vport_filter(
			cdev_info, iwdev->vsi_num, false);

	irdma_ib_unregister_device(iwdev);
	irdma_unregister_notifiers(iwdev);
	irdma_deinit_device(iwdev);
	ib_dealloc_device(&iwdev->ibdev);
	irdma_rblog_pr_debug("INIT: Gen[%d] func[%d] device remove success\n",
			     rdma_ver, PCI_FUNC(cdev_info->pdev->devfn));
#ifdef HAVE_AUXILIARY_DRIVER_INT_REMOVE
	return 0;
#endif /* HAVE_AUXILIARY_DRIVER_INT_REMOVE */
}

static const struct auxiliary_device_id icrdma_auxiliary_id_table[] = {
	{.name = "ice.iwarp", },
	{.name = "ice.roce", },
	{.name = "iavf.iwarp", },
	{.name = "iavf.roce", },
	{},
};

MODULE_DEVICE_TABLE(auxiliary, icrdma_auxiliary_id_table);

struct iidc_auxiliary_drv icrdma_core_auxiliary_drv = {
	.adrv = {
	    .name = "gen_2",
	    .id_table = icrdma_auxiliary_id_table,
	    .probe = icrdma_probe,
	    .remove = icrdma_remove,
	},
	.event_handler = icrdma_iidc_event_handler,
	.vc_receive = irdma_vchnl_receive,
};
