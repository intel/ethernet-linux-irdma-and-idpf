// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2015 - 2024 Intel Corporation */
#include "main.h"

extern unsigned int irdma_rca_rq_size;

/* types of hmc objects */
static enum irdma_hmc_rsrc_type iw_hmc_obj_types[] = {
	IRDMA_HMC_IW_QP,
	IRDMA_HMC_IW_CQ,
	IRDMA_HMC_IW_SRQ,
	IRDMA_HMC_IW_HTE,
	IRDMA_HMC_IW_ARP,
	IRDMA_HMC_IW_APBVT_ENTRY,
	IRDMA_HMC_IW_MR,
	IRDMA_HMC_IW_XF,
	IRDMA_HMC_IW_XFFL,
	IRDMA_HMC_IW_Q1,
	IRDMA_HMC_IW_Q1FL,
	IRDMA_HMC_IW_PBLE,
	IRDMA_HMC_IW_TIMER,
	IRDMA_HMC_IW_FSIMC,
	IRDMA_HMC_IW_FSIAV,
	IRDMA_HMC_IW_RRF,
	IRDMA_HMC_IW_RRFFL,
	IRDMA_HMC_IW_HDR,
	IRDMA_HMC_IW_MD,
	IRDMA_HMC_IW_OOISC,
	IRDMA_HMC_IW_OOISCFFL,
};

/**
 * irdma_iwarp_ce_handler - handle iwarp completions
 * @iwcq: iwarp cq receiving event
 */
static void irdma_iwarp_ce_handler(struct irdma_sc_cq *iwcq)
{
	struct irdma_cq *cq = iwcq->back_cq;

	if (!cq->user_mode)
		atomic_set(&cq->armed, 0);
	if (cq->ibcq.comp_handler)
		cq->ibcq.comp_handler(&cq->ibcq, cq->ibcq.cq_context);
}

/**
 * irdma_puda_ce_handler - handle puda completion events
 * @rf: RDMA PCI function
 * @cq: puda completion q for event
 */
static void irdma_puda_ce_handler(struct irdma_pci_f *rf,
				  struct irdma_sc_cq *cq)
{
	struct irdma_sc_dev *dev = &rf->sc_dev;
	u32 compl_error;
	int status;

	do {
		status = irdma_puda_poll_cmpl(dev, cq, &compl_error);
		if (status == -ENOENT)
			break;
		if (status) {
			ibdev_dbg(to_ibdev(dev), "ERR: puda status = %d\n", status);
			break;
		}
		if (compl_error) {
			ibdev_dbg(to_ibdev(dev), "ERR: puda compl_err = 0x%x\n",
				  compl_error);
			break;
		}
	} while (1);

	if (dev->hw_wa & CCQ_CQ3_POLL)
		return;
	irdma_sc_ccq_arm(cq);
}

/**
 * irdma_process_ceq - handle ceq for completions
 * @rf: RDMA PCI function
 * @ceq: ceq having cq for completion
 */
void irdma_process_ceq(struct irdma_pci_f *rf, struct irdma_ceq *ceq)
{
	struct irdma_sc_dev *dev = &rf->sc_dev;
	struct irdma_sc_ceq *sc_ceq;
	struct irdma_sc_cq *cq;
	unsigned long flags;

	sc_ceq = &ceq->sc_ceq;
	do {
		spin_lock_irqsave(&ceq->ce_lock, flags);
		cq = irdma_sc_process_ceq(dev, sc_ceq);
		if (!cq) {
			spin_unlock_irqrestore(&ceq->ce_lock, flags);
			break;
		}

		if (cq->cq_type == IRDMA_CQ_TYPE_IWARP)
			irdma_iwarp_ce_handler(cq);

		spin_unlock_irqrestore(&ceq->ce_lock, flags);

		if (cq->cq_type == IRDMA_CQ_TYPE_CQP)
			queue_work(rf->cqp_cmpl_wq, &rf->cqp_cmpl_work);
		else if (cq->cq_type == IRDMA_CQ_TYPE_ILQ ||
			 cq->cq_type == IRDMA_CQ_TYPE_IEQ)
			irdma_puda_ce_handler(rf, cq);
	} while (1);
}

static void irdma_set_flush_fields(struct irdma_sc_qp *qp,
				   struct irdma_aeqe_info *info,
				   struct irdma_qp_host_ctx_info *ctx_info)
{
	struct qp_err_code qp_err;

	qp->sq_flush_code = info->sq;
	qp->rq_flush_code = info->rq;
	if (info->sq && qp->qp_uk.uk_attrs->hw_rev >= IRDMA_GEN_3) {
		qp->err_sq_idx_valid = true;
		qp->err_sq_idx = info->wqe_idx;
	}
	if (ctx_info->roce_info->err_rq_idx_valid && qp->qp_uk.uk_attrs->hw_rev >= IRDMA_GEN_3) {
		qp->err_rq_idx_valid = true;
		qp->err_rq_idx = ctx_info->roce_info->err_rq_idx;
	}

	qp_err = irdma_ae_to_qp_err_code(info->ae_id);

	qp->flush_code = qp_err.flush_code;
	qp->event_type = qp_err.event_type;
}

/**
 * irdma_complete_cqp_request - perform post-completion cleanup
 * @cqp: device CQP
 * @cqp_request: CQP request
 *
 * Mark CQP request as done, wake up waiting thread or invoke
 * callback function and release/free CQP request.
 */
static void irdma_complete_cqp_request(struct irdma_cqp *cqp,
				       struct irdma_cqp_request *cqp_request)
{
	WRITE_ONCE(cqp_request->request_done, true);
	if (cqp_request->waiting)
		wake_up(&cqp_request->waitq);
	else if (cqp_request->callback_fcn)
		cqp_request->callback_fcn(cqp_request);
	irdma_put_cqp_request(cqp, cqp_request);
}

/**
 * irdma_process_ae_def_cmpl - handle IRDMA_AE_CQP_DEFERRED_COMPLETE event
 * @rf: RDMA PCI function
 * @info: AEQ entry info
 */
static void irdma_process_ae_def_cmpl(struct irdma_pci_f *rf,
				      struct irdma_aeqe_info *info)
{
	u32 sw_def_info;
	u64 scratch;

	irdma_cqp_ce_handler(rf, &rf->ccq.sc_cq);

	irdma_sc_cqp_def_cmpl_ae_handler(&rf->sc_dev, info, true,
					 &scratch, &sw_def_info);
	while (scratch) {
		struct irdma_cqp_request *cqp_request =
			(struct irdma_cqp_request *)(uintptr_t)scratch;

		irdma_complete_cqp_request(&rf->cqp, cqp_request);
		irdma_sc_cqp_def_cmpl_ae_handler(&rf->sc_dev, info, false,
						 &scratch, &sw_def_info);
	}
}

/**
 * irdma_process_aeq - handle aeq events
 * @rf: RDMA PCI function
 */
void irdma_process_aeq(struct irdma_pci_f *rf)
{
	struct irdma_sc_dev *dev = &rf->sc_dev;
	struct irdma_aeq *aeq = &rf->aeq;
	struct irdma_sc_aeq *sc_aeq = &aeq->sc_aeq;
	struct irdma_aeqe_info aeinfo;
	struct irdma_aeqe_info *info = &aeinfo;
	int ret;
	struct irdma_qp *iwqp = NULL;
	struct irdma_cq *iwcq = NULL;
	struct irdma_sc_qp *qp = NULL;
	struct irdma_device *iwdev = rf->iwdev;
	struct irdma_qp_host_ctx_info *ctx_info = NULL;
	struct irdma_srq *iwsrq;
	u64 srq_id;
	unsigned long flags;

	u32 aeqcnt = 0;

	if (!sc_aeq->size)
		return;

	do {
		memset(info, 0, sizeof(*info));
		ret = irdma_sc_get_next_aeqe(sc_aeq, info);
		if (ret)
			break;

		if (info->aeqe_overflow) {
			ibdev_err(&iwdev->ibdev, "AEQ has overflowed\n");
			rf->reset = true;
			rf->gen_ops.request_reset(rf);
			return;
		}

		aeqcnt++;
		atomic_inc(&iwdev->ae_info.ae_cnt);

		ibdev_dbg(&iwdev->ibdev,
			  "AEQ: ae_id = 0x%x (%s), is_qp = %d, qp_id = %d, tcp_state = %d, iwarp_state = %d, ae_src = %d\n",
			  info->ae_id, irdma_get_ae_desc(info->ae_id), info->qp,
			  info->qp_cq_id, info->tcp_state, info->iwarp_state,
			  info->ae_src);

		if (info->qp) {
			spin_lock_irqsave(&rf->qptable_lock, flags);
			iwqp = rf->qp_table[info->qp_cq_id];
			if (!iwqp) {
				spin_unlock_irqrestore(&rf->qptable_lock,
						       flags);
				if (info->ae_id == IRDMA_AE_QP_SUSPEND_COMPLETE) {
					struct irdma_device *iwdev = rf->iwdev;

					if (!iwdev->vsi.tc_change_pending)
						continue;

					atomic_dec(&iwdev->vsi.qp_suspend_reqs);
					wake_up(&iwdev->suspend_wq);
					continue;
				}
				ibdev_dbg(&iwdev->ibdev, "AEQ: qp_id %d is already freed\n",
					  info->qp_cq_id);
				continue;
			}
			irdma_qp_add_ref(&iwqp->ibqp);
			spin_unlock_irqrestore(&rf->qptable_lock, flags);
			qp = &iwqp->sc_qp;
			spin_lock_irqsave(&iwqp->lock, flags);
			iwqp->hw_tcp_state = info->tcp_state;
			iwqp->hw_iwarp_state = info->iwarp_state;

			if (info->ae_id != IRDMA_AE_QP_SUSPEND_COMPLETE) {
				iwqp->last_aeq = info->ae_id;
				iwqp->ae_src = info->ae_src;
			}

			spin_unlock_irqrestore(&iwqp->lock, flags);
		} else if (info->srq) {
			if (info->ae_id != IRDMA_AE_SRQ_LIMIT)
				continue;
		} else {
			if (info->ae_id != IRDMA_AE_CQ_OPERATION_ERROR &&
			    info->ae_id != IRDMA_AE_CQP_DEFERRED_COMPLETE)
				continue;
		}

		switch (info->ae_id) {
			struct irdma_cm_node *cm_node;
		case IRDMA_AE_LLP_CONNECTION_ESTABLISHED:
			cm_node = iwqp->cm_node;
			if (cm_node->accept_pend) {
				atomic_dec(&cm_node->listener->pend_accepts_cnt);
				cm_node->accept_pend = 0;
			}
			iwqp->rts_ae_rcvd = 1;
			wake_up_interruptible(&iwqp->waitq);
			break;
		case IRDMA_AE_LLP_FIN_RECEIVED:
			if (qp->term_flags)
				break;
			if (atomic_inc_return(&iwqp->close_timer_started) == 1) {
				iwqp->hw_tcp_state = IRDMA_TCP_STATE_CLOSE_WAIT;
				if (iwqp->ibqp_state == IB_QPS_RTS) {
					irdma_next_iw_state(iwqp,
							    IRDMA_QP_STATE_CLOSING,
							    0, 0, 0);
					irdma_cm_disconn(iwqp);
				}
				irdma_schedule_cm_timer(iwqp->cm_node,
							(struct irdma_puda_buf *)iwqp,
							IRDMA_TIMER_TYPE_CLOSE,
							1, 0);
			}
			break;
		case IRDMA_AE_LLP_CLOSE_COMPLETE:
			if (qp->term_flags)
				irdma_terminate_done(qp, 0);
			else
				irdma_cm_disconn(iwqp);
			break;
		case IRDMA_AE_BAD_CLOSE:
		case IRDMA_AE_RESET_SENT:
			irdma_next_iw_state(iwqp, IRDMA_QP_STATE_ERROR, 1, 0,
					    0);
			irdma_cm_disconn(iwqp);
			break;
		case IRDMA_AE_LLP_CONNECTION_RESET:
			if (atomic_read(&iwqp->close_timer_started))
				break;
			irdma_cm_disconn(iwqp);
			break;
		case IRDMA_AE_QP_SUSPEND_COMPLETE:
			if (iwqp->iwdev->vsi.tc_change_pending) {
				if (!atomic_dec_return(&iwqp->sc_qp.vsi->qp_suspend_reqs))
					wake_up(&iwqp->iwdev->suspend_wq);
			}
			if (iwqp->suspend_pending) {
				iwqp->suspend_pending = false;
				wake_up(&iwqp->iwdev->suspend_wq);
			}
			break;
		case IRDMA_AE_TERMINATE_SENT:
			irdma_terminate_send_fin(qp);
			break;
		case IRDMA_AE_LLP_TERMINATE_RECEIVED:
			irdma_terminate_received(qp, info);
			break;
		case IRDMA_AE_LCE_CQ_CATASTROPHIC:
		case IRDMA_AE_CQ_OPERATION_ERROR:
			ibdev_err(&iwdev->ibdev,
				  "Processing CQ[0x%x] op error, AE 0x%04X\n",
				  info->qp_cq_id, info->ae_id);
			spin_lock_irqsave(&rf->cqtable_lock, flags);
			iwcq = rf->cq_table[info->qp_cq_id];
			if (!iwcq) {
				spin_unlock_irqrestore(&rf->cqtable_lock,
						       flags);
				ibdev_dbg(&iwdev->ibdev, "AEQ: cq_id %d is already freed\n",
					  info->qp_cq_id);
				continue;
			}
			irdma_cq_add_ref(&iwcq->ibcq);
			spin_unlock_irqrestore(&rf->cqtable_lock, flags);
			if (iwcq->ibcq.event_handler) {
				struct ib_event ibevent;

				ibevent.device = iwcq->ibcq.device;
				ibevent.event = IB_EVENT_CQ_ERR;
				ibevent.element.cq = &iwcq->ibcq;
				iwcq->ibcq.event_handler(&ibevent,
							 iwcq->ibcq.cq_context);
			}
			irdma_cq_rem_ref(&iwcq->ibcq);
			break;
		case IRDMA_AE_SRQ_LIMIT:
			srq_id = info->compl_ctx;
			spin_lock_irqsave(&rf->srqtable_lock, flags);
			iwsrq = rf->srq_table[srq_id];
			if (!iwsrq) {
				spin_unlock_irqrestore(&rf->srqtable_lock,
						       flags);
				ibdev_dbg(&iwdev->ibdev,
					  "AEQ: srq_id %lluu is already freed\n",
					  srq_id);
				continue;
			}
			irdma_srq_add_ref(&iwsrq->ibsrq);
			spin_unlock_irqrestore(&rf->srqtable_lock, flags);
			irdma_srq_event(&iwsrq->sc_srq);
			irdma_srq_rem_ref(&iwsrq->ibsrq);
			break;
		case IRDMA_AE_SRQ_CATASTROPHIC_ERROR:
			break;
		case IRDMA_AE_CQP_DEFERRED_COMPLETE:
			/* Remove completed CQP requests from pending list
			 * and notify about those CQP ops completion.
			 */
			irdma_process_ae_def_cmpl(rf, info);
			break;
		case IRDMA_AE_RESET_NOT_SENT:
		case IRDMA_AE_LLP_DOUBT_REACHABILITY:
			break;
		case IRDMA_AE_RESOURCE_EXHAUSTION:
			ibdev_err(&iwdev->ibdev,
				  "Resource exhaustion reason: q1 = %d xmit or rreq = %d\n",
				  info->ae_src == IRDMA_AE_SOURCE_RSRC_EXHT_Q1,
				  info->ae_src == IRDMA_AE_SOURCE_RSRC_EXHT_XT_RR);
			break;
		case IRDMA_AE_PRIV_OPERATION_DENIED:
		case IRDMA_AE_RDMAP_ROE_BAD_LLP_CLOSE:
		case IRDMA_AE_STAG_ZERO_INVALID:
		case IRDMA_AE_IB_RREQ_AND_Q1_FULL:
		case IRDMA_AE_DDP_UBE_INVALID_DDP_VERSION:
		case IRDMA_AE_DDP_UBE_INVALID_MO:
		case IRDMA_AE_DDP_UBE_INVALID_QN:
		case IRDMA_AE_DDP_NO_L_BIT:
		case IRDMA_AE_RDMAP_ROE_INVALID_RDMAP_VERSION:
		case IRDMA_AE_RDMAP_ROE_UNEXPECTED_OPCODE:
		case IRDMA_AE_ROE_INVALID_RDMA_READ_REQUEST:
		case IRDMA_AE_ROE_INVALID_RDMA_WRITE_OR_READ_RESP:
		case IRDMA_AE_INVALID_ARP_ENTRY:
		case IRDMA_AE_INVALID_TCP_OPTION_RCVD:
		case IRDMA_AE_STALE_ARP_ENTRY:
		case IRDMA_AE_LLP_RECEIVED_MPA_CRC_ERROR:
		case IRDMA_AE_LLP_SEGMENT_TOO_SMALL:
		case IRDMA_AE_LLP_SYN_RECEIVED:
		case IRDMA_AE_LLP_TOO_MANY_RETRIES:
		case IRDMA_AE_LCE_QP_CATASTROPHIC:
		case IRDMA_AE_LCE_FUNCTION_CATASTROPHIC:
		case IRDMA_AE_LLP_TOO_MANY_RNRS:
		case IRDMA_AE_REMOTE_QP_CATASTROPHIC:
		case IRDMA_AE_LOCAL_QP_CATASTROPHIC:
		case IRDMA_AE_RCE_QP_CATASTROPHIC:
		case IRDMA_AE_UDA_XMIT_DGRAM_TOO_LONG:
		default:
			ctx_info = &iwqp->ctx_info;
			if (rdma_protocol_roce(&iwqp->iwdev->ibdev, 1)) {
				ctx_info->roce_info->err_rq_idx_valid =
					ctx_info->srq_valid ? false : info->err_rq_idx_valid;
				if (ctx_info->roce_info->err_rq_idx_valid) {
					ctx_info->roce_info->err_rq_idx = info->wqe_idx;
					irdma_sc_qp_setctx_roce(&iwqp->sc_qp, iwqp->host_ctx.va,
								ctx_info);
				}
				irdma_set_flush_fields(qp, info, ctx_info);
				irdma_cm_disconn(iwqp);
				break;
			}
			ctx_info->iwarp_info->err_rq_idx_valid = info->err_rq_idx_valid;
			if (info->rq) {
				ctx_info->iwarp_info->err_rq_idx = info->wqe_idx;
				ctx_info->tcp_info_valid = false;
				ctx_info->iwarp_info_valid = true;
				irdma_sc_qp_setctx(&iwqp->sc_qp, iwqp->host_ctx.va,
						   ctx_info);
			}
			if (iwqp->hw_iwarp_state != IRDMA_QP_STATE_RTS &&
			    iwqp->hw_iwarp_state != IRDMA_QP_STATE_TERMINATE) {
				irdma_next_iw_state(iwqp, IRDMA_QP_STATE_ERROR, 1, 0, 0);
				irdma_cm_disconn(iwqp);
			} else {
				irdma_terminate_connection(qp, info);
			}
			break;
		}
		if (info->qp)
			irdma_qp_rem_ref(&iwqp->ibqp);
	} while (1);

	if (aeqcnt)
		irdma_sc_repost_aeq_entries(dev, aeqcnt);
}

/**
 * irdma_ena_intr - set up device interrupts
 * @dev: hardware control device structure
 * @msix_id: id of the interrupt to be enabled
 */
static void irdma_ena_intr(struct irdma_sc_dev *dev, u32 msix_id)
{
	dev->irq_ops->irdma_en_irq(dev, msix_id);
}

/**
 * irdma_aeq_ceq0_irq_thread - irq thread handler for aeq and ceq 0
 * @irq: msix vector
 * @private: rf struct
 */
static irqreturn_t irdma_aeq_ceq0_irq_thread(int irq, void *private)
{
	struct irdma_pci_f *rf = private;

	if (rf->msix_shared)
		irdma_process_ceq(rf, rf->ceqlist);
	if (rf->sc_dev.hw_wa & AEQ_POLL) {
		irdma_ena_intr(&rf->sc_dev, rf->iw_msixtbl[0].idx);
		return IRQ_HANDLED;
	}
	irdma_process_aeq(rf);
	irdma_ena_intr(&rf->sc_dev, rf->iw_msixtbl[0].idx);

	return IRQ_HANDLED;
}

/**
 * irdma_ceq_irq_thread - irq thread handler for CEQ
 * @irq: msix vector
 * @private: rf struct
 */
static irqreturn_t irdma_ceq_irq_thread(int irq, void *private)
{
	struct irdma_ceq *iwceq = private;
	struct irdma_pci_f *rf = iwceq->rf;

	irdma_process_ceq(rf, iwceq);
	irdma_ena_intr(&rf->sc_dev, iwceq->msix_idx);

	return IRQ_HANDLED;
}

static void irdma_free_cqp_rq(struct irdma_sc_dev *dev, struct irdma_cqp *cqp)
{
	if (cqp->rq.va) {
		dma_free_coherent(dev->hw->device, cqp->rq.size, cqp->rq.va,
				  cqp->rq.pa);
		cqp->rq.va = NULL;
	}
	if (cqp->rq_small_bufs.va) {
		dma_free_coherent(dev->hw->device, cqp->rq_small_bufs.size,
				  cqp->rq_small_bufs.va,
				  cqp->rq_small_bufs.pa);
		cqp->rq_small_bufs.va = NULL;
	}
	if (cqp->rq_large_bufs.va) {
		dma_free_coherent(dev->hw->device, cqp->rq_large_bufs.size,
				  cqp->rq_large_bufs.va,
				  cqp->rq_large_bufs.pa);
		cqp->rq_large_bufs.va = NULL;
	}
	kfree(cqp->rqe_array);
	cqp->rqe_array = NULL;
}

/**
 * irdma_save_msix_info - copy msix vector information to iwarp device
 * @rf: RDMA PCI function
 *
 * Allocate iwdev msix table and copy the msix info to the table
 * Return 0 if successful, otherwise return error
 */
static int irdma_save_msix_info(struct irdma_pci_f *rf)
{
	struct irdma_qvlist_info *iw_qvlist;
	struct irdma_qv_info *iw_qvinfo;
	struct msix_entry *pmsix;
	u16 ceq_idx;
	u32 i;
	u32 size;

	if (!rf->msix_count) {
		ibdev_err(to_ibdev(&rf->sc_dev), "No MSI-X vectors reserved for RDMA.\n");
		return -EINVAL;
	}

	size = sizeof(struct irdma_msix_vector) * rf->msix_count;
	size += sizeof(*iw_qvlist);
	size += sizeof(*iw_qvinfo) * (rf->msix_count - 1);
	rf->iw_msixtbl = kzalloc(size, GFP_KERNEL);
	if (!rf->iw_msixtbl)
		return -ENOMEM;

	rf->iw_qvlist = (struct irdma_qvlist_info *)
			(&rf->iw_msixtbl[rf->msix_count]);
	iw_qvlist = rf->iw_qvlist;
	iw_qvinfo = iw_qvlist->qv_info;
	iw_qvlist->num_vectors = rf->msix_count;
	if (rf->sc_dev.hw_wa & MSIX_SHARED ||
	    rf->msix_count <= num_online_cpus())
		rf->msix_shared = true;
	else if (rf->msix_count > num_online_cpus() + 1)
		rf->msix_count = num_online_cpus() + 1;

	pmsix = rf->msix_entries;
	for (i = 0, ceq_idx = 0; i < rf->msix_count; i++, iw_qvinfo++) {
		rf->iw_msixtbl[i].idx = pmsix->entry;
		rf->iw_msixtbl[i].irq = pmsix->vector;
		rf->iw_msixtbl[i].cpu_affinity = ceq_idx;
		if (!i) {
			iw_qvinfo->aeq_idx = 0;
			if (rf->msix_shared)
				iw_qvinfo->ceq_idx = ceq_idx++;
			else
				iw_qvinfo->ceq_idx = IRDMA_Q_INVALID_IDX;
		} else {
			iw_qvinfo->aeq_idx = IRDMA_Q_INVALID_IDX;
			iw_qvinfo->ceq_idx = ceq_idx++;
		}
		iw_qvinfo->itr_idx = IRDMA_IDX_NOITR;
		iw_qvinfo->v_idx = rf->iw_msixtbl[i].idx;
		pmsix++;
	}

	return 0;
}

/**
 * irdma_destroy_irq - destroy device interrupts
 * @rf: RDMA PCI function
 * @msix_vec: msix vector to disable irq
 * @dev_id: parameter to pass to free_irq (used during irq setup)
 *
 * The function is called when destroying aeq/ceq
 */
static void irdma_destroy_irq(struct irdma_pci_f *rf,
			      struct irdma_msix_vector *msix_vec, void *dev_id)
{
	struct irdma_sc_dev *dev = &rf->sc_dev;

	dev->irq_ops->irdma_dis_irq(dev, msix_vec->idx);
	irq_update_affinity_hint(msix_vec->irq, NULL);
	free_irq(msix_vec->irq, dev_id);
}

/**
 * irdma_destroy_cqp  - destroy control qp
 * @rf: RDMA PCI function
 * @free_hwcqp: 1 if hw cqp should be freed
 *
 * Issue destroy cqp request and
 * free the resources associated with the cqp
 */
static void irdma_destroy_cqp(struct irdma_pci_f *rf, bool free_hwcqp)
{
	struct irdma_sc_dev *dev = &rf->sc_dev;
	struct irdma_cqp *cqp = &rf->cqp;
	int status = 0;

	status = irdma_sc_cqp_destroy(dev->cqp, free_hwcqp);
	if (status)
		ibdev_dbg(to_ibdev(dev), "ERR: Destroy CQP failed %d\n", status);

	irdma_cleanup_pending_cqp_op(rf);
	dma_free_coherent(dev->hw->device, cqp->sq.size, cqp->sq.va,
			  cqp->sq.pa);
	cqp->sq.va = NULL;
	kfree(cqp->ooo_op_array);
	cqp->ooo_op_array = NULL;
	if (cqp->rqe_array)
		irdma_free_cqp_rq(dev, cqp);
	kfree(cqp->scratch_array);
	cqp->scratch_array = NULL;
	kfree(cqp->rq_scratch_array);
	cqp->rq_scratch_array = NULL;
	kfree(cqp->cqp_requests);
	cqp->cqp_requests = NULL;
}

static void irdma_destroy_virt_aeq(struct irdma_pci_f *rf)
{
	struct irdma_aeq *aeq = &rf->aeq;
	u32 pg_cnt = DIV_ROUND_UP(aeq->mem.size, PAGE_SIZE);
	dma_addr_t *pg_arr = (dma_addr_t *)aeq->palloc.level1.addr;

	irdma_unmap_vm_page_list(&rf->hw, pg_arr, pg_cnt);
	irdma_free_pble(rf->pble_rsrc, &aeq->palloc);
	vfree(aeq->mem.va);
}

/**
 * irdma_destroy_aeq - destroy aeq
 * @rf: RDMA PCI function
 *
 * Issue a destroy aeq request and
 * free the resources associated with the aeq
 * The function is called during driver unload
 */
static void irdma_destroy_aeq(struct irdma_pci_f *rf)
{
	struct irdma_sc_dev *dev = &rf->sc_dev;
	struct irdma_aeq *aeq = &rf->aeq;
	int status = -EBUSY;

	if (!rf->msix_shared && !(dev->hw_wa & CEQ_POLL)) {
		if (rf->sc_dev.privileged)
			rf->sc_dev.irq_ops->irdma_cfg_aeq(
				&rf->sc_dev, rf->iw_msixtbl->idx, false);
		irdma_destroy_irq(rf, rf->iw_msixtbl, rf);
	}
	if (rf->reset)
		goto exit;

	aeq->sc_aeq.size = 0;
	status = irdma_cqp_aeq_cmd(dev, &aeq->sc_aeq, IRDMA_OP_AEQ_DESTROY);
	if (status)
		ibdev_dbg(to_ibdev(dev), "ERR: Destroy AEQ failed %d\n", status);

exit:
	if (aeq->virtual_map)
		irdma_destroy_virt_aeq(rf);
	else {
		dma_free_coherent(dev->hw->device, aeq->mem.size, aeq->mem.va,
				  aeq->mem.pa);
		aeq->mem.va = NULL;
	}
}

/**
 * irdma_destroy_ceq - destroy ceq
 * @rf: RDMA PCI function
 * @iwceq: ceq to be destroyed
 *
 * Issue a destroy ceq request and
 * free the resources associated with the ceq
 */
static void irdma_destroy_ceq(struct irdma_pci_f *rf, struct irdma_ceq *iwceq)
{
	struct irdma_sc_dev *dev = &rf->sc_dev;
	int status;

	if (rf->reset)
		goto exit;

	status = irdma_sc_ceq_destroy(&iwceq->sc_ceq, 0, 1);
	if (status) {
		ibdev_dbg(to_ibdev(dev), "ERR: CEQ destroy command failed %d\n", status);
		goto exit;
	}

	status = irdma_sc_cceq_destroy_done(&iwceq->sc_ceq);
	if (status)
		ibdev_dbg(to_ibdev(dev), "ERR: CEQ destroy completion failed %d\n",
			  status);
exit:
	if (dev->hw_wa & CEQ_POLL) {
		kfree(iwceq->sc_ceq.reg_cq);
	}
	dma_free_coherent(dev->hw->device, iwceq->mem.size, iwceq->mem.va,
			  iwceq->mem.pa);
	iwceq->mem.va = NULL;
}

/**
 * irdma_del_ceq_0 - destroy ceq 0
 * @rf: RDMA PCI function
 *
 * Disable the ceq 0 interrupt and destroy the ceq 0
 */
static void irdma_del_ceq_0(struct irdma_pci_f *rf)
{
	struct irdma_ceq *iwceq = rf->ceqlist;
	struct irdma_msix_vector *msix_vec;

	if (rf->sc_dev.hw_wa & CEQ_POLL) {
		irdma_destroy_ceq(rf, iwceq);
		rf->sc_dev.ceq_valid = false;
		rf->ceqs_count = 0;
		return;
	}

	if (rf->msix_shared) {
		msix_vec = &rf->iw_msixtbl[0];
		if (rf->sc_dev.privileged)
			rf->sc_dev.irq_ops->irdma_cfg_ceq(&rf->sc_dev,
							  msix_vec->ceq_id,
							  msix_vec->idx, false);
		irdma_destroy_irq(rf, msix_vec, rf);
	} else {
		msix_vec = &rf->iw_msixtbl[1];
		irdma_destroy_irq(rf, msix_vec, iwceq);
	}

	irdma_destroy_ceq(rf, iwceq);
	rf->sc_dev.ceq_valid = false;
	rf->ceqs_count = 0;
}

/**
 * irdma_del_ceqs - destroy all ceq's except CEQ 0
 * @rf: RDMA PCI function
 *
 * Go through all of the device ceq's, except 0, and for each
 * ceq disable the ceq interrupt and destroy the ceq
 */
static void irdma_del_ceqs(struct irdma_pci_f *rf)
{
	struct irdma_ceq *iwceq = &rf->ceqlist[1];
	struct irdma_msix_vector *msix_vec;
	u32 i = 0;

	if (rf->msix_shared)
		msix_vec = &rf->iw_msixtbl[1];
	else
		msix_vec = &rf->iw_msixtbl[2];

	for (i = 1; i < rf->ceqs_count; i++, msix_vec++, iwceq++) {
		if (rf->sc_dev.privileged)
			rf->sc_dev.irq_ops->irdma_cfg_ceq(&rf->sc_dev,
							  msix_vec->ceq_id,
							  msix_vec->idx, false);
		irdma_destroy_irq(rf, msix_vec, iwceq);
		irdma_cqp_ceq_cmd(&rf->sc_dev, &iwceq->sc_ceq,
				  IRDMA_OP_CEQ_DESTROY);
		dma_free_coherent(rf->sc_dev.hw->device, iwceq->mem.size,
				  iwceq->mem.va, iwceq->mem.pa);
		iwceq->mem.va = NULL;
	}
	rf->ceqs_count = 1;
}

/**
 * irdma_destroy_ccq - destroy control cq
 * @rf: RDMA PCI function
 *
 * Issue destroy ccq request and
 * free the resources associated with the ccq
 */
static void irdma_destroy_ccq(struct irdma_pci_f *rf)
{
	struct irdma_sc_dev *dev = &rf->sc_dev;
	struct irdma_ccq *ccq = &rf->ccq;
	int status = 0;

	if (rf->cqp_cmpl_wq)
		destroy_workqueue(rf->cqp_cmpl_wq);
	if (!rf->reset)
		status = irdma_sc_ccq_destroy(dev->ccq, 0, true);
	if (status)
		ibdev_dbg(to_ibdev(dev), "ERR: CCQ destroy failed %d\n", status);
	dma_free_coherent(dev->hw->device, ccq->mem_cq.size, ccq->mem_cq.va,
			  ccq->mem_cq.pa);
	ccq->mem_cq.va = NULL;
}

/**
 * irdma_close_hmc_objects_type - delete hmc objects of a given type
 * @dev: iwarp device
 * @obj_type: the hmc object type to be deleted
 * @hmc_info: host memory info struct
 * @privileged: permission to close HMC objects
 * @reset: true if called before reset
 */
static void irdma_close_hmc_objects_type(struct irdma_sc_dev *dev,
					 enum irdma_hmc_rsrc_type obj_type,
					 struct irdma_hmc_info *hmc_info,
					 bool privileged, bool reset)
{
	struct irdma_hmc_del_obj_info info = {};

	info.hmc_info = hmc_info;
	info.rsrc_type = obj_type;
	info.count = hmc_info->hmc_obj[obj_type].cnt;
	info.privileged = privileged;
	if (irdma_sc_del_hmc_obj(dev, &info, reset))
		ibdev_dbg(to_ibdev(dev), "ERR: del HMC obj of type %d failed\n",
			  obj_type);
}

/**
 * irdma_del_hmc_objects - remove all device hmc objects
 * @dev: iwarp device
 * @hmc_info: hmc_info to free
 * @privileged: permission to delete HMC objects
 * @reset: true if called before reset
 * @vers: hardware version
 */
void irdma_del_hmc_objects(struct irdma_sc_dev *dev,
			   struct irdma_hmc_info *hmc_info, bool privileged,
			   bool reset, enum irdma_vers vers)
{
	unsigned int i;

	for (i = 0; i < IW_HMC_OBJ_TYPE_NUM; i++) {
		if (dev->hmc_info->hmc_obj[iw_hmc_obj_types[i]].cnt)
			irdma_close_hmc_objects_type(dev, iw_hmc_obj_types[i],
						     hmc_info, privileged, reset);
		if (vers == IRDMA_GEN_1 && i == IRDMA_HMC_IW_TIMER)
			break;
	}
}

/**
 * irdma_create_hmc_obj_type - create hmc object of a given type
 * @dev: hardware control device structure
 * @info: information for the hmc object to create
 */
static int irdma_create_hmc_obj_type(struct irdma_sc_dev *dev,
				     struct irdma_hmc_create_obj_info *info)
{
	return irdma_sc_create_hmc_obj(dev, info);
}

/**
 * irdma_create_hmc_objs - create all hmc objects for the device
 * @rf: RDMA PCI function
 * @privileged: permission to create HMC objects
 * @vers: HW version
 *
 * Create the device hmc objects and allocate hmc pages
 * Return 0 if successful, otherwise clean up and return error
 */
static int irdma_create_hmc_objs(struct irdma_pci_f *rf, bool privileged,
				 enum irdma_vers vers)
{
	struct irdma_sc_dev *dev = &rf->sc_dev;
	struct irdma_hmc_create_obj_info info = {};
	int i, status = 0;

	info.hmc_info = dev->hmc_info;
	info.privileged = privileged;
	info.entry_type = rf->sd_type;

	for (i = 0; i < IW_HMC_OBJ_TYPE_NUM; i++) {
		if (iw_hmc_obj_types[i] == IRDMA_HMC_IW_PBLE)
			continue;
		if (dev->hmc_info->hmc_obj[iw_hmc_obj_types[i]].cnt) {
			info.rsrc_type = iw_hmc_obj_types[i];
			info.count = dev->hmc_info->hmc_obj[info.rsrc_type].cnt;
			info.add_sd_cnt = 0;
			status = irdma_create_hmc_obj_type(dev, &info);
			if (status) {
				ibdev_dbg(to_ibdev(dev),
					  "ERR: create obj type %d status = %d\n",
					  iw_hmc_obj_types[i], status);
				break;
			}
		}
		if (vers == IRDMA_GEN_1 && i == IRDMA_HMC_IW_TIMER)
			break;
	}

	if (!status)
		return irdma_sc_static_hmc_pages_allocated(dev->cqp, 0, dev->hmc_fn_id,
							   true, true);

	while (i) {
		i--;
		/* destroy the hmc objects of a given type */
		if (dev->hmc_info->hmc_obj[iw_hmc_obj_types[i]].cnt)
			irdma_close_hmc_objects_type(dev, iw_hmc_obj_types[i],
						     dev->hmc_info, privileged,
						     false);
	}

	return status;
}

/**
 * irdma_obj_aligned_mem - get aligned memory from device allocated memory
 * @rf: RDMA PCI function
 * @memptr: points to the memory addresses
 * @size: size of memory needed
 * @mask: mask for the aligned memory
 *
 * Get aligned memory of the requested size and
 * update the memptr to point to the new aligned memory
 * Return 0 if successful, otherwise return no memory error
 */
int irdma_obj_aligned_mem(struct irdma_pci_f *rf, struct irdma_dma_mem *memptr,
			  u32 size, u32 mask)
{
	unsigned long va, newva;
	unsigned long extra;

	va = (unsigned long)rf->obj_next.va;
	newva = va;
	if (mask)
		newva = ALIGN(va, (unsigned long)mask + 1ULL);
	extra = newva - va;
	memptr->va = (u8 *)va + extra;
	memptr->pa = rf->obj_next.pa + extra;
	memptr->size = size;
	if (((u8 *)memptr->va + size) > ((u8 *)rf->obj_mem.va + rf->obj_mem.size))
		return -ENOMEM;

	rf->obj_next.va = (u8 *)memptr->va + size;
	rf->obj_next.pa = memptr->pa + size;

	return 0;
}

/**
 * irdma_alloc_cqp_rq - allocate CQP RQ
 * @dev: iwarp device
 * @cqp: device CQP
 * @info: CQP init info
 * @rqsize: size of CQP RQ
 */
static int irdma_alloc_cqp_rq(struct irdma_sc_dev *dev, struct irdma_cqp *cqp,
			      struct irdma_cqp_init_info *info, u32 rqsize)
{
	cqp->rqe_array = kcalloc(rqsize, sizeof(*cqp->rqe_array), GFP_KERNEL);
	// add RQ support, conditional, Need buffers too...  Can we leverage UDA code?
	if (!cqp->rqe_array)
		return -ENOMEM;

	cqp->rq.size = ALIGN(sizeof(struct irdma_cqp_rq_wqe) * rqsize,
			     IRDMA_CQP_ALIGNMENT);
	cqp->rq.va = dma_alloc_coherent(dev->hw->device, cqp->rq.size,
					&cqp->rq.pa, GFP_KERNEL);
	if (!cqp->rq.va)
		goto error;

	cqp->rq_small_bufs.size = rqsize * IRDMA_CQP_RQ_SMALL_BUF_SZ;
	cqp->rq_small_bufs.va = dma_alloc_coherent(dev->hw->device,
						   cqp->rq_small_bufs.size,
						   &cqp->rq_small_bufs.pa,
						   GFP_KERNEL);
	if (!cqp->rq_small_bufs.va)
		goto error;

	cqp->rq_large_bufs.size = rqsize * IRDMA_CQP_RQ_LARGE_BUF_SZ;
	cqp->rq_large_bufs.va = dma_alloc_coherent(dev->hw->device,
						   cqp->rq_large_bufs.size,
						   &cqp->rq_large_bufs.pa,
						   GFP_KERNEL);
	if (!cqp->rq_large_bufs.va)
		goto error;

	info->rq_size = rqsize;
	info->rq = cqp->rq.va;
	info->rq_pa = cqp->rq.pa;
	info->rqe_array = cqp->rqe_array;
	info->rq_small_bufs = cqp->rq_small_bufs;
	info->rq_large_bufs = cqp->rq_large_bufs;
	return 0;
error:
	irdma_free_cqp_rq(dev, cqp);
	return -ENOMEM;
}

/**
 * irdma_create_cqp - create control qp
 * @rf: RDMA PCI function
 *
 * Return 0, if the cqp and all the resources associated with it
 * are successfully created, otherwise return error
 */
static int irdma_create_cqp(struct irdma_pci_f *rf)
{
	u32 sqsize = IRDMA_CQP_SW_SQSIZE_2048;
	u32 rqsize = irdma_rca_rq_size;
	struct irdma_dma_mem mem;
	struct irdma_sc_dev *dev = &rf->sc_dev;
	struct irdma_cqp_init_info cqp_init_info = {};
	struct irdma_cqp *cqp = &rf->cqp;
	u16 maj_err, min_err;
	int i, status;

	cqp->cqp_requests = kcalloc(sqsize, sizeof(*cqp->cqp_requests),
				    GFP_KERNEL);
	if (!cqp->cqp_requests)
		return -ENOMEM;

	cqp->scratch_array = kcalloc(sqsize, sizeof(*cqp->scratch_array),
				     GFP_KERNEL);
	if (!cqp->scratch_array) {
		status = -ENOMEM;
		goto err_scratch;
	}

	cqp->rq_scratch_array = kcalloc(rqsize, sizeof(*cqp->rq_scratch_array),
					GFP_KERNEL);
	if (!cqp->rq_scratch_array) {
		status = -ENOMEM;
		goto err_rq_scratch;
	}

	cqp->ooo_op_array = kcalloc(sqsize, sizeof(*cqp->ooo_op_array),
				    GFP_KERNEL);
	if (!cqp->ooo_op_array) {
		status = -ENOMEM;
		goto err_oop;
	}
	cqp_init_info.ooo_op_array = cqp->ooo_op_array;
	dev->cqp = &cqp->sc_cqp;
	dev->cqp->dev = dev;
	cqp->sq.size = ALIGN(sizeof(struct irdma_cqp_sq_wqe) * sqsize,
			     IRDMA_CQP_ALIGNMENT);
	cqp->sq.va = dma_alloc_coherent(dev->hw->device, cqp->sq.size,
					&cqp->sq.pa, GFP_KERNEL);
	if (!cqp->sq.va) {
		status = -ENOMEM;
		goto err_sq;
	}
	if (irdma_rca_ena && !rf->ftype) {
		status = irdma_alloc_cqp_rq(dev, cqp, &cqp_init_info, rqsize);
		if (status)
			goto err_rq;
		cqp_init_info.cqp_type = IRDMA_CQP_TYPE_RCA;
	} else {
		cqp_init_info.cqp_type = IRDMA_CQP_TYPE_PRIMARY;
	}

	status = irdma_obj_aligned_mem(rf, &mem, sizeof(struct irdma_cqp_ctx),
				       IRDMA_HOST_CTX_ALIGNMENT_M);
	if (status)
		goto err_ctx;

	dev->cqp->host_ctx_pa = mem.pa;
	dev->cqp->host_ctx = mem.va;
	/* populate the cqp init info */
	cqp_init_info.dev = dev;
	cqp_init_info.sq_size = sqsize;
	cqp_init_info.sq = cqp->sq.va;
	cqp_init_info.sq_pa = cqp->sq.pa;
	cqp_init_info.host_ctx_pa = mem.pa;
	cqp_init_info.host_ctx = mem.va;
	if (dev->privileged) {
		cqp_init_info.hmc_profile = rf->rsrc_profile;
		cqp_init_info.ena_vf_count = rf->max_rdma_vfs;
	}
	cqp_init_info.scratch_array = cqp->scratch_array;
	cqp_init_info.rq_scratch_array = cqp->rq_scratch_array;
	cqp_init_info.protocol_used = rf->protocol_used;
	cqp_init_info.en_rem_endpoint_trk = rf->en_rem_endpoint_trk;
	cqp_init_info.timer_slots = rf->timer_slots;
	memcpy(&cqp_init_info.dcqcn_params, &rf->dcqcn_params,
	       sizeof(cqp_init_info.dcqcn_params));

	switch (rf->rdma_ver) {
	case IRDMA_GEN_1:
		cqp_init_info.hw_maj_ver = IRDMA_CQPHC_HW_MAJVER_GEN_1;
		break;
	case IRDMA_GEN_2:
		cqp_init_info.hw_maj_ver = IRDMA_CQPHC_HW_MAJVER_GEN_2;
		break;
	case IRDMA_GEN_3:
	case IRDMA_GEN_4:
		cqp_init_info.hw_maj_ver = IRDMA_CQPHC_HW_MAJVER_GEN_3;
		if (irdma_rca_ena && !rf->ftype)
			cqp_init_info.ts_override = 0;
		else
			cqp_init_info.ts_override = 1;
		break;
	}
	status = irdma_sc_cqp_init(dev->cqp, &cqp_init_info);
	if (status) {
		ibdev_dbg(to_ibdev(dev), "ERR: cqp init status %d\n", status);
		goto err_ctx;
	}

	spin_lock_init(&cqp->req_lock);
	spin_lock_init(&cqp->compl_lock);

	status = irdma_sc_cqp_create(dev->cqp, &maj_err, &min_err);
	if (status) {
		ibdev_dbg(to_ibdev(dev),
			  "ERR: cqp create failed - status %d maj_err %d min_err %d\n",
			  status, maj_err, min_err);
		goto err_ctx;
	}

	INIT_LIST_HEAD(&cqp->cqp_avail_reqs);
	INIT_LIST_HEAD(&cqp->cqp_pending_reqs);

	/* init the waitqueue of the cqp_requests and add them to the list */
	for (i = 0; i < sqsize; i++) {
		init_waitqueue_head(&cqp->cqp_requests[i].waitq);
		list_add_tail(&cqp->cqp_requests[i].list, &cqp->cqp_avail_reqs);
	}
	init_waitqueue_head(&cqp->remove_wq);
	return 0;

err_ctx:
	irdma_free_cqp_rq(dev, cqp);
err_rq:
	dma_free_coherent(dev->hw->device, cqp->sq.size, cqp->sq.va,
			  cqp->sq.pa);
	cqp->sq.va = NULL;
err_sq:
	kfree(cqp->ooo_op_array);
	cqp->ooo_op_array = NULL;
err_oop:
	kfree(cqp->rq_scratch_array);
	cqp->rq_scratch_array = NULL;
err_rq_scratch:
	kfree(cqp->scratch_array);
	cqp->scratch_array = NULL;
err_scratch:
	kfree(cqp->cqp_requests);
	cqp->cqp_requests = NULL;

	return status;
}

/**
 * irdma_create_ccq - create control cq
 * @rf: RDMA PCI function
 *
 * Return 0, if the ccq and the resources associated with it
 * are successfully created, otherwise return error
 */
static int irdma_create_ccq(struct irdma_pci_f *rf)
{
	struct irdma_sc_dev *dev = &rf->sc_dev;
	struct irdma_ccq_init_info info = {};
	struct irdma_ccq *ccq = &rf->ccq;
	int status;
	int ccq_size = (rf->rdma_ver >= IRDMA_GEN_3) ? IW_GEN_3_CCQ_SIZE : IW_CCQ_SIZE;

	dev->ccq = &ccq->sc_cq;
	dev->ccq->dev = dev;
	info.dev = dev;
	ccq->shadow_area.size = sizeof(struct irdma_cq_shadow_area);
	ccq->mem_cq.size = ALIGN(sizeof(struct irdma_cqe) * ccq_size,
				 IRDMA_CQ0_ALIGNMENT);
	ccq->mem_cq.va = dma_alloc_coherent(dev->hw->device, ccq->mem_cq.size,
					    &ccq->mem_cq.pa, GFP_KERNEL);
	if (!ccq->mem_cq.va)
		return -ENOMEM;

	status = irdma_obj_aligned_mem(rf, &ccq->shadow_area,
				       ccq->shadow_area.size,
				       IRDMA_SHADOWAREA_M);
	if (status)
		goto exit;

	ccq->sc_cq.back_cq = ccq;
	/* populate the ccq init info */
	info.cq_base = ccq->mem_cq.va;
	info.cq_pa = ccq->mem_cq.pa;
	info.num_elem = ccq_size;
	info.shadow_area = ccq->shadow_area.va;
	info.shadow_area_pa = ccq->shadow_area.pa;
	info.ceqe_mask = false;
	info.ceq_id_valid = true;
	info.shadow_read_threshold = 16;
	info.vsi = &rf->default_vsi;
	status = irdma_sc_ccq_init(dev->ccq, &info);
	if (!status)
		status = irdma_sc_ccq_create(dev->ccq, 0, true, true);
exit:
	if (status) {
		dma_free_coherent(dev->hw->device, ccq->mem_cq.size,
				  ccq->mem_cq.va, ccq->mem_cq.pa);
		ccq->mem_cq.va = NULL;
	}

	return status;
}

/**
 * irdma_alloc_set_mac - set up a mac address table entry
 * @iwdev: irdma device
 *
 * Allocate a mac ip entry and add it to the hw table Return 0
 * if successful, otherwise return error
 */
static int irdma_alloc_set_mac(struct irdma_device *iwdev)
{
	int status;

	status = irdma_alloc_local_mac_entry(iwdev->rf,
					     &iwdev->mac_ip_table_idx);
	if (!status) {
		status = irdma_add_local_mac_entry(iwdev->rf,
						   (const u8 *)iwdev->netdev->dev_addr,
						   (u8)iwdev->mac_ip_table_idx);
		if (status)
			irdma_del_local_mac_entry(iwdev->rf,
						  (u8)iwdev->mac_ip_table_idx);
	}
	return status;
}

/**
 * irdma_cfg_ceq_vector - set up the msix interrupt vector for
 * ceq
 * @rf: RDMA PCI function
 * @iwceq: ceq associated with the vector
 * @ceq_id: the id number of the iwceq
 * @msix_vec: interrupt vector information
 *
 * Allocate interrupt resources and enable irq handling
 * Return 0 if successful, otherwise return error
 */
static int irdma_cfg_ceq_vector(struct irdma_pci_f *rf, struct irdma_ceq *iwceq,
				u16 ceq_id, struct irdma_msix_vector *msix_vec)
{
	int status;

	if (rf->msix_shared && !ceq_id) {
		snprintf(msix_vec->name, sizeof(msix_vec->name) - 1,
			 "irdma-%s-AEQCEQ-0", dev_name(&rf->pcidev->dev));
		status = request_threaded_irq(msix_vec->irq, NULL,
				irdma_aeq_ceq0_irq_thread, IRQF_ONESHOT,
				msix_vec->name, rf);
	} else {
		snprintf(msix_vec->name, sizeof(msix_vec->name) - 1,
			 "irdma-%s-CEQ-%d",
			 dev_name(&rf->pcidev->dev), ceq_id);
		status = request_threaded_irq(msix_vec->irq, NULL,
				irdma_ceq_irq_thread, IRQF_ONESHOT,
				msix_vec->name, iwceq);
	}
	cpumask_clear(&msix_vec->mask);
	cpumask_set_cpu(msix_vec->cpu_affinity, &msix_vec->mask);
	irq_update_affinity_hint(msix_vec->irq, &msix_vec->mask);
	if (status) {
		ibdev_dbg(&rf->iwdev->ibdev, "ERR: ceq irq config fail\n");
		return status;
	}

	msix_vec->ceq_id = ceq_id;
	if (rf->sc_dev.privileged)
		rf->sc_dev.irq_ops->irdma_cfg_ceq(&rf->sc_dev, ceq_id,
						  msix_vec->idx, true);
	else if (rf->rdma_ver == IRDMA_GEN_2)
		status = irdma_vchnl_req_ceq_vec_map_gen2(&rf->sc_dev, ceq_id,
							  msix_vec->idx);
	else
		status = irdma_vchnl_req_ceq_vec_map(&rf->sc_dev, ceq_id,
						     msix_vec->idx);

	return status;
}

/**
 * irdma_cfg_aeq_vector - set up the msix vector for aeq
 * @rf: RDMA PCI function
 *
 * Allocate interrupt resources and enable irq handling
 * Return 0 if successful, otherwise return error
 */
static int irdma_cfg_aeq_vector(struct irdma_pci_f *rf)
{
	struct irdma_msix_vector *msix_vec = rf->iw_msixtbl;
	int status = 0;

	if (!rf->msix_shared) {
		snprintf(msix_vec->name, sizeof(msix_vec->name) - 1,
			 "irdma-%s-AEQ", dev_name(&rf->pcidev->dev));
		status = request_threaded_irq(msix_vec->irq, NULL,
				irdma_aeq_ceq0_irq_thread, IRQF_ONESHOT,
				msix_vec->name, rf);
	}

	if (status) {
		ibdev_dbg(&rf->iwdev->ibdev, "ERR: aeq irq config fail\n");
		return status;
	}

	if (rf->sc_dev.privileged)
		rf->sc_dev.irq_ops->irdma_cfg_aeq(&rf->sc_dev, msix_vec->idx,
						  true);
	else if (rf->rdma_ver == IRDMA_GEN_2)
		status = irdma_vchnl_req_aeq_vec_map_gen2(&rf->sc_dev,
							  msix_vec->idx);
	else
		status = irdma_vchnl_req_aeq_vec_map(&rf->sc_dev, msix_vec->idx);
	return status;
}

/**
 * irdma_create_ceq - create completion event queue
 * @rf: RDMA PCI function
 * @iwceq: pointer to the ceq resources to be created
 * @ceq_id: the id number of the iwceq
 * @vsi: SC vsi struct
 *
 * Return 0, if the ceq and the resources associated with it
 * are successfully created, otherwise return error
 */
static int irdma_create_ceq(struct irdma_pci_f *rf, struct irdma_ceq *iwceq,
			    u16 ceq_id, struct irdma_sc_vsi *vsi)
{
	int status;
	struct irdma_ceq_init_info info = {};
	struct irdma_sc_dev *dev = &rf->sc_dev;
	u32 ceq_size;

	info.ceq_id = ceq_id;
	iwceq->rf = rf;
	ceq_size = min(rf->sc_dev.hmc_info->hmc_obj[IRDMA_HMC_IW_CQ].cnt,
		       dev->hw_attrs.max_hw_ceq_size);
	iwceq->mem.size = ALIGN(sizeof(struct irdma_ceqe) * ceq_size,
				IRDMA_CEQ_ALIGNMENT);
	iwceq->mem.va = dma_alloc_coherent(dev->hw->device, iwceq->mem.size,
					   &iwceq->mem.pa, GFP_KERNEL);
	if (!iwceq->mem.va)
		return -ENOMEM;

	info.ceq_id = ceq_id;
	info.ceqe_base = iwceq->mem.va;
	info.ceqe_pa = iwceq->mem.pa;
	info.elem_cnt = ceq_size;
	if (dev->hw_wa & CEQ_POLL)
		info.reg_cq = kzalloc(sizeof(struct irdma_sc_cq *) * info.elem_cnt, GFP_KERNEL);

	iwceq->sc_ceq.ceq_id = ceq_id;
	info.dev = dev;
	info.vsi = vsi;
	status = irdma_sc_ceq_init(&iwceq->sc_ceq, &info);
	if (!status) {
		if (dev->ceq_valid)
			status = irdma_cqp_ceq_cmd(&rf->sc_dev, &iwceq->sc_ceq,
						   IRDMA_OP_CEQ_CREATE);
		else
			status = irdma_sc_cceq_create(&iwceq->sc_ceq);
	}

	if (dev->hw_wa & CEQ_POLL && status)
		kfree(info.reg_cq);
	if (status) {
		dma_free_coherent(dev->hw->device, iwceq->mem.size,
				  iwceq->mem.va, iwceq->mem.pa);
		iwceq->mem.va = NULL;
	}

	return status;
}

/**
 * irdma_setup_ceq_0 - create CEQ 0 and it's interrupt resource
 * @rf: RDMA PCI function
 *
 * Allocate a list for all device completion event queues
 * Create the ceq 0 and configure it's msix interrupt vector
 * Return 0, if successfully set up, otherwise return error
 */
static int irdma_setup_ceq_0(struct irdma_pci_f *rf)
{
	struct irdma_ceq *iwceq;
	struct irdma_msix_vector *msix_vec;
	u32 i;
	int status = 0;
	u32 num_ceqs;

	num_ceqs = min(rf->msix_count, rf->sc_dev.hmc_fpm_misc.max_ceqs);
	rf->ceqlist = kcalloc(num_ceqs, sizeof(*rf->ceqlist), GFP_KERNEL);
	if (!rf->ceqlist) {
		status = -ENOMEM;
		goto exit;
	}

	iwceq = &rf->ceqlist[0];
	status = irdma_create_ceq(rf, iwceq, 0, &rf->default_vsi);
	if (status) {
		ibdev_dbg(&rf->iwdev->ibdev, "ERR: create ceq status = %d\n",
			  status);
		goto exit;
	}

	spin_lock_init(&iwceq->ce_lock);
	if (rf->sc_dev.hw_wa & CEQ_POLL) {
		rf->ceqs_count++;
		rf->sc_dev.ceq_valid = true;
		return 0;
	}

	i = rf->msix_shared ? 0 : 1;
	msix_vec = &rf->iw_msixtbl[i];
	iwceq->irq = msix_vec->irq;
	iwceq->msix_idx = msix_vec->idx;
	status = irdma_cfg_ceq_vector(rf, iwceq, 0, msix_vec);
	if (status) {
		irdma_destroy_ceq(rf, iwceq);
		goto exit;
	}

	irdma_ena_intr(&rf->sc_dev, msix_vec->idx);
	rf->ceqs_count++;

exit:
	if (status && !rf->ceqs_count) {
		kfree(rf->ceqlist);
		rf->ceqlist = NULL;
		return status;
	}
	rf->sc_dev.ceq_valid = true;

	return 0;
}

/**
 * irdma_setup_ceqs - manage the device ceq's and their interrupt resources
 * @rf: RDMA PCI function
 * @vsi: VSI structure for this CEQ
 *
 * Allocate a list for all device completion event queues
 * Create the ceq's and configure their msix interrupt vectors
 * Return 0, if ceqs are successfully set up, otherwise return error
 */
static int irdma_setup_ceqs(struct irdma_pci_f *rf, struct irdma_sc_vsi *vsi)
{
	u32 i;
	u16 ceq_id;
	struct irdma_ceq *iwceq;
	struct irdma_msix_vector *msix_vec;
	int status;
	u32 num_ceqs;

	num_ceqs = min(rf->msix_count, rf->sc_dev.hmc_fpm_misc.max_ceqs);
	i = (rf->msix_shared) ? 1 : 2;
	for (ceq_id = 1; i < num_ceqs; i++, ceq_id++) {
		iwceq = &rf->ceqlist[ceq_id];
		status = irdma_create_ceq(rf, iwceq, ceq_id, vsi);
		if (status) {
			ibdev_dbg(&rf->iwdev->ibdev,
				  "ERR: create ceq status = %d\n", status);
			goto del_ceqs;
		}
		spin_lock_init(&iwceq->ce_lock);
		msix_vec = &rf->iw_msixtbl[i];
		iwceq->irq = msix_vec->irq;
		iwceq->msix_idx = msix_vec->idx;
		status = irdma_cfg_ceq_vector(rf, iwceq, ceq_id, msix_vec);
		if (status) {
			irdma_destroy_ceq(rf, iwceq);
			goto del_ceqs;
		}
		irdma_ena_intr(&rf->sc_dev, msix_vec->idx);
		rf->ceqs_count++;
	}

	return 0;

del_ceqs:
	irdma_del_ceqs(rf);

	return status;
}

static int irdma_create_virt_aeq(struct irdma_pci_f *rf, u32 size)
{
	struct irdma_aeq *aeq = &rf->aeq;
	dma_addr_t *pg_arr;
	u32 pg_cnt;
	int status;

	if (rf->rdma_ver < IRDMA_GEN_2)
		return -EOPNOTSUPP;

	aeq->mem.size = sizeof(struct irdma_sc_aeqe) * size;
	aeq->mem.va = vzalloc(aeq->mem.size);

	if (!aeq->mem.va)
		return -ENOMEM;

	pg_cnt = DIV_ROUND_UP(aeq->mem.size, PAGE_SIZE);
	status = irdma_get_pble(rf->pble_rsrc, &aeq->palloc, pg_cnt, true);
	if (status) {
		vfree(aeq->mem.va);
		return status;
	}

	pg_arr = (dma_addr_t *)aeq->palloc.level1.addr;
	status = irdma_map_vm_page_list(&rf->hw, aeq->mem.va, pg_arr, pg_cnt);
	if (status) {
		irdma_free_pble(rf->pble_rsrc, &aeq->palloc);
		vfree(aeq->mem.va);
		return status;
	}

	return 0;
}

/**
 * irdma_create_aeq - create async event queue
 * @rf: RDMA PCI function
 *
 * Return 0, if the aeq and the resources associated with it
 * are successfully created, otherwise return error
 */
static int irdma_create_aeq(struct irdma_pci_f *rf)
{
	struct irdma_aeq_init_info info = {};
	struct irdma_sc_dev *dev = &rf->sc_dev;
	struct irdma_aeq *aeq = &rf->aeq;
	struct irdma_hmc_info *hmc_info = rf->sc_dev.hmc_info;
	u32 aeq_size;
	u8 multiplier = (rf->protocol_used == IRDMA_IWARP_PROTOCOL_ONLY) ? 2 : 1;
	int status;

	aeq_size = multiplier * hmc_info->hmc_obj[IRDMA_HMC_IW_QP].cnt +
		   hmc_info->hmc_obj[IRDMA_HMC_IW_CQ].cnt;
	aeq_size = min(aeq_size, dev->hw_attrs.max_hw_aeq_size);
	/* GEN_3 does not support virtual AEQ. Cap at max Kernel alloc size */
	if (rf->rdma_ver >= IRDMA_GEN_3)
		aeq_size = min(aeq_size, (u32)((PAGE_SIZE << MAX_PAGE_ORDER) /
			       sizeof(struct irdma_sc_aeqe)));
	aeq->mem.size = ALIGN(sizeof(struct irdma_sc_aeqe) * aeq_size,
			      IRDMA_AEQ_ALIGNMENT);
	aeq->mem.va = dma_alloc_coherent(dev->hw->device, aeq->mem.size,
					 &aeq->mem.pa,
					 GFP_KERNEL | __GFP_NOWARN);
	if (aeq->mem.va)
		goto skip_virt_aeq;
	else if (rf->rdma_ver >= IRDMA_GEN_3)
		return -ENOMEM;

	/* physically mapped aeq failed. setup virtual aeq */
	status = irdma_create_virt_aeq(rf, aeq_size);
	if (status)
		return status;

	info.virtual_map = true;
	aeq->virtual_map = info.virtual_map;
	info.pbl_chunk_size = 1;
	info.first_pm_pbl_idx = aeq->palloc.level1.idx;

skip_virt_aeq:
	info.aeqe_base = aeq->mem.va;
	info.aeq_elem_pa = aeq->mem.pa;
	info.elem_cnt = aeq_size;
	info.dev = dev;
	info.msix_idx = rf->iw_msixtbl->idx;
	status = irdma_sc_aeq_init(&aeq->sc_aeq, &info);
	if (status)
		goto err;

	status = irdma_cqp_aeq_cmd(dev, &aeq->sc_aeq, IRDMA_OP_AEQ_CREATE);
	if (status)
		goto err;

	return 0;

err:
	if (aeq->virtual_map)
		irdma_destroy_virt_aeq(rf);
	else {
		dma_free_coherent(dev->hw->device, aeq->mem.size, aeq->mem.va,
				  aeq->mem.pa);
		aeq->mem.va = NULL;
	}

	return status;
}

/**
 * irdma_setup_aeq - set up the device aeq
 * @rf: RDMA PCI function
 *
 * Create the aeq and configure its msix interrupt vector
 * Return 0 if successful, otherwise return error
 */
static int irdma_setup_aeq(struct irdma_pci_f *rf)
{
	struct irdma_sc_dev *dev = &rf->sc_dev;
	int status;

	status = irdma_create_aeq(rf);
	if (status)
		return status;

	if (dev->hw_wa & CEQ_POLL)
		return 0;
	status = irdma_cfg_aeq_vector(rf);
	if (status) {
		irdma_destroy_aeq(rf);
		return status;
	}

	if (!rf->msix_shared)
		irdma_ena_intr(dev, rf->iw_msixtbl[0].idx);

	return 0;
}

/**
 * irdma_initialize_ilq - create iwarp local queue for cm
 * @iwdev: irdma device
 *
 * Return 0 if successful, otherwise return error
 */
static int irdma_initialize_ilq(struct irdma_device *iwdev)
{
	struct irdma_puda_rsrc_info info = {};
	int status;

	info.type = IRDMA_PUDA_RSRC_TYPE_ILQ;
	info.cq_id = 1;
	info.qp_id = 1;
	info.count = 1;
	info.pd_id = 1;
	info.abi_ver = IRDMA_ABI_VER;
	info.sq_size = min(iwdev->rf->max_qp / 2, (u32)32768);
	info.rq_size = info.sq_size;
	info.buf_size = 1024;
	info.tx_buf_cnt = 2 * info.sq_size;
	info.receive = irdma_receive_ilq;
	info.xmit_complete = irdma_free_sqbuf;
	status = irdma_puda_create_rsrc(&iwdev->vsi, &info);
	if (status)
		ibdev_dbg(&iwdev->ibdev, "ERR: ilq create fail\n");

	return status;
}

/**
 * irdma_initialize_ieq - create iwarp exception queue
 * @iwdev: irdma device
 *
 * Return 0 if successful, otherwise return error
 */
static int irdma_initialize_ieq(struct irdma_device *iwdev)
{
	struct irdma_puda_rsrc_info info = {};
	int status;

	info.type = IRDMA_PUDA_RSRC_TYPE_IEQ;
	info.cq_id = 2;
	info.qp_id = iwdev->vsi.exception_lan_q;
	info.count = 1;
	info.pd_id = 2;
	info.abi_ver = IRDMA_ABI_VER;
	info.sq_size = min(iwdev->rf->max_qp / 2, (u32)32768);
	info.rq_size = info.sq_size;
	info.buf_size = iwdev->vsi.mtu + IRDMA_IPV4_PAD;
	info.tx_buf_cnt = 4096;
	status = irdma_puda_create_rsrc(&iwdev->vsi, &info);
	if (status)
		ibdev_dbg(&iwdev->ibdev, "ERR: ieq create fail\n");

	return status;
}

/**
 * irdma_reinitialize_ieq - destroy and re-create ieq
 * @vsi: VSI structure
 */
void irdma_reinitialize_ieq(struct irdma_sc_vsi *vsi)
{
	struct irdma_device *iwdev = vsi->back_vsi;
	struct irdma_pci_f *rf = iwdev->rf;

	irdma_puda_dele_rsrc(vsi, IRDMA_PUDA_RSRC_TYPE_IEQ, false);
	if (irdma_initialize_ieq(iwdev)) {
		iwdev->rf->reset = true;
		rf->gen_ops.request_reset(rf);
	}
}

/**
 * irdma_hmc_setup - create hmc objects for the device
 * @rf: RDMA PCI function
 *
 * Set up the device private memory space for the number and size of
 * the hmc objects and create the objects
 * Return 0 if successful, otherwise return error
 */
static int irdma_hmc_setup(struct irdma_pci_f *rf)
{
	struct irdma_sc_dev *dev = &rf->sc_dev;
	int status;
	u32 qpcnt;

	qpcnt = IRDMA_MAX_MEV_QPCNT;
	rf->sd_type = IRDMA_SD_TYPE_DIRECT;
	status = irdma_cfg_fpm_val(dev, qpcnt);
	if (status)
		return status;

	status = irdma_create_hmc_objs(rf, true, rf->rdma_ver);

	return status;
}

/**
 * irdma_del_init_mem - deallocate memory resources
 * @rf: RDMA PCI function
 */
static void irdma_del_init_mem(struct irdma_pci_f *rf)
{
	struct irdma_sc_dev *dev = &rf->sc_dev;

	if (!rf->sc_dev.privileged)
		irdma_vchnl_req_put_hmc_fcn(&rf->sc_dev);
	kfree(dev->hmc_info->sd_table.sd_entry);
	dev->hmc_info->sd_table.sd_entry = NULL;
	vfree(rf->mem_rsrc);
	rf->mem_rsrc = NULL;
	dma_free_coherent(rf->hw.device, rf->obj_mem.size, rf->obj_mem.va,
			  rf->obj_mem.pa);
	rf->obj_mem.va = NULL;
	if (rf->rdma_ver != IRDMA_GEN_1) {
		kfree(rf->allocated_ws_nodes);
		rf->allocated_ws_nodes = NULL;
	}
	kfree(rf->ceqlist);
	rf->ceqlist = NULL;
	kfree(rf->iw_msixtbl);
	rf->iw_msixtbl = NULL;
	kfree(rf->hmc_info_mem);
	rf->hmc_info_mem = NULL;
}
/**
 * irdma_initialize_dev - initialize device
 * @rf: RDMA PCI function
 *
 * Allocate memory for the hmc objects and initialize iwdev
 * Return 0 if successful, otherwise clean up the resources
 * and return error
 */
static int irdma_initialize_dev(struct irdma_pci_f *rf)
{
	int status;
	struct irdma_sc_dev *dev = &rf->sc_dev;
	struct irdma_device_init_info info = {};
	struct irdma_dma_mem mem;
	u32 size;

	size = sizeof(struct irdma_hmc_pble_rsrc) +
	       sizeof(struct irdma_hmc_info) +
	       (sizeof(struct irdma_hmc_obj_info) * IRDMA_HMC_IW_MAX);

	rf->hmc_info_mem = kzalloc(size, GFP_KERNEL);
	if (!rf->hmc_info_mem)
		return -ENOMEM;

	rf->pble_rsrc = (struct irdma_hmc_pble_rsrc *)rf->hmc_info_mem;
	dev->hmc_info = &rf->hw.hmc;
	dev->hmc_info->hmc_obj = (struct irdma_hmc_obj_info *)
				 (rf->pble_rsrc + 1);

	status = irdma_obj_aligned_mem(rf, &mem, IRDMA_QUERY_FPM_BUF_SIZE,
				       IRDMA_FPM_QUERY_BUF_ALIGNMENT_M);
	if (status)
		goto error;

	info.fpm_query_buf_pa = mem.pa;
	info.fpm_query_buf = mem.va;

	status = irdma_obj_aligned_mem(rf, &mem, IRDMA_COMMIT_FPM_BUF_SIZE,
				       IRDMA_FPM_COMMIT_BUF_ALIGNMENT_M);
	if (status)
		goto error;

	info.fpm_commit_buf_pa = mem.pa;
	info.fpm_commit_buf = mem.va;

	info.bar0 = rf->hw.hw_addr;
	/* Not used in SRIOV VF mode */
	info.hmc_fn_id = rf->pf_id;
	info.protocol_used = rf->protocol_used;
	info.max_vfs = rf->max_rdma_vfs;
	info.hw = &rf->hw;
	status = irdma_sc_dev_init(&rf->sc_dev, &info);
	if (status)
		goto error;

	if (!rf->sc_dev.privileged && dev->hw_attrs.uk_attrs.hw_rev <= IRDMA_GEN_2)
		status = irdma_vchnl_req_get_vlan_parsing_cfg(
				&rf->sc_dev, &rf->vlan_parse_en);
	else
		rf->vlan_parse_en = 1;
	if (status)
		goto error;
	return status;
error:
	kfree(rf->hmc_info_mem);
	rf->hmc_info_mem = NULL;

	return status;
}

/**
 * irdma_rt_deinit_hw - clean up the irdma device resources
 * @iwdev: irdma device
 *
 * remove the mac ip entry and ipv4/ipv6 addresses, destroy the
 * device queues and free the pble and the hmc objects
 */
void irdma_rt_deinit_hw(struct irdma_device *iwdev)
{
	struct irdma_sc_qp qp = {};
	ibdev_dbg(&iwdev->ibdev, "INIT: state = %d\n", iwdev->init_state);

	switch (iwdev->init_state) {
	case IP_ADDR_REGISTERED:
		if (iwdev->rf->sc_dev.hw_attrs.uk_attrs.hw_rev == IRDMA_GEN_1)
			irdma_del_local_mac_entry(iwdev->rf,
						  (u8)iwdev->mac_ip_table_idx);
		fallthrough;
	case AEQ_CREATED:
	case PBLE_CHUNK_MEM:
	case CEQS_CREATED:
	case REM_ENDPOINT_TRK_CREATED:
		if (iwdev->rf->en_rem_endpoint_trk) {
			qp.dev = &iwdev->rf->sc_dev;
			qp.qp_uk.qp_id = IRDMA_REM_ENDPOINT_TRK_QPID;
			qp.qp_uk.qp_type = IRDMA_QP_TYPE_IWARP;
			irdma_cqp_qp_destroy_cmd(qp.dev, &qp);
		}
		fallthrough;
	case IEQ_CREATED:
		if (!iwdev->roce_mode)
			irdma_puda_dele_rsrc(&iwdev->vsi, IRDMA_PUDA_RSRC_TYPE_IEQ,
					     iwdev->rf->reset);
		fallthrough;
	case ILQ_CREATED:
		if (!iwdev->roce_mode)
			irdma_puda_dele_rsrc(&iwdev->vsi,
					     IRDMA_PUDA_RSRC_TYPE_ILQ,
					     iwdev->rf->reset);
		break;
	default:
		ibdev_warn(&iwdev->ibdev, "bad init_state = %d\n", iwdev->init_state);
		break;
	}

	irdma_cleanup_cm_core(&iwdev->cm_core);
	if (iwdev->vsi.pestat) {
		irdma_vsi_stats_free(&iwdev->vsi);
		kfree(iwdev->vsi.pestat);
	}
	if (iwdev->cleanup_wq)
		destroy_workqueue(iwdev->cleanup_wq);
}

static int irdma_setup_init_state(struct irdma_pci_f *rf)
{
	int status;
	struct irdma_sc_dev *dev = &rf->sc_dev;

	if ((dev->hw_wa & NO_INTR) == 0) {
		status = irdma_save_msix_info(rf);
		if (status)
			return status;
	}

	rf->obj_mem.size = ALIGN(8192, IRDMA_HW_PAGE_SIZE);
	rf->obj_mem.va = dma_alloc_coherent(rf->hw.device, rf->obj_mem.size,
					    &rf->obj_mem.pa, GFP_KERNEL);
	if (!rf->obj_mem.va) {
		status = -ENOMEM;
		goto clean_msixtbl;
	}

	rf->obj_next = rf->obj_mem;
	status = irdma_initialize_dev(rf);
	if (status)
		goto clean_obj_mem;

	return 0;

clean_obj_mem:
	dma_free_coherent(rf->hw.device, rf->obj_mem.size, rf->obj_mem.va,
			  rf->obj_mem.pa);
	rf->obj_mem.va = NULL;
clean_msixtbl:
	kfree(rf->iw_msixtbl);
	rf->iw_msixtbl = NULL;
	return status;
}

/**
 * irdma_get_used_rsrc - determine resources used internally
 * @iwdev: irdma device
 *
 * Called at the end of open to get all internal allocations
 */
static void irdma_get_used_rsrc(struct irdma_device *iwdev)
{
	iwdev->rf->used_pds = find_first_zero_bit(iwdev->rf->allocated_pds,
						  iwdev->rf->max_pd);
	iwdev->rf->used_qps = find_first_zero_bit(iwdev->rf->allocated_qps,
						  iwdev->rf->max_qp);
	iwdev->rf->used_cqs = find_first_zero_bit(iwdev->rf->allocated_cqs,
						  iwdev->rf->max_cq);
	iwdev->rf->used_srqs = find_first_zero_bit(iwdev->rf->allocated_srqs,
						   iwdev->rf->max_srq);
	iwdev->rf->used_mrs = find_first_zero_bit(iwdev->rf->allocated_mrs,
						  iwdev->rf->max_mr);
}

void irdma_ctrl_deinit_hw(struct irdma_pci_f *rf)
{
	enum init_completion_state state = rf->init_state;

	if ((rf->sc_dev.hw_wa & TIMER_NEEDED) && rf->poll_thread) {
		kthread_stop(rf->poll_thread);
		rf->poll_thread = NULL;
	}

	rf->init_state = INVALID_STATE;
	if (rf->rsrc_created) {
		irdma_destroy_aeq(rf);
		irdma_destroy_pble_prm(rf->pble_rsrc);
		irdma_del_ceqs(rf);
		rf->rsrc_created = false;
	}

	switch (state) {
	case CEQ0_CREATED:
		irdma_del_ceq_0(rf);
		fallthrough;
	case CCQ_CREATED:
		irdma_destroy_ccq(rf);
		fallthrough;
	case HW_RSRC_INITIALIZED:
	case HMC_OBJS_CREATED:
		irdma_del_hmc_objects(&rf->sc_dev, rf->sc_dev.hmc_info, true,
				      rf->reset, rf->rdma_ver);
		fallthrough;
	case CQP_CREATED:
		irdma_destroy_cqp(rf, !rf->reset);
		fallthrough;
	case INITIAL_STATE:
		irdma_del_init_mem(rf);
		break;
	case INVALID_STATE:
	default:
		ibdev_warn(&rf->iwdev->ibdev, "bad init_state = %d\n", rf->init_state);
		break;
	}
}

/**
 * irdma_rt_init_hw - Initializes runtime portion of HW
 * @iwdev: irdma device
 * @l2params: qos, tc, mtu info from netdev driver
 *
 * Create device queues ILQ, IEQ, CEQs and PBLEs. Setup irdma
 * device resource objects.
 */
int irdma_rt_init_hw(struct irdma_device *iwdev,
		     struct irdma_l2params *l2params)
{
	struct irdma_pci_f *rf = iwdev->rf;
	struct irdma_sc_dev *dev = &rf->sc_dev;
	struct irdma_sc_qp qp = {};
	struct irdma_vsi_init_info vsi_info = {};
	struct irdma_vsi_stats_info stats_info = {};
	int status;

	vsi_info.vm_vf_type = rf->ftype ? IRDMA_VF_TYPE : IRDMA_PF_TYPE;
	vsi_info.dev = dev;
	vsi_info.back_vsi = iwdev;
	vsi_info.params = l2params;
	vsi_info.pf_data_vsi_num = iwdev->vsi_num;

	vsi_info.register_qset = rf->gen_ops.register_qset;
	vsi_info.unregister_qset = rf->gen_ops.unregister_qset;
	vsi_info.exception_lan_q = 2;
	irdma_sc_vsi_init(&iwdev->vsi, &vsi_info);

	status = irdma_setup_cm_core(iwdev, rf->rdma_ver);
	if (status)
		return status;

	stats_info.pestat = kzalloc(sizeof(*stats_info.pestat), GFP_KERNEL);
	if (!stats_info.pestat) {
		irdma_cleanup_cm_core(&iwdev->cm_core);
		return -ENOMEM;
	}
	stats_info.fcn_id = dev->hmc_fn_id;
	status = irdma_vsi_stats_init(&iwdev->vsi, &stats_info);
	if (status) {
		irdma_cleanup_cm_core(&iwdev->cm_core);
		kfree(stats_info.pestat);
		return status;
	}

	do {
		if (!iwdev->roce_mode) {
			status = irdma_initialize_ilq(iwdev);
			if (status)
				break;
			iwdev->init_state = ILQ_CREATED;
			status = irdma_initialize_ieq(iwdev);
			if (status)
				break;
			iwdev->init_state = IEQ_CREATED;
		}
		if (iwdev->rf->en_rem_endpoint_trk) {
			qp.dev = dev;
			qp.qp_uk.qp_id = IRDMA_REM_ENDPOINT_TRK_QPID;
			qp.qp_uk.qp_type = IRDMA_QP_TYPE_IWARP;
			status = irdma_cqp_qp_create_cmd(dev, &qp);
			if (status)
				break;
			iwdev->init_state = REM_ENDPOINT_TRK_CREATED;
		}
		if (!rf->rsrc_created) {
			status = irdma_setup_ceqs(rf, &iwdev->vsi);
			if (status)
				break;

			iwdev->init_state = CEQS_CREATED;

			status = irdma_hmc_init_pble(&rf->sc_dev,
						     rf->pble_rsrc);
			if (status) {
				irdma_del_ceqs(rf);
				break;
			}

			iwdev->init_state = PBLE_CHUNK_MEM;

			status = irdma_setup_aeq(rf);
			if (status) {
				irdma_destroy_pble_prm(rf->pble_rsrc);
				irdma_del_ceqs(rf);
				break;
			}
			iwdev->init_state = AEQ_CREATED;
			rf->rsrc_created = true;
		}

		if (iwdev->rf->sc_dev.hw_attrs.uk_attrs.hw_rev == IRDMA_GEN_1)
			irdma_alloc_set_mac(iwdev);
		irdma_add_ip(iwdev);
		iwdev->init_state = IP_ADDR_REGISTERED;

		/* handles asynch cleanup tasks - disconnect CM , free qp,
		 * free cq bufs
		 */
		iwdev->cleanup_wq = alloc_workqueue("irdma-cleanup-wq",
						    WQ_UNBOUND, WQ_UNBOUND_MAX_ACTIVE);
		if (!iwdev->cleanup_wq)
			return -ENOMEM;
		irdma_get_used_rsrc(iwdev);
		init_waitqueue_head(&iwdev->suspend_wq);

		return 0;
	} while (0);

	dev_err(&rf->pcidev->dev, "HW runtime init FAIL status = %d last cmpl = %d\n",
		status, iwdev->init_state);
	irdma_rt_deinit_hw(iwdev);

	return status;
}

/**
 * irdma_ctrl_init_hw - Initializes control portion of HW
 * @rf: RDMA PCI function
 *
 * Create admin queues, HMC obejcts and RF resource objects
 */
int irdma_ctrl_init_hw(struct irdma_pci_f *rf)
{
	struct irdma_sc_dev *dev = &rf->sc_dev;
	int status;

	do {
		status = irdma_setup_init_state(rf);
		if (status)
			break;
		rf->init_state = INITIAL_STATE;

		status = irdma_create_cqp(rf);
		if (status)
			break;
		rf->init_state = CQP_CREATED;

		dev->feature_info[IRDMA_FEATURE_FW_INFO] = IRDMA_FW_VER_DEFAULT;
		if (rf->rdma_ver != IRDMA_GEN_1) {
			status = irdma_get_rdma_features(dev);
			if (status)
				break;
		}

		status = irdma_hmc_setup(rf);
		if (status)
			break;
		rf->init_state = HMC_OBJS_CREATED;

		status = irdma_initialize_hw_rsrc(rf);
		if (status)
			break;
		rf->init_state = HW_RSRC_INITIALIZED;

		status = irdma_create_ccq(rf);
		if (status)
			break;
		rf->init_state = CCQ_CREATED;

		status = irdma_setup_ceq_0(rf);
		if (status)
			break;
		rf->init_state = CEQ0_CREATED;
		/* Handles processing of CQP completions */
		rf->cqp_cmpl_wq = alloc_ordered_workqueue("cqp_cmpl_wq",
							  WQ_HIGHPRI | WQ_UNBOUND);
		if (!rf->cqp_cmpl_wq) {
			status = -ENOMEM;
			break;
		}
		INIT_WORK(&rf->cqp_cmpl_work, cqp_compl_worker);
		if (dev->hw_wa & CCQ_CQ3_POLL)
			return 0;
		irdma_sc_ccq_arm(dev->ccq);
		return 0;
	} while (0);

	pr_err("IRDMA hardware initialization FAILED init_state=%d status=%d\n",
	       rf->init_state, status);
	irdma_ctrl_deinit_hw(rf);
	return status;
}

/**
 * irdma_set_hw_rsrc - set hw memory resources.
 * @rf: RDMA PCI function
 */
static void irdma_set_hw_rsrc(struct irdma_pci_f *rf)
{
	rf->allocated_qps = (void *)(rf->mem_rsrc +
		   (sizeof(struct irdma_arp_entry) * rf->arp_table_size));
	rf->allocated_cqs = &rf->allocated_qps[BITS_TO_LONGS(rf->max_qp)];
	rf->allocated_srqs = &rf->allocated_cqs[BITS_TO_LONGS(rf->max_cq)];
	rf->allocated_mrs = &rf->allocated_srqs[BITS_TO_LONGS(rf->max_srq)];
	rf->allocated_pds = &rf->allocated_mrs[BITS_TO_LONGS(rf->max_mr)];
	rf->allocated_ahs = &rf->allocated_pds[BITS_TO_LONGS(rf->max_pd)];
	rf->allocated_mcgs = &rf->allocated_ahs[BITS_TO_LONGS(rf->max_ah)];
	rf->allocated_arps = &rf->allocated_mcgs[BITS_TO_LONGS(rf->max_mcg)];

	rf->qp_table = (struct irdma_qp **)
		(&rf->allocated_arps[BITS_TO_LONGS(rf->arp_table_size)]);
	rf->cq_table = (struct irdma_cq **)(&rf->qp_table[rf->max_qp]);
	rf->srq_table = (struct irdma_srq **)(&rf->cq_table[rf->max_cq]);

	spin_lock_init(&rf->rsrc_lock);
	spin_lock_init(&rf->arp_lock);
	spin_lock_init(&rf->qptable_lock);
	spin_lock_init(&rf->cqtable_lock);
	spin_lock_init(&rf->srqtable_lock);
	spin_lock_init(&rf->qh_list_lock);
}

/**
 * irdma_calc_mem_rsrc_size - calculate memory resources size.
 * @rf: RDMA PCI function
 */
static u32 irdma_calc_mem_rsrc_size(struct irdma_pci_f *rf)
{
	u32 rsrc_size;

	rsrc_size = sizeof(struct irdma_arp_entry) * rf->arp_table_size;
	rsrc_size += sizeof(unsigned long) * BITS_TO_LONGS(rf->max_qp);
	rsrc_size += sizeof(unsigned long) * BITS_TO_LONGS(rf->max_mr);
	rsrc_size += sizeof(unsigned long) * BITS_TO_LONGS(rf->max_cq);
	rsrc_size += sizeof(unsigned long) * BITS_TO_LONGS(rf->max_srq);
	rsrc_size += sizeof(unsigned long) * BITS_TO_LONGS(rf->max_pd);
	rsrc_size += sizeof(unsigned long) * BITS_TO_LONGS(rf->arp_table_size);
	rsrc_size += sizeof(unsigned long) * BITS_TO_LONGS(rf->max_ah);
	rsrc_size += sizeof(unsigned long) * BITS_TO_LONGS(rf->max_mcg);
	rsrc_size += sizeof(struct irdma_qp **) * rf->max_qp;
	rsrc_size += sizeof(struct irdma_cq **) * rf->max_cq;
	rsrc_size += sizeof(struct irdma_srq **) * rf->max_srq;

	return rsrc_size;
}

/**
 * irdma_initialize_hw_rsrc - initialize hw resource tracking array
 * @rf: RDMA PCI function
 */
u32 irdma_initialize_hw_rsrc(struct irdma_pci_f *rf)
{
	u32 rsrc_size;
	u32 mrdrvbits;
	u32 ret;

	if (rf->rdma_ver != IRDMA_GEN_1) {
		rf->allocated_ws_nodes =
			kcalloc(BITS_TO_LONGS(IRDMA_MAX_WS_NODES),
				sizeof(unsigned long), GFP_KERNEL);
		if (!rf->allocated_ws_nodes)
			return -ENOMEM;

		set_bit(0, rf->allocated_ws_nodes);
		rf->max_ws_node_id = IRDMA_MAX_WS_NODES;
	}
	rf->max_cqe = rf->sc_dev.hw_attrs.uk_attrs.max_hw_cq_size;
	rf->max_qp = rf->sc_dev.hmc_info->hmc_obj[IRDMA_HMC_IW_QP].cnt;
	rf->max_mr = rf->sc_dev.hmc_info->hmc_obj[IRDMA_HMC_IW_MR].cnt;
	rf->max_cq = rf->sc_dev.hmc_info->hmc_obj[IRDMA_HMC_IW_CQ].cnt;
	rf->max_srq = rf->sc_dev.hmc_info->hmc_obj[IRDMA_HMC_IW_SRQ].cnt;
	rf->max_pd = rf->sc_dev.hw_attrs.max_hw_pds;
	rf->arp_table_size = rf->sc_dev.hmc_info->hmc_obj[IRDMA_HMC_IW_ARP].cnt;
	rf->max_ah = rf->sc_dev.hmc_info->hmc_obj[IRDMA_HMC_IW_FSIAV].cnt;
	rf->max_mcg = rf->max_qp;

	rsrc_size = irdma_calc_mem_rsrc_size(rf);
	rf->mem_rsrc = vzalloc(rsrc_size);
	if (!rf->mem_rsrc) {
		ret = -ENOMEM;
		goto mem_rsrc_vmalloc_fail;
	}

	rf->arp_table = (struct irdma_arp_entry *)rf->mem_rsrc;

	irdma_set_hw_rsrc(rf);

	set_bit(0, rf->allocated_mrs);
	if (rf->sc_dev.hw_wa & NO_STAG0)
		set_bit(1, rf->allocated_mrs);
	set_bit(0, rf->allocated_qps);
	set_bit(0, rf->allocated_cqs);
	set_bit(0, rf->allocated_srqs);
	set_bit(0, rf->allocated_pds);
	set_bit(0, rf->allocated_arps);
	set_bit(0, rf->allocated_ahs);
	set_bit(0, rf->allocated_mcgs);
	set_bit(2, rf->allocated_qps); /* qp 2 IEQ */
	set_bit(1, rf->allocated_qps); /* qp 1 ILQ */
	set_bit(IRDMA_REM_ENDPOINT_TRK_QPID, rf->allocated_qps); /* qp 3 Remote Endpt trk */
	set_bit(1, rf->allocated_cqs);
	set_bit(1, rf->allocated_pds);
	set_bit(2, rf->allocated_cqs);
	set_bit(2, rf->allocated_pds);

	INIT_LIST_HEAD(&rf->mc_qht_list.list);
	/* stag index mask has a minimum of 14 bits */
	mrdrvbits = 24 - max(get_count_order(rf->max_mr), 14);
	/* stag index mask has a minimum of 16 bits for MMG */
	if (rf->rdma_ver >= IRDMA_GEN_4)
		mrdrvbits = 24 - max(get_count_order(rf->max_mr), 16);
	rf->mr_stagmask = ~(((1 << mrdrvbits) - 1) << (32 - mrdrvbits));

	return 0;

mem_rsrc_vmalloc_fail:
	kfree(rf->allocated_ws_nodes);
	rf->allocated_ws_nodes = NULL;

	return ret;
}

/**
 * irdma_cqp_ce_handler_rca - handle cqp completions for forwarded CQP ops
 * @rf: RDMA PCI function
 * @cq: cq for cqp completions
 * @info: completion info
 *
 * This routine is only used for testing, where the driver running
 * on an APF (e.g. ACC) acts as an RCA.
 */
static
void irdma_cqp_ce_handler_rca(struct irdma_pci_f *rf, struct irdma_sc_cq *cq,
			      struct irdma_ccq_cqe_info *info)
{
	struct irdma_sc_dev *dev = &rf->sc_dev;
	struct irdma_cqp_rqe_bufs *rqe =
		(struct irdma_cqp_rqe_bufs *)(uintptr_t)info->scratch;
	struct irdma_ret_cqp_cmpl_info rcacmplinfo = {};
	struct irdma_rca_exec_fwd_op_info fwd_op_info = {};

	static u16 uniq_ooo_id = 0x1000;

	__le64 *wqe = rqe->small_buf.va;
	u64 temp;
	u16 op;
	u16 orig_hmc_fcn_id;
	u16 orig_wq_desc_idx;
	u16 op_ret_val;
	u16 deferred_info = 0;
	u16 maj_err_code;
	u16 min_err_code;
	int error;
	int pending = 1;	/* return pending completion first */
	int execute = 1;	/* execute on behalf on originating function */

	struct irdma_device *iwdev = rf->iwdev;

	if (!iwdev) {
		pr_err("irdma_device not found!\n");
		return;
	}

	if (info->error)
		ibdev_err(&rf->iwdev->ibdev,
			  "CQP: [Error] maj=0x%x min=0x%x\n",
			  info->maj_err_code, info->min_err_code);

	/* These error codes indicate that one of the functions with CQP op
	 * forwarding enabled is being reset.  It means there is no forwarded
	 * CQP op to be processed.
	 * Also, we should clean up all the deferred CQP requests (if any)
	 * for given function, as there will be no final completions for them.
	 */
	if (info->maj_err_code == 0xf002 && info->min_err_code == 0x0001) {
		ibdev_err(&rf->iwdev->ibdev,
			  "CQP: [RCA Function Reset Error] maj=0x%x min=0x%x hmc_fcn_id=%u\n",
			  info->maj_err_code, info->min_err_code,
			  info->orig_hmc_fcn_id);

		/* TBD: clean up pending list */
		return;
	}

	execute = (iwdev->rca_config & IRDMA_RCA_CFG_EXECUTE) != 0;
	pending = (iwdev->rca_config & IRDMA_RCA_CFG_PENDING) != 0;

	print_hex_dump_debug("CQP: FORWARDED CQP WQE ",
			     DUMP_PREFIX_OFFSET, 16, 8,
			     rqe->small_buf.va,
			     IRDMA_CQP_RQ_SMALL_BUF_SZ, false);
	print_hex_dump_debug("CQP: FORWARDED CQP DATA ",
			     DUMP_PREFIX_OFFSET, 16, 8,
			     rqe->large_buf.va,
			     IRDMA_CQP_RQ_LARGE_BUF_SZ, false);

	/* Extract originating function index, WQ desc index and CQP opcode
	 * from the forwarded WQE.
	 */
	get_64bit_val(wqe, 0, &temp);
	orig_hmc_fcn_id = info->orig_hmc_fcn_id;
	orig_wq_desc_idx = info->orig_wq_desc_idx;

	get_64bit_val(wqe, 24, &temp);
	op = (u16)FIELD_GET(IRDMA_CQPSQ_OPCODE, temp);

	rcacmplinfo.rqe_idx = info->rqe_idx;

	/* issue command to local CQP for the function */
	rcacmplinfo.hmc_fcn_id = orig_hmc_fcn_id;
	rcacmplinfo.pending = pending;

	rcacmplinfo.cqe_values[0] =
		FIELD_PREP(IRDMA_CQ_HMC_FCN_ID, orig_hmc_fcn_id) |
		FIELD_PREP(IRDMA_CQ_WQEIDX, orig_wq_desc_idx);

	/* QP_Completion Contex is filled by CQP */
	rcacmplinfo.cqe_values[1] = 0x0000000000000000;

	/* return pending completion first */
	if (pending) {
		op_ret_val = 0;
		deferred_info = uniq_ooo_id++;

		rcacmplinfo.cqe_values[2] =
			FIELD_PREP(IRDMA_CCQ_DEFINFO, deferred_info) |
			FIELD_PREP(IRDMA_CCQ_OPRETVAL, op_ret_val);

		/* TBD: Major/minor error codes are populated/overwritten
		 * by CQP, but we set them here as a WA for a bug in older
		 * versions of Simics.
		 */
		rcacmplinfo.cqe_values[3] =
			FIELD_PREP(IRDMA_CQ_SQ, 1) |
			FIELD_PREP(IRDMACQ_OP, op) |
			FIELD_PREP(IRDMA_OOO_CMPL, 0) |
			FIELD_PREP(IRDMA_CQ_WQEIDX, orig_wq_desc_idx) |
			FIELD_PREP(IRDMA_CQ_ERROR, 0) |
			FIELD_PREP(IRDMA_CQ_MAJERR, IRDMA_CQPSQ_MAJ_NO_ERROR) |
			FIELD_PREP(IRDMA_CQ_MINERR, IRDMA_CQPSQ_MIN_OOO_CMPL);

		irdma_cqp_ret_cqp_cmpl(dev, &rcacmplinfo);
	}

	if (execute) {
		switch (op) {
		case IRDMA_CQP_OP_NOP:
			op_ret_val = 0;
			error = 0;
			maj_err_code = IRDMA_CQPSQ_MAJ_NO_ERROR;
			min_err_code = 0;
			break;

		case IRDMA_CQP_OP_REG_MR:
		case IRDMA_CQP_OP_CREATE_ADDR_HANDLE:
		case IRDMA_CQP_OP_MODIFY_ADDR_HANDLE:
		case IRDMA_CQP_OP_DESTROY_ADDR_HANDLE:
		case IRDMA_CQP_OP_UPLOAD_CONTEXT:
		case IRDMA_CQP_OP_CREATE_QP:
		case IRDMA_CQP_OP_MODIFY_QP:
		case IRDMA_CQP_OP_DESTROY_QP:
			memcpy(&fwd_op_info.wqe, wqe, sizeof(fwd_op_info.wqe));

			fwd_op_info.rqe_idx = info->rqe_idx;
			fwd_op_info.orig_hmc_fcn_id = orig_hmc_fcn_id;
			fwd_op_info.orig_wq_desc_idx = orig_wq_desc_idx;
			fwd_op_info.deferred_info = deferred_info;
			fwd_op_info.op_code = op;
			fwd_op_info.pending = pending;
			fwd_op_info.buf_addr = rqe->large_buf.pa;
			fwd_op_info.scratch = info->scratch;
			irdma_cqp_rca_exec_fwd_op(dev, &fwd_op_info);
			/* completion will be sent back by RCA callback */
			return;

		default:
			op_ret_val = 0;
			error = 1;
			maj_err_code = IRDMA_CQPSQ_MAJ_ERROR;
			min_err_code = 0xFFF1;
			break;
		}
	} else {
		op_ret_val = 0;
		error = 1;
		maj_err_code = IRDMA_CQPSQ_MAJ_ERROR;
		min_err_code = 0xFFF0;
	}

	/* return final completion */
	rcacmplinfo.pending = 0;

	/* build CQE in return WQE */
	rcacmplinfo.cqe_values[2] =
		FIELD_PREP(IRDMA_CCQ_DEFINFO, deferred_info) |
		FIELD_PREP(IRDMA_CCQ_OPRETVAL, op_ret_val);

	rcacmplinfo.cqe_values[3] =
		FIELD_PREP(IRDMA_CQ_SQ, 1) |
		FIELD_PREP(IRDMACQ_OP, op) |
		FIELD_PREP(IRDMA_OOO_CMPL, pending) |
		FIELD_PREP(IRDMA_CQ_WQEIDX, orig_wq_desc_idx) |
		FIELD_PREP(IRDMA_CQ_ERROR, error) |
		FIELD_PREP(IRDMA_CQ_MAJERR, maj_err_code) |
		FIELD_PREP(IRDMA_CQ_MINERR, min_err_code);

	/* submit request, non waiting... */
	irdma_cqp_ret_cqp_cmpl(dev, &rcacmplinfo);

	irdma_sc_cqp_post_rq(dev->cqp, info->scratch);
}

/**
 * irdma_cqp_ce_handler - handle cqp completions
 * @rf: RDMA PCI function
 * @cq: cq for cqp completions
 */
void irdma_cqp_ce_handler(struct irdma_pci_f *rf, struct irdma_sc_cq *cq)
{
	struct irdma_cqp_request *cqp_request;
	struct irdma_sc_dev *dev = &rf->sc_dev;
	u32 cqe_count = 0;
	struct irdma_ccq_cqe_info info;
	unsigned long flags;
	int ret;

	do {
		memset(&info, 0, sizeof(info));
		spin_lock_irqsave(&rf->cqp.compl_lock, flags);
		ret = irdma_sc_ccq_get_cqe_info(cq, &info);
		spin_unlock_irqrestore(&rf->cqp.compl_lock, flags);
		if (ret)
			break;

		if (!info.sq) {
			irdma_cqp_ce_handler_rca(rf, cq, &info);
			cqe_count++;
			continue;
		}

		cqp_request = (struct irdma_cqp_request *)
			      (uintptr_t)info.scratch;
		if (info.error && irdma_cqp_crit_err(dev,
						     cqp_request->info.cqp_cmd,
						     info.maj_err_code,
						     info.min_err_code))
			ibdev_err(&rf->iwdev->ibdev,
				  "cqp opcode = 0x%x maj_err_code = 0x%x min_err_code = 0x%x\n",
				  info.op_code, info.maj_err_code,
				  info.min_err_code);

		if (cqp_request) {
			cqp_request->compl_info.maj_err_code =
				info.maj_err_code;
			cqp_request->compl_info.min_err_code =
				info.min_err_code;
			cqp_request->compl_info.op_ret_val = info.op_ret_val;
			cqp_request->compl_info.error = info.error;

			/*
			 * If this is deferred or pending completion, then mark
			 * CQP request as pending to not block the CQ, but don't
			 * release CQP request, as it is still on the OOO list.
			 */
			if (info.pending)
				cqp_request->pending = true;
			else
				irdma_complete_cqp_request(&rf->cqp,
							   cqp_request);
		}

		cqe_count++;
	} while (1);

	if (cqe_count) {
		irdma_process_bh(dev);
		if (dev->hw_wa & CCQ_CQ3_POLL)
			return;
		irdma_sc_ccq_arm(dev->ccq);
	}
}

/**
 * cqp_compl_worker - Handle cqp completions
 * @work: Pointer to work structure
 */
void cqp_compl_worker(struct work_struct *work)
{
	struct irdma_pci_f *rf = container_of(work, struct irdma_pci_f,
					      cqp_cmpl_work);
	struct irdma_sc_cq *cq = &rf->ccq.sc_cq;

	irdma_cqp_ce_handler(rf, cq);
}

/**
 * irdma_lookup_apbvt_entry - lookup hash table for an existing apbvt entry corresponding to port
 * @cm_core: cm's core
 * @port: port to identify apbvt entry
 */
static struct irdma_apbvt_entry *irdma_lookup_apbvt_entry(struct irdma_cm_core *cm_core,
							  u16 port)
{
	struct irdma_apbvt_entry *entry;

	hash_for_each_possible(cm_core->apbvt_hash_tbl, entry, hlist, port) {
		if (entry->port == port) {
			entry->use_cnt++;
			return entry;
		}
	}

	return NULL;
}

/**
 * irdma_next_iw_state - modify qp state
 * @iwqp: iwarp qp to modify
 * @state: next state for qp
 * @del_hash: del hash
 * @term: term message
 * @termlen: length of term message
 */
void irdma_next_iw_state(struct irdma_qp *iwqp, u8 state, u8 del_hash, u8 term,
			 u8 termlen)
{
	struct irdma_modify_qp_info info = {};

	info.next_iwarp_state = state;
	info.remove_hash_idx = del_hash;
	info.cq_num_valid = true;
	info.arp_cache_idx_valid = true;
	info.dont_send_term = true;
	info.dont_send_fin = true;
	info.termlen = termlen;

	if (term & IRDMAQP_TERM_SEND_TERM_ONLY)
		info.dont_send_term = false;
	if (term & IRDMAQP_TERM_SEND_FIN_ONLY)
		info.dont_send_fin = false;
	if (iwqp->sc_qp.term_flags && state == IRDMA_QP_STATE_ERROR)
		info.reset_tcp_conn = true;
	iwqp->hw_iwarp_state = state;
	irdma_hw_modify_qp(iwqp->iwdev, iwqp, &info, 0);
	iwqp->iwarp_state = info.next_iwarp_state;
}

/**
 * irdma_del_local_mac_entry - remove a mac entry from the hw
 * table
 * @rf: RDMA PCI function
 * @idx: the index of the mac ip address to delete
 */
void irdma_del_local_mac_entry(struct irdma_pci_f *rf, u16 idx)
{
	struct irdma_cqp *iwcqp = &rf->cqp;
	struct irdma_cqp_request *cqp_request;
	struct cqp_cmds_info *cqp_info;

	cqp_request = irdma_alloc_and_get_cqp_request(iwcqp, true);
	if (!cqp_request)
		return;

	cqp_info = &cqp_request->info;
	cqp_info->cqp_cmd = IRDMA_OP_DELETE_LOCAL_MAC_ENTRY;
	cqp_info->post_sq = 1;
	cqp_info->in.u.del_local_mac_entry.cqp = &iwcqp->sc_cqp;
	cqp_info->in.u.del_local_mac_entry.scratch = (uintptr_t)cqp_request;
	cqp_info->in.u.del_local_mac_entry.entry_idx = idx;
	cqp_info->in.u.del_local_mac_entry.ignore_ref_count = 0;

	irdma_handle_cqp_op(rf, cqp_request);
	irdma_put_cqp_request(iwcqp, cqp_request);
}

/**
 * irdma_add_local_mac_entry - add a mac ip address entry to the
 * hw table
 * @rf: RDMA PCI function
 * @mac_addr: pointer to mac address
 * @idx: the index of the mac ip address to add
 */
int irdma_add_local_mac_entry(struct irdma_pci_f *rf, const u8 *mac_addr, u16 idx)
{
	struct irdma_local_mac_entry_info *info;
	struct irdma_cqp *iwcqp = &rf->cqp;
	struct irdma_cqp_request *cqp_request;
	struct cqp_cmds_info *cqp_info;
	int status;

	cqp_request = irdma_alloc_and_get_cqp_request(iwcqp, true);
	if (!cqp_request)
		return -ENOMEM;

	cqp_info = &cqp_request->info;
	cqp_info->post_sq = 1;
	info = &cqp_info->in.u.add_local_mac_entry.info;
	ether_addr_copy(info->mac_addr, mac_addr);
	info->entry_idx = idx;
	cqp_info->in.u.add_local_mac_entry.scratch = (uintptr_t)cqp_request;
	cqp_info->cqp_cmd = IRDMA_OP_ADD_LOCAL_MAC_ENTRY;
	cqp_info->in.u.add_local_mac_entry.cqp = &iwcqp->sc_cqp;
	cqp_info->in.u.add_local_mac_entry.scratch = (uintptr_t)cqp_request;
	cqp_info->create = true;

	status = irdma_handle_cqp_op(rf, cqp_request);
	irdma_put_cqp_request(iwcqp, cqp_request);

	return status;
}

/**
 * irdma_alloc_local_mac_entry - allocate a mac entry
 * @rf: RDMA PCI function
 * @mac_tbl_idx: the index of the new mac address
 *
 * Allocate a mac address entry and update the mac_tbl_idx
 * to hold the index of the newly created mac address
 * Return 0 if successful, otherwise return error
 */
int irdma_alloc_local_mac_entry(struct irdma_pci_f *rf, u16 *mac_tbl_idx)
{
	struct irdma_cqp *iwcqp = &rf->cqp;
	struct irdma_cqp_request *cqp_request;
	struct cqp_cmds_info *cqp_info;
	int status = 0;

	cqp_request = irdma_alloc_and_get_cqp_request(iwcqp, true);
	if (!cqp_request)
		return -ENOMEM;

	cqp_info = &cqp_request->info;
	cqp_info->cqp_cmd = IRDMA_OP_ALLOC_LOCAL_MAC_ENTRY;
	cqp_info->post_sq = 1;
	cqp_info->in.u.alloc_local_mac_entry.cqp = &iwcqp->sc_cqp;
	cqp_info->in.u.alloc_local_mac_entry.scratch = (uintptr_t)cqp_request;
	cqp_info->create = true;

	status = irdma_handle_cqp_op(rf, cqp_request);
	if (!status)
		*mac_tbl_idx = (u16)cqp_request->compl_info.op_ret_val;

	irdma_put_cqp_request(iwcqp, cqp_request);

	return status;
}

/**
 * irdma_cqp_manage_apbvt_cmd - send cqp command manage apbvt
 * @iwdev: irdma device
 * @accel_local_port: port for apbvt
 * @add_port: add ordelete port
 */
static int irdma_cqp_manage_apbvt_cmd(struct irdma_device *iwdev,
				      u16 accel_local_port, bool add_port)
{
	struct irdma_apbvt_info *info;
	struct irdma_cqp_request *cqp_request;
	struct cqp_cmds_info *cqp_info;
	int status;

	cqp_request = irdma_alloc_and_get_cqp_request(&iwdev->rf->cqp, add_port);
	if (!cqp_request)
		return -ENOMEM;

	cqp_info = &cqp_request->info;
	info = &cqp_info->in.u.manage_apbvt_entry.info;
	info->add = add_port;
	info->port = accel_local_port;
	cqp_info->cqp_cmd = IRDMA_OP_MANAGE_APBVT_ENTRY;
	cqp_info->post_sq = 1;
	cqp_info->in.u.manage_apbvt_entry.cqp = &iwdev->rf->cqp.sc_cqp;
	cqp_info->in.u.manage_apbvt_entry.scratch = (uintptr_t)cqp_request;
	ibdev_dbg(&iwdev->ibdev, "DEV: %s: port=0x%04x\n",
		  (!add_port) ? "DELETE" : "ADD", accel_local_port);

	status = irdma_handle_cqp_op(iwdev->rf, cqp_request);
	irdma_put_cqp_request(&iwdev->rf->cqp, cqp_request);

	return status;
}

/**
 * irdma_add_apbvt - add tcp port to HW apbvt table
 * @iwdev: irdma device
 * @port: port for apbvt
 */
struct irdma_apbvt_entry *irdma_add_apbvt(struct irdma_device *iwdev, u16 port)
{
	struct irdma_cm_core *cm_core = &iwdev->cm_core;
	struct irdma_apbvt_entry *entry;
	unsigned long flags;

	spin_lock_irqsave(&cm_core->apbvt_lock, flags);
	entry = irdma_lookup_apbvt_entry(cm_core, port);
	if (entry) {
		spin_unlock_irqrestore(&cm_core->apbvt_lock, flags);
		return entry;
	}

	entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
	if (!entry) {
		spin_unlock_irqrestore(&cm_core->apbvt_lock, flags);
		return NULL;
	}

	entry->port = port;
	entry->use_cnt = 1;
	hash_add(cm_core->apbvt_hash_tbl, &entry->hlist, entry->port);
	spin_unlock_irqrestore(&cm_core->apbvt_lock, flags);

	if (irdma_cqp_manage_apbvt_cmd(iwdev, port, true)) {
		kfree(entry);
		return NULL;
	}

	return entry;
}

/**
 * irdma_del_apbvt - delete tcp port from HW apbvt table
 * @iwdev: irdma device
 * @entry: apbvt entry object
 */
void irdma_del_apbvt(struct irdma_device *iwdev,
		     struct irdma_apbvt_entry *entry)
{
	struct irdma_cm_core *cm_core = &iwdev->cm_core;
	unsigned long flags;

	spin_lock_irqsave(&cm_core->apbvt_lock, flags);
	if (--entry->use_cnt) {
		spin_unlock_irqrestore(&cm_core->apbvt_lock, flags);
		return;
	}

	hash_del(&entry->hlist);
	/* apbvt_lock is held across CQP delete APBVT OP (non-waiting) to
	 * protect against race where add APBVT CQP can race ahead of the delete
	 * APBVT for same port.
	 */
	irdma_cqp_manage_apbvt_cmd(iwdev, entry->port, false);
	kfree(entry);
	spin_unlock_irqrestore(&cm_core->apbvt_lock, flags);
}

void irdma_arp_cqp_op(struct irdma_pci_f *rf, u16 arp_index,
		      const unsigned char *mac_addr, u32 action)
{
	struct irdma_add_arp_cache_entry_info *info;
	struct irdma_cqp_request *cqp_request;
	struct cqp_cmds_info *cqp_info;

	cqp_request = irdma_alloc_and_get_cqp_request(&rf->cqp, false);
	if (!cqp_request)
		return;

	cqp_info = &cqp_request->info;
	if (action == IRDMA_ARP_ADD_UPDATE) {
		cqp_info->cqp_cmd = IRDMA_OP_ADD_ARP_CACHE_ENTRY;
		info = &cqp_info->in.u.add_arp_cache_entry.info;
		info->arp_index = (u16)arp_index;
		info->permanent = true;
		ether_addr_copy(info->mac_addr, mac_addr);
		cqp_info->in.u.add_arp_cache_entry.scratch =
			(uintptr_t)cqp_request;
		cqp_info->in.u.add_arp_cache_entry.cqp = &rf->cqp.sc_cqp;
	} else {
		cqp_info->cqp_cmd = IRDMA_OP_DELETE_ARP_CACHE_ENTRY;
		cqp_info->in.u.del_arp_cache_entry.scratch =
			(uintptr_t)cqp_request;
		cqp_info->in.u.del_arp_cache_entry.cqp = &rf->cqp.sc_cqp;
		cqp_info->in.u.del_arp_cache_entry.arp_index = arp_index;
	}

	cqp_info->post_sq = 1;
	irdma_handle_cqp_op(rf, cqp_request);
	irdma_put_cqp_request(&rf->cqp, cqp_request);
}

/**
 * irdma_manage_arp_cache - manage hw arp cache
 * @rf: RDMA PCI function
 * @mac_addr: mac address ptr
 * @ip_addr: ip addr for arp cache
 * @action: add, delete or modify
 */
void irdma_manage_arp_cache(struct irdma_pci_f *rf, const unsigned char *mac_addr,
			    u32 *ip_addr, u32 action)
{
	int arp_index;

	arp_index = irdma_arp_table(rf, ip_addr, mac_addr, action);
	if (arp_index == -1)
		return;

	irdma_arp_cqp_op(rf, (u16)arp_index, mac_addr, action);
}

/**
 * irdma_send_syn_cqp_callback - do syn/ack after qhash
 * @cqp_request: qhash cqp completion
 */
static void irdma_send_syn_cqp_callback(struct irdma_cqp_request *cqp_request)
{
	struct irdma_cm_node *cm_node = cqp_request->param;

	irdma_send_syn(cm_node, 1);
	irdma_rem_ref_cm_node(cm_node);
}

/**
 * irdma_manage_qhash - add or modify qhash
 * @iwdev: irdma device
 * @cminfo: cm info for qhash
 * @etype: type (syn or quad)
 * @mtype: type of qhash
 * @cmnode: cmnode associated with connection
 * @wait: wait for completion
 */
int irdma_manage_qhash(struct irdma_device *iwdev, struct irdma_cm_info *cminfo,
		       enum irdma_quad_entry_type etype,
		       enum irdma_quad_hash_manage_type mtype, void *cmnode,
		       bool wait)
{
	struct irdma_qhash_table_info *info;
	struct irdma_cqp *iwcqp = &iwdev->rf->cqp;
	struct irdma_cqp_request *cqp_request;
	struct cqp_cmds_info *cqp_info;
	struct irdma_cm_node *cm_node = cmnode;
	int status;

	cqp_request = irdma_alloc_and_get_cqp_request(iwcqp, wait);
	if (!cqp_request)
		return -ENOMEM;

	cqp_info = &cqp_request->info;
	info = &cqp_info->in.u.manage_qhash_table_entry.info;
	info->vsi = &iwdev->vsi;
	info->manage = mtype;
	info->entry_type = etype;
	if (cminfo->vlan_id < VLAN_N_VID) {
		info->vlan_valid = true;
		info->vlan_id = cminfo->vlan_id;
	} else {
		info->vlan_valid = false;
	}
	info->ipv4_valid = cminfo->ipv4;
	info->user_pri = cminfo->user_pri;
	ether_addr_copy(info->mac_addr, iwdev->netdev->dev_addr);
	info->qp_num = cminfo->qh_qpid;
	info->dest_port = cminfo->loc_port;
	info->dest_ip[0] = cminfo->loc_addr[0];
	info->dest_ip[1] = cminfo->loc_addr[1];
	info->dest_ip[2] = cminfo->loc_addr[2];
	info->dest_ip[3] = cminfo->loc_addr[3];
	if (etype == IRDMA_QHASH_TYPE_TCP_ESTABLISHED ||
	    etype == IRDMA_QHASH_TYPE_UDP_UNICAST ||
	    etype == IRDMA_QHASH_TYPE_UDP_MCAST ||
	    etype == IRDMA_QHASH_TYPE_ROCE_MCAST ||
	    etype == IRDMA_QHASH_TYPE_ROCEV2_HW) {
		info->src_port = cminfo->rem_port;
		info->src_ip[0] = cminfo->rem_addr[0];
		info->src_ip[1] = cminfo->rem_addr[1];
		info->src_ip[2] = cminfo->rem_addr[2];
		info->src_ip[3] = cminfo->rem_addr[3];
	}
	if (cmnode) {
		cqp_request->callback_fcn = irdma_send_syn_cqp_callback;
		cqp_request->param = cmnode;
		if (!wait)
			refcount_inc(&cm_node->refcnt);
	}
	if (info->ipv4_valid)
		ibdev_dbg(&iwdev->ibdev,
			  "CM: %s caller: %pS loc_port=0x%04x rem_port=0x%04x loc_addr=%pI4 rem_addr=%pI4 mac=%pM, vlan_id=%d cm_node=%p\n",
			  (!mtype) ? "DELETE" : "ADD",
			  __builtin_return_address(0), info->src_port,
			  info->dest_port, info->src_ip, info->dest_ip,
			  info->mac_addr, cminfo->vlan_id,
			  cmnode ? cmnode : NULL);
	else
		ibdev_dbg(&iwdev->ibdev,
			  "CM: %s caller: %pS loc_port=0x%04x rem_port=0x%04x loc_addr=%pI6 rem_addr=%pI6 mac=%pM, vlan_id=%d cm_node=%p\n",
			  (!mtype) ? "DELETE" : "ADD",
			  __builtin_return_address(0), info->src_port,
			  info->dest_port, info->src_ip, info->dest_ip,
			  info->mac_addr, cminfo->vlan_id,
			  cmnode ? cmnode : NULL);

	cqp_info->in.u.manage_qhash_table_entry.cqp = &iwdev->rf->cqp.sc_cqp;
	cqp_info->in.u.manage_qhash_table_entry.scratch = (uintptr_t)cqp_request;
	cqp_info->cqp_cmd = IRDMA_OP_MANAGE_QHASH_TABLE_ENTRY;
	cqp_info->post_sq = 1;
	status = irdma_handle_cqp_op(iwdev->rf, cqp_request);
	if (status && cm_node && !wait)
		irdma_rem_ref_cm_node(cm_node);

	irdma_put_cqp_request(iwcqp, cqp_request);

	return status;
}

/**
 * irdma_hw_flush_wqes - flush qp's wqe
 * @rf: RDMA PCI function
 * @qp: hardware control qp
 * @info: info for flush
 * @wait: flag wait for completion
 */
int irdma_hw_flush_wqes(struct irdma_pci_f *rf, struct irdma_sc_qp *qp,
			struct irdma_qp_flush_info *info, bool wait)
{
	int status;
	struct irdma_qp_flush_info *hw_info;
	struct irdma_cqp_request *cqp_request;
	struct cqp_cmds_info *cqp_info;
	struct irdma_qp *iwqp = qp->qp_uk.back_qp;

	cqp_request = irdma_alloc_and_get_cqp_request(&rf->cqp, wait);
	if (!cqp_request)
		return -ENOMEM;

	cqp_info = &cqp_request->info;
	hw_info = &cqp_request->info.in.u.qp_flush_wqes.info;
	memcpy(hw_info, info, sizeof(*hw_info));
	cqp_info->cqp_cmd = IRDMA_OP_QP_FLUSH_WQES;
	cqp_info->post_sq = 1;
	cqp_info->in.u.qp_flush_wqes.qp = qp;
	cqp_info->in.u.qp_flush_wqes.scratch = (uintptr_t)cqp_request;
	if (qp->dev->hw_wa & NO_FLUSH)
		/* tmp- disable flush command till FW fix */
		status = -EIO;
	else
		status = irdma_handle_cqp_op(rf, cqp_request);
	if (status) {
		qp->qp_uk.sq_flush_complete = true;
		qp->qp_uk.rq_flush_complete = true;
		irdma_put_cqp_request(&rf->cqp, cqp_request);
		return status;
	}

	if (!wait || cqp_request->compl_info.maj_err_code)
		goto put_cqp;

	if (info->rq) {
		if (cqp_request->compl_info.min_err_code == IRDMA_CQP_COMPL_SQ_WQE_FLUSHED ||
		    cqp_request->compl_info.min_err_code == 0) {
			/* RQ WQE flush was requested but did not happen */
			qp->qp_uk.rq_flush_complete = true;
		}
	}
	if (info->sq) {
		if (cqp_request->compl_info.min_err_code == IRDMA_CQP_COMPL_RQ_WQE_FLUSHED ||
		    cqp_request->compl_info.min_err_code == 0) {
			/* SQ WQE flush was requested but did not happen */
			qp->qp_uk.sq_flush_complete = true;
		}
	}

	ibdev_dbg(&rf->iwdev->ibdev,
		  "VERBS: qp_id=%d qp_type=%d qpstate=%d ibqpstate=%d last_aeq=%d hw_iw_state=%d maj_err_code=%d min_err_code=%d\n",
		  iwqp->ibqp.qp_num, rf->protocol_used, iwqp->iwarp_state,
		  iwqp->ibqp_state, iwqp->last_aeq, iwqp->hw_iwarp_state,
		  cqp_request->compl_info.maj_err_code, cqp_request->compl_info.min_err_code);
put_cqp:
	irdma_put_cqp_request(&rf->cqp, cqp_request);

	return status;
}

/**
 * irdma_gen_ae - generate AE
 * @rf: RDMA PCI function
 * @qp: qp associated with AE
 * @info: info for ae
 * @wait: wait for completion
 */
void irdma_gen_ae(struct irdma_pci_f *rf, struct irdma_sc_qp *qp,
		  struct irdma_gen_ae_info *info, bool wait)
{
	struct irdma_gen_ae_info *ae_info;
	struct irdma_cqp_request *cqp_request;
	struct cqp_cmds_info *cqp_info;

	cqp_request = irdma_alloc_and_get_cqp_request(&rf->cqp, wait);
	if (!cqp_request)
		return;

	cqp_info = &cqp_request->info;
	ae_info = &cqp_request->info.in.u.gen_ae.info;
	memcpy(ae_info, info, sizeof(*ae_info));
	cqp_info->cqp_cmd = IRDMA_OP_GEN_AE;
	cqp_info->post_sq = 1;
	cqp_info->in.u.gen_ae.qp = qp;
	cqp_info->in.u.gen_ae.scratch = (uintptr_t)cqp_request;

	irdma_handle_cqp_op(rf, cqp_request);
	irdma_put_cqp_request(&rf->cqp, cqp_request);
}

/**
 * irdma_manage_pble_bp - manage pbles
 * @dev: hardware control device structure
 * @info: info for managing pble
 */
int irdma_manage_pble_bp(struct irdma_sc_dev *dev,
			 struct irdma_manage_pble_info *info)
{
	struct irdma_manage_pble_info *hw_info;
	struct irdma_pci_f *rf = dev_to_rf(dev);
	struct irdma_cqp_request *cqp_request;
	struct cqp_cmds_info *cqp_info;
	bool wait = rf->init_state < CCQ_CREATED ? false : true;
	int status;

	cqp_request = irdma_alloc_and_get_cqp_request(&rf->cqp, wait);
	if (!cqp_request)
		return -ENOMEM;

	cqp_info = &cqp_request->info;
	hw_info = &cqp_request->info.in.u.manage_pble_bp.info;
	memcpy(hw_info, info, sizeof(*hw_info));

	cqp_info->cqp_cmd = IRDMA_OP_MANAGE_PBLE_BP;
	cqp_info->post_sq = 1;
	cqp_info->in.u.manage_pble_bp.cqp = &rf->cqp.sc_cqp;
	cqp_info->in.u.manage_pble_bp.scratch = (uintptr_t)cqp_request;

	status = irdma_handle_cqp_op(rf, cqp_request);
	irdma_put_cqp_request(&rf->cqp, cqp_request);

	return status;
}

void irdma_flush_wqes(struct irdma_qp *iwqp, u32 flush_mask)
{
	struct irdma_qp_flush_info info = {};
	struct irdma_pci_f *rf = iwqp->iwdev->rf;
	u8 flush_code = iwqp->sc_qp.flush_code;

	if ((!(flush_mask & IRDMA_FLUSH_SQ) && !(flush_mask & IRDMA_FLUSH_RQ)) ||
	    ((flush_mask & IRDMA_REFLUSH) && rf->rdma_ver >= IRDMA_GEN_3))
		return;

	if (atomic_cmpxchg(&iwqp->flush_issued, 0, 1))
		return;

	/* Set flush info fields*/
	info.sq = flush_mask & IRDMA_FLUSH_SQ;
	info.rq = flush_mask & IRDMA_FLUSH_RQ;

	/* Generate userflush errors in CQE */
	info.sq_major_code = IRDMA_FLUSH_MAJOR_ERR;
	info.sq_minor_code = FLUSH_GENERAL_ERR;
	info.rq_major_code = IRDMA_FLUSH_MAJOR_ERR;
	info.rq_minor_code = FLUSH_GENERAL_ERR;
	info.userflushcode = true;
	info.err_sq_idx_valid = iwqp->sc_qp.err_sq_idx_valid;
	info.err_sq_idx = iwqp->sc_qp.err_sq_idx;
	info.err_rq_idx_valid = iwqp->sc_qp.err_rq_idx_valid;
	info.err_rq_idx = iwqp->sc_qp.err_rq_idx;

	if (flush_mask & IRDMA_REFLUSH) {
		if (info.sq)
			iwqp->sc_qp.flush_sq = false;
		if (info.rq)
			iwqp->sc_qp.flush_rq = false;
	} else {
		if (flush_code) {
			if (info.sq && iwqp->sc_qp.sq_flush_code)
				info.sq_minor_code = flush_code;
			if (info.rq && iwqp->sc_qp.rq_flush_code)
				info.rq_minor_code = flush_code;
		}
		if (irdma_upload_context && irdma_upload_qp_context(iwqp, 0, 1))
			ibdev_warn(&iwqp->iwdev->ibdev, "failed to upload QP context\n");
		if (!iwqp->user_mode)
			irdma_sched_qp_flush_work(iwqp);
	}

	/* Issue flush */
	(void)irdma_hw_flush_wqes(rf, &iwqp->sc_qp, &info,
				  flush_mask & IRDMA_FLUSH_WAIT);
}
