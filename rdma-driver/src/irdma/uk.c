// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2015 - 2023 Intel Corporation */
#include "osdep.h"
#include "defs.h"
#include "user.h"
#include "irdma.h"

/**
 * irdma_set_fragment - set fragment in wqe
 * @wqe: wqe for setting fragment
 * @offset: offset value
 * @sge: sge length and stag
 * @valid: The wqe valid
 */
static void irdma_set_fragment(__le64 *wqe, u32 offset, struct ib_sge *sge,
			       u8 valid)
{
	if (sge) {
		set_64bit_val(wqe, offset,
			      FIELD_PREP(IRDMAQPSQ_FRAG_TO, sge->addr));
		set_64bit_val(wqe, offset + 8,
			      FIELD_PREP(IRDMAQPSQ_VALID, valid) |
			      FIELD_PREP(IRDMAQPSQ_FRAG_LEN, sge->length) |
			      FIELD_PREP(IRDMAQPSQ_FRAG_STAG, sge->lkey));
	} else {
		set_64bit_val(wqe, offset, 0);
		set_64bit_val(wqe, offset + 8,
			      FIELD_PREP(IRDMAQPSQ_VALID, valid));
	}
}

/**
 * irdma_set_fragment_gen_1 - set fragment in wqe
 * @wqe: wqe for setting fragment
 * @offset: offset value
 * @sge: sge length and stag
 * @valid: wqe valid flag
 */
static void irdma_set_fragment_gen_1(__le64 *wqe, u32 offset,
				     struct ib_sge *sge, u8 valid)
{
	if (sge) {
		set_64bit_val(wqe, offset,
			      FIELD_PREP(IRDMAQPSQ_FRAG_TO, sge->addr));
		set_64bit_val(wqe, offset + 8,
			      FIELD_PREP(IRDMAQPSQ_GEN1_FRAG_LEN, sge->length) |
			      FIELD_PREP(IRDMAQPSQ_GEN1_FRAG_STAG, sge->lkey));
	} else {
		set_64bit_val(wqe, offset, 0);
		set_64bit_val(wqe, offset + 8, 0);
	}
}

/**
 * irdma_nop_hdr - Format header section of noop WQE
 * @qp: hw qp ptr
 */
static inline u64 irdma_nop_hdr(struct irdma_qp_uk *qp)
{
	return FIELD_PREP(IRDMAQPSQ_OPCODE, IRDMAQP_OP_NOP) |
	       FIELD_PREP(IRDMAQPSQ_SIGCOMPL, false) |
	       FIELD_PREP(IRDMAQPSQ_VALID, qp->swqe_polarity);
}

/**
 * irdma_nop_1 - insert a NOP wqe
 * @qp: hw qp ptr
 */
static int irdma_nop_1(struct irdma_qp_uk *qp)
{
	__le64 *wqe;
	u32 wqe_idx;

	if (!qp->sq_ring.head)
		return -EINVAL;

	wqe_idx = IRDMA_RING_CURRENT_HEAD(qp->sq_ring);
	wqe = qp->sq_base[wqe_idx].elem;

	qp->sq_wrtrk_array[wqe_idx].quanta = IRDMA_QP_WQE_MIN_QUANTA;

	set_64bit_val(wqe, 0, 0);
	set_64bit_val(wqe, 8, 0);
	set_64bit_val(wqe, 16, 0);

	/* make sure WQE is written before valid bit is set */
	dma_wmb();

	set_64bit_val(wqe, 24, irdma_nop_hdr(qp));

	return 0;
}

/**
 * irdma_clr_wqes - clear next 128 sq entries
 * @qp: hw qp ptr
 * @qp_wqe_idx: wqe_idx
 */
void irdma_clr_wqes(struct irdma_qp_uk *qp, u32 qp_wqe_idx)
{
	struct irdma_qp_quanta *sq;
	u32 wqe_idx;

	if (!(qp_wqe_idx & 0x7F)) {
		wqe_idx = (qp_wqe_idx + 128) % qp->sq_ring.size;
		sq = qp->sq_base + wqe_idx;
		if (wqe_idx)
			memset(sq, qp->swqe_polarity ? 0 : 0xFF,
			       128 * sizeof(*sq));
		else
			memset(sq, qp->swqe_polarity ? 0xFF : 0,
			       128 * sizeof(*sq));
	}
}

/**
 * irdma_uk_qp_post_wr - ring doorbell
 * @qp: hw qp ptr
 */
void irdma_uk_qp_post_wr(struct irdma_qp_uk *qp)
{
	/* valid bit is written before ringing doorbell */
	dma_wmb();

	writel(qp->qp_id, qp->wqe_alloc_db);
	qp->initial_ring.head = qp->sq_ring.head;
}

/**
 * irdma_qp_ring_push_db -  ring qp doorbell
 * @qp: hw qp ptr
 * @wqe_idx: wqe index
 */
static void irdma_qp_ring_push_db(struct irdma_qp_uk *qp, u32 wqe_idx)
{
	if (qp->uk_attrs->hw_rev >= IRDMA_GEN_3) {
		set_64bit_val(qp->push_db, 0,
			      FIELD_PREP(IRDMA_WQEALLOC_WQE_DESC_INDEX_64, wqe_idx >> 3) | qp->qp_id);
	} else {
		set_32bit_val((__le32 *)qp->push_db, 0,
			      FIELD_PREP(IRDMA_WQEALLOC_WQE_DESC_INDEX, wqe_idx >> 3) | qp->qp_id);
	}
	qp->initial_ring.head = qp->sq_ring.head;
	qp->push_mode = true;
	qp->push_dropped = false;
}

/**
 * irdma_qp_push_wqe -  setup push wqe and ring db
 * @qp: hw qp ptr
 * @wqe: wqe ptr
 * @quanta: numbers of quanta in wqe
 * @wqe_idx: wqe index
 * @push_wqe: if to use push for the wqe
 */
void irdma_qp_push_wqe(struct irdma_qp_uk *qp, __le64 *wqe, u16 quanta,
		       u32 wqe_idx, bool push_wqe)
{
	__le64 *push;

	if (push_wqe) {
		push = (__le64 *)((uintptr_t)qp->push_wqe +
				  (wqe_idx & 0x7) * 0x20);
		memcpy(push, wqe, quanta * IRDMA_QP_WQE_MIN_SIZE);
		irdma_qp_ring_push_db(qp, wqe_idx);
		qp->last_push_db = true;
	} else if (qp->last_push_db) {
		qp->last_push_db = false;
		writel(qp->qp_id, qp->wqe_alloc_db);
	} else {
		irdma_uk_qp_post_wr(qp);
	}
}

/**
 * irdma_push_ring_free -  check if sq ring free to pust push wqe
 * @qp: hw qp ptr
 */
static inline bool irdma_push_ring_free(struct irdma_qp_uk *qp)
{
	u32 head, tail;

	head = IRDMA_RING_CURRENT_HEAD(qp->initial_ring);
	tail = IRDMA_RING_CURRENT_TAIL(qp->sq_ring);

	if (head == tail || head == (tail + 1))
		return true;

	return false;
}

/**
 * irdma_enable_push_wqe - depending on sq ring and total size
 * @qp: hw qp ptr
 * @total_size: total data size
 */
static inline bool irdma_enable_push_wqe(struct irdma_qp_uk *qp, u32 total_size)
{
	if (irdma_push_ring_free(qp) &&
		total_size <= qp->uk_attrs->max_hw_push_len) {
		return true;
	}
	return false;
}

/**
 * irdma_qp_get_next_send_wqe - pad with NOP if needed, return where next WR should go
 * @qp: hw qp ptr
 * @wqe_idx: return wqe index
 * @quanta: (in/out) ptr to size of WR in quanta. Modified in case pad is needed
 * @total_size: size of WR in bytes
 * @info: info on WR
 */
__le64 *irdma_qp_get_next_send_wqe(struct irdma_qp_uk *qp, u32 *wqe_idx,
				   u16 *quanta, u32 total_size,
				   struct irdma_post_sq_info *info)
{
	__le64 *wqe;
	__le64 *wqe_0 = NULL;
	u32 nop_wqe_idx;
	u16 wqe_quanta = *quanta;
	u16 avail_quanta;
	u16 i;

	avail_quanta = qp->uk_attrs->max_hw_sq_chunk -
		       (IRDMA_RING_CURRENT_HEAD(qp->sq_ring) %
		       qp->uk_attrs->max_hw_sq_chunk);

	if (*quanta <= avail_quanta) {
		/* WR fits in current chunk */
		if (*quanta > IRDMA_SQ_RING_FREE_QUANTA(qp->sq_ring))
			return NULL;
	} else {
		/* Need to pad with NOP */
		if (*quanta + avail_quanta >
			IRDMA_SQ_RING_FREE_QUANTA(qp->sq_ring))
			return NULL;

		nop_wqe_idx = IRDMA_RING_CURRENT_HEAD(qp->sq_ring);
		for (i = 0; i < avail_quanta; i++) {
			irdma_nop_1(qp);
			IRDMA_RING_MOVE_HEAD_NOCHECK(qp->sq_ring);
		}
		if (qp->push_db && info->push_wqe)
			irdma_qp_push_wqe(qp, qp->sq_base[nop_wqe_idx].elem,
					  avail_quanta, nop_wqe_idx, true);
	}

	*wqe_idx = IRDMA_RING_CURRENT_HEAD(qp->sq_ring);
	if (!*wqe_idx)
		qp->swqe_polarity = !qp->swqe_polarity;

	IRDMA_RING_MOVE_HEAD_BY_COUNT_NOCHECK(qp->sq_ring, *quanta);

	irdma_clr_wqes(qp, *wqe_idx);

	wqe = qp->sq_base[*wqe_idx].elem;
	if (qp->uk_attrs->hw_rev == IRDMA_GEN_1 && wqe_quanta == 1 &&
	    (IRDMA_RING_CURRENT_HEAD(qp->sq_ring) & 1)) {
		wqe_0 = qp->sq_base[IRDMA_RING_CURRENT_HEAD(qp->sq_ring)].elem;
		wqe_0[3] = cpu_to_le64(FIELD_PREP(IRDMAQPSQ_VALID,
						  qp->swqe_polarity ? 0 : 1));
	}
	qp->sq_wrtrk_array[*wqe_idx].wrid = info->wr_id;
	qp->sq_wrtrk_array[*wqe_idx].wr_len = total_size;
	qp->sq_wrtrk_array[*wqe_idx].quanta = wqe_quanta;
	qp->sq_wrtrk_array[*wqe_idx].signaled = info->signaled;

	return wqe;
}

__le64 *irdma_srq_get_next_recv_wqe(struct irdma_srq_uk *srq, u32 *wqe_idx)
{
	int ret_code;
	__le64 *wqe;

	if (IRDMA_RING_FULL_ERR(srq->srq_ring))
		return NULL;

	IRDMA_ATOMIC_RING_MOVE_HEAD(srq->srq_ring, *wqe_idx, ret_code);
	if (ret_code)
		return NULL;

	if (!*wqe_idx)
		srq->srwqe_polarity = !srq->srwqe_polarity;
	wqe = srq->srq_base[*wqe_idx * srq->wqe_size_multiplier].elem;

	return wqe;
}

/**
 * irdma_qp_get_next_recv_wqe - get next qp's rcv wqe
 * @qp: hw qp ptr
 * @wqe_idx: return wqe index
 */
__le64 *irdma_qp_get_next_recv_wqe(struct irdma_qp_uk *qp, u32 *wqe_idx)
{
	__le64 *wqe;
	int ret_code;

	if (IRDMA_RING_FULL_ERR(qp->rq_ring))
		return NULL;

	IRDMA_ATOMIC_RING_MOVE_HEAD(qp->rq_ring, *wqe_idx, ret_code);
	if (ret_code)
		return NULL;

	if (!*wqe_idx)
		qp->rwqe_polarity = !qp->rwqe_polarity;
	/* rq_wqe_size_multiplier is no of 32 byte quanta in one rq wqe */
	wqe = qp->rq_base[*wqe_idx * qp->rq_wqe_size_multiplier].elem;

	return wqe;
}

/**
 * irdma_uk_rdma_write - rdma write operation
 * @qp: hw qp ptr
 * @info: post sq information
 * @post_sq: flag to post sq
 */
int irdma_uk_rdma_write(struct irdma_qp_uk *qp, struct irdma_post_sq_info *info,
			bool post_sq)
{
	u64 hdr;
	__le64 *wqe;
	struct irdma_rdma_write *op_info;
	u32 i, wqe_idx;
	u32 total_size = 0, byte_off;
	int ret_code;
	u32 frag_cnt, addl_frag_cnt;
	bool read_fence = false;
	u16 quanta;

	info->push_wqe = false;

	op_info = &info->op.rdma_write;
	if (op_info->num_lo_sges > qp->max_sq_frag_cnt)
		return -EINVAL;

	for (i = 0; i < op_info->num_lo_sges; i++)
		total_size += op_info->lo_sg_list[i].length;

	read_fence |= info->read_fence;

	if (info->imm_data_valid)
		frag_cnt = op_info->num_lo_sges + 1;
	else
		frag_cnt = op_info->num_lo_sges;
	addl_frag_cnt = frag_cnt > 1 ? (frag_cnt - 1) : 0;
	ret_code = irdma_fragcnt_to_quanta_sq(frag_cnt, &quanta);
	if (ret_code)
		return ret_code;

	if (qp->push_db)
		info->push_wqe = irdma_enable_push_wqe(qp, total_size);

	wqe = irdma_qp_get_next_send_wqe(qp, &wqe_idx, &quanta, total_size, info);
	if (!wqe)
		return -ENOMEM;

	set_64bit_val(wqe, 16,
		      FIELD_PREP(IRDMAQPSQ_FRAG_TO, op_info->rem_addr.addr));

	if (info->imm_data_valid) {
		set_64bit_val(wqe, 0,
			      FIELD_PREP(IRDMAQPSQ_IMMDATA, info->imm_data));
		i = 0;
	} else {
		qp->wqe_ops.iw_set_fragment(wqe, 0,
					    op_info->lo_sg_list,
					    qp->swqe_polarity);
		i = 1;
	}

	for (byte_off = 32; i < op_info->num_lo_sges; i++) {
		qp->wqe_ops.iw_set_fragment(wqe, byte_off,
					    &op_info->lo_sg_list[i],
					    qp->swqe_polarity);
		byte_off += 16;
	}

	/* if not an odd number set valid bit in next fragment */
	if (qp->uk_attrs->hw_rev >= IRDMA_GEN_2 && !(frag_cnt & 0x01) &&
	    frag_cnt) {
		qp->wqe_ops.iw_set_fragment(wqe, byte_off, NULL,
					    qp->swqe_polarity);
		if (qp->uk_attrs->hw_rev == IRDMA_GEN_2)
			++addl_frag_cnt;
	}

	hdr = FIELD_PREP(IRDMAQPSQ_REMSTAG, op_info->rem_addr.lkey) |
	      FIELD_PREP(IRDMAQPSQ_OPCODE, info->op_type) |
	      FIELD_PREP(IRDMAQPSQ_IMMDATAFLAG, info->imm_data_valid) |
	      FIELD_PREP(IRDMAQPSQ_REPORTRTT, info->report_rtt) |
	      FIELD_PREP(IRDMAQPSQ_ADDFRAGCNT, addl_frag_cnt) |
	      FIELD_PREP(IRDMAQPSQ_PUSHWQE, info->push_wqe) |
	      FIELD_PREP(IRDMAQPSQ_READFENCE, read_fence) |
	      FIELD_PREP(IRDMAQPSQ_LOCALFENCE, info->local_fence) |
	      FIELD_PREP(IRDMAQPSQ_SIGCOMPL, info->signaled) |
	      FIELD_PREP(IRDMAQPSQ_VALID, qp->swqe_polarity);

	dma_wmb(); /* make sure WQE is populated before valid bit is set */

	set_64bit_val(wqe, 24, hdr);
	if (qp->push_db)
		irdma_qp_push_wqe(qp, wqe, quanta, wqe_idx, info->push_wqe);
	else if (post_sq)
		irdma_uk_qp_post_wr(qp);

	return 0;
}

int irdma_uk_atomic_write(struct irdma_qp_uk *qp,
			  struct irdma_post_sq_info *info, bool post_sq)
{
	struct irdma_atomic_write *op_info;
	u32 total_size = 0;
	u32 wqe_idx;
	u16 quanta = IRDMA_QP_WQE_MIN_QUANTA;
	__le64 *wqe;
	u64 hdr;

	info->push_wqe = qp->push_db ? true : false;

	op_info = &info->op.atomic_write;
	wqe = irdma_qp_get_next_send_wqe(qp, &wqe_idx, &quanta, total_size, info);
	if (!wqe)
		return -ENOMEM;

	set_64bit_val(wqe, 0, op_info->tagged_offset);
	set_64bit_val(wqe, 8,
		      FIELD_PREP(IRDMAQPSQ_LOCSTAG, op_info->stag) |
		      FIELD_PREP(IRDMAQPSQ_FRAG_LEN, IRDMAQP_ATOMIC_WRITE_FRAG_LEN) |
		      FIELD_PREP(IRDMAQPSQ_FRAG_VALID, qp->swqe_polarity));
	set_64bit_val(wqe, 16, op_info->remote_tagged_offset);

	hdr = FIELD_PREP(IRDMAQPSQ_REMSTAG, op_info->remote_stag) |
	      FIELD_PREP(IRDMAQPSQ_OPCODE, IRDMAQP_OP_ATOMIC_WRITE) |
	      FIELD_PREP(IRDMAQPSQ_PUSHWQE, info->push_wqe) |
	      FIELD_PREP(IRDMAQPSQ_READFENCE, info->read_fence) |
	      FIELD_PREP(IRDMAQPSQ_LOCALFENCE, info->local_fence) |
	      FIELD_PREP(IRDMAQPSQ_SIGCOMPL, info->signaled) |
	      FIELD_PREP(IRDMAQPSQ_VALID, qp->swqe_polarity);

	dma_wmb(); /* make sure WQE is populated before valid bit is set */

	set_64bit_val(wqe, 24, hdr);
	if (qp->push_db)
		irdma_qp_push_wqe(qp, wqe, quanta, wqe_idx, info->push_wqe);
	else if (post_sq)
		irdma_uk_qp_post_wr(qp);

	return 0;
}

int irdma_uk_flush_mem_region(struct irdma_qp_uk *qp,
			      struct irdma_post_sq_info *info, bool post_sq)
{
	struct irdma_flush_mem_region *op_info;
	u32 total_size = 0;
	u32 wqe_idx;
	u16 quanta = IRDMA_QP_WQE_MIN_QUANTA;
	__le64 *wqe;
	u64 hdr;

	info->push_wqe = qp->push_db ? true : false;

	op_info = &info->op.flush_mem_region;
	wqe = irdma_qp_get_next_send_wqe(qp, &wqe_idx, &quanta, total_size, info);
	if (!wqe)
		return -ENOMEM;

	set_64bit_val(wqe, 8,
		      FIELD_PREP(IRDMAQPSQ_FLUSH_MEM_LEN, op_info->length));
	set_64bit_val(wqe, 16, op_info->remote_tagged_offset);

	hdr = FIELD_PREP(IRDMAQPSQ_REMSTAG, op_info->remote_stag) |
	      FIELD_PREP(IRDMAQPSQ_OPCODE, IRDMAQP_OP_FLUSH_MEM_REGION) |
	      FIELD_PREP(IRDMAQPSQ_PUSHWQE, info->push_wqe) |
	      FIELD_PREP(IRDMAQPSQ_READFENCE, info->read_fence) |
	      FIELD_PREP(IRDMAQPSQ_LOCALFENCE, info->local_fence) |
	      FIELD_PREP(IRDMAQPSQ_SIGCOMPL, info->signaled) |
	      FIELD_PREP(IRDMAQPSQ_PLACEMENT_TYPE, op_info->placement_type) |
	      FIELD_PREP(IRDMAQPSQ_SELECTIVITY, op_info->selectivity) |
	      FIELD_PREP(IRDMAQPSQ_VALID, qp->swqe_polarity);

	dma_wmb(); /* make sure WQE is populated before valid bit is set */

	set_64bit_val(wqe, 24, hdr);
	if (qp->push_db)
		irdma_qp_push_wqe(qp, wqe, quanta, wqe_idx, info->push_wqe);
	else if (post_sq)
		irdma_uk_qp_post_wr(qp);

	return 0;
}

/**
 * irdma_uk_atomic_fetch_add - atomic fetch and add operation
 * @qp: hw qp ptr
 * @info: post sq information
 * @post_sq: flag to post sq
 */
int irdma_uk_atomic_fetch_add(struct irdma_qp_uk *qp,
			      struct irdma_post_sq_info *info, bool post_sq)
{
	struct irdma_atomic_fetch_add *op_info;
	u32 total_size = 0;
	u16 quanta = 2;
	u32 wqe_idx;
	__le64 *wqe;
	u64 hdr;

	info->push_wqe = qp->push_db ? true : false;

	op_info = &info->op.atomic_fetch_add;
	wqe = irdma_qp_get_next_send_wqe(qp, &wqe_idx, &quanta, total_size, info);
	if (!wqe)
		return -ENOMEM;

	set_64bit_val(wqe, 0, op_info->tagged_offset);
	set_64bit_val(wqe, 8,
		      FIELD_PREP(IRDMAQPSQ_LOCSTAG, op_info->stag));
	set_64bit_val(wqe, 16, op_info->remote_tagged_offset);

	hdr = FIELD_PREP(IRDMAQPSQ_ADDFRAGCNT, 1) |
	      FIELD_PREP(IRDMAQPSQ_REMSTAG, op_info->remote_stag) |
	      FIELD_PREP(IRDMAQPSQ_OPCODE, IRDMAQP_OP_ATOMIC_FETCH_ADD) |
	      FIELD_PREP(IRDMAQPSQ_PUSHWQE, info->push_wqe) |
	      FIELD_PREP(IRDMAQPSQ_READFENCE, info->read_fence) |
	      FIELD_PREP(IRDMAQPSQ_LOCALFENCE, info->local_fence) |
	      FIELD_PREP(IRDMAQPSQ_SIGCOMPL, info->signaled) |
	      FIELD_PREP(IRDMAQPSQ_VALID, qp->swqe_polarity);

	set_64bit_val(wqe, 32, op_info->fetch_add_data_bytes);
	set_64bit_val(wqe, 40, 0);
	set_64bit_val(wqe, 48, 0);
	set_64bit_val(wqe, 56,
		      FIELD_PREP(IRDMAQPSQ_VALID, qp->swqe_polarity));

	dma_wmb(); /* make sure WQE is populated before valid bit is set */

	set_64bit_val(wqe, 24, hdr);
	if (qp->push_db)
		irdma_qp_push_wqe(qp, wqe, quanta, wqe_idx, info->push_wqe);
	else if (post_sq)
		irdma_uk_qp_post_wr(qp);

	return 0;
}

/**
 * irdma_uk_atomic_compare_swap - atomic compare and swap operation
 * @qp: hw qp ptr
 * @info: post sq information
 * @post_sq: flag to post sq
 */
int irdma_uk_atomic_compare_swap(struct irdma_qp_uk *qp,
				 struct irdma_post_sq_info *info, bool post_sq)
{
	struct irdma_atomic_compare_swap *op_info;
	u32 total_size = 0;
	u16 quanta = 2;
	u32 wqe_idx;
	__le64 *wqe;
	u64 hdr;

	info->push_wqe = qp->push_db ? true : false;

	op_info = &info->op.atomic_compare_swap;
	wqe = irdma_qp_get_next_send_wqe(qp, &wqe_idx, &quanta, total_size, info);
	if (!wqe)
		return -ENOMEM;

	set_64bit_val(wqe, 0, op_info->tagged_offset);
	set_64bit_val(wqe, 8,
		      FIELD_PREP(IRDMAQPSQ_LOCSTAG, op_info->stag));
	set_64bit_val(wqe, 16, op_info->remote_tagged_offset);

	hdr = FIELD_PREP(IRDMAQPSQ_ADDFRAGCNT, 1) |
	      FIELD_PREP(IRDMAQPSQ_REMSTAG, op_info->remote_stag) |
	      FIELD_PREP(IRDMAQPSQ_OPCODE, IRDMAQP_OP_ATOMIC_COMPARE_SWAP_ADD) |
	      FIELD_PREP(IRDMAQPSQ_PUSHWQE, info->push_wqe) |
	      FIELD_PREP(IRDMAQPSQ_READFENCE, info->read_fence) |
	      FIELD_PREP(IRDMAQPSQ_LOCALFENCE, info->local_fence) |
	      FIELD_PREP(IRDMAQPSQ_SIGCOMPL, info->signaled) |
	      FIELD_PREP(IRDMAQPSQ_VALID, qp->swqe_polarity);

	set_64bit_val(wqe, 32, op_info->swap_data_bytes);
	set_64bit_val(wqe, 40, op_info->compare_data_bytes);
	set_64bit_val(wqe, 48, 0);
	set_64bit_val(wqe, 56,
		      FIELD_PREP(IRDMAQPSQ_VALID, qp->swqe_polarity));

	dma_wmb(); /* make sure WQE is populated before valid bit is set */

	set_64bit_val(wqe, 24, hdr);
	if (qp->push_db)
		irdma_qp_push_wqe(qp, wqe, quanta, wqe_idx, info->push_wqe);
	else if (post_sq)
		irdma_uk_qp_post_wr(qp);

	return 0;
}

/**
 * irdma_uk_srq_post_receive - post a receive wqe to a shared rq
 * @srq: shared rq ptr
 * @info: post rq information
 */
int irdma_uk_srq_post_receive(struct irdma_srq_uk *srq,
			      struct irdma_post_rq_info *info)
{
	u32 wqe_idx, i, byte_off;
	u32 addl_frag_cnt;
	__le64 *wqe;
	u64 hdr;

	if (srq->max_srq_frag_cnt < info->num_sges)
		return -EINVAL;

	wqe = irdma_srq_get_next_recv_wqe(srq, &wqe_idx);
	if (!wqe)
		return -ENOMEM;

	addl_frag_cnt = info->num_sges > 1 ? info->num_sges - 1 : 0;
	srq->wqe_ops.iw_set_fragment(wqe, 0, info->sg_list,
				     srq->srwqe_polarity);

	for (i = 1, byte_off = 32; i < info->num_sges; i++) {
		srq->wqe_ops.iw_set_fragment(wqe, byte_off, &info->sg_list[i],
					     srq->srwqe_polarity);
		byte_off += 16;
	}

	/* if not an odd number set valid bit in next fragment */
	if (srq->uk_attrs->hw_rev >= IRDMA_GEN_2 && !(info->num_sges & 0x01) &&
	    info->num_sges) {
		srq->wqe_ops.iw_set_fragment(wqe, byte_off, NULL,
					     srq->srwqe_polarity);
		if (srq->uk_attrs->hw_rev == IRDMA_GEN_2)
			++addl_frag_cnt;
	}

	set_64bit_val(wqe, 16, (u64)info->wr_id);
	hdr = FIELD_PREP(IRDMAQPSQ_ADDFRAGCNT, addl_frag_cnt) |
	      FIELD_PREP(IRDMAQPSQ_VALID, srq->srwqe_polarity);

	dma_wmb(); /* make sure WQE is populated before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	set_64bit_val(srq->shadow_area, 0, (wqe_idx + 1) % srq->srq_ring.size);

	return 0;
}
/**
 * irdma_uk_rdma_read - rdma read command
 * @qp: hw qp ptr
 * @info: post sq information
 * @inv_stag: flag for inv_stag
 * @post_sq: flag to post sq
 */
int irdma_uk_rdma_read(struct irdma_qp_uk *qp, struct irdma_post_sq_info *info,
		       bool inv_stag, bool post_sq)
{
	struct irdma_rdma_read *op_info;
	int ret_code;
	u32 i, byte_off, total_size = 0;
	bool local_fence = false;
	bool ord_fence = false;
	u32 addl_frag_cnt;
	__le64 *wqe;
	u32 wqe_idx;
	u16 quanta;
	u64 hdr;

	info->push_wqe &= qp->push_db ? true : false;

	op_info = &info->op.rdma_read;
	if (qp->max_sq_frag_cnt < op_info->num_lo_sges)
		return -EINVAL;

	for (i = 0; i < op_info->num_lo_sges; i++)
		total_size += op_info->lo_sg_list[i].length;

	ret_code = irdma_fragcnt_to_quanta_sq(op_info->num_lo_sges, &quanta);
	if (ret_code)
		return ret_code;

	wqe = irdma_qp_get_next_send_wqe(qp, &wqe_idx, &quanta, total_size, info);
	if (!wqe)
		return -ENOMEM;

	if (qp->rd_fence_rate && (qp->ord_cnt++ == qp->rd_fence_rate)) {
		ord_fence = true;
		qp->ord_cnt = 0;
	}

	addl_frag_cnt = op_info->num_lo_sges > 1 ?
			(op_info->num_lo_sges - 1) : 0;
	local_fence |= info->local_fence;

	qp->wqe_ops.iw_set_fragment(wqe, 0, op_info->lo_sg_list,
				    qp->swqe_polarity);
	for (i = 1, byte_off = 32; i < op_info->num_lo_sges; ++i) {
		qp->wqe_ops.iw_set_fragment(wqe, byte_off,
					    &op_info->lo_sg_list[i],
					    qp->swqe_polarity);
		byte_off += 16;
	}

	/* if not an odd number set valid bit in next fragment */
	if (qp->uk_attrs->hw_rev >= IRDMA_GEN_2 &&
	    !(op_info->num_lo_sges & 0x01) && op_info->num_lo_sges) {
		qp->wqe_ops.iw_set_fragment(wqe, byte_off, NULL,
					    qp->swqe_polarity);
		if (qp->uk_attrs->hw_rev == IRDMA_GEN_2)
			++addl_frag_cnt;
	}
	set_64bit_val(wqe, 16,
		      FIELD_PREP(IRDMAQPSQ_FRAG_TO, op_info->rem_addr.addr));
	hdr = FIELD_PREP(IRDMAQPSQ_REMSTAG, op_info->rem_addr.lkey) |
	      FIELD_PREP(IRDMAQPSQ_REPORTRTT, (info->report_rtt ? 1 : 0)) |
	      FIELD_PREP(IRDMAQPSQ_ADDFRAGCNT, addl_frag_cnt) |
	      FIELD_PREP(IRDMAQPSQ_OPCODE,
			 (inv_stag ? IRDMAQP_OP_RDMA_READ_LOC_INV : IRDMAQP_OP_RDMA_READ)) |
	      FIELD_PREP(IRDMAQPSQ_PUSHWQE, info->push_wqe) |
	      FIELD_PREP(IRDMAQPSQ_READFENCE,
			 info->read_fence || ord_fence ? 1 : 0) |
	      FIELD_PREP(IRDMAQPSQ_LOCALFENCE, local_fence) |
	      FIELD_PREP(IRDMAQPSQ_SIGCOMPL, info->signaled) |
	      FIELD_PREP(IRDMAQPSQ_VALID, qp->swqe_polarity);

	dma_wmb(); /* make sure WQE is populated before valid bit is set */

	set_64bit_val(wqe, 24, hdr);
	if (qp->push_db)
		irdma_qp_push_wqe(qp, wqe, quanta, wqe_idx, info->push_wqe);
	else if (post_sq)
		irdma_uk_qp_post_wr(qp);

	return 0;
}

/**
 * irdma_uk_send - rdma send command
 * @qp: hw qp ptr
 * @info: post sq information
 * @post_sq: flag to post sq
 */
int irdma_uk_send(struct irdma_qp_uk *qp, struct irdma_post_sq_info *info,
		  bool post_sq)
{
	__le64 *wqe;
	struct irdma_post_send *op_info;
	u64 hdr;
	u32 i, wqe_idx, total_size = 0, byte_off;
	int ret_code;
	u32 frag_cnt, addl_frag_cnt;
	bool read_fence = false;
	u16 quanta;

	info->push_wqe = false;

	op_info = &info->op.send;
	if (qp->max_sq_frag_cnt < op_info->num_sges)
		return -EINVAL;

	for (i = 0; i < op_info->num_sges; i++)
		total_size += op_info->sg_list[i].length;

	if (info->imm_data_valid)
		frag_cnt = op_info->num_sges + 1;
	else
		frag_cnt = op_info->num_sges;
	ret_code = irdma_fragcnt_to_quanta_sq(frag_cnt, &quanta);
	if (ret_code)
		return ret_code;

	if (qp->push_db)
		info->push_wqe = irdma_enable_push_wqe(qp, total_size);

	wqe = irdma_qp_get_next_send_wqe(qp, &wqe_idx, &quanta, total_size, info);
	if (!wqe)
		return -ENOMEM;

	read_fence |= info->read_fence;
	addl_frag_cnt = frag_cnt > 1 ? (frag_cnt - 1) : 0;
	if (info->imm_data_valid) {
		set_64bit_val(wqe, 0,
			      FIELD_PREP(IRDMAQPSQ_IMMDATA, info->imm_data));
		i = 0;
	} else {
		qp->wqe_ops.iw_set_fragment(wqe, 0,
					    frag_cnt ? op_info->sg_list : NULL,
					    qp->swqe_polarity);
		i = 1;
	}

	for (byte_off = 32; i < op_info->num_sges; i++) {
		qp->wqe_ops.iw_set_fragment(wqe, byte_off, &op_info->sg_list[i],
					    qp->swqe_polarity);
		byte_off += 16;
	}

	/* if not an odd number set valid bit in next fragment */
	if (qp->uk_attrs->hw_rev >= IRDMA_GEN_2 && !(frag_cnt & 0x01) &&
	    frag_cnt) {
		qp->wqe_ops.iw_set_fragment(wqe, byte_off, NULL,
					    qp->swqe_polarity);
		if (qp->uk_attrs->hw_rev == IRDMA_GEN_2)
			++addl_frag_cnt;
	}

	set_64bit_val(wqe, 16,
		      FIELD_PREP(IRDMAQPSQ_DESTQKEY, op_info->qkey) |
		      FIELD_PREP(IRDMAQPSQ_DESTQPN, op_info->dest_qp));
	hdr = FIELD_PREP(IRDMAQPSQ_REMSTAG, info->stag_to_inv) |
	      FIELD_PREP(IRDMAQPSQ_AHID, op_info->ah_id) |
	      FIELD_PREP(IRDMAQPSQ_IMMDATAFLAG,
			 (info->imm_data_valid ? 1 : 0)) |
	      FIELD_PREP(IRDMAQPSQ_REPORTRTT, (info->report_rtt ? 1 : 0)) |
	      FIELD_PREP(IRDMAQPSQ_OPCODE, info->op_type) |
	      FIELD_PREP(IRDMAQPSQ_ADDFRAGCNT, addl_frag_cnt) |
	      FIELD_PREP(IRDMAQPSQ_PUSHWQE, info->push_wqe) |
	      FIELD_PREP(IRDMAQPSQ_READFENCE, read_fence) |
	      FIELD_PREP(IRDMAQPSQ_LOCALFENCE, info->local_fence) |
	      FIELD_PREP(IRDMAQPSQ_SIGCOMPL, info->signaled) |
	      FIELD_PREP(IRDMAQPSQ_UDPHEADER, info->udp_hdr) |
	      FIELD_PREP(IRDMAQPSQ_L4LEN, info->l4len) |
	      FIELD_PREP(IRDMAQPSQ_VALID, qp->swqe_polarity);

	dma_wmb(); /* make sure WQE is populated before valid bit is set */

	set_64bit_val(wqe, 24, hdr);
	if (qp->push_db)
		irdma_qp_push_wqe(qp, wqe, quanta, wqe_idx, info->push_wqe);
	else if (post_sq)
		irdma_uk_qp_post_wr(qp);

	return 0;
}

/**
 * irdma_copy_inline_data_gen_1 - Copy inline data to wqe
 * @wqe: pointer to wqe
 * @sge_list: table of pointers to inline data
 * @num_sges: Total inline data length
 * @polarity: compatibility parameter
 */
static void irdma_copy_inline_data_gen_1(u8 *wqe, struct ib_sge *sge_list,
					 u32 num_sges, u8 polarity)
{
	u32 quanta_bytes_remaining = 16;
	u32 i;

	for (i = 0; i < num_sges; i++) {
		u8 *cur_sge = (u8 *)(uintptr_t)sge_list[i].addr;
		u32 sge_len = sge_list[i].length;

		while (sge_len) {
			u32 bytes_copied;

			bytes_copied = min(sge_len, quanta_bytes_remaining);
			memcpy(wqe, cur_sge, bytes_copied);
			wqe += bytes_copied;
			cur_sge += bytes_copied;
			quanta_bytes_remaining -= bytes_copied;
			sge_len -= bytes_copied;

			if (!quanta_bytes_remaining) {
				/* Remaining inline bytes reside after hdr */
				wqe += 16;
				quanta_bytes_remaining = 32;
			}
		}
	}
}

/**
 * irdma_inline_data_size_to_quanta_gen_1 - based on inline data, quanta
 * @data_size: data size for inline
 *
 * Gets the quanta based on inline and immediate data.
 */
static inline u16 irdma_inline_data_size_to_quanta_gen_1(u32 data_size)
{
	return data_size <= 16 ? IRDMA_QP_WQE_MIN_QUANTA : 2;
}

/**
 * irdma_copy_inline_data - Copy inline data to wqe
 * @wqe: pointer to wqe
 * @sge_list: table of pointers to inline data
 * @num_sges: number of SGE's
 * @polarity: polarity of wqe valid bit
 */
static void irdma_copy_inline_data(u8 *wqe, struct ib_sge *sge_list,
				   u32 num_sges, u8 polarity)
{
	u8 inline_valid = polarity << IRDMA_INLINE_VALID_S;
	u32 quanta_bytes_remaining = 8;
	u32 i;
	bool first_quanta = true;

	wqe += 8;

	for (i = 0; i < num_sges; i++) {
		u8 *cur_sge = (u8 *)(uintptr_t)sge_list[i].addr;
		u32 sge_len = sge_list[i].length;

		while (sge_len) {
			u32 bytes_copied;

			bytes_copied = min(sge_len, quanta_bytes_remaining);
			memcpy(wqe, cur_sge, bytes_copied);
			wqe += bytes_copied;
			cur_sge += bytes_copied;
			quanta_bytes_remaining -= bytes_copied;
			sge_len -= bytes_copied;

			if (!quanta_bytes_remaining) {
				quanta_bytes_remaining = 31;

				/* Remaining inline bytes reside after hdr */
				if (first_quanta) {
					first_quanta = false;
					wqe += 16;
				} else {
					*wqe = inline_valid;
					wqe++;
				}
			}
		}
	}
	if (!first_quanta && quanta_bytes_remaining < 31)
		*(wqe + quanta_bytes_remaining) = inline_valid;
}

/**
 * irdma_inline_data_size_to_quanta - based on inline data, quanta
 * @data_size: data size for inline
 *
 * Gets the quanta based on inline and immediate data.
 */
static u16 irdma_inline_data_size_to_quanta(u32 data_size)
{
	if (data_size <= 8)
		return IRDMA_QP_WQE_MIN_QUANTA;
	else if (data_size <= 39)
		return 2;
	else if (data_size <= 70)
		return 3;
	else if (data_size <= 101)
		return 4;
	else if (data_size <= 132)
		return 5;
	else if (data_size <= 163)
		return 6;
	else if (data_size <= 194)
		return 7;
	else
		return 8;
}

/**
 * irdma_uk_inline_rdma_write - inline rdma write operation
 * @qp: hw qp ptr
 * @info: post sq information
 * @post_sq: flag to post sq
 */
int irdma_uk_inline_rdma_write(struct irdma_qp_uk *qp,
			       struct irdma_post_sq_info *info, bool post_sq)
{
	__le64 *wqe;
	struct irdma_rdma_write *op_info;
	u64 hdr = 0;
	u32 wqe_idx;
	bool read_fence = false;
	u16 quanta;
	u32 i, total_size = 0;

	info->push_wqe = qp->push_db ? true : false;
	op_info = &info->op.rdma_write;

	if (unlikely(qp->max_sq_frag_cnt < op_info->num_lo_sges))
		return -EINVAL;

	for (i = 0; i < op_info->num_lo_sges; i++)
		total_size += op_info->lo_sg_list[i].length;

	if (unlikely(total_size > qp->max_inline_data))
		return -EINVAL;

	quanta = qp->wqe_ops.iw_inline_data_size_to_quanta(total_size);

	wqe = irdma_qp_get_next_send_wqe(qp, &wqe_idx, &quanta, total_size, info);
	if (!wqe)
		return -ENOMEM;

	read_fence |= info->read_fence;
	set_64bit_val(wqe, 16,
		      FIELD_PREP(IRDMAQPSQ_FRAG_TO, op_info->rem_addr.addr));

	hdr = FIELD_PREP(IRDMAQPSQ_REMSTAG, op_info->rem_addr.lkey) |
	      FIELD_PREP(IRDMAQPSQ_OPCODE, info->op_type) |
	      FIELD_PREP(IRDMAQPSQ_INLINEDATALEN, total_size) |
	      FIELD_PREP(IRDMAQPSQ_REPORTRTT, info->report_rtt ? 1 : 0) |
	      FIELD_PREP(IRDMAQPSQ_INLINEDATAFLAG, 1) |
	      FIELD_PREP(IRDMAQPSQ_IMMDATAFLAG, info->imm_data_valid ? 1 : 0) |
	      FIELD_PREP(IRDMAQPSQ_PUSHWQE, info->push_wqe ? 1 : 0) |
	      FIELD_PREP(IRDMAQPSQ_READFENCE, read_fence) |
	      FIELD_PREP(IRDMAQPSQ_LOCALFENCE, info->local_fence) |
	      FIELD_PREP(IRDMAQPSQ_SIGCOMPL, info->signaled) |
	      FIELD_PREP(IRDMAQPSQ_VALID, qp->swqe_polarity);

	if (info->imm_data_valid)
		set_64bit_val(wqe, 0,
			      FIELD_PREP(IRDMAQPSQ_IMMDATA, info->imm_data));

	qp->wqe_ops.iw_copy_inline_data((u8 *)wqe, op_info->lo_sg_list,
					op_info->num_lo_sges, qp->swqe_polarity);

	dma_wmb(); /* make sure WQE is populated before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	if (qp->push_db)
		irdma_qp_push_wqe(qp, wqe, quanta, wqe_idx, info->push_wqe);
	else if (post_sq)
		irdma_uk_qp_post_wr(qp);

	return 0;
}

/**
 * irdma_uk_inline_send - inline send operation
 * @qp: hw qp ptr
 * @info: post sq information
 * @post_sq: flag to post sq
 */
int irdma_uk_inline_send(struct irdma_qp_uk *qp,
			 struct irdma_post_sq_info *info, bool post_sq)
{
	__le64 *wqe;
	struct irdma_post_send *op_info;
	u64 hdr;
	u32 wqe_idx;
	bool read_fence = false;
	u16 quanta;
	u32 i, total_size = 0;

	info->push_wqe = qp->push_db ? true : false;
	op_info = &info->op.send;

	if (unlikely(qp->max_sq_frag_cnt < op_info->num_sges))
		return -EINVAL;

	for (i = 0; i < op_info->num_sges; i++)
		total_size += op_info->sg_list[i].length;

	if (unlikely(total_size > qp->max_inline_data))
		return -EINVAL;

	quanta = qp->wqe_ops.iw_inline_data_size_to_quanta(total_size);
	wqe = irdma_qp_get_next_send_wqe(qp, &wqe_idx, &quanta, total_size, info);
	if (!wqe)
		return -ENOMEM;

	set_64bit_val(wqe, 16,
		      FIELD_PREP(IRDMAQPSQ_DESTQKEY, op_info->qkey) |
		      FIELD_PREP(IRDMAQPSQ_DESTQPN, op_info->dest_qp));

	read_fence |= info->read_fence;
	hdr = FIELD_PREP(IRDMAQPSQ_REMSTAG, info->stag_to_inv) |
	      FIELD_PREP(IRDMAQPSQ_AHID, op_info->ah_id) |
	      FIELD_PREP(IRDMAQPSQ_OPCODE, info->op_type) |
	      FIELD_PREP(IRDMAQPSQ_INLINEDATALEN, total_size) |
	      FIELD_PREP(IRDMAQPSQ_IMMDATAFLAG,
			 (info->imm_data_valid ? 1 : 0)) |
	      FIELD_PREP(IRDMAQPSQ_REPORTRTT, (info->report_rtt ? 1 : 0)) |
	      FIELD_PREP(IRDMAQPSQ_INLINEDATAFLAG, 1) |
	      FIELD_PREP(IRDMAQPSQ_PUSHWQE, info->push_wqe) |
	      FIELD_PREP(IRDMAQPSQ_READFENCE, read_fence) |
	      FIELD_PREP(IRDMAQPSQ_LOCALFENCE, info->local_fence) |
	      FIELD_PREP(IRDMAQPSQ_SIGCOMPL, info->signaled) |
	      FIELD_PREP(IRDMAQPSQ_UDPHEADER, info->udp_hdr) |
	      FIELD_PREP(IRDMAQPSQ_L4LEN, info->l4len) |
	      FIELD_PREP(IRDMAQPSQ_VALID, qp->swqe_polarity);

	if (info->imm_data_valid)
		set_64bit_val(wqe, 0,
			      FIELD_PREP(IRDMAQPSQ_IMMDATA, info->imm_data));
	qp->wqe_ops.iw_copy_inline_data((u8 *)wqe, op_info->sg_list,
					op_info->num_sges, qp->swqe_polarity);

	dma_wmb(); /* make sure WQE is populated before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	if (qp->push_db)
		irdma_qp_push_wqe(qp, wqe, quanta, wqe_idx, info->push_wqe);
	else if (post_sq)
		irdma_uk_qp_post_wr(qp);

	return 0;
}

/**
 * irdma_uk_stag_local_invalidate - stag invalidate operation
 * @qp: hw qp ptr
 * @info: post sq information
 * @post_sq: flag to post sq
 */
int irdma_uk_stag_local_invalidate(struct irdma_qp_uk *qp,
				   struct irdma_post_sq_info *info,
				   bool post_sq)
{
	__le64 *wqe;
	struct irdma_inv_local_stag *op_info;
	u64 hdr;
	u32 wqe_idx;
	bool local_fence = false;
	struct ib_sge sge = {};
	u16 quanta = IRDMA_QP_WQE_MIN_QUANTA;

	info->push_wqe = qp->push_db ? true : false;
	op_info = &info->op.inv_local_stag;
	local_fence = info->local_fence;

	wqe = irdma_qp_get_next_send_wqe(qp, &wqe_idx, &quanta, 0, info);
	if (!wqe)
		return -ENOMEM;

	sge.lkey = op_info->target_stag;
	qp->wqe_ops.iw_set_fragment(wqe, 0, &sge, 0);

	set_64bit_val(wqe, 16, 0);

	hdr = FIELD_PREP(IRDMAQPSQ_OPCODE, IRDMA_OP_TYPE_INV_STAG) |
	      FIELD_PREP(IRDMAQPSQ_PUSHWQE, info->push_wqe) |
	      FIELD_PREP(IRDMAQPSQ_READFENCE, info->read_fence) |
	      FIELD_PREP(IRDMAQPSQ_LOCALFENCE, local_fence) |
	      FIELD_PREP(IRDMAQPSQ_SIGCOMPL, info->signaled) |
	      FIELD_PREP(IRDMAQPSQ_VALID, qp->swqe_polarity);

	dma_wmb(); /* make sure WQE is populated before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	if (qp->push_db)
		irdma_qp_push_wqe(qp, wqe, quanta, wqe_idx, info->push_wqe);
	else if (post_sq)
		irdma_uk_qp_post_wr(qp);

	return 0;
}

/**
 * irdma_uk_post_receive - post receive wqe
 * @qp: hw qp ptr
 * @info: post rq information
 */
int irdma_uk_post_receive(struct irdma_qp_uk *qp,
			  struct irdma_post_rq_info *info)
{
	u32 wqe_idx, i, byte_off;
	u32 addl_frag_cnt;
	__le64 *wqe;
	u64 hdr;

	if (qp->max_rq_frag_cnt < info->num_sges)
		return -EINVAL;

	wqe = irdma_qp_get_next_recv_wqe(qp, &wqe_idx);
	if (!wqe)
		return -ENOMEM;

	qp->rq_wrid_array[wqe_idx] = info->wr_id;
	addl_frag_cnt = info->num_sges > 1 ? (info->num_sges - 1) : 0;
	qp->wqe_ops.iw_set_fragment(wqe, 0, info->sg_list,
				    qp->rwqe_polarity);

	for (i = 1, byte_off = 32; i < info->num_sges; i++) {
		qp->wqe_ops.iw_set_fragment(wqe, byte_off, &info->sg_list[i],
					    qp->rwqe_polarity);
		byte_off += 16;
	}

	/* if not an odd number set valid bit in next fragment */
	if (qp->uk_attrs->hw_rev >= IRDMA_GEN_2 && !(info->num_sges & 0x01) &&
	    info->num_sges) {
		qp->wqe_ops.iw_set_fragment(wqe, byte_off, NULL,
					    qp->rwqe_polarity);
		if (qp->uk_attrs->hw_rev == IRDMA_GEN_2)
			++addl_frag_cnt;
	}

	set_64bit_val(wqe, 16, 0);
	hdr = FIELD_PREP(IRDMAQPSQ_ADDFRAGCNT, addl_frag_cnt) |
	      FIELD_PREP(IRDMAQPSQ_VALID, qp->rwqe_polarity);

	dma_wmb(); /* make sure WQE is populated before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	return 0;
}

/**
 * irdma_uk_cq_resize - reset the cq buffer info
 * @cq: cq to resize
 * @cq_base: new cq buffer addr
 * @cq_size: number of cqes
 */
void irdma_uk_cq_resize(struct irdma_cq_uk *cq, void *cq_base, int cq_size)
{
	cq->cq_base = cq_base;
	cq->cq_size = cq_size;
	IRDMA_RING_INIT(cq->cq_ring, cq->cq_size);
	cq->polarity = 1;
}

/**
 * irdma_uk_cq_set_resized_cnt - record the count of the resized buffers
 * @cq: cq to resize
 * @cq_cnt: the count of the resized cq buffers
 */
void irdma_uk_cq_set_resized_cnt(struct irdma_cq_uk *cq, u16 cq_cnt)
{
	u64 temp_val;
	u16 sw_cq_sel;
	u8 arm_next_se;
	u8 arm_next;
	u8 arm_seq_num;

	get_64bit_val(cq->shadow_area, 32, &temp_val);

	sw_cq_sel = (u16)FIELD_GET(IRDMA_CQ_DBSA_SW_CQ_SELECT, temp_val);
	sw_cq_sel += cq_cnt;

	arm_seq_num = (u8)FIELD_GET(IRDMA_CQ_DBSA_ARM_SEQ_NUM, temp_val);
	arm_next_se = (u8)FIELD_GET(IRDMA_CQ_DBSA_ARM_NEXT_SE, temp_val);
	arm_next = (u8)FIELD_GET(IRDMA_CQ_DBSA_ARM_NEXT, temp_val);

	temp_val = FIELD_PREP(IRDMA_CQ_DBSA_ARM_SEQ_NUM, arm_seq_num) |
		   FIELD_PREP(IRDMA_CQ_DBSA_SW_CQ_SELECT, sw_cq_sel) |
		   FIELD_PREP(IRDMA_CQ_DBSA_ARM_NEXT_SE, arm_next_se) |
		   FIELD_PREP(IRDMA_CQ_DBSA_ARM_NEXT, arm_next);

	set_64bit_val(cq->shadow_area, 32, temp_val);
}

/**
 * irdma_uk_cq_request_notification - cq notification request (door bell)
 * @cq: hw cq
 * @cq_notify: notification type
 */
void irdma_uk_cq_request_notification(struct irdma_cq_uk *cq,
				      enum irdma_cmpl_notify cq_notify)
{
	u64 temp_val;
	u16 sw_cq_sel;
	u8 arm_next_se = 0;
	u8 arm_next = 0;
	u8 arm_seq_num;

	get_64bit_val(cq->shadow_area, 32, &temp_val);
	arm_seq_num = (u8)FIELD_GET(IRDMA_CQ_DBSA_ARM_SEQ_NUM, temp_val);
	arm_seq_num++;
	sw_cq_sel = (u16)FIELD_GET(IRDMA_CQ_DBSA_SW_CQ_SELECT, temp_val);
	arm_next_se = (u8)FIELD_GET(IRDMA_CQ_DBSA_ARM_NEXT_SE, temp_val);
	arm_next_se |= 1;
	if (cq_notify == IRDMA_CQ_COMPL_EVENT)
		arm_next = 1;
	temp_val = FIELD_PREP(IRDMA_CQ_DBSA_ARM_SEQ_NUM, arm_seq_num) |
		   FIELD_PREP(IRDMA_CQ_DBSA_SW_CQ_SELECT, sw_cq_sel) |
		   FIELD_PREP(IRDMA_CQ_DBSA_ARM_NEXT_SE, arm_next_se) |
		   FIELD_PREP(IRDMA_CQ_DBSA_ARM_NEXT, arm_next);

	set_64bit_val(cq->shadow_area, 32, temp_val);

	dma_wmb(); /* make sure WQE is populated before valid bit is set */

	writel(cq->cq_id, cq->cqe_alloc_db);
}

/**
 * irdma_uk_cq_poll_cmpl - get cq completion info
 * @cq: hw cq
 * @info: cq poll information returned
 */
int irdma_uk_cq_poll_cmpl(struct irdma_cq_uk *cq,
			  struct irdma_cq_poll_info *info)
{
	u64 comp_ctx, qword0, qword2, qword3;
	__le64 *cqe;
	struct irdma_qp_uk *qp;
	struct irdma_srq_uk *srq;
	struct qp_err_code qp_err;
	u8 is_srq;
	struct irdma_ring *pring = NULL;
	u32 wqe_idx;
	int ret_code;
	bool move_cq_head = true;
	u8 polarity;
	bool ext_valid;
	__le64 *ext_cqe;
	unsigned long flags;

	if (cq->avoid_mem_cflct)
		cqe = IRDMA_GET_CURRENT_EXTENDED_CQ_ELEM(cq);
	else
		cqe = IRDMA_GET_CURRENT_CQ_ELEM(cq);

	get_64bit_val(cqe, 24, &qword3);
	polarity = (u8)FIELD_GET(IRDMA_CQ_VALID, qword3);
	if (polarity != cq->polarity)
		return -ENOENT;

	/* Ensure CQE contents are read after valid bit is checked */
	dma_rmb();

	ext_valid = (bool)FIELD_GET(IRDMA_CQ_EXTCQE, qword3);
	if (ext_valid) {
		u64 qword6, qword7;
		u32 peek_head;

		if (cq->avoid_mem_cflct) {
			ext_cqe = (__le64 *)((u8 *)cqe + 32);
			get_64bit_val(ext_cqe, 24, &qword7);
			polarity = (u8)FIELD_GET(IRDMA_CQ_VALID, qword7);
		} else {
			peek_head = (cq->cq_ring.head + 1) % cq->cq_ring.size;
			ext_cqe = cq->cq_base[peek_head].buf;
			get_64bit_val(ext_cqe, 24, &qword7);
			polarity = (u8)FIELD_GET(IRDMA_CQ_VALID, qword7);
			if (!peek_head)
				polarity ^= 1;
		}
		if (polarity != cq->polarity)
			return -ENOENT;

		/* Ensure ext CQE contents are read after ext valid bit is checked */
		dma_rmb();

		info->imm_valid = (bool)FIELD_GET(IRDMA_CQ_IMMVALID, qword7);
		if (info->imm_valid) {
			u64 qword4;

			get_64bit_val(ext_cqe, 0, &qword4);
			info->imm_data = (u32)FIELD_GET(IRDMA_CQ_IMMDATALOW32, qword4);
		}
		info->ud_smac_valid = (bool)FIELD_GET(IRDMA_CQ_UDSMACVALID, qword7);
		info->ud_vlan_valid = (bool)FIELD_GET(IRDMA_CQ_UDVLANVALID, qword7);
		if (info->ud_smac_valid || info->ud_vlan_valid) {
			get_64bit_val(ext_cqe, 16, &qword6);
			if (info->ud_vlan_valid)
				info->ud_vlan = (u16)FIELD_GET(IRDMA_CQ_UDVLAN, qword6);
			if (info->ud_smac_valid) {
				info->ud_smac[5] = qword6 & 0xFF;
				info->ud_smac[4] = (qword6 >> 8) & 0xFF;
				info->ud_smac[3] = (qword6 >> 16) & 0xFF;
				info->ud_smac[2] = (qword6 >> 24) & 0xFF;
				info->ud_smac[1] = (qword6 >> 32) & 0xFF;
				info->ud_smac[0] = (qword6 >> 40) & 0xFF;
			}
		}
	} else {
		info->imm_valid = false;
		info->ud_smac_valid = false;
		info->ud_vlan_valid = false;
	}

	info->q_type = (u8)FIELD_GET(IRDMA_CQ_SQ, qword3);
	is_srq = (u8)FIELD_GET(IRDMA_CQ_SRQ, qword3);
	info->error = (bool)FIELD_GET(IRDMA_CQ_ERROR, qword3);
	info->push_dropped = (bool)FIELD_GET(IRDMACQ_PSHDROP, qword3);
	info->ipv4 = (bool)FIELD_GET(IRDMACQ_IPV4, qword3);
	get_64bit_val(cqe, 8, &comp_ctx);
	if (is_srq)
		get_64bit_val(cqe, 40, (u64 *)&qp);
	else
		qp = (struct irdma_qp_uk *)(unsigned long)comp_ctx;
	if (!qp || qp->destroy_pending) {
		ret_code = -EFAULT;
		goto exit;
	}
	if (info->error) {
		info->major_err = FIELD_GET(IRDMA_CQ_MAJERR, qword3);
		info->minor_err = FIELD_GET(IRDMA_CQ_MINERR, qword3);
		switch (info->major_err) {
		case IRDMA_SRQFLUSH_RSVD_MAJOR_ERR:
			qp_err = irdma_ae_to_qp_err_code(info->minor_err);
			info->minor_err = qp_err.flush_code;
			fallthrough;
		case IRDMA_FLUSH_MAJOR_ERR:
			/* Set the min error to standard flush error code for remaining cqes */
			if (info->minor_err != FLUSH_GENERAL_ERR) {
				qword3 &= ~IRDMA_CQ_MINERR;
				qword3 |= FIELD_PREP(IRDMA_CQ_MINERR, FLUSH_GENERAL_ERR);
				set_64bit_val(cqe, 24, qword3);
			}
			info->comp_status = IRDMA_COMPL_STATUS_FLUSHED;
			break;
		default:
#define IRDMA_CIE_SIGNATURE 0xE
#define IRDMA_CQMAJERR_HIGH_NIBBLE GENMASK(15, 12)
			if (info->q_type == IRDMA_CQE_QTYPE_SQ
			    && qp->qp_type == IRDMA_QP_TYPE_ROCE_UD
			    && FIELD_GET(IRDMA_CQMAJERR_HIGH_NIBBLE, info->major_err)
			    == IRDMA_CIE_SIGNATURE) {
				info->error = 0;
				info->major_err = 0;
				info->minor_err = 0;
				info->comp_status = IRDMA_COMPL_STATUS_SUCCESS;
			} else {
				info->comp_status = IRDMA_COMPL_STATUS_UNKNOWN;
			}
			break;
		}
	} else {
		info->comp_status = IRDMA_COMPL_STATUS_SUCCESS;
	}

	get_64bit_val(cqe, 0, &qword0);
	get_64bit_val(cqe, 16, &qword2);

	info->qp_id = (u32)FIELD_GET(IRDMACQ_QPID, qword2);
	info->ud_src_qpn = (u32)FIELD_GET(IRDMACQ_UDSRCQPN, qword2);

	info->solicited_event = (bool)FIELD_GET(IRDMACQ_SOEVENT, qword3);
	wqe_idx = (u32)FIELD_GET(IRDMA_CQ_WQEIDX, qword3);
	info->qp_handle = (irdma_qp_handle)(unsigned long)qp;
	info->op_type = (u8)FIELD_GET(IRDMACQ_OP, qword3);

	if (info->q_type == IRDMA_CQE_QTYPE_RQ && is_srq) {
		srq = qp->srq_uk;

		get_64bit_val(cqe, 8, &info->wr_id);
		info->bytes_xfered = (u32)FIELD_GET(IRDMACQ_PAYLDLEN, qword0);

		if (qword3 & IRDMACQ_STAG) {
			info->stag_invalid_set = true;
			info->inv_stag = (u32)FIELD_GET(IRDMACQ_INVSTAG, qword2);
		} else {
			info->stag_invalid_set = false;
		}
		spin_lock_irqsave(srq->lock, flags);
		IRDMA_RING_MOVE_TAIL(srq->srq_ring);
		spin_unlock_irqrestore(srq->lock, flags);
		pring = &srq->srq_ring;
	} else if (info->q_type == IRDMA_CQE_QTYPE_RQ && !is_srq) {
		u32 array_idx;

		array_idx = wqe_idx / qp->rq_wqe_size_multiplier;
		info->bytes_xfered = (u32)FIELD_GET(IRDMACQ_PAYLDLEN, qword0);

		if (qword3 & IRDMACQ_STAG) {
			info->stag_invalid_set = true;
			info->inv_stag = (u32)FIELD_GET(IRDMACQ_INVSTAG, qword2);
		} else {
			info->stag_invalid_set = false;
		}

		if (info->comp_status == IRDMA_COMPL_STATUS_FLUSHED ||
		    info->comp_status == IRDMA_COMPL_STATUS_UNKNOWN) {
			spin_lock_irqsave(qp->lock, flags);
			if (!IRDMA_RING_MORE_WORK(qp->rq_ring)) {
				ret_code = -ENOENT;
				spin_unlock_irqrestore(qp->lock, flags);
				goto exit;
			}

			info->wr_id = qp->rq_wrid_array[qp->rq_ring.tail];
			IRDMA_RING_SET_TAIL(qp->rq_ring, qp->rq_ring.tail + 1);
			if (!IRDMA_RING_MORE_WORK(qp->rq_ring))
				qp->rq_flush_complete = true;
			else
				move_cq_head = false;
			spin_unlock_irqrestore(qp->lock, flags);
		} else {
			info->wr_id = qp->rq_wrid_array[array_idx];
			IRDMA_RING_SET_TAIL(qp->rq_ring, array_idx + 1);
		}
		pring = &qp->rq_ring;
	} else { /* q_type is IRDMA_CQE_QTYPE_SQ */
		if (qp->first_sq_wq) {
			if (wqe_idx + 1 >= qp->conn_wqes)
				qp->first_sq_wq = false;

			if (wqe_idx < qp->conn_wqes && qp->sq_ring.head == qp->sq_ring.tail) {
				IRDMA_RING_MOVE_HEAD_NOCHECK(cq->cq_ring);
				IRDMA_RING_MOVE_TAIL(cq->cq_ring);
				set_64bit_val(cq->shadow_area, 0,
					      IRDMA_RING_CURRENT_HEAD(cq->cq_ring));
				memset(info, 0, sizeof(*info));
				return irdma_uk_cq_poll_cmpl(cq, info);
			}
		}
		/*cease posting push mode on push drop*/
		if (info->push_dropped) {
			qp->push_mode = false;
			qp->push_dropped = true;
		}
		if (info->comp_status != IRDMA_COMPL_STATUS_FLUSHED) {
			info->wr_id = qp->sq_wrtrk_array[wqe_idx].wrid;
			if (!info->comp_status)
				info->bytes_xfered = qp->sq_wrtrk_array[wqe_idx].wr_len;
			if (!qp->sq_wrtrk_array[wqe_idx].signaled) {
				ret_code = -EFAULT;
				goto exit;
			}
			info->op_type = (u8)FIELD_GET(IRDMACQ_OP, qword3);
			IRDMA_RING_SET_TAIL(qp->sq_ring,
					    wqe_idx + qp->sq_wrtrk_array[wqe_idx].quanta);
		} else {
			spin_lock_irqsave(qp->lock, flags);
			if (!IRDMA_RING_MORE_WORK(qp->sq_ring)) {
				spin_unlock_irqrestore(qp->lock, flags);
				ret_code = -ENOENT;
				goto exit;
			}

			do {
				__le64 *sw_wqe;
				u64 wqe_qword;
				u32 tail;

				tail = qp->sq_ring.tail;
				sw_wqe = qp->sq_base[tail].elem;
				get_64bit_val(sw_wqe, 24,
					      &wqe_qword);
				info->op_type = (u8)FIELD_GET(IRDMAQPSQ_OPCODE,
							      wqe_qword);
				IRDMA_RING_SET_TAIL(qp->sq_ring,
						    tail + qp->sq_wrtrk_array[tail].quanta);
				if (info->op_type != IRDMAQP_OP_NOP) {
					info->wr_id = qp->sq_wrtrk_array[tail].wrid;
					info->bytes_xfered = qp->sq_wrtrk_array[tail].wr_len;
					break;
				}
			} while (1);

			if (info->op_type == IRDMA_OP_TYPE_BIND_MW &&
			    info->minor_err == FLUSH_PROT_ERR)
				info->minor_err = FLUSH_MW_BIND_ERR;
			if (!IRDMA_RING_MORE_WORK(qp->sq_ring))
				qp->sq_flush_complete = true;
			spin_unlock_irqrestore(qp->lock, flags);
		}
		pring = &qp->sq_ring;
	}

	ret_code = 0;

exit:
	if (!ret_code && info->comp_status == IRDMA_COMPL_STATUS_FLUSHED) {
		if (pring && IRDMA_RING_MORE_WORK(*pring))
		/* Park CQ head during a flush to generate additional CQEs
		 * from SW for all unprocessed WQEs. For GEN3 and beyond
		 * FW will generate/flush these CQEs so move to the next CQE
		 */
			move_cq_head = qp->uk_attrs->hw_rev <= IRDMA_GEN_2 ?
						false : true;
	}

	if (move_cq_head) {
		IRDMA_RING_MOVE_HEAD_NOCHECK(cq->cq_ring);
		if (!IRDMA_RING_CURRENT_HEAD(cq->cq_ring))
			cq->polarity ^= 1;

		if (ext_valid && !cq->avoid_mem_cflct) {
			IRDMA_RING_MOVE_HEAD_NOCHECK(cq->cq_ring);
			if (!IRDMA_RING_CURRENT_HEAD(cq->cq_ring))
				cq->polarity ^= 1;
		}

		IRDMA_RING_MOVE_TAIL(cq->cq_ring);
		if (!cq->avoid_mem_cflct && ext_valid)
			IRDMA_RING_MOVE_TAIL(cq->cq_ring);
		set_64bit_val(cq->shadow_area, 0,
			      IRDMA_RING_CURRENT_HEAD(cq->cq_ring));
	} else {
		qword3 &= ~IRDMA_CQ_WQEIDX;
		qword3 |= FIELD_PREP(IRDMA_CQ_WQEIDX, pring->tail);
		set_64bit_val(cqe, 24, qword3);
	}

	return ret_code;
}

#ifdef PRINT_CQES
/**
 * irdma_print_cqes - print cq completion info
 * @cq: hw cq
 */
void irdma_print_cqes(struct irdma_cq_uk *cq)
{
	u8 cq_polarity = cq->polarity;
	int i = 0;

	pr_info("%s[%d]: CQ (cq_id=%u, polarity=%d, head=%u, size=%u)\n",
		__func__, __LINE__, cq->cq_id, cq_polarity, cq->cq_ring.head,
		cq->cq_ring.size);

	while (true) {
		u64 comp_ctx, qword0, qword2, qword3;
		struct irdma_cq_poll_info cqe_info;
		struct irdma_cq_poll_info *info = &cqe_info;
		struct irdma_qp_uk *qp;
		__le64 *ext_cqe = NULL;
		bool ext_valid;
		u8 polarity;
		u32 wqe_idx;
		__le64 *cqe;

		IRDMA_GET_CQ_ELEM_AT_OFFSET(cq, i, cqe);
		get_64bit_val(cqe, 24, &qword3);
		polarity = (u8)FIELD_GET(IRDMA_CQ_VALID, qword3);

		if (polarity != cq_polarity) {
			pr_info("%s[%d]: CQ (cq_id=%u) is empty\n", __func__,
				__LINE__, cq->cq_id);
			return;
		}

		/* Ensure CQE contents are read after valid bit is checked */
		dma_rmb();

		ext_valid = (bool)FIELD_GET(IRDMA_CQ_EXTCQE, qword3);
		if (ext_valid) {
			u64 qword7;
			u32 peek_head;

			if (cq->avoid_mem_cflct) {
				ext_cqe = (__le64 *)((u8 *)cqe + 32);
				get_64bit_val(ext_cqe, 24, &qword7);
				polarity = (u8)FIELD_GET(IRDMA_CQ_VALID, qword7);
			} else {
				peek_head = IRDMA_GET_RING_OFFSET(cq->cq_ring, i + 1);
				ext_cqe = cq->cq_base[peek_head].buf;
				get_64bit_val(ext_cqe, 24, &qword7);
				polarity = (u8)FIELD_GET(IRDMA_CQ_VALID, qword7);
				if (!peek_head)
					polarity ^= 1;
			}
			if (polarity != cq_polarity) {
				pr_info("%s[%d]: Extended CQ (cq_id=%u) is empty\n",
					__func__, __LINE__, cq->cq_id);
				return;
			}

			/* Ensure ext CQE contents are read after ext valid bit is checked */
			dma_rmb();

			memset(info, 0, sizeof(*info));
			info->imm_valid = (bool)FIELD_GET(IRDMA_CQ_IMMVALID, qword7);
			if (info->imm_valid) {
				u64 qword4;

				get_64bit_val(ext_cqe, 0, &qword4);
				info->imm_data = (u32)FIELD_GET(IRDMA_CQ_IMMDATALOW32, qword4);
			}
		} else {
			info->imm_valid = false;
		}

		info->q_type = (u8)FIELD_GET(IRDMA_CQ_SQ, qword3);
		info->error = (bool)FIELD_GET(IRDMA_CQ_ERROR, qword3);
		info->push_dropped = (bool)FIELD_GET(IRDMACQ_PSHDROP, qword3);
		info->ipv4 = (bool)FIELD_GET(IRDMACQ_IPV4, qword3);
		if (info->error) {
			info->major_err = FIELD_GET(IRDMA_CQ_MAJERR, qword3);
			info->minor_err = FIELD_GET(IRDMA_CQ_MINERR, qword3);
			if (info->major_err == IRDMA_FLUSH_MAJOR_ERR)
				info->comp_status = IRDMA_COMPL_STATUS_FLUSHED;
			else
				info->comp_status = IRDMA_COMPL_STATUS_UNKNOWN;
		} else {
			info->comp_status = IRDMA_COMPL_STATUS_SUCCESS;
			info->major_err = 0;
			info->minor_err = 0;
		}

		get_64bit_val(cqe, 0, &qword0);
		get_64bit_val(cqe, 16, &qword2);

		info->qp_id = (u32)FIELD_GET(IRDMACQ_QPID, qword2);
		get_64bit_val(cqe, 8, &comp_ctx);
		info->solicited_event = (bool)FIELD_GET(IRDMACQ_SOEVENT, qword3);

		pr_info("%s[%d]: Found CQE (cq_id=%u major_err=%u minor_err=%u q_type=%u "
			"push_dropped=%s ipv4=%s solicited_event=%s imm_data=%u qp_id=%u)\n",
			__func__, __LINE__, cq->cq_id, info->major_err,
			info->minor_err, info->q_type,
			info->push_dropped ? "true" : "false",
			info->ipv4 ? "true" : "false",
			info->solicited_event ? "true" : "false",
			info->imm_valid ? info->imm_data : 0, info->qp_id);

		qp = (struct irdma_qp_uk *)(uintptr_t)comp_ctx;
		if (!qp || qp->destroy_pending) {
			pr_info("%s[%d]: Found CQE for (cq_id=%u qp_id=%u): QP destroyed\n",
				__func__, __LINE__, cq->cq_id, info->qp_id);
			goto loop_end;
		}
		wqe_idx = (u32)FIELD_GET(IRDMA_CQ_WQEIDX, qword3);
		info->qp_handle = (irdma_qp_handle)(uintptr_t)qp;
		info->op_type = (u8)FIELD_GET(IRDMACQ_OP, qword3);

		if (info->q_type == IRDMA_CQE_QTYPE_RQ) {
			u32 array_idx;

			array_idx = wqe_idx / qp->rq_wqe_size_multiplier;
			info->wr_id = qp->rq_wrid_array[array_idx];

			if (qword3 & IRDMACQ_STAG) {
				info->stag_invalid_set = true;
				info->inv_stag = (u32)FIELD_GET(IRDMACQ_INVSTAG, qword2);
			} else {
				info->stag_invalid_set = false;
			}

			pr_info("%s[%d]: Found CQE for RQ qp_id=%u rq_ring (head=%u tail=%u size=%u) "
				"wr_id=%llu wqe_idx=%u, stag_invalid_set=%s op_type=%u\n",
				__func__, __LINE__, info->qp_id,
				qp->rq_ring.head, qp->rq_ring.tail,
				qp->rq_ring.size, info->wr_id, wqe_idx,
				info->stag_invalid_set ? "true" : "false",
				info->op_type);

		} else { /* q_type is IRDMA_CQE_QTYPE_SQ */

			if (qp->first_sq_wq) {
				pr_info("%s[%d]: Found CQE for SQ first_sq_wq (qp_id=%u, wqe_idx=%u, conn_wqes=%d)\n",
					__func__, __LINE__, info->qp_id,
					wqe_idx, qp->conn_wqes);

				if (wqe_idx < qp->conn_wqes && qp->sq_ring.head == qp->sq_ring.tail)
					goto loop_end;
			}

			info->wr_id = qp->sq_wrtrk_array[wqe_idx].wrid;
			info->op_type = (u8)FIELD_GET(IRDMACQ_OP, qword3);

			pr_info("%s[%d]: Found CQE for SQ qp_id=%u, sq_ring (head=%u tail=%u size=%u) "
				"wr_id=%llu wqe_idx=%u op_type=%u\n",
				__func__, __LINE__, info->qp_id,
				qp->sq_ring.head, qp->sq_ring.tail,
				qp->sq_ring.size, info->wr_id, wqe_idx,
				info->op_type);
		}
loop_end:
			i++;
			if (!IRDMA_GET_RING_OFFSET(cq->cq_ring, i))
				cq_polarity ^= 1;

			if (ext_valid && !cq->avoid_mem_cflct) {
				i++;
				if (!IRDMA_GET_RING_OFFSET(cq->cq_ring, i))
					cq_polarity ^= 1;
			}
	}
}

/**
 * irdma_print_sq_wqes - print sqp wqes
 * @qp: hw qp
 */
void irdma_print_sq_wqes(struct irdma_qp_uk *qp)
{
	u32 wqe_idx = IRDMA_RING_CURRENT_TAIL(qp->sq_ring);
	u8 sq_polarity = qp->swqe_polarity;

	pr_info("%s[%d]: SQ (qp_id=%u sq_polarity=%d head=%u tail=%u size=%u)\n",
		__func__, __LINE__, qp->qp_id, sq_polarity, qp->sq_ring.head,
		qp->sq_ring.tail, qp->sq_ring.size);

	if (!IRDMA_RING_MORE_WORK(qp->sq_ring)) {
		pr_info("%s[%d]: SQ is empty (qp_id=%u)\n", __func__,
			__LINE__, qp->qp_id);
		return;
	}

	while (true) {
		u8 wqe_polarity;
		__le64 *wqe;
		u64 val;
		int i;

		wqe = qp->sq_base[wqe_idx].elem;
		get_64bit_val(wqe, 24, &val);
		wqe_polarity = FIELD_GET(IRDMAQPSQ_VALID, val);

		if (wqe_polarity != sq_polarity)
			break;

		pr_info("%s[%d]: Found WQE in SQ qp_id=%u wr_id=%llu wqe_idx=%u "
			"wr_len=%u quanta=%u hdr=0x%0llX\n", __func__,
			__LINE__, qp->qp_id, qp->sq_wrtrk_array[wqe_idx].wrid,
			wqe_idx, qp->sq_wrtrk_array[wqe_idx].wr_len,
			qp->sq_wrtrk_array[wqe_idx].quanta, val);

		for (i = 0; i < (qp->sq_wrtrk_array[wqe_idx].quanta * IRDMA_QP_WQE_MIN_SIZE / 8); i++)
			pr_debug("index %03d val: %016llx\n", i, *(wqe + i));
		wqe_idx += qp->sq_wrtrk_array[wqe_idx].quanta;

		if (!wqe_idx)
			sq_polarity = !qp->swqe_polarity;
	}
}
#endif /* PRINT_CQES */

/**
 * irdma_round_up_wq - return round up qp wq depth
 * @wqdepth: wq depth in quanta to round up
 */
static int irdma_round_up_wq(u32 wqdepth)
{
	int scount = 1;

	for (wqdepth--; scount <= 16; scount *= 2)
		wqdepth |= wqdepth >> scount;

	return ++wqdepth;
}

/**
 * irdma_get_wqe_shift - get shift count for maximum wqe size
 * @uk_attrs: qp HW attributes
 * @sge: Maximum Scatter Gather Elements wqe
 * @inline_data: Maximum inline data size
 * @shift: Returns the shift needed based on sge
 *
 * Shift can be used to left shift the wqe size based on number of SGEs and inlind data size.
 * For 1 SGE or inline data <= 8, shift = 0 (wqe size of 32
 * bytes). For 2 or 3 SGEs or inline data <= 39, shift = 1 (wqe
 * size of 64 bytes).
 * For 4-7 SGE's and inline <= 101 Shift of 2 otherwise (wqe
 * size of 256 bytes).
 */
void irdma_get_wqe_shift(struct irdma_uk_attrs *uk_attrs, u32 sge,
			 u32 inline_data, u8 *shift)
{
	*shift = 0;
	if (uk_attrs->hw_rev >= IRDMA_GEN_2) {
		if (sge > 1 || inline_data > 8) {
			if (sge < 4 && inline_data <= 39)
				*shift = 1;
			else if (sge < 8 && inline_data <= 101)
				*shift = 2;
			else
				*shift = 3;
		}
	} else if (sge > 1 || inline_data > 16) {
		*shift = (sge < 4 && inline_data <= 48) ? 1 : 2;
	}
}

/*
 * irdma_get_sqdepth - get SQ depth (quanta)
 * @uk_attrs: qp HW attributes
 * @sq_size: SQ size
 * @shift: shift which determines size of WQE
 * @sqdepth: depth of SQ
 */
int irdma_get_sqdepth(struct irdma_uk_attrs *uk_attrs, u32 sq_size, u8 shift, u32 *sqdepth)
{
	u32 min_size = (u32)uk_attrs->min_hw_wq_size << shift;

	*sqdepth = irdma_round_up_wq((sq_size << shift) + IRDMA_SQ_RSVD);

	if (*sqdepth < min_size)
		*sqdepth = min_size;
	else if (*sqdepth > uk_attrs->max_hw_wq_quanta)
		return -EINVAL;

	return 0;
}

/*
 * irdma_get_rqdepth - get RQ depth (quanta)
 * @uk_attrs: qp HW attributes
 * @rq_size: SRQ size
 * @shift: shift which determines size of WQE
 * @rqdepth: depth of RQ/SRQ
 */
int irdma_get_rqdepth(struct irdma_uk_attrs *uk_attrs, u32 rq_size, u8 shift, u32 *rqdepth)
{
	u32 min_size = (u32)uk_attrs->min_hw_wq_size << shift;

	*rqdepth = irdma_round_up_wq((rq_size << shift) + IRDMA_RQ_RSVD);

	if (*rqdepth < min_size)
		*rqdepth = min_size;
	else if (*rqdepth > uk_attrs->max_hw_rq_quanta)
		return -EINVAL;

	return 0;
}

/*
 * irdma_get_srqdepth - get SRQ depth (quanta)
 * @uk_attrs: qp HW attributes
 * @srq_size: SRQ size
 * @shift: shift which determines size of WQE
 * @srqdepth: depth of SRQ
 */
int irdma_get_srqdepth(struct irdma_uk_attrs *uk_attrs, u32 srq_size, u8 shift, u32 *srqdepth)
{
	*srqdepth = irdma_round_up_wq((srq_size << shift) + IRDMA_RQ_RSVD);

	if (*srqdepth < ((u32)uk_attrs->min_hw_wq_size << shift))
		*srqdepth = uk_attrs->min_hw_wq_size << shift;
	else if (*srqdepth > uk_attrs->max_hw_srq_quanta)
		return -EINVAL;

	return 0;
}

static const struct irdma_wqe_uk_ops iw_wqe_uk_ops = {
	.iw_copy_inline_data = irdma_copy_inline_data,
	.iw_inline_data_size_to_quanta = irdma_inline_data_size_to_quanta,
	.iw_set_fragment = irdma_set_fragment,
};

static const struct irdma_wqe_uk_ops iw_wqe_uk_ops_gen_1 = {
	.iw_copy_inline_data = irdma_copy_inline_data_gen_1,
	.iw_inline_data_size_to_quanta = irdma_inline_data_size_to_quanta_gen_1,
	.iw_set_fragment = irdma_set_fragment_gen_1,
};

/**
 * irdma_setup_connection_wqes - setup WQEs necessary to complete
 * connection.
 * @qp: hw qp (user and kernel)
 * @info: qp initialization info
 */
static void irdma_setup_connection_wqes(struct irdma_qp_uk *qp,
					struct irdma_qp_uk_init_info *info)
{
	u16 move_cnt = 1;

	if (info->start_wqe_idx)
		move_cnt = info->start_wqe_idx;
	else if (!info->legacy_mode &&
		 (qp->uk_attrs->feature_flags & IRDMA_FEATURE_RTS_AE))
		move_cnt = 3;
	qp->conn_wqes = move_cnt;
	IRDMA_RING_MOVE_HEAD_BY_COUNT_NOCHECK(qp->sq_ring, move_cnt);
	IRDMA_RING_MOVE_TAIL_BY_COUNT(qp->sq_ring, move_cnt);
	IRDMA_RING_MOVE_HEAD_BY_COUNT_NOCHECK(qp->initial_ring, move_cnt);
}

/**
 * irdma_uk_srq_init - initialize shared qp
 * @srq: hw srq (user and kernel)
 * @info: srq initialization info
 *
 * initializes the vars used in both user and kernel mode.
 * size of the wqe depends on numbers of max. fragements
 * allowed. Then size of wqe * the number of wqes should be the
 * amount of memory allocated for srq.
 */
int irdma_uk_srq_init(struct irdma_srq_uk *srq,
		      struct irdma_srq_uk_init_info *info)
{
	u8 rqshift;

	srq->uk_attrs = info->uk_attrs;
	if (info->max_srq_frag_cnt > srq->uk_attrs->max_hw_wq_frags)
		return -EINVAL;

	irdma_get_wqe_shift(srq->uk_attrs, info->max_srq_frag_cnt, 0, &rqshift);
	srq->srq_caps = info->srq_caps;
	srq->srq_base = info->srq;
	srq->shadow_area = info->shadow_area;
	srq->srq_id = info->srq_id;
	srq->srwqe_polarity = 0;
	srq->srq_size = info->srq_size;
	srq->wqe_size = rqshift;
	srq->max_srq_frag_cnt = min(srq->uk_attrs->max_hw_wq_frags,
				    ((u32)2 << rqshift) - 1);
	IRDMA_RING_INIT(srq->srq_ring, srq->srq_size);
	srq->wqe_size_multiplier = 1 << rqshift;
	srq->wqe_ops = iw_wqe_uk_ops;

	return 0;
}

/**
 * irdma_uk_calc_shift_wq - calculate WQE shift for both SQ and RQ
 * @ukinfo: qp initialization info
 * @sq_shift: Returns shift of SQ
 * @rq_shift: Returns shift of RQ
 */
void irdma_uk_calc_shift_wq(struct irdma_qp_uk_init_info *ukinfo, u8 *sq_shift,
			    u8 *rq_shift)
{
	bool imm_support = ukinfo->uk_attrs->hw_rev >= IRDMA_GEN_2 ? true : false;

	irdma_get_wqe_shift(ukinfo->uk_attrs,
			    imm_support ? ukinfo->max_sq_frag_cnt + 1 :
					  ukinfo->max_sq_frag_cnt,
			    ukinfo->max_inline_data, sq_shift);

	irdma_get_wqe_shift(ukinfo->uk_attrs, ukinfo->max_rq_frag_cnt, 0,
			    rq_shift);

	if (ukinfo->uk_attrs->hw_rev == IRDMA_GEN_1) {
		if (ukinfo->abi_ver > 4)
			*rq_shift = IRDMA_MAX_RQ_WQE_SHIFT_GEN1;
	}
}

/**
 * irdma_uk_calc_depth_shift_sq - calculate depth and shift for SQ size.
 * @ukinfo: qp initialization info
 * @sq_depth: Returns depth of SQ
 * @sq_shift: Returns shift of SQ
 */
int irdma_uk_calc_depth_shift_sq(struct irdma_qp_uk_init_info *ukinfo,
				 u32 *sq_depth, u8 *sq_shift)
{
	bool imm_support = ukinfo->uk_attrs->hw_rev >= IRDMA_GEN_2 ? true : false;
	int status;
	irdma_get_wqe_shift(ukinfo->uk_attrs,
			    imm_support ? ukinfo->max_sq_frag_cnt + 1 :
					  ukinfo->max_sq_frag_cnt,
			    ukinfo->max_inline_data, sq_shift);
	status = irdma_get_sqdepth(ukinfo->uk_attrs, ukinfo->sq_size,
				   *sq_shift, sq_depth);

	return status;
}

/**
 * irdma_uk_calc_depth_shift_rq - calculate depth and shift for RQ size.
 * @ukinfo: qp initialization info
 * @rq_depth: Returns depth of RQ
 * @rq_shift: Returns shift of RQ
 */
int irdma_uk_calc_depth_shift_rq(struct irdma_qp_uk_init_info *ukinfo,
				 u32 *rq_depth, u8 *rq_shift)
{
	int status;

	irdma_get_wqe_shift(ukinfo->uk_attrs, ukinfo->max_rq_frag_cnt, 0,
			    rq_shift);

	if (ukinfo->uk_attrs->hw_rev == IRDMA_GEN_1) {
		if (ukinfo->abi_ver > 4)
			*rq_shift = IRDMA_MAX_RQ_WQE_SHIFT_GEN1;
	}

	status = irdma_get_rqdepth(ukinfo->uk_attrs, ukinfo->rq_size,
				   *rq_shift, rq_depth);

	return status;
}

/**
 * irdma_uk_qp_init - initialize shared qp
 * @qp: hw qp (user and kernel)
 * @info: qp initialization info
 *
 * initializes the vars used in both user and kernel mode.
 * size of the wqe depends on numbers of max. fragements
 * allowed. Then size of wqe * the number of wqes should be the
 * amount of memory allocated for sq and rq.
 */
int irdma_uk_qp_init(struct irdma_qp_uk *qp, struct irdma_qp_uk_init_info *info)
{
	int ret_code = 0;
	u32 sq_ring_size;

	qp->uk_attrs = info->uk_attrs;
	if (info->max_sq_frag_cnt > qp->uk_attrs->max_hw_wq_frags ||
	    info->max_rq_frag_cnt > qp->uk_attrs->max_hw_wq_frags)
		return -EINVAL;

	qp->qp_caps = info->qp_caps;
	qp->sq_base = info->sq;
	qp->rq_base = info->rq;
	qp->qp_type = info->type ? info->type : IRDMA_QP_TYPE_IWARP;
	qp->shadow_area = info->shadow_area;
	qp->sq_wrtrk_array = info->sq_wrtrk_array;

	qp->rq_wrid_array = info->rq_wrid_array;
	qp->wqe_alloc_db = info->wqe_alloc_db;
	qp->rd_fence_rate = info->rd_fence_rate;
	qp->qp_id = info->qp_id;
	qp->sq_size = info->sq_size;
	qp->push_mode = false;
	qp->max_sq_frag_cnt = info->max_sq_frag_cnt;
	sq_ring_size = qp->sq_size << info->sq_shift;
	IRDMA_RING_INIT(qp->sq_ring, sq_ring_size);
	IRDMA_RING_INIT(qp->initial_ring, sq_ring_size);
	if (info->first_sq_wq) {
		irdma_setup_connection_wqes(qp, info);
		qp->swqe_polarity = 1;
		qp->first_sq_wq = true;
	} else {
		qp->swqe_polarity = 0;
	}
	qp->swqe_polarity_deferred = 1;
	qp->rwqe_polarity = 0;
	qp->rq_size = info->rq_size;
	qp->max_rq_frag_cnt = info->max_rq_frag_cnt;
	qp->max_inline_data = info->max_inline_data;
	qp->rq_wqe_size = info->rq_shift;
	IRDMA_RING_INIT(qp->rq_ring, qp->rq_size);
	qp->rq_wqe_size_multiplier = 1 << info->rq_shift;
	if (qp->uk_attrs->hw_rev == IRDMA_GEN_1)
		qp->wqe_ops = iw_wqe_uk_ops_gen_1;
	else
		qp->wqe_ops = iw_wqe_uk_ops;
	qp->srq_uk = info->srq_uk;
	qp->start_wqe_idx = info->start_wqe_idx;

	return ret_code;
}

/**
 * irdma_uk_cq_init - initialize shared cq (user and kernel)
 * @cq: hw cq
 * @info: hw cq initialization info
 */
int irdma_uk_cq_init(struct irdma_cq_uk *cq, struct irdma_cq_uk_init_info *info)
{
	cq->cq_base = info->cq_base;
	cq->cq_id = info->cq_id;
	cq->cq_size = info->cq_size;
	cq->cqe_alloc_db = info->cqe_alloc_db;
	cq->cq_ack_db = info->cq_ack_db;
	cq->shadow_area = info->shadow_area;
	cq->avoid_mem_cflct = info->avoid_mem_cflct;
	IRDMA_RING_INIT(cq->cq_ring, cq->cq_size);
	cq->polarity = 1;

	return 0;
}

/**
 * irdma_uk_clean_cq - clean cq entries
 * @q: completion context
 * @cq: cq to clean
 */
void irdma_uk_clean_cq(void *q, struct irdma_cq_uk *cq)
{
	__le64 *cqe;
	u64 qword3, comp_ctx;
	u32 cq_head;
	u8 polarity, temp;

	cq_head = cq->cq_ring.head;
	temp = cq->polarity;
	do {
		if (cq->avoid_mem_cflct)
			cqe = ((struct irdma_extended_cqe *)(cq->cq_base))[cq_head].buf;
		else
			cqe = cq->cq_base[cq_head].buf;
		get_64bit_val(cqe, 24, &qword3);
		polarity = (u8)FIELD_GET(IRDMA_CQ_VALID, qword3);

		if (polarity != temp)
			break;

		/* Ensure CQE contents are read after valid bit is checked */
		dma_rmb();

		get_64bit_val(cqe, 8, &comp_ctx);
		if ((void *)(unsigned long)comp_ctx == q)
			set_64bit_val(cqe, 8, 0);

		cq_head = (cq_head + 1) % cq->cq_ring.size;
		if (!cq_head)
			temp ^= 1;
	} while (true);
}

/**
 * irdma_fragcnt_to_quanta_sq - calculate quanta based on fragment count for SQ
 * @frag_cnt: number of fragments
 * @quanta: quanta for frag_cnt
 */
int irdma_fragcnt_to_quanta_sq(u32 frag_cnt, u16 *quanta)
{
	switch (frag_cnt) {
	case 0:
	case 1:
		*quanta = IRDMA_QP_WQE_MIN_QUANTA;
		break;
	case 2:
	case 3:
		*quanta = 2;
		break;
	case 4:
	case 5:
		*quanta = 3;
		break;
	case 6:
	case 7:
		*quanta = 4;
		break;
	case 8:
	case 9:
		*quanta = 5;
		break;
	case 10:
	case 11:
		*quanta = 6;
		break;
	case 12:
	case 13:
		*quanta = 7;
		break;
	case 14:
	case 15: /* when immediate data is present */
		*quanta = 8;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

/**
 * irdma_fragcnt_to_wqesize_rq - calculate wqe size based on fragment count for RQ
 * @frag_cnt: number of fragments
 * @wqe_size: size in bytes given frag_cnt
 */
int irdma_fragcnt_to_wqesize_rq(u32 frag_cnt, u16 *wqe_size)
{
	switch (frag_cnt) {
	case 0:
	case 1:
		*wqe_size = 32;
		break;
	case 2:
	case 3:
		*wqe_size = 64;
		break;
	case 4:
	case 5:
	case 6:
	case 7:
		*wqe_size = 128;
		break;
	case 8:
	case 9:
	case 10:
	case 11:
	case 12:
	case 13:
	case 14:
		*wqe_size = 256;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

