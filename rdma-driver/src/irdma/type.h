/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2015 - 2023 Intel Corporation */
#ifndef IRDMA_TYPE_H
#define IRDMA_TYPE_H

#include "osdep.h"

#include "irdma.h"
#include "user.h"
#include "hmc.h"
#include "uda.h"
#include "ws.h"
#include "virtchnl.h"
#include "pble.h"

#define IRDMA_DEBUG_ERR		"ERR"
#define IRDMA_DEBUG_INIT	"INIT"
#define IRDMA_DEBUG_DEV		"DEV"
#define IRDMA_DEBUG_CM		"CM"
#define IRDMA_DEBUG_VERBS	"VERBS"
#define IRDMA_DEBUG_PUDA	"PUDA"
#define IRDMA_DEBUG_ILQ		"ILQ"
#define IRDMA_DEBUG_IEQ		"IEQ"
#define IRDMA_DEBUG_QP		"QP"
#define IRDMA_DEBUG_CQ		"CQ"
#define IRDMA_DEBUG_MR		"MR"
#define IRDMA_DEBUG_PBLE	"PBLE"
#define IRDMA_DEBUG_WQE		"WQE"
#define IRDMA_DEBUG_AEQ		"AEQ"
#define IRDMA_DEBUG_CQP		"CQP"
#define IRDMA_DEBUG_HMC		"HMC"
#define IRDMA_DEBUG_USER	"USER"
#define IRDMA_DEBUG_VIRT	"VIRT"
#define IRDMA_DEBUG_DCB		"DCB"
#define	IRDMA_DEBUG_CQE		"CQE"
#define IRDMA_DEBUG_CLNT	"CLNT"
#define IRDMA_DEBUG_WS		"WS"
#define IRDMA_DEBUG_STATS	"STATS"

#define RSVD_OFFSET 0xFFFFFFFF

enum irdma_page_size {
	IRDMA_PAGE_SIZE_4K = 0,
	IRDMA_PAGE_SIZE_2M,
	IRDMA_PAGE_SIZE_1G,
};

enum irdma_hdrct_flags {
	DDP_LEN_FLAG  = 0x80,
	DDP_HDR_FLAG  = 0x40,
	RDMA_HDR_FLAG = 0x20,
};

enum irdma_term_layers {
	LAYER_RDMA = 0,
	LAYER_DDP  = 1,
	LAYER_MPA  = 2,
};

enum irdma_term_error_types {
	RDMAP_REMOTE_PROT = 1,
	RDMAP_REMOTE_OP   = 2,
	DDP_CATASTROPHIC  = 0,
	DDP_TAGGED_BUF    = 1,
	DDP_UNTAGGED_BUF  = 2,
	DDP_LLP		  = 3,
};

enum irdma_term_rdma_errors {
	RDMAP_INV_STAG		  = 0x00,
	RDMAP_INV_BOUNDS	  = 0x01,
	RDMAP_ACCESS		  = 0x02,
	RDMAP_UNASSOC_STAG	  = 0x03,
	RDMAP_TO_WRAP		  = 0x04,
	RDMAP_INV_RDMAP_VER       = 0x05,
	RDMAP_UNEXPECTED_OP       = 0x06,
	RDMAP_CATASTROPHIC_LOCAL  = 0x07,
	RDMAP_CATASTROPHIC_GLOBAL = 0x08,
	RDMAP_CANT_INV_STAG       = 0x09,
	RDMAP_UNSPECIFIED	  = 0xff,
};

enum irdma_term_ddp_errors {
	DDP_CATASTROPHIC_LOCAL      = 0x00,
	DDP_TAGGED_INV_STAG	    = 0x00,
	DDP_TAGGED_BOUNDS	    = 0x01,
	DDP_TAGGED_UNASSOC_STAG     = 0x02,
	DDP_TAGGED_TO_WRAP	    = 0x03,
	DDP_TAGGED_INV_DDP_VER      = 0x04,
	DDP_UNTAGGED_INV_QN	    = 0x01,
	DDP_UNTAGGED_INV_MSN_NO_BUF = 0x02,
	DDP_UNTAGGED_INV_MSN_RANGE  = 0x03,
	DDP_UNTAGGED_INV_MO	    = 0x04,
	DDP_UNTAGGED_INV_TOO_LONG   = 0x05,
	DDP_UNTAGGED_INV_DDP_VER    = 0x06,
};

enum irdma_term_mpa_errors {
	MPA_CLOSED  = 0x01,
	MPA_CRC     = 0x02,
	MPA_MARKER  = 0x03,
	MPA_REQ_RSP = 0x04,
};

enum irdma_hw_stats_index {
	/* gen1 - 32-bit */
	IRDMA_HW_STAT_INDEX_IP4RXDISCARD	= 0,
	IRDMA_HW_STAT_INDEX_IP4RXTRUNC		= 1,
	IRDMA_HW_STAT_INDEX_IP4TXNOROUTE	= 2,
	IRDMA_HW_STAT_INDEX_IP6RXDISCARD	= 3,
	IRDMA_HW_STAT_INDEX_IP6RXTRUNC		= 4,
	IRDMA_HW_STAT_INDEX_IP6TXNOROUTE	= 5,
	IRDMA_HW_STAT_INDEX_TCPRTXSEG		= 6,
	IRDMA_HW_STAT_INDEX_TCPRXOPTERR		= 7,
	IRDMA_HW_STAT_INDEX_TCPRXPROTOERR	= 8,
	IRDMA_HW_STAT_INDEX_RXVLANERR		= 9,
	/* gen1 - 64-bit */
	IRDMA_HW_STAT_INDEX_IP4RXOCTS		= 10,
	IRDMA_HW_STAT_INDEX_IP4RXPKTS		= 11,
	IRDMA_HW_STAT_INDEX_IP4RXFRAGS		= 12,
	IRDMA_HW_STAT_INDEX_IP4RXMCPKTS		= 13,
	IRDMA_HW_STAT_INDEX_IP4TXOCTS		= 14,
	IRDMA_HW_STAT_INDEX_IP4TXPKTS		= 15,
	IRDMA_HW_STAT_INDEX_IP4TXFRAGS		= 16,
	IRDMA_HW_STAT_INDEX_IP4TXMCPKTS		= 17,
	IRDMA_HW_STAT_INDEX_IP6RXOCTS		= 18,
	IRDMA_HW_STAT_INDEX_IP6RXPKTS		= 19,
	IRDMA_HW_STAT_INDEX_IP6RXFRAGS		= 20,
	IRDMA_HW_STAT_INDEX_IP6RXMCPKTS		= 21,
	IRDMA_HW_STAT_INDEX_IP6TXOCTS		= 22,
	IRDMA_HW_STAT_INDEX_IP6TXPKTS		= 23,
	IRDMA_HW_STAT_INDEX_IP6TXFRAGS		= 24,
	IRDMA_HW_STAT_INDEX_IP6TXMCPKTS		= 25,
	IRDMA_HW_STAT_INDEX_TCPRXSEGS		= 26,
	IRDMA_HW_STAT_INDEX_TCPTXSEG		= 27,
	IRDMA_HW_STAT_INDEX_RDMARXRDS		= 28,
	IRDMA_HW_STAT_INDEX_RDMARXSNDS		= 29,
	IRDMA_HW_STAT_INDEX_RDMARXWRS		= 30,
	IRDMA_HW_STAT_INDEX_RDMATXRDS		= 31,
	IRDMA_HW_STAT_INDEX_RDMATXSNDS		= 32,
	IRDMA_HW_STAT_INDEX_RDMATXWRS		= 33,
	IRDMA_HW_STAT_INDEX_RDMAVBND		= 34,
	IRDMA_HW_STAT_INDEX_RDMAVINV		= 35,
	IRDMA_HW_STAT_INDEX_IP4RXMCOCTS		= 36,
	IRDMA_HW_STAT_INDEX_IP4TXMCOCTS		= 37,
	IRDMA_HW_STAT_INDEX_IP6RXMCOCTS		= 38,
	IRDMA_HW_STAT_INDEX_IP6TXMCOCTS		= 39,
	IRDMA_HW_STAT_INDEX_UDPRXPKTS		= 40,
	IRDMA_HW_STAT_INDEX_UDPTXPKTS		= 41,
	IRDMA_HW_STAT_INDEX_MAX_GEN_1		= 42, /* Must be same value as next entry */

	/* gen2 - 64-bit */
	IRDMA_HW_STAT_INDEX_RXNPECNMARKEDPKTS	= 42,

	/* gen2 - 32-bit */
	IRDMA_HW_STAT_INDEX_RXRPCNPHANDLED	= 43,
	IRDMA_HW_STAT_INDEX_RXRPCNPIGNORED	= 44,
	IRDMA_HW_STAT_INDEX_TXNPCNPSENT		= 45,
	IRDMA_HW_STAT_INDEX_MAX_GEN_2		= 46,

	/* gen3 */
	IRDMA_HW_STAT_INDEX_RNR_SENT		= 46,
	IRDMA_HW_STAT_INDEX_RNR_RCVD		= 47,
	IRDMA_HW_STAT_INDEX_RDMAORDLMTCNT	= 48,
	IRDMA_HW_STAT_INDEX_RDMAIRDLMTCNT	= 49,
	IRDMA_HW_STAT_INDEX_RDMARXATS		= 50,
	IRDMA_HW_STAT_INDEX_RDMATXATS		= 51,
	IRDMA_HW_STAT_INDEX_NAKSEQERR		= 52,
	IRDMA_HW_STAT_INDEX_NAKSEQERR_IMPLIED	= 53,
	IRDMA_HW_STAT_INDEX_RTO			= 54,
	IRDMA_HW_STAT_INDEX_RXOOOPKTS		= 55,
	IRDMA_HW_STAT_INDEX_ICRCERR		= 56,
	IRDMA_HW_STAT_INDEX_MAX_GEN_3		= 57,

	IRDMA_HW_STAT_INDEX_RDMARXFLUSH		= 57,
	IRDMA_HW_STAT_INDEX_RDMATXFLUSH		= 58,
	IRDMA_HW_STAT_INDEX_RDMARXATOMICWRITE	= 59,
	IRDMA_HW_STAT_INDEX_RDMATXATOMICWRITE	= 60,
	IRDMA_HW_STAT_INDEX_MAX_GEN_4		= 61,
};

#define IRDMA_MIN_FEATURES 2

enum irdma_feature_type {
	IRDMA_FEATURE_FW_INFO = 0,
	IRDMA_HW_VERSION_INFO = 1,
	IRDMA_QP_MAX_INCR     = 2,
	IRDMA_CQ_MAX_INCR     = 3,
	IRDMA_CEQ_MAX_INCR    = 4,
	IRDMA_SD_MAX_INCR     = 5,
	IRDMA_MR_MAX_INCR     = 6,
	IRDMA_Q1_MAX_INCR     = 7,
	IRDMA_AH_MAX_INCR     = 8,
	IRDMA_SRQ_MAX_INCR    = 9,
	IRDMA_TIMER_MAX_INCR  = 10,
	IRDMA_XF_MAX_INCR     = 11,
	IRDMA_RRF_MAX_INCR    = 12,
	IRDMA_PBLE_MAX_INCR   = 13,
	IRDMA_OBJ_1           = 22,
	IRDMA_OBJ_2           = 23,
	IRDMA_ENDPT_TRK       = 24,
	IRDMA_FTN_INLINE_MAX  = 25,
	IRDMA_QSETS_MAX       = 26,
	IRDMA_ASO	      = 27,
	/* this indicates if atomics are allowed */
	IRDMA_FTN_FLAGS	      = 32,
	IRDMA_FTN_NOP         = 33,
	IRDMA_MAX_FEATURES, /* Must be last entry */
};

enum irdma_sched_prio_type {
	IRDMA_PRIO_WEIGHTED_RR     = 1,
	IRDMA_PRIO_STRICT	   = 2,
	IRDMA_PRIO_WEIGHTED_STRICT = 3,
};

enum irdma_vm_vf_type {
	IRDMA_VF_TYPE = 0,
	IRDMA_VM_TYPE,
	IRDMA_PF_TYPE,
};

enum irdma_cqp_hmc_profile {
	IRDMA_HMC_PROFILE_DEFAULT  = 1,
	IRDMA_HMC_PROFILE_FAVOR_VF = 2,
	IRDMA_HMC_PROFILE_EQUAL    = 3,
};

enum irdma_quad_entry_type {
	IRDMA_QHASH_TYPE_TCP_ESTABLISHED = 1,
	IRDMA_QHASH_TYPE_TCP_SYN,
	IRDMA_QHASH_TYPE_UDP_UNICAST,
	IRDMA_QHASH_TYPE_UDP_MCAST,
	IRDMA_QHASH_TYPE_ROCE_MCAST,
	IRDMA_QHASH_TYPE_ROCEV2_HW,
};

enum irdma_quad_hash_manage_type {
	IRDMA_QHASH_MANAGE_TYPE_DELETE = 0,
	IRDMA_QHASH_MANAGE_TYPE_ADD,
	IRDMA_QHASH_MANAGE_TYPE_MODIFY,
};

enum irdma_syn_rst_handling {
	IRDMA_SYN_RST_HANDLING_HW_TCP_SECURE = 0,
	IRDMA_SYN_RST_HANDLING_HW_TCP,
	IRDMA_SYN_RST_HANDLING_FW_TCP_SECURE,
	IRDMA_SYN_RST_HANDLING_FW_TCP,
};

enum irdma_queue_type {
	IRDMA_QUEUE_TYPE_SQ_RQ = 0,
	IRDMA_QUEUE_TYPE_CQP,
	IRDMA_QUEUE_TYPE_SRQ,
};

struct irdma_sc_dev;
struct irdma_vsi_pestat;

struct irdma_dcqcn_cc_params {
	u8 cc_cfg_valid;
	u8 min_dec_factor;
	u8 min_rate;
	u8 dcqcn_f;
	u16 rai_factor;
	u16 hai_factor;
	u16 dcqcn_t;
	u32 dcqcn_b;
	u32 rreduce_mperiod;
};

#define IRDMA_CQP_RQ_SMALL_BUF_SZ 64
#define IRDMA_CQP_RQ_LARGE_BUF_SZ 256
struct irdma_cqp_rqe_bufs {
	struct irdma_dma_mem small_buf;
	struct irdma_dma_mem large_buf;
};

struct irdma_cqp_init_info {
	u64 cqp_compl_ctx;
	u64 host_ctx_pa;
	u64 sq_pa;
	u64 rq_pa;
	struct irdma_sc_dev *dev;
	struct irdma_cqp_quanta *sq;
	struct irdma_cqp_quanta *rq;
	struct irdma_cqp_rqe_bufs *rqe_array;
	struct irdma_dma_mem rq_small_bufs;
	struct irdma_dma_mem rq_large_bufs;
	struct irdma_dcqcn_cc_params dcqcn_params;
	__le64 *host_ctx;
	u64 *scratch_array;
	u32 sq_size;
	u64 *rq_scratch_array;
	u32 rq_size;
	struct irdma_ooo_cqp_op *ooo_op_array;
	u32 pe_en_vf_cnt;
	u16 hw_maj_ver;
	u16 hw_min_ver;
	u8 struct_ver;
	u8 hmc_profile;
	u8 ena_vf_count;
	u8 ceqs_per_vf;
	u8 timer_slots;
	u8 ooisc_blksize;
	u8 rrsp_blksize;
	u8 q1_blksize;
	u8 xmit_blksize;
	u8 ts_override;
	u8 ts_shift;
	u8 en_fine_grained_timers;
	u8 blksizes_valid;
	u8 cqp_type;
	bool en_datacenter_tcp:1;
	bool disable_packed:1;
	bool rocev2_rto_policy:1;
	bool en_rem_endpoint_trk:1;
	enum irdma_protocol_used protocol_used;
};

struct irdma_terminate_hdr {
	u8 layer_etype;
	u8 error_code;
	u8 hdrct;
	u8 rsvd;
};

struct irdma_cqp_sq_wqe {
	__le64 buf[IRDMA_CQP_WQE_SIZE];
};

struct irdma_cqp_rq_wqe {
	__le64 buf[IRDMA_CQP_WQE_SIZE];
};

struct irdma_sc_aeqe {
	__le64 buf[IRDMA_AEQE_SIZE];
};

struct irdma_ceqe {
	__le64 buf[IRDMA_CEQE_SIZE];
};

struct irdma_cqp_ctx {
	__le64 buf[IRDMA_CQP_CTX_SIZE];
};

struct irdma_cq_shadow_area {
	__le64 buf[IRDMA_SHADOW_AREA_SIZE];
};

struct irdma_dev_hw_stats_offsets {
	u32 stats_offset[IRDMA_HW_STAT_INDEX_MAX_GEN_1];
};

struct irdma_dev_hw_stats {
	u64 stats_val[IRDMA_GATHER_STATS_BUF_SIZE / sizeof(u64)];
};

struct irdma_gather_stats {
	u64 val[IRDMA_GATHER_STATS_BUF_SIZE / sizeof(u64)];
};

struct irdma_hw_stat_map {
	u16 byteoff;
	u8 bitoff;
	u64 bitmask;
};

struct irdma_stats_gather_info {
	bool use_hmc_fcn_index:1;
	bool use_stats_inst:1;
	u16 hmc_fcn_index;
	u16 stats_inst_index;
	struct irdma_dma_mem stats_buff_mem;
	void *gather_stats_va;
	void *last_gather_stats_va;
};

struct irdma_vsi_pestat {
	struct irdma_hw *hw;
	struct irdma_dev_hw_stats hw_stats;
	struct irdma_stats_gather_info gather_info;
	struct timer_list stats_timer;
	struct irdma_sc_vsi *vsi;
	spinlock_t lock; /* rdma stats lock */
};

struct irdma_hw {
	u8 __iomem *hw_addr;
	u8 __iomem *priv_hw_addr;
	struct device *device;
	struct irdma_hmc_info hmc;
};

struct irdma_pfpdu {
	struct list_head rxlist;
	u32 rcv_nxt;
	u32 fps;
	u32 max_fpdu_data;
	u32 nextseqnum;
	u32 rcv_start_seq;
	bool mode:1;
	bool mpa_crc_err:1;
	u8  marker_len;
	u64 total_ieq_bufs;
	u64 fpdu_processed;
	u64 bad_seq_num;
	u64 crc_err;
	u64 no_tx_bufs;
	u64 tx_err;
	u64 out_of_order;
	u64 pmode_count;
	struct irdma_sc_ah *ah;
	struct irdma_puda_buf *ah_buf;
	spinlock_t lock; /* fpdu processing lock */
	struct irdma_puda_buf *lastrcv_buf;
};

struct irdma_sc_pd {
	struct irdma_sc_dev *dev;
	u32 pd_id;
	int abi_ver;
};

struct irdma_cqp_quanta {
	__le64 elem[IRDMA_CQP_WQE_SIZE];
};

struct irdma_ooo_cqp_op {
	struct list_head list_entry;
	u64 scratch;
	u32 def_info;
	u32 sw_def_info;
	u32 wqe_idx;
	bool deferred:1;
};

struct irdma_sc_cqp {
	spinlock_t ooo_list_lock; /* protects list of pending completions */
	struct list_head ooo_avail;
	struct list_head ooo_pnd;
	u32 last_def_cmpl_ticket;
	u32 sw_def_cmpl_ticket;
	u32 size;
	u64 sq_pa;
	u64 host_ctx_pa;
	void *back_cqp;
	struct irdma_sc_dev *dev;
	int (*process_cqp_sds)(struct irdma_sc_dev *dev,
			       struct irdma_update_sds_info *info);
	struct irdma_dma_mem sdbuf;
	struct irdma_ring sq_ring;
	struct irdma_cqp_quanta *sq_base;
	struct irdma_dcqcn_cc_params dcqcn_params;
	__le64 *host_ctx;
	u64 *scratch_array;
	u64 requested_ops;
	atomic64_t completed_ops;
	struct irdma_ooo_cqp_op *ooo_op_array;
	u64 *rq_scratch_array;
	u64 rq_pa;
	struct irdma_cqp_quanta *rq_base;
	struct irdma_cqp_rqe_bufs *rqe_array;
	struct irdma_ring rq_ring;
	u32 rq_size;
	u32 hw_rq_size;
	u32 cqp_id;
	u32 sq_size;
	u32 pe_en_vf_cnt;
	u32 hw_sq_size;
	u16 hw_maj_ver;
	u16 hw_min_ver;
	u8 struct_ver;
	u8 polarity;
	u8 rq_polarity;
	u8 cqp_type;
	u8 hmc_profile;
	u8 ena_vf_count;
	u8 timeout_count;
	u8 ceqs_per_vf;
	u8 timer_slots;
	u8 ooisc_blksize;
	u8 rrsp_blksize;
	u8 q1_blksize;
	u8 xmit_blksize;
	u8 ts_override;
	u8 ts_shift;
	u8 en_fine_grained_timers;
	u8 blksizes_valid;
	bool en_datacenter_tcp:1;
	bool disable_packed:1;
	bool rocev2_rto_policy:1;
	bool en_rem_endpoint_trk:1;
	enum irdma_protocol_used protocol_used;
};

struct irdma_sc_aeq {
	u32 size;
	u64 aeq_elem_pa;
	struct irdma_sc_dev *dev;
	struct irdma_sc_aeqe *aeqe_base;
	void *pbl_list;
	u32 elem_cnt;
	struct irdma_ring aeq_ring;
	u8 pbl_chunk_size;
	u32 first_pm_pbl_idx;
	u32 msix_idx;
	u8 polarity;
	bool virtual_map:1;
	bool pasid_valid:1;
	u32 pasid;
};

struct irdma_sc_ceq {
	u32 size;
	u64 ceq_elem_pa;
	struct irdma_sc_dev *dev;
	struct irdma_ceqe *ceqe_base;
	void *pbl_list;
	u32 ceq_id;
	u32 elem_cnt;
	struct irdma_ring ceq_ring;
	u8 pbl_chunk_size;
	u8 tph_val;
	u32 first_pm_pbl_idx;
	u8 polarity;
	struct irdma_sc_vsi *vsi;
	struct irdma_sc_cq **reg_cq;
	u32 reg_cq_size;
	spinlock_t req_cq_lock; /* protect access to reg_cq array */
	bool virtual_map:1;
	bool tph_en:1;
	bool itr_no_expire:1;
	bool pasid_valid:1;
	u32 pasid;
};

struct irdma_sc_cq {
	struct irdma_cq_uk cq_uk;
	u64 cq_pa;
	u64 shadow_area_pa;
	struct irdma_sc_dev *dev;
	struct irdma_sc_vsi *vsi;
	void *pbl_list;
	void *back_cq;
	u32 ceq_id;
	u32 shadow_read_threshold;
	u8 pbl_chunk_size;
	u8 cq_type;
	u8 tph_val;
	u32 first_pm_pbl_idx;
	bool ceqe_mask:1;
	bool virtual_map:1;
	bool check_overflow:1;
	bool ceq_id_valid:1;
	bool tph_en:1;
	bool pasid_valid:1;
	u32 pasid;
};

struct irdma_sc_qp {
	struct irdma_qp_uk qp_uk;
	u64 sq_pa;
	u64 rq_pa;
	u64 hw_host_ctx_pa;
	u64 shadow_area_pa;
	u64 q2_pa;
	struct irdma_sc_dev *dev;
	struct irdma_sc_vsi *vsi;
	struct irdma_sc_pd *pd;
	__le64 *hw_host_ctx;
	void *llp_stream_handle;
	struct irdma_pfpdu pfpdu;
	u32 ieq_qp;
	u8 *q2_buf;
	u64 qp_compl_ctx;
	u32 push_idx;
	u16 qs_handle;
	u16 push_offset;
	u8 flush_wqes_count;
	u8 sq_tph_val;
	u8 rq_tph_val;
	u8 qp_state;
	u8 hw_sq_size;
	u8 hw_rq_size;
	u8 src_mac_addr_idx;
	u8 qs_idx;
	bool suspended:1;
	bool on_qoslist:1;
	bool ieq_pass_thru:1;
	bool sq_tph_en:1;
	bool rq_tph_en:1;
	bool rcv_tph_en:1;
	bool xmit_tph_en:1;
	bool virtual_map:1;
	bool flush_sq:1;
	bool flush_rq:1;
	bool err_sq_idx_valid:1;
	bool err_rq_idx_valid:1;
	bool pasid_valid:1;
	u32 pasid;
	u32 pkt_limit;
	u32 err_sq_idx;
	u32 err_rq_idx;
	bool sq_flush_code:1;
	bool rq_flush_code:1;
	enum irdma_flush_opcode flush_code;
	enum irdma_qp_event_type event_type;
	u8 term_flags;
	u8 user_pri;
	struct list_head list;
};

struct irdma_stats_inst_info {
	u16 hmc_fn_id;
	u16 stats_idx;
	bool use_hmc_fcn_index:1;
};

struct irdma_up_info {
	u8 map[8];
	u8 cnp_up_override;
	u16 hmc_fcn_idx;
	bool use_vlan:1;
	bool use_cnp_up_override:1;
};

#define IRDMA_MAX_WS_NODES      0x3FF
#define IRDMA_WS_NODE_INVALID	0xFFFF

struct irdma_ws_move_node_info {
	u16 node_id[16];
	u8 num_nodes;
	u8 target_port;
	bool resume_traffic:1;
};

struct irdma_ws_node_info {
	u16 id;
	u16 vsi;
	u16 parent_id;
	u16 qs_handle;
	bool type_leaf:1;
	bool enable:1;
	u8 prio_type;
	u8 tc;
	u8 weight;
};

struct irdma_hmc_fpm_misc {
	u32 max_ceqs;
	u32 max_sds;
	u32 loc_mem_pages;
	u8 ird;
	u32 xf_block_size;
	u32 q1_block_size;
	u32 ht_multiplier;
	u32 timer_bucket;
	u32 rrf_block_size;
	u32 ooiscf_block_size;
};

struct irdma_vchnl_if {
	int (*vchnl_recv)(struct irdma_sc_dev *dev, u16 vf_id, u8 *msg,
			  u16 len);
};

#define IRDMA_VCHNL_MAX_MSG_SIZE 512
#define IRDMA_LEAF_DEFAULT_REL_BW		64
#define IRDMA_PARENT_DEFAULT_REL_BW		1

struct irdma_qos {
	struct list_head qplist;
	struct mutex qos_mutex; /* protect QoS attributes per QoS level */
	u32 l2_sched_node_id;
	u16 qs_handle[IRDMA_MAX_QSETS];
	u8 qs_cnt;
	u8 qs_nxt_idx;
	u8 traffic_class;
	u8 rel_bw;
	u8 prio_type;
	bool valid:1;
};

struct irdma_config_check {
	bool config_ok:1;
	bool lfc_set:1;
	bool pfc_set:1;
	u8 traffic_class;
	u8 prio;
	u16 qs_handle;
};

struct irdma_vchnl_dev {
	struct irdma_sc_dev *pf_dev;
	struct irdma_sc_vsi *vf_vsi; /* Default VSI */
	u8 *hmc_info_mem;
	u8 vchnl_msg_buf[IRDMA_VCHNL_MAX_MSG_SIZE];
	struct irdma_hmc_info hmc_info;
	struct irdma_hmc_fpm_misc hmc_fpm_misc;
	u64 fpm_query_buf_pa;
	u64 *fpm_query_buf;
	refcount_t refcnt;
	u16 pmf_index;
	u16 vf_id;
	u16 iw_vf_idx;
	u8 protocol_used;
	bool stats_initialized:1;
	bool pf_hmc_initialized:1;
	bool reset_en:1;
	bool port_vlan_en:1;
	bool multi_qset_enabled:1;
};

#define IRDMA_INVALID_STATS_IDX 0xff
struct irdma_sc_vsi {
	u16 vsi_idx;
	struct irdma_sc_dev *dev;
	struct irdma_vchnl_dev *vc_dev;
	void *back_vsi;
	u32 ilq_count;
	struct irdma_virt_mem ilq_mem;
	struct irdma_puda_rsrc *ilq;
	u32 ieq_count;
	struct irdma_virt_mem ieq_mem;
	struct irdma_puda_rsrc *ieq;
	u32 exception_lan_q;
	u16 mtu;
	u16 vf_id;
	enum irdma_vm_vf_type vm_vf_type;
	bool stats_inst_alloc:1;
	bool tc_change_pending:1;
	bool mtu_change_pending:1;
	struct irdma_vsi_pestat *pestat;
	atomic_t qp_suspend_reqs;
	int (*register_qset)(struct irdma_sc_vsi *vsi,
			     struct irdma_ws_node *tc_node);
	void (*unregister_qset)(struct irdma_sc_vsi *vsi,
				struct irdma_ws_node *tc_node);
	struct irdma_config_check cfg_check[IRDMA_MAX_USER_PRIORITY];
	bool tc_print_warning[IEEE_8021QAZ_MAX_TCS];
	u8 qos_rel_bw;
	u8 qos_prio_type;
	u16 stats_idx;
	u8 dscp_map[IRDMA_DSCP_NUM_VAL];
	struct irdma_qos qos[IRDMA_MAX_USER_PRIORITY];
	u64 hw_stats_regs[IRDMA_HW_STAT_INDEX_MAX_GEN_1];
	bool dscp_mode:1;
};

struct irdma_sc_dev {
	struct list_head cqp_cmd_head; /* head of the CQP command list */
	spinlock_t cqp_lock; /* protect CQP list access */
	bool stats_idx_array[IRDMA_MAX_STATS_COUNT_GEN1];
	struct irdma_dma_mem vf_fpm_query_buf[IRDMA_MAX_PE_ENA_VF_COUNT];
	u64 fpm_query_buf_pa;
	u64 fpm_commit_buf_pa;
	__le64 *fpm_query_buf;
	__le64 *fpm_commit_buf;
	struct irdma_hw *hw;
	u8 __iomem *db_addr;
	u32 __iomem *wqe_alloc_db;
	u32 __iomem *cq_arm_db;
	u32 __iomem *aeq_alloc_db;
	u32 __iomem *cqp_db;
	u32 __iomem *cq_ack_db;
	u32 __iomem *hw_regs[IRDMA_MAX_REGS];
	u32 ceq_itr;   /* Interrupt throttle, usecs between interrupts: 0 disabled. 2 - 8160 */
	u64 hw_masks[IRDMA_MAX_MASKS];
	u8 hw_shifts[IRDMA_MAX_SHIFTS];
	const struct irdma_hw_stat_map *hw_stats_map;
	u64 hw_stats_regs[IRDMA_HW_STAT_INDEX_MAX_GEN_1];
	u64 hw_stats_vf_regs[IRDMA_HW_STAT_INDEX_MAX_GEN_1];
	u64 feature_info[IRDMA_MAX_FEATURES];
	u64 cqp_cmd_stats[IRDMA_MAX_CQP_OPS];
	struct irdma_hw_attrs hw_attrs;
	struct irdma_hmc_info *hmc_info;
	struct irdma_vchnl_if *vchnl_if;
	struct irdma_vchnl_rdma_caps vc_caps;
	u8 vc_recv_buf[IRDMA_VCHNL_MAX_MSG_SIZE];
	u16 vc_recv_len;
	struct irdma_vchnl_dev *vc_dev[IRDMA_MAX_PE_ENA_VF_COUNT];
	spinlock_t vc_dev_lock;  /* sync vchnl_dev usage with async events like reset */
	struct workqueue_struct *vchnl_wq;
	struct irdma_sc_cqp *cqp;
	struct irdma_sc_aeq *aeq;
	struct irdma_sc_ceq *ceq[IRDMA_CEQ_MAX_COUNT];
	struct irdma_sc_cq *ccq;
	const struct irdma_irq_ops *irq_ops;
	u8 qos_dist_mode;
	struct irdma_qos qos[IRDMA_MAX_USER_PRIORITY];
	struct irdma_hmc_fpm_misc hmc_fpm_misc;
	struct irdma_ws_node *ws_tree_root;
	struct mutex ws_mutex; /* ws tree mutex */
	u32 vchnl_ver;
	u16 num_vfs;
	u16 hmc_fn_id;
	u16 vf_id;
	bool privileged:1;
	bool vchnl_up:1;
	bool ceq_valid:1;
	bool is_pf:1;
	bool double_vlan_en:1;
	bool multi_qs_enabled:1;
	u8 protocol_used;
	u64 hw_wa;	// Will have bit values for hw work arounds
	u32 wa_mem_pages;
	u8 rrf_multiplier;
	u8 xf_multiplier;
	u8 min_ird;
	bool host_mem_mrte:1;
	struct mutex vchnl_mutex;
	int (*ws_add)(struct irdma_sc_vsi *vsi, u8 user_pri);
	void (*ws_remove)(struct irdma_sc_vsi *vsi, u8 user_pri);
	void (*ws_reset)(struct irdma_sc_vsi *vsi);
};

struct irdma_modify_cq_info {
	u64 cq_pa;
	struct irdma_cqe *cq_base;
	u32 cq_size;
	u32 shadow_read_threshold;
	u8 pbl_chunk_size;
	u32 first_pm_pbl_idx;
	bool virtual_map:1;
	bool check_overflow:1;
	bool cq_resize:1;
};

struct irdma_srq_init_info {
	struct irdma_sc_pd *pd;
	struct irdma_sc_vsi *vsi;
	u64 srq_pa;
	u64 shadow_area_pa;
	u32 first_pm_pbl_idx;
	u32 pasid;
	u32 srq_size;
	u16 srq_limit;
	u8 pasid_valid;
	u8 wqe_size;
	u8 leaf_pbl_size;
	u8 virtual_map;
	u8 tph_en;
	u8 arm_limit_event;
	u8 tph_value;
	u8 pbl_chunk_size;
	struct irdma_srq_uk_init_info srq_uk_init_info;
};

struct irdma_sc_srq {
	struct irdma_sc_dev *dev;
	struct irdma_sc_vsi *vsi;
	struct irdma_sc_pd *pd;
	struct irdma_srq_uk srq_uk;
	void *back_srq;
	u64 srq_pa;
	u64 shadow_area_pa;
	u32 first_pm_pbl_idx;
	u32 pasid;
	u32 hw_srq_size;
	u16 srq_limit;
	u8 pasid_valid;
	u8 leaf_pbl_size;
	u8 virtual_map;
	u8 tph_en;
	u8 arm_limit_event;
	u8 tph_val;
};

struct irdma_modify_srq_info {
	u16 srq_limit;
	u8 arm_limit_event;
};

struct irdma_set_interrupt_info {
	u32 hmc_fcn_id;
	u32 ceq_agent_interrupt_index;
	u32 ceq_id;
	u32 aeq_agent_interrupt_index;
	u8 use_hmc_fcn_id;
	u8 set_ceq_int;
	u8 set_aeq_int;
	u8 enable_int;
};

struct irdma_ret_cqp_cmpl_info {
	u64 cqe_values[4];
	u32 hmc_fcn_id;
	u32 rqe_idx;
	u8 pending;
};

struct irdma_rca_exec_fwd_op_info {
	u64 wqe[8];
	u64 buf_addr;
	u64 scratch;
	u32 rqe_idx;
	u16 orig_hmc_fcn_id;
	u16 orig_wq_desc_idx;
	u16 deferred_info;
	u16 op_code;
	bool pending:1;
};

struct irdma_copy_data_info {
	struct irdma_rca_exec_fwd_op_info fwd_op_info;
	u64 src_addr;
	u64 dst_addr;
	u16 hmc_fcn_id;
	u16 length;
};

struct irdma_create_qp_info {
	bool ord_valid:1;
	bool tcp_ctx_valid:1;
	bool cq_num_valid:1;
	bool arp_cache_idx_valid:1;
	bool mac_valid:1;
	bool force_lpb:1;
	u8 next_iwarp_state;
};

struct irdma_modify_qp_info {
	u64 rx_win0;
	u64 rx_win1;
	u16 new_mss;
	u8 next_iwarp_state;
	u8 curr_iwarp_state;
	u8 termlen;
	bool ord_valid:1;
	bool tcp_ctx_valid:1;
	bool udp_ctx_valid:1;
	bool cq_num_valid:1;
	bool arp_cache_idx_valid:1;
	bool reset_tcp_conn:1;
	bool remove_hash_idx:1;
	bool dont_send_term:1;
	bool dont_send_fin:1;
	bool cached_var_valid:1;
	bool mss_change:1;
	bool force_lpb:1;
	bool mac_valid:1;
};

struct irdma_ccq_cqe_info {
	struct irdma_sc_cqp *cqp;
	u64 scratch;
	u32 op_ret_val;
	u32 rqe_idx;
	u16 orig_hmc_fcn_id;
	u16 orig_wq_desc_idx;
	u16 maj_err_code;
	u16 min_err_code;
	u8 op_code;
	bool error:1;
	bool pending:1;
	bool sq:1;
};

struct irdma_qos_tc_info {
	u64 tc_ctx;
	u8 rel_bw;
	u8 prio_type;
	u8 egress_virt_up;
	u8 ingress_virt_up;
};

struct irdma_l2params {
	struct irdma_qos_tc_info tc_info[IRDMA_MAX_USER_PRIORITY];
	u32 num_apps;
	u16 qs_handle_list[IRDMA_MAX_USER_PRIORITY];
	u16 mtu;
	u8 up2tc[IRDMA_MAX_USER_PRIORITY];
	u8 dscp_map[IRDMA_DSCP_NUM_VAL];
	u8 num_tc;
	u8 vsi_rel_bw;
	u8 vsi_prio_type;
	bool mtu_changed:1;
	bool tc_changed:1;
	bool dscp_mode:1;
};

struct irdma_vsi_init_info {
	struct irdma_sc_dev *dev;
	void *back_vsi;
	struct irdma_l2params *params;
	u16 exception_lan_q;
	u16 pf_data_vsi_num;
	enum irdma_vm_vf_type vm_vf_type;
	int (*register_qset)(struct irdma_sc_vsi *vsi,
			     struct irdma_ws_node *tc_node);
	void (*unregister_qset)(struct irdma_sc_vsi *vsi,
				struct irdma_ws_node *tc_node);
};

struct irdma_vsi_stats_info {
	struct irdma_vsi_pestat *pestat;
	u8 fcn_id;
	bool alloc_stats_inst:1;
};

struct irdma_device_init_info {
	u64 fpm_query_buf_pa;
	u64 fpm_commit_buf_pa;
	__le64 *fpm_query_buf;
	__le64 *fpm_commit_buf;
	struct irdma_hw *hw;
	void __iomem *bar0;
	enum irdma_protocol_used protocol_used;
	u16 max_vfs;
	u16 hmc_fn_id;
};

struct irdma_ceq_init_info {
	u64 ceqe_pa;
	struct irdma_sc_dev *dev;
	u64 *ceqe_base;
	void *pbl_list;
	u32 elem_cnt;
	u32 ceq_id;
	bool virtual_map:1;
	bool tph_en:1;
	bool itr_no_expire:1;
	u8 pbl_chunk_size;
	u8 tph_val;
	u32 first_pm_pbl_idx;
	struct irdma_sc_vsi *vsi;
	struct irdma_sc_cq **reg_cq;
};

struct irdma_aeq_init_info {
	u64 aeq_elem_pa;
	struct irdma_sc_dev *dev;
	u32 *aeqe_base;
	void *pbl_list;
	u32 elem_cnt;
	bool virtual_map:1;
	u8 pbl_chunk_size;
	u32 first_pm_pbl_idx;
	u32 msix_idx;
};

struct irdma_ccq_init_info {
	u64 cq_pa;
	u64 shadow_area_pa;
	struct irdma_sc_dev *dev;
	struct irdma_cqe *cq_base;
	__le64 *shadow_area;
	void *pbl_list;
	u32 num_elem;
	u32 ceq_id;
	u32 shadow_read_threshold;
	bool ceqe_mask:1;
	bool ceq_id_valid:1;
	bool avoid_mem_cflct:1;
	bool virtual_map:1;
	bool tph_en:1;
	u8 tph_val;
	u8 pbl_chunk_size;
	u32 first_pm_pbl_idx;
	struct irdma_sc_vsi *vsi;
};

struct irdma_udp_offload_info {
	bool ipv4:1;
	bool insert_vlan_tag:1;
	u8 ttl;
	u8 tos;
	u16 src_port;
	u16 dst_port;
	u32 dest_ip_addr[4];
	u32 snd_mss;
	u16 vlan_tag;
	u16 arp_idx;
	u32 flow_label;
	u8 udp_state;
	u32 psn_nxt;
	u32 lsn;
	u32 epsn;
	u32 psn_max;
	u32 psn_una;
	u32 local_ipaddr[4];
	u32 cwnd;
	u8 rexmit_thresh;
	u8 rnr_nak_thresh;
	u8 rnr_nak_tmr;
	u8 min_rnr_timer;
};

struct irdma_roce_offload_info {
	u64 rca_key[2];
	u16 p_key;
	u32 err_rq_idx;
	u32 qkey;
	u32 dest_qp;
	u8 roce_tver;
	u8 ack_credits;
	u8 err_rq_idx_valid;
	u32 pd_id;
	u16 ord_size;
	u16 ird_size;
	bool is_qp1:1;
	bool udprivcq_en:1;
	bool dcqcn_en:1;
	bool rcv_no_icrc:1;
	bool wr_rdresp_en:1;
	bool bind_en:1;
	bool flush_mr:1;
	bool fast_reg_en:1;
	bool priv_mode_en:1;
	bool rd_en:1;
	bool timely_en:1;
	bool dctcp_en:1;
	bool fw_cc_enable:1;
	bool use_stats_inst:1;
	u8 local_ack_timeout;
	u8 rca_config;
	u16 t_high;
	u16 t_low;
	u8 last_byte_sent;
	u8 mac_addr[ETH_ALEN];
	u8 rtomin;
};

struct irdma_iwarp_offload_info {
	u16 rcv_mark_offset;
	u16 snd_mark_offset;
	u8 ddp_ver;
	u8 rdmap_ver;
	u8 iwarp_mode;
	u32 err_rq_idx;
	u32 pd_id;
	u16 ord_size;
	u16 ird_size;
	bool ib_rd_en:1;
	bool align_hdrs:1;
	bool rcv_no_mpa_crc:1;
	bool err_rq_idx_valid:1;
	bool snd_mark_en:1;
	bool rcv_mark_en:1;
	bool wr_rdresp_en:1;
	bool fast_reg_en:1;
	bool priv_mode_en:1;
	bool rd_en:1;
	bool timely_en:1;
	bool use_stats_inst:1;
	bool ecn_en:1;
	bool dctcp_en:1;
	u16 t_high;
	u16 t_low;
	u8 last_byte_sent;
	u8 mac_addr[ETH_ALEN];
	u8 rtomin;
};

struct irdma_tcp_offload_info {
	bool ipv4:1;
	bool no_nagle:1;
	bool insert_vlan_tag:1;
	bool time_stamp:1;
	bool drop_ooo_seg:1;
	bool avoid_stretch_ack:1;
	bool wscale:1;
	bool ignore_tcp_opt:1;
	bool ignore_tcp_uns_opt:1;
	u8 cwnd_inc_limit;
	u8 dup_ack_thresh;
	u8 ttl;
	u8 src_mac_addr_idx;
	u8 tos;
	u16 src_port;
	u16 dst_port;
	u32 dest_ip_addr[4];
	//u32 dest_ip_addr0;
	//u32 dest_ip_addr1;
	//u32 dest_ip_addr2;
	//u32 dest_ip_addr3;
	u32 snd_mss;
	u16 syn_rst_handling;
	u16 vlan_tag;
	u16 arp_idx;
	u32 flow_label;
	u8 tcp_state;
	u8 snd_wscale;
	u8 rcv_wscale;
	u32 time_stamp_recent;
	u32 time_stamp_age;
	u32 snd_nxt;
	u32 snd_wnd;
	u32 rcv_nxt;
	u32 rcv_wnd;
	u32 snd_max;
	u32 snd_una;
	u32 srtt;
	u32 rtt_var;
	u32 ss_thresh;
	u32 cwnd;
	u32 snd_wl1;
	u32 snd_wl2;
	u32 max_snd_window;
	u8 rexmit_thresh;
	u32 local_ipaddr[4];
};

struct irdma_qp_host_ctx_info {
	u64 qp_compl_ctx;
	union {
		struct irdma_tcp_offload_info *tcp_info;
		struct irdma_udp_offload_info *udp_info;
	};
	union {
		struct irdma_iwarp_offload_info *iwarp_info;
		struct irdma_roce_offload_info *roce_info;
	};
	u32 send_cq_num;
	u32 rcv_cq_num;
	u32 srq_id;
	u32 rem_endpoint_idx;
	u16 stats_idx;
	bool remote_atomics_en:1;
	bool srq_valid:1;
	bool tcp_info_valid:1;
	bool iwarp_info_valid:1;
	bool stats_idx_valid:1;
	u8 user_pri;
};

struct irdma_aeqe_info {
	u64 compl_ctx;
	u32 qp_cq_id;
	u32 wqe_idx;
	u32 def_info;	/* only valid for DEF_CMPL */
	u16 ae_id;
	u8 tcp_state;
	u8 iwarp_state;
	bool qp:1;
	bool cq:1;
	bool sq:1;
	bool rq:1;
	bool srq:1;
	bool in_rdrsp_wr:1;
	bool out_rdrsp:1;
	bool aeqe_overflow:1;
	/* This flag is used to determine if we should pass the rq tail
	 * in the QP context for FW/HW. It is set when ae_src is rq for GEN1/GEN2
	 * And additionally set for inbound atomic, read and write for GEN3
	 */
	bool err_rq_idx_valid:1;
	u8 q2_data_written;
	u8 ae_src;
};

struct irdma_allocate_stag_info {
	u64 total_len;
	u64 first_pm_pbl_idx;
	u32 chunk_size;
	u32 stag_idx;
	u32 page_size;
	u32 pd_id;
	u16 access_rights;
	bool remote_access:1;
	bool use_hmc_fcn_index:1;
	bool all_memory:1;
	bool remote_atomics_en:1;
	bool non_cached:1;
	u8 placement_type;
	u16 hmc_fcn_index;
};

struct irdma_mw_alloc_info {
	u32 mw_stag_index;
	u32 page_size;
	u32 pd_id;
	bool remote_access:1;
	bool mw_wide:1;
	bool mw1_bind_dont_vldt_key:1;
	u8 remote_atomics_en;
};

struct irdma_reg_ns_stag_info {
	u64 reg_addr_pa;
	u64 va;
	u64 total_len;
	u32 page_size;
	u32 chunk_size;
	u32 first_pm_pbl_index;
	enum irdma_addressing_type addr_type;
	irdma_stag_index stag_idx;
	u16 access_rights;
	u32 pd_id;
	irdma_stag_key stag_key;
	bool use_hmc_fcn_index:1;
	u16 hmc_fcn_index;
	bool all_memory:1;
	bool pasid_valid:1;
	u8 remote_atomics_en;
	u32 pasid;
	bool non_cached:1;
	u8 placement_type;
};

struct irdma_fast_reg_stag_info {
	u64 wr_id;
	u64 reg_addr_pa;
	u64 fbo;
	void *va;
	u64 total_len;
	u32 page_size;
	u32 chunk_size;
	u32 first_pm_pbl_index;
	enum irdma_addressing_type addr_type;
	irdma_stag_index stag_idx;
	u16 access_rights;
	u32 pd_id;
	irdma_stag_key stag_key;
	bool local_fence:1;
	bool read_fence:1;
	bool signaled:1;
	bool push_wqe:1;
	bool use_hmc_fcn_index:1;
	u16 hmc_fcn_index;
	bool defer_flag:1;
	bool remote_atomics_en:1;
};

struct irdma_dealloc_stag_info {
	u32 stag_idx;
	u32 pd_id;
	bool mr:1;
	bool dealloc_pbl:1;
};

struct irdma_register_shared_stag {
	u64 va;
	enum irdma_addressing_type addr_type;
	irdma_stag_index new_stag_idx;
	irdma_stag_index parent_stag_idx;
	u32 access_rights;
	u32 pd_id;
	u32 page_size;
	irdma_stag_key new_stag_key;
	u8 remote_atomics_en;
};

struct irdma_qp_init_info {
	struct irdma_qp_uk_init_info qp_uk_init_info;
	struct irdma_sc_pd *pd;
	struct irdma_sc_vsi *vsi;
	__le64 *host_ctx;
	u8 *q2;
	u64 sq_pa;
	u64 rq_pa;
	u64 host_ctx_pa;
	u64 q2_pa;
	u64 shadow_area_pa;
	u8 sq_tph_val;
	u8 rq_tph_val;
	bool sq_tph_en:1;
	bool rq_tph_en:1;
	bool rcv_tph_en:1;
	bool xmit_tph_en:1;
	bool virtual_map:1;
};

struct irdma_sc_rdma_sys_stats_info {
	struct irdma_dma_mem stats_buf;
	u16 hmc_fcn_ids[16];
	enum irdma_sys_stats_type stats_type;
	u8 sub_type;
	u8 vf_cnt;
	bool local_fence:1;
};

struct irdma_cq_init_info {
	struct irdma_sc_dev *dev;
	u64 cq_base_pa;
	u64 shadow_area_pa;
	u32 ceq_id;
	u32 shadow_read_threshold;
	u8 pbl_chunk_size;
	u32 first_pm_pbl_idx;
	bool virtual_map:1;
	bool ceqe_mask:1;
	bool ceq_id_valid:1;
	bool tph_en:1;
	bool pasid_valid:1;
	u32 pasid;
	u8 tph_val;
	u8 type;
	struct irdma_cq_uk_init_info cq_uk_init_info;
	struct irdma_sc_vsi *vsi;
};

struct irdma_upload_context_info {
	u64 buf_pa;
	u32 qp_id;
	u16 hmc_fcn_id;
	u8 qp_type;
	bool freeze_qp:1;
	bool raw_format:1;
	bool use_hmc_fcn_id:1;
};

struct irdma_local_mac_entry_info {
	u8 mac_addr[6];
	u16 entry_idx;
};

struct irdma_add_arp_cache_entry_info {
	u8 mac_addr[ETH_ALEN];
	u32 reach_max;
	u16 arp_index;
	bool permanent:1;
};

struct irdma_apbvt_info {
	u16 port;
	bool add:1;
};

struct irdma_qhash_table_info {
	struct irdma_sc_vsi *vsi;
	enum irdma_quad_hash_manage_type manage;
	enum irdma_quad_entry_type entry_type;
	bool vlan_valid:1;
	bool ipv4_valid:1;
	u8 mac_addr[ETH_ALEN];
	u16 vlan_id;
	u8 user_pri;
	u32 qp_num;
	u32 dest_ip[4];
	u32 src_ip[4];
	u16 dest_port;
	u16 src_port;
};

struct irdma_cqp_manage_push_page_info {
	u32 push_idx;
	u16 qs_handle;
	u16 hmc_fn_id;
	u8 free_page;
	u8 push_page_type;
	u8 page_type;
	u8 use_hmc_fn_id;
};

struct irdma_qp_flush_info {
	u32 err_sq_idx;
	u32 err_rq_idx;
	u16 sq_minor_code;
	u16 sq_major_code;
	u16 rq_minor_code;
	u16 rq_major_code;
	u16 ae_code;
	u8 ae_src;
	bool sq:1;
	bool rq:1;
	bool userflushcode:1;
	bool generate_ae:1;
	bool err_sq_idx_valid:1;
	bool err_rq_idx_valid:1;
};

struct irdma_gen_ae_info {
	u16 ae_code;
	u8 ae_src;
};

struct irdma_cqp_timeout {
	u64 compl_cqp_cmds;
	u32 count;
};

struct irdma_irq_ops {
	void (*irdma_cfg_aeq)(struct irdma_sc_dev *dev, u32 idx, bool enable);
	void (*irdma_cfg_ceq)(struct irdma_sc_dev *dev, u32 ceq_id, u32 idx,
			      bool enable);
	void (*irdma_dis_irq)(struct irdma_sc_dev *dev, u32 idx);
	void (*irdma_en_irq)(struct irdma_sc_dev *dev, u32 idx);
};

void irdma_sc_ccq_arm(struct irdma_sc_cq *ccq);
int irdma_sc_ccq_create(struct irdma_sc_cq *ccq, u64 scratch,
			bool check_overflow, bool post_sq);
int irdma_sc_ccq_destroy(struct irdma_sc_cq *ccq, u64 scratch, bool post_sq);
int irdma_sc_ccq_get_cqe_info(struct irdma_sc_cq *ccq,
			      struct irdma_ccq_cqe_info *info);
int irdma_sc_ccq_init(struct irdma_sc_cq *ccq,
		      struct irdma_ccq_init_info *info);

int irdma_sc_cceq_create(struct irdma_sc_ceq *ceq);
int irdma_sc_cceq_destroy_done(struct irdma_sc_ceq *ceq);

int irdma_sc_ceq_destroy(struct irdma_sc_ceq *ceq, u64 scratch, bool post_sq);
int irdma_sc_ceq_init(struct irdma_sc_ceq *ceq,
		      struct irdma_ceq_init_info *info);
void irdma_sc_cleanup_ceqes(struct irdma_sc_cq *cq, struct irdma_sc_ceq *ceq);
void *irdma_sc_process_ceq(struct irdma_sc_dev *dev, struct irdma_sc_ceq *ceq);

int irdma_sc_aeq_init(struct irdma_sc_aeq *aeq,
		      struct irdma_aeq_init_info *info);
int irdma_sc_get_next_aeqe(struct irdma_sc_aeq *aeq,
			   struct irdma_aeqe_info *info);
void irdma_sc_repost_aeq_entries(struct irdma_sc_dev *dev, u32 count);

void irdma_sc_pd_init(struct irdma_sc_dev *dev, struct irdma_sc_pd *pd, u32 pd_id,
		      int abi_ver);
void irdma_cfg_aeq(struct irdma_sc_dev *dev, u32 idx, bool enable);
#if IS_ENABLED(CONFIG_CONFIGFS_FS)
void irdma_set_irq_rate_limit(struct irdma_sc_dev *dev, u32 idx, u32 interval);
#endif
void irdma_check_cqp_progress(struct irdma_cqp_timeout *cqp_timeout,
			      struct irdma_sc_dev *dev);
void irdma_sc_cqp_def_cmpl_ae_handler(struct irdma_sc_dev *dev,
				      struct irdma_aeqe_info *info,
				      bool first, u64 *scratch,
				      u32 *sw_def_info);
u64 irdma_sc_cqp_cleanup_handler(struct irdma_sc_dev *dev);
int irdma_sc_cqp_create(struct irdma_sc_cqp *cqp, u16 *maj_err, u16 *min_err);
int irdma_sc_cqp_destroy(struct irdma_sc_cqp *cqp, bool free_hwcqp);
int irdma_sc_cqp_init(struct irdma_sc_cqp *cqp,
		      struct irdma_cqp_init_info *info);
int irdma_sc_cqp_post_rq(struct irdma_sc_cqp *cqp, u64 scratch);
void irdma_sc_cqp_post_rqes(struct irdma_sc_cqp *cqp);
void irdma_sc_cqp_post_sq(struct irdma_sc_cqp *cqp);
int irdma_sc_poll_for_cqp_op_done(struct irdma_sc_cqp *cqp, u8 opcode,
				  struct irdma_ccq_cqe_info *cmpl_info);
int irdma_sc_qp_create(struct irdma_sc_qp *qp,
		       struct irdma_create_qp_info *info, u64 scratch,
		       bool post_sq);
int irdma_sc_qp_destroy(struct irdma_sc_qp *qp, u64 scratch,
			bool remove_hash_idx, bool ignore_mw_bnd, bool post_sq);
int irdma_sc_qp_flush_wqes(struct irdma_sc_qp *qp,
			   struct irdma_qp_flush_info *info, u64 scratch,
			   bool post_sq);
int irdma_sc_qp_init(struct irdma_sc_qp *qp, struct irdma_qp_init_info *info);
int irdma_sc_qp_modify(struct irdma_sc_qp *qp,
		       struct irdma_modify_qp_info *info, u64 scratch,
		       bool post_sq);
void irdma_sc_send_lsmm(struct irdma_sc_qp *qp, void *lsmm_buf, u32 size,
			irdma_stag stag);
void irdma_sc_send_rtt(struct irdma_sc_qp *qp, bool read);
void irdma_sc_qp_setctx(struct irdma_sc_qp *qp, __le64 *qp_ctx,
			struct irdma_qp_host_ctx_info *info);
void irdma_sc_qp_setctx_roce(struct irdma_sc_qp *qp, __le64 *qp_ctx,
			     struct irdma_qp_host_ctx_info *info);
int irdma_sc_cq_destroy(struct irdma_sc_cq *cq, u64 scratch, bool post_sq);
int irdma_sc_cq_init(struct irdma_sc_cq *cq, struct irdma_cq_init_info *info);
void irdma_sc_cq_resize(struct irdma_sc_cq *cq, struct irdma_modify_cq_info *info);
int irdma_sc_aeq_destroy(struct irdma_sc_aeq *aeq, u64 scratch, bool post_sq);
int irdma_sc_static_hmc_pages_allocated(struct irdma_sc_cqp *cqp, u64 scratch,
					u16 hmc_fn_id, bool post_sq,
					bool poll_registers);
int irdma_sc_srq_init(struct irdma_sc_srq *srq,
		      struct irdma_srq_init_info *info);
int irdma_sc_cqp_nop(struct irdma_sc_cqp *cqp, u64 scratch, bool post_sq);

void sc_vsi_update_stats(struct irdma_sc_vsi *vsi);
struct cqp_info {
	union {
		struct {
			struct irdma_sc_qp *qp;
			struct irdma_create_qp_info info;
			u64 scratch;
		} qp_create;

		struct {
			struct irdma_sc_qp *qp;
			struct irdma_modify_qp_info info;
			u64 scratch;
		} qp_modify;

		struct {
			struct irdma_sc_qp *qp;
			u64 scratch;
			bool remove_hash_idx;
			bool ignore_mw_bnd;
		} qp_destroy;

		struct {
			struct irdma_sc_cq *cq;
			u64 scratch;
			bool check_overflow;
		} cq_create;

		struct {
			struct irdma_sc_cq *cq;
			struct irdma_modify_cq_info info;
			u64 scratch;
		} cq_modify;

		struct {
			struct irdma_sc_cq *cq;
			u64 scratch;
		} cq_destroy;

		struct {
			struct irdma_sc_dev *dev;
			struct irdma_allocate_stag_info info;
			u64 scratch;
		} alloc_stag;

		struct {
			struct irdma_sc_dev *dev;
			struct irdma_mw_alloc_info info;
			u64 scratch;
		} mw_alloc;

		struct {
			struct irdma_sc_dev *dev;
			struct irdma_reg_ns_stag_info info;
			u64 scratch;
		} mr_reg_non_shared;

		struct {
			struct irdma_sc_dev *dev;
			struct irdma_dealloc_stag_info info;
			u64 scratch;
		} dealloc_stag;

		struct {
			struct irdma_sc_cqp *cqp;
			struct irdma_add_arp_cache_entry_info info;
			u64 scratch;
		} add_arp_cache_entry;

		struct {
			struct irdma_sc_cqp *cqp;
			u64 scratch;
			u16 arp_index;
		} del_arp_cache_entry;

		struct {
			struct irdma_sc_cqp *cqp;
			struct irdma_local_mac_entry_info info;
			u64 scratch;
		} add_local_mac_entry;

		struct {
			struct irdma_sc_cqp *cqp;
			u64 scratch;
			u8 entry_idx;
			u8 ignore_ref_count;
		} del_local_mac_entry;

		struct {
			struct irdma_sc_cqp *cqp;
			u64 scratch;
		} alloc_local_mac_entry;

		struct {
			struct irdma_sc_cqp *cqp;
			struct irdma_manage_pble_info info;
			u64 scratch;
		} manage_pble_bp;

		struct {
			struct irdma_sc_cqp *cqp;
			struct irdma_cqp_manage_push_page_info info;
			u64 scratch;
		} manage_push_page;

		struct {
			struct irdma_sc_dev *dev;
			struct irdma_upload_context_info info;
			u64 scratch;
		} qp_upload_context;

		struct {
			struct irdma_sc_dev *dev;
			struct irdma_hmc_fcn_info info;
			u64 scratch;
		} manage_hmc_pm;

		struct {
			struct irdma_sc_ceq *ceq;
			u64 scratch;
		} ceq_create;

		struct {
			struct irdma_sc_ceq *ceq;
			u64 scratch;
		} ceq_destroy;

		struct {
			struct irdma_sc_aeq *aeq;
			u64 scratch;
		} aeq_create;

		struct {
			struct irdma_sc_aeq *aeq;
			u64 scratch;
		} aeq_destroy;

		struct {
			struct irdma_sc_qp *qp;
			struct irdma_qp_flush_info info;
			u64 scratch;
		} qp_flush_wqes;

		struct {
			struct irdma_sc_qp *qp;
			struct irdma_gen_ae_info info;
			u64 scratch;
		} gen_ae;

		struct {
			struct irdma_sc_cqp *cqp;
			void *fpm_val_va;
			u64 fpm_val_pa;
			u16 hmc_fn_id;
			u64 scratch;
		} query_fpm_val;

		struct {
			struct irdma_sc_cqp *cqp;
			void *fpm_val_va;
			u64 fpm_val_pa;
			u16 hmc_fn_id;
			u64 scratch;
		} commit_fpm_val;

		struct {
			struct irdma_sc_cqp *cqp;
			struct irdma_apbvt_info info;
			u64 scratch;
		} manage_apbvt_entry;

		struct {
			struct irdma_sc_cqp *cqp;
			struct irdma_qhash_table_info info;
			u64 scratch;
		} manage_qhash_table_entry;

		struct {
			struct irdma_sc_dev *dev;
			struct irdma_update_sds_info info;
			u64 scratch;
		} update_pe_sds;

		struct {
			struct irdma_sc_cqp *cqp;
			struct irdma_sc_qp *qp;
			u64 scratch;
		} suspend_resume;

		struct {
			struct irdma_sc_cqp *cqp;
			struct irdma_ah_info info;
			u64 scratch;
		} ah_create;

		struct {
			struct irdma_sc_cqp *cqp;
			struct irdma_ah_info info;
			u64 scratch;
		} ah_destroy;

		struct {
			struct irdma_sc_cqp *cqp;
			struct irdma_ah_info info;
			u64 scratch;
		} ah_modify;

		struct {
			struct irdma_sc_cqp *cqp;
			struct irdma_mcast_grp_info info;
			u64 scratch;
		} mc_create;

		struct {
			struct irdma_sc_cqp *cqp;
			struct irdma_mcast_grp_info info;
			u64 scratch;
		} mc_destroy;

		struct {
			struct irdma_sc_cqp *cqp;
			struct irdma_mcast_grp_info info;
			u64 scratch;
		} mc_modify;

		struct {
			struct irdma_sc_cqp *cqp;
			struct irdma_stats_inst_info info;
			u64 scratch;
		} stats_manage;

		struct {
			struct irdma_sc_cqp *cqp;
			struct irdma_stats_gather_info info;
			u64 scratch;
		} stats_gather;

		struct {
			struct irdma_sc_cqp *cqp;
			struct irdma_ws_node_info info;
			u64 scratch;
		} ws_node;

		struct {
			struct irdma_sc_cqp *cqp;
			struct irdma_ws_move_node_info info;
			u64 scratch;
		} ws_move_node;

		struct {
			struct irdma_sc_cqp *cqp;
			struct irdma_up_info info;
			u64 scratch;
		} up_map;

		struct {
			struct irdma_sc_cqp *cqp;
			struct irdma_dma_mem query_buff_mem;
			u64 scratch;
		} query_rdma;

		struct {
			struct irdma_sc_cqp *cqp;
			struct irdma_sc_rdma_sys_stats_info info;
			u64 scratch;
		} gather_rdma_system_stats;

		struct {
			struct irdma_sc_srq *srq;
			u64 scratch;
		} srq_create;

		struct {
			struct irdma_sc_srq *srq;
			struct irdma_modify_srq_info info;
			u64 scratch;
		} srq_modify;

		struct {
			struct irdma_sc_srq *srq;
			u64 scratch;
		} srq_destroy;

		struct {
			struct irdma_sc_cqp *cqp;
			struct irdma_rca_exec_fwd_op_info info;
			u64 scratch;
		} rca_exec_fwd_op;

		struct {
			struct irdma_sc_cqp *cqp;
			struct irdma_ret_cqp_cmpl_info info;
			u64 scratch;
		} ret_cqp_cmpl;

		struct {
			struct irdma_sc_cqp *cqp;
			struct irdma_copy_data_info info;
			u64 scratch;
		} copy_data;

		struct {
			struct irdma_sc_cqp *cqp;
			u64 scratch;
		} nop;

	} u;
};

struct cqp_cmds_info {
	struct list_head cqp_cmd_entry;
	u8 cqp_cmd;
	u8 post_sq;
	struct cqp_info in;
	int cqp_cmd_exec_status;
	bool create;
};

struct irdma_vchnl_work {
	struct work_struct work;
	u8 vf_msg_buf[IRDMA_VCHNL_MAX_MSG_SIZE];
	struct irdma_sc_dev *dev;
	u16 vf_id;
	u16 len;
};

__le64 *irdma_sc_cqp_get_next_send_wqe_idx(struct irdma_sc_cqp *cqp, u64 scratch,
					   u32 *wqe_idx);

/**
 * irdma_sc_cqp_get_next_send_wqe - get next wqe on cqp sq
 * @cqp: struct for cqp hw
 * @scratch: private data for CQP WQE
 */
static inline __le64 *irdma_sc_cqp_get_next_send_wqe(struct irdma_sc_cqp *cqp, u64 scratch)
{
	u32 wqe_idx;

	return irdma_sc_cqp_get_next_send_wqe_idx(cqp, scratch, &wqe_idx);
}
#endif /* IRDMA_TYPE_H */
