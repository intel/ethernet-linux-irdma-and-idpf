/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2015 - 2024 Intel Corporation */
#ifndef IRDMA_VERBS_H
#define IRDMA_VERBS_H

#define IRDMA_MAX_SAVED_PHY_PGADDR	4
#define IRDMA_FLUSH_DELAY_MS		20

#define IRDMA_PKEY_TBL_SZ		1
#define IRDMA_DEFAULT_PKEY		0xFFFF

#define IRDMA_QPS_PER_PUSH_PAGE 16
#define IRDMA_PUSH_WIN_SIZE 256

#define IRDMA_SHADOW_PGCNT		1

#define iwdev_to_idev(iwdev)	(&(iwdev)->rf->sc_dev)

struct irdma_ucontext {
	struct ib_ucontext ibucontext;
	struct irdma_device *iwdev;
#ifdef RDMA_MMAP_DB_SUPPORT
	struct rdma_user_mmap_entry *db_mmap_entry;
#else
	struct irdma_user_mmap_entry *db_mmap_entry;
	DECLARE_HASHTABLE(mmap_hash_tbl, 6);
	spinlock_t mmap_tbl_lock; /* protect mmap hash table entries */
#endif
	struct list_head cq_reg_mem_list;
	spinlock_t cq_reg_mem_list_lock; /* protect CQ memory list */
	struct list_head qp_reg_mem_list;
	spinlock_t qp_reg_mem_list_lock; /* protect QP memory list */
	struct list_head srq_reg_mem_list;
	spinlock_t srq_reg_mem_list_lock; /* protect SRQ memory list */
#ifdef CONFIG_DEBUG_FS
	struct list_head uctx_list;
#endif
	/* FIXME: Move to kcompat ideally. Used < 4.20.0 for old diassasscoaite flow */
	struct list_head vma_list;
	struct mutex vma_list_mutex; /* protect the vma_list */
	int abi_ver;
	bool legacy_mode:1;
	bool use_raw_attrs:1;
};

struct irdma_hw_push_page {
	DECLARE_BITMAP(push_offset_bmap, IRDMA_QPS_PER_PUSH_PAGE);
	u32 push_idx;
};

struct irdma_qs_push_pages {
	u16 qs_handle;
	struct irdma_hw_push_page push_page[IRDMA_MAX_PUSH_PAGES_QSET];
};

struct irdma_pd {
	struct ib_pd ibpd;
	struct irdma_sc_pd sc_pd;
	struct mutex push_alloc_mutex; /* protect push page alloc within a PD*/
	struct irdma_qs_push_pages qs_pages[IRDMA_MAX_QSETS];
};

union irdma_sockaddr {
	struct sockaddr_in saddr_in;
	struct sockaddr_in6 saddr_in6;
};

struct irdma_av {
	u8 macaddr[16];
	struct rdma_ah_attr attrs;
	union irdma_sockaddr sgid_addr;
	union irdma_sockaddr dgid_addr;
	u8 net_type;
};

struct irdma_ah {
	struct ib_ah ibah;
	struct irdma_sc_ah sc_ah;
	struct irdma_pd *pd;
	struct irdma_av av;
	u8 sgid_index;
	union ib_gid dgid;
	struct hlist_node list;
	refcount_t refcnt;
	struct irdma_ah *parent_ah;	/* AH from cached list */
	bool sleep;
};

struct irdma_hmc_pble {
	union {
		u32 idx;
		dma_addr_t addr;
	};
};

struct irdma_cq_mr {
	struct irdma_hmc_pble cq_pbl;
	dma_addr_t shadow;
	bool split;
};

struct irdma_srq_mr {
	struct irdma_hmc_pble srq_pbl;
	dma_addr_t shadow;
};

struct irdma_qp_mr {
	struct irdma_hmc_pble sq_pbl;
	struct irdma_hmc_pble rq_pbl;
	dma_addr_t shadow;
	dma_addr_t rq_pa;
	struct page *sq_page;
};

struct irdma_cq_buf {
	struct irdma_dma_mem kmem_buf;
	struct irdma_cq_uk cq_uk;
	struct irdma_hw *hw;
	struct list_head list;
	struct work_struct work;
};

struct irdma_pbl {
	struct list_head list;
	union {
		struct irdma_qp_mr qp_mr;
		struct irdma_cq_mr cq_mr;
		struct irdma_srq_mr srq_mr;
	};

	bool pbl_allocated:1;
	bool on_list:1;
	u64 user_base;
	struct irdma_pble_alloc pble_alloc;
	struct irdma_mr *iwmr;
};

struct irdma_mr {
	union {
		struct ib_mr ibmr;
		struct ib_mw ibmw;
	};
	struct ib_umem *region;
	int access;
	u8 is_hwreg;
	u16 type;
	bool dma_mr:1;
	u32 page_cnt;
	u64 page_size;
	u64 page_msk;
	u32 npages;
	u32 stag;
	u64 len;
	u64 pgaddrmem[IRDMA_MAX_SAVED_PHY_PGADDR];
#ifdef CONFIG_DEBUG_FS
	u64 level0_pa;
#endif
	struct irdma_pbl iwpbl;
};

struct irdma_srq {
	struct ib_srq ibsrq;
	struct irdma_sc_srq sc_srq __aligned(64);
	struct irdma_dma_mem kmem;
	struct completion free_srq;
	u64 *srq_wrid_mem;
	refcount_t refcnt;
	spinlock_t lock; /* for poll srq */
	struct irdma_pbl *iwpbl;
	struct ib_sge *sg_list;
	u16 srq_head;
	u32 srq_num;
	u32 max_wr;
	bool user_mode:1;
};

struct irdma_cq {
	struct ib_cq ibcq;
	struct irdma_sc_cq sc_cq;
	u16 cq_head;
	u16 cq_size;
	u16 cq_num;
	bool user_mode;
	atomic_t armed;
	enum irdma_cmpl_notify last_notify;
	u32 polled_cmpls;
	u32 cq_mem_size;
	struct irdma_dma_mem kmem;
	struct irdma_dma_mem kmem_shadow;
	struct completion free_cq;
	refcount_t refcnt;
	spinlock_t lock; /* for poll cq */
	struct irdma_pbl *iwpbl;
	struct irdma_pbl *iwpbl_shadow;
	struct list_head resize_list;
	struct irdma_cq_poll_info cur_cqe;
	struct list_head cmpl_generated;
};

struct irdma_cmpl_gen {
	struct list_head list;
	struct irdma_cq_poll_info cpi;
};

struct disconn_work {
	struct work_struct work;
	struct irdma_qp *iwqp;
};

struct if_notify_work {
	struct work_struct work;
	struct irdma_device *iwdev;
	u32 ipaddr[4];
	u16 vlan_id;
	bool ipv4:1;
	bool ifup:1;
};

struct iw_cm_id;

struct irdma_qp_kmode {
	struct irdma_dma_mem dma_mem;
	struct irdma_sq_uk_wr_trk_info *sq_wrid_mem;
	u64 *rq_wrid_mem;
};

struct irdma_qp {
	struct ib_qp ibqp;
	struct irdma_sc_qp sc_qp;
	struct irdma_device *iwdev;
	struct irdma_cq *iwscq;
	struct irdma_cq *iwrcq;
	struct irdma_pd *iwpd;
#ifdef RDMA_MMAP_DB_SUPPORT
	struct rdma_user_mmap_entry *push_wqe_mmap_entry;
	struct rdma_user_mmap_entry *push_db_mmap_entry;
#else
	struct irdma_user_mmap_entry *push_wqe_mmap_entry;
	struct irdma_user_mmap_entry *push_db_mmap_entry;
#endif
	struct irdma_qp_host_ctx_info ctx_info;
	union {
		struct irdma_iwarp_offload_info iwarp_info;
		struct irdma_roce_offload_info roce_info;
	};

	union {
		struct irdma_tcp_offload_info tcp_info;
		struct irdma_udp_offload_info udp_info;
	};

	struct irdma_ah roce_ah;
	struct list_head teardown_entry;
	refcount_t refcnt;
	struct iw_cm_id *cm_id;
	struct irdma_cm_node *cm_node;
	struct delayed_work dwork_flush;
	struct ib_mr *lsmm_mr;
	atomic_t hw_mod_qp_pend;
	enum ib_qp_state ibqp_state;
	u32 qp_mem_size;
	u32 last_aeq;
	int max_send_wr;
	int max_recv_wr;
	atomic_t close_timer_started;
	spinlock_t lock; /* serialize posting WRs to SQ/RQ */
	struct irdma_qp_context *iwqp_context;
	void *pbl_vbase;
	dma_addr_t pbl_pbase;
	struct page *page;
	u8 iwarp_state;
	atomic_t flush_issued;
	u16 term_sq_flush_code;
	u16 term_rq_flush_code;
	u8 hw_iwarp_state;
	u8 hw_tcp_state;
	u8 ae_src;
	struct irdma_qp_kmode kqp;
	struct irdma_dma_mem host_ctx;
	struct timer_list terminate_timer;
	struct irdma_pbl *iwpbl;
	struct ib_sge *sg_list;
	struct irdma_dma_mem q2_ctx_mem;
	struct irdma_dma_mem ietf_mem;
	struct completion free_qp;
	wait_queue_head_t waitq;
	wait_queue_head_t mod_qp_waitq;
	u8 rts_ae_rcvd;
	struct irdma_mr *iwmr;
	bool active_conn:1;
	bool user_mode:1;
	bool hte_added:1;
	bool sig_all:1;
	bool pau_mode:1;
	bool suspend_pending:1;
};

enum irdma_mmap_flag {
	IRDMA_MMAP_IO_NC,
	IRDMA_MMAP_IO_WC,
};

struct irdma_user_mmap_entry {
#ifdef RDMA_MMAP_DB_SUPPORT
	struct rdma_user_mmap_entry rdma_entry;
#else
	struct irdma_ucontext *ucontext;
	struct hlist_node hlist;
	u64 pgoff_key; /* Used to compute offset (in bytes) returned to user libc's mmap */
#endif
	u64 bar_offset;
	u8 mmap_flag;
};

#define CRT_RDMA_HEADER 256

/* Adding CRT specific extensions for CRT protocol family.
 **/
enum crt_mtu {
	CRT_MTU_256  = 1,
	CRT_MTU_512  = 2,
	CRT_MTU_1024 = 3,
	CRT_MTU_2048 = 4,
	CRT_MTU_4096 = 5,
	CRT_MTU_8192 = 6
};

static inline int crt_mtu_enum_to_int(enum crt_mtu mtu)
{
	switch (mtu) {
	case CRT_MTU_256:  return  256;
	case CRT_MTU_512:  return  512;
	case CRT_MTU_1024: return 1024;
	case CRT_MTU_2048: return 2048;
	case CRT_MTU_4096: return 4096;
	case CRT_MTU_8192: return 8192;
	default:	   return -1;
	}
}

static inline enum crt_mtu crt_iboe_get_mtu(int mtu)
{
	/*
	 * Reduce Falcon headers from effective MTU.
	 **/
	mtu = mtu - CRT_RDMA_HEADER;

	if (mtu >= crt_mtu_enum_to_int(CRT_MTU_8192))
		return CRT_MTU_8192;
	else if (mtu >= crt_mtu_enum_to_int(CRT_MTU_4096))
		return CRT_MTU_4096;
	else if (mtu >= crt_mtu_enum_to_int(CRT_MTU_2048))
		return CRT_MTU_2048;
	else if (mtu >= crt_mtu_enum_to_int(CRT_MTU_1024))
		return CRT_MTU_1024;
	else if (mtu >= crt_mtu_enum_to_int(CRT_MTU_512))
		return CRT_MTU_512;
	else if (mtu >= crt_mtu_enum_to_int(CRT_MTU_256))
		return CRT_MTU_256;
	else
		return 0;
}

static inline u16 irdma_fw_major_ver(struct irdma_sc_dev *dev)
{
	return (u16)FIELD_GET(IRDMA_FW_VER_MAJOR, dev->feature_info[IRDMA_FEATURE_FW_INFO]);
}

static inline u16 irdma_fw_minor_ver(struct irdma_sc_dev *dev)
{
	return (u16)FIELD_GET(IRDMA_FW_VER_MINOR, dev->feature_info[IRDMA_FEATURE_FW_INFO]);
}

static inline void set_ib_wc_op_sq(struct irdma_cq_poll_info *cq_poll_info,
				   struct ib_wc *entry)
{
	struct irdma_sc_qp *qp;

	switch (cq_poll_info->op_type) {
	case IRDMA_OP_TYPE_RDMA_WRITE:
	case IRDMA_OP_TYPE_RDMA_WRITE_SOL:
		entry->opcode = IB_WC_RDMA_WRITE;
		break;
	case IRDMA_OP_TYPE_RDMA_READ_INV_STAG:
	case IRDMA_OP_TYPE_RDMA_READ:
		entry->opcode = IB_WC_RDMA_READ;
		break;
	case IRDMA_OP_TYPE_SEND_SOL:
	case IRDMA_OP_TYPE_SEND_SOL_INV:
	case IRDMA_OP_TYPE_SEND_INV:
	case IRDMA_OP_TYPE_SEND:
		entry->opcode = IB_WC_SEND;
		break;
	case IRDMA_OP_TYPE_FAST_REG_NSMR:
		entry->opcode = IB_WC_REG_MR;
		break;
	case IRDMA_OP_TYPE_ATOMIC_COMPARE_AND_SWAP:
		entry->opcode = IB_WC_COMP_SWAP;
		break;
	case IRDMA_OP_TYPE_ATOMIC_FETCH_AND_ADD:
		entry->opcode = IB_WC_FETCH_ADD;
		break;
	case IRDMA_OP_TYPE_INV_STAG:
		entry->opcode = IB_WC_LOCAL_INV;
		break;
	default:
		qp = cq_poll_info->qp_handle;
		ibdev_err(to_ibdev(qp->dev), "Invalid opcode = %d in CQE\n",
			  cq_poll_info->op_type);
		entry->status = IB_WC_GENERAL_ERR;
	}
}

static inline void set_ib_wc_op_rq_gen_3(struct irdma_cq_poll_info *cq_poll_info,
					 struct ib_wc *entry)
{
	switch (cq_poll_info->op_type) {
	case IRDMA_OP_TYPE_RDMA_WRITE:
	case IRDMA_OP_TYPE_RDMA_WRITE_SOL:
		entry->opcode = IB_WC_RECV_RDMA_WITH_IMM;
		break;
	default:
		entry->opcode = IB_WC_RECV;
	}
}

static inline void set_ib_wc_op_rq(struct irdma_cq_poll_info *cq_poll_info,
				   struct ib_wc *entry, bool send_imm_support)
{
	/**
	 * iWARP does not support sendImm, so the presence of Imm data
	 * must be WriteImm.
	 */
	if (!send_imm_support) {
		entry->opcode = cq_poll_info->imm_valid ?
				IB_WC_RECV_RDMA_WITH_IMM :
				IB_WC_RECV;
		return;
	}
	switch (cq_poll_info->op_type) {
	case IB_OPCODE_RDMA_WRITE_ONLY_WITH_IMMEDIATE:
	case IB_OPCODE_RDMA_WRITE_LAST_WITH_IMMEDIATE:
		entry->opcode = IB_WC_RECV_RDMA_WITH_IMM;
		break;
	default:
		entry->opcode = IB_WC_RECV;
	}
}

/**
 * irdma_mcast_mac_v4 - Get the multicast MAC for an IP address
 * @ip_addr: IPv4 address
 * @mac: pointer to result MAC address
 *
 */
static inline void irdma_mcast_mac_v4(u32 *ip_addr, u8 *mac)
{
	u8 *ip = (u8 *)ip_addr;
	unsigned char mac4[ETH_ALEN] = {0x01, 0x00, 0x5E, ip[2] & 0x7F, ip[1],
					ip[0]};

	ether_addr_copy(mac, mac4);
}

/**
 * irdma_mcast_mac_v6 - Get the multicast MAC for an IP address
 * @ip_addr: IPv6 address
 * @mac: pointer to result MAC address
 *
 */
static inline void irdma_mcast_mac_v6(u32 *ip_addr, u8 *mac)
{
	u8 *ip = (u8 *)ip_addr;
	unsigned char mac6[ETH_ALEN] = {0x33, 0x33, ip[3], ip[2], ip[1], ip[0]};

	ether_addr_copy(mac, mac6);
}

#ifdef ALLOC_HW_STATS_STRUCT_V2
extern const struct rdma_stat_desc irdma_hw_stat_descs[];

#endif /* ALLOC_HW_STATS_STRUCT_V2 */
#ifdef RDMA_MMAP_DB_SUPPORT
struct rdma_user_mmap_entry*
irdma_user_mmap_entry_insert(struct irdma_ucontext *ucontext, u64 bar_offset,
			     enum irdma_mmap_flag mmap_flag, u64 *mmap_offset);
#else
struct irdma_user_mmap_entry *
irdma_user_mmap_entry_add_hash(struct irdma_ucontext *ucontext, u64 bar_offset,
			       enum irdma_mmap_flag mmap_flag, u64 *mmap_offset);
void irdma_user_mmap_entry_del_hash(struct irdma_user_mmap_entry *entry);
#endif /* RDMA_MMAP_DB_SUPPORT */
#ifndef SET_BEST_PAGE_SZ_V1
struct irdma_mr *irdma_alloc_iwmr(struct ib_umem *region,
				  struct ib_pd *pd, u64 virt,
				  enum irdma_memreg_type reg_type);
#else
struct irdma_mr *irdma_alloc_iwmr(struct ib_umem *region,
				  struct ib_pd *pd, u64 virt, u64 start,
				  enum irdma_memreg_type reg_type);
#endif /* !SET_BEST_PAGE_SZ_V1 */
void irdma_free_iwmr(struct irdma_mr *iwmr);
int irdma_reg_user_mr_type_mem(struct irdma_mr *iwmr, int access,
			       bool create_stag);
int irdma_ib_register_device(struct irdma_device *iwdev);
void irdma_ib_unregister_device(struct irdma_device *iwdev);
void irdma_ib_qp_event(struct irdma_qp *iwqp, enum irdma_qp_event_type event);
void irdma_generate_flush_completions(struct irdma_qp *iwqp);
void irdma_remove_cmpls_list(struct irdma_cq *iwcq);
int irdma_generated_cmpls(struct irdma_cq *iwcq, struct irdma_cq_poll_info *cq_poll_info);
void irdma_sched_qp_flush_work(struct irdma_qp *iwqp);
void irdma_flush_worker(struct work_struct *work);
struct ib_mr *wa_reg_phys_mr(struct ib_pd *pd);
int irdma_hw_alloc_mw(struct irdma_device *iwdev, struct irdma_mr *iwmr);
#endif /* IRDMA_VERBS_H */
