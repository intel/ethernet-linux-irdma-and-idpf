// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2015 - 2025 Intel Corporation */
#include "main.h"

/**
 * irdma_query_device - get device attributes
 * @ibdev: device pointer from stack
 * @props: returning device attributes
 * @udata: user data
 */
static int irdma_query_device(struct ib_device *ibdev,
			      struct ib_device_attr *props,
			      struct ib_udata *udata)
{
	struct irdma_device *iwdev = to_iwdev(ibdev);
	struct irdma_pci_f *rf = iwdev->rf;
	struct pci_dev *pcidev = iwdev->rf->pcidev;
	struct irdma_hw_attrs *hw_attrs = &rf->sc_dev.hw_attrs;

	if (udata->inlen || udata->outlen)
		return -EINVAL;

	memset(props, 0, sizeof(*props));
	addrconf_addr_eui48((u8 *)&props->sys_image_guid,
			    iwdev->netdev->dev_addr);
	props->fw_ver = (u64)irdma_fw_major_ver(&rf->sc_dev) << 32 |
			irdma_fw_minor_ver(&rf->sc_dev);
	props->device_cap_flags = IB_DEVICE_MEM_WINDOW |
				  IB_DEVICE_MEM_MGT_EXTENSIONS;
	props->vendor_id = pcidev->vendor;
	props->vendor_part_id = pcidev->device;
	props->hw_ver = pcidev->revision;
	props->page_size_cap = hw_attrs->page_size_cap;
	props->max_mr_size = hw_attrs->max_mr_size;
	props->max_qp = rf->max_qp - rf->used_qps;
	props->max_qp_wr = hw_attrs->max_qp_wr;
	set_max_sge(props, rf);
	props->max_cq = rf->max_cq - rf->used_cqs;
	props->max_cqe = rf->max_cqe - 1;
	props->max_mr = rf->max_mr - rf->used_mrs;
	if (hw_attrs->uk_attrs.hw_rev >= IRDMA_GEN_3)
		props->max_mw = props->max_mr;
	props->max_pd = rf->max_pd - rf->used_pds;
	props->max_sge_rd = hw_attrs->uk_attrs.max_hw_read_sges;
	props->max_qp_rd_atom = hw_attrs->max_hw_ird;
	props->max_qp_init_rd_atom = hw_attrs->max_hw_ord;
	if (rdma_protocol_roce(ibdev, 1)) {
		props->device_cap_flags |= IB_DEVICE_RC_RNR_NAK_GEN;
		props->max_pkeys = IRDMA_PKEY_TBL_SZ;
		props->max_ah = rf->max_ah;
		if (hw_attrs->uk_attrs.hw_rev == IRDMA_GEN_2) {
			props->max_mcast_grp = rf->max_mcg;
			props->max_mcast_qp_attach = IRDMA_MAX_MGS_PER_CTX;
			props->max_total_mcast_qp_attach = rf->max_qp * IRDMA_MAX_MGS_PER_CTX;
		}
	}
	props->max_fast_reg_page_list_len = IRDMA_MAX_PAGES_PER_FMR;
	props->max_srq = rf->max_srq - rf->used_srqs;
	props->max_srq_wr = IRDMA_MAX_SRQ_WRS;
	props->max_srq_sge = hw_attrs->uk_attrs.max_hw_wq_frags;
	if (hw_attrs->uk_attrs.feature_flags & IRDMA_FEATURE_ATOMIC_OPS)
		props->atomic_cap = IB_ATOMIC_HCA;
	else
		props->atomic_cap = IB_ATOMIC_NONE;
	props->masked_atomic_cap = props->atomic_cap;
	if (hw_attrs->uk_attrs.hw_rev >= IRDMA_GEN_3) {
#define HCA_CORE_CLOCK_KHZ 1000000UL
		props->timestamp_mask = GENMASK(31, 0);
		props->hca_core_clock = HCA_CORE_CLOCK_KHZ;
	}
	if (hw_attrs->uk_attrs.hw_rev >= IRDMA_GEN_2)
		props->device_cap_flags |= IB_DEVICE_MEM_WINDOW_TYPE_2B;

	return 0;
}

static int irdma_mmap_legacy(struct irdma_ucontext *ucontext,
			     struct vm_area_struct *vma)
{
	u64 pfn;

	if (vma->vm_pgoff || vma->vm_end - vma->vm_start != PAGE_SIZE)
		return -EINVAL;

	vma->vm_private_data = ucontext;
	pfn = ((uintptr_t)ucontext->iwdev->rf->sc_dev.hw_regs[IRDMA_DB_ADDR_OFFSET] +
	       pci_resource_start(ucontext->iwdev->rf->pcidev, 0)) >> PAGE_SHIFT;

#ifdef RDMA_MMAP_DB_SUPPORT
	return rdma_user_mmap_io(&ucontext->ibucontext, vma, pfn, PAGE_SIZE,
				 pgprot_noncached(vma->vm_page_prot), NULL);
#else
	return rdma_user_mmap_io(&ucontext->ibucontext, vma, pfn, PAGE_SIZE,
				 pgprot_noncached(vma->vm_page_prot));
#endif
}

#ifdef RDMA_MMAP_DB_SUPPORT
static void irdma_mmap_free(struct rdma_user_mmap_entry *rdma_entry)
{
	struct irdma_user_mmap_entry *entry = to_irdma_mmap_entry(rdma_entry);

	kfree(entry);
}

struct rdma_user_mmap_entry*
irdma_user_mmap_entry_insert(struct irdma_ucontext *ucontext, u64 bar_offset,
			     enum irdma_mmap_flag mmap_flag, u64 *mmap_offset)
{
	struct irdma_user_mmap_entry *entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	int ret;

	if (!entry)
		return NULL;

	entry->bar_offset = bar_offset;
	entry->mmap_flag = mmap_flag;

	ret = rdma_user_mmap_entry_insert(&ucontext->ibucontext,
					  &entry->rdma_entry, PAGE_SIZE);
	if (ret) {
		kfree(entry);
		return NULL;
	}
	*mmap_offset = rdma_user_mmap_get_offset(&entry->rdma_entry);

	return &entry->rdma_entry;
}

#else /* RDMA_MMAP_DB_SUPPORT */
static inline bool find_key_in_mmap_tbl(struct irdma_ucontext *ucontext, u64 key)
{
	struct irdma_user_mmap_entry *entry;

	hash_for_each_possible(ucontext->mmap_hash_tbl, entry, hlist, key) {
		if (entry->pgoff_key == key)
			return true;
	}

	return false;
}

struct irdma_user_mmap_entry *
irdma_user_mmap_entry_add_hash(struct irdma_ucontext *ucontext, u64 bar_offset,
			       enum irdma_mmap_flag mmap_flag, u64 *mmap_offset)
{
	struct irdma_user_mmap_entry *entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	unsigned long flags;
	int retry_cnt = 0;

	if (!entry)
		return NULL;

	entry->bar_offset = bar_offset;
	entry->mmap_flag = mmap_flag;
	entry->ucontext = ucontext;
	do {
		get_random_bytes(&entry->pgoff_key, sizeof(entry->pgoff_key));

		/* The key is a page offset */
		entry->pgoff_key >>= PAGE_SHIFT;

		/*In the event of a collision in the hash table, retry a new key */
		spin_lock_irqsave(&ucontext->mmap_tbl_lock, flags);
		if (!find_key_in_mmap_tbl(ucontext, entry->pgoff_key)) {
			hash_add(ucontext->mmap_hash_tbl, &entry->hlist, entry->pgoff_key);
			spin_unlock_irqrestore(&ucontext->mmap_tbl_lock, flags);
			goto hash_add_done;
		}
		spin_unlock_irqrestore(&ucontext->mmap_tbl_lock, flags);
	} while (retry_cnt++ < 10);

	ibdev_dbg(&ucontext->iwdev->ibdev,
		  "VERBS: mmap table add failed: Cannot find a unique key\n");
	kfree(entry);
	return NULL;

hash_add_done:
	/*libc mmap uses a byte offset */
	*mmap_offset = entry->pgoff_key << PAGE_SHIFT;

	return entry;
}

static struct irdma_user_mmap_entry *irdma_find_user_mmap_entry(struct irdma_ucontext *ucontext,
								struct vm_area_struct *vma)
{
	struct irdma_user_mmap_entry *entry;
	unsigned long flags;

	if (vma->vm_end - vma->vm_start != PAGE_SIZE)
		return NULL;

	spin_lock_irqsave(&ucontext->mmap_tbl_lock, flags);
	hash_for_each_possible(ucontext->mmap_hash_tbl, entry, hlist, vma->vm_pgoff) {
		if (entry->pgoff_key == vma->vm_pgoff) {
			spin_unlock_irqrestore(&ucontext->mmap_tbl_lock, flags);
			return entry;
		}
	}

	spin_unlock_irqrestore(&ucontext->mmap_tbl_lock, flags);

	return NULL;
}

void irdma_user_mmap_entry_del_hash(struct irdma_user_mmap_entry *entry)
{
	struct irdma_ucontext *ucontext;
	unsigned long flags;

	if (!entry)
		return;

	ucontext = entry->ucontext;

	spin_lock_irqsave(&ucontext->mmap_tbl_lock, flags);
	hash_del(&entry->hlist);
	spin_unlock_irqrestore(&ucontext->mmap_tbl_lock, flags);

	kfree(entry);
}

#endif /* RDMA_MMAP_DB_SUPPORT */
/**
 * irdma_mmap - user memory map
 * @context: context created during alloc
 * @vma: kernel info for user memory map
 */
static int irdma_mmap(struct ib_ucontext *context, struct vm_area_struct *vma)
{
#ifdef RDMA_MMAP_DB_SUPPORT
	struct rdma_user_mmap_entry *rdma_entry;
#endif
	struct irdma_user_mmap_entry *entry;
	struct irdma_ucontext *ucontext;
	u64 pfn;
	int ret;

	ucontext = to_ucontext(context);

	/* Legacy support for libi40iw with hard-coded mmap key */
	if (ucontext->legacy_mode)
		return irdma_mmap_legacy(ucontext, vma);

#ifdef RDMA_MMAP_DB_SUPPORT
	rdma_entry = rdma_user_mmap_entry_get(&ucontext->ibucontext, vma);
	if (!rdma_entry) {
		ibdev_dbg(&ucontext->iwdev->ibdev,
			  "VERBS: pgoff[0x%lx] does not have valid entry\n",
			  vma->vm_pgoff);
		return -EINVAL;
	}

	entry = to_irdma_mmap_entry(rdma_entry);
#else
	entry = irdma_find_user_mmap_entry(ucontext, vma);
	if (!entry) {
		ibdev_dbg(&ucontext->iwdev->ibdev,
			  "VERBS: pgoff[0x%lx] does not have valid entry\n",
			  vma->vm_pgoff);
		return -EINVAL;
	}
#endif
	ibdev_dbg(&ucontext->iwdev->ibdev,
		  "VERBS: bar_offset [0x%llx] mmap_flag [%d]\n",
		  entry->bar_offset, entry->mmap_flag);

	pfn = (entry->bar_offset +
	      pci_resource_start(ucontext->iwdev->rf->pcidev, 0)) >> PAGE_SHIFT;

	switch (entry->mmap_flag) {
	case IRDMA_MMAP_IO_NC:
#ifdef RDMA_MMAP_DB_SUPPORT
		ret = rdma_user_mmap_io(context, vma, pfn, PAGE_SIZE,
					pgprot_noncached(vma->vm_page_prot),
					rdma_entry);
#else
		ret = rdma_user_mmap_io(context, vma, pfn, PAGE_SIZE,
					pgprot_noncached(vma->vm_page_prot));
#endif
		break;
	case IRDMA_MMAP_IO_WC:
#ifdef RDMA_MMAP_DB_SUPPORT
		ret = rdma_user_mmap_io(context, vma, pfn, PAGE_SIZE,
					pgprot_writecombine(vma->vm_page_prot),
					rdma_entry);
#else
		ret = rdma_user_mmap_io(context, vma, pfn, PAGE_SIZE,
					pgprot_writecombine(vma->vm_page_prot));
#endif
		break;
	default:
		ret = -EINVAL;
	}

	if (ret)
		ibdev_dbg(&ucontext->iwdev->ibdev,
			  "VERBS: bar_offset [0x%llx] mmap_flag[%d] err[%d]\n",
			  entry->bar_offset, entry->mmap_flag, ret);
#ifdef RDMA_MMAP_DB_SUPPORT
	rdma_user_mmap_entry_put(rdma_entry);
#endif

	return ret;
}

/**
 * irdma_push_page_avail - return if push page exists
 * @iwqp: qp ptr (user or kernel)
 * @hw_page: push page of protection domain
 */
static bool irdma_push_page_avail(struct irdma_qp *iwqp, struct irdma_hw_push_page *hw_page)
{
	struct irdma_sc_qp *qp = &iwqp->sc_qp;
	u16 push_pos = 0;

	if (hw_page->push_idx != IRDMA_INVALID_PUSH_PAGE_INDEX) {
		push_pos = find_first_zero_bit(hw_page->push_offset_bmap,
				IRDMA_QPS_PER_PUSH_PAGE);

		if (push_pos < IRDMA_QPS_PER_PUSH_PAGE) {
			qp->push_idx = hw_page->push_idx;
			qp->push_offset = push_pos * IRDMA_PUSH_WIN_SIZE;
			__set_bit(push_pos, hw_page->push_offset_bmap);

			return true;
		}
	}

	return false;
}

/**
 * irdma_get_push_page - request for new push page
 * @iwqp: qp ptr (user or kernel)
 * @hw_page: push page of protection domain
 */
static void irdma_get_push_page(struct irdma_qp *iwqp,  struct irdma_hw_push_page *hw_page)
{
	struct irdma_device *iwdev = iwqp->iwdev;
	struct irdma_sc_qp *qp = &iwqp->sc_qp;
	u32 pg_idx;
	int status;

	status = irdma_vchnl_req_manage_push_pg(&iwdev->rf->sc_dev, true,
			qp->qs_handle, &pg_idx);

	if (!status && pg_idx != IRDMA_INVALID_PUSH_PAGE_INDEX) {
		hw_page->push_idx = pg_idx;
		qp->push_idx = pg_idx;
		qp->push_offset = 0;
		__set_bit(0, hw_page->push_offset_bmap);
	}
}

/**
 * irdma_alloc_push_page_3 - allocate or use a push page for qp
 * @iwqp: qp ptr (user or kernel)
 */
static void irdma_alloc_push_page_3(struct irdma_qp *iwqp)
{
	struct irdma_qs_push_pages *qs_pages = NULL;
	struct irdma_sc_qp *qp = &iwqp->sc_qp;
	struct irdma_pd *pd = iwqp->iwpd;
	u16 qs_handle = qp->qs_handle;
	bool found;
	int i;

	mutex_lock(&pd->push_alloc_mutex);

	for (i = 0; i < IRDMA_MAX_QSETS; i++)
		if (pd->qs_pages[i].qs_handle == qs_handle) {
			qs_pages = &pd->qs_pages[i];
			break;
		}

	if (!qs_pages) {
		ibdev_dbg(&iwqp->iwdev->ibdev, "ERROR: iwpd not initialized\n");
		goto exit;
	}

	for (i = 0; i < IRDMA_MAX_PUSH_PAGES_QSET; i++) {
		found  = irdma_push_page_avail(iwqp, &qs_pages->push_page[i]);
		if (found)
			goto exit;
		if (qs_pages->push_page[i].push_idx == IRDMA_INVALID_PUSH_PAGE_INDEX) {
			irdma_get_push_page(iwqp, &qs_pages->push_page[i]);
			goto exit;
		}
	}
exit:
	mutex_unlock(&pd->push_alloc_mutex);
}

/**
 * irdma_alloc_push_page - allocate a push page for qp
 * @iwqp: qp pointer
 */
static void irdma_alloc_push_page(struct irdma_qp *iwqp)
{

	if (iwqp->iwdev->rf->sc_dev.hw_attrs.uk_attrs.hw_rev >= IRDMA_GEN_3)
		return irdma_alloc_push_page_3(iwqp);
}

/**
 * irdma_get_pbl - Retrieve pbl from a list given a virtual
 * address
 * @va: user virtual address
 * @pbl_list: pbl list to search in (QP's or CQ's)
 */
struct irdma_pbl *irdma_get_pbl(unsigned long va,
				struct list_head *pbl_list)
{
	struct irdma_pbl *iwpbl;

	list_for_each_entry(iwpbl, pbl_list, list) {
		if (iwpbl->user_base == va) {
			list_del(&iwpbl->list);
			iwpbl->on_list = false;
			return iwpbl;
		}
	}

	return NULL;
}

/**
 * irdma_clean_cqes - clean cq entries for qp
 * @iwqp: qp ptr (user or kernel)
 * @iwcq: cq ptr
 */
void irdma_clean_cqes(struct irdma_qp *iwqp, struct irdma_cq *iwcq)
{
	struct irdma_cq_uk *ukcq = &iwcq->sc_cq.cq_uk;
	unsigned long flags;
	struct irdma_cmpl_gen *cmpl_node;
	struct list_head *tmp_node, *list_node;

	spin_lock_irqsave(&iwcq->lock, flags);
	irdma_uk_clean_cq(&iwqp->sc_qp.qp_uk, ukcq);

	list_for_each_safe(list_node, tmp_node, &iwcq->cmpl_generated) {
		cmpl_node = list_entry(list_node, struct irdma_cmpl_gen, list);
		if (cmpl_node->cpi.qp_id == iwqp->ibqp.qp_num) {
			list_del(&cmpl_node->list);
			kfree(cmpl_node);
		}
	}

	spin_unlock_irqrestore(&iwcq->lock, flags);
}

static u64 irdma_compute_push_wqe_offset(struct irdma_device *iwdev, u32 page_idx)
{
	u64 bar_off = (uintptr_t)iwdev->rf->sc_dev.hw_regs[IRDMA_DB_ADDR_OFFSET];

	if (iwdev->rf->sc_dev.hw_attrs.uk_attrs.hw_rev == IRDMA_GEN_2) {
		/* skip over db page */
		bar_off += IRDMA_HW_PAGE_SIZE;
		/* skip over reserved space */
		bar_off += iwdev->rf->ftype ? IRDMA_VF_BAR_RSVD :
					      IRDMA_PF_BAR_RSVD;
	}

	/* push wqe page */
	bar_off += (u64)page_idx * IRDMA_HW_PAGE_SIZE;

	return  bar_off;
}

void irdma_remove_push_mmap_entries(struct irdma_qp *iwqp)
{
	if (iwqp->push_db_mmap_entry) {
#ifdef RDMA_MMAP_DB_SUPPORT
		rdma_user_mmap_entry_remove(iwqp->push_db_mmap_entry);
#else
		irdma_user_mmap_entry_del_hash(iwqp->push_db_mmap_entry);
#endif
		iwqp->push_db_mmap_entry = NULL;
	}
	if (iwqp->push_wqe_mmap_entry) {
#ifdef RDMA_MMAP_DB_SUPPORT
		rdma_user_mmap_entry_remove(iwqp->push_wqe_mmap_entry);
#else
		irdma_user_mmap_entry_del_hash(iwqp->push_wqe_mmap_entry);
#endif
		iwqp->push_wqe_mmap_entry = NULL;
	}
}

static int irdma_setup_push_mmap_entries(struct irdma_ucontext *ucontext,
					 struct irdma_qp *iwqp,
					 u64 *push_wqe_mmap_key,
					 u64 *push_db_mmap_key)
{
	struct irdma_device *iwdev = ucontext->iwdev;
	u64 bar_off;

	WARN_ON_ONCE(iwdev->rf->sc_dev.hw_attrs.uk_attrs.hw_rev < IRDMA_GEN_2);

	bar_off = irdma_compute_push_wqe_offset(iwdev, iwqp->sc_qp.push_idx);

#ifdef RDMA_MMAP_DB_SUPPORT
	iwqp->push_wqe_mmap_entry = irdma_user_mmap_entry_insert(ucontext,
								 bar_off, IRDMA_MMAP_IO_WC,
								 push_wqe_mmap_key);
#else
	iwqp->push_wqe_mmap_entry = irdma_user_mmap_entry_add_hash(ucontext, bar_off,
								   IRDMA_MMAP_IO_WC,
								   push_wqe_mmap_key);
#endif
	if (!iwqp->push_wqe_mmap_entry)
		return -ENOMEM;

	/* push doorbell page */
	bar_off += IRDMA_HW_PAGE_SIZE;
#ifdef RDMA_MMAP_DB_SUPPORT
	iwqp->push_db_mmap_entry = irdma_user_mmap_entry_insert(ucontext,
								bar_off, IRDMA_MMAP_IO_NC,
								push_db_mmap_key);
#else

	iwqp->push_db_mmap_entry = irdma_user_mmap_entry_add_hash(ucontext, bar_off,
								  IRDMA_MMAP_IO_NC,
								  push_db_mmap_key);
#endif
	if (!iwqp->push_db_mmap_entry) {
#ifdef RDMA_MMAP_DB_SUPPORT
		rdma_user_mmap_entry_remove(iwqp->push_wqe_mmap_entry);
#else
		irdma_user_mmap_entry_del_hash(iwqp->push_wqe_mmap_entry);
#endif
		return -ENOMEM;
	}

	return 0;
}

/**
 * irdma_setup_virt_qp - setup for allocation of virtual qp
 * @iwdev: irdma device
 * @iwqp: qp ptr
 * @init_info: initialize info to return
 */
void irdma_setup_virt_qp(struct irdma_device *iwdev,
			 struct irdma_qp *iwqp,
			 struct irdma_qp_init_info *init_info)
{
	struct irdma_pbl *iwpbl = iwqp->iwpbl;
	struct irdma_qp_mr *qpmr = &iwpbl->qp_mr;

	iwqp->page = qpmr->sq_page;
	init_info->shadow_area_pa = qpmr->shadow;
	if (iwpbl->pbl_allocated) {
		init_info->virtual_map = true;
		init_info->sq_pa = qpmr->sq_pbl.idx;
		/* Need to use contiguous buffer for RQ of QP in case it is associated with SRQ */
		init_info->rq_pa = init_info->qp_uk_init_info.srq_uk ? qpmr->rq_pa :
								       qpmr->rq_pbl.idx;
	} else {
		init_info->sq_pa = qpmr->sq_pbl.addr;
		init_info->rq_pa = qpmr->rq_pbl.addr;
	}
}

/**
 * irdma_setup_umode_qp - setup sq and rq size in user mode qp
 * @udata: user data
 * @iwdev: iwarp device
 * @iwqp: qp ptr (user or kernel)
 * @info: initialize info to return
 * @init_attr: Initial QP create attributes
 */
int irdma_setup_umode_qp(struct ib_udata *udata,
			 struct irdma_device *iwdev,
			 struct irdma_qp *iwqp,
			 struct irdma_qp_init_info *info,
			 struct ib_qp_init_attr *init_attr)
{
	struct irdma_ucontext *ucontext = kc_rdma_udata_to_drv_context(&iwqp->iwpd->ibpd, udata);
	struct irdma_qp_uk_init_info *ukinfo = &info->qp_uk_init_info;
	struct irdma_create_qp_req req = {};
	unsigned long flags;
	int ret;

	ret = ib_copy_from_udata(&req, udata,
				 min(sizeof(req), udata->inlen));
	if (ret) {
		ibdev_dbg(&iwdev->ibdev, "VERBS: ib_copy_from_data fail\n");
		return ret;
	}

	iwqp->ctx_info.qp_compl_ctx = req.user_compl_ctx;
	iwqp->user_mode = 1;
	if (req.user_wqe_bufs) {
		info->qp_uk_init_info.legacy_mode = ucontext->legacy_mode;
		spin_lock_irqsave(&ucontext->qp_reg_mem_list_lock, flags);
		iwqp->iwpbl = irdma_get_pbl((unsigned long)req.user_wqe_bufs,
					    &ucontext->qp_reg_mem_list);
		spin_unlock_irqrestore(&ucontext->qp_reg_mem_list_lock, flags);

		if (!iwqp->iwpbl) {
			ret = -ENODATA;
			ibdev_dbg(&iwdev->ibdev, "VERBS: no pbl info\n");
			return ret;
		}
	}

	if (!ucontext->use_raw_attrs) {
		/**
		 * Maintain backward compat with older ABI which passes sq and
		 * rq depth in quanta in cap.max_send_wr and cap.max_recv_wr.
		 * There is no way to compute the correct value of
		 * iwqp->max_send_wr/max_recv_wr in the kernel.
		 */
		iwqp->max_send_wr = init_attr->cap.max_send_wr;
		iwqp->max_recv_wr = init_attr->cap.max_recv_wr;
		ukinfo->sq_size = init_attr->cap.max_send_wr;
		ukinfo->rq_size = init_attr->cap.max_recv_wr;
		irdma_uk_calc_shift_wq(ukinfo, &ukinfo->sq_shift, &ukinfo->rq_shift);
	} else {
		ret = irdma_uk_calc_depth_shift_sq(ukinfo, &ukinfo->sq_depth,
						   &ukinfo->sq_shift);
		if (ret)
			return ret;

		ret = irdma_uk_calc_depth_shift_rq(ukinfo, &ukinfo->rq_depth,
						   &ukinfo->rq_shift);
		if (ret)
			return ret;

		iwqp->max_send_wr = (ukinfo->sq_depth - IRDMA_SQ_RSVD) >> ukinfo->sq_shift;
		iwqp->max_recv_wr = (ukinfo->rq_depth - IRDMA_RQ_RSVD) >> ukinfo->rq_shift;
		ukinfo->sq_size = ukinfo->sq_depth >> ukinfo->sq_shift;
		ukinfo->rq_size = ukinfo->rq_depth >> ukinfo->rq_shift;
	}
	if (req.comp_mask & IRDMA_CREATE_QP_USE_START_WQE_IDX &&
	    iwdev->rf->sc_dev.hw_attrs.uk_attrs.feature_flags & IRDMA_FEATURE_RTS_AE)
		ukinfo->start_wqe_idx = 4;
	irdma_setup_virt_qp(iwdev, iwqp, info);

	return 0;
}

/**
 * irdma_setup_kmode_qp - setup initialization for kernel mode qp
 * @iwdev: iwarp device
 * @iwqp: qp ptr (user or kernel)
 * @info: initialize info to return
 * @init_attr: Initial QP create attributes
 */
int irdma_setup_kmode_qp(struct irdma_device *iwdev,
			 struct irdma_qp *iwqp,
			 struct irdma_qp_init_info *info,
			 struct ib_qp_init_attr *init_attr)
{
	struct irdma_dma_mem *mem = &iwqp->kqp.dma_mem;
	u32 size;
	int status;
	struct irdma_qp_uk_init_info *ukinfo = &info->qp_uk_init_info;

	status = irdma_uk_calc_depth_shift_sq(ukinfo, &ukinfo->sq_depth,
					      &ukinfo->sq_shift);
	if (status)
		return status;

	status = irdma_uk_calc_depth_shift_rq(ukinfo, &ukinfo->rq_depth,
					      &ukinfo->rq_shift);
	if (status)
		return status;

	iwqp->kqp.sq_wrid_mem =
		kcalloc(ukinfo->sq_depth, sizeof(*iwqp->kqp.sq_wrid_mem), GFP_KERNEL);
	if (!iwqp->kqp.sq_wrid_mem)
		return -ENOMEM;

	iwqp->kqp.rq_wrid_mem =
		kcalloc(ukinfo->rq_depth, sizeof(*iwqp->kqp.rq_wrid_mem), GFP_KERNEL);
	if (!iwqp->kqp.rq_wrid_mem) {
		kfree(iwqp->kqp.sq_wrid_mem);
		iwqp->kqp.sq_wrid_mem = NULL;
		return -ENOMEM;
	}

	ukinfo->sq_wrtrk_array = iwqp->kqp.sq_wrid_mem;
	ukinfo->rq_wrid_array = iwqp->kqp.rq_wrid_mem;

	size = (ukinfo->sq_depth + ukinfo->rq_depth) * IRDMA_QP_WQE_MIN_SIZE;
	size += (IRDMA_SHADOW_AREA_SIZE << 3);

	mem->size = ALIGN(size, 256);
	mem->va = dma_alloc_coherent(iwdev->rf->hw.device, mem->size,
				     &mem->pa, GFP_KERNEL);
	if (!mem->va) {
		kfree(iwqp->kqp.sq_wrid_mem);
		iwqp->kqp.sq_wrid_mem = NULL;
		kfree(iwqp->kqp.rq_wrid_mem);
		iwqp->kqp.rq_wrid_mem = NULL;
		return -ENOMEM;
	}

	ukinfo->sq = mem->va;
	info->sq_pa = mem->pa;
	ukinfo->rq = &ukinfo->sq[ukinfo->sq_depth];
	info->rq_pa = info->sq_pa + (ukinfo->sq_depth * IRDMA_QP_WQE_MIN_SIZE);
	ukinfo->shadow_area = ukinfo->rq[ukinfo->rq_depth].elem;
	info->shadow_area_pa = info->rq_pa + (ukinfo->rq_depth * IRDMA_QP_WQE_MIN_SIZE);
	ukinfo->sq_size = ukinfo->sq_depth >> ukinfo->sq_shift;
	ukinfo->rq_size = ukinfo->rq_depth >> ukinfo->rq_shift;

	iwqp->max_send_wr = (ukinfo->sq_depth - IRDMA_SQ_RSVD) >> ukinfo->sq_shift;
	iwqp->max_recv_wr = (ukinfo->rq_depth - IRDMA_RQ_RSVD) >> ukinfo->rq_shift;
	init_attr->cap.max_send_wr = iwqp->max_send_wr;
	init_attr->cap.max_recv_wr = iwqp->max_recv_wr;

	return 0;
}

int irdma_cqp_create_qp_cmd(struct irdma_qp *iwqp)
{
	struct irdma_pci_f *rf = iwqp->iwdev->rf;
	struct irdma_cqp_request *cqp_request;
	struct cqp_cmds_info *cqp_info;
	struct irdma_create_qp_info *qp_info;
	int status;

	cqp_request = irdma_alloc_and_get_cqp_request(&rf->cqp, true);
	if (!cqp_request)
		return -ENOMEM;

	cqp_info = &cqp_request->info;
	qp_info = &cqp_request->info.in.u.qp_create.info;
	qp_info->mac_valid = true;
	qp_info->cq_num_valid = true;
	qp_info->next_iwarp_state = IRDMA_QP_STATE_IDLE;

	cqp_info->cqp_cmd = IRDMA_OP_QP_CREATE;
	cqp_info->post_sq = 1;
	cqp_info->in.u.qp_create.qp = &iwqp->sc_qp;
	cqp_info->in.u.qp_create.scratch = (uintptr_t)cqp_request;
	cqp_info->create = true;
	status = irdma_handle_cqp_op(rf, cqp_request);
	irdma_put_cqp_request(&rf->cqp, cqp_request);

	return status;
}

void irdma_roce_fill_and_set_qpctx_info(struct irdma_qp *iwqp,
					struct irdma_qp_host_ctx_info *ctx_info)
{
	struct irdma_device *iwdev = iwqp->iwdev;
	struct irdma_sc_dev *dev = &iwdev->rf->sc_dev;
	struct irdma_roce_offload_info *roce_info;
	struct irdma_udp_offload_info *udp_info;

	udp_info = &iwqp->udp_info;
	udp_info->snd_mss = crt_mtu_enum_to_int(crt_iboe_get_mtu(iwdev->vsi.mtu));
	if (udp_info->snd_mss >= 8192 &&
	    iwdev->rf->protocol_used == IRDMA_ROCE_PROTOCOL_ONLY) {
		udp_info->snd_mss = 4096;
		ibdev_dbg(&iwdev->ibdev,
			  "VERBS: changing snd_mss to 4096\n");
	}
	udp_info->cwnd = iwdev->roce_cwnd;
	udp_info->rexmit_thresh = 2;
	udp_info->rnr_nak_thresh = 2;
	udp_info->src_port = 0xc000;
	udp_info->dst_port = ROCE_V2_UDP_DPORT;
	roce_info = &iwqp->roce_info;
	ether_addr_copy(roce_info->mac_addr, iwdev->netdev->dev_addr);

	roce_info->rd_en = true;
	roce_info->wr_rdresp_en = true;
	if (dev->hw_attrs.uk_attrs.hw_rev >= IRDMA_GEN_3)
		roce_info->bind_en = true;
	roce_info->dcqcn_en = false;
	roce_info->rtomin = iwdev->roce_rtomin;

	/* If there is no configfs, use default configuration. */
	roce_info->rca_config = IRDMA_RCA_CFG_PENDING | IRDMA_RCA_CFG_EXECUTE |
				IRDMA_RCA_CFG_AH_MODIFY;
#if IS_ENABLED(CONFIG_CONFIGFS_FS)
	roce_info->dcqcn_en = iwdev->roce_dcqcn_en;
	roce_info->timely_en = iwdev->roce_timely_en;
	roce_info->dctcp_en = iwdev->roce_dctcp_en;
	roce_info->rtomin = iwdev->roce_rtomin;
	roce_info->rcv_no_icrc = iwdev->roce_no_icrc_en;
#endif /* IS_ENABLED(CONFIG_CONFIGFS_FS) */
	roce_info->ack_credits = iwdev->roce_ackcreds;
	roce_info->ird_size = dev->hw_attrs.max_hw_ird;
	roce_info->ord_size = dev->hw_attrs.max_hw_ord;

	if (!iwqp->user_mode) {
		roce_info->priv_mode_en = true;
		roce_info->fast_reg_en = true;
		roce_info->udprivcq_en = true;
	}
	roce_info->roce_tver = 0;

	ctx_info->roce_info = &iwqp->roce_info;
	ctx_info->udp_info = &iwqp->udp_info;
	irdma_sc_qp_setctx_roce(&iwqp->sc_qp, iwqp->host_ctx.va, ctx_info);
}

void irdma_iw_fill_and_set_qpctx_info(struct irdma_qp *iwqp,
				      struct irdma_qp_host_ctx_info *ctx_info)
{
	struct irdma_device *iwdev = iwqp->iwdev;
	struct irdma_sc_dev *dev = &iwdev->rf->sc_dev;
	struct irdma_iwarp_offload_info *iwarp_info;

	iwarp_info = &iwqp->iwarp_info;
	ether_addr_copy(iwarp_info->mac_addr, iwdev->netdev->dev_addr);
	iwarp_info->rd_en = true;
	iwarp_info->wr_rdresp_en = true;
	iwarp_info->ecn_en = true;
	iwarp_info->rtomin = 5;
#if IS_ENABLED(CONFIG_CONFIGFS_FS)
	iwarp_info->dctcp_en = iwdev->iwarp_dctcp_en;
	iwarp_info->timely_en = iwdev->iwarp_timely_en;
	iwarp_info->ecn_en = iwdev->iwarp_ecn_en;
	iwarp_info->rtomin = iwdev->iwarp_rtomin;

	if (iwarp_info->dctcp_en)
		iwarp_info->ecn_en = false;
#endif

	if (dev->hw_attrs.uk_attrs.hw_rev >= IRDMA_GEN_2)
		iwarp_info->ib_rd_en = true;
	if (!iwqp->user_mode) {
		iwarp_info->priv_mode_en = true;
		iwarp_info->fast_reg_en = true;
	}
	iwarp_info->ddp_ver = 1;
	iwarp_info->rdmap_ver = 1;

	ctx_info->iwarp_info = &iwqp->iwarp_info;
	ctx_info->iwarp_info_valid = true;
	irdma_sc_qp_setctx(&iwqp->sc_qp, iwqp->host_ctx.va, ctx_info);
	ctx_info->iwarp_info_valid = false;
}

int irdma_validate_qp_attrs(struct ib_qp_init_attr *init_attr,
			    struct irdma_device *iwdev)
{
	struct irdma_sc_dev *dev = &iwdev->rf->sc_dev;
	struct irdma_uk_attrs *uk_attrs = &dev->hw_attrs.uk_attrs;

	if (init_attr->create_flags)
		return -EOPNOTSUPP;

	if (init_attr->cap.max_inline_data > uk_attrs->max_hw_inline ||
	    init_attr->cap.max_send_sge > uk_attrs->max_hw_wq_frags ||
	    init_attr->cap.max_send_wr > uk_attrs->max_hw_wq_quanta ||
	    init_attr->cap.max_recv_wr > uk_attrs->max_hw_rq_quanta ||
	    init_attr->cap.max_recv_sge > uk_attrs->max_hw_wq_frags)
		return -EINVAL;

	if (rdma_protocol_roce(&iwdev->ibdev, 1)) {
		if (init_attr->qp_type != IB_QPT_RC &&
		    init_attr->qp_type != IB_QPT_UD &&
		    init_attr->qp_type != IB_QPT_GSI)
			return -EOPNOTSUPP;
	} else {
		if (init_attr->qp_type != IB_QPT_RC)
			return -EOPNOTSUPP;
	}

	return 0;
}

void irdma_sched_qp_flush_work(struct irdma_qp *iwqp)
{
	if (iwqp->sc_qp.qp_uk.destroy_pending)
		return;
	irdma_qp_add_ref(&iwqp->ibqp);
	if (mod_delayed_work(iwqp->iwdev->cleanup_wq, &iwqp->dwork_flush,
			     msecs_to_jiffies(IRDMA_FLUSH_DELAY_MS)))
		irdma_qp_rem_ref(&iwqp->ibqp);
}

void irdma_flush_worker(struct work_struct *work)
{
	struct delayed_work *dwork = to_delayed_work(work);
	struct irdma_qp *iwqp = container_of(dwork, struct irdma_qp, dwork_flush);

	irdma_generate_flush_completions(iwqp);
	/* For the add in irdma_sched_qp_flush_work */
	irdma_qp_rem_ref(&iwqp->ibqp);
}

struct ib_mr *wa_reg_phys_mr(struct ib_pd *pd)
{
	struct irdma_device *iwdev = to_iwdev(pd->device);
	struct irdma_pbl *iwpbl;
	struct irdma_mr *iwmr;
	int ret;

	iwmr = kzalloc(sizeof(*iwmr), GFP_KERNEL);
	if (!iwmr)
		return ERR_PTR(-ENOMEM);

	iwmr->ibmr.pd = pd;
	iwmr->ibmr.device = pd->device;
	iwpbl = &iwmr->iwpbl;
	iwpbl->iwmr = iwmr;
	iwmr->type = IRDMA_MEMREG_TYPE_MEM;
	iwmr->stag = 1 << IRDMA_CQPSQ_STAG_IDX_S;
	iwmr->page_cnt = 1;
	iwmr->page_size = SZ_4K;
	ret = irdma_hwreg_mr(iwdev, iwmr, 0xff);
	if (ret) {
		irdma_free_stag(iwdev, iwmr->stag);
		goto err;
	}

	return &iwmr->ibmr;
err:
	kfree(iwmr);
	return ERR_PTR(ret);
}

static int irdma_get_ib_acc_flags(struct irdma_qp *iwqp)
{
	int acc_flags = 0;

	if (rdma_protocol_roce(iwqp->ibqp.device, 1)) {
		if (iwqp->roce_info.wr_rdresp_en) {
			acc_flags |= IB_ACCESS_LOCAL_WRITE;
			acc_flags |= IB_ACCESS_REMOTE_WRITE;
		}
		if (iwqp->roce_info.rd_en)
			acc_flags |= IB_ACCESS_REMOTE_READ;
		if (iwqp->roce_info.bind_en)
			acc_flags |= IB_ACCESS_MW_BIND;
		if (iwqp->ctx_info.remote_atomics_en)
			acc_flags |= IB_ACCESS_REMOTE_ATOMIC;
	} else {
		if (iwqp->iwarp_info.wr_rdresp_en) {
			acc_flags |= IB_ACCESS_LOCAL_WRITE;
			acc_flags |= IB_ACCESS_REMOTE_WRITE;
		}
		if (iwqp->iwarp_info.rd_en)
			acc_flags |= IB_ACCESS_REMOTE_READ;
		if (iwqp->ctx_info.remote_atomics_en)
			acc_flags |= IB_ACCESS_REMOTE_ATOMIC;
	}
	return acc_flags;
}

/**
 * irdma_query_qp - query qp attributes
 * @ibqp: qp pointer
 * @attr: attributes pointer
 * @attr_mask: Not used
 * @init_attr: qp attributes to return
 */
static int irdma_query_qp(struct ib_qp *ibqp, struct ib_qp_attr *attr,
			  int attr_mask, struct ib_qp_init_attr *init_attr)
{
	struct irdma_qp *iwqp = to_iwqp(ibqp);
	struct irdma_sc_qp *qp = &iwqp->sc_qp;

	memset(attr, 0, sizeof(*attr));
	memset(init_attr, 0, sizeof(*init_attr));

	attr->qp_state = iwqp->ibqp_state;
	attr->cur_qp_state = iwqp->ibqp_state;
	attr->cap.max_send_wr = iwqp->max_send_wr;
	attr->cap.max_recv_wr = iwqp->max_recv_wr;
	attr->cap.max_inline_data = qp->qp_uk.max_inline_data;
	attr->cap.max_send_sge = qp->qp_uk.max_sq_frag_cnt;
	attr->cap.max_recv_sge = qp->qp_uk.max_rq_frag_cnt;
	attr->qp_access_flags = irdma_get_ib_acc_flags(iwqp);
	attr->port_num = 1;
	if (rdma_protocol_roce(ibqp->device, 1)) {
		attr->path_mtu = ib_mtu_int_to_enum(iwqp->udp_info.snd_mss);
		attr->qkey = iwqp->roce_info.qkey;
		attr->rq_psn = iwqp->udp_info.epsn;
		attr->sq_psn = iwqp->udp_info.psn_nxt;
		attr->dest_qp_num = iwqp->roce_info.dest_qp;
		attr->pkey_index = iwqp->roce_info.p_key;
		attr->retry_cnt = iwqp->udp_info.rexmit_thresh;
		attr->rnr_retry = iwqp->udp_info.rnr_nak_thresh;
		attr->min_rnr_timer = iwqp->udp_info.min_rnr_timer;
		attr->max_rd_atomic = iwqp->roce_info.ord_size;
		attr->max_dest_rd_atomic = iwqp->roce_info.ird_size;
	}

	init_attr->event_handler = iwqp->ibqp.event_handler;
	init_attr->qp_context = iwqp->ibqp.qp_context;
	init_attr->send_cq = iwqp->ibqp.send_cq;
	init_attr->recv_cq = iwqp->ibqp.recv_cq;
	init_attr->srq = iwqp->ibqp.srq;
	init_attr->cap = attr->cap;

	return 0;
}

static int irdma_wait_for_suspend(struct irdma_qp *iwqp)
{
	if (!wait_event_timeout(iwqp->iwdev->suspend_wq,
				!iwqp->suspend_pending,
				msecs_to_jiffies(IRDMA_EVENT_TIMEOUT_MS))) {
		iwqp->suspend_pending = false;
		ibdev_warn(&iwqp->iwdev->ibdev,
			   "modify_qp timed out waiting for suspend. qp_id = %d, last_ae = 0x%x\n",
			   iwqp->ibqp.qp_num, iwqp->last_aeq);
		return -EBUSY;
	}

	return 0;
}

/**
 * irdma_modify_qp_roce - modify qp request
 * @ibqp: qp's pointer for modify
 * @attr: access attributes
 * @attr_mask: state mask
 * @udata: user data
 */
int irdma_modify_qp_roce(struct ib_qp *ibqp, struct ib_qp_attr *attr,
			 int attr_mask, struct ib_udata *udata)
{
#define IRDMA_MODIFY_QP_MIN_REQ_LEN offsetofend(struct irdma_modify_qp_req, rq_flush)
#define IRDMA_MODIFY_QP_MIN_RESP_LEN offsetofend(struct irdma_modify_qp_resp, push_valid)
#define IRDMA_MODIFY_QP_RCAKEY_REQ_LEN offsetofend(struct irdma_modify_qp_req, rca_key)
	struct irdma_pd *iwpd = to_iwpd(ibqp->pd);
	struct irdma_qp *iwqp = to_iwqp(ibqp);
	struct irdma_device *iwdev = iwqp->iwdev;
	struct irdma_sc_dev *dev = &iwdev->rf->sc_dev;
	struct irdma_qp_host_ctx_info *ctx_info;
	struct irdma_roce_offload_info *roce_info;
	struct irdma_udp_offload_info *udp_info;
	struct irdma_modify_qp_info info = {};
	struct irdma_modify_qp_resp uresp = {};
	struct irdma_modify_qp_req ureq;
	unsigned long flags;
	u8 issue_modify_qp = 0;
	int ret = 0;

	ctx_info = &iwqp->ctx_info;
	roce_info = &iwqp->roce_info;
	udp_info = &iwqp->udp_info;

	if (udata) {
		if ((udata->inlen && udata->inlen < IRDMA_MODIFY_QP_MIN_REQ_LEN) ||
		    (udata->outlen && udata->outlen < IRDMA_MODIFY_QP_MIN_RESP_LEN))
			return -EINVAL;
	}

	if (udata && udata->inlen >= IRDMA_MODIFY_QP_RCAKEY_REQ_LEN)
		if (ib_copy_from_udata(&ureq, udata,
				       min(sizeof(ureq), udata->inlen)))
			return -EINVAL;

	if (attr_mask & ~IB_QP_ATTR_STANDARD_BITS)
		return -EOPNOTSUPP;

	if (attr_mask & IB_QP_DEST_QPN)
		roce_info->dest_qp = attr->dest_qp_num;

	if (attr_mask & IB_QP_PKEY_INDEX) {
		ret = irdma_query_pkey(ibqp->device, 0, attr->pkey_index,
				       &roce_info->p_key);
		if (ret)
			return ret;
	}

	if (attr_mask & IB_QP_QKEY)
		roce_info->qkey = attr->qkey;

	if (attr_mask & IB_QP_PATH_MTU) {
		udp_info->snd_mss = crt_mtu_enum_to_int((enum crt_mtu)attr->path_mtu);
		if (udp_info->snd_mss >= 8192 &&
		    iwdev->rf->protocol_used == IRDMA_ROCE_PROTOCOL_ONLY) {
			udp_info->snd_mss = 4096;
			ibdev_dbg(&iwdev->ibdev,
				  "VERBS: modify_qp: Changing snd_mss to 4096\n");
		}
	}

	if (attr_mask & IB_QP_SQ_PSN) {
		udp_info->psn_nxt = attr->sq_psn;
		udp_info->lsn =  0xffff;
		udp_info->psn_una = attr->sq_psn;
		udp_info->psn_max = attr->sq_psn;
	}

	if (attr_mask & IB_QP_RQ_PSN)
		udp_info->epsn = attr->rq_psn;

	if (attr_mask & IB_QP_RNR_RETRY)
		udp_info->rnr_nak_thresh = attr->rnr_retry;

	if (attr_mask & IB_QP_MIN_RNR_TIMER &&
	    dev->hw_attrs.uk_attrs.hw_rev >= IRDMA_GEN_3)
		udp_info->min_rnr_timer = attr->min_rnr_timer;

	if (attr_mask & IB_QP_RETRY_CNT)
		udp_info->rexmit_thresh = attr->retry_cnt;

	ctx_info->roce_info->pd_id = iwpd->sc_pd.pd_id;
	ctx_info->roce_info->rca_key[0] = 0ULL;
	ctx_info->roce_info->rca_key[1] = 0ULL;

	if (attr_mask & IB_QP_AV) {
		struct irdma_av *av = &iwqp->roce_ah.av;
		u16 vlan_id = VLAN_N_VID;
		u32 local_ip[4] = {};

		memset(&iwqp->roce_ah, 0, sizeof(iwqp->roce_ah));
		if (attr->ah_attr.ah_flags & IB_AH_GRH) {
			udp_info->ttl = attr->ah_attr.grh.hop_limit;
			udp_info->flow_label = attr->ah_attr.grh.flow_label;
			udp_info->tos = attr->ah_attr.grh.traffic_class;

			udp_info->src_port = kc_rdma_get_udp_sport(udp_info->flow_label,
								   ibqp->qp_num,
								   roce_info->dest_qp);

			irdma_qp_rem_qos(&iwqp->sc_qp);
			dev->ws_remove(iwqp->sc_qp.vsi, ctx_info->user_pri);
			if (iwqp->sc_qp.vsi->dscp_mode)
				ctx_info->user_pri =
					iwqp->sc_qp.vsi->dscp_map[irdma_tos2dscp(udp_info->tos)];
			else
				ctx_info->user_pri = rt_tos2priority(udp_info->tos);
		}
		ret = kc_irdma_set_roce_cm_info(iwqp, attr, &vlan_id);
		if (ret)
			return ret;
		if (dev->ws_add(iwqp->sc_qp.vsi, ctx_info->user_pri))
			return -ENOMEM;
		iwqp->sc_qp.user_pri = ctx_info->user_pri;
		irdma_qp_add_qos(&iwqp->sc_qp);

		if (vlan_id >= VLAN_N_VID && iwdev->dcb_vlan_mode)
			vlan_id = 0;
		if (vlan_id < VLAN_N_VID) {
			udp_info->insert_vlan_tag = true;
			udp_info->vlan_tag = vlan_id |
				ctx_info->user_pri << VLAN_PRIO_SHIFT;
		} else {
			udp_info->insert_vlan_tag = false;
		}

		av->attrs = attr->ah_attr;
		rdma_gid2ip((struct sockaddr *)&av->dgid_addr, &attr->ah_attr.grh.dgid);
		if (av->net_type == RDMA_NETWORK_IPV6) {
			__be32 *daddr =
				av->dgid_addr.saddr_in6.sin6_addr.in6_u.u6_addr32;
			__be32 *saddr =
				av->sgid_addr.saddr_in6.sin6_addr.in6_u.u6_addr32;

			irdma_copy_ip_ntohl(&udp_info->dest_ip_addr[0], daddr);
			irdma_copy_ip_ntohl(&udp_info->local_ipaddr[0], saddr);

			udp_info->ipv4 = false;
			irdma_copy_ip_ntohl(local_ip, daddr);
		} else if (av->net_type == RDMA_NETWORK_IPV4) {
			__be32 saddr = av->sgid_addr.saddr_in.sin_addr.s_addr;
			__be32 daddr = av->dgid_addr.saddr_in.sin_addr.s_addr;

			local_ip[0] = ntohl(daddr);

			udp_info->ipv4 = true;
			udp_info->dest_ip_addr[0] = 0;
			udp_info->dest_ip_addr[1] = 0;
			udp_info->dest_ip_addr[2] = 0;
			udp_info->dest_ip_addr[3] = local_ip[0];

			udp_info->local_ipaddr[0] = 0;
			udp_info->local_ipaddr[1] = 0;
			udp_info->local_ipaddr[2] = 0;
			udp_info->local_ipaddr[3] = ntohl(saddr);
		} else {
			return -EINVAL;
		}
		udp_info->arp_idx =
			irdma_add_arp(iwdev->rf, local_ip,
				      ah_attr_to_dmac(attr->ah_attr));
	}

	if (attr_mask & IB_QP_MAX_QP_RD_ATOMIC) {
		if (attr->max_rd_atomic > dev->hw_attrs.max_hw_ord) {
			ibdev_err(&iwdev->ibdev,
				  "rd_atomic = %d, above max_hw_ord=%d\n",
				  attr->max_rd_atomic,
				  dev->hw_attrs.max_hw_ord);
			return -EINVAL;
		}
		if (attr->max_rd_atomic)
			roce_info->ord_size = attr->max_rd_atomic;
		info.ord_valid = true;
	}

	if (attr_mask & IB_QP_MAX_DEST_RD_ATOMIC) {
		if (attr->max_dest_rd_atomic > dev->hw_attrs.max_hw_ird) {
			ibdev_err(&iwdev->ibdev,
				  "rd_atomic = %d, above max_hw_ird=%d\n",
				  attr->max_rd_atomic,
				  dev->hw_attrs.max_hw_ird);
			return -EINVAL;
		}
		if (attr->max_dest_rd_atomic)
			roce_info->ird_size = attr->max_dest_rd_atomic;
	}

	if (attr_mask & IB_QP_ACCESS_FLAGS) {
		if (attr->qp_access_flags & IB_ACCESS_LOCAL_WRITE)
			roce_info->wr_rdresp_en = true;
		if (attr->qp_access_flags & IB_ACCESS_REMOTE_WRITE)
			roce_info->wr_rdresp_en = true;
		if (attr->qp_access_flags & IB_ACCESS_REMOTE_READ)
			roce_info->rd_en = true;
		if (attr->qp_access_flags & IB_ACCESS_REMOTE_ATOMIC)
			ctx_info->remote_atomics_en = true;
	}

	wait_event(iwqp->mod_qp_waitq, !atomic_read(&iwqp->hw_mod_qp_pend));

	ibdev_dbg(&iwdev->ibdev,
		  "VERBS: caller: %pS qp_id=%d to_ibqpstate=%d ibqpstate=%d irdma_qpstate=%d attr_mask=0x%x\n",
		  __builtin_return_address(0), ibqp->qp_num, attr->qp_state,
		  iwqp->ibqp_state, iwqp->iwarp_state, attr_mask);

	spin_lock_irqsave(&iwqp->lock, flags);
	if (attr_mask & IB_QP_STATE) {
		if (!kc_ib_modify_qp_is_ok(iwqp->ibqp_state, attr->qp_state,
					   iwqp->ibqp.qp_type, attr_mask,
					   IB_LINK_LAYER_ETHERNET)) {
			ibdev_warn(&iwdev->ibdev, "modify_qp invalid for qp_id=%d, old_state=0x%x, new_state=0x%x\n",
				   iwqp->ibqp.qp_num, iwqp->ibqp_state,
				   attr->qp_state);
			ret = -EINVAL;
			goto exit;
		}
		info.curr_iwarp_state = iwqp->iwarp_state;

		switch (attr->qp_state) {
		case IB_QPS_INIT:
			if (iwqp->iwarp_state > IRDMA_QP_STATE_IDLE) {
				ret = -EINVAL;
				goto exit;
			}

			if (iwqp->iwarp_state == IRDMA_QP_STATE_INVALID) {
				info.next_iwarp_state = IRDMA_QP_STATE_IDLE;
				if (udata && udata->inlen >= IRDMA_MODIFY_QP_RCAKEY_REQ_LEN)
					if (ureq.rca_key_present) {
						ctx_info->roce_info->rca_key[0] = ureq.rca_key[0];
						ctx_info->roce_info->rca_key[1] = ureq.rca_key[1];
					}
				issue_modify_qp = 1;
			}
			break;
		case IB_QPS_RTR:
			if (iwqp->iwarp_state > IRDMA_QP_STATE_IDLE) {
				ret = -EINVAL;
				goto exit;
			}
			info.arp_cache_idx_valid = true;
			info.cq_num_valid = true;
			info.next_iwarp_state = IRDMA_QP_STATE_RTR;
			issue_modify_qp = 1;
			break;
		case IB_QPS_RTS:
			if (iwqp->ibqp_state < IB_QPS_RTR ||
			    iwqp->ibqp_state == IB_QPS_ERR) {
				ret = -EINVAL;
				goto exit;
			}

			info.arp_cache_idx_valid = true;
			info.cq_num_valid = true;
			info.ord_valid = true;
			info.next_iwarp_state = IRDMA_QP_STATE_RTS;
			issue_modify_qp = 1;
			if (dev->hw_attrs.uk_attrs.hw_rev == IRDMA_GEN_2 &&
			    dev->privileged)
				iwdev->rf->check_fc(&iwdev->vsi, &iwqp->sc_qp);
			udp_info->cwnd = iwdev->roce_cwnd;
			roce_info->ack_credits = iwdev->roce_ackcreds;
			if (iwdev->push_mode && udata &&
			    iwqp->sc_qp.push_idx == IRDMA_INVALID_PUSH_PAGE_INDEX) {
				spin_unlock_irqrestore(&iwqp->lock, flags);
				irdma_alloc_push_page(iwqp);
				spin_lock_irqsave(&iwqp->lock, flags);
			}
			break;
		case IB_QPS_SQD:
			if (iwqp->iwarp_state == IRDMA_QP_STATE_SQD)
				goto exit;

			if (iwqp->iwarp_state != IRDMA_QP_STATE_RTS) {
				ret = -EINVAL;
				goto exit;
			}

			info.next_iwarp_state = IRDMA_QP_STATE_SQD;
			issue_modify_qp = 1;
			iwqp->suspend_pending = true;
			break;
		case IB_QPS_SQE:
		case IB_QPS_ERR:
		case IB_QPS_RESET:
			if (iwqp->iwarp_state == IRDMA_QP_STATE_ERROR) {
				spin_unlock_irqrestore(&iwqp->lock, flags);
				if (udata && udata->inlen) {
					if (ib_copy_from_udata(&ureq, udata,
					    min(sizeof(ureq), udata->inlen)))
						return -EINVAL;

					irdma_flush_wqes(iwqp,
					    (ureq.sq_flush ? IRDMA_FLUSH_SQ : 0) |
					    (ureq.rq_flush ? IRDMA_FLUSH_RQ : 0) |
					    IRDMA_REFLUSH);
				}
				return 0;
			}

			info.next_iwarp_state = IRDMA_QP_STATE_ERROR;
			issue_modify_qp = 1;
			break;
		default:
			ret = -EINVAL;
			goto exit;
		}

		iwqp->ibqp_state = attr->qp_state;
	}

	ctx_info->send_cq_num = iwqp->iwscq->sc_cq.cq_uk.cq_id;
	ctx_info->rcv_cq_num = iwqp->iwrcq->sc_cq.cq_uk.cq_id;
	irdma_sc_qp_setctx_roce(&iwqp->sc_qp, iwqp->host_ctx.va, ctx_info);
	spin_unlock_irqrestore(&iwqp->lock, flags);

	if (attr_mask & IB_QP_STATE) {
		if (issue_modify_qp) {
			ctx_info->rem_endpoint_idx = udp_info->arp_idx;
			if (irdma_hw_modify_qp(iwdev, iwqp, &info, true))
				return -EINVAL;
			if (info.next_iwarp_state == IRDMA_QP_STATE_SQD) {
				ret = irdma_wait_for_suspend(iwqp);
				if (ret)
					return ret;
			}
			spin_lock_irqsave(&iwqp->lock, flags);
			if (iwqp->iwarp_state == info.curr_iwarp_state) {
				iwqp->iwarp_state = info.next_iwarp_state;
				iwqp->ibqp_state = attr->qp_state;
				iwqp->sc_qp.qp_state = iwqp->iwarp_state;
			}
			if (iwqp->ibqp_state > IB_QPS_RTS &&
			    !atomic_read(&iwqp->flush_issued)) {
				spin_unlock_irqrestore(&iwqp->lock, flags);
				irdma_flush_wqes(iwqp, IRDMA_FLUSH_SQ |
						       IRDMA_FLUSH_RQ |
						       IRDMA_FLUSH_WAIT);

			} else {
				spin_unlock_irqrestore(&iwqp->lock, flags);
			}
		} else {
			iwqp->ibqp_state = attr->qp_state;
		}
		if (udata && udata->outlen && dev->hw_attrs.uk_attrs.hw_rev >= IRDMA_GEN_2) {
			struct irdma_ucontext *ucontext;

			ucontext = kc_rdma_udata_to_drv_context(ibqp, udata);
			if (iwqp->sc_qp.push_idx != IRDMA_INVALID_PUSH_PAGE_INDEX &&
			    !iwqp->push_wqe_mmap_entry &&
			    !irdma_setup_push_mmap_entries(ucontext, iwqp,
				&uresp.push_wqe_mmap_key, &uresp.push_db_mmap_key)) {
				uresp.push_valid = 1;
				uresp.push_offset = iwqp->sc_qp.push_offset;
			}
			uresp.rd_fence_rate = iwdev->rd_fence_rate;
			ret = ib_copy_to_udata(udata, &uresp, min(sizeof(uresp),
					       udata->outlen));
			if (ret) {
				irdma_remove_push_mmap_entries(iwqp);
				ibdev_dbg(&iwdev->ibdev,
					  "VERBS: copy_to_udata failed\n");
				return ret;
			}
		}
	}

	return 0;
exit:
	spin_unlock_irqrestore(&iwqp->lock, flags);

	return ret;
}

/**
 * irdma_modify_qp - modify qp request
 * @ibqp: qp's pointer for modify
 * @attr: access attributes
 * @attr_mask: state mask
 * @udata: user data
 */
int irdma_modify_qp(struct ib_qp *ibqp, struct ib_qp_attr *attr, int attr_mask,
		    struct ib_udata *udata)
{
#define IRDMA_MODIFY_QP_MIN_REQ_LEN offsetofend(struct irdma_modify_qp_req, rq_flush)
#define IRDMA_MODIFY_QP_MIN_RESP_LEN offsetofend(struct irdma_modify_qp_resp, push_valid)
	struct irdma_qp *iwqp = to_iwqp(ibqp);
	struct irdma_device *iwdev = iwqp->iwdev;
	struct irdma_sc_dev *dev = &iwdev->rf->sc_dev;
	struct irdma_qp_host_ctx_info *ctx_info;
	struct irdma_tcp_offload_info *tcp_info;
	struct irdma_iwarp_offload_info *offload_info;
	struct irdma_modify_qp_info info = {};
	struct irdma_modify_qp_resp uresp = {};
	struct irdma_modify_qp_req ureq = {};
	u8 issue_modify_qp = 0;
	u8 dont_wait = 0;
	int err;
	unsigned long flags;

	if (udata) {
		if ((udata->inlen && udata->inlen < IRDMA_MODIFY_QP_MIN_REQ_LEN) ||
		    (udata->outlen && udata->outlen < IRDMA_MODIFY_QP_MIN_RESP_LEN))
			return -EINVAL;
	}

	if (attr_mask & ~IB_QP_ATTR_STANDARD_BITS)
		return -EOPNOTSUPP;

	ctx_info = &iwqp->ctx_info;
	offload_info = &iwqp->iwarp_info;
	tcp_info = &iwqp->tcp_info;
	wait_event(iwqp->mod_qp_waitq, !atomic_read(&iwqp->hw_mod_qp_pend));
	ibdev_dbg(&iwdev->ibdev,
		  "VERBS: caller: %pS qp_id=%d to_ibqpstate=%d ibqpstate=%d irdma_qpstate=%d last_aeq=%d hw_tcp_state=%d hw_iwarp_state=%d attr_mask=0x%x\n",
		  __builtin_return_address(0), ibqp->qp_num, attr->qp_state,
		  iwqp->ibqp_state, iwqp->iwarp_state, iwqp->last_aeq,
		  iwqp->hw_tcp_state, iwqp->hw_iwarp_state, attr_mask);

	spin_lock_irqsave(&iwqp->lock, flags);
	if (attr_mask & IB_QP_STATE) {
		info.curr_iwarp_state = iwqp->iwarp_state;
		switch (attr->qp_state) {
		case IB_QPS_INIT:
		case IB_QPS_RTR:
			if (iwqp->iwarp_state > IRDMA_QP_STATE_IDLE) {
				err = -EINVAL;
				goto exit;
			}

			if (iwqp->iwarp_state == IRDMA_QP_STATE_INVALID) {
				info.next_iwarp_state = IRDMA_QP_STATE_IDLE;
				issue_modify_qp = 1;
			}
			if (iwdev->push_mode && udata &&
			    iwqp->sc_qp.push_idx == IRDMA_INVALID_PUSH_PAGE_INDEX) {
				spin_unlock_irqrestore(&iwqp->lock, flags);
				irdma_alloc_push_page(iwqp);
				spin_lock_irqsave(&iwqp->lock, flags);
			}
			break;
		case IB_QPS_RTS:
			if (iwqp->iwarp_state > IRDMA_QP_STATE_RTS ||
			    !iwqp->cm_id) {
				err = -EINVAL;
				goto exit;
			}

			issue_modify_qp = 1;
			iwqp->hw_tcp_state = IRDMA_TCP_STATE_ESTABLISHED;
			iwqp->hte_added = 1;
			info.next_iwarp_state = IRDMA_QP_STATE_RTS;
			info.tcp_ctx_valid = true;
			info.ord_valid = true;
			info.arp_cache_idx_valid = true;
			info.cq_num_valid = true;
			break;
		case IB_QPS_SQD:
			if (iwqp->hw_iwarp_state > IRDMA_QP_STATE_RTS) {
				err = 0;
				goto exit;
			}

			if (iwqp->iwarp_state == IRDMA_QP_STATE_CLOSING ||
			    iwqp->iwarp_state < IRDMA_QP_STATE_RTS) {
				err = 0;
				goto exit;
			}

			if (iwqp->iwarp_state > IRDMA_QP_STATE_CLOSING) {
				err = -EINVAL;
				goto exit;
			}

			info.next_iwarp_state = IRDMA_QP_STATE_CLOSING;
			issue_modify_qp = 1;
			break;
		case IB_QPS_SQE:
			if (iwqp->iwarp_state >= IRDMA_QP_STATE_TERMINATE) {
				err = -EINVAL;
				goto exit;
			}

			info.next_iwarp_state = IRDMA_QP_STATE_TERMINATE;
			issue_modify_qp = 1;
			break;
		case IB_QPS_ERR:
		case IB_QPS_RESET:
			if (iwqp->iwarp_state == IRDMA_QP_STATE_ERROR) {
				spin_unlock_irqrestore(&iwqp->lock, flags);
				if (udata && udata->inlen) {
					if (ib_copy_from_udata(&ureq, udata,
					    min(sizeof(ureq), udata->inlen)))
						return -EINVAL;

					irdma_flush_wqes(iwqp,
					    (ureq.sq_flush ? IRDMA_FLUSH_SQ : 0) |
					    (ureq.rq_flush ? IRDMA_FLUSH_RQ : 0) |
					    IRDMA_REFLUSH);
				}
				return 0;
			}

			if (iwqp->sc_qp.term_flags) {
				spin_unlock_irqrestore(&iwqp->lock, flags);
				irdma_terminate_del_timer(&iwqp->sc_qp);
				spin_lock_irqsave(&iwqp->lock, flags);
			}
			info.next_iwarp_state = IRDMA_QP_STATE_ERROR;
			if (iwqp->hw_tcp_state > IRDMA_TCP_STATE_CLOSED &&
			    iwdev->iw_status &&
			    iwqp->hw_tcp_state != IRDMA_TCP_STATE_TIME_WAIT)
				info.reset_tcp_conn = true;
			else
				dont_wait = 1;

			issue_modify_qp = 1;
			info.next_iwarp_state = IRDMA_QP_STATE_ERROR;
			break;
		default:
			err = -EINVAL;
			goto exit;
		}

		iwqp->ibqp_state = attr->qp_state;
	}
	if (attr_mask & IB_QP_ACCESS_FLAGS) {
		ctx_info->iwarp_info_valid = true;
		if (attr->qp_access_flags & IB_ACCESS_LOCAL_WRITE)
			offload_info->wr_rdresp_en = true;
		if (attr->qp_access_flags & IB_ACCESS_REMOTE_WRITE)
			offload_info->wr_rdresp_en = true;
		if (attr->qp_access_flags & IB_ACCESS_REMOTE_READ)
			offload_info->rd_en = true;
		if (attr->qp_access_flags & IB_ACCESS_REMOTE_ATOMIC)
			ctx_info->remote_atomics_en = true;
	}

	if (ctx_info->iwarp_info_valid) {
		ctx_info->send_cq_num = iwqp->iwscq->sc_cq.cq_uk.cq_id;
		ctx_info->rcv_cq_num = iwqp->iwrcq->sc_cq.cq_uk.cq_id;
		irdma_sc_qp_setctx(&iwqp->sc_qp, iwqp->host_ctx.va, ctx_info);
	}
	spin_unlock_irqrestore(&iwqp->lock, flags);

	if (attr_mask & IB_QP_STATE) {
		if (issue_modify_qp) {
			ctx_info->rem_endpoint_idx = tcp_info->arp_idx;
			if (irdma_hw_modify_qp(iwdev, iwqp, &info, true))
				return -EINVAL;
		}

		spin_lock_irqsave(&iwqp->lock, flags);
		if (iwqp->iwarp_state == info.curr_iwarp_state) {
			iwqp->iwarp_state = info.next_iwarp_state;
			iwqp->ibqp_state = attr->qp_state;
			iwqp->sc_qp.qp_state = iwqp->iwarp_state;
		}
		spin_unlock_irqrestore(&iwqp->lock, flags);
	}

	if (issue_modify_qp && iwqp->ibqp_state > IB_QPS_RTS) {
		if (dont_wait) {
			if (iwqp->hw_tcp_state) {
				spin_lock_irqsave(&iwqp->lock, flags);
				iwqp->hw_tcp_state = IRDMA_TCP_STATE_CLOSED;
				iwqp->last_aeq = IRDMA_AE_RESET_SENT;
				spin_unlock_irqrestore(&iwqp->lock, flags);
			}
			irdma_cm_disconn(iwqp);
		} else {
			int close_timer_started;

			spin_lock_irqsave(&iwdev->cm_core.ht_lock, flags);

			if (iwqp->cm_node) {
				refcount_inc(&iwqp->cm_node->refcnt);
				spin_unlock_irqrestore(&iwdev->cm_core.ht_lock, flags);
				close_timer_started = atomic_inc_return(&iwqp->close_timer_started);
				if (iwqp->cm_id && close_timer_started == 1)
					irdma_schedule_cm_timer(iwqp->cm_node,
						(struct irdma_puda_buf *)iwqp,
						IRDMA_TIMER_TYPE_CLOSE, 1, 0);

				irdma_rem_ref_cm_node(iwqp->cm_node);
			} else {
				spin_unlock_irqrestore(&iwdev->cm_core.ht_lock, flags);
			}
		}
	}
	if (attr_mask & IB_QP_STATE && udata && udata->outlen &&
	    dev->hw_attrs.uk_attrs.hw_rev >= IRDMA_GEN_2) {
		struct irdma_ucontext *ucontext;

		ucontext = kc_rdma_udata_to_drv_context(ibqp, udata);
		if (iwqp->sc_qp.push_idx != IRDMA_INVALID_PUSH_PAGE_INDEX &&
		    !iwqp->push_wqe_mmap_entry &&
		    !irdma_setup_push_mmap_entries(ucontext, iwqp,
			&uresp.push_wqe_mmap_key, &uresp.push_db_mmap_key)) {
			uresp.push_valid = 1;
			uresp.push_offset = iwqp->sc_qp.push_offset;
		}
		uresp.rd_fence_rate = iwdev->rd_fence_rate;

		err = ib_copy_to_udata(udata, &uresp, min(sizeof(uresp),
				       udata->outlen));
		if (err) {
			irdma_remove_push_mmap_entries(iwqp);
			ibdev_dbg(&iwdev->ibdev,
				  "VERBS: copy_to_udata failed\n");
			return err;
		}
	}

	return 0;
exit:
	spin_unlock_irqrestore(&iwqp->lock, flags);

	return err;
}

/**
 * irdma_srq_free_rsrc - free up resources for srq
 * @rf: RDMA PCI function
 * @iwsrq: srq ptr
 */
void irdma_srq_free_rsrc(struct irdma_pci_f *rf, struct irdma_srq *iwsrq)
{
	struct irdma_sc_srq *srq = &iwsrq->sc_srq;

	if (!iwsrq->user_mode) {
		dma_free_coherent(rf->sc_dev.hw->device, iwsrq->kmem.size,
				  iwsrq->kmem.va, iwsrq->kmem.pa);
		iwsrq->kmem.va = NULL;
	}

	irdma_free_rsrc(rf, rf->allocated_srqs, srq->srq_uk.srq_id);
}

/**
 * irdma_cq_free_rsrc - free up resources for cq
 * @rf: RDMA PCI function
 * @iwcq: cq ptr
 */
void irdma_cq_free_rsrc(struct irdma_pci_f *rf, struct irdma_cq *iwcq)
{
	struct irdma_sc_cq *cq = &iwcq->sc_cq;

	if (!iwcq->user_mode) {
		dma_free_coherent(rf->sc_dev.hw->device, iwcq->kmem.size,
				  iwcq->kmem.va, iwcq->kmem.pa);
		iwcq->kmem.va = NULL;
		dma_free_coherent(rf->sc_dev.hw->device,
				  iwcq->kmem_shadow.size,
				  iwcq->kmem_shadow.va, iwcq->kmem_shadow.pa);
		iwcq->kmem_shadow.va = NULL;
	}

	irdma_free_rsrc(rf, rf->allocated_cqs, cq->cq_uk.cq_id);
}

/**
 * irdma_free_cqbuf - worker to free a cq buffer
 * @work: provides access to the cq buffer to free
 */
static void irdma_free_cqbuf(struct work_struct *work)
{
	struct irdma_cq_buf *cq_buf = container_of(work, struct irdma_cq_buf, work);

	dma_free_coherent(cq_buf->hw->device, cq_buf->kmem_buf.size,
			  cq_buf->kmem_buf.va, cq_buf->kmem_buf.pa);
	cq_buf->kmem_buf.va = NULL;
	kfree(cq_buf);
}

/**
 * irdma_process_resize_list - remove resized cq buffers from the resize_list
 * @iwcq: cq which owns the resize_list
 * @iwdev: irdma device
 * @lcqe_buf: the buffer where the last cqe is received
 */
int irdma_process_resize_list(struct irdma_cq *iwcq,
			      struct irdma_device *iwdev,
			      struct irdma_cq_buf *lcqe_buf)
{
	struct list_head *tmp_node, *list_node;
	struct irdma_cq_buf *cq_buf;
	int cnt = 0;

	list_for_each_safe(list_node, tmp_node, &iwcq->resize_list) {
		cq_buf = list_entry(list_node, struct irdma_cq_buf, list);
		if (cq_buf == lcqe_buf)
			return cnt;

		list_del(&cq_buf->list);
		queue_work(iwdev->cleanup_wq, &cq_buf->work);
		cnt++;
	}

	return cnt;
}

/**
 * irdma_resize_cq - resize cq
 * @ibcq: cq to be resized
 * @entries: desired cq size
 * @udata: user data
 */
static int irdma_resize_cq(struct ib_cq *ibcq, int entries,
			   struct ib_udata *udata)
{
#define IRDMA_RESIZE_CQ_MIN_REQ_LEN offsetofend(struct irdma_resize_cq_req, user_cq_buffer)
	struct irdma_cq *iwcq = to_iwcq(ibcq);
	struct irdma_sc_dev *dev = iwcq->sc_cq.dev;
	struct irdma_cqp_request *cqp_request;
	struct cqp_cmds_info *cqp_info;
	struct irdma_modify_cq_info *m_info;
	struct irdma_modify_cq_info info = {};
	struct irdma_dma_mem kmem_buf;
	struct irdma_cq_mr *cqmr_buf;
	struct irdma_pbl *iwpbl_buf;
	struct irdma_device *iwdev;
	struct irdma_pci_f *rf;
	struct irdma_cq_buf *cq_buf = NULL;
	unsigned long flags;
	int ret;

	iwdev = to_iwdev(ibcq->device);
	rf = iwdev->rf;

	if (!(rf->sc_dev.hw_attrs.uk_attrs.feature_flags &
	    IRDMA_FEATURE_CQ_RESIZE))
		return -EOPNOTSUPP;

	if (udata && udata->inlen < IRDMA_RESIZE_CQ_MIN_REQ_LEN)
		return -EINVAL;

	if (entries > rf->max_cqe)
		return -EINVAL;

	if (!iwcq->user_mode) {
		entries++;
		if (!iwcq->sc_cq.cq_uk.avoid_mem_cflct &&
		    dev->hw_attrs.uk_attrs.hw_rev >= IRDMA_GEN_2)
			entries *= 2;

		if (entries & 1)
			entries += 1; /* cq size must be an even number */
	}

	info.cq_size = max_t(int, entries, 4);

	if (info.cq_size == iwcq->sc_cq.cq_uk.cq_size - 1)
		return 0;

	if (udata) {
		struct irdma_resize_cq_req req = {};
		struct irdma_ucontext *ucontext =
			kc_rdma_udata_to_drv_context(ibcq, udata);

		/* CQ resize not supported with legacy GEN_1 libi40iw */
		if (ucontext->legacy_mode)
			return -EOPNOTSUPP;

		if (ib_copy_from_udata(&req, udata,
				       min(sizeof(req), udata->inlen)))
			return -EINVAL;

		spin_lock_irqsave(&ucontext->cq_reg_mem_list_lock, flags);
		iwpbl_buf = irdma_get_pbl((unsigned long)req.user_cq_buffer,
					  &ucontext->cq_reg_mem_list);
		spin_unlock_irqrestore(&ucontext->cq_reg_mem_list_lock, flags);

		if (!iwpbl_buf)
			return -ENOMEM;

		cqmr_buf = &iwpbl_buf->cq_mr;
		if (iwpbl_buf->pbl_allocated) {
			info.virtual_map = true;
			info.pbl_chunk_size = 1;
			info.first_pm_pbl_idx = cqmr_buf->cq_pbl.idx;
		} else {
			info.cq_pa = cqmr_buf->cq_pbl.addr;
		}
	} else {
		/* Kmode CQ resize */
		int rsize;

		rsize = info.cq_size * sizeof(struct irdma_cqe);
		kmem_buf.size = ALIGN(round_up(rsize, 256), 256);
		kmem_buf.va = dma_alloc_coherent(dev->hw->device,
						 kmem_buf.size, &kmem_buf.pa,
						 GFP_KERNEL);
		if (!kmem_buf.va)
			return -ENOMEM;

		info.cq_base = kmem_buf.va;
		info.cq_pa = kmem_buf.pa;
		cq_buf = kzalloc(sizeof(*cq_buf), GFP_KERNEL);
		if (!cq_buf) {
			ret = -ENOMEM;
			goto error;
		}
	}

	cqp_request = irdma_alloc_and_get_cqp_request(&rf->cqp, true);
	if (!cqp_request) {
		ret = -ENOMEM;
		goto error;
	}

	info.shadow_read_threshold = iwcq->sc_cq.shadow_read_threshold;
	info.cq_resize = true;

	cqp_info = &cqp_request->info;
	m_info = &cqp_info->in.u.cq_modify.info;
	memcpy(m_info, &info, sizeof(*m_info));

	cqp_info->cqp_cmd = IRDMA_OP_CQ_MODIFY;
	cqp_info->in.u.cq_modify.cq = &iwcq->sc_cq;
	cqp_info->in.u.cq_modify.scratch = (uintptr_t)cqp_request;
	cqp_info->post_sq = 1;
	cqp_info->create = true;
	ret = irdma_handle_cqp_op(rf, cqp_request);
	irdma_put_cqp_request(&rf->cqp, cqp_request);
	if (ret)
		goto error;

	spin_lock_irqsave(&iwcq->lock, flags);
	if (cq_buf) {
		cq_buf->kmem_buf = iwcq->kmem;
		cq_buf->hw = dev->hw;
		memcpy(&cq_buf->cq_uk, &iwcq->sc_cq.cq_uk, sizeof(cq_buf->cq_uk));
		INIT_WORK(&cq_buf->work, irdma_free_cqbuf);
		list_add_tail(&cq_buf->list, &iwcq->resize_list);
		iwcq->kmem = kmem_buf;
	}

	irdma_sc_cq_resize(&iwcq->sc_cq, &info);
	ibcq->cqe = info.cq_size - 1;
	spin_unlock_irqrestore(&iwcq->lock, flags);

	return 0;
error:
	if (!udata) {
		dma_free_coherent(dev->hw->device, kmem_buf.size, kmem_buf.va,
				  kmem_buf.pa);
		kmem_buf.va = NULL;
	}
	kfree(cq_buf);

	return ret;
}

/**
 * irdma_srq_event - event notification for srq limit
 * @srq: shared srq struct
 */
void irdma_srq_event(struct irdma_sc_srq *srq)
{
	struct irdma_srq *iwsrq = container_of(srq, struct irdma_srq, sc_srq);
	struct ib_srq *ibsrq = &iwsrq->ibsrq;
	struct ib_event event;

	srq->srq_limit = 0;

	if (!ibsrq->event_handler)
		return;

	event.device = ibsrq->device;
	event.element.port_num = 1;
	event.element.srq = ibsrq;
	event.event = IB_EVENT_SRQ_LIMIT_REACHED;
	ibsrq->event_handler(&event, ibsrq->srq_context);
}

/**
 * irdma_modify_srq - modify srq request
 * @ibsrq: srq's pointer for modify
 * @attr: access attributes
 * @attr_mask: state mask
 * @udata: user data
 */
static int irdma_modify_srq(struct ib_srq *ibsrq, struct ib_srq_attr *attr,
			    enum ib_srq_attr_mask attr_mask,
			    struct ib_udata *udata)
{
	struct irdma_device *iwdev = to_iwdev(ibsrq->device);
	struct irdma_srq *iwsrq = to_iwsrq(ibsrq);
	struct irdma_cqp_request *cqp_request;
	struct irdma_pci_f *rf = iwdev->rf;
	struct irdma_modify_srq_info *info;
	struct cqp_cmds_info *cqp_info;
	int status;

	if (attr_mask & IB_SRQ_MAX_WR)
		return -EINVAL;

	if (!(attr_mask & IB_SRQ_LIMIT))
		return 0;

	if (attr->srq_limit > iwsrq->sc_srq.srq_uk.srq_size)
		return -EINVAL;

	/* Execute this cqp op synchronously, so we can update srq_limit
	 * upon successful completion.
	 */
	cqp_request = irdma_alloc_and_get_cqp_request(&rf->cqp, true);
	if (!cqp_request)
		return -ENOMEM;

	cqp_info = &cqp_request->info;
	info = &cqp_info->in.u.srq_modify.info;
	info->srq_limit = attr->srq_limit;
	if (info->srq_limit > 0xFFF)
		info->srq_limit = 0xFFF;
	info->arm_limit_event = 1;

	cqp_info->cqp_cmd = IRDMA_OP_SRQ_MODIFY;
	cqp_info->post_sq = 1;
	cqp_info->in.u.srq_modify.srq = &iwsrq->sc_srq;
	cqp_info->in.u.srq_modify.scratch = (uintptr_t)cqp_request;
	cqp_info->create = true;
	status = irdma_handle_cqp_op(rf, cqp_request);
	irdma_put_cqp_request(&rf->cqp, cqp_request);
	if (status)
		return status;

	iwsrq->sc_srq.srq_limit = info->srq_limit;

	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0) || defined(RHEL_8_2) || defined(RHEL_8_3) || defined(RHEL_8_4) || defined(RHEL_8_5) || defined(RHEL_8_6) || defined(RHEL_8_7) || defined(RHEL_8_8)
static int irdma_setup_umode_srq(struct irdma_device *iwdev,
				 struct irdma_srq *iwsrq,
				 struct irdma_srq_init_info *info,
				 struct ib_udata *udata)
#else
static int irdma_setup_umode_srq(struct irdma_device *iwdev,
				 struct irdma_srq *iwsrq,
				 struct irdma_srq_init_info *info,
				 struct ib_pd *pd,
				 struct ib_udata *udata)
#endif
{
#define IRDMA_CREATE_SRQ_MIN_REQ_LEN offsetofend(struct irdma_create_srq_req, user_shadow_area)
	struct irdma_create_srq_req req = {};
	struct irdma_ucontext *ucontext;
	struct irdma_srq_mr *srqmr;
	struct irdma_pbl *iwpbl;
	unsigned long flags;
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 2, 0) && !defined(RHEL_8_2) && !defined(RHEL_8_3) && !defined(RHEL_8_4) && !defined(RHEL_8_5) && !defined(RHEL_8_6) && !defined(RHEL_8_7) && !defined(RHEL_8_8)
	struct ib_ucontext *context;
#endif

	iwsrq->user_mode = true;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0) || defined(RHEL_8_2) || defined(RHEL_8_3) || defined(RHEL_8_4) || defined(RHEL_8_5) || defined(RHEL_8_6) || defined(RHEL_8_7) || defined(RHEL_8_8)
	ucontext = rdma_udata_to_drv_context(udata, struct irdma_ucontext,
					     ibucontext);
#else
	context = pd->uobject ? pd->uobject->context : NULL;
	ucontext = kc_get_ucontext(udata);
#endif

	if (udata->inlen < IRDMA_CREATE_SRQ_MIN_REQ_LEN)
		return -EINVAL;

	if (ib_copy_from_udata(&req, udata,
			       min(sizeof(req), udata->inlen)))
		return -EFAULT;

	spin_lock_irqsave(&ucontext->srq_reg_mem_list_lock, flags);
	iwpbl = irdma_get_pbl((unsigned long)req.user_srq_buf,
			      &ucontext->srq_reg_mem_list);
	spin_unlock_irqrestore(&ucontext->srq_reg_mem_list_lock, flags);
	if (!iwpbl)
		return -EPROTO;

	iwsrq->iwpbl = iwpbl;
	srqmr = &iwpbl->srq_mr;

	if (iwpbl->pbl_allocated) {
		info->virtual_map = true;
		info->pbl_chunk_size = 1;
		info->first_pm_pbl_idx = srqmr->srq_pbl.idx;
		info->leaf_pbl_size = 1;
	} else {
		info->srq_pa = srqmr->srq_pbl.addr;
	}
	info->shadow_area_pa = srqmr->shadow;

	return 0;
}

static int irdma_setup_kmode_srq(struct irdma_device *iwdev,
				 struct irdma_srq *iwsrq,
				 struct irdma_srq_init_info *info, u32 depth,
				 u8 shift)
{
	struct irdma_srq_uk_init_info *ukinfo = &info->srq_uk_init_info;
	struct irdma_dma_mem *mem = &iwsrq->kmem;
	u32 size, ring_size;

	ring_size = depth * IRDMA_QP_WQE_MIN_SIZE;
	size = ring_size + (IRDMA_SHADOW_AREA_SIZE << 3);

	mem->size = ALIGN(size, 256);
	mem->va = dma_alloc_coherent(iwdev->rf->hw.device, mem->size,
				     &mem->pa, GFP_KERNEL);
	if (!mem->va)
		return -ENOMEM;

	ukinfo->srq = mem->va;
	ukinfo->srq_size = depth >> shift;
	ukinfo->shadow_area = mem->va + ring_size;

	info->shadow_area_pa = info->srq_pa + ring_size;
	info->srq_pa = mem->pa;

	return 0;
}

/**
 * irdma_create_srq - create srq
 * @ibsrq: ib's srq pointer
 * @initattrs: attributes for srq
 * @udata: user data for create srq
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0) || defined(RHEL_8_2) || defined(RHEL_8_3) || defined(RHEL_8_4) || defined(RHEL_8_5) || defined(RHEL_8_6) || defined(RHEL_8_7) || defined(RHEL_8_8)
static int irdma_create_srq(struct ib_srq *ibsrq,
			    struct ib_srq_init_attr *initattrs,
			    struct ib_udata *udata)
{
	struct irdma_device *iwdev = to_iwdev(ibsrq->device);
	struct ib_srq_attr *attr = &initattrs->attr;
	struct irdma_pd *iwpd = to_iwpd(ibsrq->pd);
	struct irdma_srq *iwsrq = to_iwsrq(ibsrq);
#else
static struct ib_srq *irdma_create_srq(struct ib_pd *ibpd,
				       struct ib_srq_init_attr *initattrs,
				       struct ib_udata *udata)
{
	struct irdma_device *iwdev = to_iwdev(ibpd->device);
	struct ib_srq_attr *attr = &initattrs->attr;
	struct irdma_pd *iwpd = to_iwpd(ibpd);
	struct irdma_srq *iwsrq;
#endif
	struct irdma_srq_uk_init_info *ukinfo;
	struct irdma_cqp_request *cqp_request;
	struct irdma_srq_init_info info = {};
	struct irdma_pci_f *rf = iwdev->rf;
	struct irdma_uk_attrs *uk_attrs;
	struct cqp_cmds_info *cqp_info;
	int err_code = 0;
	u32 depth;
	u8 shift;

	uk_attrs = &rf->sc_dev.hw_attrs.uk_attrs;
	ukinfo = &info.srq_uk_init_info;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 2, 0) && !defined(RHEL_8_2) && !defined(RHEL_8_3) && !defined(RHEL_8_4) && !defined(RHEL_8_5) && !defined(RHEL_8_6) && !defined(RHEL_8_7) && !defined(RHEL_8_8)
	if (initattrs->srq_type != IB_SRQT_BASIC)
		return ERR_PTR(-EOPNOTSUPP);

	iwsrq = kzalloc(sizeof(*iwsrq), GFP_KERNEL);
	if (!iwsrq)
		return ERR_PTR(-ENOMEM);
#else
	if (initattrs->srq_type != IB_SRQT_BASIC)
		return -EOPNOTSUPP;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0) || defined(RHEL_8_2) || defined(RHEL_8_3) || defined(RHEL_8_4) || defined(RHEL_8_5) || defined(RHEL_8_6) || defined(RHEL_8_7) || defined(RHEL_8_8)
	if (!(uk_attrs->feature_flags & IRDMA_FEATURE_SRQ) ||
	    attr->max_sge > uk_attrs->max_hw_wq_frags)
		return -EINVAL;
#else
	if (!(uk_attrs->feature_flags & IRDMA_FEATURE_SRQ) ||
	    attr->max_sge > uk_attrs->max_hw_wq_frags) {
		err_code = -EINVAL;
		goto error;
	}
#endif

	iwsrq->sg_list = kcalloc(uk_attrs->max_hw_wq_frags, sizeof(*iwsrq->sg_list),
				 GFP_KERNEL);
	if (!iwsrq->sg_list) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 2, 0) && !defined(RHEL_8_2) && !defined(RHEL_8_3) && !defined(RHEL_8_4) && !defined(RHEL_8_5) && !defined(RHEL_8_6) && !defined(RHEL_8_7) && !defined(RHEL_8_8)
		err_code = -ENOMEM;
		goto error;
#else
		return -ENOMEM;
#endif
	}

	refcount_set(&iwsrq->refcnt, 1);
	spin_lock_init(&iwsrq->lock);
	err_code = irdma_alloc_rsrc(rf, rf->allocated_srqs, rf->max_srq,
				    &iwsrq->srq_num, &rf->next_srq);
	if (err_code)
		goto free_sg_list;

	ukinfo->max_srq_frag_cnt = attr->max_sge;
	ukinfo->uk_attrs = uk_attrs;
	ukinfo->srq_id = iwsrq->srq_num;

	irdma_get_wqe_shift(ukinfo->uk_attrs, ukinfo->max_srq_frag_cnt, 0,
			    &shift);

	err_code = irdma_get_srqdepth(ukinfo->uk_attrs, attr->max_wr, shift, &depth);
	if (err_code)
		goto free_sg_list;

	/* Actual SRQ size in WRs for ring and HW */
	ukinfo->srq_size = depth >> shift;

	/* Max postable WRs to SRQ */
	iwsrq->max_wr = (depth - IRDMA_RQ_RSVD) >> shift;
	attr->max_wr = iwsrq->max_wr;

	if (udata)
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 2, 0) && !defined(RHEL_8_2) && !defined(RHEL_8_3) && !defined(RHEL_8_4) && !defined(RHEL_8_5) && !defined(RHEL_8_6) && !defined(RHEL_8_7) && !defined(RHEL_8_8)
		err_code = irdma_setup_umode_srq(iwdev, iwsrq, &info, ibpd, udata);
#else
		err_code = irdma_setup_umode_srq(iwdev, iwsrq, &info, udata);
#endif
	else
		err_code = irdma_setup_kmode_srq(iwdev, iwsrq, &info, depth, shift);

	if (err_code)
		goto free_rsrc;

	info.vsi = &iwdev->vsi;
	info.pd = &iwpd->sc_pd;

	err_code = irdma_sc_srq_init(&iwsrq->sc_srq, &info);
	if (err_code)
		goto free_dmem;

	cqp_request = irdma_alloc_and_get_cqp_request(&rf->cqp, true);
	if (!cqp_request) {
		err_code = -ENOMEM;
		goto free_dmem;
	}

	cqp_info = &cqp_request->info;
	cqp_info->cqp_cmd = IRDMA_OP_SRQ_CREATE;
	cqp_info->post_sq = 1;
	cqp_info->in.u.srq_create.srq = &iwsrq->sc_srq;
	cqp_info->in.u.srq_create.scratch = (uintptr_t)cqp_request;
	cqp_info->create = true;
	err_code = irdma_handle_cqp_op(rf, cqp_request);
	irdma_put_cqp_request(&rf->cqp, cqp_request);
	if (err_code)
		goto free_dmem;

	if (udata) {
		struct irdma_create_srq_resp resp = {};

		resp.srq_id = iwsrq->srq_num;
		resp.srq_size = ukinfo->srq_size;
		if (ib_copy_to_udata(udata, &resp,
				     min(sizeof(resp), udata->outlen))) {
			err_code = -EPROTO;
			goto srq_destroy;
		}
	}

	rf->srq_table[iwsrq->srq_num] = iwsrq;
	init_completion(&iwsrq->free_srq);

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 2, 0) && !defined(RHEL_8_2) && !defined(RHEL_8_3) && !defined(RHEL_8_4) && !defined(RHEL_8_5) && !defined(RHEL_8_6) && !defined(RHEL_8_7) && !defined(RHEL_8_8)
	return &iwsrq->ibsrq;
#else
	return 0;
#endif

srq_destroy:
	irdma_srq_wq_destroy(rf, &iwsrq->sc_srq);

free_dmem:
	if (!iwsrq->user_mode)
		dma_free_coherent(rf->hw.device, iwsrq->kmem.size,
				  iwsrq->kmem.va, iwsrq->kmem.pa);
free_rsrc:
	irdma_free_rsrc(rf, rf->allocated_srqs, iwsrq->srq_num);
free_sg_list:
	kfree(iwsrq->sg_list);
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 2, 0) && !defined(RHEL_8_2) && !defined(RHEL_8_3) && !defined(RHEL_8_4) && !defined(RHEL_8_5) && !defined(RHEL_8_6) && !defined(RHEL_8_7) && !defined(RHEL_8_8)
error:
	kfree(iwsrq);
	return ERR_PTR(err_code);
#else
	return err_code;
#endif
}

/**
 * irdma_query_srq - get SRQ attributes
 * @ibsrq: the SRQ to query
 * @attr: the attributes of the SRQ
 */
static int irdma_query_srq(struct ib_srq *ibsrq, struct ib_srq_attr *attr)
{
	struct irdma_srq *iwsrq = to_iwsrq(ibsrq);

	attr->max_wr = iwsrq->max_wr;
	attr->max_sge = iwsrq->sc_srq.srq_uk.max_srq_frag_cnt;
	attr->srq_limit = iwsrq->sc_srq.srq_limit;

	return 0;
}

/**
 * irdma_get_mr_access - get hw MR access permissions from IB access flags
 * @access: IB access flags
 * @hw_rev: Hardware version
 */
static inline u16 irdma_get_mr_access(int access, u8 hw_rev)
{
	u16 hw_access = 0;

	hw_access |= (access & IB_ACCESS_LOCAL_WRITE) ?
		     IRDMA_ACCESS_FLAGS_LOCALWRITE : 0;
	hw_access |= (access & IB_ACCESS_REMOTE_WRITE) ?
		     IRDMA_ACCESS_FLAGS_REMOTEWRITE : 0;
	hw_access |= (access & IB_ACCESS_REMOTE_READ) ?
		     IRDMA_ACCESS_FLAGS_REMOTEREAD : 0;
	if (hw_rev >= IRDMA_GEN_3) {
		hw_access |= (access & IB_ACCESS_MW_BIND) ?
			     IRDMA_ACCESS_FLAGS_BIND_WINDOW : 0;
	}
	hw_access |= (access & IB_ZERO_BASED) ?
		     IRDMA_ACCESS_FLAGS_ZERO_BASED : 0;
	hw_access |= IRDMA_ACCESS_FLAGS_LOCALREAD;

	return hw_access;
}

/**
 * irdma_free_stag - free stag resource
 * @iwdev: irdma device
 * @stag: stag to free
 */
void irdma_free_stag(struct irdma_device *iwdev, u32 stag)
{
	u32 stag_idx;

	stag_idx = (stag & iwdev->rf->mr_stagmask) >> IRDMA_CQPSQ_STAG_IDX_S;
	if (iwdev->rf->sc_dev.hw_wa & NO_STAG0 && stag_idx == 1)
		return;
	irdma_free_rsrc(iwdev->rf, iwdev->rf->allocated_mrs, stag_idx);
}

/**
 * irdma_create_stag - create random stag
 * @iwdev: irdma device
 */
u32 irdma_create_stag(struct irdma_device *iwdev)
{
	u32 stag;
	u32 stag_index = 0;
	u32 next_stag_index;
	u32 driver_key;
	u32 random;
	u8 consumer_key;
	int ret;

	get_random_bytes(&random, sizeof(random));
	consumer_key = (u8)random;

	driver_key = random & ~iwdev->rf->mr_stagmask;
	next_stag_index = (random & iwdev->rf->mr_stagmask) >> 8;
	next_stag_index %= iwdev->rf->max_mr;

	ret = irdma_alloc_rsrc(iwdev->rf, iwdev->rf->allocated_mrs,
			       iwdev->rf->max_mr, &stag_index,
			       &next_stag_index);
	if (ret)
		return 0;
	stag = stag_index << IRDMA_CQPSQ_STAG_IDX_S;
	stag |= driver_key;
	stag += (u32)consumer_key;

	return stag;
}

#ifndef COPY_USER_PGADDR_VER_1
/**
 * irdma_next_pbl_addr - Get next pbl address
 * @pbl: pointer to a pble
 * @pinfo: info pointer
 * @idx: index
 */
static inline u64 *irdma_next_pbl_addr(u64 *pbl, struct irdma_pble_info **pinfo,
				       u32 *idx)
{
	*idx += 1;
	if (!(*pinfo) || *idx != (*pinfo)->cnt)
		return ++pbl;
	*idx = 0;
	(*pinfo)++;

	return (*pinfo)->addr;
}

/**
 * irdma_copy_user_pgaddrs - copy user page address to pble's os locally
 * @iwmr: iwmr for IB's user page addresses
 * @pbl: ple pointer to save 1 level or 0 level pble
 * @level: indicated level 0, 1 or 2
 */
static void irdma_copy_user_pgaddrs(struct irdma_mr *iwmr, u64 *pbl,
				    enum irdma_pble_level level)
{
	struct ib_umem *region = iwmr->region;
	struct irdma_pbl *iwpbl = &iwmr->iwpbl;
	struct irdma_pble_alloc *palloc = &iwpbl->pble_alloc;
	struct irdma_pble_info *pinfo;
	struct ib_block_iter biter;
	u32 idx = 0;
	u32 pbl_cnt = 0;

	pinfo = (level == PBLE_LEVEL_1) ? NULL : palloc->level2.leaf;

	if (iwmr->type == IRDMA_MEMREG_TYPE_QP)
#ifdef HAVE_IB_UMEM_SG_HEAD
		iwpbl->qp_mr.sq_page = sg_page(region->sg_head.sgl);
#else
		iwpbl->qp_mr.sq_page = sg_page(region->sgt_append.sgt.sgl);
#endif

	rdma_umem_for_each_dma_block(region, &biter, iwmr->page_size) {
		*pbl = rdma_block_iter_dma_address(&biter);
		if (++pbl_cnt == palloc->total_cnt)
			break;
		pbl = irdma_next_pbl_addr(pbl, &pinfo, &idx);
	}
}

#endif /* !COPY_USER_PGADDR_VER_1 */
/**
 * irdma_check_mem_contiguous - check if pbls stored in arr are contiguous
 * @arr: lvl1 pbl array
 * @npages: page count
 * @pg_size: page size
 *
 */
static bool irdma_check_mem_contiguous(u64 *arr, u32 npages, u32 pg_size)
{
	u32 pg_idx;

	for (pg_idx = 0; pg_idx < npages; pg_idx++) {
		if ((*arr + (pg_size * pg_idx)) != arr[pg_idx])
			return false;
	}

	return true;
}

/**
 * irdma_check_mr_contiguous - check if MR is physically contiguous
 * @palloc: pbl allocation struct
 * @pg_size: page size
 */
static bool irdma_check_mr_contiguous(struct irdma_pble_alloc *palloc,
				      u32 pg_size)
{
	struct irdma_pble_level2 *lvl2 = &palloc->level2;
	struct irdma_pble_info *leaf = lvl2->leaf;
	u64 *arr = NULL;
	u64 *start_addr = NULL;
	int i;
	bool ret;

	if (palloc->level == PBLE_LEVEL_1) {
		arr = palloc->level1.addr;
		ret = irdma_check_mem_contiguous(arr, palloc->total_cnt,
						 pg_size);
		return ret;
	}

	start_addr = leaf->addr;

	for (i = 0; i < lvl2->leaf_cnt; i++, leaf++) {
		arr = leaf->addr;
		if ((*start_addr + (i * pg_size * PBLE_PER_PAGE)) != *arr)
			return false;
		ret = irdma_check_mem_contiguous(arr, leaf->cnt, pg_size);
		if (!ret)
			return false;
	}

	return true;
}

/**
 * irdma_setup_pbles - copy user pg address to pble's
 * @rf: RDMA PCI function
 * @iwmr: mr pointer for this memory registration
 * @lvl: requested pble levels
 */
static int irdma_setup_pbles(struct irdma_pci_f *rf, struct irdma_mr *iwmr,
			     u8 lvl)
{
	struct irdma_pbl *iwpbl = &iwmr->iwpbl;
	struct irdma_pble_alloc *palloc = &iwpbl->pble_alloc;
	struct irdma_pble_info *pinfo;
	u64 *pbl;
	int status;
	enum irdma_pble_level level = PBLE_LEVEL_1;

	if (lvl) {
		status = irdma_get_pble(rf->pble_rsrc, palloc, iwmr->page_cnt,
					lvl);
		if (status)
			return status;

		iwpbl->pbl_allocated = true;
		level = palloc->level;
		pinfo = (level == PBLE_LEVEL_1) ? &palloc->level1 :
						  palloc->level2.leaf;
		pbl = pinfo->addr;
	} else {
		pbl = iwmr->pgaddrmem;
	}

	irdma_copy_user_pgaddrs(iwmr, pbl, level);

	if (lvl)
		iwmr->pgaddrmem[0] = *pbl;

	return 0;
}

/**
 * irdma_handle_q_mem - handle memory for qp and cq
 * @iwdev: irdma device
 * @req: information for q memory management
 * @iwpbl: pble struct
 * @lvl: pble level mask
 */
static int irdma_handle_q_mem(struct irdma_device *iwdev,
			      struct irdma_mem_reg_req *req,
			      struct irdma_pbl *iwpbl, u8 lvl)
{
	struct irdma_pble_alloc *palloc = &iwpbl->pble_alloc;
	struct irdma_mr *iwmr = iwpbl->iwmr;
	struct irdma_qp_mr *qpmr = &iwpbl->qp_mr;
	struct irdma_cq_mr *cqmr = &iwpbl->cq_mr;
	struct irdma_srq_mr *srqmr = &iwpbl->srq_mr;
	struct irdma_hmc_pble *hmc_p;
	u64 *arr = iwmr->pgaddrmem;
	u32 pg_size, total;
	int err = 0;
	bool ret = true;

	pg_size = iwmr->page_size;
	err = irdma_setup_pbles(iwdev->rf, iwmr, lvl);
	if (err)
		return err;

	if (lvl)
		arr = palloc->level1.addr;

	switch (iwmr->type) {
	case IRDMA_MEMREG_TYPE_QP:
		total = req->sq_pages + req->rq_pages;
		hmc_p = &qpmr->sq_pbl;
		qpmr->shadow = (dma_addr_t)arr[total];
		/* Need to use physical address for RQ of QP in case it is associated with SRQ */
		qpmr->rq_pa = (dma_addr_t)arr[req->sq_pages];
		if (lvl) {
			ret = irdma_check_mem_contiguous(arr, req->sq_pages,
							 pg_size);
			if (ret)
				ret = irdma_check_mem_contiguous(&arr[req->sq_pages],
								 req->rq_pages,
								 pg_size);
		}

		if (!ret) {
			hmc_p->idx = palloc->level1.idx;
			hmc_p = &qpmr->rq_pbl;
			hmc_p->idx = palloc->level1.idx + req->sq_pages;
		} else {
			hmc_p->addr = arr[0];
			hmc_p = &qpmr->rq_pbl;
			hmc_p->addr = arr[req->sq_pages];
		}
		break;
	case IRDMA_MEMREG_TYPE_SRQ:
		hmc_p = &srqmr->srq_pbl;
		srqmr->shadow = (dma_addr_t)arr[req->rq_pages];
		if (lvl)
			ret = irdma_check_mem_contiguous(arr, req->rq_pages,
							 pg_size);

		if (!ret)
			hmc_p->idx = palloc->level1.idx;
		else
			hmc_p->addr = arr[0];
	break;
	case IRDMA_MEMREG_TYPE_CQ:
		hmc_p = &cqmr->cq_pbl;

		if (!cqmr->split)
			cqmr->shadow = (dma_addr_t)arr[req->cq_pages];

		if (lvl)
			ret = irdma_check_mem_contiguous(arr, req->cq_pages,
							 pg_size);

		if (!ret)
			hmc_p->idx = palloc->level1.idx;
		else
			hmc_p->addr = arr[0];
	break;
	default:
		ibdev_dbg(&iwdev->ibdev, "VERBS: MR type error\n");
		err = -EINVAL;
	}

	if (lvl && ret) {
		irdma_free_pble(iwdev->rf->pble_rsrc, palloc);
		iwpbl->pbl_allocated = false;
	}

	return err;
}

/**
 * irdma_hw_alloc_mw - create the hw memory window
 * @iwdev: irdma device
 * @iwmr: pointer to memory window info
 */
int irdma_hw_alloc_mw(struct irdma_device *iwdev, struct irdma_mr *iwmr)
{
	struct irdma_mw_alloc_info *info;
	struct irdma_pd *iwpd = to_iwpd(iwmr->ibmr.pd);
	struct irdma_cqp_request *cqp_request;
	struct cqp_cmds_info *cqp_info;
	int status;

	cqp_request = irdma_alloc_and_get_cqp_request(&iwdev->rf->cqp, true);
	if (!cqp_request)
		return -ENOMEM;

	cqp_info = &cqp_request->info;
	info = &cqp_info->in.u.mw_alloc.info;
	if (iwmr->ibmw.type == IB_MW_TYPE_1)
		info->mw_wide = true;

	info->page_size = PAGE_SIZE;
	info->mw_stag_index = iwmr->stag >> IRDMA_CQPSQ_STAG_IDX_S;
	info->pd_id = iwpd->sc_pd.pd_id;
	info->remote_access = true;
	cqp_info->cqp_cmd = IRDMA_OP_MW_ALLOC;
	cqp_info->post_sq = 1;
	cqp_info->in.u.mw_alloc.dev = &iwdev->rf->sc_dev;
	cqp_info->in.u.mw_alloc.scratch = (uintptr_t)cqp_request;
	cqp_info->create = true;
	status = irdma_handle_cqp_op(iwdev->rf, cqp_request);
	irdma_put_cqp_request(&iwdev->rf->cqp, cqp_request);

	return status;
}

/**
 * irdma_dealloc_mw - Dealloc memory window
 * @ibmw: memory window structure.
 */
static int irdma_dealloc_mw(struct ib_mw *ibmw)
{
	struct ib_pd *ibpd = ibmw->pd;
	struct irdma_pd *iwpd = to_iwpd(ibpd);
	struct irdma_mr *iwmr = to_iwmr((struct ib_mr *)ibmw);
	struct irdma_device *iwdev = to_iwdev(ibmw->device);
	struct irdma_cqp_request *cqp_request;
	struct cqp_cmds_info *cqp_info;
	struct irdma_dealloc_stag_info *info;

	cqp_request = irdma_alloc_and_get_cqp_request(&iwdev->rf->cqp, true);
	if (!cqp_request)
		return -ENOMEM;

	cqp_info = &cqp_request->info;
	info = &cqp_info->in.u.dealloc_stag.info;
	info->pd_id = iwpd->sc_pd.pd_id;
	info->stag_idx = RS_64_1(ibmw->rkey, IRDMA_CQPSQ_STAG_IDX_S);
	info->mr = false;
	cqp_info->cqp_cmd = IRDMA_OP_DEALLOC_STAG;
	cqp_info->post_sq = 1;
	cqp_info->in.u.dealloc_stag.dev = &iwdev->rf->sc_dev;
	cqp_info->in.u.dealloc_stag.scratch = (uintptr_t)cqp_request;
	irdma_handle_cqp_op(iwdev->rf, cqp_request);
	irdma_put_cqp_request(&iwdev->rf->cqp, cqp_request);
	irdma_free_stag(iwdev, iwmr->stag);
#ifdef IRDMA_ALLOC_MW_VER_1
	kfree(iwmr);
#endif /* IRDMA_ALLOC_MW_VER_1 */

	return 0;
}

/**
 * irdma_hw_alloc_stag - cqp command to allocate stag
 * @iwdev: irdma device
 * @iwmr: irdma mr pointer
 */
int irdma_hw_alloc_stag(struct irdma_device *iwdev,
			struct irdma_mr *iwmr)
{
	struct irdma_allocate_stag_info *info;
	struct ib_pd *pd = iwmr->ibmr.pd;
	struct irdma_pd *iwpd = to_iwpd(pd);
	struct irdma_cqp_request *cqp_request;
	struct cqp_cmds_info *cqp_info;
	int status;

	cqp_request = irdma_alloc_and_get_cqp_request(&iwdev->rf->cqp, true);
	if (!cqp_request)
		return -ENOMEM;

	cqp_info = &cqp_request->info;
	info = &cqp_info->in.u.alloc_stag.info;
	info->page_size = PAGE_SIZE;
	info->stag_idx = iwmr->stag >> IRDMA_CQPSQ_STAG_IDX_S;
	info->pd_id = iwpd->sc_pd.pd_id;
	info->total_len = iwmr->len;
#ifndef RHEL_7_2
	info->all_memory = (pd->flags & IB_PD_UNSAFE_GLOBAL_RKEY) ? true : false;
#endif
	info->remote_access = true;
	if (iwdev->rf->sc_dev.hw_wa & STAG_ACC_RIGHTS)
		info->access_rights = 0xffff;
	cqp_info->cqp_cmd = IRDMA_OP_ALLOC_STAG;
	cqp_info->post_sq = 1;
	cqp_info->in.u.alloc_stag.dev = &iwdev->rf->sc_dev;
	cqp_info->in.u.alloc_stag.scratch = (uintptr_t)cqp_request;
	cqp_info->create = true;
	status = irdma_handle_cqp_op(iwdev->rf, cqp_request);
	irdma_put_cqp_request(&iwdev->rf->cqp, cqp_request);
	if (!status)
		iwmr->is_hwreg = 1;

	return status;
}

/**
 * irdma_set_page - populate pbl list for fmr
 * @ibmr: ib mem to access iwarp mr pointer
 * @addr: page dma address fro pbl list
 */
static int irdma_set_page(struct ib_mr *ibmr, u64 addr)
{
	struct irdma_mr *iwmr = to_iwmr(ibmr);
	struct irdma_pbl *iwpbl = &iwmr->iwpbl;
	struct irdma_pble_alloc *palloc = &iwpbl->pble_alloc;
	u64 *pbl;

	if (unlikely(iwmr->npages == iwmr->page_cnt))
		return -ENOMEM;

	if (palloc->level == PBLE_LEVEL_2) {
		struct irdma_pble_info *palloc_info =
			palloc->level2.leaf + (iwmr->npages >> PBLE_512_SHIFT);

		palloc_info->addr[iwmr->npages & (PBLE_PER_PAGE - 1)] = addr;
	} else {
		pbl = palloc->level1.addr;
		pbl[iwmr->npages] = addr;
	}

	iwmr->npages++;
	return 0;
}

/**
 * irdma_map_mr_sg - map of sg list for fmr
 * @ibmr: ib mem to access iwarp mr pointer
 * @sg: scatter gather list
 * @sg_nents: number of sg pages
 * @sg_offset: scatter gather list for fmr
 */
static int irdma_map_mr_sg(struct ib_mr *ibmr, struct scatterlist *sg,
			   int sg_nents, unsigned int *sg_offset)
{
	struct irdma_mr *iwmr = to_iwmr(ibmr);

	iwmr->npages = 0;

	return ib_sg_to_pages(ibmr, sg, sg_nents, sg_offset, irdma_set_page);
}

/**
 * irdma_hwreg_mr - send cqp command for memory registration
 * @iwdev: irdma device
 * @iwmr: irdma mr pointer
 * @access: access for MR
 */
int irdma_hwreg_mr(struct irdma_device *iwdev, struct irdma_mr *iwmr,
		   u16 access)
{
	struct irdma_pbl *iwpbl = &iwmr->iwpbl;
	struct irdma_reg_ns_stag_info *stag_info;
	struct ib_pd *pd = iwmr->ibmr.pd;
	struct irdma_pd *iwpd = to_iwpd(pd);
	struct irdma_pble_alloc *palloc = &iwpbl->pble_alloc;
	struct irdma_cqp_request *cqp_request;
	struct cqp_cmds_info *cqp_info;
	int ret;

	cqp_request = irdma_alloc_and_get_cqp_request(&iwdev->rf->cqp, true);
	if (!cqp_request)
		return -ENOMEM;

	cqp_info = &cqp_request->info;
	stag_info = &cqp_info->in.u.mr_reg_non_shared.info;
	stag_info->va = iwpbl->user_base;
	stag_info->stag_idx = iwmr->stag >> IRDMA_CQPSQ_STAG_IDX_S;
	stag_info->stag_key = (u8)iwmr->stag;
	stag_info->total_len = iwmr->len;
#ifndef RHEL_7_2
	if ((pd->flags & IB_PD_UNSAFE_GLOBAL_RKEY) || iwmr->dma_mr)
		stag_info->all_memory = true;
	else
		stag_info->all_memory = false;
#endif
	stag_info->access_rights = irdma_get_mr_access(access,
						       iwdev->rf->sc_dev.hw_attrs.uk_attrs.hw_rev);
	stag_info->remote_atomics_en = (access & IB_ACCESS_REMOTE_ATOMIC) ? 1 : 0;
	stag_info->pd_id = iwpd->sc_pd.pd_id;
	if (stag_info->access_rights & IRDMA_ACCESS_FLAGS_ZERO_BASED)
		stag_info->addr_type = IRDMA_ADDR_TYPE_ZERO_BASED;
	else
		stag_info->addr_type = IRDMA_ADDR_TYPE_VA_BASED;
	stag_info->page_size = iwmr->page_size;

	if (iwpbl->pbl_allocated) {
		if (palloc->level == PBLE_LEVEL_1) {
			stag_info->first_pm_pbl_index = palloc->level1.idx;
			stag_info->chunk_size = 1;
		} else {
			stag_info->first_pm_pbl_index = palloc->level2.root.idx;
			stag_info->chunk_size = 3;
		}
	} else {
		stag_info->reg_addr_pa = iwmr->pgaddrmem[0];
#ifdef CONFIG_DEBUG_FS
		iwmr->level0_pa = iwmr->pgaddrmem[0];
#endif
	}

	cqp_info->cqp_cmd = IRDMA_OP_MR_REG_NON_SHARED;
	cqp_info->post_sq = 1;
	cqp_info->in.u.mr_reg_non_shared.dev = &iwdev->rf->sc_dev;
	cqp_info->in.u.mr_reg_non_shared.scratch = (uintptr_t)cqp_request;
	cqp_info->create = true;
	ret = irdma_handle_cqp_op(iwdev->rf, cqp_request);
	irdma_put_cqp_request(&iwdev->rf->cqp, cqp_request);

	if (!ret)
		iwmr->is_hwreg = 1;

	return ret;
}

#ifdef SET_BEST_PAGE_SZ_V1
/**
 * irdma_set_best_pagesz - set MR best pg size and mask values.
 * @addr: virtual address
 * @iwmr: mr pointer for this memory registration
 * @page_size_cap: Page sizes supported
 */
static void irdma_set_best_pagesz(u64 addr, struct irdma_mr *iwmr, u64 page_size_cap)
{
	struct vm_area_struct *vma;
	struct hstate *h;

	if (!iwmr->region->hugetlb) {
		iwmr->page_size = IRDMA_HW_PAGE_SIZE;
		iwmr->page_msk = ~(IRDMA_HW_PAGE_SIZE - 1);
		return;
	}
	vma = find_vma(current->mm, addr);
	if (vma && is_vm_hugetlb_page(vma)) {
		h = hstate_vma(vma);
		if ((huge_page_size(h) == SZ_2M && (page_size_cap & SZ_2M)) ||
		    (huge_page_size(h) == SZ_1G && (page_size_cap & SZ_1G))) {
			iwmr->page_size = huge_page_size(h);
			iwmr->page_msk = huge_page_mask(h);
		}
	}
}

#endif
/*
 * irdma_alloc_iwmr - Allocate iwmr
 * @region - memory region
 * @pd - protection domain
 * @virt - virtual address
 * @reg_type - registration type
 */
#ifndef SET_BEST_PAGE_SZ_V1
struct irdma_mr *irdma_alloc_iwmr(struct ib_umem *region,
				  struct ib_pd *pd, u64 virt,
				  enum irdma_memreg_type reg_type)
#else
struct irdma_mr *irdma_alloc_iwmr(struct ib_umem *region,
				  struct ib_pd *pd, u64 virt, u64 start,
				  enum irdma_memreg_type reg_type)
#endif /* SET_BEST_PAGE_SZ_V1 */
{
#if defined(SET_BEST_PAGE_SZ_V2) || defined(SET_BEST_PAGE_SZ_V1)
	struct irdma_device *iwdev = to_iwdev(pd->device);
#endif
	struct irdma_pbl *iwpbl;
	struct irdma_mr *iwmr;
#ifdef SET_BEST_PAGE_SZ_V2
	unsigned long pgsz_bitmap;
#endif

	iwmr = kzalloc(sizeof(*iwmr), GFP_KERNEL);
	if (!iwmr)
		return ERR_PTR(-ENOMEM);

	iwpbl = &iwmr->iwpbl;
	iwpbl->iwmr = iwmr;
	iwmr->region = region;
	iwmr->ibmr.pd = pd;
	iwmr->ibmr.device = pd->device;
	iwmr->ibmr.iova = virt;
	iwmr->type = reg_type;

	/* Some OOT versions of irdma_copy_user_pg_addr require the pg mask */
	iwmr->page_msk = ~(IRDMA_HW_PAGE_SIZE - 1);
#ifdef SET_BEST_PAGE_SZ_V1
	iwmr->page_size = IRDMA_HW_PAGE_SIZE;
	if (reg_type == IRDMA_MEMREG_TYPE_MEM)
		irdma_set_best_pagesz(start, iwmr,
				      iwdev->rf->sc_dev.hw_attrs.page_size_cap);
#endif
#ifdef SET_BEST_PAGE_SZ_V2
	pgsz_bitmap = (reg_type == IRDMA_MEMREG_TYPE_MEM) ?
		iwdev->rf->sc_dev.hw_attrs.page_size_cap : PAGE_SIZE;

	iwmr->page_size = ib_umem_find_best_pgsz(region, pgsz_bitmap, virt);
	if (unlikely(!iwmr->page_size)) {
		kfree(iwmr);
		return ERR_PTR(-EOPNOTSUPP);
	}

#endif
	iwmr->len = region->length;
	iwpbl->user_base = virt;
#ifdef HAVE_IB_UMEM_NUM_DMA_BLOCKS
	iwmr->page_cnt = ib_umem_num_dma_blocks(region, iwmr->page_size);
#else
	iwmr->page_cnt = irdma_ib_umem_num_dma_blocks(region, iwmr->page_size, virt);
#endif

	return iwmr;
}

void irdma_free_iwmr(struct irdma_mr *iwmr)
{
	kfree(iwmr);
}

/*
 * irdma_reg_user_mr_type_mem - Handle memory registration
 * @iwmr - irdma mr
 * @access - access rights
 * @create_stag - flag to create stag or not
 */
int irdma_reg_user_mr_type_mem(struct irdma_mr *iwmr, int access,
			       bool create_stag)
{
	struct irdma_device *iwdev = to_iwdev(iwmr->ibmr.device);
	struct irdma_pbl *iwpbl = &iwmr->iwpbl;
	u32 stag = 0;
	int err;
	u8 lvl;

	lvl = iwmr->page_cnt != 1 ? PBLE_LEVEL_1 | PBLE_LEVEL_2 : PBLE_LEVEL_0;

	err = irdma_setup_pbles(iwdev->rf, iwmr, lvl);
	if (err)
		return err;

	if (lvl) {
		err = irdma_check_mr_contiguous(&iwpbl->pble_alloc,
						iwmr->page_size);
		if (err) {
			irdma_free_pble(iwdev->rf->pble_rsrc, &iwpbl->pble_alloc);
			iwpbl->pbl_allocated = false;
		}
	}

	if (create_stag) {
		stag = irdma_create_stag(iwdev);
		if (!stag) {
			err = -ENOMEM;
			goto free_pble;
		}

		iwmr->stag = stag;
		iwmr->ibmr.rkey = stag;
		iwmr->ibmr.lkey = stag;
	}
	iwmr->access = access;
	err = irdma_hwreg_mr(iwdev, iwmr, access);
	if (err)
		goto err_hwreg;

	return 0;

err_hwreg:
	if (stag)
		irdma_free_stag(iwdev, stag);

free_pble:
	if (iwpbl->pble_alloc.level != PBLE_LEVEL_0 && iwpbl->pbl_allocated)
		irdma_free_pble(iwdev->rf->pble_rsrc, &iwpbl->pble_alloc);

	return err;
}

/*
 * irdma_reg_user_mr_type_qp - Handle QP memory registration
 * @req - memory reg req
 * @udata - user info
 * @iwmr - irdma mr
 */
static int irdma_reg_user_mr_type_qp(struct irdma_mem_reg_req req,
				     struct ib_udata *udata,
				     struct irdma_mr *iwmr)
{
	struct irdma_device *iwdev = to_iwdev(iwmr->ibmr.device);
	struct irdma_pbl *iwpbl = &iwmr->iwpbl;
	struct irdma_ucontext *ucontext;
	unsigned long flags;
	u32 total;
	int err;
	u8 lvl;

	/* iWarp: Catch page not starting on OS page boundary */
	if (!rdma_protocol_roce(&iwdev->ibdev, 1) &&
	    ib_umem_offset(iwmr->region))
		return -EINVAL;

	total = req.sq_pages + req.rq_pages + IRDMA_SHADOW_PGCNT;
	if (total > iwmr->page_cnt)
		return -EINVAL;

	total = req.sq_pages + req.rq_pages;
	lvl = total > 2 ? PBLE_LEVEL_1 : PBLE_LEVEL_0;
	err = irdma_handle_q_mem(iwdev, &req, iwpbl, lvl);
	if (err)
		return err;

	ucontext = kc_rdma_udata_to_drv_context(iwmr->ibmr.pd, udata);
	spin_lock_irqsave(&ucontext->qp_reg_mem_list_lock, flags);
	list_add_tail(&iwpbl->list, &ucontext->qp_reg_mem_list);
	iwpbl->on_list = true;
	spin_unlock_irqrestore(&ucontext->qp_reg_mem_list_lock, flags);

	return 0;
}

/*
 * irdma_reg_user_mr_type_srq - Handle SRQ memory registration
 * @req - memory reg req
 * @udata - user info
 * @iwmr - irdma mr
 */
static int irdma_reg_user_mr_type_srq(struct irdma_mem_reg_req req,
				      struct ib_udata *udata,
				      struct irdma_mr *iwmr)
{
	struct irdma_device *iwdev = to_iwdev(iwmr->ibmr.device);
	struct irdma_pbl *iwpbl = &iwmr->iwpbl;
	struct irdma_ucontext *ucontext;
	unsigned long flags;
	u32 total;
	int err;
	u8 lvl;

	total = req.rq_pages + IRDMA_SHADOW_PGCNT;
	if (total > iwmr->page_cnt)
		return -EINVAL;

	lvl = req.rq_pages > 1 ? PBLE_LEVEL_1 : PBLE_LEVEL_0;
	err = irdma_handle_q_mem(iwdev, &req, iwpbl, lvl);
	if (err)
		return err;

	ucontext = kc_rdma_udata_to_drv_context(iwmr->ibmr.pd, udata);
	spin_lock_irqsave(&ucontext->srq_reg_mem_list_lock, flags);
	list_add_tail(&iwpbl->list, &ucontext->srq_reg_mem_list);
	iwpbl->on_list = true;
	spin_unlock_irqrestore(&ucontext->srq_reg_mem_list_lock, flags);

	return 0;
}

/*
 * irdma_reg_user_mr_type_cq - Handle CQ memory registration
 * @req - memory reg req
 * @udata - user info
 * @iwmr - irdma mr
 */
static int irdma_reg_user_mr_type_cq(struct irdma_mem_reg_req req,
				     struct ib_udata *udata,
				     struct irdma_mr *iwmr)
{
	struct irdma_device *iwdev = to_iwdev(iwmr->ibmr.device);
	struct irdma_pbl *iwpbl = &iwmr->iwpbl;
	struct irdma_ucontext *ucontext;
	unsigned long flags;
	u32 total;
	int err;
	u8 lvl;

	total = req.cq_pages +
		((iwdev->rf->sc_dev.hw_attrs.uk_attrs.feature_flags & IRDMA_FEATURE_CQ_RESIZE) ? 0 : IRDMA_SHADOW_PGCNT);
	if (total > iwmr->page_cnt)
		return -EINVAL;

	lvl = req.cq_pages > 1 ? PBLE_LEVEL_1 : PBLE_LEVEL_0;
	err = irdma_handle_q_mem(iwdev, &req, iwpbl, lvl);
	if (err)
		return err;

	ucontext = kc_rdma_udata_to_drv_context(iwmr->ibmr.pd, udata);
	spin_lock_irqsave(&ucontext->cq_reg_mem_list_lock, flags);
	list_add_tail(&iwpbl->list, &ucontext->cq_reg_mem_list);
	iwpbl->on_list = true;
	spin_unlock_irqrestore(&ucontext->cq_reg_mem_list_lock, flags);

	return 0;
}

/**
 * irdma_reg_user_mr - Register a user memory region
 * @pd: ptr of pd
 * @start: virtual start address
 * @len: length of mr
 * @virt: virtual address
 * @access: access of mr
 * @udata: user data
 */
static struct ib_mr *irdma_reg_user_mr(struct ib_pd *pd, u64 start, u64 len,
				       u64 virt, int access,
				       struct ib_udata *udata)
{
#define IRDMA_MEM_REG_MIN_REQ_LEN offsetofend(struct irdma_mem_reg_req, sq_pages)
	struct irdma_device *iwdev = to_iwdev(pd->device);
	struct irdma_mem_reg_req req = {};
	struct ib_umem *region;
	struct irdma_mr *iwmr;
	int err;

	if (len > iwdev->rf->sc_dev.hw_attrs.max_mr_size)
		return ERR_PTR(-EINVAL);

	if (udata->inlen < IRDMA_MEM_REG_MIN_REQ_LEN)
		return ERR_PTR(-EINVAL);

#ifdef IB_UMEM_GET_V3
	region = ib_umem_get(pd->device, start, len, access);
#endif
#ifdef IB_UMEM_GET_V2
	region = ib_umem_get(udata, start, len, access);
#endif
#ifdef IB_UMEM_GET_V1
	region = ib_umem_get(udata, start, len, access, 0);
#endif
#ifdef IB_UMEM_GET_V0
	region = ib_umem_get(pd->uobject->context, start, len, access, 0);
#endif

	if (IS_ERR(region)) {
		ibdev_dbg(&iwdev->ibdev,
			  "VERBS: Failed to create ib_umem region err=%ld\n", PTR_ERR(region));
		return (struct ib_mr *)region;
	}

	if (ib_copy_from_udata(&req, udata, min(sizeof(req), udata->inlen))) {
		ib_umem_release(region);
		return ERR_PTR(-EFAULT);
	}

#ifndef SET_BEST_PAGE_SZ_V1
	iwmr = irdma_alloc_iwmr(region, pd, virt, req.reg_type);
#else
	iwmr = irdma_alloc_iwmr(region, pd, virt, start, req.reg_type);
#endif
	if (IS_ERR(iwmr)) {
		ib_umem_release(region);
		return (struct ib_mr *)iwmr;
	}

	switch (req.reg_type) {
	case IRDMA_MEMREG_TYPE_QP:
		err = irdma_reg_user_mr_type_qp(req, udata, iwmr);
		if (err)
			goto error;

		break;
	case IRDMA_MEMREG_TYPE_SRQ:
		err = irdma_reg_user_mr_type_srq(req, udata, iwmr);
		if (err)
			goto error;

		break;
	case IRDMA_MEMREG_TYPE_CQ:
		err = irdma_reg_user_mr_type_cq(req, udata, iwmr);
		if (err)
			goto error;

		break;
	case IRDMA_MEMREG_TYPE_MEM:
		err = irdma_reg_user_mr_type_mem(iwmr, access, true);
		if (err)
			goto error;

#ifdef CONFIG_DEBUG_FS
#ifdef SET_BEST_PAGE_SZ_V1
		if (iwmr->region->hugetlb && (iwmr->page_size == 0x200000 ||
					      iwmr->page_size == 0x40000000))
			iwdev->hugepgcnt += iwmr->page_cnt;
#endif
#endif
		break;
	default:
		err = -EINVAL;
		goto error;
	}


	return &iwmr->ibmr;

error:
	ib_umem_release(region);
	irdma_free_iwmr(iwmr);

	return ERR_PTR(err);
}

int irdma_hwdereg_mr(struct ib_mr *ib_mr)
{
	struct irdma_device *iwdev = to_iwdev(ib_mr->device);
	struct irdma_mr *iwmr = to_iwmr(ib_mr);
	struct irdma_pd *iwpd = to_iwpd(ib_mr->pd);
	struct irdma_dealloc_stag_info *info;
	struct irdma_pbl *iwpbl = &iwmr->iwpbl;
	struct irdma_cqp_request *cqp_request;
	struct cqp_cmds_info *cqp_info;
	int status;

	/* Skip HW MR de-register when it is already de-registered
	 * during an MR re-reregister and the re-registration fails
	 */
	if (!iwmr->is_hwreg)
		return 0;

	cqp_request = irdma_alloc_and_get_cqp_request(&iwdev->rf->cqp, true);
	if (!cqp_request)
		return -ENOMEM;

	cqp_info = &cqp_request->info;
	info = &cqp_info->in.u.dealloc_stag.info;
	info->pd_id = iwpd->sc_pd.pd_id;
	info->stag_idx = RS_64_1(ib_mr->rkey, IRDMA_CQPSQ_STAG_IDX_S);
	info->mr = true;
	if (iwpbl->pbl_allocated)
		info->dealloc_pbl = true;

	cqp_info->cqp_cmd = IRDMA_OP_DEALLOC_STAG;
	cqp_info->post_sq = 1;
	cqp_info->in.u.dealloc_stag.dev = &iwdev->rf->sc_dev;
	cqp_info->in.u.dealloc_stag.scratch = (uintptr_t)cqp_request;
	status = irdma_handle_cqp_op(iwdev->rf, cqp_request);
	irdma_put_cqp_request(&iwdev->rf->cqp, cqp_request);

	if (!status)
		iwmr->is_hwreg = 0;

	return status;
}

/*
 * irdma_rereg_mr_trans - Re-register a user MR for a change translation.
 * @iwmr: ptr of iwmr
 * @start: virtual start address
 * @len: length of mr
 * @virt: virtual address
 *
 * Re-register a user memory region when a change translation is requested.
 * Re-register a new region while reusing the stag from the original registration.
 */
struct ib_mr *irdma_rereg_mr_trans(struct irdma_mr *iwmr, u64 start, u64 len,
				   u64 virt, struct ib_udata *udata)
{
	struct irdma_device *iwdev = to_iwdev(iwmr->ibmr.device);
	struct irdma_pbl *iwpbl = &iwmr->iwpbl;
	struct ib_pd *pd = iwmr->ibmr.pd;
	struct ib_umem *region;
	int err;

#ifdef IB_UMEM_GET_V3
	region = ib_umem_get(pd->device, start, len, iwmr->access);
#endif
#ifdef IB_UMEM_GET_V2
	region = ib_umem_get(udata, start, len, iwmr->access);
#endif
#ifdef IB_UMEM_GET_V1
	region = ib_umem_get(udata, start, len, iwmr->access, 0);
#endif
#ifdef IB_UMEM_GET_V0
	region = ib_umem_get(pd->uobject->context, start, len, iwmr->access, 0);
#endif

	if (IS_ERR(region)) {
		ibdev_dbg(&iwdev->ibdev,
			  "VERBS: Failed to create ib_umem region err=%ld\n", PTR_ERR(region));
		return (struct ib_mr *)region;
	}

	iwmr->region = region;
	iwmr->ibmr.iova = virt;
	iwmr->ibmr.pd = pd;
	iwmr->page_size = PAGE_SIZE;

#ifdef SET_BEST_PAGE_SZ_V1
	irdma_set_best_pagesz(start, iwmr,
			      iwdev->rf->sc_dev.hw_attrs.page_size_cap);

#endif
#ifdef SET_BEST_PAGE_SZ_V2
	iwmr->page_size = ib_umem_find_best_pgsz(region,
						 iwdev->rf->sc_dev.hw_attrs.page_size_cap,
						 virt);
	if (unlikely(!iwmr->page_size)) {
		err = -EOPNOTSUPP;
		goto err;
	}
#endif
	iwmr->len = region->length;
	iwpbl->user_base = virt;
#ifdef HAVE_IB_UMEM_NUM_DMA_BLOCKS
	iwmr->page_cnt = ib_umem_num_dma_blocks(region, iwmr->page_size);
#else
	iwmr->page_cnt = irdma_ib_umem_num_dma_blocks(region, iwmr->page_size,
						      virt);
#endif

	err = irdma_reg_user_mr_type_mem(iwmr, iwmr->access, false);
	if (err)
		goto err;

#ifdef CONFIG_DEBUG_FS
#ifdef SET_BEST_PAGE_SZ_V1
	if (iwmr->region->hugetlb && (iwmr->page_size == 0x200000 ||
				      iwmr->page_size == 0x40000000))
		iwdev->hugepgcnt += iwmr->page_cnt;
#endif
#endif
	return &iwmr->ibmr;

err:
	ib_umem_release(region);
	return ERR_PTR(err);
}

#ifdef SET_DMABUF
#endif /* SET_DMABUF */
/**
 * irdma_reg_phys_mr - register kernel physical memory
 * @pd: ibpd pointer
 * @addr: physical address of memory to register
 * @size: size of memory to register
 * @access: Access rights
 * @iova_start: start of virtual address for physical buffers
 * @dma_mr: Flag indicating DMA Mem region
 */
struct ib_mr *irdma_reg_phys_mr(struct ib_pd *pd, u64 addr, u64 size, int access,
				u64 *iova_start, bool dma_mr)
{
	struct irdma_device *iwdev = to_iwdev(pd->device);
	struct irdma_pbl *iwpbl;
	struct irdma_mr *iwmr;
	u32 stag;
	int ret;

	iwmr = kzalloc(sizeof(*iwmr), GFP_KERNEL);
	if (!iwmr)
		return ERR_PTR(-ENOMEM);

	iwmr->ibmr.pd = pd;
	iwmr->ibmr.device = pd->device;
	iwpbl = &iwmr->iwpbl;
	iwpbl->iwmr = iwmr;
	iwmr->type = IRDMA_MEMREG_TYPE_MEM;
	iwmr->dma_mr = dma_mr;
	iwpbl->user_base = *iova_start;
	stag = irdma_create_stag(iwdev);
	if (!stag) {
		ret = -ENOMEM;
		goto err;
	}

	iwmr->stag = stag;
	iwmr->ibmr.iova = *iova_start;
	iwmr->ibmr.rkey = stag;
	iwmr->ibmr.lkey = stag;
	iwmr->page_cnt = 1;
	iwmr->pgaddrmem[0] = addr;
	iwmr->len = size;
	iwmr->page_size = SZ_4K;
	ret = irdma_hwreg_mr(iwdev, iwmr, access);
	if (ret) {
		irdma_free_stag(iwdev, stag);
		goto err;
	}

	return &iwmr->ibmr;

err:
	kfree(iwmr);

	return ERR_PTR(ret);
}

/**
 * irdma_get_dma_mr - register physical mem
 * @pd: ptr of pd
 * @acc: access for memory
 */
static struct ib_mr *irdma_get_dma_mr(struct ib_pd *pd, int acc)
{
	u64 kva = 0;

	return irdma_reg_phys_mr(pd, 0, 0, acc, &kva, true);
}

/**
 * irdma_del_memlist - Deleting pbl list entries for CQ/QP
 * @iwmr: iwmr for IB's user page addresses
 * @ucontext: ptr to user context
 */
void irdma_del_memlist(struct irdma_mr *iwmr,
		       struct irdma_ucontext *ucontext)
{
	struct irdma_pbl *iwpbl = &iwmr->iwpbl;
	unsigned long flags;

	switch (iwmr->type) {
	case IRDMA_MEMREG_TYPE_CQ:
		spin_lock_irqsave(&ucontext->cq_reg_mem_list_lock, flags);
		if (iwpbl->on_list) {
			iwpbl->on_list = false;
			list_del(&iwpbl->list);
		}
		spin_unlock_irqrestore(&ucontext->cq_reg_mem_list_lock, flags);
		break;
	case IRDMA_MEMREG_TYPE_QP:
		spin_lock_irqsave(&ucontext->qp_reg_mem_list_lock, flags);
		if (iwpbl->on_list) {
			iwpbl->on_list = false;
			list_del(&iwpbl->list);
		}
		spin_unlock_irqrestore(&ucontext->qp_reg_mem_list_lock, flags);
		break;
	case IRDMA_MEMREG_TYPE_SRQ:
		spin_lock_irqsave(&ucontext->srq_reg_mem_list_lock, flags);
		if (iwpbl->on_list) {
			iwpbl->on_list = false;
			list_del(&iwpbl->list);
		}
		spin_unlock_irqrestore(&ucontext->srq_reg_mem_list_lock, flags);
		break;
	default:
		break;
	}
}

/**
 * irdma_post_send -  kernel application wr
 * @ibqp: qp ptr for wr
 * @ib_wr: work request ptr
 * @bad_wr: return of bad wr if err
 */
static int irdma_post_send(struct ib_qp *ibqp,
			   kc_typeq_ib_wr struct ib_send_wr *ib_wr,
			   kc_typeq_ib_wr struct ib_send_wr **bad_wr)
{
	struct irdma_qp *iwqp;
	struct irdma_qp_uk *ukqp;
	struct irdma_sc_dev *dev;
	struct irdma_post_sq_info info;
	int err = 0;
	unsigned long flags;
	bool inv_stag;
	struct irdma_ah *ah;

	iwqp = to_iwqp(ibqp);
	ukqp = &iwqp->sc_qp.qp_uk;
	dev = &iwqp->iwdev->rf->sc_dev;

	spin_lock_irqsave(&iwqp->lock, flags);
	while (ib_wr) {
		memset(&info, 0, sizeof(info));
		inv_stag = false;
		info.wr_id = (ib_wr->wr_id);
		if ((ib_wr->send_flags & IB_SEND_SIGNALED) || iwqp->sig_all)
			info.signaled = true;
		if (ib_wr->send_flags & IB_SEND_FENCE)
			info.read_fence = true;
		switch (ib_wr->opcode) {
		case IB_WR_ATOMIC_CMP_AND_SWP:
			info.op_type = IRDMA_OP_TYPE_ATOMIC_COMPARE_AND_SWAP;
			info.op.atomic_compare_swap.tagged_offset = ib_wr->sg_list[0].addr;
			info.op.atomic_compare_swap.remote_tagged_offset =
				atomic_wr(ib_wr)->remote_addr;
			info.op.atomic_compare_swap.swap_data_bytes = atomic_wr(ib_wr)->swap;
			info.op.atomic_compare_swap.compare_data_bytes =
				atomic_wr(ib_wr)->compare_add;
			info.op.atomic_compare_swap.stag = ib_wr->sg_list[0].lkey;
			info.op.atomic_compare_swap.remote_stag = atomic_wr(ib_wr)->rkey;
			err = irdma_uk_atomic_compare_swap(ukqp, &info, false);
			break;
		case IB_WR_ATOMIC_FETCH_AND_ADD:
			info.op_type = IRDMA_OP_TYPE_ATOMIC_FETCH_AND_ADD;
			info.op.atomic_fetch_add.tagged_offset = ib_wr->sg_list[0].addr;
			info.op.atomic_fetch_add.remote_tagged_offset =
				atomic_wr(ib_wr)->remote_addr;
			info.op.atomic_fetch_add.fetch_add_data_bytes =
				atomic_wr(ib_wr)->compare_add;
			info.op.atomic_fetch_add.stag = ib_wr->sg_list[0].lkey;
			info.op.atomic_fetch_add.remote_stag = atomic_wr(ib_wr)->rkey;
			err = irdma_uk_atomic_fetch_add(ukqp, &info, false);
			break;
		case IB_WR_SEND_WITH_IMM:
			if (ukqp->qp_caps & IRDMA_SEND_WITH_IMM) {
				info.imm_data_valid = true;
				info.imm_data = ntohl(ib_wr->ex.imm_data);
			} else {
				err = -EINVAL;
				break;
			}
			fallthrough;
		case IB_WR_SEND:
		case IB_WR_SEND_WITH_INV:
			if (ib_wr->opcode == IB_WR_SEND ||
			    ib_wr->opcode == IB_WR_SEND_WITH_IMM) {
				if (ib_wr->send_flags & IB_SEND_SOLICITED)
					info.op_type = IRDMA_OP_TYPE_SEND_SOL;
				else
					info.op_type = IRDMA_OP_TYPE_SEND;
			} else {
				if (ib_wr->send_flags & IB_SEND_SOLICITED)
					info.op_type = IRDMA_OP_TYPE_SEND_SOL_INV;
				else
					info.op_type = IRDMA_OP_TYPE_SEND_INV;
				info.stag_to_inv = ib_wr->ex.invalidate_rkey;
			}

			info.op.send.num_sges = ib_wr->num_sge;
			info.op.send.sg_list = ib_wr->sg_list;
			if (iwqp->ibqp.qp_type == IB_QPT_UD ||
			    iwqp->ibqp.qp_type == IB_QPT_GSI) {
				ah = to_iwah(ud_wr(ib_wr)->ah);
				info.op.send.ah_id = ah->sc_ah.ah_info.ah_idx;
				info.op.send.qkey = ud_wr(ib_wr)->remote_qkey;
				info.op.send.dest_qp = ud_wr(ib_wr)->remote_qpn;
			}

			if (ib_wr->send_flags & IB_SEND_INLINE) {
				err = irdma_uk_inline_send(ukqp, &info, false);
			} else {
				if (iwqp->iwmr)
					ib_wr->sg_list[0].lkey = 0x100;
				err = irdma_uk_send(ukqp, &info, false);
			}
			break;
		case IB_WR_RDMA_WRITE_WITH_IMM:
			if (ukqp->qp_caps & IRDMA_WRITE_WITH_IMM) {
				info.imm_data_valid = true;
				info.imm_data = ntohl(ib_wr->ex.imm_data);
			} else {
				err = -EINVAL;
				break;
			}
			fallthrough;
		case IB_WR_RDMA_WRITE:
			if (ib_wr->send_flags & IB_SEND_SOLICITED)
				info.op_type = IRDMA_OP_TYPE_RDMA_WRITE_SOL;
			else
				info.op_type = IRDMA_OP_TYPE_RDMA_WRITE;

			info.op.rdma_write.num_lo_sges = ib_wr->num_sge;
			info.op.rdma_write.lo_sg_list = (void *)ib_wr->sg_list;
			info.op.rdma_write.rem_addr.addr = rdma_wr(ib_wr)->remote_addr;
			info.op.rdma_write.rem_addr.lkey = rdma_wr(ib_wr)->rkey;
			if (ib_wr->send_flags & IB_SEND_INLINE)
				err = irdma_uk_inline_rdma_write(ukqp, &info, false);
			else
				err = irdma_uk_rdma_write(ukqp, &info, false);
			break;
		case IB_WR_RDMA_READ_WITH_INV:
			inv_stag = true;
			fallthrough;
		case IB_WR_RDMA_READ:
			if (ib_wr->num_sge >
			    dev->hw_attrs.uk_attrs.max_hw_read_sges) {
				err = -EINVAL;
				break;
			}
			info.op_type = IRDMA_OP_TYPE_RDMA_READ;
			info.op.rdma_read.rem_addr.addr = rdma_wr(ib_wr)->remote_addr;
			info.op.rdma_read.rem_addr.lkey = rdma_wr(ib_wr)->rkey;
			info.op.rdma_read.lo_sg_list = (void *)ib_wr->sg_list;
			info.op.rdma_read.num_lo_sges = ib_wr->num_sge;
			err = irdma_uk_rdma_read(ukqp, &info, inv_stag, false);
			break;
		case IB_WR_LOCAL_INV:
			info.op_type = IRDMA_OP_TYPE_INV_STAG;
			info.local_fence = true;
			info.op.inv_local_stag.target_stag = ib_wr->ex.invalidate_rkey;
			err = irdma_uk_stag_local_invalidate(ukqp, &info, true);
			break;
		case IB_WR_REG_MR: {
			struct irdma_mr *iwmr = to_iwmr(reg_wr(ib_wr)->mr);
			struct irdma_pble_alloc *palloc = &iwmr->iwpbl.pble_alloc;
			struct irdma_fast_reg_stag_info stag_info = {};

			stag_info.signaled = info.signaled;
			stag_info.read_fence = info.read_fence;
			stag_info.access_rights =
				irdma_get_mr_access(reg_wr(ib_wr)->access,
						    dev->hw_attrs.uk_attrs.hw_rev);
			stag_info.stag_key = reg_wr(ib_wr)->key & 0xff;
			stag_info.stag_idx = reg_wr(ib_wr)->key >> 8;
			stag_info.page_size = reg_wr(ib_wr)->mr->page_size;
			stag_info.wr_id = ib_wr->wr_id;
			stag_info.addr_type = IRDMA_ADDR_TYPE_VA_BASED;
			stag_info.va = (void *)(uintptr_t)iwmr->ibmr.iova;
			stag_info.total_len = iwmr->ibmr.length;
			if (palloc->level == PBLE_LEVEL_2) {
				stag_info.chunk_size = 3;
				stag_info.first_pm_pbl_index = palloc->level2.root.idx;
			} else {
				stag_info.chunk_size = 1;
				stag_info.first_pm_pbl_index = palloc->level1.idx;
			}
			stag_info.local_fence = ib_wr->send_flags & IB_SEND_FENCE;
			err = irdma_sc_mr_fast_register(&iwqp->sc_qp, &stag_info,
							true);
			break;
		}
		default:
			err = -EINVAL;
			ibdev_dbg(&iwqp->iwdev->ibdev,
				  "VERBS: upost_send bad opcode = 0x%x\n",
				  ib_wr->opcode);
			break;
		}

		if (err)
			break;
		ib_wr = ib_wr->next;
	}

	if (!atomic_read(&iwqp->flush_issued)) {
		if (iwqp->hw_iwarp_state <= IRDMA_QP_STATE_RTS)
			irdma_uk_qp_post_wr(ukqp);
		spin_unlock_irqrestore(&iwqp->lock, flags);
	} else {
		spin_unlock_irqrestore(&iwqp->lock, flags);
		irdma_sched_qp_flush_work(iwqp);
	}

	if (err)
		*bad_wr = ib_wr;

	return err;
}

/**
 * irdma_post_srq_recv - post receive wr for kernel application
 * @ibsrq: ib srq pointer
 * @ib_wr: work request for receive
 * @bad_wr: bad wr caused an error
 */
static int irdma_post_srq_recv(struct ib_srq *ibsrq,
			       kc_typeq_ib_wr struct ib_recv_wr *ib_wr,
			       kc_typeq_ib_wr struct ib_recv_wr **bad_wr)
{
	struct irdma_srq *iwsrq = to_iwsrq(ibsrq);
	struct irdma_srq_uk *uksrq = &iwsrq->sc_srq.srq_uk;
	struct irdma_post_rq_info post_recv = {};
	unsigned long flags;
	int err = 0;

	spin_lock_irqsave(&iwsrq->lock, flags);
	while (ib_wr) {
		if (ib_wr->num_sge > uksrq->max_srq_frag_cnt) {
			err = -EINVAL;
			goto out;
		}
		post_recv.num_sges = ib_wr->num_sge;
		post_recv.wr_id = ib_wr->wr_id;
		post_recv.sg_list = ib_wr->sg_list;
		err = irdma_uk_srq_post_receive(uksrq, &post_recv);
		if (err)
			goto out;

		ib_wr = ib_wr->next;
	}

out:
	spin_unlock_irqrestore(&iwsrq->lock, flags);

	if (err)
		*bad_wr = ib_wr;

	return err;
}

/**
 * irdma_post_recv - post receive wr for kernel application
 * @ibqp: ib qp pointer
 * @ib_wr: work request for receive
 * @bad_wr: bad wr caused an error
 */
static int irdma_post_recv(struct ib_qp *ibqp,
			   kc_typeq_ib_wr struct ib_recv_wr *ib_wr,
			   kc_typeq_ib_wr struct ib_recv_wr **bad_wr)
{
	struct irdma_qp *iwqp = to_iwqp(ibqp);
	struct irdma_qp_uk *ukqp = &iwqp->sc_qp.qp_uk;
	struct irdma_post_rq_info post_recv = {};
	struct ib_sge *sg_list = iwqp->sg_list;
	unsigned long flags;
	int err = 0;

	if (ukqp->srq_uk) {
		*bad_wr = ib_wr;
		return -EINVAL;
	}

	spin_lock_irqsave(&iwqp->lock, flags);

	while (ib_wr) {
		if (ib_wr->num_sge > ukqp->max_rq_frag_cnt) {
			err = -EINVAL;
			goto out;
		}
		post_recv.num_sges = ib_wr->num_sge;
		post_recv.wr_id = ib_wr->wr_id;
		post_recv.sg_list = ib_wr->sg_list;
		if (iwqp->iwmr)
			sg_list[0].lkey = 0x100;
		err = irdma_uk_post_receive(ukqp, &post_recv);
		if (err) {
			ibdev_dbg(&iwqp->iwdev->ibdev,
				  "VERBS: post_recv err %d\n", err);
			goto out;
		}

		ib_wr = ib_wr->next;
	}

out:
	spin_unlock_irqrestore(&iwqp->lock, flags);

	if (atomic_read(&iwqp->flush_issued))
		irdma_sched_qp_flush_work(iwqp);

	if (err)
		*bad_wr = ib_wr;

	return err;
}

/**
 * irdma_flush_err_to_ib_wc_status - return change flush error code to IB status
 * @opcode: iwarp flush code
 */
static enum ib_wc_status irdma_flush_err_to_ib_wc_status(enum irdma_flush_opcode opcode)
{
	switch (opcode) {
	case FLUSH_PROT_ERR:
		return IB_WC_LOC_PROT_ERR;
	case FLUSH_REM_ACCESS_ERR:
		return IB_WC_REM_ACCESS_ERR;
	case FLUSH_LOC_QP_OP_ERR:
		return IB_WC_LOC_QP_OP_ERR;
	case FLUSH_REM_OP_ERR:
		return IB_WC_REM_OP_ERR;
	case FLUSH_LOC_LEN_ERR:
		return IB_WC_LOC_LEN_ERR;
	case FLUSH_GENERAL_ERR:
		return IB_WC_WR_FLUSH_ERR;
	case FLUSH_MW_BIND_ERR:
		return IB_WC_MW_BIND_ERR;
	case FLUSH_REM_INV_REQ_ERR:
		return IB_WC_REM_INV_REQ_ERR;
	case FLUSH_RETRY_EXC_ERR:
		return IB_WC_RETRY_EXC_ERR;
	case FLUSH_RNR_RETRY_EXC_ERR:
		return IB_WC_RNR_RETRY_EXC_ERR;
	case FLUSH_FATAL_ERR:
	default:
		return IB_WC_FATAL_ERR;
	}
}

/**
 * irdma_process_cqe - process cqe info
 * @entry: processed cqe
 * @cq_poll_info: cqe info
 */
static void irdma_process_cqe(struct ib_wc *entry,
			      struct irdma_cq_poll_info *cq_poll_info)
{
	struct irdma_sc_qp *qp;

	entry->wc_flags = 0;
	entry->pkey_index = 0;
	entry->wr_id = cq_poll_info->wr_id;

	qp = cq_poll_info->qp_handle;
	entry->qp = qp->qp_uk.back_qp;

	if (cq_poll_info->error) {
		entry->status = (cq_poll_info->comp_status == IRDMA_COMPL_STATUS_FLUSHED) ?
				irdma_flush_err_to_ib_wc_status(cq_poll_info->minor_err) : IB_WC_GENERAL_ERR;

		entry->vendor_err = cq_poll_info->major_err << 16 |
				    cq_poll_info->minor_err;
	} else {
		entry->status = IB_WC_SUCCESS;
		if (cq_poll_info->imm_valid) {
			entry->ex.imm_data = htonl(cq_poll_info->imm_data);
			entry->wc_flags |= IB_WC_WITH_IMM;
		}
		if (cq_poll_info->ud_smac_valid) {
			ether_addr_copy(entry->smac, cq_poll_info->ud_smac);
			entry->wc_flags |= IB_WC_WITH_SMAC;
		}

		if (cq_poll_info->ud_vlan_valid &&
		    dev_to_rf(qp->dev)->vlan_parse_en) {
			u16 vlan = cq_poll_info->ud_vlan & VLAN_VID_MASK;

			entry->sl = cq_poll_info->ud_vlan >> VLAN_PRIO_SHIFT;
			if (vlan) {
				entry->vlan_id = vlan;
				entry->wc_flags |= IB_WC_WITH_VLAN;
			}
		} else {
			entry->sl = 0;
		}
	}

	if (cq_poll_info->q_type == IRDMA_CQE_QTYPE_SQ) {
		set_ib_wc_op_sq(cq_poll_info, entry);
	} else {
		if (qp->dev->hw_attrs.uk_attrs.hw_rev <= IRDMA_GEN_2)
			set_ib_wc_op_rq(cq_poll_info, entry,
					qp->qp_uk.qp_caps & IRDMA_SEND_WITH_IMM ?
					true : false);
		else
			set_ib_wc_op_rq_gen_3(cq_poll_info, entry);
		if (qp->qp_uk.qp_type != IRDMA_QP_TYPE_ROCE_UD &&
		    cq_poll_info->stag_invalid_set) {
			entry->ex.invalidate_rkey = cq_poll_info->inv_stag;
			entry->wc_flags |= IB_WC_WITH_INVALIDATE;
		}
	}

	if (qp->qp_uk.qp_type == IRDMA_QP_TYPE_ROCE_UD) {
		entry->src_qp = cq_poll_info->ud_src_qpn;
		entry->slid = 0;
		entry->wc_flags |=
			(IB_WC_GRH | IB_WC_WITH_NETWORK_HDR_TYPE);
		entry->network_hdr_type = cq_poll_info->ipv4 ?
						  RDMA_NETWORK_IPV4 :
						  RDMA_NETWORK_IPV6;
	} else {
		entry->src_qp = cq_poll_info->qp_id;
	}

	entry->byte_len = cq_poll_info->bytes_xfered;
}

/**
 * irdma_poll_one - poll one entry of the CQ
 * @ukcq: ukcq to poll
 * @cur_cqe: current CQE info to be filled in
 * @entry: ibv_wc object to be filled for non-extended CQ or NULL for extended CQ
 *
 * Returns the internal irdma device error code or 0 on success
 */
static inline int irdma_poll_one(struct irdma_cq_uk *ukcq,
				 struct irdma_cq_poll_info *cur_cqe,
				 struct ib_wc *entry)
{
	int ret = irdma_uk_cq_poll_cmpl(ukcq, cur_cqe);

	if (ret)
		return ret;

	irdma_process_cqe(entry, cur_cqe);

	return 0;
}

/**
 * __irdma_poll_cq - poll cq for completion (kernel apps)
 * @iwcq: cq to poll
 * @num_entries: number of entries to poll
 * @entry: wr of a completed entry
 */
static int __irdma_poll_cq(struct irdma_cq *iwcq, int num_entries, struct ib_wc *entry)
{
	struct list_head *tmp_node, *list_node;
	struct irdma_cq_buf *last_buf = NULL;
	struct irdma_cq_poll_info *cur_cqe = &iwcq->cur_cqe;
	struct irdma_cq_buf *cq_buf;
	int ret;
	struct irdma_device *iwdev;
	struct irdma_cq_uk *ukcq;
	bool cq_new_cqe = false;
	int resized_bufs = 0;
	int npolled = 0;

	iwdev = to_iwdev(iwcq->ibcq.device);
	ukcq = &iwcq->sc_cq.cq_uk;

	/* go through the list of previously resized CQ buffers */
	list_for_each_safe(list_node, tmp_node, &iwcq->resize_list) {
		cq_buf = container_of(list_node, struct irdma_cq_buf, list);
		while (npolled < num_entries) {
			ret = irdma_poll_one(&cq_buf->cq_uk, cur_cqe, entry + npolled);
			if (!ret) {
				++npolled;
				cq_new_cqe = true;
				continue;
			}
			if (ret == -ENOENT)
				break;
			 /* QP using the CQ is destroyed. Skip reporting this CQE */
			if (ret == -EFAULT) {
				cq_new_cqe = true;
				continue;
			}
			goto error;
		}

		/* save the resized CQ buffer which received the last cqe */
		if (cq_new_cqe)
			last_buf = cq_buf;
		cq_new_cqe = false;
	}

	/* check the current CQ for new cqes */
	while (npolled < num_entries) {
		ret = irdma_poll_one(ukcq, cur_cqe, entry + npolled);
		if (ret == -ENOENT) {
			ret = irdma_generated_cmpls(iwcq, cur_cqe);
			if (!ret)
				irdma_process_cqe(entry + npolled, cur_cqe);
		}
		if (!ret) {
			++npolled;
			cq_new_cqe = true;
			continue;
		}

		if (ret == -ENOENT)
			break;
		/* QP using the CQ is destroyed. Skip reporting this CQE */
		if (ret == -EFAULT) {
			cq_new_cqe = true;
			continue;
		}
		goto error;
	}

	if (cq_new_cqe)
		/* all previous CQ resizes are complete */
		resized_bufs = irdma_process_resize_list(iwcq, iwdev, NULL);
	else if (last_buf)
		/* only CQ resizes up to the last_buf are complete */
		resized_bufs = irdma_process_resize_list(iwcq, iwdev, last_buf);
	if (resized_bufs)
		/* report to the HW the number of complete CQ resizes */
		irdma_uk_cq_set_resized_cnt(ukcq, resized_bufs);

	return npolled;
error:
	ibdev_dbg(&iwdev->ibdev, "VERBS: %s: Error polling CQ, irdma_err: %d\n",
		  __func__, ret);

	return ret;
}

/**
 * irdma_poll_cq - poll cq for completion (kernel apps)
 * @ibcq: cq to poll
 * @num_entries: number of entries to poll
 * @entry: wr of a completed entry
 */
static int irdma_poll_cq(struct ib_cq *ibcq, int num_entries,
			 struct ib_wc *entry)
{
	struct irdma_cq *iwcq;
	unsigned long flags;
	int ret;

	iwcq = to_iwcq(ibcq);

	spin_lock_irqsave(&iwcq->lock, flags);
	ret = __irdma_poll_cq(iwcq, num_entries, entry);
	spin_unlock_irqrestore(&iwcq->lock, flags);

	return ret;
}

/**
 * irdma_req_notify_cq - arm cq kernel application
 * @ibcq: cq to arm
 * @notify_flags: notofication flags
 */
static int irdma_req_notify_cq(struct ib_cq *ibcq,
			       enum ib_cq_notify_flags notify_flags)
{
	struct irdma_cq *iwcq;
	struct irdma_cq_uk *ukcq;
	unsigned long flags;
	enum irdma_cmpl_notify cq_notify = IRDMA_CQ_COMPL_EVENT;
	bool promo_event = false;
	int ret = 0;

	iwcq = to_iwcq(ibcq);
	ukcq = &iwcq->sc_cq.cq_uk;

	if (iwcq->sc_cq.dev->hw_wa & CCQ_CQ3_POLL)
		return 0;
	spin_lock_irqsave(&iwcq->lock, flags);
	if (notify_flags == IB_CQ_SOLICITED) {
		cq_notify = IRDMA_CQ_COMPL_SOLICITED;
	} else {
		if (iwcq->last_notify == IRDMA_CQ_COMPL_SOLICITED)
			promo_event = true;
	}

	if (!atomic_cmpxchg(&iwcq->armed, 0, 1) || promo_event) {
		iwcq->last_notify = cq_notify;
		irdma_uk_cq_request_notification(ukcq, cq_notify);
	}

	if ((notify_flags & IB_CQ_REPORT_MISSED_EVENTS) &&
	    (!irdma_cq_empty(iwcq) || !list_empty(&iwcq->cmpl_generated)))
		ret = 1;
	spin_unlock_irqrestore(&iwcq->lock, flags);

	return ret;
}

#ifdef ALLOC_HW_STATS_STRUCT_V2
const struct rdma_stat_desc irdma_hw_stat_descs[] = {
	/* gen1 - 32-bit */
	[IRDMA_HW_STAT_INDEX_IP4RXDISCARD].name		= "ip4InDiscards",
	[IRDMA_HW_STAT_INDEX_IP4RXTRUNC].name		= "ip4InTruncatedPkts",
	[IRDMA_HW_STAT_INDEX_IP4TXNOROUTE].name		= "ip4OutNoRoutes",
	[IRDMA_HW_STAT_INDEX_IP6RXDISCARD].name		= "ip6InDiscards",
	[IRDMA_HW_STAT_INDEX_IP6RXTRUNC].name		= "ip6InTruncatedPkts",
	[IRDMA_HW_STAT_INDEX_IP6TXNOROUTE].name		= "ip6OutNoRoutes",
	[IRDMA_HW_STAT_INDEX_RXVLANERR].name		= "rxVlanErrors",
	/* gen1 - 64-bit */
	[IRDMA_HW_STAT_INDEX_IP4RXOCTS].name		= "ip4InOctets",
	[IRDMA_HW_STAT_INDEX_IP4RXPKTS].name		= "ip4InPkts",
	[IRDMA_HW_STAT_INDEX_IP4RXFRAGS].name		= "ip4InReasmRqd",
	[IRDMA_HW_STAT_INDEX_IP4RXMCPKTS].name		= "ip4InMcastPkts",
	[IRDMA_HW_STAT_INDEX_IP4TXOCTS].name		= "ip4OutOctets",
	[IRDMA_HW_STAT_INDEX_IP4TXPKTS].name		= "ip4OutPkts",
	[IRDMA_HW_STAT_INDEX_IP4TXFRAGS].name		= "ip4OutSegRqd",
	[IRDMA_HW_STAT_INDEX_IP4TXMCPKTS].name		= "ip4OutMcastPkts",
	[IRDMA_HW_STAT_INDEX_IP6RXOCTS].name		= "ip6InOctets",
	[IRDMA_HW_STAT_INDEX_IP6RXPKTS].name		= "ip6InPkts",
	[IRDMA_HW_STAT_INDEX_IP6RXFRAGS].name		= "ip6InReasmRqd",
	[IRDMA_HW_STAT_INDEX_IP6RXMCPKTS].name		= "ip6InMcastPkts",
	[IRDMA_HW_STAT_INDEX_IP6TXOCTS].name		= "ip6OutOctets",
	[IRDMA_HW_STAT_INDEX_IP6TXPKTS].name		= "ip6OutPkts",
	[IRDMA_HW_STAT_INDEX_IP6TXFRAGS].name		= "ip6OutSegRqd",
	[IRDMA_HW_STAT_INDEX_IP6TXMCPKTS].name		= "ip6OutMcastPkts",
	[IRDMA_HW_STAT_INDEX_RDMARXRDS].name		= "InRdmaReads",
	[IRDMA_HW_STAT_INDEX_RDMARXSNDS].name		= "InRdmaSends",
	[IRDMA_HW_STAT_INDEX_RDMARXWRS].name		= "InRdmaWrites",
	[IRDMA_HW_STAT_INDEX_RDMATXRDS].name		= "OutRdmaReads",
	[IRDMA_HW_STAT_INDEX_RDMATXSNDS].name		= "OutRdmaSends",
	[IRDMA_HW_STAT_INDEX_RDMATXWRS].name		= "OutRdmaWrites",
	[IRDMA_HW_STAT_INDEX_RDMAVBND].name		= "RdmaBnd",
	[IRDMA_HW_STAT_INDEX_RDMAVINV].name		= "RdmaInv",

	/* gen2 - 32-bit */
	[IRDMA_HW_STAT_INDEX_RXRPCNPHANDLED].name	= "cnpHandled",
	[IRDMA_HW_STAT_INDEX_RXRPCNPIGNORED].name	= "cnpIgnored",
	[IRDMA_HW_STAT_INDEX_TXNPCNPSENT].name		= "cnpSent",
	/* gen2 - 64-bit */
	[IRDMA_HW_STAT_INDEX_IP4RXMCOCTS].name		= "ip4InMcastOctets",
	[IRDMA_HW_STAT_INDEX_IP4TXMCOCTS].name		= "ip4OutMcastOctets",
	[IRDMA_HW_STAT_INDEX_IP6RXMCOCTS].name		= "ip6InMcastOctets",
	[IRDMA_HW_STAT_INDEX_IP6TXMCOCTS].name		= "ip6OutMcastOctets",
	[IRDMA_HW_STAT_INDEX_UDPRXPKTS].name		= "RxUDP",
	[IRDMA_HW_STAT_INDEX_UDPTXPKTS].name		= "TxUDP",
	[IRDMA_HW_STAT_INDEX_RXNPECNMARKEDPKTS].name	= "RxECNMrkd",
	[IRDMA_HW_STAT_INDEX_TCPRTXSEG].name		= "RetransSegs",
	[IRDMA_HW_STAT_INDEX_TCPRXOPTERR].name		= "InOptErrors",
	[IRDMA_HW_STAT_INDEX_TCPRXPROTOERR].name	= "InProtoErrors",
	[IRDMA_HW_STAT_INDEX_TCPRXSEGS].name		= "InSegs",
	[IRDMA_HW_STAT_INDEX_TCPTXSEG].name		= "OutSegs",

	/* gen3 */
	[IRDMA_HW_STAT_INDEX_RNR_SENT].name		= "RNR sent",
	[IRDMA_HW_STAT_INDEX_RNR_RCVD].name		= "RNR received",
	[IRDMA_HW_STAT_INDEX_RDMAORDLMTCNT].name	= "ord limit count",
	[IRDMA_HW_STAT_INDEX_RDMAIRDLMTCNT].name	= "ird limit count",
	[IRDMA_HW_STAT_INDEX_RDMARXATS].name		= "Rx atomics",
	[IRDMA_HW_STAT_INDEX_RDMATXATS].name		= "Tx atomics",
	[IRDMA_HW_STAT_INDEX_NAKSEQERR].name		= "Nak Sequence Error",
	[IRDMA_HW_STAT_INDEX_NAKSEQERR_IMPLIED].name	= "Nak Sequence Error Implied",
	[IRDMA_HW_STAT_INDEX_RTO].name			= "RTO",
	[IRDMA_HW_STAT_INDEX_RXOOOPKTS].name		= "Rcvd Out of order packets",
	[IRDMA_HW_STAT_INDEX_ICRCERR].name		= "CRC errors",

	/* gen4 */
	[IRDMA_HW_STAT_INDEX_RDMARXFLUSH].name		= "Rx Flush",
	[IRDMA_HW_STAT_INDEX_RDMATXFLUSH].name		= "Tx Flush",
	[IRDMA_HW_STAT_INDEX_RDMARXATOMICWRITE].name	= "Rx Atomic Write",
	[IRDMA_HW_STAT_INDEX_RDMATXATOMICWRITE].name	= "Tx Atomic Write",
};
#ifdef static_assert

static_assert(ARRAY_SIZE(irdma_hw_stat_descs) >= IRDMA_HW_STAT_INDEX_MAX_GEN_4,
	      "irdma_hw_stat_descs and max_stat_idx mismatch");
#endif /* static_assert */

#endif /* ALLOC_HW_STATS_STRUCT_V2 */
/**
 * mcast_list_add -  Add a new mcast item to list
 * @rf: RDMA PCI function
 * @new_elem: pointer to element to add
 */
static void mcast_list_add(struct irdma_pci_f *rf,
			   struct mc_table_list *new_elem)
{
	list_add(&new_elem->list, &rf->mc_qht_list.list);
}

/**
 * mcast_list_del - Remove an mcast item from list
 * @mc_qht_elem: pointer to mcast table list element
 */
static void mcast_list_del(struct mc_table_list *mc_qht_elem)
{
	if (mc_qht_elem)
		list_del(&mc_qht_elem->list);
}

/**
 * mcast_list_lookup_ip - Search mcast list for address
 * @rf: RDMA PCI function
 * @ip_mcast: pointer to mcast IP address
 */
static struct mc_table_list *mcast_list_lookup_ip(struct irdma_pci_f *rf,
						  u32 *ip_mcast)
{
	struct mc_table_list *mc_qht_el;
	struct list_head *pos, *q;

	list_for_each_safe (pos, q, &rf->mc_qht_list.list) {
		mc_qht_el = list_entry(pos, struct mc_table_list, list);
		if (!memcmp(mc_qht_el->mc_info.dest_ip, ip_mcast,
			    sizeof(mc_qht_el->mc_info.dest_ip)))
			return mc_qht_el;
	}

	return NULL;
}

/**
 * irdma_mcast_cqp_op - perform a mcast cqp operation
 * @iwdev: irdma device
 * @mc_grp_ctx: mcast group info
 * @op: operation
 *
 * returns error status
 */
static int irdma_mcast_cqp_op(struct irdma_device *iwdev,
			      struct irdma_mcast_grp_info *mc_grp_ctx, u8 op)
{
	struct cqp_cmds_info *cqp_info;
	struct irdma_cqp_request *cqp_request;
	int status;

	cqp_request = irdma_alloc_and_get_cqp_request(&iwdev->rf->cqp, true);
	if (!cqp_request)
		return -ENOMEM;

	cqp_request->info.in.u.mc_create.info = *mc_grp_ctx;
	cqp_info = &cqp_request->info;
	cqp_info->cqp_cmd = op;
	cqp_info->post_sq = 1;
	cqp_info->in.u.mc_create.scratch = (uintptr_t)cqp_request;
	cqp_info->in.u.mc_create.cqp = &iwdev->rf->cqp.sc_cqp;

	if (op == IRDMA_OP_MC_CREATE)
		cqp_info->create = true;

	status = irdma_handle_cqp_op(iwdev->rf, cqp_request);
	irdma_put_cqp_request(&iwdev->rf->cqp, cqp_request);

	return status;
}

/**
 * irdma_attach_mcast - attach a qp to a multicast group
 * @ibqp: ptr to qp
 * @ibgid: pointer to global ID
 * @lid: local ID
 *
 * returns error status
 */
static int irdma_attach_mcast(struct ib_qp *ibqp, union ib_gid *ibgid, u16 lid)
{
	struct irdma_qp *iwqp = to_iwqp(ibqp);
	struct irdma_device *iwdev = iwqp->iwdev;
	struct irdma_pci_f *rf = iwdev->rf;
	struct mc_table_list *mc_qht_elem;
	struct irdma_mcast_grp_ctx_entry_info mcg_info = {};
	unsigned long flags;
	u32 ip_addr[4] = {};
	u32 mgn;
	u32 no_mgs;
	int ret = 0;
	bool ipv4;
	u16 vlan_id;
	union irdma_sockaddr sgid_addr;
	unsigned char dmac[ETH_ALEN];

	rdma_gid2ip((struct sockaddr *)&sgid_addr, ibgid);

	if (!ipv6_addr_v4mapped((struct in6_addr *)ibgid)) {
		irdma_copy_ip_ntohl(ip_addr,
				    sgid_addr.saddr_in6.sin6_addr.in6_u.u6_addr32);
		irdma_get_vlan_mac_ipv6(ip_addr, &vlan_id, NULL);
		ipv4 = false;
		ibdev_dbg(&iwdev->ibdev,
			  "VERBS: qp_id=%d, IP6address=%pI6\n", ibqp->qp_num,
			  ip_addr);
		irdma_mcast_mac_v6(ip_addr, dmac);
	} else {
		ip_addr[0] = ntohl(sgid_addr.saddr_in.sin_addr.s_addr);
		ipv4 = true;
		vlan_id = irdma_get_vlan_ipv4(ip_addr);
		irdma_mcast_mac_v4(ip_addr, dmac);
		ibdev_dbg(&iwdev->ibdev,
			  "VERBS: qp_id=%d, IP4address=%pI4, MAC=%pM\n",
			  ibqp->qp_num, ip_addr, dmac);
	}

	spin_lock_irqsave(&rf->qh_list_lock, flags);
	mc_qht_elem = mcast_list_lookup_ip(rf, ip_addr);
	if (!mc_qht_elem) {
		struct irdma_dma_mem *dma_mem_mc;

		spin_unlock_irqrestore(&rf->qh_list_lock, flags);
		mc_qht_elem = kzalloc(sizeof(*mc_qht_elem), GFP_KERNEL);
		if (!mc_qht_elem)
			return -ENOMEM;

		mc_qht_elem->mc_info.ipv4_valid = ipv4;
		memcpy(mc_qht_elem->mc_info.dest_ip, ip_addr,
		       sizeof(mc_qht_elem->mc_info.dest_ip));
		ret = irdma_alloc_rsrc(rf, rf->allocated_mcgs, rf->max_mcg,
				       &mgn, &rf->next_mcg);
		if (ret) {
			kfree(mc_qht_elem);
			return -ENOMEM;
		}

		mc_qht_elem->mc_info.mgn = mgn;
		dma_mem_mc = &mc_qht_elem->mc_grp_ctx.dma_mem_mc;
		dma_mem_mc->size = ALIGN(sizeof(u64) * IRDMA_MAX_MGS_PER_CTX,
					 IRDMA_HW_PAGE_SIZE);
		dma_mem_mc->va = dma_alloc_coherent(rf->hw.device,
						    dma_mem_mc->size,
						    &dma_mem_mc->pa,
						    GFP_KERNEL);
		if (!dma_mem_mc->va) {
			irdma_free_rsrc(rf, rf->allocated_mcgs, mgn);
			kfree(mc_qht_elem);
			return -ENOMEM;
		}

		mc_qht_elem->mc_grp_ctx.mg_id = (u16)mgn;
		memcpy(mc_qht_elem->mc_grp_ctx.dest_ip_addr, ip_addr,
		       sizeof(mc_qht_elem->mc_grp_ctx.dest_ip_addr));
		mc_qht_elem->mc_grp_ctx.ipv4_valid = ipv4;
		mc_qht_elem->mc_grp_ctx.vlan_id = vlan_id;
		if (vlan_id < VLAN_N_VID)
			mc_qht_elem->mc_grp_ctx.vlan_valid = true;
		mc_qht_elem->mc_grp_ctx.hmc_fcn_id = iwdev->rf->sc_dev.hmc_fn_id;
		mc_qht_elem->mc_grp_ctx.qs_handle =
			iwqp->sc_qp.vsi->qos[iwqp->sc_qp.user_pri].qs_handle[iwqp->sc_qp.qs_idx];
		ether_addr_copy(mc_qht_elem->mc_grp_ctx.dest_mac_addr, dmac);

		spin_lock_irqsave(&rf->qh_list_lock, flags);
		mcast_list_add(rf, mc_qht_elem);
	} else {
		if (mc_qht_elem->mc_grp_ctx.no_of_mgs ==
		    IRDMA_MAX_MGS_PER_CTX) {
			spin_unlock_irqrestore(&rf->qh_list_lock, flags);
			return -ENOMEM;
		}
	}

	mcg_info.qp_id = iwqp->ibqp.qp_num;
	no_mgs = mc_qht_elem->mc_grp_ctx.no_of_mgs;
	irdma_sc_add_mcast_grp(&mc_qht_elem->mc_grp_ctx, &mcg_info);
	spin_unlock_irqrestore(&rf->qh_list_lock, flags);

	/* Only if there is a change do we need to modify or create */
	if (!no_mgs) {
		ret = irdma_mcast_cqp_op(iwdev, &mc_qht_elem->mc_grp_ctx,
					 IRDMA_OP_MC_CREATE);
	} else if (no_mgs != mc_qht_elem->mc_grp_ctx.no_of_mgs) {
		ret = irdma_mcast_cqp_op(iwdev, &mc_qht_elem->mc_grp_ctx,
					 IRDMA_OP_MC_MODIFY);
	} else {
		return 0;
	}

	if (ret)
		goto error;

	return 0;

error:
	irdma_sc_del_mcast_grp(&mc_qht_elem->mc_grp_ctx, &mcg_info);
	if (!mc_qht_elem->mc_grp_ctx.no_of_mgs) {
		mcast_list_del(mc_qht_elem);
		dma_free_coherent(rf->hw.device,
				  mc_qht_elem->mc_grp_ctx.dma_mem_mc.size,
				  mc_qht_elem->mc_grp_ctx.dma_mem_mc.va,
				  mc_qht_elem->mc_grp_ctx.dma_mem_mc.pa);
		mc_qht_elem->mc_grp_ctx.dma_mem_mc.va = NULL;
		irdma_free_rsrc(rf, rf->allocated_mcgs,
				mc_qht_elem->mc_grp_ctx.mg_id);
		kfree(mc_qht_elem);
	}

	return ret;
}

/**
 * irdma_detach_mcast - detach a qp from a multicast group
 * @ibqp: ptr to qp
 * @ibgid: pointer to global ID
 * @lid: local ID
 *
 * returns error status
 */
static int irdma_detach_mcast(struct ib_qp *ibqp, union ib_gid *ibgid, u16 lid)
{
	struct irdma_qp *iwqp = to_iwqp(ibqp);
	struct irdma_device *iwdev = iwqp->iwdev;
	struct irdma_pci_f *rf = iwdev->rf;
	u32 ip_addr[4] = {};
	struct mc_table_list *mc_qht_elem;
	struct irdma_mcast_grp_ctx_entry_info mcg_info = {};
	int ret;
	unsigned long flags;
	union irdma_sockaddr sgid_addr;

	rdma_gid2ip((struct sockaddr *)&sgid_addr, ibgid);
	if (!ipv6_addr_v4mapped((struct in6_addr *)ibgid))
		irdma_copy_ip_ntohl(ip_addr,
				    sgid_addr.saddr_in6.sin6_addr.in6_u.u6_addr32);
	else
		ip_addr[0] = ntohl(sgid_addr.saddr_in.sin_addr.s_addr);

	spin_lock_irqsave(&rf->qh_list_lock, flags);
	mc_qht_elem = mcast_list_lookup_ip(rf, ip_addr);
	if (!mc_qht_elem) {
		spin_unlock_irqrestore(&rf->qh_list_lock, flags);
		ibdev_dbg(&iwdev->ibdev,
			  "VERBS: address not found MCG\n");
		return 0;
	}

	mcg_info.qp_id = iwqp->ibqp.qp_num;
	irdma_sc_del_mcast_grp(&mc_qht_elem->mc_grp_ctx, &mcg_info);
	if (!mc_qht_elem->mc_grp_ctx.no_of_mgs) {
		mcast_list_del(mc_qht_elem);
		spin_unlock_irqrestore(&rf->qh_list_lock, flags);
		ret = irdma_mcast_cqp_op(iwdev, &mc_qht_elem->mc_grp_ctx,
					 IRDMA_OP_MC_DESTROY);
		if (ret) {
			ibdev_dbg(&iwdev->ibdev,
				  "VERBS: failed MC_DESTROY MCG\n");
			spin_lock_irqsave(&rf->qh_list_lock, flags);
			mcast_list_add(rf, mc_qht_elem);
			spin_unlock_irqrestore(&rf->qh_list_lock, flags);
			return -EAGAIN;
		}

		dma_free_coherent(rf->hw.device,
				  mc_qht_elem->mc_grp_ctx.dma_mem_mc.size,
				  mc_qht_elem->mc_grp_ctx.dma_mem_mc.va,
				  mc_qht_elem->mc_grp_ctx.dma_mem_mc.pa);
		mc_qht_elem->mc_grp_ctx.dma_mem_mc.va = NULL;
		irdma_free_rsrc(rf, rf->allocated_mcgs,
				mc_qht_elem->mc_grp_ctx.mg_id);
		kfree(mc_qht_elem);
	} else {
		spin_unlock_irqrestore(&rf->qh_list_lock, flags);
		ret = irdma_mcast_cqp_op(iwdev, &mc_qht_elem->mc_grp_ctx,
					 IRDMA_OP_MC_MODIFY);
		if (ret) {
			ibdev_dbg(&iwdev->ibdev,
				  "VERBS: failed Modify MCG\n");
			return ret;
		}
	}

	return 0;
}

/**
 * irdma_query_ah - Query address handle
 * @ibah: pointer to address handle
 * @ah_attr: address handle attributes
 */
static int irdma_query_ah(struct ib_ah *ibah, struct rdma_ah_attr *ah_attr)
{
	struct irdma_ah *ah = to_iwah(ibah);

	memset(ah_attr, 0, sizeof(*ah_attr));
	if (ah->av.attrs.ah_flags & IB_AH_GRH) {
		ah_attr->ah_flags = IB_AH_GRH;
		ah_attr->grh.flow_label = ah->sc_ah.ah_info.flow_label;
		ah_attr->grh.traffic_class = ah->sc_ah.ah_info.tc_tos;
		ah_attr->grh.hop_limit = ah->sc_ah.ah_info.hop_ttl;
		ah_attr->grh.sgid_index = ah->sgid_index;
		ah_attr->grh.sgid_index = ah->sgid_index;
		memcpy(&ah_attr->grh.dgid, &ah->dgid,
		       sizeof(ah_attr->grh.dgid));
	}

	return 0;
}

#ifdef IB_DEALLOC_DRIVER_SUPPORT
/**
 * irdma_ib_dealloc_device
 * @ibdev: ib device
 *
 * callback from ibdev dealloc_driver to deallocate resources
 * unber irdma device
 */
static inline void irdma_ib_dealloc_device(struct ib_device *ibdev)
{
	irdma_deinit_device(to_iwdev(ibdev));
}
#endif

#ifdef IB_GET_NETDEV_OP_NOT_DEPRECATED
#ifdef GET_NETDEV_OP_V2
static struct net_device *irdma_get_netdev(struct ib_device *ibdev, u32 port_num)
#else
static struct net_device *irdma_get_netdev(struct ib_device *ibdev, u8 port_num)
#endif
{
	struct irdma_device *iwdev = to_iwdev(ibdev);

	if (iwdev->netdev) {
		dev_hold(iwdev->netdev);
		return iwdev->netdev;
	}

	return NULL;
}

#endif
#ifdef HAS_IB_SET_DEVICE_OP
static struct ib_device_ops irdma_gen3_dev_ops;
static const struct ib_device_ops irdma_stats_dev_ops = {
#if defined(ALLOC_HW_STATS_V3)
	.alloc_hw_port_stats = irdma_alloc_hw_port_stats,
#else
	.alloc_hw_stats = irdma_alloc_hw_stats,
#endif
};
#ifdef IB_DEALLOC_DRIVER_SUPPORT
static struct ib_device_ops irdma_gen1_dev_ops;
#endif /* IB_DEALLOC_DRIVER_SUPPORT */
static struct ib_device_ops irdma_roce_dev_ops;
static struct ib_device_ops irdma_mcast_ops;
static struct ib_device_ops irdma_iw_dev_ops;
static const struct ib_device_ops irdma_dev_ops = {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 3, 0) || defined(RHEL_8_2) || defined(RHEL_8_3) || defined(RHEL_8_4) || defined(RHEL_8_5) || defined(RHEL_8_6) || defined(RHEL_8_7) || defined(RHEL_8_8)
	.owner = THIS_MODULE,
	.driver_id = RDMA_DRIVER_I40IW,
	.uverbs_abi_ver = IRDMA_ABI_VER,
#endif
	.alloc_mr = irdma_alloc_mr,
	.alloc_pd = irdma_alloc_pd,
	.alloc_ucontext = irdma_alloc_ucontext,
	.create_cq = irdma_create_cq,
	.create_qp = irdma_create_qp,
	.dealloc_pd = irdma_dealloc_pd,
	.dealloc_ucontext = irdma_dealloc_ucontext,
	.dereg_mr = irdma_dereg_mr,
	.destroy_cq = irdma_destroy_cq,
	.destroy_qp = irdma_destroy_qp,
	.disassociate_ucontext = irdma_disassociate_ucontext,
	.get_dev_fw_str = irdma_get_dev_fw_str,
	.get_dma_mr = irdma_get_dma_mr,
	.get_hw_stats = irdma_get_hw_stats,
#ifdef IB_GET_NETDEV_OP_NOT_DEPRECATED
	.get_netdev = irdma_get_netdev,
#endif
	.map_mr_sg = irdma_map_mr_sg,
	.mmap = irdma_mmap,
#ifdef RDMA_MMAP_DB_SUPPORT
	.mmap_free = irdma_mmap_free,
#endif
	.poll_cq = irdma_poll_cq,
	.post_recv = irdma_post_recv,
	.post_send = irdma_post_send,
	.query_device = irdma_query_device,
	.query_port = irdma_query_port,
	.modify_port = irdma_modify_port,
	.query_qp = irdma_query_qp,
#ifdef SET_DMABUF
	.reg_user_mr_dmabuf = irdma_reg_user_mr_dmabuf,
#endif
	.reg_user_mr = irdma_reg_user_mr,
	.rereg_user_mr = irdma_rereg_user_mr,
	.req_notify_cq = irdma_req_notify_cq,
	.resize_cq = irdma_resize_cq,
#ifdef INIT_RDMA_OBJ_SIZE
	INIT_RDMA_OBJ_SIZE(ib_pd, irdma_pd, ibpd),
	INIT_RDMA_OBJ_SIZE(ib_ucontext, irdma_ucontext, ibucontext),
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0) || defined(RHEL_8_2) || defined(RHEL_8_3) || defined(RHEL_8_4) || defined(RHEL_8_5) || defined(RHEL_8_6) || defined(RHEL_8_7) || defined(RHEL_8_8)
	INIT_RDMA_OBJ_SIZE(ib_ah, irdma_ah, ibah),
	INIT_RDMA_OBJ_SIZE(ib_srq, irdma_srq, ibsrq),
#endif /* 5.2.0 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 3, 0) || defined(RHEL_8_2) || defined(RHEL_8_3) || defined(RHEL_8_4) || defined(RHEL_8_5) || defined(RHEL_8_6) || defined(RHEL_8_7) || defined(RHEL_8_8)
	INIT_RDMA_OBJ_SIZE(ib_cq, irdma_cq, ibcq),
#endif /* 5.3.0 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0) || defined(RHEL_8_5) || defined(RHEL_8_6) || defined(RHEL_8_7) || defined(RHEL_8_8)
	INIT_RDMA_OBJ_SIZE(ib_mw, irdma_mr, ibmw),
#endif /* 5.10.0 */
#ifdef GLOBAL_QP_MEM
	INIT_RDMA_OBJ_SIZE(ib_qp, irdma_qp, ibqp),
#endif /* GLOBAL_QP_MEM */
#endif /* INIT_RDMA_OBJ_SIZE */
};

#endif /* HAS_IB_SET_DEVICE_OP */
static void irdma_set_device_ops(struct ib_device *ibdev)
{
#ifndef HAS_IB_SET_DEVICE_OP
	struct ib_device *dev_ops = ibdev;

#if defined(RHEL_7_7) || defined(RHEL_7_8) || defined(RHEL_7_9) || defined(RHEL_8_2) || defined(RHEL_8_3) || defined(RHEL_8_4) || defined(RHEL_8_5) || defined(RHEL_8_6) || defined(RHEL_8_7) || defined(RHEL_8_8)
	dev_ops->uverbs_abi_ver = IRDMA_ABI_VER;
	dev_ops->driver_id = RDMA_DRIVER_I40IW;
	dev_ops->owner = THIS_MODULE;
#endif
	if (!irdma_rca_ena || to_iwdev(ibdev)->rf->ftype)
		dev_ops->alloc_hw_stats = irdma_alloc_hw_stats;
	dev_ops->alloc_mr = irdma_alloc_mr;
	dev_ops->alloc_pd = irdma_alloc_pd;
	dev_ops->alloc_ucontext = irdma_alloc_ucontext;
	dev_ops->create_cq = irdma_create_cq;
	dev_ops->create_qp = irdma_create_qp;
	dev_ops->dealloc_pd = irdma_dealloc_pd;
	dev_ops->dealloc_ucontext = irdma_dealloc_ucontext;
	dev_ops->dereg_mr = irdma_dereg_mr;
	dev_ops->destroy_cq = irdma_destroy_cq;
	dev_ops->destroy_qp = irdma_destroy_qp;
	dev_ops->disassociate_ucontext = irdma_disassociate_ucontext;
	dev_ops->get_dev_fw_str = irdma_get_dev_fw_str;
	dev_ops->get_dma_mr = irdma_get_dma_mr;
	dev_ops->get_hw_stats = irdma_get_hw_stats;
	dev_ops->get_netdev = irdma_get_netdev;
	dev_ops->map_mr_sg = irdma_map_mr_sg;
	dev_ops->mmap = irdma_mmap;
#ifdef RDMA_MMAP_DB_SUPPORT
	dev_ops->mmap_free = irdma_mmap_free;
#endif
	dev_ops->poll_cq = irdma_poll_cq;
	dev_ops->post_recv = irdma_post_recv;
	dev_ops->post_send = irdma_post_send;
	dev_ops->query_device = irdma_query_device;
	dev_ops->query_port = irdma_query_port;
	dev_ops->modify_port = irdma_modify_port;
	dev_ops->query_qp = irdma_query_qp;
#ifdef SET_DMABUF
	dev_ops->reg_user_mr_dmabuf = irdma_reg_user_mr_dmabuf,
#endif
	dev_ops->reg_user_mr = irdma_reg_user_mr;
	dev_ops->rereg_user_mr = irdma_rereg_user_mr;
	dev_ops->req_notify_cq = irdma_req_notify_cq;
	dev_ops->resize_cq = irdma_resize_cq;
	dev_ops->create_srq = irdma_create_srq;
	dev_ops->destroy_srq = irdma_destroy_srq;
	dev_ops->modify_srq = irdma_modify_srq;
	dev_ops->query_srq = irdma_query_srq;
	dev_ops->post_srq_recv = irdma_post_srq_recv;
#else  /* !HAS_IB_SET_DEVICE_OP */
	ib_set_device_ops(ibdev, &irdma_dev_ops);
	if (!irdma_rca_ena || to_iwdev(ibdev)->rf->ftype)
		ib_set_device_ops(ibdev, &irdma_stats_dev_ops);
#endif  /* !HAS_IB_SET_DEVICE_OP */
}

static void irdma_set_device_mcast_ops(struct ib_device *ibdev)
{
#ifdef HAS_IB_SET_DEVICE_OP
	struct ib_device_ops *dev_ops = &irdma_mcast_ops;
#else
	struct ib_device *dev_ops = ibdev;
#endif
	dev_ops->attach_mcast = irdma_attach_mcast;
	dev_ops->detach_mcast = irdma_detach_mcast;
#ifdef HAS_IB_SET_DEVICE_OP
	ib_set_device_ops(ibdev, &irdma_mcast_ops);
#endif
}

static void irdma_set_device_roce_ops(struct ib_device *ibdev)
{
#ifdef HAS_IB_SET_DEVICE_OP
	struct ib_device_ops *dev_ops = &irdma_roce_dev_ops;
#else
	struct ib_device *dev_ops = ibdev;
#endif
	dev_ops->create_ah = irdma_create_ah;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0) || defined(RHEL_8_5) || defined(RHEL_8_6) || defined(RHEL_8_7) || defined(RHEL_8_8)
	dev_ops->create_user_ah = irdma_create_ah;
#endif
	dev_ops->destroy_ah = irdma_destroy_ah;
	dev_ops->get_link_layer = irdma_get_link_layer;
	dev_ops->get_port_immutable = irdma_roce_port_immutable;
	dev_ops->modify_qp = irdma_modify_qp_roce;
	dev_ops->query_ah = irdma_query_ah;
	dev_ops->query_gid = irdma_query_gid_roce;
	dev_ops->query_pkey = irdma_query_pkey;
	kc_set_ibdev_add_del_gid(ibdev);
#ifdef HAS_IB_SET_DEVICE_OP
	ib_set_device_ops(ibdev, &irdma_roce_dev_ops);
#endif
}

static void irdma_set_device_iw_ops(struct ib_device *ibdev)
{
#ifdef HAS_IB_SET_DEVICE_OP
	struct ib_device_ops *dev_ops = &irdma_iw_dev_ops;
#else
	struct ib_device *dev_ops = ibdev;
#endif

#ifdef IB_IW_MANDATORY_AH_OP
	ibdev->uverbs_cmd_mask |=
		(1ull << IB_USER_VERBS_CMD_CREATE_AH) |
		(1ull << IB_USER_VERBS_CMD_DESTROY_AH);

	dev_ops->create_ah = irdma_create_ah_stub;
	dev_ops->destroy_ah = irdma_destroy_ah_stub;
#endif
	dev_ops->get_port_immutable = irdma_iw_port_immutable;
	dev_ops->modify_qp = irdma_modify_qp;
	dev_ops->query_gid = irdma_query_gid;
#ifdef IB_IW_PKEY
	dev_ops->query_pkey = irdma_iw_query_pkey;
#endif
#ifdef HAS_IB_SET_DEVICE_OP
	ib_set_device_ops(ibdev, &irdma_iw_dev_ops);
#endif
}

static inline void irdma_set_device_gen1_ops(struct ib_device *ibdev)
{
#ifdef IB_DEALLOC_DRIVER_SUPPORT
#ifdef HAS_IB_SET_DEVICE_OP
	struct ib_device_ops *dev_ops = &irdma_gen1_dev_ops;
#else
	struct ib_device *dev_ops = ibdev;
#endif
	dev_ops->dealloc_driver = irdma_ib_dealloc_device,
#ifdef HAS_IB_SET_DEVICE_OP
	ib_set_device_ops(ibdev, &irdma_gen1_dev_ops);
#endif
#endif /* IB_DEALLOC_DRIVER_SUPPORT */
}

static inline void irdma_set_device_gen3_ops(struct ib_device *ibdev)
{
#ifdef HAS_IB_SET_DEVICE_OP
	struct ib_device_ops *dev_ops = &irdma_gen3_dev_ops;
#else
	struct ib_device *dev_ops = ibdev;
#endif
	dev_ops->alloc_mw = irdma_alloc_mw,
	dev_ops->dealloc_mw = irdma_dealloc_mw,
	dev_ops->create_srq = irdma_create_srq;
	dev_ops->destroy_srq = irdma_destroy_srq;
	dev_ops->modify_srq = irdma_modify_srq;
	dev_ops->query_srq = irdma_query_srq;
	dev_ops->post_srq_recv = irdma_post_srq_recv;
#ifdef HAS_IB_SET_DEVICE_OP
	ib_set_device_ops(ibdev, &irdma_gen3_dev_ops);
#endif
}

/**
 * irdma_init_roce_device - initialization of roce rdma device
 * @iwdev: irdma device
 */
static void irdma_init_roce_device(struct irdma_device *iwdev)
{
#ifdef UVERBS_CMD_MASK
	kc_set_roce_uverbs_cmd_mask(iwdev);
#endif
	iwdev->ibdev.node_type = RDMA_NODE_IB_CA;
	addrconf_addr_eui48((u8 *)&iwdev->ibdev.node_guid,
			    iwdev->netdev->dev_addr);
	irdma_set_device_roce_ops(&iwdev->ibdev);
	if (iwdev->rf->rdma_ver == IRDMA_GEN_2)
		irdma_set_device_mcast_ops(&iwdev->ibdev);
}

/**
 * irdma_init_iw_device - initialization of iwarp rdma device
 * @iwdev: irdma device
 */
static int irdma_init_iw_device(struct irdma_device *iwdev)
{
	struct net_device *netdev = iwdev->netdev;

	iwdev->ibdev.node_type = RDMA_NODE_RNIC;
	addrconf_addr_eui48((u8 *)&iwdev->ibdev.node_guid,
			    netdev->dev_addr);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0) || defined(RHEL_8_2) || defined(RHEL_8_3) || defined(RHEL_8_4) || defined(RHEL_8_5) || defined(RHEL_8_6) || defined(RHEL_8_7) || defined(RHEL_8_8)
	iwdev->ibdev.ops.iw_add_ref = irdma_qp_add_ref;
	iwdev->ibdev.ops.iw_rem_ref = irdma_qp_rem_ref;
	iwdev->ibdev.ops.iw_get_qp = irdma_get_qp;
	iwdev->ibdev.ops.iw_connect = irdma_connect;
	iwdev->ibdev.ops.iw_accept = irdma_accept;
	iwdev->ibdev.ops.iw_reject = irdma_reject;
	iwdev->ibdev.ops.iw_create_listen = irdma_create_listen;
	iwdev->ibdev.ops.iw_destroy_listen = irdma_destroy_listen;
	memcpy(iwdev->ibdev.iw_ifname, netdev->name,
	       sizeof(iwdev->ibdev.iw_ifname));
#else
	iwdev->ibdev.iwcm = kzalloc(sizeof(*iwdev->ibdev.iwcm), GFP_KERNEL);
	if (!iwdev->ibdev.iwcm)
		return -ENOMEM;

	iwdev->ibdev.iwcm->add_ref = irdma_qp_add_ref;
	iwdev->ibdev.iwcm->rem_ref = irdma_qp_rem_ref;
	iwdev->ibdev.iwcm->get_qp = irdma_get_qp;
	iwdev->ibdev.iwcm->connect = irdma_connect;
	iwdev->ibdev.iwcm->accept = irdma_accept;
	iwdev->ibdev.iwcm->reject = irdma_reject;
	iwdev->ibdev.iwcm->create_listen = irdma_create_listen;
	iwdev->ibdev.iwcm->destroy_listen = irdma_destroy_listen;
	memcpy(iwdev->ibdev.iwcm->ifname, netdev->name,
	       sizeof(iwdev->ibdev.iwcm->ifname));
#endif
	irdma_set_device_iw_ops(&iwdev->ibdev);

	return 0;
}

/**
 * irdma_init_rdma_device - initialization of rdma device
 * @iwdev: irdma device
 */
static int irdma_init_rdma_device(struct irdma_device *iwdev)
{
	int ret;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 3, 0) && !defined(RHEL_8_2) && !defined(RHEL_8_3) && !defined(RHEL_8_4) && !defined(RHEL_8_5) && !defined(RHEL_8_6) && !defined(RHEL_8_7) && !defined(RHEL_8_8)
	iwdev->ibdev.owner = THIS_MODULE;
	iwdev->ibdev.uverbs_abi_ver = IRDMA_ABI_VER;
#endif
#ifdef UVERBS_CMD_MASK
	kc_set_rdma_uverbs_cmd_mask(iwdev);
#endif

	if (iwdev->roce_mode) {
		irdma_init_roce_device(iwdev);
	} else {
		ret = irdma_init_iw_device(iwdev);
		if (ret)
			return ret;
	}

	iwdev->ibdev.phys_port_cnt = 1;
	iwdev->ibdev.num_comp_vectors = iwdev->rf->ceqs_count;
	iwdev->ibdev.dev.parent = &iwdev->rf->pcidev->dev;
	set_ibdev_dma_device(iwdev->ibdev, &iwdev->rf->pcidev->dev);
	irdma_set_device_ops(&iwdev->ibdev);
	if (iwdev->rf->rdma_ver == IRDMA_GEN_1)
		irdma_set_device_gen1_ops(&iwdev->ibdev);
	if (iwdev->rf->rdma_ver >= IRDMA_GEN_3)
		irdma_set_device_gen3_ops(&iwdev->ibdev);

	return 0;
}

/**
 * irdma_port_ibevent - indicate port event
 * @iwdev: irdma device
 */
void irdma_port_ibevent(struct irdma_device *iwdev)
{
	struct ib_event event;

	event.device = &iwdev->ibdev;
	event.element.port_num = 1;
	event.event =
		iwdev->iw_status ? IB_EVENT_PORT_ACTIVE : IB_EVENT_PORT_ERR;
	ib_dispatch_event(&event);
}

/**
 * irdma_ib_unregister_device - unregister rdma device from IB
 * core
 * @iwdev: irdma device
 */
void irdma_ib_unregister_device(struct irdma_device *iwdev)
{
	iwdev->iw_status = 0;
	irdma_port_ibevent(iwdev);
	ib_unregister_device(&iwdev->ibdev);
#ifndef NETDEV_TO_IBDEV_SUPPORT
	dev_put(iwdev->netdev);
#endif
	irdma_release_ib_devname(iwdev);
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 2, 0) && !defined(RHEL_8_2) && !defined(RHEL_8_3) && !defined(RHEL_8_4) && !defined(RHEL_8_5) && !defined(RHEL_8_6) && !defined(RHEL_8_7) && !defined(RHEL_8_8)
	kfree(iwdev->ibdev.iwcm);
	iwdev->ibdev.iwcm = NULL;
#endif
}

/**
 * irdma_ib_register_device - register irdma device to IB core
 * @iwdev: irdma device
 */
int irdma_ib_register_device(struct irdma_device *iwdev)
{
	const char *name = irdma_set_ib_devname(iwdev);
	int ret;

	ret = irdma_init_rdma_device(iwdev);
	if (ret)
		return ret;

	kc_set_driver_id(iwdev->ibdev);
#ifdef NETDEV_TO_IBDEV_SUPPORT
	ret = ib_device_set_netdev(&iwdev->ibdev, iwdev->netdev, 1);
	if (ret)
		goto error;
#else
	dev_hold(iwdev->netdev);
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 20, 0)
#ifdef CONFIG_SUSE_KERNEL
#if SLE_VERSION_CODE <= SLE_VERSION(15, 0, 0)
	strlcpy(iwdev->ibdev.name, name, sizeof(iwdev->ibdev.name));
#endif /* SLE_VERSION_CODE */
#else
	strlcpy(iwdev->ibdev.name, name, sizeof(iwdev->ibdev.name));
#endif /* CONFIG_SUSE_KERNEL */
#endif /* LINUX_VERSION_CODE */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
	dma_set_max_seg_size(iwdev->rf->hw.device, SZ_2G);
#endif
	ret = kc_ib_register_device(&iwdev->ibdev, name, iwdev->rf->hw.device);
	if (ret)
		goto error;

	iwdev->iw_status = 1;
	irdma_port_ibevent(iwdev);

	return 0;

error:
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 2, 0) && !defined(RHEL_8_2) && !defined(RHEL_8_3) && !defined(RHEL_8_4) && !defined(RHEL_8_5) && !defined(RHEL_8_6) && !defined(RHEL_8_7) && !defined(RHEL_8_8)
	kfree(iwdev->ibdev.iwcm);
	iwdev->ibdev.iwcm = NULL;
#endif
	ibdev_dbg(&iwdev->ibdev, "VERBS: Register RDMA device fail\n");

	return ret;
}

