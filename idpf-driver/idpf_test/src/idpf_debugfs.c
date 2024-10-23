/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2019-2024 Intel Corporation */

// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2022 Intel Corporation */

#include "kcompat.h"
#include <linux/fs.h>
#include <linux/debugfs.h>
#include "idpf.h"

static struct dentry *idpf_debugfs_root;

/**************************************************************
 * command
 * The command entry in debugfs is for giving the idpf commands
 * to be executed - these will be useful for some forms of unit
 * testing.
 **************************************************************/

/**
 * idpf_debugfs_addr_in_range - check if address is in BAR's range
 * @adapter: the idpf corresponding to the address
 * @address: the address to verify
 * @bar: the BAR corresponding to the address
 */
static bool idpf_debugfs_addr_in_range(struct idpf_adapter *adapter,
				       u32 address, int bar)
{
	struct idpf_hw *hw = &adapter->hw;
	u32 hw_addr_len;

	if (bar == IDPF_BAR0)
		hw_addr_len = hw->hw_addr_len;
	else
		return false;

	if (address <= (hw_addr_len - sizeof(u32)))
		return true;

	dev_err(idpf_adapter_to_dev(adapter),
		"reg address 0x%08x too large, max=0x%08lx\n", address,
		(hw_addr_len - sizeof(u32)));

	return false;
}

/**
 * idpf_debugfs_addr_aligned - check if address is aligned to u32
 * @adapter: the idpf corresponding to the address
 * @address: the address to verify
 */
static bool idpf_debugfs_addr_aligned(struct idpf_adapter *adapter, u32 address)
{
	if (IS_ALIGNED(address, sizeof(u32)))
		return true;

	dev_err(idpf_adapter_to_dev(adapter), "register must be 32-bit aligned\n");

	return false;
}

/**
 * idpf_debugfs_write - write into command datum
 * @filp: the opened file
 * @buf: where to find the user's data
 * @count: the length of the user's data
 * @ppos: file position offset
 */
static ssize_t
idpf_debugfs_write(struct file *filp, const char __user *buf, size_t count,
		   loff_t *ppos)
{
	struct idpf_adapter *adapter =
			(struct idpf_adapter *)filp->private_data;
	struct device *dev = idpf_adapter_to_dev(adapter);
	struct idpf_hw *hw = &adapter->hw;
	char *cmd_buf, *cmd_buf_tmp;
	u32 address, value;
	ssize_t ret = 0;
	char **argv;
	int argc;

	/* don't allow partial writes */
	if (*ppos != 0)
		return 0;

	cmd_buf = memdup_user(buf, count + 1);
	if (IS_ERR(cmd_buf))
		return PTR_ERR(cmd_buf);
	cmd_buf[count] = '\0';

	cmd_buf_tmp = strchr(cmd_buf, '\n');
	if (cmd_buf_tmp) {
		*cmd_buf_tmp = '\0';
		count = (size_t)cmd_buf_tmp - (size_t)cmd_buf + 1;
	}

	argv = argv_split(GFP_KERNEL, cmd_buf, &argc);
	if (!argv) {
		ret = -ENOMEM;
		goto err_copy_from_user;
	}

	if (argc == 2 && !strncmp(argv[0], "read", 4)) {
		ret = kstrtou32(argv[1], 0, &address);
		if (ret)
			goto command_help;

		/* check the address */
		if (!idpf_debugfs_addr_in_range(adapter, address, IDPF_BAR0) ||
		    !idpf_debugfs_addr_aligned(adapter, address)) {
			ret = -EFAULT;
			dev_err(dev, "invalid address for read\n");
			goto command_write_done;
		}

		value = rd32(hw, address);
		dev_info(dev, "read: 0x%08x = 0x%08x\n", address, value);
	} else if ((argc == 3) && !strncmp(argv[0], "write", 5)) {
		ret = kstrtou32(argv[1], 0, &address);
		if (ret)
			goto command_help;

		ret = kstrtou32(argv[2], 0, &value);
		if (ret)
			goto command_help;

		/* check the address */
		if (!idpf_debugfs_addr_in_range(adapter, address, IDPF_BAR0) ||
		    !idpf_debugfs_addr_aligned(adapter, address)) {
			ret = -EFAULT;
			dev_err(dev, "invalid address for write\n");
			goto command_write_done;
		}

		wr32(hw, address, value);
		dev_info(dev, "write: 0x%08x = 0x%08x\n", address, value);
	} else if ((argc >= 2) && !strncmp(argv[0], "dft", 3)) {
		/* Set default tstamp_type to WITHIN_HORIZON */
		idpf_dft_tstamp_type = 0;

		if (argc == 2 && !strncmp(argv[1], "dump", 4)) {
			idpf_dft_dump_rules(dev);
		} else if (argc == 3 && !strncmp(argv[1], "tstamp", 6)) {
			if (!strncmp(argv[2], "beyond", 6))
				idpf_dft_tstamp_type = IDPF_DFT_BEYOND_HORIZON;
			else if (!strncmp(argv[2], "within", 6))
				idpf_dft_tstamp_type = IDPF_DFT_WITHIN_HORIZON;
			else if (!strncmp(argv[2], "before", 6))
				idpf_dft_tstamp_type = IDPF_DFT_BEFORE_HORIZON;
			else if (!strncmp(argv[2], "reverse", 7))
				idpf_dft_tstamp_type = IDPF_DFT_WITHIN_REVERSE;
			else
				goto command_help;
			 dev_info(dev, "Tstamp type now is %s\n", argv[2]);
		} else if ((argc == 5) && !strncmp(argv[1], "rule", 4)) {
			u32 idx, pacing;
			u16 port;

			ret = kstrtou32(argv[2], 0, &idx);
			if (ret)
				goto command_help;
			if (idx >= IDPF_MAX_DFT_RULES) {
				dev_info(dev, "index %u out of range, max index is: %d\n",
					 idx, IDPF_MAX_DFT_RULES - 1);
				ret = (ssize_t)count;
				goto command_write_done;
			}
			ret = kstrtou16(argv[3], 0, &port);
			if (ret)
				goto command_help;
			ret = kstrtou32(argv[4], 0, &pacing);
			if (ret)
				goto command_help;
			idpf_dft_rules[idx].port = port;
			idpf_dft_rules[idx].pacing = pacing;
			idpf_last_tstamp[idx] = 0;
			dev_info(dev, "added rule %u: Port %u Pacing %u\n",
				 idx, port, pacing);
		} else if ((argc == 3) && !strncmp(argv[1], "slotsize", 8)) {
			u32 slotsize;

			ret = kstrtou32(argv[2], 0, &slotsize);
			if (ret)
				goto command_help;

			switch (slotsize) {
			case 2:
			case 4:
			case 8:
			case 16:
				break;
			default:
				dev_info(dev, "invalid slot size: %u\n",
					 slotsize);
				dev_info(dev, "valid slot sizes 2, 4, 8, 16 (us)\n");
				ret = -EINVAL;
				goto command_write_done;
			}

			idpf_dft_hw_gran =
				slotsize << (10 - IDPF_DFLT_HW_DIV_S);
			dev_info(dev, "set fine-grained slot size to: %u us\n",
				 slotsize);
			dev_info(dev, "hw granularity is: %lu ns\n",
				 idpf_dft_hw_gran);
		} else {
			goto command_help;
		}
	} else {
command_help:
		dev_info(dev, "unknown or invalid command '%s'\n", cmd_buf);
		dev_info(dev, "available commands\n");
		dev_info(dev, "\t read <reg>\n");
		dev_info(dev, "\t write <reg> <value>\n");
		dev_info(dev, "\t dft dump\n");
		dev_info(dev, "\t dft tstamp <tstamp type> - tstamp type can be within, before, beyond or reverse\n");
		dev_info(dev, "\t dft rule <index> <port> <pacing>\n");
		dev_info(dev, "\t dft slotsize <size(us)> - fine-grained slot size in us\n");
		if (!ret)
			ret = -EINVAL;
		goto command_write_done;
	}

	/* if we get here, nothing went wrong; return bytes copied */
	ret = (ssize_t)count;

command_write_done:
	argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);
	return ret;
}

static const struct file_operations idpf_debugfs_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.write = idpf_debugfs_write,
};

/**************************************************************
 * inline_crypto
 * The inline_crypto entry in debugfs is to provide the driver
 * commands to be executed for inline cryptographic operations.
 **************************************************************/

#define IDPF_DEBUGFS_MAX_REQUEST_SIZE (IDPF_CTLQ_MAX_BUF_LEN + 32)

/**
 * idpf_debugfs_inline_crypto_read - read from inline_crypto datum
 * @filp: the opened file
 * @buf: where to write the data, for the user to read from
 * @count: the size of the user's buffer
 * @ppos: file position offset
 */
static ssize_t
idpf_debugfs_inline_crypto_read(struct file *filp, char __user *buf,
				size_t count, loff_t *ppos)
{
	struct idpf_adapter *adapter =
			(struct idpf_adapter *)filp->private_data;
	struct idpf_debugfs_response *res = &adapter->debugfs_res;
	size_t data_len;
	ssize_t ret = 0;

	if (!buf || !count)
		return -EINVAL;

	/* Don't allow partial reads */
	if (*ppos != 0)
		return 0;

	mutex_lock(&res->mutex);
	data_len = res->data_len;
	if (res->data_len && res->data) {
		if (count < data_len)
			data_len = count;
		if (copy_to_user(buf, res->data, data_len)) {
			ret = -EFAULT;
			goto err_status;
		}
		ret = data_len;
	}

err_status:
	kfree(res->data);
	res->data = NULL;
	res->data_len = 0;
	mutex_unlock(&res->mutex);
	return ret;
}

/**
 * idpf_debugfs_inline_crypto_write - write into inline_crypto datum
 * @filp: the opened file
 * @buf: where to find the user's data
 * @count: the length of the user's data
 * @ppos: file position offset
 */
static ssize_t
idpf_debugfs_inline_crypto_write(struct file *filp, const char __user *buf,
				 size_t count, loff_t *ppos)
{
	struct idpf_adapter *adapter =
			(struct idpf_adapter *)filp->private_data;
	struct idpf_debugfs_response *res = &adapter->debugfs_res;
	struct device *dev = idpf_adapter_to_dev(adapter);
	struct idpf_hw *hw = &adapter->hw;
	struct idpf_ctlq_msg **pmsg, *msg;
	const char __user *payload = NULL;
	struct idpf_dma_mem *dma = NULL;
	struct idpf_ctlq_desc desc;
	u16 num_cleaned, i;
	size_t payload_len;
	int status = 0;
	ssize_t ret;

	if (!buf)
		return -EINVAL;

	/* Do not allow partial writes */
	if (*ppos != 0)
		return 0;

	/* Request cannot exceed size of desc + size of config packet */
	if (count > IDPF_DEBUGFS_MAX_REQUEST_SIZE)
		return -ENOSPC;

	/* Minimum request length is size of desc */
	if (count < sizeof(desc))
		return -EINVAL;

	if (copy_from_user(&desc, buf, sizeof(desc)))
		return -EFAULT;

	payload_len = count - sizeof(desc);

	if (le16_to_cpu(desc.datalen) != payload_len)
		return -EINVAL;

	payload = buf + sizeof(desc);

	pmsg = kcalloc(hw->asq->ring_size, sizeof(*pmsg), GFP_KERNEL);
	if (!pmsg)
		return -ENOMEM;

	/* Clean up the descriptors before using the queue */
	num_cleaned = hw->asq->ring_size;
	status = idpf_ctlq_clean_sq(hw->asq, &num_cleaned, pmsg);
	if (status) {
		kfree(pmsg);
		return -EINVAL;
	}

	for (i = 0; i < num_cleaned; i++) {
		dma = pmsg[i]->ctx.indirect.payload;

		if (pmsg[i]->data_len && dma) {
			dmam_free_coherent(dev, dma->size, dma->va, dma->pa);
			kfree(dma);
			dma = NULL;
		}
		kfree(pmsg[i]);
	}
	kfree(pmsg);

	msg = kzalloc(sizeof(*msg), GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	msg->opcode = le16_to_cpu(desc.opcode);
	msg->data_len = le16_to_cpu(desc.datalen);
	msg->status = le16_to_cpu(desc.ret_val);
	msg->cookie.mbx.chnl_retval = le32_to_cpu(desc.cookie_high);
	msg->cookie.mbx.chnl_opcode = le32_to_cpu(desc.cookie_low);

	if (payload && payload_len) {
		dma = kzalloc(sizeof(*dma), GFP_KERNEL);
		if (!dma) {
			ret = -ENOMEM;
			goto err_dma_alloc;
		}
		dma->size = payload_len;
		dma->va = dmam_alloc_coherent(dev, dma->size, &dma->pa,
					      GFP_KERNEL);
		if (!dma->va) {
			ret = -ENOMEM;
			goto err_copy_from_user;
		}
		if (copy_from_user(dma->va, payload, payload_len)) {
			ret = -EFAULT;
			goto err_copy_from_user;
		}
		memcpy(msg->ctx.indirect.context,
		       &desc.params.indirect,
		       IDPF_INDIRECT_CTX_SIZE);
		msg->ctx.indirect.payload = dma;
	} else {
		memcpy(msg->ctx.direct,
		       &desc.params.direct,
		       IDPF_DIRECT_CTX_SIZE);
	}

	/* clear prior response before sending new request */
	mutex_lock(&res->mutex);
	kfree(res->data);
	res->data = NULL;
	res->data_len = 0;
	mutex_unlock(&res->mutex);

	status = idpf_ctlq_send(hw, hw->asq, 1, msg);
	if (status) {
		dev_info(dev, "Unable to send config packet\n");
		ret = -EIO;
		goto err_copy_from_user;
	}
	return count;

err_copy_from_user:
	if (dma) {
		if (dma->va)
			dmam_free_coherent(dev, dma->size, dma->va, dma->pa);
		kfree(dma);
	}
err_dma_alloc:
	kfree(msg);

	return ret;
}

/**
 * idpf_debugfs_mb_receive - Receive debugfs message over mailbox
 * @adapter: Driver specific private structure
 * @msg: Received message
 */
void idpf_debugfs_mb_receive(struct idpf_adapter *adapter,
			     struct idpf_ctlq_msg *msg)
{
	struct idpf_debugfs_response *res = &adapter->debugfs_res;
	struct idpf_dma_mem *dma = msg->ctx.indirect.payload;
	size_t data_len = sizeof(*msg);
	struct idpf_ctlq_msg *data;

	if (msg->data_len && dma)
		data_len += msg->data_len;

	data = kzalloc(data_len, GFP_KERNEL);
	if (!data)
		return;

	/* copy header */
	memcpy(data, msg, sizeof(*msg));

	/* copy payload */
	if (msg->data_len && dma) {
		memcpy(data + 1, dma->va, msg->data_len);
		/* user does not need to see the payload address */
		data->ctx.indirect.payload = NULL;
	}

	mutex_lock(&res->mutex);

	/* clear prior response before copying the new one */
	kfree(res->data);

	res->data = data;
	res->data_len = data_len;

	mutex_unlock(&res->mutex);
}

static const struct file_operations idpf_debugfs_inline_crypto_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.read  = idpf_debugfs_inline_crypto_read,
	.write = idpf_debugfs_inline_crypto_write,
};

/**
 * idpf_debugfs_register - setup the debugfs directory
 * @adapter: the idpf that is starting up
 */
void idpf_debugfs_register(struct idpf_adapter *adapter)
{
	const char *name = pci_name(adapter->pdev);
	struct dentry *pfile;

	if (IS_ERR_OR_NULL(idpf_debugfs_root)) {
		dev_err(idpf_adapter_to_dev(adapter), "Debugfs root not set\n");
		return;
	}

	adapter->debugfs_dir = debugfs_create_dir(name, idpf_debugfs_root);
	if (IS_ERR(adapter->debugfs_dir)) {
		dev_err(idpf_adapter_to_dev(adapter), "Failed to created debugfs directory\n");
		adapter->debugfs_dir = NULL;
		return;
	}

	pfile = debugfs_create_file("command", 0600, adapter->debugfs_dir,
				    adapter, &idpf_debugfs_fops);
	if (!pfile)
		goto create_failed;

	pfile = debugfs_create_file("inline_crypto", 0600,
				    adapter->debugfs_dir, adapter,
				    &idpf_debugfs_inline_crypto_fops);
	if (!pfile)
		goto create_failed;

	mutex_init(&adapter->debugfs_res.mutex);
	return;

create_failed:
	dev_err(idpf_adapter_to_dev(adapter), "debugfs dir/file for %s failed\n", name);
	debugfs_remove_recursive(adapter->debugfs_dir);
}

/**
 * idpf_debugfs_unregister - clear out the idpf debugfs entries
 * @adapter: the idpf that is stopping
 */
void idpf_debugfs_unregister(struct idpf_adapter *adapter)
{
	struct idpf_debugfs_response *res = &adapter->debugfs_res;

	if (IS_ERR_OR_NULL(adapter->debugfs_dir))
		return;

	debugfs_remove_recursive(adapter->debugfs_dir);
	adapter->debugfs_dir = NULL;

	mutex_lock(&res->mutex);
	kfree(res->data);
	res->data = NULL;
	res->data_len = 0;
	mutex_unlock(&res->mutex);
	mutex_destroy(&res->mutex);
}

/**
 * idpf_debugfs_init - create root directory for debugfs entries
 */
int idpf_debugfs_init(void)
{
	int status = 0;

	idpf_debugfs_root = debugfs_create_dir(KBUILD_MODNAME, NULL);
	if (IS_ERR_OR_NULL(idpf_debugfs_root)) {
		pr_info("init of debugfs failed\n");
		status = -EINVAL;
	}

	return status;
}

/**
 * idpf_debugfs_exit - remove debugfs entries
 */
void idpf_debugfs_exit(void)
{
	debugfs_remove_recursive(idpf_debugfs_root);
	idpf_debugfs_root = NULL;
}
