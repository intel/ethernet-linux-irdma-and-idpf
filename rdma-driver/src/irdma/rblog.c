// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2026 Intel Corporation */
#include "main.h"

#include <linux/percpu.h>
#include <linux/notifier.h>
#include <linux/moduleparam.h>
#include <linux/sched/signal.h>
#ifdef HAVE_PANIC_NOTIFIER_H
#include <linux/panic_notifier.h>
#endif
#include <linux/fs.h>
#include <linux/fsnotify.h>
#include <linux/dcache.h>
#include <linux/seq_file.h>

/* Maximum message size - matches kernel's LOG_LINE_MAX */
#define IRDMA_RBLOG_MAX_MSG_SIZE        1024
#define IRDMA_RBLOG_MIN_BUF_SIZE_KB     256
#define IRDMA_RBLOG_DEFAULT_BUF_SIZE_KB 16384
#define IRDMA_RBLOG_MAX_BUF_SIZE_KB     4194304

/* Per-CPU formatting buffer - avoids heap allocation on the hot path */
#define IRDMA_RBLOG_FMT_BUF_SIZE (IRDMA_RBLOG_MAX_MSG_SIZE + 64)
static DEFINE_PER_CPU(char[IRDMA_RBLOG_FMT_BUF_SIZE], irdma_rblog_fmt_buf);

/* Ring Buffer Log structure - treats buffer as character stream */
struct irdma_rblog {
	char *buffer;            /* Character stream buffer */
	u64 buffer_size;         /* Total buffer size in bytes */
	u64 head;                /* Next write position */
	u64 tail;                /* Oldest character position */
	u64 written_bytes;       /* Total bytes written to buffer (ever) */
	u64 seq;                 /* Sequence counter */
	spinlock_t lock;         /* Protects concurrent access */
	wait_queue_head_t wq;    /* Wait queue for blocking reads */
	struct dentry *dentry;   /* File dentry for inotify support */
	bool initialized;        /* Initialization flag */
};

/* Global Ring Buffer Instance */
static struct irdma_rblog irdma_global_rblog;

/* Panic notifier block */
static struct notifier_block irdma_panic_notifier;

/* ring buffer size parameter (default 16M) */
static u32 rblog_buffer_size = IRDMA_RBLOG_DEFAULT_BUF_SIZE_KB;
static char rblog_buffer_size_str[32] = "16M";

static int rblog_buffer_size_set(const char *val, const struct kernel_param *kp)
{
	u64 size_bytes;
	u32 size_kb;
	char *endp;

	if (!val)
		return -EINVAL;

	/* Use kernel's memparse() to parse size with K/M/G/T suffixes */
	size_bytes = memparse(val, &endp);
	if (size_bytes == 0) {
		pr_err("irdma: Invalid rblog_buffer_size value\n");
		return -EINVAL;
	}

	/* Convert bytes to KB */
	size_kb = (u32)(size_bytes >> 10);

	/* Validate range (256 KB to 4 GB) */
	if (size_kb < IRDMA_RBLOG_MIN_BUF_SIZE_KB) {
		pr_err("irdma: rblog_buffer_size %u KB too small (minimum: %u KB)\n", size_kb, IRDMA_RBLOG_MIN_BUF_SIZE_KB);
		return -EINVAL;
	}
	if (size_kb > IRDMA_RBLOG_MAX_BUF_SIZE_KB) {
		pr_err("irdma: rblog_buffer_size %u KB too large (maximum: %u KB)\n", size_kb, IRDMA_RBLOG_MAX_BUF_SIZE_KB);
		return -EINVAL;
	}

	rblog_buffer_size = size_kb;
	snprintf(rblog_buffer_size_str, sizeof(rblog_buffer_size_str), "%s", val);
	return 0;
}

static int rblog_buffer_size_get(char *buffer, const struct kernel_param *kp)
{
	return scnprintf(buffer, PAGE_SIZE, "%s (%u KB)\n", rblog_buffer_size_str, rblog_buffer_size);
}

static const struct kernel_param_ops rblog_buffer_size_ops = {
	.set = rblog_buffer_size_set,
	.get = rblog_buffer_size_get,
};

module_param_cb(rblog_buffer_size, &rblog_buffer_size_ops, NULL, 0444);
MODULE_PARM_DESC(rblog_buffer_size, "ring buffer size with K/M/G suffixes (e.g., 10M, 512K, 1G) or bytes (default=16M, range: 256K-4G)");

/* Prefix bitmask parameter (default: device name + function name) */
static u32 rblog_prefix_mask = IRDMA_RBLOG_PFX_DEV | IRDMA_RBLOG_PFX_FUNC;
module_param(rblog_prefix_mask, uint, 0644);
MODULE_PARM_DESC(rblog_prefix_mask, "bitmask of prefixes added to each rblog line: "
		 "bit0=device name, bit1=function name, bit2=line number (default=0x3)");

/* Maximum bytes to dump to dmesg (default 512 KB) */
static u32 rblog_dmesg_limit = 512;
module_param(rblog_dmesg_limit, uint, 0644);
MODULE_PARM_DESC(rblog_dmesg_limit, "max KB of ring buffer tail dumped to dmesg on panic (default=512)");

/* Persistent Log size - fixed at compile time */
#define IRDMA_PLOG_SIZE (32 * 1024)

/* Persistent Log structure - small linear buffer, no wrapping */
struct irdma_plog {
	char *buffer;      /* Persistent log buffer */
	size_t size;       /* Total capacity in bytes */
	size_t used;       /* Bytes written so far */
	spinlock_t lock;   /* Protects concurrent access */
	bool initialized;  /* Initialization flag */
};

/* Global Persistent Log Instance */
static struct irdma_plog irdma_global_plog;

/**
 * irdma_plog_init - Initialize Persistent Log
 */
static int irdma_plog_init(void)
{
	struct irdma_plog *plog = &irdma_global_plog;

	plog->buffer = kvmalloc(IRDMA_PLOG_SIZE, GFP_KERNEL);
	if (!plog->buffer)
		return -ENOMEM;

	plog->size = IRDMA_PLOG_SIZE;
	plog->used = 0;
	spin_lock_init(&plog->lock);
	plog->initialized = true;

	pr_info("irdma: Persistent Log initialized (%u KB)\n", IRDMA_PLOG_SIZE / 1024);
	return 0;
}

/**
 * irdma_plog_cleanup - Clean up Persistent Log
 */
static void irdma_plog_cleanup(void)
{
	struct irdma_plog *plog = &irdma_global_plog;

	if (!plog->initialized)
		return;

	kvfree(plog->buffer);
	plog->buffer = NULL;
	plog->size = 0;
	plog->used = 0;
	plog->initialized = false;
}

/**
 * irdma_rblog_panic_handler - Dump ring buffer on kernel panic
 * @nb: notifier block
 * @action: panic action
 * @data: unused
 */
int irdma_rblog_panic_handler(struct notifier_block *nb,
			      unsigned long action, void *data)
{
	pr_info("========== IRDMA Ring Buffer Dump on Panic ==========\n");
	irdma_rblog_dump_to_dmesg();
	pr_info("========== End of IRDMA Ring Buffer Dump ==========\n");
	pr_info("========== IRDMA Persistent Log Dump on Panic ==========\n");
	irdma_plog_dump_to_dmesg();
	pr_info("========== End of IRDMA Persistent Log Dump ==========\n");
	return NOTIFY_DONE;
}

/**
 * irdma_rblog_init - Initialize Ring Buffer Log
 *
 * Allocates continuous buffer based on rblog_buffer_size parameter.
 *
 * Returns 0 on success, negative error code on failure
 */
int irdma_rblog_init(void)
{
	struct irdma_rblog *rblog = &irdma_global_rblog;
	u64 buffer_size;

	if (rblog->initialized) {
		pr_warn("irdma: ring buffer already initialized\n");
		return -EEXIST;
	}

	/* Convert KB to bytes */
	buffer_size = (u64)rblog_buffer_size * 1024;

	/* Allocate continuous buffer */
	rblog->buffer = vmalloc(buffer_size);
	if (!rblog->buffer)
		return -ENOMEM;

	rblog->buffer_size = buffer_size;
	rblog->head = 0;
	rblog->tail = 0;
	rblog->written_bytes = 0;
	rblog->seq = 0;
	rblog->dentry = NULL;
	rblog->initialized = true;
	spin_lock_init(&rblog->lock);
	init_waitqueue_head(&rblog->wq);

	pr_info("irdma: Ring Buffer Log initialized (%u KB)\n", rblog_buffer_size);

	/* Initialize persistent log (non-fatal if it fails) */
	if (irdma_plog_init())
		pr_warn("irdma: persistent log init failed, continuing without it\n");

	/* Register panic notifier */
	irdma_panic_notifier.notifier_call = irdma_rblog_panic_handler;
	irdma_panic_notifier.priority = 0;
	atomic_notifier_chain_register(&panic_notifier_list, &irdma_panic_notifier);

	return 0;
}

/**
 * irdma_rblog_cleanup - Clean up Ring Buffer Log
 */
void irdma_rblog_cleanup(void)
{
	struct irdma_rblog *rblog = &irdma_global_rblog;

	if (!rblog->initialized)
		return;

	/* Unregister panic notifier */
	atomic_notifier_chain_unregister(&panic_notifier_list, &irdma_panic_notifier);

	pr_info("irdma: cleaning up ring buffer\n");

	if (rblog->buffer) {
		vfree(rblog->buffer);
		rblog->buffer = NULL;
	}

	rblog->head = 0;
	rblog->tail = 0;
	rblog->written_bytes = 0;
	rblog->seq = 0;
	rblog->buffer_size = 0;
	rblog->dentry = NULL;
	rblog->initialized = false;

	irdma_plog_cleanup();
}

/**
 * irdma_rblog_get_waitqueue - Get wait queue for poll support
 *
 * Returns pointer to wait queue
 */
wait_queue_head_t *irdma_rblog_get_waitqueue(void)
{
	struct irdma_rblog *rblog = &irdma_global_rblog;

	if (!rblog->initialized)
		return NULL;

	return &rblog->wq;
}

/**
 * irdma_rblog_get_written_bytes - Get total written bytes for poll
 *
 * Returns written_bytes counter
 */
u64 irdma_rblog_get_written_bytes(void)
{
	struct irdma_rblog *rblog = &irdma_global_rblog;
	unsigned long flags;
	u64 bytes;

	if (!rblog->initialized || !rblog->buffer)
		return 0;

	spin_lock_irqsave(&rblog->lock, flags);
	bytes = rblog->written_bytes;
	spin_unlock_irqrestore(&rblog->lock, flags);

	return bytes;
}

/**
 * irdma_rblog_set_dentry - Set the debugfs dentry for inotify support
 * @dentry: dentry from debugfs_create_file
 *
 * Stores the dentry so write functions can notify inotify watchers
 */
void irdma_rblog_set_dentry(struct dentry *dentry)
{
	struct irdma_rblog *rblog = &irdma_global_rblog;
	unsigned long flags;

	if (!rblog->initialized)
		return;

	spin_lock_irqsave(&rblog->lock, flags);
	rblog->dentry = dentry;
	spin_unlock_irqrestore(&rblog->lock, flags);
}

/**
 * irdma_rblog_write - Write a formatted message to ring buffer
 * @flags: record flags (e.g., IRDMA_RBLOG_FLAG_CONTINUATION)
 * @dev:   device for device-name prefix, or NULL
 * @func:  name of the calling function, or NULL for continuation lines
 * @line:  source line number, or 0 to omit
 * @fmt:   format string
 * @...:   variable arguments
 *
 * Formats message with timestamp and optional prefixes controlled by
 * rblog_prefix_mask (device name, function name, line number) and writes
 * to buffer as character stream.
 */
void irdma_rblog_write(u16 flags, struct device *dev, const char *func, int line, const char *fmt, ...)
{
	struct irdma_rblog *rblog = &irdma_global_rblog;
	struct inode *inode = NULL;
	va_list args;
	unsigned long irq_flags;
	char *output_buf;
	const size_t buf_size = IRDMA_RBLOG_FMT_BUF_SIZE;
	size_t output_len;
	u64 space_to_end;
	u64 first_part, second_part;
	u64 sec, nsec;

	if (!rblog->initialized || !rblog->buffer)
		return;

	output_buf = get_cpu_var(irdma_rblog_fmt_buf);

	/* Format message with timestamp if not continuation (before acquiring lock) */
	if (flags & IRDMA_RBLOG_FLAG_CONTINUATION) {
		/* Continuation - no timestamp, no function prefix */
		va_start(args, fmt);
		output_len = vsnprintf(output_buf, buf_size, fmt, args);
		va_end(args);
	} else {
		bool has_dev  = dev && (rblog_prefix_mask & IRDMA_RBLOG_PFX_DEV);
		bool has_func = func && *func && (rblog_prefix_mask & IRDMA_RBLOG_PFX_FUNC);
		bool has_line = line && (rblog_prefix_mask & IRDMA_RBLOG_PFX_LINE);

		/* Normal message - add timestamp and optional function prefix */
		sec = ktime_get_ns();
		nsec = do_div(sec, 1000000000);

		output_len = snprintf(output_buf, buf_size, "[%5llu.%06llu] ", sec, nsec / 1000);

		if (has_dev)
			output_len += snprintf(output_buf + output_len, buf_size - output_len, "%s: ", dev_name(dev));
		if (has_func)
			output_len += snprintf(output_buf + output_len, buf_size - output_len, "%s:", func);
		if (has_line)
			output_len += snprintf(output_buf + output_len, buf_size - output_len, "%d:", line);
		if (has_func || has_line)
			output_len += snprintf(output_buf + output_len, buf_size - output_len, " ");

		va_start(args, fmt);
		output_len += vsnprintf(output_buf + output_len, buf_size - output_len, fmt, args);
		va_end(args);
	}

	if (output_len >= buf_size)
		output_len = buf_size - 1;

	spin_lock_irqsave(&rblog->lock, irq_flags);

	/* Skip if output is too large for buffer */
	if (output_len > rblog->buffer_size) {
		spin_unlock_irqrestore(&rblog->lock, irq_flags);
		put_cpu_var(irdma_rblog_fmt_buf);
		return;
	}

	/* Write to buffer (may wrap) */
	space_to_end = rblog->buffer_size - rblog->head;
	if (space_to_end >= output_len) {
		/* Output fits without wrapping */
		memcpy(rblog->buffer + rblog->head, output_buf, output_len);
		rblog->head = (rblog->head + output_len) % rblog->buffer_size;
	} else {
		/* Output wraps */
		first_part = space_to_end;
		second_part = output_len - first_part;
		memcpy(rblog->buffer + rblog->head, output_buf, first_part);
		memcpy(rblog->buffer, output_buf + first_part, second_part);
		rblog->head = second_part;
	}

	/* Update total written bytes counter */
	rblog->written_bytes += output_len;

	/* Advance tail if buffer has overflowed
	 * When full: tail == head (use written_bytes to distinguish from empty)
	 */
	if (rblog->written_bytes >= rblog->buffer_size)
		rblog->tail = rblog->head;

	rblog->seq++;

	/* Update inode size and get reference for fsnotify */
	if (rblog->dentry && !IS_ERR(rblog->dentry)) {
		inode = d_inode(rblog->dentry);
		if (inode)
			i_size_write(inode, rblog->written_bytes);
	}

	spin_unlock_irqrestore(&rblog->lock, irq_flags);

	put_cpu_var(irdma_rblog_fmt_buf);

	/* Wake up any waiting readers (for poll/select support) */
	wake_up_interruptible(&rblog->wq);

	/* Notify inotify watchers (for standard tail -f support) */
	if (inode)
#ifdef HAVE_FSNOTIFY_MASK_FIRST_ARG
		fsnotify(FS_MODIFY, inode, FSNOTIFY_EVENT_INODE, NULL, NULL, inode, 0);
#else
		fsnotify(inode, FS_MODIFY, inode, FSNOTIFY_EVENT_INODE, NULL, 0);
#endif
}

/**
 * irdma_rblog_write_hex_dump - Write a hex dump to the ring buffer
 * @dev:         device for device-name prefix, or NULL
 * @func:        name of the calling function (used as line prefix in rblog)
 * @line:        source line number of the call site
 * @prefix_str:  string to prefix each line with
 * @prefix_type: controls how the prefix address is printed (DUMP_PREFIX_NONE,
 *               DUMP_PREFIX_ADDRESS, or DUMP_PREFIX_OFFSET)
 * @rowsize:     number of bytes per row; valid values: 8 or 16 (clamped)
 * @groupsize:   number of bytes per group: 1, 2, 4 or 8 (falls back to 1)
 * @buf:         data buffer to dump
 * @len:         number of bytes in @buf to dump
 * @ascii:       include ASCII representation at end of each row
 *
 * Equivalent of print_hex_dump_debug() but writes into the irdma ring
 * buffer log so that the output can be read back through debugfs.
 */
void irdma_rblog_write_hex_dump(struct device *dev, const char *func, int line,
				const char *prefix_str, int prefix_type,
				int rowsize, int groupsize,
				const void *buf, size_t len, bool ascii)
{
	const u8 *ptr = buf;
	int i, linelen;
	size_t remaining = len;
	unsigned char linebuf[200];

	if (rowsize != 16 && rowsize != 32)
		rowsize = 16;

	for (i = 0; i < len; i += rowsize) {
		linelen = min(remaining, (size_t)rowsize);
		remaining -= rowsize;

		hex_dump_to_buffer(ptr + i, linelen, rowsize, groupsize,
				   linebuf, sizeof(linebuf), ascii);

		switch (prefix_type) {
		case DUMP_PREFIX_ADDRESS:
			irdma_rblog_write(0, dev, func, line, "%s%p: %s\n",
					  prefix_str, ptr + i, linebuf);
			break;
		case DUMP_PREFIX_OFFSET:
			irdma_rblog_write(0, dev, func, line, "%s%.8x: %s\n",
					  prefix_str, i, linebuf);
			break;
		default:
			irdma_rblog_write(0, dev, func, line, "%s%s\n",
					  prefix_str, linebuf);
			break;
		}
	}
}

/**
 * irdma_rblog_read - Read ring buffer for debugfs
 * @filp: file pointer (for checking O_NONBLOCK)
 * @buf: output buffer
 * @buf_size: size of output buffer
 * @pos: file position in bytes
 *
 * Returns number of bytes written to buffer
 */
int irdma_rblog_read(struct file *filp, char *buf, size_t buf_size, loff_t *pos)
{
	struct irdma_rblog *rblog = &irdma_global_rblog;
	unsigned long flags;
	u64 oldest_available, available, read_pos;
	size_t to_read, space_to_end, first_part, second_part;

	if (!rblog->initialized || !rblog->buffer)
		return 0;

	spin_lock_irqsave(&rblog->lock, flags);

	/* Determine the "window" of valid data */
	oldest_available = (rblog->written_bytes > rblog->buffer_size) ?
			   (rblog->written_bytes - rblog->buffer_size) : 0;

	/* If user is too far behind, catch them up to the oldest data */
	if (*pos < oldest_available)
		*pos = oldest_available;

	/* If at EOF, return 0 - tail -f will use poll() to wait */
	if (*pos >= rblog->written_bytes) {
		spin_unlock_irqrestore(&rblog->lock, flags);
		return 0;
	}

	/* Calculate how much we can read from this point */
	available = rblog->written_bytes - *pos;
	to_read = (available > buf_size) ? buf_size : (size_t)available;

	/* Map logical position to physical buffer position and copy */
	read_pos = (rblog->tail + (*pos - oldest_available)) % rblog->buffer_size;

	space_to_end = rblog->buffer_size - read_pos;
	if (space_to_end >= to_read) {
		/* Data is contiguous */
		memcpy(buf, rblog->buffer + read_pos, to_read);
	} else {
		/* Data wraps */
		first_part = space_to_end;
		second_part = to_read - first_part;
		memcpy(buf, rblog->buffer + read_pos, first_part);
		memcpy(buf + first_part, rblog->buffer, second_part);
	}

	*pos += to_read;

	spin_unlock_irqrestore(&rblog->lock, flags);
	return to_read;
}

/**
 * irdma_rblog_stats_seq_show - seq_file show for ring buffer statistics
 * @m: seq_file output
 * @v: unused
 */
int irdma_rblog_stats_seq_show(struct seq_file *m, void *v)
{
	struct irdma_rblog *rblog = &irdma_global_rblog;
	unsigned long flags;
	u64 used_bytes;
	u32 percent_used;

	if (!rblog->initialized || !rblog->buffer) {
		seq_puts(m, "ring buffer not initialized\n");
		return 0;
	}

	spin_lock_irqsave(&rblog->lock, flags);

	/* Calculate current usage */
	used_bytes = (rblog->written_bytes < rblog->buffer_size) ?
		     rblog->written_bytes : rblog->buffer_size;

	/* Calculate percentage using integer arithmetic (x100 for two decimal places) */
	if (rblog->buffer_size > 0)
		percent_used = (u32)((used_bytes * 10000) / rblog->buffer_size);
	else
		percent_used = 0;

	seq_printf(m,
		   "Ring Buffer Statistics\n"
		   "===========================\n"
		   "Buffer Size:    %llu bytes (%u KB)\n"
		   "Head Position:  %llu\n"
		   "Tail Position:  %llu\n"
		   "Written Bytes:  %llu\n"
		   "Sequence:       %llu\n"
		   "Status:         %s\n"
		   "Used:           %llu bytes (%u.%02u%%)\n"
		   "Free:           %llu bytes\n",
		   rblog->buffer_size,
		   rblog_buffer_size,
		   rblog->head,
		   rblog->tail,
		   rblog->written_bytes,
		   rblog->seq,
		   rblog->initialized ? "initialized" : "not initialized",
		   used_bytes,
		   percent_used / 100, percent_used % 100,
		   rblog->buffer_size - used_bytes);

	spin_unlock_irqrestore(&rblog->lock, flags);

	return 0;
}

/**
 * irdma_rblog_dump_to_dmesg - Dump ring buffer to dmesg
 *
 * Iterates the ring buffer line by line using memchr('\n').  Each complete
 * line is printed with pr_info(); if a line crosses the wrap boundary the
 * first fragment is printed with pr_info() and the rest with pr_cont() so
 * that the kernel log assembles them into a single record.
 */
void irdma_rblog_dump_to_dmesg(void)
{
	struct irdma_rblog *rblog = &irdma_global_rblog;
	unsigned long flags;
	u64 pos, bytes_to_dump, limit, contig;
	const char *seg, *cur, *end, *nl;
	bool line_started = false;

	if (!rblog->initialized || !rblog->buffer)
		return;

	if (!spin_trylock_irqsave(&rblog->lock, flags)) {
		pr_warn("irdma: rblog lock contended during dump, skipping\n");
		return;
	}

	/* Calculate bytes available in ring buffer */
	bytes_to_dump = (rblog->written_bytes < rblog->buffer_size) ?
			rblog->written_bytes : rblog->buffer_size;

	/* Limit to the most recent rblog_dmesg_limit KB */
	limit = (u64)rblog_dmesg_limit << 10;
	if (bytes_to_dump > limit) {
		pos = (rblog->tail + (bytes_to_dump - limit)) % rblog->buffer_size;
		bytes_to_dump = limit;
		pr_info("irdma: (last %llu KB of ring buffer)\n", limit >> 10);
	} else {
		pos = rblog->tail;
	}

	/*
	 * Walk the ring buffer in at most two contiguous segments per
	 * iteration (before and after the wrap point).
	 */
	while (bytes_to_dump > 0) {
		contig = min_t(u64, bytes_to_dump, rblog->buffer_size - pos);
		seg = rblog->buffer + pos;
		cur = seg;
		end = seg + contig;

		while (cur < end) {
			nl = memchr(cur, '\n', end - cur);
			if (nl) {
				/* Print up to and including the newline */
				if (line_started) {
					pr_cont("%.*s", (int)(nl - cur + 1), cur);
					line_started = false;
				} else {
					pr_info("%.*s", (int)(nl - cur + 1), cur);
				}
				cur = nl + 1;
			} else {
				/* No newline in this segment — line continues after wrap */
				if (line_started)
					pr_cont("%.*s", (int)(end - cur), cur);
				else
					pr_info("%.*s", (int)(end - cur), cur);
				line_started = true;
				cur = end;
			}
		}

		bytes_to_dump -= contig;
		pos = (pos + contig) % rblog->buffer_size;
	}

	/* Terminate any unterminated last line */
	if (line_started)
		pr_cont("\n");

	spin_unlock_irqrestore(&rblog->lock, flags);
}

/**
 * irdma_plog_write - Write a formatted message to the persistent log
 * @fmt: format string
 * @...: variable arguments
 *
 * Writes a timestamped message to the small persistent log buffer.
 * Once the buffer is full, new messages are silently dropped.
 */
void irdma_plog_write(const char *fmt, ...)
{
	struct irdma_plog *plog = &irdma_global_plog;
	unsigned long flags;
	va_list args;
	u64 sec, nsec;
	size_t avail;
	int pfx_len, msg_len;

	if (!plog->initialized || !plog->buffer)
		return;

	/* Get timestamp before taking the lock */
	sec = ktime_get_ns();
	nsec = do_div(sec, 1000000000);

	spin_lock_irqsave(&plog->lock, flags);

	avail = plog->size - plog->used;
	if (avail < 2)
		goto out_unlock;

	/* Write timestamp prefix directly into the plog buffer */
	pfx_len = snprintf(plog->buffer + plog->used, avail,
			   "[%5llu.%06llu] ", sec, nsec / 1000);
	if (pfx_len >= (int)avail) {
		plog->used += avail - 1; /* Partial prefix, buffer now full */
		goto out_unlock;
	}
	plog->used += pfx_len;
	avail -= pfx_len;

	/* Write message directly after the prefix */
	va_start(args, fmt);
	msg_len = vsnprintf(plog->buffer + plog->used, avail, fmt, args);
	va_end(args);
	plog->used += min((size_t)msg_len, avail - 1);

out_unlock:
	spin_unlock_irqrestore(&plog->lock, flags);
}

/**
 * irdma_plog_seq_show - seq_file show callback for persistent log
 * @m: seq_file to write into
 * @v: unused iterator (single_open passes NULL)
 *
 * Called by seq_read; writes the entire persistent log buffer in one go.
 * The seq_file layer handles chunking and copy_to_user.
 */
int irdma_plog_seq_show(struct seq_file *m, void *v)
{
	struct irdma_plog *plog = &irdma_global_plog;
	unsigned long flags;

	if (!plog->initialized || !plog->buffer)
		return 0;

	spin_lock_irqsave(&plog->lock, flags);
	seq_write(m, plog->buffer, plog->used);
	spin_unlock_irqrestore(&plog->lock, flags);

	return 0;
}

/**
 * irdma_plog_dump_to_dmesg - Dump persistent log to dmesg
 */
void irdma_plog_dump_to_dmesg(void)
{
	struct irdma_plog *plog = &irdma_global_plog;
	unsigned long flags;
	const char *start, *end, *buf_end;

	if (!plog->initialized || !plog->buffer || !plog->used)
		return;

	if (!spin_trylock_irqsave(&plog->lock, flags)) {
		pr_warn("irdma: plog lock contended during dump, skipping\n");
		return;
	}

	start = plog->buffer;
	buf_end = plog->buffer + plog->used;
	while (start < buf_end) {
		end = memchr(start, '\n', buf_end - start);
		if (end) {
			pr_info("%.*s", (int)(end - start + 1), start);
			start = end + 1;
		} else {
			/* Last line with no trailing newline */
			pr_info("%.*s\n", (int)(buf_end - start), start);
			break;
		}
	}

	spin_unlock_irqrestore(&plog->lock, flags);
}
