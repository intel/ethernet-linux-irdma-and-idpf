/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2026 Intel Corporation */
#ifndef IRDMA_RBLOG_H
#define IRDMA_RBLOG_H

#include <linux/spinlock.h>
#include <linux/time.h>
#include <linux/wait.h>
#include <linux/fs.h>
#include <linux/dcache.h>

/* Ring Buffer Log for irdma driver debugging
 * Supports multi-processing/threading with spinlock protection
 * Buffer is treated as a character stream with pre-formatted messages
 * Provides debugfs interface and panic dump capability
 */

/* Flags for logging */
#define IRDMA_RBLOG_FLAG_CONTINUATION 0x0001  /* Continuation line (no timestamp) */

/* Bitmask controlling which prefixes are included in each log line.
 * Controlled at runtime via the rblog_prefix_mask module parameter.
 */
#define IRDMA_RBLOG_PFX_DEV  BIT(0)  /* include device name     (e.g. "irdma0: ") */
#define IRDMA_RBLOG_PFX_FUNC BIT(1)  /* include function name   (e.g. "my_func: ") */
#define IRDMA_RBLOG_PFX_LINE BIT(2)  /* include source line     (e.g. "123: ") */

/* Forward declaration to avoid pulling in full ib_verbs.h */
struct device;
struct seq_file;
struct notifier_block;

/* Function prototypes */
int irdma_rblog_init(void);
void irdma_rblog_cleanup(void);
void irdma_rblog_set_dentry(struct dentry *dentry);
wait_queue_head_t *irdma_rblog_get_waitqueue(void);
u64 irdma_rblog_get_written_bytes(void);
__printf(5, 6) void irdma_rblog_write(u16 flags, struct device *dev,
				      const char *func, int line,
				      const char *fmt, ...);
void irdma_rblog_write_hex_dump(struct device *dev, const char *func, int line,
				const char *prefix_str, int prefix_type,
				int rowsize, int groupsize,
				const void *buf, size_t len, bool ascii);
int irdma_rblog_read(struct file *filp, char *buf, size_t buf_size, loff_t *pos);

int irdma_rblog_stats_seq_show(struct seq_file *m, void *v);
void irdma_rblog_dump_to_dmesg(void);
int irdma_rblog_panic_handler(struct notifier_block *nb,
			      unsigned long action, void *data);

/* Persistent Log - small linear buffer for critical events (default 32 KB).
 * Unlike the ring buffer, it never wraps - writes stop when full.
 * Use irdma_plog_write() to record important events that must survive
 * ring-buffer wrap-around (e.g. driver init, fatal errors).
 */
__printf(1, 2) void irdma_plog_write(const char *fmt, ...);
int irdma_plog_seq_show(struct seq_file *m, void *v);
void irdma_plog_dump_to_dmesg(void);

/* Logging macros that combine standard kernel logging with rblog */

/* pr_* variants with rblog support */
#define irdma_rblog_pr_err(fmt, ...) \
	do { \
		if (log_backend == IRDMA_LOG_BACKEND_RBLOG) \
			irdma_rblog_write(0, NULL, __func__, __LINE__, fmt, ##__VA_ARGS__); \
		pr_err(fmt, ##__VA_ARGS__); \
	} while (0)

#define irdma_rblog_pr_warn(fmt, ...) \
	do { \
		if (log_backend == IRDMA_LOG_BACKEND_RBLOG) \
			irdma_rblog_write(0, NULL, __func__, __LINE__, fmt, ##__VA_ARGS__); \
		pr_warn(fmt, ##__VA_ARGS__); \
	} while (0)

#define irdma_rblog_pr_info(fmt, ...) \
	do { \
		if (log_backend == IRDMA_LOG_BACKEND_RBLOG) \
			irdma_rblog_write(0, NULL, __func__, __LINE__, fmt, ##__VA_ARGS__); \
		pr_info(fmt, ##__VA_ARGS__); \
	} while (0)

#define irdma_rblog_pr_debug(fmt, ...) \
	do { \
		if (log_backend == IRDMA_LOG_BACKEND_RBLOG) \
			irdma_rblog_write(0, NULL, __func__, __LINE__, fmt, ##__VA_ARGS__); \
		pr_debug(fmt, ##__VA_ARGS__); \
	} while (0)

#define irdma_rblog_pr_cont(fmt, ...) \
	do { \
		if (log_backend == IRDMA_LOG_BACKEND_RBLOG) \
			irdma_rblog_write(IRDMA_RBLOG_FLAG_CONTINUATION, NULL, NULL, 0, fmt, ##__VA_ARGS__); \
		pr_cont(fmt, ##__VA_ARGS__); \
	} while (0)

/* dev_* variants with rblog support */
#define irdma_rblog_dev_err(dev, fmt, ...) \
	do { \
		if (log_backend == IRDMA_LOG_BACKEND_RBLOG) \
			irdma_rblog_write(0, dev, __func__, __LINE__, fmt, ##__VA_ARGS__); \
		dev_err(dev, fmt, ##__VA_ARGS__); \
	} while (0)

#define irdma_rblog_dev_warn(dev, fmt, ...) \
	do { \
		if (log_backend == IRDMA_LOG_BACKEND_RBLOG) \
			irdma_rblog_write(0, dev, __func__, __LINE__, fmt, ##__VA_ARGS__); \
		dev_warn(dev, fmt, ##__VA_ARGS__); \
	} while (0)

#define irdma_rblog_dev_info(dev, fmt, ...) \
	do { \
		if (log_backend == IRDMA_LOG_BACKEND_RBLOG) \
			irdma_rblog_write(0, dev, __func__, __LINE__, fmt, ##__VA_ARGS__); \
		dev_info(dev, fmt, ##__VA_ARGS__); \
	} while (0)

/* ibdev_* variants with rblog support */
#define irdma_rblog_ibdev_err(ibdev, fmt, ...) \
	do { \
		if (log_backend == IRDMA_LOG_BACKEND_RBLOG) \
			irdma_rblog_write(0, ibdev ? &(ibdev)->dev : NULL, __func__, __LINE__, fmt, ##__VA_ARGS__); \
		ibdev_err(ibdev, fmt, ##__VA_ARGS__); \
	} while (0)

#define irdma_rblog_ibdev_warn(ibdev, fmt, ...) \
	do { \
		if (log_backend == IRDMA_LOG_BACKEND_RBLOG) \
			irdma_rblog_write(0, ibdev ? &(ibdev)->dev : NULL, __func__, __LINE__, fmt, ##__VA_ARGS__); \
		ibdev_warn(ibdev, fmt, ##__VA_ARGS__); \
	} while (0)

#define irdma_rblog_ibdev_info(ibdev, fmt, ...) \
	do { \
		if (log_backend == IRDMA_LOG_BACKEND_RBLOG) \
			irdma_rblog_write(0, ibdev ? &(ibdev)->dev : NULL, __func__, __LINE__, fmt, ##__VA_ARGS__); \
		ibdev_info(ibdev, fmt, ##__VA_ARGS__); \
	} while (0)

#define irdma_rblog_ibdev_dbg(ibdev, fmt, ...) \
	do { \
		if (log_backend == IRDMA_LOG_BACKEND_RBLOG) \
			irdma_rblog_write(0, ibdev ? &(ibdev)->dev : NULL, __func__, __LINE__, fmt, ##__VA_ARGS__); \
		ibdev_dbg(ibdev, fmt, ##__VA_ARGS__); \
	} while (0)

/* hex_dump variant with rblog support */
#define irdma_rblog_hex_dump(prefix_str, prefix_type, rowsize, groupsize, buf, len, ascii) \
	do { \
		if (log_backend == IRDMA_LOG_BACKEND_RBLOG) \
			irdma_rblog_write_hex_dump(NULL, __func__, __LINE__, \
						  prefix_str, prefix_type, \
						  rowsize, groupsize, \
						  buf, len, ascii); \
		print_hex_dump_debug(prefix_str, prefix_type, rowsize, \
				     groupsize, buf, len, ascii); \
	} while (0)

/* plog variant - records to persistent log (survives ring-buffer wrap) and pr_info */
#define irdma_plog_pr_info(fmt, ...) \
	do { \
		if (log_backend == IRDMA_LOG_BACKEND_RBLOG) \
			irdma_plog_write(fmt, ##__VA_ARGS__); \
		pr_info(fmt, ##__VA_ARGS__); \
	} while (0)

#endif /* IRDMA_RBLOG_H */
