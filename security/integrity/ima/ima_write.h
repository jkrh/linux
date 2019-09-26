/* SPDX-License-Identifier: GPL-2.0-only
 *
 * Integrity Measurement Architecture write tracking support
 *
 * Authors:
 * Janne Karhunen <janne.karhunen@gmail.com>
 * Konsta Karsisto <konsta.karsisto@gmail.com>
 *
 * File: ima_write.h
 */

#ifndef __LINUX_IMA_WRITE_H
#define __LINUX_IMA_WRITE_H

#include <linux/ima.h>

#if (defined(CONFIG_IMA_HASH_WRITES))
int ima_init_wq(void);
int ima_fix_xattr(struct dentry *dentry,
		  struct integrity_iint_cache *iint);
void ima_cancel_work(struct integrity_iint_cache *iint);
void ima_follow_file(struct integrity_iint_cache *iint,
		     struct file *file);
void ima_drop_file(struct integrity_iint_cache *iint,
		   struct file *file);
void ima_init_hash(struct integrity_iint_cache *iint,
		   struct dentry *dentry);
#else
static inline int ima_init_wq(void)
{
	return 0;
}
static inline void ima_cancel_work(struct integrity_iint_cache *iint)
{
	return;
}
static inline void ima_follow_file(struct integrity_iint_cache *iint,
				   struct file *file)
{
	return;
}
static inline void ima_drop_file(struct integrity_iint_cache *iint,
				 struct file *file)
{
	return;
}
static inline void ima_init_hash(struct integrity_iint_cache *iint,
				 struct dentry *dentry)
{
	return;
}
#endif /* CONFIG_IMA_HASH_WRITES */
#endif /* __LINUX_IMA_WRITE_H */
