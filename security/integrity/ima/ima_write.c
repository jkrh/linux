// SPDX-License-Identifier: GPL-2.0-only
/*
 * Integrity Measurement Architecture write tracking support
 *
 * Authors:
 * Janne Karhunen <janne.karhunen@gmail.com>
 * Konsta Karsisto <konsta.karsisto@gmail.com>
 *
 * File: ima_write.c
 *	implements the IMA hooks: ima_file_update, ima_file_delayed_update,
 *	ima_inode_update, ima_inode_delayed_update
 */

#include <linux/module.h>
#include <linux/file.h>
#include <linux/xattr.h>
#include <linux/ima.h>
#include <linux/iversion.h>
#include <linux/workqueue.h>
#include <linux/sizes.h>
#include <linux/fs.h>
#include <linux/writeback.h>

#include "ima.h"
#include "ima_write.h"


void ima_follow_file(struct integrity_iint_cache *iint,
		     struct file *file)
{
	struct file *f;
	int flags;

	if (!iint || !file)
		return;
	if (iint->saved_file || !(file->f_mode & FMODE_WRITE) ||
	    !test_bit(IMA_UPDATE_XATTR, &iint->atomic_flags))
		return;

	flags = file->f_flags & ~(O_WRONLY | O_APPEND |
				  O_TRUNC | O_CREAT | O_NOCTTY | O_EXCL);
	flags |= O_RDONLY;
	f = dentry_open(&file->f_path, flags, file->f_cred);
	if (IS_ERR(f)) {
		pr_err("ima: unable to open file for write tracking\n");
		return;
	}
	iint->saved_file = f;
}

/**
 * ima_init_hash - initialize the file hash(es)
 *
 * The caller must be holding the iint mutex.
 */
void ima_init_hash(struct integrity_iint_cache *iint,
		   struct dentry *dentry)
{
	if (test_bit(IMA_UPDATE_XATTR, &iint->atomic_flags))
		ima_fix_xattr(dentry, iint);
}

/**
 * ima_inode_sync_update - update the file hash(es)
 */
void ima_inode_sync_update(struct inode *inode)
{
	struct integrity_iint_cache *iint;
	bool should_update = true;
	u64 i_version;

	if (!ima_policy_flag || !S_ISREG(inode->i_mode))
		return;

	iint = integrity_iint_find(inode);
	if (!iint)
		return;

	if (!test_bit(IMA_UPDATE_XATTR, &iint->atomic_flags))
		return;

	mutex_lock(&iint->mutex);
	if (!iint->saved_file)
		goto out;
	if (IS_I_VERSION(inode)) {
		i_version = inode_query_iversion(inode);
		if (i_version == iint->version)
			should_update = false;
	}
	if (should_update) {
		iint->flags &= ~IMA_COLLECTED;
		ima_update_xattr(iint, iint->saved_file);
	}
out:
	mutex_unlock(&iint->mutex);
}
EXPORT_SYMBOL_GPL(ima_inode_sync_update);

void *ima_pre_writeback(struct inode *inode, struct writeback_control *wbc)
{
	struct integrity_iint_cache *iint;

	if (!ima_policy_flag || !IS_IMA(inode))
		return NULL;

	iint = integrity_iint_find(inode);
	if (!iint || !test_bit(IMA_UPDATE_XATTR, &iint->atomic_flags))
		return NULL;

	mutex_lock(&iint->mutex);
	if (!iint->saved_file) {
		pr_warn("ima: writeback with no file?\n");
		goto out;
	}
	iint->sync_mode = wbc->sync_mode;
	iint->nr_to_write = wbc->nr_to_write;
	if (mapping_tagged(inode->i_mapping, PAGECACHE_TAG_DIRTY) ||
		inode->i_state & I_DIRTY_PAGES)
		wbc->sync_mode = WB_SYNC_ALL;
out:
	mutex_unlock(&iint->mutex);

	return iint;
}

void ima_post_writeback(void *iint_handle, int error, struct inode *inode,
			struct writeback_control *wbc)
{
	struct integrity_iint_cache *iint = iint_handle;
	long written = -1;

	if (!ima_policy_flag || !IS_IMA(inode))
		return;
	if (!iint)
		iint = integrity_iint_find(inode);
	if (!iint || !test_bit(IMA_UPDATE_XATTR, &iint->atomic_flags))
		return;
	if (error)
		return;

	mutex_lock(&iint->mutex);
	if (!iint->saved_file)
		goto out;

	written = iint->nr_to_write - wbc->nr_to_write;
	if (written <= 0)
		goto cleanup;

	iint->flags &= ~IMA_COLLECTED;
	ima_update_xattr(iint, iint->saved_file);

cleanup:
	wbc->sync_mode = iint->sync_mode;
	if (atomic_read(&inode->i_writecount) == 0 &&
		!(inode->i_state & I_DIRTY_PAGES)) {
		fput(iint->saved_file);
		iint->saved_file = NULL;
	}

out:
	mutex_unlock(&iint->mutex);
}
