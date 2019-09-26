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

#include "ima.h"
#include "ima_write.h"

static struct workqueue_struct *ima_update_wq;

void ima_follow_file(struct integrity_iint_cache *iint,
		     struct file *file)
{
	struct ima_fl_entry *e;

	if (!iint || !file)
		return;
	if (!(file->f_mode & FMODE_WRITE) ||
	    !test_bit(IMA_UPDATE_XATTR, &iint->atomic_flags))
		return;

	list_for_each_entry(e, &iint->file_list, list) {
		if (e->file == file)
			return;
	}
	e = kmalloc(sizeof(*e), GFP_KERNEL);
	if (!e)
		return;
	e->file = file;
	list_add(&e->list, &iint->file_list);
}

void ima_drop_file(struct integrity_iint_cache *iint,
		   struct file *file)
{
	struct ima_fl_entry *e;

	list_for_each_entry(e, &iint->file_list, list) {
		if (e->file == file) {
			list_del(&e->list);
			kfree(e);
			break;
		}
	}
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
 * ima_cancel_work - cancel a pending hashing job
 */
void ima_cancel_work(struct integrity_iint_cache *iint)
{
	if (iint->ima_work.state != IMA_WORK_ACTIVE)
		return;

	cancel_delayed_work_sync(&iint->ima_work.work);
	iint->ima_work.file = NULL;
	iint->ima_work.state = IMA_WORK_CANCELLED;
}

/**
 * ima_inode_update_delay - compute inode hashing latency
 *
 * Compute how long we should wait for IO on the file before
 * running the file hash update.
 */
static unsigned long ima_inode_update_delay(struct inode *inode)
{
	unsigned long blocks, msecs;

	blocks = i_size_read(inode) / SZ_1M + 1;
	msecs = blocks * CONFIG_IMA_WRITE_HASH_LATENCY;
	if (msecs > CONFIG_IMA_WRITE_HASH_LATENCY_CEILING)
		msecs = CONFIG_IMA_WRITE_HASH_LATENCY_CEILING;

	return msecs;
}

/**
 * ima_file_sync_update - update the file hash(es)
 */
static void ima_file_sync_update(struct file *file)
{
	struct inode *inode = file_inode(file);
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
	if (IS_I_VERSION(inode)) {
		i_version = inode_query_iversion(inode);
		if (i_version == iint->version)
			should_update = false;
	}
	if (should_update) {
		iint->flags &= ~IMA_COLLECTED;
		ima_update_xattr(iint, file);
	}
	mutex_unlock(&iint->mutex);
}

static void ima_delayed_update_handler(struct work_struct *work)
{
	struct ima_work_entry *entry;

	entry = container_of(work, typeof(*entry), work.work);
	ima_file_sync_update(entry->file);
	entry->file = NULL;
	entry->state = IMA_WORK_INACTIVE;
}
/**
 * ima_file_async_update
 * @file: pointer to file structure being updated
 */
static void ima_file_async_update(struct file *file)
{
	struct inode *inode = file_inode(file);
	struct integrity_iint_cache *iint;
	unsigned long msecs;
	bool creq;

	if (!ima_policy_flag || !S_ISREG(inode->i_mode))
		return;

	iint = integrity_iint_find(inode);
	if (!iint)
		return;

	if (!test_bit(IMA_UPDATE_XATTR, &iint->atomic_flags))
		return;

	mutex_lock(&iint->mutex);
	if (iint->ima_work.state == IMA_WORK_ACTIVE)
		goto out;

	msecs = ima_inode_update_delay(inode);
	iint->ima_work.file = file;
	iint->ima_work.state = IMA_WORK_ACTIVE;
	INIT_DELAYED_WORK(&iint->ima_work.work, ima_delayed_update_handler);

	creq = queue_delayed_work(ima_update_wq,
				  &iint->ima_work.work,
				  msecs_to_jiffies(msecs));
	if (creq == false) {
		iint->ima_work.file = NULL;
		iint->ima_work.state = IMA_WORK_INACTIVE;
	}
out:
	mutex_unlock(&iint->mutex);
}

void ima_file_update(struct file *file, bool sync)
{
	if (sync)
		ima_file_sync_update(file);
	else
		ima_file_async_update(file);
}
EXPORT_SYMBOL_GPL(ima_file_update);

/**
 * ima_inode_async_update - delayed hash update of an inode
 * @inode: dirty inode chosen for writeback
 *
 * Schedule work to measure the first available 'struct file' cached
 * in the iint entry that references this inode. This allows IMA to
 * track inode writebacks.
 *
 * Note that we haven't incremented the refcount for the files we keep
 * track of in order to not mess up the normal file refcounting. If we
 * see a file whose f_count is already zero, we simply skip it. If we
 * fail to find any available file reference, the measurement will be
 * handled by the ima_check_last_writer().
 */
static void ima_inode_async_update(struct inode *inode)
{
	struct integrity_iint_cache *iint;
	struct ima_fl_entry *e;
	bool found = false;

	iint = integrity_iint_find(inode);
	if (!iint)
		return;

	if (iint->ima_work.state == IMA_WORK_ACTIVE)
		return;

	mutex_lock(&iint->mutex);
	list_for_each_entry(e, &iint->file_list, list) {
		if (file_count(e->file) == 0)
			continue;
		found = true;
		break;
	}
	mutex_unlock(&iint->mutex);
	if (found && e->file)
		ima_file_async_update(e->file);
}

static void ima_inode_sync_update(struct inode *inode)
{
	struct integrity_iint_cache *iint;
	struct ima_fl_entry *e;
	bool found = false;

	iint = integrity_iint_find(inode);
	if (!iint)
		return;

	mutex_lock(&iint->mutex);
	list_for_each_entry(e, &iint->file_list, list) {
		if (file_count(e->file) == 0)
			continue;
		found = true;
		break;
	}
	mutex_unlock(&iint->mutex);
	if (found && e->file)
		ima_file_sync_update(e->file);
}

void ima_inode_update(struct inode *inode, bool sync)
{
	if (sync)
		ima_inode_sync_update(inode);
	else
		ima_inode_async_update(inode);
}
EXPORT_SYMBOL_GPL(ima_inode_update);

int ima_init_wq(void)
{
	int error = 0;

	ima_update_wq = alloc_workqueue("ima-update-wq",
					WQ_MEM_RECLAIM |
					WQ_CPU_INTENSIVE,
					0);
	if (!ima_update_wq) {
		pr_err("Failed to allocate write measurement workqueue\n");
		error = -ENOMEM;
	}
	return error;
}
