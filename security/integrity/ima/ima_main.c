/*
 * Integrity Measurement Architecture
 *
 * Copyright (C) 2005,2006,2007,2008 IBM Corporation
 *
 * Authors:
 * Reiner Sailer <sailer@watson.ibm.com>
 * Serge Hallyn <serue@us.ibm.com>
 * Kylene Hall <kylene@us.ibm.com>
 * Mimi Zohar <zohar@us.ibm.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * File: ima_main.c
 *	implements the IMA hooks: ima_bprm_check, ima_file_mmap,
 *	ima_delayed_update, ima_delayed_inode_update,
 *	ima_file_update and ima_file_check.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/file.h>
#include <linux/binfmts.h>
#include <linux/mount.h>
#include <linux/mman.h>
#include <linux/slab.h>
#include <linux/xattr.h>
#include <linux/ima.h>
#include <linux/iversion.h>
#include <linux/workqueue.h>
#include <linux/sizes.h>
#include <linux/fs.h>

#include "ima.h"

#ifdef CONFIG_IMA_APPRAISE
int ima_appraise = IMA_APPRAISE_ENFORCE;
#else
int ima_appraise;
#endif

int ima_hash_algo = HASH_ALGO_SHA1;
static int hash_setup_done;

static struct notifier_block ima_lsm_policy_notifier = {
	.notifier_call = ima_lsm_policy_change,
};
static struct workqueue_struct *ima_update_wq;

static int __init hash_setup(char *str)
{
	struct ima_template_desc *template_desc = ima_template_desc_current();
	int i;

	if (hash_setup_done)
		return 1;

	if (strcmp(template_desc->name, IMA_TEMPLATE_IMA_NAME) == 0) {
		if (strncmp(str, "sha1", 4) == 0)
			ima_hash_algo = HASH_ALGO_SHA1;
		else if (strncmp(str, "md5", 3) == 0)
			ima_hash_algo = HASH_ALGO_MD5;
		else
			return 1;
		goto out;
	}

	i = match_string(hash_algo_name, HASH_ALGO__LAST, str);
	if (i < 0)
		return 1;

	ima_hash_algo = i;
out:
	hash_setup_done = 1;
	return 1;
}
__setup("ima_hash=", hash_setup);

/* Prevent mmap'ing a file execute that is already mmap'ed write */
static int mmap_violation_check(enum ima_hooks func, struct file *file,
				char **pathbuf, const char **pathname,
				char *filename)
{
	struct inode *inode;
	int rc = 0;

	if ((func == MMAP_CHECK) && mapping_writably_mapped(file->f_mapping)) {
		rc = -ETXTBSY;
		inode = file_inode(file);

		if (!*pathbuf)	/* ima_rdwr_violation possibly pre-fetched */
			*pathname = ima_d_path(&file->f_path, pathbuf,
					       filename);
		integrity_audit_msg(AUDIT_INTEGRITY_DATA, inode, *pathname,
				    "mmap_file", "mmapped_writers", rc, 0);
	}
	return rc;
}

/*
 * ima_rdwr_violation_check
 *
 * Only invalidate the PCR for measured files:
 *	- Opening a file for write when already open for read,
 *	  results in a time of measure, time of use (ToMToU) error.
 *	- Opening a file for read when already open for write,
 *	  could result in a file measurement error.
 *
 */
static void ima_rdwr_violation_check(struct file *file,
				     struct integrity_iint_cache *iint,
				     int must_measure,
				     char **pathbuf,
				     const char **pathname,
				     char *filename)
{
	struct inode *inode = file_inode(file);
	fmode_t mode = file->f_mode;
	bool send_tomtou = false, send_writers = false;

	if (mode & FMODE_WRITE) {
		if (atomic_read(&inode->i_readcount) && IS_IMA(inode)) {
			if (!iint)
				iint = integrity_iint_find(inode);
			/* IMA_MEASURE is set from reader side */
			if (iint && test_bit(IMA_MUST_MEASURE,
						&iint->atomic_flags))
				send_tomtou = true;
		}
	} else {
		if (must_measure)
			set_bit(IMA_MUST_MEASURE, &iint->atomic_flags);
		if (inode_is_open_for_write(inode) && must_measure)
			send_writers = true;
	}

	if (!send_tomtou && !send_writers)
		return;

	*pathname = ima_d_path(&file->f_path, pathbuf, filename);

	if (send_tomtou)
		ima_add_violation(file, *pathname, iint,
				  "invalid_pcr", "ToMToU");
	if (send_writers)
		ima_add_violation(file, *pathname, iint,
				  "invalid_pcr", "open_writers");
}

#ifdef CONFIG_IMA_MEASURE_WRITES
/**
 * ima_get_file_light
 *
 * Grab file without get_file(file), used by ima_delayed_inode_update().
 * Called with iint->mutex held.
 */
static void ima_get_file_light(struct file *file,
			       struct integrity_iint_cache *iint)
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

/**
 * ima_free_file_ref
 *
 * Remove the file from iint cache. Called with iint->mutex held. See
 * ima_delayed_inode_update() for details.
 */
static void ima_free_file_ref(struct integrity_iint_cache *iint,
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
#endif /* CONFIG_IMA_MEASURE_WRITES */

static void ima_check_last_writer(struct integrity_iint_cache *iint,
				  struct inode *inode, struct file *file)
{
	fmode_t mode = file->f_mode;
	bool update, last_writer;

	if (!(mode & FMODE_WRITE))
		return;

	/*
	 * Update security.ima always after last fput() if the file has
	 * changed and IMA_UPDATE_XATTR is set. Additionally reset the
	 * appraisal/mesurement status if we're the last writer.
	 */
	mutex_lock(&iint->mutex);
	ima_free_file_ref(iint, file);

	if (!IS_I_VERSION(inode) ||
	   !inode_eq_iversion(inode, iint->version) ||
	   (iint->flags & IMA_NEW_FILE)) {
		update = test_bit(IMA_UPDATE_XATTR, &iint->atomic_flags);
		last_writer = atomic_read(&inode->i_writecount) == 1;
		if (last_writer) {
			clear_bit(IMA_UPDATE_XATTR, &iint->atomic_flags);
			iint->flags &= ~(IMA_DONE_MASK | IMA_NEW_FILE);
			iint->measured_pcrs = 0;
		}
		if (update) {
			if (!last_writer)
				iint->flags &= ~IMA_COLLECTED;
			ima_update_xattr(iint, file);
		}
	}
	mutex_unlock(&iint->mutex);
}

/**
 * ima_file_free - called on __fput()
 * @file: pointer to file structure being freed
 *
 * Flag files that changed, based on i_version
 */
void ima_file_free(struct file *file)
{
	struct inode *inode = file_inode(file);
	struct integrity_iint_cache *iint;

	if (!ima_policy_flag || !S_ISREG(inode->i_mode))
		return;

	iint = integrity_iint_find(inode);
	if (!iint)
		return;

	ima_check_last_writer(iint, inode, file);
}

static int process_measurement(struct file *file, const struct cred *cred,
			       u32 secid, char *buf, loff_t size, int mask,
			       enum ima_hooks func)
{
	struct inode *inode = file_inode(file);
	struct integrity_iint_cache *iint = NULL;
	struct ima_template_desc *template_desc;
	char *pathbuf = NULL;
	char filename[NAME_MAX];
	const char *pathname = NULL;
	int rc = 0, action, must_appraise = 0;
	int pcr = CONFIG_IMA_MEASURE_PCR_IDX;
	struct evm_ima_xattr_data *xattr_value = NULL;
	int xattr_len = 0;
	bool violation_check;
	enum hash_algo hash_algo;

	if (!ima_policy_flag || !S_ISREG(inode->i_mode))
		return 0;

	/* Return an IMA_MEASURE, IMA_APPRAISE, IMA_AUDIT action
	 * bitmask based on the appraise/audit/measurement policy.
	 * Included is the appraise submask.
	 */
	action = ima_get_action(inode, cred, secid, mask, func, &pcr);
	violation_check = ((func == FILE_CHECK || func == MMAP_CHECK) &&
			   (ima_policy_flag & IMA_MEASURE));
	if (!action && !violation_check)
		return 0;

	must_appraise = action & IMA_APPRAISE;

	/*  Is the appraise rule hook specific?  */
	if (action & IMA_FILE_APPRAISE)
		func = FILE_CHECK;

	inode_lock(inode);

	if (action) {
		iint = integrity_inode_get(inode);
		if (!iint)
			rc = -ENOMEM;
	}

	if (!rc && violation_check)
		ima_rdwr_violation_check(file, iint, action & IMA_MEASURE,
					 &pathbuf, &pathname, filename);

	inode_unlock(inode);

	if (rc)
		goto out;
	if (!action)
		goto out;

	mutex_lock(&iint->mutex);

	if (test_and_clear_bit(IMA_CHANGE_ATTR, &iint->atomic_flags))
		/* reset appraisal flags if ima_inode_post_setattr was called */
		iint->flags &= ~(IMA_APPRAISE | IMA_APPRAISED |
				 IMA_APPRAISE_SUBMASK | IMA_APPRAISED_SUBMASK |
				 IMA_ACTION_FLAGS);

	/*
	 * Re-evaulate the file if either the xattr has changed or the
	 * kernel has no way of detecting file change on the filesystem.
	 * (Limited to privileged mounted filesystems.)
	 */
	if (test_and_clear_bit(IMA_CHANGE_XATTR, &iint->atomic_flags) ||
	    ((inode->i_sb->s_iflags & SB_I_IMA_UNVERIFIABLE_SIGNATURE) &&
	     !(inode->i_sb->s_iflags & SB_I_UNTRUSTED_MOUNTER) &&
	     !(action & IMA_FAIL_UNVERIFIABLE_SIGS))) {
		iint->flags &= ~IMA_DONE_MASK;
		iint->measured_pcrs = 0;
	}

	/* Determine if already appraised/measured based on bitmask
	 * (IMA_MEASURE, IMA_MEASURED, IMA_XXXX_APPRAISE, IMA_XXXX_APPRAISED,
	 *  IMA_AUDIT, IMA_AUDITED)
	 */
	iint->flags |= action;
	action &= IMA_DO_MASK;
	action &= ~((iint->flags & (IMA_DONE_MASK ^ IMA_MEASURED)) >> 1);

	/* If target pcr is already measured, unset IMA_MEASURE action */
	if ((action & IMA_MEASURE) && (iint->measured_pcrs & (0x1 << pcr)))
		action ^= IMA_MEASURE;

	/* HASH sets the digital signature and update flags, nothing else */
	if ((action & IMA_HASH) &&
	    !(test_bit(IMA_DIGSIG, &iint->atomic_flags))) {
		xattr_len = ima_read_xattr(file_dentry(file), &xattr_value);
		if ((xattr_value && xattr_len > 2) &&
		    (xattr_value->type == EVM_IMA_XATTR_DIGSIG))
			set_bit(IMA_DIGSIG, &iint->atomic_flags);
		iint->flags |= IMA_HASHED;
		action ^= IMA_HASH;
		set_bit(IMA_UPDATE_XATTR, &iint->atomic_flags);
	}

	if (must_appraise && (file->f_mode & FMODE_WRITE))
		set_bit(IMA_UPDATE_XATTR, &iint->atomic_flags);

	/* Cache file for measurements triggered from inode writeback */
	ima_get_file_light(file, iint);

	/* Nothing to do, just return existing appraised status */
	if (!action) {
		if (must_appraise) {
			rc = mmap_violation_check(func, file, &pathbuf,
						  &pathname, filename);
			if (!rc)
				rc = ima_get_cache_status(iint, func);
		}
		goto out_locked;
	}

	template_desc = ima_template_desc_current();
	if ((action & IMA_APPRAISE_SUBMASK) ||
		    strcmp(template_desc->name, IMA_TEMPLATE_IMA_NAME) != 0)
		/* read 'security.ima' */
		xattr_len = ima_read_xattr(file_dentry(file), &xattr_value);

	hash_algo = ima_get_hash_algo(xattr_value, xattr_len);

	rc = ima_collect_measurement(iint, file, buf, size, hash_algo);
	if (rc != 0 && rc != -EBADF && rc != -EINVAL)
		goto out_locked;

	if (!pathbuf)	/* ima_rdwr_violation possibly pre-fetched */
		pathname = ima_d_path(&file->f_path, &pathbuf, filename);

	if (action & IMA_MEASURE)
		ima_store_measurement(iint, file, pathname,
				      xattr_value, xattr_len, pcr);
	if (rc == 0 && (action & IMA_APPRAISE_SUBMASK)) {
		inode_lock(inode);
		rc = ima_appraise_measurement(func, iint, file, pathname,
					      xattr_value, xattr_len);
		inode_unlock(inode);
		if (!rc)
			rc = mmap_violation_check(func, file, &pathbuf,
						  &pathname, filename);
	}
	if (action & IMA_AUDIT)
		ima_audit_measurement(iint, pathname);

	if ((file->f_flags & O_DIRECT) && (iint->flags & IMA_PERMIT_DIRECTIO))
		rc = 0;
out_locked:
	if ((mask & MAY_WRITE) && test_bit(IMA_DIGSIG, &iint->atomic_flags) &&
	     !(iint->flags & IMA_NEW_FILE))
		rc = -EACCES;
	mutex_unlock(&iint->mutex);
	kfree(xattr_value);
out:
	if (pathbuf)
		__putname(pathbuf);
	if (must_appraise)
		if (rc && (ima_appraise & IMA_APPRAISE_ENFORCE))
			return -EACCES;
	return 0;
}

/**
 * ima_file_mmap - based on policy, collect/store measurement.
 * @file: pointer to the file to be measured (May be NULL)
 * @prot: contains the protection that will be applied by the kernel.
 *
 * Measure files being mmapped executable based on the ima_must_measure()
 * policy decision.
 *
 * On success return 0.  On integrity appraisal error, assuming the file
 * is in policy and IMA-appraisal is in enforcing mode, return -EACCES.
 */
int ima_file_mmap(struct file *file, unsigned long prot)
{
	u32 secid;

	if (file && (prot & PROT_EXEC)) {
		security_task_getsecid(current, &secid);
		return process_measurement(file, current_cred(), secid, NULL,
					   0, MAY_EXEC, MMAP_CHECK);
	}

	return 0;
}

/**
 * ima_bprm_check - based on policy, collect/store measurement.
 * @bprm: contains the linux_binprm structure
 *
 * The OS protects against an executable file, already open for write,
 * from being executed in deny_write_access() and an executable file,
 * already open for execute, from being modified in get_write_access().
 * So we can be certain that what we verify and measure here is actually
 * what is being executed.
 *
 * On success return 0.  On integrity appraisal error, assuming the file
 * is in policy and IMA-appraisal is in enforcing mode, return -EACCES.
 */
int ima_bprm_check(struct linux_binprm *bprm)
{
	int ret;
	u32 secid;

	security_task_getsecid(current, &secid);
	ret = process_measurement(bprm->file, current_cred(), secid, NULL, 0,
				  MAY_EXEC, BPRM_CHECK);
	if (ret)
		return ret;

	security_cred_getsecid(bprm->cred, &secid);
	return process_measurement(bprm->file, bprm->cred, secid, NULL, 0,
				   MAY_EXEC, CREDS_CHECK);
}

static void ima_delayed_update_handler(struct work_struct *work)
{
	struct ima_work_entry *entry;

	entry = container_of(work, typeof(*entry), work.work);

	ima_file_update(entry->file);
	fput(entry->file);
	entry->file = NULL;
}

static inline unsigned long ima_inode_update_delay(struct inode *inode)
{
	unsigned long blocks, msecs;

	blocks = i_size_read(inode) / SZ_1M + 1;
	msecs = blocks * IMA_LATENCY_INCREMENT;
	if (msecs > CONFIG_IMA_HASH_LATENCY_CEILING)
		msecs = CONFIG_IMA_HASH_LATENCY_CEILING;

	return msecs;
}

/**
 * ima_delayed_update - delayed file measurement update
 * @file: pointer to file structure being updated
 */
void ima_delayed_update(struct file *file)
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
	if (iint->ima_work.file)
		goto out;

	msecs = ima_inode_update_delay(inode);
	get_file(file);
	iint->ima_work.file = file;
	INIT_DELAYED_WORK(&iint->ima_work.work, ima_delayed_update_handler);

	creq = queue_delayed_work(ima_update_wq,
				  &iint->ima_work.work,
				  msecs_to_jiffies(msecs));
	if (creq == false) {
		iint->ima_work.file = NULL;
		fput(file);
	}
out:
	mutex_unlock(&iint->mutex);
}
EXPORT_SYMBOL_GPL(ima_delayed_update);

#ifdef CONFIG_IMA_MEASURE_WRITES
/**
 * ima_delayed_inode_update - delayed measurement update of an inode
 * @inode: dirty inode chosen for writeback
 *
 * Schedule work to measure the first available 'struct file' cached
 * in the iint entry referencing this inode. This allows IMA to track
 * inode writebacks.
 *
 * Note that we haven't incremented the refcount for the files we keep
 * track of in order to not mess up the normal get_file()/fput()
 * refcounting. If we see a file whose f_count is already zero, we
 * simply skip it. It will be removed from file_list in
 * ima_check_last_writer(), called from __fput().
 *
 * If we fail to find any available file reference, the measurement
 * will be handled by ima_check_last_writer().
 */

void ima_delayed_inode_update(struct inode *inode)
{
	struct integrity_iint_cache *iint;
	struct ima_fl_entry *e;
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
	if (iint->ima_work.file)
		goto out;

	list_for_each_entry(e, &iint->file_list, list) {
		/* f_count can be 0 already, so we do "get_file_not_zero()" */
		if (atomic_long_inc_not_zero(&e->file->f_count) == 0)
			continue;

		iint->ima_work.file = e->file;
		msecs = ima_inode_update_delay(inode);
		INIT_DELAYED_WORK(&iint->ima_work.work,
				  ima_delayed_update_handler);

		creq = queue_delayed_work(ima_update_wq,
					  &iint->ima_work.work,
					  msecs_to_jiffies(msecs));
		if (creq == false) {
			iint->ima_work.file = NULL;
			fput(e->file);
		}
		/* only try to use the first eligible e->file */
		break;
	}
out:
	mutex_unlock(&iint->mutex);
}
EXPORT_SYMBOL_GPL(ima_delayed_inode_update);
#endif

/**
 * ima_file_update - update the file measurement
 * @file: pointer to file structure being updated
 */
void ima_file_update(struct file *file)
{
	struct inode *inode = file_inode(file);
	struct integrity_iint_cache *iint;
	bool should_measure = true;
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
			should_measure = false;
	}
	if (should_measure) {
		iint->flags &= ~IMA_COLLECTED;
		ima_update_xattr(iint, file);
	}
	mutex_unlock(&iint->mutex);
}
EXPORT_SYMBOL_GPL(ima_file_update);

/**
 * ima_path_check - based on policy, collect/store measurement.
 * @file: pointer to the file to be measured
 * @mask: contains MAY_READ, MAY_WRITE, MAY_EXEC or MAY_APPEND
 *
 * Measure files based on the ima_must_measure() policy decision.
 *
 * On success return 0.  On integrity appraisal error, assuming the file
 * is in policy and IMA-appraisal is in enforcing mode, return -EACCES.
 */
int ima_file_check(struct file *file, int mask)
{
	u32 secid;

	security_task_getsecid(current, &secid);
	return process_measurement(file, current_cred(), secid, NULL, 0,
				   mask & (MAY_READ | MAY_WRITE | MAY_EXEC |
					   MAY_APPEND), FILE_CHECK);
}
EXPORT_SYMBOL_GPL(ima_file_check);

/**
 * ima_post_create_tmpfile - mark newly created tmpfile as new
 * @file : newly created tmpfile
 *
 * No measuring, appraising or auditing of newly created tmpfiles is needed.
 * Skip calling process_measurement(), but indicate which newly, created
 * tmpfiles are in policy.
 */
void ima_post_create_tmpfile(struct inode *inode)
{
	struct integrity_iint_cache *iint;
	int must_appraise;

	must_appraise = ima_must_appraise(inode, MAY_ACCESS, FILE_CHECK);
	if (!must_appraise)
		return;

	/* Nothing to do if we can't allocate memory */
	iint = integrity_inode_get(inode);
	if (!iint)
		return;

	/* needed for writing the security xattrs */
	set_bit(IMA_UPDATE_XATTR, &iint->atomic_flags);
	iint->ima_file_status = INTEGRITY_PASS;
}

/**
 * ima_post_path_mknod - mark as a new inode
 * @dentry: newly created dentry
 *
 * Mark files created via the mknodat syscall as new, so that the
 * file data can be written later.
 */
void ima_post_path_mknod(struct dentry *dentry)
{
	struct integrity_iint_cache *iint;
	struct inode *inode = dentry->d_inode;
	int must_appraise;

	must_appraise = ima_must_appraise(inode, MAY_ACCESS, FILE_CHECK);
	if (!must_appraise)
		return;

	/* Nothing to do if we can't allocate memory */
	iint = integrity_inode_get(inode);
	if (!iint)
		return;

	/* needed for re-opening empty files */
	iint->flags |= IMA_NEW_FILE;
}

/**
 * ima_read_file - pre-measure/appraise hook decision based on policy
 * @file: pointer to the file to be measured/appraised/audit
 * @read_id: caller identifier
 *
 * Permit reading a file based on policy. The policy rules are written
 * in terms of the policy identifier.  Appraising the integrity of
 * a file requires a file descriptor.
 *
 * For permission return 0, otherwise return -EACCES.
 */
int ima_read_file(struct file *file, enum kernel_read_file_id read_id)
{
	/*
	 * READING_FIRMWARE_PREALLOC_BUFFER
	 *
	 * Do devices using pre-allocated memory run the risk of the
	 * firmware being accessible to the device prior to the completion
	 * of IMA's signature verification any more than when using two
	 * buffers?
	 */
	return 0;
}

static const int read_idmap[READING_MAX_ID] = {
	[READING_FIRMWARE] = FIRMWARE_CHECK,
	[READING_FIRMWARE_PREALLOC_BUFFER] = FIRMWARE_CHECK,
	[READING_MODULE] = MODULE_CHECK,
	[READING_KEXEC_IMAGE] = KEXEC_KERNEL_CHECK,
	[READING_KEXEC_INITRAMFS] = KEXEC_INITRAMFS_CHECK,
	[READING_POLICY] = POLICY_CHECK
};

/**
 * ima_post_read_file - in memory collect/appraise/audit measurement
 * @file: pointer to the file to be measured/appraised/audit
 * @buf: pointer to in memory file contents
 * @size: size of in memory file contents
 * @read_id: caller identifier
 *
 * Measure/appraise/audit in memory file based on policy.  Policy rules
 * are written in terms of a policy identifier.
 *
 * On success return 0.  On integrity appraisal error, assuming the file
 * is in policy and IMA-appraisal is in enforcing mode, return -EACCES.
 */
int ima_post_read_file(struct file *file, void *buf, loff_t size,
		       enum kernel_read_file_id read_id)
{
	enum ima_hooks func;
	u32 secid;

	if (!file && read_id == READING_FIRMWARE) {
		if ((ima_appraise & IMA_APPRAISE_FIRMWARE) &&
		    (ima_appraise & IMA_APPRAISE_ENFORCE)) {
			pr_err("Prevent firmware loading_store.\n");
			return -EACCES;	/* INTEGRITY_UNKNOWN */
		}
		return 0;
	}

	/* permit signed certs */
	if (!file && read_id == READING_X509_CERTIFICATE)
		return 0;

	if (!file || !buf || size == 0) { /* should never happen */
		if (ima_appraise & IMA_APPRAISE_ENFORCE)
			return -EACCES;
		return 0;
	}

	func = read_idmap[read_id] ?: FILE_CHECK;
	security_task_getsecid(current, &secid);
	return process_measurement(file, current_cred(), secid, buf, size,
				   MAY_READ, func);
}

/**
 * ima_load_data - appraise decision based on policy
 * @id: kernel load data caller identifier
 *
 * Callers of this LSM hook can not measure, appraise, or audit the
 * data provided by userspace.  Enforce policy rules requring a file
 * signature (eg. kexec'ed kernel image).
 *
 * For permission return 0, otherwise return -EACCES.
 */
int ima_load_data(enum kernel_load_data_id id)
{
	bool ima_enforce, sig_enforce;

	ima_enforce =
		(ima_appraise & IMA_APPRAISE_ENFORCE) == IMA_APPRAISE_ENFORCE;

	switch (id) {
	case LOADING_KEXEC_IMAGE:
		if (IS_ENABLED(CONFIG_KEXEC_VERIFY_SIG)
		    && arch_ima_get_secureboot()) {
			pr_err("impossible to appraise a kernel image without a file descriptor; try using kexec_file_load syscall.\n");
			return -EACCES;
		}

		if (ima_enforce && (ima_appraise & IMA_APPRAISE_KEXEC)) {
			pr_err("impossible to appraise a kernel image without a file descriptor; try using kexec_file_load syscall.\n");
			return -EACCES;	/* INTEGRITY_UNKNOWN */
		}
		break;
	case LOADING_FIRMWARE:
		if (ima_enforce && (ima_appraise & IMA_APPRAISE_FIRMWARE)) {
			pr_err("Prevent firmware sysfs fallback loading.\n");
			return -EACCES;	/* INTEGRITY_UNKNOWN */
		}
		break;
	case LOADING_MODULE:
		sig_enforce = is_module_sig_enforced();

		if (ima_enforce && (!sig_enforce
				    && (ima_appraise & IMA_APPRAISE_MODULES))) {
			pr_err("impossible to appraise a module without a file descriptor. sig_enforce kernel parameter might help\n");
			return -EACCES;	/* INTEGRITY_UNKNOWN */
		}
	default:
		break;
	}
	return 0;
}

static int __init init_ima(void)
{
	int error;

	ima_init_template_list();
	hash_setup(CONFIG_IMA_DEFAULT_HASH);
	error = ima_init();

	if (error && strcmp(hash_algo_name[ima_hash_algo],
			    CONFIG_IMA_DEFAULT_HASH) != 0) {
		pr_info("Allocating %s failed, going to use default hash algorithm %s\n",
			hash_algo_name[ima_hash_algo], CONFIG_IMA_DEFAULT_HASH);
		hash_setup_done = 0;
		hash_setup(CONFIG_IMA_DEFAULT_HASH);
		error = ima_init();
	}

	error = register_blocking_lsm_notifier(&ima_lsm_policy_notifier);
	if (error)
		pr_warn("Couldn't register LSM notifier, error %d\n", error);

	if (!error) {
		ima_update_policy_flag();

		ima_update_wq = alloc_workqueue("ima-update-wq",
						WQ_MEM_RECLAIM |
						WQ_CPU_INTENSIVE,
						0);
		if (!ima_update_wq) {
			pr_err("Failed to allocate write measurement workqueue\n");
			error = -ENOMEM;
		}
	}
	return error;
}

late_initcall(init_ima);	/* Start IMA after the TPM is available */
