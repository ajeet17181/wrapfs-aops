/*
 * Copyright (c) 1998-2011 Erez Zadok
 * Copyright (c) 2009	   Shrikar Archak
 * Copyright (c) 2003-2011 Stony Brook University
 * Copyright (c) 2003-2011 The Research Foundation of SUNY
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "wrapfs.h"

static ssize_t wrapfs_read(struct file *file, char __user *buf,
		size_t count, loff_t *ppos)
{
	int err;
	struct file *lower_file;
	struct dentry *dentry = file->f_path.dentry;

	wrapfs_debug_fops(WRAPFS_SB(file->f_dentry->d_sb)->wrapfs_debug_f_ops,
				"");
	wrapfs_debug("");
	lower_file = wrapfs_lower_file(file);

	if (WRAPFS_SB(file->f_dentry->d_inode->i_sb)->mmap_option_set
			== true) {
#ifdef WRAPFS_CRYPTO
		if (is_key_null(WRAPFS_SB(file->f_dentry->d_sb)->key)) {
			wrapfs_debug("wrapfs cant read, as key is not set!!");
			return -1;
		}
#endif
		err = do_sync_read(file, buf, count, ppos);
	} else {
		err = vfs_read(lower_file, buf, count, ppos);
		if (err >= 0) {
			fsstack_copy_attr_atime(dentry->d_inode,
					lower_file->f_path.dentry->d_inode);
		}
	}

	wrapfs_debug_fops(WRAPFS_SB(file->f_dentry->d_sb)->wrapfs_debug_f_ops,
				"err : %d", err)
	return err;
}

static ssize_t wrapfs_write(struct file *file, const char __user *buf,
		size_t count, loff_t *ppos)
{
	int err = 0;
	struct file *lower_file;
	struct dentry *dentry = file->f_path.dentry;

	wrapfs_debug_fops(WRAPFS_SB(file->f_dentry->d_sb)->wrapfs_debug_f_ops,
				"");
	wrapfs_debug("");
	lower_file = wrapfs_lower_file(file);

	if (WRAPFS_SB(file->f_dentry->d_inode->i_sb)->mmap_option_set
			== true) {
#ifdef WRAPFS_CRYPTO
		if (is_key_null(WRAPFS_SB(file->f_dentry->d_sb)->key)) {
			wrapfs_debug("wrapfs cant write, as key is not set!!");
			return -1;
		}
#endif
		err = do_sync_write(file, buf, count, ppos);
	} else {
		err = vfs_write(lower_file, buf, count, ppos);
		if (err >= 0) {
			fsstack_copy_inode_size(dentry->d_inode,
					lower_file->f_path.dentry->d_inode);
			fsstack_copy_attr_times(dentry->d_inode,
					lower_file->f_path.dentry->d_inode);
		}
	}
	wrapfs_debug_fops(WRAPFS_SB(file->f_dentry->d_sb)->wrapfs_debug_f_ops,
				"err : %d", err);
	return err;
}

static int wrapfs_readdir(struct file *file, void *dirent, filldir_t filldir)
{
	int err = 0;
	struct file *lower_file = NULL;
	struct dentry *dentry = file->f_path.dentry;

	wrapfs_debug_fops(WRAPFS_SB(file->f_dentry->d_sb)->wrapfs_debug_f_ops,
				"");
	lower_file = wrapfs_lower_file(file);
	err = vfs_readdir(lower_file, filldir, dirent);
	file->f_pos = lower_file->f_pos;
	if (err >= 0)		/* copy the atime */
		fsstack_copy_attr_atime(dentry->d_inode,
					lower_file->f_path.dentry->d_inode);
	wrapfs_debug_fops(WRAPFS_SB(file->f_dentry->d_sb)->wrapfs_debug_f_ops,
				"err : %d", err);
	return err;
}

static long wrapfs_unlocked_ioctl(struct file *file, unsigned int cmd,
				  unsigned long arg)
{
	long err = -ENOTTY;
#ifdef WRAPFS_CRYPTO
	struct wrapfs_sb_info *wrapfs_sbptr = NULL;
#else
	struct file *lower_file = NULL;
#endif
	wrapfs_debug("wrapfs_unlocked_ioctl invoked!!");
	wrapfs_debug_fops(WRAPFS_SB(file->f_dentry->d_sb)->wrapfs_debug_f_ops,
				"");
#ifdef WRAPFS_CRYPTO
	wrapfs_debug("WRAPFS_CRYPTO set!!");
	if ((file) && (file->f_dentry) && (file->f_dentry->d_inode)) {
		wrapfs_sbptr = WRAPFS_SB(file->f_dentry->d_inode->i_sb);
		if (wrapfs_sbptr == NULL) {
			wrapfs_debug("sb_info is NULL!!");
			err = -EACCES;
			goto out;
		}
	} else {
		wrapfs_debug("Cannot retrieve wrapfs_sbptr!!");
		err = -EACCES;
		goto out;
	}
	if (cmd == WRAPFS_IOCTL_SET_KEY) {
		/* First flush all pages from cache.
		 * Otherwise pages will be read from cache after key change. */
		shrink_dcache_sb(file->f_dentry->d_inode->i_sb);
		if (((void *)arg) == NULL) {
			wrapfs_debug("NULL value passed for key!!");
			err = -EINVAL;
			goto out;
		}
		if (!(access_ok(VERIFY_READ, (char *)arg,
			WRAPFS_CRYPTO_KEY_LEN))) {
			wrapfs_debug("Invalid memory address!!");
			err = -EACCES;
			goto out;
		}
		memset(wrapfs_sbptr->key, 0x00, WRAPFS_CRYPTO_KEY_LEN);
		if (copy_from_user(wrapfs_sbptr->key, (char *)arg,
			WRAPFS_CRYPTO_KEY_LEN)) {
			wrapfs_debug("Error : copy_from_user failed!!");
			err = -EFAULT;
			goto out;
		}
		if (is_key_null(wrapfs_sbptr->key))
			wrapfs_debug("NULL Key from ioctl!!");
		err = 0;
	}
#else
	wrapfs_debug("WRAPFS_CRYPTO not set!!");
	lower_file = wrapfs_lower_file(file);

	/* XXX: use vfs_ioctl if/when VFS exports it */
	if (!lower_file || !lower_file->f_op)
		goto out;
	if (lower_file->f_op->unlocked_ioctl)
		err = lower_file->f_op->unlocked_ioctl(lower_file, cmd, arg);

#endif
out:
	wrapfs_debug_fops(WRAPFS_SB(file->f_dentry->d_sb)->wrapfs_debug_f_ops,
				"err : %d", (int)err);
	return err;
}

#ifdef CONFIG_COMPAT
static long wrapfs_compat_ioctl(struct file *file, unsigned int cmd,
				unsigned long arg)
{
	long err = -ENOTTY;
	struct file *lower_file;

	wrapfs_debug_fops(WRAPFS_SB(file->f_dentry->d_sb)->wrapfs_debug_f_ops,
				"");
	lower_file = wrapfs_lower_file(file);

	/* XXX: use vfs_ioctl if/when VFS exports it */
	if (!lower_file || !lower_file->f_op)
		goto out;
	if (lower_file->f_op->compat_ioctl)
		err = lower_file->f_op->compat_ioctl(lower_file, cmd, arg);

out:
	wrapfs_debug_fops(WRAPFS_SB(file->f_dentry->d_sb)->wrapfs_debug_f_ops,
				"err : %d", err);
	return err;
}
#endif

static int wrapfs_mmap(struct file *file, struct vm_area_struct *vma)
{
	int err = 0;
	bool willwrite;
	struct file *lower_file;
	const struct vm_operations_struct *saved_vm_ops = NULL;

	wrapfs_debug("");
	wrapfs_debug_fops(WRAPFS_SB(file->f_dentry->d_sb)->wrapfs_debug_f_ops,
				"");

#ifdef WRAPFS_CRYPTO
	if (is_key_null(WRAPFS_SB(file->f_dentry->d_sb)->key)) {
		wrapfs_debug("wrapfs cant mmap, as key is not set!!");
		return -1;
	}
#endif

	/* this might be deferred to mmap's writepage */
	willwrite = ((vma->vm_flags | VM_SHARED | VM_WRITE) == vma->vm_flags);

	/*
	 * File systems which do not implement ->writepage may use
	 * generic_file_readonly_mmap as their ->mmap op.  If you call
	 * generic_file_readonly_mmap with VM_WRITE, you'd get an -EINVAL.
	 * But we cannot call the lower ->mmap op, so we can't tell that
	 * writeable mappings won't work.  Therefore, our only choice is to
	 * check if the lower file system supports the ->writepage, and if
	 * not, return EINVAL (the same error that
	 * generic_file_readonly_mmap returns in that case).
	 */
	lower_file = wrapfs_lower_file(file);
	if (willwrite && !lower_file->f_mapping->a_ops->writepage) {
		err = -EINVAL;
		printk(KERN_ERR "wrapfs: lower file system does not "
		       "support writeable mmap\n");
		goto out;
	}

	/*
	 * find and save lower vm_ops.
	 *
	 * XXX: the VFS should have a cleaner way of finding the lower vm_ops
	 */
	if (!WRAPFS_F(file)->lower_vm_ops) {
		err = lower_file->f_op->mmap(lower_file, vma);
		if (err) {
			printk(KERN_ERR "wrapfs: lower mmap failed %d\n", err);
			goto out;
		}
		saved_vm_ops = vma->vm_ops; /* save: came from lower ->mmap */
		err = do_munmap(current->mm, vma->vm_start,
				vma->vm_end - vma->vm_start);
		if (err) {
			printk(KERN_ERR "wrapfs: do_munmap failed %d\n", err);
			goto out;
		}
	}

	/*
	 * Next 3 lines are all I need from generic_file_mmap.  I definitely
	 * don't want its test for ->readpage which returns -ENOEXEC.
	 */
	file_accessed(file);
	vma->vm_ops = &wrapfs_vm_ops;
	vma->vm_flags |= VM_CAN_NONLINEAR;

	/*
	 * Setting address_space_operations only when mmap is set.
	 * Otherwise assigning the default wrapfs_aops.
	 */
	if (WRAPFS_SB(file->f_dentry->d_inode->i_sb)->mmap_option_set
			== true) {
		wrapfs_debug("");
		file->f_mapping->a_ops = &wrapfs_mmap_aops;
	} else {
		wrapfs_debug("");
		file->f_mapping->a_ops = &wrapfs_aops;
	}

	if (!WRAPFS_F(file)->lower_vm_ops) /* save for our ->fault */
		WRAPFS_F(file)->lower_vm_ops = saved_vm_ops;

out:
	wrapfs_debug_fops(WRAPFS_SB(file->f_dentry->d_sb)->wrapfs_debug_f_ops,
				"err : %d", err);
	return err;
}

static int wrapfs_open(struct inode *inode, struct file *file)
{
	int err = 0;
	struct file *lower_file = NULL;
	struct path lower_path;

	wrapfs_debug("");
	wrapfs_debug_fops(WRAPFS_SB(file->f_dentry->d_sb)->wrapfs_debug_f_ops,
				"");
	/* don't open unhashed/deleted files */
	if (d_unhashed(file->f_path.dentry)) {
		err = -ENOENT;
		goto out_err;
	}

	file->private_data =
		kzalloc(sizeof(struct wrapfs_file_info), GFP_KERNEL);
	if (!WRAPFS_F(file)) {
		err = -ENOMEM;
		goto out_err;
	}

	/* open lower object and link wrapfs's file struct to lower's */
	wrapfs_get_lower_path(file->f_path.dentry, &lower_path);
	lower_file = dentry_open(lower_path.dentry, lower_path.mnt,
				 file->f_flags, current_cred());
	if (IS_ERR(lower_file)) {
		err = PTR_ERR(lower_file);
		lower_file = wrapfs_lower_file(file);
		if (lower_file) {
			wrapfs_set_lower_file(file, NULL);
			fput(lower_file); /* fput calls dput for lower_dentry */
		}
	} else {
		wrapfs_set_lower_file(file, lower_file);
	}

	if (err)
		kfree(WRAPFS_F(file));
	else
		fsstack_copy_attr_all(inode, wrapfs_lower_inode(inode));
out_err:
	wrapfs_debug_fops(WRAPFS_SB(file->f_dentry->d_sb)->wrapfs_debug_f_ops,
				"err : %d", err);
	return err;
}

static int wrapfs_flush(struct file *file, fl_owner_t id)
{
	int err = 0;
	struct file *lower_file = NULL;
	wrapfs_debug("");
	wrapfs_debug_fops(WRAPFS_SB(file->f_dentry->d_sb)->wrapfs_debug_f_ops,
				"");
	lower_file = wrapfs_lower_file(file);
	if (lower_file && lower_file->f_op && lower_file->f_op->flush) {
		wrapfs_debug("");
		err = lower_file->f_op->flush(lower_file, id);
	}
	wrapfs_debug_fops(WRAPFS_SB(file->f_dentry->d_sb)->wrapfs_debug_f_ops,
				"err : %d", err);
	return err;
}

/* release all lower object references & free the file info structure */
static int wrapfs_file_release(struct inode *inode, struct file *file)
{
	struct file *lower_file;
	lower_file = wrapfs_lower_file(file);
	wrapfs_debug("");
	wrapfs_debug_fops(WRAPFS_SB(file->f_dentry->d_sb)->wrapfs_debug_f_ops,
				"");
	if (lower_file) {
		wrapfs_set_lower_file(file, NULL);
		fput(lower_file);
	}

	kfree(WRAPFS_F(file));
	wrapfs_debug_fops(WRAPFS_SB(file->f_dentry->d_sb)->wrapfs_debug_f_ops,
				"err : %d", 0);
	return 0;
}

static int wrapfs_fsync(struct file *file, loff_t start, loff_t end,
			int datasync)
{
	int err;
	struct file *lower_file;
	struct path lower_path;
	struct dentry *dentry = file->f_path.dentry;

	wrapfs_debug("");
	wrapfs_debug_fops(WRAPFS_SB(file->f_dentry->d_sb)->wrapfs_debug_f_ops,
				"");
	err = generic_file_fsync(file, start, end, datasync);
	if (err)
		goto out;
	lower_file = wrapfs_lower_file(file);
	wrapfs_get_lower_path(dentry, &lower_path);
	err = vfs_fsync_range(lower_file, start, end, datasync);
	wrapfs_put_lower_path(dentry, &lower_path);
out:
	wrapfs_debug_fops(WRAPFS_SB(file->f_dentry->d_sb)->wrapfs_debug_f_ops,
				"err : %d", err);
	return err;
}

static int wrapfs_fasync(int fd, struct file *file, int flag)
{
	int err = 0;
	struct file *lower_file = NULL;

	wrapfs_debug_fops(WRAPFS_SB(file->f_dentry->d_sb)->wrapfs_debug_f_ops,
				"");
	lower_file = wrapfs_lower_file(file);
	if (lower_file->f_op && lower_file->f_op->fasync)
		err = lower_file->f_op->fasync(fd, lower_file, flag);

	wrapfs_debug_fops(WRAPFS_SB(file->f_dentry->d_sb)->wrapfs_debug_f_ops,
				"err : %d", err);
	return err;
}

const struct file_operations wrapfs_main_mmap_fops = {
	.llseek		= generic_file_llseek,
	.read		= wrapfs_read,
	.write		= wrapfs_write,
	.unlocked_ioctl	= wrapfs_unlocked_ioctl,
	.aio_read	= generic_file_aio_read,
	.aio_write	= generic_file_aio_write,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= wrapfs_compat_ioctl,
#endif
	.mmap		= wrapfs_mmap,
	.open		= wrapfs_open,
	.flush		= wrapfs_flush,
	.release	= wrapfs_file_release,
	.fsync		= wrapfs_fsync,
	.fasync		= wrapfs_fasync,
};

const struct file_operations wrapfs_main_fops = {
	.llseek		= generic_file_llseek,
	.read		= wrapfs_read,
	.write		= wrapfs_write,
	.unlocked_ioctl	= wrapfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= wrapfs_compat_ioctl,
#endif
	.mmap		= wrapfs_mmap,
	.open		= wrapfs_open,
	.flush		= wrapfs_flush,
	.release	= wrapfs_file_release,
	.fsync		= wrapfs_fsync,
	.fasync		= wrapfs_fasync,
};

/* trimmed directory options */
const struct file_operations wrapfs_dir_fops = {
	.llseek		= generic_file_llseek,
	.read		= generic_read_dir,
	.readdir	= wrapfs_readdir,
	.unlocked_ioctl	= wrapfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= wrapfs_compat_ioctl,
#endif
	.open		= wrapfs_open,
	.release	= wrapfs_file_release,
	.flush		= wrapfs_flush,
	.fsync		= wrapfs_fsync,
	.fasync		= wrapfs_fasync,
};
