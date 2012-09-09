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

#ifndef _WRAPFS_H_
#define _WRAPFS_H_

#include <linux/dcache.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/seq_file.h>
#include <linux/statfs.h>
#include <linux/fs_stack.h>
#include <linux/magic.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/dcache.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/page-flags.h>

#ifdef WRAPFS_CRYPTO
#include <linux/wrapfs_ioctl.h>
#endif

/* the file system name */
#define WRAPFS_NAME "wrapfs"

/* wrapfs root inode number */
#define WRAPFS_ROOT_INO     1

/* useful for tracking code reachability */
#define UDBG printk(KERN_DEFAULT "DBG:%s:%s:%d\n", __FILE__, __func__, __LINE__)

#ifdef EXTRA_CREDIT
#define WRAPFS_DEBUG_SUPERBLOCK_OPS
#define WRAPFS_DEBUG_INODE_OPS
#define WRAPFS_DEBUG_DENTRY_OPS
#define WRAPFS_DEBUG_FILE_OPS
#define WRAPFS_DEBUG_ADDRESS_SPACE_OPS
#define WRAPFS_DEBUG_OTHER_OPS
#endif

/* Custom debugging options */
#ifdef WRAPFS_DEBUG
#define wrapfs_debug(fmt, arg...) \
	printk(KERN_DEFAULT "DBG:%s:%s:%d: " fmt "\n", \
		__FILE__, __func__, __LINE__, ## arg);
#else
#define wrapfs_debug(fmt, arg...) 1;
#endif

#ifdef EXTRA_CREDIT
#define wrapfs_debug_sbops(val, fmt, arg...) \
	val ? printk(KERN_DEFAULT "DBG:%s:%s:%d: " fmt "\n", \
		__FILE__, __func__, __LINE__, ## arg) : 1;

#define wrapfs_debug_iops(val, fmt, arg...) \
	val ? printk(KERN_DEFAULT "DBG:%s:%s:%d: " fmt "\n", \
		__FILE__, __func__, __LINE__, ## arg) : 1;

#define wrapfs_debug_dops(val, fmt, arg...) \
	val ? printk(KERN_DEFAULT "DBG:%s:%s:%d: " fmt "\n", \
		__FILE__, __func__, __LINE__, ## arg) : 1;

#define wrapfs_debug_fops(val, fmt, arg...) \
	val ? printk(KERN_DEFAULT "DBG:%s:%s:%d: " fmt "\n", \
		__FILE__, __func__, __LINE__, ## arg) : 1;

#define wrapfs_debug_aops(val, fmt, arg...) \
	val ? printk(KERN_DEFAULT "DBG:%s:%s:%d: " fmt "\n", \
		__FILE__, __func__, __LINE__, ## arg) : 1;

#define wrapfs_debug_otherops(val, fmt, arg...) \
	val ? printk(KERN_DEFAULT "DBG:%s:%s:%d: " fmt "\n", \
		__FILE__, __func__, __LINE__, ## arg) : 1;
#else
#define wrapfs_debug_sbops(val, fmt, arg...) 1;
#define wrapfs_debug_iops(val, fmt, arg...) 1;
#define wrapfs_debug_dops(val, fmt, arg...) 1;
#define wrapfs_debug_fops(val, fmt, arg...) 1;
#define wrapfs_debug_aops(val, fmt, arg...) 1;
#define wrapfs_debug_otherops(val, fmt, arg...) 1;
#endif

/* operations vectors defined in specific files */
extern const struct file_operations wrapfs_main_fops;
extern const struct file_operations wrapfs_dir_fops;
extern const struct inode_operations wrapfs_main_iops;
extern const struct inode_operations wrapfs_dir_iops;
extern const struct inode_operations wrapfs_symlink_iops;
extern const struct super_operations wrapfs_sops;
extern const struct dentry_operations wrapfs_dops;
extern const struct address_space_operations wrapfs_aops, wrapfs_dummy_aops;
extern const struct vm_operations_struct wrapfs_vm_ops;

extern int wrapfs_init_inode_cache(void);
extern void wrapfs_destroy_inode_cache(void);
extern int wrapfs_init_dentry_cache(void);
extern void wrapfs_destroy_dentry_cache(void);
extern int new_dentry_private_data(struct dentry *dentry);
extern void free_dentry_private_data(struct dentry *dentry);
extern struct dentry *wrapfs_lookup(struct inode *dir, struct dentry *dentry,
				    struct nameidata *nd);
extern struct inode *wrapfs_iget(struct super_block *sb,
				 struct inode *lower_inode);
extern int wrapfs_interpose(struct dentry *dentry, struct super_block *sb,
			    struct path *lower_path);

extern const struct address_space_operations wrapfs_mmap_aops;
extern const struct file_operations wrapfs_main_mmap_fops;

/* file private data */
struct wrapfs_file_info {
	struct file *lower_file;
	const struct vm_operations_struct *lower_vm_ops;
};

/* wrapfs inode data in memory */
struct wrapfs_inode_info {
	struct inode *lower_inode;
	struct inode vfs_inode;
};

/* wrapfs dentry data in memory */
struct wrapfs_dentry_info {
	spinlock_t lock;	/* protects lower_path */
	struct path lower_path;
};


/* wrapfs super-block data in memory */
struct wrapfs_sb_info {
	struct super_block *lower_sb;
	bool mmap_option_set;
#ifdef WRAPFS_CRYPTO
	char key[WRAPFS_CRYPTO_KEY_LEN];
#endif
#ifdef EXTRA_CREDIT
	bool wrapfs_debug_sb_ops;
	bool wrapfs_debug_i_ops;
	bool wrapfs_debug_d_ops;
	bool wrapfs_debug_f_ops;
	bool wrapfs_debug_a_ops;
	bool wrapfs_debug_other_ops;
#endif
};

extern	bool mmap_option_set;
#ifdef EXTRA_CREDIT
extern	bool wrapfs_debug_sb_ops;
extern	bool wrapfs_debug_i_ops;
extern	bool wrapfs_debug_d_ops;
extern	bool wrapfs_debug_f_ops;
extern	bool wrapfs_debug_a_ops;
extern	bool wrapfs_debug_other_ops;
#endif
/*
 * inode to private data
 *
 * Since we use containers and the struct inode is _inside_ the
 * wrapfs_inode_info structure, WRAPFS_I will always (given a non-NULL
 * inode pointer), return a valid non-NULL pointer.
 */
static inline struct wrapfs_inode_info *WRAPFS_I(const struct inode *inode)
{
	return container_of(inode, struct wrapfs_inode_info, vfs_inode);
}

/* dentry to private data */
#define WRAPFS_D(dent) ((struct wrapfs_dentry_info *)(dent)->d_fsdata)

/* superblock to private data */
#define WRAPFS_SB(super) ((struct wrapfs_sb_info *)(super)->s_fs_info)

/* file to private Data */
#define WRAPFS_F(file) ((struct wrapfs_file_info *)((file)->private_data))

/* file to lower file */
static inline struct file *wrapfs_lower_file(const struct file *f)
{
	return WRAPFS_F(f)->lower_file;
}

static inline void wrapfs_set_lower_file(struct file *f, struct file *val)
{
	WRAPFS_F(f)->lower_file = val;
}

/* inode to lower inode. */
static inline struct inode *wrapfs_lower_inode(const struct inode *i)
{
	return WRAPFS_I(i)->lower_inode;
}

static inline void wrapfs_set_lower_inode(struct inode *i, struct inode *val)
{
	WRAPFS_I(i)->lower_inode = val;
}

/* superblock to lower superblock */
static inline struct super_block *wrapfs_lower_super(
	const struct super_block *sb)
{
	return WRAPFS_SB(sb)->lower_sb;
}

static inline void wrapfs_set_lower_super(struct super_block *sb,
					  struct super_block *val)
{
	WRAPFS_SB(sb)->lower_sb = val;
}

/* path based (dentry/mnt) macros */
static inline void pathcpy(struct path *dst, const struct path *src)
{
	dst->dentry = src->dentry;
	dst->mnt = src->mnt;
}
/* Returns struct path.  Caller must path_put it. */
static inline void wrapfs_get_lower_path(const struct dentry *dent,
					 struct path *lower_path)
{
	spin_lock(&WRAPFS_D(dent)->lock);
	pathcpy(lower_path, &WRAPFS_D(dent)->lower_path);
	path_get(lower_path);
	spin_unlock(&WRAPFS_D(dent)->lock);
	return;
}
static inline void wrapfs_put_lower_path(const struct dentry *dent,
					 struct path *lower_path)
{
	path_put(lower_path);
	return;
}
static inline void wrapfs_set_lower_path(const struct dentry *dent,
					 struct path *lower_path)
{
	spin_lock(&WRAPFS_D(dent)->lock);
	pathcpy(&WRAPFS_D(dent)->lower_path, lower_path);
	spin_unlock(&WRAPFS_D(dent)->lock);
	return;
}
static inline void wrapfs_reset_lower_path(const struct dentry *dent)
{
	spin_lock(&WRAPFS_D(dent)->lock);
	WRAPFS_D(dent)->lower_path.dentry = NULL;
	WRAPFS_D(dent)->lower_path.mnt = NULL;
	spin_unlock(&WRAPFS_D(dent)->lock);
	return;
}
static inline void wrapfs_put_reset_lower_path(const struct dentry *dent)
{
	struct path lower_path;
	spin_lock(&WRAPFS_D(dent)->lock);
	pathcpy(&lower_path, &WRAPFS_D(dent)->lower_path);
	WRAPFS_D(dent)->lower_path.dentry = NULL;
	WRAPFS_D(dent)->lower_path.mnt = NULL;
	spin_unlock(&WRAPFS_D(dent)->lock);
	path_put(&lower_path);
	return;
}

/* locking helpers */
static inline struct dentry *lock_parent(struct dentry *dentry)
{
	struct dentry *dir = dget_parent(dentry);
	mutex_lock_nested(&dir->d_inode->i_mutex, I_MUTEX_PARENT);
	return dir;
}

static inline void unlock_dir(struct dentry *dir)
{
	mutex_unlock(&dir->d_inode->i_mutex);
	dput(dir);
}

#ifdef WRAPFS_CRYPTO
static inline bool is_key_null(char *key)
{
	if (memcmp(key, "000000", 6) == 0)
		return true;
	return false;
}
#endif

#endif	/* not _WRAPFS_H_ */
