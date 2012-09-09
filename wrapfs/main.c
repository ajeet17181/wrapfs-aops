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
#include <linux/module.h>

bool mmap_option_set = false;
bool wrapfs_debug_sb_ops = false;
bool wrapfs_debug_i_ops = false;
bool wrapfs_debug_d_ops = false;
bool wrapfs_debug_f_ops = false;
bool wrapfs_debug_a_ops = false;
bool wrapfs_debug_other_ops = false;

/*
 * There is no need to lock the wrapfs_super_info's rwsem as there is no
 * way anyone can have a reference to the superblock at this point in time.
 */
static int wrapfs_read_super(struct super_block *sb, void *raw_data, int silent)
{
	int err = 0;
	struct super_block *lower_sb;
	struct path lower_path;
	char *dev_name = (char *) raw_data;
	struct inode *inode;
	wrapfs_debug("In wrapfs_read_super!!");

	if (!dev_name) {
		printk(KERN_ERR
		       "wrapfs: read_super: missing dev_name argument\n");
		err = -EINVAL;
		goto out;
	}

	wrapfs_debug("Lower path : %s\n", dev_name);

	/* parse lower path */
	err = kern_path(dev_name, LOOKUP_FOLLOW | LOOKUP_DIRECTORY,
			&lower_path);
	if (err) {
		printk(KERN_ERR	"wrapfs: error accessing "
		       "lower directory '%s'\n", dev_name);
		goto out;
	}

	/* allocate superblock private data */
	sb->s_fs_info = kzalloc(sizeof(struct wrapfs_sb_info), GFP_KERNEL);
	if (!WRAPFS_SB(sb)) {
		printk(KERN_CRIT "wrapfs: read_super: out of memory\n");
		err = -ENOMEM;
		goto out_free;
	}

	WRAPFS_SB(sb)->mmap_option_set = mmap_option_set;
#ifdef EXTRA_CREDIT
	WRAPFS_SB(sb)->wrapfs_debug_sb_ops = wrapfs_debug_sb_ops;
	WRAPFS_SB(sb)->wrapfs_debug_i_ops = wrapfs_debug_i_ops;
	WRAPFS_SB(sb)->wrapfs_debug_d_ops = wrapfs_debug_d_ops;
	WRAPFS_SB(sb)->wrapfs_debug_f_ops = wrapfs_debug_f_ops;
	WRAPFS_SB(sb)->wrapfs_debug_a_ops = wrapfs_debug_a_ops;
	WRAPFS_SB(sb)->wrapfs_debug_other_ops = wrapfs_debug_other_ops;
#endif
#ifdef WRAPFS_CRYPTO
	memset(WRAPFS_SB(sb)->key, 0x00, WRAPFS_CRYPTO_KEY_LEN);
	memcpy(WRAPFS_SB(sb)->key, "000000", 6);
	wrapfs_debug("key set to NULL during mount");
	/*memcpy(WRAPFS_SB(sb)->key, "abcdefghabcdefghabcdefghabcdefgh",
		WRAPFS_CRYPTO_KEY_LEN);*/
#endif

	/* set the lower superblock field of upper superblock */
	lower_sb = lower_path.dentry->d_sb;
	atomic_inc(&lower_sb->s_active);
	wrapfs_set_lower_super(sb, lower_sb);

	/* inherit maxbytes from lower file system */
	sb->s_maxbytes = lower_sb->s_maxbytes;

	/*
	 * Our c/m/atime granularity is 1 ns because we may stack on file
	 * systems whose granularity is as good.
	 */
	sb->s_time_gran = 1;

	sb->s_op = &wrapfs_sops;

	/* get a new inode and allocate our root dentry */
	inode = wrapfs_iget(sb, lower_path.dentry->d_inode);
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out_sput;
	}
	sb->s_root = d_alloc_root(inode);
	if (!sb->s_root) {
		err = -ENOMEM;
		goto out_iput;
	}
	d_set_d_op(sb->s_root, &wrapfs_dops);

	/* link the upper and lower dentries */
	sb->s_root->d_fsdata = NULL;
	err = new_dentry_private_data(sb->s_root);
	if (err)
		goto out_freeroot;


	/* if get here: cannot have error */

	/* set the lower dentries for s_root */
	wrapfs_set_lower_path(sb->s_root, &lower_path);

	/*
	 * No need to call interpose because we already have a positive
	 * dentry, which was instantiated by d_alloc_root.  Just need to
	 * d_rehash it.
	 */
	d_rehash(sb->s_root);
	if (!silent)
		printk(KERN_INFO
		       "wrapfs: mounted on top of %s type %s\n",
		       dev_name, lower_sb->s_type->name);
	goto out; /* all is well */

	/* no longer needed: free_dentry_private_data(sb->s_root); */
out_freeroot:
	dput(sb->s_root);
out_iput:
	iput(inode);
out_sput:
	/* drop refs we took earlier */
	atomic_dec(&lower_sb->s_active);
	kfree(WRAPFS_SB(sb));
	sb->s_fs_info = NULL;
out_free:
	path_put(&lower_path);

out:
	return err;
}

static inline void set_ops_false(void)
{
	mmap_option_set = false;
#ifdef EXTRA_CREDIT
	wrapfs_debug_sb_ops = false;
	wrapfs_debug_i_ops = false;
	wrapfs_debug_d_ops = false;
	wrapfs_debug_f_ops = false;
	wrapfs_debug_a_ops = false;
	wrapfs_debug_other_ops = false;
#endif
}


#ifdef EXTRA_CREDIT
static inline void set_debug_options(long debugval)
{
	if (debugval & 0x01) {
		wrapfs_debug_sb_ops = true;
		wrapfs_debug("DEBUG_WRAPFS_SUPERBLOCK_OPS enabled!!");
	}
	if (debugval & 0x02) {
		wrapfs_debug_i_ops = true;
		wrapfs_debug("DEBUG_WRAPFS_INODE_OPS enabled!!");
	}
	if (debugval & 0x04) {
		wrapfs_debug_d_ops = true;
		wrapfs_debug("DEBUG_WRAPFS_DENTRY_OPS enabled!!");
	}
	if (debugval & 0x10) {
		wrapfs_debug_f_ops = true;
		wrapfs_debug("DEBUG_WRAPFS_FILE_OPS enabled!!");
	}
	if (debugval & 0x20) {
		wrapfs_debug_a_ops = true;
		wrapfs_debug("DEBUG_WRAPFS_ADDRESS_SPACE_OPS enabled!!");
	}
	if (debugval & 0x40) {
		wrapfs_debug_other_ops = true;
		wrapfs_debug("DEBUG_WRAPFS_OTHER_OPS enabled!!");
	}
}
#endif

void parse_wrapfs_options(void *data)
{
	char *options = (char *)data;
	char *token = options;
#ifdef EXTRA_CREDIT
	char *token2 = NULL;
	char *debug = NULL;
	long debugval = 0;
#endif
	wrapfs_debug("raw_data : %s\n", options);
	set_ops_false();
	while (token != NULL) {
		token = strsep(&options, ",");
		if (token && strcmp(token, "mmap") == 0) {
			wrapfs_debug("MMAP is set");
			mmap_option_set = true;
		}
#ifdef EXTRA_CREDIT
		else if (token && strstr(token, "debug") != NULL) {
			debug = token;
			token2 = strsep(&debug, "=");
			if (strstr(token2, "debug") != NULL) {
				if (kstrtol(debug, 10, &debugval) < 0) {
					wrapfs_debug(
					"Invalid debug option. Ignoring it!!");
					debugval = 0;
				} else {
					wrapfs_debug("Debug level is set: %ld",
						debugval);
					set_debug_options(debugval);
				}
			}
		}
#endif
	}
	/*return 0;*/
}

struct dentry *wrapfs_mount(struct file_system_type *fs_type, int flags,
			    const char *dev_name, void *raw_data)
{
	void *lower_path_name = (void *) dev_name;
	wrapfs_debug("wrapfs_mount");
	parse_wrapfs_options(raw_data);
	return mount_nodev(fs_type, flags, lower_path_name,
			   wrapfs_read_super);
}

static struct file_system_type wrapfs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= WRAPFS_NAME,
	.mount		= wrapfs_mount,
	.kill_sb	= generic_shutdown_super,
	.fs_flags	= FS_REVAL_DOT,
};

static int __init init_wrapfs_fs(void)
{
	int err;

	pr_info("Registering wrapfs " WRAPFS_VERSION "\n");

	err = wrapfs_init_inode_cache();
	if (err)
		goto out;
	err = wrapfs_init_dentry_cache();
	if (err)
		goto out;
	err = register_filesystem(&wrapfs_fs_type);
out:
	if (err) {
		wrapfs_destroy_inode_cache();
		wrapfs_destroy_dentry_cache();
	}
	return err;
}

static void __exit exit_wrapfs_fs(void)
{
	wrapfs_destroy_inode_cache();
	wrapfs_destroy_dentry_cache();
	unregister_filesystem(&wrapfs_fs_type);
	pr_info("Completed wrapfs module unload\n");
}

MODULE_AUTHOR("Erez Zadok, Filesystems and Storage Lab, Stony Brook University"
	      " (http://www.fsl.cs.sunysb.edu/)");
MODULE_DESCRIPTION("Wrapfs " WRAPFS_VERSION
		   " (http://wrapfs.filesystems.org/)");
MODULE_LICENSE("GPL");

module_init(init_wrapfs_fs);
module_exit(exit_wrapfs_fs);

