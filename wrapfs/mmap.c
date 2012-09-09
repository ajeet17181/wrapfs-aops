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
#include <linux/crypto.h>
#include <linux/scatterlist.h>

static int wrapfs_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	int err;
	struct file *file, *lower_file;
	const struct vm_operations_struct *lower_vm_ops;
	struct vm_area_struct lower_vma;

	wrapfs_debug("");

	memcpy(&lower_vma, vma, sizeof(struct vm_area_struct));
	file = lower_vma.vm_file;

	wrapfs_debug_otherops(
		WRAPFS_SB(file->f_dentry->d_sb)->wrapfs_debug_other_ops,
		"");

	lower_vm_ops = WRAPFS_F(file)->lower_vm_ops;
	BUG_ON(!lower_vm_ops);

	lower_file = wrapfs_lower_file(file);
	/*
	 * XXX: vm_ops->fault may be called in parallel.  Because we have to
	 * resort to temporarily changing the vma->vm_file to point to the
	 * lower file, a concurrent invocation of wrapfs_fault could see a
	 * different value.  In this workaround, we keep a different copy of
	 * the vma structure in our stack, so we never expose a different
	 * value of the vma->vm_file called to us, even temporarily.  A
	 * better fix would be to change the calling semantics of ->fault to
	 * take an explicit file pointer.
	 */
	lower_vma.vm_file = lower_file;
	err = lower_vm_ops->fault(&lower_vma, vmf);
	wrapfs_debug_otherops(
		WRAPFS_SB(file->f_dentry->d_sb)->wrapfs_debug_other_ops,
		"err : %d", err);
	return err;
}

/* Taken from HW1 and changed the cipher from cbc to ctr to avoid padding */
#ifdef WRAPFS_CRYPTO
int my_encrypt(char *input, int inputlen, char *output, int outputlen,
		char *key, int keylen)
{
	struct crypto_blkcipher *tfm = NULL;
	struct blkcipher_desc desc;
	struct scatterlist src[1], dst[1];
	unsigned int retval = 0;

	tfm = crypto_alloc_blkcipher("ctr(aes)", 0, 0);
	if (IS_ERR(tfm)) {
		printk(KERN_INFO "crypto_alloc_blkcipher failed\n");
		return -EINVAL;
	}

	desc.tfm = tfm;
	desc.flags = 0;

	retval = crypto_blkcipher_setkey(tfm, key, keylen);
	if (retval) {
		printk(KERN_INFO "crypto_blkcipher_setkey failed\n");
		crypto_free_blkcipher(tfm);
		return -EINVAL;
	}

	sg_init_table(src, 1);
	sg_set_buf(&src[0], input, inputlen);
	sg_init_table(dst, 1);
	sg_set_buf(dst, output, outputlen);

	retval = crypto_blkcipher_encrypt(&desc, dst, src, inputlen);
	crypto_free_blkcipher(tfm);
	return retval;
}

int my_decrypt(char *input, int inputlen, char *output, int outputlen,
		char *key, int keylen)
{
	struct crypto_blkcipher *tfm = NULL;
	struct blkcipher_desc desc;
	struct scatterlist src[1], dst[1];
	unsigned int retval = 0;

	tfm = crypto_alloc_blkcipher("ctr(aes)", 0, 0);
	if (IS_ERR(tfm)) {
		printk(KERN_INFO "crypto_alloc_blkcipher failed\n");
		return -EINVAL;
	}

	desc.tfm = tfm;
	desc.flags = 0;

	retval = crypto_blkcipher_setkey(tfm, key, keylen);
	if (retval) {
		printk(KERN_INFO "crypto_blkcipher_setkey failed\n");
		crypto_free_blkcipher(tfm);
		return -EINVAL;
	}

	sg_init_table(src, 1);
	sg_set_buf(&src[0], input, inputlen);
	sg_init_table(dst, 1);
	sg_set_buf(dst, output, outputlen);

	retval = crypto_blkcipher_decrypt(&desc, dst, src, inputlen);
	crypto_free_blkcipher(tfm);
	return retval;
}
#endif

int wrapfs_readpage(struct file *file, struct page *page)
{
	int err;
	struct file *lower_file;
	struct inode *inode;
	mm_segment_t old_fs;
	char *page_data = NULL;
	mode_t orig_mode;
#ifdef WRAPFS_CRYPTO
	char *decrypted_buf = NULL;
#endif

	wrapfs_debug_aops(WRAPFS_SB(file->f_dentry->d_sb)->wrapfs_debug_a_ops,
				"");
	wrapfs_debug("");
	lower_file = wrapfs_lower_file(file);
	BUG_ON(lower_file == NULL);

	inode = file->f_path.dentry->d_inode;
	page_data = (char *) kmap(page);

	/*
	 * Use vfs_read because some lower file systems don't have a
	 * readpage method, and some file systems (esp. distributed ones)
	 * don't like their pages to be accessed directly.  Using vfs_read
	 * may be a little slower, but a lot safer, as the VFS does a lot of
	 * the necessary magic for us.
	 */
	lower_file->f_pos = page_offset(page);
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	/*
	 * generic_file_splice_write may call us on a file not opened for
	 * reading, so temporarily allow reading.
	 */
	orig_mode = lower_file->f_mode;
	lower_file->f_mode |= FMODE_READ;
	err = vfs_read(lower_file, page_data, PAGE_CACHE_SIZE,
			&lower_file->f_pos);
	lower_file->f_mode = orig_mode;
	set_fs(old_fs);

#ifdef WRAPFS_CRYPTO
	/* At this point, we have the entire page from lower file system in
	 * page_data. If WRAPFS_CRYPTO is set, we need to decrypt page_data
	 * and store it back in page_data. I have taken the decrypt function
	 * from HW1 and made necessary modifications.
	 */
	decrypted_buf = kmalloc(PAGE_CACHE_SIZE, GFP_KERNEL);
	if (decrypted_buf == NULL) {
		wrapfs_debug("kmalloc failed!!");
		kunmap(page);
		err = -ENOMEM;
		goto out;
	}
	if (my_decrypt(page_data, PAGE_CACHE_SIZE, decrypted_buf,
			PAGE_CACHE_SIZE,
			WRAPFS_SB(file->f_dentry->d_sb)->key,
			WRAPFS_CRYPTO_KEY_LEN) < 0) {
		wrapfs_debug("my_decrypt failed!!");
		kunmap(page);
		kfree(decrypted_buf);
		err = -EINVAL;
	}
	memcpy(page_data, decrypted_buf, PAGE_CACHE_SIZE);
#endif

	if (err >= 0 && err < PAGE_CACHE_SIZE)
		memset(page_data + err, 0, PAGE_CACHE_SIZE - err);
	kunmap(page);

	if (err < 0)
		goto out;
	err = 0;

	/* if vfs_read succeeded above, sync up our times */
	fsstack_copy_attr_times(inode, lower_file->f_path.dentry->d_inode);

	flush_dcache_page(page);

out:
	if (err == 0)
		SetPageUptodate(page);
	else
		ClearPageUptodate(page);
	unlock_page(page);
	wrapfs_debug_aops(WRAPFS_SB(file->f_dentry->d_sb)->wrapfs_debug_a_ops,
				"err : %d", err);
	return err;
}

static int wrapfs_writepage(struct page *page, struct writeback_control *wbc)
{
	int err = -EIO;
	struct inode *inode;
	struct inode *lower_inode;
	struct page *lower_page;
	struct address_space *lower_mapping; /* lower inode mapping */
	gfp_t mask;
	char *lower_page_data = NULL;
/*#ifdef WRAPFS_CRYPTO
	char *enc_buf = NULL;
#endif*/
	wrapfs_debug_aops(
		WRAPFS_SB(page->mapping->host->i_sb)->wrapfs_debug_a_ops, "");
	wrapfs_debug("");
	BUG_ON(!PageUptodate(page));
	wrapfs_debug("");
	inode = page->mapping->host;

	/* if no lower inode, nothing to do */
	if (!inode || !WRAPFS_I(inode) || WRAPFS_I(inode)->lower_inode) {
		err = 0;
		goto out;
	}
	lower_inode = wrapfs_lower_inode(inode);
	lower_mapping = lower_inode->i_mapping;

	/*
	 * find lower page (returns a locked page)
	 *
	 * We turn off __GFP_FS while we look for or create a new lower
	 * page.  This prevents a recursion into the file system code, which
	 * under memory pressure conditions could lead to a deadlock.  This
	 * is similar to how the loop driver behaves (see loop_set_fd in
	 * drivers/block/loop.c).  If we can't find the lower page, we
	 * redirty our page and return "success" so that the VM will call us
	 * again in the (hopefully near) future.
	 */
	mask = mapping_gfp_mask(lower_mapping) & ~(__GFP_FS);
	lower_page = find_or_create_page(lower_mapping, page->index, mask);
	if (!lower_page) {
		err = 0;
		set_page_dirty(page);
		goto out;
	}
	lower_page_data = (char *)kmap(lower_page);

	/* copy page data from our upper page to the lower page */
	copy_highpage(lower_page, page);
	flush_dcache_page(lower_page);
	SetPageUptodate(lower_page);
	set_page_dirty(lower_page);

/*#ifdef WRAPFS_CRYPTO
	enc_buf = kmalloc(PAGE_CACHE_SIZE, GFP_KERNEL);
	if (enc_buf == NULL) {
		wrapfs_debug("No memory!!");
		err = -ENOMEM;
		goto out_release;
	}
	err = my_encrypt(lower_page_data, PAGE_CACHE_SIZE, enc_buf,
			PAGE_CACHE_SIZE,
			WRAPFS_SB(inode->i_sb)->key,
			WRAPFS_CRYPTO_KEY_LEN);
	if (err < 0) {
		wrapfs_debug("encrypt error!!");
		kfree(enc_buf);
		err = -EINVAL;
		goto out_release;
	}
	memcpy(lower_page_data, enc_buf, PAGE_CACHE_SIZE);
	kfree(enc_buf);
#endif*/

	/*
	 * Call lower writepage (expects locked page).  However, if we are
	 * called with wbc->for_reclaim, then the VFS/VM just wants to
	 * reclaim our page.  Therefore, we don't need to call the lower
	 * ->writepage: just copy our data to the lower page (already done
	 * above), then mark the lower page dirty and unlock it, and return
	 * success.
	 */
	/*if (wbc->for_reclaim) {
		unlock_page(lower_page);
		goto out_release;
	}*/

	BUG_ON(!lower_mapping->a_ops->writepage);
	wait_on_page_writeback(lower_page); /* prevent multiple writers */
	clear_page_dirty_for_io(lower_page); /* emulate VFS behavior */
	err = lower_mapping->a_ops->writepage(lower_page, wbc);
	if (err < 0)
		goto out_release;

	/*
	 * Lower file systems such as ramfs and tmpfs, may return
	 * AOP_WRITEPAGE_ACTIVATE so that the VM won't try to (pointlessly)
	 * write the page again for a while.  But those lower file systems
	 * also set the page dirty bit back again.  Since we successfully
	 * copied our page data to the lower page, then the VM will come
	 * back to the lower page (directly) and try to flush it.  So we can
	 * save the VM the hassle of coming back to our page and trying to
	 * flush too.  Therefore, we don't re-dirty our own page, and we
	 * never return AOP_WRITEPAGE_ACTIVATE back to the VM (we consider
	 * this a success).
	 *
	 * We also unlock the lower page if the lower ->writepage returned
	 * AOP_WRITEPAGE_ACTIVATE.  (This "anomalous" behaviour may be
	 * addressed in future shmem/VM code.)
	 */
	if (err == AOP_WRITEPAGE_ACTIVATE) {
		err = 0;
		unlock_page(lower_page);
	}

out_release:
	kunmap(lower_page);
	/* b/c find_or_create_page increased refcnt */
	page_cache_release(lower_page);
out:
	/*
	 * We unlock our page unconditionally, because we never return
	 * AOP_WRITEPAGE_ACTIVATE.
	 */
	unlock_page(page);
	wrapfs_debug_aops(WRAPFS_SB(inode->i_sb)->wrapfs_debug_a_ops,
				"err : %d", err);
	return err;
}

/* I have followed the behavior from ecryptfs. write_begin sets up the page.
 * for writing. Following changes are made :
 * 1. If Encrypt is not enabled, then just grab the page and set it up for
 *    write_begin. It is almost similar to ecryptfs. When we seek to a position
 *    after EOF and write, then the copied bytes are adjusted accordingly and
 *    passed. For example, if the file contains 2000 bytes and if we write
 *    1000 bytes from 3000th position(by lseeking), then from contains 3000 and
 *    copied contains 1000.  So we can directly copy 1000 bytes to lower file.
 * 2. When Encrypt is enabled, three cases are possible which are commented
 *    below. We must handle zero bytes cases explicitly.
 */
int wrapfs_write_begin(struct file *file, struct address_space *mapping,
		loff_t pos, unsigned len, unsigned flags,
		struct page **pagep, void **fsdata)
{
	struct page *page;
	char *page_data;
	pgoff_t index;
	int err = 0;
	struct inode *cur_inode, *lower_inode;
	unsigned int offset = 0;

#ifdef WRAPFS_CRYPTO
	/* pgoff_t is unsigned long, loff_t is long long */
	loff_t cur_inode_size;
	pgoff_t cur_inode_last_index;
	unsigned int cur_inode_end_offset;
	unsigned int zero_count;
	char *page_data_zeros;
	struct page *page_to_zeros = NULL;
	pgoff_t tempindex;
	pgoff_t tempoffset;
	pgoff_t bytes_to_write;
	struct file *lower_file = wrapfs_lower_file(file);
	char *encrypted_buf;
	mm_segment_t old_fs;
#endif

	wrapfs_debug("");
	wrapfs_debug_aops(WRAPFS_SB(file->f_dentry->d_sb)->wrapfs_debug_a_ops,
				"");

	index = pos >> PAGE_CACHE_SHIFT;
	offset = pos & (PAGE_CACHE_SIZE - 1);
	wrapfs_debug("index : %lu, offset : %d\n", index, offset);

	page = grab_cache_page_write_begin(mapping, index, flags);
	if (!page) {
		wrapfs_debug("grab_cache_page_write_begin returned NULL!!");
		err = -ENOMEM;
		goto out;
	}
	page_data = (char *)kmap(page);
	*pagep = page;

	cur_inode = file->f_path.dentry->d_inode;
	if (cur_inode)
		lower_inode = wrapfs_lower_inode(cur_inode);

#ifdef WRAPFS_CRYPTO
	/* cur_inode* refers to the file's existing attributes */
	cur_inode_size = cur_inode->i_size;
	cur_inode_last_index = cur_inode_size >> (PAGE_CACHE_SHIFT);
	cur_inode_end_offset = cur_inode_size & (PAGE_CACHE_SIZE - 1);

	wrapfs_debug(
	"cur_inode->i_size : %lu, i_size_read(page->mapping->host) : %lu\n",
	(unsigned long)cur_inode->i_size,
	(unsigned long)i_size_read(page->mapping->host));

	if (index == cur_inode_last_index) {
		/* The page to write is same as last page in file */
		wrapfs_debug("");
		if (pos > cur_inode_size) {
			/* Need to fill zeroes upto pos,
			 * from cur_inode_size */
			wrapfs_debug("");
			zero_count = pos - cur_inode_size;
			memset(page_data + cur_inode_end_offset, 0x00,
				zero_count);
		} else if (pos == cur_inode_size) {
			wrapfs_debug("");
			/* Fine. Do a normal encryption in write_end */
		} else if (pos < cur_inode_size) {
			/* Fine. Do a normal encryption in write_end */
			wrapfs_debug("");

		}
	} else if (index < cur_inode_last_index) {
		/* The page to write is an intermediate file page.
		 * No special cases need to be handled here.
		 */
		wrapfs_debug("");
	} else if (index > cur_inode_last_index) {
		/* If we skip to a page more than the last page in file.
		 * Need to fill holes between cur_inode_last_index and index.
		 * First filling hole in the new index page upto offset.
		 */
		wrapfs_debug("");
		memset(page_data, 0x00, offset);
		tempoffset = cur_inode_end_offset;
		tempindex = cur_inode_last_index;
		lower_file->f_pos = cur_inode_size;
		encrypted_buf = kmalloc(PAGE_CACHE_SIZE, GFP_KERNEL);
		if (encrypted_buf == NULL) {
			wrapfs_debug("kmalloc failed!!");
			err = -ENOMEM;
			goto out_holes;
		}
		/* Fill zeroes in page cur_inode_last_index from cur off to end
		 * Then fill all pages from (cur_inode_last_index + 1) to index
		 * These must also be encrypted and written to lower file here
		 * itself as they are not reflected in write_end.
		 */
		while (tempindex < index) {
			page_to_zeros =
			grab_cache_page_write_begin(cur_inode->i_mapping,
							tempindex, flags);
			if (page_to_zeros == NULL) {
				wrapfs_debug("grab_cache_page failed!!");
				kfree(encrypted_buf);
				err = -ENOMEM;
				goto out_holes;
			}
			page_data_zeros = (char *)kmap(page_to_zeros);
			bytes_to_write = PAGE_CACHE_SIZE - tempoffset;
			memset(page_data_zeros + tempoffset, 0x00,
				bytes_to_write);
			err = my_encrypt(page_data_zeros, PAGE_CACHE_SIZE,
				encrypted_buf,
				PAGE_CACHE_SIZE,
				WRAPFS_SB(file->f_dentry->d_sb)->key,
				WRAPFS_CRYPTO_KEY_LEN);
			if (err < 0) {
				wrapfs_debug("Encryption failed!!");
				kfree(encrypted_buf);
				err = -EINVAL;
				goto free_pages_holes;
			}
			flush_dcache_page(page_to_zeros);

			old_fs = get_fs();
			set_fs(KERNEL_DS);
			err = vfs_write(lower_file,
					encrypted_buf + tempoffset,
					bytes_to_write,
					&lower_file->f_pos);
			set_fs(old_fs);
free_pages_holes:
			kunmap(page_to_zeros);
			unlock_page(page_to_zeros);
			page_cache_release(page_to_zeros);
			if (err < 0) {
				kfree(encrypted_buf);
				goto out_holes;
			}
			err = 0;
			mark_inode_dirty_sync(cur_inode);
			tempoffset = 0;
			tempindex++;
		} /* while ends */
out_holes:
		if ((err < 0) && (page_to_zeros != NULL))
			ClearPageUptodate(page_to_zeros);
	}
#endif

out:
	if (page)
		kunmap(page);
	if (unlikely(err)) {
		unlock_page(page);
		page_cache_release(page);
		*pagep = NULL;
	}
	wrapfs_debug_aops(WRAPFS_SB(file->f_dentry->d_sb)->wrapfs_debug_a_ops,
				"err : %d", err);
	return err;
}

int wrapfs_write_end(struct file *file, struct address_space *mapping,
		loff_t pos, unsigned len, unsigned copied,
		struct page *page, void *fsdata)
{
	char *page_data = (char *)kmap(page);
	struct file *lower_file = wrapfs_lower_file(file);
	struct inode *inode = page->mapping->host;
	struct inode *lower_inode = NULL;
	unsigned from = pos & (PAGE_CACHE_SIZE - 1);
	mm_segment_t old_fs;
	int err = 0;
#ifdef WRAPFS_CRYPTO
	struct inode *cur_inode = page->mapping->host;
	pgoff_t index = pos >> (PAGE_CACHE_SHIFT);
	loff_t cur_inode_size = cur_inode->i_size;
	pgoff_t cur_inode_last_index = cur_inode_size >> (PAGE_CACHE_SHIFT);
	unsigned int cur_inode_end_offset;
	loff_t extra_padding = pos - cur_inode_size;
	char *encrypted_buf = NULL;
	unsigned copied1 = copied;
	cur_inode_end_offset = cur_inode_size & (PAGE_CACHE_SIZE - 1);
#endif
	wrapfs_debug_aops(WRAPFS_SB(file->f_dentry->d_sb)->wrapfs_debug_a_ops,
				"");
	wrapfs_debug("");
	if (lower_file == NULL) {
		wrapfs_debug("lower_file is NULL!!\n");
		err = -EACCES;
		goto out;
	}

	wrapfs_debug("pos : %lld", pos);
	wrapfs_debug("from : %u", from);
	wrapfs_debug("copied : %u", copied);
	wrapfs_debug("lower_file->f_pos : %lld", lower_file->f_pos);
#ifdef WRAPFS_CRYPTO
	if (extra_padding > 0 && (cur_inode_last_index == index)) {
		copied = copied + pos - cur_inode_size;
		from = cur_inode_end_offset;
	}
	encrypted_buf = kmalloc(PAGE_CACHE_SIZE, GFP_KERNEL);
	if (encrypted_buf == NULL) {
		wrapfs_debug("encrypted_buf is NULL!!");
		err = -ENOMEM;
		goto out;
	}
	err = my_encrypt(page_data, PAGE_CACHE_SIZE, encrypted_buf,
				PAGE_CACHE_SIZE,
				WRAPFS_SB(file->f_dentry->d_sb)->key,
				WRAPFS_CRYPTO_KEY_LEN);
	if (err < 0) {
		wrapfs_debug("Encrypt failed!!");
		err = -EINVAL;
		kfree(encrypted_buf);
		goto out;
	}
#endif
	lower_file->f_pos = page_offset(page) + from;

	if (!PageUptodate(page))
		SetPageUptodate(page);

	wrapfs_debug("pos : %lld", pos);
	wrapfs_debug("from : %u", from);
	wrapfs_debug("copied : %u", copied);
	wrapfs_debug("lower_file->f_pos : %lld", lower_file->f_pos);

	old_fs = get_fs();
	set_fs(KERNEL_DS);
#ifndef WRAPFS_CRYPTO
	err = vfs_write(lower_file, page_data + from, copied,
				&lower_file->f_pos);
#else
	err = vfs_write(lower_file, encrypted_buf + from, copied,
				&lower_file->f_pos);
	/* If zeroes need to be placed, then err exceeds copied.
	 * In this case, we need to make err=copied1 to avoid oops in iov_iter
	 */
	if (err > 0 && extra_padding > 0)
		err = copied1;
#endif
	wrapfs_debug("err : %d", err);
	set_fs(old_fs);
	if (err < 0) {
		wrapfs_debug("vfs_write error : %d!!\n", err);
		err = -EINVAL;
#ifdef WRAPFS_CRYPTO
		kfree(encrypted_buf);
#endif
		goto out;
	}

	lower_inode = lower_file->f_path.dentry->d_inode;
	if (!lower_inode)
		lower_inode = wrapfs_lower_inode(inode);
	BUG_ON(!lower_inode);
	fsstack_copy_inode_size(inode, lower_inode);
	fsstack_copy_attr_times(inode, lower_inode);

out:
	kunmap(page);
	unlock_page(page);
	page_cache_release(page);
	wrapfs_debug_aops(WRAPFS_SB(file->f_dentry->d_sb)->wrapfs_debug_a_ops,
					"err : %d", err);
	return err;
}

sector_t wrapfs_bmap(struct address_space *mapping, sector_t block)
{
	int err = -EINVAL;
	struct inode *inode, *lower_inode;
	sector_t (*bmap)(struct address_space *, sector_t);

	wrapfs_debug("");
	inode = (struct inode *)mapping->host;
	wrapfs_debug_aops(WRAPFS_SB(inode->i_sb)->wrapfs_debug_a_ops, "");
	lower_inode = wrapfs_lower_inode(inode);
	if (!lower_inode)
		goto out;
	bmap = lower_inode->i_mapping->a_ops->bmap;
	if (bmap)
		err = bmap(lower_inode->i_mapping, block);
out:
	wrapfs_debug_aops(WRAPFS_SB(inode->i_sb)->wrapfs_debug_a_ops,
				"err : %d", err);
	return err;
}

/*
 * XXX: the default address_space_ops for wrapfs is empty.  We cannot set
 * our inode->i_mapping->a_ops to NULL because too many code paths expect
 * the a_ops vector to be non-NULL.
 */
const struct address_space_operations wrapfs_aops = {
	/* empty on purpose */
};

const struct address_space_operations wrapfs_mmap_aops = {
	.readpage = wrapfs_readpage,
	.writepage = wrapfs_writepage,
	.write_begin = wrapfs_write_begin,
	.write_end = wrapfs_write_end,
	.bmap = wrapfs_bmap,
};

const struct vm_operations_struct wrapfs_vm_ops = {
	.fault		= wrapfs_fault,
};

