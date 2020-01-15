/*
 * Resizable simple ram filesystem for Linux.
 *
 * Copyright (C) 2000 Linus Torvalds.
 *               2000 Transmeta Corp.
 *
 * Usage limits added by David Gibson, Linuxcare Australia.
 * This file is released under the GPL.
 */

/*
 * NOTE! This filesystem is probably most useful
 * not as a real filesystem, but as an example of
 * how virtual filesystems can be written.
 *
 * It doesn't get much simpler than this. Consider
 * that this file implements the full semantics of
 * a POSIX-compliant read-write filesystem.
 *
 * Note in particular how the filesystem does not
 * need to implement any data structures of its own
 * to keep track of the virtual data: using the VFS
 * caches is sufficient.
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/export.h>
#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/time.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/backing-dev.h>
#include <linux/sched.h>
#include <linux/parser.h>
#include <linux/magic.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <net/sock.h>
/*#include <linux/net/sock.h>*/
#include <linux/kallsyms.h>


struct myfs_mount_opts {
	umode_t mode;
};

struct myfs_fs_info {
	struct myfs_mount_opts mount_opts;
};

#define RAMFS_DEFAULT_MODE	0755

static const struct super_operations myfs_ops;
static const struct inode_operations myfs_dir_inode_operations;

static struct proto *tcp_prot_addr;

static unsigned long myfs_mmu_get_unmapped_area(struct file *file,
		unsigned long addr, unsigned long len, unsigned long pgoff,
		unsigned long flags)
{
	return current->mm->get_unmapped_area(file, addr, len, pgoff, flags);
}

const struct file_operations myfs_file_operations = {
	.read_iter	= generic_file_read_iter,
	//.write_iter	= generic_file_write_iter,
	.mmap		= generic_file_mmap,
	.fsync		= noop_fsync,
	.splice_read	= generic_file_splice_read,
	.splice_write	= iter_file_splice_write,
	.llseek		= generic_file_llseek,
	.get_unmapped_area	= myfs_mmu_get_unmapped_area,
};


static 
int myfs_simple_setattr(struct dentry *dentry, struct iattr *iattr)
{
    printk(KERN_INFO "myfs_file_inode_ops.setattr dentry:%s\n", dentry->d_name.name);
    return simple_setattr(dentry, iattr);
}


static
int myfs_simple_getattr(const struct path *path, struct kstat *stat,
		   u32 request_mask, unsigned int query_flags)
{

    printk(KERN_INFO "myfs_file_inode_ops.getattr path:%s\n", path->dentry->d_name.name);
    return simple_getattr(path, stat, request_mask, query_flags);
}


static 
int myfs_generic_permission(struct inode *inode, int mask)
{
    printk(KERN_INFO "myfs_file_inode_ops.permission \n");
    return generic_permission(inode, mask);
}

const struct inode_operations myfs_file_inode_operations = {
	.setattr	= myfs_simple_setattr,
	.getattr	= myfs_simple_getattr,
	.permission	= myfs_generic_permission,

};

static int myfs_simple_unlink(struct inode *dir, struct dentry *dentry)
{ 
    //rm
    printk(KERN_INFO "myfs_unlink dir:%lu dentry:%s\n", dir->i_ino, dentry->d_name.name);
    return simple_unlink(dir, dentry);
}

static
struct dentry *myfs_simple_lookup(struct inode *dir, struct dentry *dentry, unsigned int flags)
{
    printk(KERN_INFO "myfs_lookup dir:%lu dentry:%s\n", dir->i_ino, dentry->d_name.name);
    return simple_lookup(dir, dentry, flags);
}

static
int myfs_simple_link(struct dentry *old_dentry, struct inode *dir, struct dentry *dentry)
{
    printk(KERN_INFO "myfs_link dir:%lu dentry:%s oldDentry:%s\n",
           dir->i_ino, dentry->d_name.name, old_dentry->d_name.name);
    return simple_link(old_dentry, dir, dentry);
}

static 
int myfs_simple_rmdir(struct inode *dir, struct dentry *dentry)
{
    printk(KERN_INFO "myfs_rmdir dir:%lu dentry:%s\n",
           dir->i_ino, dentry->d_name.name); 
    return simple_rmdir(dir, dentry);
}

static 
int myfs_simple_rename(struct inode *old_dir, struct dentry *old_dentry,
		  struct inode *new_dir, struct dentry *new_dentry,
		  unsigned int flags)
{
    printk(KERN_INFO "myfs_rename oldDentry:%s newDentry:%s\n",
           old_dentry->d_name.name, new_dentry->d_name.name);
    return simple_rename(old_dir, old_dentry, new_dir, new_dentry, flags);
}

static const struct address_space_operations myfs_aops = {
	.readpage	= simple_readpage,
	.write_begin	= simple_write_begin,
	.write_end	= simple_write_end,
	/*.set_page_dirty	= __set_page_dirty_no_writeback,*/
};

struct inode *myfs_get_inode(struct super_block *sb,
				const struct inode *dir, umode_t mode, dev_t dev)
{
	struct inode * inode = new_inode(sb);

	if (inode) {
		inode->i_ino = get_next_ino();
		inode_init_owner(inode, dir, mode);
		inode->i_mapping->a_ops = &myfs_aops;
		mapping_set_gfp_mask(inode->i_mapping, GFP_HIGHUSER);
		mapping_set_unevictable(inode->i_mapping);
		inode->i_atime = inode->i_mtime = inode->i_ctime = current_time(inode);
		switch (mode & S_IFMT) {
		default:
			init_special_inode(inode, mode, dev);
			break;
		case S_IFREG:
			inode->i_op = &myfs_file_inode_operations;
			inode->i_fop = &myfs_file_operations;
			break;
		case S_IFDIR:
			inode->i_op = &myfs_dir_inode_operations;
			inode->i_fop = &simple_dir_operations; //TODO

			/* directory inodes start off with i_nlink == 2 (for "." entry) */
			inc_nlink(inode);
			break;
		case S_IFLNK:
			inode->i_op = &page_symlink_inode_operations;
			inode_nohighmem(inode);
			break;
		}
	}
    printk(KERN_INFO "myfs_get_inode new inode:%lu\n", inode->i_ino);
	return inode;
}

/*
 * File creation. Allocate an inode, and we're done..
 */
/* SMP-safe */
static int
myfs_mknod(struct inode *dir, struct dentry *dentry, umode_t mode, dev_t dev)
{
	struct inode * inode = myfs_get_inode(dir->i_sb, dir, mode, dev);
	int error = -ENOSPC;

    printk(KERN_INFO "myfs_mknod dir:%lu dentry:%s:%s get_inode:%lu\n",
           dir->i_ino, 
           dentry->d_name.name, dentry->d_iname,  inode->i_ino);
	if (inode) {
		d_instantiate(dentry, inode);
		dget(dentry);	/* Extra count - pin the dentry in core */
		error = 0;
		dir->i_mtime = dir->i_ctime = current_time(dir);
	}
	return error;
}

static int myfs_mkdir(struct inode * dir, struct dentry * dentry, umode_t mode)
{
	int retval = myfs_mknod(dir, dentry, mode | S_IFDIR, 0);
	if (!retval)
		inc_nlink(dir);

    printk(KERN_INFO "myfs_mkdir dir:%lu dentry:%s dir.nlink:%d\n", 
           dir->i_ino, dentry->d_name.name, dir->i_nlink);
	return retval;
}

static int myfs_create(struct inode *dir, struct dentry *dentry, umode_t mode, bool excl)
{
    printk(KERN_INFO "myfs_create dir:%lu dentry:%s \n", dir->i_ino, dentry->d_name.name);
	return myfs_mknod(dir, dentry, mode | S_IFREG, 0);
}

static int myfs_symlink(struct inode * dir, struct dentry *dentry, const char * symname)
{
	struct inode *inode;
	int error = -ENOSPC;

	inode = myfs_get_inode(dir->i_sb, dir, S_IFLNK|S_IRWXUGO, 0);
	if (inode) {
		int l = strlen(symname)+1;
		error = page_symlink(inode, symname, l);
		if (!error) {
			d_instantiate(dentry, inode);
			dget(dentry);
			dir->i_mtime = dir->i_ctime = current_time(dir);
		} else
			iput(inode);
	}
	return error;
}


/*
 * Display the mount options in /proc/mounts.
 */
static int myfs_show_options(struct seq_file *m, struct dentry *root)
{
	struct myfs_fs_info *fsi = root->d_sb->s_fs_info;

	if (fsi->mount_opts.mode != RAMFS_DEFAULT_MODE)
		seq_printf(m, ",mode=%o", fsi->mount_opts.mode);
	return 0;
}


static int myfs_generic_delete_inode(struct inode *inode)
{
    printk(KERN_INFO "myfs_sb.drop_inode \n");
    return generic_delete_inode(inode);
}

static const struct super_operations myfs_ops = {
	.statfs		= simple_statfs, 
    .drop_inode	= myfs_generic_delete_inode,
	.show_options	= myfs_show_options,
};

static const struct inode_operations myfs_dir_inode_operations = {
	.create		= myfs_create,
	.lookup		= myfs_simple_lookup,
	.link		= myfs_simple_link,
	.unlink		= myfs_simple_unlink,
	.symlink	= myfs_symlink,
	.mkdir		= myfs_mkdir,
	.rmdir		= myfs_simple_rmdir,
	.mknod		= myfs_mknod,
	.rename		= myfs_simple_rename,
};

enum {
	Opt_mode,
	Opt_err
};

static const match_table_t tokens = {
	{Opt_mode, "mode=%o"},
	{Opt_err, NULL}
};

#if 0
static int myfs_parse_options(char *data, struct myfs_mount_opts *opts)
{
	substring_t args[MAX_OPT_ARGS];
	int option;
	int token;
	char *p;

	opts->mode = RAMFS_DEFAULT_MODE;

	while ((p = strsep(&data, ",")) != NULL) {
		if (!*p)
			continue;

		token = match_token(p, tokens, args);
		switch (token) {
		case Opt_mode:
			if (match_octal(&args[0], &option))
				return -EINVAL;
			opts->mode = option & S_IALLUGO;
			break;
		/*
		 * We might like to report bad mount options here;
		 * but traditionally myfs has ignored all mount options,
		 * and as it is used as a !CONFIG_SHMEM simple substitute
		 * for tmpfs, better continue to ignore other mount options.
		 */
		}
	}

	return 0;
}
#endif 

int myfs_fill_super(struct super_block *sb, void *data, int silent)
{
	struct myfs_fs_info *fsi;
	struct inode *inode;

    printk(KERN_INFO "myfs_fill_super\n");


	fsi = kzalloc(sizeof(struct myfs_fs_info), GFP_KERNEL);
	sb->s_fs_info = fsi;
	if (!fsi)
		return -ENOMEM;

	fsi->mount_opts.mode = RAMFS_DEFAULT_MODE;
	/*err = myfs_parse_options(data, &fsi->mount_opts);*/
	/*if (err)                                         */
	/*    return err;                                  */

	sb->s_maxbytes		= MAX_LFS_FILESIZE;
	sb->s_blocksize		= PAGE_SIZE;
	sb->s_blocksize_bits	= PAGE_SHIFT;
    sb->s_magic		= 0x45119;
	sb->s_op		= &myfs_ops;
	sb->s_time_gran		= 1;

	inode = myfs_get_inode(sb, NULL, S_IFDIR | fsi->mount_opts.mode, 0);
	sb->s_root = d_make_root(inode);
	if (!sb->s_root)
		return -ENOMEM;

	return 0;
}

struct dentry *myfs_mount(struct file_system_type *fs_type,
	int flags, const char *dev_name, void *data)
{
    printk(KERN_INFO "myfs_mount dev_name:%s data:%s\n", dev_name, (const char*)data);
	return mount_nodev(fs_type, flags, data, myfs_fill_super);
}

static void myfs_kill_sb(struct super_block *sb)
{
    printk(KERN_INFO "myfs_kill_sb\n");
	kfree(sb->s_fs_info);
	kill_litter_super(sb);
}

static struct file_system_type myfs_fs_type = {
    .name		= "myfs",
    .owner   = THIS_MODULE,
	.mount		= myfs_mount,
	.kill_sb	= myfs_kill_sb,
	.fs_flags	= FS_USERNS_MOUNT,
};

extern int  tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size);

int  my_tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
{
    printk(KERN_INFO "my_tcp sendmsg size:%lu\n", size); 
    //TODO 统计流量
    return tcp_sendmsg(sk, msg,size);
}

static void change_tcp_prot_sendmsg(void)
{                                                                  
    tcp_prot_addr = (struct proto*)kallsyms_lookup_name("tcp_prot"); 
    if (tcp_prot_addr == 0)                                         
    {
        printk(KERN_INFO "can not get tcp_prot_addr\n");                 
        return ;
    }
    printk(KERN_INFO "get tcp_prot_addr %p\n", tcp_prot_addr);

    tcp_prot_addr->sendmsg= my_tcp_sendmsg;

    printk(KERN_INFO "set ramfs_ops.read ok\n");
}                                                                  

static void resume_tcp_prot_sendmsg(void)
{
    tcp_prot_addr->sendmsg= tcp_sendmsg;
    printk(KERN_INFO "resume ramfs_ops.read ok\n");
}

static int __init init_myfs_fs(void)
{
	static unsigned long once;

	if (test_and_set_bit(0, &once))
		return 0;
    printk(KERN_INFO "init_myfs_fs\n");

    change_tcp_prot_sendmsg();
	return register_filesystem(&myfs_fs_type);
}

static void __exit exit_myfs_fs(void)
{
    printk(KERN_INFO "exit_myfs_fs\n");
    resume_tcp_prot_sendmsg();
    unregister_filesystem(&myfs_fs_type);
}

module_init(init_myfs_fs);
module_exit(exit_myfs_fs);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Valentine Sinitsyn <valentine.sinitsyn@gmail.com>");
MODULE_DESCRIPTION("In-kernel phrase reverser");

