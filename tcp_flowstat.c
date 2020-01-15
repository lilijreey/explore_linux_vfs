/*
 * @file: A kernel module that statistics process base tcp read/send bytes.
 *
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/export.h>
#include <linux/seq_file.h>
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
/*#include <net/sock.h>*/
#include <linux/kallsyms.h>

#define MODULE_NAME "tcp_flowstat"

extern int tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size);
extern int tcp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int nonblock, int flags, int *addr_len);


/*static int (*origin_tcp_sendmsg)(struct sock *sk, struct msghdr *msg, size_t size);                                       */
/*static int (*origin_tcp_recvmsg)(struct sock *sk, struct msghdr *msg, size_t len, int nonblock, int flags, int *addr_len);*/

static struct proto *tcp_prot_ptr;
/*static int is_changed_tcp_prot_fn;*/


static int  my_tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
{
    printk(KERN_INFO MODULE_NAME "pid:%d my_tcp rcvmsg size:%lu\n", task_tgid_nr(current), size; 
    //TODO 统计流量
    return tcp_sendmsg(sk, msg,size);
}


static int my_tcp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, 
                          int nonblock, int flags, int *addr_len)
{
    int ret = tcp_recvmsg(sk, msg, len, nonblock, flags, addr_len);
    printk(KERN_INFO MODULE_NAME "pid:%d my_tcp_sendmsg ret:%d\n", task_tgid_nr(current), ret); 

    return ret;
}

static void change_tcp_prot_sendmsg(void)
{                                                                  
    tcp_prot_ptr = (struct proto*)kallsyms_lookup_name("tcp_prot"); 
    if (tcp_prot_ptr == NULL) {
        printk(KERN_INFO MODULE_NAME " can not get tcp_prot\n");                 
        return ;
    }

    printk(KERN_INFO MODULE_NAME " get tcp_prot_addr %p\n", tcp_prot_ptr);
    //consist no one change the tcp_prot function, excpet this moudle.

    if (tcp_prot_ptr->sendmsg != tcp_sendmsg  ||
        tcp_prot_ptr->recvmsg != tcp_recvmsg) {
        printk(KERN_INFO MODULE_NAME " tcp_sendmsg changed not set\n");
        return ;
    }

    tcp_prot_ptr->sendmsg = my_tcp_sendmsg;
    tcp_prot_ptr->recvmsg = my_tcp_recvmsg;

    printk(KERN_INFO "set ramfs_ops.read ok\n");
}                                                                  


static void resume_tcp_prot_fn(void)
{
    if (tcp_prot_ptr->sendmsg == my_tcp_sendmsg &&
        tcp_prot_ptr->recvmsg == my_tcp_recvmsg) {

        tcp_prot_ptr->sendmsg = tcp_sendmsg;
        tcp_prot_ptr->recvmsg = tcp_recvmsg;
        printk(KERN_INFO MODULE_NAME " resume tcp_prot cb read ok\n");
    }

    //TODO 是否还有正在调用中的进程？ sleep 一下在退出?
}

static int __init init_tcp_flowstat(void)
{
	static unsigned long once;

	if (test_and_set_bit(0, &once)) {
        printk(KERN_INFO MODULE_NAME " is alreay installed, ignore this insert\n");
		return 0;
    }

    change_tcp_prot_sendmsg();

    proc_create("tcp_flowstat", 0444, NULL, );
    /*register_proc_entry();*/


    printk(KERN_INFO MODULE_NAME " init ok\n");
	return 0;
}

static void __exit exit_tcp_flowstat(void)
{
	static unsigned long exiting;

	if (test_and_set_bit(0, &exiting)) {
        printk(KERN_INFO MODULE_NAME " an other process is removing this moudle.\n");
		return;
    }

    resume_tcp_prot_fn();
    printk(KERN_INFO "exit_tcp_flowstat\n");
}

module_init(init_tcp_flowstat);
module_exit(exit_tcp_flowstat);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("akozhao@tencet.com");
MODULE_DESCRIPTION("process base tcp receve/send triffic statistics");

