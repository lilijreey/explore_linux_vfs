/*
 * @file: A kernel module that statistics process base tcp read/send bytes.
 *
 */

#include <linux/init.h>
#include <linux/cpumask.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/export.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/pagemap.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/time.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/topology.h>
#include <linux/parser.h>
#include <linux/magic.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <net/sock.h>
#include <linux/kallsyms.h>

#define MODULE_NAME "tcp_flowstat"

extern int tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size);
extern int tcp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int nonblock, int flags, int *addr_len);


/*static int (*origin_tcp_sendmsg)(struct sock *sk, struct msghdr *msg, size_t size);                                       */
/*static int (*origin_tcp_recvmsg)(struct sock *sk, struct msghdr *msg, size_t len, int nonblock, int flags, int *addr_len);*/

static struct proto *tcp_prot_ptr;

static int nr_max_process;
/*static int is_changed_tcp_prot_fn;*/

//TODO 优化
struct task_flowstat {
    pid_t pid;
    size_t rx_bytes;
    size_t tx_bytes;
    struct task_struct *task;
};


#define PROCESS_TCP_FLOWSTAT "process_tcp_flowstat"

static struct task_flowstat *per_cpu_table[NR_CPUS];

inline static void clear_task_flowstat(struct task_flowstat *p)
{
    p->pid = 0;
    p->task = NULL;
}

static int my_tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
{
    struct task_flowstat *table;
    struct task_flowstat *stat;
    int ret = tcp_sendmsg(sk, msg,size);
    pid_t pid = task_tgid_nr(current);

    if (pid > 0 && ret > 0)
    {
        printk(KERN_INFO MODULE_NAME "pid:%d my_tcp rcvmsg size:%d\n", task_tgid_nr(current), ret); 

        //get_cpu() ??
        //TODO 统计流量
        table = per_cpu_table[smp_processor_id()];
        stat = &table[pid % nr_max_process];
        if (stat->pid == 0)
            stat->pid = pid;
        else if (stat->pid != pid) {
            //TODO static 冲突
            return ret;
        }

        stat->tx_bytes += ret;
    }

    return ret;
}


static int my_tcp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, 
                          int nonblock, int flags, int *addr_len)
{
    struct task_flowstat *table;
    struct task_flowstat *stat;

    int ret = tcp_recvmsg(sk, msg, len, nonblock, flags, addr_len);
    pid_t pid = task_tgid_nr(current);

    if (pid > 0 && ret > 0)
    {
        printk(KERN_INFO MODULE_NAME "pid:%d my_tcp_sendmsg ret:%d\n", task_tgid_nr(current), ret); 

        //get_cpu() ??
        //TODO 统计流量
        table = per_cpu_table[smp_processor_id()];
        stat = &table[pid % nr_max_process];

        if (stat->pid == 0)
            stat->pid = pid;
        else if (stat->pid != pid) {
            //TODO static 冲突
            return ret;
        }

        stat->rx_bytes += ret;
    }

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

static int process_tcp_flowstat_proc_show(struct seq_file *m, void *v)
{
    int p,c;
    pid_t pid=0;
    size_t rx_sum;
    size_t tx_sum;
    struct task_flowstat *stat;

    seq_printf(m, "pid\trx_bytes\ttx_bytes\n");

    for (p = 0; p < nr_max_process; ++p) {
        tx_sum = rx_sum = 0;
        for (c=0; c < num_online_cpus(); ++c) {
            stat = &per_cpu_table[c][p];
            pid = stat->pid;
            if (pid == 0)
                continue;
            rx_sum += stat->rx_bytes;
            tx_sum += stat->tx_bytes;
        }

        if (pid != 0)
        {
            seq_printf(m, "%d\t%lu\t%lu\n",pid, rx_sum, tx_sum);
            printk(KERN_INFO "pid:%d rx:%lu tx:%lu\n", pid, rx_sum, tx_sum);
        }
    }


    return 0;
}


static int process_tcp_flowstat_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, process_tcp_flowstat_proc_show, NULL);
}

static const struct file_operations process_proc_fops = {
	.open		= process_tcp_flowstat_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int alloc_table(int nr_max_process)
{
    int i;
    size_t table_size =  PAGE_ALIGN(nr_max_process * sizeof(struct task_flowstat));
    printk(KERN_INFO "nr_cpu_ids:%u nr_cpu_online:%u page_size:%lu",
           nr_cpu_ids, num_online_cpus(), PAGE_SIZE);
    //1. get oneline cpus
    //2. 计算每个core的hash-tables内存使用大小
    printk(KERN_INFO "cpu_id:%u, nr_max_process:%d per table size:%lu",
           smp_processor_id(),
           nr_max_process,
           table_size);

    //numa_node_id() ,cpu_to_node()
    //get_cpu() put_cpu() disable preempation

    //3. alloc hash table on per-cpu
    for (i=0; i < num_possible_cpus(); ++i) {                                                 
        printk(KERN_INFO "cpu:%d numa id :%u\n", i, cpu_to_node(i));
        per_cpu_table[i] = kzalloc_node(table_size, GFP_KERNEL, cpu_to_node(i));
        if (per_cpu_table[i] == NULL) {
            printk(KERN_INFO "cpu:%d alloc table failed\n", i);
            //TODO free return -ENOMEM
        }                                                                                  
    }

    return 0;
}


static void free_table(void)
{
    int i;
    printk(KERN_INFO "free_data()\n");
    for (i=0; i < num_possible_cpus(); ++i) {                                                 
        kfree(per_cpu_table[i]);
        per_cpu_table[i] = NULL;
    }
}

static int __init init_tcp_flowstat(void)
{
	static unsigned long once;

	if (test_and_set_bit(0, &once)) {
        printk(KERN_INFO MODULE_NAME " is alreay installed, ignore this insert\n");
		return 0;
    }

    //TODO get max_process
    //TODO 127 是否忽略
    //统计的起始pid 
    //
    //TODO max_process_number 模块参数
    //
//素数1009/
//4999
//5003
//10009
//20011
    nr_max_process = 10009;
    alloc_table(nr_max_process);

    change_tcp_prot_sendmsg();

    if (NULL == proc_create(PROCESS_TCP_FLOWSTAT, 0444, NULL, &process_proc_fops)) {
        printk(KERN_INFO "create /proc/" PROCESS_TCP_FLOWSTAT " failed, exit\n");
        resume_tcp_prot_fn();
        return -ENOMEM;
    }

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

    printk("exit_tcp_flowstat\n");
    remove_proc_entry(PROCESS_TCP_FLOWSTAT, NULL);

    //do_fork/do_exit hook
    resume_tcp_prot_fn();
    //TODO sleep 
    free_table();
    printk(KERN_INFO "exit_tcp_flowstat\n");
}

module_init(init_tcp_flowstat);
module_exit(exit_tcp_flowstat);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("akozhao@tencet.com");
MODULE_DESCRIPTION("process base tcp receve/send triffic statistics");

