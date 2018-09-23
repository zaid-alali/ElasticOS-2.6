#include <linux/linkage.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/rcupdate.h>
#include <linux/ksocket.h>
#include <linux/in.h>
#include <asm/signal.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <net/sock.h>
#include <asm/processor.h>
#include <asm/uaccess.h>
#include <linux/in.h>
#include <linux/kthread.h>
#include <linux/pagemap.h>
#include <linux/rmap.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/ksocket.h>
#include <eos/checkpoint_util.h>
#include <eos/eos_signal.h>

#include "eos_syscall.h"
#include "migration.h"

static inline int action_to_flag(eos_action_t action)
{
	if (unlikely(action <= EOS_NO_ACTION || action >= EOS_ACTION_MAX))
		return 0;
	else
		return 1 << action;
}

static void migration_aborted(struct task_struct *task)
{

}


int start_thread_migration(struct task_struct *t, int level)
{	
	struct siginfo info;
	int action_sig = 0;
	int retval;

	if(level == 0)
		action_sig = EOS_SIG_FULL_MIGRATE;
	else if (level == 1)
		action_sig = EOS_SIG_STRETCH_MIGRATE;
	else if (level == 2)
		action_sig = EOS_SIG_JUMP_MIGRATE;
	else
		return -1;

	info.si_errno = 0;
	info.si_pid = 0;
	info.si_uid = 0;

	retval = send_eos_signal(action_sig, &info, t);
	if (retval)
		migration_aborted(t);

	return retval;
}

int migrate_process_threads(struct task_struct *tsk, int level)
{
	struct task_struct *t;
	t = tsk;
	int r = 0;
	read_lock(&tasklist_lock);
	do {
		r = start_thread_migration(t, level);
		if (r)
			break;
	} while ((t = next_thread(t)) != tsk);
	read_unlock(&tasklist_lock);

	return 0;
}

long do_eos_migrate_process(int p_id, int level)
{
	struct task_struct *task;

	rcu_read_lock();
	task = find_task_by_vpid(p_id);

	if (!task) {
		rcu_read_unlock();
		printk("Task with id %d not found!\n", p_id);
		return -1;
	}

	if(0) printk("Migrating task with pid: %d\n", p_id);

	migrate_process_threads(task, level);

	rcu_read_unlock();

    	return 0;
}
EXPORT_SYMBOL(do_eos_migrate_process);

asmlinkage long sys_migrate_process(int p_id, int level)
{	
	return do_eos_migrate_process(p_id, level);
}


static ksocket_t __sockfd_srv;
static ksocket_t __sockfd_cli;

int sock_read(void *buff, int size)
{
    int read_so_far = 0;    
    int bytes_expected = size;
    int n = 0;
    
    while (read_so_far != bytes_expected) {
        n = krecv(__sockfd_cli, buff + read_so_far, bytes_expected - read_so_far, 0);
        if (n <= 0) {
            kclose(__sockfd_cli);
            return -1;
        }
        read_so_far += n;
    }

    return 0;
}

int handle_client(void *sockfd) {
	struct sockaddr_in addr_cli;
	struct restart_src_t *tmp_src;
	char *tmp;

	__sockfd_cli = (ksocket_t) sockfd;

	tmp = inet_ntoa(&addr_cli.sin_addr);

	kfree(tmp);

	tmp_src = (struct restart_src_t*) kmalloc(sizeof(struct restart_src_t), GFP_KERNEL);
	tmp_src->read = &sock_read;

	import_process(tmp_src);
	
	kfree(tmp_src);


	return 0;
}

int tcp_srv_same(void) {
	ksocket_t __sockfd_cli;
	struct sockaddr_in addr_srv;
	struct sockaddr_in addr_cli;
	int addr_len;
	struct sock *sk = NULL;
	int port = 9999;

	__sockfd_srv = __sockfd_cli = NULL;
	memset(&addr_cli, 0, sizeof (addr_cli));
	memset(&addr_srv, 0, sizeof (addr_srv));
	addr_srv.sin_family = AF_INET;
	addr_srv.sin_port = htons(port);
	addr_srv.sin_addr.s_addr = INADDR_ANY;
	addr_len = sizeof (struct sockaddr_in);

	__sockfd_srv = ksocket(AF_INET, SOCK_STREAM, 0);
	if (__sockfd_srv == NULL) {
		printk("EOS(PagesServer): socket failed\n");
		return -1;
	}

	sk = __sockfd_srv->sk;
	sk->__sk_common.skc_reuse = 1;

	if (kbind(__sockfd_srv, (struct sockaddr *) &addr_srv, addr_len) < 0) {
		printk("EOS(migrate_request): bind failed\n");
		return -1;
	}


	if (klisten(__sockfd_srv, 10) < 0) {
		printk("EOS(migrate_request): listen failed\n");
		return -1;
	}

	__sockfd_cli = kaccept(__sockfd_srv, (struct sockaddr *) &addr_cli, &addr_len);
	if (__sockfd_cli == NULL) {
		printk("EOS(migrate_request): accept failed\n");
		return -1;
	} else {
		kclose(__sockfd_srv);
		handle_client(__sockfd_cli);
	}
	
	return 0;
}



asmlinkage long sys_import_task(void)
{
	tcp_srv_same();
	return 0;
}

asmlinkage long sys_inject_page(int pid, unsigned long address, unsigned int length, const char *buff)
{
	if(sys_inject_page_p)
		sys_inject_page_p(pid, address, length, buff);

	return 0;
}

asmlinkage long sys_get_page(int pid, unsigned long address, unsigned int length, const char *buff)
{
	if(sys_get_page_p)
		sys_get_page_p(pid, address, length, buff);
	
	return 0;
}

asmlinkage long sys_sticky_process(int pid)
{
	sticky_mode = 1;
	return 0;
}

asmlinkage long sys_unsticky_process(int pid)
{
	sticky_mode = 0;
	sys_migrate_process(current->pid, 2);
	return 0;
}
