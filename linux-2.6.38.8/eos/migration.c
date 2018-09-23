#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <asm/signal.h>
#include <linux/cred.h>
#include <linux/user_namespace.h>
#include <linux/security.h>
#include <linux/iocontext.h>
#include <linux/spinlock.h>
#include <linux/spinlock_types.h>
#include <linux/delayacct.h>
#include <eos/checkpoint_util.h>
#include <eos/krgsyms.h>
#include <linux/ioprio.h>
#include <linux/fdtable.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/ksocket.h>
#include <linux/in.h>
#include <net/sock.h>
#include <linux/in.h>
#include <asm/signal.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/nsproxy.h>
#include <linux/spinlock.h>
#include <linux/pid_namespace.h>
#include <linux/hash.h>
#include <asm/ptrace.h>
#include <linux/mm_types.h>
#include <linux/highmem.h>
#include <eos/eos_signal.h>
#include <eos/pf_history.h>

#include "migration.h"
#include "cr_types.h"
#include "fs_util.h"
#include "signal.h"

int where_to_stop;
EXPORT_SYMBOL(where_to_stop);

#define BITS_PER_PAGE (8*PAGE_SIZE)
#define BITS_PER_PAGE_MASK (BITS_PER_PAGE-1)
#define cr_pidmap(nr)		&(init_pid_ns.pidmap[(nr) / BITS_PER_PAGE])
#define cr_pidmap_free(_p)	kfree(_p)
#define cr_pidmap_alloc()	kzalloc(PAGE_SIZE, GFP_KERNEL)

#define pid_hashfn(nr,ns) hash_long((unsigned long)nr + (unsigned long)ns, pidhash_shift)

void post_export_process(struct task_struct *tsk)
{
	tsk->is_immigrant = (tsk->is_immigrant ? tsk->is_immigrant : 1);
}

void on_export_failed(void){
}

int post_export_task(struct checkpoint_dest_t *dest, struct task_struct *tsk, struct pt_regs *task_regs)
{
	//reset_history_buffer(pfhistory);
	return 0;
}

int export_pid(struct checkpoint_dest_t *dest, struct pid_link *link)
{
	struct pid *pid = link->pid;
	int nr = pid_nr(pid);

	return dest->write((char*) &nr, sizeof(nr));
}

static int export_pids(struct checkpoint_dest_t *dest, struct task_struct *task)
{
	enum pid_type type, max_type;
	struct pid_link *link;
	int retval = 0;
	
	max_type = PIDTYPE_MAX;
	type = PIDTYPE_PID;

	for (; type < max_type; type++) {
		if (type == PIDTYPE_PID)
			link = &task->pids[type];
		else
			link = &task->group_leader->pids[type];

		retval = export_pid(dest, link);
		if (retval)
			goto out;
	}

out:
	return retval;
}

static int
alloc_pid_nr(int nr) /* MUST call with no locks held */ {
	struct pidmap *map;
	int offset = (nr & BITS_PER_PAGE_MASK);
	int result = 0; 

	if ((nr <= 0) || (nr >= PID_MAX_LIMIT)) {
		printk("Invalid pid %d", nr);
		return 0;
	}

	map = cr_pidmap(nr);
	if (unlikely(map->page == NULL)) {
		void *page = cr_pidmap_alloc();

		spin_lock_irq(&pidmap_lock);
		if (map->page) {
			/* lost a race, free our page */
			cr_pidmap_free(page);
		} else {
			map->page = page;
		}
		spin_unlock_irq(&pidmap_lock);
	}
	/* XXX assert (map->page != NULL) */

	if (!test_and_set_bit(offset, map->page)) {
		struct pid *pid;
		rcu_read_lock();
		pid = find_pid_ns(nr, &init_pid_ns);
		rcu_read_unlock();
		if (!pid) {

			// XXX: Need multi-level support
			enum pid_type type;
			struct upid *upid;
			pid = kmem_cache_alloc(init_pid_ns.pid_cachep, GFP_KERNEL);

			if (!pid) {
				clear_bit(offset, map->page);
				goto out;
			}
			pid->numbers[0].nr = nr;
			pid->numbers[0].ns = &init_pid_ns;
			pid->level = init_pid_ns.level;
			atomic_set(&pid->count, 1);
			for (type = 0; type < PIDTYPE_MAX; ++type) {
				INIT_HLIST_HEAD(&pid->tasks[type]);
			}

			spin_lock_irq(&pidmap_lock);
			upid = &pid->numbers[0];
			hlist_add_head_rcu(&upid->pid_chain, &pid_hash[pid_hashfn(upid->nr, upid->ns)]);
			spin_unlock_irq(&pidmap_lock);
		}
		atomic_dec(&map->nr_free);
		result = 1;
	}

out:
	return result;
}


struct pid *__get_pid(int nr)
{
	struct pid *pid;

	rcu_read_lock();
	pid = find_pid_ns(nr, &init_pid_ns);
	if(!pid)
	{
		alloc_pid_nr(nr);
		pid = find_pid_ns(nr, &init_pid_ns);
	}
	rcu_read_unlock();
	return pid;
}

int import_pid(struct restart_src_t *src, struct pid_link *link,
	       enum pid_type type)
{
	struct pid *pid;
	int nr;
	int retval;

	retval = src->read(&nr, sizeof(nr));
	if (retval)
		return retval;

	pid = __get_pid(nr);
	if (!pid)
		return -ENOMEM;
	INIT_HLIST_NODE(&link->node);
	link->pid = pid;

	return 0;
}

static int import_pids(struct restart_src_t *src, struct task_struct *task)
{
	enum pid_type type, max_type;
	bool leader;
	int retval = 0;

	/*
	we are supporting single-threaded processes for now. 
	Means migrated thread will be a leader. 
	This also means we will import ALL pid types.
	*/
	leader = 1; 

	if (!leader)
		max_type = PIDTYPE_PID + 1;
	else
		max_type = PIDTYPE_MAX;

	type = PIDTYPE_PID;

	for (; type < max_type; type++) {
/*		task->pids[type] = baby_sitter->pids[type];
*/

		retval = import_pid(src, &task->pids[type], type);
		if (retval) {
			//__unimport_pids(task, type);
			break;
		}

	}

	task->pid = baby_sitter->pid; //pid_nr(task_pid(task));
	/*
	 * Marker for import_group_leader(), and unimport_pids() whenever
	 * import_group_leader() fails.
	 */
	task->tgid = baby_sitter->tgid;//leader ? task->pid : 0;

	return retval;
}

static int export_group_leader(struct checkpoint_dest_t *dest, struct task_struct *task)
{
	return dest->write((char*) &(task->tgid), sizeof(task->tgid));
}

static int import_group_leader(struct restart_src_t *src, struct task_struct *task)
{
	//struct task_struct *leader = task;
	pid_t tgid;
	int err = 0;

	err = src->read(&tgid, sizeof(tgid));

	task->tgid = tgid;

	return err;
}

static int export_sched_info(struct checkpoint_dest_t *dest, struct task_struct *tsk)
{
	/* Nothing to do... */
	return 0;
}

static int import_sched_info(struct restart_src_t *src, struct task_struct *task)
{
#if defined(CONFIG_SCHEDSTATS) || defined(CONFIG_TASK_DELAY_ACCT)
	task->sched_info.pcount = 0;
#endif
	return 0;
}

/*
static int export_binfmt(struct checkpoint_dest_t *dest, struct task_struct *task)
{
	int binfmt_id;

	binfmt_id = krgsyms_export(task->binfmt);
	if (binfmt_id == KRGSYMS_UNDEF)
		return -EPERM;

	return dest->write((char*) &binfmt_id, sizeof(int));
}
*/

static int export_vfork_done(struct checkpoint_dest_t *dest, struct task_struct *task)
{
	/* TODO: not supported for now */
	return 0;
}

int import_vfork_done(struct restart_src_t *src, struct task_struct *task)
{
	/* TODO: not supported for now */
	return 0;
}

int export_cred(struct checkpoint_dest_t *dest, struct task_struct *task)
{
	const struct cred *cred = __task_cred(task);
	const struct group_info *groups = cred->group_info;
	int i, err = 0;

	goto out; // we will use the creds from the baby_sitter.

	err = dest->write((char*) cred, sizeof(*cred));
	if (err)
		goto out;

	err = dest->write((char*) &groups->ngroups, sizeof(groups->ngroups));
	if (err)
		goto out;
	if (groups->ngroups <= NGROUPS_SMALL) {
		err = dest->write((char*)
				  &groups->small_block,
				  sizeof(groups->small_block));
		goto out;
	}
	for (i = 0; i < groups->nblocks; i++) {
		err = dest->write((char*)
				  groups->blocks[i],
				  sizeof(*groups->blocks[i] * NGROUPS_PER_BLOCK));
		if (err)
			goto out;
	}

out:
	return err;
}


static int export_children(struct checkpoint_dest_t *dest, struct task_struct *task)
{
	/* Managed by children kddm object */

	/* TODO: [eababneh] find out what is meant by "Managed by children kddm object" */

	return 0;
}

static int import_children(struct restart_src_t *src, struct task_struct *task)
{
	/* Managed by children kddm object */

	/* TODO: [eababneh] find out what is meant by "Managed by children kddm object" */

	return 0;
}

static int export_sighand_struct(struct checkpoint_dest_t *dest, struct task_struct *tsk)
{
	int r = 0;

	r = dest->write((char *) tsk->sighand->action, sizeof(tsk->sighand->action));

	return r;
}

static int export_delays(struct checkpoint_dest_t *dest, struct task_struct *task)
{
	int err = 0;

#ifdef CONFIG_TASK_DELAY_ACCT
	if (task->delays)
		err = dest->write((char *) task->delays, sizeof(*task->delays));
#endif

	return err;
}

int export_exec_ids(struct checkpoint_dest_t *dest, struct task_struct *task)
{
	return 0;
}

static int export_io_context(struct checkpoint_dest_t *dest, struct task_struct *task)
{
#ifdef CONFIG_BLOCK
	struct io_context *ioc = task->io_context;

	if (!ioc)
		return 0;

	return dest->write((char *) &ioc->ioprio, sizeof(ioc->ioprio));
#else
	return 0;
#endif
}

int export_task(struct checkpoint_dest_t *dest, struct task_struct *task, struct pt_regs *task_regs)
{
	int err = 0;
	int task_pid = task->pid;
	int magic_num = 0;
	int flags = dest->flags;

	printk("Exporting task...\n");

	if(push_pending_frames)
		push_pending_frames();

	err = dest->write((char *) &flags, sizeof(flags));
	if(err)
		goto out_err;

	err = dest->write((char *) &task_pid, sizeof(task_pid));
	if(err)
		goto out_err;

	prepare_to_export(task);

	{
		err = dest->write((char *) task, sizeof(*task));
		if(err)
			goto out_err;
	}

	err = dest->write((char *) task_regs, sizeof(*task_regs));
	if(err)
		goto out_err;

	err = export_thread_info(dest, task);
	if(err)
		goto out_err;


/* TODO:
	r = export_nsproxy(action, ghost, task); 
	if (r)
		GOTO_ERROR;
*/

	if(flags != EOS_SIG_JUMP_MIGRATE)
	{
		err = export_pids(dest, task);
		if(err)
			goto out_err;
	}
	magic_num = 1111;
	err = dest->write((char *) &magic_num, sizeof(magic_num));
	if(err)
		goto out_err;

	if(flags != EOS_SIG_JUMP_MIGRATE)
	{

		err = export_group_leader(dest, task);
		if(err)
			goto out_err;

		err = export_sched_info(dest, task);	
		if(err)
			goto out_err;
	
	}

	err = cr_export_mm_struct(dest, task);
	if(err)
		goto out_err;
	

	if(flags != EOS_SIG_JUMP_MIGRATE)
	{
		err = export_vfork_done(dest, task);
		if(err)
			goto out_err;

		magic_num = 2222;
		err = dest->write((char *) &magic_num, sizeof(magic_num));
		if(err)
			goto out_err;

		err = export_cred(dest, task);
		if(err)
			goto out_err;
	}

	err = export_audit_context(dest, task);
	if(err)
		goto out_err;

	magic_num = 4444;
	err = dest->write((char *) &magic_num, sizeof(magic_num));
	if(err)
		goto out_err;

	err = export_thread_struct(dest, task);

	if(flags != EOS_SIG_JUMP_MIGRATE)
	{

		magic_num = 3333;
		err = dest->write((char *) &magic_num, sizeof(magic_num));
		if(err)
			goto out_err;

		err = export_cgroups(dest, task);
		if(err)
			goto out_err;


		magic_num = 5555;
		err = dest->write((char *) &magic_num, sizeof(magic_num));
		if(err)
			goto out_err;

		err = export_children(dest, task); // not finished.
		if(err)
			goto out_err;

		err = export_private_signals(dest, task);
		if(err)
			goto out_err;

		err = export_signal_struct(dest, task);
		if(err)
			goto out_err;

		magic_num = 6666;
		err = dest->write((char *) &magic_num, sizeof(magic_num));
		if(err)
			goto out_err;

		err = export_sighand_struct(dest, task);
		if(err)
			goto out_err;

		err = export_sched(dest, task);
		if(err)
			goto out_err;
	}

	err = export_delays(dest, task);
	if(err)
		goto out_err;

	magic_num = 7777;
	err = dest->write((char *) &magic_num, sizeof(magic_num));
	if(err)
		goto out_err;

	if(flags != EOS_SIG_JUMP_MIGRATE)
	{
		//err = export_exec_ids(dest, task);
		err = export_io_context(dest, task);
		if(err)
			goto out_err;
	}


	{
		int remote_pid = 0;
		if((flags != EOS_SIG_JUMP_MIGRATE) && dest->read){
			dest->read((char *) &remote_pid, sizeof(remote_pid));
			if(0) //(remote_pid == task->pid)
				printk("Task %d migrated successfully!\n", task->pid);
		}
		
	}
	return 0;

out_err:
	return -1;
}

int export_process(struct checkpoint_dest_t *dest, struct task_struct *tsk, struct pt_regs *task_regs)
{
	int r;
	ktime_t start,end;
	s64 actual_time;
	start=ktime_get();
	r = export_task(dest, tsk, task_regs);
	end=ktime_get();
	actual_time=ktime_to_ns(ktime_sub(end,start));
	if(0)
	printk("Time taken for export_task :%lld\n",(long long)actual_time);
	if (r)
		return r;

	post_export_task(dest, tsk, task_regs);

	return  0;
}

pid_t send_task(struct checkpoint_dest_t *dest, struct task_struct *tsk, struct pt_regs *task_regs)
{
	pid_t pid_remote_task = -1;
	int err;

	err = export_process(dest, tsk, task_regs);
	if(err){
		on_export_failed();
	}
	post_export_process(tsk);

//out:
	return err ? err : pid_remote_task;
}

//struct task_struct *baby_sitter;

int import_cred(struct restart_src_t *src, struct task_struct *task)
{
	//struct cred tmp_cred;
	//struct cred *cred;
	//struct user_struct *user;
	//struct group_info *groups;
	//int ngroups, i, err;
	unsigned long clone_flags = 0;

	task->cred = baby_sitter->cred;
	return copy_creds_task(baby_sitter, task, clone_flags);
/*

	err = ghost_read(ghost, &tmp_cred, sizeof(tmp_cred));
	if (err)
		goto out;

	cred = prepare_creds();

	cred->uid = tmp_cred.uid;
	cred->gid = tmp_cred.gid;
	cred->suid = tmp_cred.suid;
	cred->sgid = tmp_cred.sgid;
	cred->euid = tmp_cred.euid;
	cred->egid = tmp_cred.egid;
	cred->fsuid = tmp_cred.fsuid;
	cred->fsgid = tmp_cred.fsgid;
	cred->securebits = tmp_cred.securebits;
	cred->cap_inheritable = tmp_cred.cap_inheritable;
	cred->cap_permitted = tmp_cred.cap_permitted;
	cred->cap_effective = tmp_cred.cap_effective;
	cred->cap_bset = tmp_cred.cap_bset;

#ifdef CONFIG_KEYS
	BUG();
	key_put(cred->thread_keyring);
	cred->thread_keyring = NULL;
	key_put(cred->request_key_auth);
	cred->request_key_auth = NULL;
	release_tgcred(cred->tgcred);
	cred->tgcred = NULL;
#endif

#ifdef CONFIG_SECURITY
	BUG_ON(tmp_cred.security);
	security_cred_free(cred);
	cred->security = NULL;
#endif

	user = alloc_uid(task->nsproxy->krg_ns->root_user_ns, cred->uid);
	if (!user) {
		err = -ENOMEM;
		goto out_err;
	}
	free_uid(cred->user);
	cred->user = user;

	err = ghost_read(ghost, &ngroups, sizeof(ngroups));
	if (err)
		goto out_err;
	groups = groups_alloc(ngroups);
	if (!groups) {
		err = -ENOMEM;
		goto out_err;
	}
	if (ngroups <= NGROUPS_SMALL) {
		err = ghost_read(ghost,
				 &groups->small_block,
				 sizeof(groups->small_block));
		if (err)
			goto err_groups;
		else
			goto groups_ok;
	}
	for (i = 0; i < groups->nblocks; i++) {
		err = ghost_read(ghost,
				 groups->blocks[i],
				 sizeof(*groups->blocks[i] * NGROUPS_PER_BLOCK));
		if (err)
			goto err_groups;
	}
groups_ok:
	put_group_info(cred->group_info);
	cred->group_info = groups;

	rcu_assign_pointer(task->real_cred, cred);
	get_cred(cred);
	rcu_assign_pointer(task->cred, cred);
	err = 0;

out:
	return err;

err_groups:
	groups_free(groups);
out_err:
	put_cred(cred);
	goto out;
*/
}

static int import_delays(struct restart_src_t *src, struct task_struct *task)
{
	int err = 0;
#ifdef CONFIG_TASK_DELAY_ACCT
	//struct task_delay_info *delays;

	if(src->flags != EOS_SIG_JUMP_MIGRATE){
		task->delays = kmem_cache_alloc(delayacct_cache, GFP_KERNEL);
		if (!(task->delays)) {
			err = -ENOMEM;
			goto out;
		}
	}


	err = src->read(task->delays, sizeof(*(task->delays)));
	if (err && src->flags != EOS_SIG_JUMP_MIGRATE) {
		kmem_cache_free(delayacct_cache, task->delays);
		goto out;
	}

	if(src->flags != EOS_SIG_JUMP_MIGRATE){
		spin_lock_init(&(task->delays->lock));
	}

out:
#endif

	return err;
}


static int import_io_context(struct restart_src_t *src, struct task_struct *task)
{
#ifdef CONFIG_BLOCK
	struct io_context *ioc;
	unsigned short ioprio;
	int err;

	if (!task->io_context)
		return 0;

	err = src->read(&ioprio, sizeof(ioprio));
	if (err)
		return err;

	if (!ioprio_valid(ioprio)) {
		task->io_context = NULL;
		return 0;
	}

	ioc = alloc_io_context(GFP_KERNEL, -1);
	if (!ioc)
		return -ENOMEM;
	ioc->ioprio = ioprio;

	task->io_context = ioc;
#endif

	return 0;
}
static ksocket_t sockfd_cli = NULL;

int connect_to_server(char * remote_ip, int remote_port) {
    struct sockaddr_in addr_srv;
    int addr_len;

    printk("EOS(setup): Trying to connect to <%s:%d>\n", remote_ip, remote_port);

    memset(&addr_srv, 0, sizeof (addr_srv));
    addr_srv.sin_family = AF_INET;
    addr_srv.sin_port = htons(remote_port);
    addr_srv.sin_addr.s_addr = inet_addr(remote_ip);
    addr_len = sizeof (struct sockaddr_in);

    sockfd_cli = ksocket(AF_INET, SOCK_STREAM, 0);
    if (sockfd_cli == NULL) {
        printk("EOS(setup): socket failed\n");
    }

    return kconnect(sockfd_cli, (struct sockaddr*) &addr_srv, addr_len);
}

int sock_write(void *buff, int size) {
    int sent_so_far = 0;
    int n = 0;

    //printk("We are actually writing something of size: %d\n", size);
    while (sent_so_far != size) {
        n = ksend(sockfd_cli, buff + sent_so_far, size - sent_so_far, 0);
        if (n < 0) {
            printk("Writing to socket failed n = %d\n", n);
            return -1;
        }
        sent_so_far += n;
    }

    return 0;
}

int connect_socket() {
	struct checkpoint_dest_t *sock_dest;
	if (!remote_machine_ip) {
		printk("EOS(setup): Unknown remote machine or remote IP!!!\n");
		return -1;
	}

	if(!remote_machine_ip)
	{	
		printk("EOS: Uknown remote machine ip\n");
		return -2;
	}

	if (connect_to_server(remote_machine_ip, 9999)) { // TODO: the port to made configurable.
		printk("Could not connect to server [%s:%d]\n", remote_machine_ip, 9999);
		return -1;
	}

	sock_dest = (struct checkpoint_dest_t *) kmalloc(sizeof (struct checkpoint_dest_t), GFP_KERNEL);
	sock_dest->write = sock_write;
	chkpt_writer = sock_dest;

    return 0;
}

int eos_task_migrate(int sig, struct siginfo *info, struct pt_regs *regs)
{
	pid_t remote_pid;
	struct task_struct *tsk = current;

	// prepare for process shipment
	// 	1. open file, network ... etc.
	// 	2. lock some structures to prevent them from being freed while process is being checkpointed
	

	BUG_ON(tsk == NULL);
	BUG_ON(regs == NULL);

	if(!chkpt_writer){
		int ret = connect_socket();
		if(ret)
		{
			printk("EOS: Check point destination is not set...can not proceed!\n");
			return -3;
		}
	}
	
	chkpt_writer->flags = sig;

	remote_pid = send_task(chkpt_writer,tsk, regs);

	// check if process was sent succesfully...and perform the appropriate clean up.
	return 0;

}

static struct task_struct *import_task(struct restart_src_t *src, struct task_struct *orig_task, struct pt_regs *l_regs)
{
	struct task_struct *task = NULL;
	struct task_struct *tmp_task = NULL;
	int retval = 0;
	int my_magic = 0;
	int expected_magic = 0;

	if(where_to_stop == 1)
	{
		printk("where_to_stop = 1\n");
		return ERR_PTR(retval);
	}

	if(src->flags != EOS_SIG_JUMP_MIGRATE)
	{
		if(log_eos_messages) printk("Stretching to this machine\n");
		task = alloc_task_struct();
		if (!task) {
			retval = -ENOMEM;
			printk("Null task pointer import_task()\n");
			goto err_alloc_task;
		}
		
		retval = src->read(task, sizeof(struct task_struct));
	}
	else
	{
		if(log_eos_messages) printk("Jumping to this machine\n");
		task = orig_task;
		tmp_task = alloc_task_struct();
		if (!task || !tmp_task) {
			retval = -ENOMEM;
			printk("Null task pointer import_task()\n");
			goto err_alloc_task;
		}
		retval = src->read(tmp_task, sizeof(struct task_struct));
		task->fs = tmp_task->fs;
		//task->gs = tmp_task->gs;

		free_task_struct(tmp_task);
	}

	{	
		int loc = 2;
		if(where_to_stop == loc)
		{
			printk("where_to_stop = %d\n", loc);
			return ERR_PTR(retval);
		}
	}

	retval = src->read(l_regs, sizeof(struct pt_regs));
	//if (retval)
	//	goto err_regs;


	if(src->flags != EOS_SIG_JUMP_MIGRATE){
		atomic_set(&task->usage, 2);
#ifdef CONFIG_PREEMPT_NOTIFIERS
		INIT_HLIST_HEAD(&task->preempt_notifiers);
#endif
		INIT_LIST_HEAD(&task->tasks);
		INIT_LIST_HEAD(&task->ptraced);
		INIT_LIST_HEAD(&task->ptrace_entry);
		task->real_parent = NULL;
		task->parent = NULL;
		INIT_LIST_HEAD(&task->children);
		INIT_LIST_HEAD(&task->sibling);
		rcu_copy_process(task);
		//INIT_LIST_HEAD(&task->rcu_node_entry);
		task->group_leader = NULL;
		INIT_LIST_HEAD(&task->ptraced);
		INIT_LIST_HEAD(&task->ptrace_entry);
#ifdef CONFIG_X86_PTRACE_BTS
		BUG_ON(task->bts);
		BUG_ON(task->bts_buffer);
#endif

		{	
			int loc =3;
			if(where_to_stop == loc)
			{
				printk("where_to_stop = %d\n", loc);
				return ERR_PTR(retval);
			}
		}
		INIT_LIST_HEAD(&task->thread_group);
		INIT_LIST_HEAD(&task->cpu_timers[0]);
		INIT_LIST_HEAD(&task->cpu_timers[1]);
		INIT_LIST_HEAD(&task->cpu_timers[2]);

		task->notifier_mask = NULL;
		spin_lock_init(&task->alloc_lock);
		raw_spin_lock_init(&task->pi_lock);

#ifdef CONFIG_GENERIC_HARDIRQS
		BUG_ON(task->irqaction);
#endif
		//spin_lock_init(&task->pi_lock);
#ifdef CONFIG_RT_MUTEXES
		plist_head_init_raw(&task->pi_waiters, &task->pi_lock);
		BUG_ON(task->pi_blocked_on);
#endif
		{	
			int loc = 4;
			if(where_to_stop == loc)
			{
				printk("where_to_stop = %d\n", loc);
				return ERR_PTR(retval);
			}
		}
#ifdef CONFIG_DEBUG_MUTEXES
		BUG_ON(task->blocked_on); /* not blocked yet */
#endif
		/* Almost copy paste from fork.c for lock debugging stuff, to avoid
		 * fooling this node with traces from the exporting node */
#ifdef CONFIG_TRACE_IRQFLAGS
		task->irq_events = 0;
		task->hardirqs_enabled = 1;
		task->hardirq_enable_ip = _THIS_IP_;
		task->hardirq_enable_event = 0;
		task->hardirq_disable_ip = 0;
		task->hardirq_disable_event = 0;
		task->softirqs_enabled = 1;
		task->softirq_enable_ip = _THIS_IP_;
		task->softirq_enable_event = 0;
		task->softirq_disable_ip = 0;
		task->softirq_disable_event = 0;
		task->hardirq_context = 0;
		task->softirq_context = 0;
#endif
		{	
			int loc = 5;
			if(where_to_stop == loc)
			{
				printk("where_to_stop = %d\n", loc);
				return ERR_PTR(retval);
			}
		}
#if defined(SPLIT_RSS_COUNTING)
		memset(&task->rss_stat, 0, sizeof(task->rss_stat));
#endif

#ifdef CONFIG_LOCKDEP
		task->lockdep_depth = 0; /* no locks held yet */
		task->curr_chain_key = 0;
		task->lockdep_recursion = 0;
#endif
		BUG_ON(task->bio_list);
		BUG_ON(task->reclaim_state);
		BUG_ON(task->backing_dev_info);
		BUG_ON(task->last_siginfo);
#ifdef CONFIG_FUTEX
		INIT_LIST_HEAD(&task->pi_state_list);
		task->pi_state_cache = NULL;
#endif
#ifdef CONFIG_NUMA
		BUG_ON(task->mempolicy);
#endif
		task->splice_pipe = NULL;
		BUG_ON(task->scm_work_list);
#ifdef CONFIG_FUNCTION_GRAPH_TRACER
		task->ret_stack = NULL;
#endif
	
		task->is_immigrant = 2;

		{	
			int loc = 6;
			if(where_to_stop == loc)
			{
				printk("where_to_stop = %d\n", loc);
				return ERR_PTR(retval);
			}
		}

	}

	retval = import_thread_info(src, task);
	if (retval)
		goto err_alloc_task;

	// import_nsproxy() not implemented. We will use the one from the baby_sitter.

	if(src->flags != EOS_SIG_JUMP_MIGRATE){
		retval = import_pids(src, task);
		if (retval)
			goto err_alloc_task;
	}

	{	
		int loc = 7;
		if(where_to_stop == loc)
		{
			printk("where_to_stop = %d\n", loc);
			return ERR_PTR(retval);
		}
	}

	expected_magic = 1111;
	src->read(&my_magic, sizeof(my_magic));
	if(my_magic != expected_magic)
		printk("Found magic %d and expected is: %d\n", my_magic, expected_magic);

	if(src->flags != EOS_SIG_JUMP_MIGRATE){

		retval = import_group_leader(src, task);
		if (retval)
			goto err_alloc_task;

		retval = import_sched_info(src, task);
		if (retval)
			goto err_alloc_task;
	}

	retval = import_mm_struct(src, task);
	if(retval)
		goto err_alloc_task;

	if(src->flags != EOS_SIG_JUMP_MIGRATE){

		retval = import_vfork_done(src, task);
		if (retval)
			goto err_alloc_task;

		expected_magic = 2222;
		src->read(&my_magic, sizeof(my_magic));
		if(my_magic != expected_magic)
			printk("Found magic %d and expected is: %d\n", my_magic, expected_magic);

		retval = import_cred(src, task); 
		if (retval)
			goto err_alloc_task;

	}

	{	
		int loc = 8;
		if(where_to_stop == loc)
		{
			printk("where_to_stop = %d\n", loc);
			return ERR_PTR(retval);
		}
	}

	retval = import_audit_context(src, task);
	if (retval)
		goto err_alloc_task;

	expected_magic = 4444;
	src->read(&my_magic, sizeof(my_magic));
	if(my_magic != expected_magic)
		printk("Found magic %d and expected is: %d\n", my_magic, expected_magic);


	retval = import_thread_struct(src, task);
	if (retval)
		goto err_alloc_task;

	{	
		int loc = 9;
		if(where_to_stop == loc)
		{
			printk("where_to_stop = %d\n", loc);
			return ERR_PTR(retval);
		}
	}

	if(src->flags != EOS_SIG_JUMP_MIGRATE){

		retval = import_fs_struct(src, task);
		if (retval)
			goto err_alloc_task;

		retval = import_files_struct(src, task);
		if (retval)
			goto err_alloc_task;

		expected_magic = 3333;
		src->read(&my_magic, sizeof(my_magic));
		if(my_magic != expected_magic)
			printk("Found magic %d and expected is: %d\n", my_magic, expected_magic);

		retval = import_cgroups(src, task);
		if (retval)
			goto err_alloc_task;

		expected_magic = 5555;
		src->read(&my_magic, sizeof(my_magic));
		if(my_magic != expected_magic)
			printk("Found magic %d and expected is: %d\n", my_magic, expected_magic);

		retval = import_children(src, task);
		if (retval)
			goto err_alloc_task;

		retval = import_private_signals(src, task);
		if (retval)
			goto err_alloc_task;

		retval = import_signal_struct(src, task);
		if (retval)
			goto err_alloc_task;

		expected_magic = 6666;
		src->read(&my_magic, sizeof(my_magic));
		if(my_magic != expected_magic)
			printk("Found magic %d and expected is: %d\n", my_magic, expected_magic);

		retval = import_sighand_struct(src, task);
		if (retval)
			goto err_alloc_task;

		task->signal->autogroup = autogroup_task_get(baby_sitter);

			retval = import_sched(src, task);
			if (retval)
				goto err_alloc_task;
	}

	retval = import_delays(src, task);
	if (retval)
		goto err_alloc_task;

	{	
		int loc = 10;
		if(where_to_stop == loc)
		{
			printk("where_to_stop = %d\n", loc);
			return ERR_PTR(retval);
		}
	}

	expected_magic = 7777;
	src->read(&my_magic, sizeof(my_magic));
	if(my_magic != expected_magic)
		printk("Found magic %d and expected is: %d\n", my_magic, expected_magic);

	if(src->flags != EOS_SIG_JUMP_MIGRATE){
		retval = import_io_context(src, task);
		if (retval)
			goto err_alloc_task;
	}

	return task;

err_alloc_task:
	return ERR_PTR(retval);
}

static
struct task_struct *flesh_task_skeleton (struct task_struct *tskRecv,
						  struct pt_regs *l_regs)
{
	struct pid *pid;
	struct task_struct *newTsk = NULL;
	unsigned long flags;
	unsigned long stack_start;
	unsigned long stack_size;
	int *parent_tidptr;
	int *child_tidptr;
	struct siginfo info;

	BUG_ON(!l_regs || !tskRecv);

	/*
	 * The active process must be considered as remote until all links
	 * with parent and children are restored atomically.
	 */
	tskRecv->parent = tskRecv->real_parent = baby_sitter;

	flags = (tskRecv->exit_signal & CSIGNAL) | CLONE_VM | CLONE_THREAD | CLONE_SIGHAND;
	stack_start = user_stack_pointer(l_regs);
	/*
	 * Will BUG as soon as used in copy_thread (e.g. ia64, but not i386 and
	 * x86_64)
	 */
	stack_size = 0;
	parent_tidptr = NULL;
	child_tidptr = NULL;

	pid = task_pid(tskRecv);
	BUG_ON(!pid);

	eos_current = tskRecv;
	newTsk = copy_process(flags, stack_start, l_regs, stack_size,
			      child_tidptr, pid, 0, 1, tskRecv);
	eos_current = NULL;

	if (IS_ERR(newTsk)) {
		printk("Failed to copy_process\n");
		return ERR_PTR(-EINVAL);
	}

	/* TODO: distributed threads */
	BUG_ON(newTsk->group_leader->pid != newTsk->tgid);

	newTsk->did_exec = tskRecv->did_exec;

	{
		/*
		 * signals should be copied from the ghost, as do_fork does not
		 * clone the signal queue
		 */
		if (!sigisemptyset(&tskRecv->pending.signal)
		    || !list_empty(&tskRecv->pending.list)) {
			unsigned long flags;

			if (!lock_task_sighand(newTsk, &flags))
				BUG();
			list_splice(&tskRecv->pending.list, &newTsk->pending.list);
			sigorsets(&newTsk->pending.signal, &newTsk->pending.signal, &tskRecv->pending.signal);
			unlock_task_sighand(newTsk, &flags);

			init_sigpending(&tskRecv->pending);
		}
		/*
		 * Always set TIF_SIGPENDING, since migration/checkpoint
		 * interrupted the task as an (ignored) signal. This way
		 * interrupted syscalls are transparently restarted.
		 */
		set_tsk_thread_flag(newTsk, TIF_SIGPENDING);
	}

	newTsk->files->next_fd = tskRecv->files->next_fd;

	/* Remember process times until now (cleared by do_fork) */
	newTsk->utime = tskRecv->utime;
	/* stime will be updated later to account for migration time */
	newTsk->stime = tskRecv->stime;
	newTsk->gtime = tskRecv->gtime;
	newTsk->utimescaled = tskRecv->utimescaled;
	newTsk->stimescaled = tskRecv->stimescaled;
	newTsk->prev_utime = tskRecv->prev_utime;
	newTsk->prev_stime = tskRecv->prev_stime;

	/* Restore flags changed by copy_process() */
	newTsk->flags = tskRecv->flags;

	newTsk->flags &= ~PF_STARTING;

	info.si_errno = 0;
	info.si_pid = 0;
	info.si_uid = 0;
	send_eos_sleep_signal(SIGSTOP, 0, &info, newTsk);

	wake_up_new_task(newTsk, CLONE_VM);
	return newTsk;
}

void send_sig_to_pid(int signo, pid_t pid) {
    struct siginfo sinfo;
    struct task_struct *task;

    int retInt = 0;

    sinfo.si_signo = signo;
    sinfo.si_code = SI_KERNEL;

    task = pid_task(find_vpid(pid), PIDTYPE_PID);

    if (task == NULL) {
        printk("Cannot find PID from user program\r\n");
    }

    retInt = send_sig_info(signo, &sinfo, task);

//    printk("Just sent %d to process ID: %d  and returned %d \n", signo, pid, retInt);
}

void send_wakeup_sig(struct task_struct *task){
    struct siginfo sinfo;

    sinfo.si_signo = SIGCONT;
    sinfo.si_code = SI_KERNEL;

    if (task == NULL) {
        printk("Cannot find PID from user program\r\n");
    }

   send_sig_info(SIGCONT, &sinfo, task);
}


struct task_struct *import_process(struct restart_src_t *src)
{
	struct task_struct *ghost_task;
	struct task_struct *task;
	struct task_struct *active_task;
	struct pt_regs regs;
	int remote_pid = -1;
	int flags = 0;
	int err;
	int is_immig = 0;


	if(!baby_sitter) {
		printk("Can not recieve a process without a baby sitter\n");
		return NULL;
	}
	
	err = src->read(&flags, sizeof(flags));
	if(err){
		printk("Failed to read process migration flags\n");
		return NULL;
	}

	src->flags = flags;

	/* Process importation */
	err = src->read(&remote_pid, sizeof(remote_pid));
	if(err){
		printk("Failed to read migrated process id\n");
		return NULL;
	}


	task = pid_task(find_vpid(remote_pid), PIDTYPE_PID);

	if(flags != EOS_SIG_JUMP_MIGRATE && task){
		printk("Another process was found with pid: %d. Import failed!\n", remote_pid); 
		return NULL;
	} else if(flags == EOS_SIG_JUMP_MIGRATE && !task)
	{
		printk("Could not find the task with pid %d to complete the jump!\n", remote_pid); 
		return NULL;
	}

	if(flags == EOS_SIG_JUMP_MIGRATE)
	{
		is_immig = task->is_immigrant;
	}

	ghost_task = import_task(src, task, &regs);
	if (IS_ERR(ghost_task)) {
		err = PTR_ERR(ghost_task);
		goto err_task;
	}
	BUG_ON(!ghost_task);

	if(!ghost_task)
		goto err_task;

	{	
		int loc = 11;
		if(where_to_stop == loc)
		{
			printk("where_to_stop = %d\n", loc);
			return ERR_PTR(err);
		}
	}

	//reset_history_buffer(pfhistory);
	pfhistory->end_time=ktime_get();
	
	if(flags != EOS_SIG_JUMP_MIGRATE)
	{		
		int local_pid = 0;
		active_task = flesh_task_skeleton(ghost_task, &regs);
		local_pid = active_task->pid;
		if(src->write)	
		{
			src->write((char *) &local_pid, sizeof(local_pid));
		}
	}
	else 
	{
		struct siginfo info;
		task_jump_fixup(user_stack_pointer(&regs), ghost_task, 
				&regs);
		ghost_task->is_immigrant = is_immig;
		send_wakeup_sig(ghost_task);
		if(log_eos_messages) printk("Done jumping to this machine.\n");
	}

	{	
		int loc = 12;
		if(where_to_stop == loc)
		{
			printk("where_to_stop = %d\n", loc);
			return ERR_PTR(err);
		}
	}

	if (active_task == NULL || IS_ERR(active_task)) {
		err = PTR_ERR(active_task);
		goto err_active_task;
	}
	BUG_ON(!active_task);

	//free_ghost_process(ghost_task);



	return active_task;

err_active_task:
	//unimport_task(action, ghost_task);
err_task:
	return ERR_PTR(err);
}
EXPORT_SYMBOL(import_process);

