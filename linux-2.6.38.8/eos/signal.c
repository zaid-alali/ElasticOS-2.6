#include <linux/types.h>
#include <linux/sched.h>
#include <linux/signal.h>
#include <linux/hrtimer.h>
#include <linux/timer.h>
#include <linux/posix-timers.h>
#include <linux/slab.h>
#include <linux/taskstats.h>
#include <linux/taskstats_kern.h>
//#include <linux/taskstats.h>
//#include <linux/taskstats_kern.h>
#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>
#include <linux/pid.h>
#include <linux/user_namespace.h>
#include <linux/rwsem.h>

#include <eos/checkpoint_util.h>
#include "signal.h"

static int export_sigqueue(struct checkpoint_dest_t *dest,
			   struct task_struct *task,
			   struct sigqueue *sig)
{
	int err = -EBUSY;

	err = dest->write((char *) &sig->info, sizeof(sig->info));
	if (err)
		goto out;
	err = dest->write((char *) &sig->user->uid, sizeof(sig->user->uid));

out:
	return err;
}

static int export_sigpending(struct checkpoint_dest_t *dest,
			     struct task_struct *task,
			     struct sigpending *pending)
{
	struct sigpending tmp_queue;
	int nr_sig;
	struct sigqueue *q;
	unsigned long flags;
	int err;

	INIT_LIST_HEAD(&tmp_queue.list);
	nr_sig = 0;
	if (!lock_task_sighand(task, &flags))
		BUG();
	tmp_queue.signal = pending->signal;
	list_for_each_entry(q, &pending->list, list) {
		if (q->flags & SIGQUEUE_PREALLOC) {
			unlock_task_sighand(task, &flags);
			err = -EBUSY;
			goto out;
		}
		nr_sig++;
	}
	list_splice_init(&pending->list, &tmp_queue.list);
	unlock_task_sighand(task, &flags);

	err = dest->write((char *) &tmp_queue.signal, sizeof(tmp_queue.signal));
	if (err)
		goto out_splice;

	err = dest->write((char *) &nr_sig, sizeof(nr_sig));
	if (err)
		goto out_splice;

	list_for_each_entry(q, &tmp_queue.list, list) {
		err = export_sigqueue(dest, task, q);
		if (err)
			goto out_splice;
	}

out_splice:
	if (!lock_task_sighand(task, &flags))
		BUG();
	sigorsets(&pending->signal, &pending->signal, &tmp_queue.signal);
	list_splice(&tmp_queue.list, &pending->list);
	recalc_sigpending_tsk(task);
	unlock_task_sighand(task, &flags);

out:
	return err;
}

int export_private_signals(struct checkpoint_dest_t *dest, struct task_struct *task)
{
	return export_sigpending(dest, task, &task->pending);
}

static int import_sigqueue(struct restart_src_t *src,
			   struct task_struct *task,
			   struct sigqueue *sig)
{
	struct user_struct *user;
	uid_t uid;
	int err;

	err = src->read(&sig->info, sizeof(sig->info));
	if (err)
		goto out;

	err = src->read(&uid, sizeof(uid));
	if (err)
		goto out;
	user = alloc_uid(task->cred->user->user_ns, task->cred->uid);
	if (!user) {
		err = -ENOMEM;
		goto out;
	}
	atomic_inc(&user->sigpending);

	atomic_dec(&sig->user->sigpending);
	free_uid(sig->user);

	sig->user = user;

out:
	return err;
}

static int import_sigpending(struct restart_src_t *src, struct task_struct *task, struct sigpending *pending)
{
	int nr_sig;
	struct sigqueue *q;
	int i;
	int err;

	err = src->read(&pending->signal, sizeof(pending->signal));
	if (err)
		goto cleanup_queue;

	err = src->read(&nr_sig, sizeof(nr_sig));
	if (err)
		goto cleanup_queue;

	INIT_LIST_HEAD(&pending->list);
	for (i = 0; i < nr_sig; i++) {
		q = __sigqueue_alloc(-1, task, GFP_KERNEL, 0);
		if (!q) {
			err = -ENOMEM;
			goto free_queue;
		}
		err = import_sigqueue(src, task, q);
		if (err) {
			__sigqueue_free(q);
			goto free_queue;
		}
		list_add_tail(&q->list, &pending->list);
	}

out:
	return err;

cleanup_queue:
	init_sigpending(pending);
	goto out;

free_queue:
	flush_sigqueue(pending);
	goto out;
}

static int import_posix_timers(struct restart_src_t *src, struct task_struct *task)
{
	BUG_ON(!list_empty(&task->signal->posix_timers));
	return 0;
}

int import_private_signals(struct restart_src_t *src, struct task_struct *task)
{
	return import_sigpending(src, task, &task->pending);
}

#ifdef CONFIG_TASKSTATS
static int cr_export_taskstats(struct checkpoint_dest_t *dest, struct signal_struct *sig)
{
	return dest->write((char *) sig->stats, sizeof(*sig->stats));
}

static int cr_import_taskstats(struct restart_src_t *src, struct signal_struct *sig)
{
	struct taskstats *stats;
	int err = -ENOMEM;

	printk("inside cr_import_taskstats\n");

	stats = kmem_cache_alloc(taskstats_cache, GFP_KERNEL);
	if (!stats)
		goto out;

	err = src->read(stats, sizeof(*stats));
	if (!err)
		sig->stats = stats;
	else
		kmem_cache_free(taskstats_cache, stats);

out:
	return err;
}
#endif

static struct signal_struct *signal_struct_alloc(void)
{
	struct signal_struct *sig;

	sig = kmem_cache_alloc(signal_cachep, GFP_KERNEL);
	if (!sig)
		return NULL;

/*	atomic_set(&obj->signal->count, 1); */
/*	atomic_set(&obj->signal->live, 1); */
	init_waitqueue_head(&sig->wait_chldexit);
/*	obj->signal->flags = 0; */
/*	obj->signal->group_exit_code = 0; */
	sig->group_exit_task = NULL;
/*	obj->signal->group_stop_count = 0; */
	sig->curr_target = NULL;
	init_sigpending(&sig->shared_pending);

	posix_cpu_timers_init_group(sig);
	INIT_LIST_HEAD(&sig->posix_timers);

	hrtimer_init(&sig->real_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	sig->real_timer.function = it_real_fn;
	sig->leader_pid = NULL;

	sig->tty_old_pgrp = NULL;
	sig->tty = NULL;
/*	obj->signal->leader = 0;	/\* session leadership doesn't inherit *\/ */
#ifdef CONFIG_TASKSTATS
	sig->stats = NULL;
#endif
#ifdef CONFIG_AUDIT
	sig->tty_audit_buf = NULL;
#endif

	return sig;
}

int import_signal_struct(struct restart_src_t *src, struct task_struct *tsk)
{
	struct signal_struct tmp_sig;
	struct signal_struct *sig;
	int r = 0;

	sig = signal_struct_alloc();

	r = src->read(&tmp_sig, sizeof(tmp_sig));
	if (r)
		goto err_free_signal;

	atomic_set(&sig->sigcnt, 1);
	atomic_set(&sig->live, 	1);
	init_waitqueue_head(&sig->wait_chldexit);

	sig->group_exit_code 	= tmp_sig.group_exit_code;
	WARN_ON(tmp_sig.group_exit_task);
	sig->notify_count 	= tmp_sig.notify_count;
	sig->group_stop_count	= tmp_sig.group_stop_count;
	sig->flags 		= tmp_sig.flags;

	r = import_sigpending(src, tsk, &sig->shared_pending);
	if (r)
		goto err_free_signal;

	sig->it[0] 		= tmp_sig.it[0];
	sig->it[1] 		= tmp_sig.it[1];

	sig->cputimer.cputime 	= tmp_sig.cputimer.cputime;
	sig->cputimer.running 	= tmp_sig.cputimer.running;
	sig->cputime_expires 	= tmp_sig.cputime_expires;

	/*
	 * This will need proper tty handling once global control ttys
	 * will exist.
	 * The IO-linker already initialized those fields to NULL.
	 */
	/* sig->tty = NULL; */
	/* sig->tty_old_pgrp = NULL; */

	sig->leader 		= tmp_sig.leader;

	sig->utime 		= tmp_sig.utime;
	sig->stime 		= tmp_sig.stime;
	sig->cutime 		= tmp_sig.cutime;
	sig->cstime 		= tmp_sig.cstime;
	sig->gtime 		= tmp_sig.gtime;
	sig->cgtime 		= tmp_sig.cgtime;
	sig->nvcsw 		= tmp_sig.nvcsw;
	sig->nivcsw 		= tmp_sig.nivcsw;
	sig->cnvcsw 		= tmp_sig.cnvcsw;
	sig->cnivcsw 		= tmp_sig.cnivcsw;
	sig->min_flt 		= tmp_sig.min_flt;
	sig->maj_flt 		= tmp_sig.maj_flt;
	sig->cmin_flt 		= tmp_sig.cmin_flt;
	sig->cmaj_flt 		= tmp_sig.cmaj_flt;
	sig->inblock 		= tmp_sig.inblock;
	sig->oublock 		= tmp_sig.oublock;
	sig->cinblock 		= tmp_sig.cinblock;
	sig->coublock 		= tmp_sig.coublock;
	/* ioac may be an empty struct */
	if (sizeof(sig->ioac))
		sig->ioac	= tmp_sig.ioac;

	sig->sum_sched_runtime 	= tmp_sig.sum_sched_runtime;

	memcpy(sig->rlim, tmp_sig.rlim, sizeof(sig->rlim));
#ifdef CONFIG_BSD_PROCESS_ACCT
	sig->pacct 		= tmp_sig.pacct;
#endif
#ifdef CONFIG_TASKSTATS
	if (tmp_sig.stats) {
		printk("cr_import_taskstats\n");
		r = cr_import_taskstats(src, sig);
		if (r)
		{
			printk("cr_import_taskstats failed\n");
			goto err_free_signal;
		}
	}
#endif
#ifdef CONFIG_AUDIT
	sig->audit_tty 		= tmp_sig.audit_tty;
#endif

	mutex_init(&sig->cred_guard_mutex);
	tsk->signal = sig;

	r = import_posix_timers(src, tsk);
	if (r)
		goto err_free_signal;

	return r;

err_free_signal:
	return -1;

}



static int export_posix_timers(struct checkpoint_dest_t *dest, struct task_struct *task)
{
	int err = 0;
	spin_lock_irq(&task->sighand->siglock);
	if (!list_empty(&task->signal->posix_timers))
		err = -EBUSY;
	spin_unlock_irq(&task->sighand->siglock);
	return err;
}

int export_signal_struct(struct checkpoint_dest_t *dest, struct task_struct *tsk)
{
	int r = 0;

	struct signal_struct *sig = tsk->signal;
	r = dest->write(sig, sizeof(*sig));
	if (!r)
		r = export_sigpending(dest, tsk, &tsk->signal->shared_pending);
#ifdef CONFIG_TASKSTATS
	if (!r && sig->stats)
		r = cr_export_taskstats(dest, sig);
#endif
	if (!r)
		r = export_posix_timers(dest, tsk);
	
err_write:
	return r;
}

static struct sighand_struct *sighand_struct_alloc(void)
{
	return kmem_cache_alloc(sighand_cachep, GFP_KERNEL);
}

int import_sighand_struct(struct restart_src_t *src, struct task_struct *tsk)
{
	int r;

	tsk->sighand = sighand_struct_alloc();

	r = src->read(&tsk->sighand->action, sizeof(tsk->sighand->action));
	if (r) {
		goto err_read;
	}
	atomic_set(&tsk->sighand->count, 1);

err_read:
	return r;
}
