#include <linux/kernel.h>
#include <linux/sched.h>
#include <asm/processor.h>
#include <asm/system.h>
#include <asm/uaccess.h>
#include <asm/i387.h>

#include <eos/checkpoint_util.h>
#include <eos/krgsyms.h>

int export_exec_domain(struct checkpoint_dest_t *dest, struct task_struct *task)
{
	if (task_thread_info(task)->exec_domain != &default_exec_domain)
		return -EPERM;

	return 0;
}

struct exec_domain *import_exec_domain(struct restart_src_t *src)
{
	return &default_exec_domain;
}

int export_restart_block(struct checkpoint_dest_t *dest, struct task_struct *task)
{
	struct thread_info *ti = task_thread_info(task);
	//enum krgsyms_val fn_id;
	int r = 0;

/*
	fn_id = krgsyms_export(ti->restart_block.fn);
	if (fn_id == KRGSYMS_UNDEF) {
		r = -EBUSY;
		goto out;
	}

	r = dest->write((char *) &fn_id, sizeof(fn_id));
	if (r)
		goto out;
*/
	r = dest->write((char *) &ti->restart_block, sizeof(ti->restart_block));

out:
	return r;
}

int import_restart_block(struct restart_src_t *src, struct restart_block *p)
{
	enum krgsyms_val fn_id;
	int r;

	//r = src->read(&fn_id, sizeof(fn_id));
	//if (r)
	//	goto err_read;
	r = src->read(p, sizeof(*p));
	//if (r)
	//	goto err_read;
	//p->fn = krgsyms_import(fn_id);

//err_read:
	return r;
}

void prepare_to_export(struct task_struct *task)
{
	unlazy_fpu(task);
}

int export_thread_info(struct checkpoint_dest_t *dest, struct task_struct *task)
{
	int r;

	r = dest->write((char *) task->stack, sizeof(struct thread_info));
	if (r)
		goto error;

	r = export_exec_domain(dest, task);
	if (r)
		goto error;
	r = export_restart_block(dest, task);

error:
	return r;
}

int export_thread_struct(struct checkpoint_dest_t *dest, struct task_struct *tsk)
{
	int r = -EBUSY;

	if (test_tsk_thread_flag(tsk, TIF_IO_BITMAP))
		goto out;
#ifdef CONFIG_X86_DS
	if (test_tsk_thread_flag(tsk, TIF_DS_AREA_MSR))
		goto out;
#endif

#ifdef CONFIG_X86_64
	savesegment(gs, tsk->thread.gsindex);
	savesegment(fs, tsk->thread.fsindex);
	savesegment(es, tsk->thread.es);
	savesegment(ds, tsk->thread.ds);

#else /* CONFIG_X86_32 */
	lazy_save_gs(tsk->thread.gs);

	WARN_ON(tsk->thread.vm86_info);
#endif /* CONFIG_X86_32 */

	r = dest->write((char*) &tsk->thread, sizeof (tsk->thread));
	if (r)
		goto out;
	
	if(tsk->thread.fpu.state != NULL) {
		int is_fpu_alloc = 1;
		r = dest->write((char*) &is_fpu_alloc, sizeof(int));
		r = dest->write((char*) tsk->thread.fpu.state, xstate_size);
	}
	else {
		int is_fpu_alloc = 0;
		r = dest->write((char*) &is_fpu_alloc, sizeof(int));
	}

out:
	return r;
}

int import_thread_struct(struct restart_src_t *src, struct task_struct *tsk)
{
	int r;
	int ret = 0;
	int is_fpu_alloc = 0;
	union thread_xstate *temp = NULL;
	
	if(src->flags == EOS_SIG_JUMP_MIGRATE)	temp = tsk->thread.fpu.state;

	r = src->read(&tsk->thread, sizeof (tsk->thread));
	if (r)
		goto out;

	if(src->flags == EOS_SIG_JUMP_MIGRATE)	tsk->thread.fpu.state = temp;

	r = src->read(&is_fpu_alloc, sizeof(int));

	if (is_fpu_alloc == 1) {
		r = -ENOMEM;

		if(src->flags != EOS_SIG_JUMP_MIGRATE)
		{
			memset(&(tsk->thread.fpu), 0, sizeof(tsk->thread.fpu));
			ret = fpu_alloc(&tsk->thread.fpu);
			if (ret)
				goto out;
		}
		r = src->read(tsk->thread.fpu.state,  xstate_size);
		if (r && src->flags != EOS_SIG_JUMP_MIGRATE)
			free_thread_xstate(tsk);
	}

out:
	return r;
}

static void __free_thread_info(struct thread_info *ti)
{
	//ti->task->thread.xstate = NULL;
	free_thread_info(ti);
}

int import_thread_info(struct restart_src_t *src, struct task_struct *task)
{
	struct thread_info *p;
	int r;
	__u32 cpu; 

	if(src->flags == EOS_SIG_JUMP_MIGRATE)
	{
		p = task_thread_info(task);
		if(p) cpu = p->cpu;
	}
	else 
		p = alloc_thread_info(task);

	if (!p) {
		r = -ENOMEM;
		goto exit;
	}

	r = src->read(p, sizeof(struct thread_info));
	if (r)
		goto exit_free_thread_info;

	p->task = task;
	p->exec_domain = import_exec_domain(src);

	p->preempt_count = 0;
	p->addr_limit = USER_DS;
	if(src->flags == EOS_SIG_JUMP_MIGRATE) p->cpu = cpu;
	
	r = import_restart_block(src, &p->restart_block);
	if (r)
		goto exit_free_thread_info;

	task->stack = p;

exit:
	return r;

exit_free_thread_info:
	__free_thread_info(p);
	goto exit;
}
