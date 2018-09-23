#ifndef _ASM_X86_CURRENT_H
#define _ASM_X86_CURRENT_H

#include <linux/compiler.h>
#include <asm/percpu.h>

#ifndef __ASSEMBLY__
struct task_struct;

DECLARE_PER_CPU(struct task_struct *, current_task);

static __always_inline struct task_struct *get_current(void)
{
	return percpu_read_stable(current_task);
}

#define eos_current (get_current()->effective_current)
#define current ({							\
	struct task_struct *__cur = get_current();			\
	__cur->effective_current ? __cur->effective_current : __cur;	\
})

//#define current get_current()

#endif /* __ASSEMBLY__ */

#endif /* _ASM_X86_CURRENT_H */
