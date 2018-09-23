#ifndef __EOS_MIGRATION_H__
#define __EOS_MIGRATION_H__

#include <linux/sched.h>

extern int (*eos_migrate_task_ptr)(int sig, struct siginfo *info, struct pt_regs *regs);
int eos_task_migrate(int sig, struct siginfo *info, struct pt_regs *regs);

#endif /* __EOS_MIGRATION_H__ */
