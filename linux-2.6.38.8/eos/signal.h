#ifndef __SINGAL_UTIL_API__
#define __SINGAL_UTIL_API__

struct checkpoint_dest_t;
struct task_struct;

int export_private_signals(struct checkpoint_dest_t *dest, struct task_struct *task);

#endif /* __SINGAL_UTIL_API__ */
