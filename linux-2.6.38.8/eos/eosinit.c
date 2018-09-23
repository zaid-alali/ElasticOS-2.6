#include <linux/kernel.h>
#include <linux/module.h>
#include "migration.h"

struct task_struct *baby_sitter;
struct task_struct *elasticized_process;
struct task_struct *process_handle;
struct checkpoint_dest_t *chkpt_writer;
struct checkpoint_dest_t *chkpt_reader;
long (*sys_get_page_p)(int pid, unsigned long address, unsigned int length, const char *buff);
long (*sys_inject_page_p)(int pid, unsigned long address, unsigned int length, const char *buff);
long (*bcast_send_mmap)(int pid, unsigned long addr,
			unsigned long len, unsigned long prot,
			unsigned long flags, unsigned long pgoff, unsigned long ret);

long (*bcast_send_munmap)(int pid, unsigned long address, unsigned int length, unsigned long ret);

long (*bcast_send_brk)(int pid, unsigned long brk, unsigned long ret);

long (*push_pending_frames)(void);

unsigned long eos_machine_id;

int sticky_mode;
int other_machine_overloaded;
int this_machine_overloaded;

EXPORT_SYMBOL(baby_sitter);
EXPORT_SYMBOL(elasticized_process);
EXPORT_SYMBOL(bcast_send_mmap);
EXPORT_SYMBOL(bcast_send_munmap);
EXPORT_SYMBOL(bcast_send_brk);
EXPORT_SYMBOL(process_handle);
EXPORT_SYMBOL(chkpt_writer);
EXPORT_SYMBOL(chkpt_reader);
EXPORT_SYMBOL(sys_get_page_p);
EXPORT_SYMBOL(sys_inject_page_p);
EXPORT_SYMBOL(eos_machine_id);
EXPORT_SYMBOL(push_pending_frames);
EXPORT_SYMBOL(sticky_mode);
EXPORT_SYMBOL(other_machine_overloaded);
EXPORT_SYMBOL(this_machine_overloaded);

void __init eos_init(void){
	
	printk("Initializing EOS ...\n");
	eos_migrate_task_ptr = &eos_task_migrate;

}
