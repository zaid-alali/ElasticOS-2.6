#ifndef __EOS_SIGNAL_H__
#define __EOS_SIGNAL_H__

/* EOS signal */



#include <asm/signal.h>

struct siginfo;
struct task_struct;

int send_eos_signal(int sig, struct siginfo *info, struct task_struct *t);
int send_eos_sleep_signal(int sig_nr, int sig_code, struct siginfo *info, struct task_struct *t);


#endif /* __EOS_SIGNAL_H__ */
