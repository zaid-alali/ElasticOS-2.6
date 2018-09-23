
#include <linux/kernel.h>
#include <eos/pf_history.h>
#include <linux/vmalloc.h>
#include <linux/module.h>
#include <linux/time.h>

ring_buffer *pfhistory;
int eos_ring_buffer_size;

EXPORT_SYMBOL(pfhistory);
EXPORT_SYMBOL(eos_ring_buffer_size);
 
void __init_buffer(ring_buffer **cBuffer, int capacity) {
    (*cBuffer) = (ring_buffer *) vmalloc(sizeof (ring_buffer));
    (*cBuffer)->current_index = 0;
    (*cBuffer)->current_size = 0;
    (*cBuffer)->pf_remote = 0;
    (*cBuffer)->pf_local = 0;
    (*cBuffer)->capacity = capacity;
    (*cBuffer)->start_time.tv64=0;
    (*cBuffer)->end_time.tv64=0;
    (*cBuffer)->flag1=false;
    (*cBuffer)->flag2=false;
    (*cBuffer)->counter1=0;
    (*cBuffer)->counter2=0;	
    (*cBuffer)->data = (char *) vmalloc(capacity);
}
EXPORT_SYMBOL(__init_buffer);

void init_hist_buffer(void){
	if(eos_ring_buffer_size > 0)
	{
		__init_buffer(&pfhistory, eos_ring_buffer_size);
	}
	else 
	{
		printk("History buffer size can not be less than 1\n");
	}
}
EXPORT_SYMBOL(init_hist_buffer);

void reset_history_buffer(ring_buffer *cBuffer){
    cBuffer->current_index = 0;
    cBuffer->current_size = 0;
    cBuffer->pf_remote = 0;
    cBuffer->pf_local = 0;
    cBuffer->start_time.tv64 = 0;
    cBuffer->end_time.tv64 = 0;
    cBuffer->flag1=false;
    cBuffer->flag2=false;
    cBuffer->counter1=0;
    cBuffer->counter2=0;
}
EXPORT_SYMBOL(reset_history_buffer);

