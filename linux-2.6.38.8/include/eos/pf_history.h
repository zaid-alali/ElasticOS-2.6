/* 
 * File:   circular_buffer.h
 * Author: ehab
 *
 * Created on February 22, 2017, 10:51 AM
 */
#include <linux/types.h>
#include <linux/ktime.h>
#include <linux/hrtimer.h>
#ifndef CIRCULAR_BUFFER_H
#define	CIRCULAR_BUFFER_H

#define REMOTE_PAGE_FAULT   1
#define LOCAL_PAGE_FAULT    2

typedef struct ring_buffer_t {
    uint32_t pf_remote;
    uint32_t pf_local;
    uint32_t current_index;
    uint32_t current_size;
    uint32_t capacity;
    ktime_t start_time;
    ktime_t end_time;
    bool flag1;
    bool flag2;
    uint32_t counter1;
    uint32_t counter2;
    char *data;
} ring_buffer;

extern void init_hist_buffer(void);
extern void reset_history_buffer(ring_buffer *cBuffer);
extern ring_buffer *pfhistory;
extern int eos_ring_buffer_size;
extern int (*should_jump_p)(ring_buffer *pfh);

#endif	/* CIRCULAR_BUFFER_H */



