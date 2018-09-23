#ifndef __KRG_ACTION_H__
#define __KRG_ACTION_H__

typedef enum {
	EOS_NO_ACTION,
	EOS_MIGRATE,
	EOS_REMOTE_CLONE,
	EOS_CHECKPOINT,
	EOS_ACTION_MAX	   /* Always in last position */
} eos_action_t;


#endif /* __KRG_ACTION_H__ */
