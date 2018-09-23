#ifndef __CHECKPOINT_UTIL_API__
#define __CHECKPOINT_UTIL_API__

#include <linux/types.h>

#define VMAD_DUMP_NOSHANON    0x0100  /* let BLCR dump shared anonymous mappings */
#define VMAD_DUMP_NOEXEC      0x0200  /* let BLCR dump the executable */
#define VMAD_DUMP_NOPRIVATE   0x0400  /* let BLCR dump private filenamed memory */
#define VMAD_DUMP_NOSHARED    0x0800  /* let BLCR dump shared filenamed memory */

#define VMAD_DUMP_LIBS  1
#define VMAD_DUMP_EXEC  2
#define VMAD_DUMP_OTHER 4
#define VMAD_DUMP_ALL   7

#define VMAD_NAMELEN_ARCH (4096+1)

#define VMAD_DUMP_MOREPAGES_MAGIC 858585   /* This is used while dumping phys. mem. pages to tell restart to read one more page. */
#define VMAD_DUMP_PAGESDONE_MAGIC 969696   /* This is used while dumping phys. mem. pages to tell restart to stop reading pages. */

#define EOS_SIG_FULL_MIGRATE 31
#define EOS_SIG_STRETCH_MIGRATE 32
#define EOS_SIG_JUMP_MIGRATE 33

struct task_struct;
struct checkpoint_dest_t;
struct restart_src_t;
struct mm_struct;

void prepare_to_export(struct task_struct *task);
int export_thread_info(struct checkpoint_dest_t *dest, struct task_struct *task);
int export_audit_context(struct checkpoint_dest_t *dest, struct task_struct *tsk);
int export_thread_struct(struct checkpoint_dest_t *dest, struct task_struct *tsk);
int export_cgroups(struct checkpoint_dest_t *dest, struct task_struct *task);
int export_sched(struct checkpoint_dest_t *dest, struct task_struct *task);
int export_signal_struct(struct checkpoint_dest_t *dest, struct task_struct *tsk);
int export_mm_struct(struct checkpoint_dest_t *dest, struct task_struct *tsk);
int cr_export_mm_struct(struct checkpoint_dest_t *dest, struct task_struct *tsk);
int import_thread_info(struct restart_src_t *src, struct task_struct *task);
int import_thread_struct(struct restart_src_t *src, struct task_struct *tsk);
int reinit_mm(struct mm_struct *mm);
struct mm_struct *mm_init(struct mm_struct *mm, struct task_struct *p);
int alloc_ldt(mm_context_t *pc, int mincount, int reload) ;
int import_audit_context(struct restart_src_t *src, struct task_struct *task);
int import_fs_struct (struct restart_src_t *src, struct task_struct *tsk);
int import_files_struct (struct restart_src_t *src, struct task_struct *tsk);
int import_cgroups(struct restart_src_t *src, struct task_struct *tsk);
int import_sched(struct restart_src_t *src, struct task_struct *task);
int import_private_signals(struct restart_src_t *src, struct task_struct *task);
int import_signal_struct(struct restart_src_t *src, struct task_struct *tsk);
int import_sighand_struct(struct restart_src_t *src, struct task_struct *tsk);
int import_mm_struct (struct restart_src_t *src, struct task_struct *tsk);

extern unsigned long nr_scan_multiplier;

struct task_struct *import_process(struct restart_src_t *src);
extern void deactivate_page(struct page *page);
extern void move_page_to_tail(struct page *page);

extern struct task_struct *baby_sitter;
extern struct task_struct *elasticized_process;
extern struct task_struct *process_handle;
extern struct checkpoint_dest_t *chkpt_writer;
extern struct checkpoint_dest_t *chkpt_reader;

extern long (*sys_get_page_p)(int pid, unsigned long address, unsigned int length, const char *buff);
extern long (*sys_inject_page_p)(int pid, unsigned long address, unsigned int length, const char *buff);

extern long (*bcast_send_mmap)(int pid, struct file *file, unsigned long addr,
			unsigned long len, unsigned long prot,
			unsigned long flags, unsigned long pgoff, unsigned long ret);

extern long (*bcast_send_munmap)(int pid, unsigned long address, unsigned int length, unsigned long ret);

extern long (*bcast_send_brk)(int pid, unsigned long brk, unsigned long ret);
extern long (*push_pending_frames)(void);

extern long do_eos_migrate_process(int p_id, int level);

extern int my__pte_alloc(struct mm_struct *mm, struct vm_area_struct *vma,
		pmd_t *pmd, unsigned long address);
extern int my__pud_alloc(struct mm_struct *mm, pgd_t *pgd, unsigned long address);
extern int my__pmd_alloc(struct mm_struct *mm, pud_t *pud, unsigned long address);
extern int insert_anonymous_page(struct mm_struct *mm, struct vm_area_struct *vma,
		unsigned long address, pte_t *ptep, pmd_t *pmd,
		unsigned int flags, struct page ** pg);
extern int do_anonymous_page_wrapper(struct mm_struct *mm, struct vm_area_struct *vma,
		unsigned long address, pte_t *page_table, pmd_t *pmd,
		unsigned int flags, int is_remote_page);
extern void free_page_list(struct list_head *free_pages);
extern void move_active_pages_to_lru_tail(struct zone *zone,
				     struct list_head *list,
				     enum lru_list lru);

extern int where_to_stop;
extern int sticky_mode;
extern int log_eos_messages;
extern int other_machine_overloaded;
extern int this_machine_overloaded;

extern int threshold_page_pulls_slave;
extern int threshold_page_pulls_master;

extern unsigned long eos_machine_id;

#define allocate_mm()	(kmem_cache_alloc(mm_cachep, GFP_KERNEL))
#define free_mm(mm)	(kmem_cache_free(mm_cachep, (mm)))
extern struct kmem_cache *mm_cachep;

#define alloc_task_struct()    kmem_cache_alloc(task_struct_cachep, GFP_KERNEL)
#define free_task_struct(tsk)  kmem_cache_free(task_struct_cachep, (tsk))
extern struct kmem_cache *task_struct_cachep;

struct checkpoint_dest_t {
	int (*write)(void *buff, int size);
	int flags;

	// This will be used (once) for verification if assigned:
	int (*read)(void *buff, int size);
};

struct restart_src_t {
	int (*read)(void *buff, int size);
	int flags;

	// This will be used (once) for verification if assigned:
	int (*write)(void *buff, int size);
};

enum file_type {
	FILE,
	PIPE,
	SHM
};

struct regular_file_desc {
	enum file_type type;
	union {
		struct {
			fmode_t f_mode;
			int shmid;
		} shm;
		struct {
			unsigned long f_flags;
			long key;
		} pipe;
		struct {
			umode_t mode;
			loff_t pos;
			unsigned int flags;
			unsigned int uid;
			unsigned int gid;
			unsigned long ctnrid;
			char *filename;
		} file;
	};
};

#define VMAD_CHUNKHEADER_SIZE PAGE_SIZE
#define VMAD_CHUNKHEADER_MIN sizeof(struct vmadump_page_header)
#define VMAD_END_OF_CHUNKS ~0UL

enum {
  CR_SHANON_FILE,
  CR_SHANON_SHMEM,
  CR_SHANON_HUGETLB,
  CR_PSE,
};

struct vmadump_page_list_header {
    unsigned int fill;
    /* May add hash list or other data here later */
};

struct vmadump_mm_info {
    unsigned long start_code, end_code;
    unsigned long start_data, end_data;
    unsigned long start_brk,  brk;
    unsigned long start_stack;
    unsigned long arg_start, arg_end;
    unsigned long env_start, env_end;
};

struct vmadump_vma_header {
    unsigned long  start;	/* ~0 = end of list */
    unsigned long  end;
    unsigned long  flags;
    unsigned long  namelen;	/* 0 = data follows */
    unsigned long  pgoff;	/* file offset for mmap, in page units */
    int is_heap;	
};

struct vmadump_page_header {
    unsigned long start;	/* ~0 = end of list */
    unsigned int num_pages;
};

struct cr_mmaps_desc {
  /* What is mapped: */
    void *		mmaps_id; /* The (struct inode *) at checkpoint time */
    loff_t		i_size;
    int			type;
  /* Where and how is it mapped: */
    unsigned long	start, end;
    unsigned long	flags;
    unsigned long	pgoff;  /* units of PAGE_SIZE */
};

typedef enum {
    cr_bad_obj,
    cr_fs_obj,
    cr_files_obj,
    cr_file_obj,
    cr_chrdev_obj,
    cr_dup_obj,
    cr_file_info_obj,
    cr_open_file_obj,
    cr_fifo_obj,
    cr_eofiles_obj,
    cr_dir_obj,
    cr_open_dir_obj,
} cr_obj_t;

struct cr_open_file {
    cr_obj_t cr_type; /* cr_open_file_obj */

    void *file_id;	/* pre-checkpoint inode for matching */
    mode_t i_mode;
    loff_t f_pos;
    loff_t i_size;
    unsigned int f_flags;
};

struct cr_dup {
    cr_obj_t cr_type; /* cr_dup_obj */
    /* nothing more */
};

typedef enum {
    cr_bad_file_type = 0,
    cr_open_file = 1,
    cr_open_directory,
    cr_open_link,
    cr_open_fifo,
    cr_open_socket,
    cr_open_chr,
    cr_open_blk,
    cr_open_dup,
    cr_open_chkpt_req,
    cr_unknown_file = 99,
    cr_end_of_files,
} cr_file_type_t;

struct cr_file_info {
    cr_obj_t       cr_type;              /* cr_file_info_obj */
    cr_file_type_t cr_file_type;
    int		fd;
    int		cloexec;
    int		unlinked;
    void *	orig_filp;
};

struct cr_files_struct {
    cr_obj_t cr_obj;               /* cr_files_obj */
    int cr_max_fds;
    int cr_next_fd;
};

struct cr_chrdev {
    cr_obj_t cr_type; /* cr_chrdev_obj */
    unsigned int cr_major;
    unsigned int cr_minor;
    mode_t i_mode;
    unsigned int f_flags;
};

#endif /* __CHECKPOINT_UTIL_API__ */
