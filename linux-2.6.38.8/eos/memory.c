#include <linux/mm_types.h>
#include <linux/fs.h>
#include <linux/hugetlb_inline.h>
#include <linux/dcache.h>
#include <linux/gfp.h>
#include <linux/mman.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/unistd.h>
#include <linux/personality.h>
#include <linux/highmem.h>
#include <linux/ptrace.h>
#include <linux/init.h>
#include <linux/prctl.h>
#include <asm/pgtable.h>
#include <asm/pgalloc.h>
#include <asm/processor.h>
#include <asm/uaccess.h>
#include <asm/bitops.h>
#include <linux/hugetlb.h>
#include <linux/binfmts.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/rmap.h>
#include <linux/proc_fs.h>
#include <asm/mmu_context.h>
#include <asm/uaccess.h>
#include <linux/mman.h>
#include <linux/syscalls.h>

#include <eos/checkpoint_util.h>

void print_mmaps(struct task_struct *tsk) {
    struct mm_struct *mm = tsk->mm;
    struct vm_area_struct *map, *next_map;
    unsigned long next_addr;

    char *name_buff = NULL;
    char *filename = 0;

    name_buff = (char *) __get_free_page(GFP_KERNEL);

    down_read(&mm->mmap_sem);
    next_map = mm->mmap;
    next_addr = next_map ? next_map->vm_start : 0;
    while (next_map) {
        /* Call vma_find() to find the map we're looking for. */
        map = find_vma(mm, next_addr);
        if (map != next_map) break;
        next_map = map->vm_next;
        next_addr = next_map ? next_map->vm_start : 0;
        if (map->vm_file) {
            filename = d_path(&map->vm_file->f_path, name_buff, PAGE_SIZE);
        }
        printk("map->start: %lu\tmap->end: %lu\t%s\n", map->vm_start, map->vm_end,
                map->vm_file ? filename : "");
    }

    up_read(&mm->mmap_sem);
}


static char *default_map_name(struct file *f, char *buffer, int size) {
    return d_path(&f->f_path, buffer, size);
}


static inline int vmad_is_arch_map(struct task_struct *tsk, const struct vm_area_struct *map)
{
	unsigned long vdso_base = (unsigned long) tsk->mm->context.vdso;
	return (map->vm_start == vdso_base);
}

static inline int vmad_dentry_unlinked(struct dentry *dentry) {
  return ((!IS_ROOT(dentry) && d_unhashed(dentry)) ||
	  (dentry->d_inode->i_nlink == 0) ||
	  (dentry->d_flags & DCACHE_NFSFS_RENAMED));
}

static inline int vmad_is_exe(struct vm_area_struct *map) {
  return (map->vm_mm && (map->vm_mm->exe_file == map->vm_file));
}

#define is_library(FILE) 0

static inline int vmad_is_special_mmap(struct task_struct *tsk, struct vm_area_struct *map, int flags) {
  const struct file * const filp = map->vm_file;
  const unsigned long vm_flags = map->vm_flags;

  BUG_ON(!filp);
				    
  if (vmad_is_arch_map(tsk, map)) return 0;

#ifdef CONFIG_HUGETLBFS
  /* Ignore unlinked status, since hugetlbfs is not persistent */
  if (is_vm_hugetlb_page(map)) return 1;
#endif

  if (vmad_dentry_unlinked(filp->f_dentry)) {
    return (vm_flags & VM_SHARED);
  }

  return (((flags & VMAD_DUMP_NOEXEC)    &&  vmad_is_exe(map)) ||
	  ((flags & VMAD_DUMP_NOPRIVATE) && !(vm_flags & VM_SHARED)) ||
	  ((flags & VMAD_DUMP_NOSHARED)  &&  (vm_flags & VM_SHARED)));
}

static inline
pte_t *vmad_follow_addr(struct page **pagep, struct mm_struct *mm, unsigned long addr) {
    pgd_t *pgd;
#ifdef PTRS_PER_PUD
    pud_t *pud;
#endif
    pmd_t *pmd;

#if !defined(CONFIG_HUGETLBFS)
    /* Nothing to do here */
#else
    struct page *pg = follow_huge_addr(mm, addr, 0);
    if (!IS_ERR(pg)) {
	*pagep = pg;
	return NULL;
    }
#endif
    *pagep = NULL;
    pgd = pgd_offset(mm, addr);
    if (pgd_none(*pgd)) return NULL;
#ifdef PTRS_PER_PUD
    pud = pud_offset(pgd, addr);
    if (pud_none(*pud)) return NULL;
    pmd = pmd_offset(pud, addr);
#else
    pmd = pmd_offset(pgd, addr);
#endif
    if (pmd_none(*pmd)) return NULL;
#ifdef CONFIG_HUGETLBFS
    if (pmd_huge(*pmd)) {
	*pagep = follow_huge_pmd(mm, addr, pmd, 0);
	return NULL;
    }
#endif
    return pte_offset_map(pmd, addr);
}

static
int addr_copied(struct mm_struct *mm, unsigned long addr) {
    pte_t *ptep;
    struct page *pg;
    int ret;

    spin_lock(&mm->page_table_lock);
    ptep = vmad_follow_addr(&pg, mm, addr);
    if (ptep) {
	pte_t pte = *ptep;
	pte_unmap(ptep);
	if (pte_present(pte)) {
	    pg = pte_page(pte);
	    ret = PageAnon(pg);
	} else {
	    /* pte_none is false for a swapped (written) page */
	    ret = !pte_none(pte);
	}
    } else {
	ret = pg && PageAnon(pg);
    }
    spin_unlock(&mm->page_table_lock);
    return ret;
}

static inline int do_export_mm_struct(struct checkpoint_dest_t *dest,
				      struct mm_struct *mm)
{
	int r;
	r = dest->write ((char *) mm, sizeof(struct mm_struct));
	return r;
}

/*
int export_context_struct (struct checkpoint_dest_t *dest,
                           struct mm_struct *mm)
{
	int r = 0;

#ifndef CONFIG_USERMODE
	if (mm->context.ldt) {
		r = dest->write((char *) mm->context.ldt,
				mm->context.size * LDT_ENTRY_SIZE);
		if (r)
			goto err;
	}
#endif
err:
	return r;
}
*/
/*

static int export_one_vma (struct checkpoint_dest_t *dest,
                           struct task_struct *tsk,
                           struct vm_area_struct *vma,
			   hashtable_t *file_table)
{
	krgsyms_val_t vm_ops_type, initial_vm_ops_type;
	int r;

	r = dest->write((char *) vma, sizeof (struct vm_area_struct));
	if (r)
		goto out;

#ifdef CONFIG_KRG_DVFS
	r = export_vma_file (action, ghost, tsk, vma, file_table);
	if (r)
		goto out;
#endif

	r = -EPERM;
	vm_ops_type = krgsyms_export (vma->vm_ops);
	if (vma->vm_ops && vm_ops_type == KRGSYMS_UNDEF)
		goto out;

	if (action->type != EPM_CHECKPOINT
	    && vma->vm_ops && vm_ops_type == KRGSYMS_VM_OPS_SHMEM)
		goto out;

	initial_vm_ops_type = krgsyms_export (vma->initial_vm_ops);
	if (vma->initial_vm_ops && initial_vm_ops_type == KRGSYMS_UNDEF)
		goto out;

	BUG_ON(vma->vm_private_data && vm_ops_type != KRGSYMS_VM_OPS_SPECIAL_MAPPING);

	r = ghost_write (ghost, &vm_ops_type, sizeof (krgsyms_val_t));
	if (r)
		goto out;

	r = ghost_write (ghost, &initial_vm_ops_type, sizeof (krgsyms_val_t));

out:
	return r;
}



int export_vmas (struct checkpoint_dest_t *dest, struct task_struct *tsk)
{
	struct vm_area_struct *vma;
	hashtable_t *file_table;

	int r;

	BUG_ON (tsk == NULL);
	BUG_ON (tsk->mm == NULL);

	file_table = hashtable_new (FILE_TABLE_SIZE);
	if (!file_table)
		return -ENOMEM;



	r = dest->write((char *) &tsk->mm->map_count, sizeof(int));
	if (r)
		goto out;

	vma = tsk->mm->mmap;

	while (vma != NULL) {
		r = export_one_vma (action, ghost, tsk, vma, file_table);
		if (r)
			goto out;
		vma = vma->vm_next;
	}

	{
		int magic = 650874;

		r = ghost_write(ghost, &magic, sizeof(int));
	}

out:
	hashtable_free(file_table);

	return r;
}

int export_mm_struct(struct checkpoint_dest_t *dest, struct task_struct *tsk)
{
	int r = 0;

	r = do_export_mm_struct(dest, tsk->mm);

	r = export_context_struct(dest, tsk->mm);

	return 0;
}
*/
static
int addr_nonzero_file(struct mm_struct *mm, unsigned long addr) {
    int i;
    unsigned long val = 0;

    /* Simple zero check */
    for (i=0; i < (PAGE_SIZE/sizeof(long)); i++) {
	/* We ignore EFAULT and presume that it's zero here */
	get_user(val, (((long*)addr)+i));
	if (val) return 1;
    }
    return 0;
}

int addr_nonzero(struct mm_struct *mm, unsigned long addr)
{
    int i;
    struct page *pg;
    pte_t *ptep;
    unsigned long val;

    spin_lock(&mm->page_table_lock);
    ptep = vmad_follow_addr(&pg, mm, addr);
    if (ptep) {
	pte_t pte = *ptep;
	pte_unmap(ptep);
	if (pte_none(pte)) goto out_zero; /* Never faulted */
	if (pte_present(pte) && (pte_page(pte) == ZERO_PAGE(addr))) goto out_zero; /* Only READ faulted */
    } else if (!pg) {
	goto out_zero;
    }
    spin_unlock(&mm->page_table_lock);

    /* Ok, the page could be non-zero - check it... */
    for (i=0; i < (PAGE_SIZE/sizeof(long)); i++) {
	get_user(val, (((long*)addr)+i));
	if (val) return 1;
    }
    return 0;

 out_zero:
    spin_unlock(&mm->page_table_lock);
    return 0;
}

/*
static 
long store_page_chunks(struct checkpoint_dest_t *dest,
		      struct vmadump_page_header *headers,
		      int sizeof_headers, int use_directio)
{
    unsigned long old_filp_flags = 0;
    unsigned long chunk_start;
    long r, bytes = 0;
    int i;

    const int num_headers = sizeof_headers/sizeof(*headers);

    r = dest->write((char *) headers, sizeof_headers);
    if (r != sizeof_headers) goto bad_write;
    bytes += r;


    if (headers[0].start == VMAD_END_OF_CHUNKS) goto empty;

    for (i=0; i<num_headers; ++i) {
	const long len = (long)headers[i].num_pages << PAGE_SHIFT;

	chunk_start = headers[i].start;

        if (chunk_start == VMAD_END_OF_CHUNKS) {
            break;
        }

	r = write_user(ctx, file, (void *)chunk_start, len);
	if (r != len) goto bad_write;
	bytes += r;
    }

    if (use_directio)
	directio_stop(file, old_filp_flags);

empty:
    return bytes;

bad_write:
    if (r >= 0) r = -EIO;
    return r;
}

static inline loff_t
write_chunk(struct checkpoint_dest_t *dest,
             struct vmadump_page_header *chunks, unsigned int *sizeof_chunks,
             int *chunk_number, unsigned long start, unsigned long num_pages,
             int use_directio)
{
    long r = 0;

    if (num_pages || (start == VMAD_END_OF_CHUNKS)) {
        const int max_chunks = *sizeof_chunks/sizeof(*chunks);
        int index;

        index = (*chunk_number)++;
        chunks[index].start = start;
        chunks[index].num_pages = num_pages;

        if (((index + 1) >= max_chunks) || (start == VMAD_END_OF_CHUNKS)) {
            r = store_page_chunks(ctx, file, chunks, *sizeof_chunks, use_directio);
            *sizeof_chunks = VMAD_CHUNKHEADER_SIZE;
            *chunk_number = 0;
        }
    }
    return r;
}

static long 
store_page_list_header(struct checkpoint_dest_t *dest)
{
    struct vmadump_page_list_header header;
    long r;

    header.fill = 0;
    r = dest->write((char*) &header, sizeof(header));
    if (r)
        return -1;

    return 0;

}
*/
pte_t *pte_by_address(const struct mm_struct *const mm,
                             const unsigned long address)
{
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte = NULL;

    pgd = pgd_offset(mm, address);
    if (!pgd_present(*pgd))
        goto do_return;

    pud = pud_offset(pgd, address);
    if (!pud_present(*pud))
        goto do_return;

    pmd = pmd_offset(pud, address);
    if (!pmd_present(*pmd))
        goto do_return;

    pte = pte_offset_kernel(pmd, address);

return pte;

do_return:
    return pte;
}

struct page *pte_to_page(pte_t *pte)
{
	if (!pte_present(*pte))
		return NULL;

	else
		return pte_page(*pte);
}

static inline int write_pages_end_marker(struct checkpoint_dest_t *dest)
{
	int r = 0;
	unsigned long magic_number = VMAD_DUMP_PAGESDONE_MAGIC;
	r = dest->write((char *) &magic_number, sizeof(unsigned long));
	if(r)
		goto error_ret;

	return 0;
	
error_ret:
	return -1;
}

static inline int write_phys_page(struct checkpoint_dest_t *dest, struct page *pg, unsigned long address)
{
	char *pg_address = NULL;
	int r = 0;
	unsigned long magic_number = VMAD_DUMP_MOREPAGES_MAGIC;

	if(log_eos_messages) printk("Sending page at address: %lu\n", address);

	pg_address  = (char *) kmap(pg);
	r = dest->write((char *) &magic_number, sizeof(unsigned long));
	if(r)
		goto error_ret;
	r = dest->write((char *) &address, sizeof(unsigned long));
	if(r)
		goto error_ret;

	r = dest->write(pg_address, PAGE_SIZE);
	if(r)
		goto error_ret;

	if(r)
		goto error_ret;
	kunmap(pg);
	return 0;
error_ret:
	kunmap(pg);
	return -1;
}

static int
store_page_list(struct checkpoint_dest_t *dest, struct task_struct *tsk,
		struct vm_area_struct *map, int is_anon,
		int (*need_to_save) (struct mm_struct * mm, unsigned long))
{
	int r = 0;
	unsigned long addr;
	int is_anon_map = 0;
	int skip_pages = 0;
	
	unsigned long start = map->vm_start;
	unsigned long end   = map->vm_end;

	is_anon_map = is_anon;//map->anon_vma && !(map->vm_file) && !(map->vm_flags & VM_GROWSDOWN);

	if(dest->flags == EOS_SIG_FULL_MIGRATE)
	{
		skip_pages = 0;
	}
	else if (dest->flags == EOS_SIG_STRETCH_MIGRATE)
	{
		skip_pages = is_anon_map;
	}

	
	if(!skip_pages)
	{
		for (addr = start; addr < end; addr += PAGE_SIZE) {
			/* The topmost if clause (need_to_save) is to identify things like 
			* unmodified pages that can be reread from disk, or pages that were 
			* allocated and never touched (zero pages).  */
			if (need_to_save(tsk->mm, addr)) {
				pte_t *pte = pte_by_address(tsk->mm, addr);

				if (pte)
				{
					if(pte_present(*pte)) {
						write_phys_page(dest, pte_page(*pte), addr);
					} 
					else if(pte_none(*pte)) {			
						// page not allocated...
					} 	
					else { // page allocated but not present (i.e. swapped out). Fault it in and save it.
						struct page *pg = NULL;
						int res = 0;
						res = get_user_pages(tsk, tsk->mm, addr, 1, 0, 0, &pg, NULL);
						if(res == 1)
							write_phys_page(dest, pg, addr);
					}
				} 
			}
		}
	}
	
    	write_pages_end_marker(dest);

	return r;
}

/* return value: 	1. positive if map is arch_map and is stroed.
			2. Zero if not arch_map.
			3. negative on error.
*/
int vmad_store_arch_map(struct checkpoint_dest_t *dest, struct task_struct *tsk, 
			   struct vm_area_struct *map, int flags)
{
    int r = 0;

    if (vmad_is_arch_map(tsk, map)) {
	/* Just write out a section header */
        struct vmadump_vma_header head;
	head.start   = map->vm_start;
	head.end     = map->vm_end;
	head.flags   = map->vm_flags;
	head.namelen = VMAD_NAMELEN_ARCH;
	head.pgoff   = 0;

	up_read(&tsk->mm->mmap_sem);
	r = dest->write((char *) &head, sizeof(head));
	down_read(&tsk->mm->mmap_sem);
	if(!r) return 1;

    }

    return r;
}

static
int store_map(struct checkpoint_dest_t *dest, struct task_struct *tsk,
	         struct vm_area_struct *map, int flags) {
	struct vmadump_vma_header head;
	char *filename=0;
	char *buffer = 0;
	int r;
	unsigned long start, end;
	int isfilemap = 0;
	int is_anon = 0;//is_anon = map->anon_vma && !(map->vm_file) && !(map->vm_flags & VM_GROWSDOWN);

	if(log_eos_messages) printk("Sending map starting at address: %lu and ending at address:%lu\n", map->vm_start, map->vm_end);

	r = vmad_store_arch_map(dest, tsk, map, flags);
	if (r < 0) 
		return r;
	else if(r > 0)
		return 0;

	if (map->vm_flags & VM_IO) { return 0; }
	is_anon = map->anon_vma && !(map->vm_file) && !(map->vm_flags & VM_GROWSDOWN);
	head.start   = map->vm_start;
	head.end     = map->vm_end;
	head.flags   = map->vm_flags;
	head.namelen = 0;
	head.pgoff   = map->vm_pgoff;
	head.is_heap = is_anon;


	if (map->vm_file) {
		buffer = (char *) __get_free_page(GFP_KERNEL);
		if (!buffer) { return -ENOMEM; }

		filename = default_map_name(map->vm_file, buffer, PAGE_SIZE);
		head.namelen = strlen(filename);

		if (vmad_is_special_mmap(tsk, map, flags)) {
			/* Let BLCR deal with it */
			free_page((long)buffer);
			return 0;
		} else if (vmad_dentry_unlinked(map->vm_file->f_dentry)) {
			/* Region is an unlinked file - store contents, not filename */
			head.namelen = 0;
		} else if (vmad_is_exe(map)) {
			/* Region is an executable */
			if (flags & VMAD_DUMP_EXEC)
				head.namelen = 0;
		} else if (is_library(filename)) {
			/* Region is a library */
			if (flags & VMAD_DUMP_LIBS)
				head.namelen = 0;
		} else {
			/* Region is something else */
			if (flags & VMAD_DUMP_OTHER)
				head.namelen=0;
		}
		isfilemap = 1;
	}

	start     = map->vm_start;
	end       = map->vm_end;
	/* Release the mm_sem here to avoid deadlocks with page faults and
	* write locks that may happen during the writes.  (We can't use
	* the "map" pointer beyond this point. */
	up_read(&tsk->mm->mmap_sem);

	/* Spit out the section header */
	r = dest->write((char *) &head, sizeof(head));
	if (r) goto err;

	if (head.namelen > 0) {
		/* Store the filename */
		r = dest->write((char *) filename, head.namelen);
		if (r) goto err;

		r = store_page_list(dest, tsk, map, 0, addr_copied);
		if (r) goto err;
	} else {
		/* Store the contents of the VMA as defined by start, end */
		r = store_page_list(dest, tsk, map, is_anon,
			isfilemap ? addr_nonzero_file : addr_nonzero);
		if (r) goto err;

	}

	if (buffer)   free_page((long)buffer);
	down_read(&tsk->mm->mmap_sem);
	return 0;

 err:
	if (r) r = -EIO;	/* Map short writes to EIO */
	if (buffer)   free_page((long)buffer);
	down_read(&tsk->mm->mmap_sem);
	return r;
}

static int import_context_struct(struct restart_src_t *src, struct mm_struct *mm)
{
	int r = 0;

#ifndef CONFIG_USERMODE

	if (mm->context.ldt) {
		int orig_size = mm->context.size;

		mm->context.ldt = NULL;
		mm->context.size = 0;

		r = alloc_ldt (&mm->context, orig_size, 0);
		if (r < 0)
			return r;

		r = src->read(mm->context.ldt,
			       mm->context.size * LDT_ENTRY_SIZE);
		if (r)
			goto exit;
	}

	mutex_init(&mm->context.lock);
#endif
exit:
	return r;
}

int export_context_struct (struct checkpoint_dest_t *dest, struct mm_struct *mm)
{
	int r = 0;

#ifndef CONFIG_USERMODE
	if (mm->context.ldt) {
		r = dest->write((char *)	mm->context.ldt,
				mm->context.size * LDT_ENTRY_SIZE);
		if (r)
			goto err;
	}
#endif
err:
	return r;
}

int cr_export_mm_struct(struct checkpoint_dest_t *dest, struct task_struct *tsk)
{
	int r = 0;
	struct vm_area_struct     *map, *next_map;
	struct mm_struct          *mm = tsk->mm;
	struct vmadump_vma_header  term;
	unsigned long              next_addr;
	int flags = 0;

	if(dest->flags != EOS_SIG_JUMP_MIGRATE) {
		down_read(&mm->mmap_sem);
		r = dest->write((char *) mm, sizeof(struct mm_struct));
		if (r) {
			up_read(&mm->mmap_sem);
			goto err;
		}
		r = export_context_struct(dest, mm);
		up_read(&mm->mmap_sem);
		if (r) 
			goto err;
	}

	down_read(&mm->mmap_sem);
	next_map = mm->mmap;
	next_addr = next_map ? next_map->vm_start : 0;
	while (next_map) {
		map = find_vma(mm, next_addr);
		if (map != next_map) break;
		next_map = map->vm_next;
		next_addr = next_map ? next_map->vm_start : 0;
		if(((dest->flags == EOS_SIG_JUMP_MIGRATE) && (map->vm_flags & VM_GROWSDOWN)) ||
			(dest->flags != EOS_SIG_JUMP_MIGRATE)) {
			r = store_map(dest, tsk, map, flags);
			if (r) {
				up_read(&mm->mmap_sem);
				goto err;
			}
		}
	}
	up_read(&mm->mmap_sem);

	/* Terminate maps list */
	term.start = term.end = ~0L;
	r = dest->write((char *) &term, sizeof(term));
	if (r) 
		goto err;

	return 0;

err:
	return -1;

}

int reinit_mm(struct mm_struct *mm)
{
	if (!mm_init(mm, NULL))
		return -ENOMEM;
	mm->locked_vm = 0;
	mm->mmap = NULL;
	mm->mmap_cache = NULL;
	mm->map_count = 0;
	cpus_clear (mm->cpu_vm_mask);
	mm->mm_rb = RB_ROOT;
	mm->nr_ptes = 0;
	mm->token_priority = 0;
	mm->last_interval = 0;
	memset(&mm->mmap_sem, 0, sizeof(mm->mmap_sem));
	init_rwsem(&mm->mmap_sem);
	memset(&mm->page_table_lock, 0, sizeof(mm->page_table_lock));
	spin_lock_init(&mm->page_table_lock);
	/* Insert the new mm struct in the list of active mm */
	spin_lock (&mmlist_lock);
	list_add (&mm->mmlist, &init_mm.mmlist);
	spin_unlock (&mmlist_lock);
	mm->task_size  = TASK_SIZE;
#ifdef CONFIG_PROC_FS
	mm->exe_file = NULL;
	mm->num_exe_file_vmas = 0;
#endif
	//arch_pick_mmap_layout(mm);
	return 0;
}

static inline int do_import_mm_struct(struct restart_src_t *src, struct mm_struct **returned_mm)
{
	struct mm_struct *mm;
	int r = 0;

	mm = allocate_mm();
	if (!mm)
	  goto done;

	r = src->read (mm, sizeof (struct mm_struct));
	if (r)
	  goto exit_free_mm;

	r = reinit_mm(mm);
	if (r)
	  goto exit_free_mm;
done:
	if (!mm)
		return -ENOMEM;

	*returned_mm = mm;

	return r;

exit_free_mm:
	free_mm(mm);
	return r;
}

#define test_thread_flag_task(flag) \
	test_ti_thread_flag(task_thread_info(tsk), flag)

int vmad_remap(unsigned long a, unsigned long b, unsigned long c)
{
return 0;
}

int vmad_load_arch_map(struct restart_src_t *src, struct task_struct *tsk,
		       struct vmadump_vma_header *head)
{
	long r;
	void *sysenter_return;

	/* Save against overwrite by arch_setup_additional_pages() */
	sysenter_return = task_thread_info(tsk)->sysenter_return;	tsk->mm->context.vdso = (void *)(~0UL); // will be overwritten by my_arch_setup_additional_pages()

	r = __arch_setup_additional_pages(tsk, NULL, 0, head->start);

	if (r < 0) {
		printk("arch_setup_additional_pages failed %d\n", (int)r);
		goto err;
	}

	/* Call above should have overwritten tsk->mm->context.vdso with a new value.
	* Relocate if needed here.
	*/
	if (tsk->mm->context.vdso == (void *)(~0UL)) {
		/* The call above didn't overwrite mm->context.vdso.
		* Since no failure was indictated we just fill it in.
		*/
		tsk->mm->context.vdso = (void *)head->start;
	} else if (tsk->mm->context.vdso != (void *)head->start) {
		r = vmad_remap((unsigned long)tsk->mm->context.vdso, head->start, head->end - head->start);
		if (r) {
			printk("vdso remap failed %d\n", (int)r);
			goto err;
		}
		tsk->mm->context.vdso = (void *)head->start;
	}

	task_thread_info(tsk)->sysenter_return = sysenter_return;
	r = 0;
err:
    return r;
}

/*
int vmadump_load_page_list(struct restart_src_t *src, struct task_struct *tsk, int is_exec)
{
	unsigned long magic = 0;
	unsigned long address = 0;
	struct page *pg;
	struct vm_area_struct *vma;
	void *pg_address;
	int res = 0;
	
	src->read(&magic, sizeof(magic));
	while(magic != VMAD_DUMP_PAGESDONE_MAGIC)
	{
		src->read(&address, sizeof(address));
		vma = find_vma(tsk->mm, address);
		if(vma) 
		{
			pte_t *pte = pte_by_address(tsk->mm, address);

			if (pte)
			{
				struct page* pg = NULL;

				if(pte_present(*pte)) {
					pg = pte_page(*pte);
					pg_address = kmap(pg);
					src->read(pg_address, PAGE_SIZE);
					kunmap(pg);

				} 
				else if(pte_none(*pte) || !pte_present(*pte)) {	
					res = get_user_pages(tsk, tsk->mm, address, 1, 1, 1, &pg, NULL);
					if(res == 1) {
						pg_address = kmap(pg);
						src->read(pg_address, PAGE_SIZE);
						kunmap(pg);
						put_page(pg);
					}
				}					
			} 
		}
		else 
		{
			printk("EOS(vmadump_load_page_list): Could not find vma at address %lu\n", address);
			return -1;
		}
		src->read(&magic, sizeof(magic));
	}

	return 0;
} */

int vmadump_load_page_list(struct restart_src_t *src, struct task_struct *tsk, int is_exec)
{
	unsigned long magic = 0;
	unsigned long address = 0;
	struct page *pg;
	struct vm_area_struct *vma;
	void *pg_address;
	int res = 0;
	
	src->read(&magic, sizeof(magic));
	while(magic != VMAD_DUMP_PAGESDONE_MAGIC)
	{
		src->read(&address, sizeof(address));
		if(log_eos_messages) printk("Loading page at address: %lu\n", address);
		vma = find_vma(tsk->mm, address);
		if(vma) {

			if(src->flags == EOS_SIG_JUMP_MIGRATE)
			{
				pte_t *pte = pte_by_address(tsk->mm, address);

				if (pte)
				{
					struct page* pg = NULL;

					if(pte_present(*pte)) {
						pg = pte_page(*pte);
						pg_address = kmap(pg);
						src->read(pg_address, PAGE_SIZE);
						kunmap(pg);

					} 
					else if(pte_none(*pte) || !pte_present(*pte)) {	
						res = get_user_pages(tsk, tsk->mm, address, 1, 1, 1, &pg, NULL);
						if(res == 1) {
							pg_address = kmap(pg);
							src->read(pg_address, PAGE_SIZE);
							kunmap(pg);
							put_page(pg);
						}
					} else {
						printk("Should not happen. Address: %lu\n", address);
					}					
				} 
				else {
					if(log_eos_messages) printk("!pte. Address: %lu\n", address);

					res = get_user_pages(tsk, tsk->mm, address, 1, 1, 1, &pg, NULL);
					if(res == 1) {
						pg_address = kmap(pg);
						src->read(pg_address, PAGE_SIZE);
						kunmap(pg);
						put_page(pg);
					}
					else {
						printk("EOS(vmadump_load_page_list - first location): Could not find page at address %lu. Here are the memory maps:\n", address);
						print_mmaps(tsk);
						return -1;
					}
				}
			}
			else 
			{
				res = get_user_pages(tsk, tsk->mm, address, 1, 1, 1, &pg, NULL);
				if(res == 1) {
					pg_address = kmap(pg);
					src->read(pg_address, PAGE_SIZE);
					kunmap(pg);
					put_page(pg);
				}
				else {
					printk("EOS(vmadump_load_page_list - first location): Could not find page at address %lu. Here are the memory maps:\n", address);
					print_mmaps(tsk);
					return -1;
				}
			}

		}
		else {
			printk("EOS(vmadump_load_page_list -  Second location): Could not find vma at address %lu. Here are the memory maps:\n", address);
			print_mmaps(tsk);
			return -1;
		}
		src->read(&magic, sizeof(magic));
	}

	return 0;
}

unsigned long cr_mmap_pgoff(struct file *file, unsigned long addr,
	unsigned long len, unsigned long prot,
	unsigned long flag, unsigned long pgoff){
	return 0;
}

/*
static
struct file *default_map_open(const char *filename, int flags)
{
	return filp_open(filename, flags, 0);
}
*/

static
int mmap_file(struct task_struct *tsk, const struct vmadump_vma_header *head, char *filename,
	      unsigned long flags){
	struct file *file;
	long mapaddr;
	int open_flags;
	unsigned long prot;

	if (head->flags & VM_MAYSHARE) {
		if (head->flags & VM_MAYWRITE) {
			open_flags = (head->flags & (VM_MAYREAD|VM_MAYEXEC)) ? O_RDWR : O_WRONLY;
			prot = PROT_WRITE;
		} else {
			open_flags = O_RDONLY;
			prot = 0;
		}
		if (head->flags & VM_MAYREAD)  prot |= PROT_READ;
		if (head->flags & VM_MAYEXEC)  prot |= PROT_EXEC;
	} else {
		open_flags = O_RDONLY;
		prot = PROT_READ|PROT_WRITE|PROT_EXEC;
	}

	file = filp_open(filename, open_flags, 0);
	if (IS_ERR(file)) {
		printk("open('%s', 0x%x) failed: %d\n", filename, open_flags, (int)PTR_ERR(file));
		return PTR_ERR(file);
	}

	//down_write(&tsk->mm->mmap_sem);
	mapaddr = do_mmap_pgoff_task(tsk, file, head->start, head->end - head->start,
			prot, flags, head->pgoff);
	//up_write(&tsk->mm->mmap_sem);
	fput(file);
	if (mapaddr != head->start)
		printk("mmap(<file>, %p, %p, ...) failed: %p\n",
			(void *) head->start, (void *) (head->end-head->start),
			(void *) mapaddr);
	return (mapaddr == head->start) ? 0 : mapaddr;
}

static
int load_map(struct restart_src_t *src, struct task_struct *tsk, struct vmadump_vma_header *head) {
    long r;
    unsigned long mmap_prot, mmap_flags, addr;

    if(log_eos_messages) printk("Process Import: Loading vmap starts at : %lu, and ends at: %lu\n", head->start, head->end);

    if (head->namelen == VMAD_NAMELEN_ARCH) {
	return vmad_load_arch_map(src, tsk, head);
    }

    mmap_prot  = 0;
    mmap_flags = MAP_FIXED | ((head->flags & VM_MAYSHARE) ? MAP_SHARED : MAP_PRIVATE);
    if (head->flags & VM_READ)  mmap_prot |= PROT_READ;
    if (head->flags & VM_WRITE) mmap_prot |= PROT_WRITE;
    if (head->flags & VM_EXEC)  mmap_prot |= PROT_EXEC;
    if (head->flags & VM_GROWSDOWN) mmap_flags |= MAP_GROWSDOWN;
    if (head->flags & VM_EXECUTABLE) mmap_flags |= MAP_EXECUTABLE;
    if (head->flags & VM_DENYWRITE) mmap_flags |= MAP_DENYWRITE;

    if (head->namelen > 0) {
	char *filename;
	if (head->namelen > PAGE_SIZE) {
	    printk("thaw: bogus namelen %d\n", (int) head->namelen);
	    return -EINVAL;
	}
	filename = kmalloc(head->namelen+1,GFP_KERNEL);
	if (!filename) {
	    r = -ENOMEM;
	    goto err;
	}
	r = src->read(filename, head->namelen);
	if (r) {
	    kfree(filename);
	    goto err;
	}
	filename[head->namelen] = 0;

	r = mmap_file(tsk, head, filename, mmap_flags);
	if (r) {
	    printk("mmap failed: %s\n", filename);
	    kfree(filename);
	    return r;
	}
	kfree(filename);
    } else {
	/* Load the data from the dump file */
	addr = do_mmap_pgoff_task(tsk, 0, head->start, head->end - head->start, mmap_prot|PROT_WRITE, mmap_flags, 0);
	if (addr != head->start) {
	    printk("mmap(0, %08lx, %08lx, ...) = 0x%08lx (failed)\n", head->start, head->end - head->start, addr);
            if ((addr != head->start) && IS_ERR((void *) addr)) {
                r = PTR_ERR((void *) addr);
            } else {
                r = -EINVAL;
            }

	    return r;
	}

	if(head->is_heap)
	{
		struct vm_area_struct *new_vma = find_vma(tsk->mm, head->start);
		if(new_vma)
		{
			anon_vma_prepare(new_vma);
		}
	}
    }

    /* Read in patched pages */
    r = vmadump_load_page_list(src, tsk, (mmap_prot & PROT_EXEC));
    if (r) goto err;

    if (__mprotect_task(tsk,head->start,head->end - head->start, mmap_prot))
	printk("thaw: mprotect failed. (ignoring)\n");
    return 0;

 err:
    if (r >= 0) r = -EIO;	/* map short reads to EIO */
    return r;
}

void iterate_through_pages(struct vm_area_struct *vma) {
    
    unsigned long start = vma->vm_start, addr = 0, end = vma->vm_end;
    for (addr = start; addr < end; addr += PAGE_SIZE) {
        /* The topmost if clause (need_to_save) is to identify things like 
         * unmodified pages that can be reread from disk, or pages that were 
         * allocated and never touched (zero pages).  */

        pte_t *pte = pte_by_address(vma->vm_mm, addr);

        if (pte) {
            if (pte_present(*pte)) {
		struct page *page;
                //printk("pte at addr: %lu is present\n", addr);


		
		page = pte_page(*pte);      	
 		if(log_eos_messages) printk("iterate_through_pages(before) pfn:%lu mpc:%d pc:%d (%s%s%s%s)\n", page_to_pfn(page), page_mapcount(page),
                            page_count(page), PageLRU(page) ? "lru|" : "", PageSwapCache(page) ? "swap_cache|" : "",
                            PageActive(page) ? "active|" : "", PageReferenced(page) ? "referenced|" : "");
		set_pte_at(vma->vm_mm, (addr & PAGE_MASK), pte, (pte_t) {0});
		dec_mm_counter(vma->vm_mm, MM_ANONPAGES);
                //printk("Removing rmap\n");
                page_remove_rmap(page);
                //printk("Releasing page\n");
                release_pages(&page, 1, 1);

		if(log_eos_messages) printk("iterate_through_pages(after) pfn:%lu mpc:%d pc:%d (%s%s%s%s)\n", page_to_pfn(page), page_mapcount(page),
                            page_count(page), PageLRU(page) ? "lru|" : "", PageSwapCache(page) ? "swap_cache|" : "",
                            PageActive(page) ? "active|" : "", PageReferenced(page) ? "referenced|" : "");

            } else if (pte_none(*pte)) {
                //printk("pte at addr: %lu is none\n", addr);
            } else { // page allocated but not present (i.e. swapped out). Fault it in and save it.
                //printk("pte at addr: %lu is NOT present\n", addr);
            }
        }

    }
}

static inline int import_vmas(struct restart_src_t *src, struct task_struct *tsk)
{
	int r = 0;
	//struct mm_struct *mm;
	//struct vm_area_struct *map;
	//struct vmadump_mm_info mm_info;
	struct vmadump_vma_header mapheader;

	if(src->flags == EOS_SIG_JUMP_MIGRATE) {

		struct vm_area_struct     *map, *next_map;
		struct mm_struct          *mm = tsk->mm;
		unsigned long              next_addr;

		down_read(&mm->mmap_sem);
		next_map = mm->mmap;
		next_addr = next_map ? next_map->vm_start : 0;
		while (next_map) {
			map = find_vma(mm, next_addr);
			if (map != next_map) break;
			next_map = map->vm_next;
			next_addr = next_map ? next_map->vm_start : 0;
			if(map->vm_flags & VM_GROWSDOWN) {
				iterate_through_pages(map);
				break;
			}
		}
		up_read(&mm->mmap_sem);
	}

	if(0) {//src->flags == EOS_SIG_JUMP_MIGRATE) {

		struct vm_area_struct     *map, *next_map;
		struct mm_struct          *mm = tsk->mm;
		unsigned long              next_addr;

		down_read(&mm->mmap_sem);
		next_map = mm->mmap;
		next_addr = next_map ? next_map->vm_start : 0;
		while (next_map) {
			map = find_vma(mm, next_addr);
			if (map != next_map) break;
			next_map = map->vm_next;
			next_addr = next_map ? next_map->vm_start : 0;
			if(map->vm_flags & VM_GROWSDOWN) {
				do_munmap(mm, map->vm_start, map->vm_end - map->vm_start);
				break;
			}
		}
		up_read(&mm->mmap_sem);
	}
	
	r = src->read(&mapheader, sizeof(mapheader));
	while (!r && (mapheader.start != ~0 || mapheader.end != ~0)) {
		r = load_map(src, tsk, &mapheader);
		if (r) 
			goto bad_read;
		r = src->read(&mapheader, sizeof(mapheader));
	}

	if(0){//src->flags == EOS_SIG_JUMP_MIGRATE) {

		struct vm_area_struct     *map, *next_map;
		struct mm_struct          *mm = tsk->mm;
		unsigned long              next_addr;

		down_read(&mm->mmap_sem);
		next_map = mm->mmap;
		next_addr = next_map ? next_map->vm_start : 0;
		while (next_map) {
			map = find_vma(mm, next_addr);
			if (map != next_map) break;
			next_map = map->vm_next;
			next_addr = next_map ? next_map->vm_start : 0;
			if(map->vm_flags & VM_GROWSDOWN) {
				iterate_through_pages(map);
				break;
			}
		}
		up_read(&mm->mmap_sem);
	}


bad_read:
	return r;
}

int import_mm_struct (struct restart_src_t *src, struct task_struct *tsk)
{
	struct mm_struct *mm = NULL;
	int r;

	if(src->flags != EOS_SIG_JUMP_MIGRATE){

		r = do_import_mm_struct (src, &mm);
		if (r)
			return r;

		tsk->mm = mm;
		tsk->active_mm = mm;

		/* Import context */
		r = import_context_struct(src, mm);
		if (unlikely (r < 0))
			goto err;

		/* Just paranoia check */
		BUG_ON(mm->core_state);
	}

#if 0
#ifdef CONFIG_KRG_DVFS
	r = import_mm_exe_file(action, ghost, tsk);
	if (r)
		goto err;
#endif
#endif
	r = import_vmas(src, tsk);
	if (r < 0)
		goto err;

/*

	r = import_mm_counters(action, ghost, mm);
	if (r)
		goto err;

	mm->hiwater_rss = get_mm_rss(mm);
	mm->hiwater_vm = mm->total_vm;

	if (action->type == EPM_REMOTE_CLONE
	    && !(action->remote_clone.clone_flags & CLONE_VM))
		mm->locked_vm = 0;

	if (action->type == EPM_CHECKPOINT)
		r = cr_import_process_pages(action, ghost, mm);
	else
		r = import_mm_struct_end(mm, tsk);

	if (r)
		goto err;

	set = mm->anon_vma_kddm_set;

	krg_put_mm (mm->mm_id);

	return 0;
*/

err:
/*
	krg_put_mm (mm->mm_id);
	unimport_mm_struct(tsk);
*/
	return r;
}

