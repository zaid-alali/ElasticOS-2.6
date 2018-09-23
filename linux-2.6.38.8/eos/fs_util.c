#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/mnt_namespace.h>
#include <linux/dcache.h>
#include <linux/fs_struct.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/path.h>
#include <linux/time.h>
#include <linux/rcupdate.h>
#include <linux/module.h>	/* Needed by all modules */
#include <linux/kernel.h>	/* Needed for KERN_INFO */
#include <linux/slab.h>
#include <linux/fdtable.h>
#include <linux/sched.h>
#include <linux/major.h>
#include <linux/file.h>
#ifdef CONFIG_X86_64
#include <asm/ia32.h>
#endif
#include <linux/namei.h>
#include <linux/dcache.h>

#include <eos/checkpoint_util.h>

#include "fs_util.h"




#define CR_KMEM_CACHE(__struct) KMEM_CACHE(__struct, SLAB_POISON)
#define MAP_SIZE 64
#define MAP_SHIFT 6
#define CR_NO_LOCKS() ((void)0)

#define cr_set_open_fd(_fd,_fdt)	FD_SET(_fd,(_fdt)->open_fds)
#define cr_clear_open_fd(_fd,_fdt)	FD_CLR(_fd,(_fdt)->open_fds)
#define cr_read_open_fd(_fd,_fdt)	FD_ISSET(_fd,(_fdt)->open_fds)

#define cr_set_close_on_exec(_fd,_fdt)	FD_SET(_fd,(_fdt)->close_on_exec)
#define cr_clear_close_on_exec(_fd,_fdt)	FD_CLR(_fd,(_fdt)->close_on_exec)
#define cr_read_close_on_exec(_fd,_fdt)	FD_ISSET(_fd,(_fdt)->close_on_exec)

#if defined(CONFIG_SLUB) && defined(SLAB_POISON)
#define CR_KMEM_CACHE(__struct) KMEM_CACHE(__struct, SLAB_POISON)
#else
#define CR_KMEM_CACHE(__struct) KMEM_CACHE(__struct, 0)
#endif

#define CR_NEXT_FD(_files, _fdt) ((_files)->next_fd)


char *physical_d_path(const struct path *path, char *tmp)
{
	struct path ns_root;
	char *pathname;
	//bool deleted;

	/* Mnt namespace is already pinned by path->mnt */
	if (!path->mnt->mnt_ns)
		/* Not exportable */
		return NULL;

	ns_root.mnt = path->mnt->mnt_ns->root;
	ns_root.dentry = ns_root.mnt->mnt_root;
	//spin_lock(&dcache_lock);
	pathname = __d_path(path, &ns_root, tmp, PAGE_SIZE);
	//spin_unlock(&dcache_lock);
	BUG_ON(ns_root.mnt != path->mnt->mnt_ns->root
	       || ns_root.dentry != ns_root.mnt->mnt_root);

	if (IS_ERR(pathname))
		return NULL;

	return pathname;
}

/* Caller is responsible for path_get()/path_put() */
/*
static char *
cr_getpath(struct path *path, char *buf, int size)
{
	char *name = NULL;

	if (path->dentry == NULL) {
		printk("path->dentry is NULL!\n");
		goto out;
	}
	if (path->mnt == NULL) {
		printk("path->vfsmnt is NULL!\n");
		goto out;
	}

	name = d_path(path, buf, size);

out:
	return name;
}
*/

int export_fs_struct (struct checkpoint_dest_t *dest, struct task_struct *tsk)
{
	char *tmp, *file_name;
	int r, len;


	return 0; // for now we will use the fs struct from the baby sitter!

	r = -ENOMEM;
	tmp = (char *) __get_free_page (GFP_KERNEL);
	if (!tmp)
		goto err_write;

	{
		int magic = 55611;

		r = dest->write((char*) &magic, sizeof (int));
		if (r)
			goto err_write;
	}

	/* Export the umask value */
	r = dest->write((char*) &tsk->fs->umask, sizeof (int));
	if (r)
			goto err_write;

	/* Export the root path name */
	file_name = physical_d_path(&tsk->fs->root, tmp);
	if (!file_name) {
		r = -ENOENT;
		goto err_write;
	}

	len = strlen (file_name) + 1;
	r = dest->write((char*) &len, sizeof (int));
	if (r)
			goto err_write;
	r = dest->write(file_name, len);
	if (r)
			goto err_write;

	/* Export the pwd path name */
	file_name = physical_d_path(&tsk->fs->pwd, tmp);
	if (!file_name) {
		r = -ENOENT;
		goto err_write;
	}

	len = strlen (file_name) + 1;
	r = dest->write((char*) &len, sizeof (int));
	if (r)
			goto err_write;
	r = dest->write((char*) file_name, len);
	if (r)
			goto err_write;

	{
		int magic = 180574;

		r = dest->write((char*) &magic, sizeof (int));
	}

err_write:
	free_page ((unsigned long) tmp);

	return r;
}


static inline int import_file_name(struct restart_src_t *src, char *buffer)
{
	int len = 0;
	int r = 0;
	r = src->read(&len, sizeof(int));
	if (r)
		return -1;

	r = src->read(buffer, len);
	if (r)
		return -1;

	return len;
}

static int
change_pwd_fs(struct fs_struct *fs, const char *name)
{
	int retval;
	struct path path;

	retval = kern_path(name, LOOKUP_FOLLOW|LOOKUP_DIRECTORY, &path);
	if (retval)
		goto out;

	retval = inode_permission(path.dentry->d_inode, MAY_EXEC|MAY_CHDIR);
	if (retval)
		goto out_put;

	set_fs_pwd(fs, &path);

out_put:
	path_put(&path);
out:
	return retval;
}

int import_fs_struct (struct restart_src_t *src, struct task_struct *tsk)
{
	struct fs_struct *fs;
	char *buffer;
	int len = 0;
	char *file_name;
	int r;

	tsk->fs = baby_sitter->fs;
	
	return copy_fs_task(baby_sitter, CLONE_FS, tsk);

	buffer = (char *)__get_free_page(GFP_KERNEL);
	if (!buffer)
		return -ENOMEM;

	{
		int magic = 0;

		r = src->read(&magic, sizeof (int));
		BUG_ON (!r && magic != 55611);
	}

	r = -ENOMEM;
	fs = kmem_cache_alloc(fs_cachep, GFP_KERNEL);
	if (fs == NULL)
		goto exit;

	fs->users = 1;
	fs->in_exec = 0;
	spin_lock_init(&fs->lock);

	/* Import the umask value */

	r = src->read(&fs->umask, sizeof (int));
	if (r)
		goto exit_free_fs;

	/* Import the root path name */
	len = import_file_name(src, buffer);
	if(len < 0)
		goto exit_free_fs;
	file_name = buffer;

	/* Import the pwd path name */
	len = import_file_name(src, buffer);
	if(len < 0)
		goto exit_free_fs;
	file_name = buffer;

	change_pwd_fs(fs, file_name);

	{
		int magic = 0;

		r = src->read(&magic, sizeof (int));
		BUG_ON (!r && magic != 180574);
	}

	tsk->fs = fs;

exit:
	free_page ((unsigned long) buffer);

	return r;

//exit_put_root:
	path_put(&fs->root);

exit_free_fs:
	kmem_cache_free (fs_cachep, fs);
	goto exit;
}

struct cr_objectmap_s {
    struct cr_objectmap_entry_s {
        rwlock_t lock;
        struct list_head list;
    } table[MAP_SIZE];
};


typedef struct cr_objectmap_s *cr_objectmap_t;

/* doubly linked list of key=val pairs */
struct cr_objectmap_pair { /* No "_s" suffix to fit kmem_cache naming requirements */
    struct list_head list;
    void *key;
    void *val;
};

/* Map is an array of lock+list pairs */

typedef struct kmem_cache *cr_kmem_cache_ptr;

static cr_kmem_cache_ptr cr_objmap_cachep = NULL;
static cr_kmem_cache_ptr cr_object_cachep = NULL;

int
cr_object_init(void) {
    cr_objmap_cachep = CR_KMEM_CACHE(cr_objectmap_s);
    if (!cr_objmap_cachep) goto no_objmap_cachep;
    cr_object_cachep = CR_KMEM_CACHE(cr_objectmap_pair);
    if (!cr_object_cachep) goto no_object_cachep;
    return 0;

no_object_cachep:
    kmem_cache_destroy(cr_objmap_cachep);
no_objmap_cachep:
    return -ENOMEM;
}

void
cr_object_cleanup(void) {
    if (cr_objmap_cachep) kmem_cache_destroy(cr_objmap_cachep);
    if (cr_object_cachep) kmem_cache_destroy(cr_object_cachep);
}

static
int hash_it(void *x) {
    unsigned long tmp = (unsigned long) x;
    tmp = tmp ^ (tmp >> MAP_SHIFT) ^ (tmp >> (MAP_SHIFT * 2));
    return (int) (tmp % MAP_SIZE);
}

cr_objectmap_t
cr_alloc_objectmap(void) {
    static struct lock_class_key lock_key;
    struct cr_objectmap_s *map = kmem_cache_alloc(cr_objmap_cachep, GFP_KERNEL);

    if (map) {
        int i;
        struct cr_objectmap_entry_s *entry;
        for (i = 0, entry = &map->table[0]; i < MAP_SIZE; ++i, ++entry) {
            rwlock_init(&(entry->lock));
            lockdep_set_class(&(entry->lock), &lock_key);
            INIT_LIST_HEAD(&(entry->list));
        }
    }

    return map;
}

void
cr_release_objectmap(cr_objectmap_t map) {
    int i;
    struct cr_objectmap_entry_s *entry;

    for (i = 0, entry = &map->table[0]; i < MAP_SIZE; ++i, ++entry) {
        struct cr_objectmap_pair *pair, *next;

        list_for_each_entry_safe(pair, next, &(entry->list), list) {
            kmem_cache_free(cr_object_cachep, pair);
        }
    }
    kmem_cache_free(cr_objmap_cachep, map);
}

/*
 * returns int rather than void * to allow NULL key's to be placed into table
 *
 * 1 - found
 * 0 - not found (but *val_p still may be written)
 */
int
cr_find_object(cr_objectmap_t map, void *key, void **val_p) {
    int retval = 0;

    /* result is NULL by default, use return value to distinguish good NULL from evil NULL */
    if (val_p != NULL) {
        *val_p = NULL;
    }

    if (key == NULL) {
        /* special cased to avoid confusion with not present */
        // CR_KTRACE_LOW_LVL("map %p: Asked for NULL, returning NULL.", map);
        retval = 1;
    } else {
        int h = hash_it(key);
        struct cr_objectmap_entry_s *entry = &map->table[h];
        struct cr_objectmap_pair *pair;

        read_lock(&(entry->lock));

        list_for_each_entry(pair, &(entry->list), list) {
            if (pair->key == key) {
                // CR_KTRACE_LOW_LVL("map %p: Found object %p in slot %d", map, key, h);
                if (val_p != NULL)
                    *val_p = pair->val;
                retval = 1;
                break;
            } else if (pair->key > key) {
                /* Sorted order would have placed pair here */
                break;
            }
        }
        read_unlock(&(entry->lock));

        // if (!retval) CR_KTRACE_LOW_LVL("map %p: Object %p not found", map, key);
    }

    return retval;
}

/*
 *  1 if it's in there already 
 *  0 if we insert it
 */
int
cr_insert_object(cr_objectmap_t map, void *key, void *val, gfp_t flags) {
	struct cr_objectmap_pair *new_pair, *pair;
	int retval = -1;
	int h = hash_it(key);
	struct cr_objectmap_entry_s *entry = &map->table[h];

	/* If not GFP_ATOMIC, we'd better not hold any locks */
	if (flags != GFP_ATOMIC) CR_NO_LOCKS();

	/* special case NULL -> NULL */
	if (key == NULL) {
		retval = 1;
		return retval;
	}

	/* assume it's not there yet to move alloc outside of lock and keep a single pass */
	new_pair = kmem_cache_alloc(cr_object_cachep, flags);
	new_pair->key = key;
	new_pair->val = val;

	write_lock(&(entry->lock));

	list_for_each_entry(pair, &(entry->list), list) {
	if (pair->key == key) {
		/* return 1 if it's in there already */
		// CR_KTRACE_LOW_LVL("map %p: Object %p already inserted into slot %d", map, key, h);
		retval = 1;
		break;
	} else if (pair->key > key) {
			/* Sorted order places new pair here */
			break;
		}
	}
	if (retval != 1) {
		// CR_KTRACE_LOW_LVL("map %p: Inserting object %p into slot %d", map, key, h);
		list_add_tail(&new_pair->list, &pair->list);
		retval = 0;
	}
	write_unlock(&(entry->lock));

	if (retval) {
		kmem_cache_free(cr_object_cachep, new_pair);
	}

	return retval;
}

/*
 *  0 if we remove it
 *  -1 if it's not in there
 */
int
cr_remove_object(cr_objectmap_t map, void *key) {
	struct cr_objectmap_pair *pair, *next;
	struct cr_objectmap_entry_s *entry = &map->table[hash_it(key)];
	int retval = -1;

	write_lock(&(entry->lock));

	list_for_each_entry_safe(pair, next, &(entry->list), list) {
		if (pair->key == key) {
			list_del(&pair->list);
			kmem_cache_free(cr_object_cachep, pair);
			retval = 1;
			break;
		}
	}
	write_unlock(&(entry->lock));

	return retval;
}

int cr_save_files_struct(struct checkpoint_dest_t *dest, struct files_struct *files) {
	struct fdtable *fdt;
	struct cr_files_struct cr_fs;
	int retval = 0;

	cr_fs.cr_obj = cr_files_obj;

	rcu_read_lock();
	fdt = files_fdtable(files); 
	cr_fs.cr_max_fds = fdt->max_fds;
	cr_fs.cr_next_fd = CR_NEXT_FD(files, fdt);
	rcu_read_unlock();

	dest->write(&cr_fs, sizeof(cr_fs));

	retval = cr_fs.cr_max_fds;
	return retval;
}

static inline int vmad_dentry_unlinked(struct dentry *dentry) {
	return ((!IS_ROOT(dentry) && d_unhashed(dentry)) ||
		(dentry->d_inode->i_nlink == 0) ||
		(dentry->d_flags & DCACHE_NFSFS_RENAMED));
}

static int
cr_get_file_info(cr_objectmap_t map, struct file *filp, struct cr_file_info *file_info) {
	struct dentry *dentry = filp->f_dentry;
	file_info->unlinked = vmad_dentry_unlinked(dentry);

	if (cr_insert_object(map, file_info->orig_filp, file_info->orig_filp, GFP_KERNEL)) {
		/* Was in the object table (and thus is dup) */
		file_info->cr_file_type = cr_open_dup;
	} else {
		switch (dentry->d_inode->i_mode & S_IFMT) {
			case S_IFREG:
				file_info->cr_file_type = cr_open_file;
				break;
			case S_IFDIR:
				file_info->cr_file_type = cr_open_directory;
				break;
			case S_IFLNK:
				file_info->cr_file_type = cr_open_link;
				break;
			case S_IFIFO:
				file_info->cr_file_type = cr_open_fifo;
				break;
			case S_IFSOCK:
				file_info->cr_file_type = cr_open_socket;
				break;
			case S_IFCHR:
				file_info->cr_file_type = cr_open_chr;
				break;
			case S_IFBLK:
				file_info->cr_file_type = cr_open_blk;
				break;
			default: /* completely unknown */
				file_info->cr_file_type = cr_unknown_file;
		}
	}

	return 0;
}

static int
cr_get_fd_info(struct files_struct *files, int fd, struct cr_file_info *file_info) {
	struct fdtable *fdt;

	rcu_read_lock();
	fdt = files_fdtable(files); //cr_fdtable(files);
	if (cr_read_open_fd(fd, fdt)) {
		file_info->fd = fd;
		file_info->cloexec = cr_read_close_on_exec(fd, fdt);
		file_info->orig_filp = fcheck(fd);
	} else {
		printk("cr_get_fd_info: Called on closed file!");
	}
	rcu_read_unlock();

	return 0;
}

static int
cr_save_file_info(struct checkpoint_dest_t *dest, struct cr_file_info *file_info) {
	int retval;

	retval = dest->write((char *) file_info, sizeof (*file_info));
	if (retval) {
		printk("file_info: write returned %d\n", retval);
		goto out;
	}

	retval = 0;

out:
	return retval;
}

#define cr_task_tty(_t)	((_t)->signal->tty)

static int
cr_save_open_chr(struct checkpoint_dest_t *dest, struct file *filp,
        struct task_struct *tsk) {
	struct cr_chrdev cf_chrdev;
	struct inode *inode;
	int retval;

	retval = -EINVAL;
	if (!filp)
	goto out;

	inode = filp->f_dentry->d_inode;

	cf_chrdev.cr_type = cr_chrdev_obj;
	if (cr_task_tty(tsk) && (cr_task_tty(tsk) == (struct tty_struct *) filp->private_data)) {
		/* Map CTTY -> /dev/tty */
		cf_chrdev.cr_major = TTYAUX_MAJOR;
		cf_chrdev.cr_minor = 0;
	} else {
		cf_chrdev.cr_major = MAJOR(inode->i_rdev);
		cf_chrdev.cr_minor = MINOR(inode->i_rdev);
	}
	cf_chrdev.i_mode = filp->f_dentry->d_inode->i_mode;
	cf_chrdev.f_flags = filp->f_flags;

	retval = dest->write((char *) &cf_chrdev, sizeof (cf_chrdev));
	if (retval) {
		printk("open_chr: write returned %d\n", retval);
		goto out;
	}
	retval = 0;

out:
	return retval;
}

static int
cr_save_open_dup(struct checkpoint_dest_t *dest, struct file *filp) {
	struct cr_dup cf_dup;
	int retval;

	retval = -EINVAL;
	if (!filp)
		goto out;

	/* placeholder... just in case we need to do something later */
	cf_dup.cr_type = cr_dup_obj;

	retval = dest->write((char *) &cf_dup, sizeof (cf_dup));
	if (retval) {
		printk("open_dup: write returned %d\n", retval);
		goto out;
	}
	retval = 0;

out:
	return retval;
}

int export_files_struct(struct checkpoint_dest_t *dest, struct task_struct *tsk) {
    cr_objectmap_t map;
    int max_fds = 0;
    int fd = 0;
    struct file *filp;
    struct cr_file_info file_info;
    int retval = 0;

    return 0; // for now we will used the files from the baby sitter!

    cr_objmap_cachep = CR_KMEM_CACHE(cr_objectmap_s);
    cr_object_cachep = CR_KMEM_CACHE(cr_objectmap_s);

    map = cr_alloc_objectmap();

    max_fds = cr_save_files_struct(dest, tsk->files);

    spin_lock(&tsk->files->file_lock);
    for (fd = 0; fd < max_fds; ++fd) {
        /*
         * We have to do our own fget here to avoid a possible race on
         * file close.  (Probably impossible, but just to be on the safe
         * side.
         */

        /* loop around again if the file is not open or not to be saved */
        filp = fcheck(fd);
        if (!filp) {
            continue;
        }

        get_file(filp);

        memset(&file_info, 0, sizeof (file_info));
        file_info.cr_type = cr_file_info_obj;

        /* now save data for this file descriptor */
        cr_get_fd_info(tsk->files, fd, &file_info);

        spin_unlock(&tsk->files->file_lock);

        retval = cr_get_file_info(map, filp, &file_info);
        if (retval) {

        }

        retval = cr_save_file_info(dest, &file_info);
        if (retval) {

        }

        /* for now, char devices and dup(s) are supported. */
        switch (file_info.cr_file_type) {
            case cr_open_file:
                printk("    ...%d is regular file.\n", fd);
                //retval = cr_save_open_file(proc_req, filp);
                break;
            case cr_open_directory:
                printk("    ...%d is open directory.\n", fd);
                //retval = cr_save_open_dir(proc_req, filp);
                break;
            case cr_open_link:
                printk("    ...%d is open symlink.\n", fd);
                //retval = cr_save_open_link(proc_req, filp);
                break;
            case cr_open_fifo:
                printk("    ...%d is open fifo.\n", fd);
                //retval = cr_save_open_fifo(proc_req, filp);
                break;
            case cr_open_socket:
                printk("    ...%d is open socket.\n", fd);
                //retval = cr_save_open_socket(proc_req, filp);
                break;
            case cr_open_chr:
                printk("    ...%d is open character device.\n", fd);
                retval = cr_save_open_chr(dest, filp, tsk);
                break;
            case cr_open_blk:
                printk("    ...%d is an open block device.\n", fd);
                //retval = cr_save_open_blk(proc_req, filp);
                break;
            case cr_open_dup:
                printk("    ...%d is dup of %p.\n", fd, file_info.orig_filp);
                retval = cr_save_open_dup(dest, filp);
                break;
            case cr_open_chkpt_req:
                printk("    ...%d is a checkpoint request.\n", fd);
                //retval = cr_save_open_chkpt_req(proc_req, filp);
                break;
            case cr_bad_file_type:
                /* fall through */
            default:
                retval = -EBADF;
                break;
        }
             
        fput(filp);

        spin_lock(&current->files->file_lock);
    }
    
    spin_unlock(&current->files->file_lock);


    /* end marker */
    memset(&file_info, 0, sizeof (file_info));
    file_info.cr_type = cr_file_info_obj;
    file_info.cr_file_type = cr_end_of_files;
    file_info.fd = -1;
    retval = cr_save_file_info(dest, &file_info);
    if (retval < 0) {
        printk("%s: cr_save_file_info failed\n", __FUNCTION__);
    }
    return 0;

}

int import_files_struct(struct restart_src_t *src, struct task_struct *tsk)
{
	tsk->files = baby_sitter->files;
	return copy_files_task(baby_sitter, CLONE_FILES, tsk);
}

