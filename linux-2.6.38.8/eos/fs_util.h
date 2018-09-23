#ifndef __GHOST_HELPERS_H__
#define __GHOST_HELPERS_H__

char *physical_d_path(const struct path *path, char *tmp);
int export_fs_struct (struct checkpoint_dest_t *dest, struct task_struct *tsk);
int export_files_struct(struct checkpoint_dest_t *dest, struct task_struct *tsk);

#endif /* __GHOST_HELPERS_H__ */
