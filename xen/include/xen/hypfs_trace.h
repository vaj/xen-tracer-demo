#ifndef __XEN_HYPFS_TRACE_H__
#define __XEN_HYPFS_TRACE_H__

#include <xen/init.h>

struct hypfs_entry_dir;

void __init hypfs_trace_add_dir(struct hypfs_entry_dir *dir);

#endif /* __XEN_HYPFS_TRACE_H__ */
