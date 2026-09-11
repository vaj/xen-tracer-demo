#ifndef __XEN_FUNCTION_TRACE_H__
#define __XEN_FUNCTION_TRACE_H__

#include <xen/types.h>

struct hypfs_entry_dir;

void function_trace_hypfs_init(struct hypfs_entry_dir *parent);

#endif /* __XEN_FUNCTION_TRACE_H__ */
