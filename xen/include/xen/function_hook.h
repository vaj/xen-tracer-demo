#ifndef __XEN_FUNCTION_HOOK_H__
#define __XEN_FUNCTION_HOOK_H__

#include <xen/list.h>
#include <xen/livepatch.h>

struct function_hook_ops {
    livepatch_trace_func_t callback;
    unsigned long filtered_ip;
    struct list_head list;
};

bool is_patchable_function_entry(unsigned long addr);
void livepatch_get_patchable_function_entries(const unsigned long **start,
                                              const unsigned long **stop);
int filter_function_hook(struct function_hook_ops *ops,
                         const char *function_name);
int register_function_hook(struct function_hook_ops *ops);
int unregister_function_hook(struct function_hook_ops *ops);

typedef int (*function_hook_iter_t)(unsigned long ip, void *data);
int function_hook_for_each(function_hook_iter_t callback, void *data);

void function_hook_dispatch(unsigned long ip, unsigned long parent_ip);

bool is_function_hook_registered(struct function_hook_ops *ops);

#endif /* __XEN_FUNCTION_HOOK_H__ */
