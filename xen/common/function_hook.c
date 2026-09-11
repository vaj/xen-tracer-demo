/*
 * function_hook.c
 */

#include <xen/init.h>
#include <xen/lib.h>
#include <xen/list.h>
#include <xen/spinlock.h>
#include <xen/symbols.h>
#include <xen/livepatch.h>
#include <xen/function_hook.h>
#include <xen/string.h>
#include <xen/rcupdate.h>
#include <xen/cpumask.h>

static LIST_HEAD(function_hook_list);
static DEFINE_SPINLOCK(function_hook_lock);
static DEFINE_RCU_READ_LOCK(rcu_function_hook_lock);

extern const unsigned long __start_patchable_function_entries[];
extern const unsigned long __stop_patchable_function_entries[];

void function_hook_dispatch(unsigned long ip, unsigned long parent_ip)
{
    struct function_hook_ops *hook;

    rcu_read_lock(&rcu_function_hook_lock);

    list_for_each_entry_rcu ( hook, &function_hook_list, list )
    {
        if ( hook->filtered_ip == ip )
        {
            hook->callback(ip, parent_ip);
            goto out;
        }
    }

out:
    rcu_read_unlock(&rcu_function_hook_lock);
}

bool is_patchable_function_entry(unsigned long addr)
{
    const unsigned long *p;

    for ( p = __start_patchable_function_entries;
          p < __stop_patchable_function_entries; p++ )
    {
        if ( *p == addr )
            return true;
    }

    return false;
}

void livepatch_get_patchable_function_entries(const unsigned long **start,
                                              const unsigned long **stop)
{
    *start = __start_patchable_function_entries;
    *stop = __stop_patchable_function_entries;
}

int filter_function_hook(struct function_hook_ops *ops, const char *function_name)
{
    unsigned long ip;

    if ( !ops || !function_name )
        return -EINVAL;

    ip = symbols_lookup_by_name(function_name);
    if ( !ip )
        return -ENOENT;

    if ( !is_patchable_function_entry(ip) )
        return -EOPNOTSUPP;

    ops->filtered_ip = ip;
    return 0;
}

/* TODO: Assuming single CPU */
int register_function_hook(struct function_hook_ops *ops)
{
    struct function_hook_ops *hook;
    struct livepatch_func trace;
    unsigned long flags;
    int rc;

    if ( !ops || !ops->callback || !ops->filtered_ip )
        return -EINVAL;

    spin_lock(&function_hook_lock);

    list_for_each_entry ( hook, &function_hook_list, list )
    {
        if ( hook->filtered_ip == ops->filtered_ip )
        {
            rc = -EEXIST;
            goto out_unlock;
        }
    }

    local_irq_save(flags);

    rc = arch_livepatch_quiesce();
    if (rc)
        goto out_irq;

    memset(&trace, 0, sizeof(trace));
    trace.old_addr = (void *)ops->filtered_ip;

    arch_livepatch_apply_trace(&trace);
    arch_livepatch_revive();

    list_add_tail_rcu(&ops->list, &function_hook_list);

 out_irq:
    local_irq_restore(flags);
 out_unlock:
    spin_unlock(&function_hook_lock);

    return rc;

}

int unregister_function_hook(struct function_hook_ops *ops)
{
    struct function_hook_ops *hook;
    struct livepatch_func trace;
    unsigned long flags;
    bool found = false;
    int rc;

    if ( !ops || !ops->filtered_ip )
        return -EINVAL;

    spin_lock(&function_hook_lock);

    list_for_each_entry ( hook, &function_hook_list, list )
    {
        if ( hook == ops )
        {
            found = true;
            break;
        }
    }

    if ( !found )
    {
        rc = -ENOENT;
        goto out_unlock;
    }

    local_irq_save(flags);

    rc = arch_livepatch_quiesce();
    if ( rc )
        goto out_irq;

    memset(&trace, 0, sizeof(trace));
    trace.old_addr = (void *)ops->filtered_ip;

    arch_livepatch_revert_trace(&trace);
    arch_livepatch_revive();

    list_del_rcu(&ops->list);

 out_irq:
    local_irq_restore(flags);
 out_unlock:
    spin_unlock(&function_hook_lock);

    return rc;
}

int function_hook_for_each(function_hook_iter_t callback, void *data)
{
    struct function_hook_ops *hook;
    int rc = 0;

    spin_lock(&function_hook_lock);
    list_for_each_entry ( hook, &function_hook_list, list )
    {
        rc = callback(hook->filtered_ip, data);
        if ( rc )
            break;
    }
    spin_unlock(&function_hook_lock);

    return rc;
}

bool is_function_hook_registered(struct function_hook_ops *ops)
{
    struct function_hook_ops *hook;
    bool found = false;

    spin_lock(&function_hook_lock);
    list_for_each_entry ( hook, &function_hook_list, list )
    {
        if ( hook == ops )
        {
            found = true;
            break;
        }
    }
    spin_unlock(&function_hook_lock);

    return found;
}
