#include <xen/init.h>
#include <xen/hypfs.h>
#include <xen/function_hook.h>
#include <xen/symbols.h>
#include <xen/string.h>
#include <xen/guest_access.h>
#include <xen/xmalloc.h>
#include <xen/hypfs_trace.h>

static HYPFS_DIR_INIT(tracing_dir, "tracing");

/* /tracing/available_functions */
static int cf_check available_functions_read(const struct hypfs_entry *entry,
                                             XEN_GUEST_HANDLE_PARAM(void) uaddr)
{
    const unsigned long *start, *stop, *p;
    char namebuf[KSYM_NAME_LEN + 1];
    const char *name;
    unsigned long size, offset;
    int ret = 0;
    char *buf;
    unsigned int buf_size = 0;
    unsigned int buf_pos = 0;

    livepatch_get_patchable_function_entries(&start, &stop);

    /* First pass: calculate size */
    for ( p = start; p < stop; p++ )
    {
        name = symbols_lookup(*p, &size, &offset, namebuf);
        if ( name )
            buf_size += strlen(name) + 1;
    }

    if ( buf_size == 0 )
    {
        char empty = '\0';
        if ( copy_to_guest(uaddr, &empty, 1) )
            return -EFAULT;
        return 0;
    }

    buf_size++; /* For trailing \0 */

    buf = xmalloc_array(char, buf_size);
    if ( !buf )
        return -ENOMEM;

    /* Second pass: fill buffer */
    for ( p = start; p < stop; p++ )
    {
        name = symbols_lookup(*p, &size, &offset, namebuf);
        if ( name )
        {
            unsigned int len = strlen(name);
            memcpy(buf + buf_pos, name, len);
            buf[buf_pos + len] = '\n';
            buf_pos += len + 1;
        }
    }
    buf[buf_pos] = '\0';

    if ( copy_to_guest(uaddr, buf, buf_size) )
        ret = -EFAULT;

    xfree(buf);
    return ret;
}

static unsigned int cf_check available_functions_getsize(const struct hypfs_entry *entry)
{
    const unsigned long *start, *stop, *p;
    char namebuf[KSYM_NAME_LEN + 1];
    const char *name;
    unsigned long size, offset;
    unsigned int buf_size = 0;

    livepatch_get_patchable_function_entries(&start, &stop);

    for ( p = start; p < stop; p++ )
    {
        name = symbols_lookup(*p, &size, &offset, namebuf);
        if ( name )
            buf_size += strlen(name) + 1;
    }

    if ( buf_size == 0 )
        return 1;

    return buf_size + 1;
}

static const struct hypfs_funcs available_functions_funcs = {
    .enter = hypfs_node_enter,
    .exit = hypfs_node_exit,
    .read = available_functions_read,
    .write = hypfs_write_deny,
    .getsize = available_functions_getsize,
    .findentry = hypfs_leaf_findentry,
};

static HYPFS_VARSIZE_INIT(available_functions, XEN_HYPFS_TYPE_STRING,
                          "available_functions", 0, &available_functions_funcs);

/* /tracing/enabled_functions */
struct enabled_funcs_data {
    char *buf;
    unsigned int size;
    unsigned int pos;
    int rc;
};

static int enabled_functions_iter_size(unsigned long ip, void *data)
{
    struct enabled_funcs_data *d = data;
    const char *name;
    unsigned long size, offset;
    char namebuf[KSYM_NAME_LEN + 1];

    name = symbols_lookup(ip, &size, &offset, namebuf);
    if ( name )
        d->size += strlen(name) + 1;

    return 0;
}

static int enabled_functions_iter_read(unsigned long ip, void *data)
{
    struct enabled_funcs_data *d = data;
    const char *name;
    unsigned long size, offset;
    char namebuf[KSYM_NAME_LEN + 1];

    name = symbols_lookup(ip, &size, &offset, namebuf);
    if ( name )
    {
        unsigned int len = strlen(name);
        if ( d->pos + len + 1 <= d->size )
        {
            memcpy(d->buf + d->pos, name, len);
            d->buf[d->pos + len] = '\n';
            d->pos += len + 1;
        }
        else
            d->rc = -ENOBUFS;
    }

    return d->rc;
}

static int cf_check enabled_functions_read(const struct hypfs_entry *entry,
                                           XEN_GUEST_HANDLE_PARAM(void) uaddr)
{
    struct enabled_funcs_data d = { .size = 0, .pos = 0, .rc = 0 };
    int ret = 0;

    function_hook_for_each(enabled_functions_iter_size, &d);

    if ( d.size == 0 )
    {
        char empty = '\0';
        if ( copy_to_guest(uaddr, &empty, 1) )
            return -EFAULT;
        return 0;
    }

    d.size++; /* For trailing \0 */
    d.buf = xmalloc_array(char, d.size);
    if ( !d.buf )
        return -ENOMEM;

    function_hook_for_each(enabled_functions_iter_read, &d);

    if ( d.rc )
        ret = d.rc;
    else
    {
        d.buf[d.pos] = '\0';
        if ( copy_to_guest(uaddr, d.buf, d.size) )
            ret = -EFAULT;
    }

    xfree(d.buf);
    return ret;
}

static unsigned int cf_check enabled_functions_getsize(const struct hypfs_entry *entry)
{
    struct enabled_funcs_data d = { .size = 0 };

    function_hook_for_each(enabled_functions_iter_size, &d);

    if ( d.size == 0 )
        return 1;

    return d.size + 1;
}

static const struct hypfs_funcs enabled_functions_funcs = {
    .enter = hypfs_node_enter,
    .exit = hypfs_node_exit,
    .read = enabled_functions_read,
    .write = hypfs_write_deny,
    .getsize = enabled_functions_getsize,
    .findentry = hypfs_leaf_findentry,
};

static HYPFS_VARSIZE_INIT(enabled_functions, XEN_HYPFS_TYPE_STRING,
                          "enabled_functions", 0, &enabled_functions_funcs);

static bool tracing_initialized;

static void __init hypfs_trace_ensure_initialized(void)
{
    if ( tracing_initialized )
        return;

    hypfs_string_set_reference(&available_functions, "");
    hypfs_string_set_reference(&enabled_functions, "");

    hypfs_add_dir(&hypfs_root, &tracing_dir, true);
    hypfs_add_leaf(&tracing_dir, &available_functions, true);
    hypfs_add_leaf(&tracing_dir, &enabled_functions, true);

    tracing_initialized = true;
}

void __init hypfs_trace_add_dir(struct hypfs_entry_dir *dir)
{
    hypfs_trace_ensure_initialized();
    hypfs_add_dir(&tracing_dir, dir, true);
}
