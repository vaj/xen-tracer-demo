/*
 * function_trace.c
 */

#include <xen/init.h>
#include <xen/lib.h>
#include <xen/percpu.h>
#include <xen/string.h>
#include <xen/time.h>
#include <xen/function_hook.h>
#include <xen/symbols.h>
#include <xen/sched.h>
#include <xen/irq.h>
#include <xen/smp.h>
#include <xen/hypfs.h>
#include <xen/guest_access.h>
#include <xen/xmalloc.h>
#include <xen/cpumask.h>
#include <xen/hypfs_trace.h>

#define FUNCTION_TRACE_CTX_NORMAL  0
#define FUNCTION_TRACE_CTX_IRQ     (1U << 0)
#define FUNCTION_TRACE_CTX_IDLE    (1U << 2)
#define FUNCTION_TRACE_RECORD_TEXT_SIZE 384

struct function_trace_record {
    uint64_t timestamp;
    unsigned long ip;
    unsigned long parent_ip;
    unsigned int pcpu;
    domid_t domid;
    unsigned int vcpuid;
    unsigned int context_flags;
};

#define FUNCTION_TRACE_BUFSIZE 256

struct function_trace_cpu_buffer {
    struct function_trace_record records[FUNCTION_TRACE_BUFSIZE];
    unsigned int head;
    uint64_t written;
};

static struct function_trace_cpu_buffer function_trace_buffer;
static bool function_trace_recursing;

static char function_filter_name[KSYM_NAME_LEN];

static void function_trace_callback(unsigned long ip, unsigned long parent_ip)
{
    struct function_trace_cpu_buffer *buf;
    struct function_trace_record *rec;
    unsigned int ctx = FUNCTION_TRACE_CTX_NORMAL;

    if ( function_trace_recursing )
        return;

    function_trace_recursing = true;

    buf = &function_trace_buffer;
    rec = &buf->records[buf->head];

    rec->timestamp = NOW();
    rec->ip = ip;
    rec->parent_ip = parent_ip;
    rec->pcpu = smp_processor_id();

    if ( in_irq() )
        ctx |= FUNCTION_TRACE_CTX_IRQ;

    if ( is_idle_vcpu(current) )
        ctx |= FUNCTION_TRACE_CTX_IDLE;

    rec->context_flags = ctx;
    rec->domid = current->domain->domain_id;
    rec->vcpuid = current->vcpu_id;

    buf->head = (buf->head + 1) % FUNCTION_TRACE_BUFSIZE;
    buf->written++;

    function_trace_recursing = false;
}

static struct function_hook_ops function_trace_ops = {
    .callback = function_trace_callback,
};

static int function_tracer_set_filter(const char *function_name)
{
    unsigned long ip;

    if ( is_function_hook_registered(&function_trace_ops) )
        return -EBUSY;
    if ( !function_name || strlen(function_name) >= KSYM_NAME_LEN || strlen(function_name) == 0 )
        return -EINVAL;

    ip = symbols_lookup_by_name(function_name);
    if ( !ip )
        return -ENOENT;
    if ( !is_patchable_function_entry(ip) )
        return -EOPNOTSUPP;

    strlcpy(function_filter_name, function_name, sizeof(function_filter_name));
    return 0;
}

static const char *function_tracer_get_filter(void)
{
    return function_filter_name;
}

static void function_tracer_clear(void)
{
    function_trace_buffer.head = 0;
    function_trace_buffer.written = 0;
}

static int function_tracer_enable(void)
{
    int rc;

    if ( is_function_hook_registered(&function_trace_ops) )
        return 0;

    if ( !function_filter_name[0] )
        return -EINVAL;

    rc = filter_function_hook(&function_trace_ops, function_filter_name);
    if ( rc )
        return rc;

    function_tracer_clear();

    rc = register_function_hook(&function_trace_ops);
    return rc;
}

static int function_tracer_disable(void)
{
    if ( !is_function_hook_registered(&function_trace_ops) )
        return 0;

    return unregister_function_hook(&function_trace_ops);
}

static bool function_tracer_is_enabled(void)
{
    return is_function_hook_registered(&function_trace_ops);
}

static void format_ip(char *buf, size_t size, unsigned long ip)
{
    const char *name;
    unsigned long sym_size, offset;
    char namebuf[KSYM_NAME_LEN + 1];

    name = symbols_lookup(ip, &sym_size, &offset, namebuf);
    if ( name )
        snprintf(buf, size, "%s+0x%lx/0x%lx", name, offset, sym_size);
    else
        snprintf(buf, size, "0x%lx", ip);
}

static unsigned int function_tracer_get_trace_size(void)
{
    unsigned int count = function_trace_buffer.written > FUNCTION_TRACE_BUFSIZE ?
                         FUNCTION_TRACE_BUFSIZE : function_trace_buffer.written;
    return 256 + count * FUNCTION_TRACE_RECORD_TEXT_SIZE;
}

static size_t function_tracer_print_trace(char *buf, size_t size)
{
    struct function_trace_cpu_buffer *cbuf = &function_trace_buffer;
    unsigned int count = cbuf->written > FUNCTION_TRACE_BUFSIZE ? FUNCTION_TRACE_BUFSIZE : cbuf->written;
    unsigned int i, idx;
    size_t pos = 0;

    pos += scnprintf(buf + pos, size - pos, "# tracer: function\n#\n");
    pos += scnprintf(buf + pos, size - pos, "# entries-in-buffer/entries-written: %u/%"PRIu64"\n", count, cbuf->written);
    pos += scnprintf(buf + pos, size - pos, "#\n# CURRENT      PCPU  CONTEXT    TIMESTAMP_NS        FUNCTION\n");
    pos += scnprintf(buf + pos, size - pos, "#    |          |      |             |                  |\n");

    for ( i = 0; i < count; i++ )
    {
        struct function_trace_record *rec;
        char func_str[128];
        char parent_str[128];
        const char *ctx_str = "normal";

        if ( cbuf->written > FUNCTION_TRACE_BUFSIZE )
            idx = (cbuf->head + i) % FUNCTION_TRACE_BUFSIZE;
        else
            idx = i;

        rec = &cbuf->records[idx];

        if ( rec->context_flags & FUNCTION_TRACE_CTX_IDLE )
            ctx_str = "idle";
        else if ( rec->context_flags & FUNCTION_TRACE_CTX_IRQ )
            ctx_str = "irq";

        format_ip(func_str, sizeof(func_str), rec->ip);
        format_ip(parent_str, sizeof(parent_str), rec->parent_ip);

        if ( rec->context_flags & FUNCTION_TRACE_CTX_IDLE )
        {
            pos += scnprintf(
                buf + pos, size - pos,
                "idle           [%03u] %-10s %20"PRIu64": %s <-%s\n",
                rec->pcpu, ctx_str, rec->timestamp,
                func_str, parent_str);
        }
        else
        {
            pos += scnprintf(
                buf + pos, size - pos,
                "d%u/v%u          [%03u] %-10s %20"PRIu64": %s <-%s\n",
                rec->domid, rec->vcpuid, rec->pcpu,
                ctx_str, rec->timestamp,
                func_str, parent_str);
        }
    }

    return pos;
}

/* HypFS integration */

static HYPFS_DIR_INIT(function_dir, "function");

/* /tracing/function/filter */
static int cf_check function_filter_read(const struct hypfs_entry *entry,
                                         XEN_GUEST_HANDLE_PARAM(void) uaddr)
{
    const char *filter = function_tracer_get_filter();
    unsigned int len = strlen(filter);
    char *buf;
    int ret = 0;

    if ( len == 0 )
    {
        char empty = '\0';
        if ( copy_to_guest(uaddr, &empty, 1) )
            return -EFAULT;
        return 0;
    }

    buf = xmalloc_array(char, len + 2);
    if ( !buf )
        return -ENOMEM;

    snprintf(buf, len + 2, "%s\n", filter);

    if ( copy_to_guest(uaddr, buf, len + 2) )
        ret = -EFAULT;

    xfree(buf);
    return ret;
}

static int cf_check function_filter_write(struct hypfs_entry_leaf *leaf,
                                          XEN_GUEST_HANDLE_PARAM(const_void) uaddr,
                                          unsigned int ulen)
{
    char name[KSYM_NAME_LEN];
    int ret;

    if ( ulen >= KSYM_NAME_LEN || ulen == 0 )
        return -EINVAL;

    if ( copy_from_guest(name, uaddr, ulen) )
        return -EFAULT;

    name[ulen] = '\0';
    while ( ulen > 0 && (name[ulen - 1] == '\n' || name[ulen - 1] == '\0') )
    {
        name[ulen - 1] = '\0';
        ulen--;
    }

    if ( ulen == 0 )
        return -EINVAL;

    ret = function_tracer_set_filter(name);
    return ret;
}

static unsigned int cf_check function_filter_getsize(const struct hypfs_entry *entry)
{
    unsigned int len = strlen(function_tracer_get_filter());
    return len ? len + 2 : 1;
}

static const struct hypfs_funcs function_filter_funcs = {
    .enter = hypfs_node_enter,
    .exit = hypfs_node_exit,
    .read = function_filter_read,
    .write = function_filter_write,
    .getsize = function_filter_getsize,
    .findentry = hypfs_leaf_findentry,
};

static HYPFS_VARSIZE_INIT(function_filter, XEN_HYPFS_TYPE_STRING,
                          "filter", KSYM_NAME_LEN, &function_filter_funcs);

/* /tracing/function/enabled */
static int cf_check function_enabled_read(const struct hypfs_entry *entry,
                                          XEN_GUEST_HANDLE_PARAM(void) uaddr)
{
    char buf[3];
    unsigned int len;
    int ret = 0;

    len = snprintf(buf, sizeof(buf), "%d\n", function_tracer_is_enabled() ? 1 : 0);

    if ( copy_to_guest(uaddr, buf, len + 1) )
        ret = -EFAULT;

    return ret;
}

static int cf_check function_enabled_write(struct hypfs_entry_leaf *leaf,
                                           XEN_GUEST_HANDLE_PARAM(const_void) uaddr,
                                           unsigned int ulen)
{
    char buf[4];

    if ( ulen > sizeof(buf) - 1 || ulen == 0 )
        return -EINVAL;

    if ( copy_from_guest(buf, uaddr, ulen) )
        return -EFAULT;

    buf[ulen] = '\0';

    if ( !strcmp(buf, "1") || !strcmp(buf, "1\n") )
        return function_tracer_enable();
    else if ( !strcmp(buf, "0") || !strcmp(buf, "0\n") )
        return function_tracer_disable();

    return -EINVAL;
}

static unsigned int cf_check function_enabled_getsize(const struct hypfs_entry *entry)
{
    return 3; /* "0\n\0" or "1\n\0" */
}

static const struct hypfs_funcs function_enabled_funcs = {
    .enter = hypfs_node_enter,
    .exit = hypfs_node_exit,
    .read = function_enabled_read,
    .write = function_enabled_write,
    .getsize = function_enabled_getsize,
    .findentry = hypfs_leaf_findentry,
};

static HYPFS_VARSIZE_INIT(function_enabled, XEN_HYPFS_TYPE_STRING,
                          "enabled", 4, &function_enabled_funcs);

/* /tracing/function/trace */
static int cf_check function_trace_read(const struct hypfs_entry *entry,
                                        XEN_GUEST_HANDLE_PARAM(void) uaddr)
{
    unsigned int size = function_tracer_get_trace_size();
    char *buf = xzalloc_array(char, size);
    size_t len;
    int ret = 0;

    if ( !buf )
        return -ENOMEM;

    len = function_tracer_print_trace(buf, size);

    if ( copy_to_guest(uaddr, buf, size) )
        ret = -EFAULT;

    xfree(buf);
    return ret;
}

static unsigned int cf_check function_trace_getsize(const struct hypfs_entry *entry)
{
    return function_tracer_get_trace_size();
}

static const struct hypfs_funcs function_trace_funcs = {
    .enter = hypfs_node_enter,
    .exit = hypfs_node_exit,
    .read = function_trace_read,
    .write = hypfs_write_deny,
    .getsize = function_trace_getsize,
    .findentry = hypfs_leaf_findentry,
};

static HYPFS_VARSIZE_INIT(function_trace, XEN_HYPFS_TYPE_STRING,
                          "trace", 0, &function_trace_funcs);

static int __init function_trace_init(void)
{
    hypfs_string_set_reference(&function_filter, "");
    hypfs_string_set_reference(&function_enabled, "");
    hypfs_string_set_reference(&function_trace, "");

    hypfs_trace_add_dir(&function_dir);
    hypfs_add_leaf(&function_dir, &function_filter, true);
    hypfs_add_leaf(&function_dir, &function_enabled, true);
    hypfs_add_leaf(&function_dir, &function_trace, true);

    return 0;
}
__initcall(function_trace_init);
