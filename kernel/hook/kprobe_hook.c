#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/mutex.h>
#include <linux/printk.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/types.h>

#include "hook/kprobe_hook.h"
#include "klog.h" // IWYU pragma: keep

/* ------------------------------------------------------------------ */
/*  Internal tracking                                                 */
/* ------------------------------------------------------------------ */

#define KSU_KPROBE_HOOK_MAX 32

struct ksu_kprobe_hook_entry {
    struct ksu_kprobe_hook *hook;
};

static DEFINE_MUTEX(ksu_kprobe_hook_lock);
static struct ksu_kprobe_hook_entry ksu_kprobe_hook_entries[KSU_KPROBE_HOOK_MAX];
static int ksu_kprobe_hook_count;

static bool ksu_kprobe_hook_is_tracked(struct ksu_kprobe_hook *hook)
{
    int i;

    for (i = 0; i < ksu_kprobe_hook_count; i++) {
        if (ksu_kprobe_hook_entries[i].hook == hook)
            return true;
    }
    return false;
}

static int ksu_kprobe_hook_track(struct ksu_kprobe_hook *hook)
{
    if (ksu_kprobe_hook_is_tracked(hook))
        return 0;

    if (ksu_kprobe_hook_count >= KSU_KPROBE_HOOK_MAX) {
        pr_err("kprobe_hook: tracking table full, cannot record %s\n",
               hook->name ?: "unknown");
        return -ENOSPC;
    }

    ksu_kprobe_hook_entries[ksu_kprobe_hook_count++].hook = hook;
    return 0;
}

static void ksu_kprobe_hook_untrack(struct ksu_kprobe_hook *hook)
{
    int i;

    for (i = 0; i < ksu_kprobe_hook_count; i++) {
        if (ksu_kprobe_hook_entries[i].hook != hook)
            continue;

        ksu_kprobe_hook_entries[i] =
            ksu_kprobe_hook_entries[--ksu_kprobe_hook_count];
        return;
    }
}

/* ------------------------------------------------------------------ */
/*  Core API                                                          */
/* ------------------------------------------------------------------ */

int ksu_kprobe_hook_register(struct ksu_kprobe_hook *hook)
{
    int ret;

    if (!hook || !hook->symbol_name) {
        pr_err("kprobe_hook: invalid hook descriptor (no symbol_name)\n");
        return -EINVAL;
    }

    mutex_lock(&ksu_kprobe_hook_lock);

    if (hook->registered) {
        pr_err("kprobe_hook: %s (%s) is already registered\n",
               hook->name ?: "unnamed", hook->symbol_name);
        ret = -EALREADY;
        goto out_unlock;
    }

    /* Populate the underlying struct kprobe */
    hook->kp.symbol_name = hook->symbol_name;
    hook->kp.offset = hook->offset;
    hook->kp.pre_handler = hook->pre_handler;
    hook->kp.post_handler = hook->post_handler;
    hook->kp.fault_handler = hook->fault_handler;

    ret = register_kprobe(&hook->kp);
    if (ret) {
        pr_err("kprobe_hook: register_kprobe(%s) on %s failed: %d\n",
               hook->name ?: "unnamed", hook->symbol_name, ret);
        goto out_unlock;
    }

    ret = ksu_kprobe_hook_track(hook);
    if (ret) {
        unregister_kprobe(&hook->kp);
        goto out_unlock;
    }

    hook->registered = true;
    pr_info("kprobe_hook: registered %s on %s [kp=%px]\n",
            hook->name ?: "unnamed", hook->symbol_name, &hook->kp);

out_unlock:
    mutex_unlock(&ksu_kprobe_hook_lock);
    return ret;
}

void ksu_kprobe_hook_unregister(struct ksu_kprobe_hook *hook)
{
    if (!hook || !hook->registered)
        return;

    mutex_lock(&ksu_kprobe_hook_lock);

    unregister_kprobe(&hook->kp);
    synchronize_rcu();
    ksu_kprobe_hook_untrack(hook);

    hook->registered = false;
    pr_info("kprobe_hook: unregistered %s (%s)\n",
            hook->name ?: "unnamed", hook->symbol_name);

    mutex_unlock(&ksu_kprobe_hook_lock);
}

/* ------------------------------------------------------------------ */
/*  Batch operations                                                   */
/* ------------------------------------------------------------------ */

int ksu_kprobe_hook_register_batch(struct ksu_kprobe_hook hooks[], int count)
{
    int i, ret;

    for (i = 0; i < count; i++) {
        ret = ksu_kprobe_hook_register(&hooks[i]);
        if (ret) {
            pr_err("kprobe_hook: batch registration failed at index %d (%s on %s): %d\n",
                   i, hooks[i].name ?: "unnamed", hooks[i].symbol_name, ret);
            /* Roll back all previously registered hooks in this batch */
            while (--i >= 0)
                ksu_kprobe_hook_unregister(&hooks[i]);
            return ret;
        }
    }

    return 0;
}

void ksu_kprobe_hook_unregister_batch(struct ksu_kprobe_hook hooks[], int count)
{
    int i;

    for (i = 0; i < count; i++)
        ksu_kprobe_hook_unregister(&hooks[i]);
}

/* ------------------------------------------------------------------ */
/*  Lifecycle                                                         */
/* ------------------------------------------------------------------ */

void ksu_kprobe_hook_init(void)
{
    pr_info("kprobe_hook: init, tracked hooks=%d\n",
            READ_ONCE(ksu_kprobe_hook_count));
}

void ksu_kprobe_hook_exit(void)
{
    struct ksu_kprobe_hook *hooks[KSU_KPROBE_HOOK_MAX];
    int count, i;

    mutex_lock(&ksu_kprobe_hook_lock);
    count = ksu_kprobe_hook_count;
    for (i = 0; i < count; i++)
        hooks[i] = ksu_kprobe_hook_entries[i].hook;
    mutex_unlock(&ksu_kprobe_hook_lock);

    /* Unregister in reverse order */
    for (i = count - 1; i >= 0; i--)
        ksu_kprobe_hook_unregister(hooks[i]);

    pr_info("kprobe_hook: exit, all hooks cleaned up\n");
}