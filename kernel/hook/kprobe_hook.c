#include <linux/errno.h>
#include <linux/jump_label.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/mutex.h>
#include <linux/printk.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/types.h>

#include "hook/kprobe_hook.h"
#include "klog.h" // IWYU pragma: keep

/* ------------------------------------------------------------------ */
/*  Global master switch                                               */
/* ------------------------------------------------------------------ */

/*
 * Global static key that gates all kprobe hook processing.
 *
 * - When DISABLED (default after init), the internal pre-handler wrapper
 *   returns immediately without calling the user's handler.  Runtime
 *   overhead is reduced to a single nop-patched branch (tens of cycles).
 * - When ENABLED, the wrapper proceeds to check per-hook filters and
 *   then calls the user's handler.
 *
 * Use ksu_kprobe_hook_enable_all() / ksu_kprobe_hook_disable_all() to
 * toggle this switch at runtime.
 */
static DEFINE_STATIC_KEY_FALSE(ksu_kprobe_hook_global_enabled);

void ksu_kprobe_hook_enable_all(void)
{
    static_branch_enable(&ksu_kprobe_hook_global_enabled);
    pr_info("kprobe_hook: global master switch enabled\n");
}

void ksu_kprobe_hook_disable_all(void)
{
    static_branch_disable(&ksu_kprobe_hook_global_enabled);
    pr_info("kprobe_hook: global master switch disabled\n");
}

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
/*  Internal pre-handler wrapper                                       */
/* ------------------------------------------------------------------ */

/*
 * This wrapper is installed as the real kprobe pre_handler for every
 * registered hook.  It implements the three-layer gate:
 *
 *   1. Global static key         (fast path – nop when disabled)
 *   2. Per-hook static key       (optional, per-feature gate)
 *   3. Per-task filter           (optional, e.g. UID allowlist)
 *
 * Only when all three pass (or are absent) does the user's @pre_handler
 * get called.
 */
static int ksu_kprobe_hook_pre_handler(struct kprobe *kp, struct pt_regs *regs)
{
    struct ksu_kprobe_hook *hook;
    int i;

    /* Layer 1: global master switch */
    if (!static_branch_unlikely(&ksu_kprobe_hook_global_enabled))
        return 0;

    /* Find the hook descriptor from the kprobe address.
     * This is a linear scan, but with KSU_KPROBE_HOOK_MAX <= 32 and
     * the global gate filtering most of the traffic, it is acceptable.
     */
    hook = NULL;
    for (i = 0; i < ksu_kprobe_hook_count; i++) {
        if (ksu_kprobe_hook_entries[i].hook &&
            &ksu_kprobe_hook_entries[i].hook->kp == kp) {
            hook = ksu_kprobe_hook_entries[i].hook;
            break;
        }
    }

    if (unlikely(!hook))
        return 0;

    /* Layer 2: per-hook static key (feature-level gate) */
    if (hook->enabled_key &&
        !static_branch_unlikely(hook->enabled_key))
        return 0;

    /* Layer 3: per-task filter */
    if (hook->filter && !hook->filter(current))
        return 0;

    /* All gates passed – call the user's handler */
    if (hook->pre_handler)
        return hook->pre_handler(kp, regs);

    return 0;
}

/* ------------------------------------------------------------------ */
/*  Core API                                                          */
/* ------------------------------------------------------------------ */

int ksu_kprobe_hook_register(struct ksu_kprobe_hook *hook)
{
    int ret;
    unsigned long addr;

    if (!hook || (!hook->symbol_name && !hook->symbol_addr)) {
        pr_err("kprobe_hook: invalid hook descriptor (no symbol_name or symbol_addr)\n");
        return -EINVAL;
    }

    mutex_lock(&ksu_kprobe_hook_lock);

    if (hook->registered) {
        pr_err("kprobe_hook: %s is already registered\n",
               hook->name ?: "unnamed");
        ret = -EALREADY;
        goto out_unlock;
    }

    /* Resolve target address: symbol_addr takes precedence */
    if (hook->symbol_addr) {
        addr = hook->symbol_addr;
    } else {
        addr = kallsyms_lookup_name(hook->symbol_name);
        if (!addr) {
            pr_err("kprobe_hook: failed to resolve symbol %s for %s\n",
                   hook->symbol_name, hook->name ?: "unnamed");
            ret = -ENOENT;
            goto out_unlock;
        }
        hook->symbol_addr = addr;
    }

    /* Populate the underlying struct kprobe.
     * Use addr-based registration (kp.addr) to avoid leaving a named
     * entry in /proc/kallsyms, reducing the detection surface.
     */
    memset(&hook->kp, 0, sizeof(hook->kp));
    hook->kp.addr = (kprobe_opcode_t *)addr;
    hook->kp.offset = hook->offset;
    hook->kp.pre_handler = ksu_kprobe_hook_pre_handler;
    hook->kp.post_handler = NULL;   /* not used – wrapper handles this */
    hook->kp.fault_handler = hook->fault_handler;

    ret = register_kprobe(&hook->kp);
    if (ret) {
        pr_err("kprobe_hook: register_kprobe(%s) on %s failed: %d\n",
               hook->name ?: "unnamed",
               hook->symbol_name ?: "<addr-based>", ret);
        goto out_unlock;
    }

    ret = ksu_kprobe_hook_track(hook);
    if (ret) {
        unregister_kprobe(&hook->kp);
        goto out_unlock;
    }

    hook->registered = true;
    pr_info("kprobe_hook: registered %s on %s [0x%lx, kp=%px]\n",
            hook->name ?: "unnamed",
            hook->symbol_name ?: "<addr>", addr, &hook->kp);

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
            hook->name ?: "unnamed",
            hook->symbol_name ?: "<addr-based>");

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
            pr_err("kprobe_hook: batch registration failed at index %d (%s): %d\n",
                   i, hooks[i].name ?: "unnamed", ret);
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
    pr_info("kprobe_hook: init, tracked hooks=%d, global switch=%s\n",
            READ_ONCE(ksu_kprobe_hook_count),
            static_branch_unlikely(&ksu_kprobe_hook_global_enabled) ? "enabled" : "disabled");
}

void ksu_kprobe_hook_exit(void)
{
    struct ksu_kprobe_hook *hooks[KSU_KPROBE_HOOK_MAX];
    int count, i;

    /* Disable the global switch first so no new handlers fire during teardown */
    ksu_kprobe_hook_disable_all();

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