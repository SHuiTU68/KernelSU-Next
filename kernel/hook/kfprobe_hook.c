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
#include <linux/version.h>

#include "hook/kfprobe_hook.h"
#include "infra/symbol_resolver.h"
#include "klog.h" // IWYU pragma: keep

/* ================================================================== */
/*  Global master switch (static key)                                  */
/* ================================================================== */

/*
 * Three-layer gate:
 *   Layer 1 - Global static key (all hooks, nop when disabled)
 *   Layer 2 - Per-hook static key (optional, feature-level)
 *   Layer 3 - Per-task filter    (optional, e.g. UID allowlist)
 *
 * When Layer 1 is disabled the overhead per probe hit is exactly one
 * nop-patched branch (~1 cycle on modern CPUs).
 */
static DEFINE_STATIC_KEY_FALSE(kfprobe_global_enabled);

void ksu_kfprobe_hook_enable_all(void)
{
    static_branch_enable(&kfprobe_global_enabled);
}

void ksu_kfprobe_hook_disable_all(void)
{
    static_branch_disable(&kfprobe_global_enabled);
}

/* ================================================================== */
/*  Internal tracking                                                  */
/* ================================================================== */

#define KFPROBE_HOOK_MAX 32

struct kfprobe_hook_entry {
    struct ksu_kfprobe_hook *hook;
};

static DEFINE_MUTEX(kfprobe_hook_lock);
static struct kfprobe_hook_entry kfprobe_hook_entries[KFPROBE_HOOK_MAX];
static int kfprobe_hook_count;

static bool kfprobe_hook_is_tracked(struct ksu_kfprobe_hook *hook)
{
    int i;
    for (i = 0; i < kfprobe_hook_count; i++) {
        if (kfprobe_hook_entries[i].hook == hook)
            return true;
    }
    return false;
}

static int kfprobe_hook_track(struct ksu_kfprobe_hook *hook)
{
    if (kfprobe_hook_is_tracked(hook))
        return 0;
    if (kfprobe_hook_count >= KFPROBE_HOOK_MAX)
        return -ENOSPC;
    kfprobe_hook_entries[kfprobe_hook_count++].hook = hook;
    return 0;
}

static void kfprobe_hook_untrack(struct ksu_kfprobe_hook *hook)
{
    int i;
    for (i = 0; i < kfprobe_hook_count; i++) {
        if (kfprobe_hook_entries[i].hook != hook)
            continue;
        kfprobe_hook_entries[i] = kfprobe_hook_entries[--kfprobe_hook_count];
        return;
    }
}

/* ================================================================== */
/*  Internal pre-handler wrapper (kprobe entry)                        */
/* ================================================================== */

/*
 * Installed as the real kprobe pre_handler for every registered hook.
 * Implements the three-layer gate, then calls the user's handler.
 * Hot path: zero allocations, zero logging.
 */
static int kfprobe_pre_handler(struct kprobe *kp, struct pt_regs *regs)
{
    struct ksu_kfprobe_hook *hook;
    int i;

    /* Layer 1: global master switch (static key, nop when disabled) */
    if (!static_branch_unlikely(&kfprobe_global_enabled))
        return 0;

    /* Linear scan of the tracking array (max KFPROBE_HOOK_MAX = 32 entries,
     * and Layer 1 already gates most traffic). */
    for (i = 0; i < kfprobe_hook_count; i++) {
        if (kfprobe_hook_entries[i].hook &&
            &kfprobe_hook_entries[i].hook->kp == kp) {
            hook = kfprobe_hook_entries[i].hook;
            goto found;
        }
    }
    return 0;

found:
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

/* ================================================================== */
/*  Internal kretprobe handler (return-value interception)             */
/* ================================================================== */

/*
 * When a hook has @return_hook == true, we register a kretprobe whose
 * entry handler is a no-op (the original function runs), and the
 * ret-handler calls the user's @post_handler.
 */
static int kfprobe_kretpre_handler(struct kretprobe_instance *ri,
                                    struct pt_regs *regs)
{
    /* Always let the original function run – we only intercept the return. */
    return 0;
}

static int kfprobe_kret_handler(struct kretprobe_instance *ri,
                                 struct pt_regs *regs)
{
    struct ksu_kfprobe_hook *hook;

    /* Recover the hook descriptor from the kretprobe's data field. */
    hook = (struct ksu_kfprobe_hook *)ri->data;
    if (unlikely(!hook))
        return 0;

    /* Layer 1: global master switch */
    if (!static_branch_unlikely(&kfprobe_global_enabled))
        return 0;

    /* Layer 2: per-hook static key */
    if (hook->enabled_key &&
        !static_branch_unlikely(hook->enabled_key))
        return 0;

    /* Layer 3: per-task filter */
    if (hook->filter && !hook->filter(current))
        return 0;

    if (hook->post_handler)
        hook->post_handler(&hook->kp, regs);

    return 0;
}

/* ================================================================== */
/*  Core API                                                          */
/* ================================================================== */

int ksu_kfprobe_hook_register(struct ksu_kfprobe_hook *hook)
{
    int ret;
    unsigned long addr;

    if (!hook || (!hook->symbol_name && !hook->symbol_addr))
        return -EINVAL;

    mutex_lock(&kfprobe_hook_lock);

    if (hook->registered) {
        ret = -EALREADY;
        goto out_unlock;
    }

    /* Resolve target address -------------------------------------------------- */
    if (hook->symbol_addr) {
        addr = hook->symbol_addr;
    } else {
        /* Root-powered symbol resolution: use kallsyms_lookup_name which
         * is available at runtime via the symbol_resolver infrastructure. */
        addr = kallsyms_lookup_name(hook->symbol_name);
        if (!addr) {
            pr_err("kfprobe: failed to resolve %s for %s\n",
                   hook->symbol_name, hook->name ?: "unnamed");
            ret = -ENOENT;
            goto out_unlock;
        }
        hook->symbol_addr = addr;
    }

    /* Register the entry kprobe ----------------------------------------------- */
    /* Use addr-based registration (kp.addr) to avoid leaving a named entry
     * in /proc/kallsyms.  This is the primary stealth mechanism. */
    memset(&hook->kp, 0, sizeof(hook->kp));
    hook->kp.addr = (kprobe_opcode_t *)addr;
    hook->kp.offset = hook->offset;
    hook->kp.pre_handler = kfprobe_pre_handler;
    hook->kp.fault_handler = hook->fault_handler;

    ret = register_kprobe(&hook->kp);
    if (ret) {
        pr_err("kfprobe: register_kprobe(%s) failed: %d\n",
               hook->name ?: "unnamed", ret);
        goto out_unlock;
    }

    /* Register the kretprobe (return-value hook, optional) -------------------- */
    if (hook->return_hook) {
        memset(&hook->rp, 0, sizeof(hook->rp));
        hook->rp.kp.addr = (kprobe_opcode_t *)addr;
        hook->rp.handler = kfprobe_kret_handler;
        hook->rp.entry_handler = kfprobe_kretpre_handler;
        hook->rp.data_size = sizeof(struct ksu_kfprobe_hook *);
        hook->rp.maxactive = 0; /* use default (2 * NR_CPUS) */

        ret = register_kretprobe(&hook->rp);
        if (ret) {
            pr_err("kfprobe: register_kretprobe(%s) failed: %d\n",
                   hook->name ?: "unnamed", ret);
            unregister_kprobe(&hook->kp);
            goto out_unlock;
        }
        hook->use_kretprobe = true;
    }

    /* Track for lifecycle cleanup --------------------------------------------- */
    ret = kfprobe_hook_track(hook);
    if (ret) {
        unregister_kprobe(&hook->kp);
        if (hook->use_kretprobe)
            unregister_kretprobe(&hook->rp);
        goto out_unlock;
    }

    hook->registered = true;
    pr_info("kfprobe: registered %s on %s [0x%lx]%s\n",
            hook->name ?: "unnamed",
            hook->symbol_name ?: "<addr>", addr,
            hook->use_kretprobe ? " +kretprobe" : "");

out_unlock:
    mutex_unlock(&kfprobe_hook_lock);
    return ret;
}

void ksu_kfprobe_hook_unregister(struct ksu_kfprobe_hook *hook)
{
    if (!hook || !hook->registered)
        return;

    mutex_lock(&kfprobe_hook_lock);

    unregister_kprobe(&hook->kp);
    if (hook->use_kretprobe)
        unregister_kretprobe(&hook->rp);

    synchronize_rcu();
    kfprobe_hook_untrack(hook);

    hook->registered = false;
    hook->use_kretprobe = false;

    mutex_unlock(&kfprobe_hook_lock);
}

/* ================================================================== */
/*  Batch operations                                                   */
/* ================================================================== */

int ksu_kfprobe_hook_register_batch(struct ksu_kfprobe_hook hooks[], int count)
{
    int i, ret;

    for (i = 0; i < count; i++) {
        ret = ksu_kfprobe_hook_register(&hooks[i]);
        if (ret) {
            while (--i >= 0)
                ksu_kfprobe_hook_unregister(&hooks[i]);
            return ret;
        }
    }
    return 0;
}

void ksu_kfprobe_hook_unregister_batch(struct ksu_kfprobe_hook hooks[], int count)
{
    int i;
    for (i = 0; i < count; i++)
        ksu_kfprobe_hook_unregister(&hooks[i]);
}

/* ================================================================== */
/*  Lifecycle                                                         */
/* ================================================================== */

void ksu_kfprobe_hook_init(void)
{
    /* Global switch starts disabled; userspace (ksud) or the manager
     * enables it via ksu_kfprobe_hook_enable_all() when ready. */
    pr_info("kfprobe: init ready (max %d hooks)\n", KFPROBE_HOOK_MAX);
}

void ksu_kfprobe_hook_exit(void)
{
    struct ksu_kfprobe_hook *hooks[KFPROBE_HOOK_MAX];
    int count, i;

    /* Halt all processing first */
    ksu_kfprobe_hook_disable_all();

    mutex_lock(&kfprobe_hook_lock);
    count = kfprobe_hook_count;
    for (i = 0; i < count; i++)
        hooks[i] = kfprobe_hook_entries[i].hook;
    mutex_unlock(&kfprobe_hook_lock);

    for (i = count - 1; i >= 0; i--)
        ksu_kfprobe_hook_unregister(hooks[i]);
}