// SPDX-License-Identifier: GPL-2.0
/*
 * kfprobe_lsm.c - KFprobe LSM runtime patching bridge
 *
 * Bridges the KFprobe hook framework with the LSM runtime patching
 * mechanism (ksu_lsm_hook/ksu_lsm_unhook).  Allows features to register
 * LSM callbacks at runtime without calling security_add_hooks(), which
 * leaves visible traces in the security_hook_heads and LSM audit logs.
 *
 * Instead, this module uses ksu_patch_text() to directly overwrite the
 * function pointer in the target security_hook_list entry, then updates
 * the static_call (6.12+) or the hlist head (pre-6.12) accordingly.
 *
 * === Usage ===
 *   struct ksu_kfprobe_lsm_hook my_hook = {
 *       .name = "my_feature",
 *       .hook = KSU_LSM_HOOK_INIT(inode_permission, "selinux_inode_permission",
 *                                  my_handler, 0),
 *       .enabled = false,
 *   };
 *   ksu_kfprobe_lsm_register(&my_hook);
 *   ksu_kfprobe_lsm_enable(&my_hook);
 *   // ... later ...
 *   ksu_kfprobe_lsm_unregister(&my_hook);
 *
 * All registered hooks are automatically restored in reverse order by
 * ksu_kfprobe_lsm_exit().
 */

#include <linux/jump_label.h>
#include <linux/lsm_hooks.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "hook/kfprobe_hook.h"
#include "hook/kfprobe_lsm.h"
#include "hook/lsm_hook.h"
#include "klog.h" // IWYU pragma: keep

/*
 * Global static key for all LSM hooks managed by KFprobe.
 * When disabled, every patched LSM hook still runs (because the patching
 * is transparent to the caller), but the per-hook enabled flag is checked
 * and the original handler is called instead.
 */
static DEFINE_STATIC_KEY_FALSE(kfprobe_lsm_global_enabled);

/* Tracking */
#define KFPROBE_LSM_HOOK_MAX 16

static DEFINE_MUTEX(kfprobe_lsm_lock);
static struct ksu_kfprobe_lsm_hook *kfprobe_lsm_hooks[KFPROBE_LSM_HOOK_MAX];
static int kfprobe_lsm_hook_count;

/* ================================================================== */
/*  Internal helpers                                                   */
/* ================================================================== */

static int kfprobe_lsm_track(struct ksu_kfprobe_lsm_hook *h)
{
    if (kfprobe_lsm_hook_count >= KFPROBE_LSM_HOOK_MAX)
        return -ENOSPC;
    kfprobe_lsm_hooks[kfprobe_lsm_hook_count++] = h;
    return 0;
}

static void kfprobe_lsm_untrack(struct ksu_kfprobe_lsm_hook *h)
{
    int i;
    for (i = 0; i < kfprobe_lsm_hook_count; i++) {
        if (kfprobe_lsm_hooks[i] != h)
            continue;
        kfprobe_lsm_hooks[i] = kfprobe_lsm_hooks[--kfprobe_lsm_hook_count];
        return;
    }
}

/* ================================================================== */
/*  Core API                                                          */
/* ================================================================== */

/**
 * ksu_kfprobe_lsm_register() - Register a KFprobe-managed LSM hook
 * @h: Descriptor (must stay stable in memory while registered).
 *
 * Patches the target LSM slot at runtime using ksu_lsm_hook().
 * The hook starts disabled; call ksu_kfprobe_lsm_enable() to activate it.
 *
 * Returns 0 on success, negative errno on failure.
 */
int ksu_kfprobe_lsm_register(struct ksu_kfprobe_lsm_hook *h)
{
    int ret;

    if (!h || !h->hook.replacement)
        return -EINVAL;

    mutex_lock(&kfprobe_lsm_lock);

    if (h->registered) {
        ret = -EALREADY;
        goto out;
    }

    /* Patch the LSM slot via the runtime patching mechanism */
    ret = ksu_lsm_hook(&h->hook);
    if (ret) {
        pr_err("kfprobe_lsm: failed to register %s: %d\n",
               h->name ?: "unnamed", ret);
        goto out;
    }

    ret = kfprobe_lsm_track(h);
    if (ret) {
        ksu_lsm_unhook(&h->hook);
        goto out;
    }

    h->registered = true;
    h->enabled = false;
    pr_info("kfprobe_lsm: registered %s (%s)\n",
            h->name ?: "unnamed", h->hook.head_name ?: "?");

out:
    mutex_unlock(&kfprobe_lsm_lock);
    return ret;
}

/**
 * ksu_kfprobe_lsm_unregister() - Unregister a KFprobe-managed LSM hook
 * @h: Descriptor to unregister.
 *
 * Restores the original LSM handler and removes the hook from tracking.
 */
void ksu_kfprobe_lsm_unregister(struct ksu_kfprobe_lsm_hook *h)
{
    if (!h || !h->registered)
        return;

    mutex_lock(&kfprobe_lsm_lock);

    ksu_lsm_unhook(&h->hook);
    kfprobe_lsm_untrack(h);

    h->registered = false;
    h->enabled = false;
    pr_info("kfprobe_lsm: unregistered %s\n", h->name ?: "unnamed");

    mutex_unlock(&kfprobe_lsm_lock);
}

/**
 * ksu_kfprobe_lsm_enable() - Activate a registered LSM hook
 * @h: Descriptor to enable.
 *
 * When enabled, the patched LSM handler (the replacement function) is
 * used.  When disabled, the original handler is called transparently.
 *
 * Note: The LSM hook is always patched (the slot is overwritten) even
 * when disabled.  The enable/disable flag controls whether the
 * replacement function forwards to the original or runs its own logic.
 */
void ksu_kfprobe_lsm_enable(struct ksu_kfprobe_lsm_hook *h)
{
    if (h && h->registered)
        h->enabled = true;
}

/**
 * ksu_kfprobe_lsm_disable() - Deactivate a registered LSM hook
 */
void ksu_kfprobe_lsm_disable(struct ksu_kfprobe_lsm_hook *h)
{
    if (h && h->registered)
        h->enabled = false;
}

/**
 * ksu_kfprobe_lsm_is_enabled() - Check if a registered LSM hook is active
 */
bool ksu_kfprobe_lsm_is_enabled(struct ksu_kfprobe_lsm_hook *h)
{
    return h && h->registered && h->enabled;
}

/* ================================================================== */
/*  Global master switch                                               */
/* ================================================================== */

void ksu_kfprobe_lsm_enable_all(void)
{
    static_branch_enable(&kfprobe_lsm_global_enabled);
}

void ksu_kfprobe_lsm_disable_all(void)
{
    static_branch_disable(&kfprobe_lsm_global_enabled);
}

bool ksu_kfprobe_lsm_global_is_enabled(void)
{
    return static_branch_unlikely(&kfprobe_lsm_global_enabled);
}

/* ================================================================== */
/*  Lifecycle                                                         */
/* ================================================================== */

void ksu_kfprobe_lsm_init(void)
{
    pr_info("kfprobe_lsm: init ready (max %d hooks)\n",
            KFPROBE_LSM_HOOK_MAX);
}

void ksu_kfprobe_lsm_exit(void)
{
    struct ksu_kfprobe_lsm_hook *hooks[KFPROBE_LSM_HOOK_MAX];
    int count, i;

    /* Halt all processing first */
    ksu_kfprobe_lsm_disable_all();

    mutex_lock(&kfprobe_lsm_lock);
    count = kfprobe_lsm_hook_count;
    for (i = 0; i < count; i++)
        hooks[i] = kfprobe_lsm_hooks[i];
    mutex_unlock(&kfprobe_lsm_lock);

    /* Restore in reverse order */
    for (i = count - 1; i >= 0; i--)
        ksu_kfprobe_lsm_unregister(hooks[i]);
}