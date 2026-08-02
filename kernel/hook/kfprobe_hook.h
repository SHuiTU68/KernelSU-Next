#ifndef __KSU_H_KFPROBE_HOOK
#define __KSU_H_KFPROBE_HOOK

#include <linux/jump_label.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/types.h>

/**
 * struct ksu_kfprobe_hook - Descriptor for a KFprobe-based kernel function hook
 *
 * KFprobe = Kernel Function Probe. A hybrid hook engine that uses kprobe
 * (with optional kretprobe) to intercept kernel functions at the VFS/core
 * level. Optimised for low detectability, minimal overhead, and root-powered
 * stealth capabilities.
 *
 * === User-provided fields ===
 * @name:          Human-readable name for debugging (not exposed to userspace).
 * @symbol_name:   Kernel symbol to probe (e.g. "do_execveat_common").
 *                 Ignored when @symbol_addr != 0.
 * @symbol_addr:   Kernel address of the target function.  When non-zero this
 *                 takes precedence over @symbol_name and is used directly
 *                 for an address-based kprobe registration, leaving no named
 *                 entry in /proc/kallsyms.
 * @offset:        Offset within the symbol (0 = function entry).
 *
 * @pre_handler:   Called before the probed function runs.
 *                 Return 0 to continue normally, !0 to skip the original
 *                 function entirely.
 * @post_handler:  Called after the probed function returns.
 *                 Only used when @return_hook is true (kretprobe mode).
 *                 The return value is available via regs->regs[0] (arm64)
 *                 or regs->ax (x86_64).
 * @fault_handler: Called if a fault occurs in the pre/post handler.
 *
 * @private_data:  Opaque pointer passed through to handlers.
 *
 * === Optimisation / stealth fields ===
 * @enabled_key:   Optional pointer to a static_key_false.  When non-NULL the
 *                 framework checks this key before calling the user's handler.
 *                 When the key is disabled the handler returns immediately
 *                 with a single nop-patched branch.
 * @filter:        Optional per-task filter.  When non-NULL, called for each
 *                 probe hit.  The handler is only invoked if filter() returns
 *                 true.  Use this to skip irrelevant processes.
 * @return_hook:   When true, register a kretprobe in addition to (or instead
 *                 of) the entry kprobe, so that @post_handler receives the
 *                 return value.  Only the entry kprobe's pre_handler runs on
 *                 entry; the original function always executes.
 *
 * === Internal fields (managed by the framework, do not touch) ===
 * @kp:            Underlying struct kprobe.
 * @rp:            Underlying struct kretprobe (only when @return_hook is true).
 * @registered:    Whether this hook is currently registered.
 * @use_kretprobe: Internal flag indicating kretprobe was registered.
 */
struct ksu_kfprobe_hook {
    /* User-provided fields */
    const char *name;
    const char *symbol_name;
    unsigned long symbol_addr;
    loff_t offset;
    kprobe_pre_handler_t pre_handler;
    kprobe_post_handler_t post_handler;
    kprobe_fault_handler_t fault_handler;
    void *private_data;

    /* Optimisation / stealth */
    struct static_key_false *enabled_key;
    bool (*filter)(struct task_struct *task);
    bool return_hook;

    /* Internal - managed by the framework */
    struct kprobe kp;
    struct kretprobe rp;
    bool registered;
    bool use_kretprobe;
};

/* ------------------------------------------------------------------ */
/*  Core API                                                          */
/* ------------------------------------------------------------------ */

/**
 * ksu_kfprobe_hook_register() - Register a KFprobe hook on a kernel symbol
 * @hook:  Descriptor (must stay stable in memory while registered).
 *
 * If @hook->return_hook is true a kretprobe is also registered so that
 * @post_handler receives the function's return value.
 *
 * Returns 0 on success, negative errno on failure.
 */
int ksu_kfprobe_hook_register(struct ksu_kfprobe_hook *hook);

/**
 * ksu_kfprobe_hook_unregister() - Unregister a previously registered hook
 * @hook:  Descriptor to unregister.
 */
void ksu_kfprobe_hook_unregister(struct ksu_kfprobe_hook *hook);

/**
 * ksu_kfprobe_hook_register_batch() - Register an array of hooks atomically
 * @hooks:  Array of descriptors.
 * @count:  Number of entries.
 *
 * Rolls back all prior registrations on failure.
 * Returns 0 on success, negative errno on failure.
 */
int ksu_kfprobe_hook_register_batch(struct ksu_kfprobe_hook hooks[], int count);

/**
 * ksu_kfprobe_hook_unregister_batch() - Unregister an array of hooks
 */
void ksu_kfprobe_hook_unregister_batch(struct ksu_kfprobe_hook hooks[], int count);

/* ------------------------------------------------------------------ */
/*  Global master switch                                               */
/* ------------------------------------------------------------------ */

/**
 * ksu_kfprobe_hook_enable_all() - Enable all KFprobe hooks globally.
 *
 * When disabled, every registered pre_handler returns immediately after a
 * single static-key check without calling the user handler.
 */
void ksu_kfprobe_hook_enable_all(void);

/**
 * ksu_kfprobe_hook_disable_all() - Disable all KFprobe hooks globally.
 *
 * The breakpoints stay in place, but the runtime overhead drops to a
 * single nop-patched branch per probe hit.
 */
void ksu_kfprobe_hook_disable_all(void);

/* ------------------------------------------------------------------ */
/*  Lifecycle                                                         */
/* ------------------------------------------------------------------ */

void ksu_kfprobe_hook_init(void);
void ksu_kfprobe_hook_exit(void);

#endif /* __KSU_H_KFPROBE_HOOK */