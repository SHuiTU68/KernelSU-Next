#ifndef __KSU_H_KPROBE_HOOK
#define __KSU_H_KPROBE_HOOK

#include <linux/jump_label.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/types.h>

/**
 * struct ksu_kprobe_hook - Descriptor for a kprobe-based kernel function hook
 *
 * === User-provided fields ===
 * @name:          Human-readable name for debugging / logging.
 * @symbol_name:   Kernel symbol to probe (e.g. "do_execveat_common").
 *                 Ignored if @symbol_addr != 0.
 * @symbol_addr:   Kernel address of the function to probe (resolved via
 *                 kallsyms_lookup_name internally). Takes precedence over
 *                 @symbol_name. Using addresses avoids leaving a named kprobe
 *                 entry in /proc/kallsyms, reducing the detection surface.
 * @offset:        Offset within the symbol (0 = function entry).
 * @pre_handler:   Called before the probed instruction runs.
 *                 Return 0 to continue normally, !0 to skip the original.
 * @post_handler:  Called after the probed instruction (via kretprobe).
 * @fault_handler: Called if a fault occurs in the pre/post handler.
 * @private_data:  Opaque pointer passed through to handlers.
 *
 * === Optimization fields ===
 * @enabled_key:   Optional pointer to a static_key_false. When non-NULL, the
 *                 framework checks this key in the pre-handler wrapper before
 *                 calling the user's @pre_handler. When the key is disabled
 *                 (default), the wrapper returns immediately with minimal
 *                 overhead (a single nop-patched branch).
 * @filter:        Optional per-task filter. When non-NULL, called for each
 *                 probe hit. The handler is only invoked if filter() returns
 *                 true. Use this to skip irrelevant processes (e.g. only
 *                 hook for allowed UIDs). NULL = allow all.
 *
 * === Internal fields (managed by the framework, do not touch) ===
 * @kp:            Underlying struct kprobe.
 * @registered:    Whether this hook is currently registered.
 */
struct ksu_kprobe_hook {
    /* User-provided fields */
    const char *name;
    const char *symbol_name;
    unsigned long symbol_addr;
    loff_t offset;
    kprobe_pre_handler_t pre_handler;
    kprobe_post_handler_t post_handler;
    kprobe_fault_handler_t fault_handler;
    void *private_data;

    /* Optimization */
    struct static_key_false *enabled_key;
    bool (*filter)(struct task_struct *task);

    /* Internal - managed by the framework */
    struct kprobe kp;
    bool registered;
};

/**
 * ksu_kprobe_hook_register() - Register a kprobe hook on a kernel symbol
 * @hook:  Hook descriptor (must be stable in memory while registered).
 *
 * If @hook->symbol_addr is non-zero, it is used directly; otherwise
 * @hook->symbol_name is resolved via kallsyms_lookup_name.
 *
 * Returns 0 on success, negative errno on failure.
 */
int ksu_kprobe_hook_register(struct ksu_kprobe_hook *hook);

/**
 * ksu_kprobe_hook_unregister() - Unregister a previously registered kprobe hook
 * @hook:  Hook descriptor to unregister.
 */
void ksu_kprobe_hook_unregister(struct ksu_kprobe_hook *hook);

/**
 * ksu_kprobe_hook_register_batch() - Register an array of kprobe hooks
 * @hooks:  Array of hook descriptors.
 * @count:  Number of hooks in the array.
 *
 * If any single registration fails, all previously registered hooks in the
 * batch are rolled back. Returns 0 on success, negative errno on failure.
 */
int ksu_kprobe_hook_register_batch(struct ksu_kprobe_hook hooks[], int count);

/**
 * ksu_kprobe_hook_unregister_batch() - Unregister an array of kprobe hooks
 * @hooks:  Array of hook descriptors.
 * @count:  Number of hooks in the array.
 */
void ksu_kprobe_hook_unregister_batch(struct ksu_kprobe_hook hooks[], int count);

/**
 * ksu_kprobe_hook_enable_all() - Enable the global kprobe hook master switch.
 *
 * When disabled, all registered kprobe pre-handlers return immediately without
 * calling the user handler.  Enabled by default after init.
 */
void ksu_kprobe_hook_enable_all(void);

/**
 * ksu_kprobe_hook_disable_all() - Disable the global kprobe hook master switch.
 *
 * All kprobe breakpoints are still in place, but the handler overhead is
 * reduced to a single static-key check.  Use this to completely suppress
 * hook processing (e.g. during boot or when all hooks are quiescent).
 */
void ksu_kprobe_hook_disable_all(void);

/**
 * ksu_kprobe_hook_init() - Initialize the kprobe hook tracking subsystem.
 *
 * Safe to call more than once. Called automatically from kernelsu_init().
 */
void ksu_kprobe_hook_init(void);

/**
 * ksu_kprobe_hook_exit() - Unregister all tracked kprobe hooks and clean up.
 *
 * Called automatically from kernelsu_exit().
 */
void ksu_kprobe_hook_exit(void);

#endif /* __KSU_H_KPROBE_HOOK */