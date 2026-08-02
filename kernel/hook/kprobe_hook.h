#ifndef __KSU_H_KPROBE_HOOK
#define __KSU_H_KPROBE_HOOK

#include <linux/kprobes.h>
#include <linux/types.h>

/**
 * struct ksu_kprobe_hook - Descriptor for a kprobe-based kernel function hook
 *
 * @name:          Human-readable name for debugging / logging
 * @symbol_name:   Kernel symbol to probe (e.g. "do_execveat_common")
 * @offset:        Offset within the symbol (0 = function entry)
 * @pre_handler:   Called before the probed instruction runs.
 *                 Return 0 to continue normally, !0 to skip the original function.
 * @post_handler:  Called after the probed instruction (handled via kretprobe internally).
 * @fault_handler: Called if a fault occurs in the pre/post handler.
 * @private_data:  Opaque pointer passed through to handlers.
 *
 * Internal fields (managed by the framework, do not touch):
 * @kp:           Underlying struct kprobe.
 * @registered:   Whether this hook is currently registered.
 */
struct ksu_kprobe_hook {
    /* User-provided fields */
    const char *name;
    const char *symbol_name;
    loff_t offset;
    kprobe_pre_handler_t pre_handler;
    kprobe_post_handler_t post_handler;
    kprobe_fault_handler_t fault_handler;
    void *private_data;

    /* Internal - managed by the framework */
    struct kprobe kp;
    bool registered;
};

/**
 * ksu_kprobe_hook_register() - Register a kprobe hook on a kernel symbol
 * @hook:  Hook descriptor (must be stable in memory while registered)
 *
 * Returns 0 on success, negative errno on failure.
 */
int ksu_kprobe_hook_register(struct ksu_kprobe_hook *hook);

/**
 * ksu_kprobe_hook_unregister() - Unregister a previously registered kprobe hook
 * @hook:  Hook descriptor to unregister
 */
void ksu_kprobe_hook_unregister(struct ksu_kprobe_hook *hook);

/**
 * ksu_kprobe_hook_register_batch() - Register an array of kprobe hooks
 * @hooks:  Array of hook descriptors
 * @count:  Number of hooks in the array
 *
 * If any single registration fails, all previously registered hooks in the
 * batch are rolled back. Returns 0 on success, negative errno on failure.
 */
int ksu_kprobe_hook_register_batch(struct ksu_kprobe_hook hooks[], int count);

/**
 * ksu_kprobe_hook_unregister_batch() - Unregister an array of kprobe hooks
 * @hooks:  Array of hook descriptors
 * @count:  Number of hooks in the array
 */
void ksu_kprobe_hook_unregister_batch(struct ksu_kprobe_hook hooks[], int count);

/**
 * ksu_kprobe_hook_init() - Initialize the kprobe hook tracking subsystem
 *
 * Safe to call more than once. Called automatically from kernelsu_init().
 */
void ksu_kprobe_hook_init(void);

/**
 * ksu_kprobe_hook_exit() - Unregister all tracked kprobe hooks and clean up
 *
 * Called automatically from kernelsu_exit().
 */
void ksu_kprobe_hook_exit(void);

#endif /* __KSU_H_KPROBE_HOOK */