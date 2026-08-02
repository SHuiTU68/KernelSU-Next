/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KSU_H_KFPROBE_LSM
#define __KSU_H_KFPROBE_LSM

#include <linux/types.h>
#include "hook/lsm_hook.h"

/**
 * struct ksu_kfprobe_lsm_hook - Descriptor for a KFprobe-managed LSM hook
 *
 * @name:       Human-readable name (for debugging).
 * @hook:       LSM hook descriptor passed to ksu_lsm_hook().
 * @enabled:    Whether this hook is currently active.
 * @registered: Whether the LSM slot has been patched.
 *              Internal - managed by the framework.
 */
struct ksu_kfprobe_lsm_hook {
    const char *name;
    struct ksu_lsm_hook hook;
    bool enabled;
    bool registered;
};

/* ------------------------------------------------------------------ */
/*  Core API                                                          */
/* ------------------------------------------------------------------ */

int ksu_kfprobe_lsm_register(struct ksu_kfprobe_lsm_hook *h);
void ksu_kfprobe_lsm_unregister(struct ksu_kfprobe_lsm_hook *h);
void ksu_kfprobe_lsm_enable(struct ksu_kfprobe_lsm_hook *h);
void ksu_kfprobe_lsm_disable(struct ksu_kfprobe_lsm_hook *h);
bool ksu_kfprobe_lsm_is_enabled(struct ksu_kfprobe_lsm_hook *h);

/* ------------------------------------------------------------------ */
/*  Global master switch                                               */
/* ------------------------------------------------------------------ */

void ksu_kfprobe_lsm_enable_all(void);
void ksu_kfprobe_lsm_disable_all(void);
bool ksu_kfprobe_lsm_global_is_enabled(void);

/* ------------------------------------------------------------------ */
/*  Lifecycle                                                         */
/* ------------------------------------------------------------------ */

void ksu_kfprobe_lsm_init(void);
void ksu_kfprobe_lsm_exit(void);

#endif /* __KSU_H_KFPROBE_LSM */