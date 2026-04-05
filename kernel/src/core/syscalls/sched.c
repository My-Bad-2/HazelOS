#include <stdint.h>

#include "core/errors.h"
#include "core/syscalls.h"
#include "memory/vma.h"
#include "sched/process.h"
#include "sched/scheduler.h"

static inline void write_cap_out(uint64_t* ptr, uint64_t val) {
    if (!ptr) return;
    if (!vmm_is_user_region((uintptr_t)ptr, sizeof(uint64_t))) return;

    copy_to_user(ptr, &val, sizeof(uint64_t));
}

int64_t sys_process_create(
    const char* name,
    void* vspace,
    uint64_t* out_proc_cap,
    uint64_t* out_cnode_cap,
    uint64_t* out_vspace_cap
) {
    uint64_t p_cap = 0, c_cap = 0, v_cap = 0;
    int err;
    process_t* proc = process_create(name, false, vspace, &p_cap, &c_cap, &v_cap, &err);

    if (err != ERR_OK) return err;

    write_cap_out(out_proc_cap, p_cap);
    write_cap_out(out_cnode_cap, c_cap);
    write_cap_out(out_vspace_cap, v_cap);

    return ERR_OK;
}